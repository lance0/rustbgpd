#!/usr/bin/env bash
# Gate 8b MAC-churn 24-hour soak — sustained DF flip + bounded
# rotating-MAC churn on the 2-PE shared-ESI topology at
# `tests/soak/gate8b-soak.clab.yml`.
#
# Sibling to `run-gate8b-soak.sh`. The base soak validated steady
# memory under DF-flip churn only (no FDB churn). This variant
# adds sustained bridge-FDB mutation on top so the soak exercises:
#
#   - kernel-learn / local-MAC observation → Type 2 origination
#   - ADR-0059 receive-side aliasing-ECMP (FDB nexthop groups)
#   - RFC 7432 §15.1 MAC mobility sequencing
#   - Gate 8b BUM-suppression while FDB programming is in flight
#   - the ADR-0059 drift-recovery counters under realistic timing
#
# The bounded rotating set keeps the test deterministic — pool
# size, batch size, and cadence are env-tunable. Mobility (MAC
# moves between PEs) is included to exercise RFC 7432 §15.1 mobility
# sequencing while the shared-ESI aliasing-ECMP path is also under
# sustained churn.
#
# MAC injection is **direct kernel FDB mutation**:
#     docker exec <pe> bridge fdb add <mac> dev ce100a master static
# This is the kernel-learn shape the daemon classifies as local.
# We deliberately do NOT use gRPC route injection — that would
# bypass the local-observation → origination pipeline this soak
# is here to stress.
#
# Output: tests/soak/runs/gate8b-mac-churn-<UTC-timestamp>/
#   - samples.csv     one-row-per-minute timeseries (mem, df_role,
#                     df_role_changes, BUM flag state, local FDB
#                     totals, extern_learn counts, FDB-NHG / nhid
#                     counts, evpn_local_originations, error and
#                     observation-drop counters, dup-MAC moves,
#                     the four ADR-0059 drift counters)
#   - soak.log        stdout + stderr from this script
#   - pe1.log         daemon log streamed from `docker logs pe1`
#   - pe2.log         daemon log streamed from `docker logs pe2`
#   - flips.log       per-flip event log (timestamp, action, target)
#   - churn.log       per-batch FDB-churn event log
#   - state/          live MAC pool state (one file per PE)
#   - run.json        run metadata (image SHA, git rev, env at start)
#
# Prerequisites:
#   docker build --target dev -t rustbgpd:dev .
#   sudo containerlab deploy -t tests/soak/gate8b-soak.clab.yml
#
# Usage:
#   bash tests/soak/run-gate8b-mac-churn-soak.sh            # 24h default
#   SOAK_HOURS=1 bash tests/soak/run-gate8b-mac-churn-soak.sh   # 1h smoke
#   SOAK_HOURS=0.1 CHURN_INTERVAL_SEC=2 \
#       bash tests/soak/run-gate8b-mac-churn-soak.sh        # 6-min stress
#
# Tail the per-PE logs while the soak runs:
#   tail -F tests/soak/runs/gate8b-mac-churn-<UTC>/churn.log
#   tail -F tests/soak/runs/gate8b-mac-churn-<UTC>/samples.csv

set -euo pipefail

SOAK_SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SOAK_SCRIPT_DIR/../.." && pwd)"
TOPOLOGY="$SOAK_SCRIPT_DIR/gate8b-soak.clab.yml"

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

# Soak loop (inherited from run-gate8b-soak.sh)
SOAK_HOURS="${SOAK_HOURS:-24}"
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-60}"          # seconds between CSV rows
FLIP_INTERVAL_SEC="${FLIP_INTERVAL_SEC:-600}"     # 10-minute DF flips
WARMUP_SEC="${WARMUP_SEC:-120}"                   # discard first 2 min for slope
BGP_ESTABLISHED_TIMEOUT_SEC="${BGP_ESTABLISHED_TIMEOUT_SEC:-300}"
                                                  # gate before churn — refuse
                                                  # to start the validation if
                                                  # BGP never establishes
PE1_NAME="${PE1_NAME:-clab-gate8b-soak-pe1}"
PE2_NAME="${PE2_NAME:-clab-gate8b-soak-pe2}"
CLEANUP="${CLEANUP:-0}"                           # 1 = destroy topology on EXIT

# Flip mechanism. The previous `docker stop` / `docker start` approach
# tears down the clab-managed veth pair between PE1 and PE2 (the
# netns is destroyed when the container stops, taking eth1 with it
# on both sides), which breaks BGP peering on 10.0.0.x. The
# process-restart path SIGTERMs the daemon inside the container and
# then re-launches it via the same startup script — the kernel
# netns, eth1, the 10.0.0.x address, the bridge, and the kernel
# FDB rows all persist across the restart. This is the right
# semantic test for the soak: BGP tears down, peer routes are
# withdrawn, DF election re-runs, and re-establishment exercises
# the OPEN-collision FSM under load.
KILL_MODE="${KILL_MODE:-term}"                    # term | kill (crash-style)
FLIP_PE="${FLIP_PE:-pe2}"                         # which PE to flip

# MAC churn (new)
CHURN_INTERVAL_SEC="${CHURN_INTERVAL_SEC:-5}"     # seconds between churn batches
CHURN_BATCH_SIZE="${CHURN_BATCH_SIZE:-16}"        # FDB ops per batch
MAC_POOL_SIZE="${MAC_POOL_SIZE:-512}"             # bounded rotating-MAC pool size
MOBILITY_FRACTION="${MOBILITY_FRACTION:-25}"      # percent of batches that move MACs
CE_PORT="${CE_PORT:-ce100a}"                     # CE-facing bridge port
VNI="${VNI:-100}"

# Pool steady-state targets — let it breathe ~25% around POOL_TARGET
POOL_TARGET=$((MAC_POOL_SIZE / 2))                # half the pool per PE
POOL_MIN=$((POOL_TARGET / 2))
POOL_MAX=$((POOL_TARGET + POOL_TARGET / 2))

START_TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${RUN_DIR_OVERRIDE:-$SOAK_SCRIPT_DIR/runs/gate8b-mac-churn-$START_TS}"
mkdir -p "$RUN_DIR" "$RUN_DIR/state"

SAMPLES_CSV="$RUN_DIR/samples.csv"
SOAK_LOG="$RUN_DIR/soak.log"
PE1_LOG="$RUN_DIR/pe1.log"
PE2_LOG="$RUN_DIR/pe2.log"
FLIPS_LOG="$RUN_DIR/flips.log"
CHURN_LOG="$RUN_DIR/churn.log"
RUN_JSON="$RUN_DIR/run.json"
PE1_POOL="$RUN_DIR/state/pe1_macs.txt"
PE2_POOL="$RUN_DIR/state/pe2_macs.txt"
: >"$PE1_POOL"
: >"$PE2_POOL"

# Aggregate churn counters live in files because the churn loop
# runs in a background subshell — bash variable writes there are
# invisible to the parent shell that owns the CSV. Counter files
# are owned by the (serial) churn loop and read by the (separate)
# sampling loop; cat / printf are atomic for the small payload.
CHURN_ADDS_FILE="$RUN_DIR/state/churn_adds"
CHURN_DELS_FILE="$RUN_DIR/state/churn_dels"
CHURN_MOVES_FILE="$RUN_DIR/state/churn_moves"
echo 0 >"$CHURN_ADDS_FILE"
echo 0 >"$CHURN_DELS_FILE"
echo 0 >"$CHURN_MOVES_FILE"

# Re-route stdout/stderr to soak.log AND original tty so the user
# can `tail -F soak.log` from another terminal while still seeing
# live progress in the foreground tmux pane.
exec > >(tee -a "$SOAK_LOG") 2>&1

# Host mutex shared with bench/compare-criterion.sh. See
# tests/soak/host-lock.sh for sudo/HOME caveats.
# shellcheck source=./host-lock.sh
source "$SOAK_SCRIPT_DIR/host-lock.sh"
acquire_rustbgpd_host_lock
# shellcheck source=./gate8b-terminal-recovery.sh
source "$SOAK_SCRIPT_DIR/gate8b-terminal-recovery.sh"

# ---------------------------------------------------------------------------
# Helpers (shared shape with run-gate8b-soak.sh)
# ---------------------------------------------------------------------------

log() {
    printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

flip_log() {
    printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"$FLIPS_LOG"
}

churn_log() {
    printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"$CHURN_LOG"
}

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        log "ERROR: required tool '$1' not in PATH"
        exit 2
    fi
}

# Scrape Prometheus from the host using the container's clab IP.
# Same shape as run-gate8b-soak.sh — see that script for the
# image-bloat / no-curl-inside-container rationale.
prom_scrape() {
    local container="$1"
    local ip
    ip=$(docker inspect --format \
        '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' \
        "$container" 2>/dev/null | awk '{print $1}')
    [ -z "$ip" ] && return 0
    curl -sfm 5 "http://${ip}:9179/metrics" 2>/dev/null || true
}

prom_extract() {
    # $1 = scraped text, $2 = metric name, $3 = optional label match.
    # Returns the metric value (last whitespace-separated field on the
    # first matching line) or empty if the metric/label combo is not
    # present. Callers fall back to NaN in the CSV.
    local text="$1" metric="$2" label="${3:-}"
    if [ -n "$label" ]; then
        printf '%s' "$text" | awk -v m="$metric" -v l="$label" '
            $0 ~ "^"m"\\{" && index($0, l) { print $NF; exit }
        '
    else
        printf '%s' "$text" | awk -v m="$metric" '
            $0 ~ "^"m"( |\\{)" { print $NF; exit }
        '
    fi
}

container_is_running() {
    [ "$(docker inspect --format='{{.State.Running}}' "$1" 2>/dev/null || echo false)" = "true" ]
}

container_rss_mb() {
    local container="$1"
    local rss
    rss=$(docker exec "$container" sh -c '
        pid=$(pidof rustbgpd 2>/dev/null || echo "")
        if [ -n "$pid" ] && [ -r /proc/$pid/status ]; then
            awk "/^VmRSS:/ {print \$2/1024}" /proc/$pid/status
        fi
    ' 2>/dev/null || echo "")
    if [ -n "$rss" ]; then
        echo "$rss"
        return 0
    fi
    docker stats --no-stream --format '{{.MemUsage}}' "$container" 2>/dev/null | awk '
        NR == 1 {
            value = $1
            unit = value
            sub(/^[0-9.]+/, "", unit)
            sub(/[A-Za-z]+$/, "", value)
            n = value + 0
            if (unit == "KiB" || unit == "kB" || unit == "KB") { print n / 1024 }
            else if (unit == "MiB" || unit == "MB") { print n }
            else if (unit == "GiB" || unit == "GB") { print n * 1024 }
        }
    '
}

bridge_flag_state() {
    local container="$1"
    local out
    if ! out=$(docker exec "$container" bridge -d link show dev "$CE_PORT" 2>/dev/null); then
        echo "unreachable"; return 0
    fi
    if [ -z "$out" ]; then echo "unreachable"; return 0; fi
    local f m b
    f=$(printf '%s' "$out" | grep -oE 'flood (on|off)' | head -1 | awk '{print $2}')
    m=$(printf '%s' "$out" | grep -oE 'mcast_flood (on|off)' | head -1 | awk '{print $2}')
    b=$(printf '%s' "$out" | grep -oE 'bcast_flood (on|off)' | head -1 | awk '{print $2}')
    if [ "$f" = "on" ] && [ "$m" = "on" ] && [ "$b" = "on" ]; then echo "df"
    elif [ "$f" = "off" ] && [ "$m" = "off" ] && [ "$b" = "off" ]; then echo "nondf"
    else echo "mixed"; fi
}

fdb_total_count() {
    # Kernel-side FDB row count (all entries on the bridge).
    local container="$1"
    docker exec "$container" sh -c 'bridge fdb show 2>/dev/null | wc -l' 2>/dev/null || echo ""
}

fdb_extern_learn_count() {
    # Rows the daemon programmed as remote MACs (extern_learn flag).
    local container="$1"
    docker exec "$container" sh -c 'bridge fdb show 2>/dev/null | grep -c extern_learn || true' 2>/dev/null || echo ""
}

nh_count() {
    # ip nexthop entries (ADR-0059 aliasing-ECMP FDB-NHGs land here).
    local container="$1"
    docker exec "$container" sh -c 'ip nexthop show 2>/dev/null | wc -l' 2>/dev/null || echo ""
}

prom_established_total() {
    local prom="$1"
    [ -z "$prom" ] && { echo 0; return; }
    printf '%s' "$prom" | awk '
        $0 ~ /^bgp_session_established_total\{/ { sum += $NF }
        END { print sum + 0 }
    '
}

prom_established_current() {
    local prom="$1"
    [ -z "$prom" ] && { echo 0; return; }
    printf '%s' "$prom" | awk '
        $0 ~ /^bgp_peer_session_established\{/ { sum += $NF }
        END { print sum + 0 }
    '
}

pe_established_current() {
    prom_established_current "$(prom_scrape "$1")"
}

# Refuse to start churn until both PEs are currently Established.
# The OPEN-collision-race recovery time on simultaneous
# clab deploy can exceed the fixed warmup window; gating here keeps
# the validation honest — without it the soak can pass with
# `extern_learn = 0` and miss the entire remote-Type-2 receive path.
wait_established() {
    local timeout_sec="$BGP_ESTABLISHED_TIMEOUT_SEC"
    local deadline=$(($(date +%s) + timeout_sec))
    log "waiting up to ${timeout_sec}s for both PEs to reach BGP Established"
    while [ "$(date +%s)" -lt "$deadline" ]; do
        local p1 p2
        p1="$(pe_established_current "$PE1_NAME")"
        p2="$(pe_established_current "$PE2_NAME")"
        if [ "${p1:-0}" -ge 1 ] && [ "${p2:-0}" -ge 1 ]; then
            log "BGP Established gate passed (pe1_current=${p1} pe2_current=${p2})"
            return 0
        fi
        sleep 5
    done
    log "ERROR: BGP Established gate timed out after ${timeout_sec}s"
    dump_session_state_on_failure
    return 1
}

# Operator-facing diag when wait_established trips. Dumps both PEs'
# session-state metric rows plus the last 50 docker-log lines per
# container so a postmortem doesn't require re-running anything.
dump_session_state_on_failure() {
    for pe in "$PE1_NAME" "$PE2_NAME"; do
        log "=== session-state metrics: $pe ==="
        local prom matched
        prom="$(prom_scrape "$pe")"
        if [ -z "$prom" ]; then
            log "  (scrape returned empty — metrics endpoint unreachable)"
            continue
        fi
        # Wrap grep in `|| true` so an empty match doesn't propagate up
        # through `set -o pipefail` and short-circuit the rest of the
        # function (the docker-logs dump below is the real diagnostic
        # signal we need when sessions never reach Established).
        matched="$( (printf '%s\n' "$prom" \
            | grep -E '^bgp_session_(established|state_transitions|flaps)_total\{' \
            || true) | sort | head -40 )"
        if [ -z "$matched" ]; then
            log "  (no bgp_session_* rows present in scrape)"
        else
            printf '%s\n' "$matched" | while IFS= read -r line; do log "  $line"; done
        fi
    done
    for pe in "$PE1_NAME" "$PE2_NAME"; do
        log "=== docker logs --tail 50: $pe ==="
        docker logs --tail 50 "$pe" 2>&1 | tail -50 | while IFS= read -r line; do
            log "  $line"
        done
    done
}

# Verify the clab-managed eth1 + 10.0.0.x point-to-point survives.
# The previous `docker stop`/`docker start` flip would silently tear
# down this veth on both sides — fail loud here so a future
# regression to the container-restart pattern is impossible to
# misdiagnose as a daemon-side wedge.
verify_topology_link() {
    local pe ok=0
    for pe in "$PE1_NAME" "$PE2_NAME"; do
        if ! docker exec "$pe" ip -br addr show dev eth1 2>/dev/null \
            | grep -q '10\.0\.0\.'; then
            log "ERROR: $pe eth1 is missing the clab-managed 10.0.0.x address"
            ok=1
        fi
    done
    return "$ok"
}

# Wait for a freshly restarted PE's daemon to be currently Established.
# During the bind window
# right after the new daemon launches, `curl` to :9179 returns
# "connection refused" and `pe_established_current` falls back to 0,
# which simply keeps the poll loop running until the listener is
# up and the OPEN exchange completes.
wait_established_post_flip() {
    local pe="$1"
    local timeout_sec="$BGP_ESTABLISHED_TIMEOUT_SEC"
    local deadline=$(($(date +%s) + timeout_sec))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        local cur
        cur="$(pe_established_current "$pe")"
        if [ "${cur:-0}" -ge 1 ]; then
            log "post-flip re-established: $pe current=$cur"
            return 0
        fi
        sleep 5
    done
    log "WARN: post-flip $pe did not re-establish within ${timeout_sec}s"
    return 1
}

# Send the flip signal to the in-container daemon. Default SIGTERM
# exercises the coordinated drain; KILL_MODE=kill is a crash-mode
# flip for catching paths the orderly-exit path masks.
#
# The rustbgpd container image ships with `pidof` and the shell
# `kill` builtin but **not** `ps`, `pkill`, `pgrep`, or `killall`,
# and the `kill` binary itself isn't present (the image is slim by
# design). `xargs kill` would try to exec a binary; instead route
# through `sh -c` so the builtin handles the signal.
flip_stop_daemon() {
    local container="$1" signal
    case "$KILL_MODE" in
        kill) signal="-KILL" ;;
        *)    signal="-TERM" ;;
    esac
    docker exec "$container" sh -c \
        "pid=\$(pidof rustbgpd) && [ -n \"\$pid\" ] && kill ${signal} \$pid" \
        2>/dev/null || return
    local i state
    for ((i = 0; i < 30; i++)); do
        state="$(docker exec "$container" sh -c '
            if pidof rustbgpd >/dev/null 2>&1; then
                printf running
            else
                printf stopped
            fi
        ')" || return
        case "$state" in
            stopped) return 0 ;;
            running) ;;
            *) log "ERROR: $container returned unknown daemon state: $state"; return 1 ;;
        esac
        sleep 1
    done
    log "WARN: $container rustbgpd did not exit within 30s of ${KILL_MODE} signal"
    return 1
}

flip_start_daemon() {
    local container="$1" local_ip="$2" remote_ip="$3"
    docker exec "$container" /usr/local/bin/start-rustbgpd-soak-gate8b.sh \
        "$local_ip" "$remote_ip" "$VNI" || return
}

stop_pe2_daemon() {
    flip_stop_daemon "$PE2_NAME" || return; PE2_RUNNING=0
}

start_pe2_daemon() {
    flip_start_daemon "$PE2_NAME" 10.0.0.2 10.0.0.1 || return
    wait_established_post_flip "$PE2_NAME" || return; PE2_RUNNING=1
}

# ---------------------------------------------------------------------------
# MAC pool helpers
# ---------------------------------------------------------------------------

# MAC scheme: 02:aa:00:HH:HH:HH where HH:HH:HH is the rotating index
# (24 bits, supports up to 16M MACs). The MAC is intentionally stable
# across PE moves; otherwise a "mobility" batch would delete one MAC
# and add a different MAC, bypassing RFC 7432 §15.1 mobility handling.
mac_for() {
    local idx="$1"
    printf '02:aa:00:%02x:%02x:%02x' "$(( (idx >> 16) & 0xff ))" "$(( (idx >> 8) & 0xff ))" "$(( idx & 0xff ))"
}

pool_file_for() {
    case "$1" in
        1) echo "$PE1_POOL" ;;
        2) echo "$PE2_POOL" ;;
        *) return 1 ;;
    esac
}

pool_size() {
    wc -l <"$(pool_file_for "$1")"
}

# Pick `count` random integers in [0, MAC_POOL_SIZE) that are NOT
# present in either PE's pool file. Returns one index per line.
pool_pick_free() {
    # Generate `count` random integers in [0, MAC_POOL_SIZE) that
    # are NOT in either PE's pool file. Capped at ceiling*4
    # tries so a near-saturated pool can't spin forever.
    local _pe="$1" count="$2"
    awk -v want="$count" -v ceiling="$MAC_POOL_SIZE" -v pool1="$PE1_POOL" -v pool2="$PE2_POOL" '
        BEGIN {
            while ((getline line < pool1) > 0) taken[line] = 1
            close(pool1)
            while ((getline line < pool2) > 0) taken[line] = 1
            close(pool2)
            srand()
            picked = 0; tries = 0; max_tries = ceiling * 4
            while (picked < want && tries < max_tries) {
                idx = int(rand() * ceiling)
                tries++
                if (!(idx in taken) && !(idx in done)) {
                    print idx; done[idx] = 1; picked++
                }
            }
        }
    ' </dev/null
}

# Pick `count` random integers FROM the given PE's pool (existing MACs).
pool_pick_used() {
    local pe="$1" count="$2"
    shuf -n "$count" <"$(pool_file_for "$pe")" 2>/dev/null || true
}

# Add a MAC to the on-disk pool index.
pool_record_add() {
    local pe="$1" idx="$2"
    echo "$idx" >>"$(pool_file_for "$pe")"
}

# Remove a MAC from the on-disk pool index.
pool_record_del() {
    local pe="$1" idx="$2"
    local f
    f="$(pool_file_for "$pe")"
    # Use a tmp + rename so partial writes can't truncate the pool
    # mid-soak. grep -v is exact-match against the line.
    grep -vxF "$idx" "$f" >"$f.tmp" 2>/dev/null || : >"$f.tmp"
    mv "$f.tmp" "$f"
}

# ---------------------------------------------------------------------------
# FDB churn ops — exec inside the PE container, log to churn.log.
# ---------------------------------------------------------------------------

# `bridge fdb add <mac> dev <port> master static` registers the MAC
# as a local entry on the bridge, classified by the daemon as a
# locally-learned MAC and originated as RFC 7432 Type 2.
fdb_add_pe() {
    local pe="$1" mac="$2" container
    container="$(container_for_pe "$pe")"
    if container_is_running "$container"; then
        if docker exec "$container" bridge fdb add "$mac" dev "$CE_PORT" master static 2>/dev/null; then
            return 0
        fi
        churn_log "ADD failed pe=$pe mac=$mac"
        return 1
    fi
    return 1
}

fdb_del_pe() {
    local pe="$1" mac="$2" container
    container="$(container_for_pe "$pe")"
    if container_is_running "$container"; then
        if docker exec "$container" bridge fdb del "$mac" dev "$CE_PORT" master 2>/dev/null; then
            return 0
        fi
        churn_log "DEL failed pe=$pe mac=$mac"
        return 1
    fi
    return 1
}

container_for_pe() {
    case "$1" in
        1) echo "$PE1_NAME" ;;
        2) echo "$PE2_NAME" ;;
        *) return 1 ;;
    esac
}

# ---------------------------------------------------------------------------
# Churn batches — one of {add, del, mobility}. Driven by a single
# sequential loop so there are no concurrent writers to the pool
# state files; the loop runs in the background of the main soak
# loop but is itself serial.
# ---------------------------------------------------------------------------

counter_incr() {
    local file="$1" by="$2" n
    n=$(< "$file")
    echo $((n + by)) >"$file"
}

churn_batch_add() {
    local pe="$1" count="$2" idx mac added=0
    while IFS= read -r idx; do
        [ -z "$idx" ] && continue
        mac="$(mac_for "$idx")"
        if fdb_add_pe "$pe" "$mac"; then
            pool_record_add "$pe" "$idx"
            added=$((added + 1))
        fi
    done < <(pool_pick_free "$pe" "$count")
    counter_incr "$CHURN_ADDS_FILE" "$added"
    churn_log "ADD pe=$pe added=$added pool=$(pool_size "$pe")"
}

churn_batch_del() {
    local pe="$1" count="$2" idx mac removed=0
    while IFS= read -r idx; do
        [ -z "$idx" ] && continue
        mac="$(mac_for "$idx")"
        if fdb_del_pe "$pe" "$mac"; then
            pool_record_del "$pe" "$idx"
            removed=$((removed + 1))
        fi
    done < <(pool_pick_used "$pe" "$count")
    counter_incr "$CHURN_DELS_FILE" "$removed"
    churn_log "DEL pe=$pe removed=$removed pool=$(pool_size "$pe")"
}

churn_batch_mobility() {
    # Move `count` MACs between PEs. Picks the source PE with the
    # larger pool so we don't drain one side. Skip silently if
    # either PE is down — mobility requires both ends present.
    local count="$1" src dst idx mac moved=0
    if ! container_is_running "$PE1_NAME" || ! container_is_running "$PE2_NAME"; then
        churn_log "MOVE skipped (one PE down)"
        return 0
    fi
    if [ "$(pool_size 1)" -ge "$(pool_size 2)" ]; then
        src=1; dst=2
    else
        src=2; dst=1
    fi
    while IFS= read -r idx; do
        [ -z "$idx" ] && continue
        mac="$(mac_for "$idx")"
        if fdb_del_pe "$src" "$mac"; then
            if ! fdb_add_pe "$dst" "$mac"; then
                # Preserve pool/kernel consistency if the second half
                # of the move fails after the source delete succeeded.
                fdb_add_pe "$src" "$mac" || true
                churn_log "MOVE rollback src=$src dst=$dst idx=$idx"
                continue
            fi
            pool_record_del "$src" "$idx"
            pool_record_add "$dst" "$idx"
            moved=$((moved + 1))
        fi
    done < <(pool_pick_used "$src" "$count")
    counter_incr "$CHURN_MOVES_FILE" "$moved"
    churn_log "MOVE src=$src dst=$dst moved=$moved pe1_pool=$(pool_size 1) pe2_pool=$(pool_size 2)"
}

# Pick the next churn action based on current pool occupancy and
# the mobility fraction. Forces add/del when pools are near the
# bounds so the soak doesn't drift into an empty or saturated state.
churn_step() {
    local p1 p2 batch_size="$CHURN_BATCH_SIZE"
    p1="$(pool_size 1)"
    p2="$(pool_size 2)"

    # Force grow if both pools below the floor.
    if [ "$p1" -lt "$POOL_MIN" ] && [ "$p2" -lt "$POOL_MIN" ]; then
        churn_batch_add 1 "$batch_size"
        churn_batch_add 2 "$batch_size"
        return
    fi
    # Force shrink if either pool over the ceiling.
    if [ "$p1" -gt "$POOL_MAX" ]; then churn_batch_del 1 "$batch_size"; return; fi
    if [ "$p2" -gt "$POOL_MAX" ]; then churn_batch_del 2 "$batch_size"; return; fi

    # Otherwise weighted random: MOBILITY_FRACTION% mobility, then
    # 60/40 add/del split among the remainder.
    local roll=$((RANDOM % 100))
    if [ "$roll" -lt "$MOBILITY_FRACTION" ]; then
        churn_batch_mobility "$batch_size"
        return
    fi
    if [ $((roll % 5)) -lt 3 ]; then
        # ~60% add (between the two PEs round-robin)
        if [ "$p1" -le "$p2" ]; then churn_batch_add 1 "$batch_size"
        else churn_batch_add 2 "$batch_size"; fi
    else
        if [ "$p1" -ge "$p2" ]; then churn_batch_del 1 "$batch_size"
        else churn_batch_del 2 "$batch_size"; fi
    fi
}

# Background churn loop. Runs serial in its own subshell so the
# main loop can sample and flip without coordinating timestep with
# the churn cadence. Exits when the parent dies (the cleanup trap
# kills it explicitly so it doesn't outlive the soak).
churn_loop() {
    local end_unix="$1"
    while [ "$(date +%s)" -lt "$end_unix" ]; do
        churn_step
        sleep "$CHURN_INTERVAL_SEC"
    done
}

recover_terminal_pe2() {
    start_pe2_daemon || return
    verify_topology_link || return
}

sample_row() {
    local NOW="${1:-$(date +%s)}" ELAPSED PE1_PROM PE2_PROM
    local PE1_RSS PE2_RSS PE1_DF PE2_DF PE1_DF_CHANGES PE2_DF_CHANGES
    local PE1_FLAGS PE2_FLAGS PE1_CURRENT PE2_CURRENT PE1_ESTAB PE2_ESTAB
    local PE1_POOL_N PE2_POOL_N PE1_FDB_TOTAL PE2_FDB_TOTAL PE1_FDB_EXT PE2_FDB_EXT
    local PE1_NH PE2_NH PE1_ORIGS PE2_ORIGS PE1_ORIG_ERR PE2_ORIG_ERR
    local PE1_OBS_DROPS PE2_OBS_DROPS PE1_DUP_MOVES PE2_DUP_MOVES
    local PE1_REPAIRED PE2_REPAIRED PE1_REPLACED PE2_REPLACED
    local PE1_ORPHANS PE2_ORPHANS PE1_DDISABLED PE2_DDISABLED
    ELAPSED="${2:-$((NOW - START_UNIX))}"
    PE1_PROM="$(prom_scrape "$PE1_NAME")"; PE2_PROM="$(prom_scrape "$PE2_NAME")"
    PE1_RSS="$(container_rss_mb "$PE1_NAME" || echo "")"; PE2_RSS="$(container_rss_mb "$PE2_NAME" || echo "")"
    PE1_DF="$(prom_extract "$PE1_PROM" evpn_df_role 'role="df"')"; PE2_DF="$(prom_extract "$PE2_PROM" evpn_df_role 'role="df"')"
    PE1_DF_CHANGES="$(prom_extract "$PE1_PROM" evpn_df_role_changes_total)"; PE2_DF_CHANGES="$(prom_extract "$PE2_PROM" evpn_df_role_changes_total)"
    PE1_FLAGS="$(bridge_flag_state "$PE1_NAME")"; PE2_FLAGS="$(bridge_flag_state "$PE2_NAME" 2>/dev/null || echo unreachable)"
    PE1_CURRENT="$(prom_established_current "$PE1_PROM")"; PE2_CURRENT="$(prom_established_current "$PE2_PROM")"
    PE1_ESTAB="$(prom_established_total "$PE1_PROM")"; PE2_ESTAB="$(prom_established_total "$PE2_PROM")"
    PE1_POOL_N="$(pool_size 1)"; PE2_POOL_N="$(pool_size 2)"
    PE1_FDB_TOTAL="$(fdb_total_count "$PE1_NAME")"; PE2_FDB_TOTAL="$(fdb_total_count "$PE2_NAME")"
    PE1_FDB_EXT="$(fdb_extern_learn_count "$PE1_NAME")"; PE2_FDB_EXT="$(fdb_extern_learn_count "$PE2_NAME")"
    PE1_NH="$(nh_count "$PE1_NAME")"; PE2_NH="$(nh_count "$PE2_NAME")"
    PE1_ORIGS="$(prom_extract "$PE1_PROM" evpn_local_originations_total)"; PE2_ORIGS="$(prom_extract "$PE2_PROM" evpn_local_originations_total)"
    PE1_ORIG_ERR="$(prom_extract "$PE1_PROM" evpn_local_origination_errors_total)"; PE2_ORIG_ERR="$(prom_extract "$PE2_PROM" evpn_local_origination_errors_total)"
    PE1_OBS_DROPS="$(prom_extract "$PE1_PROM" evpn_local_observations_dropped_total)"; PE2_OBS_DROPS="$(prom_extract "$PE2_PROM" evpn_local_observations_dropped_total)"
    PE1_DUP_MOVES="$(prom_extract "$PE1_PROM" evpn_duplicate_mac_moves_total)"; PE2_DUP_MOVES="$(prom_extract "$PE2_PROM" evpn_duplicate_mac_moves_total)"
    PE1_REPAIRED="$(prom_extract "$PE1_PROM" evpn_fdb_nhg_drift_members_repaired_total)"; PE2_REPAIRED="$(prom_extract "$PE2_PROM" evpn_fdb_nhg_drift_members_repaired_total)"
    PE1_REPLACED="$(prom_extract "$PE1_PROM" evpn_fdb_nhg_drift_groups_replaced_total)"; PE2_REPLACED="$(prom_extract "$PE2_PROM" evpn_fdb_nhg_drift_groups_replaced_total)"
    PE1_ORPHANS="$(prom_extract "$PE1_PROM" evpn_fdb_nhg_orphans_cleaned_total)"; PE2_ORPHANS="$(prom_extract "$PE2_PROM" evpn_fdb_nhg_orphans_cleaned_total)"
    PE1_DDISABLED="$(prom_extract "$PE1_PROM" evpn_fdb_nhg_drift_disabled_total)"; PE2_DDISABLED="$(prom_extract "$PE2_PROM" evpn_fdb_nhg_drift_disabled_total)"
    {
        printf '%s' "$NOW"
        printf ',%s' "$ELAPSED" "${PE1_RSS:-NaN}" "${PE2_RSS:-NaN}" "${PE1_DF:-NaN}" "${PE2_DF:-NaN}" "${PE1_DF_CHANGES:-NaN}" "${PE2_DF_CHANGES:-NaN}" "${PE1_FLAGS:-unknown}" "${PE2_FLAGS:-unknown}" "$PE2_RUNNING" "${PE1_CURRENT:-NaN}" "${PE2_CURRENT:-NaN}" "${PE1_ESTAB:-NaN}" "${PE2_ESTAB:-NaN}" "$PE1_POOL_N" "$PE2_POOL_N" "${PE1_FDB_TOTAL:-NaN}" "${PE2_FDB_TOTAL:-NaN}" "${PE1_FDB_EXT:-NaN}" "${PE2_FDB_EXT:-NaN}" "${PE1_NH:-NaN}" "${PE2_NH:-NaN}" "${PE1_ORIGS:-NaN}" "${PE2_ORIGS:-NaN}" "${PE1_ORIG_ERR:-NaN}" "${PE2_ORIG_ERR:-NaN}" "${PE1_OBS_DROPS:-NaN}" "${PE2_OBS_DROPS:-NaN}" "${PE1_DUP_MOVES:-NaN}" "${PE2_DUP_MOVES:-NaN}" "${PE1_REPAIRED:-NaN}" "${PE2_REPAIRED:-NaN}" "${PE1_REPLACED:-NaN}" "${PE2_REPLACED:-NaN}" "${PE1_ORPHANS:-NaN}" "${PE2_ORPHANS:-NaN}" "${PE1_DDISABLED:-NaN}" "${PE2_DDISABLED:-NaN}" "$(< "$CHURN_ADDS_FILE")" "$(< "$CHURN_DELS_FILE")" "$(< "$CHURN_MOVES_FILE")"
        printf '\n'
    } >>"$SAMPLES_CSV"
}

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

require_tool docker
require_tool containerlab
require_tool curl
require_tool awk
require_tool shuf

if ! container_is_running "$PE1_NAME"; then
    log "ERROR: container $PE1_NAME not running. Deploy the topology first:"
    log "  sudo containerlab deploy -t $TOPOLOGY"
    exit 2
fi
if ! container_is_running "$PE2_NAME"; then
    log "ERROR: container $PE2_NAME not running"
    exit 2
fi

# Run metadata.
GIT_REV="$(cd "$REPO_ROOT" && git rev-parse HEAD 2>/dev/null || echo unknown)"
GIT_DIRTY="$(cd "$REPO_ROOT" && [ -n "$(git status --porcelain 2>/dev/null)" ] && echo true || echo false)"
IMAGE_ID="$(docker inspect --format='{{.Image}}' "$PE1_NAME" 2>/dev/null || echo unknown)"
KERNEL="$(uname -r)"

cat >"$RUN_JSON" <<EOF
{
  "started_at": "$START_TS",
  "git_rev": "$GIT_REV",
  "git_dirty": $GIT_DIRTY,
  "image_id": "$IMAGE_ID",
  "kernel": "$KERNEL",
  "soak_hours": $SOAK_HOURS,
  "sample_interval_sec": $SAMPLE_INTERVAL,
  "flip_interval_sec": $FLIP_INTERVAL_SEC,
  "warmup_sec": $WARMUP_SEC,
  "churn_interval_sec": $CHURN_INTERVAL_SEC,
  "churn_batch_size": $CHURN_BATCH_SIZE,
  "mac_pool_size": $MAC_POOL_SIZE,
  "mobility_fraction_pct": $MOBILITY_FRACTION,
  "pool_target": $POOL_TARGET,
  "pool_min": $POOL_MIN,
  "pool_max": $POOL_MAX,
  "ce_port": "$CE_PORT",
  "vni": $VNI,
  "topology": "$TOPOLOGY",
  "run_dir": "$RUN_DIR"
}
EOF

# Background daemon log tails. The cleanup trap kills them so they
# don't leak across runs.
docker logs -f "$PE1_NAME" >>"$PE1_LOG" 2>&1 &
PE1_TAIL_PID=$!
docker logs -f "$PE2_NAME" >>"$PE2_LOG" 2>&1 &
PE2_TAIL_PID=$!

CHURN_PID=""

cleanup() {
    set +e
    log "soak loop exiting; cleaning up background tasks"
    if [ -n "$CHURN_PID" ]; then
        kill "$CHURN_PID" 2>/dev/null || true
    fi
    kill "$PE1_TAIL_PID" "$PE2_TAIL_PID" 2>/dev/null || true
    wait "$CHURN_PID" "$PE1_TAIL_PID" "$PE2_TAIL_PID" 2>/dev/null || true
    if [ "$CLEANUP" = "1" ]; then
        log "CLEANUP=1: destroying topology"
        sudo containerlab destroy -t "$TOPOLOGY" --cleanup || true
    fi
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# CSV header
# ---------------------------------------------------------------------------

cat >"$SAMPLES_CSV" <<'EOF'
ts_unix,elapsed_sec,pe1_rss_mb,pe2_rss_mb,pe1_df_role,pe2_df_role,pe1_df_changes,pe2_df_changes,pe1_bum_flags,pe2_bum_flags,pe2_running,pe1_session_established,pe2_session_established,pe1_established_seen,pe2_established_seen,pe1_pool_size,pe2_pool_size,pe1_fdb_total,pe2_fdb_total,pe1_fdb_extern_learn,pe2_fdb_extern_learn,pe1_nh_count,pe2_nh_count,pe1_local_origs,pe2_local_origs,pe1_local_orig_errors,pe2_local_orig_errors,pe1_local_obs_drops,pe2_local_obs_drops,pe1_dup_mac_moves,pe2_dup_mac_moves,pe1_drift_members_repaired,pe2_drift_members_repaired,pe1_drift_groups_replaced,pe2_drift_groups_replaced,pe1_drift_orphans_cleaned,pe2_drift_orphans_cleaned,pe1_drift_disabled,pe2_drift_disabled,churn_adds_total,churn_dels_total,churn_moves_total
EOF

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

START_UNIX="$(date +%s)"
END_UNIX="$(awk -v s="$START_UNIX" -v h="$SOAK_HOURS" 'BEGIN { printf "%d\n", s + h * 3600 }')"
NEXT_FLIP_UNIX="$((START_UNIX + FLIP_INTERVAL_SEC))"
PE2_RUNNING=1

log "Gate 8b MAC-churn soak starting"
log "  duration=${SOAK_HOURS}h  sample=${SAMPLE_INTERVAL}s  flip=${FLIP_INTERVAL_SEC}s"
log "  churn_interval=${CHURN_INTERVAL_SEC}s  batch=${CHURN_BATCH_SIZE}  pool=${MAC_POOL_SIZE} (target=${POOL_TARGET})"
log "  mobility=${MOBILITY_FRACTION}%  ce_port=${CE_PORT}  vni=${VNI}"
log "  run_dir=$RUN_DIR"
log "  git_rev=$GIT_REV dirty=$GIT_DIRTY kernel=$KERNEL"

# Warm-up before sampling AND before churn — let the daemon's initial
# dataplane discovery settle so churn ops aren't racing instance Ready.
log "warmup: waiting ${WARMUP_SEC}s for initial dataplane discovery"
sleep "$WARMUP_SEC"

# Pre-churn topology guard: confirm the clab-managed eth1 + 10.0.0.x
# is present on both PEs. The flip mechanism depends on this
# surviving every cycle; if it isn't there at startup, the rest of
# the soak's interpretation is suspect.
if ! verify_topology_link; then
    log "FATAL: pre-churn topology check failed — clab veth missing"
    exit 5
fi

# Pre-churn gate: refuse to start the validation run unless both
# PEs have actually reached Established. Without this the harness
# can produce a "clean" smoke while the receive path
# (remote Type 2 / extern_learn / FDB-NHG) never runs.
if ! wait_established; then
    log "FATAL: not starting churn — BGP did not establish within ${BGP_ESTABLISHED_TIMEOUT_SEC}s"
    exit 3
fi

# Kick off the churn loop now that the dataplane is warm.
churn_loop "$END_UNIX" &
CHURN_PID=$!
log "churn loop started pid=$CHURN_PID"

while [ "$(date +%s)" -lt "$END_UNIX" ]; do
    NOW="$(date +%s)"
    ELAPSED="$((NOW - START_UNIX))"

    sample_row "$NOW" "$ELAPSED"

    # Flip PE2 if it's time.
    if [ "$NOW" -ge "$NEXT_FLIP_UNIX" ]; then
        # Hard pre-flip guard: the clab-managed eth1 must still be
        # in place. If it isn't, we're already off the rails and a
        # flip would only deepen the confusion in the postmortem.
        if ! verify_topology_link; then
            log "FATAL: topology link lost before flip; aborting soak"
            exit 4
        fi
        if [ "$PE2_RUNNING" = "1" ]; then
            flip_log "stopping PE2 daemon (mode=${KILL_MODE})"
            log "flip: stopping PE2 daemon (mode=${KILL_MODE})"
            if ! stop_pe2_daemon; then
                log "FATAL: PE2 daemon stop failed"
                exit 4
            fi
        else
            flip_log "starting PE2 daemon"
            log "flip: starting PE2 daemon"
            # Wait for re-establishment so the next sample isn't
            # credited as a nominal steady-state row when the
            # session has actually failed to come back. The current
            # gauge must reach 1; a cumulative counter cannot prove
            # that the restarted session is still Established.
            if ! start_pe2_daemon; then
                log "FATAL: PE2 daemon start or session recovery failed"
                exit 4
            fi
            # Kernel netns survives a process restart, so the
            # bridge / VXLAN / CE veth / FDB rows are still in
            # place — the churn pool tracking remains accurate.
            # (The old `: >$PE2_POOL` reset was only needed when
            # the container itself was destroyed by `docker stop`.)
        fi
        # Post-flip guard: assert the clab veth + 10.0.0.x is
        # still intact. With process-restart this is defense in
        # depth — the netns is untouched, so the topology must
        # survive — but it's the cheap insurance that turns a
        # future regression (anyone accidentally putting docker
        # stop/start back into the flip path) into an immediate
        # loud failure instead of another false daemon bug.
        if ! verify_topology_link; then
            log "FATAL: topology link lost after flip; aborting soak"
            exit 4
        fi
        NEXT_FLIP_UNIX="$((NOW + FLIP_INTERVAL_SEC))"
    fi

    sleep "$SAMPLE_INTERVAL"
done

if ! gate8b_terminal_recovery "$PE2_RUNNING" recover_terminal_pe2 sample_row; then
    log "FATAL: terminal PE2 recovery failed; final evidence row retained"
    exit 4
fi

log "soak loop completed; final samples in $SAMPLES_CSV"
log "totals: adds=$(< "$CHURN_ADDS_FILE") dels=$(< "$CHURN_DELS_FILE") moves=$(< "$CHURN_MOVES_FILE")"
