#!/usr/bin/env bash
# IRR-scale reload-receipt matrix: sequential policy-reload cells across
# daemons and, for rustbgpd, across both reload paths. See README.md for the
# precommitted measurement definitions, fairness protocol, and abort
# criteria.
#
# Cells:
#   rustbgpd-sighup  bare release binary; rs-config-render-derived .rpol
#                    member policy; SIGHUP parse-then-swap reloads
#   rustbgpd-txn     bare release binary; same dataset as inline
#                    [policy.definitions] chains; gRPC `rbgp config
#                    plan`+`apply` transactional reloads (txn-apply.sh)
#   bird             BIRD 3.3.x in docker --network=host; `birdc configure`
#   openbgpd         OpenBGPD 9.x in docker --network=host; `bgpctl reload`
#
# Usage: run-irr-reload.sh [cell ...]
#        (default: rustbgpd-sighup rustbgpd-txn bird openbgpd)
#
# Modes:
#   SMOKE=1   pipeline proof at a tiny shape (10 members x 100-entry lists,
#             1 reload/cell, no host-quiet gates). NOT a measurement.
#   default   the measured shape. Requires a quiet host: runs
#             tests/soak/preflight.sh first (SKIP_PREFLIGHT=1 to override),
#             1-min loadavg gate before each cell, 300 s cool-downs.
#
# Knobs (env): N_MEMBERS TOTAL_PREFIXES MIN_LIST MAX_LIST SEED
#              CHANGED_FRACTION PORT RELOADS CONTROL_SECS BIRD_THREADS
#              CELL_TIMEOUT START_TIMEOUT ARTIFACTS_DIR SKIP_PREFLIGHT
set -u

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
RSTALL="$REPO/bench/scale/reloadstall"
HARNESS="$RSTALL/target/release/reloadstall"
GEN="$RSTALL/gen-irr-scenario.py"
SAMPLER="$REPO/bench/scale/matrix/rss-sampler.sh"
TXN_APPLY="$REPO/bench/scale/irrreload/txn-apply.sh"
RBGP="$REPO/target/release/rbgp"
RENDER="$REPO/target/release/rs-config-render"
DAEMON="$REPO/target/release/rustbgpd"

SMOKE="${SMOKE:-}"
if [ -n "$SMOKE" ]; then
    N_MEMBERS="${N_MEMBERS:-10}"
    TOTAL_PREFIXES="${TOTAL_PREFIXES:-100}"
    MIN_LIST="${MIN_LIST:-100}"
    MAX_LIST="${MAX_LIST:-100}"
    RELOADS="${RELOADS:-1}"
    CONTROL_SECS="${CONTROL_SECS:-5}"
    CELL_TIMEOUT="${CELL_TIMEOUT:-900}"
    COOL_DOWN=5
else
    # The measured shape: 320 members, 572 announced /24s each (the IXP
    # matrix per-member slice), IRR filter lists log-uniform 1k-40k entries.
    N_MEMBERS="${N_MEMBERS:-320}"
    TOTAL_PREFIXES="${TOTAL_PREFIXES:-183040}"
    MIN_LIST="${MIN_LIST:-1000}"
    MAX_LIST="${MAX_LIST:-40000}"
    RELOADS="${RELOADS:-4}"
    CONTROL_SECS="${CONTROL_SECS:-30}"
    CELL_TIMEOUT="${CELL_TIMEOUT:-7200}"
    COOL_DOWN=300
fi
SEED="${SEED:-61}"
CHANGED_FRACTION="${CHANGED_FRACTION:-0.1}"
PORT="${PORT:-1790}"
# Daemon-start readiness ceiling (seconds). Parsing a multi-MB IRR
# policy takes far longer than a small-config boot, so readiness is
# polled (1 s cadence, until the BGP listener is up) instead of a
# fixed sleep; this is only the hard ceiling. A harness parameter, not
# a measurement — see README "Startup and readiness windows".
START_TIMEOUT="${START_TIMEOUT:-600}"
BIRD_THREADS="${BIRD_THREADS:-8}"
ART="${ARTIFACTS_DIR:-/tmp/irrreload-artifacts}"
RSS_LIMIT_KIB=$((100 * 1024 * 1024)) # abort a cell past 100 GiB (precommitted)

CELLS=("$@")
[ ${#CELLS[@]} -eq 0 ] && CELLS=(rustbgpd-sighup rustbgpd-txn bird openbgpd)

for tool in docker jq python3 cargo ss; do
    command -v "$tool" >/dev/null || {
        echo "missing required tool: $tool" >&2
        exit 1
    }
done

if [ -z "$SMOKE" ] && [ -z "${SKIP_PREFLIGHT:-}" ]; then
    echo "=== host-quiet preflight (tests/soak/preflight.sh) ==="
    "$REPO/tests/soak/preflight.sh" || {
        echo "preflight failed; fix the host or set SKIP_PREFLIGHT=1" >&2
        exit 1
    }
fi

echo "=== builds ==="
(cd "$REPO" && cargo build --release -q -p rustbgpd -p rustbgpctl -p rs-config-render) || exit 1
(cd "$RSTALL" && cargo build --release -q) || exit 1
for bin in "$HARNESS" "$RBGP" "$RENDER" "$DAEMON"; do
    [ -x "$bin" ] || {
        echo "missing binary after build: $bin" >&2
        exit 1
    }
done
mkdir -p "$ART"

cleanup() {
    # shellcheck disable=SC2317  # invoked via trap
    docker rm -f irr-bird irr-obgpd >/dev/null 2>&1
}
trap cleanup EXIT

load_gate() {
    [ -n "$SMOKE" ] && return 0
    local load
    while :; do
        load=$(cut -d' ' -f1 /proc/loadavg)
        if awk -v l="$load" 'BEGIN { exit !(l < 2.0) }'; then return 0; fi
        echo "load_gate: 1-min loadavg $load >= 2.0, waiting 30s"
        sleep 30
    done
}

gen_scenario() {
    local cell=$1 run=$2
    shift 2
    python3 "$GEN" "$cell" "$N_MEMBERS" "$TOTAL_PREFIXES" "$run" \
        --port "$PORT" --seed "$SEED" --min-list "$MIN_LIST" \
        --max-list "$MAX_LIST" --changed-fraction "$CHANGED_FRACTION" "$@"
}

# wait_ready <cell> <cdir>: poll (1 s cadence, ceiling START_TIMEOUT)
# until the cell's daemon listens on $PORT — large-config parses take
# far longer than the fixed 3 s the small-config harness assumed. For
# container cells this also captures daemon_pid via docker inspect,
# retried until nonzero: a single immediate inspect used to race a
# slow-starting container and record pid=0. Fails fast if the daemon
# process/container dies first. Uses/sets the caller's daemon_pid and
# container.
wait_ready() {
    local cell=$1 cdir=$2 waited=0
    while :; do
        if [ -n "$container" ]; then
            if [ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null)" != true ]; then
                echo "cell $cell: container died at start" >&2
                docker logs "$container" >"$cdir/daemon.log" 2>&1
                docker rm -f "$container" >/dev/null 2>&1
                return 1
            fi
            if [ "${daemon_pid:-0}" -le 0 ]; then
                daemon_pid=$(docker inspect -f '{{.State.Pid}}' "$container" 2>/dev/null) || daemon_pid=0
            fi
        elif [ ! -d "/proc/$daemon_pid" ]; then
            echo "cell $cell: daemon died at start (see $cdir/daemon.log)" >&2
            return 1
        fi
        if [ "${daemon_pid:-0}" -gt 0 ] && ss -ltnH "sport = :$PORT" | grep -q .; then
            return 0
        fi
        if [ "$waited" -ge "$START_TIMEOUT" ]; then
            echo "cell $cell: no listener on :$PORT after ${START_TIMEOUT}s" >&2
            return 1
        fi
        sleep 1
        waited=$((waited + 1))
    done
}

# run_cell <cell>: one matrix cell. Nonzero return = cell failed; the
# campaign continues (matrix convention).
run_cell() {
    local cell=$1
    local cdir="$ART/$cell"
    # Short run dir: the gRPC UDS path must fit SUN_LEN.
    local run="/tmp/irr-$cell"
    rm -rf "$run"
    mkdir -p "$cdir" "$run"

    local daemon_pid="" container="" reload_cmd="" pid_arg=""
    local live a b
    case $cell in
    rustbgpd-sighup)
        gen_scenario rustbgpd "$run" --render-bin "$RENDER" || return 1
        "$DAEMON" "$run/config.toml" >"$cdir/daemon.log" 2>&1 &
        daemon_pid=$!
        live="$run/member.rpol" a="$run/gen-a.rpol" b="$run/gen-b.rpol"
        pid_arg=$daemon_pid # SIGHUP path: harness signals + samples this PID
        ;;
    rustbgpd-txn)
        gen_scenario rustbgpd-txn "$run" || return 1
        "$DAEMON" "$run/config.toml" >"$cdir/daemon.log" 2>&1 &
        daemon_pid=$!
        live="$run/candidate.toml" a="$run/gen-a.toml" b="$run/gen-b.toml"
        pid_arg=$daemon_pid # RSS from the real PID; reloads via reload_cmd
        reload_cmd="$TXN_APPLY $RBGP unix://$run/grpc.sock $run/candidate.toml"
        ;;
    bird)
        gen_scenario bird "$run" --threads "$BIRD_THREADS" || return 1
        container="irr-bird"
        docker rm -f "$container" >/dev/null 2>&1
        docker run -d --name "$container" --network=host -v "$run":/etc/bird \
            bird:3.3.1 bird -f -c /etc/bird/bird.conf >/dev/null || return 1
        reload_cmd="docker exec $container birdc configure"
        live="$run/gen.conf" a="$run/gen-a.conf" b="$run/gen-b.conf"
        pid_arg=0 # the outer sampler owns RSS
        ;;
    openbgpd)
        gen_scenario openbgpd "$run" || return 1
        container="irr-obgpd"
        docker rm -f "$container" >/dev/null 2>&1
        docker run -d --name "$container" --network=host -v "$run":/etc/bgpd \
            openbgpd/openbgpd:9.1 >/dev/null || return 1
        reload_cmd="docker exec $container bgpctl reload"
        live="$run/gen.conf" a="$run/gen-a.conf" b="$run/gen-b.conf"
        pid_arg=0
        ;;
    *)
        echo "unknown cell: $cell" >&2
        return 1
        ;;
    esac

    wait_ready "$cell" "$cdir" || return 1

    "$SAMPLER" "$daemon_pid" "$cdir/rss.csv" 5 &
    local sampler_pid=$!

    local hargs=("$N_MEMBERS" "$TOTAL_PREFIXES" "$PORT" "$pid_arg"
        "$live" "$a" "$b" "$RELOADS" "$CONTROL_SECS")
    # reload_cmd is positional arg 11, so cells using it pass an explicit
    # all-changed cohort (same completion semantics as the 9-arg form).
    [ -n "$reload_cmd" ] && hargs+=("$N_MEMBERS" "$reload_cmd")

    # Background so the precommitted RSS abort criterion can kill the cell.
    timeout "$CELL_TIMEOUT" "$HARNESS" "${hargs[@]}" >"$cdir/reloadstall.log" 2>&1 &
    local hpid=$!
    local rc=""
    while kill -0 "$hpid" 2>/dev/null; do
        local last_kib
        last_kib=$(tail -n1 "$cdir/rss.csv" 2>/dev/null | cut -d, -f2)
        case ${last_kib:-} in
        '' | *[!0-9]*) ;;
        *)
            if [ "$last_kib" -gt "$RSS_LIMIT_KIB" ]; then
                echo "cell $cell: daemon RSS ${last_kib} KiB > 100 GiB, aborting cell" >&2
                kill "$hpid" 2>/dev/null
                rc=99
            fi
            ;;
        esac
        sleep 5
    done
    local hrc
    wait "$hpid"
    hrc=$?
    [ -z "$rc" ] && rc=$hrc

    kill "$sampler_pid" 2>/dev/null
    if [ -n "$container" ]; then
        docker logs "$container" >"$cdir/daemon.log" 2>&1
        docker rm -f "$container" >/dev/null 2>&1
    else
        kill "$daemon_pid" 2>/dev/null
    fi
    cp "$run/manifest.json" "$cdir/manifest.json" 2>/dev/null
    if [ "$rc" -eq 0 ]; then
        grep '^reloadstall_csv,' "$cdir/reloadstall.log" |
            sed "s/^reloadstall_csv/$cell/" >>"$ART/rows.csv"
        rm -rf "$run" # scenario reproduces from the generator + manifest
    fi
    echo "cell $cell: harness rc=$rc (artifacts: $cdir)"
    return "$rc"
}

grep -q '^cell,' "$ART/rows.csv" 2>/dev/null || echo \
    "cell,reload,peers_total,peers_changed,peers_stable,prefixes,completion_p50_s,completion_p95_s,completion_max_s,changed_maxgap_p50_ms,changed_maxgap_p95_ms,changed_maxgap_max_ms,all_observer_maxgap_p50_ms,all_observer_maxgap_p95_ms,all_observer_maxgap_max_ms,changed_first_update_p50_ms,changed_first_update_p95_ms,changed_first_update_max_ms,rss_before_mib,rss_after_mib,stable_marker_peers,sessions_up,parse_errors" \
    >"$ART/rows.csv"

overall=0
for cell in "${CELLS[@]}"; do
    status_file="$ART/$cell/status"
    if [ -f "$status_file" ] && grep -qx pass "$status_file"; then
        echo "cell $cell: already pass, skipping (rm $status_file to rerun)"
        continue
    fi
    load_gate
    echo "=== cell $cell start $(date -Is) ==="
    if run_cell "$cell"; then
        echo pass >"$status_file"
        echo "=== cell $cell PASS $(date -Is) ==="
    else
        echo "fail rc=$? $(date -Is)" >"$status_file"
        echo "=== cell $cell FAIL ==="
        overall=1
    fi
    echo "cool-down ${COOL_DOWN}s"
    sleep "$COOL_DOWN"
done

# Completion gate: every requested cell passed and produced its rows.
for cell in "${CELLS[@]}"; do
    grep -qx pass "$ART/$cell/status" 2>/dev/null || overall=1
    rows=$(grep -c "^$cell," "$ART/rows.csv" 2>/dev/null)
    if [ "${rows:-0}" -lt "$RELOADS" ]; then
        echo "cell $cell: expected >= $RELOADS measurement rows, found ${rows:-0}" >&2
        overall=1
    fi
done
echo "measurement rows: $ART/rows.csv"
exit "$overall"
