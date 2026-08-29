#!/usr/bin/env bash
# Soak: route-server flagship — 1000 real eBGP RS clients x 400 routes each
# against a bare-host rustbgpd, driven by the bench/scale/reloadstall engine.
#
# Injections (both serialized by the engine, churn running throughout):
#   - a real SIGHUP policy-file reload every RELOAD_INTERVAL_SEC, each one
#     verified by the engine's generation-marker completion barriers;
#   - a max-prefix trip/timed-restart cycle every TRIP_INTERVAL_SEC on the
#     designated member (stub 0, 127.1.0.1): announce over the configured
#     max_prefixes bound -> Cease teardown -> hold-down countdown -> the
#     daemon's one timed restart -> re-establish -> compliant re-announce,
#     with the runner asserting the daemon-side evidence chain per cycle
#     (exceeded counter, countdown via rbgp neighbor -j, re-establish bound,
#     headroom sanity).
#
# Precommitted gates: docs/soaks/soak-acceptance-gates.md (scenario 10).
# Analyzer: tests/soak/analyze-soak-rs-flagship.py.
#
# Usage:
#   bash tests/soak/run-soak-rs-flagship.sh                  # 24 h flagship
#   SOAK_PEERS=12 SOAK_ROUTES_PER_PEER=50 SOAK_SECONDS=300 \
#   RELOAD_INTERVAL_SEC=60 TRIP_INTERVAL_SEC=120 \
#   TRIP_RESTART_SECONDS=20 WARMUP_SEC=30 SAMPLE_INTERVAL=10 \
#   bash tests/soak/run-soak-rs-flagship.sh                  # smoke
#
# Output: tests/soak/runs/soak-rs-flagship-<UTC>/
#   - samples.csv      one row per SAMPLE_INTERVAL
#   - soak.log         runner stdout/stderr
#   - cycles.log       reload + trip event/evidence lines
#   - rustbgpd.log     daemon JSON logs
#   - reloadstall.log  engine stdout/stderr (markers, csv records)
#   - management-plane-load.jsonl  bounded HTTP/CLI load evidence
#   - management-plane-load.log    load-driver stdout/stderr
#   - run.json         run metadata (analyzer input)
#   - verdict.json     analyzer verdict

set -euo pipefail

SOAK_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SOAK_SCRIPT_DIR/../.." && pwd)"

# --- Shape (flagship defaults; env-overridable for smokes) ---
SOAK_PEERS="${SOAK_PEERS:-1000}"
SOAK_ROUTES_PER_PEER="${SOAK_ROUTES_PER_PEER:-400}"
SOAK_SECONDS="${SOAK_SECONDS:-86400}"
RELOAD_INTERVAL_SEC="${RELOAD_INTERVAL_SEC:-1800}"
TRIP_INTERVAL_SEC="${TRIP_INTERVAL_SEC:-14400}"
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-30}"
WARMUP_SEC="${WARMUP_SEC:-300}"
CONTROL_SECS="${CONTROL_SECS:-30}"
TRIP_LIMIT_MARGIN="${TRIP_LIMIT_MARGIN:-50}"
TRIP_PREFIXES="${TRIP_PREFIXES:-64}"
TRIP_RESTART_SECONDS="${TRIP_RESTART_SECONDS:-120}"
TRIP_REESTABLISH_SEC="${TRIP_REESTABLISH_SEC:-300}"
# Engine-side session hold after a final-cycle trip; the runner's final
# evidence drain window is half of it, so the sessions always outlive it.
TRIP_FINAL_QUIESCE_SEC="${TRIP_FINAL_QUIESCE_SEC:-120}"
CONVERGE_CAP_SEC="${CONVERGE_CAP_SEC:-900}"
LISTEN_PORT="${LISTEN_PORT:-1790}"
# gen-scenario.py pins prometheus_addr to 127.0.0.1:9179.
readonly METRICS_PORT=9179
DESIGNATED_ADDR="127.1.0.1" # stub_addr(0) — the engine's designated member
MANAGEMENT_METRICS_INTERVAL_SEC="${MANAGEMENT_METRICS_INTERVAL_SEC:-1}"
MANAGEMENT_CLI_INTERVAL_SEC="${MANAGEMENT_CLI_INTERVAL_SEC:-5}"
MANAGEMENT_TIMEOUT_SEC="${MANAGEMENT_TIMEOUT_SEC:-5}"

# Match reloadstall's base_prefix(idx) exactly for stub 1's first route:
# own_slice(1) starts at global index SOAK_ROUTES_PER_PEER. Stub 1 is stable
# while the designated stub 0 is deliberately withdrawn during trip cycles.
management_route_prefix() {
    local routes_per_peer=$1
    if [[ ! $routes_per_peer =~ ^[1-9][0-9]*$ ]]; then
        echo "SOAK_ROUTES_PER_PEER must be a positive decimal integer" >&2
        return 2
    fi
    # 20 + (idx >> 16) must remain an IPv4 octet. Compare as decimal text
    # before shell arithmetic so an oversized environment value cannot wrap.
    if ((${#routes_per_peer} > 8)) || \
        ((${#routes_per_peer} == 8 && 10#$routes_per_peer > 15466495)); then
        echo "SOAK_ROUTES_PER_PEER exhausts the reloadstall IPv4 base-prefix space" >&2
        return 2
    fi
    local index=$((10#$routes_per_peer))
    printf '%d.%d.%d.0/24\n' \
        "$((20 + (index >> 16)))" \
        "$(((index >> 8) & 255))" \
        "$((index & 255))"
}

if ! MANAGEMENT_ROUTE_PREFIX=$(management_route_prefix "$SOAK_ROUTES_PER_PEER"); then
    exit 2
fi
readonly MANAGEMENT_ROUTE_PREFIX

# --- Derived ---
TOTAL_PREFIXES=$((SOAK_PEERS * SOAK_ROUTES_PER_PEER))
RELOADS=$((SOAK_SECONDS / RELOAD_INTERVAL_SEC))
if ((TRIP_INTERVAL_SEC % RELOAD_INTERVAL_SEC != 0)); then
    echo "TRIP_INTERVAL_SEC must be a multiple of RELOAD_INTERVAL_SEC" >&2
    exit 2
fi
TRIP_EVERY=$((TRIP_INTERVAL_SEC / RELOAD_INTERVAL_SEC))
PLANNED_TRIPS=$((RELOADS / TRIP_EVERY))
MAX_PREFIXES=$((SOAK_ROUTES_PER_PEER + TRIP_LIMIT_MARGIN))
if ((TRIP_PREFIXES <= TRIP_LIMIT_MARGIN)); then
    echo "TRIP_PREFIXES ($TRIP_PREFIXES) must exceed TRIP_LIMIT_MARGIN ($TRIP_LIMIT_MARGIN) to breach" >&2
    exit 2
fi
if ((RELOADS < 1 || PLANNED_TRIPS < 1)); then
    echo "shape yields no reloads or no trips (reloads=$RELOADS trips=$PLANNED_TRIPS)" >&2
    exit 2
fi
if ((SOAK_PEERS <= 8)); then
    echo "SOAK_PEERS must exceed 8 (the engine's churner count; stub 0 must not churn)" >&2
    exit 2
fi
if ((TRIP_RESTART_SECONDS < 10)); then
    echo "TRIP_RESTART_SECONDS must be >= 10 so the 1 s countdown poll can observe it" >&2
    exit 2
fi
if ((TRIP_FINAL_QUIESCE_SEC < 30)); then
    echo "TRIP_FINAL_QUIESCE_SEC must be >= 30 (the final-trip evidence drain runs inside it)" >&2
    exit 2
fi
OVERALL_CAP_SEC="${OVERALL_CAP_SEC:-$((SOAK_SECONDS + RELOADS * 300 + PLANNED_TRIPS * (TRIP_RESTART_SECONDS + TRIP_REESTABLISH_SEC + 300) + 3600))}"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${RUN_DIR_OVERRIDE:-$SOAK_SCRIPT_DIR/runs/soak-rs-flagship-$RUN_ID}"
SAMPLES_CSV="$RUN_DIR/samples.csv"
SOAK_LOG="$RUN_DIR/soak.log"
CYCLES_LOG="$RUN_DIR/cycles.log"
RUN_JSON="$RUN_DIR/run.json"
RUSTBGPD_LOG="$RUN_DIR/rustbgpd.log"
RELOADSTALL_LOG="$RUN_DIR/reloadstall.log"
MANAGEMENT_LOAD_JSONL="$RUN_DIR/management-plane-load.jsonl"
MANAGEMENT_LOAD_LOG="$RUN_DIR/management-plane-load.log"
PROM_TMP="$RUN_DIR/.metrics.prom"

# shellcheck source=tests/soak/host-lock.sh
source "$SOAK_SCRIPT_DIR/host-lock.sh"

log() {
    printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

cycle_log() {
    printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"$CYCLES_LOG"
}

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        log "ERROR: required tool '$1' not in PATH"
        exit 2
    fi
}

pid_running() {
    [[ -n ${1:-} ]] && kill -0 "$1" 2>/dev/null
}

terminate() {
    local pid=${1:-}
    [[ -n $pid ]] || return 0
    if pid_running "$pid"; then
        kill -TERM "$pid" 2>/dev/null || true
        for _ in $(seq 1 50); do pid_running "$pid" || break; sleep 0.1; done
        if pid_running "$pid"; then kill -KILL "$pid" 2>/dev/null || true; fi
    fi
    wait "$pid" 2>/dev/null || true
}

H_PID=""
MANAGEMENT_LOAD_PID=""
DAEMON_PID=""
SCEN=""
MEASURED_START_MONOTONIC=""
MEASURED_END_MONOTONIC=""

monotonic_now() {
    python3 -c 'import time; print(f"{time.monotonic():.9f}")'
}

validate_management_timing() {
    python3 - "$MANAGEMENT_METRICS_INTERVAL_SEC" \
        "$MANAGEMENT_CLI_INTERVAL_SEC" "$MANAGEMENT_TIMEOUT_SEC" <<'PY'
import math
import sys

try:
    values = [float(value) for value in sys.argv[1:]]
except ValueError:
    raise SystemExit(1)
raise SystemExit(0 if all(math.isfinite(value) and value > 0 for value in values) else 1)
PY
}

stop_management_load() {
    local pid=${MANAGEMENT_LOAD_PID:-} rc=0 wait_tenths i
    [[ -n $pid ]] || return 0
    wait_tenths=$(python3 -c \
        'import math,sys; print(math.ceil((float(sys.argv[1]) + 2) * 10))' \
        "$MANAGEMENT_TIMEOUT_SEC")
    if pid_running "$pid"; then
        kill -TERM "$pid" 2>/dev/null || true
        for ((i = 0; i < wait_tenths; i++)); do
            pid_running "$pid" || break
            sleep 0.1
        done
        if pid_running "$pid"; then
            kill -KILL "$pid" 2>/dev/null || true
            rc=1
        fi
    fi
    wait "$pid" 2>/dev/null || rc=$?
    MANAGEMENT_LOAD_PID=""
    return "$rc"
}

cleanup() {
    local rc=$?
    trap - EXIT
    set +e
    stop_management_load
    terminate "$H_PID"
    H_PID=""
    terminate "$DAEMON_PID"
    DAEMON_PID=""
    [[ -n $SCEN && -d $SCEN ]] && rm -rf "$SCEN"
    rm -f "$PROM_TMP"
    if ((rc != 0)); then
        log "FAILED rc=$rc — artifacts preserved in $RUN_DIR"
    fi
    exit "$rc"
}

abort() {
    cycle_log "ABORT: $*"
    log "ABORT: $*"
    exit 1
}

ports_free() {
    local listeners
    listeners=$(ss -H -ltn) || return 1
    ! awk -v a=":${LISTEN_PORT}" -v b=":${METRICS_PORT}" '
        {if (substr($4,length($4)-length(a)+1)==a || substr($4,length($4)-length(b)+1)==b) used=1}
        END{exit !used}' <<<"$listeners"
}

# --- Metric extraction (names verified against crates/telemetry/src/metrics.rs) ---
prom_scrape() {
    curl -fsS --max-time 5 "http://127.0.0.1:${METRICS_PORT}/metrics" >"$PROM_TMP"
}

# Sum every series of one metric family (0 when no series exists yet).
prom_sum() {
    awk -v n="$1" '$0 ~ "^"n"[{ ]" { s += $NF } END { printf "%.0f", s }' <"$PROM_TMP"
}

# Exact unlabeled gauge value (nan when absent).
prom_get() {
    awk -v n="$1" '$0 ~ "^"n"[{ ]" { print $NF; found=1; exit }
        END { if (!found) print "nan" }' <"$PROM_TMP"
}

# One peer+scope-labeled gauge value (nan when absent).
prom_peer_scope() {
    awk -v m="$1" -v p="peer=\"$2\"" -v s="scope=\"$3\"" '
        $0 ~ "^"m"\\{" && index($0, p) && index($0, s) { print $NF; found=1; exit }
        END { if (!found) print "nan" }' <"$PROM_TMP"
}

tree_rss_mb() {
    ps -eo pid=,ppid=,rss= --no-headers | awk -v root="$DAEMON_PID" '
        {parent[$1]=$2; rss[$1]=$3} END {for (pid in parent) {p=pid
        while (p in parent && p != root && parent[p] != p) p=parent[p]
        if (p == root) total+=rss[pid]} printf "%.1f", total/1024}'
}

# Designated-member max-prefix state from the CLI: "<action> <remaining|null>".
designated_max_prefix_state() {
    timeout -k 1 5 "$RBGP" -s "unix://$SCEN/grpc.sock" -j neighbor "$DESIGNATED_ADDR" 2>/dev/null |
        python3 -c 'import json,sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
if isinstance(d, list):
    if not d:
        sys.exit(0)
    d = d[0]
r = d.get("max_prefix_restart_remaining_millis")
print(d.get("max_prefix_action", ""), r if r is not None else "null")' || true
}

# --- Trip evidence state machine (driven off engine log markers) ---
TRIP_N=""
TRIP_EXCEEDED_SEEN=0
TRIP_COUNTDOWN_SEEN=0
TRIP_TORN_SEEN=0
TRIP_REEST_SEEN=0
TRIP_HEADROOM_PENDING=0
TRIP_DEADLINE_EPOCH=0

trip_begin() {
    TRIP_N=$1
    TRIP_EXCEEDED_SEEN=0
    TRIP_COUNTDOWN_SEEN=0
    TRIP_TORN_SEEN=0
    TRIP_REEST_SEEN=0
    TRIP_HEADROOM_PENDING=0
    TRIP_DEADLINE_EPOCH=$(($(date +%s) + 60 + TRIP_RESTART_SECONDS + TRIP_REESTABLISH_SEC + 120))
    cycle_log "trip $TRIP_N announce_over"
}

trip_evidence_tick() {
    [[ -n $TRIP_N ]] || return 0
    if (($(date +%s) > TRIP_DEADLINE_EPOCH)); then
        abort "trip $TRIP_N evidence deadline exceeded (exceeded=$TRIP_EXCEEDED_SEEN countdown=$TRIP_COUNTDOWN_SEEN torn=$TRIP_TORN_SEEN reest=$TRIP_REEST_SEEN headroom_pending=$TRIP_HEADROOM_PENDING)"
    fi
    if ((TRIP_EXCEEDED_SEEN == 0)); then
        if prom_scrape; then
            local exceeded
            exceeded=$(prom_sum bgp_max_prefix_exceeded_total)
            if ((exceeded >= TRIP_N)); then
                TRIP_EXCEEDED_SEEN=1
                cycle_log "trip $TRIP_N exceeded_total=$exceeded"
            fi
        fi
    fi
    if ((TRIP_COUNTDOWN_SEEN == 0 && TRIP_REEST_SEEN == 0)); then
        local state action remaining
        state=$(designated_max_prefix_state)
        if [[ -n $state ]]; then
            read -r action remaining <<<"$state"
            if [[ $remaining != null && -n $remaining ]]; then
                TRIP_COUNTDOWN_SEEN=1
                cycle_log "trip $TRIP_N countdown_ms=$remaining action=$action"
            fi
        fi
    fi
    if ((TRIP_HEADROOM_PENDING == 1)); then
        if prom_scrape; then
            local usage limit headroom
            usage=$(prom_peer_scope bgp_max_prefix_usage "$DESIGNATED_ADDR" aggregate)
            limit=$(prom_peer_scope bgp_max_prefix_limit "$DESIGNATED_ADDR" aggregate)
            headroom=$(prom_peer_scope bgp_max_prefix_headroom "$DESIGNATED_ADDR" aggregate)
            if [[ $usage == "$SOAK_ROUTES_PER_PEER" && $limit == "$MAX_PREFIXES" ]]; then
                cycle_log "trip $TRIP_N complete usage=$usage limit=$limit headroom=$headroom"
                TRIP_N=""
                TRIP_HEADROOM_PENDING=0
            fi
        fi
    fi
}

handle_line() {
    local line=$1
    if [[ $line =~ ^reload\ ([0-9]+)\ SIGHUP\  ]]; then
        cycle_log "reload ${BASH_REMATCH[1]} issued"
    elif [[ $line =~ ^reloadstall_csv,([0-9]+), ]]; then
        cycle_log "reload ${BASH_REMATCH[1]} complete"
    elif [[ $line =~ ^trip\ ([0-9]+)\ announce_over\  ]]; then
        trip_begin "${BASH_REMATCH[1]}"
    elif [[ $line =~ ^trip\ ([0-9]+)\ torn_down\  ]]; then
        TRIP_TORN_SEEN=1
        cycle_log "trip ${BASH_REMATCH[1]} torn_down"
    elif [[ $line =~ ^trip\ ([0-9]+)\ reestablished\  ]]; then
        TRIP_REEST_SEEN=1
        cycle_log "trip ${BASH_REMATCH[1]} reestablished"
        if ((TRIP_COUNTDOWN_SEEN == 0)); then
            abort "trip ${BASH_REMATCH[1]} re-established before a hold-down countdown was observed"
        fi
    elif [[ $line =~ ^trip\ ([0-9]+)\ reannounced ]]; then
        cycle_log "trip ${BASH_REMATCH[1]} reannounced"
    elif [[ $line =~ ^trip\ ([0-9]+)\ complete\  ]]; then
        if ((TRIP_TORN_SEEN == 0 || TRIP_REEST_SEEN == 0 || TRIP_COUNTDOWN_SEEN == 0 || TRIP_EXCEEDED_SEEN == 0)); then
            abort "trip ${BASH_REMATCH[1]} completed with missing evidence (exceeded=$TRIP_EXCEEDED_SEEN countdown=$TRIP_COUNTDOWN_SEEN torn=$TRIP_TORN_SEEN reest=$TRIP_REEST_SEEN)"
        fi
        TRIP_HEADROOM_PENDING=1
    fi
}

SEEN_LINES=0
process_log() {
    local total
    total=$(wc -l <"$RELOADSTALL_LOG")
    ((total > SEEN_LINES)) || return 0
    local line
    while IFS= read -r line; do
        handle_line "$line"
    done < <(sed -n "$((SEEN_LINES + 1)),${total}p" "$RELOADSTALL_LOG")
    SEEN_LINES=$total
}

SCRAPE_FAILS=0
sample_row() {
    local elapsed=$1
    # Sessions are held open by the engine; once it exits (or if it exits
    # mid-scrape) a sample would record the harness's own teardown as
    # daemon un-health. Record a row only when the engine was alive on
    # both sides of the scrape.
    pid_running "$H_PID" || return 0
    local readyz code seconds ms
    readyz=$(curl -sS -o /dev/null --max-time 5 -w '%{http_code} %{time_total}' \
        "http://127.0.0.1:${METRICS_PORT}/readyz" 2>/dev/null) || readyz="000 0"
    read -r code seconds <<<"$readyz"
    ms=$(awk -v t="$seconds" 'BEGIN { printf "%.1f", t * 1000 }')
    if ! prom_scrape; then
        SCRAPE_FAILS=$((SCRAPE_FAILS + 1))
        cycle_log "sample scrape failed (consecutive=$SCRAPE_FAILS)"
        if ((SCRAPE_FAILS >= 5)); then
            abort "metrics endpoint unreachable for $SCRAPE_FAILS consecutive samples"
        fi
        return 0
    fi
    SCRAPE_FAILS=0
    pid_running "$H_PID" || return 0
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        "$elapsed" \
        "$(tree_rss_mb)" \
        "$(prom_get bgp_rib_attr_intern_global_size)" \
        "$(prom_sum bgp_peer_session_established)" \
        "$(prom_sum bgp_session_flaps_total)" \
        "$(prom_sum bgp_messages_sent_total)" \
        "$(prom_sum bgp_max_prefix_exceeded_total)" \
        "$code" \
        "$ms" \
        >>"$SAMPLES_CSV"
    local avail_kib
    avail_kib=$(df -Pk "$RUN_DIR" | awk 'NR==2 {print $4}')
    if ((avail_kib < 5 * 1024 * 1024)); then
        abort "host disk below 5 GiB free (${avail_kib} KiB)"
    fi
}

start_management_load() {
    if [[ -e $MANAGEMENT_LOAD_JSONL || -e $MANAGEMENT_LOAD_LOG ]]; then
        abort "management-plane evidence path already exists"
    fi
    python3 "$SOAK_SCRIPT_DIR/management_plane_load.py" \
        --output "$MANAGEMENT_LOAD_JSONL" \
        --metrics-url "http://127.0.0.1:${METRICS_PORT}/metrics" \
        --rbgp "$RBGP" \
        --socket "unix://$SCEN/grpc.sock" \
        --peers "$SOAK_PEERS" \
        --route-prefix "$MANAGEMENT_ROUTE_PREFIX" \
        --metrics-interval "$MANAGEMENT_METRICS_INTERVAL_SEC" \
        --cli-interval "$MANAGEMENT_CLI_INTERVAL_SEC" \
        --timeout "$MANAGEMENT_TIMEOUT_SEC" \
        >"$MANAGEMENT_LOAD_LOG" 2>&1 &
    MANAGEMENT_LOAD_PID=$!
    for _ in $(seq 1 50); do
        if grep -q '"record":"start"' "$MANAGEMENT_LOAD_JSONL" 2>/dev/null; then
            log "management-plane load started pid=$MANAGEMENT_LOAD_PID"
            return 0
        fi
        pid_running "$MANAGEMENT_LOAD_PID" || break
        sleep 0.1
    done
    local rc=0
    wait "$MANAGEMENT_LOAD_PID" 2>/dev/null || rc=$?
    MANAGEMENT_LOAD_PID=""
    abort "management-plane load failed before its start record (rc=$rc)"
}

write_run_json() {
    local tmp="$RUN_JSON.tmp" measured_start=null measured_end=null
    [[ -n $MEASURED_START_MONOTONIC ]] && measured_start=$MEASURED_START_MONOTONIC
    [[ -n $MEASURED_END_MONOTONIC ]] && measured_end=$MEASURED_END_MONOTONIC
    {
        echo "{"
        printf '  "run_id": "%s",\n' "$RUN_ID"
        printf '  "git_head": "%s",\n' "$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
        printf '  "peers": %d,\n' "$SOAK_PEERS"
        printf '  "routes_per_peer": %d,\n' "$SOAK_ROUTES_PER_PEER"
        printf '  "total_prefixes": %d,\n' "$TOTAL_PREFIXES"
        printf '  "soak_seconds": %d,\n' "$SOAK_SECONDS"
        printf '  "sample_interval_sec": %d,\n' "$SAMPLE_INTERVAL"
        printf '  "warmup_sec": %d,\n' "$WARMUP_SEC"
        printf '  "reload_interval_sec": %d,\n' "$RELOAD_INTERVAL_SEC"
        printf '  "trip_interval_sec": %d,\n' "$TRIP_INTERVAL_SEC"
        printf '  "planned_reloads": %d,\n' "$RELOADS"
        printf '  "planned_trips": %d,\n' "$PLANNED_TRIPS"
        printf '  "trip_every": %d,\n' "$TRIP_EVERY"
        printf '  "max_prefixes": %d,\n' "$MAX_PREFIXES"
        printf '  "trip_limit_margin": %d,\n' "$TRIP_LIMIT_MARGIN"
        printf '  "trip_prefixes": %d,\n' "$TRIP_PREFIXES"
        printf '  "trip_restart_seconds": %d,\n' "$TRIP_RESTART_SECONDS"
        printf '  "trip_reestablish_sec": %d,\n' "$TRIP_REESTABLISH_SEC"
        printf '  "trip_final_quiesce_sec": %d,\n' "$TRIP_FINAL_QUIESCE_SEC"
        printf '  "listen_port": %d,\n' "$LISTEN_PORT"
        printf '  "metrics_port": %d,\n' "$METRICS_PORT"
        printf '  "management_load_file": "management-plane-load.jsonl",\n'
        printf '  "management_metrics_interval_sec": %s,\n' "$MANAGEMENT_METRICS_INTERVAL_SEC"
        printf '  "management_cli_interval_sec": %s,\n' "$MANAGEMENT_CLI_INTERVAL_SEC"
        printf '  "management_timeout_sec": %s,\n' "$MANAGEMENT_TIMEOUT_SEC"
        printf '  "management_route_prefix": "%s",\n' "$MANAGEMENT_ROUTE_PREFIX"
        printf '  "measured_start_monotonic": %s,\n' "$measured_start"
        printf '  "measured_end_monotonic": %s,\n' "$measured_end"
        printf '  "designated_member": "%s"\n' "$DESIGNATED_ADDR"
        echo "}"
    } >"$tmp"
    mv "$tmp" "$RUN_JSON"
}

main() {
    mkdir -p "$RUN_DIR"
    exec > >(tee -a "$SOAK_LOG") 2>&1
    acquire_rustbgpd_host_lock
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    for tool in cargo curl awk python3 ss flock git ps df mktemp timeout; do
        require_tool "$tool"
    done
    if ! validate_management_timing; then
        log "ERROR: management-plane intervals and timeout must be finite positive numbers"
        exit 2
    fi

    if ! ports_free; then
        log "ERROR: port $LISTEN_PORT or $METRICS_PORT is already in use — refusing to start (not killing unknown processes)"
        exit 75
    fi

    log "route-server flagship soak starting"
    log "  shape:            ${SOAK_PEERS} peers x ${SOAK_ROUTES_PER_PEER} routes (${TOTAL_PREFIXES} total)"
    log "  window:           ${SOAK_SECONDS}s nominal (${RELOADS} reloads @ ${RELOAD_INTERVAL_SEC}s, ${PLANNED_TRIPS} trips @ ${TRIP_INTERVAL_SEC}s)"
    log "  trip member:      $DESIGNATED_ADDR max_prefixes=$MAX_PREFIXES restart=${TRIP_RESTART_SECONDS}s"
    log "  output:           $RUN_DIR"

    log "building daemon + rbgp + reloadstall (--release --locked)"
    (cd "$REPO_ROOT" && cargo build --release --locked -p rustbgpd -p rustbgpctl) \
        >"$RUN_DIR/build-root.log" 2>&1
    (cd "$REPO_ROOT" && cargo build --release --locked \
        --manifest-path bench/scale/reloadstall/Cargo.toml) \
        >"$RUN_DIR/build-reloadstall.log" 2>&1
    DAEMON="$REPO_ROOT/target/release/rustbgpd"
    RBGP="$REPO_ROOT/target/release/rbgp"
    HARNESS="$REPO_ROOT/bench/scale/target/release/reloadstall"
    sha256sum "$DAEMON" "$RBGP" "$HARNESS" >"$RUN_DIR/binaries.sha256"

    # Fresh scenario per run, never reused; /tmp keeps the gRPC UDS under
    # the SUN_LEN path cap (see gen-scenario.py).
    SCEN="$(mktemp -d /tmp/rsfs.XXXXXX)"
    GEN_TRIP_MAX_PREFIXES=$MAX_PREFIXES GEN_TRIP_RESTART_SECONDS=$TRIP_RESTART_SECONDS \
        python3 "$REPO_ROOT/bench/scale/reloadstall/gen-scenario.py" \
        "$SOAK_PEERS" "$SCEN" "$LISTEN_PORT" "$SOAK_PEERS" >"$RUN_DIR/generator.log"
    mkdir -p "$RUN_DIR/scenario"
    cp "$SCEN/config.toml" "$SCEN"/*.rpol "$RUN_DIR/scenario/"
    "$DAEMON" --check "$SCEN/config.toml" >"$RUN_DIR/daemon-check.log" 2>&1

    write_run_json

    "$DAEMON" "$SCEN/config.toml" >"$RUSTBGPD_LOG" 2>&1 &
    DAEMON_PID=$!
    log "daemon started pid=$DAEMON_PID"
    local ready=0
    for _ in $(seq 1 1200); do
        if curl -fsS --max-time 0.25 "http://127.0.0.1:${METRICS_PORT}/readyz" >/dev/null 2>&1; then
            ready=1
            break
        fi
        pid_running "$DAEMON_PID" || abort "daemon exited during startup"
        sleep 0.1
    done
    ((ready == 1)) || abort "daemon did not become ready within 120s"
    log "daemon ready"

    RELOADSTALL_CYCLE_QUIESCE_SECS=$RELOAD_INTERVAL_SEC \
        RELOADSTALL_TRIP_EVERY=$TRIP_EVERY \
        RELOADSTALL_TRIP_PREFIXES=$TRIP_PREFIXES \
        RELOADSTALL_TRIP_REESTABLISH_SECS=$TRIP_REESTABLISH_SEC \
        RELOADSTALL_FINAL_QUIESCE_SECS=$TRIP_FINAL_QUIESCE_SEC \
        "$HARNESS" "$SOAK_PEERS" "$TOTAL_PREFIXES" "$LISTEN_PORT" "$DAEMON_PID" \
        "$SCEN/member.rpol" "$SCEN/gen-a.rpol" "$SCEN/gen-b.rpol" \
        "$RELOADS" "$CONTROL_SECS" "$SOAK_PEERS" >"$RELOADSTALL_LOG" 2>&1 &
    H_PID=$!
    log "engine started pid=$H_PID"

    local converge_deadline=$(($(date +%s) + CONVERGE_CAP_SEC))
    until grep -q '^converged (' "$RELOADSTALL_LOG" 2>/dev/null; do
        pid_running "$H_PID" || abort "engine exited before convergence"
        (($(date +%s) < converge_deadline)) || abort "convergence exceeded ${CONVERGE_CAP_SEC}s"
        sleep 1
    done
    log "engine converged; starting management-plane load"
    start_management_load
    MEASURED_START_MONOTONIC=$(monotonic_now)
    write_run_json
    log "sampling starts (interval=${SAMPLE_INTERVAL}s warmup=${WARMUP_SEC}s)"

    echo "timestamp,elapsed_sec,rss_mb,intern_size,established,flaps_total,msgs_sent_total,max_prefix_exceeded_total,readyz_code,readyz_ms" >"$SAMPLES_CSV"
    local start_epoch now next_sample overall_deadline
    start_epoch=$(date +%s)
    next_sample=$start_epoch
    overall_deadline=$((start_epoch + OVERALL_CAP_SEC))

    while :; do
        now=$(date +%s)
        if ! pid_running "$H_PID"; then
            MEASURED_END_MONOTONIC=$(monotonic_now)
            process_log
            break
        fi
        pid_running "$MANAGEMENT_LOAD_PID" || abort "management-plane load exited before engine"
        pid_running "$DAEMON_PID" || abort "daemon died mid-soak"
        process_log
        trip_evidence_tick
        if ((now >= next_sample)); then
            sample_row $((now - start_epoch))
            next_sample=$((now + SAMPLE_INTERVAL))
        fi
        ((now < overall_deadline)) || abort "overall watchdog cap ${OVERALL_CAP_SEC}s exceeded"
        sleep 1
    done

    local hrc=0
    wait "$H_PID" || hrc=$?
    H_PID=""
    ((hrc == 0)) || abort "engine exited non-zero: $hrc"
    if ! stop_management_load; then
        abort "management-plane load did not terminate cleanly"
    fi
    write_run_json
    if [[ -n $TRIP_N ]]; then
        # Drain the last trip's headroom evidence (bounded). When the last
        # trip rides the last reload, the engine holds every session up for
        # TRIP_FINAL_QUIESCE_SEC after `trip N complete`, so the live loop
        # above normally settles this before the engine exits; this drain
        # (half the hold) is the fail-closed backstop.
        local drain_deadline=$(($(date +%s) + TRIP_FINAL_QUIESCE_SEC / 2))
        while [[ -n $TRIP_N ]]; do
            (($(date +%s) < drain_deadline)) || abort "trip $TRIP_N headroom evidence never settled"
            trip_evidence_tick
            sleep 1
        done
    fi
    log "engine and management-plane load completed cleanly; running analyzer"

    terminate "$DAEMON_PID"
    DAEMON_PID=""

    python3 "$SOAK_SCRIPT_DIR/analyze-soak-rs-flagship.py" "$RUN_DIR" \
        --output "$RUN_DIR/verdict.json"
    log "soak complete: verdict in $RUN_DIR/verdict.json"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
