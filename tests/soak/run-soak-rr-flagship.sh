#!/usr/bin/env bash
# Soak: route-reflector flagship — 1000 real iBGP route-reflector-client
# sessions x 100 routes each (100k total) against a bare-host rustbgpd
# route reflector, driven by the bench/scale/reloadstall engine's
# iBGP-RR mode with its steady churn running throughout.
#
# No injections: this receipt's job is the flagship-RR shape + churn +
# stability (SIGHUP reloads and max-prefix trips are receipt 1 —
# run-soak-rs-flagship.sh). The window is paced by the engine's
# RELOADSTALL_IBGP_RR_HOLD_SECS knob; at the end of the hold the engine
# runs the terminal reflected-delivery verification: every observer
# re-requests the daemon's Adj-RIB-Out with a Normal ROUTE_REFRESH and
# must complete its full-table-minus-own-slice bitmap exactly
# (99,900 non-self prefixes per observer at the flagship shape).
#
# Precommitted gates: docs/soaks/soak-acceptance-gates.md (scenario 11).
# Analyzer: tests/soak/analyze-soak-rr-flagship.py.
#
# Usage:
#   bash tests/soak/run-soak-rr-flagship.sh                  # 24 h flagship
#   SOAK_PEERS=12 SOAK_ROUTES_PER_PEER=20 SOAK_SECONDS=300 \
#   WARMUP_SEC=30 SAMPLE_INTERVAL=10 \
#   bash tests/soak/run-soak-rr-flagship.sh                  # smoke
#
# Output: tests/soak/runs/soak-rr-flagship-<UTC>/
#   - samples.csv      one row per SAMPLE_INTERVAL
#   - soak.log         runner stdout/stderr
#   - cycles.log       hold/terminal event lines + abort records
#   - rustbgpd.log     daemon JSON logs
#   - reloadstall.log  engine stdout/stderr (rr_hold lines, receipt)
#   - run.json         run metadata (analyzer input)
#   - verdict.json     analyzer verdict

set -euo pipefail

SOAK_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SOAK_SCRIPT_DIR/../.." && pwd)"

# --- Shape (flagship defaults; env-overridable for smokes) ---
SOAK_PEERS="${SOAK_PEERS:-1000}"
SOAK_ROUTES_PER_PEER="${SOAK_ROUTES_PER_PEER:-100}"
SOAK_SECONDS="${SOAK_SECONDS:-86400}"
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-30}"
WARMUP_SEC="${WARMUP_SEC:-300}"
CONTROL_SECS="${CONTROL_SECS:-30}"
CONVERGE_CAP_SEC="${CONVERGE_CAP_SEC:-900}"
TERMINAL_CAP_SEC="${TERMINAL_CAP_SEC:-1800}"
LISTEN_PORT="${LISTEN_PORT:-1790}"
IBGP_ASN="${IBGP_ASN:-64512}" # shared local AS; must be u16-representable
# gen-scenario.py pins prometheus_addr to 127.0.0.1:9179.
readonly METRICS_PORT=9179

# --- Derived ---
TOTAL_PREFIXES=$((SOAK_PEERS * SOAK_ROUTES_PER_PEER))
EXPECTED_NONSELF=$((TOTAL_PREFIXES - SOAK_ROUTES_PER_PEER))
# Churn-cycle floor: 8 churners x one flap message per 125 ms = 64
# nominal cycles/s over the hold window; 0.5x tolerates tokio timer
# drift and send backpressure under load (same rationale as the
# inject-churn soak's 0.5x window floor).
CHURN_CYCLE_FLOOR=$((SOAK_SECONDS * 64 / 2))
if ((SOAK_PEERS <= 8)); then
    echo "SOAK_PEERS must exceed 8 (the engine's churner count)" >&2
    exit 2
fi
if ((SOAK_SECONDS < 60)); then
    echo "SOAK_SECONDS must be at least 60 (one rr_hold status interval)" >&2
    exit 2
fi
OVERALL_CAP_SEC="${OVERALL_CAP_SEC:-$((SOAK_SECONDS + TERMINAL_CAP_SEC + 3600))}"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${RUN_DIR_OVERRIDE:-$SOAK_SCRIPT_DIR/runs/soak-rr-flagship-$RUN_ID}"
SAMPLES_CSV="$RUN_DIR/samples.csv"
SOAK_LOG="$RUN_DIR/soak.log"
CYCLES_LOG="$RUN_DIR/cycles.log"
RUN_JSON="$RUN_DIR/run.json"
RUSTBGPD_LOG="$RUN_DIR/rustbgpd.log"
RELOADSTALL_LOG="$RUN_DIR/reloadstall.log"
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
DAEMON_PID=""
SCEN=""
cleanup() {
    local rc=$?
    trap - EXIT
    set +e
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

tree_rss_mb() {
    ps -eo pid=,ppid=,rss= --no-headers | awk -v root="$DAEMON_PID" '
        {parent[$1]=$2; rss[$1]=$3} END {for (pid in parent) {p=pid
        while (p in parent && p != root && parent[p] != p) p=parent[p]
        if (p == root) total+=rss[pid]} printf "%.1f", total/1024}'
}

# Engine event lines -> cycles.log (analyzer input). The rr_hold and
# rr_terminal_receipt lines pass through verbatim; everything else in
# the engine log is diagnostic only.
handle_line() {
    local line=$1
    if [[ $line == rr_hold\ * || $line == rr_terminal_receipt,* ]]; then
        cycle_log "$line"
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
    # Same column set as the RS flagship sampler; this scenario
    # configures no max-prefix bounds, so max_prefix_exceeded_total must
    # stay 0 on every row (the analyzer gates it exactly).
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

write_run_json() {
    {
        echo "{"
        printf '  "run_id": "%s",\n' "$RUN_ID"
        printf '  "git_head": "%s",\n' "$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
        printf '  "peers": %d,\n' "$SOAK_PEERS"
        printf '  "routes_per_peer": %d,\n' "$SOAK_ROUTES_PER_PEER"
        printf '  "total_prefixes": %d,\n' "$TOTAL_PREFIXES"
        printf '  "expected_nonself": %d,\n' "$EXPECTED_NONSELF"
        printf '  "soak_seconds": %d,\n' "$SOAK_SECONDS"
        printf '  "sample_interval_sec": %d,\n' "$SAMPLE_INTERVAL"
        printf '  "warmup_sec": %d,\n' "$WARMUP_SEC"
        printf '  "control_secs": %d,\n' "$CONTROL_SECS"
        printf '  "churn_cycle_floor": %d,\n' "$CHURN_CYCLE_FLOOR"
        printf '  "ibgp_asn": %d,\n' "$IBGP_ASN"
        printf '  "listen_port": %d,\n' "$LISTEN_PORT"
        printf '  "metrics_port": %d\n' "$METRICS_PORT"
        echo "}"
    } >"$RUN_JSON"
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

    if ! ports_free; then
        log "ERROR: port $LISTEN_PORT or $METRICS_PORT is already in use — refusing to start (not killing unknown processes)"
        exit 75
    fi

    log "route-reflector flagship soak starting"
    log "  shape:            ${SOAK_PEERS} iBGP RR clients x ${SOAK_ROUTES_PER_PEER} routes (${TOTAL_PREFIXES} total, ${EXPECTED_NONSELF} non-self/observer)"
    log "  window:           ${SOAK_SECONDS}s hold under churn, then terminal refresh verification"
    log "  churn floor:      ${CHURN_CYCLE_FLOOR} cycles"
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
    SCEN="$(mktemp -d /tmp/rrfs.XXXXXX)"
    GEN_IBGP_RR_ASN=$IBGP_ASN \
        python3 "$REPO_ROOT/bench/scale/reloadstall/gen-scenario.py" \
        "$SOAK_PEERS" "$SCEN" "$LISTEN_PORT" >"$RUN_DIR/generator.log"
    mkdir -p "$RUN_DIR/scenario"
    cp "$SCEN/config.toml" "$RUN_DIR/scenario/"
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

    # Frozen positional contract (reloads=0, no trips); the RR shape and
    # window come from the additive iBGP-RR env knobs. The .rpol paths
    # satisfy arg positions only — the daemon never loads them here.
    RELOADSTALL_IBGP_RR_ASN=$IBGP_ASN \
        RELOADSTALL_IBGP_RR_HOLD_SECS=$SOAK_SECONDS \
        "$HARNESS" "$SOAK_PEERS" "$TOTAL_PREFIXES" "$LISTEN_PORT" "$DAEMON_PID" \
        "$SCEN/member.rpol" "$SCEN/gen-a.rpol" "$SCEN/gen-b.rpol" \
        0 "$CONTROL_SECS" >"$RELOADSTALL_LOG" 2>&1 &
    H_PID=$!
    log "engine started pid=$H_PID"

    local converge_deadline=$(($(date +%s) + CONVERGE_CAP_SEC))
    until grep -q '^converged (' "$RELOADSTALL_LOG" 2>/dev/null; do
        pid_running "$H_PID" || abort "engine exited before convergence"
        (($(date +%s) < converge_deadline)) || abort "convergence exceeded ${CONVERGE_CAP_SEC}s"
        sleep 1
    done
    log "engine converged; sampling starts (interval=${SAMPLE_INTERVAL}s warmup=${WARMUP_SEC}s)"

    echo "timestamp,elapsed_sec,rss_mb,intern_size,established,flaps_total,msgs_sent_total,max_prefix_exceeded_total,readyz_code,readyz_ms" >"$SAMPLES_CSV"
    local start_epoch now next_sample overall_deadline
    start_epoch=$(date +%s)
    next_sample=$start_epoch
    overall_deadline=$((start_epoch + OVERALL_CAP_SEC))

    while :; do
        now=$(date +%s)
        if ! pid_running "$H_PID"; then
            process_log
            break
        fi
        pid_running "$DAEMON_PID" || abort "daemon died mid-soak"
        process_log
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
    grep -q '^rr_terminal_receipt,' "$RELOADSTALL_LOG" ||
        abort "engine exited clean without a terminal receipt"
    log "engine completed cleanly; running analyzer"

    terminate "$DAEMON_PID"
    DAEMON_PID=""

    python3 "$SOAK_SCRIPT_DIR/analyze-soak-rr-flagship.py" "$RUN_DIR" \
        --output "$RUN_DIR/verdict.json"
    log "soak complete: verdict in $RUN_DIR/verdict.json"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
