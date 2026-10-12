#!/usr/bin/env bash
# Soak: EVPN route reflector — N real iBGP route-reflector-client sessions
# (l2vpn_evpn only) against a bare-host rustbgpd, driven by
# bench/evpn-load's `evpn-rr-soak` driver.
#
# Every epoch (EPOCH_SEC) each client replaces SOAK_SHIFT2 of its
# SOAK_TYPE2 Type 2 (MAC/IP) routes and SOAK_SHIFT5 of its SOAK_TYPE5 Type 5
# (IP prefix) routes, spread across CHURN_SEC; every FLAP_EVERY epochs one
# client (never client 0) sends Cease/Administrative Reset, reconnects and
# re-announces; every RELOAD_EVERY epochs the driver swaps the live config to
# the next description generation (a hot neighbor update on every client)
# and sends SIGHUP to the daemon PID, verifying one `complete` outcome.
# After each epoch the driver waits until every client's reflected view is
# exactly every other client's current windows. The management-plane load
# reads metrics, neighbors, doctor and the paged EVPN peer views of client 0.
#
# Precommitted gates: docs/soaks/soak-acceptance-gates.md (scenario 12).
# Analyzer: tests/soak/analyze-soak-evpn-rr.py.
#
# Usage:
#   bash tests/soak/run-soak-evpn-rr.sh                      # 24 h default
#   SOAK_CLIENTS=12 SOAK_TYPE2=40 SOAK_TYPE5=10 SOAK_SHIFT2=8 SOAK_SHIFT5=2 \
#   SOAK_SECONDS=300 EPOCH_SEC=20 CHURN_SEC=8 FLAP_EVERY=2 RELOAD_EVERY=3 \
#   WARMUP_SEC=30 SAMPLE_INTERVAL=10 MANAGEMENT_CLI_INTERVAL_SEC=2 \
#   MANAGEMENT_DOCTOR_INTERVAL_SEC=60 METRICS_SNAPSHOT_EVERY=3 \
#   bash tests/soak/run-soak-evpn-rr.sh                      # smoke
#
# Output: tests/soak/runs/soak-evpn-rr-<UTC>/
#   - samples.csv      one row per SAMPLE_INTERVAL
#   - soak.log         runner stdout/stderr
#   - cycles.log       epoch, flap, reload and receipt lines + abort records
#   - rustbgpd.log     daemon JSON logs
#   - driver.log       evpn-rr-soak stdout/stderr
#   - management-plane-load.jsonl / .log, doctor-bundle.tar.gz
#   - metrics-snapshots.txt.gz     full /metrics body every METRICS_SNAPSHOT_EVERY samples
#   - run.json         run metadata (analyzer input)
#   - verdict.json     analyzer verdict

set -euo pipefail

SOAK_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SOAK_SCRIPT_DIR/../.." && pwd)"

# --- Shape (24 h defaults sized for an 8 vCPU / 15 GiB host; env-overridable) ---
SOAK_CLIENTS="${SOAK_CLIENTS:-150}"
SOAK_TYPE2="${SOAK_TYPE2:-200}"
SOAK_TYPE5="${SOAK_TYPE5:-50}"
SOAK_SHIFT2="${SOAK_SHIFT2:-20}"
SOAK_SHIFT5="${SOAK_SHIFT5:-5}"
SOAK_SECONDS="${SOAK_SECONDS:-86400}"
EPOCH_SEC="${EPOCH_SEC:-60}"
CHURN_SEC="${CHURN_SEC:-30}"
CONVERGE_CAP_SEC="${CONVERGE_CAP_SEC:-60}"
INITIAL_CAP_SEC="${INITIAL_CAP_SEC:-900}"
REESTABLISH_CAP_SEC="${REESTABLISH_CAP_SEC:-120}"
FLAP_EVERY="${FLAP_EVERY:-5}"
RELOAD_EVERY="${RELOAD_EVERY:-30}"
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-30}"
WARMUP_SEC="${WARMUP_SEC:-300}"
LISTEN_PORT="${LISTEN_PORT:-1790}"
IBGP_ASN="${IBGP_ASN:-64512}"
# gen-scenario.py pins prometheus_addr to 127.0.0.1:9179.
readonly METRICS_PORT=9179
readonly EVPN_PEER="127.1.0.1" # client 0: never flapped, management-plane subject
MANAGEMENT_METRICS_INTERVAL_SEC="${MANAGEMENT_METRICS_INTERVAL_SEC:-1}"
MANAGEMENT_CLI_INTERVAL_SEC="${MANAGEMENT_CLI_INTERVAL_SEC:-5}"
MANAGEMENT_DOCTOR_INTERVAL_SEC="${MANAGEMENT_DOCTOR_INTERVAL_SEC:-600}"
MANAGEMENT_TIMEOUT_SEC="${MANAGEMENT_TIMEOUT_SEC:-5}"
# The per-series sent-counter gate reads these snapshots, so 0 is refused.
METRICS_SNAPSHOT_EVERY="${METRICS_SNAPSHOT_EVERY:-10}"

for knob in SOAK_CLIENTS SOAK_TYPE2 SOAK_TYPE5 SOAK_SHIFT2 SOAK_SHIFT5 SOAK_SECONDS \
    EPOCH_SEC CHURN_SEC CONVERGE_CAP_SEC INITIAL_CAP_SEC REESTABLISH_CAP_SEC FLAP_EVERY \
    RELOAD_EVERY SAMPLE_INTERVAL WARMUP_SEC METRICS_SNAPSHOT_EVERY; do
    if [[ ! ${!knob} =~ ^[1-9][0-9]{0,8}$ ]]; then
        echo "$knob must be a positive decimal integer" >&2
        exit 2
    fi
done

# --- Derived ---
EPOCHS=$((SOAK_SECONDS / EPOCH_SEC))
PLANNED_FLAPS=$((EPOCHS / FLAP_EVERY))
PLANNED_RELOADS=$((EPOCHS / RELOAD_EVERY))
EXPECTED_PER_CLIENT=$(((SOAK_CLIENTS - 1) * (SOAK_TYPE2 + SOAK_TYPE5)))
if ((SOAK_CLIENTS < 3)); then
    echo "SOAK_CLIENTS must be at least 3 (client 0 never flaps)" >&2
    exit 2
fi
if ((SOAK_SHIFT2 > SOAK_TYPE2 || SOAK_SHIFT5 > SOAK_TYPE5)); then
    echo "SOAK_SHIFT2/SOAK_SHIFT5 must not exceed SOAK_TYPE2/SOAK_TYPE5" >&2
    exit 2
fi
if ((SOAK_SECONDS % EPOCH_SEC != 0)); then
    echo "SOAK_SECONDS must be a multiple of EPOCH_SEC" >&2
    exit 2
fi
if ((CHURN_SEC >= EPOCH_SEC)); then
    echo "CHURN_SEC must be shorter than EPOCH_SEC" >&2
    exit 2
fi
if ((PLANNED_FLAPS < 1 || PLANNED_RELOADS < 1)); then
    echo "shape yields no flaps or no reloads (epochs=$EPOCHS flaps=$PLANNED_FLAPS reloads=$PLANNED_RELOADS)" >&2
    exit 2
fi
OVERALL_CAP_SEC="${OVERALL_CAP_SEC:-$((INITIAL_CAP_SEC + EPOCHS * (EPOCH_SEC + CONVERGE_CAP_SEC) + PLANNED_FLAPS * REESTABLISH_CAP_SEC + PLANNED_RELOADS * 120 + 3600))}"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${RUN_DIR_OVERRIDE:-$SOAK_SCRIPT_DIR/runs/soak-evpn-rr-$RUN_ID}"
SAMPLES_CSV="$RUN_DIR/samples.csv"
SOAK_LOG="$RUN_DIR/soak.log"
CYCLES_LOG="$RUN_DIR/cycles.log"
RUN_JSON="$RUN_DIR/run.json"
RUSTBGPD_LOG="$RUN_DIR/rustbgpd.log"
DRIVER_LOG="$RUN_DIR/driver.log"
MANAGEMENT_LOAD_JSONL="$RUN_DIR/management-plane-load.jsonl"
MANAGEMENT_LOAD_LOG="$RUN_DIR/management-plane-load.log"
DOCTOR_BUNDLE="$RUN_DIR/doctor-bundle.tar.gz"
METRICS_SNAPSHOTS_GZ="$RUN_DIR/metrics-snapshots.txt.gz"
PROM_TMP="$RUN_DIR/.metrics.prom"

# shellcheck source=tests/soak/host-lock.sh
source "$SOAK_SCRIPT_DIR/host-lock.sh"
# shellcheck source=tests/soak/fd-headroom.sh
source "$SOAK_SCRIPT_DIR/fd-headroom.sh"
# shellcheck source=tests/soak/flagship-lifecycle.sh
source "$SOAK_SCRIPT_DIR/flagship-lifecycle.sh"

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
ENGINE_FINISH_RELEASE_MONOTONIC=""
RUN_INTERRUPTED=0

monotonic_now() {
    python3 -c 'import time; print(f"{time.monotonic():.9f}")'
}

canonical_management_timing() {
    python3 - "$MANAGEMENT_METRICS_INTERVAL_SEC" \
        "$MANAGEMENT_CLI_INTERVAL_SEC" "$MANAGEMENT_DOCTOR_INTERVAL_SEC" \
        "$MANAGEMENT_TIMEOUT_SEC" <<'PY'
import json
import math
import sys

try:
    values = [float(value) for value in sys.argv[1:]]
except ValueError:
    raise SystemExit(1)
if not all(math.isfinite(value) and value > 0 for value in values):
    raise SystemExit(1)
print(*(json.dumps(value, allow_nan=False) for value in values), sep="\t")
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
    # Owned children already have their signal handlers. Ignore repeated
    # stop requests here so child and log-writer waits finish before marking.
    trap '' INT TERM
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
    else
        log "owned processes stopped; draining soak log"
    fi
    if ! finish_flagship_cleanup "$rc" "$RUN_INTERRUPTED"; then
        echo "ERROR: could not finish soak evidence; inspect the log and cleanup marker" >&2
        ((rc == 0)) && rc=1
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

# Append the current scrape body as one gzip member headed by a comment line;
# the analyzer reads per-series sent counters from these members.
prom_snapshot() {
    local before
    before=$(stat -c %s "$METRICS_SNAPSHOTS_GZ" 2>/dev/null || echo 0)
    if { printf '# snapshot %s elapsed_sec=%s\n' "$1" "$2"; cat "$PROM_TMP"; } |
        gzip -c >>"$METRICS_SNAPSHOTS_GZ"; then
        return 0
    fi
    if ((before == 0)); then
        rm -f "$METRICS_SNAPSHOTS_GZ"
    else
        truncate -c -s "$before" "$METRICS_SNAPSHOTS_GZ"
    fi
    return 1
}

tree_rss_mb() {
    ps -eo pid=,ppid=,rss= --no-headers | awk -v root="$DAEMON_PID" '
        {parent[$1]=$2; rss[$1]=$3} END {for (pid in parent) {p=pid
        while (p in parent && p != root && parent[p] != p) p=parent[p]
        if (p == root) total+=rss[pid]} printf "%.1f", total/1024}'
}

# Driver lines -> cycles.log (analyzer input); a driver FAIL aborts the run.
handle_line() {
    local line=$1
    if [[ $line =~ ^reload\ [0-9]+\ (issued|complete)$ || $line == evpn_epoch\ * ||
        $line == evpn_flap\ * || $line == evpn_receipt\ * ||
        $line == evpn_session_lost\ * ]]; then
        cycle_log "$line"
    elif [[ $line == FAIL:* ]]; then
        abort "driver: ${line#FAIL: }"
    fi
}

SEEN_LINES=0
process_log() {
    local total
    total=$(wc -l <"$DRIVER_LOG")
    ((total > SEEN_LINES)) || return 0
    local line
    while IFS= read -r line; do
        handle_line "$line"
    done < <(sed -n "$((SEEN_LINES + 1)),${total}p" "$DRIVER_LOG")
    SEEN_LINES=$total
}

SCRAPE_FAILS=0
SAMPLE_ROWS=0
sample_row() {
    local elapsed=$1
    # The driver holds the sessions; once it exits a sample would record the
    # harness's own teardown as daemon un-health.
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
    # Keep each command substitution in its own command (see the flagship
    # runners: Bash 5.2 signal-trap parsing).
    local timestamp rss_mb intern_size established flaps messages_sent max_prefix
    timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ) || :
    rss_mb=$(tree_rss_mb) || :
    intern_size=$(prom_get bgp_rib_attr_intern_global_size) || :
    established=$(prom_sum bgp_peer_session_established) || :
    flaps=$(prom_sum bgp_session_flaps_total) || :
    messages_sent=$(prom_sum bgp_messages_sent_total) || :
    max_prefix=$(prom_sum bgp_max_prefix_exceeded_total) || :
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$timestamp" "$elapsed" "$rss_mb" "$intern_size" "$established" \
        "$flaps" "$messages_sent" "$max_prefix" "$code" "$ms" \
        >>"$SAMPLES_CSV"
    if ((SAMPLE_ROWS % METRICS_SNAPSHOT_EVERY == 0)); then
        prom_snapshot "$timestamp" "$elapsed" || cycle_log "metrics snapshot append failed"
    fi
    SAMPLE_ROWS=$((SAMPLE_ROWS + 1))
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
        --peers "$SOAK_CLIENTS" \
        --evpn-peer "$EVPN_PEER" \
        --metrics-interval "$MANAGEMENT_METRICS_INTERVAL_SEC" \
        --cli-interval "$MANAGEMENT_CLI_INTERVAL_SEC" \
        --doctor-interval "$MANAGEMENT_DOCTOR_INTERVAL_SEC" \
        --doctor-bundle "$DOCTOR_BUNDLE" \
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
    local management_timing management_metrics_interval management_cli_interval
    local management_doctor_interval management_timeout
    if ! management_timing=$(canonical_management_timing); then
        abort "management-plane intervals and timeout are no longer valid"
    fi
    IFS=$'\t' read -r management_metrics_interval management_cli_interval \
        management_doctor_interval management_timeout <<<"$management_timing"
    [[ -n $MEASURED_START_MONOTONIC ]] && measured_start=$MEASURED_START_MONOTONIC
    [[ -n $MEASURED_END_MONOTONIC ]] && measured_end=$MEASURED_END_MONOTONIC
    {
        echo "{"
        printf '  "run_id": "%s",\n' "$RUN_ID"
        printf '  "git_head": "%s",\n' "$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
        printf '  "peers": %d,\n' "$SOAK_CLIENTS"
        printf '  "type2_per_client": %d,\n' "$SOAK_TYPE2"
        printf '  "type5_per_client": %d,\n' "$SOAK_TYPE5"
        printf '  "shift2_per_epoch": %d,\n' "$SOAK_SHIFT2"
        printf '  "shift5_per_epoch": %d,\n' "$SOAK_SHIFT5"
        printf '  "expected_per_client": %d,\n' "$EXPECTED_PER_CLIENT"
        printf '  "soak_seconds": %d,\n' "$SOAK_SECONDS"
        printf '  "epoch_sec": %d,\n' "$EPOCH_SEC"
        printf '  "churn_sec": %d,\n' "$CHURN_SEC"
        printf '  "converge_cap_sec": %d,\n' "$CONVERGE_CAP_SEC"
        printf '  "reestablish_cap_sec": %d,\n' "$REESTABLISH_CAP_SEC"
        printf '  "planned_epochs": %d,\n' "$EPOCHS"
        printf '  "flap_every": %d,\n' "$FLAP_EVERY"
        printf '  "reload_every": %d,\n' "$RELOAD_EVERY"
        printf '  "planned_flaps": %d,\n' "$PLANNED_FLAPS"
        printf '  "planned_reloads": %d,\n' "$PLANNED_RELOADS"
        printf '  "sample_interval_sec": %d,\n' "$SAMPLE_INTERVAL"
        printf '  "warmup_sec": %d,\n' "$WARMUP_SEC"
        printf '  "metrics_snapshot_every": %d,\n' "$METRICS_SNAPSHOT_EVERY"
        printf '  "ibgp_asn": %d,\n' "$IBGP_ASN"
        printf '  "listen_port": %d,\n' "$LISTEN_PORT"
        printf '  "metrics_port": %d,\n' "$METRICS_PORT"
        printf '  "management_load_file": "management-plane-load.jsonl",\n'
        printf '  "management_metrics_interval_sec": %s,\n' "$management_metrics_interval"
        printf '  "management_cli_interval_sec": %s,\n' "$management_cli_interval"
        printf '  "management_doctor_interval_sec": %s,\n' "$management_doctor_interval"
        printf '  "management_timeout_sec": %s,\n' "$management_timeout"
        printf '  "management_evpn_peer": "%s",\n' "$EVPN_PEER"
        printf '  "measured_start_monotonic": %s,\n' "$measured_start"
        printf '  "measured_end_monotonic": %s,\n' "$measured_end"
        printf '  "nofile_soft": %s,\n' "$RUSTBGPD_NOFILE_SOFT_JSON"
        printf '  "engine_finish_release_monotonic": %s\n' "${ENGINE_FINISH_RELEASE_MONOTONIC:-null}"
        echo "}"
    } >"$tmp"
    mv "$tmp" "$RUN_JSON"
}

main() {
    mkdir -p "$RUN_DIR"
    trap cleanup EXIT
    trap 'RUN_INTERRUPTED=1; exit 130' INT
    trap 'RUN_INTERRUPTED=1; exit 143' TERM
    start_flagship_lifecycle
    acquire_rustbgpd_host_lock
    for tool in cargo curl awk python3 ss flock git ps df mktemp gzip; do
        require_tool "$tool"
    done
    # Before any daemon launch: the daemon inherits this shell's soft limit.
    require_fd_headroom || exit $?
    if ! canonical_management_timing >/dev/null; then
        log "ERROR: management-plane intervals and timeout must be finite positive numbers"
        exit 2
    fi
    if ! ports_free; then
        log "ERROR: port $LISTEN_PORT or $METRICS_PORT is already in use — refusing to start (not killing unknown processes)"
        exit 75
    fi

    log "EVPN route-reflector soak starting"
    log "  shape:   ${SOAK_CLIENTS} EVPN RR clients x (${SOAK_TYPE2} Type 2 + ${SOAK_TYPE5} Type 5); ${EXPECTED_PER_CLIENT} reflected routes per client"
    log "  churn:   ${EPOCHS} epochs x ${EPOCH_SEC}s; ${SOAK_SHIFT2}+${SOAK_SHIFT5} routes replaced per client per epoch over ${CHURN_SEC}s"
    log "  faults:  ${PLANNED_FLAPS} client flaps (every ${FLAP_EVERY} epochs), ${PLANNED_RELOADS} SIGHUP reloads (every ${RELOAD_EVERY} epochs)"
    log "  output:  $RUN_DIR"

    log "building daemon + rbgp + evpn-rr-soak (--release), locked"
    (cd "$REPO_ROOT" && cargo build --release --locked -p rustbgpd -p rustbgpctl) \
        >"$RUN_DIR/build-root.log" 2>&1
    (cd "$REPO_ROOT" && cargo build --release --locked -p rustbgpd-evpn-load --bin evpn-rr-soak) \
        >"$RUN_DIR/build-driver.log" 2>&1
    DAEMON="$REPO_ROOT/target/release/rustbgpd"
    RBGP="$REPO_ROOT/target/release/rbgp"
    DRIVER="$REPO_ROOT/target/release/evpn-rr-soak"
    sha256sum "$DAEMON" "$RBGP" "$DRIVER" >"$RUN_DIR/binaries.sha256"

    # Fresh scenario per run; /tmp keeps the gRPC UDS under the SUN_LEN cap.
    SCEN="$(mktemp -d /tmp/evrr.XXXXXX)"
    GEN_IBGP_RR_ASN=$IBGP_ASN GEN_EVPN=1 \
        python3 "$REPO_ROOT/bench/scale/reloadstall/gen-scenario.py" \
        "$SOAK_CLIENTS" "$SCEN" "$LISTEN_PORT" >"$RUN_DIR/generator.log"
    mkdir -p "$RUN_DIR/scenario"
    cp "$SCEN/config-gen-a.toml" "$SCEN/config-gen-b.toml" "$RUN_DIR/scenario/"
    "$DAEMON" --check "$SCEN/config-gen-a.toml" >"$RUN_DIR/daemon-check.log" 2>&1
    "$DAEMON" --check "$SCEN/config-gen-b.toml" >>"$RUN_DIR/daemon-check.log" 2>&1

    write_run_json

    [[ ! -e $RUN_DIR/engine-finish && ! -e $RUN_DIR/driver-start ]] ||
        abort "driver handshake evidence path already exists"
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

    "$DRIVER" --daemon "127.0.0.1:${LISTEN_PORT}" --clients "$SOAK_CLIENTS" --asn "$IBGP_ASN" \
        --type2 "$SOAK_TYPE2" --type5 "$SOAK_TYPE5" \
        --shift2 "$SOAK_SHIFT2" --shift5 "$SOAK_SHIFT5" \
        --epochs "$EPOCHS" --epoch-secs "$EPOCH_SEC" --churn-secs "$CHURN_SEC" \
        --converge-cap-secs "$CONVERGE_CAP_SEC" --initial-cap-secs "$INITIAL_CAP_SEC" \
        --reestablish-cap-secs "$REESTABLISH_CAP_SEC" \
        --flap-every "$FLAP_EVERY" --reload-every "$RELOAD_EVERY" \
        --daemon-pid "$DAEMON_PID" --config-live "$SCEN/config.toml" \
        --config-gens "$SCEN/config-gen-b.toml" "$SCEN/config-gen-a.toml" \
        --metrics "127.0.0.1:${METRICS_PORT}" \
        --evidence-dir "$RUN_DIR/engine-finish" \
        --start-file "$RUN_DIR/driver-start" >"$DRIVER_LOG" 2>&1 &
    H_PID=$!
    log "driver started pid=$H_PID"

    local converge_deadline=$(($(date +%s) + INITIAL_CAP_SEC + 60))
    until grep -q '^converged (initial)' "$DRIVER_LOG" 2>/dev/null; do
        pid_running "$H_PID" || abort "driver exited before initial convergence"
        (($(date +%s) < converge_deadline)) || abort "initial convergence exceeded ${INITIAL_CAP_SEC}s"
        sleep 1
    done
    log "driver converged; starting management-plane load"
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
        pid_running "$H_PID" || { process_log; abort "driver exited before final evidence acknowledgement"; }
        pid_running "$MANAGEMENT_LOAD_PID" || abort "management-plane load exited before driver"
        pid_running "$DAEMON_PID" || abort "daemon died mid-soak"
        process_log
        if [[ -f $RUN_DIR/engine-finish/ready ]]; then
            # The driver holds every session until ack; drain the load first so
            # no probe overlaps the final Cease fan-out.
            MEASURED_END_MONOTONIC=$(monotonic_now)
            stop_management_load || abort "management-plane load did not terminate cleanly"
            pid_running "$H_PID" || abort "driver exited while draining management-plane load"
            ENGINE_FINISH_RELEASE_MONOTONIC=$(monotonic_now)
            write_run_json
            printf 'ack\n' >"$RUN_DIR/engine-finish/ack"
            break
        fi
        if ((now >= next_sample)); then
            sample_row $((now - start_epoch))
            next_sample=$((now + SAMPLE_INTERVAL))
            # Release epoch 1 only after a recorded pre-fault baseline row.
            if ((SAMPLE_ROWS > 0)) && [[ ! -e $RUN_DIR/driver-start ]]; then
                printf 'start\n' >"$RUN_DIR/driver-start"
            fi
        fi
        ((now < overall_deadline)) || abort "overall watchdog cap ${OVERALL_CAP_SEC}s exceeded"
        sleep 1
    done

    local hrc=0
    wait "$H_PID" || hrc=$?
    H_PID=""
    process_log
    ((hrc == 0)) || abort "driver exited non-zero: $hrc"
    write_run_json
    log "driver and management-plane load completed cleanly; running analyzer"

    terminate "$DAEMON_PID"
    DAEMON_PID=""

    python3 "$SOAK_SCRIPT_DIR/analyze-soak-evpn-rr.py" "$RUN_DIR" \
        --output "$RUN_DIR/verdict.json"
    log "soak complete: verdict in $RUN_DIR/verdict.json"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
