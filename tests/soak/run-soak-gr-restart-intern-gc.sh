#!/usr/bin/env bash
# Soak: GR-restart → EoR → stale-clear → gc_intern_table cycle.
#
# Repeatedly restarts FRR's bgpd to drive rustbgpd through the
# Graceful Restart state machine: session down → stale-mark →
# reconnect → EoR → stale-clear → gc_intern_table. Samples RSS and
# the bgp_rib_attr_intern_size Prometheus gauge each cycle to prove
# the interned-attribute table does not grow across restart cycles
# (the leak class fixed in #603 and unsoaked at HEAD until now).
#
# Prerequisites:
#   docker build -t rustbgpd:dev .
#   containerlab deploy -t tests/soak/soak-gr-restart-intern-gc.clab.yml
#
# Usage:
#   SOAK_SECONDS=600 bash tests/soak/run-soak-gr-restart-intern-gc.sh   # 10-min smoke
#   SOAK_HOURS=6   bash tests/soak/run-soak-gr-restart-intern-gc.sh     # 6h dry run
#   bash tests/soak/run-soak-gr-restart-intern-gc.sh                    # 6h default
#
# Output: tests/soak/runs/soak-gr-restart-<UTC>/
#   - samples.csv      one row per sample interval
#   - soak.log         harness stdout/stderr
#   - cycles.log       per-restart-cycle log
#   - rustbgpd.log     rustbgpd daemon log copied from inside the container
#   - run.json         run metadata

set -euo pipefail

SOAK_SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SOAK_SCRIPT_DIR/../.." && pwd)"
TOPOLOGY="${TOPOLOGY:-$REPO_ROOT/tests/soak/soak-gr-restart-intern-gc.clab.yml}"

SOAK_HOURS="${SOAK_HOURS:-6}"
SOAK_SECONDS="${SOAK_SECONDS:-$((SOAK_HOURS * 3600))}"
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-30}"
RESTART_INTERVAL_SEC="${RESTART_INTERVAL_SEC:-300}"
WARMUP_SEC="${WARMUP_SEC:-120}"
CLEANUP="${CLEANUP:-0}"

TOPO="${TOPO:-soak-gr-restart}"
RUSTBGPD="${RUSTBGPD:-clab-${TOPO}-rustbgpd}"
FRR="${FRR:-clab-${TOPO}-frr}"
RUSTBGPD_IP="${RUSTBGPD_IP:-10.0.0.1}"
FRR_IP="${FRR_IP:-10.0.0.2}"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${RUN_DIR_OVERRIDE:-$SOAK_SCRIPT_DIR/runs/soak-gr-restart-$RUN_ID}"
mkdir -p "$RUN_DIR"

SAMPLES_CSV="$RUN_DIR/samples.csv"
SOAK_LOG="$RUN_DIR/soak.log"
CYCLES_LOG="$RUN_DIR/cycles.log"
RUN_JSON="$RUN_DIR/run.json"
RUSTBGPD_LOG="$RUN_DIR/rustbgpd.log"

exec > >(tee -a "$SOAK_LOG") 2>&1

# shellcheck source=./host-lock.sh
source "$SOAK_SCRIPT_DIR/host-lock.sh"
acquire_rustbgpd_host_lock

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

require_container() {
    if ! docker inspect "$1" >/dev/null 2>&1; then
        log "ERROR: container '$1' not found; deploy $TOPOLOGY first"
        exit 2
    fi
}

prom_scrape() {
    local ip
    ip=$(docker inspect --format \
        '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' \
        "$RUSTBGPD" 2>/dev/null | awk '{print $1}')
    [ -z "$ip" ] && return 0
    curl -sfm 5 "http://${ip}:9179/metrics" 2>/dev/null || true
}

prom_extract_or_zero() {
    local text="$1" metric="$2"
    printf '%s' "$text" | awk -v m="$metric" '
        $0 ~ "^"m"( |\\{)" { print $NF; found=1; exit }
        END { if (!found) { print "0" } }
    '
}

# Sum all per-peer series of a labeled gauge from a scraped /metrics blob.
prom_extract_sum() {
    local prom="$1" name="$2"
    awk -v n="$name" '
        $0 ~ "^"n"[{ ]" { s += $NF }
        END { printf "%d", s+0 }
    ' <<<"$prom"
}

container_rss_mb() {
    docker exec "$RUSTBGPD" sh -c '
        pid=$(pidof rustbgpd 2>/dev/null || true)
        if [ -n "$pid" ] && [ -r "/proc/$pid/status" ]; then
            awk "/^VmRSS:/ { printf \"%.3f\", \$2 / 1024.0 }" "/proc/$pid/status"
        fi
    ' 2>/dev/null || true
}

rb_gr_active() {
    local prom
    prom=$(prom_scrape)
    [ -z "$prom" ] && { echo 0; return; }
    prom_extract_or_zero "$prom" bgp_gr_active_peers
}

frr_established_seen() {
    docker exec "$FRR" vtysh -c "show bgp neighbors $RUSTBGPD_IP json" 2>/dev/null \
        | grep -q '"bgpState":"Established"'
}

wait_established() {
    local timeout=${1:-90}
    log "Waiting for BGP session to reach Established (timeout ${timeout}s)..."
    for i in $(seq 1 "$timeout"); do
        if frr_established_seen; then
            log "BGP session established after ${i}s"
            return 0
        fi
        sleep 1
    done
    log "ERROR: BGP session did not reach Established within ${timeout}s"
    return 1
}

restart_frr_bgpd() {
    cycle_log "restarting FRR bgpd"
    # Stop bgpd, wait for rustbgpd to notice the session drop and mark stale.
    docker exec "$FRR" /usr/lib/frr/frrinit.sh stop >/dev/null 2>&1 || true
    sleep 5
    # Start bgpd again; rustbgpd will see reconnect + EoR + stale-clear + gc.
    docker exec "$FRR" /usr/lib/frr/frrinit.sh start >/dev/null 2>&1 || true
    cycle_log "FRR bgpd restart initiated"
}

write_run_json() {
    {
        echo "{"
        printf '  "run_id": "%s",\n' "$RUN_ID"
        printf '  "git_head": "%s",\n' "$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
        printf '  "soak_seconds": %d,\n' "$SOAK_SECONDS"
        printf '  "sample_interval_sec": %d,\n' "$SAMPLE_INTERVAL"
        printf '  "restart_interval_sec": %d,\n' "$RESTART_INTERVAL_SEC"
        printf '  "warmup_sec": %d,\n' "$WARMUP_SEC"
        printf '  "rustbgpd_container": "%s",\n' "$RUSTBGPD"
        printf '  "frr_container": "%s",\n' "$FRR"
        printf '  "topology": "%s"\n' "$TOPOLOGY"
        echo "}"
    } >"$RUN_JSON"
}

start_log_stream() {
    docker exec "$RUSTBGPD" sh -c \
        'touch /var/log/rustbgpd.log; tail -n +1 -F /var/log/rustbgpd.log' \
        >"$RUSTBGPD_LOG" 2>&1 &
    RUST_LOG_PID=$!
}

stop_log_stream() {
    if [ "${RUST_LOG_PID:-}" ]; then
        kill "$RUST_LOG_PID" 2>/dev/null || true
        wait "$RUST_LOG_PID" 2>/dev/null || true
    fi
}

cleanup() {
    local exit_code=$?
    set +e
    stop_log_stream
    if [ "$CLEANUP" = "1" ]; then
        log "Destroying containerlab topology"
        containerlab destroy -t "$TOPOLOGY" --cleanup >/dev/null 2>&1 || true
    fi
    exit "$exit_code"
}

trap cleanup EXIT INT TERM HUP

sample_row() {
    local elapsed=${1:?}
    local cycles=${2:?}
    local prom rss intern_size gr_active established
    prom=$(prom_scrape)
    rss=$(container_rss_mb)
    intern_size=$(prom_extract_sum "$prom" bgp_rib_attr_intern_size)
    gr_active=$(prom_extract_or_zero "$prom" bgp_gr_active_peers)
    if frr_established_seen; then
        established=1
    else
        established=0
    fi
    printf '%s,%s,%s,%s,%s,%s,%s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        "$elapsed" \
        "${rss:-nan}" \
        "$intern_size" \
        "$gr_active" \
        "$established" \
        "$cycles" \
        >>"$SAMPLES_CSV"
}

main() {
    require_tool docker
    require_tool curl
    require_tool awk
    require_container "$RUSTBGPD"
    require_container "$FRR"

    write_run_json
    start_log_stream

    log "GR-restart intern-gc soak starting"
    log "  duration:          ${SOAK_SECONDS}s"
    log "  sample interval:   ${SAMPLE_INTERVAL}s"
    log "  restart interval:  ${RESTART_INTERVAL_SEC}s"
    log "  warmup:            ${WARMUP_SEC}s"
    log "  output:            $RUN_DIR"

    wait_established 90

    log "Warmup: waiting ${WARMUP_SEC}s for initial convergence"
    sleep "$WARMUP_SEC"

    echo "timestamp,elapsed_sec,rss_mb,intern_size,gr_active_peers,bgp_established,restart_cycles" >"$SAMPLES_CSV"

    local start_epoch end_epoch next_sample next_restart cycles
    start_epoch=$(date +%s)
    end_epoch=$((start_epoch + SOAK_SECONDS))
    next_sample=$start_epoch
    next_restart=$start_epoch
    cycles=0

    sample_row 0 "$cycles"

    while [ "$(date +%s)" -lt "$end_epoch" ]; do
        now=$(date +%s)
        if [ "$now" -ge "$next_restart" ]; then
            restart_frr_bgpd
            cycles=$((cycles + 1))
            next_restart=$((now + RESTART_INTERVAL_SEC))
            # Wait for re-establishment so the cycle is well-formed.
            wait_established 60 || log "WARN: session did not re-establish after cycle $cycles"
        fi
        if [ "$now" -ge "$next_sample" ]; then
            local elapsed=$((now - start_epoch))
            sample_row "$elapsed" "$cycles"
            next_sample=$((now + SAMPLE_INTERVAL))
        fi
        sleep 1
    done

    local final_elapsed=$(( $(date +%s) - start_epoch ))
    sample_row "$final_elapsed" "$cycles"
    log "soak loop completed; $cycles restart cycles; final samples in $SAMPLES_CSV"
    log "Run the analyzer: python3 tests/soak/analyze-soak-gr-restart.py $RUN_DIR"
}

main "$@"
