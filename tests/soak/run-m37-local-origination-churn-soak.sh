#!/usr/bin/env bash
# M37 local-origination MAC-churn soak.
#
# Sustains bounded local bridge-FDB churn against the M37 topology so the
# local-MAC observation -> EVPN Type 2 origination path runs for hours without
# growing beyond the configured MAC pool. This is intentionally separate from
# the finite interop helper in tests/interop/scripts/: this script creates a
# run directory, captures daemon/consumer logs, samples RSS + EVPN counters,
# and leaves enough metadata for a 1h or 24h postmortem.
#
# Prerequisites:
#   docker build --target dev -t rustbgpd:dev .
#   containerlab deploy -t tests/interop/m37-soak.clab.yml
#
# The soak uses tests/interop/m37-soak.clab.yml (topology name
# `m37-soak`) rather than the interop variant so a concurrent CI run of
# the protected `kernel-dataplane` M37 smoke cannot destroy the soak's
# containers by-name. Override TOPOLOGY/TOPO/RUSTBGPD/CONSUMER to point
# at a different topology if needed.
#
# Usage:
#   SOAK_SECONDS=600 bash tests/soak/run-m37-local-origination-churn-soak.sh
#   SOAK_HOURS=1 bash tests/soak/run-m37-local-origination-churn-soak.sh
#   bash tests/soak/run-m37-local-origination-churn-soak.sh
#
# Output: tests/soak/runs/m37-local-origination-<UTC>/
#   - samples.csv      one row per sample interval
#   - soak.log         harness stdout/stderr
#   - churn.log        per-cycle add/delete log
#   - rustbgpd.log     rustbgpd daemon log copied from inside the container
#   - consumer.log     docker logs for the FRR consumer
#   - run.json         run metadata

set -euo pipefail

SOAK_SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SOAK_SCRIPT_DIR/../.." && pwd)"
TOPOLOGY="${TOPOLOGY:-$REPO_ROOT/tests/interop/m37-soak.clab.yml}"

SOAK_HOURS="${SOAK_HOURS:-24}"
SOAK_SECONDS="${SOAK_SECONDS:-$((SOAK_HOURS * 3600))}"
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-60}"
CHURN_INTERVAL_SEC="${CHURN_INTERVAL_SEC:-5}"
CHURN_BATCH="${CHURN_BATCH:-25}"
MAC_POOL_SIZE="${MAC_POOL_SIZE:-4096}"
LIVE_TARGET_MACS="${LIVE_TARGET_MACS:-1024}"
WARMUP_SEC="${WARMUP_SEC:-300}"
CLEANUP="${CLEANUP:-0}"
DRAIN_ON_EXIT="${DRAIN_ON_EXIT:-1}"

TOPO="${TOPO:-m37-soak}"
RUSTBGPD="${RUSTBGPD:-clab-${TOPO}-rustbgpd}"
CONSUMER="${CONSUMER:-clab-${TOPO}-consumer}"
RUSTBGPD_IP="${RUSTBGPD_IP:-10.0.0.1}"
VNI="${VNI:-100}"
VETH_PORT="${VETH_PORT:-veth${VNI}a}"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${RUN_DIR_OVERRIDE:-$SOAK_SCRIPT_DIR/runs/m37-local-origination-$RUN_ID}"
mkdir -p "$RUN_DIR"

SAMPLES_CSV="$RUN_DIR/samples.csv"
SOAK_LOG="$RUN_DIR/soak.log"
CHURN_LOG="$RUN_DIR/churn.log"
RUN_JSON="$RUN_DIR/run.json"
RUSTBGPD_LOG="$RUN_DIR/rustbgpd.log"
CONSUMER_LOG="$RUN_DIR/consumer.log"
LIVE_SET_FILE="$RUN_DIR/live-mac-indexes.txt"

exec > >(tee -a "$SOAK_LOG") 2>&1

# Host mutex shared with bench/compare-criterion.sh. See
# tests/soak/host-lock.sh for sudo/HOME caveats.
# shellcheck source=./host-lock.sh
source "$SOAK_SCRIPT_DIR/host-lock.sh"
acquire_rustbgpd_host_lock

log() {
    printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
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

require_container() {
    if ! docker inspect "$1" >/dev/null 2>&1; then
        log "ERROR: container '$1' not found; deploy $TOPOLOGY first"
        exit 2
    fi
}

format_mac() {
    local n=${1:?}
    printf '02:37:%02x:%02x:%02x:%02x' \
        $(((n >> 24) & 255)) \
        $(((n >> 16) & 255)) \
        $(((n >> 8) & 255)) \
        $((n & 255))
}

wrap_index() {
    local value=${1:?}
    if [ "$value" -gt "$MAC_POOL_SIZE" ]; then
        value=1
    fi
    printf '%s\n' "$value"
}

rb_fdb_replace() {
    local mac=${1:?}
    docker exec "$RUSTBGPD" bridge fdb replace "$mac" dev "$VETH_PORT" master static
}

rb_fdb_del() {
    local mac=${1:?}
    docker exec "$RUSTBGPD" bridge fdb del "$mac" dev "$VETH_PORT" master 2>/dev/null || true
}

frr_vtysh() {
    docker exec "$CONSUMER" vtysh -c "$1" 2>/dev/null || true
}

frr_established_seen() {
    frr_vtysh "show bgp neighbors $RUSTBGPD_IP json" \
        | grep -q '"bgpState":"Established"'
}

wait_established() {
    log "Waiting for M37 L2VPN/EVPN session to reach Established..."
    for i in $(seq 1 90); do
        if frr_established_seen; then
            log "BGP session established after ${i}s"
            return 0
        fi
        sleep 1
    done
    log "ERROR: BGP session did not reach Established within 90s"
    return 1
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
    local text="$1" metric="$2" label="${3:-}"
    if [ -n "$label" ]; then
        printf '%s' "$text" | awk -v m="$metric" -v l="$label" '
            $0 ~ "^"m"\\{" && index($0, l) { print $NF; found=1; exit }
            END { if (!found) { print "0" } }
        '
    else
        printf '%s' "$text" | awk -v m="$metric" '
            $0 ~ "^"m"( |\\{)" { print $NF; found=1; exit }
            END { if (!found) { print "0" } }
        '
    fi
}

prom_sum() {
    local text="$1" metric="$2"
    printf '%s' "$text" | awk -v m="$metric" '
        $0 ~ "^"m"( |\\{)" { sum += $NF }
        END { if (sum == "") { print "0" } else { print sum } }
    '
}

container_rss_mb() {
    docker exec "$RUSTBGPD" sh -c '
        pid=$(pidof rustbgpd 2>/dev/null || true)
        if [ -n "$pid" ] && [ -r "/proc/$pid/status" ]; then
            awk "/^VmRSS:/ { printf \"%.3f\", \$2 / 1024.0 }" "/proc/$pid/status"
        fi
    ' 2>/dev/null || true
}

rb_local_fdb_count() {
    docker exec "$RUSTBGPD" bridge fdb show dev "$VETH_PORT" master 2>/dev/null \
        | grep -ci '^02:37:' || true
}

frr_type2_count() {
    frr_vtysh "show bgp l2vpn evpn route type macip" \
        | grep -ci '02:37:' || true
}

write_run_json() {
    {
        echo "{"
        printf '  "run_id": "%s",\n' "$RUN_ID"
        printf '  "git_head": "%s",\n' "$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
        printf '  "soak_seconds": %d,\n' "$SOAK_SECONDS"
        printf '  "sample_interval_sec": %d,\n' "$SAMPLE_INTERVAL"
        printf '  "churn_interval_sec": %d,\n' "$CHURN_INTERVAL_SEC"
        printf '  "churn_batch": %d,\n' "$CHURN_BATCH"
        printf '  "mac_pool_size": %d,\n' "$MAC_POOL_SIZE"
        printf '  "live_target_macs": %d,\n' "$LIVE_TARGET_MACS"
        printf '  "warmup_sec": %d,\n' "$WARMUP_SEC"
        printf '  "rustbgpd_container": "%s",\n' "$RUSTBGPD"
        printf '  "consumer_container": "%s",\n' "$CONSUMER"
        printf '  "topology": "%s"\n' "$TOPOLOGY"
        echo "}"
    } >"$RUN_JSON"
}

start_log_streams() {
    docker exec "$RUSTBGPD" sh -c \
        'touch /var/log/rustbgpd.log; tail -n +1 -F /var/log/rustbgpd.log' \
        >"$RUSTBGPD_LOG" 2>&1 &
    RUST_LOG_PID=$!
    docker logs -f "$CONSUMER" >"$CONSUMER_LOG" 2>&1 &
    CONSUMER_LOG_PID=$!
}

stop_log_streams() {
    if [ "${RUST_LOG_PID:-}" ]; then
        kill "$RUST_LOG_PID" 2>/dev/null || true
        wait "$RUST_LOG_PID" 2>/dev/null || true
    fi
    if [ "${CONSUMER_LOG_PID:-}" ]; then
        kill "$CONSUMER_LOG_PID" 2>/dev/null || true
        wait "$CONSUMER_LOG_PID" 2>/dev/null || true
    fi
}

drain_live_macs() {
    if [ ! -s "$LIVE_SET_FILE" ]; then
        return 0
    fi
    log "Draining remaining local MACs from $VETH_PORT"
    while IFS= read -r idx; do
        [ -z "$idx" ] && continue
        rb_fdb_del "$(format_mac "$idx")"
    done <"$LIVE_SET_FILE"
    : >"$LIVE_SET_FILE"
}

cleanup() {
    local exit_code=$?
    set +e
    if [ "$DRAIN_ON_EXIT" = "1" ]; then
        drain_live_macs
    fi
    stop_log_streams
    if [ "$CLEANUP" = "1" ]; then
        log "Destroying containerlab topology"
        containerlab destroy -t "$TOPOLOGY" --cleanup >/dev/null 2>&1 || true
    fi
    exit "$exit_code"
}

trap cleanup EXIT INT TERM HUP

validate_config() {
    local pool_headroom
    if [ "$MAC_POOL_SIZE" -le "$LIVE_TARGET_MACS" ]; then
        log "ERROR: MAC_POOL_SIZE must be greater than LIVE_TARGET_MACS"
        exit 2
    fi
    if [ "$CHURN_BATCH" -le 0 ] || [ "$LIVE_TARGET_MACS" -le 0 ]; then
        log "ERROR: CHURN_BATCH and LIVE_TARGET_MACS must be positive"
        exit 2
    fi
    if [ "$CHURN_BATCH" -gt "$LIVE_TARGET_MACS" ]; then
        log "ERROR: CHURN_BATCH must not exceed LIVE_TARGET_MACS"
        exit 2
    fi
    pool_headroom=$((MAC_POOL_SIZE - LIVE_TARGET_MACS))
    if [ "$pool_headroom" -lt "$CHURN_BATCH" ]; then
        log "ERROR: MAC_POOL_SIZE - LIVE_TARGET_MACS must be at least CHURN_BATCH"
        exit 2
    fi
}

prefill_live_set() {
    : >"$LIVE_SET_FILE"
    log "Prefilling $LIVE_TARGET_MACS local MACs on $VETH_PORT"
    for idx in $(seq 1 "$LIVE_TARGET_MACS"); do
        printf '%s\n' "$idx" >>"$LIVE_SET_FILE"
        rb_fdb_replace "$(format_mac "$idx")"
    done
}

sample_row() {
    local start_epoch=${1:?}
    local churn_cycles=${2:?}
    local add_total=${3:?}
    local del_total=${4:?}
    local now elapsed prom rss fdb_count type2_count established
    local originations_inject originations_withdraw
    local origination_errors_inject origination_errors_withdraw
    local observation_drops duplicate_mac_moves
    now=$(date +%s)
    elapsed=$((now - start_epoch))
    prom=$(prom_scrape)
    rss=$(container_rss_mb)
    fdb_count=$(rb_local_fdb_count)
    type2_count=$(frr_type2_count)
    if frr_established_seen; then
        established=1
    else
        established=0
    fi
    if [ -n "$prom" ]; then
        originations_inject=$(prom_extract_or_zero "$prom" evpn_local_originations_total 'action="inject"')
        originations_withdraw=$(prom_extract_or_zero "$prom" evpn_local_originations_total 'action="withdraw"')
        origination_errors_inject=$(prom_extract_or_zero "$prom" evpn_local_origination_errors_total 'action="inject"')
        origination_errors_withdraw=$(prom_extract_or_zero "$prom" evpn_local_origination_errors_total 'action="withdraw"')
        observation_drops=$(prom_sum "$prom" evpn_local_observations_dropped_total)
        duplicate_mac_moves=$(prom_sum "$prom" evpn_duplicate_mac_moves_total)
    else
        originations_inject=nan
        originations_withdraw=nan
        origination_errors_inject=nan
        origination_errors_withdraw=nan
        observation_drops=nan
        duplicate_mac_moves=nan
    fi

    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        "$elapsed" \
        "${rss:-nan}" \
        "$LIVE_TARGET_MACS" \
        "$fdb_count" \
        "$type2_count" \
        "$established" \
        "$churn_cycles" \
        "$add_total" \
        "$del_total" \
        "$originations_inject" \
        "$originations_withdraw" \
        "$origination_errors_inject" \
        "$origination_errors_withdraw" \
        "$observation_drops" \
        "$duplicate_mac_moves" \
        >>"$SAMPLES_CSV"
}

run_churn_cycle() {
    local del_idx_ref=${1:?}
    local add_idx_ref=${2:?}
    local del_idx add_idx mac i
    del_idx=$(cat "$del_idx_ref")
    add_idx=$(cat "$add_idx_ref")

    for i in $(seq 1 "$CHURN_BATCH"); do
        mac=$(format_mac "$del_idx")
        rb_fdb_del "$mac"
        sed -i "/^${del_idx}$/d" "$LIVE_SET_FILE"
        churn_log "del $mac"
        del_idx=$(wrap_index $((del_idx + 1)))
    done

    for i in $(seq 1 "$CHURN_BATCH"); do
        mac=$(format_mac "$add_idx")
        printf '%s\n' "$add_idx" >>"$LIVE_SET_FILE"
        rb_fdb_replace "$mac"
        churn_log "add $mac"
        add_idx=$(wrap_index $((add_idx + 1)))
    done

    printf '%s\n' "$del_idx" >"$del_idx_ref"
    printf '%s\n' "$add_idx" >"$add_idx_ref"
}

main() {
    require_tool docker
    require_tool curl
    require_tool awk
    require_tool grep
    require_container "$RUSTBGPD"
    require_container "$CONSUMER"
    validate_config

    write_run_json
    start_log_streams

    log "M37 local-origination MAC-churn soak starting"
    log "  duration: ${SOAK_SECONDS}s"
    log "  sample:   ${SAMPLE_INTERVAL}s"
    log "  churn:    ${CHURN_BATCH} del + ${CHURN_BATCH} add every ${CHURN_INTERVAL_SEC}s"
    log "  pool:     ${MAC_POOL_SIZE}, live target: ${LIVE_TARGET_MACS}"
    log "  output:   $RUN_DIR"

    wait_established
    prefill_live_set

    echo "timestamp,elapsed_sec,rss_mb,live_target_macs,local_fdb_count,frr_type2_count,bgp_established,churn_cycles,mac_add_total,mac_del_total,originations_inject,originations_withdraw,origination_errors_inject,origination_errors_withdraw,observation_drops_total,duplicate_mac_moves_total" >"$SAMPLES_CSV"

    local start_epoch end_epoch next_sample next_churn churn_cycles add_total del_total
    local del_idx_file add_idx_file now
    start_epoch=$(date +%s)
    end_epoch=$((start_epoch + SOAK_SECONDS))
    next_sample=$start_epoch
    next_churn=$start_epoch
    churn_cycles=0
    add_total=$LIVE_TARGET_MACS
    del_total=0
    del_idx_file="$RUN_DIR/next-delete-index"
    add_idx_file="$RUN_DIR/next-add-index"
    printf '1\n' >"$del_idx_file"
    printf '%s\n' "$((LIVE_TARGET_MACS + 1))" >"$add_idx_file"

    sample_row "$start_epoch" "$churn_cycles" "$add_total" "$del_total"

    while [ "$(date +%s)" -lt "$end_epoch" ]; do
        now=$(date +%s)
        if [ "$now" -ge "$next_churn" ]; then
            run_churn_cycle "$del_idx_file" "$add_idx_file"
            churn_cycles=$((churn_cycles + 1))
            add_total=$((add_total + CHURN_BATCH))
            del_total=$((del_total + CHURN_BATCH))
            next_churn=$((now + CHURN_INTERVAL_SEC))
        fi
        if [ "$now" -ge "$next_sample" ]; then
            sample_row "$start_epoch" "$churn_cycles" "$add_total" "$del_total"
            next_sample=$((now + SAMPLE_INTERVAL))
        fi
        sleep 1
    done

    sample_row "$start_epoch" "$churn_cycles" "$add_total" "$del_total"
    if [ "$DRAIN_ON_EXIT" = "1" ]; then
        drain_live_macs
        del_total=$((del_total + LIVE_TARGET_MACS))
        sleep 5
        sample_row "$start_epoch" "$churn_cycles" "$add_total" "$del_total"
        DRAIN_ON_EXIT=0
    fi
    log "soak loop completed; final samples in $SAMPLES_CSV"
    log "Run a postmortem from $RUN_DIR before closing issue #134."
}

main "$@"
