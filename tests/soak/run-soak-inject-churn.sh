#!/usr/bin/env bash
# Soak: gRPC route-injection churn (automation-controller beachhead).
#
# Drives `InjectionService.AddPath` / `DeletePath` over gRPC at a
# sustained add/delete rate, proving the controller-injection path
# (the automation-controller beachhead) does not leak under
# steady-state churn. Uses `rbgp rib add` / `rbgp rib delete` from
# inside the rustbgpd container.
#
# Prerequisites:
#   docker build -t rustbgpd:dev .
#   containerlab deploy -t tests/soak/soak-inject-churn.clab.yml
#
# Usage:
#   SOAK_SECONDS=600 bash tests/soak/run-soak-inject-churn.sh   # 10-min smoke
#   SOAK_HOURS=24  bash tests/soak/run-soak-inject-churn.sh     # 24h
#   bash tests/soak/run-soak-inject-churn.sh                    # 24h default
#
# Output: tests/soak/runs/soak-inject-churn-<UTC>/
#   - samples.csv      one row per sample interval
#   - soak.log         harness stdout/stderr
#   - churn.log        per-cycle add/delete log
#   - rustbgpd.log     rustbgpd daemon log copied from inside the container
#   - run.json         run metadata

set -euo pipefail

SOAK_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SOAK_SCRIPT_DIR/../.." && pwd)"
TOPOLOGY="${TOPOLOGY:-$REPO_ROOT/tests/soak/soak-inject-churn.clab.yml}"

SOAK_HOURS="${SOAK_HOURS:-24}"
SOAK_SECONDS="${SOAK_SECONDS:-$((SOAK_HOURS * 3600))}"
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-60}"
CHURN_INTERVAL_SEC="${CHURN_INTERVAL_SEC:-5}"
CHURN_BATCH="${CHURN_BATCH:-25}"
PREFIX_POOL_SIZE="${PREFIX_POOL_SIZE:-4096}"
LIVE_TARGET_PREFIXES="${LIVE_TARGET_PREFIXES:-1024}"
WARMUP_SEC="${WARMUP_SEC:-120}"
CLEANUP="${CLEANUP:-0}"

TOPO="${TOPO:-soak-inject-churn}"
RUSTBGPD="${RUSTBGPD:-clab-${TOPO}-rustbgpd}"
FRR="${FRR:-clab-${TOPO}-frr}"
RUSTBGPD_IP="${RUSTBGPD_IP:-10.0.0.1}"
FRR_IP="${FRR_IP:-10.0.0.2}"
GRPC_ADDR="${GRPC_ADDR:-http://127.0.0.1:50051}"
NEXTHOP="${NEXTHOP:-10.0.0.1}"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${RUN_DIR_OVERRIDE:-$SOAK_SCRIPT_DIR/runs/soak-inject-churn-$RUN_ID}"

SAMPLES_CSV="$RUN_DIR/samples.csv"
SOAK_LOG="$RUN_DIR/soak.log"
CHURN_LOG="$RUN_DIR/churn.log"
RUN_JSON="$RUN_DIR/run.json"
RUSTBGPD_LOG="$RUN_DIR/rustbgpd.log"
LIVE_SET_FILE="$RUN_DIR/live-prefix-indexes.txt"

# shellcheck source=tests/soak/host-lock.sh
source "$SOAK_SCRIPT_DIR/host-lock.sh"

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

daemon_running() {
    docker exec "$RUSTBGPD" sh -c 'cat /proc/[0-9]*/comm 2>/dev/null' \
        | grep -qx rustbgpd
}

# The soak topology launches the container with `cmd: sleep infinity`;
# start the daemon explicitly. Idempotent so a re-run against a live
# topology does not double-start it.
ensure_daemon_running() {
    if daemon_running; then
        return 0
    fi
    log "rustbgpd not running in $RUSTBGPD; starting"
    # Redirect into the file the log stream tails: a detached exec's
    # stdout is otherwise discarded and rustbgpd.log stays empty.
    docker exec -d "$RUSTBGPD" sh -c \
        '/usr/local/bin/start-rustbgpd.sh >>/var/log/rustbgpd.log 2>&1'
    for _ in $(seq 1 10); do
        if daemon_running; then
            return 0
        fi
        sleep 1
    done
    log "ERROR: rustbgpd failed to start within 10s"
    return 1
}

format_prefix() {
    local n=${1:?}
    # 10.<high>.<low>.0/24 — unique /24s from the pool index.
    printf '10.%d.%d.0/24' $(((n >> 8) & 255)) $((n & 255))
}

wrap_index() {
    local value=${1:?}
    if [ "$value" -gt "$PREFIX_POOL_SIZE" ]; then
        value=1
    fi
    printf '%s\n' "$value"
}

rb_inject_add() {
    local prefix=${1:?}
    docker exec "$RUSTBGPD" rbgp -s "$GRPC_ADDR" rib add "$prefix" \
        --nexthop "$NEXTHOP" >/dev/null
}

rb_inject_del() {
    local prefix=${1:?}
    docker exec "$RUSTBGPD" rbgp -s "$GRPC_ADDR" rib delete "$prefix" \
        >/dev/null
}

frr_vtysh() {
    docker exec "$FRR" vtysh -c "$1"
}

frr_established_seen() {
    frr_vtysh "show bgp neighbors $RUSTBGPD_IP json" \
        | grep -q '"bgpState":"Established"'
}

wait_established() {
    log "Waiting for BGP session to reach Established..."
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

prom_extract_required() {
    local text="$1" metric="$2"
    printf '%s' "$text" | awk -v m="$metric" '
        $0 ~ "^"m"( |\\{)" { print $NF; found=1; exit }
        END { if (!found) { print "nan" } }
    '
}

# Sum all per-peer series of a labeled gauge from a scraped /metrics blob.
prom_extract_sum() {
    local prom="$1" name="$2"
    awk -v n="$name" '
        $0 ~ "^"n"[{ ]" { s += $NF; found=1 }
        END { if (!found) print "nan"; else printf "%d", s }
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

frr_route_count() {
    frr_vtysh "show bgp ipv4 unicast json" |
        python3 -c 'import json,sys
d=json.load(sys.stdin)
r=d.get("routes")
if not isinstance(r, dict): raise SystemExit(2)
print(len(r))'
}

run_analyzer() {
    python3 "$SOAK_SCRIPT_DIR/analyze-soak-inject-churn.py" "$RUN_DIR" --output "$RUN_DIR/verdict.json"
}

neighbor_state() {
    docker exec "$RUSTBGPD" rbgp -s "$GRPC_ADDR" neighbor -j |
        python3 -c 'import json,sys; n=json.load(sys.stdin)[0]; print(n["flap_count"], n["uptime_seconds"])'
}

wait_final_routes() {
    local count
    for _ in $(seq 1 30); do
        count=$(frr_route_count)
        [ "$count" -eq "$LIVE_TARGET_PREFIXES" ] && return 0
        sleep 1
    done
    log "ERROR: FRR route count ${count:-unknown}, expected $LIVE_TARGET_PREFIXES"
    return 1
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
        printf '  "prefix_pool_size": %d,\n' "$PREFIX_POOL_SIZE"
        printf '  "live_target_prefixes": %d,\n' "$LIVE_TARGET_PREFIXES"
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

drain_live_prefixes() {
    if [ ! -s "$LIVE_SET_FILE" ]; then
        return 0
    fi
    log "Draining remaining injected prefixes"
    while IFS= read -r idx; do
        [ -z "$idx" ] && continue
        rb_inject_del "$(format_prefix "$idx")"
    done <"$LIVE_SET_FILE"
    : >"$LIVE_SET_FILE"
}

cleanup() {
    local exit_code=$?
    set +e
    drain_live_prefixes
    stop_log_stream
    if [ "$CLEANUP" = "1" ]; then
        log "Destroying containerlab topology"
        containerlab destroy -t "$TOPOLOGY" --cleanup >/dev/null 2>&1 || true
    fi
    exit "$exit_code"
}

validate_config() {
    if [ "$PREFIX_POOL_SIZE" -le "$LIVE_TARGET_PREFIXES" ]; then
        log "ERROR: PREFIX_POOL_SIZE must be greater than LIVE_TARGET_PREFIXES"
        exit 2
    fi
    if [ "$CHURN_BATCH" -le 0 ] || [ "$LIVE_TARGET_PREFIXES" -le 0 ]; then
        log "ERROR: CHURN_BATCH and LIVE_TARGET_PREFIXES must be positive"
        exit 2
    fi
    if [ "$CHURN_BATCH" -gt "$LIVE_TARGET_PREFIXES" ]; then
        log "ERROR: CHURN_BATCH must not exceed LIVE_TARGET_PREFIXES"
        exit 2
    fi
    local pool_headroom=$((PREFIX_POOL_SIZE - LIVE_TARGET_PREFIXES))
    if [ "$pool_headroom" -lt "$CHURN_BATCH" ]; then
        log "ERROR: PREFIX_POOL_SIZE - LIVE_TARGET_PREFIXES must be at least CHURN_BATCH"
        exit 2
    fi
}

prefill_live_set() {
    : >"$LIVE_SET_FILE"
    log "Prefilling $LIVE_TARGET_PREFIXES injected prefixes"
    local idx
    for idx in $(seq 1 "$LIVE_TARGET_PREFIXES"); do
        rb_inject_add "$(format_prefix "$idx")"
        printf '%s\n' "$idx" >>"$LIVE_SET_FILE"
    done
}

sample_row() {
    local elapsed=${1:?}
    local cycles=${2:?}
    local add_total=${3:?}
    local del_total=${4:?}
    local prom rss frr_count established intern_size flap_count uptime_seconds
    prom=$(prom_scrape) || prom=""
    rss=$(container_rss_mb)
    frr_count=$(frr_route_count)
    if frr_established_seen; then
        established=1
    else
        established=0
    fi
    intern_size=$(prom_extract_sum "$prom" bgp_rib_attr_intern_global_size)
    local neighbor
    neighbor=$(neighbor_state)
    read -r flap_count uptime_seconds <<<"$neighbor"
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        "$elapsed" \
        "${rss:-nan}" \
        "$intern_size" \
        "$LIVE_TARGET_PREFIXES" \
        "$frr_count" \
        "$established" \
        "$cycles" \
        "$add_total" \
        "$del_total" \
        "$flap_count" \
        "$uptime_seconds" \
        >>"$SAMPLES_CSV"
}

run_churn_cycle() {
    local del_idx_ref=${1:?}
    local add_idx_ref=${2:?}
    local del_idx add_idx prefix i
    del_idx=$(cat "$del_idx_ref")
    add_idx=$(cat "$add_idx_ref")

    for i in $(seq 1 "$CHURN_BATCH"); do
        prefix=$(format_prefix "$del_idx")
        rb_inject_del "$prefix"
        sed -i "/^${del_idx}$/d" "$LIVE_SET_FILE"
        churn_log "del $prefix"
        del_idx=$(wrap_index $((del_idx + 1)))
    done

    for i in $(seq 1 "$CHURN_BATCH"); do
        prefix=$(format_prefix "$add_idx")
        rb_inject_add "$prefix"
        printf '%s\n' "$add_idx" >>"$LIVE_SET_FILE"
        churn_log "add $prefix"
        add_idx=$(wrap_index $((add_idx + 1)))
    done

    printf '%s\n' "$del_idx" >"$del_idx_ref"
    printf '%s\n' "$add_idx" >"$add_idx_ref"
}

main() {
    mkdir -p "$RUN_DIR"
    exec > >(tee -a "$SOAK_LOG") 2>&1
    acquire_rustbgpd_host_lock
    trap cleanup EXIT INT TERM HUP
    require_tool docker
    require_tool curl
    require_tool awk
    require_tool python3
    require_container "$RUSTBGPD"
    require_container "$FRR"
    ensure_daemon_running
    validate_config

    write_run_json
    start_log_stream

    log "gRPC inject-churn soak starting"
    log "  duration: ${SOAK_SECONDS}s"
    log "  sample:   ${SAMPLE_INTERVAL}s"
    log "  churn:    ${CHURN_BATCH} del + ${CHURN_BATCH} add every ${CHURN_INTERVAL_SEC}s"
    log "  pool:     ${PREFIX_POOL_SIZE}, live target: ${LIVE_TARGET_PREFIXES}"
    log "  output:   $RUN_DIR"

    wait_established
    prefill_live_set

    echo "timestamp,elapsed_sec,rss_mb,intern_size,live_target,frr_route_count,bgp_established,churn_cycles,add_total,del_total,flap_count,uptime_seconds" >"$SAMPLES_CSV"

    local start_epoch end_epoch next_sample next_churn cycles add_total del_total
    local del_idx_file add_idx_file now
    start_epoch=$(date +%s)
    end_epoch=$((start_epoch + SOAK_SECONDS))
    next_sample=$start_epoch
    next_churn=$((start_epoch + WARMUP_SEC))
    cycles=0
    add_total=$LIVE_TARGET_PREFIXES
    del_total=0
    del_idx_file="$RUN_DIR/next-delete-index"
    add_idx_file="$RUN_DIR/next-add-index"
    printf '1\n' >"$del_idx_file"
    printf '%s\n' "$((LIVE_TARGET_PREFIXES + 1))" >"$add_idx_file"

    sample_row 0 "$cycles" "$add_total" "$del_total"

    while [ "$(date +%s)" -lt "$end_epoch" ]; do
        now=$(date +%s)
        if [ "$now" -ge "$next_churn" ]; then
            run_churn_cycle "$del_idx_file" "$add_idx_file"
            cycles=$((cycles + 1))
            add_total=$((add_total + CHURN_BATCH))
            del_total=$((del_total + CHURN_BATCH))
            next_churn=$((now + CHURN_INTERVAL_SEC))
        fi
        if [ "$now" -ge "$next_sample" ]; then
            local elapsed=$((now - start_epoch))
            sample_row "$elapsed" "$cycles" "$add_total" "$del_total"
            next_sample=$((now + SAMPLE_INTERVAL))
        fi
        sleep 1
    done

    local final_elapsed=$(( $(date +%s) - start_epoch ))
    wait_final_routes
    sample_row "$final_elapsed" "$cycles" "$add_total" "$del_total"
    log "soak loop completed; $cycles churn cycles; final samples in $SAMPLES_CSV"
    run_analyzer
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
