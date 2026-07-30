#!/usr/bin/env bash
# Soak: config live-apply (hot-reload) churn.
#
# Repeatedly runs `rbgp config plan` → `config apply` with a candidate
# TOML that mutates the neighbor description, exercising the ADR-0063
# shape-gated live-apply path without restarting the daemon. Proves the
# live-apply path does not leak and sessions stay established across
# hundreds of config cycles.
#
# Prerequisites:
#   docker build -t rustbgpd:dev .
#   containerlab deploy -t tests/soak/soak-hot-reload.clab.yml
#
# Usage:
#   SOAK_SECONDS=600 bash tests/soak/run-soak-hot-reload.sh   # 10-min smoke
#   SOAK_HOURS=6   bash tests/soak/run-soak-hot-reload.sh     # 6h
#   bash tests/soak/run-soak-hot-reload.sh                    # 6h default
#
# Output: tests/soak/runs/soak-hot-reload-<UTC>/
#   - samples.csv      one row per sample interval
#   - soak.log         harness stdout/stderr
#   - cycles.log       per-apply-cycle log
#   - rustbgpd.log     rustbgpd daemon log
#   - run.json         run metadata

set -euo pipefail

SOAK_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SOAK_SCRIPT_DIR/../.." && pwd)"
TOPOLOGY="${TOPOLOGY:-$REPO_ROOT/tests/soak/soak-hot-reload.clab.yml}"

SOAK_HOURS="${SOAK_HOURS:-6}"
SOAK_SECONDS="${SOAK_SECONDS:-$((SOAK_HOURS * 3600))}"
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-30}"
APPLY_INTERVAL_SEC="${APPLY_INTERVAL_SEC:-120}"
WARMUP_SEC="${WARMUP_SEC:-120}"
CLEANUP="${CLEANUP:-0}"

TOPO="${TOPO:-soak-hot-reload}"
RUSTBGPD="${RUSTBGPD:-clab-${TOPO}-rustbgpd}"
FRR="${FRR:-clab-${TOPO}-frr}"
RUSTBGPD_IP="${RUSTBGPD_IP:-10.0.0.1}"
FRR_IP="${FRR_IP:-10.0.0.2}"
GRPC_ADDR="${GRPC_ADDR:-http://127.0.0.1:50051}"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${RUN_DIR_OVERRIDE:-$SOAK_SCRIPT_DIR/runs/soak-hot-reload-$RUN_ID}"

SAMPLES_CSV="$RUN_DIR/samples.csv"
SOAK_LOG="$RUN_DIR/soak.log"
CYCLES_LOG="$RUN_DIR/cycles.log"
RUN_JSON="$RUN_DIR/run.json"
RUSTBGPD_LOG="$RUN_DIR/rustbgpd.log"
CANDIDATE_TOML="$RUN_DIR/candidate.toml"

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

frr_vtysh() {
    docker exec "$FRR" vtysh -c "$1" 2>/dev/null || true
}

frr_established_seen() {
    frr_vtysh "show bgp neighbors $RUSTBGPD_IP json" \
        | grep -q '"bgpState":"Established"'
}

neighbor_state() {
    docker exec "$RUSTBGPD" rbgp -s "$GRPC_ADDR" neighbor -j |
        python3 -c 'import json,sys; n=json.load(sys.stdin)[0]; print(n["flap_count"], n["uptime_seconds"])'
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

write_candidate_toml() {
    local cycle=${1:?}
    cat >"$CANDIDATE_TOML" <<EOF
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[global.telemetry.grpc_tcp]
address = "0.0.0.0:50051"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
description = "frr-soak-hot-reload-cycle-${cycle}"
hold_time = 90

[security.grpc]
enforcement = "legacy"
EOF
}

# Plan a candidate config, extract the runtime_snapshot_token from JSON.
plan_and_extract_token() {
    local output status
    set +e
    output=$(docker exec "$RUSTBGPD" rbgp -s "$GRPC_ADDR" config plan \
        --from-file /tmp/candidate.toml -j)
    status=$?
    set -e
    case "$status" in 0|2) ;; *) return "$status";; esac
    printf '%s' "$output" | python3 -c 'import json,sys
d=json.load(sys.stdin)
t=d.get("runtime_snapshot_token")
if not isinstance(t, str) or not t: raise SystemExit(2)
print(t)'
}

run_analyzer() {
    python3 "$SOAK_SCRIPT_DIR/analyze-soak-hot-reload.py" "$RUN_DIR" --output "$RUN_DIR/verdict.json"
}

run_apply_cycle() {
    local cycle=${1:?}
    write_candidate_toml "$cycle"
    cycle_log "cycle $cycle: writing candidate TOML"
    # Copy candidate into the container (rbgp reads from_file locally).
    docker cp "$CANDIDATE_TOML" "$RUSTBGPD:/tmp/candidate.toml" >/dev/null
    local token
    token=$(plan_and_extract_token)
    if [ -z "$token" ]; then
        cycle_log "cycle $cycle: WARN plan returned no token, skipping apply"
        return 1
    fi
    cycle_log "cycle $cycle: token=$token, applying"
    docker exec "$RUSTBGPD" rbgp -s "$GRPC_ADDR" config apply \
        --from-file /tmp/candidate.toml \
        --expected-runtime-snapshot-token "$token" -j >/dev/null 2>&1 || {
        cycle_log "cycle $cycle: apply failed"
        return 1
    }
    cycle_log "cycle $cycle: apply OK"
    return 0
}

write_run_json() {
    {
        echo "{"
        printf '  "run_id": "%s",\n' "$RUN_ID"
        printf '  "git_head": "%s",\n' "$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
        printf '  "soak_seconds": %d,\n' "$SOAK_SECONDS"
        printf '  "sample_interval_sec": %d,\n' "$SAMPLE_INTERVAL"
        printf '  "apply_interval_sec": %d,\n' "$APPLY_INTERVAL_SEC"
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

sample_row() {
    local elapsed=${1:?}
    local cycles=${2:?}
    local apply_ok=${3:?}
    local apply_fail=${4:?}
    local prom rss intern_size established flap_count uptime_seconds
    prom=$(prom_scrape) || prom=""
    rss=$(container_rss_mb)
    intern_size=$(prom_extract_sum "$prom" bgp_rib_attr_intern_global_size)
    local neighbor
    neighbor=$(neighbor_state)
    read -r flap_count uptime_seconds <<<"$neighbor"
    if frr_established_seen; then
        established=1
    else
        established=0
    fi
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        "$elapsed" \
        "${rss:-nan}" \
        "$intern_size" \
        "$established" \
        "$cycles" \
        "$apply_ok" \
        "$apply_fail" \
        "$flap_count" \
        "$uptime_seconds" \
        >>"$SAMPLES_CSV"
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

    write_run_json
    start_log_stream

    log "Hot-reload (config live-apply) soak starting"
    log "  duration:         ${SOAK_SECONDS}s"
    log "  sample interval:  ${SAMPLE_INTERVAL}s"
    log "  apply interval:   ${APPLY_INTERVAL_SEC}s"
    log "  warmup:           ${WARMUP_SEC}s"
    log "  output:           $RUN_DIR"

    wait_established

    log "Warmup: waiting ${WARMUP_SEC}s"
    sleep "$WARMUP_SEC"

    echo "timestamp,elapsed_sec,rss_mb,intern_size,bgp_established,apply_cycles,apply_ok,apply_fail,flap_count,uptime_seconds" >"$SAMPLES_CSV"

    local start_epoch end_epoch next_sample next_apply cycles apply_ok apply_fail
    start_epoch=$(date +%s)
    end_epoch=$((start_epoch + SOAK_SECONDS))
    next_sample=$start_epoch
    next_apply=$start_epoch
    cycles=0
    apply_ok=0
    apply_fail=0

    sample_row 0 "$cycles" "$apply_ok" "$apply_fail"

    while [ "$(date +%s)" -lt "$end_epoch" ]; do
        now=$(date +%s)
        if [ "$now" -ge "$next_apply" ]; then
            cycles=$((cycles + 1))
            run_apply_cycle "$cycles"
            apply_ok=$((apply_ok + 1))
            next_apply=$((now + APPLY_INTERVAL_SEC))
        fi
        if [ "$now" -ge "$next_sample" ]; then
            local elapsed=$((now - start_epoch))
            sample_row "$elapsed" "$cycles" "$apply_ok" "$apply_fail"
            next_sample=$((now + SAMPLE_INTERVAL))
        fi
        sleep 1
    done

    local final_elapsed=$(( $(date +%s) - start_epoch ))
    sample_row "$final_elapsed" "$cycles" "$apply_ok" "$apply_fail"
    log "soak loop completed; $cycles apply cycles ($apply_ok ok, $apply_fail fail); final samples in $SAMPLES_CSV"
    run_analyzer
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
