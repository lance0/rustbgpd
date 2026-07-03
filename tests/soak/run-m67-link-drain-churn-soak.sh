#!/usr/bin/env bash
# M67 link-driven Ethernet Segment drain churn soak.
#
# Repeats the ADR-0085 M67 failure stimulus for hours: pe1's bound
# attachment circuit is brought down, the link-drain path must withdraw pe1's
# segment routes and promote pe2, then pe1's carrier is restored and the
# recovery hold-off must release before pe1 re-wins DF. The script records
# route/session/gauge/memory samples and leaves enough artifacts for a 1h or
# 24h receipt without claiming one in CI.
#
# Prerequisites:
#   docker build --target dev -t rustbgpd:dev .
#   containerlab deploy -t tests/soak/m67-link-drain-soak.clab.yml
#
# Usage:
#   SOAK_SECONDS=300 bash tests/soak/run-m67-link-drain-churn-soak.sh
#   SOAK_HOURS=1 bash tests/soak/run-m67-link-drain-churn-soak.sh
#   bash tests/soak/run-m67-link-drain-churn-soak.sh

set -euo pipefail

SOAK_SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SOAK_SCRIPT_DIR/../.." && pwd)"
TOPOLOGY="${TOPOLOGY:-$REPO_ROOT/tests/soak/m67-link-drain-soak.clab.yml}"

SOAK_HOURS="${SOAK_HOURS:-24}"
SOAK_SECONDS="${SOAK_SECONDS:-$((SOAK_HOURS * 3600))}"
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-30}"
CYCLE_INTERVAL_SEC="${CYCLE_INTERVAL_SEC:-90}"
RECOVERY_DELAY_SECS="${RECOVERY_DELAY_SECS:-5}"
HOLD_SAMPLE_WINDOW_MS="${HOLD_SAMPLE_WINDOW_MS:-3000}"
HOLD_DEEP_MS="${HOLD_DEEP_MS:-2000}"
BLACKOUT_BOUND_MS="${BLACKOUT_BOUND_MS:-30000}"
RELEASE_BOUND_MS="${RELEASE_BOUND_MS:-30000}"
CLEANUP="${CLEANUP:-0}"

TOPO="${TOPO:-m67-link-drain-soak}"
VTEP="${VTEP:-clab-${TOPO}-vtep}"
PE1="${PE1:-clab-${TOPO}-pe1}"
PE2="${PE2:-clab-${TOPO}-pe2}"
CE="${CE:-clab-${TOPO}-ce}"
HR="${HR:-clab-${TOPO}-hr}"

PE1_IP="${PE1_IP:-10.0.1.2}"
PE2_IP="${PE2_IP:-10.0.2.2}"
VNI="${VNI:-100}"
ESI="${ESI:-00:00:00:00:00:00:00:00:00:01}"
CE_MAC="${CE_MAC:-02:ce:ce:ce:ce:01}"
CE_HOST_IP="${CE_HOST_IP:-192.168.67.10}"
AC_IF="${AC_IF:-eth2}"
VXLAN="${VXLAN:-vxlan${VNI}}"
PROBE_INTERVAL_MS="${PROBE_INTERVAL_MS:-100}"
active_prober_tag=""

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${RUN_DIR_OVERRIDE:-$SOAK_SCRIPT_DIR/runs/m67-link-drain-$RUN_ID}"
mkdir -p "$RUN_DIR"

SAMPLES_CSV="$RUN_DIR/samples.csv"
SOAK_LOG="$RUN_DIR/soak.log"
CYCLE_LOG="$RUN_DIR/cycles.log"
RUN_JSON="$RUN_DIR/run.json"
REPORT_JSON="$RUN_DIR/report.json"

exec > >(tee -a "$SOAK_LOG") 2>&1

# Host mutex shared with bench/compare-criterion.sh. See
# tests/soak/host-lock.sh for sudo/HOME caveats.
# shellcheck source=tests/soak/host-lock.sh
source "$SOAK_SCRIPT_DIR/host-lock.sh"
acquire_rustbgpd_host_lock

failures=0
cycle=0
last_sample_sec=0
start_epoch=$(date +%s)
end_epoch=$((start_epoch + SOAK_SECONDS))

log() {
    printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

cycle_log() {
    printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"$CYCLE_LOG"
}

mark_failure() {
    failures=$((failures + 1))
    log "FAIL: $*"
    cycle_log "cycle=${cycle} failure=${failures}: $*"
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

container_ip() {
    docker inspect -f '{{range .NetworkSettings.Networks}}{{if .IPAddress}}{{println .IPAddress}}{{end}}{{end}}' "$1" 2>/dev/null \
        | awk 'NF { print; exit }'
}

prom_scrape() {
    local container=${1:?} ip
    ip=$(container_ip "$container")
    [ -z "$ip" ] && return 0
    curl -sfm 5 "http://${ip}:9179/metrics" 2>/dev/null || true
}

prom_value() {
    local container=${1:?} metric=${2:?} label_a=${3:-} label_b=${4:-} label_c=${5:-}
    prom_scrape "$container" | awk \
        -v m="$metric" -v a="$label_a" -v b="$label_b" -v c="$label_c" '
            $0 ~ "^"m"\\{" &&
                (a == "" || index($0, a)) &&
                (b == "" || index($0, b)) &&
                (c == "" || index($0, c)) {
                    print $2
                    found = 1
                    exit
                }
            END { if (!found) print "0" }
        '
}

vtep_ctl() {
    docker exec "$VTEP" rbgp -s http://127.0.0.1:50051 "$@"
}

vtep_routes() {
    local route_type=${1:?} peer=${2:?}
    vtep_ctl evpn --route-type "$route_type" --peer "$peer" -j 2>/dev/null || echo "[]"
}

vtep_route_count() {
    local route_type=${1:?} peer=${2:?} predicate=${3:-true}
    vtep_routes "$route_type" "$peer" \
        | jq "[.[] | select(${predicate})] | length" 2>/dev/null || echo 0
}

wait_vtep_routes_at_least() {
    local route_type=${1:?} peer=${2:?} predicate=${3:?} want=${4:?} attempts=${5:-90}
    local got=0
    for _ in $(seq 1 "$attempts"); do
        got=$(vtep_route_count "$route_type" "$peer" "$predicate")
        if [ "${got:-0}" -ge "$want" ] 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_vtep_routes_gone() {
    local route_type=${1:?} peer=${2:?} predicate=${3:?} attempts=${4:-90}
    local got=1
    for _ in $(seq 1 "$attempts"); do
        got=$(vtep_route_count "$route_type" "$peer" "$predicate")
        if [ "${got:-1}" -eq 0 ] 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    return 1
}

df_role() {
    local container=${1:?} role=${2:?}
    prom_value "$container" evpn_df_role "role=\"${role}\"" "vni=\"${VNI}\"" "esi=\"${ESI}\""
}

drain_gauge() {
    local container=${1:?} reason=${2:?}
    prom_value "$container" evpn_es_drained "reason=\"${reason}\"" "esi=\"${ESI}\""
}

wait_role() {
    local container=${1:?} role=${2:?} want=${3:?} attempts=${4:-90}
    for _ in $(seq 1 "$attempts"); do
        [ "$(df_role "$container" "$role")" = "$want" ] && return 0
        sleep 1
    done
    return 1
}

wait_drain_gauge() {
    local container=${1:?} reason=${2:?} want=${3:?} attempts=${4:-30}
    for _ in $(seq 1 "$attempts"); do
        [ "$(drain_gauge "$container" "$reason")" = "$want" ] && return 0
        sleep 1
    done
    return 1
}

ac_port_state() {
    docker exec "$1" bridge -d link show dev "$AC_IF" 2>/dev/null \
        | grep -o 'state [a-z]*' | head -1 | cut -d' ' -f2
}

wait_ac_state() {
    local container=${1:?} want=${2:?} attempts=${3:-60}
    for _ in $(seq 1 "$attempts"); do
        [ "$(ac_port_state "$container")" = "$want" ] && return 0
        sleep 1
    done
    return 1
}

session_state() {
    local peer=${1:?}
    vtep_ctl neighbor "$peer" -j 2>/dev/null \
        | jq -r '.state // empty' 2>/dev/null || true
}

session_established() {
    local peer=${1:?} state
    for _ in 1 2 3; do
        state=$(session_state "$peer")
        [ "$state" = "Established" ] && return 0
        [ -n "$state" ] && return 1
        sleep 0.2
    done
    return 1
}

wait_vtep_established() {
    local peer=${1:?} label=${2:?}
    log "Waiting for $label session to reach Established..."
    for i in $(seq 1 60); do
        if session_established "$peer"; then
            log "$label session established after ${i}s"
            return 0
        fi
        sleep 2
    done
    return 1
}

wait_pe_grpc() {
    local container=${1:?} label=${2:?}
    for i in $(seq 1 30); do
        if docker exec "$container" rbgp -s http://127.0.0.1:50051 \
            --token-file /etc/rustbgpd/grpc-operator.token global >/dev/null 2>&1; then
            log "$label gRPC ready after ${i}s"
            return 0
        fi
        sleep 2
    done
    return 1
}

container_rss_mb() {
    docker exec "$1" sh -c '
        pid=$(pidof rustbgpd 2>/dev/null || true)
        if [ -n "$pid" ] && [ -r "/proc/$pid/status" ]; then
            awk "/^VmRSS:/ { printf \"%.3f\", \$2 / 1024.0 }" "/proc/$pid/status"
        fi
    ' 2>/dev/null || true
}

restart_count() {
    docker inspect -f '{{.RestartCount}}' "$1" 2>/dev/null || echo 0
}

rb_fdb() {
    docker exec "$VTEP" bridge fdb show dev "$VXLAN" 2>/dev/null || true
}

rb_nh() {
    docker exec "$VTEP" ip nexthop show 2>/dev/null || true
}

ce_mac_row() {
    rb_fdb | grep -i "$CE_MAC" || true
}

group_members_of() {
    local gid=${1:?}
    rb_nh | grep -E "^id ${gid} group " \
        | grep -oE 'group [0-9/]+' | awk '{print $2}' | tr '/' ' ' || true
}

ce_mac_egress_ips() {
    local row gid dst members mid via
    row=$(ce_mac_row)
    [ -z "$row" ] && return 0
    dst=$(echo "$row" | grep -oE ' dst [0-9.]+' | awk '{print $2}' | head -1 || true)
    if [ -n "$dst" ]; then
        echo "$dst"
        return 0
    fi
    gid=$(echo "$row" | grep -oE ' nhid [0-9]+' | awk '{print $2}' | head -1 || true)
    [ -z "$gid" ] && return 0
    members=$(group_members_of "$gid")
    for mid in $members; do
        via=$(rb_nh | grep -E "^id ${mid} via " | awk '{print $4}' || true)
        [ -n "$via" ] && echo "$via"
    done
}

now_ms() {
    date +%s%3N
}

pe1_ac_down() {
    docker exec "$PE1" ip link set "$AC_IF" down
}

pe1_ac_up() {
    docker exec "$PE1" ip link set "$AC_IF" up
}

ce_recovery_broadcast() {
    docker exec "$CE" ping -c 1 -W 1 192.168.67.99 >/dev/null 2>&1 || true
}

wait_ping() {
    local attempts=${1:-90}
    for _ in $(seq 1 "$attempts"); do
        if docker exec "$HR" ping -c 1 -W 1 "$CE_HOST_IP" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

start_prober() {
    local tag=${1:?}
    local interval_sec
    interval_sec=$(awk -v ms="$PROBE_INTERVAL_MS" 'BEGIN { printf "%.3f", ms / 1000 }')
    docker exec "$HR" sh -c 'rm -f "/tmp/m67-soak-$1.log" "/tmp/m67-soak-$1.pid"' _ "$tag" || true
    docker exec -d "$HR" sh -c 'ping -i "$1" -O "$2" >"/tmp/m67-soak-$3.log" 2>&1 & echo $! >"/tmp/m67-soak-$3.pid"' _ "$interval_sec" "$CE_HOST_IP" "$tag"
    active_prober_tag="$tag"
}

stop_prober() {
    local tag=${1:?}
    docker exec "$HR" sh -c 'kill -TERM "$(cat "/tmp/m67-soak-$1.pid")" 2>/dev/null' _ "$tag" || true
    sleep 1
    if [ "$active_prober_tag" = "$tag" ]; then
        active_prober_tag=""
    fi
}

prober_max_gap_ms() {
    local tag=${1:?}
    local seqs reply_count max_gap
    seqs=$(docker exec "$HR" cat "/tmp/m67-soak-${tag}.log" 2>/dev/null \
        | grep 'bytes from' \
        | grep -oE 'icmp_seq=[0-9]+' | cut -d= -f2 || true)
    reply_count=$(printf '%s\n' "$seqs" | grep -c '[0-9]' || true)
    if [ "${reply_count:-0}" -lt 2 ]; then
        # Fewer than two replies means no gap can be measured (a missing or
        # truncated prober log, e.g. the prober never started). Emit a sentinel
        # so the gate fails loudly instead of reading a vacuous 0 ms "perfect"
        # blackout. A genuine 0 (prober ran, no dropped sequences) is distinct.
        echo -1
        return
    fi
    max_gap=$(printf '%s\n' "$seqs" \
        | awk 'NR>1 && $1>prev+1 { g=$1-prev-1; if (g>max) max=g } { prev=$1 } END { print max+0 }')
    echo $(( ${max_gap:-0} * PROBE_INTERVAL_MS ))
}

write_run_json() {
    {
        echo "{"
        printf '  "run_id": "%s",\n' "$RUN_ID"
        printf '  "git_head": "%s",\n' "$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
        printf '  "soak_seconds": %d,\n' "$SOAK_SECONDS"
        printf '  "sample_interval_sec": %d,\n' "$SAMPLE_INTERVAL"
        printf '  "cycle_interval_sec": %d,\n' "$CYCLE_INTERVAL_SEC"
        printf '  "recovery_delay_sec": %d,\n' "$RECOVERY_DELAY_SECS"
        printf '  "blackout_bound_ms": %d,\n' "$BLACKOUT_BOUND_MS"
        printf '  "release_bound_ms": %d,\n' "$RELEASE_BOUND_MS"
        printf '  "topology": "%s",\n' "$TOPOLOGY"
        printf '  "vtep_container": "%s",\n' "$VTEP"
        printf '  "pe1_container": "%s",\n' "$PE1"
        printf '  "pe2_container": "%s"\n' "$PE2"
        echo "}"
    } >"$RUN_JSON"
}

start_log_streams() {
    for c in "$VTEP" "$PE1" "$PE2"; do
        docker logs -f "$c" >"$RUN_DIR/${c}.docker.log" 2>&1 &
        log_pids="${log_pids:-} $!"
    done
}

collect_daemon_logs() {
    for c in "$VTEP" "$PE1" "$PE2"; do
        docker exec "$c" cat /var/log/rustbgpd.log >"$RUN_DIR/${c}.rustbgpd.log" 2>/dev/null || true
    done
}

cleanup() {
    set +e
    if [ -n "$active_prober_tag" ]; then
        stop_prober "$active_prober_tag" >/dev/null 2>&1 || true
    fi
    pe1_ac_up >/dev/null 2>&1 || true
    collect_daemon_logs
    for pid in ${log_pids:-}; do
        kill "$pid" >/dev/null 2>&1 || true
    done
    if [ "$CLEANUP" = "1" ] && [ -f "$TOPOLOGY" ]; then
        log "[cleanup] containerlab destroy -t $TOPOLOGY"
        containerlab destroy -t "$TOPOLOGY" --cleanup >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

sample() {
    local phase=${1:?} blackout_ms=${2:-} release_ms=${3:-}
    local now elapsed egress
    now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    elapsed=$(( $(date +%s) - start_epoch ))
    egress=$(ce_mac_egress_ips | sort -u | tr '\n' ' ' | sed 's/ $//')
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,"%s",%s,%s,%s,%s,%s,%s\n' \
        "$now" "$elapsed" "$cycle" "$phase" \
        "$(container_rss_mb "$PE1")" "$(container_rss_mb "$PE2")" "$(container_rss_mb "$VTEP")" \
        "$(session_established "$PE1_IP" && echo 1 || echo 0)" \
        "$(session_established "$PE2_IP" && echo 1 || echo 0)" \
        "$(df_role "$PE1" df)" "$(df_role "$PE2" df)" \
        "$(df_role "$PE1" nondf)" "$(df_role "$PE2" nondf)" \
        "$(drain_gauge "$PE1" link)" "$(drain_gauge "$PE1" operator)" "$(drain_gauge "$PE2" link)" \
        "$(ac_port_state "$PE1")" "$(ac_port_state "$PE2")" \
        "$(vtep_route_count 4 "$PE1_IP")" "$(vtep_route_count 1 "$PE1_IP")" "$(vtep_route_count 2 "$PE1_IP" ".mac == \"${CE_MAC}\"")" \
        "$(vtep_route_count 4 "$PE2_IP")" "$(vtep_route_count 1 "$PE2_IP")" "$(vtep_route_count 2 "$PE2_IP" ".mac == \"${CE_MAC}\"")" \
        "$egress" "${blackout_ms:-}" "${release_ms:-}" "$failures" \
        "$(restart_count "$PE1")" "$(restart_count "$PE2")" "$(restart_count "$VTEP")" \
        >>"$SAMPLES_CSV"
}

sample_if_due() {
    local phase=${1:?}
    local now
    now=$(( $(date +%s) - start_epoch ))
    if [ $((now - last_sample_sec)) -ge "$SAMPLE_INTERVAL" ]; then
        sample "$phase"
        last_sample_sec=$now
    fi
}

bootstrap() {
    log "Checking prerequisites..."
    for tool in docker curl jq python3; do
        require_tool "$tool"
    done
    for c in "$VTEP" "$PE1" "$PE2" "$CE" "$HR"; do
        require_container "$c"
    done

    write_run_json
    start_log_streams
    printf 'timestamp,elapsed_sec,cycle,phase,pe1_rss_mb,pe2_rss_mb,vtep_rss_mb,pe1_session_established,pe2_session_established,pe1_df,pe2_df,pe1_nondf,pe2_nondf,pe1_link_drain,pe1_operator_drain,pe2_link_drain,pe1_ac_state,pe2_ac_state,pe1_type4,pe1_ead,pe1_type2,pe2_type4,pe2_ead,pe2_type2,ce_mac_egress,blackout_ms,release_ms,failures,pe1_restart_count,pe2_restart_count,vtep_restart_count\n' >"$SAMPLES_CSV"

    log "Waiting for M67 gRPC/session/DF steady state..."
    wait_pe_grpc "$PE1" pe1 || { mark_failure "pe1 gRPC not ready"; exit 1; }
    wait_pe_grpc "$PE2" pe2 || { mark_failure "pe2 gRPC not ready"; exit 1; }
    wait_vtep_established "$PE1_IP" "vtep<->pe1 EVPN" || { mark_failure "vtep<->pe1 EVPN not Established"; exit 1; }
    wait_vtep_established "$PE2_IP" "vtep<->pe2 EVPN" || { mark_failure "vtep<->pe2 EVPN not Established"; exit 1; }
    wait_role "$PE1" df 1 90 || { mark_failure "pe1 did not become initial DF"; exit 1; }
    wait_role "$PE2" nondf 1 90 || { mark_failure "pe2 did not become initial NonDF"; exit 1; }
    wait_ac_state "$PE1" forwarding 60 || { mark_failure "pe1 AC did not start forwarding"; exit 1; }
    wait_ac_state "$PE2" disabled 60 || { mark_failure "pe2 AC did not start disabled"; exit 1; }
    wait_ping 90 || { mark_failure "initial hr -> CE ping failed"; exit 1; }
    wait_vtep_routes_at_least 2 "$PE1_IP" ".mac == \"${CE_MAC}\"" 1 120 \
        || { mark_failure "initial CE MAC Type 2 from pe1 missing"; exit 1; }
    sample bootstrap
    last_sample_sec=0
}

run_cycle() {
    local cycle_start tag blackout_ms up_ms elapsed gauge hold_held hold_deep hold_samples release_ok release_ms
    cycle_start=$(date +%s)
    cycle=$((cycle + 1))
    tag="cycle-${cycle}"
    cycle_log "cycle=${cycle} start"

    log "[cycle $cycle] AC down on pe1, expecting link drain and pe2 promotion"
    start_prober "$tag"
    sleep 1
    pe1_ac_down || mark_failure "cycle $cycle: could not down pe1 AC"
    wait_drain_gauge "$PE1" link 1 15 || mark_failure "cycle $cycle: pe1 link drain gauge did not reach 1"
    [ "$(drain_gauge "$PE1" operator)" = "0" ] || mark_failure "cycle $cycle: operator drain gauge changed during link failure"
    wait_vtep_routes_gone 4 "$PE1_IP" "true" 90 || mark_failure "cycle $cycle: pe1 Type 4 did not withdraw"
    wait_vtep_routes_gone 1 "$PE1_IP" "true" 90 || mark_failure "cycle $cycle: pe1 EAD routes did not withdraw"
    wait_role "$PE2" df 1 90 || mark_failure "cycle $cycle: pe2 did not promote to DF"
    wait_ac_state "$PE2" forwarding 60 || mark_failure "cycle $cycle: pe2 AC did not open"
    wait_vtep_routes_at_least 2 "$PE2_IP" ".mac == \"${CE_MAC}\"" 1 120 \
        || mark_failure "cycle $cycle: pe2 did not originate CE MAC"
    wait_ping 90 || mark_failure "cycle $cycle: ping did not recover through pe2"
    sleep 2
    stop_prober "$tag"
    blackout_ms=$(prober_max_gap_ms "$tag")
    if [ "$blackout_ms" -lt 0 ]; then
        mark_failure "cycle $cycle: blackout unmeasured (prober produced <2 replies)"
    elif [ "$blackout_ms" -ge "$BLACKOUT_BOUND_MS" ]; then
        mark_failure "cycle $cycle: blackout ${blackout_ms}ms >= ${BLACKOUT_BOUND_MS}ms"
    fi
    sample drained "$blackout_ms"

    log "[cycle $cycle] AC up on pe1, expecting held recovery then pe1 revert"
    up_ms=$(now_ms)
    pe1_ac_up || mark_failure "cycle $cycle: could not up pe1 AC"
    hold_held=1
    hold_deep=0
    hold_samples=0
    while :; do
        elapsed=$(( $(now_ms) - up_ms ))
        [ "$elapsed" -ge "$HOLD_SAMPLE_WINDOW_MS" ] && break
        gauge=$(drain_gauge "$PE1" link)
        hold_samples=$((hold_samples + 1))
        if [ "$gauge" != "1" ]; then
            hold_held=0
            break
        fi
        [ "$elapsed" -ge "$HOLD_DEEP_MS" ] && hold_deep=1
        sleep 0.2
    done
    if [ "$hold_held" -ne 1 ]; then
        mark_failure "cycle $cycle: hold-off released early at ${elapsed}ms"
    elif [ "$hold_deep" -ne 1 ]; then
        mark_failure "cycle $cycle: hold-off sample window was vacuous (${hold_samples} samples)"
    fi

    release_ok=0
    for _ in $(seq 1 60); do
        if [ "$(drain_gauge "$PE1" link)" = "0" ]; then
            release_ok=1
            break
        fi
        sleep 0.5
    done
    release_ms=$(( $(now_ms) - up_ms ))
    if [ "$release_ok" -ne 1 ]; then
        mark_failure "cycle $cycle: link drain did not release after AC up"
    elif [ "$release_ms" -ge "$RELEASE_BOUND_MS" ]; then
        mark_failure "cycle $cycle: release ${release_ms}ms >= ${RELEASE_BOUND_MS}ms"
    fi
    wait_vtep_routes_at_least 4 "$PE1_IP" "true" 1 90 || mark_failure "cycle $cycle: pe1 Type 4 did not return"
    wait_vtep_routes_at_least 1 "$PE1_IP" '.ethernet_tag == "MAX_ET"' 1 90 \
        || mark_failure "cycle $cycle: pe1 EAD-per-ES did not return"
    wait_role "$PE1" df 1 90 || mark_failure "cycle $cycle: pe1 did not re-win DF"
    wait_role "$PE2" nondf 1 90 || mark_failure "cycle $cycle: pe2 did not demote"
    wait_ac_state "$PE1" forwarding 60 || mark_failure "cycle $cycle: pe1 AC did not reopen"
    wait_ac_state "$PE2" disabled 60 || mark_failure "cycle $cycle: pe2 AC did not re-block"
    ce_recovery_broadcast
    wait_vtep_routes_at_least 2 "$PE1_IP" ".mac == \"${CE_MAC}\"" 1 120 \
        || mark_failure "cycle $cycle: pe1 CE MAC Type 2 did not return"
    wait_ping 90 || mark_failure "cycle $cycle: ping did not recover after pe1 revert"
    sample recovered "$blackout_ms" "$release_ms"

    cycle_log "cycle=${cycle} done blackout_ms=${blackout_ms} release_ms=${release_ms} failures=${failures}"
    while [ "$(date +%s)" -lt $((cycle_start + CYCLE_INTERVAL_SEC)) ] && [ "$(date +%s)" -lt "$end_epoch" ]; do
        sample_if_due idle
        sleep 1
    done
}

finish() {
    collect_daemon_logs
    log "Analyzing $SAMPLES_CSV"
    if python3 "$SOAK_SCRIPT_DIR/analyze-m67-link-drain-soak.py" "$SAMPLES_CSV" \
        --output "$REPORT_JSON"; then
        log "Analyzer verdict: pass"
    else
        mark_failure "analyzer verdict failed"
    fi
    log "Run artifacts: $RUN_DIR"
    if [ "$failures" -eq 0 ]; then
        log "PASS: M67 link-drain churn soak completed $cycle cycles with no harness failures"
    else
        log "FAIL: M67 link-drain churn soak completed $cycle cycles with $failures failure(s)"
        exit 1
    fi
}

bootstrap
log "Starting M67 link-drain churn soak for ${SOAK_SECONDS}s (cycle interval ${CYCLE_INTERVAL_SEC}s)"
while [ "$(date +%s)" -lt "$end_epoch" ]; do
    run_cycle
done
finish
