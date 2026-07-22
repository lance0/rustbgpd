#!/usr/bin/env bash
# M26 interop test — Cease subcode compatibility with FRR
#
# Validates:
#   1. Session establishes initially
#   2. FRR sends 3 prefixes, exceeding max_prefixes=2
#   3. rustbgpd sends Cease/1 (Max Prefixes) NOTIFICATION
#   4. FRR sees the NOTIFICATION and session tears down
#   5. Prometheus metric records the max-prefix event
#   6. The peer stays administratively down beyond two retry intervals
#   7. Enable while still over-limit re-latches the peer
#   8. Removing excess routes alone does not recover the peer
#   9. Explicit enable after removal re-establishes with two prefixes
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m26-cease-frr.clab.yml
#   - grpcurl installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m26-cease-frr.sh


TOPO="m26-cease-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
source "$SCRIPT_DIR/test-lib.sh"
FRR="clab-${TOPO}-frr"


grpc_metrics() {
    grpcurl_call \
        "$GRPC_ADDR" rustbgpd.v1.ControlService/GetMetrics 2>/dev/null
}

grpc_neighbor_state() {
    grpcurl_call \
        -d '{"address": "10.0.0.2"}' \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/GetNeighborState 2>/dev/null
}

grpc_enable_neighbor() {
    grpcurl_call \
        -d '{"address": "10.0.0.2"}' \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/EnableNeighbor >/dev/null
}

frr_state() {
    docker exec "$FRR" vtysh -c "show bgp neighbors 10.0.0.1 json" 2>/dev/null \
        | grep -o '"bgpState":"[^"]*"' | head -1 | cut -d'"' -f4 || true
}

max_prefix_metric_value() {
    grpc_metrics | python3 -c '
import json, re, sys
text = json.load(sys.stdin).get("prometheusText", "")
values = [float(match.group(1)) for match in re.finditer(
    r"^bgp_max_prefix_exceeded_total(?:\{[^}]*\})?\s+([0-9.eE+-]+)$",
    text,
    re.MULTILINE,
)]
print(int(sum(values)))
' 2>/dev/null || echo 0
}

wait_latched_down() {
    local minimum_metric="$1"
    for _ in $(seq 1 30); do
        local state error metric
        state=$(grpc_neighbor_state || true)
        error=$(echo "$state" | python3 -c '
import json, sys
print(json.load(sys.stdin)["lastError"])
' 2>/dev/null || echo parse-error)
        metric=$(max_prefix_metric_value)
        if echo "$error" | grep -qi "max-prefix limit exceeded" \
            && [ "$metric" -ge "$minimum_metric" ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# Use the standardized `start_rustbgpd` from test-lib.sh — handles
# both the /proc poll loop and the gRPC-ready wait.

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

test_session_establishes() {
    log "Test 1: Session establishes at the exact two-prefix bound"

    for i in $(seq 1 30); do
        local state prefix_count
        state=$(frr_state)
        if [ "$state" = "Established" ]; then
            prefix_count=$(grpc_neighbor_state | python3 -c '
import json, sys
value = json.load(sys.stdin)["prefixesReceived"]
print(int(value))
' 2>/dev/null || echo parse-error)
            if [ "$prefix_count" = "2" ]; then
                ok "Session is Established with exactly two accepted prefixes (attempt $i)"
                return 0
            fi
        fi
        sleep 2
    done
    fail "Session never held Established with exactly two prefixes within 60s"
}

inject_excess_prefix() {
    log "Injecting third FRR prefix to cross max_prefixes=2"
    docker exec "$FRR" vtysh \
        -c "configure terminal" \
        -c "router bgp 65002" \
        -c "address-family ipv4 unicast" \
        -c "network 10.10.0.0/16" >/dev/null 2>&1 || true
    if ! docker exec "$FRR" vtysh -c "show running-config" 2>/dev/null \
        | grep -q '^  network 10\.10\.0\.0/16$'; then
        fail "FRR did not install the third network statement"
        return 1
    fi
}

test_cease_notification_sent() {
    log "Test 2: Cease NOTIFICATION sent (max_prefixes exceeded)"

    # Wait for FRR to see the notification — session should bounce
    for i in $(seq 1 30); do
        local neighbor
        neighbor=$(docker exec "$FRR" vtysh -c "show bgp neighbors 10.0.0.1" 2>/dev/null || true)

        if echo "$neighbor" \
            | grep -Fq 'Notification received (Cease/Maximum Number of Prefixes Reached)'; then
            ok "FRR received Cease/Maximum Number of Prefixes Reached"
            return 0
        fi

        sleep 2
    done
    fail "FRR did not report Cease NOTIFICATION within 60s"
    log "DEBUG FRR neighbor state:"
    docker exec "$FRR" vtysh -c "show bgp neighbors 10.0.0.1" 2>/dev/null | grep -i "notif\|cease\|reset\|error\|last" || true
}

test_max_prefix_metric() {
    log "Test 3: Prometheus max-prefix-exceeded metric"

    local value
    value=$(max_prefix_metric_value)
    if [ "$value" -ge 1 ]; then
        ok "bgp_max_prefix_exceeded_total incremented (value=$value)"
    else
        fail "bgp_max_prefix_exceeded_total did not increment"
    fi
}

test_session_latches_down() {
    log "Test 4: max-prefix breach latches the peer administratively down"

    if wait_latched_down 1; then
        ok "Manager owns an actionable max-prefix latch reason"
    else
        fail "Peer did not enter the max-prefix disabled latch"
        return
    fi

    local metric_before
    metric_before=$(max_prefix_metric_value)
    # PeerManager configures a 5 s retry interval. Twelve seconds covers more
    # than two intervals and catches the old auto-reconnect/bounce behavior.
    sleep 12
    local metric_after state
    metric_after=$(max_prefix_metric_value)
    state=$(frr_state)
    if [ "$state" = "Established" ]; then
        fail "Session re-established without explicit enable"
    elif [ "$metric_after" -ne "$metric_before" ]; then
        fail "Max-prefix metric advanced while peer should remain latched ($metric_before -> $metric_after)"
    else
        ok "Peer stayed down beyond two retry intervals (FRR state=${state:-unknown})"
    fi
}

test_enable_while_over_limit_relatches() {
    log "Test 5: explicit enable while still over-limit re-latches"
    local expected
    expected=$(( $(max_prefix_metric_value) + 1 ))
    if ! grpc_enable_neighbor; then
        fail "EnableNeighbor RPC failed"
        return
    fi
    if wait_latched_down "$expected"; then
        ok "Three-prefix replay exceeded the bound again and restored the disabled latch"
    else
        fail "Over-limit explicit enable did not re-latch the peer"
    fi
}

test_recovery_requires_removal_and_enable() {
    log "Test 6: recovery requires excess removal plus explicit enable"
    local metric_before
    metric_before=$(max_prefix_metric_value)
    docker exec "$FRR" vtysh \
        -c "configure terminal" \
        -c "router bgp 65002" \
        -c "address-family ipv4 unicast" \
        -c "no network 10.10.0.0/16" >/dev/null 2>&1 || true
    if docker exec "$FRR" vtysh -c "show running-config" 2>/dev/null \
        | grep -q '^  network 10\.10\.0\.0/16$'; then
        fail "FRR retained the third network statement after removal"
        return
    fi

    sleep 12
    if [ "$(frr_state)" = "Established" ]; then
        fail "Removing the excess route bypassed the explicit-enable latch"
        return
    fi
    local error metric_after
    error=$(grpc_neighbor_state | python3 -c '
import json, sys
print(json.load(sys.stdin)["lastError"])
' 2>/dev/null || echo parse-error)
    metric_after=$(max_prefix_metric_value)
    if ! echo "$error" | grep -qi "max-prefix limit exceeded"; then
        fail "Manager-owned max-prefix last_error disappeared before explicit enable"
        return
    elif [ "$metric_after" -ne "$metric_before" ]; then
        fail "Max-prefix metric advanced after removal without enable ($metric_before -> $metric_after)"
        return
    fi
    ok "Excess removal alone preserved the manager-owned latch"

    if ! grpc_enable_neighbor; then
        fail "EnableNeighbor RPC failed after excess removal"
        return
    fi
    for _ in $(seq 1 30); do
        local state prefix_count
        state=$(frr_state)
        prefix_count=$(grpc_neighbor_state | python3 -c '
import json, sys
print(int(json.load(sys.stdin)["prefixesReceived"]))
' 2>/dev/null || echo parse-error)
        if [ "$state" = "Established" ] && [ "$prefix_count" = "2" ]; then
            ok "Session recovered only after explicit enable with two prefixes"
            return
        fi
        sleep 1
    done
    fail "Session did not recover with two prefixes after explicit enable"
}

test_frr_cease_subcode_acceptance() {
    log "Test 7: FRR accepted Cease subcode (no crash, clean teardown)"

    # Verify FRR is still running and healthy
    local frr_running
    frr_running=$(docker exec "$FRR" vtysh -c "show bgp summary json" 2>/dev/null || echo "error")

    if echo "$frr_running" | grep -q "routerId"; then
        ok "FRR still operational after receiving Cease"
    else
        fail "FRR not responding after Cease"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "M26 interop test: Cease subcode compatibility"
    log "Topology: $TOPO (max_prefixes=2, FRR starts at 2; test injects a third)"

    resolve_grpc_addr
    start_rustbgpd

    # Give the initial at-bound session time to converge.
    sleep 15

    test_session_establishes
    inject_excess_prefix || exit 1
    test_cease_notification_sent
    test_max_prefix_metric
    test_session_latches_down
    test_enable_while_over_limit_relatches
    test_recovery_requires_removal_and_enable
    test_frr_cease_subcode_acceptance

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
