#!/usr/bin/env bash
# M22 interop test — FlowSpec injection and distribution to FRR
#
# Validates:
#   1. BGP session establishes with FlowSpec capability negotiated
#   2. FlowSpec rule injected via gRPC appears in rustbgpd Loc-RIB
#   3. FRR receives the FlowSpec rule via eBGP
#   4. Second rule injected, both visible on both sides
#   5. Withdrawal of first rule propagates to FRR
#   6. Second rule survives the withdrawal
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m22-flowspec-frr.clab.yml
#   - grpcurl installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m22-flowspec-frr.sh


TOPO="m22-flowspec-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"
FRR="clab-${TOPO}-frr"


# ---------------------------------------------------------------------------
# gRPC helpers
# ---------------------------------------------------------------------------

grpc_add_flowspec() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "$1" \
        "$GRPC_ADDR" rustbgpd.v1.InjectionService/AddFlowSpec 2>/dev/null
}

grpc_delete_flowspec() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "$1" \
        "$GRPC_ADDR" rustbgpd.v1.InjectionService/DeleteFlowSpec 2>/dev/null
}

grpc_list_flowspec() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d '{"afiSafi": "ADDRESS_FAMILY_IPV4_FLOWSPEC"}' \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListFlowSpecRoutes 2>/dev/null
}


# ---------------------------------------------------------------------------
# FlowSpec rule payloads
# ---------------------------------------------------------------------------

# Rule 1: Drop TCP/80 to 192.168.1.0/24
RULE1_ADD='{
  "afiSafi": "ADDRESS_FAMILY_IPV4_FLOWSPEC",
  "components": [
    {"type": 1, "prefix": "192.168.1.0/24"},
    {"type": 3, "value": "=6"},
    {"type": 5, "value": "=80"}
  ],
  "actions": [
    {"trafficRate": {"rate": 0.0}}
  ]
}'

RULE1_DELETE='{
  "afiSafi": "ADDRESS_FAMILY_IPV4_FLOWSPEC",
  "components": [
    {"type": 1, "prefix": "192.168.1.0/24"},
    {"type": 3, "value": "=6"},
    {"type": 5, "value": "=80"}
  ]
}'

# Rule 2: Rate-limit UDP/53 to 10.0.0.0/8 at 1000 bytes/sec
RULE2_ADD='{
  "afiSafi": "ADDRESS_FAMILY_IPV4_FLOWSPEC",
  "components": [
    {"type": 1, "prefix": "10.0.0.0/8"},
    {"type": 3, "value": "=17"},
    {"type": 5, "value": "=53"}
  ],
  "actions": [
    {"trafficRate": {"rate": 1000.0}}
  ]
}'

# ---------------------------------------------------------------------------
# Wait helpers
# ---------------------------------------------------------------------------

wait_established() {
    log "Waiting for BGP session to reach Established..."
    for i in $(seq 1 45); do
        local state
        state=$(docker exec "$FRR" vtysh -c "show bgp neighbors 10.0.0.1 json" 2>/dev/null \
            | grep -o '"bgpState":"[^"]*"' | head -1 | cut -d'"' -f4 || true)
        if [ "$state" = "Established" ]; then
            ok "BGP session established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "BGP session did not reach Established within 90s"
    return 1
}

start_rustbgpd() {
    log "Starting rustbgpd daemon..."
    docker exec -d "$RUSTBGPD" /usr/local/bin/start-rustbgpd.sh
    sleep 3
    if docker exec "$RUSTBGPD" sh -c 'cat /proc/*/comm 2>/dev/null' | grep -q rustbgpd; then
        log "rustbgpd is running"
    else
        echo "ERROR: rustbgpd failed to start" >&2
        exit 1
    fi

    log "Waiting for gRPC to become available..."
    for i in $(seq 1 15); do
        if grpc_health >/dev/null 2>&1; then
            ok "gRPC endpoint ready (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "gRPC endpoint not reachable within 30s"
    return 1
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

test_flowspec_capability() {
    log "Test 1: FlowSpec capability negotiated"

    local caps
    caps=$(docker exec "$FRR" vtysh -c "show bgp neighbors 10.0.0.1" 2>/dev/null || true)
    if echo "$caps" | grep -qi "ipv4 Flowspec"; then
        ok "FlowSpec capability negotiated with FRR"
    else
        # Try JSON output
        local json_caps
        json_caps=$(docker exec "$FRR" vtysh -c "show bgp neighbors 10.0.0.1 json" 2>/dev/null || true)
        if echo "$json_caps" | grep -qi "flowspec"; then
            ok "FlowSpec capability negotiated (JSON output)"
        else
            fail "FlowSpec capability not found in neighbor output"
            log "DEBUG neighbor output:"
            echo "$caps" | grep -i "family\|flowspec\|capability" || true
        fi
    fi
}

test_inject_rule1() {
    log "Test 2: Inject FlowSpec rule 1 (drop TCP/80 to 192.168.1.0/24)"

    grpc_add_flowspec "$RULE1_ADD"
    sleep 2

    local fs_routes
    fs_routes=$(grpc_list_flowspec)

    if echo "$fs_routes" | grep -q "192.168.1.0"; then
        ok "Rule 1 present in rustbgpd FlowSpec Loc-RIB"
    else
        fail "Rule 1 not found in rustbgpd FlowSpec Loc-RIB"
        log "DEBUG FlowSpec RIB: $fs_routes"
    fi
}

test_frr_receives_rule1() {
    log "Test 3: FRR receives FlowSpec rule 1"

    for i in $(seq 1 15); do
        local frr_fs
        frr_fs=$(docker exec "$FRR" vtysh -c "show bgp ipv4 flowspec" 2>/dev/null || true)
        if echo "$frr_fs" | grep -qi "192.168.1.0"; then
            ok "FRR received FlowSpec rule for 192.168.1.0/24 (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "FRR did not receive FlowSpec rule 1 within 30s"
    log "DEBUG FRR flowspec table:"
    docker exec "$FRR" vtysh -c "show bgp ipv4 flowspec" 2>/dev/null || true
}

test_inject_rule2() {
    log "Test 4: Inject FlowSpec rule 2 (rate-limit UDP/53 to 10.0.0.0/8)"

    grpc_add_flowspec "$RULE2_ADD"
    sleep 2

    local fs_routes
    fs_routes=$(grpc_list_flowspec)

    local count
    count=$(echo "$fs_routes" | python3 -c "
import sys, json
resp = json.load(sys.stdin)
print(len(resp.get('routes', [])))
" 2>/dev/null || echo 0)

    if [ "$count" -ge 2 ]; then
        ok "Both rules present in rustbgpd FlowSpec Loc-RIB (count=$count)"
    else
        fail "Expected 2 FlowSpec rules in rustbgpd, got $count"
    fi
}

test_frr_receives_both() {
    log "Test 5: FRR receives both FlowSpec rules"

    for i in $(seq 1 15); do
        local frr_fs
        frr_fs=$(docker exec "$FRR" vtysh -c "show bgp ipv4 flowspec" 2>/dev/null || true)
        local has_rule1=false
        local has_rule2=false
        echo "$frr_fs" | grep -qi "192.168.1.0" && has_rule1=true
        echo "$frr_fs" | grep -qi "10.0.0.0" && has_rule2=true

        if [ "$has_rule1" = true ] && [ "$has_rule2" = true ]; then
            ok "FRR has both FlowSpec rules (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "FRR does not have both FlowSpec rules within 30s"
    docker exec "$FRR" vtysh -c "show bgp ipv4 flowspec" 2>/dev/null || true
}

test_withdraw_rule1() {
    log "Test 6: Withdraw FlowSpec rule 1"

    grpc_delete_flowspec "$RULE1_DELETE"
    sleep 3

    local fs_routes
    fs_routes=$(grpc_list_flowspec)

    if echo "$fs_routes" | grep -q "192.168.1.0"; then
        fail "Rule 1 still present in rustbgpd after deletion"
    else
        ok "Rule 1 withdrawn from rustbgpd FlowSpec Loc-RIB"
    fi
}

test_frr_withdrawal_propagated() {
    log "Test 7: Withdrawal propagated to FRR, rule 2 survives"

    # Wait for rule 1 to disappear from FRR
    for i in $(seq 1 15); do
        local frr_fs
        frr_fs=$(docker exec "$FRR" vtysh -c "show bgp ipv4 flowspec" 2>/dev/null || true)
        if ! echo "$frr_fs" | grep -qi "192.168.1.0"; then
            ok "Rule 1 withdrawn from FRR (attempt $i)"
            break
        fi
        if [ "$i" -eq 15 ]; then
            fail "FRR still has rule 1 after withdrawal (30s timeout)"
            return 1
        fi
        sleep 2
    done

    # Give FRR a moment to settle, then check rule 2 separately
    sleep 2
    for i in $(seq 1 10); do
        local frr_fs
        frr_fs=$(docker exec "$FRR" vtysh -c "show bgp ipv4 flowspec" 2>/dev/null || true)
        if echo "$frr_fs" | grep -qi "10.0.0.0"; then
            ok "Rule 2 still present on FRR after rule 1 withdrawal (attempt $i)"
            break
        fi
        if [ "$i" -eq 10 ]; then
            fail "Rule 2 not found on FRR after rule 1 withdrawal"
        fi
        sleep 2
    done

    # Verify rule 2 in rustbgpd
    local fs_routes
    fs_routes=$(grpc_list_flowspec)
    local count
    count=$(echo "$fs_routes" | python3 -c "
import sys, json
resp = json.load(sys.stdin)
print(len(resp.get('routes', [])))
" 2>/dev/null || echo 0)

    if [ "$count" -eq 1 ]; then
        ok "Exactly 1 FlowSpec rule remains in rustbgpd"
    else
        fail "Expected 1 FlowSpec rule in rustbgpd, got $count"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "M22 interop test: FlowSpec injection and distribution"
    log "Topology: $TOPO"

    resolve_grpc_addr
    start_rustbgpd

    wait_established || exit 1

    test_flowspec_capability
    test_inject_rule1
    test_frr_receives_rule1
    test_inject_rule2
    test_frr_receives_both
    test_withdraw_rule1
    test_frr_withdrawal_propagated

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
