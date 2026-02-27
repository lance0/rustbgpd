#!/usr/bin/env bash
# M3 interop test — rustbgpd ↔ 2× FRR (route redistribution + injection)
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m3-frr.clab.yml
#   - grpcurl installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m3-frr.sh

set -euo pipefail

TOPO="m3-frr"
RUSTBGPD="clab-${TOPO}-rustbgpd"
FRR_A="clab-${TOPO}-frr-a"
FRR_B="clab-${TOPO}-frr-b"
PROTO="proto/rustbgpd.proto"
GRPC_ADDR=""

pass=0
fail=0

log()  { printf "\033[1;34m[TEST]\033[0m %s\n" "$*"; }
ok()   { pass=$((pass + 1)); printf "\033[1;32m  PASS\033[0m %s\n" "$*"; }
fail() { fail=$((fail + 1)); printf "\033[1;31m  FAIL\033[0m %s\n" "$*"; }

# Resolve rustbgpd container management IP for gRPC access
resolve_grpc_addr() {
    local ip
    ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$RUSTBGPD" 2>/dev/null || true)
    if [ -z "$ip" ]; then
        echo "ERROR: cannot resolve management IP for $RUSTBGPD" >&2
        exit 1
    fi
    GRPC_ADDR="${ip}:50051"
    log "gRPC endpoint: $GRPC_ADDR"
}

grpc_list_received() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

grpc_list_best() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListBestRoutes 2>/dev/null
}

grpc_list_advertised() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"neighbor_address\": \"$1\"}" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListAdvertisedRoutes 2>/dev/null
}

grpc_add_path() {
    local prefix=$1 prefix_len=$2 next_hop=$3
    shift 3
    local origin=${1:-0}
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"prefix\": \"$prefix\", \"prefix_length\": $prefix_len, \"next_hop\": \"$next_hop\", \"origin\": $origin}" \
        "$GRPC_ADDR" rustbgpd.v1.InjectionService/AddPath 2>/dev/null
}

grpc_delete_path() {
    local prefix=$1 prefix_len=$2
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"prefix\": \"$prefix\", \"prefix_length\": $prefix_len}" \
        "$GRPC_ADDR" rustbgpd.v1.InjectionService/DeletePath 2>/dev/null
}

# ---------------------------------------------------------------------------
# Wait for BGP sessions to reach Established
# ---------------------------------------------------------------------------
wait_established_a() {
    log "Waiting for FRR-A session to reach Established..."
    for i in $(seq 1 45); do
        local state
        state=$(docker exec "$FRR_A" vtysh -c "show bgp neighbors 10.0.0.1 json" 2>/dev/null \
            | grep -o '"bgpState":"[^"]*"' | head -1 | cut -d'"' -f4 || true)
        if [ "$state" = "Established" ]; then
            ok "FRR-A session established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "FRR-A session did not reach Established within 90s"
    return 1
}

wait_established_b() {
    log "Waiting for FRR-B session to reach Established..."
    for i in $(seq 1 45); do
        local state
        state=$(docker exec "$FRR_B" vtysh -c "show bgp neighbors 10.0.1.1 json" 2>/dev/null \
            | grep -o '"bgpState":"[^"]*"' | head -1 | cut -d'"' -f4 || true)
        if [ "$state" = "Established" ]; then
            ok "FRR-B session established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "FRR-B session did not reach Established within 90s"
    return 1
}

wait_routes_in_rib() {
    local expected=$1
    log "Waiting for $expected received routes in RIB..."
    for i in $(seq 1 15); do
        local count
        count=$(grpc_list_received | grep -c '"prefix"' || true)
        if [ "$count" -ge "$expected" ]; then
            ok "Got $count received routes in RIB (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "Expected $expected received routes, got $(grpc_list_received | grep -c '"prefix"' || echo 0)"
    return 1
}

# Check if FRR-B has received a specific prefix from rustbgpd
frr_b_has_prefix() {
    local prefix=$1
    docker exec "$FRR_B" vtysh -c "show bgp ipv4 unicast $prefix json" 2>/dev/null \
        | grep -q '"prefix"' 2>/dev/null
}

# ---------------------------------------------------------------------------
# Test 1: Route redistribution — FRR-A → rustbgpd → FRR-B
# ---------------------------------------------------------------------------
test_route_redistribution() {
    log "Test 1: Route redistribution (FRR-A → rustbgpd → FRR-B)"

    wait_established_a || return 1
    wait_established_b || return 1
    wait_routes_in_rib 3 || return 1

    # Wait for outbound distribution to FRR-B
    log "Waiting for routes to propagate to FRR-B..."
    local found=false
    for i in $(seq 1 15); do
        if frr_b_has_prefix "192.168.1.0/24"; then
            found=true
            break
        fi
        sleep 2
    done

    if [ "$found" = "true" ]; then
        ok "FRR-B received 192.168.1.0/24 from rustbgpd"
    else
        fail "FRR-B did not receive 192.168.1.0/24"
    fi

    # Check all 3 prefixes
    for prefix in "192.168.2.0/24" "10.10.0.0/16"; do
        if frr_b_has_prefix "$prefix"; then
            ok "FRR-B received $prefix"
        else
            fail "FRR-B missing $prefix"
        fi
    done

    # Verify attributes on FRR-B: AS_PATH should contain 65001 (rustbgpd) + 65002 (FRR-A)
    local as_path
    as_path=$(docker exec "$FRR_B" vtysh -c "show bgp ipv4 unicast 192.168.1.0/24 json" 2>/dev/null || true)
    if echo "$as_path" | grep -q "65001"; then
        ok "AS_PATH on FRR-B contains 65001 (rustbgpd)"
    else
        fail "AS_PATH on FRR-B missing 65001"
    fi
    if echo "$as_path" | grep -q "65002"; then
        ok "AS_PATH on FRR-B contains 65002 (FRR-A)"
    else
        fail "AS_PATH on FRR-B missing 65002"
    fi
}

# ---------------------------------------------------------------------------
# Test 2: Split horizon — FRR-A does NOT receive back its own routes
# ---------------------------------------------------------------------------
test_split_horizon() {
    log "Test 2: Split horizon (FRR-A should not receive its own routes back)"

    # Check Adj-RIB-Out for FRR-A — should be empty (all routes came from A)
    local advertised
    advertised=$(grpc_list_advertised "10.0.0.2" || echo "{}")
    local count
    count=$(echo "$advertised" | grep -c '"prefix"' || true)

    if [ "$count" -eq 0 ]; then
        ok "No routes advertised back to FRR-A (split horizon works)"
    else
        fail "Split horizon violated: $count routes advertised to FRR-A"
    fi
}

# ---------------------------------------------------------------------------
# Test 3: Route injection via gRPC — AddPath + redistribution
# ---------------------------------------------------------------------------
test_route_injection() {
    log "Test 3: Route injection via gRPC AddPath"

    # Inject a route
    local result
    result=$(grpc_add_path "172.16.0.0" 16 "10.0.0.1" 0 || echo "ERROR")
    if echo "$result" | grep -q "uuid"; then
        ok "AddPath returned uuid"
    else
        fail "AddPath failed: $result"
    fi

    # Wait for best routes to include our injected route
    sleep 3
    local best
    best=$(grpc_list_best)
    if echo "$best" | grep -q '"prefix": "172.16.0.0"'; then
        ok "Injected route in Loc-RIB"
    else
        fail "Injected route not in Loc-RIB"
    fi

    # Both FRR-A and FRR-B should receive the injected route
    log "Waiting for injected route to propagate..."
    sleep 3

    if frr_b_has_prefix "172.16.0.0/16"; then
        ok "FRR-B received injected route 172.16.0.0/16"
    else
        fail "FRR-B did not receive injected route 172.16.0.0/16"
    fi

    local frr_a_routes
    frr_a_routes=$(docker exec "$FRR_A" vtysh -c "show bgp ipv4 unicast 172.16.0.0/16 json" 2>/dev/null || true)
    if echo "$frr_a_routes" | grep -q '"prefix"'; then
        ok "FRR-A received injected route 172.16.0.0/16"
    else
        fail "FRR-A did not receive injected route 172.16.0.0/16"
    fi
}

# ---------------------------------------------------------------------------
# Test 4: Withdrawal propagation — FRR-A withdraws → FRR-B sees withdrawal
# ---------------------------------------------------------------------------
test_withdrawal_propagation() {
    log "Test 4: Withdrawal propagation (FRR-A → rustbgpd → FRR-B)"

    # Withdraw 192.168.2.0/24 from FRR-A
    docker exec "$FRR_A" vtysh -c "conf t" -c "router bgp 65002" \
        -c "address-family ipv4 unicast" -c "no network 192.168.2.0/24" \
        -c "end" 2>/dev/null

    log "Waiting for withdrawal to propagate..."
    sleep 5

    # FRR-B should no longer have the prefix
    if frr_b_has_prefix "192.168.2.0/24"; then
        fail "FRR-B still has 192.168.2.0/24 after withdrawal"
    else
        ok "192.168.2.0/24 withdrawn from FRR-B"
    fi

    # Other routes should still be present on FRR-B
    if frr_b_has_prefix "192.168.1.0/24"; then
        ok "192.168.1.0/24 still present on FRR-B"
    else
        fail "192.168.1.0/24 unexpectedly removed from FRR-B"
    fi

    # Re-add the route
    docker exec "$FRR_A" vtysh -c "conf t" -c "router bgp 65002" \
        -c "address-family ipv4 unicast" -c "network 192.168.2.0/24" \
        -c "end" 2>/dev/null
    sleep 3
}

# ---------------------------------------------------------------------------
# Test 5: DeletePath — withdrawal propagated to all peers
# ---------------------------------------------------------------------------
test_delete_path() {
    log "Test 5: DeletePath via gRPC"

    # Delete the injected route from test 3
    local result
    result=$(grpc_delete_path "172.16.0.0" 16 || echo "ERROR")

    sleep 3

    # Should be gone from Loc-RIB
    local best
    best=$(grpc_list_best)
    if echo "$best" | grep -q '"prefix": "172.16.0.0"'; then
        fail "Injected route still in Loc-RIB after DeletePath"
    else
        ok "Injected route removed from Loc-RIB"
    fi

    # Should be withdrawn from FRR-B
    if frr_b_has_prefix "172.16.0.0/16"; then
        fail "FRR-B still has 172.16.0.0/16 after DeletePath"
    else
        ok "172.16.0.0/16 withdrawn from FRR-B"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "M3 interop test: rustbgpd ↔ 2× FRR"
    log "Topology: $TOPO"

    resolve_grpc_addr

    test_route_redistribution
    test_split_horizon
    test_route_injection
    test_withdrawal_propagation
    test_delete_path

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
