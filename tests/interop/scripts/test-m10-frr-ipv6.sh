#!/usr/bin/env bash
# M10 interop test — rustbgpd ↔ FRR dual-stack (MP-BGP / IPv6 unicast)
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m10-frr-ipv6.clab.yml
#   - grpcurl installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m10-frr-ipv6.sh

set -euo pipefail

TOPO="m10-frr-ipv6"
RUSTBGPD="clab-${TOPO}-rustbgpd"
FRR="clab-${TOPO}-frr"
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

grpc_list_routes() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

grpc_list_routes_for_peer() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"neighbor_address\": \"$1\"}" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

grpc_list_best_routes() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListBestRoutes 2>/dev/null
}

# ---------------------------------------------------------------------------
# Wait for BGP session to reach Established
# ---------------------------------------------------------------------------
wait_established() {
    log "Waiting for BGP session to reach Established..."
    for i in $(seq 1 45); do
        local state
        state=$(docker exec "$FRR" vtysh -c "show bgp neighbors 10.0.0.1 json" 2>/dev/null \
            | grep -o '"bgpState":"[^"]*"' | head -1 | cut -d'"' -f4 || true)
        if [ "$state" = "Established" ]; then
            ok "Session established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "Session did not reach Established within 90s"
    return 1
}

# Wait for routes to appear in the RIB
wait_routes() {
    local expected=$1
    log "Waiting for $expected routes in RIB..."
    for i in $(seq 1 15); do
        local count
        count=$(grpc_list_routes | grep -c '"prefix"' || true)
        if [ "$count" -ge "$expected" ]; then
            ok "Got $count routes in RIB (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "Expected $expected routes, got $(grpc_list_routes | grep -c '"prefix"' || echo 0)"
    return 1
}

# Start rustbgpd inside the container (CMD is sleep infinity)
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
}

# ---------------------------------------------------------------------------
# Test 1: Session establishes with MP-BGP IPv6 capability
# ---------------------------------------------------------------------------
test_session_with_ipv6_cap() {
    log "Test 1: Session establishes with MP-BGP IPv6 unicast capability"

    wait_established || return 1

    # Verify FRR sees the IPv6 unicast AFI/SAFI negotiated
    local caps
    caps=$(docker exec "$FRR" vtysh -c "show bgp neighbors 10.0.0.1 json" 2>/dev/null || true)

    if echo "$caps" | grep -q "ipv6Unicast"; then
        ok "IPv6 unicast AFI/SAFI negotiated"
    else
        fail "IPv6 unicast AFI/SAFI not negotiated"
    fi
}

# ---------------------------------------------------------------------------
# Test 2: IPv4 prefixes received (backward compatibility)
# ---------------------------------------------------------------------------
test_ipv4_routes_received() {
    log "Test 2: IPv4 routes received (backward compatibility)"

    wait_routes 4 || return 1

    local routes
    routes=$(grpc_list_routes_for_peer "10.0.0.2")

    for prefix in "192.168.1.0" "10.10.0.0"; do
        if echo "$routes" | grep -q "\"prefix\": \"$prefix\""; then
            ok "IPv4 prefix $prefix present"
        else
            fail "IPv4 prefix $prefix missing"
        fi
    done
}

# ---------------------------------------------------------------------------
# Test 3: IPv6 prefixes received via MP_REACH_NLRI
# ---------------------------------------------------------------------------
test_ipv6_routes_received() {
    log "Test 3: IPv6 routes received via MP_REACH_NLRI"

    local routes
    routes=$(grpc_list_routes_for_peer "10.0.0.2")

    for prefix in "2001:db8:1::" "2001:db8:2::"; do
        if echo "$routes" | grep -q "\"prefix\": \"$prefix\""; then
            ok "IPv6 prefix $prefix present"
        else
            fail "IPv6 prefix $prefix missing"
        fi
    done
}

# ---------------------------------------------------------------------------
# Test 4: IPv6 routes appear in best routes (Loc-RIB)
# ---------------------------------------------------------------------------
test_ipv6_best_routes() {
    log "Test 4: IPv6 routes in best routes (Loc-RIB)"

    local best
    best=$(grpc_list_best_routes)

    for prefix in "2001:db8:1::" "2001:db8:2::"; do
        if echo "$best" | grep -q "\"prefix\": \"$prefix\""; then
            ok "IPv6 prefix $prefix in best routes"
        else
            fail "IPv6 prefix $prefix not in best routes"
        fi
    done
}

# ---------------------------------------------------------------------------
# Test 5: IPv6 route withdrawal
# ---------------------------------------------------------------------------
test_ipv6_withdrawal() {
    log "Test 5: IPv6 route withdrawal"

    # Withdraw 2001:db8:2::/48 from FRR
    docker exec "$FRR" vtysh -c "conf t" -c "router bgp 65002" \
        -c "address-family ipv6 unicast" -c "no network 2001:db8:2::/48" \
        -c "end" 2>/dev/null

    log "Waiting for withdrawal to propagate..."
    sleep 5

    local routes
    routes=$(grpc_list_routes_for_peer "10.0.0.2")

    if echo "$routes" | grep -q '"prefix": "2001:db8:2::"'; then
        fail "2001:db8:2::/48 still present after withdrawal"
    else
        ok "2001:db8:2::/48 withdrawn"
    fi

    # Other routes (IPv4 + remaining IPv6) should still be present
    if echo "$routes" | grep -q '"prefix": "2001:db8:1::"'; then
        ok "2001:db8:1::/48 still present"
    else
        fail "2001:db8:1::/48 unexpectedly removed"
    fi

    if echo "$routes" | grep -q '"prefix": "192.168.1.0"'; then
        ok "IPv4 192.168.1.0/24 still present"
    else
        fail "IPv4 192.168.1.0/24 unexpectedly removed"
    fi

    # Re-add the route for clean state
    docker exec "$FRR" vtysh -c "conf t" -c "router bgp 65002" \
        -c "address-family ipv6 unicast" -c "network 2001:db8:2::/48" \
        -c "end" 2>/dev/null
    sleep 3
}

# ---------------------------------------------------------------------------
# Test 6: Route injection via gRPC (IPv6)
# ---------------------------------------------------------------------------
test_ipv6_injection() {
    log "Test 6: IPv6 route injection via gRPC"

    local result
    result=$(grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d '{
            "prefix": "2001:db8:ff::",
            "prefix_length": 48,
            "next_hop": "fd00::1",
            "origin": 0,
            "as_path": [65001],
            "local_pref": 100
        }' \
        "$GRPC_ADDR" rustbgpd.v1.InjectionService/AddPath 2>&1 || true)

    sleep 2

    local best
    best=$(grpc_list_best_routes)

    if echo "$best" | grep -q '"prefix": "2001:db8:ff::"'; then
        ok "Injected IPv6 prefix 2001:db8:ff::/48 in best routes"
    else
        fail "Injected IPv6 prefix 2001:db8:ff::/48 not found in best routes"
    fi

    # Clean up: withdraw injected route
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d '{
            "prefix": "2001:db8:ff::",
            "prefix_length": 48
        }' \
        "$GRPC_ADDR" rustbgpd.v1.InjectionService/DeletePath 2>/dev/null || true
    sleep 2
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "M10 interop test: rustbgpd ↔ FRR (MP-BGP / IPv6 unicast)"
    log "Topology: $TOPO"

    resolve_grpc_addr
    start_rustbgpd

    test_session_with_ipv6_cap
    test_ipv4_routes_received
    test_ipv6_routes_received
    test_ipv6_best_routes
    test_ipv6_withdrawal
    test_ipv6_injection

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
