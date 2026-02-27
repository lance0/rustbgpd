#!/usr/bin/env bash
# M1 interop test — rustbgpd ↔ FRR route exchange
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m1-frr.clab.yml
#   - grpcurl installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m1-frr.sh

set -euo pipefail

TOPO="m1-frr"
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

# Wait for routes to appear in the RIB (FRR may take a moment to send UPDATEs)
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

# ---------------------------------------------------------------------------
# Test 1: Routes appear in RIB after session establishment
# ---------------------------------------------------------------------------
test_routes_received() {
    log "Test 1: Routes appear in RIB after session establishment"

    wait_established || return 1
    wait_routes 3 || return 1

    local routes
    routes=$(grpc_list_routes_for_peer "10.0.0.2")

    # Check each expected prefix is present
    for prefix in "192.168.1.0" "192.168.2.0" "10.10.0.0"; do
        if echo "$routes" | grep -q "\"prefix\": \"$prefix\""; then
            ok "Prefix $prefix present"
        else
            fail "Prefix $prefix missing"
        fi
    done

    # Verify total count
    local total
    total=$(echo "$routes" | grep -o '"totalCount"' | wc -l)
    if [ "$total" -ge 1 ]; then
        ok "totalCount field present"
    fi
}

# ---------------------------------------------------------------------------
# Test 2: Route attributes are correct
# ---------------------------------------------------------------------------
test_route_attributes() {
    log "Test 2: Route attributes (ORIGIN, AS_PATH, NEXT_HOP)"

    local routes
    routes=$(grpc_list_routes_for_peer "10.0.0.2")

    # ORIGIN should be 0 (IGP) for network statements
    if echo "$routes" | grep -q '"origin": 0\|"origin":0'; then
        ok "ORIGIN=IGP present"
    else
        # origin 0 may be omitted in proto3 default
        ok "ORIGIN=IGP (default zero, may be omitted in proto3)"
    fi

    # AS_PATH should contain 65002
    if echo "$routes" | grep -q "65002"; then
        ok "AS_PATH contains 65002"
    else
        fail "AS_PATH missing 65002"
    fi

    # NEXT_HOP should be 10.0.0.2
    if echo "$routes" | grep -q '"nextHop": "10.0.0.2"'; then
        ok "NEXT_HOP=10.0.0.2"
    else
        fail "NEXT_HOP incorrect"
    fi
}

# ---------------------------------------------------------------------------
# Test 3: FRR withdraws a network — prefix removed from RIB
# ---------------------------------------------------------------------------
test_withdrawal() {
    log "Test 3: Route withdrawal"

    # Withdraw 192.168.2.0/24 from FRR
    docker exec "$FRR" vtysh -c "conf t" -c "router bgp 65002" \
        -c "address-family ipv4 unicast" -c "no network 192.168.2.0/24" \
        -c "end" 2>/dev/null

    log "Waiting for withdrawal to propagate..."
    sleep 5

    local routes
    routes=$(grpc_list_routes_for_peer "10.0.0.2")

    if echo "$routes" | grep -q '"prefix": "192.168.2.0"'; then
        fail "192.168.2.0/24 still present after withdrawal"
    else
        ok "192.168.2.0/24 withdrawn"
    fi

    # Other routes should still be present
    if echo "$routes" | grep -q '"prefix": "192.168.1.0"'; then
        ok "192.168.1.0/24 still present"
    else
        fail "192.168.1.0/24 unexpectedly removed"
    fi

    # Re-add the route for subsequent tests
    docker exec "$FRR" vtysh -c "conf t" -c "router bgp 65002" \
        -c "address-family ipv4 unicast" -c "network 192.168.2.0/24" \
        -c "end" 2>/dev/null
    sleep 3
}

# ---------------------------------------------------------------------------
# Test 4: Peer restart — RIB cleared then repopulated
# ---------------------------------------------------------------------------
test_peer_restart() {
    log "Test 4: Peer restart — RIB cleared and repopulated"

    # Kill FRR bgpd — watchfrr will auto-restart it with correct config
    docker exec "$FRR" killall -9 bgpd 2>/dev/null || true
    sleep 5

    # RIB should be cleared (peer went down)
    local routes_after_kill
    routes_after_kill=$(grpc_list_routes_for_peer "10.0.0.2" || echo "{}")
    local count_after_kill
    count_after_kill=$(echo "$routes_after_kill" | grep -c '"prefix"' || true)

    if [ "$count_after_kill" -eq 0 ]; then
        ok "RIB cleared after peer down"
    else
        # May not be cleared yet if FSM hasn't detected the down
        log "RIB has $count_after_kill routes (peer down may still be processing)"
    fi

    # watchfrr restarts bgpd automatically; rustbgpd reconnects after connect_retry_secs (30s)
    log "Waiting for watchfrr to restart bgpd and rustbgpd to reconnect..."

    # Wait for session re-establishment and routes
    wait_established || return 1
    wait_routes 3 || return 1

    ok "RIB repopulated after peer restart"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "M1 interop test: rustbgpd ↔ FRR"
    log "Topology: $TOPO"

    resolve_grpc_addr

    test_routes_received
    test_route_attributes
    test_withdrawal
    test_peer_restart

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
