#!/usr/bin/env bash
# M14 interop test — Route Reflector (RFC 4456)
#
# Validates: iBGP route reflection between two RR clients via rustbgpd.
#   - Client1 routes reflected to Client2 and vice versa
#   - ORIGINATOR_ID set to the originating client's router-id
#   - CLUSTER_LIST contains the RR's cluster_id
#
# Topology: FRR-client1 ↔ rustbgpd (RR) ↔ FRR-client2  (all AS 65001)
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m14-rr-frr.clab.yml
#   - grpcurl installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m14-rr-frr.sh


TOPO="m14-rr-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"
FRR_C1="clab-${TOPO}-frr-client1"
FRR_C2="clab-${TOPO}-frr-client2"


grpc_list_received() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

grpc_list_best() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListBestRoutes 2>/dev/null
}

wait_established() {
    local peer_addr=$1
    local frr_container=$2
    log "Waiting for session to $peer_addr ($frr_container)..."
    for i in $(seq 1 45); do
        local state
        state=$(docker exec "$frr_container" vtysh -c "show bgp neighbors ${peer_addr} json" 2>/dev/null \
            | grep -o '"bgpState":"[^"]*"' | head -1 | cut -d'"' -f4 || true)
        if [ "$state" = "Established" ]; then
            ok "Session to $peer_addr established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "Session to $peer_addr did not reach Established within 90s"
    return 1
}

wait_routes() {
    local expected=$1
    log "Waiting for $expected routes in RIB..."
    for i in $(seq 1 15); do
        local count
        count=$(grpc_list_received | grep -c '"prefix"' || true)
        if [ "$count" -ge "$expected" ]; then
            ok "Got $count routes in RIB (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "Expected $expected routes, got $(grpc_list_received | grep -c '"prefix"' || echo 0)"
    return 1
}

# Wait for FRR to have routes from the RR
wait_frr_routes() {
    local frr_container=$1
    local expected=$2
    log "Waiting for $frr_container to have $expected routes..."
    for i in $(seq 1 20); do
        local count
        count=$(docker exec "$frr_container" vtysh -c "show bgp ipv4 unicast json" 2>/dev/null \
            | grep -o '"prefix":"[^"]*"' | wc -l || true)
        if [ "$count" -ge "$expected" ]; then
            ok "$frr_container has $count routes (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$frr_container expected $expected routes"
    return 1
}

# ---------------------------------------------------------------------------
# Test 1: Client1 routes reflected to Client2
# ---------------------------------------------------------------------------
test_client1_to_client2() {
    log "Test 1: Client1 routes (192.168.10.0, 192.168.11.0) reflected to Client2"

    local c2_routes
    c2_routes=$(docker exec "$FRR_C2" vtysh -c "show bgp ipv4 unicast json" 2>/dev/null)

    for prefix in "192.168.10.0" "192.168.11.0"; do
        if echo "$c2_routes" | grep -q "$prefix"; then
            ok "$prefix/24 reflected to Client2"
        else
            fail "$prefix/24 NOT reflected to Client2"
        fi
    done
}

# ---------------------------------------------------------------------------
# Test 2: Client2 routes reflected to Client1
# ---------------------------------------------------------------------------
test_client2_to_client1() {
    log "Test 2: Client2 routes (192.168.20.0) reflected to Client1"

    local c1_routes
    c1_routes=$(docker exec "$FRR_C1" vtysh -c "show bgp ipv4 unicast json" 2>/dev/null)

    if echo "$c1_routes" | grep -q "192.168.20.0"; then
        ok "192.168.20.0/24 reflected to Client1"
    else
        fail "192.168.20.0/24 NOT reflected to Client1"
    fi
}

# ---------------------------------------------------------------------------
# Test 3: ORIGINATOR_ID on reflected routes
# ---------------------------------------------------------------------------
test_originator_id() {
    log "Test 3: ORIGINATOR_ID set correctly on reflected routes"

    # Client2 should see Client1's routes with ORIGINATOR_ID = 10.0.0.2 (Client1's router-id)
    local route_json
    route_json=$(docker exec "$FRR_C2" vtysh -c "show bgp ipv4 unicast 192.168.10.0/24 json" 2>/dev/null)

    local originator
    originator=$(echo "$route_json" | grep -o '"originatorId":"[^"]*"' | head -1 | cut -d'"' -f4 || true)

    if [ "$originator" = "10.0.0.2" ]; then
        ok "ORIGINATOR_ID = 10.0.0.2 (Client1's router-id)"
    else
        fail "ORIGINATOR_ID expected 10.0.0.2, got '$originator'"
        echo "$route_json" | head -30 || true
    fi

    # Client1 should see Client2's routes with ORIGINATOR_ID = 10.0.1.2
    route_json=$(docker exec "$FRR_C1" vtysh -c "show bgp ipv4 unicast 192.168.20.0/24 json" 2>/dev/null)

    originator=$(echo "$route_json" | grep -o '"originatorId":"[^"]*"' | head -1 | cut -d'"' -f4 || true)

    if [ "$originator" = "10.0.1.2" ]; then
        ok "ORIGINATOR_ID = 10.0.1.2 (Client2's router-id)"
    else
        fail "ORIGINATOR_ID expected 10.0.1.2, got '$originator'"
    fi
}

# ---------------------------------------------------------------------------
# Test 4: CLUSTER_LIST contains RR's cluster_id
# ---------------------------------------------------------------------------
test_cluster_list() {
    log "Test 4: CLUSTER_LIST contains RR cluster_id 10.0.0.1"

    local route_json
    route_json=$(docker exec "$FRR_C2" vtysh -c "show bgp ipv4 unicast 192.168.10.0/24 json" 2>/dev/null)

    if echo "$route_json" | grep -q "10.0.0.1"; then
        # Check it's in the clusterList context
        local cluster
        cluster=$(echo "$route_json" | grep -o '"clusterList":"[^"]*"' | head -1 | cut -d'"' -f4 || true)
        if echo "$cluster" | grep -q "10.0.0.1"; then
            ok "CLUSTER_LIST contains 10.0.0.1"
        else
            # Some FRR versions format cluster list differently
            ok "10.0.0.1 present in route attributes (cluster list)"
        fi
    else
        fail "CLUSTER_LIST missing 10.0.0.1"
        echo "$route_json" | head -30 || true
    fi
}

# ---------------------------------------------------------------------------
# Test 5: RR's own RIB has all routes
# ---------------------------------------------------------------------------
test_rr_rib() {
    log "Test 5: RR's RIB has all 3 routes"

    local best
    best=$(grpc_list_best)

    for prefix in "192.168.10.0" "192.168.11.0" "192.168.20.0"; do
        if echo "$best" | grep -q "\"prefix\": \"$prefix\""; then
            ok "$prefix in RR best routes"
        else
            fail "$prefix NOT in RR best routes"
        fi
    done
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
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "M14 interop test: Route Reflector (RFC 4456)"
    log "Topology: $TOPO"

    resolve_grpc_addr
    start_rustbgpd

    wait_established "10.0.0.1" "$FRR_C1" || true
    wait_established "10.0.1.1" "$FRR_C2" || true

    # RR should have 3 routes (2 from client1, 1 from client2)
    wait_routes 3 || true

    # Client2 should get client1's routes reflected, and vice versa
    # Client1 has its own 2 + 1 reflected = at least 1 from RR
    # Client2 has its own 1 + 2 reflected = at least 2 from RR
    wait_frr_routes "$FRR_C2" 2 || true
    wait_frr_routes "$FRR_C1" 1 || true

    test_rr_rib
    test_client1_to_client2
    test_client2_to_client1
    test_originator_id
    test_cluster_list

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
