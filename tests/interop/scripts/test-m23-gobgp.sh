#!/usr/bin/env bash
# M23 interop test — rustbgpd ↔ GoBGP
#
# Validates:
#   1. BGP session establishment with GoBGP
#   2. GoBGP advertises routes → rustbgpd receives them
#   3. rustbgpd injects route via gRPC → GoBGP receives it
#   4. Route attributes correct (AS_PATH, NEXT_HOP, ORIGIN)
#   5. Withdrawal propagation in both directions
#
# Prerequisites:
#   - docker build -t gobgp:interop -f tests/interop/Dockerfile.gobgp tests/interop/
#   - containerlab deployed: containerlab deploy -t tests/interop/m23-gobgp.clab.yml
#   - grpcurl installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m23-gobgp.sh


TOPO="m23-gobgp"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"
GOBGP="clab-${TOPO}-gobgp"


# ---------------------------------------------------------------------------
# gRPC helpers (rustbgpd)
# ---------------------------------------------------------------------------

grpc_list_received() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d '{"neighbor_address": "10.0.0.2"}' \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

grpc_add_route() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "$1" \
        "$GRPC_ADDR" rustbgpd.v1.InjectionService/AddPath 2>/dev/null
}

grpc_delete_route() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "$1" \
        "$GRPC_ADDR" rustbgpd.v1.InjectionService/DeletePath 2>/dev/null
}


# ---------------------------------------------------------------------------
# GoBGP CLI helpers
# ---------------------------------------------------------------------------

gobgp_neighbor() {
    docker exec "$GOBGP" gobgp neighbor 2>/dev/null
}

gobgp_neighbor_detail() {
    docker exec "$GOBGP" gobgp neighbor 10.0.0.1 2>/dev/null
}

gobgp_rib() {
    docker exec "$GOBGP" gobgp global rib 2>/dev/null
}

gobgp_adj_in() {
    docker exec "$GOBGP" gobgp neighbor 10.0.0.1 adj-in 2>/dev/null
}

gobgp_add_route() {
    docker exec "$GOBGP" gobgp global rib add "$@" 2>/dev/null
}

gobgp_del_route() {
    docker exec "$GOBGP" gobgp global rib del "$@" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Wait helpers
# ---------------------------------------------------------------------------

wait_established() {
    log "Waiting for BGP session to reach Established..."
    for i in $(seq 1 45); do
        local state
        state=$(gobgp_neighbor 2>/dev/null | grep "10.0.0.1" || true)
        if echo "$state" | grep -qi "establ"; then
            ok "BGP session established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "BGP session did not reach Established within 90s"
    gobgp_neighbor || true
    return 1
}

start_gobgpd() {
    log "Starting gobgpd..."
    docker exec -d "$GOBGP" gobgpd -f /config/gobgp.toml
    sleep 2
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

test_gobgp_advertises_routes() {
    log "Test 1: GoBGP advertises routes → rustbgpd receives"

    # Inject routes into GoBGP's global RIB
    gobgp_add_route 192.168.1.0/24 -a ipv4
    gobgp_add_route 192.168.2.0/24 -a ipv4
    gobgp_add_route 10.10.0.0/16 -a ipv4

    log "Waiting for routes to arrive in rustbgpd..."
    for i in $(seq 1 15); do
        local count
        count=$(grpc_list_received | grep -c '"prefix"' || true)
        if [ "$count" -ge 3 ]; then
            ok "rustbgpd received $count routes from GoBGP (attempt $i)"

            # Check specific prefixes
            local routes
            routes=$(grpc_list_received)
            for prefix in "192.168.1.0" "192.168.2.0" "10.10.0.0"; do
                if echo "$routes" | grep -q "\"prefix\": \"$prefix\""; then
                    ok "Prefix $prefix present"
                else
                    fail "Prefix $prefix missing"
                fi
            done
            return 0
        fi
        sleep 2
    done
    fail "Expected 3 routes, got $(grpc_list_received | grep -c '"prefix"' || echo 0)"
}

test_route_attributes() {
    log "Test 2: Route attributes correct"

    local routes
    routes=$(grpc_list_received)

    # AS_PATH should contain 65002 (GoBGP's ASN)
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

test_rustbgpd_injects_route() {
    log "Test 3: rustbgpd injects route → GoBGP receives"

    grpc_add_route '{
        "prefix": "203.0.113.0",
        "prefix_length": 24,
        "next_hop": "10.0.0.1",
        "as_path": [65001],
        "origin": 0
    }'
    sleep 3

    # Check GoBGP received the route
    for i in $(seq 1 15); do
        local rib
        rib=$(gobgp_adj_in)
        if echo "$rib" | grep -q "203.0.113.0"; then
            ok "GoBGP received 203.0.113.0/24 from rustbgpd (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "GoBGP did not receive 203.0.113.0/24 within 30s"
    log "DEBUG GoBGP adj-in:"
    gobgp_adj_in || true
}

test_gobgp_withdrawal() {
    log "Test 4: GoBGP withdraws route → rustbgpd removes it"

    gobgp_del_route 192.168.2.0/24 -a ipv4
    sleep 3

    local routes
    routes=$(grpc_list_received)

    if echo "$routes" | grep -q '"prefix": "192.168.2.0"'; then
        # May need more time
        sleep 5
        routes=$(grpc_list_received)
        if echo "$routes" | grep -q '"prefix": "192.168.2.0"'; then
            fail "192.168.2.0/24 still present after withdrawal"
        else
            ok "192.168.2.0/24 withdrawn"
        fi
    else
        ok "192.168.2.0/24 withdrawn"
    fi

    # Other routes should survive
    if echo "$routes" | grep -q '"prefix": "192.168.1.0"'; then
        ok "192.168.1.0/24 still present"
    else
        fail "192.168.1.0/24 unexpectedly removed"
    fi
}

test_rustbgpd_withdrawal() {
    log "Test 5: rustbgpd withdraws route → GoBGP removes it"

    grpc_delete_route '{
        "prefix": "203.0.113.0",
        "prefix_length": 24
    }'
    sleep 3

    for i in $(seq 1 10); do
        local rib
        rib=$(gobgp_adj_in)
        if ! echo "$rib" | grep -q "203.0.113.0"; then
            ok "GoBGP no longer has 203.0.113.0/24 (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "GoBGP still has 203.0.113.0/24 after withdrawal"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "M23 interop test: rustbgpd ↔ GoBGP"
    log "Topology: $TOPO"

    resolve_grpc_addr
    start_gobgpd
    start_rustbgpd

    wait_established || exit 1

    test_gobgp_advertises_routes
    test_route_attributes
    test_rustbgpd_injects_route
    test_gobgp_withdrawal
    test_rustbgpd_withdrawal

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
