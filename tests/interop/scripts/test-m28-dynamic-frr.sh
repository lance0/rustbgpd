#!/usr/bin/env bash
# M28 interop test — rustbgpd dynamic neighbors ↔ FRR
#
# Validates:
#   1. Dynamic session auto-accepted from FRR
#   2. Dynamic peer visible via gRPC with is_dynamic flag
#   3. Routes received from dynamic peer
#   4. Peer-group inheritance on dynamic peer
#   5. Dynamic neighbor range listed via gRPC
#   6. Dynamic peer auto-removed on disconnect
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m28-dynamic-frr.clab.yml
#   - grpcurl installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m28-dynamic-frr.sh

TOPO="m28-dynamic-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"
FRR="clab-${TOPO}-frr"

# ---------------------------------------------------------------------------
# gRPC helpers
# ---------------------------------------------------------------------------

grpc_list_neighbors() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/ListNeighbors 2>/dev/null
}

grpc_list_dynamic_neighbors() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/ListDynamicNeighbors 2>/dev/null
}

grpc_list_received() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d '{"neighbor_address": "10.0.0.2"}' \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

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
            log "BGP session established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    echo "ERROR: BGP session did not reach Established within 90s" >&2
    return 1
}

wait_routes() {
    local expected=$1
    log "Waiting for $expected routes in RIB..."
    for i in $(seq 1 15); do
        local count
        count=$(grpc_list_received | grep -c '"prefix"' || true)
        if [ "$count" -ge "$expected" ]; then
            log "Got $count routes in RIB (attempt $i)"
            return 0
        fi
        sleep 2
    done
    echo "ERROR: Expected $expected routes, got $(grpc_list_received | grep -c '"prefix"' || echo 0)" >&2
    return 1
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

test_dynamic_session_established() {
    log "Test 1: Dynamic session auto-accepted from FRR"

    local state
    state=$(docker exec "$FRR" vtysh -c "show bgp neighbors 10.0.0.1 json" 2>/dev/null \
        | grep -o '"bgpState":"[^"]*"' | head -1 | cut -d'"' -f4 || true)

    if [ "$state" = "Established" ]; then
        ok "FRR shows session Established — rustbgpd auto-accepted dynamic peer"
    else
        fail "FRR session state = '$state' (expected 'Established')"
    fi
}

test_dynamic_peer_visible() {
    log "Test 2: Dynamic peer visible in ListNeighbors with is_dynamic=true"

    local neighbors
    neighbors=$(grpc_list_neighbors)

    local result
    result=$(echo "$neighbors" | python3 -c "
import sys, json
resp = json.load(sys.stdin)
for n in resp.get('neighbors', []):
    cfg = n.get('config', {})
    if cfg.get('address') == '10.0.0.2':
        print('found')
        if n.get('isDynamic', False):
            print('dynamic')
        break
" 2>/dev/null || true)

    if echo "$result" | grep -q "found"; then
        ok "Peer 10.0.0.2 present in ListNeighbors"
    else
        fail "Peer 10.0.0.2 NOT found in ListNeighbors"
        return
    fi

    if echo "$result" | grep -q "dynamic"; then
        ok "Peer 10.0.0.2 has isDynamic=true"
    else
        fail "Peer 10.0.0.2 does NOT have isDynamic=true"
    fi
}

test_routes_received() {
    log "Test 3: Routes received from dynamic peer (192.168.1.0/24, 192.168.2.0/24)"

    local routes
    routes=$(grpc_list_received)

    local count
    count=$(echo "$routes" | grep -c '"prefix"' || true)

    if [ "$count" -ge 2 ]; then
        ok "Received $count routes from dynamic peer 10.0.0.2"
    else
        fail "Expected >= 2 routes, got $count"
        return
    fi

    local found
    found=$(echo "$routes" | python3 -c "
import sys, json
resp = json.load(sys.stdin)
prefixes = set()
for r in resp.get('routes', []):
    p = r.get('prefix', '') + '/' + str(r.get('prefixLength', 0))
    prefixes.add(p)
if '192.168.1.0/24' in prefixes:
    print('prefix1')
if '192.168.2.0/24' in prefixes:
    print('prefix2')
" 2>/dev/null || true)

    if echo "$found" | grep -q "prefix1"; then
        ok "192.168.1.0/24 received"
    else
        fail "192.168.1.0/24 NOT received"
    fi

    if echo "$found" | grep -q "prefix2"; then
        ok "192.168.2.0/24 received"
    else
        fail "192.168.2.0/24 NOT received"
    fi
}

test_peer_group_inherited() {
    log "Test 4: Dynamic peer inherits peer_group 'ix-members'"

    local neighbors
    neighbors=$(grpc_list_neighbors)

    local pg
    pg=$(echo "$neighbors" | python3 -c "
import sys, json
resp = json.load(sys.stdin)
for n in resp.get('neighbors', []):
    cfg = n.get('config', {})
    if cfg.get('address') == '10.0.0.2':
        print(cfg.get('peerGroup', ''))
        break
" 2>/dev/null || true)

    if [ "$pg" = "ix-members" ]; then
        ok "Dynamic peer 10.0.0.2 has peerGroup='ix-members'"
    else
        fail "Dynamic peer 10.0.0.2 peerGroup='$pg' (expected 'ix-members')"
    fi
}

test_dynamic_range_listed() {
    log "Test 5: ListDynamicNeighbors shows range 10.0.0.0/24"

    local resp
    resp=$(grpc_list_dynamic_neighbors)

    local result
    result=$(echo "$resp" | python3 -c "
import sys, json
resp = json.load(sys.stdin)
for r in resp.get('ranges', []):
    if r.get('prefix') == '10.0.0.0/24':
        print('found')
        if r.get('peerGroup') == 'ix-members':
            print('pg_ok')
        break
" 2>/dev/null || true)

    if echo "$result" | grep -q "found"; then
        ok "Dynamic range 10.0.0.0/24 present in ListDynamicNeighbors"
    else
        fail "Dynamic range 10.0.0.0/24 NOT found in ListDynamicNeighbors"
        return
    fi

    if echo "$result" | grep -q "pg_ok"; then
        ok "Dynamic range has peerGroup='ix-members'"
    else
        fail "Dynamic range peerGroup mismatch"
    fi
}

test_dynamic_peer_removed_on_disconnect() {
    log "Test 6: Dynamic peer removed after session teardown"

    # Tear down the BGP session from FRR side
    log "Clearing BGP sessions on FRR..."
    docker exec "$FRR" vtysh -c "clear bgp *" 2>/dev/null || true

    # Poll until peer disappears from ListNeighbors
    log "Waiting for dynamic peer to be removed..."
    for i in $(seq 1 30); do
        local neighbors
        neighbors=$(grpc_list_neighbors)

        local found
        found=$(echo "$neighbors" | python3 -c "
import sys, json
resp = json.load(sys.stdin)
for n in resp.get('neighbors', []):
    cfg = n.get('config', {})
    if cfg.get('address') == '10.0.0.2':
        print('found')
        break
" 2>/dev/null || true)

        if [ -z "$found" ]; then
            ok "Dynamic peer 10.0.0.2 removed after disconnect (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "Dynamic peer 10.0.0.2 still present after 60s"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    log "M28 interop test: rustbgpd dynamic neighbors ↔ FRR"
    log "Topology: $TOPO"

    resolve_grpc_addr
    start_rustbgpd

    wait_established || exit 1
    wait_routes 2 || exit 1

    test_dynamic_session_established
    test_dynamic_peer_visible
    test_routes_received
    test_peer_group_inherited
    test_dynamic_range_listed
    test_dynamic_peer_removed_on_disconnect

    print_summary
}

main "$@"
