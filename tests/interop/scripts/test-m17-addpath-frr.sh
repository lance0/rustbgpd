#!/usr/bin/env bash
# M17 interop test — Add-Path multi-path send (RFC 7911)
#
# Validates: rustbgpd receives routes from multiple peers for the same prefix,
# then advertises multiple paths to an Add-Path-capable client peer.
#
# Topology:
#   FRR-A (AS 65002) → rustbgpd (AS 65001) ← FRR-B (AS 65003)
#                            ↓
#                     FRR-Client (AS 65004)
#
# Both FRR-A and FRR-B advertise 192.168.10.0/24.
# FRR-Client has addpath-rx-all-paths and should receive 2 paths.
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m17-addpath-frr.clab.yml
#   - grpcurl installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m17-addpath-frr.sh


TOPO="m17-addpath-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"
FRR_A="clab-${TOPO}-frr-a"
FRR_B="clab-${TOPO}-frr-b"
FRR_CLIENT="clab-${TOPO}-frr-client"


grpc_list_received() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

grpc_list_received_for_peer() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"neighbor_address\": \"$1\"}" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

grpc_list_advertised() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"neighbor_address\": \"$1\"}" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListAdvertisedRoutes 2>/dev/null
}

wait_established() {
    local peer_addr=$1
    local frr_container=$2
    log "Waiting for BGP session to $peer_addr (on $frr_container) to reach Established..."
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
# Test 1: Both source peers' routes appear in Adj-RIB-In
# ---------------------------------------------------------------------------
test_received_routes() {
    log "Test 1: Routes from both source peers appear in Adj-RIB-In"

    # FRR-A sends 192.168.10.0/24 + 192.168.1.0/24
    local routes_a
    routes_a=$(grpc_list_received_for_peer "10.0.0.2")
    for prefix in "192.168.10.0" "192.168.1.0"; do
        if echo "$routes_a" | grep -q "\"prefix\": \"$prefix\""; then
            ok "FRR-A: $prefix present"
        else
            fail "FRR-A: $prefix missing"
        fi
    done

    # FRR-B sends 192.168.10.0/24 + 192.168.2.0/24
    local routes_b
    routes_b=$(grpc_list_received_for_peer "10.0.1.2")
    for prefix in "192.168.10.0" "192.168.2.0"; do
        if echo "$routes_b" | grep -q "\"prefix\": \"$prefix\""; then
            ok "FRR-B: $prefix present"
        else
            fail "FRR-B: $prefix missing"
        fi
    done
}

# ---------------------------------------------------------------------------
# Test 2: FRR-Client receives multiple paths for the shared prefix
# ---------------------------------------------------------------------------
test_multipath_on_client() {
    log "Test 2: FRR-Client receives multiple paths for 192.168.10.0/24"

    # Wait for FRR-Client to have routes
    for i in $(seq 1 20); do
        local path_count
        path_count=$(docker exec "$FRR_CLIENT" vtysh -c "show bgp ipv4 unicast 192.168.10.0/24 json" 2>/dev/null \
            | python3 -c "
import json, sys
data = json.load(sys.stdin)
paths = data.get('paths', [])
print(len(paths))
" 2>/dev/null || echo "0")
        if [ "$path_count" -ge 2 ]; then
            ok "FRR-Client has $path_count paths for 192.168.10.0/24"
            return 0
        fi
        sleep 2
    done
    fail "FRR-Client expected 2+ paths for 192.168.10.0/24, got $path_count"
}

# ---------------------------------------------------------------------------
# Test 3: Advertised routes to client have distinct path_ids
# ---------------------------------------------------------------------------
test_advertised_path_ids() {
    log "Test 3: Advertised routes to FRR-Client have distinct path_ids"

    local advertised
    advertised=$(grpc_list_advertised "10.0.2.2")

    # Count routes for 192.168.10.0 — should be 2 (one per source peer)
    local count
    count=$(echo "$advertised" | python3 -c "
import json, sys
data = json.load(sys.stdin)
matching = [r for r in data.get('routes', []) if r.get('prefix') == '192.168.10.0']
path_ids = set()
for r in matching:
    pid = r.get('pathId', 0)
    path_ids.add(pid)
print(len(matching), len(path_ids))
" 2>/dev/null || echo "0 0")

    local route_count path_id_count
    route_count=$(echo "$count" | cut -d' ' -f1)
    path_id_count=$(echo "$count" | cut -d' ' -f2)

    if [ "$route_count" -ge 2 ]; then
        ok "Advertised $route_count routes for 192.168.10.0/24 to client"
    else
        fail "Expected 2+ advertised routes for 192.168.10.0/24, got $route_count"
    fi

    if [ "$path_id_count" -ge 2 ]; then
        ok "Path IDs are distinct ($path_id_count unique)"
    else
        fail "Expected distinct path IDs, got $path_id_count unique"
    fi
}

# ---------------------------------------------------------------------------
# Test 4: Unique prefixes still advertised normally
# ---------------------------------------------------------------------------
test_unique_prefixes() {
    log "Test 4: Unique prefixes (192.168.1.0, 192.168.2.0) advertised to client"

    local advertised
    advertised=$(grpc_list_advertised "10.0.2.2")

    for prefix in "192.168.1.0" "192.168.2.0"; do
        if echo "$advertised" | grep -q "\"prefix\": \"$prefix\""; then
            ok "$prefix/24 advertised to client"
        else
            fail "$prefix/24 missing from client advertisements"
        fi
    done
}

# ---------------------------------------------------------------------------
# Test 5: Different AS_PATHs for multi-path routes on FRR-Client
# ---------------------------------------------------------------------------
test_different_aspaths() {
    log "Test 5: Multi-path routes on FRR-Client have different AS_PATHs"

    # eBGP next-hop-self means both paths share the same NH (rustbgpd's address).
    # The real Add-Path validation is that the client sees distinct AS_PATHs —
    # one via AS 65002 (FRR-A) and one via AS 65003 (FRR-B).
    local aspaths
    aspaths=$(docker exec "$FRR_CLIENT" vtysh -c "show bgp ipv4 unicast 192.168.10.0/24 json" 2>/dev/null \
        | python3 -c "
import json, sys
data = json.load(sys.stdin)
paths = data.get('paths', [])
for p in paths:
    asp = p.get('aspath', {})
    if isinstance(asp, dict):
        print(asp.get('string', ''))
    elif isinstance(asp, str):
        print(asp)
" 2>/dev/null || echo "")

    local has_65002=false has_65003=false
    while IFS= read -r line; do
        if echo "$line" | grep -q "65002"; then has_65002=true; fi
        if echo "$line" | grep -q "65003"; then has_65003=true; fi
    done <<< "$aspaths"

    if $has_65002; then
        ok "Path via AS 65002 (FRR-A) present"
    else
        fail "Path via AS 65002 (FRR-A) missing"
    fi

    if $has_65003; then
        ok "Path via AS 65003 (FRR-B) present"
    else
        fail "Path via AS 65003 (FRR-B) missing"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "M17 interop test: Add-Path multi-path send (RFC 7911)"
    log "Topology: $TOPO"

    resolve_grpc_addr
    start_rustbgpd

    wait_established "10.0.0.1" "$FRR_A" || true
    wait_established "10.0.1.1" "$FRR_B" || true
    wait_established "10.0.2.1" "$FRR_CLIENT" || true

    # Wait for routes from both source peers
    wait_routes 4 || true

    # Wait for FRR-Client to settle
    sleep 5

    test_received_routes
    test_multipath_on_client
    test_advertised_path_ids
    test_unique_prefixes
    test_different_aspaths

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
