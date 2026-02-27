#!/usr/bin/env bash
# M4 interop test — rustbgpd ↔ 10× FRR (dynamic peers + per-peer policy)
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m4-frr.clab.yml
#   - grpcurl installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m4-frr.sh

set -euo pipefail

TOPO="m4-frr"
RUSTBGPD="clab-${TOPO}-rustbgpd"
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

grpc() {
    local args=("$@")
    local method="${args[-1]}"
    unset 'args[-1]'
    grpcurl -plaintext -import-path . -proto "$PROTO" "${args[@]}" "$GRPC_ADDR" "$method" 2>/dev/null
}

grpc_list_neighbors() {
    grpc rustbgpd.v1.NeighborService/ListNeighbors
}

grpc_add_neighbor() {
    local addr=$1 asn=$2 desc=$3
    grpc -d "{\"config\": {\"address\": \"$addr\", \"remote_asn\": $asn, \"description\": \"$desc\"}}" \
        rustbgpd.v1.NeighborService/AddNeighbor
}

grpc_delete_neighbor() {
    local addr=$1
    grpc -d "{\"address\": \"$addr\"}" \
        rustbgpd.v1.NeighborService/DeleteNeighbor
}

grpc_list_received() {
    grpc rustbgpd.v1.RibService/ListReceivedRoutes
}

grpc_list_best() {
    grpc rustbgpd.v1.RibService/ListBestRoutes
}

grpc_list_advertised() {
    grpc -d "{\"neighbor_address\": \"$1\"}" \
        rustbgpd.v1.RibService/ListAdvertisedRoutes
}

grpc_add_path() {
    local prefix=$1 prefix_len=$2 next_hop=$3
    grpc -d "{\"prefix\": \"$prefix\", \"prefix_length\": $prefix_len, \"next_hop\": \"$next_hop\"}" \
        rustbgpd.v1.InjectionService/AddPath
}

grpc_enable_neighbor() {
    grpc -d "{\"address\": \"$1\"}" \
        rustbgpd.v1.NeighborService/EnableNeighbor
}

grpc_disable_neighbor() {
    grpc -d "{\"address\": \"$1\", \"reason\": \"test\"}" \
        rustbgpd.v1.NeighborService/DisableNeighbor
}

# Wait for a specific FRR peer to reach Established
wait_frr_established() {
    local container=$1 peer_addr=$2 label=$3
    log "Waiting for $label session to reach Established..."
    for i in $(seq 1 45); do
        local state
        state=$(docker exec "$container" vtysh -c "show bgp neighbors $peer_addr json" 2>/dev/null \
            | grep -o '"bgpState":"[^"]*"' | head -1 | cut -d'"' -f4 || true)
        if [ "$state" = "Established" ]; then
            ok "$label session established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$label session did not reach Established within 90s"
    return 1
}

# ---------------------------------------------------------------------------
# Test 1: All 8 static sessions establish
# ---------------------------------------------------------------------------
test_static_sessions() {
    log "Test 1: All 8 static sessions establish"

    for i in $(seq 1 8); do
        num=$(printf "%02d" $i)
        net=$((9 + i))
        container="clab-${TOPO}-frr-${num}"
        wait_frr_established "$container" "10.0.${net}.1" "FRR-${num}" || true
    done
}

# ---------------------------------------------------------------------------
# Test 2: ListNeighbors returns correct count
# ---------------------------------------------------------------------------
test_list_neighbors() {
    log "Test 2: ListNeighbors returns 8 peers"

    local result
    result=$(grpc_list_neighbors)
    local count
    count=$(echo "$result" | grep -c '"state"' || true)

    if [ "$count" -eq 8 ]; then
        ok "ListNeighbors returned 8 peers"
    else
        fail "ListNeighbors returned $count peers (expected 8)"
    fi
}

# ---------------------------------------------------------------------------
# Test 3: Received routes from all peers
# ---------------------------------------------------------------------------
test_received_routes() {
    log "Test 3: Received routes from 8 peers (16 total)"

    log "Waiting for routes..."
    for i in $(seq 1 15); do
        local count
        count=$(grpc_list_received | grep -c '"prefix"' || true)
        if [ "$count" -ge 16 ]; then
            ok "Got $count received routes (>= 16)"
            return 0
        fi
        sleep 2
    done

    local count
    count=$(grpc_list_received | grep -c '"prefix"' || true)
    fail "Expected >= 16 routes, got $count"
}

# ---------------------------------------------------------------------------
# Test 4: Per-peer export policy — FRR-01 does NOT see 10.x routes
# ---------------------------------------------------------------------------
test_per_peer_export_policy() {
    log "Test 4: Per-peer export policy (FRR-01 denied 10.0.0.0/8)"

    # Inject a 10.x route
    grpc_add_path "10.99.0.0" 24 "10.0.10.1" > /dev/null 2>&1 || true
    sleep 3

    # FRR-01 should NOT see the 10.99.0.0/24 route (denied by per-peer policy)
    local frr01_routes
    frr01_routes=$(docker exec "clab-${TOPO}-frr-01" vtysh \
        -c "show bgp ipv4 unicast 10.99.0.0/24 json" 2>/dev/null || true)
    if echo "$frr01_routes" | grep -q '"prefix"'; then
        fail "FRR-01 received 10.99.0.0/24 despite deny policy"
    else
        ok "FRR-01 correctly denied 10.99.0.0/24"
    fi

    # FRR-02 SHOULD see it (no per-peer policy)
    local frr02_routes
    frr02_routes=$(docker exec "clab-${TOPO}-frr-02" vtysh \
        -c "show bgp ipv4 unicast 10.99.0.0/24 json" 2>/dev/null || true)
    if echo "$frr02_routes" | grep -q '"prefix"'; then
        ok "FRR-02 received 10.99.0.0/24 (no deny policy)"
    else
        fail "FRR-02 did not receive 10.99.0.0/24"
    fi
}

# ---------------------------------------------------------------------------
# Test 5: Dynamic AddNeighbor — add FRR-09
# ---------------------------------------------------------------------------
test_add_neighbor() {
    log "Test 5: Dynamic AddNeighbor (FRR-09, AS 65018)"

    local result
    result=$(grpc_add_neighbor "10.0.18.2" 65018 "frr-09-dynamic" 2>&1 || true)

    # Wait for session to establish
    sleep 5
    wait_frr_established "clab-${TOPO}-frr-09" "10.0.18.1" "FRR-09 (dynamic)" || true

    # ListNeighbors should now return 9
    local count
    count=$(grpc_list_neighbors | grep -c '"state"' || true)
    if [ "$count" -eq 9 ]; then
        ok "ListNeighbors returned 9 after AddNeighbor"
    else
        fail "ListNeighbors returned $count (expected 9)"
    fi
}

# ---------------------------------------------------------------------------
# Test 6: Dynamic DeleteNeighbor — remove FRR-09
# ---------------------------------------------------------------------------
test_delete_neighbor() {
    log "Test 6: Dynamic DeleteNeighbor (FRR-09)"

    grpc_delete_neighbor "10.0.18.2" > /dev/null 2>&1 || true
    sleep 3

    # ListNeighbors should return 8 again
    local count
    count=$(grpc_list_neighbors | grep -c '"state"' || true)
    if [ "$count" -eq 8 ]; then
        ok "ListNeighbors returned 8 after DeleteNeighbor"
    else
        fail "ListNeighbors returned $count (expected 8)"
    fi
}

# ---------------------------------------------------------------------------
# Test 7: Enable/Disable neighbor
# ---------------------------------------------------------------------------
test_enable_disable() {
    log "Test 7: Disable and re-enable FRR-01"

    grpc_disable_neighbor "10.0.10.2" > /dev/null 2>&1 || true
    sleep 5

    # FRR-01 should not be Established
    local state
    state=$(docker exec "clab-${TOPO}-frr-01" vtysh -c "show bgp neighbors 10.0.10.1 json" 2>/dev/null \
        | grep -o '"bgpState":"[^"]*"' | head -1 | cut -d'"' -f4 || true)
    if [ "$state" != "Established" ]; then
        ok "FRR-01 session dropped after disable (state: ${state:-unknown})"
    else
        fail "FRR-01 still Established after disable"
    fi

    grpc_enable_neighbor "10.0.10.2" > /dev/null 2>&1 || true
    wait_frr_established "clab-${TOPO}-frr-01" "10.0.10.1" "FRR-01 (re-enabled)" || true
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "M4 interop test: rustbgpd ↔ 10× FRR"
    log "Topology: $TOPO"

    resolve_grpc_addr

    test_static_sessions
    test_list_neighbors
    test_received_routes
    test_per_peer_export_policy
    test_add_neighbor
    test_delete_neighbor
    test_enable_disable

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
