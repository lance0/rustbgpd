#!/usr/bin/env bash
# M12 interop test — Extended Communities (RFC 4360)
#
# Validates that rustbgpd correctly decodes extended communities from FRR,
# stores them in the RIB, exposes them via gRPC, and round-trips injected
# routes with extended communities.
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m12-ec-frr.clab.yml
#   - grpcurl installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m12-ec-frr.sh

set -euo pipefail

TOPO="m12-ec-frr"
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

grpc_list_received() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

grpc_list_received_for_peer() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"neighbor_address\": \"$1\"}" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

grpc_list_best() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListBestRoutes 2>/dev/null
}

grpc_add_path() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "$1" \
        "$GRPC_ADDR" rustbgpd.v1.InjectionService/AddPath 2>/dev/null
}

grpc_delete_path() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "$1" \
        "$GRPC_ADDR" rustbgpd.v1.InjectionService/DeletePath 2>/dev/null
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

# ---------------------------------------------------------------------------
# Test 1: Routes received with extended communities
# ---------------------------------------------------------------------------
test_routes_have_extended_communities() {
    log "Test 1: Routes received with extended communities"

    wait_established || return 1
    wait_routes 2 || return 1

    local routes
    routes=$(grpc_list_received_for_peer "10.0.0.2")

    # Verify both prefixes present
    for prefix in "192.168.1.0" "192.168.2.0"; do
        if echo "$routes" | grep -q "\"prefix\": \"$prefix\""; then
            ok "Prefix $prefix present"
        else
            fail "Prefix $prefix missing"
        fi
    done

    # Verify extendedCommunities field is present (proto3 JSON uses camelCase)
    if echo "$routes" | grep -q '"extendedCommunities"'; then
        ok "extendedCommunities field present in route data"
    else
        fail "extendedCommunities field missing from route data"
    fi
}

# ---------------------------------------------------------------------------
# Test 2: Extended community values are correct
# ---------------------------------------------------------------------------
test_ec_values_correct() {
    log "Test 2: Extended community values (RT:65002:100)"

    local routes
    routes=$(grpc_list_received_for_peer "10.0.0.2")

    # Compute expected EC value for RT:65002:100 (2-octet AS specific)
    # Type=0x00, Subtype=0x02, ASN=65002 (0xFDEA), Value=100 (0x00000064)
    # Full: 0x0002FDEA00000064
    local expected_ec
    expected_ec=$(printf "%d" 0x0002FDEA00000064)
    log "Expected EC decimal: $expected_ec"

    # grpcurl renders uint64 as a JSON string in proto3 format
    if echo "$routes" | grep -q "\"$expected_ec\""; then
        ok "RT:65002:100 value correct ($expected_ec)"
    else
        # Also check if rendered as a number (some grpcurl versions)
        if echo "$routes" | grep -q "$expected_ec"; then
            ok "RT:65002:100 value correct ($expected_ec, numeric format)"
        else
            fail "RT:65002:100 value not found (expected $expected_ec)"
            log "Route data:"
            echo "$routes" | grep -A2 "extendedCommunities" || true
        fi
    fi

    # Both routes should have the same EC (route-map applies to all)
    local ec_count
    ec_count=$(echo "$routes" | grep -c "extendedCommunities" || true)
    if [ "$ec_count" -ge 2 ]; then
        ok "Both routes have extendedCommunities"
    else
        fail "Expected 2 routes with ECs, got $ec_count"
    fi
}

# ---------------------------------------------------------------------------
# Test 3: Inject route with extended community via gRPC
# ---------------------------------------------------------------------------
test_inject_with_ec() {
    log "Test 3: Inject route with extended community"

    # RT:65001:42 (2-octet AS specific)
    # Type=0x00, Subtype=0x02, ASN=65001 (0xFDE9), Value=42 (0x0000002A)
    # Full: 0x0002FDE90000002A
    local inject_ec
    inject_ec=$(printf "%d" 0x0002FDE90000002A)
    log "Injecting 10.99.0.0/24 with RT:65001:42 ($inject_ec)"

    # Inject route with EC
    local result
    result=$(grpc_add_path "{
        \"prefix\": \"10.99.0.0\",
        \"prefix_length\": 24,
        \"next_hop\": \"10.0.0.1\",
        \"origin\": 0,
        \"as_path\": [65001],
        \"extended_communities\": [\"$inject_ec\"]
    }")

    # Verify injection succeeded (empty response = success)
    ok "AddPath accepted"

    sleep 2

    # Verify injected route appears in best routes with EC
    local best
    best=$(grpc_list_best)

    if echo "$best" | grep -q '"prefix": "10.99.0.0"'; then
        ok "Injected route 10.99.0.0/24 in best routes"
    else
        fail "Injected route 10.99.0.0/24 not found in best routes"
    fi

    if echo "$best" | grep -q "$inject_ec"; then
        ok "Injected EC value present in best routes ($inject_ec)"
    else
        fail "Injected EC value not found in best routes"
        log "Best routes data:"
        echo "$best" | grep -B2 -A5 "10.99.0.0" || true
    fi
}

# ---------------------------------------------------------------------------
# Test 4: Extended communities in best routes for FRR-originated routes
# ---------------------------------------------------------------------------
test_ec_in_best_routes() {
    log "Test 4: Extended communities in best routes"

    local best
    best=$(grpc_list_best)

    local expected_ec
    expected_ec=$(printf "%d" 0x0002FDEA00000064)

    # FRR-originated routes should have ECs in best routes too
    if echo "$best" | grep -q '"prefix": "192.168.1.0"'; then
        ok "FRR route 192.168.1.0/24 in best routes"
    else
        fail "FRR route 192.168.1.0/24 not found in best routes"
    fi

    if echo "$best" | grep -q "$expected_ec"; then
        ok "RT:65002:100 present in best routes"
    else
        fail "RT:65002:100 not found in best routes"
    fi
}

# ---------------------------------------------------------------------------
# Test 5: Delete injected route and verify removal
# ---------------------------------------------------------------------------
test_delete_injected() {
    log "Test 5: Delete injected route"

    grpc_delete_path '{"prefix": "10.99.0.0", "prefix_length": 24}'

    sleep 2

    local best
    best=$(grpc_list_best)

    if echo "$best" | grep -q '"prefix": "10.99.0.0"'; then
        fail "Injected route 10.99.0.0/24 still present after deletion"
    else
        ok "Injected route 10.99.0.0/24 removed"
    fi

    # FRR routes should still be present
    if echo "$best" | grep -q '"prefix": "192.168.1.0"'; then
        ok "FRR route 192.168.1.0/24 still present"
    else
        fail "FRR route 192.168.1.0/24 unexpectedly removed"
    fi
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
# Main
# ---------------------------------------------------------------------------
main() {
    log "M12 interop test: Extended Communities (RFC 4360)"
    log "Topology: $TOPO"

    resolve_grpc_addr
    start_rustbgpd

    test_routes_have_extended_communities
    test_ec_values_correct
    test_inject_with_ec
    test_ec_in_best_routes
    test_delete_injected

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
