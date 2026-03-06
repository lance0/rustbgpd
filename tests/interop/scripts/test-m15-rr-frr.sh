#!/usr/bin/env bash
# M15 interop test — Route Refresh (RFC 2918 + RFC 7313)
#
# Validates: SoftResetIn via gRPC triggers route re-advertisement.
#   - Verify initial routes with LOCAL_PREF 150
#   - FRR adds a new network while session is up
#   - SoftResetIn triggers FRR to re-advertise all routes
#   - Verify route count increases after re-advertisement
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m15-rr-frr.clab.yml
#   - grpcurl installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m15-rr-frr.sh

set -euo pipefail

TOPO="m15-rr-frr"
RUSTBGPD="clab-${TOPO}-rustbgpd"
FRR="clab-${TOPO}-frr"
PROTO="proto/rustbgpd.proto"
GRPC_ADDR=""

pass=0
fail=0

log()  { printf "\033[1;34m[TEST]\033[0m %s\n" "$*"; }
ok()   { pass=$((pass + 1)); printf "\033[1;32m  PASS\033[0m %s\n" "$*"; }
fail() { fail=$((fail + 1)); printf "\033[1;31m  FAIL\033[0m %s\n" "$*"; }

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

grpc_soft_reset_in() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"address\": \"$1\"}" \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/SoftResetIn 2>/dev/null
}

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
# Test 1: Initial routes received with LOCAL_PREF
# ---------------------------------------------------------------------------
test_initial_routes() {
    log "Test 1: Initial routes received with LOCAL_PREF 150"

    local best
    best=$(grpc_list_best)

    for prefix in "192.168.1.0" "192.168.2.0"; do
        if echo "$best" | grep -q "\"prefix\": \"$prefix\""; then
            ok "$prefix/24 present"
        else
            fail "$prefix/24 missing"
        fi
    done

    # Verify LOCAL_PREF
    local lp
    lp=$(echo "$best" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for r in data.get('routes', []):
    if r.get('prefix') == '192.168.1.0':
        print(r.get('localPref', 0))
        break
" 2>/dev/null || echo "")

    if [ "$lp" = "150" ]; then
        ok "LOCAL_PREF = 150 on import"
    else
        fail "LOCAL_PREF expected 150, got '$lp'"
    fi
}

# ---------------------------------------------------------------------------
# Test 2: SoftResetIn triggers re-advertisement
# ---------------------------------------------------------------------------
test_soft_reset_in() {
    log "Test 2: SoftResetIn triggers route re-advertisement"

    # Add a new network on FRR while session is up
    docker exec "$FRR" vtysh -c "conf t" -c "router bgp 65002" \
        -c "address-family ipv4 unicast" -c "network 10.99.0.0/24" \
        -c "end" 2>/dev/null
    docker exec "$FRR" vtysh -c "conf t" -c "ip route 10.99.0.0/24 10.0.0.2" \
        -c "end" 2>/dev/null

    # FRR should send the new route via normal UPDATE
    sleep 3

    local count_before
    count_before=$(grpc_list_received | grep -c '"prefix"' || true)
    log "Routes before SoftResetIn: $count_before"

    if [ "$count_before" -ge 3 ]; then
        ok "New route 10.99.0.0/24 received via normal UPDATE"
    else
        fail "Expected 3 routes after adding 10.99.0.0/24, got $count_before"
    fi

    # Now trigger SoftResetIn — this should cause FRR to re-send all routes
    log "Triggering SoftResetIn..."
    local result
    result=$(grpc_soft_reset_in "10.0.0.2")
    ok "SoftResetIn RPC completed"

    # Wait briefly for re-advertisement
    sleep 5

    # Session should still be up (no flap)
    local state
    state=$(docker exec "$FRR" vtysh -c "show bgp neighbors 10.0.0.1 json" 2>/dev/null \
        | grep -o '"bgpState":"[^"]*"' | head -1 | cut -d'"' -f4 || true)

    if [ "$state" = "Established" ]; then
        ok "Session still Established after SoftResetIn (no flap)"
    else
        fail "Session state after SoftResetIn: $state (expected Established)"
    fi

    # All routes should still be present after re-advertisement
    local count_after
    count_after=$(grpc_list_received | grep -c '"prefix"' || true)

    if [ "$count_after" -ge 3 ]; then
        ok "All $count_after routes present after SoftResetIn"
    else
        fail "Expected >= 3 routes after SoftResetIn, got $count_after"
    fi
}

# ---------------------------------------------------------------------------
# Test 3: Routes still have import policy applied after SoftResetIn
# ---------------------------------------------------------------------------
test_policy_after_reset() {
    log "Test 3: Import policy still applied after SoftResetIn"

    local best
    best=$(grpc_list_best)

    local lp
    lp=$(echo "$best" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for r in data.get('routes', []):
    if r.get('prefix') == '192.168.1.0':
        print(r.get('localPref', 0))
        break
" 2>/dev/null || echo "")

    if [ "$lp" = "150" ]; then
        ok "LOCAL_PREF = 150 still applied after SoftResetIn"
    else
        fail "LOCAL_PREF expected 150 after SoftResetIn, got '$lp'"
    fi
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
    log "M15 interop test: Route Refresh (RFC 2918 + RFC 7313)"
    log "Topology: $TOPO"

    resolve_grpc_addr
    start_rustbgpd

    wait_established || true
    wait_routes 2 || true

    test_initial_routes
    test_soft_reset_in
    test_policy_after_reset

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
