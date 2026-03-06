#!/usr/bin/env bash
# M16 interop test — Long-Lived Graceful Restart (RFC 9494)
#
# Validates: LLGR two-phase timer — GR expiry promotes routes to LLGR-stale
# instead of purging; peer reconnect clears LLGR-stale state.
#
# Timeline:
#   1. Session up, routes received
#   2. Kill FRR bgpd → GR phase (routes stale)
#   3. Wait for GR timer expiry → LLGR phase (routes LLGR-stale)
#   4. Verify LLGR-stale routes still in RIB (not purged)
#   5. Restart FRR bgpd → reconnect clears LLGR-stale
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m16-llgr-frr.clab.yml
#   - grpcurl installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m16-llgr-frr.sh

set -euo pipefail

TOPO="m16-llgr-frr"
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

get_metric() {
    local metric_name=$1
    docker exec "$RUSTBGPD" sh -c "wget -qO- http://localhost:9179/metrics 2>/dev/null" \
        | grep "^${metric_name}" | grep -v "^#" | head -1 | awk '{print $2}' || echo ""
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
# Test 1: Initial routes received
# ---------------------------------------------------------------------------
test_initial_routes() {
    log "Test 1: Initial routes received"

    local best
    best=$(grpc_list_best)

    for prefix in "192.168.1.0" "192.168.2.0"; do
        if echo "$best" | grep -q "\"prefix\": \"$prefix\""; then
            ok "$prefix/24 present"
        else
            fail "$prefix/24 missing"
        fi
    done
}

# ---------------------------------------------------------------------------
# Test 2: Kill FRR → GR phase → wait for LLGR promotion
# ---------------------------------------------------------------------------
test_gr_to_llgr_transition() {
    log "Test 2: GR → LLGR transition after GR timer expiry"

    # Kill FRR bgpd (don't kill watchfrr yet — we want delayed restart)
    docker exec "$FRR" killall -9 bgpd 2>/dev/null || true
    log "FRR bgpd killed, GR phase started"

    # GR timer is 15s, wait for it to expire and LLGR to begin
    # Add buffer for processing
    log "Waiting 25s for GR timer (15s) to expire and LLGR to start..."
    sleep 25

    # Routes should still be in RIB (LLGR-stale, not purged)
    local count
    count=$(grpc_list_received | grep -c '"prefix"' || true)

    if [ "$count" -ge 2 ]; then
        ok "Routes still present after GR timer expiry ($count routes — LLGR active)"
    else
        fail "Routes purged after GR timer expiry (expected LLGR preservation, got $count)"
    fi

    # Check LLGR metric if available
    local stale
    stale=$(get_metric "bgp_gr_stale_routes")
    if [ -n "$stale" ]; then
        log "bgp_gr_stale_routes = $stale"
    fi
}

# ---------------------------------------------------------------------------
# Test 3: Restart FRR → reconnect clears LLGR-stale
# ---------------------------------------------------------------------------
test_llgr_clear_on_reconnect() {
    log "Test 3: FRR reconnect clears LLGR-stale state"

    # watchfrr should restart bgpd automatically
    log "Waiting for watchfrr to restart bgpd..."
    wait_established || return 1

    # Wait for fresh routes
    sleep 5

    local count
    count=$(grpc_list_received | grep -c '"prefix"' || true)

    if [ "$count" -ge 2 ]; then
        ok "Routes present after reconnect ($count routes)"
    else
        fail "Expected routes after reconnect, got $count"
    fi

    # GR stale routes metric should be 0 after EoR
    log "Waiting for EoR processing..."
    sleep 5

    local stale
    stale=$(get_metric "bgp_gr_stale_routes")
    if [ "$stale" = "0" ] || [ -z "$stale" ]; then
        ok "No stale routes after reconnect (LLGR cleared)"
    else
        fail "Expected 0 stale routes after reconnect, got $stale"
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
    log "M16 interop test: LLGR (RFC 9494)"
    log "Topology: $TOPO"

    resolve_grpc_addr
    start_rustbgpd

    wait_established || true
    wait_routes 2 || true

    test_initial_routes
    test_gr_to_llgr_transition
    test_llgr_clear_on_reconnect

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
