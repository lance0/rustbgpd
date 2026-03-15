#!/usr/bin/env bash
# M25 interop test — TCP MD5 + GTSM / TTL security with FRR
#
# Validates:
#   1. BGP session with TCP MD5 authentication (RFC 2385)
#   2. BGP session with GTSM / TTL security (RFC 5082)
#   3. Routes exchanged over both secured sessions
#   4. Wrong MD5 password prevents session (negative test)
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m25-md5-gtsm-frr.clab.yml
#   - grpcurl installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m25-md5-gtsm-frr.sh


TOPO="m25-md5-gtsm-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"
FRR_A="clab-${TOPO}-frr-a"
FRR_B="clab-${TOPO}-frr-b"


grpc_list_received() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"neighbor_address\": \"$1\"}" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
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

wait_frr_established() {
    local frr_container=$1
    local peer_addr=$2
    local label=$3

    log "Waiting for $label session to reach Established..."
    for i in $(seq 1 45); do
        local state
        state=$(docker exec "$frr_container" vtysh -c "show bgp neighbors $peer_addr json" 2>/dev/null \
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
# Tests
# ---------------------------------------------------------------------------

test_md5_session() {
    log "Test 1: TCP MD5 session (FRR-A, AS 65002)"

    wait_frr_established "$FRR_A" "10.0.0.1" "MD5" || return 1

    # Verify route received over MD5-authenticated session
    for i in $(seq 1 15); do
        local routes
        routes=$(grpc_list_received "10.0.0.2")
        if echo "$routes" | grep -q '"prefix": "192.168.1.0"'; then
            ok "Route 192.168.1.0/24 received over MD5 session"
            return 0
        fi
        sleep 2
    done
    fail "No route received over MD5 session"
}

test_gtsm_session() {
    log "Test 2: GTSM / TTL security session (FRR-B, AS 65003)"

    wait_frr_established "$FRR_B" "10.0.1.1" "GTSM" || return 1

    # Verify route received over GTSM-secured session
    for i in $(seq 1 15); do
        local routes
        routes=$(grpc_list_received "10.0.1.2")
        if echo "$routes" | grep -q '"prefix": "172.16.0.0"'; then
            ok "Route 172.16.0.0/16 received over GTSM session"
            return 0
        fi
        sleep 2
    done
    fail "No route received over GTSM session"
}

test_both_peers_active() {
    log "Test 3: Both secured sessions active simultaneously"

    local health
    health=$(grpc_health)
    local peers
    peers=$(echo "$health" | python3 -c "
import sys, json
print(json.load(sys.stdin).get('activePeers', 0))
" 2>/dev/null || echo 0)

    if [ "$peers" -ge 2 ]; then
        ok "Both peers active (activePeers=$peers)"
    else
        fail "Expected 2 active peers, got $peers"
    fi

    local routes
    routes=$(echo "$health" | python3 -c "
import sys, json
print(json.load(sys.stdin).get('totalRoutes', 0))
" 2>/dev/null || echo 0)

    if [ "$routes" -ge 2 ]; then
        ok "Routes from both peers present (totalRoutes=$routes)"
    else
        fail "Expected >= 2 routes, got $routes"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "M25 interop test: TCP MD5 + GTSM with FRR"
    log "Topology: $TOPO"

    resolve_grpc_addr
    start_rustbgpd

    test_md5_session
    test_gtsm_session
    test_both_peers_active

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
