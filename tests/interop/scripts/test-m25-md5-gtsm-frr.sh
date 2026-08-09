#!/usr/bin/env bash
# M25 interop test — TCP MD5 + GTSM / TTL security with FRR
#
# Validates:
#   1. BGP session with TCP MD5 authentication (RFC 2385)
#   2. BGP session with GTSM / TTL security (RFC 5082)
#   3. Routes exchanged over both secured sessions
#   4. IPv6 dynamic accepted sockets inherit MD5 + GTSM from their peer group
#   5. Wrong MD5 and missing GTSM each prevent the IPv6 session
#   6. Restoring each protection restores the session and route
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m25-md5-gtsm-frr.clab.yml
#   - grpcurl installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m25-md5-gtsm-frr.sh


TOPO="m25-md5-gtsm-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"
FRR_A="clab-${TOPO}-frr-a"
FRR_B="clab-${TOPO}-frr-b"
FRR_C="clab-${TOPO}-frr-c"
RUSTBGPD_V6="2001:db8:25::1"
FRR_C_V6="2001:db8:25::2"
FRR_C_PREFIX="2001:db8:2500::/48"


grpc_list_received() {
    grpcurl_call \
        -d "{\"neighbor_address\": \"$1\"}" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

grpc_list_neighbors() {
    grpcurl_call \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/ListNeighbors 2>/dev/null
}

grpc_list_dynamic_neighbors() {
    grpcurl_call \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/ListDynamicNeighbors 2>/dev/null
}

wait_route_received() {
    local peer_addr=$1
    local prefix=$2
    local label=$3
    local prefix_addr=${prefix%/*}
    local prefix_length=${prefix#*/}

    for i in $(seq 1 15); do
        if grpc_list_received "$peer_addr" \
            | jq -e --arg prefix "$prefix_addr" --argjson prefix_length "$prefix_length" '
                any(.routes[]?;
                    .prefix == $prefix and .prefixLength == $prefix_length)
            ' >/dev/null 2>&1; then
            ok "$label route $prefix received (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$label route $prefix was not received within 30s"
    return 1
}

wait_frr_not_established() {
    local frr_container=$1
    local peer_addr=$2
    local label=$3

    # Require a full 10-second stable window. A one-shot non-Established read
    # immediately after `clear bgp` would be vacuous even if the bad transport
    # configuration re-established on the next connect attempt.
    for i in $(seq 1 5); do
        local neighbor_json state
        if ! neighbor_json=$(docker exec "$frr_container" \
            vtysh -c "show bgp neighbors $peer_addr json" 2>/dev/null); then
            fail "$label could not read the FRR neighbor state (attempt $i)"
            return 1
        fi
        if ! state=$(jq -er '
            [.. | objects | .bgpState?
                | select(type == "string" and length > 0)][0]
        ' <<<"$neighbor_json" 2>/dev/null); then
            fail "$label received no verifiable FRR neighbor state (attempt $i)"
            return 1
        fi
        if [ "$state" = "Established" ]; then
            fail "$label unexpectedly re-established during negative window (attempt $i)"
            return 1
        fi
        sleep 2
    done
    ok "$label stayed down for the 10-second negative window"
}

frr_c_neighbor_command() {
    local command=$1

    docker exec "$FRR_C" vtysh \
        -c "configure terminal" \
        -c "router bgp 65004" \
        -c "$command" >/dev/null 2>&1
    # FRR resets the peer asynchronously after a transport command. Let that
    # reset leave Idle before clearing, otherwise a clear issued in the same
    # instant can be consumed by the old FSM and leave the next active-open on
    # its full connect-retry timer.
    sleep 1
    docker exec "$FRR_C" vtysh -c "clear bgp $RUSTBGPD_V6" >/dev/null 2>&1
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
    log "Test 4: All secured sessions active simultaneously"

    local health
    health=$(grpc_health)
    local peers
    peers=$(echo "$health" | python3 -c "
import sys, json
print(json.load(sys.stdin).get('activePeers', 0))
" 2>/dev/null || echo 0)

    if [ "$peers" -eq 3 ]; then
        ok "All three peers active (activePeers=$peers)"
    else
        fail "Expected 3 active peers, got $peers"
    fi

    local routes
    routes=$(echo "$health" | python3 -c "
import sys, json
print(json.load(sys.stdin).get('totalRoutes', 0))
" 2>/dev/null || echo 0)

    if [ "$routes" -eq 3 ]; then
        ok "Routes from all three peers present (totalRoutes=$routes)"
    else
        fail "Expected exactly 3 routes, got $routes"
    fi
}

test_ipv6_dynamic_auth() {
    log "Test 3: IPv6 dynamic accepted socket with MD5 + GTSM (FRR-C, AS 65004)"

    wait_frr_established "$FRR_C" "$RUSTBGPD_V6" "IPv6 dynamic MD5+GTSM" || return 1
    wait_route_received "$FRR_C_V6" "$FRR_C_PREFIX" "IPv6 dynamic MD5+GTSM" || return 1

    local neighbors ranges result
    neighbors=$(grpc_list_neighbors)
    ranges=$(grpc_list_dynamic_neighbors)
    result=$(NEIGHBORS="$neighbors" RANGES="$ranges" python3 - <<'PY'
import json
import os

neighbors = json.loads(os.environ["NEIGHBORS"])
ranges = json.loads(os.environ["RANGES"])
peer_ok = any(
    row.get("config", {}).get("address") == "2001:db8:25::2"
    and row.get("config", {}).get("peerGroup") == "ipv6-dynamic-auth"
    and row.get("isDynamic") is True
    for row in neighbors.get("neighbors", [])
)
range_ok = any(
    row.get("prefix") == "2001:db8:25::/64"
    and row.get("peerGroup") == "ipv6-dynamic-auth"
    and row.get("remoteAsn") == 65004
    for row in ranges.get("ranges", [])
)
if peer_ok:
    print("peer_ok")
if range_ok:
    print("range_ok")
PY
)
    if grep -q '^peer_ok$' <<<"$result"; then
        ok "IPv6 peer is dynamic and inherits the authenticated peer group"
    else
        fail "IPv6 peer was not exposed as a dynamic peer in the authenticated group"
    fi
    if grep -q '^range_ok$' <<<"$result"; then
        ok "IPv6 authenticated dynamic range is exposed with AS 65004"
    else
        fail "IPv6 authenticated dynamic range was not exposed as configured"
    fi
}

test_ipv6_md5_negative_and_restore() {
    log "Test 5: Wrong IPv6 MD5 password fails closed, then restores"

    frr_c_neighbor_command \
        "neighbor $RUSTBGPD_V6 password wrong-interop-secret-m25-v6"
    wait_frr_not_established "$FRR_C" "$RUSTBGPD_V6" "Wrong-MD5 IPv6 session" || return 1

    frr_c_neighbor_command \
        "neighbor $RUSTBGPD_V6 password interop-secret-m25-v6"
    wait_frr_established "$FRR_C" "$RUSTBGPD_V6" "IPv6 MD5 restore" || return 1
    wait_route_received "$FRR_C_V6" "$FRR_C_PREFIX" "IPv6 MD5 restore"
}

test_ipv6_gtsm_negative_and_restore() {
    log "Test 6: Missing IPv6 GTSM fails closed, then restores"

    frr_c_neighbor_command "no neighbor $RUSTBGPD_V6 ttl-security hops 1"
    wait_frr_not_established "$FRR_C" "$RUSTBGPD_V6" "No-GTSM IPv6 session" || return 1

    frr_c_neighbor_command "neighbor $RUSTBGPD_V6 ttl-security hops 1"
    wait_frr_established "$FRR_C" "$RUSTBGPD_V6" "IPv6 GTSM restore" || return 1
    wait_route_received "$FRR_C_V6" "$FRR_C_PREFIX" "IPv6 GTSM restore"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "M25 interop test: TCP MD5 + GTSM with FRR (static + IPv6 dynamic accept)"
    log "Topology: $TOPO"

    resolve_grpc_addr
    start_rustbgpd "/usr/local/bin/start-rustbgpd.sh"

    test_md5_session
    test_gtsm_session
    test_ipv6_dynamic_auth
    test_both_peers_active
    test_ipv6_md5_negative_and_restore
    test_ipv6_gtsm_negative_and_restore

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
