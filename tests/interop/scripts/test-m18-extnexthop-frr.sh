#!/usr/bin/env bash
# M18 interop test — Extended Next-Hop (RFC 8950)
#
# Validates: rustbgpd advertises the RFC 8950 Extended Next Hop capability
# for IPv4 unicast, and does not use an IPv6 next hop when the peer does not
# reciprocate.
#
# Topology: rustbgpd (AS 65001) ↔ FRR (AS 65002) on dual-stack link, one
# session over IPv4 transport (10.0.0.1 ↔ 10.0.0.2).
#
# FRR advertises Extended Next Hop only on sessions over IPv6 transport; its
# `neighbor ... capability extended-nexthop` line has no effect on this IPv4
# session. The capability is therefore received by FRR but NOT negotiated,
# and rustbgpd must send IPv4 routes in the IPv4 body with an IPv4 next hop.
# Negotiated-ENHE behaviour against FRR is covered by M53 (IPv6 link-local
# transport) and against GoBGP by M107.
#
# Key proof points:
#   - FRR receives rustbgpd's Extended Next Hop capability for IPv4 unicast
#     and does not advertise its own (exact `extendedNexthop` value)
#   - IPv4 + IPv6 routes exchanged over single IPv4 session
#   - rustbgpd's injected IPv4 route reaches FRR with IPv4 next hop 10.0.0.1,
#     not the configured IPv6 next hop fd00::1
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m18-extnexthop-frr.clab.yml
#   - grpcurl installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m18-extnexthop-frr.sh


TOPO="m18-extnexthop-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
source "$SCRIPT_DIR/test-lib.sh"
FRR="clab-${TOPO}-frr"


grpc_list_received() {
    grpcurl_call \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

grpc_list_best() {
    grpcurl_call \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListBestRoutes 2>/dev/null
}

grpc_inject_route() {
    grpcurl_call \
        -d "{\"prefix\": \"$1\", \"prefix_length\": $2, \"next_hop\": \"$3\", \"origin\": 0}" \
        "$GRPC_ADDR" rustbgpd.v1.InjectionService/AddPath 2>/dev/null
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

# Use the robust `start_rustbgpd` from test-lib.sh (10 s poll loop
# rather than a 3 s fixed sleep) — required under parallel CI load.

# ---------------------------------------------------------------------------
# Test 1: Session establishes with both address families
# ---------------------------------------------------------------------------
test_session_established() {
    log "Test 1: Session establishes with dual-stack families"

    # Verify FRR sees both IPv4 and IPv6 address families negotiated
    local neighbor_json
    neighbor_json=$(docker exec "$FRR" vtysh -c "show bgp neighbors 10.0.0.1 json" 2>/dev/null)

    if echo "$neighbor_json" | grep -q '"bgpState":"Established"'; then
        ok "Session is Established"
    else
        fail "Session not Established"
    fi

    # FRR reports `neighborCapabilities.extendedNexthop` as "advertised",
    # "received" or "advertisedAndReceived", so the key alone proves nothing.
    # On this IPv4-transport session FRR does not advertise the capability,
    # so the exact expected value is "received": rustbgpd sent it, FRR did
    # not, and it is not negotiated. `extendedNexthopFamililesByPeer` (FRR's
    # spelling) lists the NLRI families FRR received with an IPv6 next hop.
    local enhe enhe_ipv4
    enhe=$(printf '%s\n' "$neighbor_json" \
        | jq -r '."10.0.0.1".neighborCapabilities.extendedNexthop // "absent"' 2>/dev/null \
        || echo "unreadable")
    enhe_ipv4=$(printf '%s\n' "$neighbor_json" \
        | jq -r '."10.0.0.1".neighborCapabilities.extendedNexthopFamililesByPeer.ipv4Unicast // "absent"' 2>/dev/null \
        || echo "unreadable")
    if [ "$enhe" = "received" ] && [ "$enhe_ipv4" = "recieved" ]; then
        ok "FRR received rustbgpd's Extended Next Hop capability for IPv4 unicast (not negotiated: FRR does not advertise it over IPv4 transport)"
    else
        fail "Expected FRR extendedNexthop=received with ipv4Unicast=recieved, got extendedNexthop=$enhe ipv4Unicast=$enhe_ipv4"
    fi
}

# ---------------------------------------------------------------------------
# Test 2: IPv4 routes received from FRR
# ---------------------------------------------------------------------------
test_ipv4_routes_received() {
    log "Test 2: IPv4 unicast routes received from FRR"

    local routes
    routes=$(grpc_list_received)

    for prefix in "192.168.1.0" "192.168.2.0"; do
        if echo "$routes" | grep -q "\"prefix\": \"$prefix\""; then
            ok "IPv4 prefix $prefix received"
        else
            fail "IPv4 prefix $prefix missing"
        fi
    done
}

# ---------------------------------------------------------------------------
# Test 3: IPv6 routes received from FRR
# ---------------------------------------------------------------------------
test_ipv6_routes_received() {
    log "Test 3: IPv6 unicast routes received from FRR"

    local routes
    routes=$(grpc_list_received)

    if echo "$routes" | grep -q "2001:db8:1::"; then
        ok "IPv6 prefix 2001:db8:1::/48 received"
    else
        fail "IPv6 prefix 2001:db8:1::/48 missing"
    fi
}

# ---------------------------------------------------------------------------
# Test 4: Injected IPv4 route arrives at FRR
# ---------------------------------------------------------------------------
test_injected_route_reaches_frr() {
    log "Test 4: Injected IPv4 route reaches FRR"

    grpc_inject_route "10.99.0.0" 24 "10.0.0.1"
    sleep 3

    local frr_routes
    frr_routes=$(docker exec "$FRR" vtysh -c "show bgp ipv4 unicast 10.99.0.0/24 json" 2>/dev/null)

    if echo "$frr_routes" | grep -q "10.99.0.0"; then
        ok "Injected route 10.99.0.0/24 received by FRR"
    else
        fail "Injected route 10.99.0.0/24 not received by FRR"
    fi
}

# ---------------------------------------------------------------------------
# Test 5: Without negotiated Extended Next Hop, FRR sees an IPv4 next hop
# ---------------------------------------------------------------------------
test_ipv4_nexthop_without_enhe() {
    log "Test 5: IPv4 route from rustbgpd carries IPv4 next hop (Extended Next Hop not negotiated)"

    local route_json
    route_json=$(docker exec "$FRR" vtysh -c "show bgp ipv4 unicast 10.99.0.0/24 json" 2>/dev/null)

    # FRR did not advertise Extended Next Hop (Test 1), so RFC 8950 forbids an
    # IPv6 next hop for IPv4 NLRI. rustbgpd's eBGP export sets the next hop to
    # its local IPv4 session address (10.0.0.1, which is also the injected next
    # hop), so FRR must see exactly ipv4/10.0.0.1.
    # Seeing the configured `local_ipv6_nexthop` (fd00::1) here would mean the
    # export ignored the peer's missing capability.
    local nh
    nh=$(printf '%s\n' "$route_json" \
        | jq -r '[.paths[0].nexthops[]? | "\(.afi)/\(.ip)"] | join(",")' 2>/dev/null \
        || echo "unreadable")
    if [ "$nh" = "ipv4/10.0.0.1" ]; then
        ok "FRR sees IPv4 next-hop 10.0.0.1 on 10.99.0.0/24 (no IPv6 next hop without negotiated Extended Next Hop)"
    else
        fail "Expected exactly IPv4 next-hop 10.0.0.1 on 10.99.0.0/24, FRR shows '${nh}'"
    fi
}
# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "M18 interop test: Extended Next-Hop (RFC 8950)"
    log "Topology: $TOPO"

    resolve_grpc_addr
    start_rustbgpd

    wait_frr_established "$FRR" 10.0.0.1 || true
    wait_routes 3 || true

    test_session_established
    test_ipv4_routes_received
    test_ipv6_routes_received
    test_injected_route_reaches_frr
    test_ipv4_nexthop_without_enhe

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
