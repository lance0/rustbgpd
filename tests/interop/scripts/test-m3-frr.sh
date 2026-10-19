#!/usr/bin/env bash
# M3 interop test — rustbgpd ↔ 2× FRR (route redistribution + injection)
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m3-frr.clab.yml
#   - grpcurl installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m3-frr.sh


TOPO="m3-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
source "$SCRIPT_DIR/test-lib.sh"
FRR_A="clab-${TOPO}-frr-a"
FRR_B="clab-${TOPO}-frr-b"
FRR_C="clab-${TOPO}-frr-c"


# Resolve rustbgpd container management IP for gRPC access

grpc_list_received() {
    grpcurl_call \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

grpc_list_best() {
    grpcurl_call \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListBestRoutes 2>/dev/null
}

grpc_list_advertised() {
    grpcurl_call \
        -d "{\"neighbor_address\": \"$1\"}" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListAdvertisedRoutes 2>/dev/null
}

grpc_add_path() {
    local prefix=$1 prefix_len=$2 next_hop=$3
    shift 3
    local origin=${1:-0}
    grpcurl_call \
        -d "{\"prefix\": \"$prefix\", \"prefix_length\": $prefix_len, \"next_hop\": \"$next_hop\", \"origin\": $origin}" \
        "$GRPC_ADDR" rustbgpd.v1.InjectionService/AddPath 2>/dev/null
}

grpc_delete_path() {
    local prefix=$1 prefix_len=$2
    grpcurl_call \
        -d "{\"prefix\": \"$prefix\", \"prefix_length\": $prefix_len}" \
        "$GRPC_ADDR" rustbgpd.v1.InjectionService/DeletePath 2>/dev/null
}

wait_routes_in_rib() {
    local expected=$1
    log "Waiting for $expected received routes in RIB..."
    for i in $(seq 1 15); do
        local count
        count=$(grpc_list_received | grep -c '"prefix"' || true)
        if [ "$count" -ge "$expected" ]; then
            ok "Got $count received routes in RIB (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "Expected $expected received routes, got $(grpc_list_received | grep -c '"prefix"' || echo 0)"
    return 1
}

# Check if FRR-B has received a specific prefix from rustbgpd
frr_b_has_prefix() {
    local prefix=$1
    docker exec "$FRR_B" vtysh -c "show bgp ipv4 unicast $prefix json" 2>/dev/null \
        | grep -q '"prefix"' 2>/dev/null
}

# ---------------------------------------------------------------------------
# Test 1: Route redistribution — FRR-A → rustbgpd → FRR-B
# ---------------------------------------------------------------------------
test_route_redistribution() {
    log "Test 1: Route redistribution (FRR-A → rustbgpd → FRR-B)"

    wait_frr_established "$FRR_A" 10.0.0.1 FRR-A || return 1
    wait_frr_established "$FRR_B" 10.0.1.1 FRR-B || return 1
    wait_routes_in_rib 3 || return 1

    # Wait for outbound distribution to FRR-B
    log "Waiting for routes to propagate to FRR-B..."
    local found=false
    for i in $(seq 1 15); do
        if frr_b_has_prefix "192.168.1.0/24"; then
            found=true
            break
        fi
        sleep 2
    done

    if [ "$found" = "true" ]; then
        ok "FRR-B received 192.168.1.0/24 from rustbgpd"
    else
        fail "FRR-B did not receive 192.168.1.0/24"
    fi

    # Check all 3 prefixes
    for prefix in "192.168.2.0/24" "10.10.0.0/16"; do
        if frr_b_has_prefix "$prefix"; then
            ok "FRR-B received $prefix"
        else
            fail "FRR-B missing $prefix"
        fi
    done

    # Verify attributes on FRR-B: AS_PATH should contain 65001 (rustbgpd) + 65002 (FRR-A)
    local as_path
    as_path=$(docker exec "$FRR_B" vtysh -c "show bgp ipv4 unicast 192.168.1.0/24 json" 2>/dev/null || true)
    if echo "$as_path" | grep -q "65001"; then
        ok "AS_PATH on FRR-B contains 65001 (rustbgpd)"
    else
        fail "AS_PATH on FRR-B missing 65001"
    fi
    if echo "$as_path" | grep -q "65002"; then
        ok "AS_PATH on FRR-B contains 65002 (FRR-A)"
    else
        fail "AS_PATH on FRR-B missing 65002"
    fi
}

# ---------------------------------------------------------------------------
# Test 2: Split horizon — FRR-A does NOT receive back its own routes
# ---------------------------------------------------------------------------
test_split_horizon() {
    log "Test 2: Split horizon (FRR-A should not receive its own routes back)"

    # Check Adj-RIB-Out for FRR-A — should be empty (all routes came from A)
    local advertised
    advertised=$(grpc_list_advertised "10.0.0.2" || echo "{}")
    local count
    count=$(echo "$advertised" | grep -c '"prefix"' || true)

    if [ "$count" -eq 0 ]; then
        ok "No routes advertised back to FRR-A (split horizon works)"
    else
        fail "Split horizon violated: $count routes advertised to FRR-A"
    fi
}

# ---------------------------------------------------------------------------
# Test 3: Route injection via gRPC — AddPath + redistribution
# ---------------------------------------------------------------------------
test_route_injection() {
    log "Test 3: Route injection via gRPC AddPath"

    # Inject a route
    local result
    result=$(grpc_add_path "172.16.0.0" 16 "10.0.0.1" 0 || echo "ERROR")
    if [ "$result" = "ERROR" ]; then
        fail "AddPath gRPC call failed"
    else
        ok "AddPath succeeded"
    fi

    # Wait for best routes to include our injected route
    sleep 3
    local best
    best=$(grpc_list_best)
    if echo "$best" | grep -q '"prefix": "172.16.0.0"'; then
        ok "Injected route in Loc-RIB"
    else
        fail "Injected route not in Loc-RIB"
    fi

    # Both FRR-A and FRR-B should receive the injected route
    log "Waiting for injected route to propagate..."
    sleep 3

    if frr_b_has_prefix "172.16.0.0/16"; then
        ok "FRR-B received injected route 172.16.0.0/16"
    else
        fail "FRR-B did not receive injected route 172.16.0.0/16"
    fi

    local frr_a_routes
    frr_a_routes=$(docker exec "$FRR_A" vtysh -c "show bgp ipv4 unicast 172.16.0.0/16 json" 2>/dev/null || true)
    if echo "$frr_a_routes" | grep -q '"prefix"'; then
        ok "FRR-A received injected route 172.16.0.0/16"
    else
        fail "FRR-A did not receive injected route 172.16.0.0/16"
    fi
}

# ---------------------------------------------------------------------------
# Test 4: Withdrawal propagation — FRR-A withdraws → FRR-B sees withdrawal
# ---------------------------------------------------------------------------
test_withdrawal_propagation() {
    log "Test 4: Withdrawal propagation (FRR-A → rustbgpd → FRR-B)"

    # Withdraw 192.168.2.0/24 from FRR-A
    docker exec "$FRR_A" vtysh -c "conf t" -c "router bgp 65002" \
        -c "address-family ipv4 unicast" -c "no network 192.168.2.0/24" \
        -c "end" 2>/dev/null

    log "Waiting for withdrawal to propagate..."
    sleep 5

    # FRR-B should no longer have the prefix
    if frr_b_has_prefix "192.168.2.0/24"; then
        fail "FRR-B still has 192.168.2.0/24 after withdrawal"
    else
        ok "192.168.2.0/24 withdrawn from FRR-B"
    fi

    # Other routes should still be present on FRR-B
    if frr_b_has_prefix "192.168.1.0/24"; then
        ok "192.168.1.0/24 still present on FRR-B"
    else
        fail "192.168.1.0/24 unexpectedly removed from FRR-B"
    fi

    # Re-add the route
    docker exec "$FRR_A" vtysh -c "conf t" -c "router bgp 65002" \
        -c "address-family ipv4 unicast" -c "network 192.168.2.0/24" \
        -c "end" 2>/dev/null
    sleep 3
}

# ---------------------------------------------------------------------------
# Test 5: DeletePath — withdrawal propagated to all peers
# ---------------------------------------------------------------------------
test_delete_path() {
    log "Test 5: DeletePath via gRPC"

    # Delete the injected route from test 3
    local result
    result=$(grpc_delete_path "172.16.0.0" 16 || echo "ERROR")

    sleep 3

    # Should be gone from Loc-RIB
    local best
    best=$(grpc_list_best)
    if echo "$best" | grep -q '"prefix": "172.16.0.0"'; then
        fail "Injected route still in Loc-RIB after DeletePath"
    else
        ok "Injected route removed from Loc-RIB"
    fi

    # Should be withdrawn from FRR-B
    if frr_b_has_prefix "172.16.0.0/16"; then
        fail "FRR-B still has 172.16.0.0/16 after DeletePath"
    else
        ok "172.16.0.0/16 withdrawn from FRR-B"
    fi
}

# ---------------------------------------------------------------------------
# Test 6: next-hop self — AddPath with next_hop 0.0.0.0 reaches each FRR peer
# with that session's local address, and the controller contract holds:
# created / unchanged outcomes, NOT_FOUND by default, NOT_PRESENT with
# allow_missing.
# ---------------------------------------------------------------------------
frr_next_hop() {
    local container=$1 prefix=$2
    docker exec "$container" vtysh -c "show bgp ipv4 unicast $prefix json" 2>/dev/null \
        | python3 -c '
import json, sys
text = sys.stdin.read()
start = text.find("{")
paths = json.loads(text[start:]).get("paths", []) if start >= 0 else []
print(paths[0]["nexthops"][0]["ip"] if paths else "")
'
}

grpc_delete_path_allow_missing() {
    local prefix=$1 prefix_len=$2
    grpcurl_call \
        -d "{\"prefix\": \"$prefix\", \"prefix_length\": $prefix_len, \"allow_missing\": true}" \
        "$GRPC_ADDR" rustbgpd.v1.InjectionService/DeletePath 2>/dev/null
}

# Pre-policy Adj-RIB-In next hop FRR-C recorded from rustbgpd (iBGP).
frr_c_received_next_hop() {
    local afi=$1 prefix=$2
    docker exec "$FRR_C" vtysh -c "show bgp $afi unicast neighbors 10.0.2.1 received-routes json" 2>/dev/null \
        | python3 -c '
import json, sys
route = json.load(sys.stdin).get("receivedRoutes", {}).get(sys.argv[1], {})
print(route.get("nextHopGlobal") or route.get("nextHop") or "")
' "$prefix"
}

expect_frr_next_hop() {
    local container=$1 prefix=$2 expected=$3 actual=""
    for _ in $(seq 1 15); do
        actual=$(frr_next_hop "$container" "$prefix")
        [ "$actual" = "$expected" ] && break
        sleep 1
    done
    if [ "$actual" = "$expected" ]; then
        ok "$container: $prefix next hop $actual (session local address)"
    else
        fail "$container: $prefix next hop '$actual', expected $expected"
    fi
}

test_next_hop_self_injection() {
    log "Test 6: AddPath next hop 0.0.0.0 is next-hop self per session"

    local result
    result=$(grpc_add_path "172.17.0.0" 16 "0.0.0.0" 0 || echo "ERROR")
    if echo "$result" | grep -q '"outcome": "PATH_INJECT_OUTCOME_CREATED"'; then
        ok "AddPath 0.0.0.0 accepted (CREATED)"
    else
        fail "AddPath 0.0.0.0 not created: $result"
    fi
    result=$(grpc_add_path "172.17.0.0" 16 "0.0.0.0" 0 || echo "ERROR")
    if echo "$result" | grep -q '"outcome": "PATH_INJECT_OUTCOME_UNCHANGED"'; then
        ok "Identical AddPath reports UNCHANGED"
    else
        fail "Identical AddPath did not report UNCHANGED: $result"
    fi

    expect_frr_next_hop "$FRR_A" "172.17.0.0/16" "10.0.0.1"
    expect_frr_next_hop "$FRR_B" "172.17.0.0/16" "10.0.1.1"
    # iBGP keeps a received next hop, so only next-hop self puts 10.0.2.1 here;
    # an unresolved 0.0.0.0 would show up as such in the Adj-RIB-In.
    local actual=""
    for _ in $(seq 1 15); do
        actual=$(frr_c_received_next_hop ipv4 "172.17.0.0/16")
        [ "$actual" = "10.0.2.1" ] && break
        sleep 1
    done
    if [ "$actual" = "10.0.2.1" ]; then
        ok "$FRR_C (iBGP): 172.17.0.0/16 received with next hop 10.0.2.1"
    else
        fail "$FRR_C (iBGP): 172.17.0.0/16 received next hop '$actual', expected 10.0.2.1"
    fi

    # IPv6 next-hop self over this IPv4-only session has no local IPv6
    # address: the route is refused for FRR-C rather than sent with ::. The
    # refusal is only evidence while IPv6 unicast is negotiated.
    if docker exec "$FRR_C" vtysh -c "show bgp neighbors 10.0.2.1 json" 2>/dev/null \
        | python3 -c '
import json, sys
caps = json.load(sys.stdin)["10.0.2.1"]["neighborCapabilities"]["multiprotocolExtensions"]
sys.exit(caps.get("ipv6Unicast", {}).get("advertisedAndReceived") is not True)
'; then
        ok "$FRR_C negotiated IPv6 unicast with rustbgpd"
    else
        fail "$FRR_C did not negotiate IPv6 unicast; the IPv6 refusal check is vacuous"
    fi
    result=$(grpcurl_call \
        -d '{"prefix": "2001:db8:3::", "prefix_length": 48, "next_hop": "::"}' \
        "$GRPC_ADDR" rustbgpd.v1.InjectionService/AddPath 2>/dev/null || echo "ERROR")
    if echo "$result" | grep -q '"outcome": "PATH_INJECT_OUTCOME_CREATED"'; then
        ok "AddPath :: accepted (CREATED)"
    else
        fail "AddPath :: not created: $result"
    fi
    sleep 3
    actual=$(frr_c_received_next_hop ipv6 "2001:db8:3::/48")
    if [ -z "$actual" ]; then
        ok "$FRR_C: 2001:db8:3::/48 refused (no local IPv6 next hop)"
    else
        fail "$FRR_C: 2001:db8:3::/48 received with next hop '$actual'"
    fi
    if docker exec "$FRR_C" vtysh -c "show bgp neighbors 10.0.2.1 json" 2>/dev/null \
        | python3 -c 'import json, sys; sys.exit(json.load(sys.stdin)["10.0.2.1"]["bgpState"] != "Established")'; then
        ok "$FRR_C session stays Established"
    else
        fail "$FRR_C session is not Established"
    fi
    grpc_delete_path "2001:db8:3::" 48 >/dev/null || fail "DeletePath 2001:db8:3::/48 failed"

    result=$(grpc_delete_path "172.17.0.0" 16 || echo "ERROR")
    if echo "$result" | grep -q '"outcome": "PATH_DELETE_OUTCOME_DELETED"'; then
        ok "DeletePath reports DELETED"
    else
        fail "DeletePath did not report DELETED: $result"
    fi
    local status
    status=$(grpcurl_call -d '{"prefix": "172.17.0.0", "prefix_length": 16}' \
        "$GRPC_ADDR" rustbgpd.v1.InjectionService/DeletePath 2>&1 || true)
    if echo "$status" | grep -q "NotFound"; then
        ok "Missing DeletePath without allow_missing is NOT_FOUND"
    else
        fail "Missing DeletePath without allow_missing: $status"
    fi
    result=$(grpc_delete_path_allow_missing "172.17.0.0" 16 || echo "ERROR")
    if echo "$result" | grep -q '"outcome": "PATH_DELETE_OUTCOME_NOT_PRESENT"'; then
        ok "Missing DeletePath with allow_missing is NOT_PRESENT"
    else
        fail "Missing DeletePath with allow_missing: $result"
    fi

    local gone=false
    for _ in $(seq 1 15); do
        if ! frr_b_has_prefix "172.17.0.0/16"; then
            gone=true
            break
        fi
        sleep 1
    done
    if [ "$gone" = true ]; then
        ok "172.17.0.0/16 withdrawn from FRR-B"
    else
        fail "FRR-B still has 172.17.0.0/16 after DeletePath"
    fi
}

# Start rustbgpd inside the container (CMD is sleep infinity)
# Use the robust `start_rustbgpd` from test-lib.sh (10 s poll loop
# rather than a 3 s fixed sleep) — required under parallel CI load.

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "M3 interop test: rustbgpd ↔ 2× FRR"
    log "Topology: $TOPO"

    resolve_grpc_addr
    start_rustbgpd

    test_route_redistribution
    test_split_horizon
    test_route_injection
    test_withdrawal_propagation
    test_delete_path
    test_next_hop_self_injection

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
