#!/usr/bin/env bash
# M45 interop test — controller-injected EVPN Type 5 (IP Prefix) route
# through rustbgpd's gRPC InjectionService toward a real FRR peer.
#
# Validates the injection direction added in PR #204 (the mirror of
# M30b's decode direction):
#   1. rustbgpd reaches Established with FRR on L2VPN/EVPN.
#   2. InjectionService.AddEvpnRoute (route_type 5) is accepted.
#   3. rustbgpd's ListEvpnRoutes surfaces the injected Type 5 route.
#   4. FRR receives the Type 5 NLRI into its global BGP EVPN RIB with
#      the injected prefix, next-hop = rustbgpd (10.0.0.1), and the
#      requested route-target — proving the over-the-wire NLRI +
#      extended-community encoding decodes cleanly on a real peer.
#   5. DeleteEvpnRoute withdraws it; FRR drops it from the EVPN RIB.
#
# Pure control-plane: no kernel VRF / L3VNI on the FRR side, so the
# route lands in `show bgp l2vpn evpn` (received, not VRF-imported).
# This keeps the smoke runnable on the hosted CI runner. Kernel install
# of a received Type 5 is covered by the M39 symmetric-IRB test.
#
# Prerequisites:
#   - containerlab deploy -t tests/interop/m45-evpn-type5-injection.clab.yml
#   - grpcurl installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m45-evpn-type5-injection.sh

TOPO="m45-evpn-type5-injection"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

FRR="clab-${TOPO}-frr"
RUSTBGPD_IP="10.0.0.1"
RD="65000:5000"
PREFIX="198.51.100.0"
PREFIX_LEN=24
VNI=100
RT="65000:100"
ROUTER_MAC="02:00:00:00:50:00"

# ---------------------------------------------------------------------------
# gRPC helpers
# ---------------------------------------------------------------------------

# `|| true` so a non-zero grpcurl exit (RPC error) doesn't trip the
# `set -e` from test-lib.sh — the assertions inspect the captured text.
grpc_add_type5() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"routeType\":5,\"rd\":\"$RD\",\"ethernetTag\":0,\"label\":$VNI,\"nextHop\":\"$RUSTBGPD_IP\",\"routeTargets\":[\"$RT\"],\"disableVxlanEncap\":false,\"prefix\":\"$PREFIX\",\"prefixLength\":$PREFIX_LEN,\"routerMac\":\"$ROUTER_MAC\"}" \
        "$GRPC_ADDR" rustbgpd.v1.InjectionService/AddEvpnRoute 2>&1 || true
}

grpc_delete_type5() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"routeType\":5,\"rd\":\"$RD\",\"ethernetTag\":0,\"prefix\":\"$PREFIX\",\"prefixLength\":$PREFIX_LEN}" \
        "$GRPC_ADDR" rustbgpd.v1.InjectionService/DeleteEvpnRoute 2>&1 || true
}

grpc_list_evpn() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d '{}' \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListEvpnRoutes 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# FRR helpers
# ---------------------------------------------------------------------------

frr_type5_routes() {
    docker exec "$FRR" vtysh -c "show bgp l2vpn evpn route type prefix" 2>/dev/null || true
}

# Poll FRR's EVPN RIB until the injected prefix is present / absent.
wait_frr_type5_present() {
    local timeout=${1:-30}
    local attempts=$((timeout / 2))
    for _ in $(seq 1 "$attempts"); do
        if frr_type5_routes | grep -q "$PREFIX"; then
            return 0
        fi
        sleep 2
    done
    return 1
}

wait_frr_type5_absent() {
    local timeout=${1:-20}
    local attempts=$((timeout / 2))
    for _ in $(seq 1 "$attempts"); do
        if ! frr_type5_routes | grep -q "$PREFIX"; then
            return 0
        fi
        sleep 2
    done
    return 1
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

resolve_grpc_addr
start_rustbgpd

# Test 1: rustbgpd ↔ FRR Established on L2VPN/EVPN
wait_frr_established "$FRR" "$RUSTBGPD_IP" "FRR L2VPN/EVPN" \
    && ok "FRR reached Established with rustbgpd" \
    || fail "FRR did not reach Established"

# Test 2: inject the Type 5 route via the gRPC InjectionService
log "[test] Injecting Type 5 ${PREFIX}/${PREFIX_LEN} via AddEvpnRoute"
add_out=$(grpc_add_type5)
if echo "$add_out" | grep -qi "error"; then
    fail "AddEvpnRoute Type 5 rejected: $add_out"
else
    ok "AddEvpnRoute Type 5 accepted"
fi

# Test 3: rustbgpd ListEvpnRoutes surfaces the injected Type 5
log "[test] rustbgpd ListEvpnRoutes shows the injected Type 5"
evpn_json=$(grpc_list_evpn)
if echo "$evpn_json" | grep -q '"routeType": 5' && echo "$evpn_json" | grep -q "$PREFIX"; then
    ok "ListEvpnRoutes includes the injected Type 5 prefix"
else
    fail "ListEvpnRoutes missing the injected Type 5"
    echo "$evpn_json" | head -40 >&2
fi

# Test 4: FRR receives the Type 5 NLRI into its global EVPN RIB
log "[test] FRR receives the injected Type 5 NLRI"
if wait_frr_type5_present 30; then
    ok "FRR EVPN RIB contains injected ${PREFIX}/${PREFIX_LEN}"
else
    fail "FRR never received the injected Type 5 within 30s"
    frr_type5_routes >&2
fi

# Test 4b: the received route carries the right next-hop + route-target.
# This is the only Type 5 in the table, so co-presence in the detail
# view is an unambiguous decode signal without correlating fields.
log "[test] Received Type 5 carries next-hop + route-target"
detail=$(docker exec "$FRR" vtysh -c "show bgp l2vpn evpn route detail" 2>/dev/null || true)
if echo "$detail" | grep -q "$PREFIX"; then
    if echo "$detail" | grep -q "$RUSTBGPD_IP"; then
        ok "next-hop ${RUSTBGPD_IP} preserved on the received Type 5"
    else
        fail "next-hop ${RUSTBGPD_IP} not present on the received Type 5"
        echo "$detail" | head -40 >&2
    fi
    if echo "$detail" | grep -q "$RT"; then
        ok "route-target ${RT} decoded on the received Type 5"
    else
        fail "route-target ${RT} missing on the received Type 5"
        echo "$detail" | head -40 >&2
    fi
else
    fail "FRR route detail does not contain ${PREFIX}"
    echo "$detail" | head -40 >&2
fi

# Test 5: withdrawal — DeleteEvpnRoute removes it; FRR drops it
log "[test] Withdrawal: DeleteEvpnRoute removes the Type 5"
del_out=$(grpc_delete_type5)
if echo "$del_out" | grep -qi "error"; then
    fail "DeleteEvpnRoute Type 5 rejected: $del_out"
else
    ok "DeleteEvpnRoute Type 5 accepted"
fi
if wait_frr_type5_absent 20; then
    ok "FRR dropped ${PREFIX}/${PREFIX_LEN} after withdrawal"
else
    fail "FRR still shows ${PREFIX}/${PREFIX_LEN} 20s after withdrawal"
    frr_type5_routes >&2
fi

print_summary
