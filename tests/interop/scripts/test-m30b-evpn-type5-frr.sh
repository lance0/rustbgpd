#!/usr/bin/env bash
# M30b interop test — EVPN Type 5 (RFC 9136) IP Prefix origination from
# FRR through rustbgpd as a Route Reflector.
#
# Validates:
#   1. iBGP L2VPN/EVPN session reaches Established between FRR vtep-a
#      and rustbgpd RR.
#   2. FRR originates the tenant prefix (192.0.2.1/32 in vrf1) as a
#      Type 5 EVPN NLRI with RD 65000:100.
#   3. rustbgpd's gRPC ListEvpnRoutes surfaces the Type 5 route with
#      the expected prefix, RD, next-hop, label/VNI, and tunnel_type.
#   4. The Route Target extended community (65000:100) is preserved on
#      the RR side, plus the BGP Encapsulation community (VXLAN, 8).
#   5. Withdrawing the tenant prefix on FRR (ip addr del) propagates
#      to the RR — ListEvpnRoutes drops the entry within a few seconds.
#
# Prerequisites:
#   - containerlab deploy -t tests/interop/m30b-evpn-type5-frr.clab.yml
#   - grpcurl + jq installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m30b-evpn-type5-frr.sh

TOPO="m30b-evpn-type5-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

VTEP_A="clab-${TOPO}-vtep-a"
VTEP_A_IP="10.0.0.2"
RR_ADDR="10.0.0.1"
TENANT_PREFIX="192.0.2.1/32"
TENANT_HOST="192.0.2.1"
TENANT_DEV="lo-vrf1"
EXPECTED_RD="65000:100"
EXPECTED_VNI=100

# RT(65000:100) encoded as transitive two-octet AS-Specific (type 0x00,
# subtype 0x02): wire bytes 00 02 fd e8 00 00 00 64 → u64 BE = 842122827661412.
EXPECTED_RT_U64="842122827661412"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

grpc_list_evpn() {
    grpcurl_call \
        -d '{}' \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListEvpnRoutes 2>/dev/null
}

# Poll FRR's L2VPN/EVPN RIB for a Type 5 entry containing $TENANT_HOST.
# Returns 0 on success, 1 on timeout. 60s budget — VRF + L3VNI
# redistribution can take 10-20s after FRR boot.
wait_frr_type5_originated() {
    local timeout=${1:-60}
    local attempts=$((timeout / 2))
    for _ in $(seq 1 "$attempts"); do
        if docker exec "$VTEP_A" vtysh -c "show bgp l2vpn evpn route type prefix json" 2>/dev/null \
            | grep -q "\\[5\\]:\\[0\\]:\\[32\\]:\\[$TENANT_HOST\\]"; then
            return 0
        fi
        sleep 2
    done
    return 1
}

# Poll rustbgpd's ListEvpnRoutes until a Type 5 entry for $TENANT_PREFIX
# is absent. Returns 0 on success, 1 on timeout.
wait_rustbgpd_type5_withdrawn() {
    local timeout=${1:-30}
    local attempts=$((timeout / 2))
    for _ in $(seq 1 "$attempts"); do
        local n
        n=$(grpc_list_evpn | jq -r --arg p "$TENANT_PREFIX" \
            '[.routes[]? | select(.routeType == 5 and .prefix == $p)] | length')
        if [ "${n:-0}" = "0" ]; then
            return 0
        fi
        sleep 2
    done
    return 1
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required (apt-get install jq)" >&2
    exit 1
fi

resolve_grpc_addr
start_rustbgpd

# Test 1: session reaches Established
wait_frr_established "$VTEP_A" "$RR_ADDR" "VTEP-A L2VPN/EVPN" \
    || fail "VTEP-A did not reach Established"

# Test 2: FRR originates the Type 5 NLRI for the tenant prefix
log "[test] FRR originates Type 5 for $TENANT_PREFIX (RD $EXPECTED_RD)"
if wait_frr_type5_originated 60; then
    ok "FRR shows Type 5 NLRI for $TENANT_PREFIX in L2VPN/EVPN RIB"
else
    fail "FRR never originated Type 5 for $TENANT_PREFIX within 60s"
    docker exec "$VTEP_A" vtysh -c "show bgp l2vpn evpn route type prefix" >&2 || true
    docker exec "$VTEP_A" vtysh -c "show evpn vni 100" >&2 || true
fi

# Test 3: rustbgpd surfaces the Type 5 with expected fields
log "[test] rustbgpd ListEvpnRoutes shows the Type 5 with expected fields"
evpn_json=$(grpc_list_evpn)
type5_entry=$(echo "$evpn_json" | jq -c --arg p "$TENANT_PREFIX" \
    '.routes[]? | select(.routeType == 5 and .prefix == $p)' 2>/dev/null | head -1)
if [ -z "$type5_entry" ]; then
    fail "rustbgpd has no Type 5 entry for $TENANT_PREFIX"
    echo "$evpn_json" | head -40 >&2
else
    ok "Type 5 entry present for $TENANT_PREFIX"

    rd=$(echo "$type5_entry" | jq -r '.rd')
    [ "$rd" = "$EXPECTED_RD" ] && ok "RD = $EXPECTED_RD" \
        || fail "RD expected $EXPECTED_RD, got '$rd'"

    nh=$(echo "$type5_entry" | jq -r '.nextHop')
    [ "$nh" = "$VTEP_A_IP" ] && ok "next_hop = $VTEP_A_IP (vtep-a)" \
        || fail "next_hop expected $VTEP_A_IP, got '$nh'"

    label=$(echo "$type5_entry" | jq -r '.label')
    # RFC 9136 + RFC 8365 §5: VXLAN encap puts the raw 24-bit VNI in
    # the label field. FRR observed to send the raw VNI (100). Tolerate
    # the shifted (label-with-S-bit) form too in case a future FRR
    # release changes encoding (M30 test 6 uses the same defensive
    # tolerance for Type 2 VNI labels).
    if [ "$label" = "$EXPECTED_VNI" ] || [ "$label" = "$((EXPECTED_VNI << 4))" ]; then
        ok "label encodes VNI $EXPECTED_VNI (raw or shifted form)"
    else
        fail "label expected $EXPECTED_VNI or $((EXPECTED_VNI << 4)), got '$label'"
    fi
fi

# Test 4: RT extended community + BGP Encapsulation (VXLAN) preserved
log "[test] RT $EXPECTED_RD + VXLAN encap community preserved"
if [ -n "$type5_entry" ]; then
    if echo "$type5_entry" | jq -e --arg rt "$EXPECTED_RT_U64" \
        '.extendedCommunities | index($rt)' >/dev/null 2>&1; then
        ok "RT $EXPECTED_RD encoded community present"
    else
        fail "RT $EXPECTED_RD (u64=$EXPECTED_RT_U64) not in extendedCommunities"
        echo "$type5_entry" | jq -r '.extendedCommunities' >&2
    fi
    tt=$(echo "$type5_entry" | jq -r '.tunnelType')
    [ "$tt" = "8" ] && ok "tunnel_type = 8 (VXLAN encap, RFC 9012)" \
        || fail "tunnel_type expected 8, got '$tt'"
fi

# Test 5: withdrawal — remove the tenant prefix on vtep-a
log "[test] Withdrawal: remove $TENANT_PREFIX from $TENANT_DEV on vtep-a"
docker exec "$VTEP_A" ip addr del "$TENANT_PREFIX" dev "$TENANT_DEV" 2>/dev/null || true
if wait_rustbgpd_type5_withdrawn 30; then
    ok "rustbgpd dropped Type 5 for $TENANT_PREFIX after FRR withdrawal"
else
    fail "rustbgpd still shows Type 5 for $TENANT_PREFIX 30s after withdrawal"
    grpc_list_evpn | jq -c '.routes[]? | select(.routeType == 5)' >&2 || true
fi

print_summary
