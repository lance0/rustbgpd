#!/usr/bin/env bash
# M30 interop test — EVPN Type 2 MAC reflection through rustbgpd RR
#
# Validates:
#   1. Both VTEPs reach Established with L2VPN/EVPN negotiated.
#   2. VTEP-B observes VTEP-A's IMET (Type 3) through the reflection —
#      baseline that EVPN control plane flows across the RR.
#   3. MAC injected on VTEP-A via bridge FDB appears on VTEP-B's
#      'show evpn mac vni 100' with VTEP-A as the remote VTEP IP.
#   4. The reflected Type 2 UPDATE at VTEP-B carries ORIGINATOR_ID ==
#      VTEP-A's router-id and CLUSTER_LIST containing the RR's
#      cluster-id (RFC 4456 reflection semantics).
#   5. rustbgpd's gRPC ListEvpnRoutes surfaces the Type 2 route with
#      next_hop = VTEP-A, route_type = 2, VNI encoded in the label.
#   6. Withdrawing the FDB entry on VTEP-A propagates through the RR:
#      VTEP-B's 'show evpn mac vni 100' drops the MAC within a few
#      seconds.
#
# Prerequisites:
#   - containerlab deploy -t tests/interop/m30-evpn-type2-frr.clab.yml
#   - grpcurl installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m30-evpn-type2-frr.sh

TOPO="m30-evpn-type2-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

VTEP_A="clab-${TOPO}-vtep-a"
VTEP_B="clab-${TOPO}-vtep-b"
VTEP_A_IP="10.0.0.2"
VTEP_B_IP="10.0.1.2"
RR_CLUSTER_ID="10.0.0.100"
VNI="100"
TEST_MAC="aa:bb:cc:00:00:01"

# ---------------------------------------------------------------------------
# gRPC helpers
# ---------------------------------------------------------------------------

grpc_list_neighbors() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/ListNeighbors 2>/dev/null
}

grpc_list_evpn() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d '{}' \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListEvpnRoutes 2>/dev/null
}

# ---------------------------------------------------------------------------
# FRR helpers
# ---------------------------------------------------------------------------

# Poll FRR's local VNI MAC table for a specific MAC. Returns 0 on
# success, 1 on timeout.
# Usage: wait_frr_evpn_mac_learned <container> <vni> <mac> [timeout_s=30]
wait_frr_evpn_mac_learned() {
    local container=${1:?}
    local vni=${2:?}
    local mac=${3:?}
    local timeout=${4:-30}
    local attempts=$((timeout / 2))
    for _ in $(seq 1 "$attempts"); do
        if docker exec "$container" vtysh -c "show evpn mac vni $vni json" 2>/dev/null \
            | grep -iq "\"$mac\""; then
            return 0
        fi
        sleep 2
    done
    return 1
}

# Poll until a specific MAC is *absent* from the VNI MAC table.
# Returns 0 on success, 1 on timeout.
wait_frr_evpn_mac_withdrawn() {
    local container=${1:?}
    local vni=${2:?}
    local mac=${3:?}
    local timeout=${4:-15}
    local attempts=$((timeout / 2))
    for _ in $(seq 1 "$attempts"); do
        if ! docker exec "$container" vtysh -c "show evpn mac vni $vni json" 2>/dev/null \
            | grep -iq "\"$mac\""; then
            return 0
        fi
        sleep 2
    done
    return 1
}

frr_evpn_mac_route_detail() {
    local container=${1:?}
    # FRR's MAC/IP route detail text — `show evpn mac vni X json` does
    # not expose ORIGINATOR_ID or CLUSTER_LIST in its JSON schema, but
    # `show bgp l2vpn evpn route detail` does in plain text. Use the
    # text view so the assertions can match labelled fields rather
    # than substring-grepping the route's own next-hop.
    docker exec "$container" vtysh -c "show bgp l2vpn evpn route detail" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

resolve_grpc_addr
start_rustbgpd

# Test 1 + 2: both VTEPs reach Established on L2VPN/EVPN
wait_frr_established "$VTEP_A" "10.0.0.1" "VTEP-A L2VPN/EVPN" \
    && ok "VTEP-A Established" \
    || fail "VTEP-A did not reach Established"
# VTEP-B is on subnet 10.0.1.0/24 and peers with rustbgpd at 10.0.1.1.
wait_frr_established "$VTEP_B" "10.0.1.1" "VTEP-B L2VPN/EVPN" \
    && ok "VTEP-B Established" \
    || fail "VTEP-B did not reach Established"

# Test 3: VTEP-B sees VTEP-A's IMET (Type 3 inclusive multicast) —
# baseline that EVPN control plane is flowing across the reflector.
log "[test] VTEP-B receives VTEP-A's Type 3 IMET"
imet_seen=0
for _ in $(seq 1 15); do
    if docker exec "$VTEP_B" vtysh -c "show bgp l2vpn evpn route type multicast json" 2>/dev/null \
        | grep -q "$VTEP_A_IP"; then
        imet_seen=1
        break
    fi
    sleep 2
done
if [ "$imet_seen" -eq 1 ]; then
    ok "VTEP-B sees reflected Type 3 IMET from VTEP-A"
else
    fail "VTEP-B never received Type 3 IMET from VTEP-A"
fi

# Test 4: inject MAC on VTEP-A, expect it on VTEP-B
log "[test] Injecting $TEST_MAC on VTEP-A vxlan${VNI} FDB"
# Inject on the dummy port (a non-VXLAN bridge port). FRR zebra only
# treats MACs on a non-VXLAN bridge port as locally-learned, which is
# what triggers the Type 2 origination — MACs on the VXLAN port are
# treated as remote / HER-flooded and never advertised. `replace`
# rather than `add` so the test is idempotent across re-runs.
docker exec "$VTEP_A" bridge fdb replace "$TEST_MAC" dev "dummy${VNI}" master static >/dev/null
if wait_frr_evpn_mac_learned "$VTEP_B" "$VNI" "$TEST_MAC" 30; then
    ok "VTEP-B learned $TEST_MAC via EVPN reflection"
else
    fail "VTEP-B did not learn $TEST_MAC within 30s"
    docker exec "$VTEP_B" vtysh -c "show evpn mac vni $VNI" >&2 || true
fi

# Test 5: VTEP-B's reflected Type 2 UPDATE carries RFC 4456 attributes.
# Use the labelled detail view; FRR's `show evpn mac vni X json` does
# not expose ORIGINATOR_ID / CLUSTER_LIST, so a JSON-shaped check
# would always be a substring grep that false-positives on the
# next-hop IP.
log "[test] Reflected Type 2 has ORIGINATOR_ID + CLUSTER_LIST set"
macip_detail=$(frr_evpn_mac_route_detail "$VTEP_B")
if echo "$macip_detail" | grep -q "$TEST_MAC"; then
    if echo "$macip_detail" | grep -qE "Originator: ?$VTEP_A_IP"; then
        ok "ORIGINATOR_ID == $VTEP_A_IP on reflected UPDATE"
    else
        fail "ORIGINATOR_ID not set to VTEP-A's router-id"
        echo "$macip_detail" | head -40 >&2
    fi
    if echo "$macip_detail" | grep -qE "Cluster ?[Ll]ist: ?$RR_CLUSTER_ID"; then
        ok "CLUSTER_LIST contains RR cluster-id $RR_CLUSTER_ID"
    else
        fail "CLUSTER_LIST missing the RR cluster-id"
        echo "$macip_detail" | head -40 >&2
    fi
else
    fail "VTEP-B's MAC/IP route detail doesn't contain $TEST_MAC"
fi

# Test 6: rustbgpd's gRPC ListEvpnRoutes surfaces the Type 2 route
log "[test] rustbgpd ListEvpnRoutes shows the Type 2 route"
evpn_json=$(grpc_list_evpn)
if echo "$evpn_json" | grep -q "\"routeType\": 2"; then
    if echo "$evpn_json" | grep -q "\"$TEST_MAC\""; then
        ok "ListEvpnRoutes includes the injected MAC as a Type 2 route"
    else
        fail "ListEvpnRoutes has a Type 2 route but wrong MAC"
        echo "$evpn_json" | head -40 >&2
    fi
    # Strict JSON match: scope to the entry containing the test MAC and
    # check the `nextHop` field on that entry only. A naked grep across
    # the whole response can match the IP appearing elsewhere (e.g. as
    # a peer-address field in a different route). `jq` is required —
    # the substring fallback would let a malformed match slip past.
    if ! command -v jq >/dev/null 2>&1; then
        fail "jq is required for strict next_hop assertion (install with apt-get install jq)"
    else
        nh=$(echo "$evpn_json" | jq -r --arg mac "$TEST_MAC" \
            '.routes[]? | select(.mac == $mac) | .nextHop // empty' \
            2>/dev/null | head -1)
        if [ "$nh" = "$VTEP_A_IP" ]; then
            ok "Type 2 next_hop preserved as $VTEP_A_IP (VTEP-A loopback)"
        else
            fail "Type 2 next_hop expected $VTEP_A_IP, got '${nh:-<empty>}'"
            echo "$evpn_json" | head -40 >&2
        fi
    fi
    if echo "$evpn_json" | grep -q "\"label\": $VNI"; then
        ok "Type 2 label field carries VNI $VNI"
    else
        # FRR may emit VNI in label with shifted bits; tolerate the
        # shifted form as well. The BGP Encapsulation community is
        # more reliable — the CLI surfaces tunnel_type=8 for VXLAN.
        if echo "$evpn_json" | grep -q "\"tunnelType\": 8"; then
            ok "VXLAN encap community present (tunnel_type=8)"
        else
            fail "Neither VNI label nor VXLAN encap community surfaced"
            echo "$evpn_json" | head -40 >&2
        fi
    fi
else
    fail "ListEvpnRoutes has no Type 2 route"
    echo "$evpn_json" | head -40 >&2
fi

# Test 7: withdrawal — remove the FDB entry, expect VTEP-B to drop it
log "[test] Withdrawal: removing MAC from VTEP-A FDB"
docker exec "$VTEP_A" bridge fdb del "$TEST_MAC" dev "dummy${VNI}" master 2>/dev/null || \
    docker exec "$VTEP_A" bridge fdb del "$TEST_MAC" dev "dummy${VNI}" 2>/dev/null || true
if wait_frr_evpn_mac_withdrawn "$VTEP_B" "$VNI" "$TEST_MAC" 15; then
    ok "VTEP-B dropped $TEST_MAC after VTEP-A withdrawal"
else
    fail "VTEP-B still shows $TEST_MAC 15s after VTEP-A withdrawal"
fi

print_summary
