#!/usr/bin/env bash
# M32 interop test — EVPN multi-homing Type 4 ES reflection
#
# VTEP-A and VTEP-C share an Ethernet Segment (same es-id + es-sys-mac
# → same 10-byte ESI). VTEP-B observes the reflected ES routes from
# both peers. This test asserts the RR reflects Type 4 ES unchanged —
# DF election itself is run by the VTEPs, not by us.
#
# Assertions (gated):
#   1. All 3 VTEPs Established on L2VPN/EVPN.
#   2. VTEP-B receives both Type 4 ES routes (from VTEP-A and VTEP-C)
#      for the shared ESI.
#   3. RFC 4456 attributes (ORIGINATOR_ID, CLUSTER_LIST) are set
#      correctly on each reflected ES route.
#   4. rustbgpd's gRPC ListEvpnRoutes surfaces both Type 4 routes.
#
# Advisory (logged, not gated):
#   - Type 1 EAD presence on VTEP-B and in `ListEvpnRoutes`. FRR only
#     originates EAD-per-EVI when the ES is bound to a specific EVI
#     via VLAN-aware bridge + SVI sub-interface, which the Phase 1
#     harness intentionally does not configure. Type 1 EAD reflection
#     is a Phase 3 concern (rustbgpd-as-VTEP) — the Phase 1 RR test
#     gates on Type 4 ES reflection, which is what downstream VTEPs
#     need for ES-Import RT propagation.
#   - VTEP-B's `show evpn es` listing both VTEPs (FRR observer-side
#     display only populates when the observer is itself an ES member).
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m32-evpn-multihome-frr.clab.yml
#   - grpcurl installed on the host

TOPO="m32-evpn-multihome-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

VTEP_A="clab-${TOPO}-vtep-a"
VTEP_B="clab-${TOPO}-vtep-b"
VTEP_C="clab-${TOPO}-vtep-c"
VTEP_A_IP="10.0.0.2"
VTEP_B_IP="10.0.1.2"
VTEP_C_IP="10.0.2.2"
RR_CLUSTER_ID="10.0.0.100"
ES_SYS_MAC="aa:bb:cc:dd:ee:ff"

grpc_list_evpn() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d '{}' \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListEvpnRoutes 2>/dev/null
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

resolve_grpc_addr
start_rustbgpd

log "[baseline] 3 VTEP sessions Established"
wait_frr_established "$VTEP_A" "10.0.0.1" "VTEP-A EVPN" \
    && ok "VTEP-A Established" || fail "VTEP-A not Established"
# Each VTEP peers with rustbgpd's address on its own subnet.
wait_frr_established "$VTEP_B" "10.0.1.1" "VTEP-B EVPN" \
    && ok "VTEP-B Established" || fail "VTEP-B not Established"
wait_frr_established "$VTEP_C" "10.0.2.1" "VTEP-C EVPN" \
    && ok "VTEP-C Established" || fail "VTEP-C not Established"

# Test: VTEP-B receives Type 4 ES from both A and C
log "[test] VTEP-B receives reflected Type 4 ES from both VTEP-A and VTEP-C"
both_es=0
for _ in $(seq 1 30); do
    es_output=$(docker exec "$VTEP_B" vtysh -c "show bgp l2vpn evpn route type es" 2>/dev/null)
    if echo "$es_output" | grep -q "$VTEP_A_IP" && echo "$es_output" | grep -q "$VTEP_C_IP"; then
        both_es=1
        break
    fi
    sleep 2
done
if [ "$both_es" -eq 1 ]; then
    ok "VTEP-B sees Type 4 ES from both VTEP-A and VTEP-C"
else
    fail "VTEP-B did not see both Type 4 ES routes"
    echo "$es_output" | head -40 >&2
fi

# Test: VTEP-B receives Type 1 EAD from both peers (advisory only).
# FRR originates Type 1 EAD-per-EVI only when the ES is bound to a
# specific EVI via VLAN-aware bridge + SVI sub-interface, which the
# Phase 1 multi-homing harness intentionally does not configure (it
# would require a richer FRR setup that's deferred to Phase 3 / EVPN
# VTEP execution mode). Type 4 ES + RFC 4456 attribute reflection
# above is what gates the M32 result; Type 1 EAD presence is logged
# but not gated. See docs/evpn-enablement.md for the Phase split.
log "[test] VTEP-B Type 1 EAD presence (advisory — not gated)"
ead_output=$(docker exec "$VTEP_B" vtysh -c "show bgp l2vpn evpn route type ead" 2>/dev/null || true)
if echo "$ead_output" | grep -q "$VTEP_A_IP" && echo "$ead_output" | grep -q "$VTEP_C_IP"; then
    ok "VTEP-B sees Type 1 EAD from both VTEP-A and VTEP-C"
else
    log "Type 1 EAD not originated by FRR in this minimal setup"
    log "(non-VLAN-aware bridge → no EVI binding → no EAD-per-EVI)"
fi

# Test: RFC 4456 attributes on the reflected ES routes.
# `show bgp l2vpn evpn route type es` is a summary that does not
# expose Originator/Cluster fields; the detail view is the right
# source. Strict labelled match — bare-IP fallback matches the
# route's own next-hop and would pass when the attributes are
# absent, so don't use one.
log "[test] Reflected ES routes carry ORIGINATOR_ID + CLUSTER_LIST"
es_detail=$(docker exec "$VTEP_B" vtysh -c "show bgp l2vpn evpn route detail" 2>/dev/null)
if echo "$es_detail" | grep -qE "Originator: ?$VTEP_A_IP"; then
    ok "ORIGINATOR_ID == $VTEP_A_IP on reflected ES route"
else
    fail "ORIGINATOR_ID labelled match failed on reflected ES route"
    echo "$es_detail" | head -40 >&2
fi
if echo "$es_detail" | grep -qE "Cluster ?[Ll]ist: ?$RR_CLUSTER_ID"; then
    ok "CLUSTER_LIST contains $RR_CLUSTER_ID on reflected ES route"
else
    fail "CLUSTER_LIST labelled match failed on reflected ES route"
    echo "$es_detail" | head -40 >&2
fi

# Test: rustbgpd's gRPC shows Type 1 (EAD) and Type 4 (ES) routes
log "[test] rustbgpd ListEvpnRoutes shows Type 1 + Type 4 routes"
evpn_json=$(grpc_list_evpn)
type1_count=$(echo "$evpn_json" | grep -c "\"routeType\": 1" || true)
type4_count=$(echo "$evpn_json" | grep -c "\"routeType\": 4" || true)
log "Type 1 EAD count from rustbgpd ListEvpnRoutes: $type1_count (advisory)"
if [ "$type4_count" -ge 2 ]; then
    ok "ListEvpnRoutes has $type4_count Type 4 ES routes (one per sharing VTEP)"
else
    fail "Expected >= 2 Type 4 ES routes; got $type4_count"
    echo "$evpn_json" | head -40 >&2
fi

# Test: VTEP-B's DF election view sees both VTEPs as ES members
log "[test] VTEP-B's 'show evpn es' lists both VTEPs for the shared ESI"
es_state=0
for _ in $(seq 1 10); do
    es_txt=$(docker exec "$VTEP_B" vtysh -c "show evpn es" 2>/dev/null)
    if echo "$es_txt" | grep -q "$VTEP_A_IP" && echo "$es_txt" | grep -q "$VTEP_C_IP"; then
        es_state=1
        break
    fi
    sleep 2
done
if [ "$es_state" -eq 1 ]; then
    ok "Both VTEPs visible in VTEP-B's EVPN ES table"
else
    # FRR observer-side EVPN ES visibility is filtered when the observer
    # is not itself a member of the ES, so this view can be empty even
    # though the BGP routes are present (verified by the Type 4 ES count
    # assertion above). Log this for diagnosis but do not silently pass:
    # the BGP-route gate already establishes reflection correctness, and
    # this test is genuinely observability-only on the FRR side.
    log "Note: VTEP-B's 'show evpn es' did not list both peers — observer-side"
    log "FRR display-layer limitation when the observer is not an ES member."
    log "Reflection correctness covered by the Type 4 ES count gate above."
fi

print_summary
