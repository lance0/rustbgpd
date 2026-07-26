#!/usr/bin/env bash
# M75 interop test — RT-Constrain (RFC 4684) VPNv4 reflection filtering
# against GoBGP v3.
#
# Validates:
#   1. iBGP sessions establish to all three RR clients; SAFI 128 negotiated
#      everywhere; SAFI 132 (rtc) negotiated on src + sink only.
#   2. Both GoBGP RTC peers ACCEPT the RR's self-originated default RTC
#      NLRI into adj-in (wire-level pin: the default carries the mandatory
#      empty AS_PATH; without it GoBGP treat-as-withdraws the UPDATE and
#      the whole feature dead-ends).
#   3. RR receives BOTH VPN routes from the source (the accepted default
#      defeats GoBGP's outbound RTC filter toward the RR).
#   4. rbgp rib rtc (Loc-RIB, best-only) shows the local default row,
#      sink's unique extra-RT /96, src's red /96, and the dual-originated
#      blue /96 exactly once.
#   5. RTC routes themselves reflect between clients (src sees sink's NLRI
#      through the RR with ORIGINATOR_ID set).
#   6. The filter: sink (VRF blue only) receives the RT-65001:100 route and
#      NOT the RT-65001:200 route.
#   7. sink2 (no rtc family) receives BOTH routes unfiltered —
#      SAFI-132-not-negotiated means no filtering.
#   8. Widening sink's membership (adding the red RTC NLRI) delivers the
#      red route with zero session flaps; narrowing withdraws exactly it.
#   9. The default RTC NLRI injected by the sink matches ALL RTs (red
#      re-delivered), and its withdrawal narrows back.
#  10. Nothing is installed into any dataplane on the RR.
#  11. No RTC reflection UPDATE storm (GoBGP issue #1630 signature): the
#      RR's UPDATE counters are quiet after convergence.
#
# iBGP-only on purpose: GoBGP's eBGP RTC handling is broken upstream
# (gobgp #2427).
#
# Prerequisites:
#   - docker build --target dev -t rustbgpd:dev .
#   - docker build -t gobgp:interop -f tests/interop/Dockerfile.gobgp tests/interop
#   - containerlab deployed:
#       containerlab deploy -t tests/interop/m75-rtc-vpnv4-filter-gobgp.clab.yml

TOPO="m75-rtc-vpnv4-filter-gobgp"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
source "$SCRIPT_DIR/test-lib.sh"

GOBGP_SRC="clab-${TOPO}-gobgp-src"
GOBGP_SINK="clab-${TOPO}-gobgp-sink"
GOBGP_SINK2="clab-${TOPO}-gobgp-sink2"

SRC_ADDR="10.0.0.2"
SINK_ADDR="10.0.1.2"
SINK2_ADDR="10.0.2.2"

BLUE_PREFIX="10.100.1.0/24"
RED_PREFIX="10.200.1.0/24"
BLUE_RD="65001:100"
RED_RD="65001:200"
BLUE_RT="65001:100"
RED_RT="65001:200"
# Extra import RT on the sink's blue VRF, matched by no VPN route: its /96
# RTC NLRI is unique in the topology, so a sink-attributed row is visible in
# rustbgpd's best-path-only RTC view (src and sink both originate the blue
# /96, and only the tiebreak winner shows).
SINK_EXTRA_RT="65001:111"

start_gobgpd() {
    local container=${1:?}
    log "Starting gobgpd in $container..."
    docker exec -d "$container" sh -c \
        'nohup gobgpd -f /config/gobgp.toml >/tmp/gobgpd.log 2>&1'
}

gobgp() {
    local container=${1:?}
    shift
    docker exec "$container" gobgp "$@" 2>/dev/null
}

gobgp_neighbor() {
    local container=${1:?}
    gobgp "$container" neighbor 2>/dev/null || true
}

gobgp_vpnv4_json() {
    local container=${1:?}
    gobgp "$container" global rib -a vpnv4 -j
}

rustbgpd_vpn_json() {
    docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 rib vpn -j
}

rustbgpd_rtc_json() {
    docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 rib rtc -j
}

rustbgpd_neighbor_json() {
    local peer=${1:?}
    docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 neighbor "$peer" -j
}

wait_gobgp_established() {
    local container=${1:?}
    local peer=${2:?}
    local label=${3:?}

    log "Waiting for $label session to $peer..."
    for i in $(seq 1 45); do
        local state
        state=$(gobgp_neighbor "$container" | grep -F -- "$peer" || true)
        if echo "$state" | grep -qi "establ"; then
            ok "$label session established (attempt $i)"
            return 0
        fi
        sleep 2
    done

    fail "$label session did not reach Established within 90s"
    gobgp_neighbor "$container" || true
    return 1
}

# Assert an afi-safi shows "advertised and received" in GoBGP's per-neighbor
# capability view. Family names render as e.g. "l3vpn-ipv4-unicast:" and
# "rtc:" under the multiprotocol capability.
assert_family_negotiated() {
    local container=${1:?}
    local peer=${2:?}
    local family=${3:?}
    local label=${4:?}

    if gobgp "$container" neighbor "$peer" \
        | grep -A 30 "Neighbor capabilities" \
        | grep -E "(^|[[:space:]])${family}:" \
        | grep -q "advertised and received"; then
        ok "$label negotiated $family"
    else
        fail "$label did not negotiate $family"
        gobgp "$container" neighbor "$peer" | grep -A 30 "Neighbor capabilities" || true
    fi
}

assert_family_absent() {
    local container=${1:?}
    local peer=${2:?}
    local family=${3:?}
    local label=${4:?}

    if gobgp "$container" neighbor "$peer" \
        | grep -A 30 "Neighbor capabilities" \
        | grep -E "(^|[[:space:]])${family}:" \
        | grep -q "advertised and received"; then
        fail "$label unexpectedly negotiated $family"
        gobgp "$container" neighbor "$peer" | grep -A 30 "Neighbor capabilities" || true
    else
        ok "$label did not negotiate $family (as configured)"
    fi
}

# Wire-level regression pin for the missing-AS_PATH fix on the RR's
# self-originated default RTC NLRI: GoBGP must ACCEPT it into adj-in. A
# malformed default (no empty AS_PATH) is treated-as-withdraw instead
# (gobgpd.log: "well-known mandatory attributes are not present. type : 2").
wait_default_rtc_accepted() {
    local container=${1:?} rr=${2:?} label=${3:?}
    log "Waiting for $label to accept the RR's default RTC NLRI into adj-in..."
    for i in $(seq 1 30); do
        if gobgp "$container" neighbor "$rr" adj-in -a rtc | grep -qi "default"; then
            ok "$label accepted the RR's default RTC NLRI (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$label never accepted the RR's default RTC NLRI (AS_PATH regression? check gobgpd.log for 'treated as withdraw')"
    gobgp "$container" neighbor "$rr" adj-in -a rtc || true
    docker exec "$container" sh -c 'grep "treated as withdraw" /tmp/gobgpd.log' >&2 || true
    return 1
}

rustbgpd_rd_count() {
    local rd=${1:?}
    rustbgpd_vpn_json | jq --arg rd "$rd" \
        '[.[] | select(.route_distinguisher == $rd)] | length' 2>/dev/null || echo 0
}

wait_rustbgpd_rd() {
    local rd=${1:?}
    log "Waiting for rustbgpd VPN RIB to hold rd=$rd..."
    for i in $(seq 1 30); do
        if [ "$(rustbgpd_rd_count "$rd")" -ge 1 ]; then
            ok "rustbgpd holds rd=$rd (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "rustbgpd VPN RIB missing rd=$rd"
    rustbgpd_vpn_json | jq . || true
    return 1
}

# The sink's GoBGP vpnv4 JSON is keyed by "<rd>:<prefix>".
vpnv4_key_present() {
    local container=${1:?}
    local key=${2:?}
    gobgp_vpnv4_json "$container" | jq -e --arg key "$key" 'has($key)' >/dev/null
}

wait_vpnv4_key() {
    local container=${1:?} key=${2:?} label=${3:?}
    log "Waiting for $label to hold $key..."
    for i in $(seq 1 30); do
        if vpnv4_key_present "$container" "$key"; then
            ok "$label holds $key (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$label missing $key"
    gobgp_vpnv4_json "$container" | jq . || true
    return 1
}

wait_vpnv4_key_gone() {
    local container=${1:?} key=${2:?} label=${3:?}
    log "Waiting for $label to drop $key..."
    for i in $(seq 1 30); do
        if ! vpnv4_key_present "$container" "$key"; then
            ok "$label dropped $key (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$label still holds $key"
    gobgp_vpnv4_json "$container" | jq . || true
    return 1
}

assert_vpnv4_key_absent() {
    local container=${1:?} key=${2:?} label=${3:?}
    if vpnv4_key_present "$container" "$key"; then
        fail "$label holds $key but must not (RTC filter breach)"
        gobgp_vpnv4_json "$container" | jq . || true
    else
        ok "$label does not hold $key"
    fi
}

# One RTC row in rustbgpd's RIB matching origin-AS / RT / len / peer.
rtc_row_count() {
    local origin_as=${1:?} rt=${2:?} len=${3:?} peer=${4:?}
    rustbgpd_rtc_json | jq \
        --argjson oas "$origin_as" --arg rt "$rt" \
        --argjson len "$len" --arg peer "$peer" '
        [.[] | select(
            .is_default == false
            and .origin_as == $oas
            and .route_target == $rt
            and .prefix_len == $len
            and .peer_address == $peer
        )] | length' 2>/dev/null || echo 0
}

wait_rtc_row() {
    local origin_as=${1:?} rt=${2:?} len=${3:?} peer=${4:?} label=${5:?}
    log "Waiting for RR RTC RIB row: $label..."
    for i in $(seq 1 30); do
        if [ "$(rtc_row_count "$origin_as" "$rt" "$len" "$peer")" -ge 1 ]; then
            ok "RR RTC RIB holds $label (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "RR RTC RIB missing $label"
    rustbgpd_rtc_json | jq . || true
    return 1
}

sink_flap_count() {
    rustbgpd_neighbor_json "$SINK_ADDR" | jq -r '.flap_count'
}

sink_session_state() {
    rustbgpd_neighbor_json "$SINK_ADDR" | jq -r '.state'
}

assert_no_flap() {
    local baseline=${1:?} label=${2:?}
    local now state
    now=$(sink_flap_count)
    state=$(sink_session_state)
    if [ "$now" = "$baseline" ] && [ "$state" = "Established" ]; then
        ok "$label: sink session Established, flap count unchanged ($now)"
    else
        fail "$label: sink flapped (flap_count $baseline -> $now, state $state)"
    fi
}

rr_updates_sent_total() {
    local total=0 peer v
    for peer in "$SRC_ADDR" "$SINK_ADDR" "$SINK2_ADDR"; do
        v=$(rustbgpd_neighbor_json "$peer" | jq -r '.updates_sent' 2>/dev/null || echo 0)
        total=$((total + ${v:-0}))
    done
    echo "$total"
}

test_setup_vrfs() {
    log "Setup: src VRFs blue(RT $BLUE_RT) + red(RT $RED_RT), one route each; sink VRF blue only"
    gobgp "$GOBGP_SRC" vrf add blue rd "$BLUE_RD" rt both "$BLUE_RT"
    gobgp "$GOBGP_SRC" vrf add red rd "$RED_RD" rt both "$RED_RT"
    gobgp "$GOBGP_SRC" vrf blue rib add "$BLUE_PREFIX" nexthop "$SRC_ADDR"
    gobgp "$GOBGP_SRC" vrf red rib add "$RED_PREFIX" nexthop "$SRC_ADDR"
    gobgp "$GOBGP_SINK" vrf add blue rd "$BLUE_RD" rt both "$BLUE_RT" "$SINK_EXTRA_RT"
    ok "VRFs configured and one VPN route injected per src VRF"
}

test_rr_receives_both() {
    log "Test 1: RR receives BOTH VPN routes (default-RTC origination defeats GoBGP's filter toward the RR)"
    wait_rustbgpd_rd "$BLUE_RD"
    wait_rustbgpd_rd "$RED_RD"
}

# NOTE: rbgp rib rtc reads the Loc-RIB (best path per NLRI only). src and
# sink both originate the blue /96, so only the tiebreak winner is visible
# with its peer attribution; sink's membership visibility is pinned via its
# unique SINK_EXTRA_RT /96 instead, and the total row count pins that
# nothing else leaked in.
test_rr_rtc_table() {
    log "Test 2: rbgp rib rtc shows local default + sink's unique /96 + src's two /96s"

    if rustbgpd_rtc_json | jq -e \
        '[.[] | select(.is_default == true and .peer_address == "0.0.0.0")] | length >= 1' >/dev/null; then
        ok "RR RTC RIB holds the locally-originated default row"
    else
        fail "RR RTC RIB missing the locally-originated default row"
        rustbgpd_rtc_json | jq . || true
    fi

    wait_rtc_row 65001 "RT:$SINK_EXTRA_RT" 96 "$SINK_ADDR" "sink's 65001:RT:$SINK_EXTRA_RT/96"
    wait_rtc_row 65001 "RT:$RED_RT" 96 "$SRC_ADDR" "src's 65001:RT:$RED_RT/96"

    # The blue /96 is dual-originated (src + sink); best-only view shows one
    # winner, from either peer.
    if rustbgpd_rtc_json | jq -e --arg rt "RT:$BLUE_RT" \
        --arg src "$SRC_ADDR" --arg sink "$SINK_ADDR" '
        [.[] | select(.is_default == false and .route_target == $rt
                      and .prefix_len == 96
                      and (.peer_address == $src or .peer_address == $sink))]
        | length == 1' >/dev/null; then
        ok "RR RTC RIB holds the dual-originated 65001:RT:$BLUE_RT/96 (best-only)"
    else
        fail "RR RTC RIB missing 65001:RT:$BLUE_RT/96"
        rustbgpd_rtc_json | jq . || true
    fi

    # Exactly 4 rows total: default + blue(best) + red(src) + extra(sink).
    local count
    count=$(rustbgpd_rtc_json | jq 'length')
    if [ "$count" -eq 4 ]; then
        ok "RR RTC RIB holds exactly 4 rows"
    else
        fail "RR RTC RIB holds $count rows, expected 4"
        rustbgpd_rtc_json | jq . || true
    fi
}

test_rtc_reflection() {
    log "Test 3: RTC routes reflect between clients (src sees sink's NLRI via the RR)"
    # src originates its own blue RTC NLRI, so the reflected copy shows up as
    # an extra path under the same NLRI key carrying ORIGINATOR_ID (type 9)
    # set to the sink's router-id.
    for i in $(seq 1 30); do
        if gobgp "$GOBGP_SRC" global rib -a rtc -j | jq -e --arg oid "$SINK_ADDR" '
            [.[] | .[] | select(
                [.attrs[] | select(.type == 9 and .value == $oid)] | length > 0
            )] | length >= 1' >/dev/null; then
            ok "src holds sink's reflected RTC NLRI with ORIGINATOR_ID=$SINK_ADDR (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "src never received sink's reflected RTC NLRI"
    gobgp "$GOBGP_SRC" global rib -a rtc -j | jq . || true
    return 1
}

test_sink_filtered() {
    log "Test 4: the filter — sink gets the blue route and NOT the red route"
    wait_vpnv4_key "$GOBGP_SINK" "${BLUE_RD}:${BLUE_PREFIX}" "sink"
    # Blue arrived, so the RR has staged toward the sink; give any in-flight
    # UPDATE a moment, then pin red's absence.
    sleep 3
    assert_vpnv4_key_absent "$GOBGP_SINK" "${RED_RD}:${RED_PREFIX}" "sink"
}

test_sink2_unfiltered() {
    log "Test 5: sink2 (rtc NOT negotiated) receives BOTH routes unfiltered"
    wait_vpnv4_key "$GOBGP_SINK2" "${BLUE_RD}:${BLUE_PREFIX}" "sink2"
    wait_vpnv4_key "$GOBGP_SINK2" "${RED_RD}:${RED_PREFIX}" "sink2"
}

# Widen/narrow drive the sink's red membership via `global rib add/del -a
# rtc` rather than `vrf add/del red`: GoBGP 3.37.0 SEGFAULTs in
# table.(*Table).deleteRTCPathsByVrf on `vrf del` while the RR's default
# RTC NLRI sits in its table (upstream bug, nil RouteTarget on the default).
# The wire-level RR behavior under test — SAFI-132 announce/withdraw driving
# delta VPN UPDATEs — is identical either way.
test_widen_without_reset() {
    log "Test 6: widening sink's membership (add RTC $RED_RT) delivers red with zero flaps"
    local flap_before
    flap_before=$(sink_flap_count)
    gobgp "$GOBGP_SINK" global rib add -a rtc asn 65001 rt "$RED_RT"
    wait_vpnv4_key "$GOBGP_SINK" "${RED_RD}:${RED_PREFIX}" "sink"
    assert_no_flap "$flap_before" "widen"
}

test_narrow_withdraws() {
    log "Test 7: narrowing (del RTC $RED_RT) withdraws exactly the red route"
    local flap_before
    flap_before=$(sink_flap_count)
    gobgp "$GOBGP_SINK" global rib del -a rtc asn 65001 rt "$RED_RT"
    wait_vpnv4_key_gone "$GOBGP_SINK" "${RED_RD}:${RED_PREFIX}" "sink"
    if vpnv4_key_present "$GOBGP_SINK" "${BLUE_RD}:${BLUE_PREFIX}"; then
        ok "sink still holds the blue route after the red withdraw"
    else
        fail "sink lost the blue route alongside the red withdraw"
    fi
    assert_no_flap "$flap_before" "narrow"
}

# The default RTC NLRI matches every RT: injecting it re-delivers red;
# removing it withdraws red again while the VRF-derived blue /96 keeps blue.
test_default_rtc_injection() {
    log "Test 8: sink injects the default RTC NLRI — matches ALL RTs"
    gobgp "$GOBGP_SINK" global rib add -a rtc default
    wait_vpnv4_key "$GOBGP_SINK" "${RED_RD}:${RED_PREFIX}" "sink"

    gobgp "$GOBGP_SINK" global rib del -a rtc default
    wait_vpnv4_key_gone "$GOBGP_SINK" "${RED_RD}:${RED_PREFIX}" "sink"
    if vpnv4_key_present "$GOBGP_SINK" "${BLUE_RD}:${BLUE_PREFIX}"; then
        ok "sink still holds the blue route after the default withdrawal"
    else
        fail "sink lost the blue route alongside the default withdrawal"
    fi
}

test_no_dataplane_install() {
    log "Test 9: RR installed nothing into any dataplane"

    local mpls ipv4
    if capture_ip_routes mpls "$RUSTBGPD" MPLS -M; then
        if [ -z "$mpls" ]; then
            ok "RR MPLS routing table is empty"
        else
            fail "RR has unexpected MPLS routes"
            printf '%s\n' "$mpls" >&2
        fi
    fi

    if capture_ip_routes ipv4 "$RUSTBGPD" IPv4; then
        if grep -qE "${BLUE_PREFIX%/*}|${RED_PREFIX%/*}" <<<"$ipv4"; then
            fail "RR kernel routing table contains a VPN-derived route"
            printf '%s\n' "$ipv4" >&2
        else
            ok "RR kernel routing table has no VPN-derived routes"
        fi
    fi
}

capture_ip_routes() {
    local output_var=$1 container=$2 table_label=$3 captured
    shift 3
    if ! captured=$(docker exec "$container" ip "$@" route show 2>&1); then
        fail "$container $table_label route inspection failed"
        printf '%s\n' "$captured" >&2
        return 1
    fi
    printf -v "$output_var" '%s' "$captured"
}

test_no_update_storm() {
    log "Test 10: no RTC reflection UPDATE storm (GoBGP #1630 signature)"
    local before after delta
    before=$(rr_updates_sent_total)
    sleep 6
    after=$(rr_updates_sent_total)
    delta=$((after - before))
    if [ "$delta" -le 2 ]; then
        ok "RR UPDATE counters quiet after convergence (delta=$delta over 6s)"
    else
        fail "RR still sending UPDATEs after convergence (delta=$delta over 6s) — possible RTC reflection loop"
    fi
}

main() {
    log "M75 interop test: RT-Constrain VPNv4 reflection filtering via GoBGP"
    log "Topology: $TOPO"

    preflight
    resolve_grpc_addr
    start_gobgpd "$GOBGP_SRC"
    start_gobgpd "$GOBGP_SINK"
    start_gobgpd "$GOBGP_SINK2"
    start_rustbgpd

    wait_gobgp_established "$GOBGP_SRC" "10.0.0.1" "source" || exit 1
    wait_gobgp_established "$GOBGP_SINK" "10.0.1.1" "sink" || exit 1
    wait_gobgp_established "$GOBGP_SINK2" "10.0.2.1" "sink2" || exit 1

    assert_family_negotiated "$GOBGP_SRC" "10.0.0.1" "l3vpn-ipv4-unicast" "source"
    assert_family_negotiated "$GOBGP_SINK" "10.0.1.1" "l3vpn-ipv4-unicast" "sink"
    assert_family_negotiated "$GOBGP_SINK2" "10.0.2.1" "l3vpn-ipv4-unicast" "sink2"
    assert_family_negotiated "$GOBGP_SRC" "10.0.0.1" "rtc" "source"
    assert_family_negotiated "$GOBGP_SINK" "10.0.1.1" "rtc" "sink"
    assert_family_absent "$GOBGP_SINK2" "10.0.2.1" "rtc" "sink2"

    wait_default_rtc_accepted "$GOBGP_SRC" "10.0.0.1" "source"
    wait_default_rtc_accepted "$GOBGP_SINK" "10.0.1.1" "sink"

    test_setup_vrfs
    test_rr_receives_both
    test_rr_rtc_table
    test_rtc_reflection
    test_sink_filtered
    test_sink2_unfiltered
    test_widen_without_reset
    test_narrow_withdraws
    test_default_rtc_injection
    test_no_dataplane_install
    test_no_update_storm

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
