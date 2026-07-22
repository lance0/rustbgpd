#!/usr/bin/env bash
# M74 interop test — VPNv4 route reflection against GoBGP v3.
#
# ADR-0077 §9 release gate. Validates:
#   1. VPNv4 (SAFI 128) iBGP sessions establish to both RR clients with the
#      l3vpn-ipv4-unicast family negotiated.
#   2. GoBGP source injects two VPNv4 routes with distinct Route
#      Distinguishers but the same inner prefix (RD-scoped identity), each
#      with an MPLS label and a Route Target extended community.
#   3. rustbgpd stores both in its VPN RIB with RD, label, and RT intact.
#   4. rustbgpd reflects both to the GoBGP sink with next-hop, label stack,
#      RD, and RT preserved verbatim (ADR-0077 §6 guardrail).
#   5. Source withdrawal of one route removes exactly that route from
#      rustbgpd and the sink; the other RD survives.
#   6. Nothing is installed into any dataplane: the RR has no MPLS routes
#      and no kernel routes derived from the VPN family.
#
# Prerequisites:
#   - docker build --target dev -t rustbgpd:dev .
#   - docker build -t gobgp:interop -f tests/interop/Dockerfile.gobgp tests/interop
#   - containerlab deployed:
#       containerlab deploy -t tests/interop/m74-vpnv4-reflection-gobgp.clab.yml

TOPO="m74-vpnv4-reflection-gobgp"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
source "$SCRIPT_DIR/test-lib.sh"

GOBGP_SRC="clab-${TOPO}-gobgp-src"
GOBGP_SINK="clab-${TOPO}-gobgp-sink"

SRC_ADDR="10.0.0.2"
INNER_PREFIX="10.100.1.0/24"
RD1="65000:1"
RD2="65000:2"
LABEL1=100
LABEL2=200
RT1="65000:1"
RT2="65000:2"

# gobgp global rib add/del -a vpnv4 takes identical argument lists
# (<prefix> label <n> rd <rd> [rt <rt>] [nexthop <ip>]).
ROUTE1_ARGS=("$INNER_PREFIX" label "$LABEL1" rd "$RD1" rt "$RT1" nexthop "$SRC_ADDR")
ROUTE2_ARGS=("$INNER_PREFIX" label "$LABEL2" rd "$RD2" rt "$RT2" nexthop "$SRC_ADDR")

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

assert_safi128_negotiated() {
    local container=${1:?}
    local peer=${2:?}
    local label=${3:?}

    if gobgp "$container" neighbor "$peer" \
        | grep -A 20 "Neighbor capabilities" \
        | grep "l3vpn-ipv4-unicast" \
        | grep -q "advertised and received"; then
        ok "$label negotiated l3vpn-ipv4-unicast (SAFI 128)"
    else
        fail "$label did not negotiate l3vpn-ipv4-unicast"
        gobgp "$container" neighbor "$peer" | grep -A 20 "Neighbor capabilities" || true
    fi
}

# Field-by-field ADR-0077 §6 preservation check against rustbgpd's VPN RIB:
# RD, inner prefix, label stack, next-hop, RT, and source peer all verbatim.
rustbgpd_has_route() {
    local rd=${1:?}
    local lbl=${2:?}
    local rt=${3:?}
    rustbgpd_vpn_json | jq -e \
        --arg rd "$rd" --arg pfx "$INNER_PREFIX" --argjson lbl "$lbl" \
        --arg rt "RT:$rt" --arg nh "$SRC_ADDR" '
        [.[] | select(
            .afi_safi == "l3vpn_ipv4_unicast"
            and .route_distinguisher == $rd
            and .prefix == $pfx
            and .labels == [$lbl]
            and .next_hop == $nh
            and .peer_address == $nh
            and (.extended_communities | index($rt) != null)
        )] | length == 1' >/dev/null
}

rustbgpd_rd_count() {
    local rd=${1:?}
    rustbgpd_vpn_json | jq --arg rd "$rd" \
        '[.[] | select(.route_distinguisher == $rd)] | length' 2>/dev/null || echo 0
}

# Field-by-field preservation check on the sink's GoBGP vpnv4 RIB. The JSON
# is keyed by "<rd>:<prefix>"; each path carries the label stack in the NLRI,
# the next-hop in the MP_REACH attr (type 14), and RTs in the extended
# communities attr (type 16, subtype 2).
sink_has_route() {
    local rd=${1:?}
    local lbl=${2:?}
    local rt=${3:?}
    gobgp_vpnv4_json "$GOBGP_SINK" | jq -e \
        --arg key "${rd}:${INNER_PREFIX}" --argjson lbl "$lbl" \
        --arg rt "$rt" --arg nh "$SRC_ADDR" '
        .[$key][0] as $p
        | ($p != null)
        and ($p.nlri.labels == [$lbl])
        and ([$p.attrs[] | select(.type == 14)][0].nexthop == $nh)
        and ([$p.attrs[] | select(.type == 16)
              | .value[] | select(.subtype == 2) | .value]
             | index($rt) != null)' >/dev/null
}

sink_rd_present() {
    local rd=${1:?}
    gobgp_vpnv4_json "$GOBGP_SINK" | jq -e --arg key "${rd}:${INNER_PREFIX}" \
        'has($key)' >/dev/null
}

wait_rustbgpd_route() {
    local rd=${1:?} lbl=${2:?} rt=${3:?}
    log "Waiting for rustbgpd VPN RIB to hold rd=$rd label=$lbl rt=RT:$rt nh=$SRC_ADDR..."
    for i in $(seq 1 30); do
        if rustbgpd_has_route "$rd" "$lbl" "$rt"; then
            ok "rustbgpd holds rd=$rd with RD/label/RT/next-hop intact (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "rustbgpd VPN RIB missing rd=$rd with expected fields"
    rustbgpd_vpn_json | jq . || true
    return 1
}

wait_rustbgpd_rd_gone() {
    local rd=${1:?}
    log "Waiting for rustbgpd VPN RIB to drop rd=$rd..."
    for i in $(seq 1 30); do
        if [ "$(rustbgpd_rd_count "$rd")" -eq 0 ]; then
            ok "rustbgpd removed rd=$rd (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "rustbgpd VPN RIB still holds rd=$rd"
    rustbgpd_vpn_json | jq . || true
    return 1
}

wait_sink_route() {
    local rd=${1:?} lbl=${2:?} rt=${3:?}
    log "Waiting for GoBGP sink to hold reflected rd=$rd label=$lbl rt=$rt nh=$SRC_ADDR..."
    for i in $(seq 1 30); do
        if sink_has_route "$rd" "$lbl" "$rt"; then
            ok "sink holds rd=$rd with next-hop/label/RD/RT preserved verbatim (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "GoBGP sink missing reflected rd=$rd with expected fields"
    gobgp_vpnv4_json "$GOBGP_SINK" | jq . || true
    return 1
}

wait_sink_rd_gone() {
    local rd=${1:?}
    log "Waiting for GoBGP sink to drop rd=$rd..."
    for i in $(seq 1 30); do
        if ! sink_rd_present "$rd"; then
            ok "sink removed rd=$rd (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "GoBGP sink still holds rd=$rd"
    gobgp_vpnv4_json "$GOBGP_SINK" | jq . || true
    return 1
}

test_vpnv4_reflection() {
    log "Test 1: GoBGP source injects two VPNv4 routes (distinct RDs, same inner prefix)"
    gobgp "$GOBGP_SRC" global rib add -a vpnv4 "${ROUTE1_ARGS[@]}"
    gobgp "$GOBGP_SRC" global rib add -a vpnv4 "${ROUTE2_ARGS[@]}"

    wait_rustbgpd_route "$RD1" "$LABEL1" "$RT1"
    wait_rustbgpd_route "$RD2" "$LABEL2" "$RT2"
    wait_sink_route "$RD1" "$LABEL1" "$RT1"
    wait_sink_route "$RD2" "$LABEL2" "$RT2"
}

test_vpnv4_withdrawal() {
    log "Test 2: GoBGP source withdraws rd=$RD1; rd=$RD2 must survive"
    gobgp "$GOBGP_SRC" global rib del -a vpnv4 "${ROUTE1_ARGS[@]}"

    wait_rustbgpd_rd_gone "$RD1"
    wait_sink_rd_gone "$RD1"

    if [ "$(rustbgpd_rd_count "$RD2")" -eq 1 ]; then
        ok "rustbgpd still holds rd=$RD2 after rd=$RD1 withdrawal (RD-scoped identity)"
    else
        fail "rustbgpd lost rd=$RD2 alongside the rd=$RD1 withdrawal"
    fi
    if sink_rd_present "$RD2"; then
        ok "sink still holds rd=$RD2 after rd=$RD1 withdrawal"
    else
        fail "sink lost rd=$RD2 alongside the rd=$RD1 withdrawal"
    fi
}

test_no_dataplane_install() {
    log "Test 3: RR installed nothing into any dataplane"

    local mpls
    mpls=$(docker exec "$RUSTBGPD" ip -M route show 2>/dev/null || true)
    if [ -z "$mpls" ]; then
        ok "RR MPLS routing table is empty"
    else
        fail "RR has unexpected MPLS routes"
        echo "$mpls" >&2
    fi

    if docker exec "$RUSTBGPD" ip route show | grep -qF "${INNER_PREFIX%/*}"; then
        fail "RR kernel routing table contains a VPN-derived route"
        docker exec "$RUSTBGPD" ip route show >&2 || true
    else
        ok "RR kernel routing table has no VPN-derived routes"
    fi
}

main() {
    log "M74 interop test: VPNv4 route reflection via GoBGP"
    log "Topology: $TOPO"

    preflight
    resolve_grpc_addr
    start_gobgpd "$GOBGP_SRC"
    start_gobgpd "$GOBGP_SINK"
    start_rustbgpd

    wait_gobgp_established "$GOBGP_SRC" "10.0.0.1" "source" || exit 1
    wait_gobgp_established "$GOBGP_SINK" "10.0.1.1" "sink" || exit 1

    assert_safi128_negotiated "$GOBGP_SRC" "10.0.0.1" "source"
    assert_safi128_negotiated "$GOBGP_SINK" "10.0.1.1" "sink"

    test_vpnv4_reflection
    test_vpnv4_withdrawal
    test_no_dataplane_install

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
