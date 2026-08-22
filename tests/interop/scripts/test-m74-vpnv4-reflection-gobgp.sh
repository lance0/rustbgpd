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
# The same gate now proves VPNv6 with reused RDs, family/peer-scoped views,
# same-path RFC 4456 attributes, family-independent withdrawals, and no exact
# inner-prefix installation in either kernel family.
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
RR_CLUSTER_ID="10.0.0.1"
INNER_PREFIX="10.100.1.0/24"
V6_PREFIX="2001:db8:100::/64"
V6_NH="2001:db8::2"
RD1="65000:1"
RD2="65000:2"
LABEL1=100
LABEL2=200
V6_LABEL1=300
V6_LABEL2=400
RT1="65000:1"
RT2="65000:2"
V6_RT1="65000:101"
V6_RT2="65000:102"

# gobgp global rib add/del -a vpnv4 takes identical argument lists
# (<prefix> label <n> rd <rd> [rt <rt>] [nexthop <ip>]).
ROUTE1_ARGS=("$INNER_PREFIX" label "$LABEL1" rd "$RD1" rt "$RT1" nexthop "$SRC_ADDR")
ROUTE2_ARGS=("$INNER_PREFIX" label "$LABEL2" rd "$RD2" rt "$RT2" nexthop "$SRC_ADDR")
V6_ROUTE1=("$V6_PREFIX" label "$V6_LABEL1" rd "$RD1" rt "$V6_RT1" nexthop "$V6_NH")
V6_ROUTE2=("$V6_PREFIX" label "$V6_LABEL2" rd "$RD2" rt "$V6_RT2" nexthop "$V6_NH")

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

sink_adj_in_json() {
    gobgp "$GOBGP_SINK" neighbor "10.0.1.1" adj-in -a "${1:?}" -j
}

rustbgpd_vpn_json() {
    docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 \
        rib vpn -a "${1:?}" --neighbor "$SRC_ADDR" -j
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

assert_family_negotiated() {
    local container=${1:?}
    local peer=${2:?}
    local family=${3:?}
    local label=${4:?}

    if gobgp "$container" neighbor "$peer" \
        | grep -A 30 "Neighbor capabilities" \
        | grep -F "$family" \
        | grep -q "advertised and received"; then
        ok "$label negotiated $family"
    else
        fail "$label did not negotiate $family"
        gobgp "$container" neighbor "$peer" | grep -A 30 "Neighbor capabilities" || true
    fi
}

# Field-by-field ADR-0077 §6 preservation check against rustbgpd's VPN RIB:
# RD, inner prefix, label stack, next-hop, RT, and source peer all verbatim.
rustbgpd_has_route() {
    local family=${1:?} pfx=${2:?} rd=${3:?} lbl=${4:?} rt=${5:?} nh=${6:?}
    rustbgpd_vpn_json "$family" | jq -e \
        --arg family "$family" --arg peer "$SRC_ADDR" --arg pfx "$pfx" \
        --arg rd "$rd" --argjson lbl "$lbl" --arg rt "RT:$rt" --arg nh "$nh" '
        [.[] | select(
            .afi_safi == $family
            and .peer_address == $peer
            and .route_distinguisher == $rd
            and .prefix == $pfx
            and .labels == [$lbl]
            and .next_hop == $nh
            and .extended_communities == [$rt]
        )] | length == 1' >/dev/null
}

rustbgpd_exact_keys() {
    local family=${1:?}
    shift
    local keys
    keys=$(printf '%s\n' "$@" | jq -R . | jq -cs .)
    rustbgpd_vpn_json "$family" | jq -e \
        --arg family "$family" --arg peer "$SRC_ADDR" --argjson keys "$keys" '
        all(.[]; .afi_safi == $family and .peer_address == $peer)
        and ([.[] | "\(.route_distinguisher)|\(.prefix)"] | sort) == ($keys | sort)' \
        >/dev/null
}

rustbgpd_rd_count() {
    local family=${1:?} rd=${2:?}
    rustbgpd_vpn_json "$family" | jq --arg rd "$rd" \
        '[.[] | select(.route_distinguisher == $rd)] | length' 2>/dev/null || echo query-error
}

# Apply every sink predicate to one exact path. `actual_family` makes the
# family-scoped query itself part of the contract and enables a synthetic
# wrong-family negative without depending on a live daemon.
sink_json_has_route() {
    local actual_family=${1:?} family=${2:?} key=${3:?}
    local lbl=${4:?} rt=${5:?} nh=${6:?}
    jq -e --arg actual "$actual_family" --arg family "$family" --arg key "$key" \
        --argjson lbl "$lbl" --arg rt "$rt" --arg nh "$nh" \
        --arg orig "$SRC_ADDR" --arg cluster "$RR_CLUSTER_ID" '
        ($actual == $family)
        and ((.[$key] // []) as $paths
             | ($paths | length) == 1
             and ($paths[0] as $p
                  | ($p.nlri.labels == [$lbl])
                  and ([$p.attrs[] | select(.type == 14)] as $mp
                       | ($mp | length) == 1 and $mp[0].nexthop == $nh)
                  and ([$p.attrs[] | select(.type == 16)
                        | .value[] | select(.subtype == 2) | .value] == [$rt])
                  and ([$p.attrs[] | select(.type == 9)] as $oid
                       | ($oid | length) == 1 and $oid[0].value == $orig)
                  and ([$p.attrs[] | select(.type == 10)] as $clusters
                       | ($clusters | length) == 1
                       and $clusters[0].value == [$cluster])))' >/dev/null
}

sink_has_route() {
    local family=${1:?} pfx=${2:?} rd=${3:?} lbl=${4:?} rt=${5:?} nh=${6:?}
    sink_adj_in_json "$family" \
        | sink_json_has_route "$family" "$family" "${rd}:${pfx}" "$lbl" "$rt" "$nh"
}

sink_exact_keys() {
    local family=${1:?}
    shift
    local keys
    keys=$(printf '%s\n' "$@" | jq -R . | jq -cs .)
    sink_adj_in_json "$family" | jq -e --argjson keys "$keys" '
        (keys | sort) == ($keys | sort) and all(.[]; length == 1)' >/dev/null
}

sink_key_present() {
    local family=${1:?} pfx=${2:?} rd=${3:?}
    sink_adj_in_json "$family" | jq -r --arg key "${rd}:${pfx}" 'has($key)'
}

wait_rustbgpd_route() {
    local family=${1:?} pfx=${2:?} rd=${3:?} lbl=${4:?} rt=${5:?} nh=${6:?}
    log "Waiting for rustbgpd $family to hold $rd|$pfx label=$lbl rt=RT:$rt nh=$nh..."
    for i in $(seq 1 30); do
        if rustbgpd_has_route "$family" "$pfx" "$rd" "$lbl" "$rt" "$nh"; then
            ok "rustbgpd holds $rd|$pfx with family/peer/fields intact (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "rustbgpd $family missing $rd|$pfx with expected fields"
    rustbgpd_vpn_json "$family" | jq . || true
    return 1
}

wait_rustbgpd_rd_gone() {
    local family=${1:?} rd=${2:?}
    log "Waiting for rustbgpd $family to drop rd=$rd..."
    for i in $(seq 1 30); do
        if [ "$(rustbgpd_rd_count "$family" "$rd")" = 0 ]; then
            ok "rustbgpd removed $family rd=$rd (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "rustbgpd $family still holds rd=$rd"
    rustbgpd_vpn_json "$family" | jq . || true
    return 1
}

wait_sink_route() {
    local family=${1:?} pfx=${2:?} rd=${3:?} lbl=${4:?} rt=${5:?} nh=${6:?}
    log "Waiting for sink $family $rd:$pfx label=$lbl rt=$rt nh=$nh..."
    for i in $(seq 1 30); do
        if sink_has_route "$family" "$pfx" "$rd" "$lbl" "$rt" "$nh"; then
            ok "sink holds one $rd:$pfx path with fields + RFC 4456 attrs (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "GoBGP sink missing reflected $family $rd:$pfx with expected fields"
    sink_adj_in_json "$family" | jq . || true
    return 1
}

wait_sink_rd_gone() {
    local family=${1:?} pfx=${2:?} rd=${3:?} present
    log "Waiting for GoBGP sink to drop $family rd=$rd..."
    for i in $(seq 1 30); do
        if present=$(sink_key_present "$family" "$pfx" "$rd") && [ "$present" = false ]; then
            ok "sink removed $family rd=$rd (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "GoBGP sink still holds $family rd=$rd"
    sink_adj_in_json "$family" | jq . || true
    return 1
}

assert_api_state() {
    local family=${1:?} label=${2:?}
    shift 2
    if rustbgpd_exact_keys "$family" "$@"; then
        ok "rustbgpd $family has exact scoped keys ($label)"
    else
        fail "rustbgpd $family key/family/peer inventory drifted ($label)"
    fi
}

assert_sink_state() {
    local family=${1:?} label=${2:?}
    shift 2
    if sink_exact_keys "$family" "$@"; then
        ok "sink $family adj-in has exact one-path keys ($label)"
    else
        fail "sink $family adj-in key/path inventory drifted ($label)"
    fi
}

test_sink_json_negatives() {
    local key="${RD1}:${INNER_PREFIX}" complete second cross
    complete=$(jq -cn --argjson lbl "$LABEL1" --arg nh "$SRC_ADDR" \
        --arg rt "$RT1" --arg orig "$SRC_ADDR" --arg cluster "$RR_CLUSTER_ID" \
        '{nlri:{labels:[$lbl]},attrs:[{type:14,nexthop:$nh},
          {type:16,value:[{subtype:2,value:$rt}]},{type:9,value:$orig},
          {type:10,value:[$cluster]}]}')
    second=$(jq -cn --arg key "$key" --argjson p "$complete" '{($key):[$p,$p]}')
    cross=$(jq -cn --arg key "$key" --argjson p "$complete" '{($key):[
        ($p | .attrs |= map(select(.type != 9 and .type != 10))),
        ($p | .attrs |= map(select(.type == 9 or .type == 10)))]}')
    reject_sink_json second-path vpnv4 vpnv4 "$second"
    reject_sink_json cross-path-lending vpnv4 vpnv4 "$cross"
    reject_sink_json wrong-family vpnv6 vpnv4 \
        "$(jq -cn --arg key "$key" --argjson p "$complete" '{($key):[$p]}')"
}

reject_sink_json() {
    local label=${1:?} actual=${2:?} family=${3:?} json=${4:?}
    if printf '%s\n' "$json" | sink_json_has_route "$actual" "$family" \
        "${RD1}:${INNER_PREFIX}" "$LABEL1" "$RT1" "$SRC_ADDR"; then
        fail "synthetic sink predicate accepted $label"
    else
        ok "synthetic sink predicate rejects $label"
    fi
}

test_dual_family_reflection() {
    log "Test 1: source injects two VPNv4 and two VPNv6 routes with shared RDs"
    gobgp "$GOBGP_SRC" global rib add -a vpnv4 "${ROUTE1_ARGS[@]}"
    gobgp "$GOBGP_SRC" global rib add -a vpnv4 "${ROUTE2_ARGS[@]}"
    gobgp "$GOBGP_SRC" global rib add -a vpnv6 "${V6_ROUTE1[@]}"
    gobgp "$GOBGP_SRC" global rib add -a vpnv6 "${V6_ROUTE2[@]}"

    wait_rustbgpd_route l3vpn_ipv4_unicast "$INNER_PREFIX" "$RD1" "$LABEL1" "$RT1" "$SRC_ADDR"
    wait_rustbgpd_route l3vpn_ipv4_unicast "$INNER_PREFIX" "$RD2" "$LABEL2" "$RT2" "$SRC_ADDR"
    wait_rustbgpd_route l3vpn_ipv6_unicast "$V6_PREFIX" "$RD1" "$V6_LABEL1" "$V6_RT1" "$V6_NH"
    wait_rustbgpd_route l3vpn_ipv6_unicast "$V6_PREFIX" "$RD2" "$V6_LABEL2" "$V6_RT2" "$V6_NH"
    wait_sink_route vpnv4 "$INNER_PREFIX" "$RD1" "$LABEL1" "$RT1" "$SRC_ADDR"
    wait_sink_route vpnv4 "$INNER_PREFIX" "$RD2" "$LABEL2" "$RT2" "$SRC_ADDR"
    wait_sink_route vpnv6 "$V6_PREFIX" "$RD1" "$V6_LABEL1" "$V6_RT1" "$V6_NH"
    wait_sink_route vpnv6 "$V6_PREFIX" "$RD2" "$V6_LABEL2" "$V6_RT2" "$V6_NH"
    assert_api_state l3vpn_ipv4_unicast initial "$RD1|$INNER_PREFIX" "$RD2|$INNER_PREFIX"
    assert_api_state l3vpn_ipv6_unicast initial "$RD1|$V6_PREFIX" "$RD2|$V6_PREFIX"
    assert_sink_state vpnv4 initial "$RD1:$INNER_PREFIX" "$RD2:$INNER_PREFIX"
    assert_sink_state vpnv6 initial "$RD1:$V6_PREFIX" "$RD2:$V6_PREFIX"
}

test_family_withdrawals() {
    log "Test 2: withdraw VPNv6 RD1, then VPNv4 RD1, preserving both RD2 siblings"
    gobgp "$GOBGP_SRC" global rib del -a vpnv6 "${V6_ROUTE1[@]}"
    wait_rustbgpd_rd_gone l3vpn_ipv6_unicast "$RD1"
    wait_sink_rd_gone vpnv6 "$V6_PREFIX" "$RD1"
    assert_api_state l3vpn_ipv4_unicast after-v6 "$RD1|$INNER_PREFIX" "$RD2|$INNER_PREFIX"
    assert_api_state l3vpn_ipv6_unicast after-v6 "$RD2|$V6_PREFIX"
    assert_sink_state vpnv4 after-v6 "$RD1:$INNER_PREFIX" "$RD2:$INNER_PREFIX"
    assert_sink_state vpnv6 after-v6 "$RD2:$V6_PREFIX"

    gobgp "$GOBGP_SRC" global rib del -a vpnv4 "${ROUTE1_ARGS[@]}"
    wait_rustbgpd_rd_gone l3vpn_ipv4_unicast "$RD1"
    wait_sink_rd_gone vpnv4 "$INNER_PREFIX" "$RD1"
    assert_api_state l3vpn_ipv4_unicast final "$RD2|$INNER_PREFIX"
    assert_api_state l3vpn_ipv6_unicast final "$RD2|$V6_PREFIX"
    assert_sink_state vpnv4 final "$RD2:$INNER_PREFIX"
    assert_sink_state vpnv6 final "$RD2:$V6_PREFIX"
}

test_no_dataplane_install() {
    log "Test 3: RR installed nothing into any dataplane"

    local mpls ipv4 ipv6
    if capture_ip_routes mpls "$RUSTBGPD" MPLS -M route show; then
        if [ -z "$mpls" ]; then
            ok "RR MPLS routing table is empty"
        else
            fail "RR has unexpected MPLS routes"
            printf '%s\n' "$mpls" >&2
        fi
    fi

    if capture_ip_routes ipv4 "$RUSTBGPD" IPv4 -4 route show table all; then
        if grep -qF "${INNER_PREFIX%/*}" <<<"$ipv4"; then
            fail "RR kernel table-all contains the exact VPNv4 inner prefix"
            printf '%s\n' "$ipv4" >&2
        else
            ok "RR kernel table-all lacks the exact VPNv4 inner prefix"
        fi
    fi
    if capture_ip_routes ipv6 "$RUSTBGPD" IPv6 -6 route show table all; then
        if grep -qF "${V6_PREFIX%/*}" <<<"$ipv6"; then
            fail "RR kernel table-all contains the exact VPNv6 inner prefix"
            printf '%s\n' "$ipv6" >&2
        else
            ok "RR kernel table-all lacks the exact VPNv6 inner prefix"
        fi
    fi
}

capture_ip_routes() {
    local output_var=$1 container=$2 table_label=$3 captured
    shift 3
    if ! captured=$(docker exec "$container" ip "$@" 2>&1); then
        fail "$container $table_label route inspection failed"
        printf '%s\n' "$captured" >&2
        return 1
    fi
    printf -v "$output_var" '%s' "$captured"
}

main() {
    log "M74 interop test: dual VPNv4/VPNv6 route reflection via GoBGP"
    log "Topology: $TOPO"

    preflight
    resolve_grpc_addr
    start_gobgpd "$GOBGP_SRC"
    start_gobgpd "$GOBGP_SINK"
    start_rustbgpd
    test_sink_json_negatives

    wait_gobgp_established "$GOBGP_SRC" "10.0.0.1" "source" || exit 1
    wait_gobgp_established "$GOBGP_SINK" "10.0.1.1" "sink" || exit 1

    assert_family_negotiated "$GOBGP_SRC" "10.0.0.1" l3vpn-ipv4-unicast source
    assert_family_negotiated "$GOBGP_SRC" "10.0.0.1" l3vpn-ipv6-unicast source
    assert_family_negotiated "$GOBGP_SINK" "10.0.1.1" l3vpn-ipv4-unicast sink
    assert_family_negotiated "$GOBGP_SINK" "10.0.1.1" l3vpn-ipv6-unicast sink

    test_dual_family_reflection
    test_family_withdrawals
    test_no_dataplane_install

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
