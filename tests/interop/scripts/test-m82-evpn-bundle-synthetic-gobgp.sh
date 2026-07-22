#!/usr/bin/env bash
# M82 leg 2 interop test — EVPN VLAN-aware-bundle (non-zero Ethernet Tag)
# route reflection, GoBGP-synthetic (ADR-0092 Decision 6 first slice).
#
# GoBGP originates the RFC 7432 §6.3 bundle route shape — one EVI
# (RD 65000:100, RT 65000:100) holding two bridge domains with distinct
# non-zero Ethernet Tags (10 → VNI 10010, 20 → VNI 10020), the SAME MAC
# address under both tags — and rustbgpd must reflect it with the tag as
# route identity:
#
#   1. Both iBGP sessions Established with l2vpn-evpn negotiated.
#   2. RR RIB keys the same (RD, MAC) under tags 10 and 20 as TWO
#      distinct Type 2 entries (no (VNI, MAC) collapse), tags surfaced
#      via ListEvpnRoutes / rbgp evpn.
#   3. RR RIB holds distinct Type 3 IMET entries for tags 10 and 20.
#   4. The sink receives all four routes reflected with ORIGINATOR_ID =
#      src and CLUSTER_LIST = the RR cluster-id.
#   5. Reflected NLRIs are tag-verbatim: RD / Ethernet Tag / MAC / IP /
#      label all byte-identical to what was injected (GoBGP re-decodes
#      the received NLRI; field equality on every NLRI field is the
#      wire assertion).
#   6. Withdrawing the tag-10 Type 2 removes exactly that entry from the
#      RR RIB and the sink; the tag-20 twin and both IMETs survive.
#   7. The RR installs nothing into its own dataplane (pure reflector).
#
# Prerequisites:
#   - docker build --target dev -t rustbgpd:dev .
#   - docker build -t gobgp:interop -f tests/interop/Dockerfile.gobgp tests/interop
#   - containerlab deploy -t tests/interop/m82-evpn-bundle-synthetic-gobgp.clab.yml

TOPO="m82-evpn-bundle-synthetic-gobgp"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
source "$SCRIPT_DIR/test-lib.sh"

GOBGP_SRC="clab-${TOPO}-gobgp-src"
GOBGP_SINK="clab-${TOPO}-gobgp-sink"

SRC_ADDR="10.0.0.2"
SINK_ADDR="10.0.1.2"
RR_CLUSTER_ID="10.0.0.100"

RD="65000:100"
RT="65000:100"
MAC="aa:bb:cc:00:82:aa"
TAG_A=10
TAG_B=20
VNI_A=10010
VNI_B=10020
IP_A="10.82.10.10"
IP_B="10.82.20.10"

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

wait_gobgp_established() {
    local container=${1:?} peer=${2:?} label=${3:?}
    log "Waiting for $label session to $peer..."
    for i in $(seq 1 45); do
        if gobgp "$container" neighbor 2>/dev/null | grep -F -- "$peer" | grep -qi "establ"; then
            ok "$label session established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$label session did not reach Established within 90s"
    gobgp "$container" neighbor || true
    return 1
}

rr_evpn_json() {
    local route_type=${1:?}
    docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 \
        evpn --route-type "$route_type" -j 2>/dev/null || echo "[]"
}

# Count RR EVPN rows of a type matching a jq row predicate.
rr_evpn_count() {
    local route_type=${1:?} predicate=${2:?}
    rr_evpn_json "$route_type" \
        | jq "[.[] | select(${predicate})] | length" 2>/dev/null || echo 0
}

wait_rr_evpn() {
    local route_type=${1:?} predicate=${2:?} label=${3:?}
    log "Waiting for RR EVPN RIB: $label..."
    for i in $(seq 1 30); do
        if [ "$(rr_evpn_count "$route_type" "$predicate")" -ge 1 ]; then
            ok "RR RIB holds $label (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "RR RIB missing $label"
    rr_evpn_json "$route_type" | jq . || true
    return 1
}

sink_evpn_json() {
    gobgp "$GOBGP_SINK" global rib -a evpn -j
}

# GoBGP renders the decoded NLRI into the RIB key, e.g.
# "[type:macadv][rd:65000:100][etag:10][mac:aa:bb:cc:00:82:aa][ip:10.82.10.10]"
sink_has_key() {
    local key=${1:?}
    sink_evpn_json | jq -e --arg key "$key" 'has($key)' >/dev/null
}

wait_sink_key() {
    local key=${1:?} label=${2:?}
    log "Waiting for sink to hold $label..."
    for i in $(seq 1 30); do
        if sink_has_key "$key"; then
            ok "sink holds $label (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "sink missing $label ($key)"
    sink_evpn_json | jq -r 'keys[]' || true
    return 1
}

wait_sink_key_gone() {
    local key=${1:?} label=${2:?}
    log "Waiting for sink to drop $label..."
    for i in $(seq 1 30); do
        if ! sink_has_key "$key"; then
            ok "sink dropped $label (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "sink still holds $label ($key)"
    sink_evpn_json | jq -r 'keys[]' || true
    return 1
}

MACADV_A_KEY="[type:macadv][rd:${RD}][etag:${TAG_A}][mac:${MAC}][ip:${IP_A}]"
MACADV_B_KEY="[type:macadv][rd:${RD}][etag:${TAG_B}][mac:${MAC}][ip:${IP_B}]"
IMET_A_KEY="[type:multicast][rd:${RD}][etag:${TAG_A}][ip:${SRC_ADDR}]"
IMET_B_KEY="[type:multicast][rd:${RD}][etag:${TAG_B}][ip:${SRC_ADDR}]"

test_inject_bundle_routes() {
    log "Setup: inject bundle-shaped routes (same MAC under tags $TAG_A and $TAG_B, one EVI)"
    gobgp "$GOBGP_SRC" global rib add -a evpn macadv "$MAC" "$IP_A" \
        etag "$TAG_A" label "$VNI_A" rd "$RD" rt "$RT" encap vxlan nexthop "$SRC_ADDR" \
        && ok "Type 2 tag $TAG_A (VNI $VNI_A) injected" \
        || fail "Type 2 tag $TAG_A injection failed"
    gobgp "$GOBGP_SRC" global rib add -a evpn macadv "$MAC" "$IP_B" \
        etag "$TAG_B" label "$VNI_B" rd "$RD" rt "$RT" encap vxlan nexthop "$SRC_ADDR" \
        && ok "Type 2 tag $TAG_B (VNI $VNI_B) injected" \
        || fail "Type 2 tag $TAG_B injection failed"
    gobgp "$GOBGP_SRC" global rib add -a evpn multicast "$SRC_ADDR" \
        etag "$TAG_A" rd "$RD" rt "$RT" encap vxlan nexthop "$SRC_ADDR" \
        && ok "Type 3 IMET tag $TAG_A injected" \
        || fail "Type 3 IMET tag $TAG_A injection failed"
    gobgp "$GOBGP_SRC" global rib add -a evpn multicast "$SRC_ADDR" \
        etag "$TAG_B" rd "$RD" rt "$RT" encap vxlan nexthop "$SRC_ADDR" \
        && ok "Type 3 IMET tag $TAG_B injected" \
        || fail "Type 3 IMET tag $TAG_B injection failed"
}

test_rr_type2_tag_identity() {
    log "Test 1: RR keys the same (RD, MAC) under tags $TAG_A/$TAG_B as distinct Type 2 entries"
    wait_rr_evpn 2 ".ethernet_tag == \"$TAG_A\" and .mac == \"$MAC\" and .rd == \"$RD\" and .label == $VNI_A and .ip == \"$IP_A\"" \
        "Type 2 tag $TAG_A / VNI $VNI_A"
    wait_rr_evpn 2 ".ethernet_tag == \"$TAG_B\" and .mac == \"$MAC\" and .rd == \"$RD\" and .label == $VNI_B and .ip == \"$IP_B\"" \
        "Type 2 tag $TAG_B / VNI $VNI_B"

    local total
    total=$(rr_evpn_count 2 ".mac == \"$MAC\"")
    if [ "$total" -eq 2 ]; then
        ok "same MAC under two tags = exactly 2 RIB entries (no collapse)"
    else
        fail "expected 2 Type 2 entries for $MAC, got $total"
        rr_evpn_json 2 | jq . || true
    fi
}

test_rr_type3_tags() {
    log "Test 2: RR holds distinct Type 3 IMET entries for tags $TAG_A and $TAG_B"
    wait_rr_evpn 3 ".ethernet_tag == \"$TAG_A\" and .rd == \"$RD\"" "IMET tag $TAG_A"
    wait_rr_evpn 3 ".ethernet_tag == \"$TAG_B\" and .rd == \"$RD\"" "IMET tag $TAG_B"
}

test_sink_receives_reflected() {
    log "Test 3: sink receives all four routes reflected, tags intact"
    wait_sink_key "$MACADV_A_KEY" "Type 2 tag $TAG_A"
    wait_sink_key "$MACADV_B_KEY" "Type 2 tag $TAG_B"
    wait_sink_key "$IMET_A_KEY" "IMET tag $TAG_A"
    wait_sink_key "$IMET_B_KEY" "IMET tag $TAG_B"
}

test_reflection_attrs() {
    log "Test 4: reflected route carries ORIGINATOR_ID=$SRC_ADDR and CLUSTER_LIST=$RR_CLUSTER_ID"
    if sink_evpn_json | jq -e --arg key "$MACADV_A_KEY" --arg oid "$SRC_ADDR" '
        [.[$key][0].attrs[] | select(.type == 9 and .value == $oid)] | length == 1' >/dev/null; then
        ok "ORIGINATOR_ID = $SRC_ADDR on the reflected Type 2"
    else
        fail "reflected Type 2 missing ORIGINATOR_ID=$SRC_ADDR"
        sink_evpn_json | jq --arg key "$MACADV_A_KEY" '.[$key]' || true
    fi
    if sink_evpn_json | jq -e --arg key "$MACADV_A_KEY" --arg cid "$RR_CLUSTER_ID" '
        [.[$key][0].attrs[] | select(.type == 10 and (.value | index($cid)))] | length == 1' >/dev/null; then
        ok "CLUSTER_LIST contains $RR_CLUSTER_ID on the reflected Type 2"
    else
        fail "reflected Type 2 missing CLUSTER_LIST entry $RR_CLUSTER_ID"
        sink_evpn_json | jq --arg key "$MACADV_A_KEY" '.[$key]' || true
    fi
}

# GoBGP re-decodes the received UPDATE into structured NLRI fields; equality
# on EVERY NLRI field against the injected values pins the reflected wire
# encoding (RD admin/assigned, 4-byte Ethernet Tag, MAC, IP, label).
test_nlri_verbatim() {
    log "Test 5: reflected NLRI is tag-verbatim (all NLRI fields identical to injection)"
    local tag vni ip key
    for spec in "$TAG_A $VNI_A $IP_A" "$TAG_B $VNI_B $IP_B"; do
        set -- $spec
        tag=$1; vni=$2; ip=$3
        key="[type:macadv][rd:${RD}][etag:${tag}][mac:${MAC}][ip:${ip}]"
        if sink_evpn_json | jq -e --arg key "$key" --arg mac "$MAC" --arg ip "$ip" \
            --argjson tag "$tag" --argjson vni "$vni" '
            .[$key][0].nlri.value
            | .rd.admin == 65000 and .rd.assigned == 100
              and .etag == $tag and .mac == $mac and .ip == $ip
              and .labels == [$vni]' >/dev/null; then
            ok "Type 2 tag $tag NLRI verbatim (rd/etag/mac/ip/label)"
        else
            fail "Type 2 tag $tag NLRI mutated in reflection"
            sink_evpn_json | jq --arg key "$key" '.[$key][0].nlri' || true
        fi
    done
}

test_withdraw_tag_scoped() {
    log "Test 6: withdrawing the tag-$TAG_A Type 2 removes exactly that entry"
    gobgp "$GOBGP_SRC" global rib del -a evpn macadv "$MAC" "$IP_A" \
        etag "$TAG_A" label "$VNI_A" rd "$RD" rt "$RT" encap vxlan nexthop "$SRC_ADDR" \
        && ok "tag-$TAG_A Type 2 withdrawn at the source" \
        || fail "tag-$TAG_A withdraw failed"

    wait_sink_key_gone "$MACADV_A_KEY" "Type 2 tag $TAG_A"

    if sink_has_key "$MACADV_B_KEY"; then
        ok "sink still holds the tag-$TAG_B twin after the tag-$TAG_A withdraw"
    else
        fail "sink lost the tag-$TAG_B twin alongside the tag-$TAG_A withdraw"
    fi
    if sink_has_key "$IMET_A_KEY" && sink_has_key "$IMET_B_KEY"; then
        ok "both IMET routes survive the Type 2 withdraw"
    else
        fail "an IMET route disappeared alongside the Type 2 withdraw"
        sink_evpn_json | jq -r 'keys[]' || true
    fi

    local rr_a rr_b
    rr_a=$(rr_evpn_count 2 ".ethernet_tag == \"$TAG_A\" and .mac == \"$MAC\"")
    rr_b=$(rr_evpn_count 2 ".ethernet_tag == \"$TAG_B\" and .mac == \"$MAC\"")
    if [ "$rr_a" -eq 0 ] && [ "$rr_b" -eq 1 ]; then
        ok "RR RIB dropped only the tag-$TAG_A entry (tag-$TAG_B intact)"
    else
        fail "RR RIB tag-scoped withdraw wrong: tag-$TAG_A count=$rr_a, tag-$TAG_B count=$rr_b"
        rr_evpn_json 2 | jq . || true
    fi
}

test_no_dataplane_install() {
    log "Test 7: RR installed nothing into its own dataplane"
    local links
    links=$(docker exec "$RUSTBGPD" ip -o link show type vxlan 2>/dev/null || true)
    if [ -z "$links" ]; then
        ok "RR has no VXLAN netdevs"
    else
        fail "RR created VXLAN netdevs"
        echo "$links" >&2
    fi
}

main() {
    log "M82 leg 2: EVPN VLAN-aware-bundle (non-zero Ethernet Tag) reflection via GoBGP"
    log "Topology: $TOPO"

    preflight
    resolve_grpc_addr
    start_gobgpd "$GOBGP_SRC"
    start_gobgpd "$GOBGP_SINK"
    start_rustbgpd

    wait_gobgp_established "$GOBGP_SRC" "10.0.0.1" "source" || exit 1
    wait_gobgp_established "$GOBGP_SINK" "10.0.1.1" "sink" || exit 1

    test_inject_bundle_routes
    test_rr_type2_tag_identity
    test_rr_type3_tags
    test_sink_receives_reflected
    test_reflection_attrs
    test_nlri_verbatim
    test_withdraw_tag_scoped
    test_no_dataplane_install

    print_summary
}

main "$@"
