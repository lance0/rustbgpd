#!/usr/bin/env bash
# M82 leg 1 interop test — EVPN VLAN-aware-bundle (non-zero Ethernet
# Tag) route reflection against Nokia SR Linux 25.10. rustbgpd's FIRST
# vendor-NOS interop receipt (ADR-0092 Decision 6 ground truth).
#
# SR Linux runs two mac-vrf bridge domains in VLAN-aware-bundle
# interoperability mode: vlan-aware-bundle-eth-tag 10 (evi 100, RD
# 192.0.2.2:100, VNI 10010) and 20 (evi 101, RD 192.0.2.2:101, VNI
# 10020), shared RT target:65000:100, the SAME static MAC in both
# bridge domains. Assertions:
#
#   1. SR Linux iBGP EVPN session Established (both ends agree).
#   2. RR holds SR Linux's Type 3 IMET routes for tags 10 AND 20 as
#      distinct RIB entries (non-zero tags surfaced via rbgp evpn).
#   3. RR holds SR Linux's Type 2 MAC/IP routes: the same MAC keyed
#      under tags 10 and 20 = two distinct entries (no collapse),
#      labels = the per-tag VNIs.
#   4. The GoBGP sink receives all four routes reflected with the tags
#      intact in the re-decoded NLRI, ORIGINATOR_ID = SR Linux and
#      CLUSTER_LIST = the RR cluster-id (RFC 4456 reflection).
#   5. Reflected Type 2 NLRIs are tag-verbatim (etag + MAC + label
#      field equality on the sink's re-decoded NLRI).
#   6. Withdraw: deleting the bd10 static MAC on SR Linux withdraws
#      exactly the tag-10 Type 2 everywhere; the tag-20 twin and both
#      IMETs survive.
#
# Prerequisites:
#   - docker build --target dev -t rustbgpd:dev .
#   - docker build -t gobgp:interop -f tests/interop/Dockerfile.gobgp tests/interop
#   - docker pull ghcr.io/nokia/srlinux:latest
#   - containerlab deploy -t tests/interop/m82-evpn-bundle-srlinux.clab.yml

TOPO="m82-evpn-bundle-srlinux"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"

SRL="clab-${TOPO}-srl"
GOBGP_SINK="clab-${TOPO}-gobgp-sink"

SRL_ADDR="10.0.0.2"
SINK_ADDR="10.0.1.2"
RR_CLUSTER_ID="10.0.0.100"

RD_A="192.0.2.2:100"
RD_B="192.0.2.2:101"
MAC="aa:bb:cc:00:82:aa"
TAG_A=10
TAG_B=20
VNI_A=10010
VNI_B=10020

srl_cli() {
    # -u root: sr_cli refuses unmapped users; root is aaa-mapped admin.
    docker exec -u root "$SRL" sr_cli "$@" 2>/dev/null
}

gobgp_sink() {
    docker exec "$GOBGP_SINK" gobgp "$@" 2>/dev/null
}

start_gobgpd_sink() {
    log "Starting gobgpd in $GOBGP_SINK..."
    docker exec -d "$GOBGP_SINK" sh -c \
        'nohup gobgpd -f /config/gobgp.toml >/tmp/gobgpd.log 2>&1'
}

rr_evpn_json() {
    local route_type=${1:?}
    docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 \
        evpn --route-type "$route_type" -j 2>/dev/null || echo "[]"
}

rr_evpn_count() {
    local route_type=${1:?} predicate=${2:?}
    rr_evpn_json "$route_type" \
        | jq "[.[] | select(${predicate})] | length" 2>/dev/null || echo 0
}

wait_rr_evpn() {
    local route_type=${1:?} predicate=${2:?} label=${3:?}
    log "Waiting for RR EVPN RIB: $label..."
    for i in $(seq 1 45); do
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

wait_rr_evpn_gone() {
    local route_type=${1:?} predicate=${2:?} label=${3:?}
    log "Waiting for RR EVPN RIB to drop: $label..."
    for i in $(seq 1 45); do
        if [ "$(rr_evpn_count "$route_type" "$predicate")" -eq 0 ]; then
            ok "RR RIB dropped $label (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "RR RIB still holds $label"
    rr_evpn_json "$route_type" | jq . || true
    return 1
}

sink_evpn_json() {
    gobgp_sink global rib -a evpn -j
}

sink_has_key() {
    local key=${1:?}
    sink_evpn_json | jq -e --arg key "$key" 'has($key)' >/dev/null
}

wait_sink_key() {
    local key=${1:?} label=${2:?}
    log "Waiting for sink to hold $label..."
    for i in $(seq 1 45); do
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
    for i in $(seq 1 45); do
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

# GoBGP renders Type 2 keys from the re-decoded NLRI. SR Linux
# advertises MAC-only Type 2 routes for static MACs (no IP), so the
# [ip:...] segment is empty.
MACADV_A_KEY_PREFIX="[type:macadv][rd:${RD_A}][etag:${TAG_A}][mac:${MAC}]"
MACADV_B_KEY_PREFIX="[type:macadv][rd:${RD_B}][etag:${TAG_B}][mac:${MAC}]"

sink_macadv_key() {
    # Resolve the full RIB key for a Type 2 key prefix (IP part varies).
    local prefix=${1:?}
    sink_evpn_json | jq -r --arg p "$prefix" 'keys[] | select(startswith($p))' | head -1
}

wait_srl_established() {
    log "Waiting for the SR Linux EVPN session to Established..."
    for i in $(seq 1 60); do
        # `info from state ... session-state` — the tabular `show` output
        # contains the word "established" even when nothing is (summary
        # line), so pin the state leaf exactly.
        if srl_cli "info from state network-instance default protocols bgp neighbor 10.0.0.1 session-state" \
            | grep -q "session-state established"; then
            ok "SR Linux reports the session Established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "SR Linux session did not reach Established within 120s"
    srl_cli "show network-instance default protocols bgp neighbor" || true
    return 1
}

test_sessions() {
    log "Test 1: EVPN sessions Established on both RR clients"
    wait_srl_established || exit 1
    log "Waiting for the sink session..."
    for i in $(seq 1 45); do
        if gobgp_sink neighbor 2>/dev/null | grep -F "10.0.1.1" | grep -qi establ; then
            ok "sink session established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "sink session did not reach Established within 90s"
    gobgp_sink neighbor || true
    exit 1
}

test_rr_imet_tags() {
    log "Test 2: RR holds SR Linux IMET routes with non-zero tags $TAG_A and $TAG_B"
    wait_rr_evpn 3 ".ethernet_tag == \"$TAG_A\" and .rd == \"$RD_A\" and .peer == \"$SRL_ADDR\"" \
        "IMET tag $TAG_A (rd $RD_A)"
    wait_rr_evpn 3 ".ethernet_tag == \"$TAG_B\" and .rd == \"$RD_B\" and .peer == \"$SRL_ADDR\"" \
        "IMET tag $TAG_B (rd $RD_B)"
}

test_rr_type2_tag_identity() {
    log "Test 3: RR keys the same MAC under tags $TAG_A/$TAG_B as distinct Type 2 entries"
    wait_rr_evpn 2 ".ethernet_tag == \"$TAG_A\" and .mac == \"$MAC\" and .label == $VNI_A" \
        "Type 2 tag $TAG_A / VNI $VNI_A"
    wait_rr_evpn 2 ".ethernet_tag == \"$TAG_B\" and .mac == \"$MAC\" and .label == $VNI_B" \
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

test_sink_receives_reflected() {
    log "Test 4: sink receives all four SR Linux routes reflected, tags intact"
    wait_sink_key "[type:multicast][rd:${RD_A}][etag:${TAG_A}][ip:192.0.2.2]" "IMET tag $TAG_A"
    wait_sink_key "[type:multicast][rd:${RD_B}][etag:${TAG_B}][ip:192.0.2.2]" "IMET tag $TAG_B"

    local key_a key_b
    for i in $(seq 1 45); do
        key_a=$(sink_macadv_key "$MACADV_A_KEY_PREFIX")
        key_b=$(sink_macadv_key "$MACADV_B_KEY_PREFIX")
        [ -n "$key_a" ] && [ -n "$key_b" ] && break
        sleep 2
    done
    if [ -n "$key_a" ] && [ -n "$key_b" ]; then
        ok "sink holds both Type 2 routes (tags $TAG_A + $TAG_B)"
    else
        fail "sink missing a reflected Type 2 (tag $TAG_A: '${key_a:-none}', tag $TAG_B: '${key_b:-none}')"
        sink_evpn_json | jq -r 'keys[]' || true
        return 1
    fi

    if sink_evpn_json | jq -e --arg key "$key_a" --arg oid "$SRL_ADDR" '
        [.[$key][0].attrs[] | select(.type == 9 and .value == $oid)] | length == 1' >/dev/null; then
        ok "ORIGINATOR_ID = $SRL_ADDR (SR Linux) on the reflected Type 2"
    else
        fail "reflected Type 2 missing ORIGINATOR_ID=$SRL_ADDR"
        sink_evpn_json | jq --arg key "$key_a" '.[$key]' || true
    fi
    if sink_evpn_json | jq -e --arg key "$key_a" --arg cid "$RR_CLUSTER_ID" '
        [.[$key][0].attrs[] | select(.type == 10 and (.value | index($cid)))] | length == 1' >/dev/null; then
        ok "CLUSTER_LIST contains $RR_CLUSTER_ID on the reflected Type 2"
    else
        fail "reflected Type 2 missing CLUSTER_LIST entry $RR_CLUSTER_ID"
        sink_evpn_json | jq --arg key "$key_a" '.[$key]' || true
    fi
}

test_nlri_verbatim() {
    log "Test 5: reflected Type 2 NLRIs are tag-verbatim (etag + MAC + VNI label)"
    local key
    key=$(sink_macadv_key "$MACADV_A_KEY_PREFIX")
    if [ -n "$key" ] && sink_evpn_json | jq -e --arg key "$key" --arg mac "$MAC" \
        --argjson tag "$TAG_A" --argjson vni "$VNI_A" '
        .[$key][0].nlri.value
        | .etag == $tag and .mac == $mac and .labels == [$vni]' >/dev/null; then
        ok "Type 2 tag $TAG_A NLRI verbatim (etag/mac/label $VNI_A)"
    else
        fail "Type 2 tag $TAG_A NLRI mutated in reflection"
        [ -n "$key" ] && sink_evpn_json | jq --arg key "$key" '.[$key][0].nlri' || true
    fi
    key=$(sink_macadv_key "$MACADV_B_KEY_PREFIX")
    if [ -n "$key" ] && sink_evpn_json | jq -e --arg key "$key" --arg mac "$MAC" \
        --argjson tag "$TAG_B" --argjson vni "$VNI_B" '
        .[$key][0].nlri.value
        | .etag == $tag and .mac == $mac and .labels == [$vni]' >/dev/null; then
        ok "Type 2 tag $TAG_B NLRI verbatim (etag/mac/label $VNI_B)"
    else
        fail "Type 2 tag $TAG_B NLRI mutated in reflection"
        [ -n "$key" ] && sink_evpn_json | jq --arg key "$key" '.[$key][0].nlri' || true
    fi
}

test_withdraw_tag_scoped() {
    log "Test 6: deleting the bd10 static MAC withdraws exactly the tag-$TAG_A Type 2"
    local key_a key_b
    key_a=$(sink_macadv_key "$MACADV_A_KEY_PREFIX")
    if docker exec -u root "$SRL" sr_cli --candidate-mode --commit-at-end \
        "delete network-instance bd10 bridge-table static-mac mac AA:BB:CC:00:82:AA" \
        >/dev/null 2>&1; then
        ok "bd10 static MAC deleted on SR Linux"
    else
        fail "SR Linux static-mac delete failed"
        return 1
    fi

    wait_rr_evpn_gone 2 ".ethernet_tag == \"$TAG_A\" and .mac == \"$MAC\"" "Type 2 tag $TAG_A"
    [ -n "$key_a" ] && wait_sink_key_gone "$key_a" "Type 2 tag $TAG_A"

    key_b=$(sink_macadv_key "$MACADV_B_KEY_PREFIX")
    if [ -n "$key_b" ]; then
        ok "sink still holds the tag-$TAG_B twin after the tag-$TAG_A withdraw"
    else
        fail "sink lost the tag-$TAG_B twin alongside the tag-$TAG_A withdraw"
    fi
    if sink_has_key "[type:multicast][rd:${RD_A}][etag:${TAG_A}][ip:192.0.2.2]" \
        && sink_has_key "[type:multicast][rd:${RD_B}][etag:${TAG_B}][ip:192.0.2.2]"; then
        ok "both IMET routes survive the Type 2 withdraw"
    else
        fail "an IMET route disappeared alongside the Type 2 withdraw"
        sink_evpn_json | jq -r 'keys[]' || true
    fi
}

main() {
    log "M82 leg 1: EVPN VLAN-aware-bundle reflection — Nokia SR Linux vendor receipt"
    log "Topology: $TOPO"

    preflight
    resolve_grpc_addr
    start_gobgpd_sink
    start_rustbgpd

    test_sessions
    test_rr_imet_tags
    test_rr_type2_tag_identity
    test_sink_receives_reflected
    test_nlri_verbatim
    test_withdraw_tag_scoped

    print_summary
}

main "$@"
