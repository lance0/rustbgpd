#!/usr/bin/env bash
# M72 interop test — rustbgpd receive-side RFC 9136 §4.3 ESI
# overlay-index Type 5 ALL-ACTIVE recursion against two real GoBGP
# peers.
#
# rustbgpd is the device under test (VTEP / receive side) with a full
# L3 VRF datapath. pe1 originates an ESI overlay-index Type 5 (non-zero
# ESI, Router-MAC extcomm, Gateway Address 0.0.0.0). pe1 and pe2
# originate all-active EAD-per-ES + EAD-per-EVI state for that ESI, so
# rustbgpd should resolve the Type 5 to a deterministic multi-VTEP
# target set and install:
#
#   - a VRF-table ECMP route over l3vxlan100,
#   - one L3 neighbor per remote VTEP,
#   - one Router-MAC FDB row carrying nhid,
#   - an FDB nexthop group whose members resolve to both PEs.
#
# Usage:
#   containerlab deploy -t tests/interop/m72-evpn-esi-overlay-type5-all-active-gobgp.clab.yml
#   bash tests/interop/scripts/test-m72-evpn-esi-overlay-type5-all-active-gobgp.sh
#   containerlab destroy -t tests/interop/m72-evpn-esi-overlay-type5-all-active-gobgp.clab.yml

set -euo pipefail

TOPO="m72-evpn-esi-overlay-type5-all-active-gobgp"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH

VTEP="clab-${TOPO}-vtep"
PE1="clab-${TOPO}-pe1"
PE2="clab-${TOPO}-pe2"
RUSTBGPD="$VTEP"
export RUSTBGPD

# shellcheck disable=SC1091
# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

VTEP_IP="10.0.1.1"
PE1_IP="10.0.1.2"
PE2_IP="10.0.2.2"
L3VNI=100
L2VNI=10
TENANT_VRF="vrf1"
TABLE_ID=100
VTEP_ROUTER_MAC="02:00:00:00:01:01"
L3VXLAN="l3vxlan${L3VNI}"

TARGET_PREFIX="203.0.113.0/24"
RD_L3="65000:100"
RT_L3="65000:100"
RD_L2_PE1="65000:11"
RD_L2_PE2="65000:12"
RT_L2="65000:10"
TYPE5_ROUTER_MAC="02:00:00:00:72:01"
ESI_GOBGP=(esi 0 00:00:00:00:00:00:00:00:01)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

pe1_rib() { docker exec "$PE1" gobgp global rib "$@"; }
pe2_rib() { docker exec "$PE2" gobgp global rib "$@"; }

wait_gobgp_established() {
    local pe=${1:?}
    local peer=${2:?}
    local label=${3:-BGP}
    log "Waiting for $label session to reach Established..."
    for i in $(seq 1 45); do
        local state
        state=$(docker exec "$pe" gobgp neighbor "$peer" 2>/dev/null | grep -i 'BGP state' || true)
        if echo "$state" | grep -qi "establ"; then
            ok "$label session established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$label session did not reach Established within 90s"
    docker exec "$pe" gobgp neighbor "$peer" >&2 2>/dev/null || true
    return 1
}

drop_gauge() {
    local reason=${1:?}
    prom_scrape "$VTEP" | awk \
        -v v="vrf=\"${TENANT_VRF}\"" \
        -v r="reason=\"${reason}\"" '
        $0 ~ /^evpn_ip_vrf_remote_prefix_drops\{/ && index($0, v) && index($0, r) {
            print $2
            exit
        }'
}

drop_gauge_at_least_1() {
    local reason=${1:?}
    local got
    got=$(drop_gauge "$reason")
    [ "${got:-0}" -ge 1 ] 2>/dev/null
}

drop_gauge_is_zero() {
    local reason=${1:?}
    local got
    got=$(drop_gauge "$reason")
    [ "${got:-0}" -eq 0 ] 2>/dev/null
}

route_dump() {
    docker exec "$VTEP" ip route show table "$TABLE_ID" "$TARGET_PREFIX" 2>/dev/null || true
}

vrf_route_absent() {
    [ -z "$(route_dump)" ]
}

vrf_route_installed_ecmp() {
    local dump
    dump=$(route_dump)
    [ -n "$dump" ] || return 1
    echo "$dump" | grep -q "^${TARGET_PREFIX}" || return 1
    echo "$dump" | grep -q " proto bgp" || return 1
    echo "$dump" | grep -q "nexthop via ${PE1_IP} dev ${L3VXLAN} .*onlink" || return 1
    echo "$dump" | grep -q "nexthop via ${PE2_IP} dev ${L3VXLAN} .*onlink" || return 1
}

vrf_installed_count() {
    grpcurl_call \
        -d '{"name":"'"$TENANT_VRF"'"}' \
        "$GRPC_ADDR" rustbgpd.v1.EvpnService/GetIpVrf 2>/dev/null \
        | jq -r '.installedRoutesCount // 0' 2>/dev/null || echo 0
}

vrf_installed_count_is() {
    local want=${1:?}
    [ "$(vrf_installed_count)" = "$want" ]
}

wait_until() {
    local timeout=$1
    shift
    local attempts=$((timeout / 2))
    [ "$attempts" -lt 1 ] && attempts=1
    for _ in $(seq 1 "$attempts"); do
        if "$@"; then
            return 0
        fi
        sleep 2
    done
    return 1
}

l3_neigh_dump() {
    docker exec "$VTEP" ip neigh show dev "$L3VXLAN" 2>/dev/null || true
}

nh_dump() {
    docker exec "$VTEP" ip nexthop show 2>/dev/null || true
}

fdb_dump() {
    docker exec "$VTEP" bridge fdb show dev "$L3VXLAN" 2>/dev/null || true
}

nh_id_for_via() {
    local ip=${1:?}
    nh_dump | grep -E "^id [0-9]+ via ${ip} " | grep -E ' fdb' \
        | awk '{print $2}' | head -1 || true
}

nh_line() {
    local id=${1:?}
    nh_dump | grep -E "^id ${id} " | head -1 || true
}

group_members_of() {
    local gid=${1:?}
    nh_line "$gid" | grep -oE 'group [0-9/]+' | awk '{print $2}' | tr '/' ' ' || true
}

router_mac_fdb_row() {
    fdb_dump | grep -i "$TYPE5_ROUTER_MAC" | head -1 || true
}

router_mac_group_id() {
    router_mac_fdb_row | grep -oE ' nhid [0-9]+' | awk '{print $2}' | head -1 || true
}

no_duplicate_single_dst_router_mac_rows() {
    ! fdb_dump | grep -i "$TYPE5_ROUTER_MAC" | grep -qE '[[:space:]]dst[[:space:]][^[:space:]]+'
}

l3_nhg_absent() {
    local group_id=${1:?}
    local member1=${2:?}
    local member2=${3:?}
    ! nh_dump | grep -qE "^id ${group_id} " \
        && ! nh_dump | grep -qE "^id ${member1} " \
        && ! nh_dump | grep -qE "^id ${member2} "
}

router_mac_fdb_absent() {
    [ -z "$(router_mac_fdb_row)" ]
}

l3_neighbors_absent() {
    ! l3_neigh_dump | grep -qE "^(${PE1_IP}|${PE2_IP}) "
}

assert_l3_resolution_state() {
    local group_id member1 member2 members line1 line2 gline row

    if ! vrf_route_installed_ecmp; then
        return 1
    fi

    if ! l3_neigh_dump | grep -qE "^${PE1_IP} .*lladdr ${TYPE5_ROUTER_MAC} "; then
        return 1
    fi
    if ! l3_neigh_dump | grep -qE "^${PE2_IP} .*lladdr ${TYPE5_ROUTER_MAC} "; then
        return 1
    fi

    row=$(router_mac_fdb_row)
    [ -n "$row" ] || return 1
    echo "$row" | grep -qE ' self( |$)' || return 1
    echo "$row" | grep -qE ' nhid [0-9]+' || return 1
    no_duplicate_single_dst_router_mac_rows || return 1

    group_id=$(echo "$row" | grep -oE ' nhid [0-9]+' | awk '{print $2}' | head -1)
    [ -n "$group_id" ] || return 1
    gline=$(nh_line "$group_id")
    [ -n "$gline" ] || return 1
    echo "$gline" | grep -qE ' fdb( |$)' || return 1
    echo "$gline" | grep -q " group " || return 1

    member1=$(nh_id_for_via "$PE1_IP")
    member2=$(nh_id_for_via "$PE2_IP")
    [ -n "$member1" ] && [ -n "$member2" ] || return 1
    [ "$member1" != "$member2" ] || return 1

    line1=$(nh_line "$member1")
    line2=$(nh_line "$member2")
    echo "$line1" | grep -qE ' fdb( |$)' || return 1
    echo "$line2" | grep -qE ' fdb( |$)' || return 1

    members=$(group_members_of "$group_id")
    echo "$members" | tr ' ' '\n' | grep -qx "$member1" || return 1
    echo "$members" | tr ' ' '\n' | grep -qx "$member2" || return 1
}

record_l3_ids() {
    CAPTURED_GROUP_ID=$(router_mac_group_id)
    CAPTURED_MEMBER1_ID=$(nh_id_for_via "$PE1_IP")
    CAPTURED_MEMBER2_ID=$(nh_id_for_via "$PE2_IP")
    [ -n "${CAPTURED_GROUP_ID:-}" ] && [ -n "${CAPTURED_MEMBER1_ID:-}" ] && [ -n "${CAPTURED_MEMBER2_ID:-}" ]
}

pe1_add_type5() {
    pe1_rib add -a evpn prefix "$TARGET_PREFIX" "${ESI_GOBGP[@]}" etag 0 label "$L3VNI" \
        rd "$RD_L3" rt "$RT_L3" encap vxlan router-mac "$TYPE5_ROUTER_MAC" \
        nexthop "$PE1_IP"
}

pe1_del_type5() {
    pe1_rib del -a evpn prefix "$TARGET_PREFIX" "${ESI_GOBGP[@]}" etag 0 label "$L3VNI" \
        rd "$RD_L3" 2>/dev/null || true
}

add_ead_per_es_all_active() {
    local pe=${1:?}
    local rd=${2:?}
    local ip=${3:?}
    "$pe" add -a evpn a-d "${ESI_GOBGP[@]}" etag 4294967295 label 0 \
        rd "$rd" rt "$RT_L2" encap vxlan esi-label 0 \
        nexthop "$ip"
}

del_ead_per_es() {
    local pe=${1:?}
    local rd=${2:?}
    "$pe" del -a evpn a-d "${ESI_GOBGP[@]}" etag 4294967295 label 0 \
        rd "$rd" 2>/dev/null || true
}

add_ead_per_evi() {
    local pe=${1:?}
    local rd=${2:?}
    local ip=${3:?}
    "$pe" add -a evpn a-d "${ESI_GOBGP[@]}" etag 0 label "$L2VNI" \
        rd "$rd" rt "$RT_L2" encap vxlan nexthop "$ip"
}

del_ead_per_evi() {
    local pe=${1:?}
    local rd=${2:?}
    "$pe" del -a evpn a-d "${ESI_GOBGP[@]}" etag 0 label "$L2VNI" \
        rd "$rd" 2>/dev/null || true
}

pe1_add_all_active_eads() {
    add_ead_per_es_all_active pe1_rib "$RD_L2_PE1" "$PE1_IP" &&
    add_ead_per_evi pe1_rib "$RD_L2_PE1" "$PE1_IP"
}

pe2_add_all_active_eads() {
    add_ead_per_es_all_active pe2_rib "$RD_L2_PE2" "$PE2_IP" &&
    add_ead_per_evi pe2_rib "$RD_L2_PE2" "$PE2_IP"
}

pe1_del_all_active_eads() {
    del_ead_per_es pe1_rib "$RD_L2_PE1" &&
    del_ead_per_evi pe1_rib "$RD_L2_PE1"
}

pe2_del_all_active_eads() {
    del_ead_per_es pe2_rib "$RD_L2_PE2" &&
    del_ead_per_evi pe2_rib "$RD_L2_PE2"
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

log "vtep (DUT): $VTEP — pe1/pe2 (GoBGP route sources): $PE1 / $PE2"

log "Provisioning VTEP kernel topology (vrf1 + L3VNI $L3VNI + linked L2VNI $L2VNI)"
docker exec "$VTEP" /usr/local/bin/start-rustbgpd-m72-vtep.sh \
    "$VTEP_IP" "$L3VNI" "$TENANT_VRF" "$VTEP_ROUTER_MAC" "$L2VNI" >/dev/null

resolve_grpc_addr
start_rustbgpd

wait_gobgp_established "$PE1" "$VTEP_IP" "GoBGP-PE1 ↔ rustbgpd-VTEP L2VPN/EVPN" || print_summary
wait_gobgp_established "$PE2" "10.0.2.1" "GoBGP-PE2 ↔ rustbgpd-VTEP L2VPN/EVPN" || print_summary

log "Clearing any stale M72 routes from the GoBGP RIBs"
pe1_del_type5
pe1_del_all_active_eads
pe2_del_all_active_eads

# ---------------------------------------------------------------------------
# Phase 1 — fail-closed: ESI overlay Type 5 with no resolving EAD state
# ---------------------------------------------------------------------------

log "[phase 1] PE1 injects ONLY the ESI overlay-index Type 5 (no EAD)"
if pe1_add_type5; then
    ok "PE1 originated the ESI overlay-index Type 5 for $TARGET_PREFIX"
else
    fail "PE1 Type 5 injection failed"
fi

log "[phase 1] rustbgpd must hold it unresolved (no EAD-per-ES/EVI)"
if wait_until 40 drop_gauge_at_least_1 "unresolved_esi_overlay_index"; then
    ok "drop gauge unresolved_esi_overlay_index >= 1 (= $(drop_gauge unresolved_esi_overlay_index))"
else
    fail "drop gauge unresolved_esi_overlay_index never reached >= 1"
    prom_scrape "$VTEP" | grep '^evpn_ip_vrf_remote_prefix_drops' >&2 || true
    docker exec "$VTEP" tail -80 /var/log/rustbgpd.log >&2 2>/dev/null || true
fi

if vrf_route_absent && vrf_installed_count_is 0; then
    ok "no vrf1 kernel route / installed_routes_count=0 before EAD state"
else
    fail "vrf1 route present before the ESI was resolvable"
    docker exec "$VTEP" ip route show table "$TABLE_ID" >&2 || true
fi

# ---------------------------------------------------------------------------
# Phase 2 — all-active resolves: two PEs supply EAD-per-ES/EVI
# ---------------------------------------------------------------------------

log "[phase 2] PE1 and PE2 add all-active EAD-per-ES + EAD-per-EVI"
if pe1_add_all_active_eads; then
    ok "PE1 all-active EAD state injected"
else
    fail "PE1 all-active EAD injection failed"
fi
if pe2_add_all_active_eads; then
    ok "PE2 all-active EAD state injected"
else
    fail "PE2 all-active EAD injection failed"
fi

log "[phase 2] rustbgpd resolves all-active target set and installs ECMP route + FDB-NHG"
if wait_until 90 assert_l3_resolution_state; then
    ok "all-active L3 resolution installed"
    printf "%s\n" "$(route_dump)"
    ok "Router-MAC FDB row: $(router_mac_fdb_row)"
    ok "ip nexthop group/member state captured"
else
    fail "rustbgpd did not install the expected all-active L3 resolution"
    docker exec "$VTEP" ip route show table "$TABLE_ID" >&2 || true
    l3_neigh_dump >&2
    fdb_dump >&2
    nh_dump >&2
    prom_scrape "$VTEP" | grep '^evpn_ip_vrf_remote_prefix_drops' >&2 || true
    docker exec "$VTEP" tail -100 /var/log/rustbgpd.log >&2 2>/dev/null || true
fi

if wait_until 30 vrf_installed_count_is 1; then
    ok "rustbgpd reports installed_routes_count=1 for vrf1"
else
    fail "rustbgpd kernel route exists but installed_routes_count != 1"
fi

if wait_until 30 drop_gauge_is_zero "unresolved_esi_overlay_index"; then
    ok "drop gauge unresolved_esi_overlay_index back to 0 after resolution"
else
    fail "drop gauge unresolved_esi_overlay_index still nonzero after import (= $(drop_gauge unresolved_esi_overlay_index))"
fi

if drop_gauge_is_zero "unsupported_all_active_esi_overlay_index"; then
    ok "drop gauge unsupported_all_active_esi_overlay_index stayed 0 for valid all-active"
else
    fail "valid all-active target set still reported unsupported_all_active_esi_overlay_index (= $(drop_gauge unsupported_all_active_esi_overlay_index))"
fi

if record_l3_ids; then
    ok "captured L3 NHG ids: group=$CAPTURED_GROUP_ID pe1=$CAPTURED_MEMBER1_ID pe2=$CAPTURED_MEMBER2_ID"
else
    fail "could not capture L3 NHG ids"
fi

# ---------------------------------------------------------------------------
# Phase 3 — member change: remove PE2, then restore it
# ---------------------------------------------------------------------------

log "[phase 3] PE2 withdraws its all-active EAD state (target set collapses below minimum)"
pe2_del_all_active_eads
ok "PE2 all-active EAD state withdrawn"

if wait_until 60 vrf_route_absent && wait_until 30 router_mac_fdb_absent && wait_until 30 vrf_installed_count_is 0; then
    ok "all-active route and Router-MAC FDB row withdrawn after one-member collapse"
else
    fail "all-active route/FDB state survived a one-member collapse"
    docker exec "$VTEP" ip route show table "$TABLE_ID" >&2 || true
    fdb_dump >&2
    nh_dump >&2
fi

log "[phase 3] PE2 re-adds its all-active EAD state"
if pe2_add_all_active_eads; then
    ok "PE2 all-active EAD state re-injected"
else
    fail "PE2 all-active EAD reinjection failed"
fi

if wait_until 90 assert_l3_resolution_state && wait_until 30 vrf_installed_count_is 1; then
    ok "two-way all-active ECMP route returned after PE2 re-add"
else
    fail "all-active ECMP route did not return after PE2 re-add"
    docker exec "$VTEP" ip route show table "$TABLE_ID" >&2 || true
    fdb_dump >&2
    nh_dump >&2
fi

record_l3_ids || fail "could not recapture L3 NHG ids after re-add"

# ---------------------------------------------------------------------------
# Phase 4 — withdraw: delete the Type 5 and assert cleanup
# ---------------------------------------------------------------------------

log "[phase 4] PE1 withdraws the ESI overlay-index Type 5"
pe1_del_type5
ok "PE1 withdrew the Type 5 for $TARGET_PREFIX"

if wait_until 60 vrf_route_absent && wait_until 30 vrf_installed_count_is 0; then
    ok "vrf1 route withdrawn / installed_routes_count=0 after Type 5 withdraw"
else
    fail "vrf1 route survived Type 5 withdraw"
    docker exec "$VTEP" ip route show table "$TABLE_ID" >&2 || true
fi

if wait_until 60 router_mac_fdb_absent; then
    ok "Router-MAC FDB nhid row removed after Type 5 withdraw"
else
    fail "Router-MAC FDB row survived Type 5 withdraw"
    fdb_dump >&2
fi

if wait_until 60 l3_nhg_absent "$CAPTURED_GROUP_ID" "$CAPTURED_MEMBER1_ID" "$CAPTURED_MEMBER2_ID"; then
    ok "captured L3 NHG/member nexthops removed after Type 5 withdraw"
else
    fail "captured L3 NHG/member nexthops survived Type 5 withdraw"
    nh_dump >&2
fi

if wait_until 60 l3_neighbors_absent; then
    ok "per-VTEP L3 neighbors removed after Type 5 withdraw"
else
    fail "per-VTEP L3 neighbors survived Type 5 withdraw"
    l3_neigh_dump >&2
fi

log "[phase 4] PEs clean residual EAD state for rerun safety"
pe1_del_all_active_eads
pe2_del_all_active_eads
ok "PE EAD state cleaned up"

print_summary
