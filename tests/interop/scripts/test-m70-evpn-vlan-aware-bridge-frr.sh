#!/usr/bin/env bash
# M70 smoke — ADR-0089 VLAN-aware bridge receipt against FRR 10.3.1.
#
# rustbgpd owns the VLAN-aware side: one vlan_filtering=1 bridge
# (`brvlan`) with VLAN10/VNI100 and VLAN20/VNI200. FRR owns the
# traditional side: one bridge/VXLAN per VNI. FRR originates the same
# MAC independently in both VNIs, and rustbgpd must program VLAN-scoped
# FDB rows without cross-VLAN deletion.

set -euo pipefail

TOPO="m70-evpn-vlan-aware-bridge-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

RUSTBGPD="clab-${TOPO}-rustbgpd"
FRR="clab-${TOPO}-frr"
RUSTBGPD_IP="10.0.0.1"
FRR_IP="10.0.0.2"
BRIDGE="brvlan"
SHARED_MAC="02:aa:bb:cc:70:70"

frr_vtysh() {
    docker exec "$FRR" vtysh -c "$1" 2>/dev/null || true
}

wait_until() {
    local timeout=${1:?}
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

rb_fdb() {
    local vxlan=${1:?}
    docker exec "$RUSTBGPD" bridge fdb show dev "$vxlan" 2>/dev/null || true
}

rb_has_vlan_master_row() {
    local vxlan=${1:?} mac=${2:?} vlan=${3:?}
    rb_fdb "$vxlan" \
        | grep -iF "$mac" \
        | grep -E "vlan[[:space:]]+$vlan\\b" \
        | grep -E '(^|[[:space:]])master([[:space:]]|$)' \
        | grep -qE 'extern_learn|offload'
}

rb_has_vxlan_self_dst_row() {
    local vxlan=${1:?} mac=${2:?} dst=${3:?}
    rb_fdb "$vxlan" \
        | grep -iF "$mac" \
        | grep "dst $dst" \
        | grep 'self' \
        | grep -qE 'extern_learn|offload'
}

rb_has_vlan_remote_fdb() {
    local vxlan=${1:?} mac=${2:?} vlan=${3:?} dst=${4:?}
    rb_has_vlan_master_row "$vxlan" "$mac" "$vlan" \
        && rb_has_vxlan_self_dst_row "$vxlan" "$mac" "$dst"
}

frr_inject_mac() {
    local vni=${1:?} mac=${2:?}
    docker exec "$FRR" bridge fdb replace "$mac" dev "dummy${vni}" master static
}

frr_withdraw_mac() {
    local vni=${1:?} mac=${2:?}
    docker exec "$FRR" bridge fdb del "$mac" dev "dummy${vni}" master 2>/dev/null || true
}

frr_has_vni() {
    local vni=${1:?}
    frr_vtysh "show evpn vni" | grep -qE "\\b${vni}\\b"
}

frr_route_detail_has_rd_route_rt() {
    local rd=${1:?} route=${2:?} rt=${3:?}
    # M70 fixes the fixture at VNI100/VNI200 and exact RT/RD strings,
    # so substring matching inside one FRR route-detail block is sound.
    # Revisit if a future fixture adds ambiguous values such as
    # VNI1000/RT 65000:1000 next to VNI100/RT 65000:100.
    frr_vtysh "show bgp l2vpn evpn route detail" \
        | awk -v rd="Route Distinguisher: ${rd}" -v route="$route" -v rt="$rt" '
            /^Route Distinguisher:/ {
                if (block != "" && index(block, rd) && index(block, route) && index(block, rt)) {
                    found = 1
                }
                block = $0
                next
            }
            { block = block "\n" $0 }
            END {
                if (block != "" && index(block, rd) && index(block, route) && index(block, rt)) {
                    found = 1
                }
                exit(found ? 0 : 1)
            }'
}

frr_has_type3_vni() {
    local vni=${1:?}
    frr_route_detail_has_rd_route_rt \
        "10.0.0.2:${vni}" \
        "[3]:[0]:[32]:[$FRR_IP]" \
        "RT:65000:${vni}"
}

frr_has_local_mac_vni() {
    local vni=${1:?} mac=${2:?}
    frr_vtysh "show evpn mac vni $vni json" | grep -iqF "$mac"
}

frr_type2_has_mac_rt() {
    local mac=${1:?} rt_value=${2:?}
    frr_route_detail_has_rd_route_rt \
        "10.0.0.2:${rt_value}" \
        "[2]:[0]:[48]:[$mac]" \
        "RT:65000:${rt_value}"
}

dump_debug() {
    echo "--- FRR show evpn vni ---" >&2
    frr_vtysh "show evpn vni" >&2 || true
    echo "--- FRR Type 2 detail ---" >&2
    frr_vtysh "show bgp l2vpn evpn route detail" >&2 || true
    echo "--- rustbgpd vxlan100 FDB ---" >&2
    rb_fdb vxlan100 >&2 || true
    echo "--- rustbgpd vxlan200 FDB ---" >&2
    rb_fdb vxlan200 >&2 || true
    echo "--- rustbgpd log tail ---" >&2
    docker exec "$RUSTBGPD" tail -80 /var/log/rustbgpd.log >&2 || true
}

resolve_grpc_addr

log "Verifying rustbgpd ADR-0089 VLAN-aware topology..."
if docker exec "$RUSTBGPD" ip -d link show "$BRIDGE" | grep -q "vlan_filtering 1"; then
    ok "rustbgpd bridge $BRIDGE is VLAN-aware"
else
    fail "rustbgpd bridge $BRIDGE is missing vlan_filtering=1"
fi
for tuple in "100 10" "200 20"; do
    vni="${tuple% *}"
    vlan="${tuple#* }"
    if docker exec "$RUSTBGPD" ip -d link show "vxlan${vni}" >/dev/null; then
        ok "rustbgpd has vxlan${vni}"
    else
        fail "rustbgpd missing vxlan${vni}"
    fi
    if docker exec "$RUSTBGPD" bridge vlan show dev "vxlan${vni}" \
        | grep -qE "\\b${vlan}\\b"; then
        ok "vxlan${vni} carries bridge VLAN ${vlan}"
    else
        fail "vxlan${vni} missing bridge VLAN ${vlan}"
    fi
done

wait_frr_established "$FRR" "$RUSTBGPD_IP" "M70 FRR↔rustbgpd L2VPN/EVPN" \
    || fail "FRR did not establish to rustbgpd"

log "[baseline] FRR discovered and originated both traditional VNIs"
for vni in 100 200; do
    if wait_until 30 frr_has_vni "$vni"; then
        ok "FRR discovered VNI $vni"
    else
        fail "FRR did not discover VNI $vni"
        dump_debug
    fi
    if wait_until 60 frr_has_type3_vni "$vni"; then
        ok "FRR originated Type 3 IMET for VNI $vni"
    else
        fail "FRR did not originate Type 3 IMET for VNI $vni"
        dump_debug
    fi
done

log "[test] FRR originates the same MAC in VNI100 and VNI200"
frr_inject_mac 100 "$SHARED_MAC"
frr_inject_mac 200 "$SHARED_MAC"

if wait_until 60 frr_has_local_mac_vni 100 "$SHARED_MAC"; then
    ok "FRR local VNI100 MAC table contains $SHARED_MAC"
else
    fail "FRR did not learn $SHARED_MAC in VNI100"
    dump_debug
fi

if wait_until 60 frr_has_local_mac_vni 200 "$SHARED_MAC"; then
    ok "FRR local VNI200 MAC table contains $SHARED_MAC"
else
    fail "FRR did not learn $SHARED_MAC in VNI200"
    dump_debug
fi

if wait_until 60 frr_type2_has_mac_rt "$SHARED_MAC" 100; then
    ok "FRR advertised $SHARED_MAC with RT 65000:100"
else
    fail "FRR Type 2 for $SHARED_MAC missing RT 65000:100"
    dump_debug
fi

if wait_until 60 frr_type2_has_mac_rt "$SHARED_MAC" 200; then
    ok "FRR advertised $SHARED_MAC with RT 65000:200"
else
    fail "FRR Type 2 for $SHARED_MAC missing RT 65000:200"
    dump_debug
fi

log "[test] rustbgpd programs VLAN-scoped remote FDB rows"
if wait_until 90 rb_has_vlan_remote_fdb vxlan100 "$SHARED_MAC" 10 "$FRR_IP"; then
    ok "rustbgpd programmed $SHARED_MAC on vxlan100 vlan 10 dst $FRR_IP"
else
    fail "rustbgpd did not program $SHARED_MAC on vxlan100 vlan 10"
    dump_debug
fi

if wait_until 90 rb_has_vlan_remote_fdb vxlan200 "$SHARED_MAC" 20 "$FRR_IP"; then
    ok "rustbgpd programmed $SHARED_MAC on vxlan200 vlan 20 dst $FRR_IP"
else
    fail "rustbgpd did not program $SHARED_MAC on vxlan200 vlan 20"
    dump_debug
fi

log "[test] withdrawing VNI100 removes only VLAN10/VNI100 state"
frr_withdraw_mac 100 "$SHARED_MAC"

if wait_until 60 sh -c "! docker exec '$RUSTBGPD' bridge fdb show dev vxlan100 2>/dev/null | grep -qiF '$SHARED_MAC'"; then
    ok "rustbgpd removed $SHARED_MAC from vxlan100 after VNI100 withdraw"
else
    fail "rustbgpd kept $SHARED_MAC on vxlan100 after VNI100 withdraw"
    dump_debug
fi

if rb_has_vlan_remote_fdb vxlan200 "$SHARED_MAC" 20 "$FRR_IP"; then
    ok "VNI200/VLAN20 row survived the VNI100 withdraw"
else
    fail "VNI200/VLAN20 row was disturbed by the VNI100 withdraw"
    dump_debug
fi

log "[cleanup assertion] withdrawing VNI200 removes the remaining row"
frr_withdraw_mac 200 "$SHARED_MAC"
if wait_until 60 sh -c "! docker exec '$RUSTBGPD' bridge fdb show dev vxlan200 2>/dev/null | grep -qiF '$SHARED_MAC'"; then
    ok "rustbgpd removed $SHARED_MAC from vxlan200 after VNI200 withdraw"
else
    fail "rustbgpd kept $SHARED_MAC on vxlan200 after VNI200 withdraw"
    dump_debug
fi

print_summary
