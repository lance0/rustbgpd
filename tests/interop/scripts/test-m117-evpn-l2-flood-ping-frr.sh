#!/usr/bin/env bash
# M117 — L2 ARP ping across VXLAN between a rustbgpd VTEP and an FRR
# 10.7.1 VTEP, with no static flood rows and no static neighbours.
#
# Asserts:
#   1. Premise: no zero-MAC row without extern_learn on rustbgpd's
#      vxlan117, and no permanent neighbour entries on either host.
#   2. The L2VPN/EVPN session is Established and FRR's Type 3 IMET
#      reaches rustbgpd, which programs exactly one zero-MAC row
#      `dst 10.0.117.2 self extern_learn` on vxlan117.
#   3. FRR builds its flood row toward rustbgpd from rustbgpd's IMET.
#   4. With both ARP caches empty, h1 pings h2. h1's entry for h2 is
#      ARP-learned (not permanent): the broadcast ARP request crossed
#      the VXLAN tunnel through the daemon's flood row.
#   5. When FRR withdraws its IMET (`no advertise-all-vni`), rustbgpd
#      removes the row; when FRR re-advertises, the row returns.
#
# Usage:
#   docker build --target dev -t rustbgpd:dev .
#   containerlab deploy -t tests/interop/m117-evpn-l2-flood-ping-frr.clab.yml
#   bash tests/interop/scripts/test-m117-evpn-l2-flood-ping-frr.sh
#   containerlab destroy -t tests/interop/m117-evpn-l2-flood-ping-frr.clab.yml --cleanup

set -euo pipefail

TOPO="m117-evpn-l2-flood-ping-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

RUSTBGPD="clab-${TOPO}-rustbgpd"
FRR="clab-${TOPO}-frr"
H1="clab-${TOPO}-h1"
H2="clab-${TOPO}-h2"
RUSTBGPD_VTEP="10.0.117.1"
FRR_VTEP="10.0.117.2"
H2_IP="192.168.117.20"
H2_MAC="02:11:17:00:00:02"
VXLAN="vxlan117"
ZERO_MAC="00:00:00:00:00:00"

preflight

flood_rows() {
    docker exec "${1:?}" bridge fdb show dev "$VXLAN" 2>/dev/null | grep "^$ZERO_MAC" || true
}

rb_has_owned_flood_row() {
    flood_rows "$RUSTBGPD" | grep "dst $FRR_VTEP " | grep -q extern_learn
}

rb_has_no_flood_row() {
    [ -z "$(flood_rows "$RUSTBGPD")" ]
}

frr_has_flood_row() {
    flood_rows "$FRR" | grep -q "dst $RUSTBGPD_VTEP "
}

frr_evpn() {
    docker exec "$FRR" vtysh -c "conf t" -c "router bgp 65000" \
        -c "address-family l2vpn evpn" -c "$1" >/dev/null
}

ping_h2() {
    docker exec "$H1" ping -c 3 -W 2 -q "$H2_IP" >/dev/null 2>&1
}

dump_state() {
    log "rustbgpd $VXLAN FDB:"
    docker exec "$RUSTBGPD" bridge fdb show dev "$VXLAN" >&2 || true
    log "FRR $VXLAN FDB:"
    docker exec "$FRR" bridge fdb show dev "$VXLAN" >&2 || true
    log "FRR EVPN routes:"
    docker exec "$FRR" vtysh -c "show bgp l2vpn evpn route" >&2 || true
    log "rustbgpd log tail:"
    docker exec "$RUSTBGPD" tail -40 /var/log/rustbgpd.log >&2 || true
}

# 1. Premise.
static_rows=$(flood_rows "$RUSTBGPD" | grep -v extern_learn || true)
if [ -z "$static_rows" ]; then
    ok "no static zero-MAC flood row on rustbgpd $VXLAN"
else
    fail "static zero-MAC flood rows present: $static_rows"
fi
for host in "$H1" "$H2"; do
    docker exec "$host" ip neigh flush all
    if docker exec "$host" ip neigh show nud permanent | grep -q .; then
        fail "$host has permanent neighbour entries"
    else
        ok "$host has no static neighbours"
    fi
done

# 2. Session and the daemon's flood row from FRR's IMET.
wait_frr_established "$FRR" "$RUSTBGPD_VTEP" "L2VPN/EVPN" || { dump_state; print_summary; }
if wait_until 30 1 rb_has_owned_flood_row; then
    ok "rustbgpd programmed zero-MAC dst $FRR_VTEP extern_learn from FRR's IMET"
else
    fail "rustbgpd never programmed a flood row toward $FRR_VTEP"
    dump_state
fi
rows=$(flood_rows "$RUSTBGPD" | wc -l)
if [ "$rows" -eq 1 ]; then
    ok "exactly one flood row (no row toward rustbgpd's own VTEP)"
else
    fail "expected one flood row, found $rows"
fi

# 3. FRR's flood row toward rustbgpd, from rustbgpd's IMET.
if wait_until 30 1 frr_has_flood_row; then
    ok "FRR flood row toward $RUSTBGPD_VTEP present"
else
    fail "FRR has no flood row toward $RUSTBGPD_VTEP"
fi

# 4. ARP-driven ping.
if wait_until 10 1 ping_h2; then
    ok "h1 pinged h2 across VXLAN"
else
    fail "h1 cannot ping h2"
    dump_state
fi
neigh=$(docker exec "$H1" ip neigh show "$H2_IP" dev eth1 || true)
if grep -qi "lladdr $H2_MAC" <<<"$neigh" && ! grep -q PERMANENT <<<"$neigh"; then
    ok "h1 learned h2 by ARP: $neigh"
else
    fail "h1 neighbour entry for h2 is not ARP-learned: '$neigh'"
fi

# 5. Withdraw and re-advertise FRR's IMET.
frr_evpn "no advertise-all-vni"
if wait_until 30 1 rb_has_no_flood_row; then
    ok "rustbgpd removed the flood row after FRR withdrew its IMET"
else
    fail "flood row survived FRR's IMET withdrawal"
    dump_state
fi
frr_evpn "advertise-all-vni"
if wait_until 30 1 rb_has_owned_flood_row; then
    ok "flood row returned when FRR re-advertised its IMET"
else
    fail "flood row did not return after FRR re-advertised"
    dump_state
fi
docker exec "$H1" ip neigh flush all
if wait_until 10 1 ping_h2; then
    ok "h1 pinged h2 again after re-advertisement"
else
    fail "h1 cannot ping h2 after re-advertisement"
fi

print_summary
