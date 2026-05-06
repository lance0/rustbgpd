#!/usr/bin/env bash
# M36 smoke — Gate 7b real-VTEP smoke against a Linux kernel.
#
# Validates that rustbgpd, configured as an EVPN VTEP with a
# pre-existing bridge + VXLAN port in its container netns,
# receives Type 2 routes from an FRR peer and programs them into
# the kernel bridge FDB through the rtnetlink dataplane. Asserts:
#
# 1. Both peers reach Established with L2VPN/EVPN negotiated.
# 2. After FRR injects MAC 02:aa:bb:cc:dd:01 on its dummy100
#    bridge port (which makes zebra originate a Type 2), rustbgpd's
#    `bridge fdb show dev vxlan100` shows that MAC with
#    `extern_learn` and `dst 10.0.0.2` (FRR's loopback).
# 3. After FRR removes the MAC, rustbgpd's bridge FDB drops it.
# 4. The foreign-static entry 02:99:99:99:99:99 (pre-loaded by
#    start-rustbgpd-vtep.sh) survives both the program and
#    withdraw cycles — proves ADR-0054 §5/§7 foreign-entry
#    preservation against a real kernel, not just the fake.
#
# Usage:
#   docker build -t rustbgpd:dev .
#   sudo containerlab deploy -t tests/interop/m36-evpn-vtep-smoke.clab.yml
#   bash tests/interop/scripts/test-m36-evpn-vtep-smoke.sh
#   sudo containerlab destroy -t tests/interop/m36-evpn-vtep-smoke.clab.yml

set -eu

TOPO="m36-evpn-vtep-smoke"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

RUSTBGPD="clab-${TOPO}-rustbgpd"
ORIGINATOR="clab-${TOPO}-originator"
ORIGINATOR_IP="10.0.0.2"
VNI="100"
BRIDGE="br${VNI}"
VXLAN="vxlan${VNI}"
TEST_MAC="02:aa:bb:cc:dd:01"
FOREIGN_MAC="02:99:99:99:99:99"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Dump rustbgpd's bridge FDB inside its container netns.
rb_fdb() {
    docker exec "$RUSTBGPD" bridge fdb show dev "$VXLAN" 2>/dev/null || true
}

rb_fdb_has_mac() {
    local mac=${1:?}
    rb_fdb | grep -qiF "$mac"
}

rb_fdb_has_extern_learn() {
    local mac=${1:?}
    rb_fdb | grep -iF "$mac" | grep -qE 'extern_learn|offload'
}

rb_fdb_dst_for_mac() {
    local mac=${1:?}
    rb_fdb | awk -v m="$mac" 'tolower($1) == tolower(m) { for (i=1; i<NF; i++) if ($i == "dst") print $(i+1) }' | head -1
}

# Both rows are required for a correct EVPN VTEP entry:
#   - bridge-master row: shows `master <bridge>` (no dst). Without
#     this row the bridge floods unicast frames instead of sending
#     them through the VXLAN tunnel.
#   - VXLAN-self+dst row: shows `self` and `dst <remote>`. Without
#     this row the VXLAN driver doesn't know where to encap.
rb_fdb_has_bridge_master_row() {
    local mac=${1:?}
    rb_fdb | grep -iF "$mac" | grep -q 'master '
}

rb_fdb_has_vxlan_self_dst_row() {
    local mac=${1:?}
    local want_dst=${2:?}
    rb_fdb | grep -iF "$mac" | grep "dst $want_dst" | grep -q 'self'
}

# Inject / withdraw a static MAC on the FRR side. Zebra
# auto-detects the bridge FDB change and originates / withdraws a
# Type 2 route.
frr_inject_mac() {
    local mac=${1:?}
    docker exec "$ORIGINATOR" bridge fdb add "$mac" \
        dev "dummy${VNI}" master static 2>/dev/null || true
}

frr_withdraw_mac() {
    local mac=${1:?}
    docker exec "$ORIGINATOR" bridge fdb del "$mac" \
        dev "dummy${VNI}" master 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Drive the smoke
# ---------------------------------------------------------------------------

resolve_grpc_addr
log "rustbgpd container: $RUSTBGPD"
log "originator container: $ORIGINATOR"

# Verify the rustbgpd VTEP setup landed: bridge + VXLAN exist with
# the right attributes, foreign static entry pre-loaded.
log "Verifying VTEP topology inside rustbgpd container..."
docker exec "$RUSTBGPD" ip -d link show "$BRIDGE" >/dev/null \
    || { fail "bridge $BRIDGE missing in rustbgpd netns"; exit 1; }
docker exec "$RUSTBGPD" ip -d link show "$VXLAN" >/dev/null \
    || { fail "VXLAN port $VXLAN missing"; exit 1; }
if rb_fdb_has_mac "$FOREIGN_MAC"; then
    ok "foreign static FDB entry $FOREIGN_MAC pre-loaded"
else
    fail "foreign static FDB entry $FOREIGN_MAC was not pre-loaded"
fi

# Wait for the BGP session to come up. resolve_grpc_addr is the
# rustbgpd-side gRPC; FRR side comes up automatically via daemon
# autostart in the container image.
log "Waiting for L2VPN/EVPN session to reach Established..."
for i in $(seq 1 60); do
    state=$(docker exec "$ORIGINATOR" vtysh -c \
        "show bgp neighbor 10.0.0.1 json" 2>/dev/null \
        | grep -oE '"bgpState":"[^"]+"' | head -1)
    if echo "$state" | grep -q '"bgpState":"Established"'; then
        ok "session Established after ${i}s"
        break
    fi
    if [ "$i" -eq 60 ]; then
        fail "session never reached Established within 60s"
        docker exec "$ORIGINATOR" vtysh -c "show bgp neighbor 10.0.0.1" >&2 || true
        docker exec "$RUSTBGPD" tail -50 /var/log/rustbgpd.log >&2 || true
        exit 1
    fi
    sleep 1
done

# ---------------------------------------------------------------------------
# Inject MAC on FRR, observe FDB on rustbgpd
# ---------------------------------------------------------------------------

log "Injecting $TEST_MAC on originator..."
frr_inject_mac "$TEST_MAC"

log "Polling rustbgpd's bridge FDB for the programmed entry..."
got_program=0
for i in $(seq 1 30); do
    if rb_fdb_has_mac "$TEST_MAC" && rb_fdb_has_extern_learn "$TEST_MAC"; then
        got_program=1
        break
    fi
    sleep 1
done

if [ "$got_program" -eq 1 ]; then
    dst=$(rb_fdb_dst_for_mac "$TEST_MAC")
    if [ "$dst" = "$ORIGINATOR_IP" ]; then
        ok "rustbgpd programmed $TEST_MAC dst=$dst with extern_learn"
    else
        fail "MAC $TEST_MAC programmed but dst is '$dst' (want $ORIGINATOR_IP)"
        rb_fdb >&2
    fi

    # Both rows must be present — the bridge-master row plumbs
    # bridge forwarding via vxlan100, the VXLAN-self+dst row gives
    # the driver the encap target. A passing extern_learn+dst check
    # alone wouldn't catch a missing bridge-master row, which would
    # leave forwarding wrong (flood instead of unicast).
    if rb_fdb_has_bridge_master_row "$TEST_MAC"; then
        ok "bridge-master row present for $TEST_MAC"
    else
        fail "bridge-master row missing for $TEST_MAC (data plane would flood)"
        rb_fdb >&2
    fi
    if rb_fdb_has_vxlan_self_dst_row "$TEST_MAC" "$ORIGINATOR_IP"; then
        ok "VXLAN-self+dst row present for $TEST_MAC -> $ORIGINATOR_IP"
    else
        fail "VXLAN-self+dst row missing for $TEST_MAC (no encap target)"
        rb_fdb >&2
    fi
else
    fail "rustbgpd never programmed $TEST_MAC into the kernel FDB"
    log "rustbgpd FDB:"
    rb_fdb >&2
    log "rustbgpd log tail:"
    docker exec "$RUSTBGPD" tail -80 /var/log/rustbgpd.log >&2 || true
    log "FRR EVPN routes:"
    docker exec "$ORIGINATOR" vtysh -c "show bgp l2vpn evpn route" >&2 || true
fi

# Foreign-entry preservation through the program cycle.
if rb_fdb_has_mac "$FOREIGN_MAC"; then
    ok "foreign static FDB entry survived program cycle"
else
    fail "foreign static FDB entry was deleted during program"
fi

# ---------------------------------------------------------------------------
# Withdraw on FRR, observe FDB drop on rustbgpd
# ---------------------------------------------------------------------------

log "Withdrawing $TEST_MAC on originator..."
frr_withdraw_mac "$TEST_MAC"

log "Polling rustbgpd's bridge FDB for the withdraw..."
got_withdraw=0
for i in $(seq 1 30); do
    if ! rb_fdb_has_mac "$TEST_MAC"; then
        got_withdraw=1
        break
    fi
    sleep 1
done

if [ "$got_withdraw" -eq 1 ]; then
    ok "rustbgpd withdrew $TEST_MAC from the kernel FDB"
else
    fail "rustbgpd did not withdraw $TEST_MAC within 30s"
    rb_fdb >&2
fi

# Foreign-entry preservation through the withdraw cycle.
if rb_fdb_has_mac "$FOREIGN_MAC"; then
    ok "foreign static FDB entry survived withdraw cycle"
else
    fail "foreign static FDB entry was deleted during withdraw"
fi

print_summary
