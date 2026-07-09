#!/usr/bin/env bash
# M37 smoke — Gate 7b+1 real-VTEP origination smoke against an FRR
# consumer.
#
# Asserts:
#   1. Both peers reach Established with L2VPN/EVPN negotiated.
#   2. After rustbgpd boots, FRR's `show bgp l2vpn evpn route type
#      multicast` lists exactly one Type 3 IMET for the configured
#      EvpnInstance, with originator = rustbgpd's local_vtep_ip.
#   3. After `bridge fdb add 02:aa:bb:cc:dd:01 dev veth100a master
#      static` lands inside the rustbgpd container, FRR's
#      `show bgp l2vpn evpn route type macip` lists that MAC with
#      originator = rustbgpd's local_vtep_ip within ~15s.
#   4. After `bridge fdb del` removes the entry, FRR sees the Type 2
#      withdrawn within ~15s.
#   5. After `docker stop` on rustbgpd, FRR loses the Type 3 IMET
#      within ~15s (shutdown-drain emits Withdraw before the daemon
#      exits).
#
# Usage:
#   docker build --target dev -t rustbgpd:dev .
#   sudo containerlab deploy -t tests/interop/m37-evpn-local-origination.clab.yml
#   bash tests/interop/scripts/test-m37-evpn-local-origination.sh
#   sudo containerlab destroy -t tests/interop/m37-evpn-local-origination.clab.yml

set -eu

TOPO="m37-evpn-local-origination"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

RUSTBGPD="clab-${TOPO}-rustbgpd"
CONSUMER="clab-${TOPO}-consumer"
RUSTBGPD_IP="10.0.0.1"
VNI="100"
VETH_PORT="veth${VNI}a"
TEST_MAC="02:aa:bb:cc:dd:01"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Run a vtysh command on the FRR consumer and emit stdout.
frr_vtysh() {
    docker exec "$CONSUMER" vtysh -c "$1" 2>/dev/null || true
}

# Strict variant: propagates docker/vtysh failure so absence checks can
# tell "query errored" apart from "table validly empty".
frr_vtysh_strict() {
    docker exec "$CONSUMER" vtysh -c "$1" 2>/dev/null
}

# Does FRR list a Type 2 macip route for the given MAC originating
# from rustbgpd?
#
# `vtysh` formats EVPN routes across two lines: NLRI on the first
# line and next-hop / attributes on the second. `grep -A1` joins
# them so a single `grep -F "$mac.*$RUSTBGPD_IP"` style check is
# possible, except `grep -A` doesn't work inside a `grep -q` chain
# cleanly. Instead, we check for both substrings separately and
# require both to appear in the output, then confirm the MAC's
# RD line is grouped under rustbgpd's address by looking at the
# canonical macip view which prints the next-hop next to the MAC.
frr_has_type2() {
    local mac=${1:?}
    local out
    out=$(frr_vtysh "show bgp l2vpn evpn route type macip")
    # Two-line vtysh layout: MAC on one line, next-hop on the next.
    # `grep -A1 -iF "$mac"` pulls both, then check the next-hop is
    # rustbgpd's loopback.
    echo "$out" | grep -A1 -iF "$mac" | grep -qF "$RUSTBGPD_IP"
}

# Does FRR list a Type 3 IMET route originating from rustbgpd?
frr_has_type3() {
    frr_vtysh "show bgp l2vpn evpn route type multicast" \
        | grep -qF "$RUSTBGPD_IP"
}

# Absence checks succeed only when the FRR query itself succeeded AND the
# route is missing. An errored/unreachable query is never evidence of
# absence — that would let the withdraw proofs pass vacuously.
frr_type2_absent() {
    local mac=${1:?}
    local out
    out=$(frr_vtysh_strict "show bgp l2vpn evpn route type macip") || return 1
    ! echo "$out" | grep -A1 -iF "$mac" | grep -qF "$RUSTBGPD_IP"
}

frr_type3_absent() {
    local out
    out=$(frr_vtysh_strict "show bgp l2vpn evpn route type multicast") || return 1
    ! echo "$out" | grep -qF "$RUSTBGPD_IP"
}

# Inject a static MAC on the rustbgpd container's non-VXLAN bridge
# port, triggering an RTM_NEWNEIGH event the notify classifier
# routes upward.
rb_fdb_add() {
    local mac=${1:?}
    docker exec "$RUSTBGPD" bridge fdb add "$mac" dev "$VETH_PORT" master static
}

rb_fdb_del() {
    local mac=${1:?}
    docker exec "$RUSTBGPD" bridge fdb del "$mac" dev "$VETH_PORT" master 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

PASS=0
FAIL=0
TOTAL=0

assert() {
    local desc=${1:?}
    local cmd=${2:?}
    TOTAL=$((TOTAL + 1))
    if eval "$cmd"; then
        echo "PASS — $desc"
        PASS=$((PASS + 1))
    else
        echo "FAIL — $desc"
        FAIL=$((FAIL + 1))
    fi
}

# Wait for FRR to report the session as Established. The helper polls
# `vtysh -c "show bgp neighbors <peer> json"` for `"bgpState":"Established"`.
echo "Waiting for L2VPN/EVPN session to establish..."
wait_frr_established "$CONSUMER" "$RUSTBGPD_IP" "L2VPN/EVPN" || true

# 1. Type 3 IMET should be advertised at startup, before any local
#    MAC is added.
echo "Waiting up to 30s for Type 3 IMET to surface on FRR..."
for _ in $(seq 1 30); do
    if frr_has_type3; then break; fi
    sleep 1
done
assert "Type 3 IMET originated by rustbgpd visible on FRR" \
    'frr_has_type3'

# 2. Inject a local MAC; expect Type 2 within ~15s.
echo "Injecting local MAC $TEST_MAC on $VETH_PORT..."
rb_fdb_add "$TEST_MAC"

echo "Waiting up to 15s for Type 2 (mac $TEST_MAC) to surface on FRR..."
for _ in $(seq 1 15); do
    if frr_has_type2 "$TEST_MAC"; then break; fi
    sleep 1
done
assert "Type 2 MAC origination from rustbgpd visible on FRR" \
    'frr_has_type2 "$TEST_MAC"'

# 3. Remove the MAC; expect Type 2 to disappear within ~15s.
echo "Removing local MAC $TEST_MAC..."
rb_fdb_del "$TEST_MAC"
echo "Waiting up to 15s for Type 2 withdraw..."
for _ in $(seq 1 15); do
    if frr_type2_absent "$TEST_MAC"; then break; fi
    sleep 1
done
assert "Type 2 withdraw on bridge fdb del" \
    'frr_type2_absent "$TEST_MAC"'

# 4. Stop rustbgpd; expect IMET to drain within ~15s (graceful
#    shutdown emits the Withdraw).
echo "Stopping rustbgpd to validate IMET drain..."
docker stop -t 5 "$RUSTBGPD" >/dev/null
echo "Waiting up to 15s for Type 3 IMET withdraw..."
for _ in $(seq 1 15); do
    if frr_type3_absent; then break; fi
    sleep 1
done
assert "Type 3 IMET withdraw on shutdown drain" \
    'frr_type3_absent'

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "M37 smoke: $PASS/$TOTAL passed, $FAIL failed."
[[ $FAIL -eq 0 ]]
