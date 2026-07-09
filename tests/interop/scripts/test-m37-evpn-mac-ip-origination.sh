#!/usr/bin/env bash
# M37+IP smoke — Gate 7b+2 MAC+IP origination against an FRR consumer.
#
# Exercises the FRR-style replace model:
#
#   1. `bridge fdb add MAC dev veth100a master static` → rustbgpd
#      originates a MAC-only Type 2 (NLRI carries no IP).
#   2. `ip neigh add IP lladdr MAC dev br100 nud reachable` populates
#      the bridge's neighbour table → rustbgpd withdraws the
#      MAC-only and emits a MAC+IP Type 2 (NLRI carries the IP).
#   3. `ip neigh del IP dev br100` clears the binding → rustbgpd
#      withdraws the MAC+IP and re-emits the MAC-only.
#   4. `bridge fdb del MAC dev veth100a master` → rustbgpd
#      withdraws the MAC-only.
#
# The clab topology enables `neigh_suppress on` on the VXLAN port
# so the kernel routes the ARP/ND-snooped binding into the bridge's
# neighbour table, where AF_INET RTM_NEWNEIGH surfaces it to the
# daemon. Without that prerequisite the binding goes elsewhere and
# the daemon never sees an IpAdded.
#
# Usage:
#   docker build --target dev -t rustbgpd:dev .
#   sudo containerlab deploy -t tests/interop/m37-evpn-mac-ip-origination.clab.yml
#   bash tests/interop/scripts/test-m37-evpn-mac-ip-origination.sh
#   sudo containerlab destroy -t tests/interop/m37-evpn-mac-ip-origination.clab.yml

set -eu

TOPO="m37-evpn-mac-ip-origination"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

RUSTBGPD="clab-${TOPO}-rustbgpd"
CONSUMER="clab-${TOPO}-consumer"
RUSTBGPD_IP="10.0.0.1"
VNI="100"
BRIDGE="br${VNI}"
VETH_PORT="veth${VNI}a"
TEST_MAC="02:aa:bb:cc:dd:01"
TEST_IP="192.0.2.10"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

frr_vtysh() {
    docker exec "$CONSUMER" vtysh -c "$1" 2>/dev/null || true
}

# Strict variant: propagates docker/vtysh failure so absence checks can
# tell "query errored" apart from "table validly empty".
frr_vtysh_strict() {
    docker exec "$CONSUMER" vtysh -c "$1" 2>/dev/null
}

# Returns 0 if FRR sees a Type 2 for `$mac` with a "no IP" NLRI
# (MAC-only). FRR 10.3.1 prints macip routes as
# `[2]:[EthTag]:[MAClen]:[MAC]` for MAC-only and
# `[2]:[EthTag]:[MAClen]:[MAC]:[IPlen]:[IP]` for MAC+IP. Older
# diagnostic comments in this tree used an extra field before
# `[48]`; keep one optional field in the matcher so this smoke is
# tolerant of both renderings while still requiring the MAC-only
# line to end at the MAC.
frr_has_mac_only() {
    local mac=${1:?}
    frr_vtysh "show bgp l2vpn evpn route type macip" \
        | grep -qiE "\[2\]:\[[^]]*\]:(\[[^]]*\]:)?\[48\]:\[$mac\][[:space:]]*$"
}

# Returns 0 if FRR sees a MAC+IP Type 2 for `$mac` carrying `$ip`.
frr_has_mac_ip() {
    local mac=${1:?}
    local ip=${2:?}
    frr_vtysh "show bgp l2vpn evpn route type macip" \
        | grep -qiE "\[2\]:\[[^]]*\]:(\[[^]]*\]:)?\[48\]:\[$mac\]:\[(32|128)\]:\[$ip\]"
}

# Absence checks succeed only when the FRR query itself succeeded AND the
# route is missing. An errored/unreachable query is never evidence of
# absence — that would let the withdraw proofs pass vacuously.
frr_mac_only_absent() {
    local mac=${1:?}
    local out
    out=$(frr_vtysh_strict "show bgp l2vpn evpn route type macip") || return 1
    ! echo "$out" \
        | grep -qiE "\[2\]:\[[^]]*\]:(\[[^]]*\]:)?\[48\]:\[$mac\][[:space:]]*$"
}

frr_mac_ip_absent() {
    local mac=${1:?}
    local ip=${2:?}
    local out
    out=$(frr_vtysh_strict "show bgp l2vpn evpn route type macip") || return 1
    ! echo "$out" \
        | grep -qiE "\[2\]:\[[^]]*\]:(\[[^]]*\]:)?\[48\]:\[$mac\]:\[(32|128)\]:\[$ip\]"
}

# Returns 0 once FRR sees rustbgpd's startup Type 3 IMET, which is a
# cheap proxy that the EVPN instance and originator loop are Ready.
frr_has_type3() {
    frr_vtysh "show bgp l2vpn evpn route type multicast" \
        | grep -qF "[3]:[0]:[32]:[$RUSTBGPD_IP]"
}

rb_fdb_add() {
    docker exec "$RUSTBGPD" bridge fdb add "$1" dev "$VETH_PORT" master static
}
rb_fdb_del() {
    docker exec "$RUSTBGPD" bridge fdb del "$1" dev "$VETH_PORT" master 2>/dev/null || true
}
rb_neigh_add() {
    local ip=${1:?}
    local mac=${2:?}
    docker exec "$RUSTBGPD" ip neigh replace "$ip" lladdr "$mac" dev "$BRIDGE" nud reachable
}
rb_neigh_del() {
    local ip=${1:?}
    docker exec "$RUSTBGPD" ip neigh del "$ip" dev "$BRIDGE" 2>/dev/null || true
}

wait_until() {
    local desc=${1:?}
    local cmd=${2:?}
    local timeout=${3:-15}
    for _ in $(seq 1 "$timeout"); do
        if eval "$cmd"; then return 0; fi
        sleep 1
    done
    echo "TIMEOUT — $desc"
    return 1
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

echo "Waiting for L2VPN/EVPN session to establish..."
wait_frr_established "$CONSUMER" "$RUSTBGPD_IP" "L2VPN/EVPN" || true
wait_until "Type 3 IMET surfaces on FRR" \
    "frr_has_type3" 30 || true
assert "Type 3 IMET originated before MAC injection" \
    "frr_has_type3"

# 1. Add static FDB entry → MAC-only Type 2 surfaces.
echo "Adding static FDB entry $TEST_MAC..."
rb_fdb_add "$TEST_MAC"
wait_until "MAC-only Type 2 surfaces on FRR" \
    "frr_has_mac_only \"$TEST_MAC\"" 30 || true
assert "MAC-only Type 2 originated" \
    "frr_has_mac_only \"$TEST_MAC\""

# 2. Add ARP entry on bridge → MAC-only withdrawn, MAC+IP emitted.
echo "Adding bridge neighbour $TEST_IP → $TEST_MAC..."
rb_neigh_add "$TEST_IP" "$TEST_MAC"
wait_until "MAC+IP Type 2 surfaces on FRR" \
    "frr_has_mac_ip \"$TEST_MAC\" \"$TEST_IP\"" 30 || true
assert "MAC+IP Type 2 originated after IpAdded" \
    "frr_has_mac_ip \"$TEST_MAC\" \"$TEST_IP\""
assert "MAC-only Type 2 withdrawn under replace model" \
    "frr_mac_only_absent \"$TEST_MAC\""

# 3. Delete bridge neighbour → MAC+IP withdrawn, MAC-only re-emitted.
echo "Removing bridge neighbour $TEST_IP..."
rb_neigh_del "$TEST_IP"
wait_until "MAC+IP withdrawn after IpRemoved" \
    "frr_mac_ip_absent \"$TEST_MAC\" \"$TEST_IP\"" 15 || true
assert "MAC+IP Type 2 withdrawn on IpRemoved" \
    "frr_mac_ip_absent \"$TEST_MAC\" \"$TEST_IP\""
wait_until "MAC-only re-emitted on downgrade" \
    "frr_has_mac_only \"$TEST_MAC\"" 30 || true
assert "MAC-only Type 2 re-emitted after last IP removed" \
    "frr_has_mac_only \"$TEST_MAC\""

# 4. Delete the FDB entry → MAC-only withdrawn.
echo "Removing static FDB entry $TEST_MAC..."
rb_fdb_del "$TEST_MAC"
wait_until "MAC-only Type 2 withdrawn on Aged" \
    "frr_mac_only_absent \"$TEST_MAC\"" 15 || true
assert "MAC-only Type 2 withdrawn on FDB del" \
    "frr_mac_only_absent \"$TEST_MAC\""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "M37+IP smoke: $PASS/$TOTAL passed, $FAIL failed."
[[ $FAIL -eq 0 ]]
