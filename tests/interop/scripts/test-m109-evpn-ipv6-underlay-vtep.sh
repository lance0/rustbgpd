#!/usr/bin/env bash
# M109 — EVPN L2 over an IPv6-only VXLAN underlay, rustbgpd ↔ FRR 10.7.1.
#
# Every other EVPN leg in this suite runs the underlay over IPv4. M109
# carries the tunnel endpoints, the BGP transport, and every EVPN next
# hop over IPv6 and asserts the *values*, not just route presence — the
# address family of the next hop is the whole point of the receipt.
#
# Asserts, in order:
#
#   1. Neither underlay interface holds an IPv4 address (premise: no
#      IPv4 path exists that could rescue a later assertion).
#   2. The L2VPN/EVPN session reaches Established over IPv6 transport.
#   3. Type 3 IMET in both directions, each carrying the originator's
#      IPv6 VTEP address as the MP_REACH next hop.
#   4. Type 2 MAC-only and MAC+IP in both directions, again with the
#      originator's IPv6 VTEP address as next hop.
#   5. rustbgpd programs FRR's MAC into the kernel FDB — both the
#      bridge-master row and the `self` row with `dst fd00:109::2` —
#      and withdraws both when FRR withdraws the MAC.
#   6. Two foreign static rows, one of them carrying an IPv6 `dst`,
#      survive the program and withdraw cycles untouched.
#
# On the "16-byte next hop" claim: rustbgpd's L2VPN/EVPN MP_REACH
# decoder accepts a next-hop length of 4 or 16 and rejects everything
# else, and its encoder writes 4 for IPv4 and 16 for IPv6. An IPv6
# next-hop *value* observed on the far side is therefore only reachable
# through the 16-octet encoding — asserting the value asserts the
# length, and does so in terms an operator can read back off the wire.
#
# Usage:
#   docker build --target dev -t rustbgpd:dev .
#   containerlab deploy -t tests/interop/m109-evpn-ipv6-underlay-vtep.clab.yml
#   bash tests/interop/scripts/test-m109-evpn-ipv6-underlay-vtep.sh
#   containerlab destroy -t tests/interop/m109-evpn-ipv6-underlay-vtep.clab.yml --cleanup

TOPO="m109-evpn-ipv6-underlay-vtep"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

RUSTBGPD="clab-${TOPO}-rustbgpd"
export RUSTBGPD
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

FRR="clab-${TOPO}-frr"

RB_VTEP="fd00:109::1"
FRR_VTEP="fd00:109::2"
VNI="109"
BRIDGE="br${VNI}"
VXLAN="vxlan${VNI}"
RB_LOCAL_PORT="veth${VNI}a"
FRR_LOCAL_PORT="dummy${VNI}"

# MACs are distinct per direction so a grep can never confuse them.
FRR_MAC="02:aa:bb:cc:dd:09"
FRR_HOST_IP="2001:db8:109::9"
RB_MAC="02:aa:bb:cc:dd:19"
RB_HOST_IP="2001:db8:109::19"

# Foreign rows the daemon must never touch. One bridge-master row (the
# M36 shape) and one `self` row whose `dst` is an IPv6 address — the
# second one is the IPv6-specific case, because a reconciler that could
# not parse a 16-byte NDA_DST out of the FDB dump would classify it as
# unowned garbage and reap it.
FOREIGN_MASTER_MAC="02:99:99:99:99:99"
FOREIGN_SELF_MAC="02:99:99:99:99:98"
FOREIGN_SELF_DST="fd00:109::98"

# ---------------------------------------------------------------------------
# Evidence helpers — every failing assertion dumps what it looked at.
# ---------------------------------------------------------------------------

rb_fdb() {
    docker exec "$RUSTBGPD" bridge fdb show dev "$VXLAN" 2>/dev/null || true
}

dump_state() {
    echo "--- rustbgpd: bridge fdb show dev $VXLAN ---" >&2
    rb_fdb >&2
    echo "--- rustbgpd: ListEvpnRoutes ---" >&2
    rb_evpn_json 2>/dev/null | jq -c '.routes[]?' >&2 || true
    echo "--- FRR: show bgp l2vpn evpn route ---" >&2
    docker exec "$FRR" vtysh -c "show bgp l2vpn evpn route" 2>/dev/null >&2 || true
}

# Full EVPN RIB as rustbgpd sees it. Exits non-zero when the RPC itself
# fails, so absence checks can tell "query broke" from "route gone".
rb_evpn_json() {
    grpcurl_call -d '{}' "$GRPC_ADDR" rustbgpd.v1.RibService/ListEvpnRoutes 2>/dev/null
}

# Next hop of the first EVPN route matching a jq row predicate; empty
# when nothing matches.
#
# The predicates below pin `routeType`, `mac`/`ip`, and — for received
# routes — that `ip` is absent for the MAC-only case. They are jq field
# comparisons on decoded values, not text matching against a rendered
# line, so there is no rendering change that can make one silently stop
# matching.
rb_route_next_hop() {
    local predicate=${1:?}
    rb_evpn_json | jq -r "[.routes[]? | select(${predicate})] | .[0].nextHop // empty" 2>/dev/null || true
}

wait_rb_next_hop() {
    local predicate=${1:?} want=${2:?} attempts=${3:-40}
    for _ in $(seq 1 "$attempts"); do
        if [ "$(rb_route_next_hop "$predicate")" = "$want" ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

assert_rb_next_hop() {
    local predicate=${1:?} want=${2:?} label=${3:?}
    if wait_rb_next_hop "$predicate" "$want"; then
        ok "$label — next hop $want"
    else
        fail "$label — want next hop $want, got '$(rb_route_next_hop "$predicate")'"
        dump_state
    fi
}

# "<next-hop> <afi>" for every path FRR holds under the exact EVPN
# prefix key $2, in its JSON dump of route type $1.
#
# Anchoring: the prefix is matched with jq `==` against the JSON object
# key, which FRR emits without the trailing ` RD <rd>` that its *text*
# rendering appends (that suffix is what broke text-anchored matchers on
# the 10.3.1 → 10.7.1 move). An exact key comparison has no partial-match
# failure mode. The paired `afi` field makes the family explicit rather
# than inferred from the shape of the address string.
frr_nexthops_for() {
    local rtype=${1:?} prefix=${2:?}
    docker exec "$FRR" vtysh -c "show bgp l2vpn evpn route type $rtype json" 2>/dev/null \
        | jq -r --arg p "$prefix" '
            to_entries[] | select(.value | type == "object") | .value
            | to_entries[] | select(.value | type == "object" and has("paths"))
            | select(.key == $p) | .value.paths[][]
            | .nexthops[]? | "\(.ip) \(.afi)"
          ' 2>/dev/null || true
}

wait_frr_nexthop() {
    local rtype=${1:?} prefix=${2:?} want=${3:?} attempts=${4:-40}
    for _ in $(seq 1 "$attempts"); do
        if frr_nexthops_for "$rtype" "$prefix" | grep -qxF "$want"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

assert_frr_nexthop() {
    local rtype=${1:?} prefix=${2:?} want=${3:?} label=${4:?}
    if wait_frr_nexthop "$rtype" "$prefix" "$want"; then
        ok "$label — next hop '$want'"
    else
        fail "$label — want '$want' under prefix $prefix, got '$(frr_nexthops_for "$rtype" "$prefix" | tr '\n' '|')'"
        dump_state
    fi
}

# ---------------------------------------------------------------------------
# FDB row predicates
# ---------------------------------------------------------------------------

# Bridge-master row: without it the bridge floods unicast instead of
# handing the frame to the VXLAN port.
fdb_has_master_row() {
    rb_fdb | grep -iF "${1:?}" | grep "master $BRIDGE" | grep -qE 'extern_learn|offload'
}

# VXLAN self row: `dst <remote VTEP>` is the encap target. This is the
# assertion the whole leg exists for — the remote VTEP is an IPv6
# address, so a passing row proves the rtnetlink writer emitted a
# 16-byte NDA_DST and the kernel accepted it on an AF_BRIDGE neighbour.
fdb_has_self_dst_row() {
    local mac=${1:?} dst=${2:?}
    rb_fdb | grep -iF "$mac" | grep -F "dst $dst" | grep 'self' \
        | grep -qE 'extern_learn|offload'
}

fdb_has_mac() {
    rb_fdb | grep -qiF "${1:?}"
}

wait_until() {
    local cmd=${1:?} attempts=${2:-40}
    for _ in $(seq 1 "$attempts"); do
        if eval "$cmd"; then return 0; fi
        sleep 1
    done
    return 1
}

# ---------------------------------------------------------------------------
# Injection helpers
# ---------------------------------------------------------------------------

frr_add_mac()   { docker exec "$FRR" bridge fdb add "$1" dev "$FRR_LOCAL_PORT" master static 2>/dev/null || true; }
frr_del_mac()   { docker exec "$FRR" bridge fdb del "$1" dev "$FRR_LOCAL_PORT" master 2>/dev/null || true; }
frr_add_neigh() { docker exec "$FRR" ip -6 neigh replace "$1" lladdr "$2" dev "$BRIDGE" nud reachable 2>/dev/null || true; }
frr_del_neigh() { docker exec "$FRR" ip -6 neigh del "$1" dev "$BRIDGE" 2>/dev/null || true; }

rb_add_mac()   { docker exec "$RUSTBGPD" bridge fdb add "$1" dev "$RB_LOCAL_PORT" master static 2>/dev/null || true; }
rb_add_neigh() { docker exec "$RUSTBGPD" ip -6 neigh replace "$1" lladdr "$2" dev "$BRIDGE" nud reachable 2>/dev/null || true; }

# ---------------------------------------------------------------------------
# Phase 1 — premise: the underlay carries no IPv4 at all
# ---------------------------------------------------------------------------

resolve_grpc_addr
log "rustbgpd container: $RUSTBGPD (VTEP $RB_VTEP)"
log "FRR container:      $FRR (VTEP $FRR_VTEP)"

log "[1] underlay premise: eth1 holds no IPv4 address on either side"
for node in "$RUSTBGPD" "$FRR"; do
    v4=$(docker exec "$node" ip -4 -o addr show dev eth1 2>/dev/null || true)
    if [ -z "$v4" ]; then
        ok "$node eth1 has no IPv4 address"
    else
        # A single IPv4 address here would let the tunnel and the BGP
        # session fall back to IPv4 and every later assertion could pass
        # without the IPv6 path ever working.
        fail "$node eth1 unexpectedly carries an IPv4 address — the IPv6-only premise is broken"
        echo "$v4" >&2
    fi
done

log "[1b] both VXLAN devices use an IPv6 tunnel source"
assert_vxlan_local() {
    local node=${1:?} want=${2:?}
    local devinfo
    devinfo=$(docker exec "$node" ip -d link show "$VXLAN" 2>/dev/null || true)
    # `local <addr>` in `ip -d link show` is rendered from
    # IFLA_VXLAN_LOCAL6 for an IPv6 tunnel source, so this doubles as a
    # check that the kernel accepted an IPv6 VTEP on the device.
    if echo "$devinfo" | grep -qF "local $want"; then
        ok "$node $VXLAN has local $want"
    else
        fail "$node $VXLAN is not sourced from $want"
        echo "$devinfo" >&2
    fi
}
assert_vxlan_local "$RUSTBGPD" "$RB_VTEP"
assert_vxlan_local "$FRR" "$FRR_VTEP"

# ---------------------------------------------------------------------------
# Phase 2 — session over IPv6 transport
# ---------------------------------------------------------------------------

log "[2] L2VPN/EVPN session Established over the IPv6 transport"
wait_frr_established "$FRR" "$RB_VTEP" "L2VPN/EVPN over IPv6" || {
    docker exec "$FRR" vtysh -c "show bgp neighbor $RB_VTEP" >&2 || true
    docker exec "$RUSTBGPD" tail -60 /var/log/rustbgpd.log >&2 || true
}

# ---------------------------------------------------------------------------
# Phase 3 — Type 3 IMET, both directions, IPv6 next hop
# ---------------------------------------------------------------------------
# The Type 3 NLRI's own originating-router field is IPv6 too, which FRR
# renders as the `[128]` length marker in the prefix key. Matching that
# key and then asserting the separate MP_REACH next hop covers both the
# NLRI encoding and the next-hop encoding.

log "[3] Type 3 IMET rustbgpd → FRR"
assert_frr_nexthop multicast "[3]:[0]:[128]:[$RB_VTEP]" "$RB_VTEP ipv6" \
    "FRR received rustbgpd's Type 3 IMET"

log "[3b] Type 3 IMET FRR → rustbgpd"
assert_rb_next_hop ".routeType == 3 and .ip == \"$FRR_VTEP\"" "$FRR_VTEP" \
    "rustbgpd received FRR's Type 3 IMET"

# ---------------------------------------------------------------------------
# Phase 4 — foreign rows planted before any programming happens
# ---------------------------------------------------------------------------

log "[4] planting foreign FDB rows the daemon must never touch"
docker exec "$RUSTBGPD" bridge fdb add "$FOREIGN_MASTER_MAC" dev "$VXLAN" \
    dst "$FOREIGN_SELF_DST" vni "$VNI" master static 2>/dev/null || true
docker exec "$RUSTBGPD" bridge fdb add "$FOREIGN_SELF_MAC" dev "$VXLAN" \
    dst "$FOREIGN_SELF_DST" self static 2>/dev/null || true

if fdb_has_mac "$FOREIGN_MASTER_MAC" && fdb_has_mac "$FOREIGN_SELF_MAC"; then
    ok "both foreign rows planted"
else
    fail "foreign rows were not planted — the preservation checks below would be vacuous"
    dump_state
fi

# ---------------------------------------------------------------------------
# Phase 5 — FRR → rustbgpd: Type 2 and kernel FDB toward an IPv6 VTEP
# ---------------------------------------------------------------------------

log "[5] FRR originates a MAC-only Type 2 for $FRR_MAC"
frr_add_mac "$FRR_MAC"
assert_rb_next_hop \
    ".routeType == 2 and .mac == \"$FRR_MAC\" and (.ip // \"\") == \"\"" \
    "$FRR_VTEP" "rustbgpd received FRR's MAC-only Type 2"

log "[5b] rustbgpd programs the bridge-master FDB row"
if wait_until "fdb_has_master_row \"$FRR_MAC\""; then
    ok "bridge-master row present for $FRR_MAC with extern_learn"
else
    fail "bridge-master row missing for $FRR_MAC — the bridge would flood instead of tunnelling"
    dump_state
fi

log "[5c] rustbgpd programs the VXLAN self row with dst $FRR_VTEP"
if wait_until "fdb_has_self_dst_row \"$FRR_MAC\" \"$FRR_VTEP\""; then
    ok "self row present: $(rb_fdb | grep -iF "$FRR_MAC" | grep -F "dst $FRR_VTEP" | head -1 | tr -s ' ')"
else
    fail "no FDB row for $FRR_MAC with dst $FRR_VTEP — kernel FDB programming toward an IPv6 remote VTEP failed"
    dump_state
fi

log "[5d] FRR upgrades to MAC+IP after an ND binding for $FRR_HOST_IP"
frr_add_neigh "$FRR_HOST_IP" "$FRR_MAC"
assert_rb_next_hop \
    ".routeType == 2 and .mac == \"$FRR_MAC\" and .ip == \"$FRR_HOST_IP\"" \
    "$FRR_VTEP" "rustbgpd received FRR's MAC+IP Type 2"

log "[5e] foreign rows survived the program cycle"
if fdb_has_mac "$FOREIGN_MASTER_MAC" && fdb_has_mac "$FOREIGN_SELF_MAC"; then
    ok "both foreign rows survived programming"
else
    fail "a foreign row was removed during programming"
    dump_state
fi

# ---------------------------------------------------------------------------
# Phase 6 — rustbgpd → FRR: Type 2 origination with an IPv6 next hop
# ---------------------------------------------------------------------------
# rustbgpd runs the FRR-style replace model: the MAC-only route is
# withdrawn when an IP binding appears. So the MAC-only assertion has to
# land before the neighbour is added.

log "[6] rustbgpd originates a MAC-only Type 2 for $RB_MAC"
rb_add_mac "$RB_MAC"
assert_frr_nexthop macip "[2]:[0]:[48]:[$RB_MAC]" "$RB_VTEP ipv6" \
    "FRR received rustbgpd's MAC-only Type 2"

log "[6b] rustbgpd originates a MAC+IP Type 2 for $RB_MAC / $RB_HOST_IP"
rb_add_neigh "$RB_HOST_IP" "$RB_MAC"
assert_frr_nexthop macip "[2]:[0]:[48]:[$RB_MAC]:[128]:[$RB_HOST_IP]" "$RB_VTEP ipv6" \
    "FRR received rustbgpd's MAC+IP Type 2"

# ---------------------------------------------------------------------------
# Phase 7 — withdraw
# ---------------------------------------------------------------------------
# The absence assertion is paired with a presence assertion over the SAME
# dump: the foreign rows must still be there. An empty or failed
# `bridge fdb show` therefore cannot satisfy the withdraw check — it
# fails the foreign-row half instead of passing both vacuously.

log "[7] FRR withdraws $FRR_MAC; rustbgpd must drop both kernel rows"
frr_del_neigh "$FRR_HOST_IP"
frr_del_mac "$FRR_MAC"

if wait_until "! fdb_has_mac \"$FRR_MAC\""; then
    ok "FDB rows for $FRR_MAC withdrawn"
else
    fail "FDB rows for $FRR_MAC still present 40s after withdraw"
    dump_state
fi

log "[7b] foreign rows survived the withdraw cycle (guards the check above)"
after=$(rb_fdb)
if echo "$after" | grep -qiF "$FOREIGN_MASTER_MAC" \
    && echo "$after" | grep -iF "$FOREIGN_SELF_MAC" | grep -qF "dst $FOREIGN_SELF_DST"; then
    ok "both foreign rows intact, including the IPv6-dst self row"
else
    fail "a foreign row was removed during withdraw — and the withdraw assertion above is therefore not meaningful"
    echo "$after" >&2
fi

print_summary
