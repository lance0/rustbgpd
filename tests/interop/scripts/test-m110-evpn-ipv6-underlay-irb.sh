#!/usr/bin/env bash
# M110 — EVPN Type 5 symmetric Interface-less IRB (RFC 9136 §4.4.2) on
# an IPv6-only VXLAN underlay, rustbgpd PE1 ↔ FRR 10.7.1 PE2.
#
# The L3 companion to M109. M109 proves the L2 path over an IPv6
# underlay; M110 proves origination from the kernel routing table and
# import into the tenant VRF, with the tunnel endpoints and every EVPN
# next hop on IPv6. It mirrors M39's assertions, one family over.
#
# Asserts:
#
#   1. Neither underlay interface holds an IPv4 address, and both
#      L3VXLAN devices are sourced from their IPv6 VTEP address.
#   2. The L2VPN/EVPN session reaches Established over IPv6 transport.
#   3. FRR sees PE1's Type 5 for 2001:db8:110:1::/64 with PE1's IPv6
#      VTEP address as next hop.
#   4. rustbgpd sees PE2's Type 5 for 2001:db8:110:2::/64 with PE2's
#      IPv6 VTEP address as next hop.
#   5. PE1's kernel installs PE2's prefix in vrf1's table with
#      `via <IPv6 VTEP> dev l3vxlan110 proto bgp ... onlink`.
#   6. PE1's L3 neighbor row maps PE2's IPv6 VTEP to its router MAC,
#      PERMANENT + extern_learn.
#   7. PE1's L3VXLAN FDB row maps that router MAC to `dst <IPv6 VTEP>`.
#   8. gRPC `IpVrfState.installed_routes_count == 1`.
#   9. Bidirectional tenant ping across the L3VNI over the IPv6 VXLAN
#      tunnel. The tenant subnets do not overlap and no IPv4 path
#      exists, so the L3VNI is the only path that can carry it.
#  10. Withdraw in both directions clears the far side.
#
# Tenant prefixes are IPv6 because the Interface-less IRB install path
# does not implement `RTA_VIA`: the prefix family must match the
# VTEP / next-hop family. A cross-family pair is refused at origination
# and dropped at import — see `docs/LIMITATIONS.md`. This leg exercises
# the supported same-family combination.
#
# Manual leg. FRR 10.7.1 has a startup race in its per-VRF
# `advertise ipv6 unicast` Type 5 origination on an IPv6 underlay: it can
# advertise its IPv4 `bgp router-id` zero-padded into the 16-octet IPv6
# next-hop field instead of the L3VNI's tunnel source. That makes
# assertions 3b through 8b red, correctly — rustbgpd programmed what it
# was sent. The assertions are not relaxed to absorb it. See
# `docs/artifacts/interop/m110-frr-ipv6-l3vni-next-hop-20260905T114909Z/`
# and the topology header.
#
# Prerequisites: containerlab, grpcurl, jq, and the `vrf` kernel module.
#
# Usage:
#   containerlab deploy -t tests/interop/m110-evpn-ipv6-underlay-irb.clab.yml
#   bash tests/interop/scripts/test-m110-evpn-ipv6-underlay-irb.sh
#   containerlab destroy -t tests/interop/m110-evpn-ipv6-underlay-irb.clab.yml --cleanup

TOPO="m110-evpn-ipv6-underlay-irb"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Two PEs rather than the single-rustbgpd shape the shared lib assumes.
# Override RUSTBGPD before sourcing so `preflight` (which runs at source
# time) checks pe1 and the lib helpers target it.
PE1="clab-${TOPO}-pe1"
PE2="clab-${TOPO}-pe2"
RUSTBGPD="$PE1"
export RUSTBGPD

INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

PE1_VTEP="fd00:110::1"
PE2_VTEP="fd00:110::2"

L3VNI=110
TENANT_VRF="vrf1"
PE1_TABLE_ID=110
PE1_L3VXLAN="l3vxlan110"
PE1_ROUTER_MAC="02:00:00:00:01:10"

PE1_TENANT_ADDR="2001:db8:110:1::1/64"
PE1_TENANT_HOST="2001:db8:110:1::1"
PE1_TENANT_DEV="lo-vrf1"
PE1_PREFIX="2001:db8:110:1::/64"
PE1_PREFIX_KEY="[5]:[0]:[64]:[2001:db8:110:1::]"

PE2_TENANT_ADDR="2001:db8:110:2::1/64"
PE2_TENANT_HOST="2001:db8:110:2::1"
PE2_PREFIX="2001:db8:110:2::/64"
PE2_PREFIX_KEY="[5]:[0]:[64]:[2001:db8:110:2::]"

# ---------------------------------------------------------------------------
# Evidence helpers — every failing assertion dumps what it examined.
# ---------------------------------------------------------------------------

pe1_routes() { docker exec "$PE1" ip -6 route show table "$PE1_TABLE_ID" 2>/dev/null || true; }
pe1_neigh()  { docker exec "$PE1" ip -6 neigh show dev "$PE1_L3VXLAN" 2>/dev/null || true; }
pe1_fdb()    { docker exec "$PE1" bridge fdb show dev "$PE1_L3VXLAN" 2>/dev/null || true; }

dump_state() {
    echo "--- PE1: ip -6 route show table $PE1_TABLE_ID ---" >&2
    pe1_routes >&2
    echo "--- PE1: ip -6 neigh show dev $PE1_L3VXLAN ---" >&2
    pe1_neigh >&2
    echo "--- PE1: bridge fdb show dev $PE1_L3VXLAN ---" >&2
    pe1_fdb >&2
    echo "--- PE1: ListEvpnRoutes (type 5) ---" >&2
    rb_evpn_json 2>/dev/null | jq -c '.routes[]? | select(.routeType == 5)' >&2 || true
    echo "--- PE2: show bgp l2vpn evpn route type prefix ---" >&2
    docker exec "$PE2" vtysh -c "show bgp l2vpn evpn route type prefix" 2>/dev/null >&2 || true
}

rb_evpn_json() {
    grpcurl_call -d '{}' "$GRPC_ADDR" rustbgpd.v1.RibService/ListEvpnRoutes 2>/dev/null
}

# Next hop of the Type 5 route for a prefix as rustbgpd decoded it.
# jq field comparison on decoded values, not text matching on a rendered
# line — no rendering change can make this silently stop matching.
rb_type5_next_hop() {
    local prefix=${1:?}
    rb_evpn_json | jq -r --arg p "$prefix" \
        '[.routes[]? | select(.routeType == 5 and .prefix == $p)] | .[0].nextHop // empty' \
        2>/dev/null || true
}

assert_rb_type5_next_hop() {
    local prefix=${1:?} want=${2:?} label=${3:?} attempts=${4:-60}
    for _ in $(seq 1 "$attempts"); do
        [ "$(rb_type5_next_hop "$prefix")" = "$want" ] && break
        sleep 1
    done
    if [ "$(rb_type5_next_hop "$prefix")" = "$want" ]; then
        ok "$label — next hop $want"
    else
        fail "$label — want next hop $want for $prefix, got '$(rb_type5_next_hop "$prefix")'"
        dump_state
    fi
}

# "<next-hop> <afi>" per path under the exact EVPN prefix key.
#
# Anchoring: the key is compared with jq `==` against FRR's JSON object
# key, which carries no trailing ` RD <rd>` (that suffix exists only in
# the text rendering, and is exactly what broke text-anchored matchers
# on the 10.3.1 → 10.7.1 move). Exact key equality has no partial-match
# failure mode, and the `afi` field states the family rather than
# leaving it to be inferred from the address string.
frr_type5_nexthops() {
    local prefix=${1:?}
    docker exec "$PE2" vtysh -c "show bgp l2vpn evpn route type prefix json" 2>/dev/null \
        | jq -r --arg p "$prefix" '
            to_entries[] | select(.value | type == "object") | .value
            | to_entries[] | select(.value | type == "object" and has("paths"))
            | select(.key == $p) | .value.paths[][]
            | .nexthops[]? | "\(.ip) \(.afi)"
          ' 2>/dev/null || true
}

assert_frr_type5_nexthop() {
    local prefix=${1:?} want=${2:?} label=${3:?} attempts=${4:-60}
    for _ in $(seq 1 "$attempts"); do
        frr_type5_nexthops "$prefix" | grep -qxF "$want" && break
        sleep 1
    done
    if frr_type5_nexthops "$prefix" | grep -qxF "$want"; then
        ok "$label — next hop '$want'"
    else
        fail "$label — want '$want' under $prefix, got '$(frr_type5_nexthops "$prefix" | tr '\n' '|')'"
        dump_state
    fi
}

# Strict variant: propagates a failed query so absence checks can tell
# "FRR unreachable" apart from "route validly gone".
frr_type5_dump_strict() {
    docker exec "$PE2" vtysh -c "show bgp l2vpn evpn route type prefix json" 2>/dev/null
}

wait_until() {
    local cmd=${1:?} attempts=${2:-60}
    for _ in $(seq 1 "$attempts"); do
        if eval "$cmd"; then return 0; fi
        sleep 1
    done
    return 1
}

pe1_route_installed() {
    # Field-exact match on the destination, then every operational flag
    # the install path is documented to set on the same line:
    # `proto bgp` so the originator's own observer never re-originates
    # it, and `onlink` because the next hop is not reachable through a
    # connected route on the L3VXLAN device.
    pe1_routes | awk -v p="$PE2_PREFIX" '$1 == p { print; exit }' \
        | grep -qE "via ${PE2_VTEP} dev ${PE1_L3VXLAN} proto bgp .*\bonlink\b"
}

pe1_installed_count() {
    grpcurl_call -d '{"name":"vrf1"}' "$GRPC_ADDR" rustbgpd.v1.EvpnService/GetIpVrf 2>/dev/null \
        | jq -r '.installedRoutesCount // 0' 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Setup — PE1 kernel topology before the daemon starts, so the IP-VRF
# readiness probe sees a fully-formed L3VXLAN device.
# ---------------------------------------------------------------------------

log "Provisioning PE1 kernel topology (IPv6 tunnel source $PE1_VTEP)"
docker exec "$PE1" /usr/local/bin/start-rustbgpd-m39-pe1.sh \
    "$PE1_VTEP" "$L3VNI" "$TENANT_VRF" "$PE1_TENANT_ADDR" "$PE1_ROUTER_MAC" >/dev/null

resolve_grpc_addr
start_rustbgpd

# ---------------------------------------------------------------------------
# Phase 1 — premise
# ---------------------------------------------------------------------------

log "[1] underlay premise: eth1 holds no IPv4 address on either side"
for node in "$PE1" "$PE2"; do
    v4=$(docker exec "$node" ip -4 -o addr show dev eth1 2>/dev/null || true)
    if [ -z "$v4" ]; then
        ok "$node eth1 has no IPv4 address"
    else
        fail "$node eth1 unexpectedly carries an IPv4 address — the IPv6-only premise is broken"
        echo "$v4" >&2
    fi
done

log "[1b] both L3VXLAN devices use an IPv6 tunnel source"
assert_vxlan_local() {
    local node=${1:?} dev=${2:?} want=${3:?}
    local devinfo
    devinfo=$(docker exec "$node" ip -d link show "$dev" 2>/dev/null || true)
    # `local <addr>` here is rendered from IFLA_VXLAN_LOCAL6, so this
    # also confirms the kernel accepted an IPv6 VTEP on the device.
    if echo "$devinfo" | grep -qF "local $want"; then
        ok "$node $dev has local $want"
    else
        fail "$node $dev is not sourced from $want"
        echo "$devinfo" >&2
    fi
}
assert_vxlan_local "$PE1" "$PE1_L3VXLAN" "$PE1_VTEP"
assert_vxlan_local "$PE2" "vxlan${L3VNI}" "$PE2_VTEP"

# ---------------------------------------------------------------------------
# Phase 2 — session
# ---------------------------------------------------------------------------

log "[2] L2VPN/EVPN session Established over the IPv6 transport"
wait_frr_established "$PE2" "$PE1_VTEP" "PE1↔PE2 L2VPN/EVPN over IPv6" || {
    docker exec "$PE2" vtysh -c "show bgp neighbor $PE1_VTEP" >&2 || true
    docker exec "$PE1" tail -60 /var/log/rustbgpd.log >&2 || true
}

# ---------------------------------------------------------------------------
# Phase 3 — Type 5 both directions with IPv6 next hops
# ---------------------------------------------------------------------------

log "[3] FRR sees PE1's Type 5 for $PE1_PREFIX"
assert_frr_type5_nexthop "$PE1_PREFIX_KEY" "$PE1_VTEP ipv6" \
    "FRR received rustbgpd's Type 5"

log "[3b] rustbgpd sees PE2's Type 5 for $PE2_PREFIX"
assert_rb_type5_next_hop "$PE2_PREFIX" "$PE2_VTEP" \
    "rustbgpd received FRR's Type 5"

# ---------------------------------------------------------------------------
# Phase 4 — kernel install of the imported prefix
# ---------------------------------------------------------------------------

log "[4] PE1 kernel installs $PE2_PREFIX in table $PE1_TABLE_ID"
if wait_until "pe1_route_installed"; then
    ok "kernel route: $(pe1_routes | awk -v p="$PE2_PREFIX" '$1 == p { print; exit }')"
else
    fail "PE2's prefix never installed with via $PE2_VTEP dev $PE1_L3VXLAN proto bgp onlink"
    dump_state
fi

log "[5] PE1 L3 neighbor row maps $PE2_VTEP → PE2's router MAC"
# PE2's router MAC is zebra-derived from its SVI, so the value is not
# ours to pin; the assertion is that a link-layer address resolves the
# IPv6 VTEP and carries the ownership flags the apply path sets.
neigh_dump=$(pe1_neigh)
if echo "$neigh_dump" | grep -qE "^${PE2_VTEP}[[:space:]].*lladdr" \
    && echo "$neigh_dump" | grep -E "^${PE2_VTEP}[[:space:]]" | grep -qE "PERMANENT|extern_learn|offload"; then
    ok "neighbor row: $(echo "$neigh_dump" | grep -E "^${PE2_VTEP}[[:space:]]" | head -1)"
else
    fail "neighbor row for $PE2_VTEP missing or wrong shape"
    echo "$neigh_dump" >&2
fi

log "[6] PE1 L3VXLAN FDB row maps PE2's router MAC → dst $PE2_VTEP"
fdb_dump=$(pe1_fdb)
if echo "$fdb_dump" | grep -F "dst $PE2_VTEP" | grep -q 'self'; then
    ok "FDB row: $(echo "$fdb_dump" | grep -F "dst $PE2_VTEP" | head -1)"
else
    fail "no L3VXLAN FDB row with dst $PE2_VTEP — the encap target for the L3VNI is missing"
    echo "$fdb_dump" >&2
fi

log "[7] gRPC IpVrfState.installed_routes_count == 1 for vrf1"
if wait_until '[ "$(pe1_installed_count)" = "1" ]' 30; then
    ok "installed_routes_count=1 on vrf1"
else
    fail "installed_routes_count is '$(pe1_installed_count)', want 1"
    dump_state
fi

# ---------------------------------------------------------------------------
# Phase 5 — datapath
# ---------------------------------------------------------------------------
# The tenant subnets do not overlap and the underlay carries no IPv4, so
# the L3VNI tunnel is the only path that can carry these packets.

log "[8] ping $PE2_TENANT_HOST from PE1 vrf1 (PE1 → PE2 over the IPv6 underlay)"
if docker exec "$PE1" ip vrf exec "$TENANT_VRF" \
    ping -6 -c 3 -W 2 -I "$PE1_TENANT_HOST" "$PE2_TENANT_HOST" >/dev/null 2>&1; then
    ok "tenant ping PE1 → PE2 succeeded"
else
    fail "tenant ping PE1 → PE2 failed"
    docker exec "$PE1" ip vrf exec "$TENANT_VRF" \
        ping -6 -c 3 -W 2 -I "$PE1_TENANT_HOST" "$PE2_TENANT_HOST" >&2 2>&1 || true
    dump_state
fi

log "[8b] ping $PE1_TENANT_HOST from PE2 vrf1 (PE2 → PE1 over the IPv6 underlay)"
if docker exec "$PE2" ip vrf exec "$TENANT_VRF" \
    ping -6 -c 3 -W 2 -I "$PE2_TENANT_HOST" "$PE1_TENANT_HOST" >/dev/null 2>&1; then
    ok "tenant ping PE2 → PE1 succeeded"
else
    fail "tenant ping PE2 → PE1 failed"
    docker exec "$PE2" vtysh -c "show ipv6 route vrf vrf1" >&2 || true
    dump_state
fi

# ---------------------------------------------------------------------------
# Phase 6 — withdraw, origination side
# ---------------------------------------------------------------------------
# The absence check is guarded by a presence check over the SAME dump:
# PE2's own Type 5 must still be there. A failed or empty query
# therefore fails the guard instead of satisfying the absence check.

log "[9] withdraw: remove $PE1_TENANT_ADDR on PE1, expect FRR to drop the Type 5"
docker exec "$PE1" ip addr del "$PE1_TENANT_ADDR" dev "$PE1_TENANT_DEV" 2>/dev/null || true

frr_lost_pe1_type5() {
    local dump
    dump=$(frr_type5_dump_strict) || return 1
    # Guard: PE2's own Type 5 must still be present, so an empty or
    # broken dump cannot pass this as a withdrawal.
    grep -qF "$PE2_PREFIX_KEY" <<<"$dump" || return 1
    ! grep -qF "$PE1_PREFIX_KEY" <<<"$dump"
}

if wait_until "frr_lost_pe1_type5" 30; then
    ok "FRR dropped PE1's Type 5 for $PE1_PREFIX (and still holds its own)"
else
    fail "FRR still shows PE1's Type 5 30s after withdraw, or the guard route vanished too"
    docker exec "$PE2" vtysh -c "show bgp l2vpn evpn route type prefix" >&2 || true
fi

# ---------------------------------------------------------------------------
# Phase 7 — withdraw, import side
# ---------------------------------------------------------------------------

log "[10] reverse withdraw: remove $PE2_TENANT_ADDR on PE2, expect PE1 dataplane cleanup"
docker exec "$PE2" ip addr del "$PE2_TENANT_ADDR" dev lo-vrf1 2>/dev/null || true

# Guard for every absence check below: the L3VXLAN device's own
# link-local route stays in table 110 for as long as the device exists,
# so a table that still shows it is a table that was really read.
pe1_route_gone() {
    local dump
    dump=$(docker exec "$PE1" ip -6 route show table "$PE1_TABLE_ID" 2>/dev/null) || return 1
    echo "$dump" | grep -qE "^fe80::/64 dev ${PE1_L3VXLAN}\b" || return 1
    ! echo "$dump" | awk -v p="$PE2_PREFIX" '$1 == p { found = 1 } END { exit !found }'
}

log "[11] PE1 kernel removes $PE2_PREFIX from vrf1's table"
if wait_until "pe1_route_gone"; then
    ok "kernel route absent from table $PE1_TABLE_ID (table still readable)"
else
    fail "PE1 still holds $PE2_PREFIX, or table $PE1_TABLE_ID could not be read"
    dump_state
fi

log "[12] PE1 L3 neighbor row for $PE2_VTEP cleared"
neigh_after=$(docker exec "$PE1" ip -6 neigh show dev "$PE1_L3VXLAN" 2>/dev/null) \
    && neigh_query_ok=1 || neigh_query_ok=0
if [ "$neigh_query_ok" -eq 1 ] && ! echo "$neigh_after" | grep -qE "^${PE2_VTEP}[[:space:]].*lladdr"; then
    ok "neighbor row for $PE2_VTEP gone"
else
    fail "neighbor row for $PE2_VTEP still present, or the neigh query failed"
    echo "$neigh_after" >&2
fi

log "[12b] PE1 L3VXLAN FDB row for dst $PE2_VTEP cleared"
fdb_after=$(docker exec "$PE1" bridge fdb show dev "$PE1_L3VXLAN" 2>/dev/null) \
    && fdb_query_ok=1 || fdb_query_ok=0
if [ "$fdb_query_ok" -eq 1 ] && ! echo "$fdb_after" | grep -qF "dst $PE2_VTEP"; then
    ok "FDB row for dst $PE2_VTEP gone"
else
    fail "FDB row for dst $PE2_VTEP still present, or the fdb query failed"
    echo "$fdb_after" >&2
fi

log "[13] gRPC IpVrfState.installed_routes_count drops back to 0 for vrf1"
if wait_until '[ "$(pe1_installed_count)" = "0" ]' 30; then
    ok "installed_routes_count converged to 0 on vrf1"
else
    fail "installed_routes_count is '$(pe1_installed_count)', want 0"
    dump_state
fi

print_summary
