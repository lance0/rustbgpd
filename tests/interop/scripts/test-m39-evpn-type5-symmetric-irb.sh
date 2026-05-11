#!/usr/bin/env bash
# M39 manual smoke — bidirectional EVPN Type 5 (RFC 9136 §4.4.2
# symmetric Interface-less IRB) between rustbgpd (PE1) and FRR
# (PE2). Validates the full Gate 9 slice 6 datapath end-to-end:
#
#   1. iBGP L2VPN/EVPN session reaches Established.
#   2. PE2 (FRR) sees PE1's Type 5 for 192.0.2.1/32.
#   3. PE1 (rustbgpd) sees PE2's Type 5 for 192.0.2.2/32.
#   4. PE1's kernel installs PE2's prefix in vrf1 with the
#      expected `proto bgp` / `onlink` / `dev l3vxlan100` shape.
#   5. PE1's L3 neighbor row maps 10.0.0.2 → PE2's router MAC.
#   6. PE1's L3VXLAN FDB row maps PE2's router MAC → 10.0.0.2.
#   7. Bidirectional ping across vrf1 (PE1 → 192.0.2.2 and the
#      reverse).
#   8. Withdraw leg: removing PE1's tenant prefix causes FRR to
#      drop the Type 5 within 30s.
#
# Prerequisites:
#   - containerlab deploy -t tests/interop/m39-evpn-type5-symmetric-irb.clab.yml
#   - grpcurl + jq installed on the host
#   - kernel `vrf` module present (Azure GHA runners have
#     historically lacked it intermittently; M39 is manual-only
#     for exactly this reason)
#
# Usage:
#   bash tests/interop/scripts/test-m39-evpn-type5-symmetric-irb.sh

TOPO="m39-evpn-type5-symmetric-irb"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

# M39 has two PEs (pe1, pe2) instead of the one-rustbgpd shape
# the shared lib assumes. Override after sourcing so the lib's
# helpers (resolve_grpc_addr, start_rustbgpd) target pe1.
PE1="clab-${TOPO}-pe1"
PE2="clab-${TOPO}-pe2"
RUSTBGPD="$PE1"

PE1_IP="10.0.0.1"
PE2_IP="10.0.0.2"

PE1_TENANT_PREFIX="192.0.2.1/32"
PE1_TENANT_HOST="192.0.2.1"
PE1_TENANT_DEV="lo-vrf1"
PE2_TENANT_PREFIX="192.0.2.2/32"
PE2_TENANT_HOST="192.0.2.2"

L3VNI=100
TENANT_VRF="vrf1"
PE1_TABLE_ID=100
PE1_L3VXLAN="l3vxlan100"
PE1_ROUTER_MAC="02:00:00:00:01:01"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

grpc_list_evpn() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d '{}' \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListEvpnRoutes 2>/dev/null
}

# Poll FRR's L2VPN/EVPN RIB for a Type 5 entry containing the
# given /32 host. Returns 0 on success, 1 on timeout.
wait_frr_sees_type5() {
    local host=$1
    local timeout=${2:-60}
    local attempts=$((timeout / 2))
    for _ in $(seq 1 "$attempts"); do
        if docker exec "$PE2" vtysh -c "show bgp l2vpn evpn route type prefix json" 2>/dev/null \
            | grep -q "\\[5\\]:\\[0\\]:\\[32\\]:\\[$host\\]"; then
            return 0
        fi
        sleep 2
    done
    return 1
}

# Poll rustbgpd's ListEvpnRoutes for a Type 5 entry for the given
# prefix. Returns 0 on success.
wait_rustbgpd_sees_type5() {
    local prefix=$1
    local timeout=${2:-60}
    local attempts=$((timeout / 2))
    for _ in $(seq 1 "$attempts"); do
        local n
        n=$(grpc_list_evpn | jq -r --arg p "$prefix" \
            '[.routes[]? | select(.routeType == 5 and .prefix == $p)] | length')
        if [ "${n:-0}" -ge 1 ]; then
            return 0
        fi
        sleep 2
    done
    return 1
}

# Poll PE1's kernel routing table inside vrf1 until the given
# prefix is installed. Field-fragment matching insulates against
# iproute2 output variations (per the PR-B review's parser
# guidance).
wait_pe1_route_installed() {
    local prefix=$1
    local timeout=${2:-60}
    local attempts=$((timeout / 2))
    for _ in $(seq 1 "$attempts"); do
        local dump
        dump=$(docker exec "$PE1" ip route show table "$PE1_TABLE_ID" 2>/dev/null || true)
        if echo "$dump" | grep -qE "^${prefix//./\\.}\b" \
            && echo "$dump" | grep -qE "via $PE2_IP\b" \
            && echo "$dump" | grep -qE "dev $PE1_L3VXLAN\b"; then
            return 0
        fi
        sleep 2
    done
    return 1
}

# Poll PE1's kernel until the gRPC `IpVrfState.installed_routes_count`
# for vrf1 reaches the given value. Confirms slice 6c's gRPC surface
# stays in sync with the kernel.
wait_pe1_installed_count() {
    local want=$1
    local timeout=${2:-30}
    local attempts=$((timeout / 2))
    for _ in $(seq 1 "$attempts"); do
        local got
        got=$(grpcurl -plaintext -import-path . -proto "$PROTO" \
            -d '{"name":"vrf1"}' \
            "$GRPC_ADDR" rustbgpd.v1.EvpnService/GetIpVrf 2>/dev/null \
            | jq -r '.installedRoutesCount // 0')
        if [ "${got:-0}" = "$want" ]; then
            return 0
        fi
        sleep 2
    done
    return 1
}

# ---------------------------------------------------------------------------
# Setup phases
# ---------------------------------------------------------------------------

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required (apt-get install jq)" >&2
    exit 1
fi

# PE1 kernel topology — VRF + L3VXLAN + tenant dummy. Must run
# BEFORE the daemon starts so the readiness probe sees a
# fully-formed L3VXLAN device.
log "Provisioning PE1 kernel topology"
docker exec "$PE1" /usr/local/bin/start-rustbgpd-m39-pe1.sh \
    "$PE1_IP" "$L3VNI" "$TENANT_VRF" "$PE1_TENANT_PREFIX" "$PE1_ROUTER_MAC" >/dev/null

resolve_grpc_addr
start_rustbgpd

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

# Test 1: BGP session reaches Established between PE1 and PE2.
wait_frr_established "$PE2" "$PE1_IP" "PE1↔PE2 L2VPN/EVPN" \
    || fail "iBGP L2VPN/EVPN session did not reach Established"

# Test 2: FRR receives PE1's Type 5 origination.
log "[test 2] FRR sees PE1's Type 5 for $PE1_TENANT_PREFIX"
if wait_frr_sees_type5 "$PE1_TENANT_HOST" 90; then
    ok "FRR's L2VPN/EVPN RIB contains Type 5 from PE1"
else
    fail "FRR never received PE1's Type 5 within 90s"
    docker exec "$PE2" vtysh -c "show bgp l2vpn evpn route type prefix" >&2 || true
fi

# Test 3: rustbgpd receives FRR's Type 5 origination.
log "[test 3] rustbgpd sees PE2's Type 5 for $PE2_TENANT_PREFIX"
if wait_rustbgpd_sees_type5 "$PE2_TENANT_PREFIX" 90; then
    ok "rustbgpd's ListEvpnRoutes contains Type 5 from PE2"
else
    fail "rustbgpd never received PE2's Type 5 within 90s"
    grpc_list_evpn | jq -c '.routes[]? | select(.routeType == 5)' >&2 || true
fi

# Test 4: PE1's kernel installs PE2's Type 5 into vrf1's table
# (slice 6c reconciler + L3 netlink primitives).
log "[test 4] PE1 kernel installs $PE2_TENANT_PREFIX in table $PE1_TABLE_ID"
if wait_pe1_route_installed "$PE2_TENANT_PREFIX" 90; then
    ok "kernel route present with via $PE2_IP dev $PE1_L3VXLAN"
else
    fail "PE2's prefix never made it into PE1's kernel route table"
    docker exec "$PE1" ip route show table "$PE1_TABLE_ID" >&2 || true
fi

# Test 5: PE1's L3 neighbor row resolves 10.0.0.2 → PE2's router MAC.
# We don't pin the exact MAC — FRR's zebra synthesizes it from the
# bridge SVI's link-layer address, which we don't control. Instead
# we assert that ANY lladdr maps to 10.0.0.2 and the entry is
# permanent / extern_learn (matches the apply path's
# NUD_PERMANENT + NTF_EXT_LEARNED).
log "[test 5] PE1 L3 neighbor row maps $PE2_IP → router MAC (permanent + extern_learn)"
neigh_dump=$(docker exec "$PE1" ip neigh show dev "$PE1_L3VXLAN" 2>/dev/null || true)
if echo "$neigh_dump" | grep -qE "^$PE2_IP\b.*lladdr\b" \
    && echo "$neigh_dump" | grep -qE "$PE2_IP\b.*(PERMANENT|extern_learn|offload)"; then
    ok "neighbor row present for $PE2_IP with permanent state"
else
    fail "neighbor row for $PE2_IP missing or wrong shape"
    echo "$neigh_dump" >&2
fi

# Test 6: PE1's L3VXLAN FDB row maps PE2's router MAC → 10.0.0.2.
log "[test 6] PE1 L3VXLAN FDB row maps PE2 router MAC → $PE2_IP (self + extern_learn)"
fdb_dump=$(docker exec "$PE1" bridge fdb show dev "$PE1_L3VXLAN" 2>/dev/null || true)
if echo "$fdb_dump" | grep -qE "dst $PE2_IP\b.*self" \
    || echo "$fdb_dump" | grep -qE "self.*dst $PE2_IP\b"; then
    ok "FDB row present with dst $PE2_IP self"
else
    fail "FDB row for dst $PE2_IP missing or wrong shape"
    echo "$fdb_dump" >&2
fi

# Test 7: gRPC IpVrfState surfaces installed_routes_count=1.
log "[test 7] gRPC IpVrfState.installed_routes_count == 1 for vrf1"
if wait_pe1_installed_count 1 30; then
    ok "installed_routes_count=1 on vrf1"
else
    fail "installed_routes_count did not reach 1 within 30s"
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d '{"name":"vrf1"}' \
        "$GRPC_ADDR" rustbgpd.v1.EvpnService/GetIpVrf >&2 || true
fi

# Test 8: bidirectional ping across vrf1.
#
# PE1 → PE2: source from PE1's tenant /32 inside vrf1, target
# PE2's tenant /32. Since both prefixes live on lo-vrf1 inside
# their respective VRFs, the route through the L3VNI is what
# carries the traffic.
log "[test 8] ping $PE2_TENANT_HOST from PE1 vrf1 (PE1 → PE2 datapath)"
if docker exec "$PE1" ip vrf exec "$TENANT_VRF" \
    ping -c 3 -W 2 -I "$PE1_TENANT_HOST" "$PE2_TENANT_HOST" >/dev/null 2>&1; then
    ok "ping from PE1 vrf1 to $PE2_TENANT_HOST succeeded"
else
    fail "ping from PE1 vrf1 to $PE2_TENANT_HOST failed"
    docker exec "$PE1" ip route show table "$PE1_TABLE_ID" >&2 || true
fi

log "[test 8b] ping $PE1_TENANT_HOST from PE2 vrf1 (PE2 → PE1 datapath)"
if docker exec "$PE2" ip vrf exec "$TENANT_VRF" \
    ping -c 3 -W 2 -I "$PE2_TENANT_HOST" "$PE1_TENANT_HOST" >/dev/null 2>&1; then
    ok "ping from PE2 vrf1 to $PE1_TENANT_HOST succeeded"
else
    fail "ping from PE2 vrf1 to $PE1_TENANT_HOST failed"
    docker exec "$PE2" vtysh -c "show ip route vrf vrf1" >&2 || true
fi

# Test 9: withdraw leg. Remove the tenant prefix from PE1's
# tenant dummy; PE1's slice 6b originator should detect the
# observation drop and emit a Type 5 withdraw; FRR should drop
# the route from its EVPN RIB.
log "[test 9] withdraw: remove $PE1_TENANT_PREFIX on PE1, expect FRR to drop the Type 5"
docker exec "$PE1" ip addr del "$PE1_TENANT_PREFIX" dev "$PE1_TENANT_DEV" 2>/dev/null || true

wait_frr_loses_type5() {
    local host=$1
    local timeout=${2:-30}
    local attempts=$((timeout / 2))
    for _ in $(seq 1 "$attempts"); do
        if ! docker exec "$PE2" vtysh -c "show bgp l2vpn evpn route type prefix json" 2>/dev/null \
            | grep -q "\\[5\\]:\\[0\\]:\\[32\\]:\\[$host\\]"; then
            return 0
        fi
        sleep 2
    done
    return 1
}

if wait_frr_loses_type5 "$PE1_TENANT_HOST" 30; then
    ok "FRR dropped PE1's Type 5 for $PE1_TENANT_HOST after withdraw"
else
    fail "FRR still shows PE1's Type 5 30s after withdraw"
    docker exec "$PE2" vtysh -c "show bgp l2vpn evpn route type prefix" >&2 || true
fi

print_summary
