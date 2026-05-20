#!/usr/bin/env bash
# M39b manual smoke — RFC 8365 §5.1.2.1 auto-derived Route Targets,
# cross-vendor against FRR. The over-the-wire proof for the
# `auto_derive_route_target` config: rustbgpd PE1 and FRR PE2 each
# DERIVE their import/export RT (no explicit RT on either side), and
# Type 5 routes still import across the iBGP L2VPN/EVPN session.
#
# Validates:
#   1. iBGP L2VPN/EVPN session reaches Established.
#   2. FRR sees rustbgpd PE1's Type 5 for 192.0.2.0/24.
#   3. The RT FRR received is the AS:VNI form (65000:100) — i.e.
#      rustbgpd's `auto_derive_route_target` for an IP-VRF and FRR's
#      default tenant-VRF auto-RT agree on the wire.
#   4. FRR IMPORTS PE1's prefix into vrf1's IP RIB — the derived RT
#      matched FRR's derived import RT (rustbgpd → FRR direction).
#   5. rustbgpd IMPORTS FRR PE2's Type 5 (198.51.100.0/24) into
#      vrf1's kernel table — the derived RT matched on rustbgpd's
#      import side too (FRR → rustbgpd direction).
#
# This is a manual / protected-runner smoke (kernel `vrf` module +
# CAP_NET_ADMIN), modeled on M39 and reusing its kernel topology and
# start scripts. It does not run on the hosted CI runner.
#
# Prerequisites:
#   - containerlab deploy -t tests/interop/m39b-evpn-auto-rt-frr.clab.yml
#   - grpcurl + jq installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m39b-evpn-auto-rt-frr.sh

TOPO="m39b-evpn-auto-rt-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

PE1="clab-${TOPO}-pe1"
PE2="clab-${TOPO}-pe2"
RUSTBGPD="$PE1"
export RUSTBGPD

# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

PE1_IP="10.0.0.1"
PE2_IP="10.0.0.2"
L3VNI=100
TENANT_VRF="vrf1"
PE1_TENANT_ADDR="192.0.2.1/24"
PE1_ROUTER_MAC="02:00:00:00:01:01"
PE1_TABLE_ID=100
PE1_L3VXLAN="l3vxlan100"

PE1_ORIGINATED_HOST="192.0.2.0"
PE1_ORIGINATED_PLEN=24
PE1_ORIGINATED_PREFIX="192.0.2.0/24"
PE2_ORIGINATED_PREFIX="198.51.100.0/24"

# Auto-derived L3VNI / IP-VRF RT for AS 65000 / VNI 100 is plain AS:VNI
# (FRR's default tenant-VRF auto-RT form), i.e. "65000:100".
EXPECTED_AUTO_RT="65000:100"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

grpc_list_evpn() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d '{}' \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListEvpnRoutes 2>/dev/null || true
}

wait_frr_sees_type5() {
    local host=$1 plen=$2 timeout=${3:-60}
    local attempts=$((timeout / 2))
    for _ in $(seq 1 "$attempts"); do
        if docker exec "$PE2" vtysh -c "show bgp l2vpn evpn route type prefix json" 2>/dev/null \
            | grep -q "\\[5\\]:\\[0\\]:\\[$plen\\]:\\[$host\\]"; then
            return 0
        fi
        sleep 2
    done
    return 1
}

# FRR installs the imported Type 5 into the tenant VRF's IP RIB only
# when the route's RT matches vrf1's (auto-derived) import RT.
wait_frr_vrf_route_installed() {
    local prefix=$1 timeout=${2:-60}
    local attempts=$((timeout / 2))
    for _ in $(seq 1 "$attempts"); do
        if docker exec "$PE2" vtysh -c "show ip route vrf $TENANT_VRF json" 2>/dev/null \
            | grep -q "$prefix"; then
            return 0
        fi
        sleep 2
    done
    return 1
}

wait_pe1_route_installed() {
    local prefix=$1 timeout=${2:-60}
    local attempts=$((timeout / 2))
    for _ in $(seq 1 "$attempts"); do
        local line
        line=$(docker exec "$PE1" ip route show table "$PE1_TABLE_ID" 2>/dev/null \
            | grep -E "^${prefix//./\\.}\b" | head -1)
        if [ -n "$line" ] \
            && echo "$line" | grep -qE "via $PE2_IP\b" \
            && echo "$line" | grep -qE "dev $PE1_L3VXLAN\b"; then
            return 0
        fi
        sleep 2
    done
    return 1
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required (apt-get install jq)" >&2
    exit 1
fi

log "Provisioning PE1 kernel topology"
docker exec "$PE1" /usr/local/bin/start-rustbgpd-m39-pe1.sh \
    "$PE1_IP" "$L3VNI" "$TENANT_VRF" "$PE1_TENANT_ADDR" "$PE1_ROUTER_MAC" >/dev/null

resolve_grpc_addr
start_rustbgpd

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

# Test 1: session up
wait_frr_established "$PE2" "$PE1_IP" "PE1↔PE2 L2VPN/EVPN" \
    && ok "session Established" \
    || fail "session did not reach Established"

# Test 2: FRR sees PE1's auto-RT Type 5 (control plane crosses)
if wait_frr_sees_type5 "$PE1_ORIGINATED_HOST" "$PE1_ORIGINATED_PLEN" 60; then
    ok "FRR received PE1's Type 5 for $PE1_ORIGINATED_PREFIX"
else
    fail "FRR never received PE1's Type 5 within 60s"
    docker exec "$PE2" vtysh -c "show bgp l2vpn evpn route type prefix" >&2 || true
fi

# Test 3: the RT on the wire is the AS:VNI form — proves rustbgpd's
# IP-VRF auto-RT and FRR's default tenant-VRF auto-RT agree.
log "[test] auto-derived RT on the wire is $EXPECTED_AUTO_RT"
detail=$(docker exec "$PE2" vtysh -c "show bgp l2vpn evpn route detail" 2>/dev/null || true)
if echo "$detail" | grep -q "$PE1_ORIGINATED_HOST" \
    && echo "$detail" | grep -q "$EXPECTED_AUTO_RT"; then
    ok "auto-derived AS:VNI RT $EXPECTED_AUTO_RT present on the received route"
else
    fail "expected auto-derived RT $EXPECTED_AUTO_RT not found on the wire"
    echo "$detail" | grep -iE "route distinguisher|extended comm|rt:|192.0.2" | head -20 >&2
fi

# Test 4: FRR imports PE1's prefix into vrf1 — rustbgpd→FRR auto-RT
# import actually works (the derived RTs matched).
if wait_frr_vrf_route_installed "$PE1_ORIGINATED_PREFIX" 60; then
    ok "FRR imported $PE1_ORIGINATED_PREFIX into $TENANT_VRF via the auto-derived RT"
else
    fail "FRR did not import $PE1_ORIGINATED_PREFIX into $TENANT_VRF"
    docker exec "$PE2" vtysh -c "show ip route vrf $TENANT_VRF" >&2 || true
fi

# Test 5: rustbgpd imports FRR's Type 5 into vrf1 kernel — FRR→rustbgpd
# auto-RT import works on rustbgpd's import side too.
if wait_pe1_route_installed "$PE2_ORIGINATED_PREFIX" 60; then
    ok "rustbgpd imported $PE2_ORIGINATED_PREFIX into $TENANT_VRF kernel via the auto-derived RT"
else
    fail "rustbgpd did not install $PE2_ORIGINATED_PREFIX in table $PE1_TABLE_ID"
    docker exec "$PE1" ip route show table "$PE1_TABLE_ID" >&2 || true
fi

print_summary
