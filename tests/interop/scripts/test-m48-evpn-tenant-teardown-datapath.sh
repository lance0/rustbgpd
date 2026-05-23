#!/usr/bin/env bash
# M48 interop test — runtime EVPN tenant teardown over the kernel L3
# datapath (ADR-0063 / #210) against a real FRR peer.
#
# Builds on M39 (symmetric Interface-less IRB) and adds the runtime
# teardown leg M47 (control-plane) cannot reach: dropping a *linked*
# IP-VRF together with its L2VNI in one ApplyEvpnRuntime pass.
#
#   1. iBGP L2VPN/EVPN Established; PE1 boots a tenant — L2VNI 10 linked
#      to IP-VRF vrf1 (L3VNI 100).
#   2. FRR sees PE1's Type 5 (192.0.2.0/24) and Type 3 IMET (L2VNI 10);
#      PE1 imports FRR's Type 5 (198.51.100.0/24) into vrf1's kernel
#      table (proves the datapath is live before teardown).
#   3. ApplyEvpnRuntime drops the whole tenant (L2VNI 10 + IP-VRF vrf1).
#      The daemon converges it through the atomic tenant-teardown path
#      (vrf1 is referenced by L2VNI 10) and reports COMMITTED.
#   4. FRR withdraws PE1's Type 5 + IMET; PE1's imported kernel L3 route
#      drains. The tenant is gone end-to-end without a restart.
#
# Requires CAP_NET_ADMIN + the kernel `vrf`/`vxlan` modules (same as
# M39) — runs on the self-hosted kernel-dataplane runner, not hosted CI.
#
# Prerequisites:
#   - containerlab deploy -t tests/interop/m48-evpn-tenant-teardown-datapath.clab.yml
#   - grpcurl + jq installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m48-evpn-tenant-teardown-datapath.sh

TOPO="m48-evpn-tenant-teardown-datapath"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

PE1="clab-${TOPO}-pe1"
PE2="clab-${TOPO}-pe2"
RUSTBGPD="$PE1"
export RUSTBGPD

# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

PE1_IP="10.0.0.1"
L2VNI_RD="65000:10"
L3VNI=100
TENANT_VRF="vrf1"
PE1_TABLE_ID=100
PE1_ROUTER_MAC="02:00:00:00:01:01"
PE1_TENANT_ADDR="192.0.2.1/24"
PE1_ORIGINATED_HOST="192.0.2.0"
PE1_ORIGINATED_PLEN=24
PE2_ORIGINATED_PREFIX="198.51.100.0/24"
TEARDOWN_TOML="$SCRIPT_DIR/../configs/rustbgpd-m48-teardown.toml"

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required (apt-get install jq)" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

grpc_list_evpn() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d '{}' "$GRPC_ADDR" rustbgpd.v1.RibService/ListEvpnRoutes 2>/dev/null
}

grpc_apply_teardown() {
    jq -Rs '{candidateToml: ., validateOnly: false}' <"$TEARDOWN_TOML" \
        | grpcurl -plaintext -import-path . -proto "$PROTO" -d @ \
            "$GRPC_ADDR" rustbgpd.v1.EvpnService/ApplyEvpnRuntime 2>&1 || true
}

frr_type5_has() {
    docker exec "$PE2" vtysh -c "show bgp l2vpn evpn route type prefix json" 2>/dev/null \
        | grep -q "\\[5\\]:\\[0\\]:\\[$1\\]:\\[$2\\]"
}

# True if FRR's EVPN RIB holds a multicast (Type 3 IMET) route under
# the given RD.
frr_imet_has_rd() {
    docker exec "$PE2" vtysh -c "show bgp l2vpn evpn route type multicast" 2>/dev/null \
        | grep -q "$1"
}

pe1_route_present() {
    docker exec "$PE1" ip route show table "$PE1_TABLE_ID" 2>/dev/null \
        | grep -qE "^${1//./\\.}\b"
}

wait_until() { # <timeout> <cmd...>
    local timeout=$1; shift
    local attempts=$((timeout / 2))
    for _ in $(seq 1 "$attempts"); do
        if "$@"; then return 0; fi
        sleep 2
    done
    return 1
}
not() { ! "$@"; }

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

log "Provisioning PE1 kernel topology (vrf1 + L3VXLAN + tenant dummy)"
docker exec "$PE1" /usr/local/bin/start-rustbgpd-m39-pe1.sh \
    "$PE1_IP" "$L3VNI" "$TENANT_VRF" "$PE1_TENANT_ADDR" "$PE1_ROUTER_MAC" >/dev/null

resolve_grpc_addr
start_rustbgpd

# ---------------------------------------------------------------------------
# Tests — tenant comes up
# ---------------------------------------------------------------------------

wait_frr_established "$PE2" "$PE1_IP" "PE1↔PE2 L2VPN/EVPN" || print_summary

log "[test] FRR sees PE1's Type 5 (192.0.2.0/24)"
if wait_until 90 frr_type5_has "$PE1_ORIGINATED_PLEN" "$PE1_ORIGINATED_HOST"; then
    ok "FRR EVPN RIB contains PE1's Type 5"
else
    fail "FRR never received PE1's Type 5 within 90s"
    docker exec "$PE2" vtysh -c "show bgp l2vpn evpn route type prefix" >&2 || true
fi

log "[test] FRR sees PE1's Type 3 IMET (L2VNI RD ${L2VNI_RD})"
if wait_until 60 frr_imet_has_rd "$L2VNI_RD"; then
    ok "FRR EVPN RIB contains PE1's IMET under ${L2VNI_RD}"
else
    fail "FRR never received PE1's IMET within 60s"
    docker exec "$PE2" vtysh -c "show bgp l2vpn evpn route type multicast" >&2 || true
fi

log "[test] PE1 imports FRR's Type 5 (${PE2_ORIGINATED_PREFIX}) into vrf1 kernel table"
if wait_until 90 pe1_route_present "$PE2_ORIGINATED_PREFIX"; then
    ok "PE1 kernel route for ${PE2_ORIGINATED_PREFIX} present in table ${PE1_TABLE_ID}"
else
    fail "PE1 never installed FRR's Type 5 within 90s"
    docker exec "$PE1" ip route show table "$PE1_TABLE_ID" >&2 || true
fi

# ---------------------------------------------------------------------------
# Teardown — drop the whole tenant at runtime
# ---------------------------------------------------------------------------

log "[test] ApplyEvpnRuntime tears down the tenant (L2VNI 10 + IP-VRF vrf1)"
apply_out=$(grpc_apply_teardown)
if echo "$apply_out" | grep -q "EVPN_RUNTIME_APPLY_COMMITTED"; then
    ok "ApplyEvpnRuntime committed the teardown"
else
    fail "ApplyEvpnRuntime did not commit the teardown"
    echo "$apply_out" | head -60 >&2
fi
if printf '%s' "$apply_out" | jq -e \
    '(.plan.evpnInstances.deleted // []) | index("10")' >/dev/null 2>&1; then
    ok "teardown plan deletes L2VNI 10"
else
    fail "teardown plan does not list L2VNI 10 in evpnInstances.deleted"
    echo "$apply_out" | head -60 >&2
fi
if printf '%s' "$apply_out" | jq -e \
    '(.plan.evpnIpVrfs.deleted // []) | index("vrf1")' >/dev/null 2>&1; then
    ok "teardown plan deletes IP-VRF vrf1"
else
    fail "teardown plan does not list IP-VRF vrf1 in evpnIpVrfs.deleted"
    echo "$apply_out" | head -60 >&2
fi

log "[test] FRR withdraws PE1's Type 5 after teardown"
if wait_until 30 not frr_type5_has "$PE1_ORIGINATED_PLEN" "$PE1_ORIGINATED_HOST"; then
    ok "FRR dropped PE1's Type 5 (192.0.2.0/24) after teardown"
else
    fail "FRR still shows PE1's Type 5 30s after teardown"
    docker exec "$PE2" vtysh -c "show bgp l2vpn evpn route type prefix" >&2 || true
fi

log "[test] FRR withdraws PE1's Type 3 IMET after teardown"
if wait_until 30 not frr_imet_has_rd "$L2VNI_RD"; then
    ok "FRR dropped PE1's IMET (${L2VNI_RD}) after teardown"
else
    fail "FRR still shows PE1's IMET 30s after teardown"
    docker exec "$PE2" vtysh -c "show bgp l2vpn evpn route type multicast" >&2 || true
fi

log "[test] PE1 drains the imported kernel L3 route after teardown"
if wait_until 60 not pe1_route_present "$PE2_ORIGINATED_PREFIX"; then
    ok "PE1 kernel route for ${PE2_ORIGINATED_PREFIX} drained from table ${PE1_TABLE_ID}"
else
    fail "PE1 kernel still has ${PE2_ORIGINATED_PREFIX} 60s after teardown"
    docker exec "$PE1" ip route show table "$PE1_TABLE_ID" >&2 || true
fi

print_summary
