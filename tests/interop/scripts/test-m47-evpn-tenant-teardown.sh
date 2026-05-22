#!/usr/bin/env bash
# M47 interop test — runtime EVPN tenant teardown via ApplyEvpnRuntime
# (ADR-0063 / #210) against a real FRR peer.
#
# Validates the atomic tenant-teardown shape of the EVPN runtime-mutation
# API — the first interop smoke to drive EvpnService/ApplyEvpnRuntime:
#   1. rustbgpd reaches Established with FRR on L2VPN/EVPN.
#   2. The booted tenant (L2VNI 100 + Ethernet Segment ...01) advertises
#      its Type 3 (IMET) and Type 1/4 (EAD / ES) routes; FRR receives them
#      into its global EVPN RIB (RD 65000:100) and rustbgpd's own RIB shows
#      the locally-originated Type 3 + Type 4.
#   3. ApplyEvpnRuntime is driven with a candidate that drops the whole
#      tenant. The daemon converges the L2VNI + ES delete as one atomic
#      tenant teardown and reports COMMITTED.
#   4. Every tenant route is withdrawn: FRR drops RD 65000:100 and
#      rustbgpd's RIB no longer holds the tenant's Type 3 / Type 4.
#
# Pure control-plane: no kernel bridge / VXLAN / VRF on either side, so the
# tenant routes live only in `show bgp l2vpn evpn` and the smoke runs
# without the `vrf`/`vxlan` kernel modules. The linked-IP-VRF + kernel-L3
# teardown datapath is a follow-up smoke.
#
# Prerequisites:
#   - containerlab deploy -t tests/interop/m47-evpn-tenant-teardown.clab.yml
#   - grpcurl + jq installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m47-evpn-tenant-teardown.sh

TOPO="m47-evpn-tenant-teardown"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

FRR="clab-${TOPO}-frr"
RUSTBGPD_IP="10.0.0.1"
TENANT_RD="65000:100"
TEARDOWN_TOML="$SCRIPT_DIR/../configs/rustbgpd-m47-teardown.toml"

if ! command -v jq &>/dev/null; then
    echo "ERROR: jq not found in PATH (needed to build the ApplyEvpnRuntime payload)" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# gRPC helpers
# ---------------------------------------------------------------------------

grpc_list_evpn() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d '{}' \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListEvpnRoutes 2>/dev/null || true
}

# Drive EvpnService/ApplyEvpnRuntime with the teardown candidate. The
# candidate TOML is passed verbatim as the `candidate_toml` string; jq
# handles the multi-line escaping.
grpc_apply_teardown() {
    jq -Rs '{candidateToml: ., validateOnly: false}' <"$TEARDOWN_TOML" \
        | grpcurl -plaintext -import-path . -proto "$PROTO" -d @ \
            "$GRPC_ADDR" rustbgpd.v1.EvpnService/ApplyEvpnRuntime 2>&1 || true
}

# ---------------------------------------------------------------------------
# FRR helpers
# ---------------------------------------------------------------------------

frr_evpn_table() {
    docker exec "$FRR" vtysh -c "show bgp l2vpn evpn" 2>/dev/null || true
}

wait_frr_rd_present() {
    local timeout=${1:-30}
    local attempts=$((timeout / 2))
    for _ in $(seq 1 "$attempts"); do
        if frr_evpn_table | grep -q "$TENANT_RD"; then
            return 0
        fi
        sleep 2
    done
    return 1
}

wait_frr_rd_absent() {
    local timeout=${1:-20}
    local attempts=$((timeout / 2))
    for _ in $(seq 1 "$attempts"); do
        if ! frr_evpn_table | grep -q "$TENANT_RD"; then
            return 0
        fi
        sleep 2
    done
    return 1
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

resolve_grpc_addr
start_rustbgpd

# Test 1: rustbgpd ↔ FRR Established on L2VPN/EVPN.
wait_frr_established "$FRR" "$RUSTBGPD_IP" "FRR L2VPN/EVPN" || print_summary

# Test 2: FRR receives the booted tenant (RD 65000:100 covers IMET + ES + EAD).
log "[test] FRR receives the tenant's EVPN routes (RD ${TENANT_RD})"
if wait_frr_rd_present 30; then
    ok "FRR EVPN RIB contains the tenant RD ${TENANT_RD}"
else
    fail "FRR never received the tenant routes within 30s"
    frr_evpn_table >&2
fi

# Test 3: rustbgpd's own RIB holds the locally-originated Type 3 + Type 4.
log "[test] rustbgpd ListEvpnRoutes shows the tenant's Type 3 + Type 4"
evpn_json=$(grpc_list_evpn)
if echo "$evpn_json" | grep -q '"routeType": 3'; then
    ok "ListEvpnRoutes includes the L2VNI Type 3 (IMET)"
else
    fail "ListEvpnRoutes missing the L2VNI Type 3 (IMET)"
    echo "$evpn_json" | head -60 >&2
fi
if echo "$evpn_json" | grep -q '"routeType": 4'; then
    ok "ListEvpnRoutes includes the Ethernet Segment Type 4"
else
    fail "ListEvpnRoutes missing the Ethernet Segment Type 4"
    echo "$evpn_json" | head -60 >&2
fi

# Test 4: tear the tenant down at runtime via ApplyEvpnRuntime.
log "[test] ApplyEvpnRuntime tears down the tenant (L2VNI 100 + ES ...01)"
apply_out=$(grpc_apply_teardown)
if echo "$apply_out" | grep -q "EVPN_RUNTIME_APPLY_COMMITTED"; then
    ok "ApplyEvpnRuntime committed the teardown"
else
    fail "ApplyEvpnRuntime did not commit the teardown"
    echo "$apply_out" | head -60 >&2
fi
# The plan summary should attribute the delete to the L2VNI.
if echo "$apply_out" | grep -q '"100"'; then
    ok "teardown plan deletes L2VNI 100"
else
    fail "teardown plan does not list L2VNI 100 as deleted"
    echo "$apply_out" | head -60 >&2
fi

# Test 5: FRR drops the whole tenant after the teardown.
log "[test] FRR withdraws the tenant routes after teardown"
if wait_frr_rd_absent 20; then
    ok "FRR dropped the tenant RD ${TENANT_RD} after teardown"
else
    fail "FRR still shows the tenant RD ${TENANT_RD} 20s after teardown"
    frr_evpn_table >&2
fi

# Test 6: rustbgpd's RIB no longer holds the tenant's Type 3 / Type 4.
log "[test] rustbgpd ListEvpnRoutes drained the tenant routes"
evpn_json=$(grpc_list_evpn)
if echo "$evpn_json" | grep -q '"routeType": 3' || echo "$evpn_json" | grep -q '"routeType": 4'; then
    fail "ListEvpnRoutes still shows tenant Type 3/4 after teardown"
    echo "$evpn_json" | head -60 >&2
else
    ok "ListEvpnRoutes no longer shows the tenant's Type 3 / Type 4"
fi

print_summary
