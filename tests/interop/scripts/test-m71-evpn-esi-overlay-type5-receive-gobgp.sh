#!/usr/bin/env bash
# M71 interop test — rustbgpd receive-side RFC 9136 §4.3 ESI
# overlay-index Type 5 SINGLE-ACTIVE recursion (PR #541), against a
# real GoBGP peer.
#
# rustbgpd is the device under test (VTEP / receive side) with a full
# L3 VRF datapath. GoBGP is the route source. The driver injects an
# ESI overlay-index Type 5 (non-zero ESI, Router-MAC extcomm, Gateway
# Address 0.0.0.0) and the Type 1 EAD-per-ES / EAD-per-EVI rows that
# rustbgpd recursively resolves it through, then exercises the four
# correctness phases:
#
#   Phase 1 (fail-closed, no EAD): the Type 5 alone is held unresolved.
#     `evpn_ip_vrf_remote_prefix_drops{vrf="vrf1",reason=
#     "unresolved_esi_overlay_index"}` >= 1, no kernel route in vrf1.
#   Phase 2 (single-active resolves): EAD-per-ES (single-active) +
#     EAD-per-EVI let rustbgpd import the prefix into vrf1 — kernel
#     route via the PE VTEP, the unresolved drop gauge falls to 0.
#   Phase 3 (single-PE all-active fail-closed): advertising the same
#     EAD-per-ES without the Single-Active flag withdraws the import.
#     The all-active writer refuses a target set with fewer than two
#     candidates, so `...{reason="unsupported_all_active_target_set"}` >= 1
#     and the kernel route is gone.
#   Phase 4 (withdraw): deleting the Type 5 leaves vrf1 clean.
#
# Why GoBGP and not FRR: the proof needs byte-exact, independent
# control over the EAD-per-ES Single-Active vs All-Active ESI Label
# flag injected/withdrawn separately from the Type 5. FRR's EVPN
# multi-homing is all-active only and cannot originate a single-active
# EAD-per-ES, so it cannot drive phase 2.
#
# Usage:
#   containerlab deploy -t tests/interop/m71-evpn-esi-overlay-type5-receive-gobgp.clab.yml
#   bash tests/interop/scripts/test-m71-evpn-esi-overlay-type5-receive-gobgp.sh
#   containerlab destroy -t tests/interop/m71-evpn-esi-overlay-type5-receive-gobgp.clab.yml

set -euo pipefail

TOPO="m71-evpn-esi-overlay-type5-receive-gobgp"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH

VTEP="clab-${TOPO}-vtep"
PE="clab-${TOPO}-pe"
# The shared lib's resolve_grpc_addr / start_rustbgpd target $RUSTBGPD.
RUSTBGPD="$VTEP"
export RUSTBGPD

# shellcheck disable=SC1091
# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

VTEP_IP="10.0.0.1"
PE_IP="10.0.0.2"
L3VNI=100
L2VNI=10
TENANT_VRF="vrf1"
TABLE_ID=100
VTEP_ROUTER_MAC="02:00:00:00:01:01"
L3VXLAN="l3vxlan${L3VNI}"

# The ESI overlay Type 5 the PE originates.
TARGET_PREFIX="203.0.113.0/24"
RD_L3="65000:100"
RT_L3="65000:100"
RD_L2="65000:10"
RT_L2="65000:10"
# Router MAC carried by the Type 5 (the inner destination MAC for the
# recursive lookup). Operator-independent of the VTEP's own router_mac.
TYPE5_ROUTER_MAC="02:00:00:00:71:01"
# 10-byte wire ESI 00:00:00:00:00:00:00:00:00:01 — gobgp CLI form is
# `esi 0 <9 value bytes>` (type 0 + 9 value bytes); same shape as M65.
ESI_GOBGP=(esi 0 00:00:00:00:00:00:00:00:01)

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required (apt-get install jq)" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

pe_rib() { docker exec "$PE" gobgp global rib "$@"; }

# Wait for the GoBGP peer's session to the VTEP to reach Established.
wait_gobgp_established() {
    local peer=${1:?}
    local label=${2:-BGP}
    log "Waiting for $label session to reach Established..."
    for i in $(seq 1 45); do
        local state
        state=$(docker exec "$PE" gobgp neighbor "$peer" 2>/dev/null | grep -i 'BGP state' || true)
        if echo "$state" | grep -qi "establ"; then
            ok "$label session established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$label session did not reach Established within 90s"
    docker exec "$PE" gobgp neighbor "$peer" >&2 2>/dev/null || true
    return 1
}

# Value of the drop gauge for a given reason (label order tolerant).
# Empty when the series is absent.
drop_gauge() {
    local reason=${1:?}
    prom_scrape "$VTEP" | awk \
        -v v="vrf=\"${TENANT_VRF}\"" \
        -v r="reason=\"${reason}\"" '
        $0 ~ /^evpn_ip_vrf_remote_prefix_drops\{/ && index($0, v) && index($0, r) {
            print $2
            exit
        }'
}

# True once the named drop gauge is >= 1.
drop_gauge_at_least_1() {
    local reason=${1:?}
    local got
    got=$(drop_gauge "$reason")
    [ "${got:-0}" -ge 1 ] 2>/dev/null
}

# True once the named drop gauge reads 0 (or the series is absent).
drop_gauge_is_zero() {
    local reason=${1:?}
    local got
    got=$(drop_gauge "$reason")
    [ "${got:-0}" -eq 0 ] 2>/dev/null
}

# The full kernel route line for $TARGET_PREFIX in vrf1's table, or
# empty if absent.
vrf_route_line() {
    docker exec "$VTEP" ip route show table "$TABLE_ID" "$TARGET_PREFIX" 2>/dev/null \
        | head -1 || true
}

# True once the kernel installed $TARGET_PREFIX via the PE VTEP on the
# L3VXLAN device (the imported-Type-5 shape: proto bgp + onlink).
vrf_route_installed_via_pe() {
    local line
    line=$(vrf_route_line)
    [ -n "$line" ] || return 1
    case " $line " in *" via $PE_IP "*) ;; *) return 1 ;; esac
    case " $line " in *" dev $L3VXLAN "*) ;; *) return 1 ;; esac
    case " $line " in *" proto bgp "*) ;; *) return 1 ;; esac
    case " $line " in *" onlink "*) ;; *) return 1 ;; esac
}

vrf_route_absent() {
    [ -z "$(vrf_route_line)" ]
}

# gRPC installed_routes_count for vrf1, used as a second assertion after
# the kernel route is present.
vrf_installed_count() {
    grpcurl_call \
        -d '{"name":"'"$TENANT_VRF"'"}' \
        "$GRPC_ADDR" rustbgpd.v1.EvpnService/GetIpVrf 2>/dev/null \
        | jq -r '.installedRoutesCount // 0' 2>/dev/null || echo 0
}

vrf_installed_count_is() {
    local want=${1:?}
    [ "$(vrf_installed_count)" = "$want" ]
}

wait_until() {
    local timeout=$1
    shift
    local attempts=$((timeout / 2))
    [ "$attempts" -lt 1 ] && attempts=1
    for _ in $(seq 1 "$attempts"); do
        if "$@"; then
            return 0
        fi
        sleep 2
    done
    return 1
}

not() { ! "$@"; }

# Inject / withdraw the ESI overlay-index Type 5 from the PE. Non-zero
# ESI, Router-MAC extcomm, Gateway Address 0.0.0.0 (the `gw` arg
# omitted defaults to the unspecified address), L3VNI 100 in the label
# slot, RT 65000:100.
pe_add_type5() {
    pe_rib add -a evpn prefix "$TARGET_PREFIX" "${ESI_GOBGP[@]}" etag 0 label "$L3VNI" \
        rd "$RD_L3" rt "$RT_L3" encap vxlan router-mac "$TYPE5_ROUTER_MAC" \
        nexthop "$PE_IP"
}

pe_del_type5() {
    pe_rib del -a evpn prefix "$TARGET_PREFIX" "${ESI_GOBGP[@]}" etag 0 label "$L3VNI" \
        rd "$RD_L3" 2>/dev/null || true
}

# EAD-per-ES with the Single-Active ESI Label flag (RFC 7432 §7.5). etag
# MAX_ET (4294967295), label 0. The single_active mode is keyed on
# (next_hop, ESI) — its etag is not part of the Type 5 resolution match.
pe_add_ead_per_es_single_active() {
    pe_rib add -a evpn a-d "${ESI_GOBGP[@]}" etag 4294967295 label 0 \
        rd "$RD_L2" rt "$RT_L2" encap vxlan esi-label 0 single-active \
        nexthop "$PE_IP"
}

pe_del_ead_per_es() {
    pe_rib del -a evpn a-d "${ESI_GOBGP[@]}" etag 4294967295 label 0 \
        rd "$RD_L2" 2>/dev/null || true
}

# EAD-per-ES advertised as ALL-ACTIVE (no single-active flag). The
# receive path projects an all-active target set; with only one PE in
# M71, the L3 writer refuses it fail-closed instead of downgrading it
# to the scalar single-active path.
pe_add_ead_per_es_all_active() {
    pe_rib add -a evpn a-d "${ESI_GOBGP[@]}" etag 4294967295 label 0 \
        rd "$RD_L2" rt "$RT_L2" encap vxlan esi-label 0 \
        nexthop "$PE_IP"
}

# EAD-per-EVI on L2VNI 10 (etag 0, label == L2VNI). Its label names the
# local L2VNI for the resolver; its etag (0) must match the Type 5's.
pe_add_ead_per_evi() {
    pe_rib add -a evpn a-d "${ESI_GOBGP[@]}" etag 0 label "$L2VNI" \
        rd "$RD_L2" rt "$RT_L2" encap vxlan nexthop "$PE_IP"
}

pe_del_ead_per_evi() {
    pe_rib del -a evpn a-d "${ESI_GOBGP[@]}" etag 0 label "$L2VNI" \
        rd "$RD_L2" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

log "vtep (DUT, receive side): $VTEP — pe (route source, GoBGP): $PE"

log "Provisioning VTEP kernel topology (vrf1 + L3VNI $L3VNI + linked L2VNI $L2VNI)"
docker exec "$VTEP" /usr/local/bin/start-rustbgpd-m71-vtep.sh \
    "$VTEP_IP" "$L3VNI" "$TENANT_VRF" "$VTEP_ROUTER_MAC" "$L2VNI" >/dev/null

resolve_grpc_addr
start_rustbgpd

wait_gobgp_established "$VTEP_IP" "GoBGP-PE ↔ rustbgpd-VTEP L2VPN/EVPN" || print_summary

log "Clearing any stale M71 routes from the GoBGP RIB"
pe_del_type5
pe_del_ead_per_es
pe_del_ead_per_evi

# ---------------------------------------------------------------------------
# Phase 1 — fail-closed: ESI overlay Type 5 with no resolving EAD state
# ---------------------------------------------------------------------------

log "[phase 1] PE injects ONLY the ESI overlay-index Type 5 (no EAD)"
if pe_add_type5; then
    ok "PE originated the ESI overlay-index Type 5 for $TARGET_PREFIX"
else
    fail "PE Type 5 injection failed"
fi

log "[phase 1] rustbgpd must hold it unresolved (no EAD-per-ES/EVI)"
if wait_until 40 drop_gauge_at_least_1 "unresolved_esi_overlay_index"; then
    ok "drop gauge unresolved_esi_overlay_index >= 1 (= $(drop_gauge unresolved_esi_overlay_index))"
else
    fail "drop gauge unresolved_esi_overlay_index never reached >= 1"
    prom_scrape "$VTEP" | grep '^evpn_ip_vrf_remote_prefix_drops' >&2 || true
    docker exec "$VTEP" tail -60 /var/log/rustbgpd.log >&2 2>/dev/null || true
fi

log "[phase 1] no kernel route may exist in vrf1 before resolution"
if vrf_route_absent && vrf_installed_count_is 0; then
    ok "no vrf1 kernel route / installed_routes_count=0 before EAD state"
else
    fail "vrf1 route present before the ESI was resolvable"
    docker exec "$VTEP" ip route show table "$TABLE_ID" >&2 || true
fi

# ---------------------------------------------------------------------------
# Phase 2 — single-active resolves: EAD-per-ES (SA) + EAD-per-EVI
# ---------------------------------------------------------------------------

log "[phase 2] PE adds the single-active EAD-per-ES + EAD-per-EVI"
if pe_add_ead_per_es_single_active; then
    ok "PE originated EAD-per-ES (single-active)"
else
    fail "PE EAD-per-ES (single-active) injection failed"
fi
if pe_add_ead_per_evi; then
    ok "PE originated EAD-per-EVI on L2VNI $L2VNI"
else
    fail "PE EAD-per-EVI injection failed"
fi

log "[phase 2] rustbgpd resolves the ESI overlay and imports $TARGET_PREFIX into vrf1"
if wait_until 90 vrf_route_installed_via_pe; then
    ok "vrf1 kernel route installed: $(vrf_route_line)"
else
    fail "rustbgpd did not install the expected vrf1 kernel route for $TARGET_PREFIX"
    docker exec "$VTEP" ip route show table "$TABLE_ID" >&2 || true
    prom_scrape "$VTEP" | grep '^evpn_ip_vrf_remote_prefix_drops' >&2 || true
    docker exec "$VTEP" tail -80 /var/log/rustbgpd.log >&2 2>/dev/null || true
fi

log "[phase 2] gRPC installed_routes_count must report exactly one imported route"
if wait_until 30 vrf_installed_count_is 1; then
    ok "rustbgpd reports installed_routes_count=1 for vrf1"
else
    fail "rustbgpd kernel route exists but installed_routes_count != 1"
fi

log "[phase 2] the unresolved-overlay drop gauge must fall back to 0"
if wait_until 30 drop_gauge_is_zero "unresolved_esi_overlay_index"; then
    ok "drop gauge unresolved_esi_overlay_index back to 0 after resolution"
else
    fail "drop gauge unresolved_esi_overlay_index still nonzero after import (= $(drop_gauge unresolved_esi_overlay_index))"
    prom_scrape "$VTEP" | grep '^evpn_ip_vrf_remote_prefix_drops' >&2 || true
fi

# ---------------------------------------------------------------------------
# Phase 3 — all-active fail-closed: advertise EAD-per-ES all-active
# ---------------------------------------------------------------------------

log "[phase 3] PE advertises the EAD-per-ES as ALL-ACTIVE"
# Advertising the same (RD, ESI, etag) EAD-per-ES without the
# single-active flag must make the folded mode non-single-active,
# whether GoBGP replaces the prior row or briefly exposes mixed signals.
if pe_add_ead_per_es_all_active; then
    ok "PE advertised EAD-per-ES (all-active)"
else
    fail "PE EAD-per-ES (all-active) advertise failed"
fi

log "[phase 3] rustbgpd must withdraw the import and fail closed"
if wait_until 60 drop_gauge_at_least_1 "unsupported_all_active_target_set"; then
    ok "drop gauge unsupported_all_active_target_set >= 1 (= $(drop_gauge unsupported_all_active_target_set))"
else
    fail "drop gauge unsupported_all_active_target_set never reached >= 1"
    prom_scrape "$VTEP" | grep '^evpn_ip_vrf_remote_prefix_drops' >&2 || true
fi

log "[phase 3] the vrf1 kernel route must be withdrawn"
if wait_until 60 vrf_route_absent && wait_until 30 vrf_installed_count_is 0; then
    ok "vrf1 kernel route withdrawn / installed_routes_count=0 under all-active"
else
    fail "vrf1 route survived the all-active downgrade"
    docker exec "$VTEP" ip route show table "$TABLE_ID" >&2 || true
fi

# ---------------------------------------------------------------------------
# Phase 4 — withdraw: delete the Type 5
# ---------------------------------------------------------------------------

log "[phase 4] PE withdraws the ESI overlay-index Type 5"
if pe_del_type5; then
    ok "PE withdrew the Type 5 for $TARGET_PREFIX"
else
    fail "PE Type 5 withdrawal failed"
fi

log "[phase 4] vrf1 must be clean (no route, no residual import)"
if wait_until 30 vrf_route_absent && wait_until 30 vrf_installed_count_is 0; then
    ok "vrf1 clean after the Type 5 withdraw"
else
    fail "vrf1 not clean after the Type 5 withdraw"
    docker exec "$VTEP" ip route show table "$TABLE_ID" >&2 || true
fi

log "[phase 4] PE cleans up residual EAD state for rerun safety"
pe_del_ead_per_es
pe_del_ead_per_evi
ok "PE EAD state cleaned up"

print_summary
