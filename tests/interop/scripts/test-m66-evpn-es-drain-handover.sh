#!/usr/bin/env bash
# M66 — ADR-0084 Ethernet Segment drain service handover, rustbgpd on
# BOTH sides.
#
# The proof M65 couldn't be: M65 used GoBGP segment PEs because
# rustbgpd had no deliberate origination-side withdrawal stimulus.
# `rbgp evpn es drain <esi>` is that stimulus now, so the two
# single-active segment PEs AND the remote VTEP (receive side) are
# all rustbgpd. The drain on pe1 must withdraw exactly its segment
# origination state (Type 4 + EAD-per-ES + EAD-per-EVI + the member
# VNI's local Type 2 routes), hand the service to pe2 (DF re-election
# + flood-path MAC relearning + pe2's own Type 2 origination), and
# undrain must restore pe1 from its kept observation caches.
#
# Asserts (hard on mechanism, informational on timing — the M63/M65
# philosophy):
#
# 1. Steady state: vtep RIB carries Type 4 + EAD-per-ES (etag MAX_ET)
#    + EAD-per-EVI (etag 0) from BOTH PEs and Type 3 IMET from both;
#    pe1 is DF (highest-preference 200 > 100), pe2 NonDF; after
#    traffic bootstraps, the CE MAC's Type 2 comes from pe1 ONLY and
#    lands behind the ADR-0083 one-member FDB nexthop group (member =
#    pe1's per-VTEP NH, pe2's NH pre-created as standby).
# 2. Authorization: the drain RPC is operator_only (ADR-0064). The
#    observer principal gets PermissionDenied; an operator drain of an
#    unconfigured ESI gets NotFound.
# 3. Drain (operator, on pe1): response says drained=true changed=true
#    member_vni_count=1; a repeat is an idempotent no-op
#    (changed=false). On the vtep, ALL FOUR route classes from pe1
#    withdraw while pe2's stay intact. pe2 promotes to DF. pe1's own
#    surface shows the drain (df gauge 0 + the segment actor's drain
#    log line).
# 4. Service handover: connectivity restores via pe2 — the vtep's CE
#    MAC FDB row resolves toward pe2's VTEP IP (pe2 learned the CE MAC
#    through the now-open flood path and originated its own Type 2).
#    The receive-side backup-swap counter MAY fire transiently
#    (ordering-dependent) — logged, not asserted. Blackout window
#    measured from a 100 ms prober — informational, with one generous
#    < 30 s hard bound. (Note the enforcement limit: the drained PE's
#    stale kernel known-unicast path may keep forwarding during the
#    window, which only makes the service gap smaller.)
# 5. SIGHUP while drained (ADR-0084 decision 3): a config reload that
#    KEEPS the drained ES configured — made non-trivial by adding a
#    bridge-less L2VNI, which forces a live EVPN runtime apply — must
#    not resurrect pe1's routes. The reload is proven applied (the new
#    VNI appears in `evpn instances`) while pe1's segment routes stay
#    withdrawn and the df gauge stays 0.
# 6. Undrain: Type 4 + both EAD classes return from pe1 immediately;
#    pe1 re-wins DF (revertive highest-preference), pe2 demotes. The
#    CE then emits one maintenance-exit ARP broadcast (the GARP
#    pattern real CEs produce) and the CE MAC's Type 2 from pe1 plus
#    end-to-end service are asserted. The broadcast is pe1's re-learn
#    stimulus: the remaining same-ESI local-bias gap means pe2's
#    Type 2 usurped pe1's kernel-learned local AC row while drained,
#    and (now that the in-place port move IS observed and drops the
#    stale local claim) pe1 originates nothing for the CE MAC until
#    its kernel relearns it on the AC — see the phase 7 comment.
# 7. Foreign state: the start-script's pre-loaded foreign FDB row and
#    the static all-zero flood entries survive the whole cycle.
#
# Usage:
#   docker build -t rustbgpd:dev .
#   containerlab deploy -t tests/interop/m66-evpn-es-drain-handover.clab.yml
#   bash tests/interop/scripts/test-m66-evpn-es-drain-handover.sh
#   containerlab destroy -t tests/interop/m66-evpn-es-drain-handover.clab.yml

set -eu

TOPO="m66-evpn-es-drain-handover"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUSTBGPD="clab-${TOPO}-vtep"
export RUSTBGPD
# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

VTEP="clab-${TOPO}-vtep"
PE1="clab-${TOPO}-pe1"
PE2="clab-${TOPO}-pe2"
CE="clab-${TOPO}-ce"
HR="clab-${TOPO}-hr"

PE1_IP="10.0.1.2"
PE2_IP="10.0.2.2"
VNI="100"
BRIDGE="br${VNI}"
VXLAN="vxlan${VNI}"
ESI="00:00:00:00:00:00:00:00:00:01"
UNKNOWN_ESI="00:00:00:00:00:00:00:00:00:7f"
CE_MAC="02:ce:ce:ce:ce:01"
CE_HOST_IP="192.168.66.10"
# Pre-loaded by start-rustbgpd-vtep.sh before rustbgpd starts.
PRELOADED_FOREIGN_MAC="02:99:99:99:99:99"
PROBE_INTERVAL_MS="100"
# Hard sanity bound on the measured blackout. Generous: the handover
# is multi-stage (drain propagation + DF re-election + flood-path
# relearn + the originator's 5 s FDB poll + the dataplane's RIB-event
# apply), and the drained PE's stale unicast path usually shrinks the
# observed gap to near zero anyway. Mechanism asserts are strict; the
# bound only catches a hang.
BLACKOUT_BOUND_MS="30000"
PROBER_PREFIX="m66"
VTEP_ROUTE_WAIT_ATTEMPTS="60"
ROLE_WAIT_ATTEMPTS="60"
PE_GRPC_ATTEMPTS="20"
VTEP_ESTABLISHED_ATTEMPTS="45"
WAIT_PING_ATTEMPTS="60"

OPERATOR_TOKEN_FILE="/etc/rustbgpd/grpc-operator.token"
OBSERVER_SOCK="unix:///var/lib/rustbgpd/grpc-observer.sock"
SIGHUP_MARKER="m66-sighup-while-drained"

# ---------------------------------------------------------------------------
# Shared helpers live in test-lib.sh; M66-specific assertions stay below.
# ---------------------------------------------------------------------------

# Assert all four pe1 route classes are ABSENT from the vtep RIB
# right now (used post-drain and post-SIGHUP). $1 = phase label.
assert_pe1_routes_absent() {
    local label=${1:?}
    local t4 ead_es ead_evi t2
    t4=$(vtep_route_count 4 "$PE1_IP")
    ead_es=$(vtep_route_count 1 "$PE1_IP" '.ethernet_tag == "MAX_ET"')
    ead_evi=$(vtep_route_count 1 "$PE1_IP" '.ethernet_tag != "MAX_ET"')
    t2=$(vtep_route_count 2 "$PE1_IP" ".mac == \"${CE_MAC}\"")
    if [ "$t4" -eq 0 ] && [ "$ead_es" -eq 0 ] && [ "$ead_evi" -eq 0 ] && [ "$t2" -eq 0 ]; then
        ok "$label: pe1 Type 4 / EAD-per-ES / EAD-per-EVI / Type 2 all absent from the vtep RIB"
    else
        fail "$label: pe1 routes still present (t4=$t4 ead_es=$ead_es ead_evi=$ead_evi t2=$t2)"
        vtep_ctl evpn --peer "$PE1_IP" 2>/dev/null >&2 || true
    fi
}

# ---------------------------------------------------------------------------
# Phase 1 — bring-up: daemons, sessions, DF election, segment routes
# ---------------------------------------------------------------------------

resolve_grpc_addr
log "vtep (DUT/RR): $VTEP — pe1 (preferred DF): $PE1 — pe2 (backup): $PE2"

log "[phase 1] kernel topology present in each rustbgpd netns"
docker exec "$VTEP" ip -d link show "$BRIDGE" >/dev/null \
    || { fail "bridge $BRIDGE missing in vtep netns"; exit 1; }
docker exec "$PE1" ip -d link show "$VXLAN" >/dev/null \
    || { fail "VXLAN port $VXLAN missing on pe1"; exit 1; }
docker exec "$PE2" ip -d link show "$VXLAN" >/dev/null \
    || { fail "VXLAN port $VXLAN missing on pe2"; exit 1; }

log "[phase 1] waiting for rustbgpd gRPC on all three nodes..."
grpc_ready=0
for i in $(seq 1 15); do
    if grpc_health >/dev/null 2>&1; then
        ok "vtep gRPC endpoint ready (attempt $i)"
        grpc_ready=1
        break
    fi
    sleep 2
done
if [ "$grpc_ready" -ne 1 ]; then
    fail "vtep gRPC endpoint not reachable within 30s"
    print_summary
fi
wait_pe_grpc "$PE1" "pe1 (operator listener)" || print_summary
wait_pe_grpc "$PE2" "pe2 (operator listener)" || print_summary

wait_vtep_established "$PE1_IP" "vtep<->pe1 EVPN" || print_summary
wait_vtep_established "$PE2_IP" "vtep<->pe2 EVPN" || print_summary

log "[phase 1] DF election must settle on the configured preferences (pe1 200 > pe2 100)"
if wait_for_role "$PE1" df 1 60; then
    ok "pe1 elected DF (highest-preference)"
else
    fail "pe1 did not become DF within 60s"
    prom_scrape "$PE1" | grep '^evpn_df_role' >&2 || true
fi
if wait_for_role "$PE2" nondf 1 60; then
    ok "pe2 settled NonDF"
else
    fail "pe2 did not settle NonDF within 60s"
    prom_scrape "$PE2" | grep '^evpn_df_role' >&2 || true
fi

log "[phase 1] vtep RIB: segment route classes from both PEs"
for peer in "$PE1_IP" "$PE2_IP"; do
    got=$(wait_vtep_routes_at_least 4 "$peer" "true" 1 60) \
        && ok "Type 4 (ES) from $peer present ($got)" \
        || fail "Type 4 (ES) from $peer missing"
    got=$(wait_vtep_routes_at_least 1 "$peer" '.ethernet_tag == "MAX_ET"' 1 60) \
        && ok "EAD-per-ES (etag MAX_ET) from $peer present ($got)" \
        || fail "EAD-per-ES from $peer missing"
    got=$(wait_vtep_routes_at_least 1 "$peer" '.ethernet_tag != "MAX_ET"' 1 60) \
        && ok "EAD-per-EVI from $peer present ($got)" \
        || fail "EAD-per-EVI from $peer missing"
    got=$(wait_vtep_routes_at_least 3 "$peer" "true" 1 60) \
        && ok "Type 3 IMET from $peer present ($got) — flood path advertised" \
        || fail "Type 3 IMET from $peer missing"
done

# ---------------------------------------------------------------------------
# Phase 2 — traffic bootstrap + DF-only Type 2 origination + NHG shape
# ---------------------------------------------------------------------------

log "[phase 2] bootstrap hr -> CE traffic (flood via pe1, the DF; CE reply teaches pe1 the CE MAC)"
wait_ping "first hr -> CE ping reply" || print_summary

log "[phase 2] CE MAC Type 2 must originate from pe1 ONLY (DF-gated kernel learning)"
t2_pe1=$(wait_vtep_routes_at_least 2 "$PE1_IP" ".mac == \"${CE_MAC}\"" 1 60) \
    && ok "Type 2 for $CE_MAC from pe1 present ($t2_pe1)" \
    || fail "Type 2 for $CE_MAC from pe1 missing"
t2_pe2=$(vtep_route_count 2 "$PE2_IP" ".mac == \"${CE_MAC}\"")
if [ "$t2_pe2" -eq 0 ]; then
    ok "no Type 2 for $CE_MAC from pe2 (NonDF never saw a CE frame)"
else
    fail "pe2 advertised $CE_MAC while NonDF (count=$t2_pe2)"
fi
esi_on_t2=$(vtep_routes 2 "$PE1_IP" | jq -r ".[] | select(.mac == \"${CE_MAC}\") | .esi" | head -1)
if [ "$esi_on_t2" = "$ESI" ]; then
    ok "pe1's Type 2 carries the segment ESI $ESI"
else
    fail "pe1's Type 2 ESI is '$esi_on_t2' (want $ESI)"
fi

log "[phase 2] ADR-0083 receive-side shape: one-member NHG via pe1, pe2 NH pre-created standby"
group_id=""
for _ in $(seq 1 60); do
    group_id=$(ce_mac_row | grep -oE ' nhid [0-9]+' | awk '{print $2}' | head -1 || true)
    [ -n "$group_id" ] && break
    sleep 1
done
if [ -n "$group_id" ]; then
    ok "FDB row for $CE_MAC carries nhid $group_id"
else
    fail "FDB row for $CE_MAC never gained an nhid"
    rb_fdb >&2
    docker exec "$VTEP" tail -60 /var/log/rustbgpd.log >&2 || true
fi
member_id=$(nh_id_for_via "$PE1_IP")
standby_id=$(nh_id_for_via "$PE2_IP")
members=$(group_members_of "${group_id:-0}")
if [ -n "$member_id" ] && [ "$members" = "$member_id" ]; then
    ok "group ${group_id:-?} has exactly one member: $member_id (via $PE1_IP — the DF)"
else
    fail "group ${group_id:-?} members '$members' (want exactly the via-$PE1_IP NH '$member_id')"
    rb_nh >&2
fi
if [ -n "$standby_id" ] && [ "$standby_id" != "$member_id" ]; then
    ok "backup per-VTEP NH pre-created: $standby_id (via $PE2_IP)"
else
    fail "no pre-created backup NH via $PE2_IP (got '$standby_id')"
    rb_nh >&2
fi

ping_burst_ok "baseline ping burst hr -> CE (via $PE1_IP)"

# ---------------------------------------------------------------------------
# Phase 3 — authorization: drain is operator_only (ADR-0064)
# ---------------------------------------------------------------------------

log "[phase 3] observer principal must be denied the drain RPC"
observer_out=$(pe_ctl_observer "$PE1" evpn es drain "$ESI" 2>&1) && observer_rc=0 || observer_rc=$?
if [ "$observer_rc" -ne 0 ] \
    && printf '%s' "$observer_out" | grep -qi "does not have permission" \
    && printf '%s' "$observer_out" | grep -q "operator_only"; then
    ok "observer drain denied: PermissionDenied, operator_only tier surfaced (exit $observer_rc)"
else
    fail "observer drain not denied as expected (exit $observer_rc): $observer_out"
fi
if [ "$(prom_df_role "$PE1" df)" = "1" ]; then
    ok "pe1 still DF after the denied drain (handler never ran)"
else
    fail "pe1 DF role changed after a DENIED drain"
fi

log "[phase 3] operator drain of an unconfigured ESI must be NotFound"
unknown_out=$(pe_ctl "$PE1" evpn es drain "$UNKNOWN_ESI" 2>&1) && unknown_rc=0 || unknown_rc=$?
if [ "$unknown_rc" -ne 0 ] && printf '%s' "$unknown_out" | grep -qi "not found"; then
    ok "unconfigured ESI drain rejected with NotFound (exit $unknown_rc)"
else
    fail "unconfigured ESI drain not rejected as expected (exit $unknown_rc): $unknown_out"
fi

# ---------------------------------------------------------------------------
# Phase 4 — drain pe1: route withdrawal + DF handover
# ---------------------------------------------------------------------------

log "[phase 4] starting the 100ms blackout prober on hr..."
start_prober drain
sleep 2

log "[phase 4] draining ES $ESI on pe1 (operator)"
drain_json=$(pe_ctl "$PE1" evpn es drain "$ESI" -j 2>&1) && drain_rc=0 || drain_rc=$?
if [ "$drain_rc" -eq 0 ] \
    && [ "$(printf '%s' "$drain_json" | jq -r '.drained')" = "true" ] \
    && [ "$(printf '%s' "$drain_json" | jq -r '.changed')" = "true" ] \
    && [ "$(printf '%s' "$drain_json" | jq -r '.member_vni_count')" = "1" ]; then
    ok "drain applied: drained=true changed=true member_vni_count=1"
else
    fail "drain response unexpected (exit $drain_rc): $drain_json"
fi

log "[phase 4] drain idempotence: repeating the drain is a no-op"
drain2_json=$(pe_ctl "$PE1" evpn es drain "$ESI" -j 2>&1) && drain2_rc=0 || drain2_rc=$?
if [ "$drain2_rc" -eq 0 ] \
    && [ "$(printf '%s' "$drain2_json" | jq -r '.drained')" = "true" ] \
    && [ "$(printf '%s' "$drain2_json" | jq -r '.changed')" = "false" ]; then
    ok "repeat drain: drained=true changed=false (idempotent no-op)"
else
    fail "repeat drain response unexpected (exit $drain2_rc): $drain2_json"
fi

log "[phase 4] pe1's own surface shows the drain"
if docker exec "$PE1" sh -c 'grep -q "draining Ethernet Segment (operator)" /var/log/rustbgpd.log'; then
    ok "pe1 segment actor logged the operator drain"
else
    fail "pe1 drain log line missing"
fi
drained_df=$(prom_df_role "$PE1" df)
if [ "${drained_df:-_}" = "0" ]; then
    ok "pe1 df gauge dropped to 0 (drained PE exits its own election)"
else
    fail "pe1 df gauge is '$drained_df' after the drain (want 0)"
fi

log "[phase 4] vtep RIB: pe1's four route classes withdraw, pe2's stay"
got=$(wait_vtep_routes_gone 4 "$PE1_IP" "true" 60) \
    && ok "pe1 Type 4 withdrawn from the vtep" \
    || fail "pe1 Type 4 still present after 60s ($got)"
got=$(wait_vtep_routes_gone 1 "$PE1_IP" "true" 60) \
    && ok "pe1 EAD-per-ES + EAD-per-EVI withdrawn from the vtep" \
    || fail "pe1 EAD routes still present after 60s ($got)"
got=$(wait_vtep_routes_gone 2 "$PE1_IP" "true" 60) \
    && ok "pe1 Type 2 routes withdrawn from the vtep" \
    || fail "pe1 Type 2 routes still present after 60s ($got)"
assert_pe1_routes_absent "post-drain"
pe2_t4=$(vtep_route_count 4 "$PE2_IP")
pe2_ead=$(vtep_route_count 1 "$PE2_IP")
if [ "$pe2_t4" -ge 1 ] && [ "$pe2_ead" -ge 2 ]; then
    ok "pe2's Type 4 + EAD routes intact across pe1's drain (t4=$pe2_t4 ead=$pe2_ead)"
else
    fail "pe2's routes disturbed by pe1's drain (t4=$pe2_t4 ead=$pe2_ead)"
fi

log "[phase 4] pe2 must promote to DF (pe1's Type 4 left the candidate set)"
if wait_for_role "$PE2" df 1 60; then
    ok "pe2 promoted to DF"
else
    fail "pe2 did not promote to DF within 60s"
    prom_scrape "$PE2" | grep '^evpn_df_role' >&2 || true
fi

# Receive-side swap transient: ordering-dependent (the vtep may
# process pe1's EAD-per-ES withdrawal before the Type 2 withdrawal,
# firing one backup swap before the row teardown). Informational only.
swaps=$(prom_value "$VTEP" "evpn_single_active_backup_swaps_total")
log "  INFO: vtep evpn_single_active_backup_swaps_total=${swaps:-absent} after the drain (transient, not asserted)"

# ---------------------------------------------------------------------------
# Phase 5 — service handover: CE MAC re-resolves toward pe2
# ---------------------------------------------------------------------------

log "[phase 5] pe2 must learn the CE MAC via the flood path and take over Type 2 origination"
got=$(wait_vtep_routes_at_least 2 "$PE2_IP" ".mac == \"${CE_MAC}\"" 1 90) \
    && ok "Type 2 for $CE_MAC now originated by pe2 ($got)" \
    || fail "pe2 never originated the CE MAC within 90s"

handover_done=0
for _ in $(seq 1 60); do
    # Strict: the egress set must be EXACTLY {pe2}. A row resolving to
    # both PEs would mask a single-active receive-side regression.
    if [ "$(ce_mac_egress_ips | sort -u | tr '\n' ' ' | sed 's/ $//')" = "$PE2_IP" ]; then
        handover_done=1
        break
    fi
    sleep 1
done
if [ "$handover_done" -eq 1 ]; then
    ok "vtep FDB row for $CE_MAC resolves toward exactly $PE2_IP (handover complete)"
    log "  row: $(ce_mac_row)"
else
    fail "vtep FDB row for $CE_MAC never resolved toward $PE2_IP"
    rb_fdb >&2
    rb_nh >&2
    docker exec "$VTEP" tail -60 /var/log/rustbgpd.log >&2 || true
fi

wait_ping "hr -> CE ping reply via pe2" || true
ping_burst_ok "post-handover ping burst hr -> CE (via $PE2_IP)"

# Let the prober record a clean recovery segment, then measure.
sleep 3
stop_prober drain
blackout_ms=$(prober_max_gap_ms drain)
log "=================================================================="
log " MEASURED HANDOVER BLACKOUT WINDOW: ${blackout_ms} ms"
log "   (max consecutive ${PROBE_INTERVAL_MS}ms probes lost across the"
log "   drain; the drained PE's stale known-unicast path — the BUM-only"
log "   enforcement limit — typically keeps this near zero while the"
log "   control-plane handover completes behind it.)"
log "=================================================================="
if [ "$blackout_ms" -lt "$BLACKOUT_BOUND_MS" ]; then
    ok "blackout ${blackout_ms}ms < ${BLACKOUT_BOUND_MS}ms sanity bound"
else
    fail "blackout ${blackout_ms}ms >= ${BLACKOUT_BOUND_MS}ms — service did not hand over"
fi

# ---------------------------------------------------------------------------
# Phase 6 — SIGHUP while drained: the reload must not resurrect routes
# ---------------------------------------------------------------------------

log "[phase 6] config reload on pe1 WHILE DRAINED (ADR-0084 decision 3)"
# Make the reload non-trivial: add a bridge-less L2VNI, forcing a live
# EVPN runtime apply (the snapshot-republish path the drain must
# survive). The ES itself stays configured, so its drain entry must
# not be GC'd. On a re-run against a live topology the marker already
# exists — fall back to an identical-config SIGHUP (weaker but valid).
if docker exec "$PE1" sh -c "grep -q '$SIGHUP_MARKER' /etc/rustbgpd/config.toml"; then
    log "  (marker already present — re-run; sending identical-config SIGHUP)"
else
    docker exec -i "$PE1" sh -c "cat >> /etc/rustbgpd/config.toml" <<EOF

# $SIGHUP_MARKER: driver-appended bridge-less L2VNI so the SIGHUP
# performs a real EVPN runtime apply while ES $ESI is drained.
[[evpn_instances]]
vni = 200
rd = "10.0.1.2:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.1.2"
EOF
fi
docker exec "$PE1" sh -c 'kill -HUP "$(cat /var/run/rustbgpd.pid)"' \
    && ok "SIGHUP delivered to pe1's captured rustbgpd PID" \
    || fail "could not SIGHUP pe1"

reload_applied=0
for _ in $(seq 1 30); do
    if pe_ctl "$PE1" evpn instances 2>/dev/null | grep -qE "vni=200( |$)"; then
        reload_applied=1
        break
    fi
    sleep 1
done
if [ "$reload_applied" -eq 1 ]; then
    ok "reload demonstrably applied (L2VNI 200 live in 'evpn instances')"
else
    fail "reload did not apply L2VNI 200 within 30s"
    docker exec "$PE1" tail -40 /var/log/rustbgpd.log >&2 || true
fi

# Settle, then assert the drain survived the republish.
sleep 5
assert_pe1_routes_absent "post-SIGHUP (still drained)"
post_hup_df=$(prom_df_role "$PE1" df)
if [ "${post_hup_df:-_}" = "0" ]; then
    ok "pe1 df gauge still 0 after the reload (drain survived)"
else
    fail "pe1 df gauge is '$post_hup_df' after the reload (drain resurrected?)"
fi

# ---------------------------------------------------------------------------
# Phase 7 — undrain: routes return, pe1 re-wins DF, service holds
# ---------------------------------------------------------------------------

log "[phase 7] starting the undrain re-pin prober on hr..."
start_prober undrain
sleep 2

log "[phase 7] undraining ES $ESI on pe1 (operator)"
undrain_json=$(pe_ctl "$PE1" evpn es undrain "$ESI" -j 2>&1) && undrain_rc=0 || undrain_rc=$?
if [ "$undrain_rc" -eq 0 ] \
    && [ "$(printf '%s' "$undrain_json" | jq -r '.drained')" = "false" ] \
    && [ "$(printf '%s' "$undrain_json" | jq -r '.changed')" = "true" ]; then
    ok "undrain applied: drained=false changed=true"
else
    fail "undrain response unexpected (exit $undrain_rc): $undrain_json"
fi
undrain2_json=$(pe_ctl "$PE1" evpn es undrain "$ESI" -j 2>&1) && undrain2_rc=0 || undrain2_rc=$?
if [ "$undrain2_rc" -eq 0 ] \
    && [ "$(printf '%s' "$undrain2_json" | jq -r '.changed')" = "false" ]; then
    ok "repeat undrain: changed=false (idempotent no-op)"
else
    fail "repeat undrain response unexpected (exit $undrain2_rc): $undrain2_json"
fi

log "[phase 7] vtep RIB: segment route classes return from pe1"
got=$(wait_vtep_routes_at_least 4 "$PE1_IP" "true" 1 60) \
    && ok "pe1 Type 4 re-originated ($got)" \
    || fail "pe1 Type 4 did not return"
got=$(wait_vtep_routes_at_least 1 "$PE1_IP" '.ethernet_tag == "MAX_ET"' 1 60) \
    && ok "pe1 EAD-per-ES re-originated ($got)" \
    || fail "pe1 EAD-per-ES did not return"
got=$(wait_vtep_routes_at_least 1 "$PE1_IP" '.ethernet_tag != "MAX_ET"' 1 60) \
    && ok "pe1 EAD-per-EVI re-originated ($got)" \
    || fail "pe1 EAD-per-EVI did not return"

log "[phase 7] revertive preference election: pe1 re-wins DF"
if wait_for_role "$PE1" df 1 60; then
    ok "pe1 re-elected DF"
else
    fail "pe1 did not re-win DF within 60s"
    prom_scrape "$PE1" | grep '^evpn_df_role' >&2 || true
fi
if wait_for_role "$PE2" nondf 1 60; then
    ok "pe2 demoted to NonDF"
else
    fail "pe2 did not demote within 60s"
fi

# The CE speaks on maintenance exit (one ARP broadcast to an unused
# address — the GARP-after-maintenance pattern real CEs emit). This
# floods out both CE legs and re-teaches both PEs' kernel bridges
# that the CE MAC is local on their ACs. It is required because the
# PE remote-MAC projection has no same-ESI local bias (still open,
# deferred to the ES↔interface binding design): while pe1 was
# drained, pe2's Type 2 for the CE MAC was programmed as a REMOTE
# row on pe1's bridge, usurping its kernel-learned local AC row
# (real EVPN implementations never point an own-segment MAC at the
# ES peer). The second gap this proof originally surfaced — that
# in-place port move emitting no local-delete observation, so pe1's
# cache kept claiming the MAC and the undrain replayed a stale
# Type 2 — is FIXED (the classifier surfaces the VXLAN-port
# RTM_NEWNEIGH and the originator drops the stale claim, live or
# drained; see the topology header). Without CE chatter pe1 now
# simply has no Type 2 for the CE MAC after undrain; with it, pe1's
# kernel relearns the MAC on the AC (another in-place move, observed
# as a local learn), pe1 re-advertises with a bumped RFC 7432 §15
# mobility sequence, and the steady state below holds — the asserts
# were written to survive exactly this fix (fresh relearn instead of
# stale replay).
log "[phase 7] CE maintenance-exit broadcast (ARP for an unused address)"
docker exec "$CE" ping -c 1 -W 1 192.168.66.99 >/dev/null 2>&1 || true

log "[phase 7] CE MAC Type 2 from pe1 present after undrain (fresh kernel relearn after the CE broadcast)"
got=$(wait_vtep_routes_at_least 2 "$PE1_IP" ".mac == \"${CE_MAC}\"" 1 60) \
    && ok "pe1 Type 2 for $CE_MAC present after undrain ($got)" \
    || fail "pe1 Type 2 for $CE_MAC did not return"

wait_ping "hr -> CE ping reply after undrain" || true
ping_burst_ok "post-undrain ping burst hr -> CE"
sleep 2
stop_prober undrain
repin_ms=$(prober_max_gap_ms undrain)
log "  INFO: undrain re-pin worst gap: ${repin_ms} ms (informational; both PEs advertise the CE MAC during the revert window)"
log "  INFO: post-undrain CE MAC egress set: $(ce_mac_egress_ips | tr '\n' ' ')"

# ---------------------------------------------------------------------------
# Phase 8 — foreign state survived the whole cycle
# ---------------------------------------------------------------------------

if rb_fdb | grep -qi "$PRELOADED_FOREIGN_MAC"; then
    ok "pre-loaded foreign FDB row $PRELOADED_FOREIGN_MAC untouched"
else
    fail "pre-loaded foreign FDB row $PRELOADED_FOREIGN_MAC was deleted"
    rb_fdb >&2
fi
flood_rows=$(rb_fdb | grep -c "^00:00:00:00:00:00" || true)
if [ "${flood_rows:-0}" -eq 2 ]; then
    ok "both static all-zero flood entries untouched"
else
    fail "static flood entries disturbed (count=$flood_rows, want 2)"
    rb_fdb >&2
fi

print_summary
