#!/usr/bin/env bash
# M67 — ADR-0085 link-driven Ethernet Segment drain failover and
# held-off recovery, rustbgpd on BOTH sides. No RPC in the failover
# path.
#
# M66 proved the ADR-0084 drain primitive with the operator RPC as
# the stimulus; this job proves the production trigger end-to-end: a
# real attachment-circuit failure on the active PE. pe1 binds its
# CE-facing AC (`interface = "eth2"`, `recovery_delay_secs = 5`), so
# `ip link set eth2 down` INSIDE pe1 — the binding watches pe1's own
# ifindex carrier, which is why the injection point is pe1's end of
# the veth (the CE side drops carrier too: cable-pull semantics) —
# must drive, automatically: the `link` drain reason
# (`evpn_es_drained{esi, reason="link"}` gauge), the RFC 7432 §8.2
# withdrawal wire shape (Type 4 + EAD-per-ES + EAD-per-EVI + the
# member VNI's Type 2s gone from the vtep), pe2's DF promotion, the
# receive-side handover, and service continuity. Carrier return must
# be HELD for `recovery_delay_secs` before origination resumes
# (RFC 8584 §3 recovery damping), a flap inside the window must
# re-arm the hold (decision 3), and the operator/link drain reasons
# must compose so neither trigger overrides the other (decision 2).
#
# Asserts (hard on mechanism, informational on timing — the
# M63/M65/M66 philosophy; the ONE strict-ish timing assert is the
# hold-off itself, framed as "the gauge is still 1 at up+3 s", not
# as an exact-duration measure — recovery_delay_secs=5 gives 2 s of
# margin):
#
# 1. Bring-up/steady state (M66 phase 1-2 shape, with deliberately
#    longer converge waits — waiting longer at bring-up is free, and
#    a slow runner must not bleed into the timed phases): sessions,
#    pe1 DF / pe2 NonDF, all route classes from both PEs, CE-MAC
#    Type 2 from pe1 only behind the ADR-0083 one-member NHG, pe1's
#    carrier monitor demonstrably armed (log line), and every
#    evpn_es_drained gauge 0 (an absent series counts as 0 — the
#    series is only instantiated on the first transition).
# 2. AC failure: link gauge {reason="link"} -> 1 (operator stays 0),
#    the coordinator's link-drain log line, df gauge -> 0, all four
#    route classes withdrawn while pe2's survive, pe2 promotes,
#    handover to exactly pe2 (strict egress set), prober recovers
#    (blackout informational + generous < 30 s bound).
# 3. Recovery hold-off: after `ip link set eth2 up` the link gauge
#    must still read 1 on every sub-second sample through up+3 s
#    (early release = hold-off broken), then drop to 0 (release
#    latency logged, ~5 s expected), then pe1's routes return, pe1
#    re-wins DF revertively, and — after the CE's maintenance-exit
#    broadcast, the M66-established relearn stimulus — pe1's Type 2
#    and end-to-end service return.
# 4. Flap damping: down-up-down-up inside the hold-off window. The
#    gauge stays 1 throughout, INCLUDING at a sample point past the
#    FIRST up's would-be deadline (proving the re-arm cancelled it),
#    routes stay withdrawn, and recovery completes only after the
#    LAST up + hold-off.
# 5. Operator composition: operator drain while the link is up ->
#    drained (reasons=[operator]); a full link down/up cycle behind
#    the hold-off flips only the link gauge while the ES STAYS
#    withdrawn (operator reason holds); operator undrain -> both
#    gauges 0, routes return. Neither trigger overrides the other.
# 6. Foreign state: the pre-loaded foreign FDB row and the static
#    all-zero flood entries survive the whole cycle. The script is
#    re-runnable against a live topology (end state == start state).
#
# Single-active whole-port AC gate (the close of the M66-era
# "BUM-flood-only enforcement" limit for bound single-active
# segments): the non-DF PE's bound AC bridge port is held in STP
# state `disabled` — ALL traffic blocked, known unicast included —
# and re-opened on DF promotion. Asserted at three points: steady
# state (pe2 disabled / pe1 forwarding), post-failover (promoted pe2
# forwarding — a prerequisite for the flood-path relearn), and
# post-revert (demoted pe2 re-blocked). The gate needs the
# `interface` binding for the port handle; unbound segments remain
# BUM-flood-only.
#
# Usage:
#   docker build --target dev -t rustbgpd:dev .
#   containerlab deploy -t tests/interop/m67-evpn-link-drain-failover.clab.yml
#   bash tests/interop/scripts/test-m67-evpn-link-drain-failover.sh
#   containerlab destroy -t tests/interop/m67-evpn-link-drain-failover.clab.yml

set -eu

TOPO="m67-evpn-link-drain-failover"
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
CE_MAC="02:ce:ce:ce:ce:01"
CE_HOST_IP="192.168.67.10"
CE_RECOVERY_BROADCAST_IP="192.168.67.99"
# pe1's bound attachment circuit (must match `interface` in
# rustbgpd-m67-pe1.toml). The failure injection target.
AC_IF="eth2"
# Must match `recovery_delay_secs` in the PE configs.
RECOVERY_DELAY_SECS="5"
# The strict-ish hold-off sample window: the link gauge must still be
# 1 on every sample through this many ms after carrier return. 3 s
# against a 5 s hold-off leaves 2 s of margin for scrape latency.
HOLD_SAMPLE_WINDOW_MS="3000"
# Pre-loaded by start-rustbgpd-vtep.sh before rustbgpd starts.
PRELOADED_FOREIGN_MAC="02:99:99:99:99:99"
PROBE_INTERVAL_MS="100"
# Hard sanity bound on the measured blackout. Generous: the failover
# is multi-stage (carrier event + drain + withdrawal propagation + DF
# re-election + BUM-flood gate flip on pe2 + flood-path relearn) and,
# unlike M66, pe1's AC is REALLY dead so there is no stale-unicast
# path hiding the gap. Mechanism asserts are strict; the bound only
# catches a hang.
BLACKOUT_BOUND_MS="30000"
PROBER_PREFIX="m67"
VTEP_ROUTE_WAIT_ATTEMPTS="90"
ROLE_WAIT_ATTEMPTS="90"
PE_GRPC_ATTEMPTS="30"
VTEP_ESTABLISHED_ATTEMPTS="60"
WAIT_PING_ATTEMPTS="90"

OPERATOR_TOKEN_FILE="/etc/rustbgpd/grpc-operator.token"

# ---------------------------------------------------------------------------
# Shared helpers live in test-lib.sh; M67-specific assertions stay below.
# ---------------------------------------------------------------------------

# Assert all four pe1 route classes are ABSENT from the vtep RIB
# right now. $1 = phase label.
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

# Wait for pe1's three segment route classes to return to the vtep
# RIB after a recovery. $1 = phase label.
assert_pe1_segment_routes_return() {
    local label=${1:?}
    local got
    got=$(wait_vtep_routes_at_least 4 "$PE1_IP" "true" 1 90) \
        && ok "$label: pe1 Type 4 re-originated ($got)" \
        || fail "$label: pe1 Type 4 did not return"
    got=$(wait_vtep_routes_at_least 1 "$PE1_IP" '.ethernet_tag == "MAX_ET"' 1 90) \
        && ok "$label: pe1 EAD-per-ES re-originated ($got)" \
        || fail "$label: pe1 EAD-per-ES did not return"
    got=$(wait_vtep_routes_at_least 1 "$PE1_IP" '.ethernet_tag != "MAX_ET"' 1 90) \
        && ok "$label: pe1 EAD-per-EVI re-originated ($got)" \
        || fail "$label: pe1 EAD-per-EVI did not return"
}

# Wait for pe1's four route classes to leave the vtep RIB after a
# drain trigger. $1 = phase label.
assert_pe1_routes_withdraw() {
    local label=${1:?}
    local got
    got=$(wait_vtep_routes_gone 4 "$PE1_IP" "true" 90) \
        && ok "$label: pe1 Type 4 withdrawn from the vtep" \
        || fail "$label: pe1 Type 4 still present after 90s ($got)"
    got=$(wait_vtep_routes_gone 1 "$PE1_IP" "true" 90) \
        && ok "$label: pe1 EAD-per-ES + EAD-per-EVI withdrawn from the vtep" \
        || fail "$label: pe1 EAD routes still present after 90s ($got)"
    got=$(wait_vtep_routes_gone 2 "$PE1_IP" "true" 90) \
        && ok "$label: pe1 Type 2 routes withdrawn from the vtep" \
        || fail "$label: pe1 Type 2 routes still present after 90s ($got)"
}

# ---------------------------------------------------------------------------
# Phase 1 — bring-up + steady state (generous converge waits BEFORE
# any failure: a slow runner must stall here, not in the timed
# phases — waiting longer at bring-up is free)
# ---------------------------------------------------------------------------

resolve_grpc_addr
log "vtep (DUT/RR): $VTEP — pe1 (preferred DF, bound AC $AC_IF): $PE1 — pe2 (backup): $PE2"

log "[phase 1] kernel topology present in each rustbgpd netns"
docker exec "$VTEP" ip -d link show "$BRIDGE" >/dev/null \
    || { fail "bridge $BRIDGE missing in vtep netns"; exit 1; }
docker exec "$PE1" ip -d link show "$VXLAN" >/dev/null \
    || { fail "VXLAN port $VXLAN missing on pe1"; exit 1; }
docker exec "$PE2" ip -d link show "$VXLAN" >/dev/null \
    || { fail "VXLAN port $VXLAN missing on pe2"; exit 1; }

log "[phase 1] waiting for rustbgpd gRPC on all three nodes..."
grpc_ready=0
for i in $(seq 1 30); do
    if grpc_health >/dev/null 2>&1; then
        ok "vtep gRPC endpoint ready (attempt $i)"
        grpc_ready=1
        break
    fi
    sleep 2
done
if [ "$grpc_ready" -ne 1 ]; then
    fail "vtep gRPC endpoint not reachable within 60s"
    print_summary
fi
wait_pe_grpc "$PE1" "pe1 (operator listener)" || print_summary
wait_pe_grpc "$PE2" "pe2 (operator listener)" || print_summary

wait_vtep_established "$PE1_IP" "vtep<->pe1 EVPN" || print_summary
wait_vtep_established "$PE2_IP" "vtep<->pe2 EVPN" || print_summary

# Re-run detection: the evpn_es_drained series is only instantiated on
# the first drain transition and persists at 0 afterwards, so its
# presence on pe1 means a prior drain cycle already ran against this
# topology. After a full cycle BOTH PEs may legitimately advertise the
# CE MAC on the shared ESI (RFC 7432 aliasing — the CE has spoken on
# both legs), so the fresh-bring-up "Type 2 from the DF only" pin is
# downgraded to informational on a re-run; everything else stays
# strict.
RERUN=0
if prom_scrape "$PE1" | grep -q '^evpn_es_drained'; then
    RERUN=1
    log "  INFO: prior drain cycle detected (evpn_es_drained series present) — re-run mode"
fi

log "[phase 1] ADR-0085 carrier monitor must be armed on pe1 (the binding's eventing path)"
monitor_armed=0
for _ in $(seq 1 30); do
    if docker exec "$PE1" sh -c 'grep -q "link carrier monitor started" /var/log/rustbgpd.log' 2>/dev/null; then
        monitor_armed=1
        break
    fi
    sleep 1
done
if [ "$monitor_armed" -eq 1 ]; then
    ok "pe1 link carrier monitor started for the ES interface binding"
else
    fail "pe1 link carrier monitor never started (binding not armed?)"
    docker exec "$PE1" tail -60 /var/log/rustbgpd.log >&2 || true
fi

log "[phase 1] DF election must settle on the configured preferences (pe1 200 > pe2 100)"
if wait_for_role "$PE1" df 1 90; then
    ok "pe1 elected DF (highest-preference)"
else
    fail "pe1 did not become DF within 90s"
    prom_scrape "$PE1" | grep '^evpn_df_role' >&2 || true
fi
if wait_for_role "$PE2" nondf 1 90; then
    ok "pe2 settled NonDF"
else
    fail "pe2 did not settle NonDF within 90s"
    prom_scrape "$PE2" | grep '^evpn_df_role' >&2 || true
fi

log "[phase 1] no drain reason held at steady state (link up, no operator drain)"
assert_drain_gauge "$PE1" link 0 "pe1 link drain gauge clear at steady state"
assert_drain_gauge "$PE1" operator 0 "pe1 operator drain gauge clear at steady state"
assert_drain_gauge "$PE2" link 0 "pe2 link drain gauge clear at steady state"

log "[phase 1] single-active AC gate: the non-DF blocks its whole AC port, the DF forwards"
assert_ac_gate "$PE2" disabled "pe2 (NonDF) AC port blocked"
assert_ac_gate "$PE1" forwarding "pe1 (DF) AC port forwarding"

log "[phase 1] vtep RIB: segment route classes from both PEs"
for peer in "$PE1_IP" "$PE2_IP"; do
    got=$(wait_vtep_routes_at_least 4 "$peer" "true" 1 90) \
        && ok "Type 4 (ES) from $peer present ($got)" \
        || fail "Type 4 (ES) from $peer missing"
    got=$(wait_vtep_routes_at_least 1 "$peer" '.ethernet_tag == "MAX_ET"' 1 90) \
        && ok "EAD-per-ES (etag MAX_ET) from $peer present ($got)" \
        || fail "EAD-per-ES from $peer missing"
    got=$(wait_vtep_routes_at_least 1 "$peer" '.ethernet_tag != "MAX_ET"' 1 90) \
        && ok "EAD-per-EVI from $peer present ($got)" \
        || fail "EAD-per-EVI from $peer missing"
    got=$(wait_vtep_routes_at_least 3 "$peer" "true" 1 90) \
        && ok "Type 3 IMET from $peer present ($got) — flood path advertised" \
        || fail "Type 3 IMET from $peer missing"
done

log "[phase 1] bootstrap hr -> CE traffic (flood via pe1, the DF; CE reply teaches pe1 the CE MAC)"
wait_ping "first hr -> CE ping reply" 90 || print_summary

log "[phase 1] CE MAC Type 2 must originate from pe1 ONLY (DF-gated kernel learning)"
t2_pe1=$(wait_vtep_routes_at_least 2 "$PE1_IP" ".mac == \"${CE_MAC}\"" 1 120) \
    && ok "Type 2 for $CE_MAC from pe1 present ($t2_pe1)" \
    || { fail "Type 2 for $CE_MAC from pe1 missing"; docker exec "$PE1" tail -60 /var/log/rustbgpd.log >&2 || true; }
t2_pe2=$(vtep_route_count 2 "$PE2_IP" ".mac == \"${CE_MAC}\"")
if [ "$RERUN" -eq 1 ]; then
    log "  INFO: re-run — pe2 Type 2 count for $CE_MAC is $t2_pe2 (a prior cycle's CE broadcasts taught pe2's AC too; shared-ESI co-advertisement is legitimate aliasing, DF-only pin skipped)"
elif [ "$t2_pe2" -eq 0 ]; then
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

log "[phase 1] ADR-0083 receive-side shape: one-member NHG via pe1, pe2 NH pre-created standby"
group_id=""
for _ in $(seq 1 120); do
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
if [ "$RERUN" -eq 1 ]; then
    # Re-run: with both PEs co-advertising the CE MAC after a prior
    # cycle, the row may legitimately still resolve toward pe2 (no
    # EAD event since the last cycle forces a swap back) — the strict
    # member pin is a fresh-bring-up property. The failover phases
    # below stay strict and re-pin it.
    log "  INFO: re-run — group ${group_id:-?} members '$members' (via-$PE1_IP NH '$member_id', via-$PE2_IP NH '$standby_id'); one-member-is-the-DF pin skipped"
elif [ -n "$member_id" ] && [ "$members" = "$member_id" ]; then
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
# Phase 2 — AC failure on the active PE: the link, not an RPC, drives
# the drain, the wire shape, and the handover
# ---------------------------------------------------------------------------

log "[phase 2] starting the 100ms blackout prober on hr..."
start_prober fail
sleep 2

log "[phase 2] AC FAILURE: ip link set $AC_IF down inside pe1 (cable-pull semantics — the CE leg loses carrier too)"
pe1_ac_down \
    && ok "pe1 AC $AC_IF admin-down injected (blackout begins)" \
    || fail "could not down pe1's AC"

log "[phase 2] pe1 must drain itself: reason=link, no operator involvement"
if wait_drain_gauge "$PE1" link 1 15; then
    ok "pe1 evpn_es_drained{reason=\"link\"} -> 1 (carrier loss detected and drained)"
else
    fail "pe1 link drain gauge never reached 1 within 15s of the AC failure"
    prom_scrape "$PE1" | grep '^evpn_es_drained' >&2 || true
    docker exec "$PE1" tail -60 /var/log/rustbgpd.log >&2 || true
fi
assert_drain_gauge "$PE1" operator 0 "operator reason untouched by the link failure"
if docker exec "$PE1" sh -c 'grep -q "attachment-circuit carrier changed Ethernet Segment link drain" /var/log/rustbgpd.log'; then
    ok "pe1 link-drain coordinator logged the carrier-driven drain"
else
    fail "pe1 link-drain coordinator log line missing"
fi
drained_df=$(prom_df_role "$PE1" df)
if [ "${drained_df:-_}" = "0" ]; then
    ok "pe1 df gauge dropped to 0 (drained PE exits its own election)"
else
    fail "pe1 df gauge is '$drained_df' after the link drain (want 0)"
fi

log "[phase 2] vtep RIB: pe1's four route classes withdraw (RFC 7432 §8.2 shape), pe2's stay"
assert_pe1_routes_withdraw "post-AC-failure"
assert_pe1_routes_absent "post-AC-failure"
pe2_t4=$(vtep_route_count 4 "$PE2_IP")
pe2_ead=$(vtep_route_count 1 "$PE2_IP")
if [ "$pe2_t4" -ge 1 ] && [ "$pe2_ead" -ge 2 ]; then
    ok "pe2's Type 4 + EAD routes intact across pe1's link drain (t4=$pe2_t4 ead=$pe2_ead)"
else
    fail "pe2's routes disturbed by pe1's link drain (t4=$pe2_t4 ead=$pe2_ead)"
fi

log "[phase 2] pe2 must promote to DF (pe1's Type 4 left the candidate set)"
if wait_for_role "$PE2" df 1 90; then
    ok "pe2 promoted to DF"
else
    fail "pe2 did not promote to DF within 90s"
    prom_scrape "$PE2" | grep '^evpn_df_role' >&2 || true
fi

log "[phase 2] single-active AC gate: promoted pe2 must open its AC port (prerequisite for the flood-path relearn below)"
assert_ac_gate "$PE2" forwarding "pe2 (promoted DF) AC port forwarding"

log "[phase 2] service handover: pe2 learns the CE MAC via the flood path and takes over Type 2 origination"
got=$(wait_vtep_routes_at_least 2 "$PE2_IP" ".mac == \"${CE_MAC}\"" 1 120) \
    && ok "Type 2 for $CE_MAC now originated by pe2 ($got)" \
    || fail "pe2 never originated the CE MAC within 120s"

handover_done=0
for _ in $(seq 1 90); do
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

wait_ping "hr -> CE ping reply via pe2" 90 || true
ping_burst_ok "post-failover ping burst hr -> CE (via $PE2_IP)"

# Let the prober record a clean recovery segment, then measure.
sleep 3
stop_prober fail
blackout_ms=$(prober_max_gap_ms fail)
log "=================================================================="
log " MEASURED LINK-FAILURE FAILOVER BLACKOUT: ${blackout_ms} ms"
log "   (max consecutive ${PROBE_INTERVAL_MS}ms probes lost across the"
log "   AC failure. Unlike M66's RPC drain, pe1's AC is REALLY dead, so"
log "   this is the genuine end-to-end failover: carrier event -> drain"
log "   -> withdrawal -> DF promotion -> flood relearn -> handover.)"
log "=================================================================="
if [ "$blackout_ms" -lt "$BLACKOUT_BOUND_MS" ]; then
    ok "blackout ${blackout_ms}ms < ${BLACKOUT_BOUND_MS}ms sanity bound"
else
    fail "blackout ${blackout_ms}ms >= ${BLACKOUT_BOUND_MS}ms — service did not fail over"
fi

# ---------------------------------------------------------------------------
# Phase 3 — recovery hold-off: carrier return must NOT undrain for
# recovery_delay_secs (the one strict-ish timing assert)
# ---------------------------------------------------------------------------

log "[phase 3] starting the recovery re-pin prober on hr..."
start_prober recover
sleep 2

log "[phase 3] AC RECOVERY: ip link set $AC_IF up inside pe1 (hold-off ${RECOVERY_DELAY_SECS}s arms)"
up_ms=$(now_ms)
pe1_ac_up \
    && ok "pe1 AC $AC_IF admin-up injected" \
    || fail "could not bring pe1's AC back up"

# Strict-ish: every sample through up+${HOLD_SAMPLE_WINDOW_MS}ms must
# still read 1 — an early release breaks ADR-0085 decision 3. Framed
# as "still held at t+3s", not an exact-duration measure: the 5s
# hold-off leaves 2s of margin for scrape latency. Anti-vacuity is a
# DEEP sample (one all-good read at elapsed >= ${HOLD_DEEP_MS}ms),
# not a raw sample count: on a loaded runner each docker-exec scrape
# can take >600ms, so a count requirement measures the runner's exec
# throughput instead of the hold-off (observed: 3 samples, all '1',
# assert failed — the invariant HELD).
HOLD_DEEP_MS="2000"
hold_held=1
hold_deep=0
hold_samples=0
while :; do
    elapsed=$(( $(now_ms) - up_ms ))
    [ "$elapsed" -ge "$HOLD_SAMPLE_WINDOW_MS" ] && break
    gauge=$(drain_gauge "$PE1" link)
    hold_samples=$((hold_samples + 1))
    if [ "$gauge" != "1" ]; then
        hold_held=0
        break
    fi
    [ "$elapsed" -ge "$HOLD_DEEP_MS" ] && hold_deep=1
    sleep 0.2
done
if [ "$hold_held" -eq 1 ] && [ "$hold_deep" -eq 1 ]; then
    ok "recovery hold-off held: link gauge 1 on all $hold_samples samples through up+${HOLD_SAMPLE_WINDOW_MS}ms (deep sample >= ${HOLD_DEEP_MS}ms)"
elif [ "$hold_held" -eq 1 ]; then
    fail "recovery hold-off vacuous: $hold_samples samples all read 1 but none landed at >= ${HOLD_DEEP_MS}ms (runner too slow to sample the window)"
else
    fail "recovery hold-off broken: gauge read '${gauge:-?}' at ${elapsed}ms, before up+${HOLD_SAMPLE_WINDOW_MS}ms (samples=$hold_samples)"
    docker exec "$PE1" tail -40 /var/log/rustbgpd.log >&2 || true
fi
# The mid-hold-off route check is only meaningful while the hold-off
# is still pending: on a loaded runner the sampling loop plus the RIB
# queries can overrun the ${RECOVERY_DELAY_SECS}s hold-off itself, at
# which point routes legitimately return and the assert would blame
# the daemon for the runner's latency. Phase 3's release check below
# still proves the routes return only after the hold-off.
mid_elapsed=$(( $(now_ms) - up_ms ))
if [ "$mid_elapsed" -lt $(( RECOVERY_DELAY_SECS * 1000 - 500 )) ]; then
    assert_pe1_routes_absent "mid-hold-off (carrier back, still drained)"
else
    log "  SKIP mid-hold-off route check: ${mid_elapsed}ms already elapsed (runner latency ate the window)"
fi

log "[phase 3] ...then the link reason must release"
release_ok=0
for _ in $(seq 1 30); do
    if [ "$(drain_gauge "$PE1" link)" = "0" ]; then
        release_ok=1
        break
    fi
    sleep 0.5
done
release_ms=$(( $(now_ms) - up_ms ))
if [ "$release_ok" -eq 1 ]; then
    ok "link drain released after the hold-off (observed ~${release_ms}ms after carrier return; configured $((RECOVERY_DELAY_SECS * 1000))ms)"
else
    fail "link drain never released within ${release_ms}ms of carrier return"
    prom_scrape "$PE1" | grep '^evpn_es_drained' >&2 || true
fi

log "[phase 3] pe1's segment routes return and pe1 re-wins DF (revertive preference)"
assert_pe1_segment_routes_return "post-recovery"
if wait_for_role "$PE1" df 1 90; then
    ok "pe1 re-elected DF"
else
    fail "pe1 did not re-win DF within 90s"
    prom_scrape "$PE1" | grep '^evpn_df_role' >&2 || true
fi
if wait_for_role "$PE2" nondf 1 90; then
    ok "pe2 demoted to NonDF"
else
    fail "pe2 did not demote within 90s"
fi

log "[phase 3] single-active AC gate re-engages after the revert: demoted pe2 blocks, recovered pe1 forwards"
assert_ac_gate "$PE2" disabled "pe2 (demoted NonDF) AC port re-blocked"
assert_ac_gate "$PE1" forwarding "pe1 (re-elected DF) AC port forwarding"

log "[phase 3] CE maintenance-exit broadcast (pe1's AC re-learn stimulus, M66 pattern)"
ce_recovery_broadcast
got=$(wait_vtep_routes_at_least 2 "$PE1_IP" ".mac == \"${CE_MAC}\"" 1 120) \
    && ok "pe1 Type 2 for $CE_MAC present after recovery ($got)" \
    || fail "pe1 Type 2 for $CE_MAC did not return"

wait_ping "hr -> CE ping reply after recovery" 90 || true
ping_burst_ok "post-recovery ping burst hr -> CE"
sleep 2
stop_prober recover
repin_ms=$(prober_max_gap_ms recover)
log "  INFO: recovery re-pin worst gap: ${repin_ms} ms (informational; both PEs may advertise the CE MAC during the revert window)"
log "  INFO: post-recovery CE MAC egress set: $(ce_mac_egress_ips | tr '\n' ' ')"

# ---------------------------------------------------------------------------
# Phase 4 — flap damping: an unstable AC stays drained until it holds
# carrier for the full hold-off (the timer re-arms on every up edge)
# ---------------------------------------------------------------------------

log "[phase 4] flap sequence: down, up, down-within-hold-off, up — the ES must stay drained throughout"
pe1_ac_down
if wait_drain_gauge "$PE1" link 1 15; then
    ok "flap: link drain re-engaged on the down edge"
else
    fail "flap: link drain did not re-engage"
fi
got=$(wait_vtep_routes_gone 4 "$PE1_IP" "true" 90) \
    && ok "flap: pe1 Type 4 withdrawn again" \
    || fail "flap: pe1 Type 4 still present ($got)"

pe1_ac_up
first_up_ms=$(now_ms)
sleep 2.5
gauge=$(drain_gauge "$PE1" link)
if [ "$gauge" = "1" ]; then
    ok "flap: still drained 2.5s into the first hold-off"
else
    fail "flap: gauge '$gauge' 2.5s into the first hold-off (want 1)"
fi
pe1_ac_down
sleep 0.5
pe1_ac_up
last_up_ms=$(now_ms)
sleep 2.5

# Sample point: past the FIRST up's would-be deadline (proves the
# re-arm cancelled it) but well inside the LAST up's window. The
# sleeps put it at ~first_up+5.6s / ~last_up+2.5s nominally; guard
# both sides so a stalled host degrades to an informational skip
# instead of a false verdict.
sample_ms=$(now_ms)
since_first=$(( sample_ms - first_up_ms ))
since_last=$(( sample_ms - last_up_ms ))
gauge=$(drain_gauge "$PE1" link)
if [ "$since_first" -ge $(( RECOVERY_DELAY_SECS * 1000 )) ] && [ "$since_last" -le 4000 ]; then
    if [ "$gauge" = "1" ]; then
        ok "flap damping: still drained ${since_first}ms after the FIRST up (its deadline passed un-fired — the re-arm cancelled it; ${since_last}ms after the last up)"
    else
        fail "flap damping broken: gauge '$gauge' ${since_first}ms after the first up / ${since_last}ms after the last up (the cancelled deadline fired?)"
        docker exec "$PE1" tail -40 /var/log/rustbgpd.log >&2 || true
    fi
    t4_now=$(vtep_route_count 4 "$PE1_IP")
    if [ "$t4_now" -eq 0 ]; then
        ok "flap damping: pe1 Type 4 still withdrawn mid-flap-recovery"
    else
        fail "flap damping: pe1 Type 4 returned mid-hold-off (count=$t4_now)"
    fi
else
    log "  INFO: flap sample window overshot (since_first=${since_first}ms since_last=${since_last}ms) — re-arm sample skipped on this slow host"
fi

log "[phase 4] recovery completes after the LAST up + hold-off"
release_ok=0
for _ in $(seq 1 30); do
    if [ "$(drain_gauge "$PE1" link)" = "0" ]; then
        release_ok=1
        break
    fi
    sleep 0.5
done
release_ms=$(( $(now_ms) - last_up_ms ))
if [ "$release_ok" -eq 1 ]; then
    ok "flap recovery released (~${release_ms}ms after the LAST up; configured $((RECOVERY_DELAY_SECS * 1000))ms)"
else
    fail "flap recovery never released within ${release_ms}ms of the last up"
fi
assert_pe1_segment_routes_return "post-flap"
if wait_for_role "$PE1" df 1 90; then
    ok "pe1 re-elected DF after the flap sequence"
else
    fail "pe1 did not re-win DF after the flap sequence"
fi
ce_recovery_broadcast
got=$(wait_vtep_routes_at_least 2 "$PE1_IP" ".mac == \"${CE_MAC}\"" 1 120) \
    && ok "pe1 Type 2 for $CE_MAC present after the flap sequence ($got)" \
    || fail "pe1 Type 2 for $CE_MAC did not return after the flap sequence"
wait_ping "hr -> CE ping reply after the flap sequence" 90 || true
ping_burst_ok "post-flap ping burst hr -> CE"

# ---------------------------------------------------------------------------
# Phase 5 — operator composition: the operator and link reasons hold
# independently (ADR-0085 decision 2); a link cycle never overrides a
# maintenance drain
# ---------------------------------------------------------------------------

log "[phase 5] operator drain while the link is up (maintenance begins)"
drain_json=$(pe_ctl "$PE1" evpn es drain "$ESI" -j 2>&1) && drain_rc=0 || drain_rc=$?
if [ "$drain_rc" -eq 0 ] \
    && [ "$(printf '%s' "$drain_json" | jq -r '.drained')" = "true" ] \
    && [ "$(printf '%s' "$drain_json" | jq -r '.changed')" = "true" ] \
    && [ "$(printf '%s' "$drain_json" | jq -r '(.reasons // []) | join(",")')" = "operator" ]; then
    ok "operator drain applied: drained=true changed=true reasons=[operator]"
else
    fail "operator drain response unexpected (exit $drain_rc): $drain_json"
fi
if wait_drain_gauge "$PE1" operator 1 15; then
    ok "pe1 evpn_es_drained{reason=\"operator\"} -> 1"
else
    fail "pe1 operator drain gauge never reached 1"
fi
assert_drain_gauge "$PE1" link 0 "link reason untouched by the operator drain"
got=$(wait_vtep_routes_gone 4 "$PE1_IP" "true" 90) \
    && ok "pe1 Type 4 withdrawn under the operator drain" \
    || fail "pe1 Type 4 still present under the operator drain ($got)"

log "[phase 5] cable work during the maintenance window: link down, then up (hold-off cycles behind the operator reason)"
pe1_ac_down
if wait_drain_gauge "$PE1" link 1 15; then
    ok "link reason joined the operator reason (both held)"
else
    fail "link reason did not engage during the maintenance window"
fi
assert_drain_gauge "$PE1" operator 1 "operator reason still held with the link down"
pe1_ac_up
if wait_drain_gauge "$PE1" link 0 30; then
    ok "link reason released after the hold-off (cable work done)"
else
    fail "link reason never released after the maintenance link cycle"
fi
assert_drain_gauge "$PE1" operator 1 "operator reason SURVIVES the link recovery (composition)"
assert_pe1_routes_absent "operator-drained after the link cycle (link recovery must not undrain a maintenance drain)"

log "[phase 5] operator undrain (maintenance ends): last reason drops, origination returns"
undrain_json=$(pe_ctl "$PE1" evpn es undrain "$ESI" -j 2>&1) && undrain_rc=0 || undrain_rc=$?
if [ "$undrain_rc" -eq 0 ] \
    && [ "$(printf '%s' "$undrain_json" | jq -r '.drained')" = "false" ] \
    && [ "$(printf '%s' "$undrain_json" | jq -r '.changed')" = "true" ] \
    && [ "$(printf '%s' "$undrain_json" | jq -r '(.reasons // []) | length')" = "0" ]; then
    ok "operator undrain applied: drained=false changed=true reasons=[]"
else
    fail "operator undrain response unexpected (exit $undrain_rc): $undrain_json"
fi
assert_drain_gauge "$PE1" operator 0 "operator gauge clear after the undrain"
assert_drain_gauge "$PE1" link 0 "link gauge clear after the undrain"
assert_pe1_segment_routes_return "post-undrain"
if wait_for_role "$PE1" df 1 90; then
    ok "pe1 re-elected DF after maintenance"
else
    fail "pe1 did not re-win DF after maintenance"
fi
ce_recovery_broadcast
got=$(wait_vtep_routes_at_least 2 "$PE1_IP" ".mac == \"${CE_MAC}\"" 1 120) \
    && ok "pe1 Type 2 for $CE_MAC present after maintenance ($got)" \
    || fail "pe1 Type 2 for $CE_MAC did not return after maintenance"
wait_ping "hr -> CE ping reply after maintenance" 90 || true
ping_burst_ok "post-maintenance ping burst hr -> CE"

# ---------------------------------------------------------------------------
# Phase 6 — foreign state survived the whole cycle
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
