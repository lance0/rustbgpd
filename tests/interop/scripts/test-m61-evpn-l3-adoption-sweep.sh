#!/usr/bin/env bash
# M61 — ADR-0079 EVPN L3 adoption sweep kill-and-restart proof.
#
# Validates the EVPN L3 adoption sweep end-to-end against a real
# Linux kernel: rustbgpd imports FRR-originated Type 5 prefixes into
# vrf1's kernel table over the M39/M48 symmetric Interface-less IRB
# datapath, is SIGKILLed so the kernel rows outlive the process, and
# restarts in the same netns with
# RUSTBGPD_EVPN_ADOPTION_REAP_DEFERRAL_SECS=5. Asserts:
#
# 1. Both peers reach Established; FRR's Type 5 prefixes A
#    (198.51.100.0/24, from the start-script tenant address) and B
#    (203.0.113.0/24, driver-injected on lo-vrf1) land in PE1's
#    `ip route show table 100` as `via 10.0.0.2 dev l3vxlan100
#    proto bgp ... onlink` rows, together with the shared resolution
#    rows: the L3 neighbor (10.0.0.2 → FRR's router MAC, `PERMANENT`
#    + `extern_learn` on l3vxlan100) and the L3VXLAN FDB row (the
#    router MAC, `extern_learn` + `self`, dst 10.0.0.2).
#
#    Resolution-row design: FRR's Type 5 next-hop is the L3VNI's VTEP
#    IP — one per VRF — so a second next-hop for B would need a whole
#    second VRF + L3VNI on the FRR side. A and B therefore share ONE
#    next-hop / router MAC, meaning ONE neighbor + ONE FDB row serve
#    both prefixes. The asserts are designed around that: neighbor/FDB
#    adopted counters are 1, their reaped counters are 0, and the
#    shared rows must stay present continuously while A re-claims them.
# 2. Foreign rows planted while rustbgpd is running — a `proto static`
#    route in the VRF table, a permanent neighbor WITHOUT
#    `extern_learn`, and (ADR-0082) a neighbor with the FULL legacy
#    marker pair (`extern_learn` + `nud permanent`) but a foreign
#    `protocol zebra` ownership stamp — survive the entire cycle.
#    The zebra-stamped row is the new discrimination the NDA_PROTOCOL
#    stamp buys: the pre-stamp rule would have adopted and reaped it.
# 3. After `kill -9` of the rustbgpd process (container and netns
#    survive — this is NOT a container stop), every marker row is
#    still in the kernel: the crash-leftover premise.
# 4. While rustbgpd is down, FRR withdraws prefix B (its tenant
#    address removed, so it will not be re-advertised).
# 5. After restart, prefix A's route and the shared resolution rows
#    stay present with their markers CONTINUOUSLY (adopted, then
#    re-claimed by the re-advertised Type 5 — polled every second so
#    a transient reap would be caught), while B's route is reaped
#    once the 5 s deferral passes and a reconcile pass fires (bounded
#    by the periodic reconcile cadence, so the window allows 90 s).
#    The re-claimed neighbor row must also show the ADR-0082
#    NDA_PROTOCOL ownership stamp (`proto bgp` in `ip neigh show`) —
#    the re-claim re-applies the row with replace semantics, so the
#    stamped write lands even if the adopted leftover predated it.
#    Because B shares its resolution rows with A there is no
#    resolution-row reap in this topology, so the route-before-
#    resolution reap order is not observable here — it is pinned by
#    the reconcile unit tests; this driver asserts the end state
#    (route reaped, shared rows intact).
# 6. Prometheus reports evpn_l3_route_adopted_total == 2 and
#    evpn_l3_route_reaped_total == 1 for the restarted process, with
#    the neighbor/FDB counters matching the shared-resolution design
#    (adopted == 1, reaped == 0).
#
# Usage:
#   docker build -t rustbgpd:dev .
#   containerlab deploy -t tests/interop/m61-evpn-l3-adoption-sweep.clab.yml
#   bash tests/interop/scripts/test-m61-evpn-l3-adoption-sweep.sh
#   containerlab destroy -t tests/interop/m61-evpn-l3-adoption-sweep.clab.yml

set -eu

TOPO="m61-evpn-l3-adoption-sweep"
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
TABLE_ID=100
L3VXLAN="l3vxlan${L3VNI}"
PE1_ROUTER_MAC="02:00:00:00:01:01"
PE1_TENANT_ADDR="192.0.2.1/24"
# Prefix A: originated by FRR from the start-script tenant address.
PREFIX_A="198.51.100.0/24"
# Prefix B: driver-injected second tenant address on FRR's lo-vrf1,
# withdrawn while rustbgpd is down.
PREFIX_B="203.0.113.0/24"
B_TENANT_ADDR="203.0.113.1/24"
# Foreign rows planted by this driver while rustbgpd is running:
# a `proto static` route (no `proto bgp` marker) and a permanent
# neighbor without `extern_learn` — never adopted, never reaped.
FOREIGN_PREFIX="198.18.0.0/24"
FOREIGN_NEIGH_IP="10.0.0.99"
FOREIGN_NEIGH_MAC="02:99:99:99:99:97"
# Foreign-by-stamp neighbor (ADR-0082): carries the full legacy
# marker pair (`extern_learn` + `nud permanent`) on the managed
# L3VXLAN device, but `protocol zebra` proves another controller
# owns it — the sweep must leave it untouched.
FOREIGN_STAMP_NEIGH_IP="10.0.0.98"
FOREIGN_STAMP_NEIGH_MAC="02:99:99:99:99:96"
REAP_DEFERRAL_SECS="5"
# Bounded wait for the reap: 5 s deferral + the periodic reconcile
# cadence (the reap fires on the first clean L3 pass after the
# deferral) + generous margin, mirroring the M60 window.
REAP_WINDOW_SECS="90"

# Both daemon lifetimes run nohup'd with a log file so the failure
# paths can dump it; `sleep infinity` (the container's PID 1) keeps
# the netns alive across the SIGKILL.
START_CMD="nohup /usr/local/bin/rustbgpd /etc/rustbgpd/config.toml >/var/log/rustbgpd.log 2>&1 &"

# ---------------------------------------------------------------------------
# Helpers (L3 marker shapes shared with the netns_l3_install suite)
# ---------------------------------------------------------------------------

# Dump PE1's vrf1 kernel route table / L3VXLAN neighbors / L3VXLAN FDB
# inside its container netns.
pe1_routes() {
    docker exec "$PE1" ip route show table "$TABLE_ID" 2>/dev/null || true
}

pe1_neigh() {
    docker exec "$PE1" ip neigh show dev "$L3VXLAN" 2>/dev/null || true
}

pe1_l3fdb() {
    docker exec "$PE1" bridge fdb show dev "$L3VXLAN" 2>/dev/null || true
}

pe1_route_present() {
    pe1_routes | grep -qF "$1"
}

# Full owned-route marker shape: prefix via the FRR VTEP out the
# L3VXLAN device with `proto bgp` + `onlink` on the same line.
pe1_route_marked() {
    pe1_routes | grep -F "$1" | grep -F "via ${PE2_IP}" \
        | grep -F "dev ${L3VXLAN}" | grep -F "proto bgp" | grep -qF "onlink"
}

# Shared L3 neighbor row: FRR's VTEP IP resolved to the router MAC
# with the PERMANENT + extern_learn marker pair.
pe1_neigh_marked() {
    pe1_neigh | awk -v ip="$PE2_IP" '$1 == ip' \
        | grep -F "extern_learn" | grep -qF "PERMANENT"
}

# ADR-0082: managed L3 neighbor rows carry the NDA_PROTOCOL
# ownership stamp (RTPROT_BGP); the kernel stores and echoes it for
# IP neighbors since 5.0, and iproute2 prints it as `proto bgp` on
# the plain `ip neigh show` row.
pe1_neigh_stamped() {
    pe1_neigh | awk -v ip="$PE2_IP" '$1 == ip' \
        | grep -F "extern_learn" | grep -qF "proto bgp"
}

pe1_neigh_lladdr() {
    pe1_neigh | awk -v ip="$PE2_IP" \
        '$1 == ip { for (i = 1; i < NF; i++) if ($i == "lladdr") print $(i+1) }' | head -1
}

# Shared L3VXLAN FDB row: the remote router MAC with extern_learn +
# self (NTF_SELF — the VXLAN driver consults this row), dst = FRR.
pe1_l3fdb_marked() {
    local mac=${1:?}
    pe1_l3fdb | grep -iF "$mac" | grep -F "dst ${PE2_IP}" \
        | grep -F "extern_learn" | grep -qF "self"
}

pe1_foreign_neigh_present() {
    pe1_neigh | awk -v ip="$FOREIGN_NEIGH_IP" '$1 == ip' | grep -qF "PERMANENT"
}

# The zebra-stamped foreign neighbor must keep ALL of its row intact:
# legacy marker pair still present (neither adopted-and-reaped nor
# rewritten) and the foreign stamp still on it.
pe1_foreign_stamped_neigh_present() {
    pe1_neigh | awk -v ip="$FOREIGN_STAMP_NEIGH_IP" '$1 == ip' \
        | grep -F "extern_learn" | grep -F "PERMANENT" | grep -qF "proto zebra"
}

# Inject / withdraw the second tenant prefix on the FRR side. The
# per-VRF `redistribute connected` picks up the connected route and
# the L2VPN/EVPN block re-originates / withdraws it as Type 5.
frr_inject_prefix_b() {
    docker exec "$PE2" ip addr add "$B_TENANT_ADDR" dev "lo-${TENANT_VRF}" 2>/dev/null || true
}

frr_withdraw_prefix_b() {
    docker exec "$PE2" ip addr del "$B_TENANT_ADDR" dev "lo-${TENANT_VRF}" 2>/dev/null || true
}

# Scrape Prometheus via the container's management IP (M38 pattern —
# the rustbgpd:dev runtime image intentionally stays small and does
# not carry curl/wget, so the HTTP request runs from the host).
prom_scrape() {
    local ip
    ip=$(resolve_ip "$PE1")
    if [ -z "$ip" ]; then
        echo "ERROR: could not resolve management IP for $PE1" >&2
        return 1
    fi
    curl -sfm 5 "http://${ip}:9179/metrics" 2>/dev/null \
        || wget -qO- -T 5 "http://${ip}:9179/metrics" 2>/dev/null \
        || true
}

# Read an unlabelled counter value; empty if the line isn't emitted.
prom_counter() {
    local name=${1:?}
    prom_scrape | awk -v n="$name" '$1 == n { print $2; exit }'
}

rustbgpd_pid() {
    docker exec "$PE1" sh -c 'pidof rustbgpd 2>/dev/null' || true
}

# Wait for a Type 5 prefix to land fully marked in vrf1's kernel
# table. Bounded poll, 1 s grain.
wait_route_programmed() {
    local prefix=${1:?}
    local label=${2:?}
    for _ in $(seq 1 90); do
        if pe1_route_marked "$prefix"; then
            ok "PE1 programmed $label via ${PE2_IP} dev ${L3VXLAN} proto bgp onlink"
            return 0
        fi
        sleep 1
    done
    fail "PE1 never programmed $label into table ${TABLE_ID}"
    pe1_routes >&2
    docker exec "$PE1" tail -80 /var/log/rustbgpd.log >&2 || true
    return 1
}

# ---------------------------------------------------------------------------
# Phase 1 — baseline: both Type 5 routes + shared resolution rows (M39 path)
# ---------------------------------------------------------------------------

resolve_grpc_addr
log "rustbgpd container: $PE1"
log "FRR container: $PE2"

log "Provisioning PE1 kernel topology (vrf1 + L3VXLAN + tenant dummy)..."
docker exec "$PE1" /usr/local/bin/start-rustbgpd-m39-pe1.sh \
    "$PE1_IP" "$L3VNI" "$TENANT_VRF" "$PE1_TENANT_ADDR" "$PE1_ROUTER_MAC" >/dev/null
docker exec "$PE1" ip -d link show "$TENANT_VRF" >/dev/null \
    || { fail "VRF $TENANT_VRF missing in PE1 netns"; exit 1; }
docker exec "$PE1" ip -d link show "$L3VXLAN" >/dev/null \
    || { fail "L3VXLAN $L3VXLAN missing in PE1 netns"; exit 1; }

start_rustbgpd "$START_CMD" || exit 1

wait_frr_established "$PE2" "$PE1_IP" "L2VPN/EVPN" || exit 1

log "Injecting prefix B (${PREFIX_B}) on FRR's lo-${TENANT_VRF}..."
frr_inject_prefix_b

wait_route_programmed "$PREFIX_A" "prefix A ($PREFIX_A)" || exit 1
wait_route_programmed "$PREFIX_B" "prefix B ($PREFIX_B)" || exit 1

# Shared resolution rows: A and B resolve via FRR's single VTEP IP /
# router MAC (see the design note in the header), so exactly one
# neighbor + one FDB row serve both. Capture the router MAC from the
# neighbor row and require the FDB row to carry the same MAC — that
# ties the two halves of the resolution pair together.
if pe1_neigh_marked; then
    ok "L3 neighbor ${PE2_IP} present with PERMANENT + extern_learn on ${L3VXLAN}"
else
    fail "L3 neighbor ${PE2_IP} missing or unmarked on ${L3VXLAN}"
    pe1_neigh >&2
fi
# ADR-0082 baseline: a fresh install must already carry the stamp.
if pe1_neigh_stamped; then
    ok "L3 neighbor ${PE2_IP} carries the NDA_PROTOCOL ownership stamp (proto bgp)"
else
    fail "L3 neighbor ${PE2_IP} missing the proto bgp ownership stamp"
    pe1_neigh >&2
fi
ROUTER_MAC=$(pe1_neigh_lladdr)
if [ -z "$ROUTER_MAC" ]; then
    fail "could not capture FRR's router MAC from the L3 neighbor row"
    pe1_neigh >&2
    print_summary
fi
log "FRR router MAC (from the neighbor row): $ROUTER_MAC"
if pe1_l3fdb_marked "$ROUTER_MAC"; then
    ok "L3VXLAN FDB row $ROUTER_MAC dst ${PE2_IP} present with extern_learn + self"
else
    fail "L3VXLAN FDB row for $ROUTER_MAC missing or unmarked"
    pe1_l3fdb >&2
fi

# ---------------------------------------------------------------------------
# Phase 2 — plant foreign rows while rustbgpd is running
# ---------------------------------------------------------------------------

# `proto static` (no `proto bgp` marker) → never adopted, never
# reaped, even though it sits in the configured VRF table with
# onlink out the managed L3VXLAN device.
log "Planting foreign static route $FOREIGN_PREFIX in table ${TABLE_ID}..."
docker exec "$PE1" ip route add "$FOREIGN_PREFIX" via "$PE2_IP" \
    dev "$L3VXLAN" onlink proto static table "$TABLE_ID"
if pe1_route_present "$FOREIGN_PREFIX"; then
    ok "foreign static route $FOREIGN_PREFIX planted"
else
    fail "foreign static route $FOREIGN_PREFIX did not land"
fi

# Permanent but WITHOUT extern_learn → fails the marker pair, never
# adopted, never reaped.
log "Planting foreign permanent neighbor $FOREIGN_NEIGH_IP on ${L3VXLAN}..."
docker exec "$PE1" ip neigh add "$FOREIGN_NEIGH_IP" \
    lladdr "$FOREIGN_NEIGH_MAC" dev "$L3VXLAN" nud permanent
if pe1_foreign_neigh_present; then
    ok "foreign permanent neighbor $FOREIGN_NEIGH_IP planted"
else
    fail "foreign permanent neighbor $FOREIGN_NEIGH_IP did not land"
fi

# extern_learn + permanent + `protocol zebra` → matches the legacy
# marker pair exactly but is foreign BY STAMP (ADR-0082). The
# post-restart sweep must classify it NotOurs: never adopted (the
# neighbor adopted counter stays 1 below) and never reaped.
log "Planting foreign zebra-stamped neighbor $FOREIGN_STAMP_NEIGH_IP on ${L3VXLAN}..."
docker exec "$PE1" ip neigh add "$FOREIGN_STAMP_NEIGH_IP" \
    lladdr "$FOREIGN_STAMP_NEIGH_MAC" dev "$L3VXLAN" nud permanent \
    extern_learn protocol zebra
if pe1_foreign_stamped_neigh_present; then
    ok "foreign zebra-stamped neighbor $FOREIGN_STAMP_NEIGH_IP planted (extern_learn + PERMANENT + proto zebra)"
else
    fail "foreign zebra-stamped neighbor $FOREIGN_STAMP_NEIGH_IP did not land"
fi

# ---------------------------------------------------------------------------
# Phase 3 — SIGKILL: kernel rows must outlive the process
# ---------------------------------------------------------------------------

# Keep the first lifetime's log around for post-mortems — the restart
# invocation truncates /var/log/rustbgpd.log.
docker exec "$PE1" sh -c 'cp /var/log/rustbgpd.log /var/log/rustbgpd.run1.log' || true

pid=$(rustbgpd_pid)
if [ -z "$pid" ]; then
    fail "could not resolve rustbgpd pid before kill"
    exit 1
fi
log "SIGKILLing rustbgpd (pid $pid) inside its container (netns survives)..."
docker exec "$PE1" sh -c "kill -9 $pid"
for _ in $(seq 1 10); do
    [ -z "$(rustbgpd_pid)" ] && break
    sleep 1
done
if [ -z "$(rustbgpd_pid)" ]; then
    ok "rustbgpd process gone after SIGKILL"
else
    fail "rustbgpd still running after SIGKILL"
    exit 1
fi

# The crash-leftover premise: marker rows survive the dead owner.
if pe1_route_marked "$PREFIX_A"; then
    ok "route A survived the SIGKILL (proto bgp onlink, kernel-resident)"
else
    fail "route A vanished with the process — no crash leftover to adopt"
    pe1_routes >&2
fi
if pe1_route_marked "$PREFIX_B"; then
    ok "route B survived the SIGKILL (proto bgp onlink, kernel-resident)"
else
    fail "route B vanished with the process — no crash leftover to adopt"
    pe1_routes >&2
fi
if pe1_neigh_marked; then
    ok "shared L3 neighbor survived the SIGKILL"
else
    fail "shared L3 neighbor vanished with the process"
    pe1_neigh >&2
fi
if pe1_l3fdb_marked "$ROUTER_MAC"; then
    ok "shared L3VXLAN FDB row survived the SIGKILL"
else
    fail "shared L3VXLAN FDB row vanished with the process"
    pe1_l3fdb >&2
fi

# ---------------------------------------------------------------------------
# Phase 4 — withdraw prefix B on FRR while rustbgpd is down
# ---------------------------------------------------------------------------

log "Withdrawing $PREFIX_B on FRR while rustbgpd is down..."
frr_withdraw_prefix_b

# Make sure FRR will not re-advertise B: poll its EVPN table until
# the Type 5 is gone.
b_withdrawn=0
for _ in $(seq 1 30); do
    # Capture the table only when vtysh actually answered: a failed
    # exec must read as "still unknown", not "withdrawn", or a
    # momentarily unavailable FRR would falsely pass the gate.
    if evpn_table=$(docker exec "$PE2" vtysh -c "show bgp l2vpn evpn route" 2>/dev/null) \
        && ! printf '%s\n' "$evpn_table" | grep -qF "203.0.113.0"; then
        b_withdrawn=1
        break
    fi
    sleep 1
done
if [ "$b_withdrawn" -eq 1 ]; then
    ok "FRR withdrew the Type 5 for $PREFIX_B (will not re-advertise)"
else
    fail "FRR still advertises $PREFIX_B after its tenant address was removed"
    docker exec "$PE2" vtysh -c "show bgp l2vpn evpn route" >&2 || true
fi

# ---------------------------------------------------------------------------
# Phase 5 — restart with a short adoption-reap deferral
# ---------------------------------------------------------------------------

log "Restarting rustbgpd with RUSTBGPD_EVPN_ADOPTION_REAP_DEFERRAL_SECS=${REAP_DEFERRAL_SECS}..."
start_rustbgpd "RUSTBGPD_EVPN_ADOPTION_REAP_DEFERRAL_SECS=${REAP_DEFERRAL_SECS} ${START_CMD}" || exit 1

# ---------------------------------------------------------------------------
# Phase 6 — reap window: A + shared rows continuous, B's route reaped
# ---------------------------------------------------------------------------

# Poll every second. Route A and the shared resolution rows must
# NEVER disappear — the sweep adopts them, then the re-advertised
# Type 5 re-claims them (and the shared neighbor/FDB rows are exempt
# from the reap while A claims them); a transient reap+reinstall
# would show up at this grain. Route B must be reaped (adopted,
# unclaimed) once the deferral passes and a reconcile pass fires.
# B has no resolution rows of its own (shared-next-hop design, see
# header), so there is no resolution reap to order-check here — the
# route-before-resolution reap order is pinned by the reconcile unit
# tests; this driver asserts the end state below.
log "Polling the reap window (A + shared rows continuous, B's route reaped within ${REAP_WINDOW_SECS}s)..."
a_held=1
b_reaped_after=""
for i in $(seq 1 "$REAP_WINDOW_SECS"); do
    if ! pe1_route_marked "$PREFIX_A"; then
        a_held=0
        fail "route A disappeared or lost its markers ${i}s after restart"
        pe1_routes >&2
        break
    fi
    if ! pe1_neigh_marked; then
        a_held=0
        fail "shared L3 neighbor disappeared or lost its markers ${i}s after restart"
        pe1_neigh >&2
        break
    fi
    if ! pe1_l3fdb_marked "$ROUTER_MAC"; then
        a_held=0
        fail "shared L3VXLAN FDB row disappeared or lost its markers ${i}s after restart"
        pe1_l3fdb >&2
        break
    fi
    if ! pe1_route_present "$PREFIX_B"; then
        b_reaped_after="$i"
        break
    fi
    sleep 1
done

if [ "$a_held" -eq 1 ]; then
    ok "route A + shared resolution rows stayed marked across the reap window"
fi
if [ -n "$b_reaped_after" ]; then
    ok "route B reaped ${b_reaped_after}s after restart (deferral ${REAP_DEFERRAL_SECS}s)"
else
    if [ "$a_held" -eq 1 ]; then
        fail "route B was not reaped within ${REAP_WINDOW_SECS}s"
        pe1_routes >&2
        docker exec "$PE1" tail -80 /var/log/rustbgpd.log >&2 || true
    fi
fi

# Settle two more reconcile passes, then re-assert the shared rows:
# if the reap wrongly treated them as unclaimed it would fire in the
# same pass as (or right after) B's route reap, so this catches a
# delayed resolution-row reap that the loop's break just missed.
sleep 10
if pe1_route_marked "$PREFIX_A"; then
    ok "route A still fully marked after the sweep"
else
    fail "route A missing or unmarked after the sweep"
    pe1_routes >&2
fi
if pe1_neigh_marked && pe1_l3fdb_marked "$ROUTER_MAC"; then
    ok "shared resolution rows still marked after the sweep (claimed by A, never reaped)"
else
    fail "a shared resolution row was reaped despite A re-claiming it"
    pe1_neigh >&2
    pe1_l3fdb >&2
fi

# ADR-0082: the re-claimed neighbor row must show the ownership stamp.
# The re-claim re-applies the row with netlink replace semantics, so
# the stamped write overwrites whatever the adopted leftover carried;
# the re-apply rides the convergence / reconcile cadence, so poll.
neigh_stamp_seen=0
for _ in $(seq 1 60); do
    if pe1_neigh_stamped; then
        neigh_stamp_seen=1
        break
    fi
    sleep 1
done
if [ "$neigh_stamp_seen" -eq 1 ]; then
    ok "re-claimed L3 neighbor row carries the NDA_PROTOCOL ownership stamp (proto bgp)"
else
    fail "re-claimed L3 neighbor row never showed proto bgp after restart"
    pe1_neigh >&2
fi

# Foreign rows: unmarked, untouched through kill, restart, and reap.
if pe1_route_present "$FOREIGN_PREFIX"; then
    ok "foreign static route $FOREIGN_PREFIX survived the kill-and-restart cycle"
else
    fail "foreign static route $FOREIGN_PREFIX was deleted"
    pe1_routes >&2
fi
if pe1_foreign_neigh_present; then
    ok "foreign permanent neighbor $FOREIGN_NEIGH_IP survived the cycle"
else
    fail "foreign permanent neighbor $FOREIGN_NEIGH_IP was deleted"
    pe1_neigh >&2
fi
# The foreign-by-stamp row: legacy marker pair intact AND still
# stamped zebra — proof the sweep discriminated on NDA_PROTOCOL
# rather than adopting (and reaping) on flags alone.
if pe1_foreign_stamped_neigh_present; then
    ok "foreign zebra-stamped neighbor $FOREIGN_STAMP_NEIGH_IP survived the cycle untouched"
else
    fail "foreign zebra-stamped neighbor $FOREIGN_STAMP_NEIGH_IP was adopted/reaped or rewritten"
    pe1_neigh >&2
fi

# ---------------------------------------------------------------------------
# Phase 7 — Prometheus adoption/reap counters
# ---------------------------------------------------------------------------

# Counters are process-local, so the restarted daemon reports exactly
# this cycle: routes A + B adopted on the first sweep, B reaped, and
# the single shared neighbor + FDB row adopted and never reaped
# (claimed by A). Metrics fold in via DataplaneReport, so allow a
# short settle.
log "Polling Prometheus for the L3 adoption/reap counters..."
r_adopted=""
r_reaped=""
n_adopted=""
n_reaped=""
f_adopted=""
f_reaped=""
for _ in $(seq 1 15); do
    r_adopted=$(prom_counter "evpn_l3_route_adopted_total")
    r_reaped=$(prom_counter "evpn_l3_route_reaped_total")
    n_adopted=$(prom_counter "evpn_l3_neighbor_adopted_total")
    n_reaped=$(prom_counter "evpn_l3_neighbor_reaped_total")
    f_adopted=$(prom_counter "evpn_l3vxlan_fdb_adopted_total")
    f_reaped=$(prom_counter "evpn_l3vxlan_fdb_reaped_total")
    if [ "${r_adopted:-0}" -eq 2 ] 2>/dev/null && [ "${r_reaped:-0}" -eq 1 ] 2>/dev/null \
        && [ "${n_adopted:-0}" -eq 1 ] 2>/dev/null && [ "${f_adopted:-0}" -eq 1 ] 2>/dev/null; then
        break
    fi
    sleep 1
done
if [ "${r_adopted:-0}" -eq 2 ] 2>/dev/null; then
    ok "evpn_l3_route_adopted_total=$r_adopted (== 2: A + B)"
else
    fail "evpn_l3_route_adopted_total='$r_adopted' (want 2)"
    prom_scrape | grep -E '^evpn_l3' >&2 || true
fi
if [ "${r_reaped:-0}" -eq 1 ] 2>/dev/null; then
    ok "evpn_l3_route_reaped_total=$r_reaped (== 1: B)"
else
    fail "evpn_l3_route_reaped_total='$r_reaped' (want 1)"
    prom_scrape | grep -E '^evpn_l3' >&2 || true
fi
if [ "${n_adopted:-0}" -eq 1 ] 2>/dev/null; then
    ok "evpn_l3_neighbor_adopted_total=$n_adopted (== 1: shared row)"
else
    fail "evpn_l3_neighbor_adopted_total='$n_adopted' (want 1)"
    prom_scrape | grep -E '^evpn_l3' >&2 || true
fi
if [ "${n_reaped:-0}" -eq 0 ] 2>/dev/null; then
    ok "evpn_l3_neighbor_reaped_total=$n_reaped (== 0: claimed by A)"
else
    fail "evpn_l3_neighbor_reaped_total='$n_reaped' (want 0)"
    prom_scrape | grep -E '^evpn_l3' >&2 || true
fi
if [ "${f_adopted:-0}" -eq 1 ] 2>/dev/null; then
    ok "evpn_l3vxlan_fdb_adopted_total=$f_adopted (== 1: shared row)"
else
    fail "evpn_l3vxlan_fdb_adopted_total='$f_adopted' (want 1)"
    prom_scrape | grep -E '^evpn_l3' >&2 || true
fi
if [ "${f_reaped:-0}" -eq 0 ] 2>/dev/null; then
    ok "evpn_l3vxlan_fdb_reaped_total=$f_reaped (== 0: claimed by A)"
else
    fail "evpn_l3vxlan_fdb_reaped_total='$f_reaped' (want 0)"
    prom_scrape | grep -E '^evpn_l3' >&2 || true
fi

print_summary
