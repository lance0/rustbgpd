#!/usr/bin/env bash
# M60 — ADR-0079 single-dst FDB adoption sweep kill-and-restart proof.
#
# Validates the EVPN FDB adoption sweep end-to-end against a real
# Linux kernel: rustbgpd programs `extern_learn` single-dst rows from
# FRR Type 2 routes (the M36 path), is SIGKILLed so the kernel rows
# outlive the process, and restarts in the same netns with
# RUSTBGPD_EVPN_ADOPTION_REAP_DEFERRAL_SECS=5. Asserts:
#
# 1. Both peers reach Established; FRR-injected MACs A
#    (02:aa:bb:cc:dd:01) and B (02:aa:bb:cc:dd:02) land in rustbgpd's
#    `bridge fdb show dev vxlan100` with `extern_learn` + `dst
#    10.0.0.2` (M36 asserts).
# 2. A foreign-static row planted while rustbgpd is running (no
#    extern_learn marker) survives the entire cycle, as does the
#    start-script's pre-loaded foreign row.
# 3. After `kill -9` of the rustbgpd process (container and netns
#    survive — this is NOT a container stop), rows A and B are still
#    in the kernel FDB: the crash-leftover premise.
# 4. While rustbgpd is down, FRR withdraws MAC B (binding removed, so
#    it will not be re-advertised).
# 5. After restart, row A remains present with `extern_learn`
#    CONTINUOUSLY (adopted, then re-claimed by the re-advertised
#    Type 2 — polled every second so a transient reap would be
#    caught), while row B is reaped once the 5 s deferral passes and
#    a reconcile pass fires (bounded by the 60 s periodic dump, so
#    the window allows ~90 s).
# 6. Prometheus reports evpn_fdb_single_dst_adopted_total >= 2 and
#    evpn_fdb_single_dst_reaped_total == 1 for the restarted process.
#
# Usage:
#   docker build -t rustbgpd:dev .
#   sudo containerlab deploy -t tests/interop/m60-evpn-adoption-sweep.clab.yml
#   bash tests/interop/scripts/test-m60-evpn-adoption-sweep.sh
#   sudo containerlab destroy -t tests/interop/m60-evpn-adoption-sweep.clab.yml

set -eu

TOPO="m60-evpn-adoption-sweep"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

RUSTBGPD="clab-${TOPO}-rustbgpd"
ORIGINATOR="clab-${TOPO}-originator"
ORIGINATOR_IP="10.0.0.2"
VNI="100"
BRIDGE="br${VNI}"
VXLAN="vxlan${VNI}"
MAC_A="02:aa:bb:cc:dd:01"
MAC_B="02:aa:bb:cc:dd:02"
# Planted by this driver while rustbgpd is running (step 2 above).
FOREIGN_MAC="02:99:99:99:99:98"
# Pre-loaded by start-rustbgpd-vtep.sh before rustbgpd starts.
PRELOADED_FOREIGN_MAC="02:99:99:99:99:99"
REAP_DEFERRAL_SECS="5"
# Bounded wait for the reap: 5 s deferral + the 60 s periodic-dump
# cadence (the reap fires on the first reconcile pass after the
# deferral, and the periodic dump is the guaranteed pass) + margin.
REAP_WINDOW_SECS="90"

# ---------------------------------------------------------------------------
# Helpers (FDB shapes shared with M36)
# ---------------------------------------------------------------------------

# Dump rustbgpd's bridge FDB inside its container netns.
rb_fdb() {
    docker exec "$RUSTBGPD" bridge fdb show dev "$VXLAN" 2>/dev/null || true
}

rb_fdb_has_mac() {
    local mac=${1:?}
    rb_fdb | grep -qiF "$mac"
}

rb_fdb_has_extern_learn() {
    local mac=${1:?}
    rb_fdb | grep -iF "$mac" | grep -qE 'extern_learn|offload'
}

rb_fdb_dst_for_mac() {
    local mac=${1:?}
    rb_fdb | awk -v m="$mac" 'tolower($1) == tolower(m) { for (i=1; i<NF; i++) if ($i == "dst") print $(i+1) }' | head -1
}

# Inject / withdraw a static MAC on the FRR side. Zebra auto-detects
# the bridge FDB change and originates / withdraws a Type 2 route.
frr_inject_mac() {
    local mac=${1:?}
    docker exec "$ORIGINATOR" bridge fdb add "$mac" \
        dev "dummy${VNI}" master static 2>/dev/null || true
}

frr_withdraw_mac() {
    local mac=${1:?}
    docker exec "$ORIGINATOR" bridge fdb del "$mac" \
        dev "dummy${VNI}" master 2>/dev/null || true
}

# Scrape Prometheus via the container's management IP (M38 pattern —
# the rustbgpd:dev runtime image intentionally stays small and does
# not carry curl/wget, so the HTTP request runs from the host).
prom_scrape() {
    local ip
    ip=$(resolve_ip "$RUSTBGPD")
    if [ -z "$ip" ]; then
        echo "ERROR: could not resolve management IP for $RUSTBGPD" >&2
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
    docker exec "$RUSTBGPD" sh -c 'pidof rustbgpd 2>/dev/null' || true
}

# Wait for a MAC to land programmed (present + extern_learn + right
# dst). Bounded poll, 1 s grain.
wait_programmed() {
    local mac=${1:?}
    local label=${2:?}
    for _ in $(seq 1 30); do
        if rb_fdb_has_mac "$mac" && rb_fdb_has_extern_learn "$mac"; then
            local dst
            dst=$(rb_fdb_dst_for_mac "$mac")
            if [ "$dst" = "$ORIGINATOR_IP" ]; then
                ok "rustbgpd programmed $label dst=$dst with extern_learn"
                return 0
            fi
        fi
        sleep 1
    done
    fail "rustbgpd never programmed $label into the kernel FDB"
    rb_fdb >&2
    docker exec "$RUSTBGPD" tail -80 /var/log/rustbgpd.log >&2 || true
    return 1
}

# ---------------------------------------------------------------------------
# Phase 1 — baseline: both MACs programmed (the M36 path)
# ---------------------------------------------------------------------------

resolve_grpc_addr
log "rustbgpd container: $RUSTBGPD"
log "originator container: $ORIGINATOR"

log "Verifying VTEP topology inside rustbgpd container..."
docker exec "$RUSTBGPD" ip -d link show "$BRIDGE" >/dev/null \
    || { fail "bridge $BRIDGE missing in rustbgpd netns"; exit 1; }
docker exec "$RUSTBGPD" ip -d link show "$VXLAN" >/dev/null \
    || { fail "VXLAN port $VXLAN missing"; exit 1; }

wait_frr_established "$ORIGINATOR" "10.0.0.1" "L2VPN/EVPN" || exit 1

log "Injecting $MAC_A and $MAC_B on originator..."
frr_inject_mac "$MAC_A"
frr_inject_mac "$MAC_B"

wait_programmed "$MAC_A" "MAC A ($MAC_A)" || exit 1
wait_programmed "$MAC_B" "MAC B ($MAC_B)" || exit 1

# ---------------------------------------------------------------------------
# Phase 2 — plant a foreign row while rustbgpd is running
# ---------------------------------------------------------------------------

# No extern_learn marker → never adopted, never reaped. `master`
# lands it in the bridge-owned FDB the sweep iterates, so this is a
# real negative test, not an invisible `self` row.
log "Planting foreign static row $FOREIGN_MAC while rustbgpd is running..."
docker exec "$RUSTBGPD" bridge fdb add "$FOREIGN_MAC" \
    dev "$VXLAN" master static
if rb_fdb_has_mac "$FOREIGN_MAC"; then
    ok "foreign static row $FOREIGN_MAC planted"
else
    fail "foreign static row $FOREIGN_MAC did not land"
fi

# ---------------------------------------------------------------------------
# Phase 3 — SIGKILL: kernel rows must outlive the process
# ---------------------------------------------------------------------------

# Keep the first lifetime's log around for post-mortems — the restart
# start-script invocation truncates /var/log/rustbgpd.log.
docker exec "$RUSTBGPD" sh -c 'cp /var/log/rustbgpd.log /var/log/rustbgpd.run1.log' || true

pid=$(rustbgpd_pid)
if [ -z "$pid" ]; then
    fail "could not resolve rustbgpd pid before kill"
    exit 1
fi
log "SIGKILLing rustbgpd (pid $pid) inside its container (netns survives)..."
docker exec "$RUSTBGPD" sh -c "kill -9 $pid"
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

# The crash-leftover premise: extern_learn rows survive the dead owner.
if rb_fdb_has_mac "$MAC_A" && rb_fdb_has_extern_learn "$MAC_A"; then
    ok "row A survived the SIGKILL (extern_learn, kernel-resident)"
else
    fail "row A vanished with the process — no crash leftover to adopt"
    rb_fdb >&2
fi
if rb_fdb_has_mac "$MAC_B" && rb_fdb_has_extern_learn "$MAC_B"; then
    ok "row B survived the SIGKILL (extern_learn, kernel-resident)"
else
    fail "row B vanished with the process — no crash leftover to adopt"
    rb_fdb >&2
fi

# ---------------------------------------------------------------------------
# Phase 4 — withdraw MAC B on FRR while rustbgpd is down
# ---------------------------------------------------------------------------

log "Withdrawing $MAC_B on originator while rustbgpd is down..."
frr_withdraw_mac "$MAC_B"

# Make sure FRR will not re-advertise B: poll its EVPN table until
# the Type 2 is gone.
b_withdrawn=0
for _ in $(seq 1 30); do
    # Capture the table only when vtysh actually answered: a failed
    # exec must read as "still unknown", not "withdrawn", or a
    # momentarily unavailable FRR would falsely pass the gate.
    if evpn_table=$(docker exec "$ORIGINATOR" vtysh -c "show bgp l2vpn evpn route" 2>/dev/null) \
        && ! printf '%s\n' "$evpn_table" | grep -qiF "$MAC_B"; then
        b_withdrawn=1
        break
    fi
    sleep 1
done
if [ "$b_withdrawn" -eq 1 ]; then
    ok "FRR withdrew the Type 2 for $MAC_B (will not re-advertise)"
else
    fail "FRR still advertises $MAC_B after the binding was removed"
    docker exec "$ORIGINATOR" vtysh -c "show bgp l2vpn evpn route" >&2 || true
fi

# ---------------------------------------------------------------------------
# Phase 5 — restart with a short adoption-reap deferral
# ---------------------------------------------------------------------------

log "Restarting rustbgpd with RUSTBGPD_EVPN_ADOPTION_REAP_DEFERRAL_SECS=${REAP_DEFERRAL_SECS}..."
start_rustbgpd "RUSTBGPD_EVPN_ADOPTION_REAP_DEFERRAL_SECS=${REAP_DEFERRAL_SECS} /usr/local/bin/start-rustbgpd-vtep.sh 10.0.0.1 ${VNI}" || exit 1

# Adoption window: poll every second. Row A must NEVER disappear —
# the sweep adopts it, then the re-advertised Type 2 re-claims it; a
# transient reap+reinstall would show up at this grain. Row B must be
# reaped (adopted, unclaimed) once the deferral passes and a
# reconcile pass fires.
log "Polling the reap window (A continuous, B reaped within ${REAP_WINDOW_SECS}s)..."
a_held=1
b_reaped_after=""
for i in $(seq 1 "$REAP_WINDOW_SECS"); do
    if ! rb_fdb_has_mac "$MAC_A" || ! rb_fdb_has_extern_learn "$MAC_A"; then
        a_held=0
        fail "row A disappeared or lost extern_learn ${i}s after restart"
        rb_fdb >&2
        break
    fi
    if ! rb_fdb_has_mac "$MAC_B"; then
        b_reaped_after="$i"
        break
    fi
    sleep 1
done

if [ "$a_held" -eq 1 ]; then
    ok "row A stayed present with extern_learn across the reap window"
fi
if [ -n "$b_reaped_after" ]; then
    ok "row B reaped ${b_reaped_after}s after restart (deferral ${REAP_DEFERRAL_SECS}s)"
else
    if [ "$a_held" -eq 1 ]; then
        fail "row B was not reaped within ${REAP_WINDOW_SECS}s"
        rb_fdb >&2
        docker exec "$RUSTBGPD" tail -80 /var/log/rustbgpd.log >&2 || true
    fi
fi

# A must still be fully programmed (re-claimed, right encap target).
dst=$(rb_fdb_dst_for_mac "$MAC_A")
if [ "$dst" = "$ORIGINATOR_IP" ]; then
    ok "row A still points at dst=$dst after the sweep"
else
    fail "row A dst is '$dst' after the sweep (want $ORIGINATOR_IP)"
    rb_fdb >&2
fi

# Foreign rows: planted and pre-loaded, both unmarked, both untouched.
if rb_fdb_has_mac "$FOREIGN_MAC"; then
    ok "planted foreign row $FOREIGN_MAC survived the kill-and-restart cycle"
else
    fail "planted foreign row $FOREIGN_MAC was deleted"
    rb_fdb >&2
fi
if rb_fdb_has_mac "$PRELOADED_FOREIGN_MAC"; then
    ok "pre-loaded foreign row $PRELOADED_FOREIGN_MAC survived the cycle"
else
    fail "pre-loaded foreign row $PRELOADED_FOREIGN_MAC was deleted"
fi

# ---------------------------------------------------------------------------
# Phase 6 — Prometheus adoption/reap counters
# ---------------------------------------------------------------------------

# Counters are process-local, so the restarted daemon reports exactly
# this cycle: A + B adopted on the first pass, B reaped. Metrics fold
# in via DataplaneReport, so allow a short settle.
log "Polling Prometheus for the adoption/reap counters..."
adopted=""
reaped=""
for _ in $(seq 1 15); do
    adopted=$(prom_counter "evpn_fdb_single_dst_adopted_total")
    reaped=$(prom_counter "evpn_fdb_single_dst_reaped_total")
    if [ "${adopted:-0}" -ge 2 ] 2>/dev/null && [ "${reaped:-0}" -eq 1 ] 2>/dev/null; then
        break
    fi
    sleep 1
done
if [ "${adopted:-0}" -ge 2 ] 2>/dev/null; then
    ok "evpn_fdb_single_dst_adopted_total=$adopted (>= 2)"
else
    fail "evpn_fdb_single_dst_adopted_total='$adopted' (want >= 2)"
    prom_scrape | grep -E '^evpn_fdb' >&2 || true
fi
if [ "${reaped:-0}" -eq 1 ] 2>/dev/null; then
    ok "evpn_fdb_single_dst_reaped_total=$reaped (== 1)"
else
    fail "evpn_fdb_single_dst_reaped_total='$reaped' (want 1)"
    prom_scrape | grep -E '^evpn_fdb' >&2 || true
fi

print_summary
