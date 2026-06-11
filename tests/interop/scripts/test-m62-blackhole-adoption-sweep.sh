#!/usr/bin/env bash
# M62 — ADR-0079 blackhole discard adoption sweep kill-and-restart proof.
#
# Validates the RFC 7999 blackhole adoption sweep end-to-end against a
# real Linux kernel: rustbgpd installs kernel discard routes
# (`RTN_BLACKHOLE` + `RTPROT_BGP` in the main table — the M41 path)
# from FRR-tagged host routes, is SIGKILLed so the kernel rows outlive
# the process, and restarts in the same netns with
# RUSTBGPD_BLACKHOLE_ADOPTION_REAP_DEFERRAL_SECS=5. Asserts:
#
# 1. The session reaches Established; tagged host routes A
#    (203.0.113.66/32) and B (203.0.113.68/32) install as
#    `blackhole ... proto bgp` kernel rows and `ListBlackholeDiscards`
#    reports both as `installed` (M41 asserts).
# 2. A foreign `proto static` blackhole row (203.0.113.99/32) planted
#    while rustbgpd is running survives the entire cycle — no
#    `proto bgp` marker, so it is never adopted or reaped.
# 3. After `kill -9` of the rustbgpd process (container and netns
#    survive — this is NOT a container stop), rows A and B are still
#    in the kernel FIB: the crash-leftover premise.
# 4. While rustbgpd is down, FRR withdraws prefix B (`no network`, so
#    it will not be re-advertised).
# 5. After restart, row A remains present with the `proto bgp` marker
#    CONTINUOUSLY (adopted, then re-claimed by the re-advertised
#    route — polled every second so a transient reap would be
#    caught), while row B is reaped once the 5 s deferral passes and
#    a reconcile pass fires (bounded by the 30 s periodic reconcile,
#    so the window allows 60 s) — and NEVER before the deferral
#    elapses: B must surface as `installed/adopted_pending_reap` on
#    `ListBlackholeDiscards` while it waits (a zero-deferral reap
#    would never emit that state), and after the reap B drops off the
#    status surface entirely while A reads `installed` with reason
#    `adopted`/`owned`.
# 6. Prometheus reports bgp_blackhole_discard_adopted_total >= 2 and
#    bgp_blackhole_discard_reaped_total == 1 for the restarted
#    process.
#
# Usage:
#   docker build -t rustbgpd:dev .
#   containerlab deploy -t tests/interop/m62-blackhole-adoption-sweep.clab.yml
#   bash tests/interop/scripts/test-m62-blackhole-adoption-sweep.sh
#   containerlab destroy -t tests/interop/m62-blackhole-adoption-sweep.clab.yml

set -eu

TOPO="m62-blackhole-adoption-sweep"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

FRR="clab-${TOPO}-frr"
PREFIX_A="203.0.113.66/32"   # survives the cycle: adopted + re-claimed
PREFIX_B="203.0.113.68/32"   # withdrawn while down: adopted + reaped
FOREIGN_PREFIX="203.0.113.99/32"
REAP_DEFERRAL_SECS="5"
# Bounded wait for the reap: 5 s deferral + the 30 s periodic
# reconcile cadence (the reap fires on the first reconcile pass after
# the deferral, and the periodic tick is the guaranteed pass) + margin.
REAP_WINDOW_SECS="60"
# Keep asserting row A this long after B's reap — adoption means A
# keeps discarding with zero gap, including across the reap pass.
REAP_MARGIN_SECS="5"

# ---------------------------------------------------------------------------
# Helpers (kernel-route and status shapes shared with M41)
# ---------------------------------------------------------------------------

# Exact-prefix kernel rows inside rustbgpd's netns.
rb_route() {
    local prefix=${1:?}
    docker exec "$RUSTBGPD" ip route show exact "$prefix" 2>/dev/null || true
}

# Any blackhole row for the prefix, regardless of proto.
kernel_blackhole_present() {
    local prefix=${1:?}
    rb_route "$prefix" | grep -Eq "^blackhole ${prefix%/*}\b"
}

# A blackhole row carrying our ownership marker (RTN_BLACKHOLE +
# RTPROT_BGP). iproute2 prints the proto as `bgp` when rt_protos
# knows 186 and as the raw number otherwise — accept both.
kernel_blackhole_marker_present() {
    local prefix=${1:?}
    rb_route "$prefix" | grep -E "^blackhole ${prefix%/*}\b" \
        | grep -Eq 'proto (bgp|186)\b'
}

# The foreign row must keep its non-marker proto.
kernel_blackhole_foreign_present() {
    local prefix=${1:?}
    rb_route "$prefix" | grep -E "^blackhole ${prefix%/*}\b" \
        | grep -Eq 'proto (static|4)\b'
}

grpc_blackholes() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListBlackholeDiscards 2>/dev/null
}

normalize_blackhole_state() {
    case "$1" in
        BLACKHOLE_DISCARD_STATE_INSTALLED) echo "installed" ;;
        BLACKHOLE_DISCARD_STATE_REJECTED) echo "rejected" ;;
        BLACKHOLE_DISCARD_STATE_FAILED) echo "failed" ;;
        1) echo "installed" ;;
        2) echo "rejected" ;;
        3) echo "failed" ;;
        *) echo "$1" ;;
    esac
}

# Emits "state|reason" for the prefix, or "MISSING".
blackhole_status() {
    local prefix=$1
    local plen=${prefix#*/}
    local addr=${prefix%/*}
    local status
    status=$(grpc_blackholes | jq -r --arg addr "$addr" --argjson plen "$plen" '
        [.discards[]? | select(.prefix == $addr and .prefixLength == $plen)]
        | if length == 0 then "MISSING" else "\(.[0].state)|\(.[0].reason)" end
    ')
    if [ "$status" = "MISSING" ] || [ -z "$status" ]; then
        echo "MISSING"
        return
    fi
    local state=${status%%|*}
    local reason=${status#*|}
    printf '%s|%s\n' "$(normalize_blackhole_state "$state")" "$reason"
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

dump_state_on_failure() {
    echo "===== rustbgpd ListBlackholeDiscards (raw) =====" >&2
    grpc_blackholes | jq . >&2 || true
    echo "===== rustbgpd container routes =====" >&2
    docker exec "$RUSTBGPD" ip route show >&2 || true
    echo "===== rustbgpd log tail =====" >&2
    docker exec "$RUSTBGPD" tail -80 /var/log/rustbgpd.log >&2 || true
    echo "===== FRR vtysh: BGP summary =====" >&2
    docker exec "$FRR" vtysh -c 'show ip bgp summary' >&2 || true
    echo "===== FRR vtysh: advertised-routes to 10.0.0.1 =====" >&2
    docker exec "$FRR" vtysh -c 'show ip bgp neighbor 10.0.0.1 advertised-routes' >&2 || true
}

wait_blackhole_status() {
    local prefix=$1
    local expected_state=$2
    local expected_reason=${3:-}
    log "Waiting for BLACKHOLE status $prefix -> $expected_state ${expected_reason:+($expected_reason)}..."
    for i in $(seq 1 30); do
        local status
        status=$(blackhole_status "$prefix")
        local state=${status%%|*}
        local reason=${status#*|}
        if [ "$state" = "$expected_state" ] \
            && { [ -z "$expected_reason" ] || [ "$reason" = "$expected_reason" ]; }; then
            ok "$prefix BLACKHOLE status is $state/$reason after ${i}s"
            return 0
        fi
        sleep 1
    done
    fail "$prefix BLACKHOLE status did not become $expected_state/${expected_reason:-*} (last: $(blackhole_status "$prefix"))"
    dump_state_on_failure
    return 1
}

wait_kernel_blackhole_marker() {
    local prefix=$1
    log "Waiting for marker kernel blackhole route $prefix..."
    for i in $(seq 1 30); do
        if kernel_blackhole_marker_present "$prefix"; then
            ok "$prefix installed as kernel blackhole route (proto bgp) after ${i}s"
            return 0
        fi
        sleep 1
    done
    fail "$prefix did not install as a proto-bgp kernel blackhole route"
    dump_state_on_failure
    return 1
}

# ---------------------------------------------------------------------------
# Phase 1 — baseline: both discards installed (the M41 path)
# ---------------------------------------------------------------------------

resolve_grpc_addr
log "rustbgpd container: $RUSTBGPD"
log "FRR container: $FRR"

# Keep a daemon log inside the container for post-mortems — the M41
# start script execs rustbgpd with output otherwise discarded by the
# detached docker exec.
start_rustbgpd "/usr/local/bin/start-rustbgpd.sh >/var/log/rustbgpd.log 2>&1" || exit 1

wait_frr_established "$FRR" "10.0.0.1" "rustbgpd ↔ FRR" || exit 1

wait_kernel_blackhole_marker "$PREFIX_A" || exit 1
wait_kernel_blackhole_marker "$PREFIX_B" || exit 1
wait_blackhole_status "$PREFIX_A" "installed" || exit 1
wait_blackhole_status "$PREFIX_B" "installed" || exit 1

# ---------------------------------------------------------------------------
# Phase 2 — plant a foreign row while rustbgpd is running
# ---------------------------------------------------------------------------

# `proto static`, so it lacks the RTPROT_BGP half of the ownership
# marker: never adopted, never reaped. Same table, same RTN_BLACKHOLE
# type — a real negative test for the marker discriminator.
log "Planting foreign blackhole row $FOREIGN_PREFIX (proto static) while rustbgpd is running..."
docker exec "$RUSTBGPD" ip route add blackhole "$FOREIGN_PREFIX" proto static
if kernel_blackhole_foreign_present "$FOREIGN_PREFIX"; then
    ok "foreign proto-static blackhole row $FOREIGN_PREFIX planted"
else
    fail "foreign blackhole row $FOREIGN_PREFIX did not land"
fi

# ---------------------------------------------------------------------------
# Phase 3 — SIGKILL: kernel rows must outlive the process
# ---------------------------------------------------------------------------

# Keep the first lifetime's log around for post-mortems — the restart
# invocation truncates /var/log/rustbgpd.log.
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

# The crash-leftover premise: kernel discard rows survive the dead owner.
if kernel_blackhole_marker_present "$PREFIX_A"; then
    ok "row A survived the SIGKILL (proto bgp, kernel-resident)"
else
    fail "row A vanished with the process — no crash leftover to adopt"
    rb_route "$PREFIX_A" >&2
fi
if kernel_blackhole_marker_present "$PREFIX_B"; then
    ok "row B survived the SIGKILL (proto bgp, kernel-resident)"
else
    fail "row B vanished with the process — no crash leftover to adopt"
    rb_route "$PREFIX_B" >&2
fi
if kernel_blackhole_foreign_present "$FOREIGN_PREFIX"; then
    ok "foreign row $FOREIGN_PREFIX still present after the SIGKILL"
else
    fail "foreign row $FOREIGN_PREFIX disappeared after the SIGKILL"
fi

# ---------------------------------------------------------------------------
# Phase 4 — withdraw prefix B on FRR while rustbgpd is down
# ---------------------------------------------------------------------------

log "Withdrawing $PREFIX_B on FRR while rustbgpd is down..."
docker exec "$FRR" vtysh \
    -c 'configure terminal' \
    -c 'router bgp 65002' \
    -c 'address-family ipv4 unicast' \
    -c "no network $PREFIX_B" >/dev/null 2>&1

# Make sure FRR will not re-advertise B: poll its BGP table until the
# prefix is gone.
b_withdrawn=0
for _ in $(seq 1 30); do
    # Capture the output only when vtysh actually answered: a failed
    # exec must read as "still unknown", not "withdrawn", or a
    # momentarily unavailable FRR would falsely pass the gate.
    if out=$(docker exec "$FRR" vtysh -c "show ip bgp $PREFIX_B" 2>/dev/null) \
        && printf '%s\n' "$out" | grep -q "Network not in table"; then
        b_withdrawn=1
        break
    fi
    sleep 1
done
if [ "$b_withdrawn" -eq 1 ]; then
    ok "FRR withdrew $PREFIX_B (will not re-advertise)"
else
    fail "FRR still carries $PREFIX_B after the network statement was removed"
    docker exec "$FRR" vtysh -c "show ip bgp $PREFIX_B" >&2 || true
fi

# ---------------------------------------------------------------------------
# Phase 5 — restart with a short adoption-reap deferral
# ---------------------------------------------------------------------------

log "Restarting rustbgpd with RUSTBGPD_BLACKHOLE_ADOPTION_REAP_DEFERRAL_SECS=${REAP_DEFERRAL_SECS}..."
restart_epoch=$(date +%s)
start_rustbgpd "RUSTBGPD_BLACKHOLE_ADOPTION_REAP_DEFERRAL_SECS=${REAP_DEFERRAL_SECS} /usr/local/bin/start-rustbgpd.sh >/var/log/rustbgpd.log 2>&1" || exit 1

# Adoption window: poll every second. Row A must NEVER disappear —
# the sweep adopts it, then the re-advertised route re-claims it; a
# transient reap+reinstall would show up at this grain. Row B must be
# reaped (adopted, unclaimed) once the deferral passes and a
# reconcile pass fires — but never before the deferral: while it
# waits, ListBlackholeDiscards must surface it as
# installed/adopted_pending_reap (a state only emitted before the
# reap deadline). A is asserted for REAP_MARGIN_SECS beyond B's reap
# so the reap pass itself is covered.
log "Polling the reap window (A continuous, B pending then reaped within ${REAP_WINDOW_SECS}s)..."
a_held=1
b_reaped_after=""
b_pending_seen=0
margin_left="$REAP_MARGIN_SECS"
i=0
while :; do
    i=$((i + 1))
    if ! kernel_blackhole_marker_present "$PREFIX_A"; then
        a_held=0
        fail "row A disappeared or lost its proto-bgp marker ${i}s after restart"
        rb_route "$PREFIX_A" >&2
        break
    fi
    if [ -z "$b_reaped_after" ]; then
        if ! kernel_blackhole_present "$PREFIX_B"; then
            b_reaped_after="$i"
            b_reap_elapsed=$(( $(date +%s) - restart_epoch ))
        else
            if [ "$(blackhole_status "$PREFIX_B")" = "installed|adopted_pending_reap" ]; then
                b_pending_seen=1
            fi
            if [ "$i" -ge "$REAP_WINDOW_SECS" ]; then
                break
            fi
        fi
    else
        margin_left=$((margin_left - 1))
        if [ "$margin_left" -le 0 ]; then
            break
        fi
    fi
    sleep 1
done

if [ "$a_held" -eq 1 ]; then
    ok "row A stayed present with the proto-bgp marker across the reap window"
fi
if [ -n "$b_reaped_after" ]; then
    ok "row B reaped ${b_reaped_after}s after restart (deferral ${REAP_DEFERRAL_SECS}s)"
    # `restart_epoch` predates the daemon's own deferral clock, so
    # this is a conservative not-before bound; the pending-state
    # assert below is the structural half of the same property.
    if [ "${b_reap_elapsed:-0}" -ge "$REAP_DEFERRAL_SECS" ]; then
        ok "row B outlived the deferral (reaped ${b_reap_elapsed}s after restart began, >= ${REAP_DEFERRAL_SECS}s)"
    else
        fail "row B reaped ${b_reap_elapsed}s after restart began — before the ${REAP_DEFERRAL_SECS}s deferral"
    fi
else
    if [ "$a_held" -eq 1 ]; then
        fail "row B was not reaped within ${REAP_WINDOW_SECS}s"
        dump_state_on_failure
    fi
fi
if [ "$b_pending_seen" -eq 1 ]; then
    ok "row B surfaced as installed/adopted_pending_reap before the reap"
else
    fail "row B never surfaced as adopted_pending_reap — reap may have fired without the deferral"
fi

# A must have been re-claimed: status reads installed with reason
# `adopted` (the claiming pass) or `owned` (steady state thereafter).
a_status=$(blackhole_status "$PREFIX_A")
case "$a_status" in
    "installed|adopted"|"installed|owned")
        ok "row A status after the sweep is $a_status (adopted + re-claimed)"
        ;;
    *)
        fail "row A status after the sweep is '$a_status' (want installed/adopted or installed/owned)"
        dump_state_on_failure
        ;;
esac

# B must be gone from the status surface once reaped — nothing owns
# or tracks the prefix anymore.
b_status=$(blackhole_status "$PREFIX_B")
if [ "$b_status" = "MISSING" ]; then
    ok "row B is gone from ListBlackholeDiscards after the reap"
else
    fail "row B still on ListBlackholeDiscards after the reap (status: $b_status)"
    dump_state_on_failure
fi

# Foreign row: unmarked, untouched, never adopted (no status row).
if kernel_blackhole_foreign_present "$FOREIGN_PREFIX"; then
    ok "foreign row $FOREIGN_PREFIX survived the kill-and-restart cycle (still proto static)"
else
    fail "foreign row $FOREIGN_PREFIX was deleted or re-protoed"
    rb_route "$FOREIGN_PREFIX" >&2
fi
foreign_status=$(blackhole_status "$FOREIGN_PREFIX")
if [ "$foreign_status" = "MISSING" ]; then
    ok "foreign row $FOREIGN_PREFIX was never adopted (no status row)"
else
    fail "foreign row $FOREIGN_PREFIX has a status row (status: $foreign_status)"
    dump_state_on_failure
fi

# ---------------------------------------------------------------------------
# Phase 6 — Prometheus adoption/reap counters
# ---------------------------------------------------------------------------

# Counters are process-local, so the restarted daemon reports exactly
# this cycle: A + B adopted on the first sweep pass (BGP cannot have
# reconverged before it), B reaped. Allow a short settle.
log "Polling Prometheus for the adoption/reap counters..."
adopted=""
reaped=""
for _ in $(seq 1 15); do
    adopted=$(prom_counter "bgp_blackhole_discard_adopted_total")
    reaped=$(prom_counter "bgp_blackhole_discard_reaped_total")
    if [ "${adopted:-0}" -ge 2 ] 2>/dev/null && [ "${reaped:-0}" -eq 1 ] 2>/dev/null; then
        break
    fi
    sleep 1
done
if [ "${adopted:-0}" -ge 2 ] 2>/dev/null; then
    ok "bgp_blackhole_discard_adopted_total=$adopted (>= 2)"
else
    fail "bgp_blackhole_discard_adopted_total='$adopted' (want >= 2)"
    prom_scrape | grep -E '^bgp_blackhole' >&2 || true
fi
if [ "${reaped:-0}" -eq 1 ] 2>/dev/null; then
    ok "bgp_blackhole_discard_reaped_total=$reaped (== 1)"
else
    fail "bgp_blackhole_discard_reaped_total='$reaped' (want 1)"
    prom_scrape | grep -E '^bgp_blackhole' >&2 || true
fi

print_summary
