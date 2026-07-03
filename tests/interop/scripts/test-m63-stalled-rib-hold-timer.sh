#!/usr/bin/env bash
# M63 — ADR-0078 stalled-RIB hold-timer survival proof (#422/#429).
#
# Inbound transport→RIB backpressure against a real FRR peer: the RIB
# manager is artificially stalled (RUSTBGPD_TEST_RIB_INGEST_STALL_MS=
# 12000, i.e. 12 s per RoutesReceived batch) and the RIB channel is
# shrunk (RUSTBGPD_TEST_RIB_CHANNEL_CAPACITY=2) so an FRR route flood
# saturates the channel and parks the session task on the blocking
# delivery. With hold_time 9 s on both sides, every per-batch park
# exceeds the negotiated hold time. Asserts:
#
# 1. Session reaches Established with the test envs active and the
#    negotiated hold time is 9 s.
# 2. FRR floods 4000 /32s in 8 waves of 500, spaced 2 s apart — the
#    wave spacing forces >= 8 distinct UPDATE batches regardless of
#    how densely FRR packs NLRI, so the guaranteed stall is
#    >= 8 x 12 s = 96 s >> 2 x hold (18 s), and >= 4 batches overflow
#    the 2-slot channel.
# 3. During a 40 s survival window inside the stall, the session
#    stays Established on BOTH ends. FRR's view is authoritative
#    (vtysh polled at 1 s grain with the capture-only-on-success
#    form: a failed exec reads as unknown, never a verdict).
#    rustbgpd's own gRPC view is polled with a short client timeout:
#    GetNeighborState round-trips both the session task (bounded
#    100 ms, reported as stale=true when parked) and the RIB query
#    channel (drained only between stalled batches, so the RPC
#    itself can block ~one stall interval) — a timeout or a
#    stale=true reading is an unknown (and corroborates the park),
#    but a fresh reading must be Established.
# 4. bgp_inbound_rib_backpressure_total{peer} > 0 — the channel
#    really filled and the block-never-drop path ran (strict).
# 5. bgp_hold_timer_rearmed_pending_input_total{peer} is logged,
#    informationally only — in THIS scenario it is expected to stay
#    0: the FSM restarts the hold timer when each parked delivery
#    completes (Event::UpdateReceived fires after the blocking RIB
#    send returns), so the select loop never observes an expired
#    deadline even though every park exceeds the hold time. The
#    pending-input re-arm path guards expiries that race genuinely
#    unprocessed input and stays covered by the transport unit
#    tests. Survival itself (FRR's hold timer fed by the
#    writer-owned cadence while we are parked) + backpressure +
#    never-drop + zero flaps are M63's deterministic receipts.
# 6. After the flood drains, rustbgpd's RIB holds EXACTLY the 4000
#    injected routes — the ADR-0078 never-drop receipt.
# 7. Zero session flaps over the whole run: rustbgpd flap_count == 0
#    and bgp_session_flaps_total == 0, FRR connectionsEstablished
#    == 1 with state Established.
#
# Usage:
#   docker build --target dev -t rustbgpd:dev .
#   containerlab deploy -t tests/interop/m63-stalled-rib-hold-timer.clab.yml
#   bash tests/interop/scripts/test-m63-stalled-rib-hold-timer.sh
#   containerlab destroy -t tests/interop/m63-stalled-rib-hold-timer.clab.yml --cleanup

set -eu

TOPO="m63-stalled-rib-hold-timer"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

FRR="clab-${TOPO}-frr"
RUSTBGPD_IP="10.63.0.1"
FRR_IP="10.63.0.2"

STALL_MS=12000
CHANNEL_CAPACITY=2
HOLD_TIME=9
WAVES=8
ROUTES_PER_WAVE=500
WAVE_GAP_SECS=2
TOTAL_ROUTES=$((WAVES * ROUTES_PER_WAVE))
# Must exceed 2 x hold (18 s) and sit inside the guaranteed stall
# (>= WAVES x 12 s = 96 s).
SURVIVAL_WINDOW_SECS=40
# Drain bound: WAVES batches x 12 s stall each is the floor; FRR may
# split waves into more batches, so leave generous headroom.
DRAIN_BOUND_SECS=360

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Scrape Prometheus via the container's management IP (M60 pattern —
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

# Sum a labeled counter across all label sets (the peer label is the
# remote SocketAddr, whose port differs between inbound and outbound
# session shapes). Prints 0 when no series exists.
prom_labeled_sum() {
    local name=${1:?}
    prom_scrape | awk -v n="$name" \
        'index($1, n "{") == 1 { s += $2 } END { printf "%d\n", s + 0 }'
}

grpc_neighbor_state() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"address\":\"${FRR_IP}\"}" \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/GetNeighborState 2>/dev/null
}

# Survival-window variant with a short client deadline: the RPC fills
# RIB-side policy counters through the priority query channel, which
# the stalled manager drains only between batches, so an unbounded
# call can block ~one stall interval and wreck the 1 s poll grain. A
# timeout is an unknown reading (and itself evidence of the stall).
grpc_neighbor_state_quick() {
    grpcurl -plaintext -max-time 2 -import-path . -proto "$PROTO" \
        -d "{\"address\":\"${FRR_IP}\"}" \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/GetNeighborState 2>/dev/null
}

# RIB-side received-route count (the never-drop receipt must come
# from the RIB, not the transport's own bookkeeping). total_count is
# pagination-proof.
rib_received_count() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"neighbor_address\":\"${FRR_IP}\"}" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null \
        | jq -r '.totalCount // 0'
}

# FRR's view of the session, JSON. Callers must only consume the
# output when the exec itself succeeded.
frr_neighbor_json() {
    docker exec "$FRR" vtysh -c "show bgp neighbors ${RUSTBGPD_IP} json" 2>/dev/null
}

dump_state_on_failure() {
    echo "===== rustbgpd GetNeighborState ${FRR_IP} =====" >&2
    grpc_neighbor_state | jq . >&2 || true
    echo "===== rustbgpd ADR-0078 metrics =====" >&2
    prom_scrape | grep -E '^bgp_(inbound_rib_backpressure|hold_timer_rearmed|session_flaps)' >&2 || true
    echo "===== rustbgpd log tail =====" >&2
    docker exec "$RUSTBGPD" tail -60 /var/log/rustbgpd.log >&2 || true
    echo "===== FRR vtysh: BGP summary =====" >&2
    docker exec "$FRR" vtysh -c 'show ip bgp summary' >&2 || true
}

# ---------------------------------------------------------------------------
# Phase 1 — start rustbgpd with the ADR-0078 fault-injection envs
# ---------------------------------------------------------------------------

resolve_grpc_addr
log "rustbgpd container: $RUSTBGPD"
log "FRR container: $FRR"
log "Stall ${STALL_MS} ms/batch, channel capacity ${CHANNEL_CAPACITY}, hold ${HOLD_TIME} s"
log "Flood: ${WAVES} waves x ${ROUTES_PER_WAVE} routes, ${WAVE_GAP_SECS} s apart (${TOTAL_ROUTES} total)"

start_rustbgpd "RUSTBGPD_TEST_RIB_INGEST_STALL_MS=${STALL_MS} RUSTBGPD_TEST_RIB_CHANNEL_CAPACITY=${CHANNEL_CAPACITY} /usr/local/bin/start-rustbgpd.sh" || exit 1

wait_frr_established "$FRR" "$RUSTBGPD_IP" "rustbgpd ↔ FRR" || exit 1

# Confirm the negotiated hold time is the small one the survival
# math depends on.
neg_hold=""
if frr_json=$(frr_neighbor_json); then
    neg_hold=$(printf '%s\n' "$frr_json" \
        | jq -r --arg p "$RUSTBGPD_IP" '.[$p].bgpTimerHoldTimeMsecs // empty')
fi
if [ "$neg_hold" = "$((HOLD_TIME * 1000))" ]; then
    ok "negotiated hold time is ${HOLD_TIME} s (${neg_hold} ms)"
else
    fail "negotiated hold time is '${neg_hold}' ms (want $((HOLD_TIME * 1000)))"
fi

# ---------------------------------------------------------------------------
# Phase 2 — flood: 8 waves of 500 /32 Null0 statics, 2 s apart
# ---------------------------------------------------------------------------

# Each wave is one `vtysh -f` load of pre-generated `ip route X/32
# Null0` lines (Null0 statics are always active, so resolution can't
# flake) that redistribute into BGP. The inter-wave gap is far above
# FRR's sub-second UPDATE coalescing, so each wave yields at least
# one distinct UPDATE batch no matter how densely FRR packs NLRI —
# that lower-bounds the batch count, and with it the guaranteed
# stall, without trusting packing behavior.
log "Injecting ${WAVES} waves of ${ROUTES_PER_WAVE} /32 statics on FRR..."
inject_start=$(date +%s)
for w in $(seq 0 $((WAVES - 1))); do
    base=$((w * ROUTES_PER_WAVE))
    docker exec "$FRR" sh -c "
        i=${base}
        end=$((base + ROUTES_PER_WAVE))
        : > /tmp/m63-wave.conf
        while [ \$i -lt \$end ]; do
            echo \"ip route 10.200.\$((i / 250)).\$((i % 250 + 1))/32 Null0\" >> /tmp/m63-wave.conf
            i=\$((i + 1))
        done
        vtysh -f /tmp/m63-wave.conf >/dev/null 2>&1
    " || { fail "wave $((w + 1)) injection failed"; exit 1; }
    log "  wave $((w + 1))/${WAVES} injected (routes ${base}..$((base + ROUTES_PER_WAVE - 1)))"
    if [ "$w" -lt $((WAVES - 1)) ]; then
        sleep "$WAVE_GAP_SECS"
    fi
done
ok "all ${TOTAL_ROUTES} routes injected on FRR ($(($(date +%s) - inject_start)) s)"

# ---------------------------------------------------------------------------
# Phase 3 — survival window: Established on both ends at 1 s grain
# ---------------------------------------------------------------------------

# The guaranteed stall is >= WAVES x 12 s = 96 s, so this whole 40 s
# window sits inside it, and 40 s >> 2 x hold (18 s): if the writer
# task's KEEPALIVE cadence or the pending-input hold re-arm were
# broken, one side would have expired its hold timer well before the
# window ends (that is exactly how the pre-#422 bug presented).
log "Survival window: polling both ends every 1 s for ${SURVIVAL_WINDOW_SECS} s..."
window_start=$(date +%s)
frr_established=0
frr_unknown=0
rb_established=0
rb_parked=0
survival_failed=0
while [ $(($(date +%s) - window_start)) -lt "$SURVIVAL_WINDOW_SECS" ]; do
    # FRR side — capture output only when the exec succeeds; a failed
    # exec is an unknown, never a verdict.
    if frr_json=$(frr_neighbor_json); then
        frr_state=$(printf '%s\n' "$frr_json" \
            | jq -r --arg p "$RUSTBGPD_IP" '.[$p].bgpState // empty')
        if [ "$frr_state" = "Established" ]; then
            frr_established=$((frr_established + 1))
        elif [ -n "$frr_state" ]; then
            fail "FRR saw state '$frr_state' $(($(date +%s) - window_start)) s into the survival window"
            survival_failed=1
            break
        else
            frr_unknown=$((frr_unknown + 1))
        fi
    else
        frr_unknown=$((frr_unknown + 1))
    fi

    # rustbgpd side — a timed-out RPC (RIB query channel blocked
    # behind a stalled batch) and a stale=true reading (parked
    # session task missed the bounded QueryState deadline) are both
    # expected unknowns that corroborate the park; only a fresh
    # reading carries a verdict.
    if rb_json=$(grpc_neighbor_state_quick) && [ -n "$rb_json" ]; then
        rb_stale_flag=$(printf '%s\n' "$rb_json" | jq -r '.stale // false')
        rb_state=$(printf '%s\n' "$rb_json" | jq -r '.state // empty')
        if [ "$rb_stale_flag" = "true" ]; then
            rb_parked=$((rb_parked + 1))
        elif [ "$rb_state" = "SESSION_STATE_ESTABLISHED" ]; then
            rb_established=$((rb_established + 1))
        else
            fail "rustbgpd saw non-stale state '$rb_state' $(($(date +%s) - window_start)) s into the survival window"
            survival_failed=1
            break
        fi
    else
        rb_parked=$((rb_parked + 1))
    fi

    sleep 1
done
window_span=$(($(date +%s) - window_start))
log "Survival window (${window_span} s): FRR established=${frr_established} unknown=${frr_unknown}; rustbgpd established=${rb_established} parked/stale/timeout=${rb_parked}"
# Gate: no contradicting reading on either end, and enough positive
# FRR confirmations spread across the window to witness the whole
# > 2 x hold span (each iteration is >= 1 s; the rustbgpd poll's 2 s
# client deadline caps an iteration at ~3 s, so 10 confirmations
# cover >= 10 s of grain across the >= 40 s span).
if [ "$survival_failed" -eq 0 ] && [ "$frr_established" -ge 10 ]; then
    ok "session stayed Established on both ends across the ${window_span} s survival window (> 2 x hold = $((2 * HOLD_TIME)) s)"
else
    [ "$survival_failed" -eq 0 ] && fail "too few FRR Established readings (${frr_established}) — window inconclusive"
    dump_state_on_failure
fi
if [ "$rb_parked" -gt 0 ]; then
    ok "rustbgpd QueryState read as parked ${rb_parked} time(s) (stale or RPC deadline) — the session task really parked on the RIB channel"
else
    log "NOTE: no parked QueryState readings observed (parking not caught at this grain)"
fi

# ---------------------------------------------------------------------------
# Phase 4 — drain: every injected route must land (never-drop receipt)
# ---------------------------------------------------------------------------

log "Waiting for the flood to drain (count stable at ${TOTAL_ROUTES}, bound ${DRAIN_BOUND_SECS} s)..."
drain_start=$(date +%s)
last_count=0
drained=0
while [ $(($(date +%s) - drain_start)) -lt "$DRAIN_BOUND_SECS" ]; do
    count=$(rib_received_count || echo "")
    if [ -n "$count" ] && [ "$count" != "$last_count" ]; then
        log "  RIB received-route count: $count"
        last_count=$count
    fi
    if [ "${count:-0}" = "$TOTAL_ROUTES" ]; then
        drained=1
        break
    fi
    sleep 5
done
if [ "$drained" -eq 1 ]; then
    elapsed=$(($(date +%s) - inject_start))
    ok "flood drained: RIB holds ${TOTAL_ROUTES} routes ${elapsed} s after injection started"
else
    fail "RIB count stuck at '${last_count}' after ${DRAIN_BOUND_SECS} s (want ${TOTAL_ROUTES})"
    dump_state_on_failure
fi

# Stability + exactness: poll once more after a full stalled batch
# interval has provably elapsed — the count must still be EXACTLY
# the injected number (a drop would undershoot; a duplicate-delivery
# bug would overshoot).
sleep $(( STALL_MS / 1000 + 1 ))
final_count=$(rib_received_count || echo "")
if [ "$final_count" = "$TOTAL_ROUTES" ]; then
    ok "never-drop receipt: RIB received-route count == ${TOTAL_ROUTES} exactly and stable"
else
    fail "RIB count moved to '${final_count}' after drain (want exactly ${TOTAL_ROUTES})"
    dump_state_on_failure
fi

# ---------------------------------------------------------------------------
# Phase 5 — ADR-0078 saturation + re-arm counters
# ---------------------------------------------------------------------------

backpressure=$(prom_labeled_sum "bgp_inbound_rib_backpressure_total")
if [ "${backpressure:-0}" -gt 0 ]; then
    ok "bgp_inbound_rib_backpressure_total=${backpressure} (> 0): the channel filled and the session parked instead of dropping"
else
    fail "bgp_inbound_rib_backpressure_total=${backpressure} — the channel never saturated; the scenario did not exercise ADR-0078"
    dump_state_on_failure
fi

# Informational only (see header): in this scenario the counter is
# expected to be 0 — every park ends with the UPDATE's normal hold
# reset (Event::UpdateReceived fires after the blocking send
# returns), so the select loop never sees an expired deadline. The
# pending-input re-arm path is pinned by transport unit tests; what
# M63 pins is that the parks themselves never expire either side.
rearmed=$(prom_labeled_sum "bgp_hold_timer_rearmed_pending_input_total")
log "bgp_hold_timer_rearmed_pending_input_total=${rearmed} (informational — expected 0 in this shape; see script header)"

# ---------------------------------------------------------------------------
# Phase 6 — zero flaps end to end, both views
# ---------------------------------------------------------------------------

# Post-drain the session task is responsive again, so a fresh
# (stale=false) reading must be available within a few seconds.
rb_flaps=""
rb_state=""
for _ in $(seq 1 10); do
    if rb_json=$(grpc_neighbor_state) && [ -n "$rb_json" ] \
        && [ "$(printf '%s\n' "$rb_json" | jq -r '.stale // false')" = "false" ]; then
        rb_state=$(printf '%s\n' "$rb_json" | jq -r '.state // empty')
        rb_flaps=$(printf '%s\n' "$rb_json" | jq -r '.flapCount // 0')
        break
    fi
    sleep 1
done
if [ "$rb_state" = "SESSION_STATE_ESTABLISHED" ] && [ "${rb_flaps:-1}" = "0" ]; then
    ok "rustbgpd: Established with flap_count=0 after the run"
else
    fail "rustbgpd post-run state='${rb_state}' flap_count='${rb_flaps}' (want Established / 0)"
    dump_state_on_failure
fi

flap_metric=$(prom_labeled_sum "bgp_session_flaps_total")
if [ "${flap_metric:-1}" = "0" ]; then
    ok "bgp_session_flaps_total=0 — no transitions out of Established all run"
else
    fail "bgp_session_flaps_total=${flap_metric} (want 0)"
    dump_state_on_failure
fi

frr_drops=""
frr_estab_count=""
frr_state=""
if frr_json=$(frr_neighbor_json); then
    frr_state=$(printf '%s\n' "$frr_json" \
        | jq -r --arg p "$RUSTBGPD_IP" '.[$p].bgpState // empty')
    frr_estab_count=$(printf '%s\n' "$frr_json" \
        | jq -r --arg p "$RUSTBGPD_IP" '.[$p].connectionsEstablished // empty')
    frr_drops=$(printf '%s\n' "$frr_json" \
        | jq -r --arg p "$RUSTBGPD_IP" '.[$p].connectionsDropped // empty')
fi
if [ "$frr_state" = "Established" ] && [ "$frr_estab_count" = "1" ] && [ "$frr_drops" = "0" ]; then
    ok "FRR: Established with connectionsEstablished=1, connectionsDropped=0 — its hold timer never expired"
else
    fail "FRR post-run state='${frr_state}' connectionsEstablished='${frr_estab_count}' connectionsDropped='${frr_drops}' (want Established/1/0)"
    dump_state_on_failure
fi

print_summary
