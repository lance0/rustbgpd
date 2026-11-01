#!/usr/bin/env bash
# M51b interop test — single-hop BFD for [[dynamic_neighbors]] range sessions
# vs FRR bfdd.
#
# rustbgpd has only a dynamic range (10.0.0.0/16) with `bfd = { profile =
# "fast" }`: 300 ms × 3 ≈ 900 ms detection, 90 s BGP hold timer. frr1 and
# frr2 dial in over separate links. The test proves:
#   1. Both accepted sessions reach Established and BFD Up, from both sides
#      (rustbgpd GetBfdSessions + bfd_session_up, FRR `show bfd peers`).
#   2. Failure: frr1 is frozen with `docker pause` (the cgroup freezer: no
#      kernel module, unlike netem), so its bfdd stops sending while the link
#      and carrier stay up.
#      rustbgpd's BFD for 10.0.0.2 goes Down within the detection time plus
#      the polling margin, and the session is torn down with a Cease / BFD
#      Down NOTIFICATION (RFC 9384 subcode 10, inside an RFC 8538 Hard Reset
#      when the N bit is negotiated), far under the hold timer. The ended
#      session's BFD session and `bfd_session_up` series are removed with it.
#      frr2's BGP session and BFD session stay up, without a flap.
#   3. Recovery: once frr1 is unpaused, it dials in again and the
#      new session's BFD session comes Up on both sides.
#
# Prerequisites:
#   - docker build --target dev -t rustbgpd:dev .
#   - containerlab deploy -t tests/interop/m51b-bfd-dynamic-frr.clab.yml
#   - grpcurl + jq installed on the host

set -euo pipefail

TOPO="m51b-bfd-dynamic-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
source "$SCRIPT_DIR/test-lib.sh"
FRR1="clab-${TOPO}-frr1"
FRR2="clab-${TOPO}-frr2"
PEER1="10.0.0.2"
PEER2="10.0.1.2"
LOCAL1="10.0.0.1"
LOCAL2="10.0.1.1"
LOG="/tmp/rustbgpd-m51b.log"
# The detection time (300 ms × 3) plus the 100 ms poll and gRPC round trip.
DETECT_BOUND_MS=2000
# The detection time plus 600 ms for scheduling jitter on a shared runner.
DETECT_LOG_BOUND_MS=1500

resolve_grpc_addr
start_rustbgpd "exec /usr/local/bin/rustbgpd /etc/rustbgpd/config.toml >$LOG 2>&1"

rb_bfd_state() {
    # rustbgpd's BFD state for $1, or empty when it runs no session to $1.
    grpcurl_call -d "{}" "$GRPC_ADDR" rustbgpd.v1.BfdService/GetBfdSessions 2>/dev/null \
        | jq -r --arg peer "$1" '[.sessions[]? | select(.peerAddress == $peer)][0].state // ""'
}

rb_bfd_peers() {
    grpcurl_call -d "{}" "$GRPC_ADDR" rustbgpd.v1.BfdService/GetBfdSessions 2>/dev/null \
        | jq -r '[.sessions[]?.peerAddress] | sort | join(",")'
}

rb_neighbor_json() {
    grpcurl_call -d "{\"address\": \"$1\"}" \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/GetNeighborState 2>/dev/null
}

rb_established() {
    rb_neighbor_json "$1" | jq -e '(.stale // false) == false
        and .state == "SESSION_STATE_ESTABLISHED"' >/dev/null
}

rb_not_established() {
    ! rb_established "$1"
}

bfd_session_absent() {
    [[ ",$(rb_bfd_peers)," != *",$1,"* ]]
}

rb_flaps() {
    rb_neighbor_json "$1" | jq -er 'select((.stale // false) == false)
        | (.flapCount // "0") | tostring'
}

bfd_up_gauge() {
    prom_scrape "$RUSTBGPD" | awk -v peer="peer=\"$1\"" '
        /^bfd_session_up\{/ && index($0, peer) { print $2; exit }'
}

frr_bfd_status() {
    docker exec "$1" vtysh -c "show bfd peers json" 2>/dev/null \
        | jq -r --arg peer "$2" '[.[] | select(.peer == $peer)][0].status // ""'
}

frr_connections() {
    docker exec "$1" vtysh -c "show bgp neighbors $2 json" 2>/dev/null \
        | jq -r --arg peer "$2" '.[$peer].connectionsEstablished // empty'
}

both_bfd_up() {
    [ "$(rb_bfd_state "$1")" = "BFD_SESSION_STATE_UP" ] \
        && [ "$(frr_bfd_status "$2" "$3")" = "up" ]
}

bfd_down_notification_logs() {
    # Sent NOTIFICATIONs to $1 whose cause is BFD Down: Cease/10, or the
    # RFC 8538 Hard Reset (6/9) that wraps it when the N bit is negotiated.
    docker exec "$RUSTBGPD" cat "$LOG" \
        | jq -Rsc --arg peer "$1" '[split("\n")[] | fromjson?
            | .fields | select(.peer == $peer and .direction == "sent" and .code == 6
                and ((.subcode == 10) or (.subcode == 9
                    and ((.description // "") | test("BFD Down")))))] | length'
}

now_ms() { date +%s%3N; }

dump_state_on_failure() {
    echo "===== rustbgpd GetBfdSessions =====" >&2
    grpcurl_call -d "{}" "$GRPC_ADDR" rustbgpd.v1.BfdService/GetBfdSessions >&2 2>&1 || true
    for frr in "$FRR1" "$FRR2"; do
        echo "===== $frr show bfd peers / show bgp summary =====" >&2
        docker exec "$frr" vtysh -c 'show bfd peers' -c 'show bgp summary' >&2 2>&1 || true
    done
    echo "===== rustbgpd log tail =====" >&2
    docker exec "$RUSTBGPD" tail -n 60 "$LOG" >&2 || true
}

# --- 1. Both dynamic sessions Established with BFD Up ------------------------

wait_frr_established "$FRR1" "$LOCAL1" "frr1 → rustbgpd range"
wait_frr_established "$FRR2" "$LOCAL2" "frr2 → rustbgpd range"

for pair in "$PEER1 $FRR1 $LOCAL1" "$PEER2 $FRR2 $LOCAL2"; do
    read -r peer frr local <<<"$pair"
    if wait_until 40 0.5 both_bfd_up "$peer" "$frr" "$local"; then
        ok "dynamic session $peer: BFD Up on rustbgpd and FRR"
    else
        fail "dynamic session $peer: BFD did not reach Up on both sides"
        dump_state_on_failure
    fi
    if [ "$(bfd_up_gauge "$peer")" = "1" ]; then
        ok "bfd_session_up{peer=\"$peer\"} = 1"
    else
        fail "bfd_session_up{peer=\"$peer\"} is '$(bfd_up_gauge "$peer")', not 1"
    fi
done

frr2_connections_before=$(frr_connections "$FRR2" "$LOCAL2")
frr2_flaps_before=$(rb_flaps "$PEER2" || echo "")
notifications_before=$(bfd_down_notification_logs "$PEER1")

# --- 2. Silent path failure on frr1: BFD tears its session down --------------

log "Freezing frr1 so its bfdd stops sending (the link stays up)..."
break_ms=$(now_ms)
if ! docker pause "$FRR1"; then
    fail "could not pause $FRR1 to inject the BFD failure"
    dump_state_on_failure
    print_summary
fi
applied_ms=$(now_ms)

down_ms=""
for _ in $(seq 1 100); do
    state=$(rb_bfd_state "$PEER1")
    if [ "$state" != "BFD_SESSION_STATE_UP" ]; then
        down_ms=$(now_ms)
        break
    fi
    sleep 0.1
done
if [ -n "$down_ms" ]; then
    elapsed=$((down_ms - break_ms))
    if [ "$elapsed" -le "$DETECT_BOUND_MS" ]; then
        ok "rustbgpd BFD for $PEER1 left Up ${elapsed} ms after the failure (detect 900 ms, bound ${DETECT_BOUND_MS} ms)"
    else
        fail "rustbgpd BFD for $PEER1 left Up only after ${elapsed} ms (bound ${DETECT_BOUND_MS} ms)"
    fi
else
    fail "rustbgpd BFD for $PEER1 stayed Up for 10 s after the failure"
    dump_state_on_failure
fi

if wait_until 50 0.2 rb_not_established "$PEER1"; then
    teardown_ms=$(( $(now_ms) - break_ms ))
    ok "rustbgpd tore the $PEER1 session down ${teardown_ms} ms after the failure (<< 90 s hold timer)"
else
    fail "rustbgpd kept the $PEER1 session Established after BFD Down"
    dump_state_on_failure
fi

# frr1 is frozen once `docker pause` returns, so detection fires at most one
# detection time (900 ms) after that; the daemon's own log stamps it.
down_log_ms=$(docker exec "$RUSTBGPD" cat "$LOG" \
    | jq -Rr --arg peer "$PEER1" 'fromjson? | select(.fields.peer == $peer
        and .fields.message == "BFD down — tearing down BGP session before the hold timer")
        | .timestamp' | tail -n 1 | xargs -r -I{} date -d {} +%s%3N)
if [ -n "$down_log_ms" ] && [ $((down_log_ms - applied_ms)) -le "$DETECT_LOG_BOUND_MS" ]; then
    ok "the daemon logged BFD Down for $PEER1 $((down_log_ms - applied_ms)) ms after frr1 was frozen (detect 900 ms, bound ${DETECT_LOG_BOUND_MS} ms)"
else
    fail "BFD Down for $PEER1 was not logged within ${DETECT_LOG_BOUND_MS} ms of the freeze (log ${down_log_ms:-none}, applied $applied_ms)"
fi

notifications_after=$(bfd_down_notification_logs "$PEER1")
if [ "$notifications_after" -gt "$notifications_before" ]; then
    ok "rustbgpd sent a Cease / BFD Down NOTIFICATION to $PEER1"
else
    fail "no Cease / BFD Down NOTIFICATION to $PEER1 in the rustbgpd log"
    dump_state_on_failure
fi

# The ended session took its BFD session and series with it.
wait_until 20 0.5 bfd_session_absent "$PEER1" || true
peers_now=$(rb_bfd_peers)
if [ "$peers_now" = "$PEER2" ]; then
    ok "the ended session's BFD session is removed; only $PEER2 remains"
else
    fail "BFD sessions after the teardown: '$peers_now' (expected '$PEER2')"
    dump_state_on_failure
fi
if [ -z "$(bfd_up_gauge "$PEER1")" ]; then
    ok "bfd_session_up{peer=\"$PEER1\"} is removed with its session"
else
    fail "bfd_session_up{peer=\"$PEER1\"} outlived its session ($(bfd_up_gauge "$PEER1"))"
fi

# frr2 never moved.
if [ "$(rb_bfd_state "$PEER2")" = "BFD_SESSION_STATE_UP" ] \
    && [ "$(frr_bfd_status "$FRR2" "$LOCAL2")" = "up" ] && rb_established "$PEER2" \
    && [ "$(frr_connections "$FRR2" "$LOCAL2")" = "$frr2_connections_before" ] \
    && [ "$(rb_flaps "$PEER2" || echo "")" = "$frr2_flaps_before" ]; then
    ok "frr2's session and BFD stayed up without a flap (FRR establishments $frr2_connections_before, local flaps ${frr2_flaps_before:-0})"
else
    fail "frr2's session or BFD moved during frr1's failure"
    dump_state_on_failure
fi

# --- 3. Recovery: a new session registers a new BFD session ------------------

log "Unpausing frr1; it dials in again..."
if ! docker unpause "$FRR1"; then
    fail "could not unpause $FRR1"
    dump_state_on_failure
    print_summary
fi
wait_frr_established "$FRR1" "$LOCAL1" "frr1 → rustbgpd range (recovered)"
if wait_until 40 0.5 both_bfd_up "$PEER1" "$FRR1" "$LOCAL1"; then
    ok "the recovered session's BFD is Up on both sides"
else
    fail "the recovered session's BFD did not reach Up"
    dump_state_on_failure
fi
if [ "$(rb_bfd_peers)" = "$PEER1,$PEER2" ]; then
    ok "both dynamic sessions run BFD again"
else
    fail "BFD sessions after recovery: '$(rb_bfd_peers)'"
fi

print_summary
