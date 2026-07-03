#!/usr/bin/env bash
# M51 interop test — ADR-0067 single-hop BFD + RFC 5882 coupling vs FRR bfdd.
#
# rustbgpd and FRR peer with BFD enabled (fast profile) and a 90 s BGP hold
# timer. The test proves:
#   1. BGP reaches Established AND BFD reaches Up — asserted from BOTH sides
#      (rustbgpd GetBfdSessions + FRR `show bfd peers`).
#   2. Failover: killing FRR's bfdd makes BFD fail; rustbgpd's BFD detection
#      window is ~900 ms (300 ms × 3), and the RFC 5882 coupling tears the BGP
#      session down far under the 90 s hold timer — proving the coupling, not a
#      hold-timer expiry. (The assertions poll up to 10 s for CI headroom.)
#   3. Recovery: watchfrr restarts bfdd; BFD and BGP re-establish.
#
# Prerequisites:
#   - docker build --target dev -t rustbgpd:dev .
#   - containerlab deploy -t tests/interop/m51-bfd-frr.clab.yml
#   - grpcurl + jq installed on the host

set -euo pipefail

TOPO="m51-bfd-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"
FRR1="clab-${TOPO}-frr1"
PEER="10.0.0.2"

resolve_grpc_addr
start_rustbgpd

# --- 1. BGP Established + BFD Up (both sides) --------------------------------

wait_frr_established "$FRR1" "10.0.0.1" "rustbgpd ↔ frr1"

grpc_bfd_state() {
    # State of the BFD session to $PEER as reported by rustbgpd, e.g.
    # "BFD_SESSION_STATE_UP". Empty if the session is absent.
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"peer_address\": \"$PEER\"}" \
        "$GRPC_ADDR" rustbgpd.v1.BfdService/GetBfdSessions 2>/dev/null \
        | jq -r '.sessions[0].state // ""'
}

grpc_bgp_state() {
    # rustbgpd's own view of the BGP session FSM state to $PEER.
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"address\": \"$PEER\"}" \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/GetNeighborState 2>/dev/null \
        | jq -r '.state // ""'
}

frr_bfd_status() {
    docker exec "$FRR1" vtysh -c "show bfd peers json" 2>/dev/null \
        | jq -r '.[0].status // ""'
}

dump_state_on_failure() {
    echo "===== rustbgpd GetBfdSessions (raw) =====" >&2
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"peer_address\": \"$PEER\"}" \
        "$GRPC_ADDR" rustbgpd.v1.BfdService/GetBfdSessions >&2 2>&1 || true
    echo "===== rustbgpd GetNeighborState (raw) =====" >&2
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"address\": \"$PEER\"}" \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/GetNeighborState >&2 2>&1 || true
    echo "===== frr1 vtysh: show bfd peers =====" >&2
    docker exec "$FRR1" vtysh -c 'show bfd peers' >&2 2>&1 || true
    echo "===== frr1 vtysh: show ip bgp summary =====" >&2
    docker exec "$FRR1" vtysh -c 'show ip bgp summary' >&2 2>&1 || true
}

wait_grpc_bfd() {
    local want=$1 label=$2 attempts=${3:-30}
    for _ in $(seq 1 "$attempts"); do
        [ "$(grpc_bfd_state)" = "$want" ] && {
            ok "rustbgpd BFD session $label"
            return 0
        }
        sleep 1
    done
    fail "rustbgpd BFD session did not reach $label"
    dump_state_on_failure
    return 1
}

wait_grpc_bfd "BFD_SESSION_STATE_UP" "Up"

for _ in $(seq 1 30); do
    [ "$(frr_bfd_status)" = "up" ] && break
    sleep 1
done
if [ "$(frr_bfd_status)" = "up" ]; then
    ok "FRR reports BFD peer Up"
else
    fail "FRR did not report BFD peer Up"
    dump_state_on_failure
fi

# --- 2. Failover: BFD down → BGP torn down faster than the hold timer --------

log "Killing FRR bfdd (single SIGKILL; watchfrr restarts it for recovery)..."
# A single kill is enough: rustbgpd's ~900 ms detection window fires long before
# watchfrr respawns bfdd, so the down/teardown below is observable. Re-killing in
# a loop would trip watchfrr's crash-loop backoff and bfdd would never come back
# (recovery leg). This mirrors the M11/M16 `killall -9 <daemon>` idiom.
docker exec "$FRR1" killall -9 bfdd 2>/dev/null || true

# rustbgpd's BFD must drop within a few detection windows — well under 90 s.
START=$(date +%s)
DROPPED=0
for _ in $(seq 1 10); do
    state=$(grpc_bfd_state)
    if [ "$state" != "BFD_SESSION_STATE_UP" ] && [ -n "$state" ]; then
        DROPPED=1
        break
    fi
    sleep 1
done
ELAPSED=$(( $(date +%s) - START ))
if [ "$DROPPED" -eq 1 ]; then
    ok "rustbgpd BFD went down ${ELAPSED}s after failure (<< 90 s hold timer)"
else
    fail "rustbgpd BFD did not go down within 10 s of the BFD failure"
    dump_state_on_failure
fi

# The RFC 5882 coupling must tear the BGP session down (not wait out the hold).
BGP_DOWN=0
for _ in $(seq 1 10); do
    state=$(grpc_bgp_state)
    if [ "$state" != "SESSION_STATE_ESTABLISHED" ]; then
        BGP_DOWN=1
        break
    fi
    sleep 1
done
ELAPSED=$(( $(date +%s) - START ))
if [ "$BGP_DOWN" -eq 1 ]; then
    ok "rustbgpd tore down BGP ${ELAPSED}s after BFD failure (<< 90 s hold timer)"
else
    fail "rustbgpd did not tear down BGP within 10 s (coupling not firing)"
    dump_state_on_failure
fi

# --- 3. Recovery: watchfrr restarts bfdd → BFD + BGP re-establish -----------

log "Waiting for BFD + BGP to recover (watchfrr restarts bfdd)..."
# Recovery is a full daemon cold-start: watchfrr respawn + bfdd init + zebra
# registration + the BFD three-way handshake, so allow a generous window.
wait_grpc_bfd "BFD_SESSION_STATE_UP" "Up again" 60
wait_frr_established "$FRR1" "10.0.0.1" "rustbgpd ↔ frr1 (recovered)"

print_summary
