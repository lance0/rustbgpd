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
#   4. Strict + remote AdminDown: rustbgpd restarts in strict mode while FRR's
#      BFD peer is administratively shut down.  The local BFD session starts
#      Down and BGP is withheld; a fresh FRR AdminDown packet releases BGP while
#      GetBfdSessions remains truthfully Down.  `no shutdown` restores BFD Up
#      without BGP churn.
#
# Prerequisites:
#   - docker build --target dev -t rustbgpd:dev .
#   - containerlab deploy -t tests/interop/m51-bfd-frr.clab.yml
#   - grpcurl + jq installed on the host

set -euo pipefail

TOPO="m51-bfd-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
source "$SCRIPT_DIR/test-lib.sh"
FRR1="clab-${TOPO}-frr1"
PEER="10.0.0.2"
FRR_BFD_PEER="10.0.0.1"
STRICT_CONFIG="/etc/rustbgpd/config-strict.toml"
STRICT_LOG="/tmp/rustbgpd-m51-strict.log"

resolve_grpc_addr
start_rustbgpd

# --- 1. BGP Established + BFD Up (both sides) --------------------------------

wait_frr_established "$FRR1" "10.0.0.1" "rustbgpd ↔ frr1"

grpc_bfd_state() {
    # State of the BFD session to $PEER as reported by rustbgpd, e.g.
    # "BFD_SESSION_STATE_UP". Empty if the session is absent.
    grpc_bfd_json \
        | jq -r '.sessions[0].state // ""'
}

grpc_bfd_json() {
    grpcurl_call \
        -d "{\"peer_address\": \"$PEER\"}" \
        "$GRPC_ADDR" rustbgpd.v1.BfdService/GetBfdSessions 2>/dev/null
}

grpc_bfd_remote_admin_down() {
    # proto3 optional presence is part of the oracle: an older daemon omitting
    # field 5 is unknown, never silently equivalent to false.
    grpc_bfd_json | jq -er '
        .sessions[0] as $session
        | if ($session | type) != "object" then
            error("BFD session is absent")
          elif ($session | has("remoteAdministrativeDown")) then
            ($session.remoteAdministrativeDown | tostring)
          else
            error("remoteAdministrativeDown is absent")
          end
    '
}

grpc_bgp_json() {
    grpcurl_call \
        -d "{\"address\": \"$PEER\"}" \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/GetNeighborState 2>/dev/null
}

grpc_bgp_authoritative_json() {
    # GetNeighborState uses `stale=true` plus a placeholder Idle when its
    # bounded session-task query times out.  Missing/invalid JSON, a missing
    # state, and stale snapshots are all unknown — never evidence of BGP Down,
    # strict withholding, or session continuity.
    local snapshot
    snapshot=$(grpc_bgp_json) || return 1
    printf '%s\n' "$snapshot" | jq -e '
        type == "object"
        and ((.stale // false) == false)
        and (((.state // "") | type) == "string")
        and ((.state // "") | length > 0)
    ' >/dev/null || return 1
    printf '%s\n' "$snapshot"
}

grpc_bgp_state() {
    # Authoritative rustbgpd FSM state.  Returns non-zero for an empty, invalid,
    # missing-state, or stale snapshot so callers cannot false-green on Idle.
    grpc_bgp_authoritative_json | jq -er '.state'
}

wait_grpc_bgp_established() {
    local label=$1 attempts=${2:-30} state
    for _ in $(seq 1 "$attempts"); do
        if ! state=$(grpc_bgp_state); then
            fail "$label BGP state was unavailable or stale"
            dump_state_on_failure
            return 1
        fi
        if [ "$state" = "SESSION_STATE_ESTABLISHED" ]; then
            ok "$label BGP state is authoritatively Established"
            return 0
        fi
        sleep 1
    done
    fail "$label BGP state did not reach authoritative Established"
    dump_state_on_failure
    return 1
}

frr_bfd_status() {
    docker exec "$FRR1" vtysh -c "show bfd peers json" 2>/dev/null \
        | jq -r '.[0].status // ""'
}

frr_bgp_connections_established() {
    docker exec "$FRR1" vtysh \
        -c "show bgp neighbors $FRR_BFD_PEER json" 2>/dev/null \
        | jq -r --arg peer "$FRR_BFD_PEER" \
            '.[$peer].connectionsEstablished // empty'
}

frr_bfd_peer_command() {
    local command=${1:?}
    docker exec "$FRR1" vtysh \
        -c "configure terminal" \
        -c "bfd" \
        -c "peer $FRR_BFD_PEER" \
        -c "$command" >/dev/null 2>&1
}

frr_bfd_peer_admin_down_pulse() {
    # The peer is already shut down.  Toggle it in one vtysh transaction so
    # bfdd emits a fresh AdminDown after rustbgpd is listening, before a normal
    # transmit timer can move rustbgpd's local FSM out of Down.
    docker exec "$FRR1" vtysh \
        -c "configure terminal" \
        -c "bfd" \
        -c "peer $FRR_BFD_PEER" \
        -c "no shutdown" \
        -c "shutdown" >/dev/null 2>&1
}

stop_rustbgpd() {
    log "Stopping rustbgpd before the strict-mode phase..."
    if ! docker exec "$RUSTBGPD" sh -c '
        pids=$(pidof rustbgpd 2>/dev/null) || exit 1
        for pid in $pids; do
            kill -TERM "$pid" || exit 1
        done
    '; then
        fail "rustbgpd was not running or could not be signaled for strict-mode restart"
        dump_state_on_failure
        return 1
    fi
    for _ in $(seq 1 30); do
        if ! docker exec "$RUSTBGPD" pidof rustbgpd >/dev/null 2>&1; then
            ok "rustbgpd stopped cleanly"
            return 0
        fi
        sleep 1
    done
    fail "rustbgpd did not stop within 30 s"
    return 1
}

dump_state_on_failure() {
    echo "===== rustbgpd GetBfdSessions (raw) =====" >&2
    grpcurl_call \
        -d "{\"peer_address\": \"$PEER\"}" \
        "$GRPC_ADDR" rustbgpd.v1.BfdService/GetBfdSessions >&2 2>&1 || true
    echo "===== rustbgpd GetNeighborState (raw) =====" >&2
    grpcurl_call \
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

wait_grpc_bfd_remote_admin_down() {
    local want=$1 label=$2 attempts=${3:-30} observed
    for _ in $(seq 1 "$attempts"); do
        if observed=$(grpc_bfd_remote_admin_down) && [ "$observed" = "$want" ]; then
            ok "rustbgpd BFD remote AdminDown cause $label"
            return 0
        fi
        sleep 1
    done
    fail "rustbgpd BFD remote AdminDown cause did not become $label (wanted=$want, last=${observed:-unknown})"
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
BGP_STATE_UNKNOWN=0
for _ in $(seq 1 10); do
    if ! state=$(grpc_bgp_state); then
        BGP_STATE_UNKNOWN=1
        break
    fi
    if [ "$state" != "SESSION_STATE_ESTABLISHED" ]; then
        BGP_DOWN=1
        break
    fi
    sleep 1
done
ELAPSED=$(( $(date +%s) - START ))
if [ "$BGP_STATE_UNKNOWN" -eq 1 ]; then
    fail "rustbgpd BGP state became unavailable or stale during the teardown oracle"
    dump_state_on_failure
elif [ "$BGP_DOWN" -eq 1 ]; then
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

# --- 4. Strict: remote AdminDown permits BGP while local BFD stays Down ------

log "Restarting rustbgpd in strict BFD mode for the remote-AdminDown receipt..."
stop_rustbgpd

# Disable FRR's BFD peer while rustbgpd is absent.  On strict startup this
# leaves rustbgpd's local BFD state Down and BGP withheld.  FRR documents this
# peer-level `shutdown` as sending an AdminDown control packet; the explicit
# no-shutdown/shutdown pulse below sends a fresh packet after the receiver is
# listening, rather than relying on one emitted before rustbgpd started.
frr_bfd_peer_command "shutdown"
if [ "$(frr_bfd_status)" = "shutdown" ]; then
    ok "FRR BFD peer is administratively shut down before strict startup"
else
    fail "FRR BFD peer did not report shutdown before strict startup"
    dump_state_on_failure
fi
start_rustbgpd \
    "exec /usr/local/bin/rustbgpd $STRICT_CONFIG >$STRICT_LOG 2>&1"
wait_grpc_bfd "BFD_SESSION_STATE_DOWN" "Down (strict startup)"
wait_grpc_bfd_remote_admin_down "false" "explicitly false at strict startup"

strict_leaked=0
strict_observed=0
strict_unknown=0
for _ in $(seq 1 3); do
    if ! state=$(grpc_bgp_state); then
        strict_unknown=1
        break
    fi
    strict_observed=$((strict_observed + 1))
    if [ "$state" = "SESSION_STATE_ESTABLISHED" ]; then
        strict_leaked=1
        break
    fi
    sleep 1
done
if [ "$strict_unknown" -eq 1 ]; then
    fail "strict-withhold BGP state was unavailable or stale"
    dump_state_on_failure
elif [ "$strict_observed" -eq 3 ] && [ "$strict_leaked" -eq 0 ]; then
    ok "strict BFD kept BGP withheld while the local BFD session was Down"
else
    fail "strict withhold was not continuously observable before remote AdminDown (samples=$strict_observed, established=$strict_leaked)"
    dump_state_on_failure
fi

log "Pulsing FRR's BFD peer no-shutdown → shutdown to send remote AdminDown..."
frr_bfd_peer_admin_down_pulse
if [ "$(frr_bfd_status)" = "shutdown" ]; then
    ok "FRR reports the BFD peer shutdown after the AdminDown pulse"
else
    fail "FRR BFD peer status was not observable as shutdown after the pulse"
    dump_state_on_failure
fi
wait_frr_established "$FRR1" "$FRR_BFD_PEER" \
    "strict rustbgpd ↔ frr1 (remote AdminDown permits BGP)"
wait_grpc_bgp_established "strict remote-AdminDown"
wait_grpc_bfd "BFD_SESSION_STATE_DOWN" "Down while remote AdminDown permits BGP"
wait_grpc_bfd_remote_admin_down "true" "asserted while BGP is permitted"

# The primary oracle is the public presence-aware field, not daemon logs: local
# BFD stays Down while field 5 explains why RFC 5882 permits the BGP adjacency.

# Capture independent continuity signals before FRR resumes BFD: rustbgpd's
# per-session flap counter and FRR's lifetime Established count.  The baseline
# is accepted only from an authoritative, non-stale Established snapshot; BFD
# recovery must change neither.
strict_baseline_valid=0
flaps_before=""
uptime_before=""
if strict_before=$(grpc_bgp_authoritative_json); then
    state_before=$(printf '%s\n' "$strict_before" | jq -r '.state')
    if [ "$state_before" = "SESSION_STATE_ESTABLISHED" ]; then
        strict_baseline_valid=1
        flaps_before=$(printf '%s\n' "$strict_before" | jq -r '.flapCount // 0')
        uptime_before=$(printf '%s\n' "$strict_before" | jq -r '.uptimeSeconds // 0')
    else
        fail "continuity baseline was authoritative but not Established (state=$state_before)"
        dump_state_on_failure
    fi
else
    fail "continuity baseline BGP snapshot was unavailable or stale"
    dump_state_on_failure
fi
frr_established_before=$(frr_bgp_connections_established)

log "Re-enabling FRR BFD; BFD must recover without bouncing established BGP..."
frr_bfd_peer_command "no shutdown"
wait_grpc_bfd "BFD_SESSION_STATE_UP" "Up after FRR no shutdown" 60
wait_grpc_bfd_remote_admin_down "false" "cleared after FRR no shutdown" 60
sleep 2

strict_after_valid=0
state_after=""
flaps_after=""
uptime_after=""
if strict_after=$(grpc_bgp_authoritative_json); then
    state_after=$(printf '%s\n' "$strict_after" | jq -r '.state')
    flaps_after=$(printf '%s\n' "$strict_after" | jq -r '.flapCount // 0')
    uptime_after=$(printf '%s\n' "$strict_after" | jq -r '.uptimeSeconds // 0')
    strict_after_valid=1
else
    fail "post-recovery BGP snapshot was unavailable or stale"
    dump_state_on_failure
fi
frr_established_after=$(frr_bgp_connections_established)

if [ "$strict_baseline_valid" -eq 1 ] && [ "$strict_after_valid" -eq 1 ] \
    && [ "$state_after" = "SESSION_STATE_ESTABLISHED" ] \
    && [ -n "$flaps_before" ] && [ "$flaps_before" = "$flaps_after" ] \
    && [ -n "$uptime_before" ] && [ -n "$uptime_after" ] \
    && [ "$uptime_after" -ge "$uptime_before" ] \
    && [ -n "$frr_established_before" ] \
    && [ "$frr_established_before" = "$frr_established_after" ]; then
    ok "BFD recovered without BGP churn (rustbgpd flaps $flaps_before → $flaps_after; FRR establishments $frr_established_before → $frr_established_after)"
else
    fail "BGP churned while BFD recovered (state=$state_after, rustbgpd flaps $flaps_before→$flaps_after, uptime $uptime_before→$uptime_after, FRR establishments $frr_established_before→$frr_established_after)"
    dump_state_on_failure
fi

print_summary
