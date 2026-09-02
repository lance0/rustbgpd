#!/usr/bin/env bash
# M108 interop test — RFC 5883 multihop BFD + RFC 5882 coupling vs FRR bfdd
# across a two-hop path (rustbgpd — mid — FRR).
#
# rustbgpd and its FRR iBGP route-reflector client peer between routed /32
# loopbacks with multihop BFD and a 90 s BGP hold timer. The test proves:
#   1. BGP reaches Established AND BFD reaches Up — asserted from BOTH sides
#      (rustbgpd GetBfdSessions + FRR `show bfd peers`), and both sides report
#      the session as multihop.
#   2. Failover: cutting the middle hop (mid stops forwarding) makes BFD fail.
#      the RFC 5882 coupling tears the BGP session down with a Cease / BFD Down NOTIFICATION
#      (RFC 9384 subcode 10) far under the 90 s hold timer — proving the
#      coupling, not a hold-timer expiry. The BFD-down oracle polls every
#      100 ms and reports the observed latency.
#   3. Recovery: forwarding is restored; BFD and BGP re-establish on both sides.
#
# Prerequisites:
#   - docker build --target dev -t rustbgpd:dev .
#   - containerlab deploy -t tests/interop/m108-bfd-multihop-frr.clab.yml
#   - grpcurl + jq installed on the host

set -euo pipefail

TOPO="m108-bfd-multihop-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
source "$SCRIPT_DIR/test-lib.sh"
FRR1="clab-${TOPO}-frr1"
MID="clab-${TOPO}-mid"
PEER="10.255.0.2"
FRR_BFD_PEER="10.255.0.1"
# Bound the BFD-down oracle well below the 90 second BGP hold timer.
BFD_DOWN_BOUND_MS=3000

resolve_grpc_addr
start_rustbgpd

grpc_bfd_json() {
    grpcurl_call \
        -d "{\"peer_address\": \"$PEER\"}" \
        "$GRPC_ADDR" rustbgpd.v1.BfdService/GetBfdSessions 2>/dev/null
}

grpc_bfd_state() {
    # State of the BFD session to $PEER as reported by rustbgpd, e.g.
    # "BFD_SESSION_STATE_UP". Empty if the session is absent.
    grpc_bfd_json | jq -r '.sessions[0].state // ""'
}

grpc_bfd_multihop() {
    # `multihop` is a plain proto3 bool: grpcurl omits it when false, so
    # "false" here means either single-hop or a daemon predating the field.
    grpc_bfd_json | jq -r '.sessions[0].multihop // false'
}

grpc_bgp_json() {
    grpcurl_call \
        -d "{\"address\": \"$PEER\"}" \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/GetNeighborState 2>/dev/null
}

grpc_bgp_state() {
    # Authoritative rustbgpd FSM state. Returns non-zero for an empty, invalid,
    # missing-state, or stale snapshot so callers cannot false-green on Idle.
    local snapshot
    snapshot=$(grpc_bgp_json) || return 1
    printf '%s\n' "$snapshot" | jq -er '
        select(type == "object")
        | select((.stale // false) == false)
        | .state
        | select(type == "string" and length > 0)
    '
}

wait_grpc_bgp_established() {
    local label=$1 attempts=${2:-30} state
    for _ in $(seq 1 "$attempts"); do
        if state=$(grpc_bgp_state) && [ "$state" = "SESSION_STATE_ESTABLISHED" ]; then
            ok "$label BGP state is authoritatively Established"
            return 0
        fi
        sleep 1
    done
    fail "$label BGP state did not reach authoritative Established"
    dump_state_on_failure
    return 1
}

frr_bfd_peer_json() {
    docker exec "$FRR1" vtysh -c "show bfd peers json" 2>/dev/null \
        | jq -c --arg peer "$FRR_BFD_PEER" \
            '[.[] | select(.peer == $peer)][0] // {}'
}

frr_bfd_status() {
    frr_bfd_peer_json | jq -r '.status // ""'
}

frr_bfd_multihop() {
    frr_bfd_peer_json | jq -r '.multihop // false'
}

# Cease / BFD Down (RFC 9384: code 6, subcode 10) NOTIFICATIONs rustbgpd has
# sent to the peer, from the public Prometheus counter. Label order inside the
# braces is not part of the contract, so each pair is matched independently.
bfd_down_notifications_sent() {
    prom_scrape "$RUSTBGPD" | awk -v peer="peer=\"$PEER\"" '
        /^bgp_notifications_sent_total\{/ && /[{,]code="6"/ && /[{,]subcode="10"/ && index($0, peer) {
            print $2; exit
        }'
}

mid_forwarding() {
    docker exec "$MID" sh -c "echo $1 > /proc/sys/net/ipv4/ip_forward"
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
    echo "===== rustbgpd bgp_notifications_sent_total =====" >&2
    prom_scrape "$RUSTBGPD" | grep '^bgp_notifications_sent_total' >&2 || true
    echo "===== mid ip_forward / routes =====" >&2
    docker exec "$MID" sh -c 'cat /proc/sys/net/ipv4/ip_forward; ip route' >&2 2>&1 || true
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

wait_frr_bfd() {
    local want=$1 label=$2 attempts=${3:-30}
    for _ in $(seq 1 "$attempts"); do
        [ "$(frr_bfd_status)" = "$want" ] && {
            ok "FRR reports BFD peer $label"
            return 0
        }
        sleep 1
    done
    fail "FRR did not report BFD peer $label"
    dump_state_on_failure
    return 1
}

# --- 1. BGP Established + BFD Up (both sides, multihop) ----------------------

wait_frr_established "$FRR1" "$FRR_BFD_PEER" "rustbgpd ↔ frr1 (two hops)"
wait_grpc_bgp_established "two-hop"
wait_grpc_bfd "BFD_SESSION_STATE_UP" "Up"
if [ "$(grpc_bfd_multihop)" = "true" ]; then
    ok "rustbgpd reports the BFD session as multihop (RFC 5883)"
else
    fail "rustbgpd did not report the BFD session as multihop"
    dump_state_on_failure
fi
wait_frr_bfd "up" "Up"
if [ "$(frr_bfd_multihop)" = "true" ]; then
    ok "FRR reports the BFD peer as multihop"
else
    fail "FRR did not report the BFD peer as multihop"
    dump_state_on_failure
fi

notifications_before=$(bfd_down_notifications_sent)
notifications_before=${notifications_before:-0}

# --- 2. Failover: cut the middle hop → BFD down → BGP torn down --------------

log "Cutting the middle hop (mid stops forwarding)..."
mid_forwarding 0
CUT_MS=$(now_ms)

# rustbgpd's BFD must drop within the lab bound. Poll every 100 ms.
BFD_DOWN_MS=""
for _ in $(seq 1 100); do
    state=$(grpc_bfd_state)
    if [ "$state" = "BFD_SESSION_STATE_DOWN" ]; then
        BFD_DOWN_MS=$(( $(now_ms) - CUT_MS ))
        break
    fi
    sleep 0.1
done
if [ -n "$BFD_DOWN_MS" ] && [ "$BFD_DOWN_MS" -le "$BFD_DOWN_BOUND_MS" ]; then
    ok "rustbgpd multihop BFD went down ${BFD_DOWN_MS} ms after the cut (bound ${BFD_DOWN_BOUND_MS} ms)"
elif [ -n "$BFD_DOWN_MS" ]; then
    fail "rustbgpd multihop BFD went down only after ${BFD_DOWN_MS} ms (bound ${BFD_DOWN_BOUND_MS} ms)"
    dump_state_on_failure
else
    fail "rustbgpd multihop BFD did not go down within 10 s of the cut"
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
ELAPSED_MS=$(( $(now_ms) - CUT_MS ))
if [ "$BGP_STATE_UNKNOWN" -eq 1 ]; then
    fail "rustbgpd BGP state became unavailable or stale during the teardown oracle"
    dump_state_on_failure
elif [ "$BGP_DOWN" -eq 1 ]; then
    ok "rustbgpd tore down BGP ${ELAPSED_MS} ms after the cut (<< 90 s hold timer)"
else
    fail "rustbgpd did not tear down BGP within 10 s (coupling not firing)"
    dump_state_on_failure
fi

# RFC 9384: the teardown is a Cease / BFD Down NOTIFICATION, visible on the
# public counter even though the cut path never delivers it to FRR.
notifications_after=""
for _ in $(seq 1 10); do
    notifications_after=$(bfd_down_notifications_sent)
    if [ -n "$notifications_after" ] && [ "$notifications_after" -gt "$notifications_before" ]; then
        break
    fi
    sleep 1
done
if [ -n "$notifications_after" ] && [ "$notifications_after" -gt "$notifications_before" ]; then
    ok "rustbgpd sent a Cease / BFD Down NOTIFICATION (RFC 9384 6/10; counter $notifications_before → $notifications_after)"
else
    fail "no Cease / BFD Down NOTIFICATION counted (before=$notifications_before after=${notifications_after:-absent})"
    dump_state_on_failure
fi

# FRR's own multihop session must see the same loss.
wait_frr_bfd "down" "Down after the cut" 10

# --- 3. Recovery: restore forwarding → BFD + BGP re-establish ---------------

log "Restoring the middle hop..."
mid_forwarding 1
wait_grpc_bfd "BFD_SESSION_STATE_UP" "Up again" 60
wait_frr_bfd "up" "Up again" 60
wait_frr_established "$FRR1" "$FRR_BFD_PEER" "rustbgpd ↔ frr1 (recovered)"
wait_grpc_bgp_established "recovered" 60

print_summary
