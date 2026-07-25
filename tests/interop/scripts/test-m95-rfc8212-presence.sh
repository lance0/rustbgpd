#!/usr/bin/env bash
# M95 interop test — ADR-0112 step 4, live RFC 8212 import policy-presence
# transitions against real sessions.
#
# What makes this test load-bearing is the pair of peers:
#
#   frr  (AS 65002) advertises RFC 2918 Route Refresh. A presence transition
#        against it must converge — and for the restore direction the Route
#        Refresh is the ONLY thing that can bring the routes back, because the
#        reserved deny retained nothing and FRR has no reason to re-advertise
#        on its own.
#   bird (AS 65003) runs `enable route refresh off`, so its Established session
#        genuinely lacks the capability in its OPEN. A presence transition
#        against it must be rejected before anything is mutated.
#
# Phases:
#   1. Two-peer transition with BIRD in the set -> rejected whole; both peers
#      keep their routes, their verdicts, and their sessions.
#   2. Single-peer transition against FRR (present -> missing) -> converges:
#      FRR's routes leave the RIB after a real Route Refresh, BIRD untouched.
#   3. Single-peer transition against FRR (missing -> present) -> converges:
#      FRR's routes return, which only the Route Refresh can achieve.
#   4. FRR down with graceful-restart-retained stale routes -> the same
#      phase-2 edit is deferred rather than applied over retained state.
#
# Prerequisites:
#   - docker build --target dev -t rustbgpd:dev .
#   - docker build -t bird:2-bookworm -f tests/interop/Dockerfile.bird tests/interop
#   - containerlab deploy -t tests/interop/m95-rfc8212-presence-frr-bird.clab.yml
#   - grpcurl + jq on the host

set -euo pipefail

TOPO="m95-rfc8212-presence"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
source "$SCRIPT_DIR/test-lib.sh"
FRR="clab-${TOPO}-frr"
BIRD="clab-${TOPO}-bird"

FRR_PEER="10.95.1.2"
BIRD_PEER="10.95.2.2"

preflight
resolve_grpc_addr

if ! docker inspect "$BIRD" &>/dev/null; then
    echo "ERROR: container $BIRD not running — deploy topology first" >&2
    exit 1
fi

DAEMON_LOG=/tmp/rustbgpd.log
LOG_MARK=$(mktemp)
trap 'rm -f "$LOG_MARK"' EXIT

log "Starting BIRD..."
docker exec "$BIRD" sh -c \
    'mkdir -p /run/bird && (bird -d -c /etc/bird/bird.conf >>/tmp/bird.log 2>&1 &)'

# The daemon's own log is the only place a rejected reload explains itself, so
# capture it to a file the assertions can read rather than to the exec's stdout.
start_rustbgpd "exec /usr/local/bin/rustbgpd /etc/rustbgpd/config.toml >$DAEMON_LOG 2>&1"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

neighbor_state() {
    grpcurl_call -d "{\"address\": \"$1\"}" \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/GetNeighborState 2>/dev/null
}

# Received routes are keyed by the *peer that sent them*, so a per-peer count
# separates "FRR's routes are gone" from "the RIB is empty".
count_routes_from() {
    grpcurl_call "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null \
        | jq -r --arg p "$1" '[.routes[]? | select(.peerAddress == $p)] | length'
}

rfc8212_import_status() {
    neighbor_state "$1" | jq -r '.rfc8212ImportPolicy // "UNSET"'
}

session_marker() {
    # flapCount alone is not enough (a replacement handle restarts at 0), so
    # pair it with uptime the way M34 does.
    neighbor_state "$1" | jq -r '"\(.flapCount // 0)/\(.uptimeSeconds // 0)"'
}

assert_no_flap() {
    local peer=$1 before=$2 after=$3 label=$4
    local before_flaps=${before%%/*} before_up=${before##*/}
    local after_flaps=${after%%/*} after_up=${after##*/}
    if [ "$after_flaps" != "$before_flaps" ]; then
        fail "$label: $peer flapped (flapCount $before_flaps -> $after_flaps); a policy-presence \
             edit is a Route Refresh, never a session reset"
    elif [ "$after_up" -lt "$before_up" ]; then
        fail "$label: $peer session handle was replaced (uptimeSeconds $before_up -> $after_up)"
    else
        ok "$label: $peer stayed Established (flapCount $after_flaps, uptime $before_up -> $after_up)"
    fi
}

daemon_pid() {
    docker exec "$RUSTBGPD" sh -c \
        'grep -lF rustbgpd /proc/[0-9]*/comm 2>/dev/null | head -1 | cut -d/ -f3'
}

# Capture the daemon's log tail from this point on, so a phase can assert on
# what the reload actually reported rather than only on observable state.
mark_log() {
    docker exec "$RUSTBGPD" sh -c "wc -l < $DAEMON_LOG" > "$LOG_MARK" 2>/dev/null \
        || echo 0 > "$LOG_MARK"
}

log_since_mark() {
    local mark
    mark=$(tr -dc '0-9' < "$LOG_MARK")
    docker exec "$RUSTBGPD" tail -n "+$((mark + 1))" "$DAEMON_LOG" 2>/dev/null
}

sighup_with() {
    local variant=$1
    local pid
    pid=$(daemon_pid)
    if [ -z "$pid" ]; then
        fail "rustbgpd PID not found in /proc"
        exit 1
    fi
    docker exec "$RUSTBGPD" sh -c \
        "cp /etc/rustbgpd/config.${variant}.toml /etc/rustbgpd/config.toml && kill -HUP $pid"
    log "SIGHUP sent with config.${variant}.toml (pid $pid)"
    # Reload + Route Refresh + peer re-advertisement + re-import.
    sleep 8
}

wait_routes_from() {
    local peer=$1 want=$2 label=$3
    for i in $(seq 1 25); do
        if [ "$(count_routes_from "$peer")" -eq "$want" ]; then
            ok "$label (after ${i}s)"
            return 0
        fi
        sleep 1
    done
    fail "$label — observed $(count_routes_from "$peer") routes from $peer, wanted $want"
    return 1
}

# ---------------------------------------------------------------------------
# 0. Both sessions up, both verdicts PRESENT, both peers' routes imported
# ---------------------------------------------------------------------------

wait_frr_established "$FRR" "10.95.1.1" "rustbgpd <-> FRR"

log "Waiting for the BIRD session to reach Established..."
bird_up=0
for i in $(seq 1 45); do
    if docker exec "$BIRD" birdc show protocols edge 2>/dev/null \
        | grep -q Established; then
        ok "rustbgpd <-> BIRD session established (attempt $i)"
        bird_up=1
        break
    fi
    sleep 2
done
if [ "$bird_up" -ne 1 ]; then
    fail "BIRD session did not reach Established within 90s"
    docker exec "$BIRD" birdc show protocols all edge 2>&1 || true
    print_summary
fi

# The premise of the whole lab: BIRD really did not offer Route Refresh, and
# FRR really did. Read it off each speaker's own view of the OPEN exchange, not
# off rustbgpd, so the lab cannot pass against a daemon that merely believes it.
# Only BIRD's OWN advertisement counts; the "Neighbor capabilities" block right
# below it is rustbgpd's, which does offer Route Refresh.
if docker exec "$BIRD" birdc show protocols all edge 2>/dev/null \
    | awk '/Local capabilities/{f=1; next} /Neighbor capabilities/{f=0} f' \
    | grep -qi "route refresh"; then
    fail "BIRD advertised Route Refresh — the no-capability half of this lab is vacuous"
else
    ok "BIRD advertised NO Route Refresh capability (premise of phases 1 and 4)"
fi
if docker exec "$FRR" vtysh -c "show bgp neighbors 10.95.1.1 json" 2>/dev/null \
    | jq -e '.["10.95.1.1"].neighborCapabilities.routeRefresh != null' >/dev/null; then
    ok "FRR negotiated the Route Refresh capability"
else
    fail "FRR did not negotiate Route Refresh — the convergence phases would be vacuous"
fi

wait_routes_from "$FRR_PEER" 3 "FRR's 3 routes imported under the global chain"
wait_routes_from "$BIRD_PEER" 2 "BIRD's 2 routes imported under the global chain"

for peer in "$FRR_PEER" "$BIRD_PEER"; do
    status=$(rfc8212_import_status "$peer")
    if [ "$status" = "RFC8212_POLICY_STATUS_PRESENT" ]; then
        ok "$peer reports import PRESENT before any edit"
    else
        fail "$peer reports import $status before any edit — expected PRESENT"
    fi
done

# ---------------------------------------------------------------------------
# 1. Two-peer transition including BIRD -> rejected whole, nothing mutated
# ---------------------------------------------------------------------------

log "PHASE 1: removing the global import chain while BOTH peers inherit it"
frr_marker=$(session_marker "$FRR_PEER")
bird_marker=$(session_marker "$BIRD_PEER")
mark_log
sighup_with "no-global-import"

phase1_log=$(log_since_mark)
if grep -q "did not negotiate Route Refresh" <<<"$phase1_log"; then
    ok "the reload named the missing Route Refresh capability"
else
    fail "the reload did not report the missing capability; log tail: $(tail -5 <<<"$phase1_log")"
fi
if grep -q "no peer was modified" <<<"$phase1_log"; then
    ok "the rejection stated that no peer was modified"
else
    fail "the rejection did not state that no peer was modified"
fi
if grep -qi "clear the session" <<<"$phase1_log"; then
    ok "the rejection carried operator remediation (clear/reconnect)"
else
    fail "the rejection carried no remediation guidance"
fi

# The headline no-partial-state assertion: the CAPABLE peer, which would have
# transitioned happily on its own, is exactly where it was. Phase 2b is this
# phase's discriminator — same edit shape, same capable peer, opposite outcome,
# differing only in whether the incapable peer is in the transition set.
for peer in "$FRR_PEER" "$BIRD_PEER"; do
    status=$(rfc8212_import_status "$peer")
    if [ "$status" = "RFC8212_POLICY_STATUS_PRESENT" ]; then
        ok "$peer still reports import PRESENT after the rejected edit"
    else
        fail "$peer reports import $status after a rejected edit — the verdict must not move"
    fi
done
frr_routes=$(count_routes_from "$FRR_PEER")
bird_routes=$(count_routes_from "$BIRD_PEER")
if [ "$frr_routes" -eq 3 ] && [ "$bird_routes" -eq 2 ]; then
    ok "both peers kept every imported route across the rejected edit (3 + 2)"
else
    fail "routes moved during a rejected edit — FRR $frr_routes (want 3), BIRD $bird_routes (want 2)"
fi
assert_no_flap "$FRR_PEER" "$frr_marker" "$(session_marker "$FRR_PEER")" "phase 1"
assert_no_flap "$BIRD_PEER" "$bird_marker" "$(session_marker "$BIRD_PEER")" "phase 1"

# ---------------------------------------------------------------------------
# 2. Single-peer transition against FRR -> converges through Route Refresh
# ---------------------------------------------------------------------------

log "PHASE 2a: pinning BIRD's own content-equal chain (installs nothing)"
bird_marker=$(session_marker "$BIRD_PEER")
sighup_with "bird-pinned"
if [ "$(count_routes_from "$BIRD_PEER")" -eq 2 ] \
    && [ "$(rfc8212_import_status "$BIRD_PEER")" = "RFC8212_POLICY_STATUS_PRESENT" ]; then
    ok "a content-equal chain edit applied to the no-capability peer untouched"
else
    fail "the content-equal chain edit disturbed BIRD — it moves no chain and must not be gated"
fi
assert_no_flap "$BIRD_PEER" "$bird_marker" "$(session_marker "$BIRD_PEER")" "phase 2a"

log "PHASE 2b: removing the global import chain — only FRR's verdict moves"
frr_marker=$(session_marker "$FRR_PEER")
bird_marker=$(session_marker "$BIRD_PEER")
mark_log
sighup_with "frr-missing"

phase2_log=$(log_since_mark)
if grep -q "sent ROUTE-REFRESH" <<<"$phase2_log" \
    || grep -q "soft reset in requested" <<<"$phase2_log"; then
    ok "the committed transition issued a real Route Refresh to FRR"
else
    fail "no Route Refresh was issued for the committed transition"
fi

status=$(rfc8212_import_status "$FRR_PEER")
if [ "$status" = "RFC8212_POLICY_STATUS_MISSING" ]; then
    ok "FRR reports import MISSING — the reserved deny is live"
else
    fail "FRR reports import $status after removing its last explicit import policy"
fi
wait_routes_from "$FRR_PEER" 0 \
    "FRR's routes left the RIB after the Route Refresh re-advertisement"
if [ "$(count_routes_from "$BIRD_PEER")" -eq 2 ] \
    && [ "$(rfc8212_import_status "$BIRD_PEER")" = "RFC8212_POLICY_STATUS_PRESENT" ]; then
    ok "BIRD, whose verdict did not move, kept its routes and its PRESENT status"
else
    fail "the FRR-only transition disturbed BIRD"
fi
assert_no_flap "$FRR_PEER" "$frr_marker" "$(session_marker "$FRR_PEER")" "phase 2b"
assert_no_flap "$BIRD_PEER" "$bird_marker" "$(session_marker "$BIRD_PEER")" "phase 2b"

# ---------------------------------------------------------------------------
# 3. Restore direction — only the Route Refresh can bring the routes back
# ---------------------------------------------------------------------------

log "PHASE 3: restoring the global import chain — FRR MISSING -> PRESENT"
frr_marker=$(session_marker "$FRR_PEER")
sighup_with "bird-pinned"

status=$(rfc8212_import_status "$FRR_PEER")
if [ "$status" = "RFC8212_POLICY_STATUS_PRESENT" ]; then
    ok "FRR reports import PRESENT again"
else
    fail "FRR reports import $status after restoring an explicit import policy"
fi
# The reserved deny retained nothing and FRR has no independent reason to
# re-advertise, so routes returning IS the Route Refresh having converged.
wait_routes_from "$FRR_PEER" 3 \
    "FRR's 3 routes relearned — only the Route Refresh could have asked for them"
assert_no_flap "$FRR_PEER" "$frr_marker" "$(session_marker "$FRR_PEER")" "phase 3"

# ---------------------------------------------------------------------------
# 4. Down peer with graceful-restart-retained routes -> deferred
# ---------------------------------------------------------------------------

log "PHASE 4: killing FRR's bgpd so its routes are retained as GR stale"
docker exec "$FRR" sh -c 'kill -9 $(pidof bgpd)' || true
retained=0
for i in $(seq 1 30); do
    state=$(neighbor_state "$FRR_PEER" | jq -r '.state // "UNKNOWN"')
    routes=$(count_routes_from "$FRR_PEER")
    if [ "$state" != "ESTABLISHED" ] && [ "$routes" -gt 0 ]; then
        ok "FRR is down ($state) with $routes route(s) retained as stale (after ${i}s)"
        retained=1
        break
    fi
    sleep 1
done
if [ "$retained" -ne 1 ]; then
    fail "could not reach a down-with-retained-stale state; phase 4 cannot discriminate"
else
    mark_log
    sighup_with "frr-missing"
    phase4_log=$(log_since_mark)
    if grep -qi "stale route" <<<"$phase4_log"; then
        ok "the reload deferred the transition while stale routes are retained"
    else
        fail "the reload did not defer on retained stale state; tail: $(tail -5 <<<"$phase4_log")"
    fi
    status=$(rfc8212_import_status "$FRR_PEER")
    if [ "$status" = "RFC8212_POLICY_STATUS_PRESENT" ]; then
        ok "the retained routes stay paired with the verdict they were accepted under"
    else
        fail "FRR reports import $status — a deferred edit must not move the verdict"
    fi
fi

print_summary
