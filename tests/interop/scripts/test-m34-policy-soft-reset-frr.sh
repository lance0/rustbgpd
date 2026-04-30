#!/usr/bin/env bash
# M34 interop test — SIGHUP policy soft-reset
#
# Validates the auto-fire path inside
# `PeerManager::update_runtime_policies`: when a SIGHUP changes a
# policy referenced by an Established peer's import chain, the peer
# manager issues a Route Refresh so routes already accepted in the
# AdjRibIn under the prior policy get re-evaluated.
#
# Test flow:
#   1. Establish session FRR (AS 65002) ↔ rustbgpd (AS 65001).
#   2. FRR advertises 192.168.1.0/24, 192.168.2.0/24, 10.10.0.0/16.
#   3. Wait until rustbgpd's RIB has all three (initial config has
#      `policy.definitions.filter.default_action = "permit"`).
#   4. Capture session uptime so we can verify the SIGHUP doesn't
#      flap the session.
#   5. Replace /etc/rustbgpd/config.toml with the deny variant
#      (adds a deny rule for 192.168.1.0/24) and SIGHUP.
#   6. Wait briefly, then assert:
#        - Session is still Established (no flap).
#        - 192.168.1.0/24 is gone from rustbgpd's RIB (auto Route
#          Refresh fired and the new policy filtered it out on
#          re-import).
#        - 192.168.2.0/24 and 10.10.0.0/16 are still present.
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m34-policy-soft-reset-frr.clab.yml
#   - grpcurl + jq installed on the host

set -euo pipefail

TOPO="m34-policy-soft-reset-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"
FRR="clab-${TOPO}-frr"

preflight
resolve_grpc_addr
start_rustbgpd

# ---------------------------------------------------------------------------
# 1. Session establishment + initial route import
# ---------------------------------------------------------------------------

wait_frr_established "$FRR" "10.0.0.1" "rustbgpd ↔ FRR"

grpc_list_received() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

count_prefix() {
    # The gRPC payload returns `prefix` (network address) and
    # `prefixLength` separately; join them and count exact matches.
    local prefix=$1
    grpc_list_received \
        | jq -r --arg p "$prefix" \
            '[.routes[]? | "\(.prefix)/\(.prefixLength)"] | map(select(. == $p)) | length'
}

wait_route() {
    local prefix=$1
    log "Waiting for $prefix in rustbgpd's RIB..."
    for i in $(seq 1 20); do
        if [ "$(count_prefix "$prefix")" -ge 1 ]; then
            ok "$prefix present after ${i}s"
            return 0
        fi
        sleep 1
    done
    fail "$prefix never appeared in RIB within 20s"
    return 1
}

wait_route "192.168.1.0/24"
wait_route "192.168.2.0/24"
wait_route "10.10.0.0/16"

# ---------------------------------------------------------------------------
# 2. Capture session uptime to verify SIGHUP doesn't flap
# ---------------------------------------------------------------------------

session_uptime_secs() {
    docker exec "$FRR" vtysh -c "show bgp neighbors 10.0.0.1 json" 2>/dev/null \
        | jq -r '."10.0.0.1".bgpTimerUpEstablishedEpoch // 0'
}

initial_uptime=$(session_uptime_secs)
log "Pre-SIGHUP session uptime epoch: $initial_uptime"
if [ "$initial_uptime" = "0" ]; then
    fail "could not read session uptime epoch from FRR — session not Established?"
    exit 1
fi

# ---------------------------------------------------------------------------
# 3. SIGHUP with the deny variant
# ---------------------------------------------------------------------------

log "Replacing config with deny variant and sending SIGHUP..."
# `pgrep` isn't in the rustbgpd:dev image; walk /proc to find the
# daemon PID. The container's other processes (init, sleep, this
# exec sh) don't match the comm name.
docker exec "$RUSTBGPD" sh -c '
    set -e
    cp /etc/rustbgpd/config.deny.toml /etc/rustbgpd/config.toml
    pid=$(grep -lF rustbgpd /proc/[0-9]*/comm 2>/dev/null | head -1 | cut -d/ -f3)
    if [ -z "$pid" ]; then
        echo "ERROR: rustbgpd PID not found in /proc" >&2
        exit 1
    fi
    kill -HUP "$pid"
    echo "SIGHUP sent to PID $pid"
'

# Reload + Route Refresh + re-import takes a moment. 6 seconds is a
# generous bound for this single-peer / 3-route scenario; tighten if
# CI proves stable.
sleep 6

# ---------------------------------------------------------------------------
# 4. Assertions
# ---------------------------------------------------------------------------

post_uptime=$(session_uptime_secs)
log "Post-SIGHUP session uptime epoch: $post_uptime"
if [ "$post_uptime" != "$initial_uptime" ]; then
    fail "session flapped during SIGHUP (epoch moved $initial_uptime → $post_uptime); \
         policy reload should NOT tear the session — the auto-refresh path is a Route \
         Refresh, not a session reset"
else
    ok "session stayed Established across SIGHUP (no flap)"
fi

# The headline assertion: 192.168.1.0/24 should be gone, the others stay.
denied_count=$(count_prefix "192.168.1.0/24")
if [ "$denied_count" -eq 0 ]; then
    ok "192.168.1.0/24 dropped from RIB after SIGHUP — auto Route Refresh + re-import fired"
else
    fail "192.168.1.0/24 still in RIB ($denied_count entries) — auto Route Refresh \
         did NOT fire or did not re-filter on import. This is the correctness gap \
         the M34 test is designed to catch."
fi

permitted_a=$(count_prefix "192.168.2.0/24")
permitted_b=$(count_prefix "10.10.0.0/16")
if [ "$permitted_a" -ge 1 ] && [ "$permitted_b" -ge 1 ]; then
    ok "192.168.2.0/24 and 10.10.0.0/16 still present (re-imported under new policy)"
else
    fail "expected 192.168.2.0/24 + 10.10.0.0/16 to survive (default_action=permit); \
         got counts $permitted_a / $permitted_b"
fi

print_summary
