#!/usr/bin/env bash
# M22 interop test — FlowSpec injection and distribution to FRR
#
# Validates:
#   1. BGP session establishes with FlowSpec capability negotiated
#   2. FlowSpec rule injected via gRPC appears in rustbgpd Loc-RIB
#   3. FRR receives the FlowSpec rule via eBGP
#   4. Second rule injected, both visible on both sides
#   5. Withdrawal of first rule propagates to FRR
#   6. Second rule survives the withdrawal
#   7. Session stays Established across the entire test (no flap)
#
# Convergence-signal discipline (after the second-flake post-mortem):
# the prior version relied on `show bgp ipv4 flowspec` text grep,
# which is FRR's display path and lags the underlying RIB by tens of
# seconds. That hid a real bug — session flaps during FlowSpec
# exchange would cause both sides to lose state, and the test would
# only "pass" once FRR re-established and re-received the rules.
# This rewrite uses `show bgp ipv4 flowspec json` for state queries
# and `show bgp summary json` to detect flaps directly via
# `connectionsDropped`. Text views are kept as debug fallbacks only.
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m22-flowspec-frr.clab.yml
#   - grpcurl + jq installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m22-flowspec-frr.sh


TOPO="m22-flowspec-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"
FRR="clab-${TOPO}-frr"


# ---------------------------------------------------------------------------
# gRPC helpers
# ---------------------------------------------------------------------------

grpc_add_flowspec() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "$1" \
        "$GRPC_ADDR" rustbgpd.v1.InjectionService/AddFlowSpec 2>/dev/null
}

grpc_delete_flowspec() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "$1" \
        "$GRPC_ADDR" rustbgpd.v1.InjectionService/DeleteFlowSpec 2>/dev/null
}

grpc_list_flowspec() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d '{"afiSafi": "ADDRESS_FAMILY_IPV4_FLOWSPEC"}' \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListFlowSpecRoutes 2>/dev/null
}


# ---------------------------------------------------------------------------
# FRR direct-signal helpers — JSON queries with jq, *not* text grep.
# ---------------------------------------------------------------------------

# Total FlowSpec routes in FRR's RIB. `null` is rendered as empty
# string by `jq -r`, which we coerce to 0.
frr_flowspec_count() {
    docker exec "$FRR" vtysh -c "show bgp ipv4 flowspec json" 2>/dev/null \
        | jq -r '.totalRoutes // 0' 2>/dev/null \
        || echo 0
}

# Returns 0 if FRR has a FlowSpec route whose key contains the given
# substring (e.g. "192.168.1.0/24"); 1 otherwise. The JSON keys are
# the FlowSpec NLRI string representation; substring match handles
# the variable destination/source-port/protocol trailing parts.
frr_flowspec_has_prefix() {
    local needle="$1"
    docker exec "$FRR" vtysh -c "show bgp ipv4 flowspec json" 2>/dev/null \
        | jq -e --arg n "$needle" \
            '.routes // {} | to_entries | any(.key | contains($n))' \
            >/dev/null 2>&1
}

# `connectionsDropped` from FRR's per-peer summary. Increments every
# time the session leaves Established. Used to assert no flap during
# the test.
frr_session_drops() {
    docker exec "$FRR" vtysh -c "show bgp summary json" 2>/dev/null \
        | jq -r '.ipv4Unicast.peers["10.0.0.1"].connectionsDropped // 0' 2>/dev/null \
        || echo 0
}

# Snapshot at start of test; later checks assert this hasn't grown.
INITIAL_DROPS=""


# ---------------------------------------------------------------------------
# FlowSpec rule payloads
# ---------------------------------------------------------------------------

# Rule 1: Drop TCP/80 to 192.168.1.0/24
RULE1_ADD='{
  "afiSafi": "ADDRESS_FAMILY_IPV4_FLOWSPEC",
  "components": [
    {"type": 1, "prefix": "192.168.1.0/24"},
    {"type": 3, "value": "=6"},
    {"type": 5, "value": "=80"}
  ],
  "actions": [
    {"trafficRate": {"rate": 0.0}}
  ]
}'

RULE1_DELETE='{
  "afiSafi": "ADDRESS_FAMILY_IPV4_FLOWSPEC",
  "components": [
    {"type": 1, "prefix": "192.168.1.0/24"},
    {"type": 3, "value": "=6"},
    {"type": 5, "value": "=80"}
  ]
}'

# Rule 2: Rate-limit UDP/53 to 10.0.0.0/8 at 1000 bytes/sec
RULE2_ADD='{
  "afiSafi": "ADDRESS_FAMILY_IPV4_FLOWSPEC",
  "components": [
    {"type": 1, "prefix": "10.0.0.0/8"},
    {"type": 3, "value": "=17"},
    {"type": 5, "value": "=53"}
  ],
  "actions": [
    {"trafficRate": {"rate": 1000.0}}
  ]
}'

# ---------------------------------------------------------------------------
# Wait helpers
# ---------------------------------------------------------------------------

wait_established() {
    log "Waiting for BGP session to reach Established..."
    for i in $(seq 1 45); do
        local state
        state=$(docker exec "$FRR" vtysh -c "show bgp neighbors 10.0.0.1 json" 2>/dev/null \
            | grep -o '"bgpState":"[^"]*"' | head -1 | cut -d'"' -f4 || true)
        if [ "$state" = "Established" ]; then
            ok "BGP session established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "BGP session did not reach Established within 90s"
    return 1
}

# Use the standardized `start_rustbgpd` from test-lib.sh — handles
# both the /proc poll loop and the gRPC-ready wait.

# Assert the session has NOT flapped since the test started. Called
# at the end of every test step that touches the session, so a flap
# is attributed to the operation that caused it rather than masked
# by an eventual recovery.
assert_no_flap() {
    local current
    current=$(frr_session_drops)
    if [ "$current" != "$INITIAL_DROPS" ]; then
        fail "session flapped during test: connectionsDropped \
$INITIAL_DROPS → $current. The prior test version masked this by \
waiting on FRR's vtysh display, which would eventually show \
re-received rules after a re-establish — hiding the flap entirely."
        echo "--- rustbgpd → FRR session diagnostic ---" >&2
        docker exec "$FRR" vtysh -c "show bgp neighbor 10.0.0.1" 2>&1 \
            | grep -iE "Last reset|state|Connections" | head -5 >&2 || true
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

test_flowspec_capability() {
    log "Test 1: FlowSpec capability negotiated"

    local caps
    caps=$(docker exec "$FRR" vtysh -c "show bgp neighbors 10.0.0.1" 2>/dev/null || true)
    if echo "$caps" | grep -qi "ipv4 Flowspec"; then
        ok "FlowSpec capability negotiated with FRR"
    else
        # Try JSON output
        local json_caps
        json_caps=$(docker exec "$FRR" vtysh -c "show bgp neighbors 10.0.0.1 json" 2>/dev/null || true)
        if echo "$json_caps" | grep -qi "flowspec"; then
            ok "FlowSpec capability negotiated (JSON output)"
        else
            fail "FlowSpec capability not found in neighbor output"
            log "DEBUG neighbor output:"
            echo "$caps" | grep -i "family\|flowspec\|capability" || true
        fi
    fi
}

test_inject_rule1() {
    log "Test 2: Inject FlowSpec rule 1 (drop TCP/80 to 192.168.1.0/24)"

    grpc_add_flowspec "$RULE1_ADD"
    sleep 2

    local fs_routes
    fs_routes=$(grpc_list_flowspec)

    if echo "$fs_routes" | grep -q "192.168.1.0"; then
        ok "Rule 1 present in rustbgpd FlowSpec Loc-RIB"
    else
        fail "Rule 1 not found in rustbgpd FlowSpec Loc-RIB"
        log "DEBUG FlowSpec RIB: $fs_routes"
    fi
    assert_no_flap
}

test_frr_receives_rule1() {
    log "Test 3: FRR receives FlowSpec rule 1 (JSON convergence signal)"

    # Direct signal: query FRR's flowspec RIB as JSON via
    # `show bgp ipv4 flowspec json` and check the routes map.
    # 30 retries × 1 s = 30 s — generous for a single rule
    # advertisement under any plausible load. The prior
    # 60- and 120-second windows were measuring FRR's text
    # display path, which lags the RIB by a separate
    # mechanism; the JSON path returns the underlying state
    # directly and converges within a few seconds in practice.
    for i in $(seq 1 30); do
        if frr_flowspec_has_prefix "192.168.1.0/24"; then
            ok "FRR received FlowSpec rule for 192.168.1.0/24 (attempt $i)"
            assert_no_flap
            return 0
        fi
        sleep 1
    done
    fail "FRR did not receive FlowSpec rule 1 within 30s"
    log "DEBUG FRR flowspec table (text):"
    docker exec "$FRR" vtysh -c "show bgp ipv4 flowspec" 2>/dev/null || true
    log "DEBUG FRR flowspec JSON:"
    docker exec "$FRR" vtysh -c "show bgp ipv4 flowspec json" 2>/dev/null || true
    assert_no_flap
}

test_inject_rule2() {
    log "Test 4: Inject FlowSpec rule 2 (rate-limit UDP/53 to 10.0.0.0/8)"

    grpc_add_flowspec "$RULE2_ADD"
    sleep 2

    local fs_routes
    fs_routes=$(grpc_list_flowspec)

    local count
    count=$(echo "$fs_routes" | python3 -c "
import sys, json
resp = json.load(sys.stdin)
print(len(resp.get('routes', [])))
" 2>/dev/null || echo 0)

    if [ "$count" -ge 2 ]; then
        ok "Both rules present in rustbgpd FlowSpec Loc-RIB (count=$count)"
    else
        fail "Expected 2 FlowSpec rules in rustbgpd, got $count"
    fi
    assert_no_flap
}

test_frr_receives_both() {
    log "Test 5: FRR receives both FlowSpec rules (JSON convergence signal)"

    # 30 retries × 1 s = 30 s window using the JSON query.
    for i in $(seq 1 30); do
        local count
        count=$(frr_flowspec_count)
        if [ "$count" -ge 2 ] \
            && frr_flowspec_has_prefix "192.168.1.0/24" \
            && frr_flowspec_has_prefix "10.0.0.0/8"; then
            ok "FRR has both FlowSpec rules (attempt $i, count=$count)"
            assert_no_flap
            return 0
        fi
        sleep 1
    done
    fail "FRR does not have both FlowSpec rules within 30s"
    log "DEBUG FRR flowspec JSON:"
    docker exec "$FRR" vtysh -c "show bgp ipv4 flowspec json" 2>/dev/null || true
    assert_no_flap
}

test_withdraw_rule1() {
    log "Test 6: Withdraw FlowSpec rule 1"

    grpc_delete_flowspec "$RULE1_DELETE"
    sleep 3

    local fs_routes
    fs_routes=$(grpc_list_flowspec)

    if echo "$fs_routes" | grep -q "192.168.1.0"; then
        fail "Rule 1 still present in rustbgpd after deletion"
    else
        ok "Rule 1 withdrawn from rustbgpd FlowSpec Loc-RIB"
    fi
    assert_no_flap
}

test_frr_withdrawal_propagated() {
    log "Test 7: Withdrawal propagated to FRR, rule 2 survives"

    # JSON-direct check: rule 1 should be absent and rule 2
    # should still be present, asserted in a single converged
    # state. The prior version polled rule 1's disappearance
    # and rule 2's survival in two separate loops with a 65 s
    # window because FRR's text view briefly drops both rules
    # mid-MP_UNREACH-processing. The JSON view (totalRoutes
    # plus routes-map keys) reflects the underlying RIB
    # without that display lag, so 30 s is plenty.
    for i in $(seq 1 30); do
        local count
        count=$(frr_flowspec_count)
        local has_rule1=false
        local has_rule2=false
        frr_flowspec_has_prefix "192.168.1.0/24" && has_rule1=true
        frr_flowspec_has_prefix "10.0.0.0/8" && has_rule2=true

        if [ "$has_rule1" = false ] && [ "$has_rule2" = true ] && [ "$count" -eq 1 ]; then
            ok "FRR converged on post-withdrawal state: rule 1 gone, rule 2 present (attempt $i)"
            break
        fi
        if [ "$i" -eq 30 ]; then
            echo "--- FRR flowspec JSON (final) ---" >&2
            docker exec "$FRR" vtysh -c "show bgp ipv4 flowspec json" 2>/dev/null >&2 || true
            fail "FRR did not converge on (rule1=gone, rule2=present) within 30s — \
rule1=$has_rule1 rule2=$has_rule2 totalRoutes=$count"
            assert_no_flap
            return 1
        fi
        sleep 1
    done

    # Verify rule 2 in rustbgpd
    local fs_routes
    fs_routes=$(grpc_list_flowspec)
    local count
    count=$(echo "$fs_routes" | python3 -c "
import sys, json
resp = json.load(sys.stdin)
print(len(resp.get('routes', [])))
" 2>/dev/null || echo 0)

    if [ "$count" -eq 1 ]; then
        ok "Exactly 1 FlowSpec rule remains in rustbgpd"
    else
        fail "Expected 1 FlowSpec rule in rustbgpd, got $count"
    fi
    assert_no_flap
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "M22 interop test: FlowSpec injection and distribution"
    log "Topology: $TOPO"

    resolve_grpc_addr
    start_rustbgpd

    wait_established || exit 1

    # Snapshot the connectionsDropped counter immediately after the
    # session is up. Every test step asserts this hasn't grown,
    # surfacing a flap at the operation that caused it instead of
    # letting it hide behind a slow eventual recovery.
    INITIAL_DROPS=$(frr_session_drops)
    log "Captured initial connectionsDropped = $INITIAL_DROPS for flap detection"

    test_flowspec_capability
    test_inject_rule1
    test_frr_receives_rule1
    test_inject_rule2
    test_frr_receives_both
    test_withdraw_rule1
    test_frr_withdrawal_propagated

    echo ""
    print_summary
    [ "$fail" -eq 0 ] || exit 1
}

main "$@"
