#!/usr/bin/env bash
# M26 interop test — Cease subcode compatibility with FRR
#
# Validates:
#   1. Session establishes initially
#   2. FRR sends 3 prefixes, exceeding max_prefixes=2
#   3. rustbgpd sends Cease/1 (Max Prefixes) NOTIFICATION
#   4. FRR sees the NOTIFICATION and session tears down
#   5. Prometheus metric records the max-prefix event
#   6. The peer stays administratively down beyond two retry intervals
#   7. Enable while still over-limit re-latches the peer
#   8. Removing excess routes alone does not recover the peer
#   9. Explicit enable after removal re-establishes with two prefixes
#  10. max_prefix_action = "block" (second FRR peer): the session never resets,
#      net-new prefixes beyond the bound are withheld in arrival order, and one
#      ROUTE-REFRESH after usage falls back under the bound makes FRR replay
#      the withheld prefix
#  11. max_prefix_action = "warning" (third FRR peer): nothing is withheld and
#      exactly one warning is reported
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m26-cease-frr.clab.yml
#   - grpcurl and jq installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m26-cease-frr.sh


TOPO="m26-cease-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
source "$SCRIPT_DIR/test-lib.sh"
FRR="clab-${TOPO}-frr"


grpc_metrics() {
    grpcurl_call \
        "$GRPC_ADDR" rustbgpd.v1.ControlService/GetMetrics 2>/dev/null
}

grpc_neighbor_state() {
    grpcurl_call \
        -d '{"address": "10.0.0.2"}' \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/GetNeighborState 2>/dev/null
}

grpc_enable_neighbor() {
    grpcurl_call \
        -d '{"address": "10.0.0.2"}' \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/EnableNeighbor >/dev/null
}

frr_state() {
    docker exec "$FRR" vtysh -c "show bgp neighbors 10.0.0.1 json" 2>/dev/null \
        | grep -o '"bgpState":"[^"]*"' | head -1 | cut -d'"' -f4 || true
}

max_prefix_metric_value() {
    grpc_metrics | python3 -c '
import json, re, sys
text = json.load(sys.stdin).get("prometheusText", "")
values = [float(match.group(1)) for match in re.finditer(
    r"^bgp_max_prefix_exceeded_total(?:\{[^}]*\})?\s+([0-9.eE+-]+)$",
    text,
    re.MULTILINE,
)]
print(int(sum(values)))
' 2>/dev/null || echo 0
}

wait_latched_down() {
    local minimum_metric="$1"
    for _ in $(seq 1 30); do
        local state error metric
        state=$(grpc_neighbor_state || true)
        error=$(echo "$state" | python3 -c '
import json, sys
print(json.load(sys.stdin)["lastError"])
' 2>/dev/null || echo parse-error)
        metric=$(max_prefix_metric_value)
        if echo "$error" | grep -qi "max-prefix limit exceeded" \
            && [ "$metric" -ge "$minimum_metric" ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# ---------------------------------------------------------------------------
# Non-teardown actions: helpers
# ---------------------------------------------------------------------------
FRR_BLOCK="clab-${TOPO}-frr-block"
FRR_WARN="clab-${TOPO}-frr-warn"
BLOCK_PEER="10.0.1.2"   # frr-block as the daemon names it
BLOCK_LOCAL="10.0.1.1"  # the daemon as frr-block names it
WARN_PEER="10.0.2.2"
WARN_LOCAL="10.0.2.1"

grpc_neighbor_state_for() {
    grpcurl_call \
        -d "{\"address\": \"$1\"}" \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/GetNeighborState 2>/dev/null
}

# Exact Prometheus series (name plus rendered labels) -> integer value, or the
# word "absent". A counter that never incremented has no series yet; a gauge
# for a configured scope is always present.
metric_series() {
    grpc_metrics | jq -r '.prometheusText // ""' 2>/dev/null \
        | awk -v s="$1" '$1 == s { found = 1; v = $2 }
            END { if (found) printf "%d\n", v; else print "absent" }' || echo error
}

# Daemon's received view for one peer as a sorted, space-joined prefix list.
received_prefixes() {
    grpcurl_call \
        -d "{\"neighbor_address\": \"$1\"}" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null \
        | jq -r '[.routes[]? | "\(.prefix)/\(.prefixLength)"] | sort | join(" ")' \
            2>/dev/null || echo error
}

wait_received() {
    local peer="$1" expected="$2"
    for _ in $(seq 1 60); do
        if [ "$(received_prefixes "$peer")" = "$expected" ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_metric_series() {
    local series="$1" expected="$2"
    for _ in $(seq 1 60); do
        if [ "$(metric_series "$series")" = "$expected" ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

updates_received() {
    grpc_neighbor_state_for "$1" | jq -r '.updatesReceived // "0"' 2>/dev/null || echo error
}

wait_updates_received_above() {
    local peer="$1" floor="$2" now
    for _ in $(seq 1 60); do
        now=$(updates_received "$peer")
        if [ "$now" != "error" ] && [ "$now" -gt "$floor" ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

frr_neighbor_field() {
    local container="$1" peer="$2" filter="$3"
    docker exec "$container" vtysh -c "show bgp neighbors $peer json" 2>/dev/null \
        | jq -r --arg peer "$peer" ".[\$peer] | $filter" 2>/dev/null || echo error
}

frr_refresh_received() {
    frr_neighbor_field "$1" "$2" '.messageStats.routeRefreshRecv'
}

frr_advertised() {
    docker exec "$1" vtysh \
        -c "show bgp ipv4 unicast neighbors $2 advertised-routes json" 2>/dev/null \
        | jq -r '.advertisedRoutes // {} | keys | sort | join(" ")' 2>/dev/null || echo error
}

wait_frr_advertised() {
    local container="$1" peer="$2" expected="$3"
    for _ in $(seq 1 60); do
        if [ "$(frr_advertised "$container" "$peer")" = "$expected" ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

frr_network() {
    local container="$1" asn="$2" statement="$3"
    docker exec "$container" vtysh \
        -c "configure terminal" \
        -c "router bgp $asn" \
        -c "address-family ipv4 unicast" \
        -c "$statement" >/dev/null 2>&1
}

# One comparable line: daemon state, flaps out of Established and NOTIFICATIONs
# in either direction, then FRR's state and connection counters. Any session
# reset changes it.
session_counters() {
    local container="$1" local_addr="$2" peer="$3" daemon frr
    daemon=$(grpc_neighbor_state_for "$peer" | jq -r '[
        .state,
        (.flapCount // "0"),
        (.notificationsSent // "0"),
        (.notificationsReceived // "0")
    ] | join(",")' 2>/dev/null || echo error)
    frr=$(frr_neighbor_field "$container" "$local_addr" \
        '[.bgpState, .connectionsEstablished, .connectionsDropped] | join(",")')
    echo "daemon=$daemon frr=$frr"
}

assert_session_unchanged() {
    local label="$1" baseline="$2" container="$3" local_addr="$4" peer="$5" now
    now=$(session_counters "$container" "$local_addr" "$peer")
    if [ "$now" = "$baseline" ]; then
        ok "$label: session never reset ($now)"
    else
        fail "$label: session counters changed: before [$baseline] after [$now]"
    fi
}

assert_eq() {
    local label="$1" expected="$2" actual="$3"
    if [ "$actual" = "$expected" ]; then
        ok "$label ($actual)"
    else
        fail "$label: expected [$expected], got [$actual]"
    fi
}

warning_event_count() {
    grpcurl_call \
        -d "{\"neighbor_address\": \"$1\", \"event_types\": [\"BGP_EVENT_TYPE_MAX_PREFIX_WARNING\"]}" \
        "$GRPC_ADDR" rustbgpd.v1.EventService/ListSessionEvents 2>/dev/null \
        | jq -r '.events // [] | length' 2>/dev/null || echo error
}

inbound_limit_row() {
    grpc_neighbor_state_for "$1" | jq -r '.inboundPrefixLimits[]?
        | select(.scope == "ipv4_unicast")
        | [.usage, .limit, (.blocking // false), (.reason // "")] | join(",")' \
        2>/dev/null || echo error
}

# Use the standardized `start_rustbgpd` from test-lib.sh — handles
# both the /proc poll loop and the gRPC-ready wait.

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

test_session_establishes() {
    log "Test 1: Session establishes at the exact two-prefix bound"

    for i in $(seq 1 30); do
        local state prefix_count
        state=$(frr_state)
        if [ "$state" = "Established" ]; then
            prefix_count=$(grpc_neighbor_state | python3 -c '
import json, sys
value = json.load(sys.stdin)["prefixesReceived"]
print(int(value))
' 2>/dev/null || echo parse-error)
            if [ "$prefix_count" = "2" ]; then
                ok "Session is Established with exactly two accepted prefixes (attempt $i)"
                return 0
            fi
        fi
        sleep 2
    done
    fail "Session never held Established with exactly two prefixes within 60s"
}

inject_excess_prefix() {
    log "Injecting third FRR prefix to cross max_prefixes=2"
    docker exec "$FRR" vtysh \
        -c "configure terminal" \
        -c "router bgp 65002" \
        -c "address-family ipv4 unicast" \
        -c "network 10.10.0.0/16" >/dev/null 2>&1 || true
    if ! docker exec "$FRR" vtysh -c "show running-config" 2>/dev/null \
        | grep '^  network 10\.10\.0\.0/16$' >/dev/null; then
        fail "FRR did not install the third network statement"
        return 1
    fi
}

test_cease_notification_sent() {
    log "Test 2: Cease NOTIFICATION sent (max_prefixes exceeded)"

    # Wait for FRR to see the notification — session should bounce
    for i in $(seq 1 30); do
        local neighbor
        neighbor=$(docker exec "$FRR" vtysh -c "show bgp neighbors 10.0.0.1" 2>/dev/null || true)

        if echo "$neighbor" \
            | grep -Fq 'Notification received (Cease/Maximum Number of Prefixes Reached)'; then
            ok "FRR received Cease/Maximum Number of Prefixes Reached"
            return 0
        fi

        sleep 2
    done
    fail "FRR did not report Cease NOTIFICATION within 60s"
    log "DEBUG FRR neighbor state:"
    docker exec "$FRR" vtysh -c "show bgp neighbors 10.0.0.1" 2>/dev/null | grep -i "notif\|cease\|reset\|error\|last" || true
}

test_max_prefix_metric() {
    log "Test 3: Prometheus max-prefix-exceeded metric"

    local value
    value=$(max_prefix_metric_value)
    if [ "$value" -ge 1 ]; then
        ok "bgp_max_prefix_exceeded_total incremented (value=$value)"
    else
        fail "bgp_max_prefix_exceeded_total did not increment"
    fi
}

test_session_latches_down() {
    log "Test 4: max-prefix breach latches the peer administratively down"

    if wait_latched_down 1; then
        ok "Manager owns an actionable max-prefix latch reason"
    else
        fail "Peer did not enter the max-prefix disabled latch"
        return
    fi

    local metric_before
    metric_before=$(max_prefix_metric_value)
    # PeerManager configures a 5 s retry interval. Twelve seconds covers more
    # than two intervals and catches the old auto-reconnect/bounce behavior.
    sleep 12
    local metric_after state
    metric_after=$(max_prefix_metric_value)
    state=$(frr_state)
    if [ "$state" = "Established" ]; then
        fail "Session re-established without explicit enable"
    elif [ "$metric_after" -ne "$metric_before" ]; then
        fail "Max-prefix metric advanced while peer should remain latched ($metric_before -> $metric_after)"
    else
        ok "Peer stayed down beyond two retry intervals (FRR state=${state:-unknown})"
    fi
}

test_enable_while_over_limit_relatches() {
    log "Test 5: explicit enable while still over-limit re-latches"
    local expected
    expected=$(( $(max_prefix_metric_value) + 1 ))
    if ! grpc_enable_neighbor; then
        fail "EnableNeighbor RPC failed"
        return
    fi
    if wait_latched_down "$expected"; then
        ok "Three-prefix replay exceeded the bound again and restored the disabled latch"
    else
        fail "Over-limit explicit enable did not re-latch the peer"
    fi
}

test_recovery_requires_removal_and_enable() {
    log "Test 6: recovery requires excess removal plus explicit enable"
    local metric_before
    metric_before=$(max_prefix_metric_value)
    docker exec "$FRR" vtysh \
        -c "configure terminal" \
        -c "router bgp 65002" \
        -c "address-family ipv4 unicast" \
        -c "no network 10.10.0.0/16" >/dev/null 2>&1 || true
    if docker exec "$FRR" vtysh -c "show running-config" 2>/dev/null \
        | grep '^  network 10\.10\.0\.0/16$' >/dev/null; then
        fail "FRR retained the third network statement after removal"
        return
    fi

    sleep 12
    if [ "$(frr_state)" = "Established" ]; then
        fail "Removing the excess route bypassed the explicit-enable latch"
        return
    fi
    local error metric_after
    error=$(grpc_neighbor_state | python3 -c '
import json, sys
print(json.load(sys.stdin)["lastError"])
' 2>/dev/null || echo parse-error)
    metric_after=$(max_prefix_metric_value)
    if ! echo "$error" | grep -qi "max-prefix limit exceeded"; then
        fail "Manager-owned max-prefix last_error disappeared before explicit enable"
        return
    elif [ "$metric_after" -ne "$metric_before" ]; then
        fail "Max-prefix metric advanced after removal without enable ($metric_before -> $metric_after)"
        return
    fi
    ok "Excess removal alone preserved the manager-owned latch"

    if ! grpc_enable_neighbor; then
        fail "EnableNeighbor RPC failed after excess removal"
        return
    fi
    for _ in $(seq 1 30); do
        local state prefix_count
        state=$(frr_state)
        prefix_count=$(grpc_neighbor_state | python3 -c '
import json, sys
print(int(json.load(sys.stdin)["prefixesReceived"]))
' 2>/dev/null || echo parse-error)
        if [ "$state" = "Established" ] && [ "$prefix_count" = "2" ]; then
            ok "Session recovered only after explicit enable with two prefixes"
            return
        fi
        sleep 1
    done
    fail "Session did not recover with two prefixes after explicit enable"
}

test_frr_cease_subcode_acceptance() {
    log "Test 7: FRR accepted Cease subcode (no crash, clean teardown)"

    # Verify FRR is still running and healthy
    local frr_running
    frr_running=$(docker exec "$FRR" vtysh -c "show bgp summary json" 2>/dev/null || echo "error")

    if echo "$frr_running" | grep -q "routerId"; then
        ok "FRR still operational after receiving Cease"
    else
        fail "FRR not responding after Cease"
    fi
}

test_block_action_withholds_and_recovers() {
    log "Test 8: block action withholds beyond the bound and recovers by one ROUTE-REFRESH"
    local blocking="bgp_max_prefix_blocking{peer=\"$BLOCK_PEER\",scope=\"ipv4_unicast\"}"
    local blocked_total="bgp_max_prefix_blocked_total{peer=\"$BLOCK_PEER\",scope=\"ipv4_unicast\"}"
    local refresh_sent="bgp_messages_sent_total{peer=\"$BLOCK_PEER\",type=\"route_refresh\"}"
    local p1="172.16.1.0/24" p2="172.16.2.0/24" p3="172.16.3.0/24"
    local p4="172.16.4.0/24" p5="172.16.5.0/24"

    wait_frr_established "$FRR_BLOCK" "$BLOCK_LOCAL" "block peer" || return
    if ! wait_received "$BLOCK_PEER" "$p1 $p2"; then
        fail "block peer did not converge under the bound: [$(received_prefixes "$BLOCK_PEER")]"
        return
    fi
    local baseline
    baseline=$(session_counters "$FRR_BLOCK" "$BLOCK_LOCAL" "$BLOCK_PEER")
    case "$baseline" in
        daemon=SESSION_STATE_ESTABLISHED,*" frr=Established,"*) ok "Baseline under the bound: $baseline" ;;
        *) fail "block peer baseline is not Established on both sides: $baseline"; return ;;
    esac
    assert_eq "No blocking episode under the bound" "0" "$(metric_series "$blocking")"
    assert_eq "No ROUTE-REFRESH received by FRR yet" "0" \
        "$(frr_refresh_received "$FRR_BLOCK" "$BLOCK_LOCAL")"
    assert_eq "No ROUTE-REFRESH sent by the daemon yet" "0" "$(metric_series "$refresh_sent")"

    # Fill the bound exactly: the last slot is admitted and opens no episode.
    frr_network "$FRR_BLOCK" 65003 "network $p3" || true
    if wait_received "$BLOCK_PEER" "$p1 $p2 $p3"; then
        ok "Third prefix takes the last slot"
    else
        fail "Third prefix was not admitted: [$(received_prefixes "$BLOCK_PEER")]"
        return
    fi
    assert_eq "Filling the bound exactly opens no episode" "0" "$(metric_series "$blocking")"
    assert_eq "No episode counted at the bound" "absent" "$(metric_series "$blocked_total")"

    # Exceed it one prefix at a time so arrival order is known.
    frr_network "$FRR_BLOCK" 65003 "network $p4" || true
    if wait_metric_series "$blocking" "1"; then
        ok "Fourth prefix opened a blocking episode"
    else
        fail "bgp_max_prefix_blocking never became 1"
        return
    fi
    local updates_before
    updates_before=$(updates_received "$BLOCK_PEER")
    frr_network "$FRR_BLOCK" 65003 "network $p5" || true
    if ! wait_frr_advertised "$FRR_BLOCK" "$BLOCK_LOCAL" "$p1 $p2 $p3 $p4 $p5" \
        || ! wait_updates_received_above "$BLOCK_PEER" "$updates_before"; then
        fail "FRR did not advertise all five prefixes to the daemon"
        return
    fi
    ok "FRR advertises five prefixes; the daemon processed the fifth UPDATE"
    assert_eq "Arrival order decides: only the first three are held" \
        "$p1 $p2 $p3" "$(received_prefixes "$BLOCK_PEER")"
    assert_eq "One episode counted for two withheld prefixes" "1" \
        "$(metric_series "$blocked_total")"
    assert_eq "NeighborState reports the open episode" \
        "3,3,true,inbound_prefix_limit_reached" "$(inbound_limit_row "$BLOCK_PEER")"
    assert_session_unchanged "While blocking" "$baseline" \
        "$FRR_BLOCK" "$BLOCK_LOCAL" "$BLOCK_PEER"
    assert_eq "No ROUTE-REFRESH while over the bound" "0" \
        "$(frr_refresh_received "$FRR_BLOCK" "$BLOCK_LOCAL")"

    # Withdrawing a withheld prefix frees no slot.
    updates_before=$(updates_received "$BLOCK_PEER")
    frr_network "$FRR_BLOCK" 65003 "no network $p5" || true
    if ! wait_updates_received_above "$BLOCK_PEER" "$updates_before"; then
        fail "Daemon never processed the withdrawal of the withheld prefix"
        return
    fi
    assert_eq "Withdrawing a withheld prefix keeps the episode open" "1" \
        "$(metric_series "$blocking")"
    assert_eq "Withdrawing a withheld prefix requests no replay" "0" \
        "$(frr_refresh_received "$FRR_BLOCK" "$BLOCK_LOCAL")"

    # Withdrawing an accepted prefix takes usage under the bound.
    frr_network "$FRR_BLOCK" 65003 "no network $p1" || true
    if wait_received "$BLOCK_PEER" "$p2 $p3 $p4"; then
        ok "FRR replayed on ROUTE-REFRESH: the withheld prefix is back"
    else
        fail "Withheld prefix $p4 did not return: [$(received_prefixes "$BLOCK_PEER")]"
        log "DEBUG FRR message stats:"
        frr_neighbor_field "$FRR_BLOCK" "$BLOCK_LOCAL" '.messageStats' || true
        log "DEBUG FRR advertised: [$(frr_advertised "$FRR_BLOCK" "$BLOCK_LOCAL")]"
    fi
    # Let any second refresh or replay-driven episode show itself.
    sleep 5
    assert_eq "FRR received exactly one ROUTE-REFRESH" "1" \
        "$(frr_refresh_received "$FRR_BLOCK" "$BLOCK_LOCAL")"
    assert_eq "Daemon sent exactly one ROUTE-REFRESH" "1" "$(metric_series "$refresh_sent")"
    assert_eq "Received view is stable after the replay" \
        "$p2 $p3 $p4" "$(received_prefixes "$BLOCK_PEER")"
    assert_eq "Episode closed" "0" "$(metric_series "$blocking")"
    assert_eq "Replay that fits the bound opens no second episode" "1" \
        "$(metric_series "$blocked_total")"
    assert_eq "NeighborState reports the closed episode" \
        "3,3,false," "$(inbound_limit_row "$BLOCK_PEER")"
    assert_session_unchanged "After recovery" "$baseline" \
        "$FRR_BLOCK" "$BLOCK_LOCAL" "$BLOCK_PEER"
}

test_warning_action_reports_and_keeps_accepting() {
    log "Test 9: warning action withholds nothing and reports one crossing"
    local warning_total="bgp_max_prefix_warning_total{peer=\"$WARN_PEER\",scope=\"ipv4_unicast\"}"
    local blocking="bgp_max_prefix_blocking{peer=\"$WARN_PEER\",scope=\"ipv4_unicast\"}"
    local blocked_total="bgp_max_prefix_blocked_total{peer=\"$WARN_PEER\",scope=\"ipv4_unicast\"}"
    local refresh_sent="bgp_messages_sent_total{peer=\"$WARN_PEER\",type=\"route_refresh\"}"
    local q="172.17.1.0/24 172.17.2.0/24"

    wait_frr_established "$FRR_WARN" "$WARN_LOCAL" "warning peer" || return
    if ! wait_received "$WARN_PEER" "$q"; then
        fail "warning peer did not converge under the bound: [$(received_prefixes "$WARN_PEER")]"
        return
    fi
    local baseline
    baseline=$(session_counters "$FRR_WARN" "$WARN_LOCAL" "$WARN_PEER")
    case "$baseline" in
        daemon=SESSION_STATE_ESTABLISHED,*" frr=Established,"*) ok "Baseline under the bound: $baseline" ;;
        *) fail "warning peer baseline is not Established on both sides: $baseline"; return ;;
    esac
    assert_eq "No warning under the bound" "absent" "$(metric_series "$warning_total")"

    local n
    for n in 3 4 5; do
        frr_network "$FRR_WARN" 65004 "network 172.17.$n.0/24" || true
        q="$q 172.17.$n.0/24"
    done
    if wait_received "$WARN_PEER" "$q"; then
        ok "All five prefixes accepted past a bound of three"
    else
        fail "warning action withheld something: [$(received_prefixes "$WARN_PEER")]"
    fi
    assert_eq "One warning for one crossing" "1" "$(metric_series "$warning_total")"
    # The session task counts the warning before it delivers routes, but the
    # session event is published by the peer manager from a notification, so
    # the received view does not prove the event is already in the history.
    local events
    for _ in $(seq 1 60); do
        events=$(warning_event_count "$WARN_PEER")
        case "$events" in
            "" | error | 0) sleep 1 ;;
            *) break ;;
        esac
    done
    # Let a duplicate event show itself.
    sleep 5
    assert_eq "One max-prefix warning session event" "1" "$(warning_event_count "$WARN_PEER")"
    assert_eq "warning never opens a blocking episode" "0" "$(metric_series "$blocking")"
    assert_eq "warning never counts a blocking episode" "absent" "$(metric_series "$blocked_total")"
    assert_eq "warning requests no replay" "0" "$(metric_series "$refresh_sent")"
    assert_session_unchanged "After the warning" "$baseline" \
        "$FRR_WARN" "$WARN_LOCAL" "$WARN_PEER"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "M26 interop test: Cease subcode compatibility"
    log "Topology: $TOPO (max_prefixes=2, FRR starts at 2; test injects a third)"

    resolve_grpc_addr
    start_rustbgpd

    # Give the initial at-bound session time to converge.
    sleep 15

    test_session_establishes
    inject_excess_prefix || exit 1
    test_cease_notification_sent
    test_max_prefix_metric
    test_session_latches_down
    test_enable_while_over_limit_relatches
    test_recovery_requires_removal_and_enable
    test_frr_cease_subcode_acceptance
    test_block_action_withholds_and_recovers
    test_warning_action_reports_and_keeps_accepting

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
