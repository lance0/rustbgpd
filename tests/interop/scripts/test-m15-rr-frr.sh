#!/usr/bin/env bash
# M15 interop test — Route Refresh (RFC 2918 + RFC 7313)
#
# Validates: SoftResetIn via gRPC triggers route re-advertisement.
#   - Verify initial routes with LOCAL_PREF 150
#   - FRR adds a new network while session is up
#   - SoftResetIn triggers FRR to re-advertise all routes
#   - Verify routes and import policy remain intact after re-advertisement
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m15-rr-frr.clab.yml
#   - grpcurl installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m15-rr-frr.sh


TOPO="m15-rr-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"
FRR="clab-${TOPO}-frr"
FRR_PEER="10.0.0.1"
RUSTBGPD_PEER="10.0.0.2"


grpc_list_received() {
    grpcurl_call \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

grpc_list_best() {
    grpcurl_call \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListBestRoutes 2>/dev/null
}

grpc_soft_reset_in() {
    grpcurl_call \
        -d "{\"address\": \"$1\"}" \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/SoftResetIn 2>/dev/null
}

grpc_neighbor_state() {
    grpcurl_call \
        -d "{\"address\": \"$1\"}" \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/GetNeighborState 2>/dev/null
}

frr_refresh_received() {
    docker exec "$FRR" vtysh -c "show bgp neighbors $FRR_PEER json" 2>/dev/null \
        | jq -er --arg peer "$FRR_PEER" '
            .[$peer].messageStats.routeRefreshRecv
            | if type == "number" and . >= 0 and floor == .
              then .
              else error("routeRefreshRecv is not a non-negative integer")
              end
        '
}

rustbgpd_updates_received() {
    grpc_neighbor_state "$RUSTBGPD_PEER" \
        | jq -er '
            .updatesReceived
            | tonumber
            | select(. >= 0 and floor == .)
        '
}

stable_receipt_baseline() {
    local refresh_previous updates_previous
    if ! refresh_previous=$(frr_refresh_received); then
        return 1
    fi
    if ! updates_previous=$(rustbgpd_updates_received); then
        return 1
    fi

    for _ in $(seq 1 10); do
        sleep 1

        local refresh_current updates_current
        if ! refresh_current=$(frr_refresh_received); then
            return 1
        fi
        if ! updates_current=$(rustbgpd_updates_received); then
            return 1
        fi

        if [ "$refresh_current" -eq "$refresh_previous" ] \
            && [ "$updates_current" -eq "$updates_previous" ]; then
            printf '%s %s\n' "$refresh_current" "$updates_current"
            return 0
        fi

        refresh_previous=$refresh_current
        updates_previous=$updates_current
    done

    return 1
}

wait_established() {
    log "Waiting for BGP session to reach Established..."
    for i in $(seq 1 45); do
        local state
        state=$(docker exec "$FRR" vtysh -c "show bgp neighbors $FRR_PEER json" 2>/dev/null \
            | grep -o '"bgpState":"[^"]*"' | head -1 | cut -d'"' -f4 || true)
        if [ "$state" = "Established" ]; then
            ok "Session established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "Session did not reach Established within 90s"
    return 1
}

wait_routes() {
    local expected=$1
    log "Waiting for $expected routes in RIB..."
    for i in $(seq 1 15); do
        local count
        count=$(grpc_list_received | grep -c '"prefix"' || true)
        if [ "$count" -ge "$expected" ]; then
            ok "Got $count routes in RIB (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "Expected $expected routes, got $(grpc_list_received | grep -c '"prefix"' || echo 0)"
    return 1
}

wait_received_prefix() {
    local prefix=$1
    local prefix_length=$2
    log "Waiting for $prefix/$prefix_length in received routes..."
    for i in $(seq 1 15); do
        if grpc_list_received \
            | jq -e --arg prefix "$prefix" --argjson prefix_length "$prefix_length" '
                any(.routes[]?;
                    .prefix == $prefix
                    and .prefixLength == $prefix_length)
            ' >/dev/null; then
            ok "$prefix/$prefix_length received (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$prefix/$prefix_length was not received"
    return 1
}

# ---------------------------------------------------------------------------
# Test 1: Initial routes received with LOCAL_PREF
# ---------------------------------------------------------------------------
test_initial_routes() {
    log "Test 1: Initial routes received with LOCAL_PREF 150"

    local best
    best=$(grpc_list_best)

    for prefix in "192.168.1.0" "192.168.2.0"; do
        if echo "$best" | grep -q "\"prefix\": \"$prefix\""; then
            ok "$prefix/24 present"
        else
            fail "$prefix/24 missing"
        fi
    done

    # Verify LOCAL_PREF
    local lp
    lp=$(echo "$best" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for r in data.get('routes', []):
    if r.get('prefix') == '192.168.1.0':
        print(r.get('localPref', 0))
        break
" 2>/dev/null || echo "")

    if [ "$lp" = "150" ]; then
        ok "LOCAL_PREF = 150 on import"
    else
        fail "LOCAL_PREF expected 150, got '$lp'"
    fi
}

# ---------------------------------------------------------------------------
# Test 2: SoftResetIn triggers re-advertisement
# ---------------------------------------------------------------------------
test_soft_reset_in() {
    log "Test 2: SoftResetIn triggers route re-advertisement"

    # Add a new network on FRR while session is up
    docker exec "$FRR" vtysh -c "conf t" -c "router bgp 65002" \
        -c "address-family ipv4 unicast" -c "network 10.99.0.0/24" \
        -c "end" 2>/dev/null
    docker exec "$FRR" vtysh -c "conf t" -c "ip route 10.99.0.0/24 10.0.0.2" \
        -c "end" 2>/dev/null

    # Wait for the third route's normal UPDATE by prefix identity before taking
    # either refresh receipt snapshot.
    if ! wait_received_prefix "10.99.0.0" 24; then
        return
    fi

    local count_before
    count_before=$(grpc_list_received | grep -c '"prefix"' || true)
    log "Routes before SoftResetIn: $count_before"

    if [ "$count_before" -ge 3 ]; then
        ok "New route 10.99.0.0/24 received via normal UPDATE"
    else
        fail "Expected 3 routes after adding 10.99.0.0/24, got $count_before"
    fi

    local baseline refresh_before updates_before
    if ! baseline=$(stable_receipt_baseline); then
        fail "Refresh receipts did not produce two equal valid baseline samples"
        return
    fi
    read -r refresh_before updates_before <<< "$baseline"
    log "Receipts before SoftResetIn: routeRefreshRecv=$refresh_before, updatesReceived=$updates_before"

    # Now trigger SoftResetIn — this should cause FRR to re-send all routes.
    log "Triggering SoftResetIn..."
    if grpc_soft_reset_in "$RUSTBGPD_PEER" >/dev/null; then
        ok "SoftResetIn RPC completed"
    else
        fail "SoftResetIn RPC failed"
        return
    fi

    local refresh_after=$refresh_before
    local updates_after=$updates_before
    local expected_refresh=$((refresh_before + 1))
    local deltas_observed=0
    local quiet_tail_samples=0
    for i in $(seq 1 20); do
        if ! refresh_after=$(frr_refresh_received); then
            fail "FRR routeRefreshRecv receipt became missing, malformed, or nonnumeric"
            return
        fi
        if ! updates_after=$(rustbgpd_updates_received); then
            fail "rustbgpd updatesReceived receipt became missing, malformed, or nonnumeric"
            return
        fi
        if [ "$refresh_after" -eq "$expected_refresh" ] \
            && [ "$updates_after" -gt "$updates_before" ]; then
            if [ "$deltas_observed" -eq 0 ]; then
                deltas_observed=1
                log "Refresh receipt deltas observed (attempt $i); checking quiet tail"
            else
                quiet_tail_samples=$((quiet_tail_samples + 1))
                if [ "$quiet_tail_samples" -ge 3 ]; then
                    break
                fi
            fi
        fi
        if [ "$refresh_after" -gt "$expected_refresh" ]; then
            break
        fi
        sleep 1
    done

    if [ "$refresh_after" -eq "$expected_refresh" ] \
        && [ "$quiet_tail_samples" -ge 3 ]; then
        ok "FRR received exactly one Route Refresh ($refresh_before -> $refresh_after; quiet tail stable)"
    else
        fail "FRR Route Refresh delta expected +1, got $refresh_before -> $refresh_after"
    fi
    if [ "$updates_after" -gt "$updates_before" ]; then
        ok "FRR re-advertised UPDATEs ($updates_before -> $updates_after received)"
    else
        fail "No UPDATE received after Route Refresh (stayed $updates_after)"
    fi

    # Session should still be up (no flap)
    local state
    state=$(docker exec "$FRR" vtysh -c "show bgp neighbors $FRR_PEER json" 2>/dev/null \
        | grep -o '"bgpState":"[^"]*"' | head -1 | cut -d'"' -f4 || true)

    if [ "$state" = "Established" ]; then
        ok "Session still Established after SoftResetIn (no flap)"
    else
        fail "Session state after SoftResetIn: $state (expected Established)"
    fi

    # All routes should still be present after re-advertisement
    local count_after
    count_after=$(grpc_list_received | grep -c '"prefix"' || true)

    if [ "$count_after" -ge 3 ]; then
        ok "All $count_after routes present after SoftResetIn"
    else
        fail "Expected >= 3 routes after SoftResetIn, got $count_after"
    fi
}

# ---------------------------------------------------------------------------
# Test 3: Routes still have import policy applied after SoftResetIn
# ---------------------------------------------------------------------------
test_policy_after_reset() {
    log "Test 3: Import policy still applied after SoftResetIn"

    local best
    best=$(grpc_list_best)

    local lp
    lp=$(echo "$best" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for r in data.get('routes', []):
    if r.get('prefix') == '192.168.1.0':
        print(r.get('localPref', 0))
        break
" 2>/dev/null || echo "")

    if [ "$lp" = "150" ]; then
        ok "LOCAL_PREF = 150 still applied after SoftResetIn"
    else
        fail "LOCAL_PREF expected 150 after SoftResetIn, got '$lp'"
    fi
}

# Use the robust `start_rustbgpd` from test-lib.sh (10 s poll loop
# rather than a 3 s fixed sleep) — required under parallel CI load
# where the docker fork can land slowly.

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "M15 interop test: Route Refresh (RFC 2918 + RFC 7313)"
    log "Topology: $TOPO"

    resolve_grpc_addr
    start_rustbgpd

    wait_established || true
    wait_routes 2 || true

    test_initial_routes
    test_soft_reset_in
    test_policy_after_reset

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
