#!/usr/bin/env bash
# M11 interop test — Graceful Restart (RFC 4724) receiving speaker
#
# Validates that rustbgpd correctly preserves routes when a GR-capable peer
# restarts, clears stale flags on End-of-RIB, and sweeps stale routes when
# the GR timer expires without reconnection.
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m11-gr-frr.clab.yml
#   - grpcurl installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m11-gr-frr.sh


TOPO="m11-gr-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"
FRR="clab-${TOPO}-frr"


# Resolve rustbgpd container management IP for gRPC access

grpc_list_routes() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

grpc_list_routes_for_peer() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"neighbor_address\": \"$1\"}" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

grpc_list_neighbors() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/ListNeighbors 2>/dev/null
}

grpc_get_metrics() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.ControlService/GetMetrics 2>/dev/null
}

# Extract a specific prometheus metric value from GetMetrics output
# Usage: get_metric_value "bgp_gr_active_peers"
get_metric_value() {
    local metric_name=$1
    local metrics
    metrics=$(grpc_get_metrics)
    # Prometheus text format: metric_name{labels} value
    # The gRPC response wraps it in JSON with prometheusText field
    echo "$metrics" | grep -oP "${metric_name}[^}]*\}\s+\K[0-9.]+" | head -1 || echo "0"
}

# Get total stale route count across all peers
get_stale_route_count() {
    local metrics
    metrics=$(grpc_get_metrics)
    local total=0
    while IFS= read -r val; do
        total=$((total + ${val%.*}))
    done < <(echo "$metrics" | grep -oP 'bgp_gr_stale_routes\{[^}]*\}\s+\K[0-9.]+' || true)
    echo "$total"
}

# Get GR active peer count
get_gr_active_count() {
    local metrics
    metrics=$(grpc_get_metrics)
    local total=0
    while IFS= read -r val; do
        total=$((total + ${val%.*}))
    done < <(echo "$metrics" | grep -oP 'bgp_gr_active_peers\{[^}]*\}\s+\K[0-9.]+' || true)
    echo "$total"
}

# ---------------------------------------------------------------------------
# Wait for BGP session to reach Established
# ---------------------------------------------------------------------------
wait_established() {
    log "Waiting for BGP session to reach Established..."
    for i in $(seq 1 45); do
        local state
        state=$(docker exec "$FRR" vtysh -c "show bgp neighbors 10.0.0.1 json" 2>/dev/null \
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

# Wait for routes to appear in the RIB
wait_routes() {
    local expected=$1
    log "Waiting for $expected routes in RIB..."
    for i in $(seq 1 15); do
        local count
        count=$(grpc_list_routes | grep -c '"prefix"' || true)
        if [ "$count" -ge "$expected" ]; then
            ok "Got $count routes in RIB (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "Expected $expected routes, got $(grpc_list_routes | grep -c '"prefix"' || echo 0)"
    return 1
}

# Wait for rustbgpd neighbor state to show a specific session state
wait_rustbgpd_state() {
    local expected=$1
    local max_attempts=${2:-30}
    log "Waiting for rustbgpd neighbor state: $expected..."
    for i in $(seq 1 "$max_attempts"); do
        local state
        state=$(grpc_list_neighbors 2>/dev/null \
            | grep -o '"state": "[^"]*"' | head -1 | cut -d'"' -f4 || true)
        if [ "$state" = "$expected" ]; then
            return 0
        fi
        sleep 2
    done
    return 1
}

# ---------------------------------------------------------------------------
# Test 1: GR capability negotiated — session established with GR-capable peer
# ---------------------------------------------------------------------------
test_gr_capability_negotiated() {
    log "Test 1: GR capability negotiated with FRR"

    wait_established || return 1
    wait_routes 3 || return 1

    # Verify FRR sees GR capability from rustbgpd
    local nbr_json
    nbr_json=$(docker exec "$FRR" vtysh -c "show bgp neighbors 10.0.0.1 json" 2>/dev/null || true)

    if echo "$nbr_json" | grep -qi "gracefulRestart"; then
        ok "FRR reports GR capability in neighbor state"
    else
        fail "FRR does not report GR capability"
    fi

    # Verify routes are present and NOT stale initially
    local stale_count
    stale_count=$(get_stale_route_count)
    if [ "$stale_count" -eq 0 ]; then
        ok "No stale routes in steady state"
    else
        fail "Expected 0 stale routes in steady state, got $stale_count"
    fi
}

# ---------------------------------------------------------------------------
# Test 2: Peer restart preserves routes (stale marking)
# ---------------------------------------------------------------------------
test_peer_restart_preserves_routes() {
    log "Test 2: Peer restart preserves routes as stale"

    # Verify we have routes before the kill
    local pre_count
    pre_count=$(grpc_list_routes | grep -c '"prefix"' || true)
    if [ "$pre_count" -lt 3 ]; then
        fail "Expected at least 3 routes before peer kill, got $pre_count"
        return 1
    fi
    log "Pre-restart route count: $pre_count"

    # Kill FRR bgpd — simulates an ungraceful peer restart
    log "Killing FRR bgpd to trigger GR..."
    docker exec "$FRR" killall -9 bgpd 2>/dev/null || true

    # Wait for rustbgpd to detect the session down and enter GR
    log "Waiting for rustbgpd to detect session down and enter GR..."
    sleep 5

    # Check GR is active
    local gr_active
    gr_active=$(get_gr_active_count)
    if [ "$gr_active" -ge 1 ]; then
        ok "GR active (bgp_gr_active_peers=$gr_active)"
    else
        fail "Expected GR to be active, bgp_gr_active_peers=$gr_active"
    fi

    # Check routes are preserved (stale)
    local stale_count
    stale_count=$(get_stale_route_count)
    if [ "$stale_count" -ge 3 ]; then
        ok "Routes preserved as stale ($stale_count stale routes)"
    else
        fail "Expected at least 3 stale routes, got $stale_count"
    fi

    # Routes should still be in the RIB (preserved, not withdrawn)
    local rib_count
    rib_count=$(grpc_list_routes | grep -c '"prefix"' || true)
    if [ "$rib_count" -ge 3 ]; then
        ok "Routes still in RIB during GR ($rib_count routes)"
    else
        fail "Expected routes preserved in RIB, got $rib_count"
    fi
}

# ---------------------------------------------------------------------------
# Test 3: Peer reconnects and EoR clears stale routes
# ---------------------------------------------------------------------------
test_eor_clears_stale() {
    log "Test 3: Peer reconnects, EoR clears stale flag"

    # watchfrr should restart bgpd automatically
    log "Waiting for FRR bgpd to restart (via watchfrr) and session to re-establish..."

    wait_established || {
        fail "Session did not re-establish after peer restart"
        return 1
    }

    # Wait for EoR exchange — FRR sends EoR after initial table dump
    log "Waiting for End-of-RIB exchange..."
    sleep 10

    # After EoR, stale routes should be cleared
    local stale_count
    stale_count=$(get_stale_route_count)
    if [ "$stale_count" -eq 0 ]; then
        ok "Stale routes cleared after EoR (stale_count=$stale_count)"
    else
        fail "Expected 0 stale routes after EoR, got $stale_count"
    fi

    # GR should no longer be active for this peer
    local gr_active
    gr_active=$(get_gr_active_count)
    if [ "$gr_active" -eq 0 ]; then
        ok "GR completed (bgp_gr_active_peers=$gr_active)"
    else
        fail "Expected GR to be complete, bgp_gr_active_peers=$gr_active"
    fi

    # Routes should still be present and valid
    local rib_count
    rib_count=$(grpc_list_routes | grep -c '"prefix"' || true)
    if [ "$rib_count" -ge 3 ]; then
        ok "Routes valid after GR completion ($rib_count routes)"
    else
        fail "Expected at least 3 routes after GR, got $rib_count"
    fi
}

# ---------------------------------------------------------------------------
# Test 4: GR timer expiry sweeps stale routes
# ---------------------------------------------------------------------------
test_timer_expiry_sweeps_stale() {
    log "Test 4: GR timer expiry sweeps stale routes"

    # Verify we have routes
    local pre_count
    pre_count=$(grpc_list_routes | grep -c '"prefix"' || true)
    if [ "$pre_count" -lt 3 ]; then
        fail "Expected at least 3 routes before test, got $pre_count"
        return 1
    fi

    # Kill FRR bgpd AND stop watchfrr so it doesn't restart
    log "Killing FRR bgpd and watchfrr to prevent restart..."
    docker exec "$FRR" killall -9 bgpd 2>/dev/null || true
    docker exec "$FRR" killall -9 watchfrr 2>/dev/null || true

    # Wait for rustbgpd to enter GR
    sleep 5

    local gr_active
    gr_active=$(get_gr_active_count)
    if [ "$gr_active" -ge 1 ]; then
        ok "GR active after peer kill (bgp_gr_active_peers=$gr_active)"
    else
        fail "Expected GR active, got $gr_active"
    fi

    local stale_count
    stale_count=$(get_stale_route_count)
    if [ "$stale_count" -ge 3 ]; then
        ok "Routes stale during GR ($stale_count stale)"
    else
        fail "Expected stale routes, got $stale_count"
    fi

    # Wait for GR timer to expire (restart_time=30s)
    # The timer starts when session goes down, so we need to wait ~30s from
    # when we killed bgpd (already waited 5s above)
    log "Waiting for GR restart timer to expire (30s)..."
    sleep 30

    # After timer expiry, stale routes should be swept
    local post_stale
    post_stale=$(get_stale_route_count)
    if [ "$post_stale" -eq 0 ]; then
        ok "Stale routes swept after timer expiry"
    else
        fail "Expected 0 stale routes after timer expiry, got $post_stale"
    fi

    # Routes should be gone from RIB
    local post_count
    post_count=$(grpc_list_routes_for_peer "10.0.0.2" | grep -c '"prefix"' || true)
    if [ "$post_count" -eq 0 ]; then
        ok "RIB cleared after GR timer expiry"
    else
        fail "Expected 0 routes from peer after sweep, got $post_count"
    fi

    # Timer expired counter should have incremented
    local expired
    expired=$(get_metric_value "bgp_gr_timer_expired_total")
    if [ "${expired%.*}" -ge 1 ]; then
        ok "bgp_gr_timer_expired_total incremented ($expired)"
    else
        fail "Expected bgp_gr_timer_expired_total >= 1, got $expired"
    fi

    # GR should be complete
    gr_active=$(get_gr_active_count)
    if [ "$gr_active" -eq 0 ]; then
        ok "GR completed after timer expiry"
    else
        fail "Expected GR complete, bgp_gr_active_peers=$gr_active"
    fi
}

# Start rustbgpd inside the container (CMD is sleep infinity)
start_rustbgpd() {
    log "Starting rustbgpd daemon..."
    docker exec -d "$RUSTBGPD" /usr/local/bin/start-rustbgpd.sh
    sleep 3
    if docker exec "$RUSTBGPD" sh -c 'cat /proc/*/comm 2>/dev/null' | grep -q rustbgpd; then
        log "rustbgpd is running"
    else
        echo "ERROR: rustbgpd failed to start" >&2
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "M11 interop test: Graceful Restart (RFC 4724)"
    log "Topology: $TOPO"

    resolve_grpc_addr
    start_rustbgpd

    test_gr_capability_negotiated
    test_peer_restart_preserves_routes
    test_eor_clears_stale
    test_timer_expiry_sweeps_stale

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
