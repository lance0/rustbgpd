#!/usr/bin/env bash
# M27 interop test — rustbgpd ↔ FRR-A + FRR-B + Python RTR v2 server
#
# Validates:
#   1. RTR v2 negotiation (not falling back to v1)
#   2. ASPA record delivery over RTR v2
#   3. ASPA validation states: valid (single-hop), valid (multi-hop),
#      invalid (non-provider hop), unknown (no ASPA record)
#   4. Best-path ASPA preference (step 0.7): Valid beats Invalid
#   5. Best-path explain shows aspa_preference as decisive reason
#   6. ROA + ASPA coexistence over single RTR v2 session
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m27-aspa-rtr2.clab.yml
#   - grpcurl installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m27-aspa-rtr2.sh

TOPO="m27-aspa-rtr2"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"
FRR_A="clab-${TOPO}-frr-a"
FRR_B="clab-${TOPO}-frr-b"
RTR_SERVER="clab-${TOPO}-rtr-server"

# ---------------------------------------------------------------------------
# Setup helpers
# ---------------------------------------------------------------------------

# Patch the RTR server address into the rustbgpd config before starting.
patch_rpki_config() {
    local rtr_ip
    rtr_ip=$(resolve_ip "$RTR_SERVER")
    if [ -z "$rtr_ip" ]; then
        echo "ERROR: cannot resolve management IP for $RTR_SERVER" >&2
        exit 1
    fi
    log "RTR server address: ${rtr_ip}:3323"

    docker exec "$RUSTBGPD" sh -c \
        "sed 's/STAYRTR_ADDR/${rtr_ip}/' /etc/rustbgpd/config.toml > /tmp/config.toml"
}

# Start the Python RTR v2 server in background.
start_rtr_server() {
    log "Starting RTR v2 server..."
    docker exec -d "$RTR_SERVER" python3 /usr/local/bin/rtr-v2-server.py

    for i in $(seq 1 15); do
        if docker exec "$RTR_SERVER" sh -c 'cat /tmp/rtr-server-status.json 2>/dev/null' \
            | grep -q '"listening": true'; then
            ok "RTR v2 server is listening (attempt $i)"
            return 0
        fi
        sleep 1
    done
    fail "RTR v2 server did not start within 15s"
    return 1
}

# Start rustbgpd with patched RPKI config.
start_rustbgpd() {
    log "Starting rustbgpd daemon..."
    docker exec -d "$RUSTBGPD" sh -c '/usr/local/bin/rustbgpd /tmp/config.toml > /tmp/rustbgpd.log 2>&1'
    sleep 3
    if docker exec "$RUSTBGPD" sh -c 'cat /proc/*/comm 2>/dev/null' | grep -q rustbgpd; then
        log "rustbgpd is running"
    else
        echo "ERROR: rustbgpd failed to start" >&2
        docker exec "$RUSTBGPD" cat /tmp/config.toml >&2 || true
        exit 1
    fi

    log "Waiting for gRPC to become available..."
    for i in $(seq 1 15); do
        if grpc_health >/dev/null 2>&1; then
            ok "gRPC endpoint ready (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "gRPC endpoint not reachable within 30s"
    return 1
}

# ---------------------------------------------------------------------------
# gRPC query helpers
# ---------------------------------------------------------------------------

grpc_list_received_peer() {
    local peer=$1
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"neighbor_address\": \"$peer\"}" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

grpc_list_received_all() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

grpc_list_best() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListBestRoutes 2>/dev/null
}

grpc_explain() {
    local prefix=$1
    local prefix_len=$2
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"prefix\": \"$prefix\", \"prefix_length\": $prefix_len}" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ExplainBestPath 2>/dev/null
}

# ---------------------------------------------------------------------------
# Wait helpers
# ---------------------------------------------------------------------------

wait_established() {
    local container=$1
    local peer_addr=$2
    local label=$3
    log "Waiting for $label BGP session to reach Established..."
    for i in $(seq 1 45); do
        local state
        state=$(docker exec "$container" vtysh -c "show bgp neighbors $peer_addr json" 2>/dev/null \
            | grep -o '"bgpState":"[^"]*"' | head -1 | cut -d'"' -f4 || true)
        if [ "$state" = "Established" ]; then
            ok "$label BGP session established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$label BGP session did not reach Established within 90s"
    return 1
}

wait_routes() {
    local expected=$1
    log "Waiting for $expected routes in RIB..."
    for i in $(seq 1 20); do
        local count
        count=$(grpc_list_received_all | grep -c '"prefix"' || true)
        if [ "$count" -ge "$expected" ]; then
            ok "Got $count routes in RIB (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "Expected $expected routes, got $(grpc_list_received_all | grep -c '"prefix"' || echo 0)"
    return 1
}

# Wait for ASPA validation states to populate (not all "unknown")
wait_aspa_validation() {
    log "Waiting for ASPA validation states to populate..."
    for i in $(seq 1 30); do
        local routes
        routes=$(grpc_list_received_all)
        if echo "$routes" | grep -q '"aspaState": "valid"'; then
            ok "ASPA validation states populated (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "ASPA validation states not populated within 60s"
    return 1
}

# ---------------------------------------------------------------------------
# Helper: extract field from route by prefix
# ---------------------------------------------------------------------------
extract_route_field() {
    local routes=$1
    local prefix=$2
    local prefix_len=$3
    local field=$4
    echo "$routes" | python3 -c "
import sys, json
resp = json.load(sys.stdin)
for r in resp.get('routes', []):
    if r['prefix'] == '$prefix' and r['prefixLength'] == $prefix_len:
        print(r.get('$field', 'missing'))
        break
else:
    print('missing')
" 2>/dev/null || echo "missing"
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

test_rtr_v2_session() {
    log "Test 1: RTR v2 session negotiation"

    # Check rustbgpd logs for v2 connection
    local logs
    logs=$(docker exec "$RUSTBGPD" cat /tmp/rustbgpd.log 2>/dev/null || true)

    if echo "$logs" | grep -q '"rtr_version":2'; then
        ok "RTR v2 connection established (rtr_version=2 in logs)"
    elif echo "$logs" | grep -q 'rtr_version=2'; then
        ok "RTR v2 connection established (rtr_version=2 in logs)"
    else
        fail "RTR v2 connection not found in logs"
        log "Log snippet: $(echo "$logs" | grep -i 'rtr\|RTR\|rpki\|RPKI\|connect' | head -5)"
    fi

    # Ensure no fallback to v1
    if echo "$logs" | grep -q "falling back to v1"; then
        fail "RTR fell back to v1 (unexpected)"
    else
        ok "No RTR v1 fallback detected"
    fi
}

test_aspa_valid_single_hop() {
    log "Test 2: 192.168.1.0/24 — single-hop, ASPA valid"

    local routes
    routes=$(grpc_list_received_peer "10.0.0.2")

    local state
    state=$(extract_route_field "$routes" "192.168.1.0" 24 "aspaState")

    if [ "$state" = "valid" ]; then
        ok "192.168.1.0/24 aspa_state = valid (single-hop)"
    else
        fail "192.168.1.0/24 aspa_state = '$state' (expected 'valid')"
    fi
}

test_aspa_valid_multi_hop() {
    log "Test 3: 192.168.2.0/24 — AS_PATH [65002, 65003], ASPA valid"

    local routes
    routes=$(grpc_list_received_peer "10.0.0.2")

    local state
    state=$(extract_route_field "$routes" "192.168.2.0" 24 "aspaState")

    if [ "$state" = "valid" ]; then
        ok "192.168.2.0/24 aspa_state = valid (65003 authorizes 65002)"
    else
        fail "192.168.2.0/24 aspa_state = '$state' (expected 'valid')"
    fi
}

test_aspa_invalid() {
    log "Test 4: 192.168.3.0/24 — AS_PATH [65002, 65004], ASPA invalid"

    local routes
    routes=$(grpc_list_received_peer "10.0.0.2")

    local state
    state=$(extract_route_field "$routes" "192.168.3.0" 24 "aspaState")

    if [ "$state" = "invalid" ]; then
        ok "192.168.3.0/24 aspa_state = invalid (65004 does not authorize 65002)"
    else
        fail "192.168.3.0/24 aspa_state = '$state' (expected 'invalid')"
    fi
}

test_aspa_unknown() {
    log "Test 5: 192.168.4.0/24 — AS_PATH [65002, 65005], ASPA unknown"

    local routes
    routes=$(grpc_list_received_peer "10.0.0.2")

    local state
    state=$(extract_route_field "$routes" "192.168.4.0" 24 "aspaState")

    if [ "$state" = "unknown" ]; then
        ok "192.168.4.0/24 aspa_state = unknown (no ASPA record for 65005)"
    else
        fail "192.168.4.0/24 aspa_state = '$state' (expected 'unknown')"
    fi
}

test_aspa_best_path_preference() {
    log "Test 6: 172.16.0.0/24 — best-path prefers ASPA Valid (FRR-B) over Invalid (FRR-A)"

    local best
    best=$(grpc_list_best)

    # Check that the best route for 172.16.0.0/24 is ASPA valid
    local state
    state=$(extract_route_field "$best" "172.16.0.0" 24 "aspaState")

    if [ "$state" = "valid" ]; then
        ok "172.16.0.0/24 best route has aspa_state = valid"
    else
        fail "172.16.0.0/24 best route has aspa_state = '$state' (expected 'valid')"
    fi

    # Check that it came from FRR-B (10.0.1.2), not FRR-A
    local peer
    peer=$(extract_route_field "$best" "172.16.0.0" 24 "peerAddress")

    if [ "$peer" = "10.0.1.2" ]; then
        ok "172.16.0.0/24 best route from FRR-B (10.0.1.2) — ASPA step 0.7 was decisive"
    else
        fail "172.16.0.0/24 best route from '$peer' (expected '10.0.1.2' / FRR-B)"
    fi
}

test_aspa_best_path_explain() {
    log "Test 7: ExplainBestPath for 172.16.0.0/24 shows aspa_preference reason"

    local explain
    explain=$(grpc_explain "172.16.0.0" 24)

    if echo "$explain" | grep -qi "aspa_preference"; then
        ok "ExplainBestPath shows aspa_preference as decisive reason"
    else
        fail "ExplainBestPath does not mention aspa_preference"
        log "Explain output: $(echo "$explain" | head -20)"
    fi
}

test_rpki_aspa_coexistence() {
    log "Test 8: ROA + ASPA coexistence over single RTR v2 session"

    local routes
    routes=$(grpc_list_received_peer "10.0.0.2")

    # Check 192.168.1.0/24 has both RPKI valid AND ASPA valid
    local rpki_state
    rpki_state=$(extract_route_field "$routes" "192.168.1.0" 24 "validationState")

    local aspa_state
    aspa_state=$(extract_route_field "$routes" "192.168.1.0" 24 "aspaState")

    if [ "$rpki_state" = "valid" ] && [ "$aspa_state" = "valid" ]; then
        ok "192.168.1.0/24: validationState=valid AND aspaState=valid (coexistence)"
    else
        fail "192.168.1.0/24: validationState='$rpki_state', aspaState='$aspa_state' (expected both 'valid')"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "M27 interop test: rustbgpd ↔ FRR-A + FRR-B + RTR v2 (ASPA)"
    log "Topology: $TOPO"

    resolve_grpc_addr
    start_rtr_server || exit 1
    patch_rpki_config
    start_rustbgpd || exit 1

    wait_established "$FRR_A" "10.0.0.1" "FRR-A" || exit 1
    wait_established "$FRR_B" "10.0.1.1" "FRR-B" || exit 1
    wait_routes 6 || exit 1
    wait_aspa_validation || exit 1

    test_rtr_v2_session
    test_aspa_valid_single_hop
    test_aspa_valid_multi_hop
    test_aspa_invalid
    test_aspa_unknown
    test_aspa_best_path_preference
    test_aspa_best_path_explain
    test_rpki_aspa_coexistence

    echo ""
    print_summary
}

main "$@"
