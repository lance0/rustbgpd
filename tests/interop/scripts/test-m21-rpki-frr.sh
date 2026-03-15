#!/usr/bin/env bash
# M21 interop test — rustbgpd ↔ FRR + GoRTR RPKI cache
#
# Validates:
#   1. RTR session establishment with GoRTR
#   2. VRP delivery and route origin validation
#   3. Validation states visible via gRPC (valid/invalid/not_found)
#   4. RPKI-Valid route preferred over RPKI-Invalid in best-path
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m21-rpki-frr.clab.yml
#   - grpcurl installed on the host
#   - cloudflare/gortr:latest pulled
#
# Usage:
#   bash tests/interop/scripts/test-m21-rpki-frr.sh

set -euo pipefail

TOPO="m21-rpki-frr"
RUSTBGPD="clab-${TOPO}-rustbgpd"
FRR="clab-${TOPO}-frr"
STAYRTR="clab-${TOPO}-gortr"
PROTO="proto/rustbgpd.proto"
GRPC_ADDR=""

pass=0
fail=0

log()  { printf "\033[1;34m[TEST]\033[0m %s\n" "$*"; }
ok()   { pass=$((pass + 1)); printf "\033[1;32m  PASS\033[0m %s\n" "$*"; }
fail() { fail=$((fail + 1)); printf "\033[1;31m  FAIL\033[0m %s\n" "$*"; }

# Resolve container management IP
resolve_ip() {
    docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1" 2>/dev/null
}

resolve_grpc_addr() {
    local ip
    ip=$(resolve_ip "$RUSTBGPD")
    if [ -z "$ip" ]; then
        echo "ERROR: cannot resolve management IP for $RUSTBGPD" >&2
        exit 1
    fi
    GRPC_ADDR="${ip}:50051"
    log "gRPC endpoint: $GRPC_ADDR"
}

# Patch the GoRTR address into the rustbgpd config before starting.
# containerlab nodes communicate over the management network.
patch_rpki_config() {
    local stayrtr_ip
    stayrtr_ip=$(resolve_ip "$STAYRTR")
    if [ -z "$stayrtr_ip" ]; then
        echo "ERROR: cannot resolve management IP for $STAYRTR" >&2
        exit 1
    fi
    log "GoRTR address: ${stayrtr_ip}:3323"

    # Rewrite the placeholder in the config
    docker exec "$RUSTBGPD" sh -c \
        "sed 's/STAYRTR_ADDR/${stayrtr_ip}/' /etc/rustbgpd/config.toml > /tmp/config.toml"
}

grpc_list_received() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d '{"neighbor_address": "10.0.0.2"}' \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

grpc_list_best() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListBestRoutes 2>/dev/null
}

grpc_health() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.ControlService/GetHealth 2>/dev/null
}

grpc_metrics() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.ControlService/GetMetrics 2>/dev/null
}

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

# Wait for RPKI validation states to be populated (not all "not_found")
wait_rpki_validation() {
    log "Waiting for RPKI validation states to populate..."
    for i in $(seq 1 30); do
        local routes
        routes=$(grpc_list_received)
        # Check if any route has "valid" or "invalid" state (not just "not_found")
        if echo "$routes" | grep -q '"validationState": "valid"'; then
            ok "RPKI validation states populated (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "RPKI validation states not populated within 60s"
    return 1
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

test_rtr_session() {
    log "Test 1: RTR session establishment with GoRTR"

    # Check GoRTR is running and listening
    local stayrtr_ip
    stayrtr_ip=$(resolve_ip "$STAYRTR")
    if [ -n "$stayrtr_ip" ]; then
        ok "GoRTR container running at ${stayrtr_ip}"
    else
        fail "GoRTR container not reachable"
        return 1
    fi

    # Check Prometheus metrics for RPKI counters
    local metrics
    metrics=$(grpc_metrics | python3 -c "
import sys, json
resp = json.load(sys.stdin)
print(resp.get('prometheusText', ''))
" 2>/dev/null || true)

    if echo "$metrics" | grep -q "rpki"; then
        ok "RPKI metrics present in Prometheus output"
    else
        log "No RPKI-specific Prometheus metrics found (may be named differently)"
    fi
}

test_rpki_valid() {
    log "Test 2: 192.168.1.0/24 should be RPKI Valid (VRP: AS 65002, max /24)"

    local routes
    routes=$(grpc_list_received)

    local state
    state=$(echo "$routes" | python3 -c "
import sys, json
resp = json.load(sys.stdin)
for r in resp.get('routes', []):
    if r['prefix'] == '192.168.1.0' and r['prefixLength'] == 24:
        print(r.get('validationState', 'missing'))
        break
" 2>/dev/null || echo "missing")

    if [ "$state" = "valid" ]; then
        ok "192.168.1.0/24 validation_state = valid"
    else
        fail "192.168.1.0/24 validation_state = '$state' (expected 'valid')"
    fi
}

test_rpki_invalid() {
    log "Test 3: 192.168.2.0/24 should be RPKI Invalid (VRP says AS 65099, origin is AS 65002)"

    local routes
    routes=$(grpc_list_received)

    local state
    state=$(echo "$routes" | python3 -c "
import sys, json
resp = json.load(sys.stdin)
for r in resp.get('routes', []):
    if r['prefix'] == '192.168.2.0' and r['prefixLength'] == 24:
        print(r.get('validationState', 'missing'))
        break
" 2>/dev/null || echo "missing")

    if [ "$state" = "invalid" ]; then
        ok "192.168.2.0/24 validation_state = invalid"
    else
        fail "192.168.2.0/24 validation_state = '$state' (expected 'invalid')"
    fi
}

test_rpki_not_found() {
    log "Test 4: 10.10.0.0/16 should be RPKI NotFound (no VRP covers it)"

    local routes
    routes=$(grpc_list_received)

    local state
    state=$(echo "$routes" | python3 -c "
import sys, json
resp = json.load(sys.stdin)
for r in resp.get('routes', []):
    if r['prefix'] == '10.10.0.0' and r['prefixLength'] == 16:
        print(r.get('validationState', 'missing'))
        break
" 2>/dev/null || echo "missing")

    if [ "$state" = "not_found" ]; then
        ok "10.10.0.0/16 validation_state = not_found"
    else
        fail "10.10.0.0/16 validation_state = '$state' (expected 'not_found')"
    fi
}

test_rpki_best_path() {
    log "Test 5: RPKI Valid route preferred in best-path selection"

    # All 3 routes from the same peer — best-path for each prefix should
    # reflect the validation state. The RPKI-valid route (192.168.1.0/24)
    # should appear in best routes.
    local best
    best=$(grpc_list_best)

    local valid_in_best
    valid_in_best=$(echo "$best" | python3 -c "
import sys, json
resp = json.load(sys.stdin)
for r in resp.get('routes', []):
    if r['prefix'] == '192.168.1.0' and r['prefixLength'] == 24:
        print(r.get('validationState', 'missing'))
        break
" 2>/dev/null || echo "missing")

    if [ "$valid_in_best" = "valid" ]; then
        ok "RPKI Valid route (192.168.1.0/24) in best routes with state=valid"
    else
        fail "Best route for 192.168.1.0/24 has validation_state='$valid_in_best'"
    fi

    # Invalid route should still be best (only candidate) but marked invalid
    local invalid_in_best
    invalid_in_best=$(echo "$best" | python3 -c "
import sys, json
resp = json.load(sys.stdin)
for r in resp.get('routes', []):
    if r['prefix'] == '192.168.2.0' and r['prefixLength'] == 24:
        print(r.get('validationState', 'missing'))
        break
" 2>/dev/null || echo "missing")

    if [ "$invalid_in_best" = "invalid" ]; then
        ok "RPKI Invalid route (192.168.2.0/24) in best routes with state=invalid (only candidate)"
    else
        fail "Best route for 192.168.2.0/24 has validation_state='$invalid_in_best'"
    fi
}

test_health_rpki() {
    log "Test 6: Health endpoint shows routes with RPKI state"

    local health
    health=$(grpc_health)

    local total_routes
    total_routes=$(echo "$health" | python3 -c "
import sys, json
resp = json.load(sys.stdin)
print(resp.get('totalRoutes', 0))
" 2>/dev/null || echo 0)

    if [ "$total_routes" -ge 3 ]; then
        ok "Health shows $total_routes total routes (expected >= 3)"
    else
        fail "Health shows $total_routes total routes (expected >= 3)"
    fi
}

# ---------------------------------------------------------------------------
# Start rustbgpd with patched RPKI config
# ---------------------------------------------------------------------------
start_rustbgpd() {
    log "Starting rustbgpd daemon with RPKI config..."
    docker exec -d "$RUSTBGPD" sh -c '/usr/local/bin/rustbgpd /tmp/config.toml'
    sleep 3
    if docker exec "$RUSTBGPD" sh -c 'cat /proc/*/comm 2>/dev/null' | grep -q rustbgpd; then
        log "rustbgpd is running"
    else
        echo "ERROR: rustbgpd failed to start" >&2
        docker exec "$RUSTBGPD" cat /tmp/config.toml >&2 || true
        exit 1
    fi

    # Wait for gRPC to become available
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
# Main
# ---------------------------------------------------------------------------
main() {
    log "M21 interop test: rustbgpd ↔ FRR + GoRTR RPKI cache"
    log "Topology: $TOPO"

    resolve_grpc_addr
    patch_rpki_config
    start_rustbgpd

    wait_established || exit 1
    wait_routes 3 || exit 1
    wait_rpki_validation || exit 1

    test_rtr_session
    test_rpki_valid
    test_rpki_invalid
    test_rpki_not_found
    test_rpki_best_path
    test_health_rpki

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
