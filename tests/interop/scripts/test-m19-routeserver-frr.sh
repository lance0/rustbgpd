#!/usr/bin/env bash
# M19 interop test — Transparent Route Server
#
# Validates: route_server_client = true skips local ASN prepend and preserves
# original NEXT_HOP on eBGP re-advertisement.
#
# Topology: FRR-A (AS 65002) → rustbgpd (AS 65001, RS) → FRR-B (AS 65003)
#
# FRR-A advertises: 192.168.1.0/24, 192.168.2.0/24
# FRR-B advertises: 192.168.3.0/24
#
# Expected on FRR-B for routes from FRR-A:
#   - AS_PATH = [65002] (no 65001 prepend)
#   - NEXT_HOP = 10.0.0.2 (FRR-A's original, not rustbgpd's)
#
# Expected on FRR-A for routes from FRR-B:
#   - AS_PATH = [65003] (no 65001 prepend)
#   - NEXT_HOP = 10.0.1.2 (FRR-B's original)
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m19-routeserver-frr.clab.yml
#   - grpcurl installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m19-routeserver-frr.sh


TOPO="m19-routeserver-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"
FRR_A="clab-${TOPO}-frr-a"
FRR_B="clab-${TOPO}-frr-b"


grpc_list_received() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

wait_established() {
    local peer_addr=$1
    local frr_container=$2
    log "Waiting for BGP session to $peer_addr (on $frr_container) to reach Established..."
    for i in $(seq 1 45); do
        local state
        state=$(docker exec "$frr_container" vtysh -c "show bgp neighbors ${peer_addr} json" 2>/dev/null \
            | grep -o '"bgpState":"[^"]*"' | head -1 | cut -d'"' -f4 || true)
        if [ "$state" = "Established" ]; then
            ok "Session to $peer_addr established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "Session to $peer_addr did not reach Established within 90s"
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

wait_frr_routes() {
    local frr_container=$1
    local expected=$2
    log "Waiting for $frr_container to receive $expected routes..."
    for i in $(seq 1 20); do
        local count
        count=$(docker exec "$frr_container" vtysh -c "show bgp ipv4 unicast json" 2>/dev/null \
            | grep -o '"prefix":"[^"]*"' | wc -l || true)
        if [ "$count" -ge "$expected" ]; then
            ok "$frr_container has $count routes (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$frr_container expected $expected routes, got $count"
    return 1
}

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

# Helper: extract AS_PATH string from FRR JSON for a prefix
frr_aspath() {
    local container=$1
    local prefix=$2
    docker exec "$container" vtysh -c "show bgp ipv4 unicast $prefix json" 2>/dev/null \
        | python3 -c "
import json, sys
data = json.load(sys.stdin)
for path in data.get('paths', []):
    asp = path.get('aspath', {})
    if isinstance(asp, dict):
        print(asp.get('string', ''))
    elif isinstance(asp, str):
        print(asp)
    break
" 2>/dev/null || echo ""
}

# Helper: extract next-hop from FRR JSON for a prefix
frr_nexthop() {
    local container=$1
    local prefix=$2
    docker exec "$container" vtysh -c "show bgp ipv4 unicast $prefix json" 2>/dev/null \
        | python3 -c "
import json, sys
data = json.load(sys.stdin)
for path in data.get('paths', []):
    for nh in path.get('nexthops', []):
        print(nh.get('ip', ''))
        break
    break
" 2>/dev/null || echo ""
}

# ---------------------------------------------------------------------------
# Test 1: FRR-B receives routes from FRR-A without AS 65001 in path
# ---------------------------------------------------------------------------
test_no_asn_prepend_on_b() {
    log "Test 1: FRR-B receives FRR-A's routes without AS 65001 prepend"

    local aspath
    aspath=$(frr_aspath "$FRR_B" "192.168.1.0/24")

    if echo "$aspath" | grep -q "65002"; then
        ok "AS_PATH contains origin AS 65002: $aspath"
    else
        fail "AS_PATH missing origin AS 65002: '$aspath'"
    fi

    if echo "$aspath" | grep -q "65001"; then
        fail "AS_PATH contains route server AS 65001 (should be transparent): $aspath"
    else
        ok "AS_PATH does not contain route server AS 65001"
    fi
}

# ---------------------------------------------------------------------------
# Test 2: FRR-B sees original NEXT_HOP from FRR-A
# ---------------------------------------------------------------------------
test_nexthop_preserved_on_b() {
    log "Test 2: FRR-B sees original NEXT_HOP from FRR-A (10.0.0.2)"

    local nh
    nh=$(frr_nexthop "$FRR_B" "192.168.1.0/24")

    if [ "$nh" = "10.0.0.2" ]; then
        ok "NEXT_HOP preserved: 10.0.0.2 (FRR-A's address)"
    else
        fail "NEXT_HOP expected 10.0.0.2, got '$nh'"
    fi
}

# ---------------------------------------------------------------------------
# Test 3: FRR-A receives routes from FRR-B without AS 65001
# ---------------------------------------------------------------------------
test_no_asn_prepend_on_a() {
    log "Test 3: FRR-A receives FRR-B's routes without AS 65001 prepend"

    local aspath
    aspath=$(frr_aspath "$FRR_A" "192.168.3.0/24")

    if echo "$aspath" | grep -q "65003"; then
        ok "AS_PATH contains origin AS 65003: $aspath"
    else
        fail "AS_PATH missing origin AS 65003: '$aspath'"
    fi

    if echo "$aspath" | grep -q "65001"; then
        fail "AS_PATH contains route server AS 65001: $aspath"
    else
        ok "AS_PATH does not contain route server AS 65001"
    fi
}

# ---------------------------------------------------------------------------
# Test 4: FRR-A sees original NEXT_HOP from FRR-B
# ---------------------------------------------------------------------------
test_nexthop_preserved_on_a() {
    log "Test 4: FRR-A sees original NEXT_HOP from FRR-B (10.0.1.2)"

    local nh
    nh=$(frr_nexthop "$FRR_A" "192.168.3.0/24")

    if [ "$nh" = "10.0.1.2" ]; then
        ok "NEXT_HOP preserved: 10.0.1.2 (FRR-B's address)"
    else
        fail "NEXT_HOP expected 10.0.1.2, got '$nh'"
    fi
}

# ---------------------------------------------------------------------------
# Test 5: Both prefixes from FRR-A arrive at FRR-B
# ---------------------------------------------------------------------------
test_all_prefixes_forwarded() {
    log "Test 5: Both FRR-A prefixes forwarded to FRR-B"

    for prefix in "192.168.1.0" "192.168.2.0"; do
        local frr_b_routes
        frr_b_routes=$(docker exec "$FRR_B" vtysh -c "show bgp ipv4 unicast json" 2>/dev/null)
        if echo "$frr_b_routes" | grep -q "$prefix"; then
            ok "$prefix/24 present on FRR-B"
        else
            fail "$prefix/24 missing on FRR-B"
        fi
    done
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "M19 interop test: Transparent Route Server"
    log "Topology: $TOPO"

    resolve_grpc_addr
    start_rustbgpd

    wait_established "10.0.0.1" "$FRR_A" || true
    wait_established "10.0.1.1" "$FRR_B" || true

    # Wait for routes from both peers
    wait_routes 3 || true

    # Wait for FRR-B to receive forwarded routes (1 local + 2 from FRR-A = 3)
    wait_frr_routes "$FRR_B" 3 || true
    # Wait for FRR-A to receive forwarded routes (2 local + 1 from FRR-B = 3)
    wait_frr_routes "$FRR_A" 3 || true

    test_no_asn_prepend_on_b
    test_nexthop_preserved_on_b
    test_no_asn_prepend_on_a
    test_nexthop_preserved_on_a
    test_all_prefixes_forwarded

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
