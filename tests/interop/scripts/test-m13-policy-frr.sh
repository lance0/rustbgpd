#\!/usr/bin/env bash
# M13 interop test — Policy Engine
#
# Validates: import/export policy actions end-to-end with FRR.
#   - Import: set_local_pref, set_community_add, AS_PATH regex match, prefix deny
#   - Export: set_med, set_as_path_prepend, prefix deny filter
#
# Topology: FRR-A (AS 65002) → rustbgpd (AS 65001) → FRR-B (AS 65003)
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m13-policy-frr.clab.yml
#   - grpcurl installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m13-policy-frr.sh

set -euo pipefail

TOPO="m13-policy-frr"
RUSTBGPD="clab-${TOPO}-rustbgpd"
FRR_A="clab-${TOPO}-frr-a"
FRR_B="clab-${TOPO}-frr-b"
PROTO="proto/rustbgpd.proto"
GRPC_ADDR=""

pass=0
fail=0

log()  { printf "\033[1;34m[TEST]\033[0m %s\n" "$*"; }
ok()   { pass=$((pass + 1)); printf "\033[1;32m  PASS\033[0m %s\n" "$*"; }
fail() { fail=$((fail + 1)); printf "\033[1;31m  FAIL\033[0m %s\n" "$*"; }

resolve_grpc_addr() {
    local ip
    ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$RUSTBGPD" 2>/dev/null || true)
    if [ -z "$ip" ]; then
        echo "ERROR: cannot resolve management IP for $RUSTBGPD" >&2
        exit 1
    fi
    GRPC_ADDR="${ip}:50051"
    log "gRPC endpoint: $GRPC_ADDR"
}

grpc_list_received() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

grpc_list_received_for_peer() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"neighbor_address\": \"$1\"}" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes 2>/dev/null
}

grpc_list_best() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListBestRoutes 2>/dev/null
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

# Wait for FRR-B to receive routes from rustbgpd
wait_frr_b_routes() {
    local expected=$1
    log "Waiting for FRR-B to receive $expected routes..."
    for i in $(seq 1 20); do
        local count
        count=$(docker exec "$FRR_B" vtysh -c "show bgp ipv4 unicast json" 2>/dev/null \
            | grep -o '"prefix":"[^"]*"' | wc -l || true)
        if [ "$count" -ge "$expected" ]; then
            ok "FRR-B has $count routes (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "FRR-B expected $expected routes, got $(docker exec "$FRR_B" vtysh -c "show bgp ipv4 unicast json" 2>/dev/null | grep -o '"prefix":"[^"]*"' | wc -l || echo 0)"
    return 1
}

# ---------------------------------------------------------------------------
# Test 1: Import policy — AS_PATH regex sets LOCAL_PREF
# ---------------------------------------------------------------------------
test_import_local_pref() {
    log "Test 1: Import policy — AS_PATH regex match sets LOCAL_PREF 200"

    local best
    best=$(grpc_list_best)

    # Routes from AS 65002 should have LOCAL_PREF 200 (via match_as_path "_65002_")
    local lp
    lp=$(echo "$best" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for r in data.get('routes', []):
    if r.get('prefix') == '192.168.1.0':
        print(r.get('localPref', 0))
        break
" 2>/dev/null || echo "")

    if [ "$lp" = "200" ]; then
        ok "192.168.1.0/24 has LOCAL_PREF 200"
    else
        fail "192.168.1.0/24 LOCAL_PREF expected 200, got '$lp'"
        echo "$best" | grep -A10 "192.168.1.0" || true
    fi
}

# ---------------------------------------------------------------------------
# Test 2: Import policy — community added to matching prefix
# ---------------------------------------------------------------------------
test_import_community_add() {
    log "Test 2: Import policy — community 65001:100 added to 10.10.0.0/16"

    local best
    best=$(grpc_list_best)

    # 10.10.0.0/16 matches prefix 10.0.0.0/8 le 16, should get community 65001:100
    # Standard community 65001:100 = (65001 << 16) | 100 = 4259840100
    local comm_value="4259840100"

    if echo "$best" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for r in data.get('routes', []):
    if r.get('prefix') == '10.10.0.0':
        comms = r.get('communities', [])
        if $comm_value in comms:
            sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
        ok "10.10.0.0/16 has community 65001:100"
    else
        fail "10.10.0.0/16 missing community 65001:100"
        echo "$best" | grep -A10 "10.10.0.0" || true
    fi
}

# ---------------------------------------------------------------------------
# Test 3: Export policy — 10.10.0.0/16 denied to FRR-B
# ---------------------------------------------------------------------------
test_export_deny() {
    log "Test 3: Export policy — 10.10.0.0/16 denied to FRR-B"

    local frr_b_routes
    frr_b_routes=$(docker exec "$FRR_B" vtysh -c "show bgp ipv4 unicast json" 2>/dev/null)

    if echo "$frr_b_routes" | grep -q "10.10.0.0"; then
        fail "10.10.0.0/16 should be denied but appeared on FRR-B"
    else
        ok "10.10.0.0/16 correctly denied to FRR-B"
    fi

    # 192.168.1.0 and 192.168.2.0 should be present
    for prefix in "192.168.1.0" "192.168.2.0"; do
        if echo "$frr_b_routes" | grep -q "$prefix"; then
            ok "$prefix/24 present on FRR-B"
        else
            fail "$prefix/24 missing on FRR-B"
        fi
    done
}

# ---------------------------------------------------------------------------
# Test 4: Export policy — MED set to 50 on FRR-B
# ---------------------------------------------------------------------------
test_export_med() {
    log "Test 4: Export policy — MED 50 on routes received by FRR-B"

    local route_json
    route_json=$(docker exec "$FRR_B" vtysh -c "show bgp ipv4 unicast 192.168.1.0/24 json" 2>/dev/null)

    local med
    med=$(echo "$route_json" | grep -o '"metric":[0-9]*' | head -1 | cut -d: -f2 || true)

    if [ "$med" = "50" ]; then
        ok "192.168.1.0/24 MED=50 on FRR-B"
    else
        fail "192.168.1.0/24 MED expected 50, got '$med'"
        echo "$route_json" | head -20 || true
    fi
}

# ---------------------------------------------------------------------------
# Test 5: Export policy — AS_PATH prepended (65001 appears 3 times total)
# ---------------------------------------------------------------------------
test_export_as_path_prepend() {
    log "Test 5: Export policy — AS_PATH prepend (65001 ×2 + natural = 3 occurrences)"

    local route_json
    route_json=$(docker exec "$FRR_B" vtysh -c "show bgp ipv4 unicast 192.168.1.0/24 json" 2>/dev/null)

    # AS_PATH should be: 65001 65001 65001 65002
    # (1 natural eBGP prepend + 2 from policy = 3× 65001, then 65002)
    local as_path
    as_path=$(echo "$route_json" | grep -o '"aspath":"[^"]*"' | head -1 | cut -d'"' -f4 || true)

    local count_65001
    count_65001=$(echo "$as_path" | grep -o "65001" | wc -l || true)

    if [ "$count_65001" -eq 3 ]; then
        ok "AS_PATH has 3× 65001 (1 natural + 2 prepended): $as_path"
    else
        fail "AS_PATH expected 3× 65001, got $count_65001: '$as_path'"
    fi

    if echo "$as_path" | grep -q "65002"; then
        ok "AS_PATH contains origin AS 65002"
    else
        fail "AS_PATH missing origin AS 65002"
    fi
}

# ---------------------------------------------------------------------------
# Test 6: Import LOCAL_PREF applies to all routes from AS 65002
# ---------------------------------------------------------------------------
test_import_local_pref_all_routes() {
    log "Test 6: Import LOCAL_PREF 200 applies to all routes from AS 65002"

    local best
    best=$(grpc_list_best)

    for prefix in "192.168.1.0" "192.168.2.0" "10.10.0.0"; do
        local lp
        lp=$(echo "$best" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for r in data.get('routes', []):
    if r.get('prefix') == '$prefix':
        print(r.get('localPref', 0))
        break
" 2>/dev/null || echo "")

        if [ "$lp" = "200" ]; then
            ok "$prefix has LOCAL_PREF 200"
        else
            fail "$prefix LOCAL_PREF expected 200, got '$lp'"
        fi
    done
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

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "M13 interop test: Policy Engine"
    log "Topology: $TOPO"

    resolve_grpc_addr
    start_rustbgpd

    # Wait for both sessions
    wait_established "10.0.0.1" "$FRR_A" || true
    wait_established "10.0.1.1" "$FRR_B" || true

    # Wait for routes from FRR-A to arrive
    wait_routes 3 || true

    # Wait for FRR-B to receive exported routes (2 of 3 — 10.10.0.0 denied)
    wait_frr_b_routes 2 || true

    test_import_local_pref
    test_import_community_add
    test_import_local_pref_all_routes
    test_export_deny
    test_export_med
    test_export_as_path_prepend

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
