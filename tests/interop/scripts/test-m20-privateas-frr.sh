#!/usr/bin/env bash
# M20 interop test — Private AS Removal
#
# Validates: remove_private_as modes (remove, all, replace) applied to
# outbound eBGP advertisements.
#
# Topology:
#   FRR-Source (AS 64512) → rustbgpd (AS 65001) → FRR-Remove (AS 65002)
#                                               → FRR-All     (AS 65003)
#                                               → FRR-Replace (AS 65004)
#
# FRR-Source advertises:
#   - 192.168.1.0/24: AS_PATH = [64512] (all-private)
#   - 192.168.2.0/24: AS_PATH = [64512, 64000] (mixed, via route-map prepend)
#
# Expected results (after rustbgpd prepends its own AS 65001):
#
# | Prefix           | Loc-RIB AS_PATH  | remove outbound    | all outbound      | replace outbound      |
# |------------------|------------------|--------------------|-------------------|-----------------------|
# | 192.168.1.0/24   | [64512]          | [65001]            | [65001]           | [65001, 65001]        |
# | 192.168.2.0/24   | [64512, 64000]   | [65001, 64512, 64000] | [65001, 64000] | [65001, 65001, 64000] |
#
# "remove" only strips when the ENTIRE original AS_PATH is private.
# "all" strips all private ASNs unconditionally.
# "replace" replaces each private ASN with the local ASN (65001).
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m20-privateas-frr.clab.yml
#   - grpcurl installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m20-privateas-frr.sh

set -euo pipefail

TOPO="m20-privateas-frr"
RUSTBGPD="clab-${TOPO}-rustbgpd"
FRR_SOURCE="clab-${TOPO}-frr-source"
FRR_REMOVE="clab-${TOPO}-frr-remove"
FRR_ALL="clab-${TOPO}-frr-all"
FRR_REPLACE="clab-${TOPO}-frr-replace"
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

# Helper: extract AS_PATH string from FRR for a prefix
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

# ---------------------------------------------------------------------------
# Test 1: Source routes arrive with private AS in path
# ---------------------------------------------------------------------------
test_source_routes_received() {
    log "Test 1: Routes from FRR-Source (AS 64512) received"

    local routes
    routes=$(grpc_list_received)

    for prefix in "192.168.1.0" "192.168.2.0"; do
        if echo "$routes" | grep -q "\"prefix\": \"$prefix\""; then
            ok "Prefix $prefix received from source"
        else
            fail "Prefix $prefix missing from source"
        fi
    done
}

# ---------------------------------------------------------------------------
# Test 2: "remove" mode — all-private path stripped, mixed path unchanged
# ---------------------------------------------------------------------------
test_remove_mode() {
    log "Test 2: remove mode — all-private stripped, mixed unchanged"

    # 192.168.1.0/24: original [64512] → all_private=true → removed → prepend → [65001]
    local aspath_1
    aspath_1=$(frr_aspath "$FRR_REMOVE" "192.168.1.0/24")
    log "  remove: 192.168.1.0/24 AS_PATH = '$aspath_1'"

    if [ "$aspath_1" = "65001" ]; then
        ok "192.168.1.0/24: AS_PATH=[65001] (private ASN removed)"
    else
        fail "192.168.1.0/24: expected AS_PATH='65001', got '$aspath_1'"
    fi

    # 192.168.2.0/24: original [64512, 64000] → has public → unchanged → prepend → [65001, 64512, 64000]
    local aspath_2
    aspath_2=$(frr_aspath "$FRR_REMOVE" "192.168.2.0/24")
    log "  remove: 192.168.2.0/24 AS_PATH = '$aspath_2'"

    if echo "$aspath_2" | grep -q "64512"; then
        ok "192.168.2.0/24: private ASN 64512 preserved (mixed path, not all-private)"
    else
        fail "192.168.2.0/24: expected 64512 preserved in mixed path, got '$aspath_2'"
    fi

    if echo "$aspath_2" | grep -q "64000"; then
        ok "192.168.2.0/24: public ASN 64000 present"
    else
        fail "192.168.2.0/24: public ASN 64000 missing"
    fi
}

# ---------------------------------------------------------------------------
# Test 3: "all" mode — all private ASNs stripped unconditionally
# ---------------------------------------------------------------------------
test_all_mode() {
    log "Test 3: all mode — all private ASNs stripped"

    # 192.168.1.0/24: [64512] → strip 64512 → [] → prepend → [65001]
    local aspath_1
    aspath_1=$(frr_aspath "$FRR_ALL" "192.168.1.0/24")
    log "  all: 192.168.1.0/24 AS_PATH = '$aspath_1'"

    if [ "$aspath_1" = "65001" ]; then
        ok "192.168.1.0/24: AS_PATH=[65001] (private stripped)"
    else
        fail "192.168.1.0/24: expected AS_PATH='65001', got '$aspath_1'"
    fi

    # 192.168.2.0/24: [64512, 64000] → strip 64512 → [64000] → prepend → [65001, 64000]
    local aspath_2
    aspath_2=$(frr_aspath "$FRR_ALL" "192.168.2.0/24")
    log "  all: 192.168.2.0/24 AS_PATH = '$aspath_2'"

    if echo "$aspath_2" | grep -q "64512"; then
        fail "192.168.2.0/24: private ASN 64512 should be removed in 'all' mode"
    else
        ok "192.168.2.0/24: private ASN 64512 removed"
    fi

    if echo "$aspath_2" | grep -q "64000"; then
        ok "192.168.2.0/24: public ASN 64000 preserved"
    else
        fail "192.168.2.0/24: public ASN 64000 missing"
    fi

    if echo "$aspath_2" | grep -q "65001"; then
        ok "192.168.2.0/24: local ASN 65001 prepended"
    else
        fail "192.168.2.0/24: local ASN 65001 missing"
    fi
}

# ---------------------------------------------------------------------------
# Test 4: "replace" mode — private ASNs replaced with local ASN
# ---------------------------------------------------------------------------
test_replace_mode() {
    log "Test 4: replace mode — private ASNs replaced with local ASN"

    # 192.168.1.0/24: [64512] → replace 64512→65001 → [65001] → prepend → [65001, 65001]
    local aspath_1
    aspath_1=$(frr_aspath "$FRR_REPLACE" "192.168.1.0/24")
    log "  replace: 192.168.1.0/24 AS_PATH = '$aspath_1'"

    local count_65001
    count_65001=$(echo "$aspath_1" | grep -o "65001" | wc -l || true)

    if [ "$count_65001" -eq 2 ]; then
        ok "192.168.1.0/24: AS_PATH has 2× 65001 (1 replaced + 1 prepended)"
    else
        fail "192.168.1.0/24: expected 2× 65001, got $count_65001 in '$aspath_1'"
    fi

    if echo "$aspath_1" | grep -q "64512"; then
        fail "192.168.1.0/24: private ASN 64512 should be replaced"
    else
        ok "192.168.1.0/24: private ASN 64512 replaced"
    fi

    # 192.168.2.0/24: [64512, 64000] → replace 64512→65001 → [65001, 64000] → prepend → [65001, 65001, 64000]
    local aspath_2
    aspath_2=$(frr_aspath "$FRR_REPLACE" "192.168.2.0/24")
    log "  replace: 192.168.2.0/24 AS_PATH = '$aspath_2'"

    count_65001=$(echo "$aspath_2" | grep -o "65001" | wc -l || true)

    if [ "$count_65001" -eq 2 ]; then
        ok "192.168.2.0/24: AS_PATH has 2× 65001 (1 replaced + 1 prepended)"
    else
        fail "192.168.2.0/24: expected 2× 65001, got $count_65001 in '$aspath_2'"
    fi

    if echo "$aspath_2" | grep -q "64000"; then
        ok "192.168.2.0/24: public ASN 64000 preserved"
    else
        fail "192.168.2.0/24: public ASN 64000 missing"
    fi

    if echo "$aspath_2" | grep -q "64512"; then
        fail "192.168.2.0/24: private ASN 64512 should be replaced"
    else
        ok "192.168.2.0/24: private ASN 64512 replaced"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "M20 interop test: Private AS Removal"
    log "Topology: $TOPO"

    resolve_grpc_addr
    start_rustbgpd

    wait_established "10.0.0.1" "$FRR_SOURCE" || true
    wait_established "10.0.1.1" "$FRR_REMOVE" || true
    wait_established "10.0.2.1" "$FRR_ALL" || true
    wait_established "10.0.3.1" "$FRR_REPLACE" || true

    # Wait for routes from source
    wait_routes 2 || true

    # Wait for all observers to receive routes
    wait_frr_routes "$FRR_REMOVE" 2 || true
    wait_frr_routes "$FRR_ALL" 2 || true
    wait_frr_routes "$FRR_REPLACE" 2 || true

    test_source_routes_received
    test_remove_mode
    test_all_mode
    test_replace_mode

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
