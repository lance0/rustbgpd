#!/usr/bin/env bash
# M24 interop test — BMP collector integration
#
# Validates:
#   1. rustbgpd connects outbound to BMP receiver (TCP 11019)
#   2. Initiation message sent with sys_name
#   3. PeerUp sent when FRR session establishes
#   4. RouteMonitoring sent when FRR sends UPDATEs
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m24-bmp-frr.clab.yml
#   - grpcurl installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m24-bmp-frr.sh

set -euo pipefail

TOPO="m24-bmp-frr"
RUSTBGPD="clab-${TOPO}-rustbgpd"
FRR="clab-${TOPO}-frr"
BMP_RECEIVER="clab-${TOPO}-bmp-receiver"
PROTO="proto/rustbgpd.proto"
GRPC_ADDR=""
BMP_MESSAGES="/tmp/bmp-messages.json"

pass=0
fail=0

log()  { printf "\033[1;34m[TEST]\033[0m %s\n" "$*"; }
ok()   { pass=$((pass + 1)); printf "\033[1;32m  PASS\033[0m %s\n" "$*"; }
fail() { fail=$((fail + 1)); printf "\033[1;31m  FAIL\033[0m %s\n" "$*"; }

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

grpc_health() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.ControlService/GetHealth 2>/dev/null
}

# Patch BMP receiver address into rustbgpd config
patch_bmp_config() {
    local bmp_ip
    bmp_ip=$(resolve_ip "$BMP_RECEIVER")
    if [ -z "$bmp_ip" ]; then
        echo "ERROR: cannot resolve management IP for $BMP_RECEIVER" >&2
        exit 1
    fi
    log "BMP receiver address: ${bmp_ip}:11019"

    docker exec "$RUSTBGPD" sh -c \
        "sed 's/BMP_RECEIVER_ADDR/${bmp_ip}/' /etc/rustbgpd/config.toml > /tmp/config.toml"
}

start_bmp_receiver() {
    log "Starting BMP receiver..."
    docker exec -d "$BMP_RECEIVER" python3 /usr/local/bin/bmp-receiver.py
    sleep 1
    log "BMP receiver started"
}

start_rustbgpd() {
    log "Starting rustbgpd daemon..."
    docker exec -d "$RUSTBGPD" sh -c '/usr/local/bin/rustbgpd /tmp/config.toml'
    sleep 3
    if docker exec "$RUSTBGPD" sh -c 'cat /proc/*/comm 2>/dev/null' | grep -q rustbgpd; then
        log "rustbgpd is running"
    else
        echo "ERROR: rustbgpd failed to start" >&2
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

# Read BMP messages from the receiver's output file
get_bmp_messages() {
    docker exec "$BMP_RECEIVER" cat "$BMP_MESSAGES" 2>/dev/null || echo '{"messages":[]}'
}

has_bmp_type() {
    local type_name=$1
    get_bmp_messages | python3 -c "
import sys, json
data = json.load(sys.stdin)
types = [m['type_name'] for m in data.get('messages', [])]
sys.exit(0 if '$type_name' in types else 1)
" 2>/dev/null
}

count_bmp_type() {
    local type_name=$1
    get_bmp_messages | python3 -c "
import sys, json
data = json.load(sys.stdin)
count = sum(1 for m in data.get('messages', []) if m['type_name'] == '$type_name')
print(count)
" 2>/dev/null || echo 0
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

test_bmp_initiation() {
    log "Test 1: BMP Initiation message received"

    # Wait for BMP Initiation to appear
    for i in $(seq 1 30); do
        if has_bmp_type "Initiation"; then
            ok "BMP Initiation message received (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "No BMP Initiation message within 60s"
    log "DEBUG: BMP messages received:"
    get_bmp_messages
}

test_bmp_peerup() {
    log "Test 2: BMP PeerUp message received (after BGP session establishes)"

    for i in $(seq 1 15); do
        if has_bmp_type "PeerUp"; then
            ok "BMP PeerUp message received (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "No BMP PeerUp message within 30s"
}

test_bmp_route_monitoring() {
    log "Test 3: BMP RouteMonitoring messages received (FRR sends UPDATEs)"

    # FRR advertises 2 prefixes — should generate RouteMonitoring messages
    for i in $(seq 1 15); do
        local count
        count=$(count_bmp_type "RouteMonitoring")
        if [ "$count" -ge 1 ]; then
            ok "BMP RouteMonitoring messages received (count=$count, attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "No BMP RouteMonitoring messages within 30s"
}

test_bmp_message_order() {
    log "Test 4: BMP message ordering (Initiation before PeerUp)"

    local messages
    messages=$(get_bmp_messages)

    local order_ok
    order_ok=$(echo "$messages" | python3 -c "
import sys, json
data = json.load(sys.stdin)
msgs = data.get('messages', [])
types = [m['type_name'] for m in msgs]
if 'Initiation' not in types or 'PeerUp' not in types:
    print('missing')
    sys.exit(0)
init_idx = types.index('Initiation')
peer_idx = types.index('PeerUp')
print('ok' if init_idx < peer_idx else 'wrong_order')
" 2>/dev/null || echo "error")

    if [ "$order_ok" = "ok" ]; then
        ok "Initiation received before PeerUp"
    else
        fail "Message ordering incorrect: $order_ok"
    fi
}

test_bmp_message_summary() {
    log "Test 5: BMP message summary"

    local messages
    messages=$(get_bmp_messages)

    local summary
    summary=$(echo "$messages" | python3 -c "
import sys, json
data = json.load(sys.stdin)
msgs = data.get('messages', [])
from collections import Counter
counts = Counter(m['type_name'] for m in msgs)
total = len(msgs)
parts = [f'{k}={v}' for k, v in sorted(counts.items())]
print(f'{total} total: {', '.join(parts)}')
" 2>/dev/null || echo "error")

    local total
    total=$(echo "$messages" | python3 -c "
import sys, json
print(len(json.load(sys.stdin).get('messages', [])))
" 2>/dev/null || echo 0)

    if [ "$total" -ge 3 ]; then
        ok "BMP summary: $summary"
    else
        fail "Expected at least 3 BMP messages, got: $summary"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "M24 interop test: BMP collector integration"
    log "Topology: $TOPO"

    resolve_grpc_addr
    patch_bmp_config
    start_bmp_receiver
    start_rustbgpd

    wait_established || exit 1

    # Give BMP messages time to flow after session establishment
    sleep 5

    test_bmp_initiation
    test_bmp_peerup
    test_bmp_route_monitoring
    test_bmp_message_order
    test_bmp_message_summary

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
