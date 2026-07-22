#!/usr/bin/env bash
# M91 interop test — RFC 7606 revised error handling, malformed-attribute
# injection: one raw UPDATE per disposition class, asserting session
# survival, RIB contents, bgp_update_malformed_total, and the §6 DEBUG
# capture between phases.

set -euo pipefail

TOPO="m91-rfc7606-malformed"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
source "$SCRIPT_DIR/test-lib.sh"

RAW_PEER="clab-${TOPO}-raw-peer"
PEER_ADDR="10.91.1.2"
RUST_LOG_FILE="/var/log/rustbgpd.log"

BASELINE_PREFIX="198.51.100.91/32"
TAW_PREFIX="198.51.100.92/32"
DISCARD_PREFIX="198.51.100.93/32"

resolve_grpc_addr
RUST_IP=$(resolve_ip "$RUSTBGPD")
# DEBUG on the transport crate so the RFC 7606 §6 full-message capture is
# emitted; capture the daemon output for the log assertion.
start_rustbgpd "RUST_LOG=info,rustbgpd_transport=debug /usr/local/bin/start-rustbgpd.sh >${RUST_LOG_FILE} 2>&1"

grpc_list_neighbors() {
    grpcurl_call \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/ListNeighbors
}

grpc_list_received() {
    grpcurl_call \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes
}

dump_state_on_failure() {
    echo "===== rustbgpd NeighborService/ListNeighbors =====" >&2
    grpc_list_neighbors | jq . >&2 || true
    echo "===== rustbgpd RibService/ListReceivedRoutes =====" >&2
    grpc_list_received | jq . >&2 || true
    echo "===== rustbgpd metrics =====" >&2
    curl -fsS "http://${RUST_IP}:9179/metrics" | grep 'bgp_update_malformed_total' >&2 || true
    echo "===== rustbgpd log tail =====" >&2
    docker exec "$RUSTBGPD" tail -50 "$RUST_LOG_FILE" >&2 || true
    echo "===== raw fixture logs =====" >&2
    docker exec "$RAW_PEER" cat /tmp/m91-fixture.log >&2 || true
}

wait_rust_established() {
    local expected=$1 desc=$2
    log "Waiting for $PEER_ADDR Established=$expected ($desc)..."
    for _ in $(seq 1 45); do
        local json established
        if json=$(grpc_list_neighbors 2>/dev/null); then
            established=$(printf '%s\n' "$json" | jq -r --arg addr "$PEER_ADDR" '
                any(.neighbors[]?;
                    .config.address == $addr
                    and (.state == "SESSION_STATE_ESTABLISHED" or .state == 6))')
            if [ "$established" = "$expected" ]; then
                ok "$desc"
                return 0
            fi
        fi
        sleep 1
    done
    fail "$desc"
    dump_state_on_failure
    return 1
}

wait_received_presence() {
    local prefix=$1 expected=$2 desc=$3
    local addr=${prefix%/*}
    local plen=${prefix#*/}
    log "Waiting for received-route presence for $prefix -> $expected ($desc)..."
    for _ in $(seq 1 30); do
        local json found
        if json=$(grpc_list_received 2>/dev/null); then
            found=$(printf '%s\n' "$json" | jq -r --arg addr "$addr" --argjson plen "$plen" '
                any(.routes[]?; .prefix == $addr and .prefixLength == $plen)' 2>/dev/null)
            if [ "$found" = "$expected" ]; then
                ok "$desc"
                return 0
            fi
        fi
        sleep 1
    done
    fail "$desc"
    dump_state_on_failure
    return 1
}

wait_malformed_counter_at_least() {
    local disposition=$1 want=$2
    log "Waiting for bgp_update_malformed_total disposition=$disposition >= $want..."
    for _ in $(seq 1 30); do
        local metrics value
        metrics=$(curl -fsS "http://${RUST_IP}:9179/metrics" 2>/dev/null || true)
        value=$(printf '%s\n' "$metrics" | awk -v disposition="$disposition" '
            $1 ~ /^bgp_update_malformed_total/ && $0 ~ "disposition=\"" disposition "\"" { print $2; found=1 }
            END { if (!found) print 0 }' | tail -1)
        if [ "${value%.*}" -ge "$want" ] 2>/dev/null; then
            ok "malformed counter disposition=$disposition reached $value"
            return 0
        fi
        sleep 1
    done
    fail "malformed counter disposition=$disposition did not reach $want"
    dump_state_on_failure
    return 1
}

assert_debug_capture_at_least() {
    local want=$1
    log "Checking the RFC 7606 §6 full-message DEBUG capture (>= $want)..."
    for _ in $(seq 1 15); do
        local count
        count=$(docker exec "$RUSTBGPD" grep -c 'malformed UPDATE captured in full' "$RUST_LOG_FILE" 2>/dev/null || echo 0)
        if [ "${count:-0}" -ge "$want" ] 2>/dev/null; then
            ok "§6 DEBUG capture present ($count occurrences)"
            return 0
        fi
        sleep 1
    done
    fail "§6 DEBUG capture not found in $RUST_LOG_FILE"
    dump_state_on_failure
    return 1
}

trigger_phase() {
    local phase=$1
    log "Triggering fixture phase $phase..."
    docker exec "$RAW_PEER" touch "/tmp/m91-phase${phase}"
}

log "Starting raw RFC 7606 fixture..."
docker exec -d "$RAW_PEER" sh -c 'python3 /usr/local/bin/m91_rfc7606_raw_bgp.py >/tmp/m91-fixture.log 2>&1'

# Phase 1 — clean baseline.
wait_rust_established true "session established against the raw fixture"
wait_received_presence "$BASELINE_PREFIX" true "baseline route accepted"

# Phase 2 — malformed MED: treat-as-withdraw.
trigger_phase 2
wait_received_presence "$BASELINE_PREFIX" false "treat-as-withdraw removed the re-announced baseline"
wait_received_presence "$TAW_PREFIX" false "treat-as-withdraw admitted no announcement"
wait_rust_established true "session survives treat-as-withdraw"
wait_malformed_counter_at_least "treat_as_withdraw" 1
assert_debug_capture_at_least 1

# Phase 3 — malformed AGGREGATOR: attribute-discard.
trigger_phase 3
wait_received_presence "$DISCARD_PREFIX" true "attribute-discard kept the announcement"
wait_rust_established true "session survives attribute-discard"
wait_malformed_counter_at_least "attribute_discard" 1

# Phase 4 — malformed MED, no reachable NLRI: RFC 7606 §5.2 session reset.
trigger_phase 4
wait_rust_established false "no-reachable-NLRI malformed UPDATE reset the session (RFC 7606 §5.2)"
wait_malformed_counter_at_least "session_reset" 1

# The fixture logs the NOTIFICATION only if it was an UPDATE error (3/x).
log "Checking the fixture observed NOTIFICATION 3/x..."
notified=0
for _ in $(seq 1 15); do
    if docker exec "$RAW_PEER" grep -q 'received NOTIFICATION 3/' /tmp/m91-fixture.log 2>/dev/null; then
        ok "fixture received UPDATE-error NOTIFICATION"
        notified=1
        break
    fi
    sleep 1
done
if [ "$notified" -ne 1 ]; then
    fail "fixture did not observe an UPDATE-error NOTIFICATION"
    dump_state_on_failure
fi

print_summary
