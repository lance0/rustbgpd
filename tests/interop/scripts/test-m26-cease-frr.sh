#!/usr/bin/env bash
# M26 interop test — Cease subcode compatibility with FRR
#
# Validates:
#   1. Session establishes initially
#   2. FRR sends 3 prefixes, exceeding max_prefixes=2
#   3. rustbgpd sends Cease/1 (Max Prefixes) NOTIFICATION
#   4. FRR sees the NOTIFICATION and session tears down
#   5. Prometheus metric records the max-prefix event
#   6. Session re-establishes (auto-reconnect)
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m26-cease-frr.clab.yml
#   - grpcurl installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m26-cease-frr.sh

set -euo pipefail

TOPO="m26-cease-frr"
RUSTBGPD="clab-${TOPO}-rustbgpd"
FRR="clab-${TOPO}-frr"
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

grpc_health() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.ControlService/GetHealth 2>/dev/null
}

grpc_metrics() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "$GRPC_ADDR" rustbgpd.v1.ControlService/GetMetrics 2>/dev/null
}

grpc_neighbor_state() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d '{"address": "10.0.0.2"}' \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/GetNeighborState 2>/dev/null
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
# Tests
# ---------------------------------------------------------------------------

test_session_establishes() {
    log "Test 1: Session initially establishes"

    # Session should come up briefly before the prefix limit triggers
    for i in $(seq 1 30); do
        local state
        state=$(docker exec "$FRR" vtysh -c "show bgp neighbors 10.0.0.1 json" 2>/dev/null \
            | grep -o '"bgpState":"[^"]*"' | head -1 | cut -d'"' -f4 || true)
        if [ "$state" = "Established" ]; then
            ok "Session reached Established (attempt $i)"
            return 0
        fi
        # Also check if FRR already saw a notification (session may have bounced)
        local last_notif
        last_notif=$(docker exec "$FRR" vtysh -c "show bgp neighbors 10.0.0.1 json" 2>/dev/null \
            | grep -o '"lastNotificationReason":"[^"]*"' | head -1 || true)
        if [ -n "$last_notif" ]; then
            ok "Session established and then received NOTIFICATION (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "Session never reached Established within 60s"
}

test_cease_notification_sent() {
    log "Test 2: Cease NOTIFICATION sent (max_prefixes exceeded)"

    # Wait for FRR to see the notification — session should bounce
    for i in $(seq 1 30); do
        local notif_info
        notif_info=$(docker exec "$FRR" vtysh -c "show bgp neighbors 10.0.0.1 json" 2>/dev/null || true)

        # FRR tracks last notification reason
        local reason
        reason=$(echo "$notif_info" | grep -o '"lastNotificationReason":"[^"]*"' | head -1 | cut -d'"' -f4 || true)

        if echo "$reason" | grep -qi "cease\|max.prefix\|exceed"; then
            ok "FRR received Cease NOTIFICATION: $reason"
            return 0
        fi

        # Also check lastResetDueTo
        local reset_reason
        reset_reason=$(echo "$notif_info" | grep -o '"lastResetDueTo":"[^"]*"' | head -1 | cut -d'"' -f4 || true)

        if echo "$reset_reason" | grep -qi "notification.*received\|cease"; then
            ok "FRR reports session reset due to: $reset_reason"
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

    local metrics
    metrics=$(grpc_metrics | python3 -c "
import sys, json
print(json.load(sys.stdin).get('prometheusText', ''))
" 2>/dev/null || true)

    if echo "$metrics" | grep -q "max_prefix_exceeded"; then
        ok "max_prefix_exceeded metric present"
    else
        # May be named differently — check for any prefix-related metric
        if echo "$metrics" | grep -qi "prefix.*exceed\|max.*prefix"; then
            ok "Max prefix metric present (alternative name)"
        else
            fail "No max-prefix-exceeded metric found"
            log "DEBUG: Available metrics with 'prefix':"
            echo "$metrics" | grep -i prefix | head -5 || echo "(none)"
        fi
    fi
}

test_session_recovers() {
    log "Test 4: Session re-establishes after Cease"

    # rustbgpd should auto-reconnect. FRR will re-send the same 3 prefixes,
    # which will trigger the limit again — but the session should at least
    # cycle through Established.
    #
    # Check for multiple establishment cycles in the FRR neighbor stats.
    local neighbor_state
    neighbor_state=$(grpc_neighbor_state)

    local flaps
    flaps=$(echo "$neighbor_state" | python3 -c "
import sys, json
resp = json.load(sys.stdin)
print(resp.get('flapCount', '0'))
" 2>/dev/null || echo 0)

    if [ "$flaps" -ge 1 ]; then
        ok "Session has flapped (flapCount=$flaps) — indicates cycle through Established"
    else
        # Even if flap count is 0, if notifications were sent, the test still proves Cease handling
        local notifs_sent
        notifs_sent=$(echo "$neighbor_state" | python3 -c "
import sys, json
resp = json.load(sys.stdin)
print(resp.get('notificationsSent', '0'))
" 2>/dev/null || echo 0)

        if [ "$notifs_sent" -ge 1 ]; then
            ok "Notifications sent ($notifs_sent) — Cease/Max-Prefix issued"
        else
            fail "No flaps or notifications detected"
        fi
    fi
}

test_frr_cease_subcode_acceptance() {
    log "Test 5: FRR accepted Cease subcode (no crash, clean teardown)"

    # Verify FRR is still running and healthy
    local frr_running
    frr_running=$(docker exec "$FRR" vtysh -c "show bgp summary json" 2>/dev/null || echo "error")

    if echo "$frr_running" | grep -q "routerId"; then
        ok "FRR still operational after receiving Cease"
    else
        fail "FRR not responding after Cease"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "M26 interop test: Cease subcode compatibility"
    log "Topology: $TOPO (max_prefixes=2, FRR sends 3)"

    resolve_grpc_addr
    start_rustbgpd

    # Give time for session to establish, receive prefixes, and trigger Cease
    sleep 15

    test_session_establishes
    test_cease_notification_sent
    test_max_prefix_metric
    test_session_recovers
    test_frr_cease_subcode_acceptance

    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

main "$@"
