#!/usr/bin/env bash
# Shared test library for interop test scripts.
#
# Source this at the top of each test script after setting TOPO:
#   TOPO="m1-frr"
#   SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
#   source "$SCRIPT_DIR/test-lib.sh"
#
# Provides:
#   - Pre-flight checks (docker, grpcurl, containerlab topology running)
#   - Timestamped log/ok/fail helpers
#   - resolve_grpc_addr, resolve_ip
#   - start_rustbgpd with gRPC health wait
#   - wait_established (FRR vtysh polling)
#   - Trap-based cleanup: auto-destroy containerlab on EXIT if CLEANUP=1

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration (set TOPO before sourcing)
# ---------------------------------------------------------------------------

: "${TOPO:?TOPO must be set before sourcing test-lib.sh}"
PROTO="proto/rustbgpd.proto"
GRPC_ADDR=""
RUSTBGPD="clab-${TOPO}-rustbgpd"

pass=0
fail=0

# ---------------------------------------------------------------------------
# Timestamped output helpers
# ---------------------------------------------------------------------------

_ts() { date +%H:%M:%S 2>/dev/null || true; }

log()  { printf "\033[1;34m[%s TEST]\033[0m %s\n" "$(_ts)" "$*"; }
ok()   { pass=$((pass + 1)); printf "\033[1;32m  [%s] PASS\033[0m %s\n" "$(_ts)" "$*"; }
fail() { fail=$((fail + 1)); printf "\033[1;31m  [%s] FAIL\033[0m %s\n" "$(_ts)" "$*"; }

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

preflight() {
    local errors=0

    if ! command -v docker &>/dev/null; then
        echo "ERROR: docker not found in PATH" >&2
        errors=$((errors + 1))
    fi

    if ! command -v grpcurl &>/dev/null; then
        echo "ERROR: grpcurl not found in PATH" >&2
        errors=$((errors + 1))
    fi

    if ! docker inspect "$RUSTBGPD" &>/dev/null; then
        echo "ERROR: container $RUSTBGPD not running — deploy topology first:" >&2
        echo "  containerlab deploy -t tests/interop/${TOPO}.clab.yml" >&2
        errors=$((errors + 1))
    fi

    if [ ! -f "$PROTO" ]; then
        echo "ERROR: proto file not found at $PROTO — run from repo root" >&2
        errors=$((errors + 1))
    fi

    if [ "$errors" -gt 0 ]; then
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Common helpers
# ---------------------------------------------------------------------------

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

# Wait for a FRR neighbor to reach Established state.
# Usage: wait_frr_established <frr_container> <peer_addr> [label]
wait_frr_established() {
    local frr_container=${1:?}
    local peer_addr=${2:?}
    local label=${3:-BGP}

    log "Waiting for $label session to reach Established..."
    for i in $(seq 1 45); do
        local state
        state=$(docker exec "$frr_container" vtysh -c "show bgp neighbors $peer_addr json" 2>/dev/null \
            | grep -o '"bgpState":"[^"]*"' | head -1 | cut -d'"' -f4 || true)
        if [ "$state" = "Established" ]; then
            ok "$label session established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$label session did not reach Established within 90s"
    return 1
}

# ---------------------------------------------------------------------------
# Test summary
# ---------------------------------------------------------------------------

print_summary() {
    echo ""
    log "Results: $pass passed, $fail failed"
    if [ "$fail" -gt 0 ]; then
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Run pre-flight on source
# ---------------------------------------------------------------------------

preflight
