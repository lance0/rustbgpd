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

# Standardized rustbgpd start, used by every interop script. Pass a
# custom command string to run a non-default daemon invocation
# (e.g. M21/M24 launch the binary directly against `/tmp/config.toml`
# after rewriting placeholders at runtime); omit the argument to use
# the wrapper at `/usr/local/bin/start-rustbgpd.sh`.
start_rustbgpd() {
    local start_cmd="${1:-/usr/local/bin/start-rustbgpd.sh}"
    log "Starting rustbgpd daemon..."
    docker exec -d "$RUSTBGPD" sh -c "$start_cmd"

    # Poll /proc for rustbgpd up to 10 s. The previous 3 s fixed sleep
    # was tight under heavy CI load (parallel containerlab deploys);
    # the loop keeps the local fast path quick while giving slow
    # environments room to land the fork.
    local found=0
    for i in $(seq 1 10); do
        if docker exec "$RUSTBGPD" sh -c 'cat /proc/*/comm 2>/dev/null' | grep -q rustbgpd; then
            log "rustbgpd is running (after ${i}s)"
            found=1
            break
        fi
        sleep 1
    done

    if [ "$found" -ne 1 ]; then
        echo "ERROR: rustbgpd failed to start within 10s" >&2
        echo "--- docker top $RUSTBGPD ---" >&2
        docker top "$RUSTBGPD" 2>&1 >&2 || true
        echo "--- container /proc comm names ---" >&2
        docker exec "$RUSTBGPD" sh -c 'cat /proc/[0-9]*/comm 2>/dev/null' >&2 || true
        echo "--- foreground rustbgpd (2 s capture) ---" >&2
        # Run the binary in the foreground briefly to capture any
        # immediate-exit output (config error, panic, etc.). If it
        # does start cleanly here, the 2 s timeout terminates it.
        docker exec "$RUSTBGPD" sh -c 'timeout 2 /usr/local/bin/rustbgpd /etc/rustbgpd/config.toml 2>&1 || true' >&2 || true
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
# Trap-based cleanup
# ---------------------------------------------------------------------------
# Auto-destroy the containerlab topology on script exit (success, fail,
# CTRL-C, hup) when CLEANUP=1. Default off so a developer iterating on a
# failing script can poke at the live containers; flip on for CI.
#
# `_clab_topology_file` is resolved against the standard tests/interop
# layout — sourced scripts live in tests/interop/scripts/, the .clab.yml
# is in tests/interop/${TOPO}.clab.yml.

_clab_topology_file() {
    printf "%s/../%s.clab.yml" "$SCRIPT_DIR" "$TOPO"
}

_cleanup_on_exit() {
    local exit_code=$?
    if [ "${CLEANUP:-0}" = "1" ]; then
        local topo_file
        topo_file="$(_clab_topology_file)"
        if [ -f "$topo_file" ]; then
            log "[cleanup] containerlab destroy -t $topo_file"
            containerlab destroy -t "$topo_file" --cleanup >/dev/null 2>&1 || true
        fi
    fi
    return "$exit_code"
}

trap _cleanup_on_exit EXIT INT TERM HUP

# ---------------------------------------------------------------------------
# Run pre-flight on source
# ---------------------------------------------------------------------------

preflight
