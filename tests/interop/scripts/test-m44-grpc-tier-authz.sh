#!/usr/bin/env bash
# M44 interop test — ADR-0064 gRPC tier authorization over native mTLS.
#
# Validates the v0.24.0 production-default `enforcement = "tier"`
# end-to-end over the wire, not just in config validation:
#
#   1. observer principal CAN call a sensitive_read RPC
#      (ListReceivedRoutes) and CANNOT call a mutating RPC
#      (AddNeighbor) — denied with PermissionDenied.
#   2. automation principal CAN call a mutating RPC and CANNOT call an
#      operator_only RPC (TriggerMrtDump) — denied.
#   3. operator principal CAN call an operator_only RPC.
#   4. A certificate whose principal is absent from
#      [security.grpc.roles] is denied for any RPC.
#   5. The `bgp_grpc_authz_decisions_total` metric records the denials
#      under bounded result labels.
#
# Prerequisites:
#   docker build -t rustbgpd:dev .
#   bash tests/interop/scripts/gen-m44-certs.sh
#   containerlab deploy -t tests/interop/m44-grpc-tier-authz.clab.yml
#
# Usage:
#   bash tests/interop/scripts/test-m44-grpc-tier-authz.sh

TOPO="m44-grpc-tier-authz"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

CERT_DIR="$SCRIPT_DIR/../configs/m44-certs"
SERVER_NAME="rustbgpd.local"

# mTLS grpcurl wrapper. Verifies the server cert against the fixed
# -servername (the server cert has a DNS:rustbgpd.local SAN) while
# connecting to the container's dynamic IP. $1 = client cert basename,
# remaining args pass through to grpcurl.
grpc_mtls() {
    local who=$1
    shift
    grpcurl \
        -cacert "$CERT_DIR/ca.pem" \
        -cert "$CERT_DIR/${who}.pem" \
        -key "$CERT_DIR/${who}.key" \
        -servername "$SERVER_NAME" \
        -import-path . -proto "$PROTO" \
        "$@" 2>&1
}

# Assert a principal's call to a method is ALLOWED — i.e. it reaches
# the handler. The handler may itself succeed or return a non-authz
# error, but it must NOT be PermissionDenied.
assert_allowed() {
    local desc=$1 who=$2 method=$3 data=${4:-}
    local out
    # grpcurl exits non-zero on any RPC error (including the
    # PermissionDenied we're checking for); `|| true` keeps the
    # library's `set -e` from aborting the run on that expected
    # non-zero status.
    if [ -n "$data" ]; then
        out=$(grpc_mtls "$who" -d "$data" "$GRPC_ADDR" "$method") || true
    else
        out=$(grpc_mtls "$who" "$GRPC_ADDR" "$method") || true
    fi
    if printf '%s' "$out" | grep -q "PermissionDenied"; then
        fail "$desc (expected allow, got PermissionDenied)"
        printf '  grpcurl output: %s\n' "$out" >&2
    else
        ok "$desc"
    fi
}

# Assert a principal's call to a method is DENIED with PermissionDenied.
assert_denied() {
    local desc=$1 who=$2 method=$3 data=${4:-}
    local out
    # See assert_allowed: `|| true` absorbs grpcurl's expected
    # non-zero exit so `set -e` doesn't abort the run.
    if [ -n "$data" ]; then
        out=$(grpc_mtls "$who" -d "$data" "$GRPC_ADDR" "$method") || true
    else
        out=$(grpc_mtls "$who" "$GRPC_ADDR" "$method") || true
    fi
    if printf '%s' "$out" | grep -q "PermissionDenied"; then
        ok "$desc"
    else
        fail "$desc (expected PermissionDenied)"
        printf '  grpcurl output: %s\n' "$out" >&2
    fi
}

prom_scrape() {
    local ip
    ip=$(resolve_ip "$RUSTBGPD")
    [ -z "$ip" ] && return 0
    curl -sfm 5 "http://${ip}:9179/metrics" 2>/dev/null || true
}

# Start the daemon and wait for the mTLS gRPC endpoint. The library
# start_rustbgpd waits via a *plaintext* GetHealth, which an mTLS
# listener rejects, so M44 rolls its own readiness check using the
# operator client cert (GetHealth is sensitive_read; operator's
# ceiling permits it).
start_rustbgpd_mtls() {
    log "Starting rustbgpd (mTLS gRPC listener)..."
    docker exec -d "$RUSTBGPD" sh -c "/usr/local/bin/start-rustbgpd.sh"
    local up=0
    for i in $(seq 1 10); do
        if docker exec "$RUSTBGPD" sh -c 'cat /proc/*/comm 2>/dev/null' | grep -q rustbgpd; then
            log "rustbgpd process up (after ${i}s)"
            up=1
            break
        fi
        sleep 1
    done
    if [ "$up" -ne 1 ]; then
        fail "rustbgpd failed to start"
        docker exec "$RUSTBGPD" sh -c 'timeout 2 /usr/local/bin/rustbgpd /etc/rustbgpd/config.toml 2>&1 || true' >&2 || true
        print_summary
        exit 1
    fi
    log "Waiting for mTLS gRPC endpoint..."
    for i in $(seq 1 15); do
        # grpc_mtls returns grpcurl's exit code; operator's GetHealth
        # (sensitive_read) succeeds once the listener is up.
        if grpc_mtls operator "$GRPC_ADDR" "rustbgpd.v1.ControlService/GetHealth" \
            >/dev/null 2>&1; then
            ok "mTLS gRPC endpoint ready (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "mTLS gRPC endpoint not reachable within 30s"
    print_summary
    exit 1
}

main() {
    log "M44 interop test: ADR-0064 gRPC tier authorization over mTLS"
    log "Topology: $TOPO"

    resolve_grpc_addr
    start_rustbgpd_mtls

    local add_neighbor='{"config":{"address":"10.0.0.3","remote_asn":65003,"hold_time":90}}'

    # observer: sensitive_read allowed, mutating denied.
    assert_allowed "observer CAN ListReceivedRoutes (sensitive_read)" \
        observer "rustbgpd.v1.RibService/ListReceivedRoutes" \
        '{"neighbor_address":"10.0.0.2"}'
    assert_denied "observer CANNOT AddNeighbor (mutating)" \
        observer "rustbgpd.v1.NeighborService/AddNeighbor" "$add_neighbor"

    # automation: mutating allowed, operator_only denied.
    assert_allowed "automation CAN AddNeighbor (mutating)" \
        automation "rustbgpd.v1.NeighborService/AddNeighbor" "$add_neighbor"
    assert_denied "automation CANNOT TriggerMrtDump (operator_only)" \
        automation "rustbgpd.v1.ControlService/TriggerMrtDump" '{}'

    # operator: operator_only allowed.
    assert_allowed "operator CAN TriggerMrtDump (operator_only)" \
        operator "rustbgpd.v1.ControlService/TriggerMrtDump" '{}'

    # unmapped principal: denied for any RPC.
    assert_denied "unmapped principal CANNOT ListReceivedRoutes" \
        intruder "rustbgpd.v1.RibService/ListReceivedRoutes" \
        '{"neighbor_address":"10.0.0.2"}'

    # Metric records the denials under bounded labels.
    log "Checking bgp_grpc_authz_decisions_total denial labels..."
    local metrics
    metrics=$(prom_scrape)
    if printf '%s' "$metrics" | grep -q 'bgp_grpc_authz_decisions_total{[^}]*result="role_tier_denied"'; then
        ok "metric records role_tier_denied"
    else
        fail "metric missing role_tier_denied label"
    fi
    if printf '%s' "$metrics" | grep -q 'bgp_grpc_authz_decisions_total{[^}]*result="principal_unmapped"'; then
        ok "metric records principal_unmapped"
    else
        fail "metric missing principal_unmapped label"
    fi

    print_summary
}

main "$@"
