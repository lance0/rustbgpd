#!/usr/bin/env bash
# Guarded FlowSpec rollback refusal (ADR-0144 §1). Local only: it is not
# wired into hosted CI.
#
# Runs the released image (default ghcr.io/lance0/rustbgpd:0.80.1, which
# predates the guarded methods) with no peers and calls all four guarded
# methods from a client built on this tree's proto. Bars:
#   - no guarded call returns OK (any other status is accepted);
#   - the lease table and the local FlowSpec rules, holding one unowned rule
#     that the guarded delete names, are byte-identical before and after the
#     four calls;
#   - control: AddLeasedFlowSpec on the same server returns OK and changes
#     both listings (otherwise the run is INVALID: the server was not
#     serving or not mutable).
#
#   OUT_DIR=/abs/dir bash tests/interop/scripts/qualify-guarded-flowspec-rollback.sh
set -uo pipefail

OUT_DIR="${OUT_DIR:?OUT_DIR must name an absolute results directory}"
IMAGE="${IMAGE:-ghcr.io/lance0/rustbgpd:0.80.1}"
NAME="guarded-rollback-$$"
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT" || exit 1
mkdir -p "$OUT_DIR"
STATE_DIR="$(mktemp -d /tmp/guarded-rollback.XXXXXX)"
TOKEN_FILE="tests/fixtures/grpc-test-only-operator.token"
VERDICTS="$OUT_DIR/rollback-verdicts"
: >"$VERDICTS"

# shellcheck disable=SC2317  # invoked by the EXIT trap
cleanup() {
    docker logs "$NAME" >"$OUT_DIR/rollback-daemon.log" 2>&1
    docker rm -f "$NAME" >/dev/null 2>&1
    rm -rf "$STATE_DIR"
}
trap cleanup EXIT

cat >"$STATE_DIR/config.toml" <<'EOF'
[global]
asn = 65001
router_id = "192.0.2.1"
listen_port = 1179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[global.telemetry.grpc_tcp]
address = "0.0.0.0:50051"
token_file = "/run/rustbgpd/token"
principal = "rustbgpd://operator/test-only"

[security.grpc]
enforcement = "tier"

[security.grpc.roles]
"rustbgpd://operator/test-only" = "operator"
EOF
chmod 0644 "$STATE_DIR/config.toml"

verdict() {
    printf '%s %s %s\n' "$1" "$2" "$3" | tee -a "$VERDICTS"
}

docker run -d --name "$NAME" \
    -v "$STATE_DIR/config.toml:/etc/rustbgpd/config.toml:ro" \
    -v "$ROOT/$TOKEN_FILE:/run/rustbgpd/token:ro" \
    "$IMAGE" >/dev/null || { verdict start INVALID "docker run failed"; exit 2; }
ADDR="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NAME"):50051"
TOKEN="$(cat "$TOKEN_FILE")"
call() {
    grpcurl -plaintext -import-path . -proto proto/rustbgpd.proto \
        -H "authorization: Bearer $TOKEN" -d "$1" "$ADDR" "rustbgpd.v1.$2"
}
for _ in $(seq 1 30); do
    call '{}' ControlService/GetHealth >/dev/null 2>&1 && break
    sleep 1
done
call '{}' ControlService/GetHealth >"$OUT_DIR/rollback-health.json" 2>&1 \
    || { verdict start INVALID "the daemon never answered GetHealth"; exit 2; }
docker inspect -f '{{.Image}} {{index .Config.Labels "org.opencontainers.image.version"}} {{index .Config.Labels "org.opencontainers.image.revision"}}' "$NAME" \
    >"$OUT_DIR/rollback-image"

snapshot() {
    {
        call '{}' InjectionService/ListInjectionLeases
        call '{"afiSafi": "ADDRESS_FAMILY_IPV4_FLOWSPEC", "receivedPeerAddress": "0.0.0.0"}' \
            RibService/ListFlowSpecRoutes
    } 2>&1
}

RULE='{"afiSafi": "ADDRESS_FAMILY_IPV4_FLOWSPEC", "components": [{"type": 1, "prefix": "203.0.113.9/32"}], "actions": [{"trafficRate": {"rate": 0}}]}'
WINDOW='{"incarnation": "1", "sequence": "1"}'
# Pre-existing state the guarded delete names: an unowned rule.
PRESENT='{"afiSafi": "ADDRESS_FAMILY_IPV4_FLOWSPEC", "components": [{"type": 1, "prefix": "203.0.113.20/32"}], "actions": [{"trafficRate": {"rate": 0}}]}'
call "$PRESENT" InjectionService/AddFlowSpec >/dev/null 2>&1 \
    || { verdict start INVALID "the pre-existing rule could not be added"; exit 2; }
snapshot >"$OUT_DIR/rollback-before"
: >"$OUT_DIR/rollback-calls"
any_ok=false
for method_body in \
    "IssueMutationWindow|{\"owner\": \"qual\", \"windowSeconds\": 60}" \
    "AddGuardedFlowSpec|{\"rule\": $RULE, \"lease\": {\"owner\": \"qual\", \"leaseSeconds\": 30}, \"window\": $WINDOW, \"revision\": \"1\"}" \
    "DeleteGuardedFlowSpec|{\"afiSafi\": \"ADDRESS_FAMILY_IPV4_FLOWSPEC\", \"components\": [{\"type\": 1, \"prefix\": \"203.0.113.20/32\"}], \"owner\": \"qual\", \"revision\": \"1\"}" \
    "RenewGuardedLease|{\"owner\": \"qual\", \"generation\": {\"incarnation\": \"1\", \"sequence\": \"1\"}, \"leaseSeconds\": 30, \"window\": $WINDOW}"; do
    method=${method_body%%|*}
    body=${method_body#*|}
    if reply=$(call "$body" "InjectionService/$method" 2>&1); then
        any_ok=true
        printf '%s OK %s\n' "$method" "$(printf '%s' "$reply" | tr -d '\n')" >>"$OUT_DIR/rollback-calls"
    else
        printf '%s %s\n' "$method" "$(printf '%s' "$reply" | grep -o 'Code: [A-Za-z]*' | head -1)" >>"$OUT_DIR/rollback-calls"
    fi
done
snapshot >"$OUT_DIR/rollback-after"

if $any_ok; then
    verdict guarded_refused FAIL "a guarded call returned OK; see rollback-calls"
else
    verdict guarded_refused PASS "all four guarded calls non-OK: $(cut -d' ' -f2- "$OUT_DIR/rollback-calls" | sort -u | tr '\n' ' ')"
fi
if cmp -s "$OUT_DIR/rollback-before" "$OUT_DIR/rollback-after"; then
    verdict inventory_unchanged PASS "leases and local FlowSpec rules byte-identical"
else
    verdict inventory_unchanged FAIL "inventory changed; diff rollback-before rollback-after"
fi
if call "{\"rule\": $RULE, \"lease\": {\"owner\": \"qual\", \"leaseSeconds\": 30}}" \
    InjectionService/AddLeasedFlowSpec >"$OUT_DIR/rollback-control" 2>&1 \
    && snapshot >"$OUT_DIR/rollback-control-after" \
    && ! cmp -s "$OUT_DIR/rollback-after" "$OUT_DIR/rollback-control-after"; then
    verdict legacy_control PASS "AddLeasedFlowSpec committed and changed the inventory"
else
    verdict legacy_control INVALID "the legacy control did not commit; see rollback-control"
fi
grep -q ' FAIL \| INVALID ' "$VERDICTS" && exit 1
exit 0
