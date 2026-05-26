#!/usr/bin/env bash
# M54 interop test — ADR-0070 read-only gNMI / OpenConfig over mTLS.
#
# Validates the collector-facing path with gnmic, not an in-process
# client:
#
#   1. Capabilities reports gNMI 0.10.0, OpenConfig BGP models, and
#      JSON / JSON_IETF encodings.
#   2. Get reads the supported OpenConfig global + neighbor state
#      subset over the mTLS TCP listener.
#   3. Subscribe STREAM/SAMPLE emits repeated snapshots for a supported
#      OpenConfig leaf.
#
# Prerequisites:
#   docker build -t rustbgpd:dev .
#   bash tests/interop/scripts/gen-m54-certs.sh
#   containerlab deploy -t tests/interop/m54-gnmi-openconfig.clab.yml
#
# Usage:
#   bash tests/interop/scripts/test-m54-gnmi-openconfig.sh

TOPO="m54-gnmi-openconfig"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

CERT_DIR="$SCRIPT_DIR/../configs/m54-certs"
SERVER_NAME="rustbgpd.local"
OC_BGP="/network-instances/network-instance[name=DEFAULT]/protocols/protocol[identifier=BGP][name=BGP]/bgp"

if ! command -v gnmic &>/dev/null; then
    echo "ERROR: gnmic not found in PATH" >&2
    exit 1
fi

gnmic_mtls() {
    gnmic \
        --address "$GRPC_ADDR" \
        --tls-ca "$CERT_DIR/ca.pem" \
        --tls-cert "$CERT_DIR/operator.pem" \
        --tls-key "$CERT_DIR/operator.key" \
        --tls-server-name "$SERVER_NAME" \
        --format json \
        --no-prefix \
        "$@" 2>&1
}

gnmic_mtls_timeout() {
    local duration=$1
    shift
    timeout "$duration" gnmic \
        --address "$GRPC_ADDR" \
        --tls-ca "$CERT_DIR/ca.pem" \
        --tls-cert "$CERT_DIR/operator.pem" \
        --tls-key "$CERT_DIR/operator.key" \
        --tls-server-name "$SERVER_NAME" \
        --format json \
        --no-prefix \
        "$@" 2>&1
}

assert_jq() {
    local desc=$1 json=$2 filter=$3
    if printf '%s' "$json" | jq -e "$filter" >/dev/null; then
        ok "$desc"
    else
        fail "$desc (jq filter failed: $filter)"
        printf '  output:\n%s\n' "$json" >&2
    fi
}

assert_contains() {
    local desc=$1 haystack=$2 needle=$3
    if printf '%s' "$haystack" | grep -Fq "$needle"; then
        ok "$desc"
    else
        fail "$desc (missing: $needle)"
        printf '  output:\n%s\n' "$haystack" >&2
    fi
}

assert_count_at_least() {
    local desc=$1 haystack=$2 needle=$3 want=$4
    local got
    got=$( (printf '%s' "$haystack" | grep -Fo "$needle" || true) | wc -l | tr -d ' ')
    if [ "$got" -ge "$want" ]; then
        ok "$desc"
    else
        fail "$desc (wanted >= $want occurrences of $needle, got $got)"
        printf '  output:\n%s\n' "$haystack" >&2
    fi
}

start_rustbgpd_gnmi() {
    log "Starting rustbgpd (mTLS gNMI listener)..."
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

    log "Waiting for gNMI Capabilities over mTLS..."
    for i in $(seq 1 15); do
        if gnmic_mtls capabilities >/dev/null 2>&1; then
            ok "gNMI endpoint ready (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "gNMI endpoint not reachable within 30s"
    print_summary
    exit 1
}

main() {
    log "M54 interop test: ADR-0070 gNMI / OpenConfig over mTLS"
    log "Topology: $TOPO"

    resolve_grpc_addr
    start_rustbgpd_gnmi

    log "Checking gNMI Capabilities..."
    local caps
    caps=$(gnmic_mtls capabilities)
    assert_jq "Capabilities reports gNMI 0.10.0" "$caps" '.version == "0.10.0"'
    assert_jq "Capabilities advertises openconfig-bgp" "$caps" \
        '."supported-models" | any(.name == "openconfig-bgp")'
    assert_jq "Capabilities advertises JSON encoding" "$caps" \
        '.encodings | index("JSON") != null'
    assert_jq "Capabilities advertises JSON_IETF encoding" "$caps" \
        '.encodings | index("JSON_IETF") != null'

    log "Checking OpenConfig BGP global state via Get..."
    local global
    global=$(gnmic_mtls get \
        --encoding json_ietf \
        --type STATE \
        --path "$OC_BGP/global/state")
    assert_contains "Get global state includes local AS" "$global" '65001'
    assert_contains "Get global state includes router-id" "$global" '10.0.0.1'

    log "Checking OpenConfig BGP neighbor state via Get..."
    local neighbor
    neighbor=$(gnmic_mtls get \
        --encoding json_ietf \
        --type STATE \
        --path "$OC_BGP/neighbors/neighbor[neighbor-address=10.0.0.2]/state")
    assert_contains "Get neighbor state includes neighbor address" "$neighbor" '10.0.0.2'
    assert_contains "Get neighbor state includes peer AS" "$neighbor" '65002'

    log "Checking Subscribe STREAM/SAMPLE..."
    local stream rc
    set +e
    stream=$(gnmic_mtls_timeout 5s subscribe \
        --encoding json_ietf \
        --mode stream \
        --stream-mode sample \
        --sample-interval 1s \
        --path "$OC_BGP/global/state/router-id")
    rc=$?
    set -e
    if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; then
        fail "Subscribe STREAM/SAMPLE returned unexpected exit code $rc"
        printf '  output:\n%s\n' "$stream" >&2
    else
        assert_count_at_least "Subscribe SAMPLE emits repeated router-id snapshots" \
            "$stream" '10.0.0.1' 2
    fi

    print_summary
}

main "$@"
