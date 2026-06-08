#!/usr/bin/env bash
# M54 interop test — ADR-0070 gNMI / OpenConfig over mTLS.
#
# Validates the collector-facing path with gnmic, not an in-process
# client:
#
#   1. Capabilities reports gNMI 0.10.0, OpenConfig BGP models, and
#      JSON / JSON_IETF encodings.
#   2. Get reads the supported OpenConfig global + neighbor state
#      subset over the mTLS TCP listener.
#   3. Set can add/delete a static numbered neighbor through the
#      transaction-backed OpenConfig config subset.
#   4. Set can create/delete peer-group objects and dynamic-neighbor
#      prefix ranges, with durable TOML persistence.
#   5. Set commit-confirmed can confirm and cancel a pending mutation.
#   6. Subscribe STREAM/SAMPLE emits repeated snapshots for a supported
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
    if printf '%s' "$haystack" | grep -Fq -- "$needle"; then
        ok "$desc"
    else
        fail "$desc (missing: $needle)"
        printf '  output:\n%s\n' "$haystack" >&2
    fi
}

assert_not_contains() {
    local desc=$1 haystack=$2 needle=$3
    if printf '%s' "$haystack" | grep -Fq -- "$needle"; then
        fail "$desc (unexpected: $needle)"
        printf '  output:\n%s\n' "$haystack" >&2
    else
        ok "$desc"
    fi
}

config_toml() {
    docker exec "$RUSTBGPD" sh -c 'cat /etc/rustbgpd/config.toml'
}

assert_config_contains() {
    local desc=$1 needle=$2 config
    config=$(config_toml)
    assert_contains "$desc" "$config" "$needle"
}

assert_config_not_contains() {
    local desc=$1 needle=$2 config
    config=$(config_toml)
    assert_not_contains "$desc" "$config" "$needle"
}

assert_count_at_least() {
    local desc=$1 haystack=$2 needle=$3 want=$4
    local got
    got=$( (printf '%s' "$haystack" | grep -Fo -- "$needle" || true) | wc -l | tr -d ' ')
    if [ "$got" -ge "$want" ]; then
        ok "$desc"
    else
        fail "$desc (wanted >= $want occurrences of $needle, got $got)"
        printf '  output:\n%s\n' "$haystack" >&2
    fi
}

gnmic_set_ok() {
    local desc=$1 output rc
    shift
    set +e
    output=$(gnmic_mtls_timeout 30s set "$@")
    rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
        return 0
    fi
    fail "$desc (gnmic set failed with rc=$rc)"
    printf '  output:\n%s\n' "$output" >&2
    print_summary
    exit 1
}

gnmic_get_ok() {
    local desc=$1 output rc
    shift
    set +e
    output=$(gnmic_mtls_timeout 30s get "$@")
    rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
        printf '%s' "$output"
        return 0
    fi
    fail "$desc (gnmic get failed with rc=$rc)"
    printf '  output:\n%s\n' "$output" >&2
    print_summary
    exit 1
}

# gnmic over mTLS as a caller-chosen client identity, for authz/negative
# assertions. --debug forces the server status code onto stderr even when
# --format json would otherwise hide it: gnmic surfaces rpc errors only in
# debug log lines in default format mode.
gnmic_mtls_as() {
    local cert=$1
    shift
    timeout 30s gnmic \
        --address "$GRPC_ADDR" \
        --tls-ca "$CERT_DIR/ca.pem" \
        --tls-cert "$CERT_DIR/${cert}.pem" \
        --tls-key "$CERT_DIR/${cert}.key" \
        --tls-server-name "$SERVER_NAME" \
        --format json \
        --no-prefix \
        --debug \
        "$@" 2>&1
}

# Assert a gnmic Set is REJECTED carrying a specific gRPC status code
# (e.g. PermissionDenied, Unimplemented). A Set that unexpectedly
# succeeds is itself a failure.
gnmic_set_rejected() {
    local desc=$1 want_code=$2 cert=$3 output rc
    shift 3
    set +e
    output=$(gnmic_mtls_as "$cert" set "$@")
    rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
        fail "$desc (expected $want_code, but Set succeeded)"
        printf '  output:\n%s\n' "$output" >&2
        return
    fi
    assert_contains "$desc" "$output" "$want_code"
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
    global=$(gnmic_get_ok "Get global state" \
        --encoding json_ietf \
        --type STATE \
        --path "$OC_BGP/global/state")
    assert_contains "Get global state includes local AS" "$global" '65001'
    assert_contains "Get global state includes router-id" "$global" '10.0.0.1'

    log "Checking OpenConfig BGP neighbor state via Get..."
    local neighbor
    neighbor=$(gnmic_get_ok "Get neighbor state" \
        --encoding json_ietf \
        --type STATE \
        --path "$OC_BGP/neighbors/neighbor[neighbor-address=10.0.0.2]/state")
    assert_contains "Get neighbor state includes neighbor address" "$neighbor" '10.0.0.2'
    assert_contains "Get neighbor state includes peer AS" "$neighbor" '65002'

    log "Checking OpenConfig BGP static-neighbor Set add/delete via gnmic..."
    local set_peer="10.0.0.3"
    local set_peer_path="$OC_BGP/neighbors/neighbor[neighbor-address=$set_peer]"
    gnmic_set_ok "Set add static neighbor" \
        --update "$set_peer_path/config/peer-as:::uint:::65003"
    local after_set
    after_set=$(gnmic_get_ok "Get neighbors after Set add" \
        --encoding json_ietf \
        --type STATE \
        --path "$OC_BGP/neighbors")
    assert_contains "Set add surfaces new neighbor through Get" "$after_set" "$set_peer"
    assert_contains "Set add surfaces new peer AS through Get" "$after_set" '65003'

    gnmic_set_ok "Set delete static neighbor" --delete "$set_peer_path"
    local after_delete
    after_delete=$(gnmic_get_ok "Get neighbors after Set delete" \
        --encoding json_ietf \
        --type STATE \
        --path "$OC_BGP/neighbors")
    assert_not_contains "Set delete removes neighbor from Get" "$after_delete" "$set_peer"

    log "Checking OpenConfig BGP peer-group Set via gnmic..."
    local pg_name="m54-dyn"
    local pg_path="$OC_BGP/peer-groups/peer-group[peer-group-name=$pg_name]"
    gnmic_set_ok "Set create peer-group object" \
        --update "$pg_path/config/peer-group-name:::string:::$pg_name" \
        --update "$pg_path/timers/config/hold-time:::uint:::45"
    assert_config_contains "Peer-group Set persists group table" "[peer_groups.$pg_name]"
    assert_config_contains "Peer-group Set persists hold_time" "hold_time = 45"

    log "Checking OpenConfig BGP dynamic-neighbor-prefix Set via gnmic..."
    local dyn_prefix="198.51.100.0/24"
    local dyn_path="$OC_BGP/global/dynamic-neighbor-prefixes/dynamic-neighbor-prefix[prefix=$dyn_prefix]"
    gnmic_set_ok "Set create dynamic-neighbor-prefix" \
        --update "$dyn_path/config/prefix:::string:::$dyn_prefix" \
        --update "$dyn_path/config/peer-group:::string:::$pg_name"
    assert_config_contains "Dynamic-neighbor Set persists range prefix" "prefix = \"$dyn_prefix\""
    assert_config_contains "Dynamic-neighbor Set persists peer-group reference" "peer_group = \"$pg_name\""
    assert_config_contains "Dynamic-neighbor Set defaults remote_asn to accept-any" "remote_asn = 0"

    local bad_dyn_prefix="198.51.101.0/24"
    local bad_dyn_path="$OC_BGP/global/dynamic-neighbor-prefixes/dynamic-neighbor-prefix[prefix=$bad_dyn_prefix]"
    gnmic_set_rejected "operator Set of dynamic-neighbor-prefix with undefined peer-group is InvalidArgument" \
        "InvalidArgument" operator \
        --update "$bad_dyn_path/config/prefix:::string:::$bad_dyn_prefix" \
        --update "$bad_dyn_path/config/peer-group:::string:::missing-m54-group"
    assert_config_not_contains "Rejected dynamic-neighbor Set did not persist range" "$bad_dyn_prefix"

    gnmic_set_ok "Set delete dynamic-neighbor-prefix" --delete "$dyn_path"
    assert_config_not_contains "Set delete removes dynamic-neighbor range" "$dyn_prefix"
    gnmic_set_ok "Set delete peer-group object" --delete "$pg_path"
    assert_config_not_contains "Set delete removes peer-group object" "[peer_groups.$pg_name]"

    log "Checking OpenConfig BGP commit-confirmed Set confirm via gnmic..."
    local confirm_peer="10.0.0.4"
    local confirm_peer_path="$OC_BGP/neighbors/neighbor[neighbor-address=$confirm_peer]"
    gnmic_set_ok "Commit-confirmed Set request" \
        --commit-id m54-confirm \
        --commit-request \
        --rollback-duration 120s \
        --update "$confirm_peer_path/config/peer-as:::uint:::65004"
    gnmic_set_ok "Commit-confirmed Set confirm" \
        --commit-id m54-confirm \
        --commit-confirm
    local after_confirm
    after_confirm=$(gnmic_get_ok "Get neighbors after commit confirm" \
        --encoding json_ietf \
        --type STATE \
        --path "$OC_BGP/neighbors")
    assert_contains "Commit-confirmed Set confirm keeps neighbor" "$after_confirm" "$confirm_peer"
    assert_contains "Commit-confirmed Set confirm keeps peer AS" "$after_confirm" '65004'

    log "Checking OpenConfig BGP commit-confirmed Set cancel via gnmic..."
    local cancel_peer="10.0.0.5"
    local cancel_peer_path="$OC_BGP/neighbors/neighbor[neighbor-address=$cancel_peer]"
    gnmic_set_ok "Commit-confirmed Set request before cancel" \
        --commit-id m54-cancel \
        --commit-request \
        --rollback-duration 120s \
        --update "$cancel_peer_path/config/peer-as:::uint:::65005"
    local pending_cancel
    pending_cancel=$(gnmic_get_ok "Get neighbors before commit cancel" \
        --encoding json_ietf \
        --type STATE \
        --path "$OC_BGP/neighbors")
    assert_contains "Commit-confirmed Set request exposes pending neighbor" "$pending_cancel" "$cancel_peer"
    gnmic_set_ok "Commit-confirmed Set cancel" \
        --commit-id m54-cancel \
        --commit-cancel
    local after_cancel
    after_cancel=$(gnmic_get_ok "Get neighbors after commit cancel" \
        --encoding json_ietf \
        --type STATE \
        --path "$OC_BGP/neighbors")
    assert_not_contains "Commit-confirmed Set cancel rolls back neighbor" "$after_cancel" "$cancel_peer"

    log "Checking gNMI Set authorization + unsupported-path rejection..."
    # observer maps to the read-tier observer role; gNMI Set is operator_only,
    # so the tier gate must deny it before any mutation reaches the bridge.
    local denied_peer="10.0.0.6"
    local denied_path="$OC_BGP/neighbors/neighbor[neighbor-address=$denied_peer]"
    gnmic_set_rejected "observer principal CANNOT Set static neighbor (PermissionDenied)" \
        "PermissionDenied" observer \
        --update "$denied_path/config/peer-as:::uint:::65006"
    local after_denied
    after_denied=$(gnmic_get_ok "Get neighbors after denied Set" \
        --encoding json_ietf \
        --type STATE \
        --path "$OC_BGP/neighbors")
    assert_not_contains "Denied Set did not mutate config" "$after_denied" "$denied_peer"

    # operator is authorized, but local-as is not a transaction-backed Set
    # leaf yet — the bridge must reject it as Unimplemented, not apply it.
    gnmic_set_rejected "operator Set of unsupported leaf is Unimplemented" \
        "Unimplemented" operator \
        --update "$OC_BGP/neighbors/neighbor[neighbor-address=10.0.0.2]/config/local-as:::uint:::65099"

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
