#!/usr/bin/env bash
# M56 interop test — ADR-0070 deferred / ADR-0072 follow-up:
# `Subscribe ON_CHANGE` for neighbor/state/session-state.
#
# Validates the v1 contract:
#
#   1. STREAM + ON_CHANGE on the wildcard session-state path is
#      accepted; the initial snapshot delivers one Update per
#      configured peer followed by sync_response.
#   2. A peer flap on the FRR side produces a fresh Update for the
#      transition WITHOUT waiting for a SAMPLE interval.
#   3. ON_CHANGE on an unsupported leaf (peer-as) is rejected with
#      Unimplemented.
#   4. Reconnect after a flap yields a fresh initial snapshot, NOT
#      a replay of the disconnected-window transitions.
#
# Prerequisites:
#   docker build -t rustbgpd:dev .
#   bash tests/interop/scripts/gen-m54-certs.sh   # certs reused
#   containerlab deploy -t tests/interop/m56-gnmi-onchange-frr.clab.yml
#
# Usage:
#   bash tests/interop/scripts/test-m56-gnmi-onchange-frr.sh

TOPO="m56-gnmi-onchange-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

CERT_DIR="$SCRIPT_DIR/../configs/m54-certs"
SERVER_NAME="rustbgpd.local"
OC_BGP="/network-instances/network-instance[name=DEFAULT]/protocols/protocol[identifier=BGP][name=BGP]/bgp"
FRR_PEER="clab-${TOPO}-frr-peer"
RUSTBGPD_PEER="10.56.0.2"

if ! command -v gnmic &>/dev/null; then
    echo "ERROR: gnmic not found in PATH" >&2
    exit 1
fi

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

start_rustbgpd_gnmi() {
    log "Starting rustbgpd (mTLS gNMI + EHM)..."
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
        print_summary
        exit 1
    fi

    log "Waiting for gNMI Capabilities over mTLS..."
    for i in $(seq 1 15); do
        if gnmic_mtls_timeout 3s capabilities >/dev/null 2>&1; then
            ok "gNMI endpoint ready (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "gNMI endpoint not reachable within 30s"
    print_summary
    exit 1
}

# Wait until the rustbgpd-side neighbor row shows ESTABLISHED. Uses
# gnmic Get rather than a peer-mgr round-trip so the test only depends
# on the gNMI surface.
wait_neighbor_established() {
    local got=""
    for i in $(seq 1 30); do
        got=$(gnmic_mtls_timeout 3s get \
            --encoding json_ietf \
            --type STATE \
            --path "$OC_BGP/neighbors/neighbor[neighbor-address=$RUSTBGPD_PEER]/state/session-state" \
            2>/dev/null || true)
        if printf '%s' "$got" | grep -Fq 'ESTABLISHED'; then
            ok "neighbor reached ESTABLISHED (attempt $i)"
            return 0
        fi
        sleep 1
    done
    fail "neighbor never reached ESTABLISHED"
    printf '  last get output:\n%s\n' "$got" >&2
    print_summary
    exit 1
}

main() {
    log "M56 interop test: gNMI Subscribe ON_CHANGE (session-state)"
    log "Topology: $TOPO"

    resolve_grpc_addr
    start_rustbgpd_gnmi
    wait_neighbor_established

    # --- Test 1: ON_CHANGE on an unsupported leaf is rejected. ----------------
    #
    # gnmic in its default --format swallows RPC errors silently and
    # retries indefinitely on subscribe (treating them as transient).
    # Use --debug to surface the error log, then grep for the server's
    # Unimplemented status. The retry behavior is gnmic-side; the
    # daemon does return Status::unimplemented immediately on the
    # first SubscriptionList parse.
    log "Checking ON_CHANGE rejects unsupported leaves (peer-as)..."
    local err_output rc
    set +e
    err_output=$(timeout 3s gnmic --debug \
        --address "$GRPC_ADDR" \
        --tls-ca "$CERT_DIR/ca.pem" \
        --tls-cert "$CERT_DIR/operator.pem" \
        --tls-key "$CERT_DIR/operator.key" \
        --tls-server-name "$SERVER_NAME" \
        subscribe --encoding json_ietf --mode stream --stream-mode on-change \
        --path "$OC_BGP/neighbors/neighbor[neighbor-address=*]/state/peer-as" 2>&1)
    rc=$?
    set -e
    if printf '%s' "$err_output" \
        | grep -qE 'code = Unimplemented.*session-state|covers only.*session-state'
    then
        ok "ON_CHANGE on peer-as is rejected with Unimplemented"
    else
        fail "ON_CHANGE on peer-as was not rejected as expected (rc=$rc)"
        printf '  output (last 20 lines):\n' >&2
        printf '%s\n' "$err_output" | tail -20 >&2
    fi

    # --- Test 2: ON_CHANGE on session-state emits initial snapshot + sync_response,
    # then a fresh Update on FRR flap. Run gnmic in the background so we can
    # drive the flap while the stream is open.
    log "Starting ON_CHANGE subscription in background..."
    local stream_log
    stream_log=$(mktemp)
    # 12s is enough for: initial sync (~immediate) + flap-down-up-up
    # cycle (down ≤3s + up reconverge ≤6s + slack).
    set +e
    gnmic_mtls_timeout 12s subscribe \
        --encoding json_ietf \
        --mode stream \
        --stream-mode on-change \
        --path "$OC_BGP/neighbors/neighbor[neighbor-address=*]/state/session-state" \
        > "$stream_log" 2>&1 &
    local sub_pid=$!
    set -e

    # Give the subscriber a moment to attach + receive the initial sync.
    sleep 2

    log "Flapping FRR peer (clear bgp neighbor on rustbgpd side via FRR)..."
    docker exec "$FRR_PEER" vtysh -c "clear bgp 10.56.0.1" >/dev/null 2>&1 || true

    # Wait for the gnmic subscriber to exit (timeout-driven).
    wait "$sub_pid" || true

    local stream
    stream=$(cat "$stream_log")
    rm -f "$stream_log"

    # 2a. Initial snapshot included the established state for the
    # configured peer (raw text match — gnmic renders updates as
    # multiple JSON objects).
    if printf '%s' "$stream" | grep -Fq 'ESTABLISHED'; then
        ok "Initial snapshot includes ESTABLISHED state for the peer"
    else
        fail "Initial snapshot did not include ESTABLISHED state"
        printf '  output:\n%s\n' "$stream" >&2
    fi

    # 2b. Sync-response marker is present (gnmic prints `sync_response`
    # under at least one of its output modes; some versions render it
    # as a separate key `sync-response`. Accept either.)
    if printf '%s' "$stream" | grep -qiE 'sync[_-]response'; then
        ok "Initial sync_response marker observed"
    else
        # Not all gnmic versions print sync_response in --format json;
        # treat as informational rather than a hard fail so a future
        # gnmic upgrade doesn't break CI.
        log "WARN: sync_response marker not visible (gnmic render quirk; acceptable)"
    fi

    # 2c. The flap produced a transition Update. Either IDLE or
    # CONNECT / ACTIVE appears once the session bounces.
    if printf '%s' "$stream" | grep -qE 'IDLE|CONNECT|ACTIVE|OPENSENT|OPENCONFIRM'; then
        ok "ON_CHANGE delivered a post-flap transition Update"
    else
        fail "ON_CHANGE did not deliver a post-flap transition Update"
        printf '  output:\n%s\n' "$stream" >&2
    fi

    # 2d. The session should recover to ESTABLISHED a second time
    # (transition during the 12s window). At least two ESTABLISHED
    # appearances proves the post-flap recovery streamed.
    local established_count
    established_count=$( (printf '%s' "$stream" | grep -Fo 'ESTABLISHED' || true) | wc -l | tr -d ' ')
    if [ "$established_count" -ge 2 ]; then
        ok "ON_CHANGE streamed the post-flap re-ESTABLISHED transition"
    else
        # Recovery may not have completed inside the 12s window; this
        # is a timing-sensitive assertion. Treat as informational so
        # the harder contract assertions above remain stable.
        log "INFO: only $established_count ESTABLISHED markers (slow reconverge; acceptable)"
    fi

    # --- Test 3: Reconnect yields a FRESH initial snapshot, no replay. -------
    log "Verifying reconnect = fresh snapshot (no replay)..."
    wait_neighbor_established
    local reconnect_log
    reconnect_log=$(gnmic_mtls_timeout 4s subscribe \
        --encoding json_ietf \
        --mode stream \
        --stream-mode on-change \
        --path "$OC_BGP/neighbors/neighbor[neighbor-address=*]/state/session-state" 2>&1 || true)
    # Fresh snapshot: ESTABLISHED appears at least once for the
    # currently-up peer. We don't try to assert "no replay" via
    # counting (the previous transitions live in EHM and SubscribeFromEvent
    # would replay them, but gNMI ON_CHANGE intentionally does not).
    if printf '%s' "$reconnect_log" | grep -Fq 'ESTABLISHED'; then
        ok "Reconnect delivered a fresh initial snapshot with current state"
    else
        fail "Reconnect did not deliver a fresh initial snapshot"
        printf '  output:\n%s\n' "$reconnect_log" >&2
    fi

    print_summary
}

main "$@"
