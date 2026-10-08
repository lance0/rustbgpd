#!/usr/bin/env bash
# M115 interop test — conditional advertisement (advertise-if-absent)
#
# Validates: conditional advertisement m115-backup, attached to frr-b with
# advertise_if = "absent" and settle_time = 2, advertises the payload prefix
# 198.51.100.0/24 to frr-b only while the condition prefix 192.0.2.0/24 is
# absent from rustbgpd's RIB. frr-a sources all three prefixes:
#   1. condition present: frr-b does not receive the payload, explain stops it
#      with conditional_advertisement_suppressed, and the metrics read
#      present / not permitted;
#   2. frr-a withdraws the condition: after settle_time frr-b receives the
#      payload with rustbgpd's next hop, explain passes it, and the metrics
#      read absent / permitted;
#   3. frr-a re-announces the condition: after settle_time the payload is
#      withdrawn from frr-b and phase 1 holds again.
# The control prefix 198.51.101.0/24, outside the definition, stays on frr-b
# throughout.
#
# Evidence:
#   - FRR's pre-policy Adj-RIB-In on frr-b (`received-routes`);
#   - rustbgpd's ExplainAdvertisedRoute gate ladder and Prometheus metrics;
#   - a tshark capture in rustbgpd's network namespace, judged by
#     m115_wire_oracle.py: exact receiver-bound event order, one announcement
#     and no withdrawal of the control, exactly one NEXT_HOP per announcement,
#     each payload change at least settle_time after the source's condition
#     change, no MP_REACH_NLRI / MP_UNREACH_NLRI, and no NOTIFICATION apart
#     from a listed Cease / collision resolution on the source session before
#     it is Established;
#   - both FRR sessions stay on their first connection.
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m115-conditional-advertisement-frr.clab.yml
#   - grpcurl, jq, curl and python3 on the host
#   - capture image: docker build -t bmpsink:m115 -f tests/interop/Dockerfile.bmpsink tests/interop
#     (override with M115_CAPTURE_IMAGE)
#
# Usage:
#   bash tests/interop/scripts/test-m115-conditional-advertisement-frr.sh

TOPO="m115-conditional-advertisement-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

FRR_A="clab-${TOPO}-frr-a"
FRR_B="clab-${TOPO}-frr-b"
SOURCE_ADDR="10.115.0.2"
RECEIVER_ADDR="10.115.1.2"
# rustbgpd's address on frr-b's session: eBGP export sets it as NEXT_HOP.
EXPORT_NH="10.115.1.1"
CONDITION="192.0.2.0/24"
PAYLOAD="198.51.100.0/24"
CONTROL="198.51.101.0/24"
DEFINITION="m115-backup"
SETTLE=2

CAPTURE_IMAGE="${M115_CAPTURE_IMAGE:-bmpsink:m115}"
CAPTURE_CONTAINER="m115-capture-$$"
CAPTURE_DIR="$(mktemp -d /tmp/m115-capture.XXXXXX)"

m115_on_exit() {
    local exit_code=$?
    trap - EXIT INT TERM HUP
    set +e
    docker rm -f "$CAPTURE_CONTAINER" >/dev/null 2>&1
    rm -rf "$CAPTURE_DIR"
    _cleanup_on_exit
    exit "$exit_code"
}
trap m115_on_exit EXIT

# Arm the capture in rustbgpd's network namespace before the daemon starts, so
# every UPDATE in both directions is on it.
start_capture() {
    if ! docker image inspect "$CAPTURE_IMAGE" >/dev/null 2>&1; then
        echo "ERROR: capture image $CAPTURE_IMAGE missing; build it from tests/interop/Dockerfile.bmpsink" >&2
        exit 1
    fi
    log "Starting tshark capture in rustbgpd's network namespace"
    docker run -d --name "$CAPTURE_CONTAINER" \
        --network "container:$RUSTBGPD" \
        --cap-add=NET_ADMIN --cap-add=NET_RAW \
        "$CAPTURE_IMAGE" tshark -p -i any -f 'tcp port 179' -w /tmp/m115.pcap >/dev/null
    wait_capture_ready "$CAPTURE_CONTAINER" /tmp/m115.pcap - || exit 1
    ok "capture armed before rustbgpd startup"
}

stop_capture() {
    local status
    docker kill --signal=INT "$CAPTURE_CONTAINER" >/dev/null
    status=$(timeout 15 docker wait "$CAPTURE_CONTAINER")
    case "$status" in
        0|130) ;;
        *)
            echo "ERROR: tshark capture exited with status '$status'" >&2
            docker logs "$CAPTURE_CONTAINER" >&2 || true
            exit 1
            ;;
    esac
    docker cp -q "$CAPTURE_CONTAINER:/tmp/m115.pcap" "$CAPTURE_DIR/m115.pcap"
    docker run --rm -v "$CAPTURE_DIR:/capture:ro" "$CAPTURE_IMAGE" \
        tshark -r /capture/m115.pcap -Y bgp -T pdml >"$CAPTURE_DIR/m115.pdml"
}

# Add or remove (`no`) a `network` statement on frr-a.
frr_a_network() {
    local negate=${1?} prefix=${2:?}
    docker exec "$FRR_A" vtysh -c "configure terminal" -c "router bgp 65002" \
        -c "address-family ipv4 unicast" -c "${negate:+no }network $prefix" >/dev/null
}

# Pre-policy Adj-RIB-In next hop frr-b recorded for PREFIX from rustbgpd.
received_next_hop() {
    local prefix=${1:?}
    docker exec "$FRR_B" vtysh -c "show bgp ipv4 unicast neighbors $EXPORT_NH received-routes json" 2>/dev/null \
        | jq -r --arg prefix "$prefix" '.receivedRoutes[$prefix].nextHop // empty'
}

has_received() { [ -n "$(received_next_hop "$1")" ]; }
lacks_received() { [ -z "$(received_next_hop "$1")" ]; }
has_condition_and_control() { has_received "$CONDITION" && has_received "$CONTROL"; }

# Value of the one series of metric NAME carrying every LABEL (`key="value"`).
ca_metric() {
    local name=${1:?} scrape
    shift
    scrape=$(prom_scrape "$RUSTBGPD")
    awk -v n="$name{" -v want="$*" '
        index($1, n) == 1 {
            k = split(want, w, " "); hit = 1
            for (i = 1; i <= k; i++) if (index($1, w[i]) == 0) hit = 0
            if (hit) print $2
        }' <<<"$scrape"
}

# "condition-state permitted", e.g. "present 0"; empty if any series is missing.
ca_state() {
    local state value permitted current=""
    for state in present absent unknown; do
        value=$(ca_metric bgp_conditional_advertisement_condition "name=\"$DEFINITION\"" "state=\"$state\"")
        [ -n "$value" ] || return 0
        [ "$value" = 1 ] && current="${current:+$current+}$state"
    done
    permitted=$(ca_metric bgp_conditional_advertisement_permitted "name=\"$DEFINITION\"" 'advertise_if="absent"')
    [ -n "$permitted" ] && echo "$current $permitted"
}

ca_state_is() { [ "$(ca_state)" = "$1" ]; }

assert_ca_state() {
    local expected=${1:?} actual
    actual=$(ca_state)
    if [ "$actual" = "$expected" ]; then
        ok "metrics: condition/permitted = $expected"
    else
        fail "metrics: condition/permitted = '$actual', expected '$expected'"
    fi
}

# "<verdict> <code>" of the conditional_advertisement rung for PREFIX to frr-b.
ca_gate() {
    local prefix=${1:?}
    grpcurl_call -d "{\"peer_address\": \"$RECEIVER_ADDR\", \"prefix\": \"${prefix%/*}\", \"prefix_length\": ${prefix#*/}}" \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ExplainAdvertisedRoute 2>/dev/null \
        | jq -r '[.gates[]? | select(.gate == "conditional_advertisement") | "\(.verdict) \(.code // "")"] | join(",")'
}

assert_ca_gate() {
    local prefix=${1:?} expected=${2:?} actual
    actual=$(ca_gate "$prefix")
    if [ "$actual" = "$expected" ]; then
        ok "explain: $prefix conditional_advertisement rung = $expected"
    else
        fail "explain: $prefix conditional_advertisement rung = '$actual', expected '$expected'"
    fi
}

in_best_routes() {
    local prefix=${1:?}
    grpcurl_call "$GRPC_ADDR" rustbgpd.v1.RibService/ListBestRoutes 2>/dev/null \
        | jq -e --arg addr "${prefix%/*}" --argjson len "${prefix#*/}" \
            'any(.routes[]?; .prefix == $addr and .prefixLength == $len)' >/dev/null
}

# expect_frr_b PAYLOAD-STATE CONDITION-STATE: each is "present" or "absent".
# The control prefix must always be present with rustbgpd's next hop.
expect_frr_b() {
    local want_payload=${1:?} want_condition=${2:?} prefix want actual
    for prefix in "$PAYLOAD:$want_payload" "$CONDITION:$want_condition" "$CONTROL:present"; do
        want=${prefix#*:}
        prefix=${prefix%%:*}
        actual=$(received_next_hop "$prefix")
        if [ "$want" = absent ] && [ -z "$actual" ]; then
            ok "frr-b does not hold $prefix"
        elif [ "$want" = present ] && [ "$actual" = "$EXPORT_NH" ]; then
            ok "frr-b holds $prefix with next hop $EXPORT_NH"
        else
            fail "frr-b holds $prefix with next hop '${actual}', expected $want"
        fi
    done
}

assert_first_connection() {
    local frr=${1:?} peer=${2:?} counters
    counters=$(docker exec "$frr" vtysh -c "show bgp neighbors $peer json" 2>/dev/null \
        | jq -r --arg peer "$peer" '.[$peer] | "\(.bgpState) \(.connectionsEstablished) \(.connectionsDropped)"')
    if [ "$counters" = "Established 1 0" ]; then
        ok "$frr session stayed on its first connection"
    else
        fail "$frr session state/established/dropped = '$counters', expected 'Established 1 0'"
    fi
}

# wait_or_fail DESCRIPTION SECONDS COMMAND [ARGS...]
wait_or_fail() {
    local what=${1:?} seconds=${2:?}
    shift 2
    if wait_until "$seconds" 1 "$@"; then
        ok "$what"
    else
        fail "$what: not observed within ${seconds}s"
    fi
}

# Judge the capture: the oracle runs to completion first, so a parse failure
# or a short verdict list is a FAIL.
assert_wire() {
    local want=7 got=0 verdicts verdict message
    if ! verdicts=$(python3 "$SCRIPT_DIR/m115_wire_oracle.py" "$CAPTURE_DIR/m115.pdml" \
        "$SOURCE_ADDR" "$RECEIVER_ADDR" "$EXPORT_NH" "$CONDITION" "$PAYLOAD" "$CONTROL" "$SETTLE"); then
        fail "wire: oracle could not judge the capture"
        return
    fi
    while read -r verdict message; do
        [ -n "$verdict" ] || continue
        got=$((got + 1))
        if [ "$verdict" = PASS ]; then ok "wire: $message"; else fail "wire: $message"; fi
    done <<<"$verdicts"
    if [ "$got" -ne "$want" ]; then
        fail "wire: oracle returned $got verdict(s), expected $want"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "M115 interop test: conditional advertisement (advertise-if-absent)"
    log "Topology: $TOPO"

    if docker exec "$RUSTBGPD" rustbgpd --check /etc/rustbgpd/config.toml >/dev/null 2>&1; then
        ok "rustbgpd accepts the M115 config"
    else
        fail "rustbgpd rejected the M115 config"
    fi

    resolve_grpc_addr
    start_capture
    # shellcheck disable=SC2119 # no argument selects the standard start wrapper
    start_rustbgpd

    wait_frr_established "$FRR_A" 10.115.0.1 "$FRR_A" || true
    wait_frr_established "$FRR_B" "$EXPORT_NH" "$FRR_B" || true

    log "Phase 1: condition present, payload added"
    wait_or_fail "frr-b received the condition and the control" 30 has_condition_and_control
    # The payload is added only after the condition has settled present, so
    # the startup pending window cannot leak it.
    wait_or_fail "condition settled present, payload not permitted" 20 ca_state_is "present 0"
    frr_a_network "" "$PAYLOAD"
    wait_or_fail "rustbgpd selected the payload" 20 in_best_routes "$PAYLOAD"
    # The gate is already applied; allow far longer than settle_time for a leak.
    sleep $((SETTLE * 3))
    expect_frr_b absent present
    assert_ca_gate "$PAYLOAD" "EXPORT_GATE_VERDICT_STOP conditional_advertisement_suppressed"
    # Outside the definition: the gate does not apply to the control.
    assert_ca_gate "$CONTROL" "EXPORT_GATE_VERDICT_NOT_APPLICABLE conditional_advertisement"
    assert_ca_state "present 0"

    log "Phase 2: frr-a withdraws the condition"
    frr_a_network no "$CONDITION"
    wait_or_fail "frr-b received the payload" 30 has_received "$PAYLOAD"
    expect_frr_b present absent
    assert_ca_gate "$PAYLOAD" "EXPORT_GATE_VERDICT_PASS conditional_advertisement"
    assert_ca_state "absent 1"

    log "Phase 3: frr-a re-announces the condition"
    frr_a_network "" "$CONDITION"
    wait_or_fail "payload withdrawn from frr-b" 30 lacks_received "$PAYLOAD"
    expect_frr_b absent present
    assert_ca_gate "$PAYLOAD" "EXPORT_GATE_VERDICT_STOP conditional_advertisement_suppressed"
    assert_ca_state "present 0"

    assert_first_connection "$FRR_A" 10.115.0.1
    assert_first_connection "$FRR_B" "$EXPORT_NH"

    stop_capture
    assert_wire

    print_summary
}

main "$@"
