#!/usr/bin/env bash
# Load-bearing negative controls:
# - Removing type-17 reconstruction makes the canonical accepted-path check red.
# - Bypassing inbound RFC 6793 reconstruction admits 203.0.113.94/32 instead of
#   retaining it as an as_path_loop rejection.
# - Removing type-17 projection makes the independent sink path check red.
# - Removing type-18 projection makes the independent sink aggregator check red.

TOPO="m94-as4-migration-exabgp"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

SOURCE="clab-${TOPO}-exa-source"
PROXY="clab-${TOPO}-old-proxy"
SINK="clab-${TOPO}-old-sink"
SOURCE_PEER="10.94.0.2"
SINK_PEER="10.94.1.3"
ACCEPTED_PREFIX="203.0.113.95/32"
LOOP_PREFIX="203.0.113.94/32"

rbgp() {
    docker exec "$RUSTBGPD" rbgp -s http://127.0.0.1:50051 "$@"
}

assert_true() {
    local label=${1:?}; shift
    if "$@"; then ok "$label"; else fail "$label"; fi
}

wait_for() {
    local label=${1:?}; shift
    for i in $(seq 1 45); do
        if "$@"; then
            ok "$label (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$label timed out after 90s"
    return 1
}

neighbor_is_old_established() {
    local peer=${1:?}
    rbgp neighbor "$peer" -j 2>/dev/null | jq -e '
        .state == "Established"
        and .negotiated_session.four_octet_as == false
    ' >/dev/null
}

source_projection_is_exact() {
    docker exec "$PROXY" cat /tmp/m94-source-receipt.json 2>/dev/null | jq -e '
        .negotiated_as4 == false
        and .exa_advertised_as4 == false
        and .rust_advertised_as4 == true
        and .accepted_prefix == "203.0.113.95/32"
        and .accepted_projection.as_path == [65010, 23456]
        and .accepted_projection.as4_path == [65010, 4200000194]
        and .accepted_projection.aggregator_as == 23456
        and .accepted_projection.aggregator_router_id == "10.94.0.2"
        and .accepted_projection.as4_aggregator_as == 4200000294
        and .accepted_projection.as4_aggregator_router_id == "10.94.0.2"
        and .loop_prefix == "203.0.113.94/32"
        and .loop_as_path == [65010, 23456]
        and .loop_as4_path == [65010, 4200000094]
    ' >/dev/null
}

accepted_route_is_exact() {
    rbgp rib received "$SOURCE_PEER" -j 2>/dev/null | jq -e \
        --arg prefix "$ACCEPTED_PREFIX" '
        [.[] | select(.prefix == $prefix and .as_path == [65010, 4200000194])]
        | length == 1
    ' >/dev/null
}

accepted_route_is_absent() {
    rbgp rib received "$SOURCE_PEER" -j 2>/dev/null | jq -e \
        --arg prefix "$ACCEPTED_PREFIX" '
        [.[] | select(.prefix == $prefix)] | length == 0
    ' >/dev/null
}

loop_route_is_rejected() {
    rbgp rib received "$SOURCE_PEER" --rejected -j 2>/dev/null | jq -e \
        --arg prefix "$LOOP_PREFIX" '
        [.rejected_routes[] |
            select(.prefix == $prefix
                   and .reason == "as_path_loop"
                   and .as_path == "65010 4200000094")]
        | length == 1
    ' >/dev/null
}

sink_announce_is_exact() {
    docker exec "$SINK" cat /tmp/m94-sink-receipt.json 2>/dev/null | jq -e '
        .announced == true
        and .withdrawn == false
        and .negotiated_as4 == false
        and .peer_open_my_as == 23456
        and .peer_advertised_as4 == true
        and .as_path == [65010, 23456]
        and .as4_path == [65010, 4200000194]
        and .aggregator_as == 23456
        and .aggregator_router_id == "10.94.0.2"
        and .as4_aggregator_as == 4200000294
        and .as4_aggregator_router_id == "10.94.0.2"
    ' >/dev/null
}

sink_observed_withdrawal() {
    docker exec "$SINK" cat /tmp/m94-sink-receipt.json 2>/dev/null \
        | jq -e '.announced == true and .withdrawn == true' >/dev/null
}

main() {
    log "M94: RFC 6793 AS4 migration with independent source and sink witnesses"
    resolve_grpc_addr

    docker exec -d "$PROXY" sh -c \
        'exec python3 /usr/local/bin/m94_as4_oracle.py proxy /tmp/m94-source-receipt.json >/tmp/m94-proxy.log 2>&1'
    docker exec -d "$SINK" sh -c \
        'exec python3 /usr/local/bin/m94_as4_oracle.py sink /tmp/m94-sink-receipt.json >/tmp/m94-sink.log 2>&1'
    start_rustbgpd /usr/local/bin/start-rustbgpd.sh
    docker exec "$SOURCE" exabgp validate /fixtures/exabgp.conf >/dev/null
    docker exec -d "$SOURCE" sh -c \
        'exec exabgp server /fixtures/exabgp.conf >/tmp/m94-exabgp.log 2>&1'

    wait_for "rustbgpd/ExaBGP session negotiated without ASN4" \
        neighbor_is_old_established "$SOURCE_PEER" || true
    wait_for "rustbgpd/independent sink session negotiated without ASN4" \
        neighbor_is_old_established "$SINK_PEER" || true
    wait_for "bounded proxy sees ExaBGP OLD OPEN and exact source projection" \
        source_projection_is_exact || true

    wait_for "accepted route has its reconstructed four-octet path" \
        accepted_route_is_exact || true
    wait_for "local-AS loop is rejected only after reconstruction" \
        loop_route_is_rejected || true
    wait_for "independent sink sees exact AS4_PATH and AS4_AGGREGATOR" \
        sink_announce_is_exact || true

    assert_true "source session remains Established" \
        neighbor_is_old_established "$SOURCE_PEER"
    assert_true "sink session remains Established" \
        neighbor_is_old_established "$SINK_PEER"

    docker exec "$SOURCE" touch /tmp/m94-withdraw
    wait_for "independent sink observes the withdrawal" sink_observed_withdrawal || true
    wait_for "withdrawn route leaves the received RIB" accepted_route_is_absent || true
    assert_true "source session remains Established after withdrawal" \
        neighbor_is_old_established "$SOURCE_PEER"
    assert_true "sink session remains Established after withdrawal" \
        neighbor_is_old_established "$SINK_PEER"

    log "Results: $pass passed, $fail failed"
    [ "$fail" -eq 0 ]
}

main "$@"
