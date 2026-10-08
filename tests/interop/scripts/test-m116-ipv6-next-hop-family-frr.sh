#!/usr/bin/env bash
# M116 interop test — IPv6 routes keep an IPv6 next hop over IPv4 transport
#
# Validates: IPv6 unicast routes learned and advertised over IPv4-transport
# sessions reach an iBGP receiver and a route-server client with an IPv6 next
# hop, never an IPv4 one:
#   - 2001:db8:1160::/48, import `next-hop self`: the source session is IPv4,
#     so self resolves to the neighbor's local_ipv6_nexthop 2001:db8:116::1;
#   - 2001:db8:1161::/48, import `set_next_hop = "10.116.0.99"`: an IPv4 next
#     hop does not apply to an IPv6 route, which keeps the received
#     2001:db8:116::2;
#   - 2001:db8:1162::/48, export `set_next_hop` to an IPv4 address on both
#     receivers: likewise not applied, so the route keeps 2001:db8:116::2.
#
# Evidence, per receiver and prefix:
#   - rustbgpd's best route next hop (gRPC), localizing a failure to import;
#   - FRR's pre-policy Adj-RIB-In (`received-routes`, soft-reconfiguration):
#     the route is present, so it was not treated as withdrawn, and carries
#     the expected next hop;
#   - a tshark capture in rustbgpd's network namespace, judged from raw
#     MP_REACH_NLRI bytes: every UPDATE announcing the prefix has a 16- or
#     32-octet next hop with the expected global address, no receiver-bound
#     IPv6 MP_REACH_NLRI has any other next-hop length, and no NOTIFICATION is
#     sent or received;
#   - both receiver sessions stay on their first connection.
#
# Topology: frr-source (eBGP) -> rustbgpd -> frr-ibgp (iBGP) + frr-rs (RS client)
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m116-ipv6-next-hop-family-frr.clab.yml
#   - grpcurl, jq and python3 on the host
#   - capture image: docker build -t bmpsink:m116 -f tests/interop/Dockerfile.bmpsink tests/interop
#     (override with M116_CAPTURE_IMAGE)
#
# Usage:
#   bash tests/interop/scripts/test-m116-ipv6-next-hop-family-frr.sh

TOPO="m116-ipv6-next-hop-family-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

FRR_SOURCE="clab-${TOPO}-frr-source"
FRR_IBGP="clab-${TOPO}-frr-ibgp"
FRR_RS="clab-${TOPO}-frr-rs"
SELF_PREFIX="2001:db8:1160::/48"
IMPORT_V4_PREFIX="2001:db8:1161::/48"
EXPORT_V4_PREFIX="2001:db8:1162::/48"
SELF_NH="2001:db8:116::1"
RECEIVED_NH="2001:db8:116::2"

CAPTURE_IMAGE="${M116_CAPTURE_IMAGE:-bmpsink:m116}"
CAPTURE_CONTAINER="m116-capture-$$"
CAPTURE_DIR="$(mktemp -d /tmp/m116-capture.XXXXXX)"

m116_on_exit() {
    local exit_code=$?
    trap - EXIT INT TERM HUP
    set +e
    docker rm -f "$CAPTURE_CONTAINER" >/dev/null 2>&1
    rm -rf "$CAPTURE_DIR"
    _cleanup_on_exit
    exit "$exit_code"
}
trap m116_on_exit EXIT

# Arm the capture in rustbgpd's network namespace before the daemon starts, so
# every UPDATE toward the receivers is on it.
start_capture() {
    if ! docker image inspect "$CAPTURE_IMAGE" >/dev/null 2>&1; then
        echo "ERROR: capture image $CAPTURE_IMAGE missing; build it from tests/interop/Dockerfile.bmpsink" >&2
        exit 1
    fi
    log "Starting tshark capture in rustbgpd's network namespace"
    docker run -d --name "$CAPTURE_CONTAINER" \
        --network "container:$RUSTBGPD" \
        --cap-add=NET_ADMIN --cap-add=NET_RAW \
        "$CAPTURE_IMAGE" tshark -p -i any -f 'tcp port 179' -w /tmp/m116.pcap >/dev/null
    wait_capture_ready "$CAPTURE_CONTAINER" /tmp/m116.pcap - || exit 1
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
    docker cp -q "$CAPTURE_CONTAINER:/tmp/m116.pcap" "$CAPTURE_DIR/m116.pcap"
    docker run --rm -v "$CAPTURE_DIR:/capture:ro" "$CAPTURE_IMAGE" \
        tshark -r /capture/m116.pcap -Y bgp -T pdml >"$CAPTURE_DIR/m116.pdml"
}

# Pre-policy Adj-RIB-In next hop FRR recorded for PREFIX from rustbgpd.
received_next_hop() {
    local frr=${1:?} peer=${2:?} prefix=${3:?}
    docker exec "$frr" vtysh -c "show bgp ipv6 unicast neighbors $peer received-routes json" 2>/dev/null \
        | jq -r --arg prefix "$prefix" '.receivedRoutes[$prefix] | .nextHopGlobal // .nextHop // empty'
}

wait_received() {
    local frr=${1:?} peer=${2:?} prefix=${3:?}
    log "Waiting for $frr to receive $prefix"
    for i in $(seq 1 30); do
        if [ -n "$(received_next_hop "$frr" "$peer" "$prefix")" ]; then
            ok "$frr received $prefix (attempt $i)"
            return 0
        fi
        sleep 1
    done
    fail "$frr did not receive $prefix within 30s"
    return 1
}

assert_received_next_hop() {
    local frr=${1:?} peer=${2:?} prefix=${3:?} expected=${4:?}
    local actual
    actual=$(received_next_hop "$frr" "$peer" "$prefix")
    if [ "$actual" = "$expected" ]; then
        ok "$frr received $prefix with next hop $expected"
    else
        fail "$frr received $prefix with next hop '${actual}', expected $expected"
    fi
}

# rustbgpd's own best route next hop; localizes a failure to import or export.
assert_rib_next_hop() {
    local prefix=${1:?} expected=${2:?} actual
    actual=$(grpcurl_call "$GRPC_ADDR" rustbgpd.v1.RibService/ListBestRoutes 2>/dev/null \
        | jq -r --arg addr "${prefix%/*}" --argjson len "${prefix#*/}" \
            '[.routes[]? | select(.prefix == $addr and .prefixLength == $len) | .nextHop] | join(",")')
    if [ "$actual" = "$expected" ]; then
        ok "rustbgpd best route $prefix has next hop $expected"
    else
        fail "rustbgpd best route $prefix has next hop '${actual}', expected $expected"
    fi
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

# Judge the capture with m116_wire_oracle.py: one verdict per expectation,
# then one for every receiver-bound IPv6 MP_REACH_NLRI and one for
# NOTIFICATION. The oracle runs to completion first, so a parse failure or a
# short verdict list is a FAIL.
assert_wire() {
    local -a expected=(
        10.116.1.2 "$SELF_PREFIX" "$SELF_NH"
        10.116.1.2 "$IMPORT_V4_PREFIX" "$RECEIVED_NH"
        10.116.1.2 "$EXPORT_V4_PREFIX" "$RECEIVED_NH"
        10.116.2.2 "$SELF_PREFIX" "$SELF_NH"
        10.116.2.2 "$IMPORT_V4_PREFIX" "$RECEIVED_NH"
        10.116.2.2 "$EXPORT_V4_PREFIX" "$RECEIVED_NH"
    )
    local want=$((${#expected[@]} / 3 + 2)) got=0 verdicts verdict message
    if ! verdicts=$(python3 "$SCRIPT_DIR/m116_wire_oracle.py" "$CAPTURE_DIR/m116.pdml" "${expected[@]}"); then
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
    log "M116 interop test: IPv6 routes keep an IPv6 next hop over IPv4 transport"
    log "Topology: $TOPO"

    if docker exec "$RUSTBGPD" rustbgpd --check /etc/rustbgpd/config.toml >/dev/null 2>&1; then
        ok "rustbgpd accepts the M116 config"
    else
        fail "rustbgpd rejected the M116 config"
    fi

    resolve_grpc_addr
    start_capture
    # shellcheck disable=SC2119 # no argument selects the standard start wrapper
    start_rustbgpd

    wait_frr_established "$FRR_SOURCE" 10.116.0.1 "$FRR_SOURCE" || true
    wait_frr_established "$FRR_IBGP" 10.116.1.1 "$FRR_IBGP" || true
    wait_frr_established "$FRR_RS" 10.116.2.1 "$FRR_RS" || true

    for frr_peer in "$FRR_IBGP 10.116.1.1" "$FRR_RS 10.116.2.1"; do
        # shellcheck disable=SC2086 # deliberate split into container and peer
        set -- $frr_peer
        wait_received "$1" "$2" "$SELF_PREFIX" || true
        wait_received "$1" "$2" "$IMPORT_V4_PREFIX" || true
        wait_received "$1" "$2" "$EXPORT_V4_PREFIX" || true
    done

    assert_rib_next_hop "$SELF_PREFIX" "$SELF_NH"
    assert_rib_next_hop "$IMPORT_V4_PREFIX" "$RECEIVED_NH"
    assert_rib_next_hop "$EXPORT_V4_PREFIX" "$RECEIVED_NH"

    for frr_peer in "$FRR_IBGP 10.116.1.1" "$FRR_RS 10.116.2.1"; do
        # shellcheck disable=SC2086 # deliberate split into container and peer
        set -- $frr_peer
        assert_received_next_hop "$1" "$2" "$SELF_PREFIX" "$SELF_NH"
        assert_received_next_hop "$1" "$2" "$IMPORT_V4_PREFIX" "$RECEIVED_NH"
        assert_received_next_hop "$1" "$2" "$EXPORT_V4_PREFIX" "$RECEIVED_NH"
        assert_first_connection "$1" "$2"
    done

    stop_capture
    assert_wire

    print_summary
}

main "$@"
