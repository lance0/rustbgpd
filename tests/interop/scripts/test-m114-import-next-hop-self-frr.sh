#!/usr/bin/env bash
# M114 interop test — import next-hop self on the wire
#
# Validates: a route whose import policy sets `next-hop self` is advertised to
# an iBGP receiver and to a route-server client with rustbgpd's own address
# (the local address of the source session, 10.114.0.1) as its NEXT_HOP. Both
# export paths keep the stored next hop, so neither may carry the received
# 10.114.0.2. An unrewritten control route must keep 10.114.0.2 on both.
#
# Evidence, per receiver and prefix:
#   - FRR's pre-policy Adj-RIB-In (`received-routes`, soft-reconfiguration);
#   - a tshark capture in rustbgpd's network namespace: every UPDATE carrying
#     the prefix has exactly one NEXT_HOP attribute, no MP_REACH_NLRI, and the
#     expected address; no NOTIFICATION is sent or received;
#   - both receiver sessions stay on their first connection.
#
# Topology: frr-source (eBGP) -> rustbgpd -> frr-ibgp (iBGP) + frr-rs (RS client)
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m114-import-next-hop-self-frr.clab.yml
#   - grpcurl, jq and python3 on the host
#   - capture image: docker build -t bmpsink:m114 -f tests/interop/Dockerfile.bmpsink tests/interop
#     (override with M114_CAPTURE_IMAGE)
#
# Usage:
#   bash tests/interop/scripts/test-m114-import-next-hop-self-frr.sh

TOPO="m114-import-next-hop-self-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

FRR_SOURCE="clab-${TOPO}-frr-source"
FRR_IBGP="clab-${TOPO}-frr-ibgp"
FRR_RS="clab-${TOPO}-frr-rs"
SELF_PREFIX="198.51.100.0/24"
CONTROL_PREFIX="198.51.101.0/24"
SELF_NH="10.114.0.1"
RECEIVED_NH="10.114.0.2"

CAPTURE_IMAGE="${M114_CAPTURE_IMAGE:-bmpsink:m114}"
CAPTURE_CONTAINER="m114-capture-$$"
CAPTURE_DIR="$(mktemp -d /tmp/m114-capture.XXXXXX)"

m114_on_exit() {
    local exit_code=$?
    trap - EXIT INT TERM HUP
    set +e
    docker rm -f "$CAPTURE_CONTAINER" >/dev/null 2>&1
    rm -rf "$CAPTURE_DIR"
    _cleanup_on_exit
    exit "$exit_code"
}
trap m114_on_exit EXIT

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
        "$CAPTURE_IMAGE" tshark -p -i any -f 'tcp port 179' -w /tmp/m114.pcap >/dev/null
    wait_capture_ready "$CAPTURE_CONTAINER" /tmp/m114.pcap - || exit 1
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
    docker cp -q "$CAPTURE_CONTAINER:/tmp/m114.pcap" "$CAPTURE_DIR/m114.pcap"
    docker run --rm -v "$CAPTURE_DIR:/capture:ro" "$CAPTURE_IMAGE" \
        tshark -r /capture/m114.pcap -Y bgp -T pdml >"$CAPTURE_DIR/m114.pdml"
}

# Pre-policy Adj-RIB-In next hop FRR recorded for PREFIX from rustbgpd.
received_next_hop() {
    local frr=${1:?} peer=${2:?} prefix=${3:?}
    docker exec "$frr" vtysh -c "show bgp ipv4 unicast neighbors $peer received-routes json" 2>/dev/null \
        | jq -r --arg prefix "$prefix" '.receivedRoutes[$prefix].nextHop // empty'
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

# rustbgpd's own best route already carries the rewritten next hop on main;
# this localizes a failure below to export.
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

# Judge the capture. Each <proto name="bgp"> in the PDML is one BGP message;
# the expectation list is "receiver prefix next-hop" triples.
assert_wire() {
    local verdict message
    while read -r verdict message; do
        if [ "$verdict" = PASS ]; then ok "wire: $message"; else fail "wire: $message"; fi
    done < <(python3 - "$CAPTURE_DIR/m114.pdml" \
        10.114.1.2 "$SELF_PREFIX" "$SELF_NH" \
        10.114.1.2 "$CONTROL_PREFIX" "$RECEIVED_NH" \
        10.114.2.2 "$SELF_PREFIX" "$SELF_NH" \
        10.114.2.2 "$CONTROL_PREFIX" "$RECEIVED_NH" <<'PY'
import sys
import xml.etree.ElementTree as ET

path, *flat = sys.argv[1:]
expected = [tuple(flat[i : i + 3]) for i in range(0, len(flat), 3)]
seen = {(dst, prefix): [] for dst, prefix, _ in expected}
notifications = 0


def fields(node, name):
    return [f for f in node.iter("field") if f.get("name") == name]


for packet in ET.parse(path).getroot().iter("packet"):
    ip = next((p for p in packet.iter("proto") if p.get("name") == "ip"), None)
    if ip is None:
        continue
    dst = fields(ip, "ip.dst")[0].get("show")
    for bgp in (p for p in packet.iter("proto") if p.get("name") == "bgp"):
        kind = fields(bgp, "bgp.type")
        if not kind:
            continue
        if kind[0].get("show") == "3":
            notifications += 1
        if kind[0].get("show") != "2":
            continue
        codes = [f.get("show") for f in fields(bgp, "bgp.update.path_attribute.type_code")]
        next_hops = [f.get("show") for f in fields(bgp, "bgp.update.path_attribute.next_hop")]
        prefixes = {
            f"{p.get('show')}/{n.get('show')}"
            for nlri in fields(bgp, "bgp.update.nlri")
            for p, n in zip(fields(nlri, "bgp.nlri_prefix"), fields(nlri, "bgp.prefix_length"))
        }
        for key in seen:
            if key[0] == dst and key[1] in prefixes:
                seen[key].append((codes.count("3"), codes.count("14"), next_hops))

for dst, prefix, next_hop in expected:
    updates = seen[(dst, prefix)]
    detail = (
        f"to {dst} {prefix}: {len(updates)} UPDATE(s), NEXT_HOP counts "
        f"{[u[0] for u in updates]}, MP_REACH counts {[u[1] for u in updates]}, "
        f"next hops {sorted({h for u in updates for h in u[2]})}"
    )
    good = updates and all(u[0] == 1 and u[1] == 0 and u[2] == [next_hop] for u in updates)
    print(
        ("PASS " if good else "FAIL ")
        + detail
        + ("" if good else f"; expected one NEXT_HOP {next_hop} per UPDATE")
    )
print(
    ("PASS" if notifications == 0 else "FAIL")
    + f" {notifications} NOTIFICATION message(s) captured"
)
PY
    )
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "M114 interop test: import next-hop self on the wire"
    log "Topology: $TOPO"

    if docker exec "$RUSTBGPD" rustbgpd --check /etc/rustbgpd/config.toml >/dev/null 2>&1; then
        ok "rustbgpd accepts the M114 config"
    else
        fail "rustbgpd rejected the M114 config"
    fi

    resolve_grpc_addr
    start_capture
    # shellcheck disable=SC2119 # no argument selects the standard start wrapper
    start_rustbgpd

    wait_frr_established "$FRR_SOURCE" 10.114.0.1 "$FRR_SOURCE" || true
    wait_frr_established "$FRR_IBGP" 10.114.1.1 "$FRR_IBGP" || true
    wait_frr_established "$FRR_RS" 10.114.2.1 "$FRR_RS" || true

    for frr_peer in "$FRR_IBGP 10.114.1.1" "$FRR_RS 10.114.2.1"; do
        # shellcheck disable=SC2086 # deliberate split into container and peer
        set -- $frr_peer
        wait_received "$1" "$2" "$SELF_PREFIX" || true
        wait_received "$1" "$2" "$CONTROL_PREFIX" || true
    done

    assert_rib_next_hop "$SELF_PREFIX" "$SELF_NH"
    assert_rib_next_hop "$CONTROL_PREFIX" "$RECEIVED_NH"

    assert_received_next_hop "$FRR_IBGP" 10.114.1.1 "$SELF_PREFIX" "$SELF_NH"
    assert_received_next_hop "$FRR_IBGP" 10.114.1.1 "$CONTROL_PREFIX" "$RECEIVED_NH"
    assert_received_next_hop "$FRR_RS" 10.114.2.1 "$SELF_PREFIX" "$SELF_NH"
    assert_received_next_hop "$FRR_RS" 10.114.2.1 "$CONTROL_PREFIX" "$RECEIVED_NH"

    assert_first_connection "$FRR_IBGP" 10.114.1.1
    assert_first_connection "$FRR_RS" 10.114.2.1

    stop_capture
    assert_wire

    print_summary
}

main "$@"
