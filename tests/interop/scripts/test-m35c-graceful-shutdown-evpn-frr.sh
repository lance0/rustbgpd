#!/usr/bin/env bash
# M35c interop test — RFC 8326 Graceful Shutdown on EVPN outbound.
#
# Inject an EVPN Type 2 route first so FRR has a steady-state,
# untagged L2VPN/EVPN path. Then toggle
# NeighborService.SetGracefulShutdown on and off without route churn.
# The test captures the actual BGP UPDATE bytes in the FRR container
# and checks for 0xffff0000 on the wire. This proves the EVPN-specific
# outbound advertise path calls attach_graceful_shutdown_if_enabled
# during force re-emit.

set -euo pipefail

TOPO="m35c-graceful-shutdown-evpn-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
source "$SCRIPT_DIR/test-lib.sh"
FRR="clab-${TOPO}-frr"

TEST_MAC="02:00:00:00:35:0c"
EVPN_ADD='{
  "routeType": 2,
  "rd": "65001:100",
  "ethernetTag": 0,
  "mac": "02:00:00:00:35:0c",
  "ip": "192.0.2.35",
  "label": 100,
  "nextHop": "10.0.0.1",
  "routeTargets": ["65001:100"]
}'

grpc_add_evpn() {
    grpcurl_call \
        -d "$EVPN_ADD" \
        "$GRPC_ADDR" rustbgpd.v1.InjectionService/AddEvpnRoute >/dev/null
}

grpc_set_gshut() {
    local enabled=${1:?}
    grpcurl_call \
        -d "{\"address\":\"10.0.0.2\",\"enabled\":${enabled}}" \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/SetGracefulShutdown >/dev/null
}

frr_evpn_detail() {
    docker exec "$FRR" vtysh -c "show bgp l2vpn evpn route detail" 2>/dev/null
}

frr_evpn_macip_json() {
    docker exec "$FRR" vtysh -c "show bgp l2vpn evpn route type macip json" 2>/dev/null || true
}

frr_has_mac() {
    {
        frr_evpn_detail
        frr_evpn_macip_json
    } | grep -qi "$TEST_MAC"
}

install_bgp_capture() {
    docker exec -i "$FRR" sh -c 'cat > /tmp/rustbgpd-bgp-update-capture.py' <<'PY'
"""BGP UPDATE capture with per-flow TCP stream reassembly.

BGP messages run over TCP and can split across segment boundaries —
the marker, the length field, or a community-attribute value can each
land at the boundary. Without buffering per-flow we'd miss UPDATEs or
miscount when bytes span packets, which makes interop tests flaky
under CI load. This parser keeps a per-(src,sport,dst,dport) byte
buffer, appends each segment's TCP payload, and only counts complete
BGP messages from the head of the buffer (trimming as it goes).
"""
import json
import socket
import sys
import time

src_ip, dst_ip, duration, output = sys.argv[1], sys.argv[2], float(sys.argv[3]), sys.argv[4]
MARKER = b"\xff" * 16
GSHUT = b"\xff\xff\x00\x00"
BGP_HDR_LEN = 19  # 16-byte marker + 2-byte length + 1-byte type
BGP_TYPE_UPDATE = 2

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
sock.bind(("eth1", 0))
sock.settimeout(0.25)

flows = {}  # (src, sport, dst, dport) -> bytearray of in-order TCP payload
end = time.time() + duration
updates = 0
gshut_updates = 0


def parse_buf(buf):
    """Pop complete BGP messages from `buf`. Updates global counters.

    Resyncs to the next marker if the buffer head isn't aligned.
    Stops cleanly when the next message is incomplete and waits for
    more bytes to arrive on the next segment.
    """
    global updates, gshut_updates
    while len(buf) >= BGP_HDR_LEN:
        if bytes(buf[:16]) != MARKER:
            # Mid-stream desync — skip ahead to the next marker we
            # find. Drop everything before it; never going to be a
            # valid BGP message.
            idx = buf.find(MARKER)
            if idx < 0:
                # No marker anywhere; throw away all but the last
                # 15 bytes (a marker could still be split across the
                # end of this buffer + the next segment).
                if len(buf) > 15:
                    del buf[: len(buf) - 15]
                return
            del buf[:idx]
            continue
        length = int.from_bytes(buf[16:18], "big")
        if length < BGP_HDR_LEN:
            # Malformed length — discard one byte and re-search for
            # the next marker.
            del buf[:1]
            continue
        if len(buf) < length:
            return  # need more bytes
        if buf[18] == BGP_TYPE_UPDATE:
            updates += 1
            if GSHUT in bytes(buf[:length]):
                gshut_updates += 1
        del buf[:length]


while time.time() < end:
    try:
        frame = sock.recv(65535)
    except (TimeoutError, socket.timeout):
        continue

    if len(frame) < 54:
        continue
    eth_type = int.from_bytes(frame[12:14], "big")
    offset = 14
    if eth_type == 0x8100 and len(frame) >= 58:
        eth_type = int.from_bytes(frame[16:18], "big")
        offset = 18
    if eth_type != 0x0800 or len(frame) < offset + 20:
        continue

    ihl = (frame[offset] & 0x0F) * 4
    if frame[offset + 9] != 6:
        continue
    src = socket.inet_ntoa(frame[offset + 12:offset + 16])
    dst = socket.inet_ntoa(frame[offset + 16:offset + 20])
    if src != src_ip or dst != dst_ip:
        continue

    tcp = offset + ihl
    if len(frame) < tcp + 20:
        continue
    sport = int.from_bytes(frame[tcp:tcp + 2], "big")
    dport = int.from_bytes(frame[tcp + 2:tcp + 4], "big")
    if sport != 179 and dport != 179:
        continue

    data_offset = ((frame[tcp + 12] >> 4) & 0x0F) * 4
    payload = frame[tcp + data_offset:]
    if not payload:
        continue
    key = (src, sport, dst, dport)
    buf = flows.setdefault(key, bytearray())
    buf.extend(payload)
    parse_buf(buf)

with open(output, "w", encoding="utf-8") as f:
    json.dump({"updates": updates, "gshut_updates": gshut_updates}, f)
PY
}

# Capture window must exceed the post-emit sleep so a delayed
# re-emit at the tail of the wait still lands inside the capture.
# Each call site waits for the capture file to land via
# `wait_for_capture` before asserting, so we don't have to align
# durations precisely — just keep the capture longer than the
# expected re-emit latency under CI load.
CAPTURE_DURATION_SECS=8

start_bgp_capture() {
    local output=${1:?}
    docker exec "$FRR" rm -f "$output"
    docker exec -d "$FRR" python3 /tmp/rustbgpd-bgp-update-capture.py \
        10.0.0.1 10.0.0.2 "$CAPTURE_DURATION_SECS" "$output" >/dev/null
    sleep 0.5
}

# `start_bgp_capture` runs the python parser in a detached container
# process; the JSON output file appears only after the capture
# duration elapses. Poll for it before asserting, with slack beyond
# the configured duration so the test fails loudly rather than
# asserting against an empty/missing file.
wait_for_capture() {
    local output=${1:?}
    local deadline=$((CAPTURE_DURATION_SECS * 2 + 4))
    for _ in $(seq 1 $((deadline * 2))); do
        if docker exec "$FRR" test -s "$output" 2>/dev/null; then
            return 0
        fi
        sleep 0.5
    done
    fail "BGP capture file $output never appeared within ${deadline}s"
    return 1
}

assert_capture_gshut() {
    local output=${1:?}
    local want=${2:?}
    local label=${3:?}
    local summary updates gshut_updates

    summary=$(docker exec "$FRR" cat "$output" 2>/dev/null || echo '{}')
    updates=$(echo "$summary" | jq -r '.updates // 0')
    gshut_updates=$(echo "$summary" | jq -r '.gshut_updates // 0')

    if [ "$updates" -lt 1 ]; then
        fail "$label captured no BGP UPDATEs (summary: $summary)"
        dump_state_on_failure
        return 1
    fi

    if [ "$want" = "present" ] && [ "$gshut_updates" -gt 0 ]; then
        ok "$label (updates=$updates, gshut_updates=$gshut_updates)"
        return 0
    fi
    if [ "$want" = "absent" ] && [ "$gshut_updates" -eq 0 ]; then
        ok "$label (updates=$updates, gshut_updates=0)"
        return 0
    fi

    fail "$label unexpected GShut capture state (summary: $summary)"
    dump_state_on_failure
    return 1
}

dump_state_on_failure() {
    echo "===== FRR EVPN detail =====" >&2
    frr_evpn_detail >&2 || true
    echo "===== FRR EVPN Type 2 JSON =====" >&2
    frr_evpn_macip_json | jq . >&2 || true
    echo "===== rustbgpd ListEvpnRoutes =====" >&2
    grpcurl_call \
        -d '{}' "$GRPC_ADDR" rustbgpd.v1.RibService/ListEvpnRoutes 2>&1 \
        | head -80 >&2 || true
    echo "===== rustbgpd NeighborState 10.0.0.2 =====" >&2
    grpcurl_call \
        -d '{"address":"10.0.0.2"}' \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/GetNeighborState 2>&1 \
        | head -80 >&2 || true
}

wait_evpn_state() {
    local label=${1:?}
    for i in $(seq 1 30); do
        if frr_has_mac; then
            ok "$label after ${i}s"
            return 0
        fi
        sleep 1
    done
    fail "$label did not converge within 30s"
    dump_state_on_failure
    return 1
}

resolve_grpc_addr
start_rustbgpd
wait_frr_established "$FRR" "10.0.0.1" "rustbgpd ↔ FRR EVPN"
install_bgp_capture

log "Injecting EVPN Type 2 $TEST_MAC while GShut toggle is off..."
start_bgp_capture /tmp/m35c-initial.json
grpc_add_evpn
sleep 5
wait_for_capture /tmp/m35c-initial.json
assert_capture_gshut /tmp/m35c-initial.json absent "Initial EVPN advertise omits GShut"
wait_evpn_state "FRR has EVPN Type 2 route in steady state"

log "Toggling GRACEFUL_SHUTDOWN advertise ON for EVPN peer..."
start_bgp_capture /tmp/m35c-on.json
grpc_set_gshut true
sleep 5
wait_for_capture /tmp/m35c-on.json
assert_capture_gshut /tmp/m35c-on.json present "Toggle-on EVPN re-emit carries GShut"
wait_evpn_state "FRR still has EVPN Type 2 route after GShut toggle-on"

log "Toggling GRACEFUL_SHUTDOWN advertise OFF for EVPN peer..."
start_bgp_capture /tmp/m35c-off.json
grpc_set_gshut false
sleep 5
wait_for_capture /tmp/m35c-off.json
assert_capture_gshut /tmp/m35c-off.json absent "Toggle-off EVPN re-emit clears GShut"
wait_evpn_state "FRR still has EVPN Type 2 route after GShut toggle-off"

print_summary
