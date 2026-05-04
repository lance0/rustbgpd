#!/usr/bin/env bash
# M35b interop test — RFC 8326 Graceful Shutdown on FlowSpec outbound.
#
# Inject a FlowSpec rule first so FRR has a steady-state, untagged
# path. Then toggle NeighborService.SetGracefulShutdown on and off
# without route churn. FRR 10.3.1's FlowSpec JSON/text views do not
# expose standard communities, so the test captures the actual BGP
# UPDATE bytes in the FRR container and checks for 0xffff0000 on the
# wire. This proves the FlowSpec-specific outbound advertise path calls
# attach_graceful_shutdown_if_enabled during force re-emit.

set -euo pipefail

TOPO="m35b-graceful-shutdown-flowspec-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"
FRR="clab-${TOPO}-frr"

RULE_PREFIX="192.168.35.0/24"
RULE_ADD='{
  "afiSafi": "ADDRESS_FAMILY_IPV4_FLOWSPEC",
  "components": [
    {"type": 1, "prefix": "192.168.35.0/24"},
    {"type": 3, "value": "=6"},
    {"type": 5, "value": "=443"}
  ],
  "actions": [
    {"trafficRate": {"rate": 0.0}}
  ]
}'

grpc_add_flowspec() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "$RULE_ADD" \
        "$GRPC_ADDR" rustbgpd.v1.InjectionService/AddFlowSpec >/dev/null
}

grpc_set_gshut() {
    local enabled=${1:?}
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"address\":\"10.0.0.2\",\"enabled\":${enabled}}" \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/SetGracefulShutdown >/dev/null
}

frr_flowspec_json() {
    docker exec "$FRR" vtysh -c "show bgp ipv4 flowspec json" 2>/dev/null
}

frr_flowspec_route_json() {
    frr_flowspec_json | jq -c --arg p "$RULE_PREFIX" '
        (.routes // {})
        | to_entries
        | map(select(.key | contains($p)))
        | first
        | .value // empty
    ' 2>/dev/null
}

frr_has_rule() {
    frr_flowspec_json | jq -e --arg p "$RULE_PREFIX" '
        (.routes // {}) | to_entries | any(.key | contains($p))
    ' >/dev/null 2>&1
}

install_bgp_capture() {
    docker exec -i "$FRR" sh -c 'cat > /tmp/rustbgpd-bgp-update-capture.py' <<'PY'
import json
import socket
import sys
import time

src_ip, dst_ip, duration, output = sys.argv[1], sys.argv[2], float(sys.argv[3]), sys.argv[4]
marker = b"\xff" * 16
gshut = b"\xff\xff\x00\x00"

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
sock.bind(("eth1", 0))
sock.settimeout(0.25)

end = time.time() + duration
updates = 0
gshut_updates = 0

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
    pos = 0
    while True:
        idx = payload.find(marker, pos)
        if idx < 0 or len(payload) < idx + 19:
            break
        length = int.from_bytes(payload[idx + 16:idx + 18], "big")
        if length < 19 or len(payload) < idx + length:
            pos = idx + 1
            continue
        if payload[idx + 18] == 2:
            updates += 1
            if gshut in payload[idx:idx + length]:
                gshut_updates += 1
        pos = idx + length

with open(output, "w", encoding="utf-8") as f:
    json.dump({"updates": updates, "gshut_updates": gshut_updates}, f)
PY
}

start_bgp_capture() {
    local output=${1:?}
    docker exec "$FRR" rm -f "$output"
    docker exec -d "$FRR" python3 /tmp/rustbgpd-bgp-update-capture.py \
        10.0.0.1 10.0.0.2 4 "$output" >/dev/null
    sleep 0.5
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
    echo "===== FRR FlowSpec JSON =====" >&2
    frr_flowspec_json | jq . >&2 || true
    echo "===== FRR FlowSpec text =====" >&2
    docker exec "$FRR" vtysh -c "show bgp ipv4 flowspec" >&2 || true
    echo "===== rustbgpd NeighborState 10.0.0.2 =====" >&2
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d '{"address":"10.0.0.2"}' \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/GetNeighborState 2>&1 \
        | head -80 >&2 || true
}

wait_flowspec_state() {
    local label=${1:?}
    for i in $(seq 1 30); do
        if frr_has_rule; then
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
wait_frr_established "$FRR" "10.0.0.1" "rustbgpd ↔ FRR FlowSpec"
install_bgp_capture

log "Injecting FlowSpec rule $RULE_PREFIX while GShut toggle is off..."
start_bgp_capture /tmp/m35b-initial.json
grpc_add_flowspec
sleep 5
assert_capture_gshut /tmp/m35b-initial.json absent "Initial FlowSpec advertise omits GShut"
wait_flowspec_state "FRR has FlowSpec route in steady state"

log "Toggling GRACEFUL_SHUTDOWN advertise ON for FlowSpec peer..."
start_bgp_capture /tmp/m35b-on.json
grpc_set_gshut true
sleep 5
assert_capture_gshut /tmp/m35b-on.json present "Toggle-on FlowSpec re-emit carries GShut"
wait_flowspec_state "FRR still has FlowSpec route after GShut toggle-on"

log "Toggling GRACEFUL_SHUTDOWN advertise OFF for FlowSpec peer..."
start_bgp_capture /tmp/m35b-off.json
grpc_set_gshut false
sleep 5
assert_capture_gshut /tmp/m35b-off.json absent "Toggle-off FlowSpec re-emit clears GShut"
wait_flowspec_state "FRR still has FlowSpec route after GShut toggle-off"

print_summary
