#!/usr/bin/env bash
# M99 interop test — RFC 9072 extended Optional Parameters against FRR 10.3.1.
#
# The driver starts host tshark inside rustbgpd's network namespace before the
# daemon starts. It exports only raw TCP payload plus sequence/flow metadata;
# the embedded Python oracle independently reassembles each directional stream
# and decodes BGP framing and OPEN Optional Parameters.
#
# Prerequisites: deployed topology, grpcurl, jq, python3, host tshark, nsenter,
# and passwordless sudo for entering the already-deployed lab namespace.

set -euo pipefail

TOPO="m99-rfc9072-extended-open-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

FRR="clab-${TOPO}-frr"
CAPTURE="$(mktemp /tmp/m99-rfc9072.XXXXXX.pcap)"
PAYLOADS="$(mktemp /tmp/m99-rfc9072.XXXXXX.tsv)"
CAPTURE_LOG="$(mktemp /tmp/m99-rfc9072.XXXXXX.log)"
CAPTURE_PID=""

cleanup_m99() {
    if [ -n "$CAPTURE_PID" ] && kill -0 "$CAPTURE_PID" 2>/dev/null; then
        kill -INT "$CAPTURE_PID" 2>/dev/null || true
        wait "$CAPTURE_PID" 2>/dev/null || true
    fi
    rm -f "$CAPTURE" "$PAYLOADS" "$CAPTURE_LOG"
}

m99_on_exit() {
    local exit_code=$?
    trap - EXIT INT TERM HUP
    set +e
    cleanup_m99
    _cleanup_on_exit
    exit "$exit_code"
}
trap m99_on_exit EXIT INT TERM HUP

preflight_m99() {
    local errors=0
    for binary in python3 tshark nsenter; do
        if ! command -v "$binary" >/dev/null 2>&1; then
            echo "ERROR: M99 requires host $binary" >&2
            errors=$((errors + 1))
        fi
    done
    if ! sudo -n true >/dev/null 2>&1; then
        echo "ERROR: M99 requires passwordless sudo for host tshark namespace capture" >&2
        errors=$((errors + 1))
    fi
    if ! docker inspect "$FRR" >/dev/null 2>&1; then
        echo "ERROR: container $FRR not running — deploy the M99 topology first" >&2
        errors=$((errors + 1))
    fi
    if [ "$errors" -ne 0 ]; then
        exit 1
    fi
}

wait_frr_ready() {
    local running summary listener_ready peer_ready
    local consecutive_ready=0
    log "Waiting for FRR to settle both passive neighbors and listen on TCP/179"
    for _ in $(seq 1 80); do
        running=$(docker exec "$FRR" vtysh -c 'show running-config' 2>/dev/null || true)
        summary=$(docker exec "$FRR" vtysh -c 'show bgp summary json' 2>/dev/null || true)
        listener_ready=""
        peer_ready=""
        if docker exec "$FRR" awk \
            '$2 ~ /:00B3$/ && $4 == "0A" { found = 1 } END { exit !found }' \
            /proc/net/tcp /proc/net/tcp6 2>/dev/null; then
            listener_ready=yes
        fi
        if jq -e '
            .ipv4Unicast.peers["10.99.0.1"] != null
            and .ipv4Unicast.peers["10.99.1.1"] != null
        ' <<<"$summary" >/dev/null 2>&1; then
            peer_ready=yes
        fi
        if grep -Fq 'neighbor 10.99.0.1 remote-as 65001' <<<"$running" \
            && grep -Fq 'neighbor 10.99.1.1 remote-as 65001' <<<"$running" \
            && [ "$listener_ready" = yes ] \
            && [ "$peer_ready" = yes ]; then
            consecutive_ready=$((consecutive_ready + 1))
            # Five 250 ms samples provide a full second after the peer objects
            # first become visible, so capture cannot race FRR's event-loop
            # settlement and record an unanswered first connection epoch.
            if [ "$consecutive_ready" -ge 5 ]; then
                ok "FRR passive neighbors and TCP/179 listener stable for one second before capture"
                return 0
            fi
        else
            consecutive_ready=0
        fi
        sleep 0.25
    done
    echo "ERROR: FRR did not settle both passive neighbors and TCP/179 listener" >&2
    docker exec "$FRR" vtysh -c 'show running-config' >&2 || true
    docker exec "$FRR" vtysh -c 'show bgp summary json' >&2 || true
    docker logs "$FRR" >&2 || true
    return 1
}

start_capture() {
    local rust_pid
    rust_pid=$(docker inspect -f '{{.State.Pid}}' "$RUSTBGPD")
    case "$rust_pid" in
        ''|*[!0-9]*)
            echo "ERROR: could not resolve the rustbgpd container PID" >&2
            exit 1
            ;;
    esac

    log "Starting host tshark raw TCP capture in rustbgpd's network namespace"
    # shellcheck disable=SC2024 # the runner must own both redirected artifacts
    sudo -n nsenter -t "$rust_pid" -n \
        tshark -i any -f 'tcp port 179 and (net 10.99.0.0/24 or net 10.99.1.0/24)' \
        -w - >"$CAPTURE" 2>"$CAPTURE_LOG" &
    CAPTURE_PID=$!

    for _ in $(seq 1 20); do
        if grep -q 'Capturing on' "$CAPTURE_LOG"; then
            ok "host tshark capture armed before rustbgpd startup"
            return 0
        fi
        if ! kill -0 "$CAPTURE_PID" 2>/dev/null; then
            echo "ERROR: host tshark exited before capture became ready" >&2
            cat "$CAPTURE_LOG" >&2
            exit 1
        fi
        sleep 0.25
    done
    echo "ERROR: host tshark did not report capture readiness" >&2
    cat "$CAPTURE_LOG" >&2
    exit 1
}

stop_capture() {
    if kill -0 "$CAPTURE_PID" 2>/dev/null; then
        # The capture may exit between the liveness probe and the signal.
        kill -INT "$CAPTURE_PID" 2>/dev/null || true
    fi
    set +e
    wait "$CAPTURE_PID"
    local capture_rc=$?
    set -e
    CAPTURE_PID=""
    case "$capture_rc" in
        0|130) ;;
        *)
            echo "ERROR: host tshark exited with status $capture_rc" >&2
            cat "$CAPTURE_LOG" >&2
            exit 1
            ;;
    esac
    if [ ! -s "$CAPTURE" ]; then
        echo "ERROR: host tshark produced no capture bytes" >&2
        exit 1
    fi
    ok "raw OPEN exchange captured by host tshark"
}

export_payloads() {
    tshark -r "$CAPTURE" -Y 'tcp.len > 0' -T fields \
        -E 'separator=/t' -E 'occurrence=f' \
        -e tcp.stream -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport \
        -e tcp.seq_raw -e tcp.payload > "$PAYLOADS"
    if [ ! -s "$PAYLOADS" ]; then
        echo "ERROR: M99 capture contains no TCP payload rows" >&2
        exit 1
    fi
}

analyze_payloads() {
    python3 - "$PAYLOADS" <<'PY'
from __future__ import annotations

import collections
import pathlib
import sys


class ProofError(Exception):
    pass


def need(condition: bool, detail: str) -> None:
    if not condition:
        raise ProofError(detail)


def decode_capabilities(message: bytes) -> set[int]:
    need(len(message) >= 29, "OPEN is shorter than its fixed fields")
    non_extended_len = message[28]
    cursor = 29
    end = len(message)
    extended = non_extended_len != 0 and message[cursor] == 255
    if extended:
        need(cursor + 3 <= end, "extended Optional Parameters header is truncated")
        cursor += 1
        aggregate_len = int.from_bytes(message[cursor : cursor + 2], "big")
        cursor += 2
        need(cursor + aggregate_len == end, "extended aggregate does not consume OPEN")
        parameter_len_width = 2
    else:
        need(cursor + non_extended_len == end, "classic aggregate does not consume OPEN")
        parameter_len_width = 1

    capabilities: set[int] = set()
    while cursor < end:
        need(cursor + 1 + parameter_len_width <= end, "Optional Parameter header is truncated")
        parameter_type = message[cursor]
        cursor += 1
        parameter_len = int.from_bytes(
            message[cursor : cursor + parameter_len_width], "big"
        )
        cursor += parameter_len_width
        parameter_end = cursor + parameter_len
        need(parameter_type == 2, f"unexpected Optional Parameter type {parameter_type}")
        need(parameter_end <= end, "type 2 Optional Parameter exceeds aggregate")
        while cursor < parameter_end:
            need(cursor + 2 <= parameter_end, "capability TLV header is truncated")
            code = message[cursor]
            length = message[cursor + 1]
            cursor += 2
            need(cursor + length <= parameter_end, f"capability {code} exceeds type 2 parameter")
            capabilities.add(code)
            cursor += length
        need(cursor == parameter_end, "type 2 Optional Parameter was not consumed exactly")
    need(cursor == end, "Optional Parameters aggregate was not consumed exactly")
    return capabilities


def decode_messages(payload: bytes, label: str) -> list[bytes]:
    messages: list[bytes] = []
    cursor = 0
    while cursor < len(payload):
        need(cursor + 19 <= len(payload), f"{label}: trailing partial BGP header")
        need(payload[cursor : cursor + 16] == b"\xff" * 16, f"{label}: invalid BGP marker")
        length = int.from_bytes(payload[cursor + 16 : cursor + 18], "big")
        need(19 <= length <= 4096, f"{label}: invalid BGP length {length}")
        need(cursor + length <= len(payload), f"{label}: trailing partial BGP message")
        messages.append(payload[cursor : cursor + length])
        cursor += length
    return messages


def reassemble(rows: list[tuple[int, bytes]], label: str) -> bytes:
    octets: dict[int, int] = {}
    for sequence, payload in rows:
        for offset, value in enumerate(payload):
            position = sequence + offset
            prior = octets.get(position)
            need(
                prior is None or prior == value,
                f"{label}: conflicting retransmission at TCP sequence {position}",
            )
            octets[position] = value
    need(bool(octets), f"{label}: empty directional TCP stream")
    first = min(octets)
    last = max(octets)
    need(len(octets) == last - first + 1, f"{label}: gap in TCP payload sequence space")
    return bytes(octets[position] for position in range(first, last + 1))


path = pathlib.Path(sys.argv[1])
segments: dict[tuple[str, str, int, str, int], list[tuple[int, bytes]]] = collections.defaultdict(list)
for line_number, raw in enumerate(path.read_text().splitlines(), 1):
    fields = raw.split("\t")
    need(len(fields) == 7, f"payload row {line_number} has {len(fields)} fields")
    stream, source, source_port, destination, destination_port, sequence, payload_hex = fields
    need(all((stream, source, source_port, destination, destination_port, sequence, payload_hex)),
         f"payload row {line_number} has an empty required field")
    try:
        payload = bytes.fromhex(payload_hex.replace(":", ""))
        key = (stream, source, int(source_port), destination, int(destination_port))
        segments[key].append((int(sequence), payload))
    except ValueError as error:
        raise ProofError(f"payload row {line_number} is malformed: {error}") from error

expected_pairs = {
    ("10.99.0.2", "10.99.0.1"): "FRR->A",
    ("10.99.0.1", "10.99.0.2"): "rustbgpd->A",
    ("10.99.1.2", "10.99.1.1"): "FRR->B",
    ("10.99.1.1", "10.99.1.2"): "rustbgpd->B",
}
decoded: dict[str, tuple[bytes, set[int]]] = {}
print("M99 captured TCP stream inventory:", file=sys.stderr)
for key in sorted(segments):
    stream, source, source_port, destination, destination_port = key
    rows = segments[key]
    first = min(sequence for sequence, _ in rows)
    last = max(sequence + len(payload) for sequence, payload in rows)
    captured = sum(len(payload) for _, payload in rows)
    print(
        f"  stream={stream} {source}:{source_port}->{destination}:{destination_port} "
        f"segments={len(rows)} captured_bytes={captured} sequence_span={first}:{last}",
        file=sys.stderr,
    )
need(len(segments) == 4, f"expected four directional TCP streams, found {len(segments)}")
for key, rows in segments.items():
    stream, source, source_port, destination, destination_port = key
    label = expected_pairs.get((source, destination))
    need(label is not None, f"stream {stream}: unexpected IP direction {source}->{destination}")
    need(source_port == 179 or destination_port == 179, f"{label}: neither TCP port is 179")
    payload = reassemble(rows, label)
    messages = decode_messages(payload, label)
    opens = [message for message in messages if message[18] == 1]
    notifications = [message for message in messages if message[18] == 3]
    need(len(opens) == 1, f"{label}: expected exactly one OPEN, found {len(opens)}")
    need(not notifications, f"{label}: captured a BGP NOTIFICATION")
    decoded[label] = (opens[0], decode_capabilities(opens[0]))

need(set(decoded) == set(expected_pairs.values()), "one or more required directions are absent")

frr_a = decoded["FRR->A"][0]
need(frr_a[28] == 255 and frr_a[29] == 255, "FRR->A did not force RFC 9072 framing")
frr_a_aggregate = int.from_bytes(frr_a[30:32], "big")
need(1 <= frr_a_aggregate <= 255, f"FRR->A aggregate is not forced-small: {frr_a_aggregate}")
need(len(frr_a) == 32 + frr_a_aggregate, "FRR->A OPEN length disagrees with aggregate")

rust_a = decoded["rustbgpd->A"][0]
need(len(rust_a) == 342, f"rustbgpd->A OPEN is {len(rust_a)} bytes, expected 342")
need(rust_a[16:19] == bytes.fromhex("015601"), "rustbgpd->A header is not length 0x0156/type 1")
need(
    rust_a[28:35] == bytes.fromhex("ffff0136020133"),
    f"rustbgpd->A RFC 9072 prefix drifted: {rust_a[28:35].hex()}",
)

frr_b = decoded["FRR->B"][0]
need(frr_b[28] != 255, "FRR->B classic control used the RFC 9072 marker")

rust_b = decoded["rustbgpd->B"][0]
need(len(rust_b) == 49, f"rustbgpd->B OPEN is {len(rust_b)} bytes, expected 49")
need(rust_b[16:19] == bytes.fromhex("003101"), "rustbgpd->B header is not length 49/type 1")
need(rust_b[28:31] == bytes.fromhex("140212"), "rustbgpd->B classic prefix drifted")
need(rust_b[29] != 255, "rustbgpd->B classic control used the RFC 9072 marker")

for link in ("A", "B"):
    common = decoded[f"FRR->{link}"][1] & decoded[f"rustbgpd->{link}"][1]
    need(common, f"link {link}: common negotiated capability inventory is empty")
    print(f"M99 link {link} common capability codes: {','.join(map(str, sorted(common)))}")

print("M99 raw-stream RFC 9072 proof complete")
PY
    ok "four streams, exact OPEN bytes, exact parameter consumption, and zero NOTIFICATIONs"
    ok "both links have a non-empty common capability inventory"
}

main() {
    preflight_m99
    resolve_grpc_addr
    wait_frr_ready
    start_capture
    # shellcheck disable=SC2119 # no argument selects the standard start wrapper
    start_rustbgpd
    wait_frr_established "$FRR" "10.99.0.1" "M99 extended" || exit 1
    wait_frr_established "$FRR" "10.99.1.1" "M99 classic control" || exit 1
    sleep 1
    stop_capture
    export_payloads
    analyze_payloads
    print_summary
}

main "$@"
