#!/usr/bin/env python3
"""Verify the exact M105 raw-client messages from decoded TCP payload rows."""

from __future__ import annotations

import ipaddress
import json
import struct
import sys
from collections import defaultdict
from pathlib import Path


MARKER = b"\xff" * 16
RAW = "10.105.0.10"
RECEIVERS = {
    "10.105.0.1": "rustbgpd",
    "10.105.0.2": "bird",
    "10.105.0.3": "openbgpd",
    "10.105.0.4": "gobgp",
    "10.105.0.5": "frr",
}
BASELINE = "198.51.104.0/24"
PROBE = "198.51.105.0/24"


def need(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def reassemble(parts: list[tuple[int, bytes]]) -> bytes:
    need(bool(parts), "TCP stream has no payload")
    base = min(sequence for sequence, _ in parts)
    cursor = base
    output = bytearray()
    for sequence, payload in sorted(parts):
        need(sequence <= cursor, f"TCP gap before sequence {sequence}")
        overlap = cursor - sequence
        if overlap:
            start = sequence - base
            need(start >= 0, "TCP segment precedes stream base")
            need(
                output[start : start + min(overlap, len(payload))] == payload[:overlap],
                "conflicting TCP overlap",
            )
        if overlap < len(payload):
            output.extend(payload[overlap:])
            cursor = sequence + len(payload)
    return bytes(output)


def messages(data: bytes) -> list[tuple[int, bytes]]:
    decoded: list[tuple[int, bytes]] = []
    cursor = 0
    while cursor < len(data):
        need(len(data) - cursor >= 19, "trailing partial BGP header")
        need(data[cursor : cursor + 16] == MARKER, "BGP marker mismatch")
        length, message_type = struct.unpack("!HB", data[cursor + 16 : cursor + 19])
        need(19 <= length <= 4096, f"invalid BGP length {length}")
        need(cursor + length <= len(data), "trailing partial BGP message")
        decoded.append((message_type, data[cursor + 19 : cursor + length]))
        cursor += length
    return decoded


def capabilities(body: bytes) -> dict[int, list[bytes]]:
    need(len(body) >= 10 and body[0] == 4, "invalid raw OPEN")
    length = body[9]
    optional = body[10 : 10 + length]
    need(len(optional) == length, "truncated OPEN optional parameters")
    found: dict[int, list[bytes]] = defaultdict(list)
    cursor = 0
    while cursor < len(optional):
        need(cursor + 2 <= len(optional) and optional[cursor] == 2, "unexpected OPEN parameter")
        parameter_length = optional[cursor + 1]
        value = optional[cursor + 2 : cursor + 2 + parameter_length]
        need(len(value) == parameter_length, "truncated OPEN parameter")
        cursor += 2 + parameter_length
        cap_cursor = 0
        while cap_cursor < len(value):
            need(cap_cursor + 2 <= len(value), "truncated capability header")
            code = value[cap_cursor]
            cap_length = value[cap_cursor + 1]
            cap_value = value[cap_cursor + 2 : cap_cursor + 2 + cap_length]
            need(len(cap_value) == cap_length, "truncated capability value")
            found[code].append(cap_value)
            cap_cursor += 2 + cap_length
    return dict(found)


def decode_nlri(raw: bytes) -> list[str]:
    prefixes: list[str] = []
    cursor = 0
    while cursor < len(raw):
        length = raw[cursor]
        cursor += 1
        octets = (length + 7) // 8
        need(length <= 32 and cursor + octets <= len(raw), "invalid IPv4 NLRI")
        packed = raw[cursor : cursor + octets] + b"\x00" * (4 - octets)
        cursor += octets
        prefixes.append(str(ipaddress.IPv4Network((packed, length), strict=False)))
    return prefixes


def update(body: bytes) -> tuple[list[str], dict[int, tuple[int, bytes]], list[str]]:
    need(len(body) >= 4, "short UPDATE")
    withdrawn_length = int.from_bytes(body[:2], "big")
    need(2 + withdrawn_length + 2 <= len(body), "truncated withdrawn routes")
    withdrawn = decode_nlri(body[2 : 2 + withdrawn_length])
    cursor = 2 + withdrawn_length
    attributes_length = int.from_bytes(body[cursor : cursor + 2], "big")
    attributes_raw = body[cursor + 2 : cursor + 2 + attributes_length]
    need(len(attributes_raw) == attributes_length, "truncated path attributes")
    announced = decode_nlri(body[cursor + 2 + attributes_length :])
    attributes: dict[int, tuple[int, bytes]] = {}
    cursor = 0
    while cursor < len(attributes_raw):
        need(cursor + 3 <= len(attributes_raw), "truncated attribute header")
        flags = attributes_raw[cursor]
        code = attributes_raw[cursor + 1]
        cursor += 2
        if flags & 0x10:
            need(cursor + 2 <= len(attributes_raw), "truncated extended attribute length")
            length = int.from_bytes(attributes_raw[cursor : cursor + 2], "big")
            cursor += 2
        else:
            length = attributes_raw[cursor]
            cursor += 1
        value = attributes_raw[cursor : cursor + length]
        need(len(value) == length, "truncated attribute value")
        need(code not in attributes, f"duplicate attribute {code}")
        attributes[code] = (flags, value)
        cursor += length
    return withdrawn, attributes, announced


def verify_announcement(
    attributes: dict[int, tuple[int, bytes]],
    *,
    segment_type: int,
    members: tuple[int, ...],
) -> None:
    expected_codes = {1, 2, 3, 8, 32}
    need(set(attributes) == expected_codes, f"attribute codes differ: {set(attributes)}")
    need(attributes[1] == (0x40, b"\x00"), "ORIGIN differs")
    path = bytes([segment_type, len(members)]) + b"".join(
        member.to_bytes(4, "big") for member in members
    )
    need(attributes[2] == (0x40, path), "AS_PATH differs")
    need(attributes[3] == (0x40, ipaddress.IPv4Address(RAW).packed), "NEXT_HOP differs")
    need(attributes[8] == (0xC0, struct.pack("!HH", 64512, 105)), "COMMUNITIES differs")
    need(
        attributes[32] == (0xC0, struct.pack("!III", 64512, 105, 1)),
        "LARGE_COMMUNITIES differs",
    )


def verify_stream(data: bytes, destination: str) -> dict[str, object]:
    decoded = messages(data)
    opens = [body for message_type, body in decoded if message_type == 1]
    need(len(opens) == 1, f"{destination}: expected one OPEN")
    caps = capabilities(opens[0])
    need(int.from_bytes(opens[0][1:3], "big") == 64512, f"{destination}: OPEN AS differs")
    need(caps.get(65) == [(64512).to_bytes(4, "big")], f"{destination}: capability 65 differs")
    need(caps.get(9) == [b"\x02"], f"{destination}: BGP Role differs")
    need(struct.pack("!HBB", 1, 0, 1) in caps.get(1, []), f"{destination}: IPv4 capability absent")

    baseline = []
    probe = []
    withdrawals = []
    for message_type, body in decoded:
        if message_type != 2:
            continue
        withdrawn, attributes, announced = update(body)
        if announced == [BASELINE]:
            baseline.append(attributes)
        if announced == [PROBE]:
            probe.append(attributes)
        if set(withdrawn) == {BASELINE, PROBE}:
            withdrawals.append((attributes, announced))
    need(len(baseline) == 1, f"{destination}: baseline UPDATE count differs")
    need(len(probe) == 1, f"{destination}: AS_SET UPDATE count differs")
    need(len(withdrawals) == 1, f"{destination}: withdrawal UPDATE count differs")
    verify_announcement(baseline[0], segment_type=2, members=(64512,))
    verify_announcement(probe[0], segment_type=1, members=(64512, 64513))
    need(withdrawals[0] == ({}, []), f"{destination}: withdrawal carries reachability")
    return {
        "destination": destination,
        "open_role": "rs-client",
        "baseline_as_path": {"segment_type": 2, "members": [64512]},
        "as_set_path": {"segment_type": 1, "members": [64512, 64513]},
        "next_hop": RAW,
        "community": "64512:105",
        "large_community": "64512:105:1",
        "withdrawn": [BASELINE, PROBE],
    }


def analyze(lines: list[str]) -> dict[str, object]:
    streams: dict[tuple[str, str], list[tuple[int, bytes]]] = defaultdict(list)
    for line_number, raw_line in enumerate(lines, 1):
        fields = raw_line.rstrip("\n").split("\t")
        need(len(fields) == 5, f"row {line_number}: expected five TSV fields")
        stream, source, destination, sequence, payload = fields
        if source != RAW or destination not in RECEIVERS or not payload:
            continue
        streams[(stream, destination)].append(
            (int(sequence), bytes.fromhex(payload.replace(":", "")))
        )
    by_destination: dict[str, list[tuple[int, bytes]]] = defaultdict(list)
    for (_, destination), parts in streams.items():
        need(destination not in by_destination, f"{destination}: multiple raw TCP streams")
        by_destination[destination] = parts
    need(set(by_destination) == set(RECEIVERS), "capture receiver set differs")
    receivers = {
        RECEIVERS[destination]: verify_stream(reassemble(parts), destination)
        for destination, parts in sorted(by_destination.items())
    }
    return {"schema": "m105-wire/1", "raw_client": RAW, "receivers": receivers}


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} PAYLOADS.tsv", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    receipt = analyze(path.read_text(encoding="utf-8").splitlines(keepends=True))
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"M105 packet oracle failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
