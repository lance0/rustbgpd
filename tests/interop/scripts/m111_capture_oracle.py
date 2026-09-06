#!/usr/bin/env python3
"""Check M111 SRv6 VPN reflection using independently decoded TCP payloads."""

from __future__ import annotations

import ipaddress
import json
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

from m105_capture_oracle import capabilities, messages, need, reassemble, update

SOURCE = "2001:db8:111:10::2"
RR_SOURCE = "2001:db8:111:10::1"
RR_SINK = "2001:db8:111:20::1"
SINK = "2001:db8:111:20::2"
DIRECTIONS = {
    (SOURCE, RR_SOURCE): "source_to_rr",
    (RR_SOURCE, SOURCE): "rr_to_source",
    (RR_SINK, SINK): "rr_to_sink",
    (SINK, RR_SINK): "sink_to_rr",
}
ROUTER_IDS = {SOURCE: "10.111.0.2", RR_SOURCE: "10.111.0.1", RR_SINK: "10.111.0.1", SINK: "10.111.0.3"}
PREFIXES = {1: "198.51.111.0/24", 2: "2001:db8:111:1000::/64"}
RD = struct.pack("!HHI", 0, 65001, 111)
STRUCTURE = bytes([40, 24, 16, 0, 16, 64])
LOCATOR = ipaddress.IPv6Network("2001:db8:111:1::/64")


def tlvs(raw: bytes) -> list[tuple[int, bytes]]:
    result = []
    cursor = 0
    while cursor < len(raw):
        need(cursor + 3 <= len(raw), "truncated SRv6 TLV header")
        kind, length = struct.unpack("!BH", raw[cursor:cursor + 3])
        cursor += 3
        value = raw[cursor:cursor + length]
        need(len(value) == length, "truncated SRv6 TLV value")
        result.append((kind, value))
        cursor += length
    return result


def srv6(value: bytes, afi: int, label: bytes) -> dict[str, object]:
    services = tlvs(value)
    need(len(services) == 1 and services[0][0] == 5, "expected one SRv6 L3 Service TLV")
    service = services[0][1]
    need(bool(service) and service[0] == 0, "invalid L3 Service reserved field")
    infos = tlvs(service[1:])
    need(len(infos) == 1 and infos[0][0] == 1, "expected one SID Information sub-TLV")
    info = infos[0][1]
    need(len(info) >= 21, "short SID Information sub-TLV")
    need(info[0] == info[17] == info[20] == 0, "SID Information flags or reserved fields differ")
    behavior = int.from_bytes(info[18:20], "big")
    need(behavior == {1: 0x13, 2: 0x12}[afi], "unexpected SRv6 endpoint behavior")
    structures = tlvs(info[21:])
    need(structures == [(1, STRUCTURE)], "SRv6 SID Structure differs")
    block, node, function, argument, transposition, offset = STRUCTURE
    # RFC 9252 verified erratum 7817 permits equality at the end of the SID.
    need(block + node + function + argument >= offset + transposition, "transposition exceeds SID structure")
    sid = ipaddress.IPv6Address(info[1:17])
    need(sid in LOCATOR, "SID is outside configured locator")
    mask = ((1 << transposition) - 1) << (128 - offset - transposition)
    need(int(sid) & mask == 0, "transposed SID bits must be zero")
    label_value = int.from_bytes(label, "big") >> 4
    # Erratum 7652 places the transposed bits in the high-order label bits.
    need(label_value & ((1 << (20 - transposition)) - 1) == 0, "unused transposition label bits are nonzero")
    transposed = label_value >> (20 - transposition)
    need(transposed != 0, "transposed function is zero")
    reconstructed = ipaddress.IPv6Address(int(sid) | (transposed << (128 - offset - transposition)))
    return {"prefix_sid_hex": value.hex(), "advertised_sid": str(sid), "service_sid": str(reconstructed),
            "endpoint_behavior": behavior, "structure": list(STRUCTURE), "transposed_function": transposed}


def vpn_nlri(raw: bytes, afi: int, *, withdrawn: bool) -> bytes:
    prefix = ipaddress.ip_network(PREFIXES[afi])
    expected_bits = 88 + prefix.prefixlen
    expected = bytes([expected_bits]) + raw[1:4] + RD + prefix.network_address.packed[:(prefix.prefixlen + 7) // 8]
    need(len(raw) >= 12 and raw == expected, f"VPN NLRI differs for {PREFIXES[afi]}")
    label = raw[1:4]
    if not withdrawn:
        # RFC 8277 requires the three reserved bits to be ignored on reception.
        need(int.from_bytes(label, "big") & 1 == 1, "VPN announcement label is not a single bottom-of-stack label")
    return label


def mp_attribute(code: int, value: bytes) -> tuple[int, bytes, bytes]:
    need(len(value) >= 3, "short MP attribute")
    afi, safi = struct.unpack("!HB", value[:3])
    need(afi in PREFIXES and safi == 128, "unexpected MP family")
    if code == 15:
        return afi, b"", value[3:]
    need(len(value) >= 5, "short MP_REACH")
    length = value[3]
    need(length in (24, 48) and len(value) >= 5 + length, "invalid VPN IPv6 next-hop length")
    next_hop = value[4:4 + length]
    need(value[4 + length] == 0, "MP_REACH reserved byte differs")
    for start in range(0, length, 24):
        need(next_hop[start:start + 8] == bytes(8), "next-hop RD is not zero")
        address = ipaddress.IPv6Address(next_hop[start + 8:start + 24])
        need(not address.is_unspecified and not address.is_multicast, "invalid IPv6 next hop")
        need(start == 0 or address.is_link_local, "second next hop is not link-local")
    return afi, next_hop, value[5 + length:]


def verify_stream(data: bytes, source: str, name: str) -> tuple[dict, dict]:
    decoded = messages(data)
    counts = Counter(kind for kind, _ in decoded)
    need(counts[1] == 1 and decoded[0][0] == 1, f"{name}: expected one initial OPEN")
    need(counts[3] == 0, f"{name}: NOTIFICATION present")
    need(set(counts) <= {1, 2, 4, 5}, f"{name}: unknown BGP message type")
    opening = decoded[0][1]
    caps = capabilities(opening)
    need(len(opening) == 10 + opening[9], f"{name}: trailing OPEN bytes")
    need(int.from_bytes(opening[1:3], "big") == 65001, f"{name}: OPEN AS differs")
    need(opening[5:9] == ipaddress.IPv4Address(ROUTER_IDS[source]).packed, f"{name}: router ID differs")
    for afi in PREFIXES:
        need(struct.pack("!HBB", afi, 0, 128) in caps.get(1, []), f"{name}: VPN family {afi} absent")
    extended_next_hops = []
    for value in caps.get(5, []):
        need(len(value) % 6 == 0, f"{name}: malformed Extended Next Hop capability")
        extended_next_hops.extend(struct.iter_unpack("!HHH", value))
    vpnv4_ipv6_receive = (1, 128, 2) in extended_next_hops
    if source in (RR_SOURCE, SINK):
        need(vpnv4_ipv6_receive, f"{name}: VPNv4 IPv6 receive capability absent")
    events = {afi: {"announce": [], "withdraw": []} for afi in PREFIXES}
    for index, (kind, body) in enumerate(decoded):
        if kind != 2:
            continue
        withdrawn, attrs, announced = update(body)
        need(not withdrawn and not announced, f"{name}: legacy IPv4 reachability present")
        for code in (14, 15):
            if code not in attrs:
                continue
            afi, next_hop, nlri = mp_attribute(code, attrs[code][1])
            if not nlri:
                need(code == 15, "empty MP_REACH")
                continue
            need(name in ("source_to_rr", "rr_to_sink"), f"{name}: unexpected reverse reachability")
            label = vpn_nlri(nlri, afi, withdrawn=code == 15)
            event = {"index": index, "attrs": attrs, "nlri": nlri, "next_hop": next_hop}
            if code == 14:
                need(40 in attrs and attrs[40][0] & 0xC0 == 0xC0, "optional transitive Prefix-SID absent")
                event["srv6"] = srv6(attrs[40][1], afi, label)
            events[afi]["announce" if code == 14 else "withdraw"].append(event)
    return {"open_count": counts[1], "notification_count": counts[3],
            "vpnv4_ipv6_receive": vpnv4_ipv6_receive,
            "message_counts": dict(sorted(counts.items()))}, events


def compare_attributes(source: dict, reflected: dict, *, announcement: bool) -> None:
    reflected = reflected.copy()
    if announcement:
        for code, address in ((9, "10.111.0.2"), (10, "10.111.0.1")):
            need(code not in source, "source unexpectedly carries reflector attributes")
            need(code in reflected, f"reflected attribute {code} absent")
            flags, value = reflected.pop(code)
            need(flags & ~0x10 == 0x80 and value == ipaddress.IPv4Address(address).packed,
                 f"reflected attribute {code} differs")
    need(source.keys() == reflected.keys(), "reflected attribute set differs")
    for code, (flags, value) in source.items():
        output_flags, output_value = reflected[code]
        need(value == output_value, f"reflected attribute {code} value differs")
        flags &= ~0x10
        output_flags &= ~0x10
        need(output_flags == flags or (code == 40 and output_flags == flags | 0x20),
             f"reflected attribute {code} flags differ")


def analyze(lines: list[str]) -> dict[str, object]:
    parts = defaultdict(list)
    stream_ids = defaultdict(set)
    for number, line in enumerate(lines, 1):
        fields = line.rstrip("\n").split("\t")
        need(len(fields) == 5, f"row {number}: expected five TSV fields")
        stream, source, destination, sequence, payload = fields
        if not source or not destination:
            continue
        pair = (str(ipaddress.IPv6Address(source)), str(ipaddress.IPv6Address(destination)))
        if pair not in DIRECTIONS or not payload:
            continue
        need(bool(stream), f"row {number}: TCP stream ID absent")
        stream_ids[pair].add(stream)
        parts[pair].append((int(sequence), bytes.fromhex(payload.replace(":", ""))))
    need(set(stream_ids) == set(DIRECTIONS), "capture is missing a session direction")
    for pair, ids in stream_ids.items():
        need(len(ids) == 1, f"{DIRECTIONS[pair]}: reconnect or multiple TCP streams")
        need(ids == stream_ids[(pair[1], pair[0])], "reverse TCP stream ID differs")
    streams = {}
    routes = {}
    for pair, name in DIRECTIONS.items():
        streams[name], routes[name] = verify_stream(reassemble(parts[pair]), pair[0], name)
        streams[name]["tcp_stream"] = next(iter(stream_ids[pair]))
    families = {}
    for afi, prefix in PREFIXES.items():
        original = routes["source_to_rr"][afi]
        reflected = routes["rr_to_sink"][afi]
        for name, events in (("source", original), ("reflected", reflected)):
            need(len(events["announce"]) == len(events["withdraw"]) == 1,
                 f"{name} {prefix}: expected one announcement and withdrawal")
            need(events["announce"][0]["index"] < events["withdraw"][0]["index"],
                 f"{name} {prefix}: withdrawal precedes announcement")
        for kind in ("announce", "withdraw"):
            incoming, outgoing = original[kind][0], reflected[kind][0]
            need(incoming["nlri"] == outgoing["nlri"], f"{prefix}: {kind} VPN NLRI changed")
            need(incoming["next_hop"] == outgoing["next_hop"], f"{prefix}: next hop changed")
            compare_attributes(incoming["attrs"], outgoing["attrs"], announcement=kind == "announce")
        announcement = original["announce"][0]
        families[f"vpnv{4 if afi == 1 else 6}"] = {
            "prefix": prefix, "rd": "65001:111", "announcement_count_per_leg": 1,
            "withdrawal_count_per_leg": 1, "nlri_hex": announcement["nlri"].hex(),
            "withdrawn_nlri_hex": original["withdraw"][0]["nlri"].hex(),
            "next_hop_hex": announcement["next_hop"].hex(), **announcement["srv6"],
        }
    return {"schema": "m111-wire/1", "streams": streams, "families": families}


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} PAYLOADS.tsv", file=sys.stderr)
        return 2
    receipt = analyze(Path(sys.argv[1]).read_text(encoding="utf-8").splitlines(keepends=True))
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"M111 packet oracle failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
