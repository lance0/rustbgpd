#!/usr/bin/env python3
"""Verify native global-table SRv6 service reflection from TCP payloads."""

from __future__ import annotations

import ipaddress
import json
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

from m105_capture_oracle import capabilities, messages, need, reassemble, update
from m111_capture_oracle import compare_attributes, tlvs

SOURCE = "2001:db8:125:10::2"
RR_SOURCE = "2001:db8:125:10::1"
RR_SINK = "2001:db8:125:20::1"
SINK = "2001:db8:125:20::2"
DIRECTIONS = {
    (SOURCE, RR_SOURCE): "source_to_rr", (RR_SOURCE, SOURCE): "rr_to_source",
    (RR_SINK, SINK): "rr_to_sink", (SINK, RR_SINK): "sink_to_rr",
}
ROUTER_IDS = {SOURCE: "10.125.0.2", RR_SOURCE: "10.125.0.1",
              RR_SINK: "10.125.0.1", SINK: "10.125.0.3"}
PREFIXES = {1: "198.51.125.0/24", 2: "2001:db8:125:1000::/64"}
STRUCTURE = bytes([40, 24, 16, 0, 0, 0])
LOCATOR = ipaddress.IPv6Network("2001:db8:125:1::/64")


def srv6(value: bytes, afi: int) -> dict:
    services = tlvs(value)
    need(len(services) == 1 and services[0][0] == 5, "expected one L3 Service TLV")
    service = services[0][1]
    need(bool(service) and service[0] == 0, "invalid Service reserved field")
    infos = tlvs(service[1:])
    need(len(infos) == 1 and infos[0][0] == 1, "expected one SID Information sub-TLV")
    info = infos[0][1]
    need(len(info) >= 21, "short SID Information")
    need(info[0] == info[17] == info[20] == 0, "SID flags or reserved fields differ")
    behavior = int.from_bytes(info[18:20], "big")
    need(behavior == {1: 0x13, 2: 0x12}[afi], "unexpected endpoint behavior")
    need(tlvs(info[21:]) == [(1, STRUCTURE)], "global SID Structure differs")
    sid = ipaddress.IPv6Address(info[1:17])
    need(sid in LOCATOR, "SID outside configured locator")
    need((int(sid) >> 48) & 0xFFFF != 0, "SID Function is zero")
    need(int(sid) & ((1 << 48) - 1) == 0, "unexpected unused SID tail")
    return {"prefix_sid_hex": value.hex(), "service_sid": str(sid),
            "endpoint_behavior": behavior, "structure": list(STRUCTURE)}


def mp_attribute(code: int, value: bytes) -> tuple[int, bytes, bytes]:
    need(len(value) >= 3, "short MP attribute")
    afi, safi = struct.unpack("!HB", value[:3])
    need(afi in PREFIXES and safi == 1, "expected global unicast AFI/SAFI")
    if code == 15:
        return afi, b"", value[3:]
    need(len(value) >= 5, "short MP_REACH")
    length = value[3]
    need(length in (16, 32) and len(value) >= 5 + length, "invalid IPv6 next-hop length")
    next_hop = value[4:4 + length]
    need(value[4 + length] == 0, "MP_REACH reserved byte differs")
    need(next_hop[:16] == ipaddress.IPv6Address(SOURCE).packed, "source next hop differs")
    if length == 32:
        need(ipaddress.IPv6Address(next_hop[16:]).is_link_local, "second next hop is not link-local")
    return afi, next_hop, value[5 + length:]


def verify_stream(data: bytes, source: str, name: str) -> tuple[dict, dict]:
    decoded = messages(data)
    counts = Counter(kind for kind, _ in decoded)
    need(counts[1] == 1 and decoded[0][0] == 1, f"{name}: expected one initial OPEN")
    need(counts[3] == 0, f"{name}: NOTIFICATION present")
    need(set(counts) <= {1, 2, 4, 5}, f"{name}: unknown BGP message type")
    opening = decoded[0][1]
    caps = capabilities(opening)
    need(len(opening) == 10 + opening[9], "trailing OPEN bytes")
    need(int.from_bytes(opening[1:3], "big") == 65001, "OPEN AS differs")
    need(opening[5:9] == ipaddress.IPv4Address(ROUTER_IDS[source]).packed, "router ID differs")
    for afi in PREFIXES:
        need(struct.pack("!HBB", afi, 0, 1) in caps.get(1, []), "unicast family absent")
    ext = []
    for value in caps.get(5, []):
        need(len(value) % 6 == 0, "malformed Extended Next Hop capability")
        ext.extend(struct.iter_unpack("!HHH", value))
    if source in (RR_SOURCE, SINK):
        need((1, 1, 2) in ext, "IPv4 IPv6 next-hop receive capability absent")
    events = {afi: {"announce": [], "withdraw": []} for afi in PREFIXES}
    eors = Counter()
    for index, (kind, body) in enumerate(decoded):
        if kind != 2:
            continue
        withdrawn, attrs, announced = update(body)
        need(not announced, "legacy IPv4 announcement present")
        if not withdrawn and not attrs:
            eors[1] += 1
        if withdrawn:
            need(name in ("source_to_rr", "rr_to_sink") and withdrawn == [PREFIXES[1]],
                 "legacy IPv4 withdrawal identity differs")
            need(not attrs, "legacy withdrawal carries attributes")
            prefix = ipaddress.ip_network(PREFIXES[1])
            events[1]["withdraw"].append({
                "index": index, "attrs": attrs, "next_hop": b"",
                "nlri": bytes([prefix.prefixlen]) + prefix.network_address.packed[:3],
                "encoding": "legacy",
            })
        for code in (14, 15):
            if code not in attrs:
                continue
            need(attrs[code][0] & ~0x10 == 0x80, "MP attribute flags differ")
            afi, next_hop, nlri = mp_attribute(code, attrs[code][1])
            if not nlri:
                need(code == 15, "empty MP_REACH")
                need(len(attrs) == 1 and not withdrawn, "EoR carries other attributes or withdrawals")
                eors[afi] += 1
                continue
            need(name in ("source_to_rr", "rr_to_sink"), "unexpected reverse reachability")
            prefix = ipaddress.ip_network(PREFIXES[afi])
            expected = bytes([prefix.prefixlen]) + prefix.network_address.packed[:prefix.prefixlen // 8]
            need(nlri == expected, "global NLRI differs (labels and RD must be absent)")
            event = {"index": index, "attrs": attrs, "nlri": nlri,
                     "next_hop": next_hop, "encoding": "mp"}
            if code == 14:
                need(40 in attrs and attrs[40][0] & 0xC0 == 0xC0, "optional transitive Prefix-SID absent")
                event["srv6"] = srv6(attrs[40][1], afi)
            events[afi]["announce" if code == 14 else "withdraw"].append(event)
    need(all(count == 1 for count in eors.values()), "duplicate EoR")
    return {"open_count": counts[1], "notification_count": counts[3], "eor_counts": dict(eors),
            "message_counts": dict(sorted(counts.items()))}, events


def analyze(lines: list[str]) -> dict:
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
        need(bool(stream), "TCP stream ID absent")
        stream_ids[pair].add(stream)
        parts[pair].append((int(sequence), bytes.fromhex(payload.replace(":", ""))))
    need(set(stream_ids) == set(DIRECTIONS), "missing a session direction")
    streams, routes = {}, {}
    for pair, name in DIRECTIONS.items():
        need(len(stream_ids[pair]) == 1, f"{name}: reconnect or multiple TCP streams")
        need(stream_ids[pair] == stream_ids[(pair[1], pair[0])], "reverse stream ID differs")
        streams[name], routes[name] = verify_stream(reassemble(parts[pair]), pair[0], name)
        streams[name]["tcp_stream"] = next(iter(stream_ids[pair]))
    families = {}
    for afi, prefix in PREFIXES.items():
        original, reflected = routes["source_to_rr"][afi], routes["rr_to_sink"][afi]
        for name, events in (("source", original), ("reflected", reflected)):
            need(len(events["announce"]) == len(events["withdraw"]) == 1,
                 f"{name} {prefix}: expected one announcement and withdrawal")
            need(events["announce"][0]["index"] < events["withdraw"][0]["index"], "withdrawal precedes announcement")
        for kind in ("announce", "withdraw"):
            incoming, outgoing = original[kind][0], reflected[kind][0]
            need(incoming["nlri"] == outgoing["nlri"], "NLRI changed")
            # Link-local next hops identify the source link and are not carried
            # to the other client. The global next hop must remain identical.
            need(incoming["next_hop"][:16] == outgoing["next_hop"][:16], "next hop changed")
            if kind == "announce":
                need(len(outgoing["next_hop"]) == 16, "reflected next hop retains source link-local address")
            incoming_attrs = {k: v for k, v in incoming["attrs"].items() if k not in (14, 15)}
            attrs = {k: v for k, v in outgoing["attrs"].items() if k not in (14, 15)}
            if kind == "announce":
                for code, address in ((9, "10.125.0.2"), (10, "10.125.0.1")):
                    need(code not in incoming["attrs"], "source carries RR attributes")
                    need(code in attrs, f"reflected attribute {code} absent")
                    flags, value = attrs.pop(code)
                    need(flags & ~0x10 == 0x80 and value == ipaddress.IPv4Address(address).packed,
                         "RR attribute differs")
            compare_attributes(incoming_attrs, attrs, announcement=False)
        advertisement = original["announce"][0]
        families[f"ipv{4 if afi == 1 else 6}"] = {
            "prefix": prefix, "afi": afi, "safi": 1,
            "announcement_count_per_leg": 1, "withdrawal_count_per_leg": 1,
            "nlri_hex": advertisement["nlri"].hex(), "next_hop_hex": advertisement["next_hop"].hex(),
            "reflected_next_hop_hex": reflected["announce"][0]["next_hop"].hex(),
            "source_withdrawal_encoding": original["withdraw"][0]["encoding"],
            "reflected_withdrawal_encoding": reflected["withdraw"][0]["encoding"],
            **advertisement["srv6"],
        }
    return {"schema": "m125-wire/1", "streams": streams, "families": families}


if __name__ == "__main__":
    try:
        need(len(sys.argv) == 2, "usage: m125_capture_oracle.py PAYLOADS.tsv")
        print(json.dumps(analyze(Path(sys.argv[1]).read_text().splitlines()), sort_keys=True))
    except (OSError, ValueError) as error:
        print(f"M125 packet oracle failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
