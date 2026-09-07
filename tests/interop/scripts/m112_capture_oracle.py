#!/usr/bin/env python3
"""Independent, bounded M112 MAC-only SRv6 EVPN wire and observer checks."""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import struct
from collections import Counter, defaultdict
from pathlib import Path

from m105_capture_oracle import capabilities, messages, need, reassemble, update

SOURCE = "2001:db8:112:10::2"
RR_SOURCE = "2001:db8:112:10::1"
RR_SINK = "2001:db8:112:20::1"
SINK = "2001:db8:112:20::2"
SOURCE_ID = "10.112.0.2"
RR_ID = "10.112.0.1"
SINK_ID = "10.112.0.3"
RD = "10.112.0.2:112"
SID = "2001:db8:112:1:1::"
STRUCTURE = [40, 24, 16, 0, 0, 0]
INVALID_STRUCTURE = [100, 24, 16, 0, 0, 0]
FAMILY = bytes.fromhex("001946")
TARGET = "02:00:00:00:01:12"
SURVIVOR = "02:00:00:00:02:12"
PHASES = ("baseline", "malformed", "recovery", "withdraw", "cleanup")
SEMANTIC_PHASES = PHASES[:3] + ("semantic_invalid", "semantic_recovery") + PHASES[3:]
EXPECTED = {
    "baseline": {TARGET, SURVIVOR}, "malformed": {SURVIVOR},
    "recovery": {TARGET, SURVIVOR}, "withdraw": {SURVIVOR}, "cleanup": set(),
    "semantic_invalid": {SURVIVOR}, "semantic_recovery": {TARGET, SURVIVOR},
}
DIRECTIONS = {
    (SOURCE, RR_SOURCE): "source_to_rr", (RR_SOURCE, SOURCE): "rr_to_source",
    (RR_SINK, SINK): "rr_to_sink", (SINK, RR_SINK): "sink_to_rr",
}
ROUTER_IDS = {SOURCE: SOURCE_ID, RR_SOURCE: RR_ID, RR_SINK: RR_ID, SINK: SINK_ID}


def tlvs(raw: bytes) -> list[tuple[int, bytes]]:
    result = []
    while raw:
        need(len(raw) >= 3, "truncated SRv6 TLV header")
        kind, length = struct.unpack("!BH", raw[:3])
        need(len(raw) >= 3 + length, "truncated SRv6 TLV value")
        result.append((kind, raw[3:3 + length]))
        raw = raw[3 + length:]
    return result


def service(value: bytes, *, semantic_invalid: bool = False) -> dict:
    structure = INVALID_STRUCTURE if semantic_invalid else STRUCTURE
    outer = tlvs(value)
    need(len(outer) == 1 and outer[0][0] == 6, "expected one L2 Service TLV6")
    body = outer[0][1]
    need(body[:1] == b"\0", "L2 reserved byte differs")
    infos = tlvs(body[1:])
    need(len(infos) == 1 and infos[0][0] == 1, "expected one SID Information")
    info = infos[0][1]
    need(len(info) >= 21, "short SID Information")
    need(info[0] == info[17] == info[20] == 0, "SID reserved bytes or flags differ")
    need(str(ipaddress.IPv6Address(info[1:17])) == SID, "service SID differs")
    need(info[18:20] == b"\0\x17", "expected End.DT2U23")
    need(tlvs(info[21:]) == [(1, bytes(structure))], "SID Structure differs")
    return {"sid": SID, "endpoint_behavior": 23, "structure": structure,
            "prefix_sid_hex": value.hex()}


def type2s(raw: bytes, *, withdrawn: bool = False) -> list[tuple[str, bytes]]:
    rows = []
    while raw:
        need(len(raw) >= 2 and raw[0] == 2 and raw[1] == 33,
             "expected MAC-only one-label Type2")
        nlri, raw = raw[:35], raw[35:]
        need(len(nlri) == 35, "truncated Type2")
        body = nlri[2:]
        need(body[:8] == bytes.fromhex("00010a7000020070"), "RD differs")
        need(body[18:22] == bytes(4), "Ethernet tag differs")
        need(body[22] == 48 and body[29] == 0, "MAC/IP lengths differ")
        mac = body[23:29].hex(":")
        need(mac in (TARGET, SURVIVOR), "unexpected MAC")
        # RFC 7432 section 7.2 excludes ESI and labels from the Type2 key.
        # Announcements still prove exact service bytes; withdrawals identify
        # a route without requiring those non-key fields to be retained.
        if not withdrawn:
            need(body[8:18] == bytes(10), "ESI differs")
            need(body[30:] == bytes.fromhex("000030"), "EVPN implicit-null label differs")
        rows.append((mac, nlri))
    need(len({mac for mac, _ in rows}) == len(rows), "duplicate Type2 in UPDATE")
    return rows


def mp(code: int, value: bytes) -> tuple[bytes, list[tuple[str, bytes]]]:
    need(value[:3] == FAMILY, "unexpected MP family")
    if code == 15:
        return b"", type2s(value[3:], withdrawn=True)
    need(len(value) >= 21 and value[3] == 16 and value[20] == 0,
         "expected 16-byte IPv6 next hop and zero reserved byte")
    next_hop = value[4:20]
    need(next_hop == ipaddress.IPv6Address(SOURCE).packed, "next hop differs")
    routes = type2s(value[21:])
    need(bool(routes), "empty MP_REACH")
    return next_hop, routes


def attributes(attrs: dict, *, reflected: bool, malformed: bool = False,
               semantic_invalid: bool = False) -> dict:
    expected = {1, 2, 5, 14, 16, 40} | ({9, 10} if reflected else set())
    need(set(attrs) == expected, "announcement attribute set differs")
    for code, flags, value in (
        (1, 0x40, b"\0"), (2, 0x40, b""), (5, 0x40, struct.pack("!I", 100)),
        (16, 0xC0, bytes.fromhex("0002fde900000070")),
    ):
        need(attrs[code][0] & ~0x10 == flags and attrs[code][1] == value,
             f"attribute {code} differs")
    need(attrs[14][0] & ~0x10 == 0x80, "MP_REACH flags differ")
    need(attrs[40][0] & ~0x10 in ((0xC0, 0xE0) if reflected else (0xC0,)),
         "Prefix-SID flags differ")
    if reflected:
        for code, address in ((9, SOURCE_ID), (10, RR_ID)):
            need(attrs[code][0] & ~0x10 == 0x80
                 and attrs[code][1] == ipaddress.IPv4Address(address).packed,
                 f"reflector attribute {code} differs")
    value = attrs[40][1]
    if malformed:
        # Traversable outer TLV and SID Information; only SID Structure's
        # declared value length is wrong (seven, with six bytes available).
        need(len(value) == 37 and value[-9:-6] == b"\x01\0\x07",
             "malformed control is not the expected nested-length error")
        repaired = value[:-7] + b"\x06" + value[-6:]
        return service(repaired)
    return service(value, semantic_invalid=semantic_invalid)


def verify_stream(data: bytes, source: str, name: str, *,
                  semantic_control: bool = False) -> tuple[dict, dict]:
    decoded = messages(data)
    counts = Counter(kind for kind, _ in decoded)
    need(bool(decoded) and decoded[0][0] == 1 and counts[1] == 1,
         f"{name}: expected one initial OPEN")
    need(counts[3] == 0, f"{name}: NOTIFICATION present")
    need(set(counts) <= {1, 2, 4, 5}, f"{name}: unexpected BGP message type")
    opening = decoded[0][1]
    caps = capabilities(opening)
    need(len(opening) == 10 + opening[9], "trailing OPEN data")
    need(int.from_bytes(opening[1:3], "big") == 65001, "OPEN AS differs")
    need(opening[5:9] == ipaddress.IPv4Address(ROUTER_IDS[source]).packed,
         "OPEN router ID differs")
    need(bytes.fromhex("00190046") in caps.get(1, []), "EVPN capability absent")
    need(caps.get(65) == [struct.pack("!I", 65001)], "AS4 capability differs")
    events = {TARGET: [], SURVIVOR: []}
    for index, (kind, body) in enumerate(decoded):
        if kind != 2:
            continue
        withdrawn, attrs, announced = update(body)
        need(not withdrawn and not announced, "legacy reachability present")
        need(not ({14, 15} <= attrs.keys()), "mixed MP_REACH/MP_UNREACH")
        need(14 in attrs or 15 in attrs, "UPDATE lacks EVPN MP attribute")
        code = 14 if 14 in attrs else 15
        next_hop, rows = mp(code, attrs[code][1])
        if code == 15:
            need(set(attrs) == {15} and attrs[15][0] & ~0x10 == 0x80,
                 "withdrawal attributes differ")
        if not rows:  # EVPN End-of-RIB
            continue
        need(name in ("source_to_rr", "rr_to_sink"), "unexpected reverse reachability")
        action = "withdraw" if code == 15 else "announce"
        if code == 14:
            need(40 in attrs, "Prefix-SID absent")
            malformed = name == "source_to_rr" and attrs[40][1][-9:-6] == b"\x01\0\x07"
            invalid = (semantic_control and name == "source_to_rr"
                       and attrs[40][1][-6:] == bytes(INVALID_STRUCTURE))
            attributes(attrs, reflected=name == "rr_to_sink", malformed=malformed,
                       semantic_invalid=invalid)
            if invalid:
                need([mac for mac, _ in rows] == [TARGET], "invalid UPDATE affects survivor")
                action = "semantic_invalid"
            if malformed:
                need([mac for mac, _ in rows] == [TARGET], "malformed UPDATE affects survivor")
                action = "malformed"
        for mac, nlri in rows:
            events[mac].append({"action": action, "index": index, "nlri": nlri,
                                "next_hop": next_hop, "attrs": attrs})
    return {"open_count": counts[1], "notification_count": counts[3],
            "message_counts": dict(sorted(counts.items()))}, events


def analyze(lines: list[str], *, semantic_control: bool = False) -> dict:
    parts, ids = defaultdict(list), defaultdict(set)
    for number, line in enumerate(lines, 1):
        fields = line.rstrip("\n").split("\t")
        need(len(fields) == 5, f"row {number}: expected five fields")
        stream, source, destination, sequence, payload = fields
        if not source or not destination or not payload:
            continue
        pair = (str(ipaddress.IPv6Address(source)), str(ipaddress.IPv6Address(destination)))
        if pair not in DIRECTIONS:
            continue
        need(bool(stream), "missing TCP stream ID")
        ids[pair].add(stream)
        parts[pair].append((int(sequence), bytes.fromhex(payload.replace(":", ""))))
    need(set(ids) == set(DIRECTIONS), "missing captured session direction")
    streams, routes = {}, {}
    for pair, name in DIRECTIONS.items():
        need(len(ids[pair]) == 1, f"{name}: reconnect or multiple TCP streams")
        need(ids[pair] == ids[(pair[1], pair[0])], "reverse stream ID differs")
        streams[name], routes[name] = verify_stream(
            reassemble(parts[pair]), pair[0], name, semantic_control=semantic_control)
        streams[name]["tcp_stream"] = next(iter(ids[pair]))
    expected_source = {TARGET: ["announce", "malformed", "announce", "withdraw"],
                       SURVIVOR: ["announce", "withdraw"]}
    expected_sink = {TARGET: ["announce", "withdraw", "announce", "withdraw"],
                     SURVIVOR: ["announce", "withdraw"]}
    if semantic_control:
        expected_source[TARGET][3:3] = ["semantic_invalid", "announce"]
        expected_sink[TARGET][3:3] = ["withdraw", "announce"]
    for name, expected in (("source_to_rr", expected_source), ("rr_to_sink", expected_sink)):
        for mac, actions in expected.items():
            need([event["action"] for event in routes[name][mac]] == actions,
                 f"{name} {mac}: wrong transition history")
        target, survivor = routes[name][TARGET], routes[name][SURVIVOR]
        need(survivor[0]["index"] < target[1]["index"]
             and survivor[-1]["index"] > target[-1]["index"],
             f"{name}: survivor does not span target transitions")
    for mac in (TARGET, SURVIVOR):
        incoming, outgoing = routes["source_to_rr"][mac], routes["rr_to_sink"][mac]
        for source, reflected in zip(incoming, outgoing, strict=True):
            if source["action"] == "announce":
                need(source["nlri"] == reflected["nlri"], "reflected NLRI differs")
                need(source["next_hop"] == reflected["next_hop"], "reflected next hop differs")
                for code in (1, 2, 5, 16, 40):
                    need(source["attrs"][code][1] == reflected["attrs"][code][1],
                         f"reflected attribute {code} value differs")
            else:
                # Compare RD plus Ethernet tag / MAC / empty IP fields. Both
                # rows have already passed the exact MAC-only Type2 shape.
                need((source["nlri"][2:10], source["nlri"][20:32])
                     == (reflected["nlri"][2:10], reflected["nlri"][20:32]),
                     "reflected withdrawal key differs")
    withdrawals = {
        name: sorted(({
            "mac": mac, "message_index": event["index"],
            "label_hex": event["nlri"][32:].hex(), "esi_hex": event["nlri"][10:20].hex(),
        } for mac, events in routes[name].items() for event in events
            if event["action"] == "withdraw"), key=lambda event: event["message_index"])
        for name in ("source_to_rr", "rr_to_sink")
    }
    return {"schema": "m112-semantic-wire/1" if semantic_control else "m112-wire/1", "streams": streams,
            "target": TARGET, "survivor": SURVIVOR, "rd": RD, "next_hop": SOURCE,
            "label_hex": "000030", **service(routes["source_to_rr"][TARGET][0]["attrs"][40][1]),
            "source_actions": expected_source, "reflected_actions": expected_sink,
            "withdrawals": withdrawals}


def observer(snapshot: list[dict], phase: str) -> dict:
    found = set()
    for response in snapshot:
        destination = response.get("destination", {})
        paths = destination.get("paths", [])
        need(len(paths) == 1, "observer must expose one retained path per destination")
        path = paths[0]
        need(path.get("best") is True, "observer path is not best")
        need(not any(path.get(key, False) for key in
                     ("isWithdraw", "filtered", "stale", "isNexthopInvalid")),
             "observer path is withdrawn, filtered, stale or invalid")
        need(path.get("family") == {"afi": 25, "safi": 70}, "observer family differs")
        need(path.get("sourceAsn") == 65001 and path.get("sourceId") == RR_ID
             and path.get("neighborIp") == RR_SINK, "observer source differs")
        nlri = base64.b64decode(path.get("nlriBinary", ""), validate=True)
        rows = type2s(nlri)
        need(len(rows) == 1, "observer NLRI missing or batched")
        mac = rows[0][0]
        need(mac not in found, "duplicate observer route")
        found.add(mac)
        raw_attrs = b"".join(base64.b64decode(value, validate=True)
                             for value in path.get("pattrsBinary", []))
        _, attrs, _ = update(b"\0\0" + struct.pack("!H", len(raw_attrs)) + raw_attrs)
        attributes(attrs, reflected=True)
        _, mp_rows = mp(14, attrs[14][1])
        need(mp_rows == rows, "observer MP_REACH and NLRI binary disagree")
    need(found == EXPECTED[phase], f"observer {phase}: route set differs: {sorted(found)}")
    return {"phase": phase, "macs": sorted(found), "binary_attributes_verified": True}


def rr_route(row: dict, *, require_typed: bool, semantic_invalid: bool = False) -> bool:
    need(row.get("route_type") == 2 and row.get("rd") == RD
         and row.get("ip", "") == "" and row.get("next_hop") == SOURCE
         and row.get("peer") == SOURCE and row.get("label") == 48
         and row.get("label2") == 0 and row.get("tunnel_type") == 0
         and row.get("ethernet_tag") == "0" and row.get("esi") == bytes(10).hex(":"),
         "RR route fields differ")
    view = row.get("prefix_sid")
    if view is None:
        need(not require_typed, "RR Prefix-SID typed visibility is required")
        return False
    service(bytes.fromhex(view.get("raw_value", "")), semantic_invalid=semantic_invalid)
    need(view.get("flags") == 0xC0, "RR stored Prefix-SID flags differ")
    need(not view.get("decode_error"), "RR typed Prefix-SID decode failed")
    services = view.get("services", [])
    need(len(services) == 1 and services[0].get("tlv_type") == 6, "RR service kind differs")
    infos = services[0].get("sids", [])
    need(len(infos) == 1 and infos[0].get("sid_value") == SID
         and infos[0].get("endpoint_behavior") == 23 and infos[0].get("flags") == 0,
         "RR SID information differs")
    structures = infos[0].get("structures", [])
    keys = ("locator_block_length", "locator_node_length", "function_length",
            "argument_length", "transposition_length", "transposition_offset")
    need(len(structures) == 1 and [structures[0].get(key) for key in keys] == (INVALID_STRUCTURE if semantic_invalid else STRUCTURE),
         "RR typed SID structure differs")
    return True


def rr(snapshot: list[dict], phase: str, *, require_typed: bool) -> dict:
    found = set()
    typed = True
    for row in snapshot:
        mac = row.get("mac")
        need(mac in (TARGET, SURVIVOR) and mac not in found, "unexpected or duplicate RR MAC")
        found.add(mac)
        typed = rr_route(row, require_typed=require_typed) and typed
    need(found == EXPECTED[phase], f"RR {phase}: route set differs")
    return {"phase": phase, "macs": sorted(found), "typed_visibility_verified": typed and bool(found)}


def received(snapshot: dict, phase: str) -> dict:
    need(snapshot.get("view") == "received" and snapshot.get("neighbor") == SOURCE,
         "received view or neighbor differs")
    need(snapshot.get("next_page_token") == "", "received page is incomplete")
    expected = {TARGET, SURVIVOR} if phase == "semantic_invalid" else EXPECTED[phase]
    rows = snapshot.get("routes", [])
    need(snapshot.get("total_count") == len(expected) == len(rows), "received count differs")
    need({row.get("mac") for row in rows} == expected, "received route set differs")
    for row in rows:
        rr_route(row, require_typed=True,
                 semantic_invalid=phase == "semantic_invalid" and row["mac"] == TARGET)
    return {"phase": phase, "macs": sorted(expected), "retained_attributes_verified": True}


def explain(snapshot: dict, phase: str) -> dict:
    need(phase in ("semantic_invalid", "semantic_recovery"), "unexpected explain phase")
    need(snapshot.get("key") == {"rd": RD, "mac_ip": {
        "ethernet_tag": 0, "mac": TARGET, "ip": ""}}, "explain key differs")
    need(snapshot.get("received_from") == SOURCE and snapshot.get("candidate_count") == 1,
         "explain source or candidate count differs")
    need(snapshot.get("selection_deferred") is False, "selection is deferred")
    invalid = phase == "semantic_invalid"
    route = snapshot.get("received")
    need(isinstance(route, dict) and route.get("mac") == TARGET, "retained target is absent")
    rr_route(route, require_typed=True, semantic_invalid=invalid)
    export = snapshot.get("export") or {}
    need(export.get("peer_address") == SINK and export.get("outbound_dirty") is False,
         "export destination differs or remains dirty")
    if invalid:
        need(snapshot.get("best") is None and snapshot.get("selection_best") is None,
             "invalid target remains selected")
        need((snapshot.get("selection_reason") or {}).get("code") == "srv6_sid_invalid",
             "semantic selection reason is absent")
        need(any(gate.get("gate") == "srv6_service" and gate.get("code") == "srv6_sid_invalid"
                 and gate.get("verdict") == "stop" for gate in export.get("gates", [])),
             "semantic export stop gate is absent")
        need(export.get("decision") == "no_best_route", "invalid export decision differs")
        need(export.get("staged") is None and export.get("advertised") is None
             and export.get("already_advertised") is False, "invalid target remains exported")
    else:
        need(snapshot.get("selection_reason") is None, "recovered target remains ineligible")
        for name in ("best", "selection_best"):
            need(snapshot.get(name) == route, f"recovered {name} differs from received")
        need(export.get("decision") == "advertise" and export.get("already_advertised") is True,
             "recovered target is not advertised")
        for name in ("staged", "advertised"):
            exported = export.get(name)
            need(isinstance(exported, dict) and exported.get("mac") == TARGET,
                 f"recovered {name} target absent")
            rr_route(exported, require_typed=True)
        need(not any(gate.get("code") == "srv6_sid_invalid" for gate in export.get("gates", [])),
             "recovered target retains semantic stop")
    return {"phase": phase, "target": TARGET, "retention_and_selection_verified": True}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("wire", "observer", "rr", "received", "explain"))
    parser.add_argument("path", type=Path)
    parser.add_argument("--phase", choices=SEMANTIC_PHASES)
    parser.add_argument("--require-typed", action="store_true")
    parser.add_argument("--semantic-control", action="store_true")
    args = parser.parse_args()
    if args.mode == "wire":
        result = analyze(args.path.read_text().splitlines(), semantic_control=args.semantic_control)
    else:
        need(args.phase is not None, "snapshot mode requires --phase")
        value = json.loads(args.path.read_text())
        if args.mode in ("received", "explain"):
            need(isinstance(value, dict), "snapshot must be a JSON object")
            result = received(value, args.phase) if args.mode == "received" else explain(value, args.phase)
        else:
            need(isinstance(value, list), "snapshot must be a JSON array")
            result = observer(value, args.phase) if args.mode == "observer" else rr(
                value, args.phase, require_typed=args.require_typed)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError) as error:
        raise SystemExit(f"M112 oracle failed: {error}") from error
