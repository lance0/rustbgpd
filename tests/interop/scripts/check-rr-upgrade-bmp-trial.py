#!/usr/bin/env python3
"""Bounded IPv4 RR upgrade receipt assertions; never manufactures BMP data.

The existing raw sink supplies complete message bytes. The existing CLI owns
OPEN negotiation, EOR completeness, conversion, and semantic comparison.
GoBGP's per-neighbor Adj-RIB-In proves delivery at the independent observer.
"""

import importlib.util
import ipaddress
import json
from pathlib import Path
import sys
import tempfile

PREFIX = "198.51.100.0/24"
ORIGINATOR = "192.0.2.20"
SPEC = importlib.util.spec_from_file_location(
    "m81", Path(__file__).with_name("m81-bmp-assert.py")
)
M81 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M81)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def capture(source, connection, observer, destination):
    rows = [row for row in M81.load(source) if row["conn"] == int(connection)]
    require(rows and rows[0]["type"] == M81.INIT, "capture lacks initial Initiation")
    require([row["seq"] for row in rows] == list(range(len(rows))), "capture sequence gap")
    selected = []
    peer_up = False
    for row in rows:
        raw = row["raw"]
        require(len(raw) >= 6 and raw[0] == 3, "expected BMP version 3")
        require(int.from_bytes(raw[1:5], "big") == len(raw), "BMP length mismatch")
        require(raw[5] == row["type"], "sink type differs from original bytes")
        if row["type"] not in (M81.RM, M81.PEER_UP, M81.PEER_DOWN):
            continue
        require(len(raw) >= 48, "short BMP peer header")
        kind, flags, address = M81.peer_hdr(row)
        if address != observer:
            continue
        require(kind == 0, "observer is not a global-instance peer")
        require(row["type"] != M81.PEER_DOWN, "observer disconnected during capture")
        if row["type"] == M81.PEER_UP:
            require(not peer_up, "multiple observer generations in capture")
            peer_up = True
        else:
            require(peer_up, "UPDATE precedes observer Peer Up")
            require(flags & 0xD0 == 0x50, "expected IPv4 O=1/L=1 outgoing post-policy")
            selected.append(M81.pdu_kind(M81.rm_pdu(row)))
    require("announce" in selected and "eor" in selected, "missing announcement or EOR")
    # Reconstruct this actual TCP connection without changing any BMP bytes.
    Path(destination).write_bytes(b"".join(row["raw"] for row in rows))
    return {"connection": int(connection), "messages": len(rows), "observer_updates": selected}


def observer(data, next_hop, cluster):
    require(isinstance(data, dict) and set(data) == {PREFIX}, "observer prefix inventory differs")
    paths = data[PREFIX]
    require(len(paths) == 1, "observer requires exactly one path from this RR")
    attrs = paths[0]["attrs"]
    for kind, field, expected in [(3, "nexthop", next_hop), (9, "value", ORIGINATOR), (10, "value", [cluster])]:
        values = [attr[field] for attr in attrs if attr["type"] == kind]
        require(values == [expected], f"observer attribute {kind} differs: {values}")
    return {"delivered_prefix": PREFIX, "next_hop": next_hop, "originator": ORIGINATOR, "cluster_list": [cluster]}


def snapshot(path, peer, next_hop, cluster):
    rows = [json.loads(line) for line in Path(path).read_text().splitlines()]
    require(rows[0]["record"] == "header" and rows[-1] == {"record": "trailer", "routes": 1}, "snapshot is not one complete route")
    routes = [row for row in rows if row["record"] == "route"]
    require(len(routes) == 1, "snapshot route inventory differs")
    route = routes[0]
    require(route["peer"] == peer and route["peer_asn"] == 65001, "snapshot observer identity differs")
    require(route["prefix"] == PREFIX and route["next_hop"] == next_hop, "snapshot prefix or next hop differs")
    expected = [
        {"type_code": kind, "flags": 128, "value": ipaddress.IPv4Address(value).packed.hex()}
        for kind, value in [(9, ORIGINATOR), (10, cluster)]
    ]
    require(route["unknown_attrs"] == expected, "reflection numeric types, flags or full bytes differ")
    return {"reflection_attributes": route["unknown_attrs"]}


def report(data, divergent):
    require(data["schema"] == "rbgp-ribdiff/1", "unexpected comparison schema")
    require(data["verdict"] == ("divergent" if divergent else "in_sync"), "unexpected comparison verdict")
    entries = data["entries"]
    if not divergent:
        require(not entries, "equal trial contains differences")
        require(sum(row["matched"] for row in data["summaries"]) == 1, "empty equality is not proof")
    else:
        require(len(entries) == 1, "expected exactly one changed route")
        require(entries[0]["class"] == "attribute_changed", "expected attribute-only divergence")
        deltas = entries[0]["attribute_deltas"]
        require(len(deltas) == 1 and deltas[0]["attribute"] == "unknown", "expected only reflection attribute delta")
        for side, cluster in [("incumbent", "192.0.2.1"), ("rustbgpd", "192.0.2.2")]:
            expected = [
                {"type_code": kind, "flags": 128, "value": list(ipaddress.IPv4Address(value).packed)}
                for kind, value in [(9, ORIGINATOR), (10, cluster)]
            ]
            require(deltas[0][side] == expected, f"{side} delta lost reflection bytes")
    return {"verdict": data["verdict"]}


def self_test():
    # Format-level checker controls only, not producer or daemon qualification.
    good = {PREFIX: [{"attrs": [
        {"type": 3, "nexthop": "192.0.2.20"},
        {"type": 9, "value": ORIGINATOR},
        {"type": 10, "value": ["192.0.2.1"]},
    ]}]}
    observer(good, "192.0.2.20", "192.0.2.1")
    for broken in [{}, {PREFIX: []}, {PREFIX: good[PREFIX] * 2}]:
        try:
            observer(broken, "192.0.2.20", "192.0.2.1")
        except ValueError:
            pass
        else:
            raise AssertionError("incomplete or duplicate observer inventory passed")
    for index, field, value in [(0, "nexthop", "192.0.2.21"), (1, "value", "192.0.2.21"), (2, "value", ["192.0.2.2"])]:
        broken = json.loads(json.dumps(good))
        broken[PREFIX][0]["attrs"][index][field] = value
        try:
            observer(broken, "192.0.2.20", "192.0.2.1")
        except ValueError:
            pass
        else:
            raise AssertionError("wrong next hop or reflection attribute passed")
    equal = {"schema": "rbgp-ribdiff/1", "verdict": "in_sync", "entries": [], "summaries": [{"matched": 1}]}
    report(equal, False)
    empty = dict(equal, summaries=[])
    try:
        report(empty, False)
    except ValueError:
        pass
    else:
        raise AssertionError("empty equality passed")
    delta = {"attribute": "unknown"}
    for side, cluster in [("incumbent", "192.0.2.1"), ("rustbgpd", "192.0.2.2")]:
        delta[side] = [
            {"type_code": kind, "flags": 128, "value": list(ipaddress.IPv4Address(value).packed)}
            for kind, value in [(9, ORIGINATOR), (10, cluster)]
        ]
    divergent = {
        "schema": "rbgp-ribdiff/1", "verdict": "divergent",
        "entries": [{"class": "attribute_changed", "attribute_deltas": [delta]}],
    }
    report(divergent, True)
    for field, value in [("type_code", 9), ("flags", 192), ("value", [192, 0, 2])]:
        broken = json.loads(json.dumps(divergent))
        broken["entries"][0]["attribute_deltas"][0]["rustbgpd"][1][field] = value
        try:
            report(broken, True)
        except ValueError:
            pass
        else:
            raise AssertionError("wrong type, flags or truncated reflection bytes passed")
    # Minimal format fixtures exercise stream reconstruction and snapshot
    # assertions. They are never used by the native trial or its receipts.
    with tempfile.TemporaryDirectory(prefix="rr-upgrade-checker-") as temporary:
        directory = Path(temporary)
        peer = "192.0.2.30"
        header = bytearray(42)
        header[22:26] = ipaddress.IPv4Address(peer).packed
        header[26:30] = (65001).to_bytes(4, "big")
        header[30:34] = ipaddress.IPv4Address(peer).packed

        def bgp(kind, body):
            return b"\xff" * 16 + (19 + len(body)).to_bytes(2, "big") + bytes([kind]) + body

        def bmp(kind, body):
            return b"\x03" + (6 + len(body)).to_bytes(4, "big") + bytes([kind]) + body

        opens = bgp(1, bytes.fromhex("04fde9005ac000020a00"))
        opens += bgp(1, bytes.fromhex("04fde9005ac000021e00"))
        peer_up = bmp(M81.PEER_UP, header + bytes(20) + opens)
        header[1] = 0x50
        attrs = bytes.fromhex("40010100400200400304c000021440050400000064800904c0000214800a04c0000201")
        announce = bmp(M81.RM, header + bgp(2, b"\0\0" + len(attrs).to_bytes(2, "big") + attrs + bytes.fromhex("18c63364")))
        eor = bmp(M81.RM, header + bgp(2, bytes(4)))
        messages = [bmp(M81.INIT, b""), peer_up, announce, eor]
        rows = [{"conn": 0, "seq": index, "version": 3, "type": raw[5], "len": len(raw), "hex": raw.hex()} for index, raw in enumerate(messages)]
        source, destination = directory / "format.jsonl", directory / "format.bmp"
        source.write_text("".join(json.dumps(row) + "\n" for row in rows))
        capture(source, 0, peer, destination)
        require(destination.read_bytes() == b"".join(messages), "capture reconstruction changed original bytes")
        wrong_view = json.loads(json.dumps(rows))
        raw = bytes.fromhex(wrong_view[2]["hex"])
        wrong_view[2]["hex"] = (raw[:7] + b"\x40" + raw[8:]).hex()
        gap = json.loads(json.dumps(rows))
        gap[2]["seq"] = 9
        for broken in [rows[:-1], wrong_view, gap]:
            source.write_text("".join(json.dumps(row) + "\n" for row in broken))
            try:
                capture(source, 0, peer, destination)
            except ValueError:
                pass
            else:
                raise AssertionError("missing EOR, incoming view or sequence gap passed")

        golden = Path(__file__).parents[3] / "crates/cli/tests/fixtures/ribsnap/rr-from-bmp.expected.ndjson"
        snapshot(golden, peer, ORIGINATOR, "192.0.2.1")
        records = [json.loads(line) for line in golden.read_text().splitlines()]
        truncated = records[:-1]
        wrong_peer = json.loads(json.dumps(records))
        wrong_peer[1]["peer"] = "192.0.2.31"
        wrong_bytes = json.loads(json.dumps(records))
        wrong_bytes[1]["unknown_attrs"][1]["value"] = "c00002"
        for broken in [truncated, wrong_peer, wrong_bytes]:
            source.write_text("".join(json.dumps(row) + "\n" for row in broken))
            try:
                snapshot(source, peer, ORIGINATOR, "192.0.2.1")
            except ValueError:
                pass
            else:
                raise AssertionError("truncated snapshot, wrong observer or incomplete bytes passed")
    return {"checker_controls": "passed"}


if __name__ == "__main__":
    try:
        command, *args = sys.argv[1:]
        if command == "capture":
            result = capture(*args)
        elif command == "observer":
            result = observer(json.loads(Path(args[0]).read_text()), *args[1:])
        elif command == "snapshot":
            result = snapshot(*args)
        elif command == "report":
            result = report(json.loads(Path(args[0]).read_text()), args[1] == "divergent")
        elif command == "--self-test":
            result = self_test()
        else:
            raise ValueError("expected capture, observer, snapshot, report, or --self-test")
        print(json.dumps(result, indent=2))
    except (ValueError, KeyError, IndexError, TypeError, OSError) as error:
        sys.exit(f"FAIL: {error}")
