#!/usr/bin/env python3
"""M113: controlled Type 6 source -> rustbgpd RR -> raw receiver proof.

Run only in a reserved daemon/lab slot, with an explicit freshly built --daemon
and a new --output directory. Uses loopback addresses, no host network changes.
The PCAP is captured from the actual sockets; this is not vendor interoperability.
TShark 4.2.2 is pinned to the binary validated against upstream packet-bgp.c at
40459284278611128aac5cef35a563218933f8da. All phase progress requires wire evidence.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import getpass
import os
import ipaddress
import json
from pathlib import Path
import select
import shutil
import signal
import socket
import struct
import subprocess
import time
import xml.etree.ElementTree as ET

from evpn_peer_sync_oracle import attribute
from m94_as4_oracle import BgpReader, send_message
from m105_capture_oracle import capabilities, messages, need, reassemble, update

FAMILY = bytes.fromhex("001946")
RD = bytes.fromhex("0000fde900000006")
RT = bytes.fromhex("0002fde900000071")
RR = "127.0.0.1"
RR_ID = "10.113.0.1"
SOURCE, ALTERNATE, SINK = "127.0.0.2", "127.0.0.3", "127.0.0.4"
# Transport addresses stay loopback; BGP payloads use valid unicast identities.
NEXT_HOPS = {SOURCE: "192.0.2.2", ALTERNATE: "192.0.2.3"}
ROUTER_IDS = {SOURCE: "10.113.0.2", ALTERNATE: "10.113.0.3", SINK: "10.113.0.4"}
TSHARK_SHA256 = "1be3296c467ba299c4e89b4d6a2dfb8d0985a8bba2a8af3fa2ac3f10c3062668"
# Independent literal RFC 9251 layouts; do not derive expected bytes from smet().
VECTORS = [
    "06180000fde900000006000000000020ef01010120c0000201f2",
    "06340000fde900000006000000008020010db800000000000000000000000180ff3e000000000000000000000000000120c0000201f2",
    "06140000fde90000000600000000000020c000020100",
    "06200000fde9000000060000000000008020010db800000000000000000000000201",
]


def address(value: str) -> bytes:
    raw = b"" if value == "*" else ipaddress.ip_address(value).packed
    return bytes([len(raw) * 8]) + raw


def smet(source: str, group: str, originator: str, flags: int, tag: int = 0) -> bytes:
    body = RD + struct.pack("!I", tag) + address(source) + address(group) + address(originator)
    body += bytes([flags])
    return bytes([6, len(body)]) + body


def decode_smet(raw: bytes) -> dict:
    need(len(raw) >= 2 and raw[0] == 6 and len(raw) == raw[1] + 2, "bad Type 6 envelope")
    need(len(raw) >= 18, "short SMET payload")
    cursor, values, lengths = 14, [], []
    for index in range(3):
        need(cursor < len(raw), "missing SMET address length")
        width = raw[cursor]
        cursor += 1
        need(width in ((32, 128) if index == 2 else (0, 32, 128)), "bad SMET address length")
        size = width // 8
        need(cursor + size <= len(raw), "truncated SMET address")
        values.append(str(ipaddress.ip_address(raw[cursor:cursor + size])) if size else "*")
        lengths.append(width)
        cursor += size
    need(cursor + 1 == len(raw), "missing or extra SMET Flags octet")
    need(not (lengths[0] and not lengths[1]), "source with wildcard group")
    need(not lengths[0] or lengths[0] == lengths[1], "mixed source/group families")
    return {"rd": raw[2:10].hex(), "tag": int.from_bytes(raw[10:14], "big"),
            "source": values[0], "group": values[1], "originator": values[2],
            "lengths": lengths, "flags": raw[-1]}


def key(raw: bytes) -> str:
    decode_smet(raw)
    return raw[:-1].hex()


def split_nlri(data: bytes) -> list[bytes]:
    result = []
    while data:
        need(len(data) >= 2, "truncated EVPN envelope")
        length = 2 + data[1]
        raw, data = data[:length], data[length:]
        decode_smet(raw)
        result.append(raw)
    return result


def update_body(announced=(), withdrawn=(), *, peer=SOURCE, preference=200) -> bytes:
    attrs = b""
    if announced:
        attrs = attribute(1, b"\0", 0x40) + attribute(2, b"", 0x40)
        attrs += attribute(5, struct.pack("!I", preference), 0x40) + attribute(16, RT, 0xC0)
        reach = FAMILY + b"\x04" + ipaddress.IPv4Address(NEXT_HOPS[peer]).packed + b"\0"
        attrs += attribute(14, reach + b"".join(announced))
    if withdrawn:
        attrs += attribute(15, FAMILY + b"".join(withdrawn))
    return b"\0\0" + struct.pack("!H", len(attrs)) + attrs


def reflected_events(body: bytes) -> list[dict]:
    withdrawn, attrs, announced = update(body)
    need(not withdrawn and not announced, "unexpected IPv4 NLRI")
    events = []
    if 15 in attrs:
        raw = attrs[15][1]
        need(raw[:3] == FAMILY, "wrong withdrawal family")
        for nlri in split_nlri(raw[3:]):
            need(nlri[-1] == 0, "key-derived withdrawal did not use zero flags")
            events.append({"kind": "withdraw", "key": key(nlri), "nlri": nlri.hex()})
    if 14 in attrs:
        reach = attrs[14][1]
        need(len(reach) >= 9 and reach[:4] == FAMILY + b"\x04" and reach[8] == 0,
             "wrong reflected next-hop framing")
        next_hop = str(ipaddress.IPv4Address(reach[4:8]))
        peer = next((peer for peer, expected in NEXT_HOPS.items() if next_hop == expected), None)
        need(peer is not None, "rewritten reflected next hop")
        for code, expected in [(1, b"\0"), (2, b""), (16, RT),
                               (9, ipaddress.IPv4Address(ROUTER_IDS[peer]).packed),
                               (10, ipaddress.IPv4Address(RR_ID).packed)]:
            need(code in attrs and attrs[code][1] == expected, f"wrong reflected attribute {code}")
        need(5 in attrs and len(attrs[5][1]) == 4, "missing LOCAL_PREF")
        for nlri in split_nlri(reach[9:]):
            events.append({"kind": "announce", "key": key(nlri), "nlri": nlri.hex(),
                           "next_hop": next_hop, "originator_id": ROUTER_IDS[peer],
                           "preference": int.from_bytes(attrs[5][1], "big")})
    need(14 in attrs or 15 in attrs, "UPDATE has no EVPN MP attribute")
    return events


def expected_route(nlri: bytes, peer=SOURCE, preference=200) -> dict:
    return {"kind": "announce", "key": key(nlri), "nlri": nlri.hex(),
            "next_hop": NEXT_HOPS[peer], "originator_id": ROUTER_IDS[peer], "preference": preference}


def phase_complete(state: dict, seen: list, required: list, expected: dict) -> bool:
    authorized = Counter(required)
    observed = Counter((event["kind"], event["key"]) for event in seen)
    need(observed <= authorized, "unexpected or duplicate receiver transition during phase")
    for event in seen:
        if event["kind"] == "announce":
            need(event == expected.get(event["key"]), "wrong reflected payload or unexpected announcement")
    complete = observed == authorized
    if complete:
        need(state == expected, "wrong receiver state after phase acknowledgements")
    return complete


def open_body(peer: str) -> bytes:
    caps = b"\x01\x04\x00\x19\x00\x46\x41\x04" + struct.pack("!I", 65001)
    optional = bytes([2, len(caps)]) + caps
    return struct.pack("!BHH4sB", 4, 65001, 90, ipaddress.IPv4Address(ROUTER_IDS[peer]).packed,
                       len(optional)) + optional


class Peer:
    def __init__(self, peer: str, port: int, records: list, timeout: float):
        self.peer, self.sent, self.received = peer, [], []
        deadline = time.monotonic() + timeout
        while True:
            self.sock = socket.socket()
            self.sock.settimeout(0.25)
            self.sock.bind((peer, 0))
            try:
                self.sock.connect((RR, port))
                break
            except (ConnectionRefusedError, TimeoutError):
                self.sock.close()
                need(time.monotonic() < deadline, f"{peer}: daemon connection deadline")
                time.sleep(0.05)  # Readiness retry, never a phase/absence assertion.
        self.record = {"peer": peer, "port": self.sock.getsockname()[1],
                       "sent": self.sent, "received": self.received}
        records.append(self.record)
        self.reader = BgpReader(self.sock)
        self.sock.settimeout(timeout)
        try:
            self.send(1, open_body(peer))
            kind, body = self.read()
            need(kind == 1 and body[1:3] == struct.pack("!H", 65001)
                 and body[5:9] == ipaddress.IPv4Address(RR_ID).packed, "wrong RR OPEN")
            caps = capabilities(body)
            need(bytes.fromhex("00190046") in caps.get(1, [])
                 and caps.get(65) == [struct.pack("!I", 65001)], "missing EVPN/AS4 capability")
            self.send(4)
            need(self.read() == (4, b""), "expected RR KEEPALIVE")
            self.sock.settimeout(0.1)
            self.last_keepalive = time.monotonic()
        except BaseException:
            self.sock.close()
            raise

    def send(self, kind: int, body=b""):
        send_message(self.sock, kind, body)
        self.sent.append([kind, body.hex()])

    def read(self):
        kind, body = self.reader.read_message()
        self.received.append([kind, body.hex()])
        return kind, body

    def close(self):
        self.sock.close()


class Proof:
    def __init__(self, port: int, timeout: float, receipt: dict):
        self.port, self.timeout, self.receipt = port, timeout, receipt
        self.peers, self.state, self.events = {}, {}, []

    def connect(self, peer):
        connection = Peer(peer, self.port, self.receipt["connections"], self.timeout)
        self.peers[peer] = connection
        return connection

    def pump(self, deadline, *, resetting=None):
        need(time.monotonic() < deadline, "wire acknowledgement deadline exceeded")
        peers = list(self.peers.values())
        for peer in peers:
            if time.monotonic() - peer.last_keepalive >= 15:
                peer.send(4)
                peer.last_keepalive = time.monotonic()
        ready, _, _ = select.select([p.sock for p in peers], [], [], 0.1)
        for peer in peers:
            if peer.sock not in ready and not peer.reader.buffer:
                continue
            try:
                kind, body = peer.read()
            except socket.timeout:
                continue
            if kind == 3 and peer.peer == resetting:
                need(body[:2] == bytes([3, 9]), f"wrong reset NOTIFICATION: {body.hex()}")
                return True
            need(kind in (2, 4), f"unexpected BGP message from RR: {kind} {body.hex()}")
            if kind == 2 and peer.peer == SINK:
                for event in reflected_events(body):
                    self.events.append(event)
                    if event["kind"] == "withdraw":
                        need(event["key"] in self.state, "withdrawal for absent receiver key")
                        del self.state[event["key"]]
                    else:
                        self.state[event["key"]] = event
        return False

    def phase(self, name: str, peer: str, body: bytes, expected: dict, required: list):
        start = len(self.events)
        self.peers[peer].send(2, body)
        deadline = time.monotonic() + self.timeout
        while True:
            self.pump(deadline)
            seen = self.events[start:]
            if phase_complete(self.state, seen, required, expected):
                self.receipt["phases"].append({"name": name, "events": seen,
                                               "receiver": dict(self.state)})
                print(f"PASS {name}", flush=True)
                return

    def expect_reset(self, name: str, body: bytes):
        start = len(self.events)
        self.peers[SOURCE].send(2, body)
        deadline = time.monotonic() + self.timeout
        while True:
            notified = self.pump(deadline, resetting=SOURCE)
            phase_complete(self.state, self.events[start:], [], {})
            if notified:
                break
        self.peers.pop(SOURCE).close()
        self.receipt["phases"].append({"name": name, "notification": "0309", "events": []})
        print(f"PASS {name}", flush=True)

    def run(self):
        self.connect(SINK)
        self.connect(SOURCE)
        self.connect(ALTERNATE)
        v4, target, default, wildcard_v6 = map(bytes.fromhex, VECTORS)
        initial = [v4, target, default, wildcard_v6]
        state = {key(n): expected_route(n) for n in initial}
        self.phase("four-independent-shapes", SOURCE, update_body(initial), state,
                   [("announce", key(n)) for n in initial])
        distinct = smet("2001:db8::1", "ff3e::1", "192.0.2.2", 0xf2)
        state = state | {key(distinct): expected_route(distinct)}
        self.phase("distinct-originator", SOURCE, update_body([distinct]), state,
                   [("announce", key(distinct))])
        changed = target[:-1] + b"\xfa"
        state = state | {key(target): expected_route(changed)}
        self.phase("flags-only-f2-to-fa", SOURCE, update_body([changed]), state,
                   [("announce", key(target))])
        marker = smet("*", "239.113.0.3", "192.0.2.3", 2)
        state = state | {key(marker): expected_route(marker, ALTERNATE, 100)}
        self.phase("lower-preference-alternate", ALTERNATE,
                   update_body([target, marker], peer=ALTERNATE, preference=100), state,
                   [("announce", key(marker))])
        state = state | {key(target): expected_route(target, ALTERNATE, 100)}
        self.phase("zero-flags-withdraw-fallback", SOURCE,
                   update_body(withdrawn=[target[:-1] + b"\0"]), state,
                   [("announce", key(target))])
        state = {k: v for k, v in state.items() if k != key(target)}
        self.phase("zero-flags-withdraw-last-path", ALTERNATE,
                   update_body(withdrawn=[target[:-1] + b"\0"], peer=ALTERNATE), state,
                   [("withdraw", key(target))])
        state = state | {key(target): expected_route(changed)}
        self.phase("restore-target", SOURCE, update_body([changed]), state,
                   [("announce", key(target))])
        # Canonical invalid (S,G) flags + valid sibling announcement + independent
        # explicit withdrawal. All three keys must disappear; unrelated keys stay.
        removed = [target, v4, default]
        state = {k: v for k, v in state.items() if k not in {key(n) for n in removed}}
        self.phase("update-wide-treat-as-withdraw", SOURCE,
                   update_body([target[:-1] + b"\xf0", v4], [default]), state,
                   [("withdraw", key(n)) for n in removed])
        state = state | {key(n): expected_route(n) for n in initial}
        self.phase("same-session-recovery", SOURCE, update_body(initial), state,
                   [("announce", key(n)) for n in removed])
        # Explicitly withdraw each source's remaining routes before reset controls.
        source_routes = initial + [distinct]
        state = {key(marker): expected_route(marker, ALTERNATE, 100)}
        self.phase("source-cleanup", SOURCE,
                   update_body(withdrawn=[n[:-1] + b"\0" for n in source_routes]), state,
                   [("withdraw", key(n)) for n in source_routes])
        self.phase("alternate-cleanup", ALTERNATE,
                   update_body(withdrawn=[marker[:-1] + b"\0"], peer=ALTERNATE), {},
                   [("withdraw", key(marker))])
        malformed = {
            "missing-flags": target[:1] + bytes([target[1] - 1]) + target[2:-1],
            "extra-byte": target[:1] + bytes([target[1] + 1]) + target[2:] + b"\0",
            "mixed-source-group-family": smet("192.0.2.1", "ff3e::1", "192.0.2.1", 2),
        }
        for name, raw in malformed.items():
            for withdraw in [False, True]:
                phase = f"reset-{name}-{'withdraw' if withdraw else 'announce'}"
                self.expect_reset(phase, update_body(
                    withdrawn=[raw]) if withdraw else update_body([raw]))
                # The source NOTIFICATION is on another TCP connection. A fresh
                # alternate-source marker acknowledges progress on the receiver
                # stream and rejects any earlier malformed-route leak/churn.
                self.phase(f"{phase}-receiver-barrier", ALTERNATE,
                           update_body([marker], peer=ALTERNATE, preference=100),
                           {key(marker): expected_route(marker, ALTERNATE, 100)},
                           [("announce", key(marker))])
                self.phase(f"{phase}-barrier-cleanup", ALTERNATE,
                           update_body(withdrawn=[marker[:-1] + b"\0"], peer=ALTERNATE), {},
                           [("withdraw", key(marker))])
                self.connect(SOURCE)
                self.phase(f"{phase}-recovery", SOURCE, update_body([target]),
                           {key(target): expected_route(target)}, [("announce", key(target))])
                self.phase(f"{phase}-cleanup", SOURCE,
                           update_body(withdrawn=[target[:-1] + b"\0"]), {},
                           [("withdraw", key(target))])

    def close(self):
        for peer in self.peers.values():
            peer.close()


def decoder_fields(root) -> Counter:
    result = Counter()
    need(not any(f.get("name") == "_ws.malformed" for f in root.iter()),
         "TShark reports malformed reflected packet")
    names = ["bgp.evpn.nlri.rt", "bgp.evpn.nlri.rd", "bgp.evpn.nlri.etag",
             "bgp.mcast_vpn_nlri_source_length", "bgp.mcast_vpn_nlri_group_length",
             "bgp.evpn.nlri.or_length", "bgp.evpn.nlri.igmp_mc_flags"]
    for node in root.iter("field"):
        if node.get("name") != "bgp.evpn.nlri":
            continue
        fields = {f.get("name"): f for f in node.iter("field")}
        need(all(n in fields for n in names), "TShark omitted a typed SMET field")
        numeric = lambda name, fields=fields: int(fields[name].get("show", ""), 0)
        decoded = [numeric("bgp.evpn.nlri.rt"), fields["bgp.evpn.nlri.rd"].get("value"),
                   numeric("bgp.evpn.nlri.etag")]
        for prefix, length_name in [
            ("bgp.mcast_vpn_nlri_source_addr", "bgp.mcast_vpn_nlri_source_length"),
            ("bgp.mcast_vpn_nlri_group_addr", "bgp.mcast_vpn_nlri_group_length"),
            ("bgp.evpn.nlri.or_addr", "bgp.evpn.nlri.or_length"),
        ]:
            width = numeric(length_name)
            present = [name for name in (prefix + "_ipv4", prefix + "_ipv6") if name in fields]
            if width == 0:
                need(not present, "TShark assigned an address to a wildcard")
                value = "*"
            else:
                need(width in (32, 128), "TShark reports invalid address width")
                name = prefix + ("_ipv4" if width == 32 else "_ipv6")
                need(present == [name], "TShark address is missing or uses the wrong family")
                value = str(ipaddress.ip_address(fields[name].get("show", "")))
            decoded.extend([width, value])
        decoded.append(numeric("bgp.evpn.nlri.igmp_mc_flags"))
        result[tuple(decoded)] += 1
    need(bool(result), "TShark decoded no reflected SMET")
    return result


def check_decoder(root, nlrib: list[bytes]) -> int:
    expected = Counter()
    for raw in nlrib:
        view = decode_smet(raw)
        source, group, origin = view["lengths"]
        expected[(6, view["rd"], view["tag"], source, view["source"], group, view["group"],
                  origin, view["originator"], view["flags"])] += 1
    need(decoder_fields(root) == expected,
         "independent TShark key/lengths/flags differ from actual reflected stream")
    return sum(expected.values())


def check_event_receipts(events: list, phases: list):
    accepted = [event for phase in phases for event in phase["events"]]
    need(events == accepted, "captured receiver events differ from accepted phase receipts")


def verify_saved_capture(output: Path, port: int, receipt: dict) -> dict:
    rows = (output / "payloads.tsv").read_text()
    streams = defaultdict(list)
    for row in rows.splitlines():
        stream, source, dest, sport, dport, sequence, payload = row.split("\t")
        streams[(stream, source, dest, int(sport), int(dport))].append(
            (int(sequence), bytes.fromhex(payload.replace(":", ""))))
    reflected = []
    for connection in receipt["connections"]:
        for sent in [True, False]:
            peer, local = connection["peer"], connection["port"]
            endpoint = (peer, RR, local, port) if sent else (RR, peer, port, local)
            matches = [parts for stream, parts in streams.items() if stream[1:] == endpoint]
            need(len(matches) == 1, f"capture missing/ambiguous connection {endpoint}")
            actual = [[kind, body.hex()] for kind, body in messages(reassemble(matches[0]))]
            expected = connection["sent" if sent else "received"]
            need(actual[:len(expected)] == expected, f"capture/transcript mismatch {endpoint}")
            if sent:
                need(actual == expected, "extra source bytes in PCAP")
            elif peer == SINK:
                need(all(kind == 4 and not body for kind, body in actual[len(expected):]),
                     "unacknowledged sink update/notification")
                reflected.extend(event for kind, raw in actual if kind == 2
                                 for event in reflected_events(bytes.fromhex(raw)))
    check_event_receipts(reflected, receipt["phases"])
    pdml = (output / "reflected.pdml").read_bytes()
    count = check_decoder(ET.fromstring(pdml), [bytes.fromhex(e["nlri"]) for e in reflected])
    return {"sha256": hashlib.sha256((output / "m113.pcap").read_bytes()).hexdigest(),
            "payloads_sha256": hashlib.sha256((output / "payloads.tsv").read_bytes()).hexdigest(),
            "pdml_sha256": hashlib.sha256(pdml).hexdigest(),
            "reflected_nlri_count": count, "tshark_full_key_and_flags_match": True}


def verify_capture(tshark: str, output: Path, port: int, receipt: dict):
    common = [tshark, "-r", str(output / "m113.pcap"), "-d", f"tcp.port=={port},bgp"]
    fields = ["tcp.stream", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
              "tcp.seq_raw", "tcp.payload"]
    rows = subprocess.run(common + ["-Y", "tcp.len > 0", "-T", "fields", "-E", "separator=/t"]
                          + [arg for field in fields for arg in ("-e", field)],
                          capture_output=True, check=True, text=True).stdout
    (output / "payloads.tsv").write_text(rows)
    pdml = subprocess.run(common + ["-Y", f"ip.dst == {SINK} && tcp.srcport == {port}",
                                   "-T", "pdml"], capture_output=True, check=True).stdout
    (output / "reflected.pdml").write_bytes(pdml)
    receipt["capture"] = verify_saved_capture(output, port, receipt)


def replay(output: Path):
    receipt = json.loads((output / "result.json").read_text())
    need(receipt.get("passed") is True and not receipt.get("cleanup_errors")
         and all(receipt.get(field) == 0 for field in ("runner_exit", "daemon_exit", "capture_exit")),
         "saved proof did not finish successfully with clean owned processes")
    need(receipt.get("tshark_sha256") == TSHARK_SHA256
         and "TShark (Wireshark) 4.2.2 " in receipt.get("tshark_version", ""),
         "saved proof used a different independent decoder")
    need(hashlib.sha256((output / "m113.pcap").read_bytes()).hexdigest() == receipt["capture"]["sha256"],
         "saved PCAP hash differs from original capture")
    need(verify_saved_capture(output, receipt["port"], receipt) == receipt["capture"],
         "replayed capture checks differ from saved receipt")


def config(output: Path, port: int) -> str:
    text = f'''config_epoch = 2
[global]
asn = 65001
router_id = "{RR_ID}"
cluster_id = "{RR_ID}"
listen_port = {port}
listen_addresses = ["{RR}"]
[global.telemetry]
log_format = "json"
[global.telemetry.grpc_uds]
path = {json.dumps(str(output / "api.sock"))}
access_mode = "read_only"
'''
    for peer in [SOURCE, ALTERNATE, SINK]:
        text += f'''\n[[neighbors]]
address = "{peer}"
remote_asn = 65001
hold_time = 90
graceful_restart = false
route_reflector_client = true
families = ["l2vpn_evpn"]
'''
    return text


def stop(process, sig=signal.SIGTERM):
    if process is not None and process.poll() is None:
        process.send_signal(sig)
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            raise RuntimeError("owned process required forced termination")


def termination_requested(signum, _frame):
    raise RuntimeError(f"received signal {signum}; stopping owned proof processes")


def remove_capture(name: str, receipt: dict):
    try:
        cleanup = subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=15)
        need(not cleanup.returncode or b"No such container" in cleanup.stderr,
             cleanup.stderr.decode(errors="replace"))
    except Exception as error:
        receipt["passed"] = False
        receipt.setdefault("cleanup_errors", []).append(str(error))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--daemon", type=Path, help="explicit daemon binary for a reserved live run")
    mode.add_argument("--replay", type=Path, help="recheck saved proof without a daemon, capture privilege, or TShark")
    parser.add_argument("--output", type=Path, help="new directory required for a live run")
    parser.add_argument("--tshark", default="tshark")
    parser.add_argument("--port", type=int, default=21179)
    parser.add_argument("--timeout", type=float, default=45)
    capture_options = parser.add_mutually_exclusive_group()
    capture_options.add_argument("--capture-sudo", action="store_true", help="use existing sudo -n tcpdump permission")
    capture_options.add_argument("--capture-image", help="existing Docker image with tcpdump; owned host-network capture only")
    args = parser.parse_args()
    if args.replay is not None:
        need(args.output is None and not args.capture_sudo and args.capture_image is None,
             "--replay cannot use live output/capture options")
        replay(args.replay)
        print(f"PASS replayed saved SMET proof: {args.replay}")
        return
    need(args.output is not None, "--daemon requires --output")
    signal.signal(signal.SIGTERM, termination_requested)
    daemon = args.daemon.resolve(strict=True)
    tshark = shutil.which(args.tshark)
    need(tshark is not None, "tshark unavailable")
    need(hashlib.sha256(Path(tshark).read_bytes()).hexdigest() == TSHARK_SHA256,
         "TShark binary differs from frozen 4.2.2 decoder")
    version = subprocess.check_output([tshark, "--version"], text=True)
    need("TShark (Wireshark) 4.2.2 " in version, "wrong TShark version")
    need(1024 <= args.port <= 65535 and args.timeout > 0, "invalid port/timeout")
    output = args.output.resolve()
    need(len(os.fsencode(output / "api.sock")) < 108, "output path is too long for the owned Unix socket")
    with socket.socket() as probe:
        probe.bind((RR, args.port))  # Refuse to attach this proof to an existing listener.
    output.mkdir(parents=True, exist_ok=False)
    receipt = {"passed": False, "port": args.port, "connections": [], "phases": [],
               "capture_image": args.capture_image,
               "daemon_sha256": hashlib.sha256(daemon.read_bytes()).hexdigest(),
               "tshark_sha256": TSHARK_SHA256, "tshark_version": version.splitlines()[0]}
    (output / "rr.toml").write_text(config(output, args.port))
    capture = process = proof = None
    capture_name = f"m113-capture-{os.getpid()}-{time.time_ns()}" if args.capture_image else None

    def stop_capture():
        if capture_name and capture is not None and capture.poll() is None:
            subprocess.run(["docker", "kill", "--signal=SIGINT", capture_name],
                           check=True, capture_output=True, timeout=10)
            capture.wait(timeout=15)
        else:
            stop(capture, signal.SIGINT)

    try:
        with (output / "capture.log").open("w+") as capture_log, (output / "daemon.log").open("w") as daemon_log:
            tcpdump = ["tcpdump", "-i", "lo", "-U", "-n", "-Z", getpass.getuser(),
                       "-w", str(output / "m113.pcap"), "tcp", "port", str(args.port)]
            command = (["sudo", "-n"] if args.capture_sudo else []) + tcpdump
            if capture_name:
                command = ["docker", "run", "--rm", "--name", capture_name, "--network", "host",
                           "--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN", "--mount",
                           f"type=bind,src={output},dst=/capture", args.capture_image,
                           "tcpdump", "-i", "lo", "-U", "-n", "-Z", "root",
                           "-w", "/capture/m113.pcap", "tcp", "port", str(args.port)]
            capture = subprocess.Popen(command, stdout=capture_log, stderr=capture_log)
            deadline = time.monotonic() + 10
            while "listening on" not in (output / "capture.log").read_text():
                need(capture.poll() is None and time.monotonic() < deadline,
                     "capture did not become ready; see capture.log")
                time.sleep(0.05)
            process = subprocess.Popen([str(daemon), str(output / "rr.toml")],
                                       stdout=daemon_log, stderr=daemon_log)
            proof = Proof(args.port, args.timeout, receipt)
            proof.run()
            proof.close()
            stop(process)
            stop_capture()
        need(process.returncode == 0, f"daemon exit {process.returncode}")
        need(capture.returncode == 0, f"capture exit {capture.returncode}")
        verify_capture(tshark, output, args.port, receipt)
        receipt["passed"] = True
        print(f"PASS captured reflection and pinned independent decoder: {output}")
    except Exception as error:
        receipt["error"] = str(error)
        raise
    finally:
        if proof:
            proof.close()
        for cleanup in [lambda: stop(process), stop_capture]:
            try:
                cleanup()
            except Exception as error:
                receipt["passed"] = False
                receipt.setdefault("cleanup_errors", []).append(str(error))
        if capture_name:
            # Also reap a stuck owned container if its docker-run client exited.
            remove_capture(capture_name, receipt)
        receipt["daemon_exit"] = process.returncode if process else None
        receipt["capture_exit"] = capture.returncode if capture else None
        receipt["runner_exit"] = 0 if receipt["passed"] else 1
        (output / "result.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        need(not receipt.get("cleanup_errors"), "owned process cleanup failed; see result.json")


if __name__ == "__main__":
    main()
