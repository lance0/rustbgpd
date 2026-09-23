#!/usr/bin/env python3
"""Run a rendered arouteserver-mode route server and check RPKI-invalid export.

The caller renders the route-server config into ``--rendered`` with the RTR
cache address ``127.0.0.1:3323``. This script serves the VRPs from an
in-process RTR cache, rewrites that address and the host paths, starts the
daemon, and drives raw eBGP members from 127.0.0.2 (the announcer) and
127.0.0.3/127.0.0.4 (the receivers).

A loopback NEXT_HOP is malformed on the wire, so the announcer uses 192.0.2.2
and the rendered strict next-hop ownership check is dropped; it does not take
part in RPKI handling.
"""

import argparse
import importlib.util
import ipaddress
import json
from pathlib import Path
import select
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("raw", ROOT / "tests/interop/scripts/m105_raw_peer.py")
raw = importlib.util.module_from_spec(SPEC)
sys.modules["raw"] = raw
SPEC.loader.exec_module(raw)

ANNOUNCER, ANNOUNCER_AS = 2, 4242
RECEIVERS = {3: 4243, 4: 4244}
INVALID = "198.51.100.0/24"
VALID = "203.0.113.0/24"
NOT_FOUND = "198.18.0.0/24"
# Invalid by maxLength under VALID's own ROA: the usual blackhole shape.
BLACKHOLE = "203.0.113.66/32"
BLACKHOLE_MARKER = (65500, 666)
ROA_INVALID = ("198.51.100.0", 24, 24, 64511)
ROA_VALID = ("203.0.113.0", 24, 24, ANNOUNCER_AS)
ROA_MAKES_INVALID_VALID = ("198.51.100.0", 24, 24, ANNOUNCER_AS)


class RtrCache:
    """RTR cache (RFC 8210 PDUs) with Serial Notify and incremental updates."""

    def __init__(self, roas):
        self.lock = threading.Lock()
        self.tables = [set(roas)]
        self.sessions = []
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.port = self.listener.getsockname()[1]
        self.full_tables_served = 0
        threading.Thread(target=self.accept, daemon=True).start()

    @staticmethod
    def prefix_pdu(version, announce, roa):
        address, length, max_length, asn = roa
        return struct.pack("!BBHIBBBx", version, 4, 0, 20, int(announce), length, max_length) \
            + socket.inet_aton(address) + struct.pack("!I", asn)

    def serve(self, stream, version, since):
        with self.lock:
            serial = len(self.tables) - 1
            current = self.tables[serial]
            if since is None:
                pdus = [self.prefix_pdu(version, True, roa) for roa in sorted(current)]
            else:
                old = self.tables[since]
                pdus = [self.prefix_pdu(version, False, roa) for roa in sorted(old - current)]
                pdus += [self.prefix_pdu(version, True, roa) for roa in sorted(current - old)]
        stream.sendall(struct.pack("!BBHI", version, 3, 1, 8) + b"".join(pdus)
                       + struct.pack("!BBHIIIII", version, 7, 1, 24, serial, 3600, 600, 7200))
        if since is None:
            self.full_tables_served += 1

    def session(self, stream):
        try:
            while True:
                header = raw.recvn(stream, 8)
                version, kind = header[0], header[1]
                body = raw.recvn(stream, struct.unpack("!I", header[4:8])[0] - 8)
                with self.lock:
                    if (stream, version) not in self.sessions:
                        self.sessions.append((stream, version))
                if kind == 2:
                    self.serve(stream, version, None)
                elif kind == 1:
                    since = struct.unpack("!I", body[:4])[0]
                    if since < len(self.tables):
                        self.serve(stream, version, since)
                    else:
                        stream.sendall(struct.pack("!BBHI", version, 8, 0, 8))
        except (EOFError, OSError):
            pass

    def accept(self):
        while True:
            stream, _ = self.listener.accept()
            threading.Thread(target=self.session, args=(stream,), daemon=True).start()

    def publish(self, roas):
        with self.lock:
            self.tables.append(set(roas))
            serial = len(self.tables) - 1
            for stream, version in self.sessions:
                try:
                    stream.sendall(struct.pack("!BBHII", version, 0, 1, 12, serial))
                except OSError:
                    pass


def prefixes(data):
    result = set()
    while data:
        bits = data[0]
        count = (bits + 7) // 8
        result.add(str(ipaddress.IPv4Address(data[1:count + 1] + bytes(4 - count))) + f"/{bits}")
        data = data[count + 1:]
    return result


def bound_bgp_port(log_path, daemon):
    deadline = time.monotonic() + 30
    while True:
        for line in log_path.read_text().splitlines():
            try:
                fields = json.loads(line).get("fields", {})
            except ValueError:
                continue
            if fields.get("message") == "BGP listener bound":
                return int(fields["addr"].rsplit(":", 1)[1])
        assert daemon.poll() is None, "daemon exited before binding its BGP listener"
        assert time.monotonic() < deadline, "daemon did not report its BGP listener"
        time.sleep(.1)


def announcement(prefix, communities=()):
    attrs = raw.attribute(0x40, 1, b"\0")
    attrs += raw.attribute(0x40, 2, struct.pack("!BBI", 2, 1, ANNOUNCER_AS))
    attrs += raw.attribute(0x40, 3, ipaddress.IPv4Address("192.0.2.2").packed)
    if communities:
        attrs += raw.attribute(0xC0, 8, b"".join(struct.pack("!HH", *c) for c in communities))
    return raw.message(2, b"\0\0" + struct.pack("!H", len(attrs)) + attrs + raw.nlri(prefix))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--rbgp", required=True, type=Path)
    parser.add_argument("--rendered", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--scenario", required=True, choices=("plain", "blackhole-site"))
    args = parser.parse_args()
    blackhole = args.scenario == "blackhole-site"
    args.out.chmod(0o700)
    run = args.out / "run"
    shutil.copytree(args.rendered, run)
    state = args.out / "state"
    state.mkdir(mode=0o700)
    grpc = state / "grpc.sock"

    rtr = RtrCache([ROA_INVALID, ROA_VALID])
    config_path = run / "config.toml"
    config = config_path.read_text()
    for old, new in (
        ("listen_port = 179\n",
         f'listen_port = 0\nlisten_addresses = ["127.0.0.1"]\nruntime_state_dir = "{state}"\n'),
        ('path = "/var/lib/rustbgpd/grpc.sock"', f'path = "{grpc}"'),
        ('address = "127.0.0.1:3323"', f'address = "127.0.0.1:{rtr.port}"'),
        ('next_hop_ownership = "strict_peer"\n', ""),
    ):
        assert config.count(old) == (3 if old.startswith("next_hop") else 1), (old, config)
        config = config.replace(old, new)
    config_path.write_text(config)

    sessions, routes, checks = {}, {}, []
    routes_to_send = [announcement(INVALID), announcement(VALID), announcement(NOT_FOUND)]
    if blackhole:
        routes_to_send.append(announcement(BLACKHOLE, [BLACKHOLE_MARKER]))
    last_keepalive = time.monotonic()
    log_path = args.out / "daemon.log"
    log = log_path.open("w")
    daemon = subprocess.Popen([str(args.binary), str(config_path)], stdout=log, stderr=log)

    def rbgp(*command):
        result = subprocess.run([str(args.rbgp), "--addr", f"unix://{grpc}", "--json", *command],
                                capture_output=True, text=True, timeout=20)
        assert result.returncode == 0, (command, result.stdout, result.stderr)
        return json.loads(result.stdout)

    def connect(last, asn):
        deadline = time.monotonic() + 30

        def remaining():
            left = deadline - time.monotonic()
            assert daemon.poll() is None and left > 0, f"peer 127.0.0.{last} did not connect"
            return left

        while True:
            stream = socket.socket()
            stream.settimeout(remaining())
            stream.bind((f"127.0.0.{last}", 0))
            try:
                stream.connect(("127.0.0.1", bgp_port))
                caps = raw.capability(1, struct.pack("!HBB", 1, 0, 1)) + raw.capability(2, b"")
                caps += raw.capability(9, bytes([2])) + raw.capability(65, struct.pack("!I", asn))
                optional = bytes([2, len(caps)]) + caps
                body = struct.pack("!BHHIB", 4, asn, 90, int(ipaddress.IPv4Address(f"192.0.2.{last}")),
                                   len(optional))
                stream.sendall(raw.message(1, body + optional))
                stream.settimeout(remaining())
                kind, body = raw.read_message(stream)
                assert kind == 1, ("expected OPEN", last, kind, body.hex())
                stream.sendall(raw.message(4))
                stream.settimeout(remaining())
                kind, body = raw.read_message(stream)
                assert kind == 4, ("expected KEEPALIVE", last, kind, body.hex())
                stream.settimeout(2)
                sessions[last], routes[last] = stream, set()
                stream.sendall(raw.message(2, b"\0\0\0\0"))
                return
            except (ConnectionRefusedError, ConnectionResetError, EOFError, TimeoutError):
                stream.close()
                remaining()
                time.sleep(.1)

    def drain(seconds):
        nonlocal last_keepalive
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            assert daemon.poll() is None, "daemon exited"
            if time.monotonic() - last_keepalive >= 5:
                for stream in sessions.values():
                    stream.sendall(raw.message(4))
                last_keepalive = time.monotonic()
            ready, _, _ = select.select(list(sessions.values()), [], [], .05)
            for stream in ready:
                last = next(peer for peer, value in sessions.items() if value is stream)
                kind, body = raw.read_message(stream)
                if kind == 2:
                    withdrawn_len = int.from_bytes(body[:2], "big")
                    routes[last] -= prefixes(body[2:2 + withdrawn_len])
                    pos = 2 + withdrawn_len
                    attrs_len = int.from_bytes(body[pos:pos + 2], "big")
                    routes[last] |= prefixes(body[pos + 2 + attrs_len:])
                elif kind == 5:
                    if last == ANNOUNCER:
                        for update in routes_to_send:
                            stream.sendall(update)
                    stream.sendall(raw.message(2, b"\0\0\0\0"))
                else:
                    assert kind == 4, ("unexpected BGP message", last, kind, body.hex())

    def wait(predicate, label, seconds=20):
        deadline = time.monotonic() + seconds
        while not predicate():
            assert time.monotonic() < deadline, (label, routes)
            drain(.1)
        drain(.5)
        assert predicate(), ("unstable result", label, routes)

    def validation(prefix):
        return json.dumps(rbgp("rpki", "validate", prefix, str(ANNOUNCER_AS))).lower()

    def rib(view, peer):
        document = rbgp("rib", view, f"127.0.0.{peer}")
        rows = document if isinstance(document, list) else document["routes"]
        return {row["prefix"]: row.get("validation_state", "") for row in rows}

    def observe(label, exported):
        """Every receiver's Adj-RIB-Out, on the wire and over gRPC, is exactly `exported`."""
        try:
            wait(lambda: all(routes[peer] == exported for peer in RECEIVERS), label)
        except AssertionError:
            pass  # the checks below name what differs
        adj_in = rib("received", ANNOUNCER)
        sent = {peer: set(rib("advertised", peer)) for peer in RECEIVERS}
        checks.append({"label": label, "wire": {p: sorted(v) for p, v in routes.items()},
                       "adj_rib_in": adj_in, "adj_rib_out": {p: sorted(v) for p, v in sent.items()}})
        (args.out / "checks.json").write_text(json.dumps(checks, indent=2) + "\n")
        announced = {INVALID, VALID, NOT_FOUND} | ({BLACKHOLE} if blackhole else set())
        assert set(adj_in) == announced, (label, "announcer Adj-RIB-In", adj_in)
        state = "valid" if INVALID in exported else "invalid"
        assert adj_in[INVALID] == state, (label, "announcer Adj-RIB-In", adj_in)
        if blackhole:
            assert adj_in[BLACKHOLE] == "invalid", (label, "announcer Adj-RIB-In", adj_in)
        for peer in RECEIVERS:
            assert routes[peer] == exported, (label, f"127.0.0.{peer} received on the wire", sorted(routes[peer]))
            assert sent[peer] == exported, (label, f"127.0.0.{peer} Adj-RIB-Out", sorted(sent[peer]))

    try:
        bgp_port = bound_bgp_port(log_path, daemon)
        connect(ANNOUNCER, ANNOUNCER_AS)
        for peer, asn in RECEIVERS.items():
            connect(peer, asn)
        deadline = time.monotonic() + 30
        while rtr.full_tables_served == 0 or '"invalid"' not in validation(INVALID):
            assert time.monotonic() < deadline, "the daemon did not load the VRPs"
            drain(.2)
        for update in routes_to_send:
            sessions[ANNOUNCER].sendall(update)
        # The invalid route is retained (Adj-RIB-In) but reaches no member.
        # An authorized blackhole request is not origin-validated (ARouteServer
        # parity), so it is still announced although its /32 is RPKI-invalid.
        expected = {VALID, NOT_FOUND} | ({BLACKHOLE} if blackhole else set())
        observe("initial", expected)
        if not blackhole:
            rtr.publish([ROA_INVALID, ROA_VALID, ROA_MAKES_INVALID_VALID])
            observe("invalid-to-valid", expected | {INVALID})
            rtr.publish([ROA_INVALID, ROA_VALID])
            observe("valid-to-invalid", expected)
        (args.out / "result.json").write_text(json.dumps({"status": "pass", "checks": [c["label"] for c in checks]}) + "\n")
        print(f"{args.scenario}: " + ", ".join(c["label"] for c in checks) + " passed")
    finally:
        for stream in sessions.values():
            stream.close()
        daemon.terminate()
        try:
            daemon.wait(timeout=10)
        except subprocess.TimeoutExpired:
            daemon.kill()
            daemon.wait(timeout=10)
        log.close()


if __name__ == "__main__":
    main()
