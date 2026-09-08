#!/usr/bin/env python3
"""Exercise global export replacement/removal with local raw iBGP peers."""

import argparse
import importlib.util
import ipaddress
import json
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("raw", ROOT / "tests/interop/scripts/m105_raw_peer.py")
raw = importlib.util.module_from_spec(SPEC)
sys.modules["raw"] = raw
SPEC.loader.exec_module(raw)
TEST = "198.51.100.0/24"
CONTROL = "198.51.101.0/24"


def prefixes(data):
    result = set()
    while data:
        bits = data[0]
        count = (bits + 7) // 8
        assert bits <= 32 and len(data) >= count + 1
        result.add(str(ipaddress.IPv4Address(data[1:count + 1] + bytes(4 - count))) + f"/{bits}")
        data = data[count + 1:]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--rbgp", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    args.out.mkdir(mode=0o700, exist_ok=True)
    (args.out / "state").mkdir(mode=0o700)
    with socket.socket() as bgp, socket.socket() as metrics:
        bgp.bind(("127.0.0.1", 0))
        metrics.bind(("127.0.0.1", 0))
        bgp_port, metrics_port = bgp.getsockname()[1], metrics.getsockname()[1]
    addr = "unix://" + str(args.out / "state/grpc.sock")
    config = f'''config_epoch = 2
[global]
asn = 65001
ebgp_requires_policy = true
router_id = "192.0.2.1"
cluster_id = "192.0.2.1"
listen_port = {bgp_port}
listen_addresses = ["127.0.0.1"]
runtime_state_dir = "{args.out}/state"
[global.telemetry]
prometheus_addr = "127.0.0.1:{metrics_port}"
log_format = "json"
[global.telemetry.grpc_uds]
path = "{args.out}/state/grpc.sock"
principal = "rustbgpd://operator/global-export-test"
[security.grpc]
enforcement = "tier"
[security.grpc.roles]
"rustbgpd://operator/global-export-test" = "operator"
[peer_groups.receivers]
route_reflector_client = true
families = ["ipv4_unicast"]
[[neighbors]]
address = "127.0.0.2"
remote_asn = 65001
peer_group = "receivers"
[[neighbors]]
address = "127.0.0.3"
remote_asn = 65001
peer_group = "receivers"
[[dynamic_neighbors]]
prefix = "127.0.0.4/32"
remote_asn = 65001
peer_group = "receivers"
[policy]
export_chain = CHAIN
[policy.definitions.deny-a]
default_action = "permit"
[[policy.definitions.deny-a.statements]]
prefix = "{TEST}"
action = "deny"
[policy.definitions.deny-b]
default_action = "permit"
[[policy.definitions.deny-b.statements]]
prefix = "{CONTROL}"
action = "deny"
'''
    config_path = args.out / "config.toml"
    for name, chain in (("a", ["deny-a"]), ("b", ["deny-b"]), ("none", [])):
        (args.out / f"{name}.toml").write_text(config.replace("CHAIN", json.dumps(chain)))
    config_path.write_bytes((args.out / "a.toml").read_bytes())
    if args.prepare_only:
        print("Fixtures prepared; no daemon started")
        return

    sessions, routes, snapshots = {}, {}, []
    last_keepalive = time.monotonic()
    log_path = args.out / "daemon.log"
    log = log_path.open("w")
    daemon = subprocess.Popen([str(args.binary), str(config_path)], stdout=log, stderr=log)

    def connect(last):
        deadline = time.monotonic() + 15
        while True:
            stream = socket.socket()
            stream.settimeout(2)
            stream.bind((f"127.0.0.{last}", 0))
            try:
                stream.connect(("127.0.0.1", bgp_port))
                caps = raw.capability(1, struct.pack("!HBB", 1, 0, 1))
                caps += raw.capability(2, b"") + raw.capability(65, struct.pack("!I", 65001))
                optional = bytes([2, len(caps)]) + caps
                body = struct.pack("!BHHIB", 4, 65001, 90, int(ipaddress.IPv4Address(f"192.0.2.{last}")), len(optional))
                stream.sendall(raw.message(1, body + optional))
                kind, _ = raw.read_message(stream)
                assert kind == 1, ("expected OPEN", kind)
                stream.sendall(raw.message(4))
                kind, _ = raw.read_message(stream)
                assert kind == 4, ("expected KEEPALIVE", kind)
                sessions[last], routes[last] = stream, set()
                stream.sendall(raw.message(2, b"\0\0\0\0"))
                return
            except (ConnectionRefusedError, ConnectionResetError, EOFError):
                stream.close()
                assert daemon.poll() is None and time.monotonic() < deadline, "peer did not connect"
                time.sleep(.1)

    attrs = raw.attribute(0x40, 1, b"\0") + raw.attribute(0x40, 2, b"")
    attrs += raw.attribute(0x40, 3, ipaddress.IPv4Address("192.0.2.2").packed)
    attrs += raw.attribute(0x40, 5, struct.pack("!I", 100))
    announcement = raw.message(2, b"\0\0" + struct.pack("!H", len(attrs)) + attrs + raw.nlri(TEST) + raw.nlri(CONTROL))

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
                    assert body == b"\0\1\0\1"
                    if last == 2:
                        stream.sendall(announcement)
                    stream.sendall(raw.message(2, b"\0\0\0\0"))
                else:
                    assert kind == 4, ("unexpected BGP message", last, kind, body.hex())

    def wait(predicate, label):
        deadline = time.monotonic() + 20
        while not predicate():
            assert time.monotonic() < deadline, (label, routes)
            drain(.1)
        drain(.2)
        assert predicate(), ("unstable result", label, routes)

    def observe(label, expected):
        wait(lambda: all(routes[peer] == expected for peer in sessions if peer != 2), label)
        result = subprocess.run([str(args.rbgp), "--addr", addr, "--json", "policy", "stats", "--direction", "export"], capture_output=True, text=True, timeout=10, check=True)
        snapshot = {"label": label, "routes": {str(peer): sorted(value) for peer, value in routes.items()}, "stats": json.loads(result.stdout)}
        snapshots.append(snapshot)
        (args.out / "snapshots.json").write_text(json.dumps(snapshots, indent=2) + "\n")

    def reload(name, expected):
        offset = log_path.stat().st_size
        config_path.write_bytes((args.out / f"{name}.toml").read_bytes())
        daemon.send_signal(signal.SIGHUP)
        wait(lambda: "reload generation applied" in log_path.read_text()[offset:], "SIGHUP completion")
        observe(f"reload-{name}", expected)

    def reconnect(last, label, expected):
        sessions.pop(last).close()
        routes.pop(last)
        # Wait for the old transport's peer-down before opening its replacement.
        drain(.5)
        connect(last)
        observe(label, expected)

    try:
        connect(2)
        connect(3)
        sessions[2].sendall(announcement)
        observe("initial-a", {CONTROL})
        reload("b", {TEST})
        reconnect(3, "static-b-reconnect", {TEST})
        connect(4)
        observe("dynamic-b-admission", {TEST})
        reload("none", {TEST, CONTROL})
        reconnect(3, "static-none-reconnect", {TEST, CONTROL})
        reconnect(4, "dynamic-none-reconnect", {TEST, CONTROL})
        for snapshot in snapshots:
            chains = snapshot["stats"]["chains"]
            assert all(row["peer_address"] != "global" for row in chains), snapshot
            if "none" in snapshot["label"]:
                assert chains == [], snapshot
            else:
                for peer in snapshot["routes"]:
                    if peer != "2":
                        rows = [row for row in chains if row["peer_address"] == f"127.0.0.{peer}"]
                        assert len(rows) == 1 and rows[0]["routes_evaluated"] > 0, snapshot
        (args.out / "result.json").write_text(json.dumps({"status": "pass", "phases": [s["label"] for s in snapshots]}) + "\n")
        print("Global export A/B/removal, static/dynamic reconnect, and per-peer stats passed")
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
        (args.out / "cleanup.json").write_text(json.dumps({"daemon_pid": daemon.pid, "exit_code": daemon.returncode}) + "\n")


if __name__ == "__main__":
    main()
