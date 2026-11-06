#!/usr/bin/env python3
"""Owned-container VPN FlowSpec receipt; no installation or traffic claim.

Provide an already-built daemon and the checksum-pinned GoBGP 4.11.0 release
binaries. Pre-pull ubuntu:24.04 and nicolaka/netshoot:v0.14; no image is built.
Run from the candidate repository with --binary, --binary-sha256, --source-id,
--gobgp-dir and a new --output directory. Containers and their network are
removed on exit. The nonzero-offset comparator probe is a separate verdict:
GoBGP 4.11.0 does not implement RFC 8956's shortened pattern encoding.
Container CPU affinity follows the invoking process (use taskset when needed).
Exit zero requires the core checks and both offset captures to complete; read
the separate FAIL comparator verdict before making a support claim.
"""

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import time
import urllib.request

from m105_capture_oracle import capabilities, messages, need, reassemble, update


FAMILIES = {
    3: (1, 133, "ipv4-flowspec", "ipv4_flowspec"),
    4: (2, 133, "ipv6-flowspec", "ipv6_flowspec"),
    13: (1, 134, "ipv4-l3vpn-flowspec", "l3vpn_ipv4_flowspec"),
    14: (2, 134, "ipv6-l3vpn-flowspec", "l3vpn_ipv6_flowspec"),
}
ENUMS = {number: "ADDRESS_FAMILY_" + family[3].upper() for number, family in FAMILIES.items()}
GOBGP_HASHES = {
    "gobgp": "f2a64916729cb019a6b1b8e1ff83cbf2653d93eae1c5ece498e586bf26afab93",
    "gobgpd": "58127efa0ff1aaeadfbb802c771b18134c401c8c16229b6d3d2ab30935f288b2",
}
RUNTIME = "ubuntu@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852"
CAPTURE = "nicolaka/netshoot@sha256:7f08c4aff13ff61a35d30e30c5c1ea8396eac6ab4ce19fd02d5a4b3b5d0d09a2"


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def key(rule):
    return rule["afiSafi"], rule.get("rd", ""), json.dumps(rule["components"], sort_keys=True)


def rule(family, rd=None, rt="44407:777", components=None):
    value = {"afiSafi": ENUMS[family], "components": components or [
        {"type": 3, "value": "=6"}, {"type": 5, "value": "=443"}],
        "actions": [{"trafficRate": {"rate": 0}}]}
    if rd is not None:
        value.update(rd=f"44407:{rd}", routeTargets=[rt])
    return value


def numeric_items(component):
    values = [int(value.strip().removeprefix("=")) for value in component["value"].split(",")]
    result = []
    for index, value in enumerate(values):
        width = 1 if value <= 255 else 2 if value <= 65535 else 4
        op = 1 | ({1: 0, 2: 16, 4: 32}[width]) | (128 if index == len(values) - 1 else 0)
        result.append({"op": op, "value": value})
    return result


def expected_nlri(rule):
    """The small admitted fixture grammar, independently encoded per RFC 8956."""
    data = bytearray()
    if rule.get("rd"):
        admin, assigned = map(int, rule["rd"].split(":"))
        data.extend(struct.pack("!HHI", 0, admin, assigned))
    for component in rule["components"]:
        data.append(component["type"])
        if component["type"] in (1, 2):
            prefix = ipaddress.ip_network(component["prefix"])
            offset = component.get("offset", 0)
            bits = prefix.prefixlen - offset
            need(bits > 0 or prefix.prefixlen == offset == 0, "invalid fixture offset")
            data.append(prefix.prefixlen)
            if prefix.version == 6:
                data.append(offset)
            else:
                need(offset == 0, "IPv4 fixture has an offset")
            octets = (bits + 7) // 8
            pattern = (int(prefix.network_address) << offset) & ((1 << prefix.max_prefixlen) - 1)
            data.extend(pattern.to_bytes(prefix.max_prefixlen // 8, "big")[:octets])
        else:
            for item in numeric_items(component):
                data.append(item["op"])
                data.extend(item["value"].to_bytes(1 << ((item["op"] >> 4) & 3), "big"))
    return bytes(data)


def expected_gobgp(rule):
    value = []
    for component in rule["components"]:
        row = {"type": component["type"]}
        if component["type"] in (1, 2):
            row["value"] = {"prefix": component["prefix"]}
            if ":" in component["prefix"]:
                row["offset"] = component.get("offset", 0)
        else:
            row["value"] = numeric_items(component)
        value.append(row)
    result = {"value": value}
    if rule.get("rd"):
        admin, assigned = map(int, rule["rd"].split(":"))
        result["rd"] = {"type": 0, "admin": admin, "assigned": assigned}
    return result


def check_gobgp(document, expected, family, source):
    need(isinstance(document, dict), "GoBGP RIB is not an object")
    rows = [paths[0] for paths in document.values() if isinstance(paths, list) and len(paths) == 1]
    need(len(rows) == len(document) == len(expected), "GoBGP exact path count differs")
    canonical = lambda value: json.dumps(value, sort_keys=True)
    actual = {canonical(row["nlri"]): row for row in rows}
    need(len(actual) == len(rows), "GoBGP duplicate NLRI identity")
    need(set(actual) == {canonical(expected_gobgp(r)) for r in expected}, "GoBGP exact NLRI differs")
    afi, safi = FAMILIES[family][:2]
    for desired in expected:
        nlri = expected_gobgp(desired)
        row = actual[canonical(nlri)]
        need(row.get("neighbor-ip") == source, "GoBGP path came from another source")
        need(not row.get("withdrawal") and not row.get("stale"), "GoBGP path is withdrawn/stale")
        attrs = row["attrs"]
        reaches = [a for a in attrs if a["type"] == 14]
        need(len(reaches) == 1, "GoBGP path lacks unique MP_REACH")
        reach = reaches[0]
        need((reach["afi"], reach["safi"]) == (afi, safi), "GoBGP MP_REACH family differs")
        need(reach["value"] == [{"NLRI": nlri, "ID": 0}], "GoBGP MP_REACH NLRI differs")
        extended = [a["value"] for a in attrs if a["type"] == 16]
        want = [{"type": 128, "subtype": 6, "as": 0, "rate": 0}]
        want += [{"type": 0, "subtype": 2, "value": rt} for rt in desired.get("routeTargets", [])]
        need(len(extended) == 1 and sorted(map(canonical, extended[0])) == sorted(map(canonical, want)),
             "GoBGP scope RT/action differs on the received path")


def split_nlri(data):
    rows = []
    while data:
        width = 2 if data[0] >= 240 else 1
        need(len(data) >= width, "truncated FlowSpec length")
        length = int.from_bytes(data[:width], "big") & (4095 if width == 2 else 255)
        need(length > 0 and len(data) >= width + length, "truncated/empty FlowSpec NLRI")
        need(width == (1 if length < 240 else 2), "noncanonical FlowSpec length")
        rows.append((width, data[width:width + length]))
        data = data[width + length:]
    return rows


def wire_observations(lines):
    streams = {}
    for line in lines:
        stream, src, dst, sequence, payload = line.split("\t")
        streams.setdefault((stream, src, dst), []).append((int(sequence), bytes.fromhex(payload.replace(":", ""))))
    opens, routes = [], []
    for (stream, src, dst), parts in streams.items():
        for kind, body in messages(reassemble(parts)):
            if kind == 1:
                families = sorted((int.from_bytes(v[:2], "big"), v[3]) for v in capabilities(body).get(1, []))
                opens.append({"stream": stream, "source": src, "destination": dst, "families": families})
            elif kind == 2:
                withdrawn, attrs, announced = update(body)
                need(not withdrawn and not announced, "unexpected IPv4 UPDATE body NLRI")
                for code in (14, 15):
                    if code not in attrs:
                        continue
                    raw = attrs[code][1]
                    afi, safi = int.from_bytes(raw[:2], "big"), raw[2]
                    need((afi, safi) in {(v[0], v[1]) for v in FAMILIES.values()}, "unexpected wire family")
                    offset = 5 + raw[3] if code == 14 else 3
                    if code == 14:
                        need(raw[3] == 0 and raw[4] == 0, "FlowSpec MP_REACH has a next hop/reserved byte")
                    extended = attrs.get(16, (0, b""))[1]
                    need(len(extended) % 8 == 0, "extended community length differs")
                    communities = sorted(extended[i:i + 8].hex() for i in range(0, len(extended), 8))
                    for width, nlri in split_nlri(raw[offset:]):
                        routes.append({"source": src, "destination": dst, "family": [afi, safi],
                                       "announce": code == 14, "length_octets": width,
                                       "nlri": nlri.hex(), "communities": communities})
    return {"opens": opens, "routes": routes}


def check_wire(observed, daemon, peer, global_peer, initial, replacement):
    family_pairs = {(v[0], v[1]) for v in FAMILIES.values()}
    for source, destination, want in ((daemon, peer, family_pairs), (peer, daemon, family_pairs),
                                     (daemon, global_peer, {(1, 133), (2, 133)}),
                                     (global_peer, daemon, family_pairs)):
        opens = [row for row in observed["opens"] if (row["source"], row["destination"]) == (source, destination)]
        need(opens and all(set(map(tuple, row["families"])) == want for row in opens), "OPEN opt-in family set differs")
    rows = observed["routes"]
    need(not any(r["source"] == daemon and r["destination"] == global_peer and r["family"][1] == 134 for r in rows),
         "VPN NLRI leaked to the unnegotiated peer")
    for desired in initial:
        family = next(n for n, name in ENUMS.items() if name == desired["afiSafi"])
        wire_key = (list(FAMILIES[family][:2]), expected_nlri(desired).hex())
        matching = [r for r in rows if r["source"] == daemon and r["destination"] == peer
                    and (r["family"], r["nlri"]) == wire_key]
        announcements = [r for r in matching if r["announce"]]
        need(announcements and any(not r["announce"] for r in matching), "missing exact announcement/withdrawal")
        communities = ["8006000000000000"] + [struct.pack("!HHI", 2, 44407, int(rt.split(":")[1])).hex()
                                                        for rt in desired.get("routeTargets", [])]
        need(announcements[0]["communities"] == sorted(communities), "initial wire RT/action differs")
        want_announces = 2 if key(desired) == key(replacement) else 1
        need(len(announcements) == want_announces, "unexpected replacement count")
        if want_announces == 2:
            need(announcements[1]["communities"] == sorted(["8006000000000000", "0002ad770000030a"]),
                 "replacement RT is not 44407:778")
    return {"initial_rules": len(initial), "exact_withdrawals": len(initial), "rt_replacements": 1}


class Lab:
    def __init__(self, args):
        self.args = args
        self.root = Path(args.proto_root).resolve()
        self.out = Path(args.output).resolve()
        self.out.mkdir(parents=True)
        self.name = f"vpn-flowspec-{os.getpid()}"
        self.containers = []
        self.network = False
        self.capture = None
        self.token = (self.root / "tests/fixtures/grpc-test-only-operator.token").read_text().strip()
        self.results = []
        self.cpus = ",".join(map(str, sorted(os.sched_getaffinity(0))))

    def save(self, name, value):
        (self.out / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

    def command(self, *args, check=True, input=None, timeout=30):
        result = subprocess.run(args, input=input, text=True, capture_output=True, timeout=timeout)
        with (self.out / "commands.jsonl").open("a") as stream:
            stream.write(json.dumps({"args": args, "status": result.returncode, "stdout": result.stdout, "stderr": result.stderr}) + "\n")
        if check:
            result.check_returncode()
        return result.stdout if check else result

    def docker(self, container, *args):
        return self.command("docker", "exec", container, *args)

    def rpc(self, method, payload=None):
        result = self.command("grpcurl", "-max-time", "10", "-plaintext", "-import-path", str(self.root),
                              "-proto", "proto/rustbgpd.proto", "-H", f"authorization: Bearer {self.token}",
                              "-d", "@", f"{self.addresses['daemon']}:50051", f"rustbgpd.v1.{method}",
                              input=json.dumps(payload or {}))
        return json.loads(result)

    def wait(self, label, read, check, seconds=30):
        deadline = time.monotonic() + seconds
        while True:
            value = read()
            try:
                check(value)
                need(time.monotonic() < deadline, "observation exceeded its deadline")
                print(f"PASS {label}", flush=True)
                self.results.append(label)
                return value
            except (ValueError, AssertionError):
                if time.monotonic() >= deadline:
                    raise
            time.sleep(0.25)

    def ready(self, container, args):
        for _ in range(30):
            result = self.command("docker", "exec", container, *args, check=False)
            if result.returncode == 0:
                return
            time.sleep(0.25)
        raise RuntimeError(f"{container}: startup failed: {result.stderr}")

    def start(self):
        need(digest(self.args.binary) == self.args.binary_sha256, "candidate binary hash differs")
        for name, expected in GOBGP_HASHES.items():
            need(digest(Path(self.args.gobgp_dir) / name) == expected, f"{name} release binary hash differs")
        images = {}
        for image in (RUNTIME, CAPTURE):
            inspected = json.loads(self.command("docker", "image", "inspect", image))[0]
            need(inspected["Architecture"] == "amd64", "runtime image architecture differs")
            images[image] = inspected["Id"]
        self.save("provenance.json", {"binary_sha256": self.args.binary_sha256, "source_id": self.args.source_id,
                                    "candidate_revision": self.command("git", "-C", str(self.root), "rev-parse", "HEAD").strip(),
                                    "candidate_dirty": bool(self.command("git", "-C", str(self.root), "status", "--porcelain").strip()),
                                    "gobgp_version": "4.11.0", "gobgp_source": "53ceb78fe284018ce83a92f3039198f0a86dc823",
                                    "gobgp_binaries": GOBGP_HASHES, "images": images})
        self.command("docker", "network", "create", "--internal", self.name)
        self.network = True
        for role in ("daemon", "peer", "global"):
            name = f"{self.name}-{role}"
            config = self.out / role
            config.mkdir()
            binds = ["-v", f"{config}:/config:ro"]
            if role == "daemon":
                binds += ["-v", f"{Path(self.args.binary).resolve()}:/usr/local/bin/rustbgpd:ro"]
                (config / "token").write_text(self.token)
            else:
                binds += ["-v", f"{Path(self.args.gobgp_dir).resolve()}:/gobgp:ro"]
            self.command("docker", "run", "-d", "--name", name, "--network", self.name,
                         "--cpuset-cpus", self.cpus, "--cpus", "2", *binds, RUNTIME, "sleep", "infinity")
            self.containers.append(name)
        self.nodes = dict(zip(("daemon", "peer", "global"), self.containers))
        self.addresses = {role: self.command("docker", "inspect", "-f",
                                            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name).strip()
                          for role, name in self.nodes.items()}
        self.write_configs()
        self.capture = f"{self.name}-capture"
        self.command("docker", "run", "-d", "--name", self.capture, "--network", f"container:{self.nodes['daemon']}",
                     "--cpuset-cpus", self.cpus, "--cap-add", "NET_RAW", "-v", f"{self.out}:/out", CAPTURE,
                     "tcpdump", "-n", "-U", "-s", "0", "-i", "eth0", "-w", "/out/capture.pcap", "tcp", "port", "179")
        self.wait("capture armed", lambda: (self.out / "capture.pcap").exists(), lambda v: need(v, "capture not armed"))
        for role, name in self.nodes.items():
            executable = "/usr/local/bin/rustbgpd /config/config.toml" if role == "daemon" else "/gobgp/gobgpd -f /config/config.toml"
            self.command("docker", "exec", "-d", name, "sh", "-c", f"exec {executable} >/tmp/daemon.log 2>&1")
            if role != "daemon":
                for binary in GOBGP_HASHES:
                    need(self.docker(name, f"/gobgp/{binary}", "--version").strip() == f"{binary} version 4.11.0",
                         f"{binary} runtime version differs")
                self.ready(name, ["/gobgp/gobgp", "global"])
        for role in ("peer", "global"):
            self.wait(f"{role} Established", lambda role=role: self.docker(self.nodes[role], "/gobgp/gobgp", "neighbor", self.addresses["daemon"]),
                      lambda value: need("BGP state = SESSION_STATE_ESTABLISHED" in value, "session not Established"))
        self.sessions()

    def write_configs(self):
        config = f'''[global]
asn = 65001
router_id = "{self.addresses['daemon']}"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
[global.telemetry.grpc_tcp]
address = "0.0.0.0:50051"
token_file = "/config/token"
principal = "rustbgpd://operator/test-only"
[security.grpc.roles]
"rustbgpd://operator/test-only" = "operator"
[policy.definitions.permit]
default_action = "permit"
'''
        for role, asn in (("peer", 65002), ("global", 65003)):
            families = [row[3] for number, row in FAMILIES.items() if role == "peer" or number < 13]
            config += f'''[[neighbors]]
address = "{self.addresses[role]}"
remote_asn = {asn}
hold_time = 90
graceful_restart = false
families = {json.dumps(families)}
import_policy_chain = ["permit"]
export_policy_chain = ["permit"]
'''
            peer_config = f'''[global.config]
as = {asn}
router-id = "{self.addresses[role]}"
[[neighbors]]
[neighbors.config]
neighbor-address = "{self.addresses['daemon']}"
peer-as = 65001
[neighbors.timers.config]
connect-retry = 1
'''
            for family in ("ipv4-flowspec", "ipv6-flowspec", "l3vpn-ipv4-flowspec", "l3vpn-ipv6-flowspec"):
                peer_config += f'[[neighbors.afi-safis]]\n[neighbors.afi-safis.config]\nafi-safi-name = "{family}"\n'
            (self.out / role / "config.toml").write_text(peer_config)
        (self.out / "daemon/config.toml").write_text(config)

    def sessions(self):
        rows = [self.rpc("NeighborService/GetNeighborState", {"address": self.addresses[role]}) for role in ("peer", "global")]
        for row in rows:
            need(row["state"] == "SESSION_STATE_ESTABLISHED" and not row.get("stale"), "session observation unavailable/down")
            need(int(row.get("flapCount", 0)) == 0, "unexpected session flap")
        return rows

    def peer_rib(self, role, family):
        return json.loads(self.docker(self.nodes[role], "/gobgp/gobgp", "global", "rib", "-a", FAMILIES[family][2], "-j"))

    def snapshot(self, label, rules):
        def read():
            return {role: {number: self.peer_rib(role, number) for number in FAMILIES} for role in ("peer", "global")}
        def check(document):
            for role in ("peer", "global"):
                for number in FAMILIES:
                    expected = [r for r in rules if r["afiSafi"] == ENUMS[number] and (role == "peer" or number < 13)]
                    check_gobgp(document[role][number], expected, number, self.addresses["daemon"])
            self.sessions()
        value = self.wait(label, read, check)
        self.save(label + ".json", value)

    def add(self, desired, outcome="CREATED"):
        reply = self.rpc("InjectionService/AddFlowSpec", desired)
        need(reply["outcome"] == "FLOW_SPEC_INJECT_OUTCOME_" + outcome, "injection outcome differs")

    def delete(self, desired):
        payload = {name: value for name, value in desired.items() if name in ("afiSafi", "rd", "components")}
        reply = self.rpc("InjectionService/DeleteFlowSpec", payload)
        need(reply["outcome"] == "FLOW_SPEC_DELETE_OUTCOME_DELETED", "delete outcome differs")

    def discard_count(self):
        with urllib.request.urlopen(f"http://{self.addresses['daemon']}:9179/metrics", timeout=5) as response:
            metrics = response.read().decode()
        (self.out / "metrics.txt").write_text(metrics)
        values = re.findall(r'^bgp_vpn_flowspec_nlri_discarded_total\{peer="' + re.escape(self.addresses['peer']) + r'"\} (\d+)$', metrics, re.M)
        need(len(values) <= 1, "duplicate discard metric")
        return int(values[0]) if values else 0

    def received(self, family):
        reply = self.rpc("RibService/ListFlowSpecRoutes", {"afiSafi": ENUMS[family], "receivedPeerAddress": self.addresses["peer"]})
        need(reply.get("receivedView") is True, "received view not acknowledged")
        return reply.get("receivedRoutes", [])

    def inbound(self):
        before = self.discard_count()
        for family, prefix in ((13, "203.0.113.0/24"), (14, "2001:db8:900::/64")):
            args = ["rd", "44407:900", "match", "destination", prefix]
            if family == 14:
                args += ["label", "=74566"]
            for action in ("add", "del"):
                extra = ["then", "discard", "rt", "44407:777"] if action == "add" else []
                self.docker(self.nodes["peer"], "/gobgp/gobgp", "global", "rib", action, "-a", FAMILIES[family][2], *args, *extra)
                before += 1
                self.wait(f"{family} received {action} discarded", self.discard_count,
                          lambda v, expected=before: need(v == expected, "discard counter differs"))
                need(not self.received(family), "VPN input reached the received RIB")
                self.sessions()
        args = ["match", "destination", "2001:db8:901::/64"]
        self.docker(self.nodes["peer"], "/gobgp/gobgp", "global", "rib", "add", "-a", "ipv6-flowspec", *args, "then", "discard")
        self.wait("global IPv6 receive positive control", lambda: self.received(4), lambda v: need(len(v) == 1, "global rule not received"))
        self.docker(self.nodes["peer"], "/gobgp/gobgp", "global", "rib", "del", "-a", "ipv6-flowspec", *args)
        self.wait("global IPv6 receive withdrawal", lambda: self.received(4), lambda v: need(not v, "global rule remains"))
        self.save("receive-discard.json", {"vpn_discarded": before, "vpn_received": {str(n): self.received(n) for n in (13, 14)}})

    def stop_capture(self, name):
        if self.capture:
            self.command("docker", "kill", "--signal", "SIGINT", self.capture)
            self.command("docker", "wait", self.capture)
            log = self.command("docker", "logs", self.capture, check=False)
            log.check_returncode()
            (self.out / name).write_text(log.stdout + log.stderr)
            dropped = re.findall(r"(\d+) packets dropped by kernel", log.stdout + log.stderr)
            need(dropped == ["0"], "capture dropped packets or lacks the drop counter")
            self.command("docker", "rm", self.capture)
            self.capture = None

    def wire(self):
        output = self.command("tshark", "-n", "-r", str(self.out / "capture.pcap"), "-Y", "tcp.len > 0",
                              "-T", "fields", "-e", "tcp.stream", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.seq_raw", "-e", "tcp.payload")
        (self.out / "capture.tsv").write_text(output)
        value = wire_observations(output.splitlines())
        self.save("wire.json", value)
        return value

    def offset_probe(self):
        desired = rule(14, 901, components=[{"type": 2, "prefix": "::1234:5678:9a00:0/104", "offset": 64},
                                           {"type": 3, "value": "=6"}])
        expected = expected_nlri(desired).hex()
        need(expected == "0000ad7700000385026840123456789a038106", "RFC 8956 offset vector differs")
        self.capture = f"{self.name}-offset-capture"
        self.command("docker", "run", "-d", "--name", self.capture, "--network", f"container:{self.nodes['daemon']}",
                     "--cpuset-cpus", self.cpus, "--cap-add", "NET_RAW", "-v", f"{self.out}:/out", CAPTURE,
                     "tcpdump", "-n", "-U", "-s", "0", "-i", "eth0", "-w", "/out/offset.pcap", "tcp", "port", "179")
        self.wait("offset capture armed", lambda: (self.out / "offset.pcap").exists(), lambda v: need(v, "capture not armed"))
        self.add(desired)
        # A local read acknowledges API admission; the independent capture and
        # peer RIB below decide whether this comparator received the same rule.
        self.save("offset-local.json", self.rpc("RibService/ListFlowSpecRoutes", {"afiSafi": ENUMS[14], "receivedPeerAddress": "0.0.0.0"}))
        def read(strict=False):
            output = self.command("tshark", "-n", "-r", str(self.out / "offset.pcap"), "-Y", "tcp.len > 0",
                                  "-T", "fields", "-e", "tcp.stream", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.seq_raw", "-e", "tcp.payload")
            try:
                return wire_observations(output.splitlines()) if output else {"routes": []}
            except ValueError as error:
                if strict:
                    raise
                # Live captures can end between TCP segments. The completed
                # capture is parsed strictly after the witness arrives.
                return {"routes": [], "incomplete": str(error)}
        observed = self.wait("RFC 8956 nonzero offset wire", read,
                             lambda value: need(any(r["source"] == self.addresses["daemon"] and r["destination"] == self.addresses["peer"]
                                                    and r["family"] == [2, 134] and r["nlri"] == expected
                                                    for r in value["routes"]), "exact RFC offset NLRI not captured"))
        self.save("offset-wire.json", observed)
        peer = self.peer_rib("peer", 14)
        self.save("offset-peer.json", peer)
        try:
            check_gobgp(peer, [desired], 14, self.addresses["daemon"])
            verdict = {"result": "PASS", "reason": "GoBGP decoded the complete RFC offset rule"}
        except (ValueError, KeyError) as error:
            verdict = {"result": "FAIL", "reason": f"GoBGP 4.11.0 nonzero-offset decode: {error}"}
        self.save("offset-verdict.json", verdict)
        self.docker(self.nodes["peer"], "/gobgp/gobgp", "global", "rib", "add", "-a", "ipv6-l3vpn-flowspec",
                    "rd", "44407:902", "match", "source", "::1234:5678:9a00:0/104", "64", "protocol", "=6",
                    "then", "discard", "rt", "44407:777")
        vendor_bytes = "0000ad77000003860268400000000000000000123456789a038106"
        self.wait("pinned GoBGP offset framing witness", read,
                  lambda value: need(any(r["source"] == self.addresses["peer"] and r["destination"] == self.addresses["daemon"]
                                         and r["family"] == [2, 134] and r["nlri"] == vendor_bytes
                                         for r in value["routes"]), "pinned vendor offset bytes not captured"))
        self.save("vendor-offset-verdict.json", {
            "result": "FAIL", "reason": "GoBGP 4.11.0 emits 13 pattern octets; RFC 8956 requires 5 for length 104 offset 64",
            "expected_nlri": expected_nlri(dict(desired, rd="44407:902")).hex(), "observed_nlri": vendor_bytes,
            "source": "https://github.com/osrg/gobgp/blob/53ceb78fe284018ce83a92f3039198f0a86dc823/pkg/packet/bgp/bgp.go",
            "standard": "https://www.rfc-editor.org/rfc/rfc8956.html#section-3.8.1",
        })
        self.save("offset-receiver-state.json", self.rpc("NeighborService/GetNeighborState", {"address": self.addresses["peer"]}))
        self.stop_capture("offset-capture.log")
        self.save("offset-wire.json", read(strict=True))
        print(verdict["result"] + " nonzero-offset GoBGP comparator: " + verdict["reason"], flush=True)
        return {"result": "FAIL", "decode": verdict,
                "reason": "pinned GoBGP sender uses full-prefix framing for a nonzero offset"}

    def run(self):
        self.start()
        initial = [rule(n) for n in (3, 4)] + [rule(n, rd) for n in (13, 14) for rd in (40, 41)]
        initial.append(rule(14, 42, components=[{"type": 1, "prefix": "2001:db8:40::/64"},
                       {"type": 2, "prefix": "2001:db8:41::/64"}, {"type": 3, "value": "=17"},
                       {"type": 5, "value": "=53"}, {"type": 13, "value": "=74565"}]))
        for family in (13, 14):
            for length in (239, 240):
                values = [1] + list(range(1000, 1076)) if length == 239 else list(range(1000, 1077))
                desired = rule(family, length, components=[{"type": 5, "value": ",".join(f"={v}" for v in values)}])
                need(len(expected_nlri(desired)) == length, "boundary fixture length differs")
                initial.append(desired)
        for desired in initial:
            self.add(desired)
        self.snapshot("announced", initial)
        for family in (13, 14):
            request = {k: v for k, v in rule(family, 40).items() if k in ("afiSafi", "components", "rd")}
            reply = self.rpc("InjectionService/ListFlowSpecExportDispositions", request)
            rows = {row["peerAddress"]: row for row in reply["peers"]}
            need(rows[self.addresses["global"]]["disposition"] == "PATH_EXPORT_DISPOSITION_WITHHELD"
                 and rows[self.addresses["global"]]["reason"] == "family_not_negotiated", "non-export evidence differs")
            self.save(f"non-export-{family}.json", reply)
        replacement = rule(14, 40, rt="44407:778")
        self.add(replacement, "REPLACED")
        self.add(replacement, "UNCHANGED")
        current = [replacement if key(r) == key(replacement) else r for r in initial]
        self.snapshot("rt-replaced", current)
        for desired in (replacement, rule(13, 40), rule(14, 41), rule(13, 41)):
            self.delete(desired)
            current = [r for r in current if key(r) != key(desired)]
            self.snapshot(f"withdraw-{desired['afiSafi'].split('_')[-2]}-{desired['rd'].split(':')[1]}", current)
        for desired in current:
            self.delete(desired)
        self.snapshot("withdraw-all", [])
        self.inbound()
        self.snapshot("receive-clean", [])
        self.stop_capture("capture.log")
        observed = self.wire()
        proof = check_wire(observed, self.addresses["daemon"], self.addresses["peer"], self.addresses["global"], initial, replacement)
        self.save("core-verdict.json", {"result": "PASS", **proof, "checks": self.results})
        print("PASS VPNv4/VPNv6 FlowSpec core receipt (offset zero)", flush=True)
        offset = self.offset_probe()
        self.save("verdict.json", {"core": "PASS", "nonzero_offset": offset,
                                   "scope": "GoBGP wire/control-plane only; no installation, forwarding, timing or scale evidence"})
        return 0

    def cleanup(self):
        failures = []
        if self.capture:
            self.command("docker", "kill", "--signal", "SIGINT", self.capture, check=False)
            self.command("docker", "wait", self.capture, check=False)
            removed = self.command("docker", "rm", "-f", self.capture, check=False)
            if removed.returncode:
                failures.append(self.capture)
        for name in self.containers:
            result = self.command("docker", "exec", name, "cat", "/tmp/daemon.log", check=False)
            (self.out / (name.rsplit("-", 1)[1] + ".log")).write_text(result.stdout + result.stderr)
            if self.command("docker", "rm", "-f", name, check=False).returncode:
                failures.append(name)
        if self.network:
            if self.command("docker", "network", "rm", self.name, check=False).returncode:
                failures.append(self.name)
        self.save("cleanup.json", {"result": "FAIL" if failures else "PASS", "remaining": failures})
        need(not failures, f"owned lab cleanup failed: {failures}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "binary-sha256", "source-id", "gobgp-dir", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--proto-root", default=".")
    lab = Lab(parser.parse_args())
    try:
        return lab.run()
    except Exception as error:
        lab.save("verdict.json", {"result": "FAIL", "reason": str(error)})
        raise
    finally:
        lab.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
