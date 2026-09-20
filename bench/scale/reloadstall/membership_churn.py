#!/usr/bin/env python3
"""Two rotating receive-only members alongside reloadstall's unchanged fleet.

Linux-only local lab helper. The core Rust harness remains responsible for its
wire, churn, and session gates. This helper stages member/dataset generations,
receives both complete base tables at each joining pair, and captures roster,
dataset, and unchanged TCP-session evidence. It does not reconnect a session.
"""

import asyncio
import json
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import sys
import time
import urllib.request

KEY = b"membership-lab-key"
JOIN_SECONDS = 60


def address(member):
    return f"127.1.{member // 200}.{member % 200 + 1}"


def roster(peers, generation):
    return list(range(peers)) + [peers + 2 * generation, peers + 2 * generation + 1]


def dataset_names(members):
    return {f"client-{i}-{kind}" for i in members for kind in ("origins", "prefixes")}


def write_json(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def prepare(run, peers, total, reloads):
    if peers < 8 or total % 2 or peers + 2 * (reloads + 1) > 1024:
        raise ValueError("need >=8 core members, an even dual-family table, and ASNs below 65536")
    if os.environ.get("GEN_DUALSTACK") != "1" or int(os.environ.get("GEN_FILTER_COUNT", "0")):
        raise ValueError("membership cell requires dual-stack permit-set-preserving generations")
    if int(os.environ.get("RELOADSTALL_IPV4_PREFIXES", str(total // 2))) != total // 2:
        raise ValueError("membership cell currently requires an equal family split")
    template = (run / "config.toml").read_text()
    head, *neighbors = template.split("[[neighbors]]")
    if len(neighbors) != peers or 'import_chain = ["member-in"]' not in head:
        raise ValueError("expected the route-server gen-scenario.py configuration")
    (run / "datasets").mkdir()
    (run / "members").mkdir()
    manifest = {"peers": peers, "total": total, "reloads": reloads, "join_seconds": JOIN_SECONDS}
    write_json(run / "membership.json", manifest)
    for member in range(peers + 2 * (reloads + 1)):
        prefixes = []
        if member < peers:
            quotient, remainder = divmod(total // 2, peers)
            start = member * quotient + min(member, remainder)
            for index in range(start, start + quotient + (member < remainder)):
                prefixes += [f"{20 + (index >> 16)}.{(index >> 8) & 255}.{index & 255}.0/24",
                             f"3001:{index >> 16:x}:{index & 65535:x}::/48"]
            if member >= peers - 8:
                churner = member - (peers - 8)
                for index in range(16):
                    prefixes += [f"172.{16 + churner}.{index}.0/24", f"3002:{churner:x}:{index:x}::/48"]
        else:
            # Receive-only members still have real, referenced import guards.
            prefixes = ["192.0.2.0/24", "2001:db8::/48"]
        (run / f"datasets/client-{member}-origins.list").write_text(f"{64512 + member}\n")
        (run / f"datasets/client-{member}-prefixes.list").write_text("\n".join(prefixes) + "\n")
    for generation in range(reloads + 1):
        members = roster(peers, generation)
        paths = ["member.rpol"] + [f"members/client-{member}.rpol" for member in members]
        config = head.replace('rpol_files = ["member.rpol"]', "rpol_files = " + json.dumps(paths))
        for member in members:
            policies = []
            for kind, syntax in (("origins", "asn-set"), ("prefixes", "prefix-set")):
                name = f"client-{member}-{kind}"
                config += f'\n[policy.datasets.{name}]\npath = "datasets/{name}.list"\n'
                policies.append(f"dataset {syntax} {name}")
            policies.append(f"policy client-{member} {{\n"
                            f" term authorized {{ if route.origin-as in client-{member}-origins && route.prefix in client-{member}-prefixes {{ accept }} }}\n"
                            " term default { reject }\n}")
            (run / f"members/client-{member}.rpol").write_text("\n".join(policies) + "\n")
        for member in members:
            if member < peers:
                config += "\n[[neighbors]]" + neighbors[member]
            else:
                config += (f'\n[[neighbors]]\naddress = "{address(member)}"\nremote_asn = {64512 + member}\n'
                           'route_server_client = true\nfamilies = ["ipv4_unicast", "ipv6_unicast"]\nhold_time = 180\n')
                if member % 2 == peers % 2:
                    config += f'md5_password = "{KEY.decode()}"\n'
            config += f'ttl_security = true\nimport_policy_chain = ["client-{member}"]\n'
        (run / f"config-{generation}.toml").write_text(config)
    install(run, 0)
    (run / "membership-finish").mkdir()


def install(run, generation):
    shutil.copyfile(run / f"config-{generation}.toml", run / "config.toml.next")
    (run / "config.toml.next").replace(run / "config.toml")


def cli(run, binary, *args):
    result = subprocess.run([binary, "--addr", f"unix://{run}/grpc.sock", "--json", *args],
                            check=True, capture_output=True, text=True, timeout=10)
    # Preserve the last successful real response before interpreting optional fields.
    (run / f"last-{args[0]}.json").write_text(result.stdout)
    return json.loads(result.stdout)


def snapshot(run, binary, port, peers):
    rows = {row["address"]: row for row in cli(run, binary, "neighbor")}
    sockets = {}
    for line in Path("/proc/net/tcp").read_text().splitlines()[1:]:
        fields = line.split()
        if fields[3] != "01" or int(fields[1].split(":")[1], 16) != port:
            continue
        remote = socket.inet_ntoa(struct.pack("<I", int(fields[2].split(":")[0], 16)))
        if remote in sockets:
            raise AssertionError(f"multiple established sockets for {remote}")
        sockets[remote] = [fields[1], fields[2], fields[9]]
    core = {}
    for member in range(peers):
        addr = address(member)
        row = rows[addr]
        assert row["state"] == "Established" and not row.get("stale", False), (addr, row)
        core[addr] = {"socket": sockets[addr], "flaps": row["flap_count"], "uptime": row["uptime_seconds"]}
    return rows, core


def check_continuity(before, after):
    assert before.keys() == after.keys(), "core roster changed"
    for addr, old in before.items():
        new = after[addr]
        assert old["socket"] == new["socket"], f"TCP identity changed: {addr}"
        assert old["flaps"] == new["flaps"], f"flap count changed: {addr}"
        assert new["uptime"] >= old["uptime"], f"uptime decreased: {addr}"


def stage(run, binary, port):
    generation = int(os.environ["RELOADSTALL_STAGE_RELOAD"])
    deadline = time.monotonic() + JOIN_SECONDS + 15
    while not (run / f"membership-{generation - 1}.json").exists():
        if (run / "membership-error.txt").exists():
            raise AssertionError((run / "membership-error.txt").read_text())
        if time.monotonic() > deadline:
            raise TimeoutError("previous joining roster did not settle")
        time.sleep(0.05)
    peers = json.loads((run / "membership.json").read_text())["peers"]
    _, before = snapshot(run, binary, port, peers)
    write_json(run / f"before-{generation}.json", before)
    install(run, generation)
    # The watcher waits for the committed roster, not merely staged files.
    write_json(run / "membership-request.json", {"generation": generation, "staged_monotonic": time.monotonic()})
    deadline = time.monotonic() + 10
    while not (run / f"membership-armed-{generation}").exists():
        if time.monotonic() > deadline:
            raise TimeoutError("watcher did not arm expected departures before SIGHUP")
        time.sleep(0.01)


def frame(kind, body=b""):
    return b"\xff" * 16 + struct.pack("!HB", 19 + len(body), kind) + body


def check_open(body):
    if len(body) < 10 or body[0] != 4 or len(body) != 10 + body[9]:
        raise ValueError("invalid OPEN")
    options, families = body[10:], set()
    while options:
        if len(options) < 2 or len(options) < 2 + options[1]:
            raise ValueError("truncated OPEN option")
        kind, size = options[:2]
        value, options = options[2:2 + size], options[2 + size:]
        if kind != 2:
            continue
        while value:
            if len(value) < 2 or len(value) < 2 + value[1]:
                raise ValueError("truncated capability")
            kind, size = value[:2]
            capability, value = value[2:2 + size], value[2 + size:]
            if kind == 1:
                if size != 4:
                    raise ValueError("invalid multiprotocol capability")
                families.add((int.from_bytes(capability[:2], "big"), capability[3]))
    if not {(1, 1), (2, 1)} <= families:
        raise ValueError("joining member did not negotiate both unicast families")


def nlri_indices(data, family, total):
    """Decode unique base-table indexes; churn prefixes are outside this space."""
    result = []
    while data:
        bits = data[0]
        maximum = 32 if family == 4 else 128
        if bits > maximum:
            raise ValueError("invalid NLRI prefix length")
        width = (bits + 7) // 8
        if len(data) < width + 1:
            raise ValueError("truncated NLRI")
        value = data[1:width + 1]
        data = data[width + 1:]
        if family == 4 and bits == 24:
            index = int.from_bytes(value, "big") - (20 << 16)
        elif family == 6 and bits == 48 and value[:2] == b"\x30\x01":
            index = int.from_bytes(value[2:], "big")
        else:
            continue
        if 0 <= index < total:
            result.append(index)
    return result


def apply_update(body, inventories, total, marker=None):
    if len(body) < 4:
        raise ValueError("short UPDATE")
    withdrawn = int.from_bytes(body[:2], "big")
    if 4 + withdrawn > len(body):
        raise ValueError("truncated withdrawn routes")
    for index in nlri_indices(body[2:2 + withdrawn], 4, total):
        inventories[4].discard(index)
    length = int.from_bytes(body[2 + withdrawn:4 + withdrawn], "big")
    offset = 4 + withdrawn
    if offset + length > len(body):
        raise ValueError("truncated path attributes")
    attributes, nlri = body[offset:offset + length], body[offset + length:]
    announced = {4: nlri_indices(nlri, 4, total), 6: []}
    communities = set()
    while attributes:
        if len(attributes) < 3:
            raise ValueError("truncated attribute header")
        flags, kind = attributes[:2]
        width = 2 if flags & 16 else 1
        if len(attributes) < 2 + width:
            raise ValueError("truncated attribute length")
        size = int.from_bytes(attributes[2:2 + width], "big")
        if len(attributes) < 2 + width + size:
            raise ValueError("truncated attribute body")
        value, attributes = attributes[2 + width:2 + width + size], attributes[2 + width + size:]
        if kind == 8:
            if len(value) % 4:
                raise ValueError("invalid communities length")
            communities.update(int.from_bytes(value[i:i + 4], "big") for i in range(0, len(value), 4))
        if kind not in (14, 15):
            continue
        if len(value) < 3:
            raise ValueError("short MP attribute")
        afi, safi = struct.unpack("!HB", value[:3])
        if (afi, safi) != (2, 1):
            raise ValueError("unexpected MP family")
        if kind == 14:
            if len(value) < 5 or len(value) < 5 + value[3]:
                raise ValueError("truncated MP next hop")
            announced[6].extend(nlri_indices(value[5 + value[3]:], 6, total))
        else:
            for index in nlri_indices(value[3:], 6, total):
                inventories[6].discard(index)
    if marker is not None and any(announced.values()):
        actual = communities & {(65400 << 16) | value for value in (1000, 2000)}
        if actual != {(65400 << 16) | marker}:
            raise ValueError("joining base route has the wrong export generation marker")
    for family, indices in announced.items():
        inventories[family].update(indices)


class Receiver:
    def __init__(self, member, md5, port, total, generation=0):
        self.member, self.md5, self.port, self.total = member, md5, port, total
        self.inventories = {4: set(), 6: set()}
        self.closed = False
        self.removing = False
        self.established = False
        self.writer = None
        self.marker = 2000 if generation % 2 else 1000

    async def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255)
        if self.md5:
            peer = struct.pack("=HH4s", socket.AF_INET, 0, socket.inet_aton("127.0.0.1"))
            option = peer.ljust(128, b"\0") + struct.pack("=BBHi", 0, 0, len(KEY), 0) + KEY.ljust(80, b"\0")
            sock.setsockopt(socket.IPPROTO_TCP, 14, option)
        sock.bind((address(self.member), 0))
        sock.setblocking(False)
        try:
            await asyncio.wait_for(asyncio.get_running_loop().sock_connect(sock, ("127.0.0.1", self.port)), 5)
            reader, self.writer = await asyncio.open_connection(sock=sock)
            caps = b"\x01\x04\x00\x01\x00\x01\x01\x04\x00\x02\x00\x01" + b"\x41\x04" + struct.pack("!I", 64512 + self.member)
            options = bytes([2, len(caps)]) + caps
            body = struct.pack("!BHH4sB", 4, 64512 + self.member, 180,
                               socket.inet_aton(f"240.1.{self.member // 200}.{self.member % 200 + 1}"), len(options)) + options
            self.writer.write(frame(1, body))
            await self.writer.drain()
            async with asyncio.TaskGroup() as group:
                keepalive = group.create_task(self.keepalive())
                while True:
                    try:
                        header = await reader.readexactly(19)
                    except asyncio.IncompleteReadError as error:
                        if error.partial:
                            raise ValueError("truncated BGP header") from error
                        assert self.removing, f"unexpected EOF from member {self.member}"
                        break
                    length, kind = struct.unpack("!HB", header[16:])
                    if header[:16] != b"\xff" * 16 or not 19 <= length <= 4096:
                        raise ValueError("invalid BGP header")
                    body = await reader.readexactly(length - 19)
                    if kind == 1:
                        check_open(body)
                        self.writer.write(frame(4))
                        await self.writer.drain()
                    elif kind == 4:
                        self.established = True
                    elif kind == 2:
                        apply_update(body, self.inventories, self.total, None if self.removing else self.marker)
                    elif kind == 3:
                        assert self.removing and body[:2] == b"\x06\x02", f"unexpected notification: {body.hex()}"
                        break
                    else:
                        raise ValueError(f"unexpected BGP message {kind}")
                keepalive.cancel()
        finally:
            self.closed = True
            if self.writer:
                self.writer.close()
                await self.writer.wait_closed()
            else:
                sock.close()

    async def keepalive(self):
        while True:
            await asyncio.sleep(30)
            self.writer.write(frame(4))
            await self.writer.drain()

    def complete(self):
        return self.established and not self.closed and all(len(v) == self.total for v in self.inventories.values())


async def wait_until(predicate, timeout, detail):
    try:
        async with asyncio.timeout(timeout):
            while not predicate():
                await asyncio.sleep(0.05)
    except TimeoutError as error:
        raise TimeoutError(f"{detail} exceeded {timeout}s") from error


async def watch(run, binary, port):
    manifest = json.loads((run / "membership.json").read_text())
    peers, total, reloads = manifest["peers"], manifest["total"] // 2, manifest["reloads"]
    receivers = []
    async with asyncio.TaskGroup() as tasks:
        for generation in range(reloads + 1):
            staged = None
            if generation:
                await wait_until(lambda generation=generation: (run / "membership-request.json").exists() and
                                 json.loads((run / "membership-request.json").read_text())["generation"] == generation,
                                 600, "next stage")
                for receiver in receivers:
                    receiver.removing = True
                (run / f"membership-armed-{generation}").touch()
                staged = json.loads((run / "membership-request.json").read_text())["staged_monotonic"]
                expected = {address(member) for member in roster(peers, generation)}
                # New sockets open only after the API roster matches the expected roster.
                async with asyncio.timeout(JOIN_SECONDS):
                    while True:
                        rows = await asyncio.to_thread(cli, run, binary, "neighbor")
                        if {row["address"] for row in rows} == expected:
                            break
                        await asyncio.sleep(0.1)
                await wait_until(lambda receivers=receivers: all(r.closed for r in receivers), 10, "removed member close")
            started = time.monotonic()
            receivers = [Receiver(peers + 2 * generation + offset, offset == 0, port, total, generation) for offset in range(2)]
            for receiver in receivers:
                tasks.create_task(receiver.run())
            budget = max(0, staged + JOIN_SECONDS - time.monotonic()) if generation else 600
            await wait_until(lambda receivers=receivers: all(r.complete() for r in receivers), budget, "joining inventories")
            joined = time.monotonic()
            rows, after = await asyncio.to_thread(snapshot, run, binary, port, peers)
            expected = {address(member) for member in roster(peers, generation)}
            assert set(rows) == expected, "neighbor roster differs from generation"
            assert all(row["state"] == "Established" and not row.get("stale", False) for row in rows.values())
            if generation:
                check_continuity(json.loads((run / f"before-{generation}.json").read_text()), after)
            stats = await asyncio.to_thread(cli, run, binary, "policy", "stats")
            datasets = stats["datasets"]
            names = dataset_names(roster(peers, generation))
            assert {row["name"] for row in datasets} == names, "dataset status roster mismatch"
            assert all(row["records"] > 0 and not row["last_error"] for row in datasets), "dataset load failure"
            metrics = await asyncio.to_thread(lambda: urllib.request.urlopen("http://127.0.0.1:9179/metrics", timeout=5).read().decode())
            loaded = set(re.findall(r'^bgp_policy_dataset_loaded_timestamp_seconds\{dataset="([^"]+)"\}', metrics, re.MULTILINE))
            assert loaded == names, "loaded dataset metric roster mismatch"
            for member in range(peers, peers + 2 * generation):
                assert not any(f'dataset="{name}"' in metrics for name in dataset_names([member])), "removed dataset series survived"
            receipt = {"generation": generation, "join_export_seconds": joined - started,
                       "stage_to_join_seconds": joined - staged if staged is not None else None,
                       "members": sorted(rows), "datasets": sorted(row["name"] for row in datasets), "core": after,
                       "dataset_status": [{key: value for key, value in row.items() if key != "path"} for row in datasets],
                       "joining": [{"address": address(r.member), "md5": r.md5,
                                    "export_marker": f"65400:{r.marker}",
                                    "ipv4": len(r.inventories[4]), "ipv6": len(r.inventories[6])} for r in receivers]}
            write_json(run / f"membership-{generation}.json", receipt)
            (run / f"metrics-{generation}.txt").write_text(metrics)
        finish = run / "membership-finish"
        await wait_until(lambda: (finish / "ready").exists(), 120, "harness final evidence")
        (finish / "ack").write_text("membership gates passed\n")
        await wait_until(lambda: (run / "membership-stop").exists(), 120, "driver cleanup")
        for receiver in receivers:
            receiver.removing = True
            receiver.writer.write(frame(3, b"\x06\x02"))
            await receiver.writer.drain()
            receiver.writer.close()


def main():
    command, directory, *args = sys.argv[1:]
    run = Path(directory)
    if command == "prepare":
        prepare(run, *map(int, args))
    elif command == "stage":
        stage(run, args[0], int(args[1]))
    elif command == "watch":
        try:
            asyncio.run(watch(run, args[0], int(args[1])))
        except BaseException as error:
            (run / "membership-error.txt").write_text(repr(error) + "\n")
            raise
    else:
        raise ValueError(f"unknown command {command}")


if __name__ == "__main__":
    main()
