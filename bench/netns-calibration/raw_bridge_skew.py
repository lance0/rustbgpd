#!/usr/bin/env python3
"""Measure raw bridge-FDB to IP-neighbor notification skew on Linux."""

from __future__ import annotations

import argparse
import csv
import errno
import ipaddress
import json
import math
import os
import select
import shutil
import socket
import struct
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import cast

NETLINK_ROUTE = 0
RTMGRP_NEIGH = 4
RTM_NEWNEIGH = 28
RTM_DELNEIGH = 29
NLMSG_OVERRUN = 4
NLMSG_ERROR = 2
AF_INET = int(socket.AF_INET)
AF_INET6 = int(socket.AF_INET6)
AF_BRIDGE = int(getattr(socket, "AF_BRIDGE", 7))
NDA_DST, NDA_LLADDR, NDA_VLAN, NDA_MASTER, NDA_IFINDEX = 1, 2, 5, 9, 8
MSG_TRUNC = getattr(socket, "MSG_TRUNC", 0x20)
MAX_ARTIFACT_BYTES = 10 * 1024 * 1024
VALID_NUD = 0x02 | 0x04 | 0x40 | 0x80
INVALID_NUD = 0x01 | 0x08 | 0x10 | 0x20
CAMPAIGNS = {"serial-1": 1, "burst-8": 8, "burst-32": 32}


class MeasurementError(RuntimeError):
    """The measurement lost data, identity, or its closed execution boundary."""


def align4(value: int) -> int:
    return (value + 3) & ~3


@dataclass(frozen=True)
class Event:
    message: str
    family: int
    ifindex: int
    state: int
    flags: int
    dst: str | None
    lladdr: str | None
    vlan: int | None
    master: int | None
    nda_ifindex: int | None
    timestamp_ns: int


def _attrs(data: bytes, offset: int, end: int) -> dict[int, bytes]:
    result: dict[int, bytes] = {}
    while offset < end:
        if end - offset < 4:
            raise MeasurementError("malformed rtattr framing")
        length, kind = struct.unpack_from("=HH", data, offset)
        if length < 4 or offset + length > end:
            raise MeasurementError("malformed rtattr length")
        kind &= 0x3FFF
        if kind in result:
            raise MeasurementError(f"duplicate rtattr {kind}")
        result[kind] = data[offset + 4 : offset + length]
        offset += align4(length)
    if offset != end:
        raise MeasurementError("unaligned rtattr framing")
    return result


def _exact_u16(value: bytes, name: str) -> int:
    if len(value) != 2:
        raise MeasurementError(f"bad {name} length")
    return struct.unpack("=H", value)[0]


def _exact_u32(value: bytes, name: str) -> int:
    if len(value) != 4:
        raise MeasurementError(f"bad {name} length")
    return struct.unpack("=I", value)[0]


def _decode_ip(family: int, value: bytes) -> str:
    size = 4 if family == AF_INET else 16
    if len(value) != size:
        raise MeasurementError("bad NDA_DST length")
    return str(ipaddress.ip_address(value))


def parse_datagram(
    data: bytes, sender_pid: int, msg_flags: int, timestamp_ns: int
) -> list[Event]:
    """Decode one datagram using its immediate post-receipt raw-clock time."""
    if sender_pid != 0:
        raise MeasurementError("relevant datagram has non-kernel sender")
    if msg_flags & MSG_TRUNC:
        raise MeasurementError("truncated netlink datagram")
    events: list[Event] = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 16:
            raise MeasurementError("malformed nlmsghdr framing")
        length, kind, _nlflags, seq, pid = struct.unpack_from("=IHHII", data, offset)
        if length < 16 or offset + length > len(data):
            raise MeasurementError("malformed nlmsg length")
        if kind in (NLMSG_OVERRUN, NLMSG_ERROR):
            raise MeasurementError("NLMSG_OVERRUN/ERROR")
        if kind in (RTM_NEWNEIGH, RTM_DELNEIGH):
            if seq != 0 or pid != 0:
                raise MeasurementError("relevant event has non-kernel pid/sequence")
            if length < 28:
                raise MeasurementError("short ndmsg")
            family, _pad1, _pad2, ifindex, state, ndflags, _ndtype = struct.unpack_from(
                "=BBHiHBB", data, offset + 16
            )
            if family in (AF_BRIDGE, AF_INET, AF_INET6):
                attrs = _attrs(data, offset + 28, offset + length)
                dst = (
                    _decode_ip(family, attrs[NDA_DST])
                    if family in (AF_INET, AF_INET6) and NDA_DST in attrs
                    else None
                )
                lladdr = attrs.get(NDA_LLADDR)
                if lladdr is not None and len(lladdr) != 6:
                    raise MeasurementError("bad NDA_LLADDR length")
                events.append(
                    Event(
                        message="new" if kind == RTM_NEWNEIGH else "delete",
                        family=family,
                        ifindex=ifindex,
                        state=state,
                        flags=ndflags,
                        dst=dst,
                        lladdr=(
                            ":".join(f"{part:02x}" for part in lladdr)
                            if lladdr is not None
                            else None
                        ),
                        vlan=(
                            _exact_u16(attrs[NDA_VLAN], "NDA_VLAN")
                            if NDA_VLAN in attrs
                            else None
                        ),
                        master=(
                            _exact_u32(attrs[NDA_MASTER], "NDA_MASTER")
                            if NDA_MASTER in attrs
                            else None
                        ),
                        nda_ifindex=(
                            _exact_u32(attrs[NDA_IFINDEX], "NDA_IFINDEX")
                            if NDA_IFINDEX in attrs
                            else None
                        ),
                        timestamp_ns=timestamp_ns,
                    )
                )
        aligned = align4(length)
        if offset + aligned > len(data) or any(data[offset + length : offset + aligned]):
            raise MeasurementError("bad nlmsg alignment padding")
        offset += aligned
    if offset != len(data):
        raise MeasurementError("unaligned nlmsg framing")
    return events


class Observer:
    """Exactly one standard-library NETLINK_ROUTE multicast socket."""

    def __init__(self, receive_bytes: int = 4 * 1024 * 1024):
        self.socket = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, receive_bytes)
        self.socket.bind((0, RTMGRP_NEIGH))

    def ready(self, timeout_seconds: float = 0.0) -> bool:
        readable, _, _ = select.select(
            [self.socket], [], [], max(0.0, timeout_seconds)
        )
        return bool(readable)

    def receive(self, timeout_seconds: float | None = None) -> list[Event]:
        if timeout_seconds is not None and not self.ready(timeout_seconds):
            return []
        try:
            data, _ancillary, flags, address = self.socket.recvmsg(65536)
        except OSError as exc:
            if exc.errno == errno.ENOBUFS:
                raise MeasurementError("NETLINK_ROUTE ENOBUFS") from exc
            raise
        timestamp_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
        return parse_datagram(data, address[0], flags, timestamp_ns)

    def close(self) -> None:
        self.socket.close()


class Pairer:
    """Pair first qualifying NEW events against a deterministic expected table."""

    def __init__(self, expected: list[dict[str, object]]):
        self.expected = {str(row["sample_id"]): row for row in expected}
        if len(self.expected) != len(expected):
            raise MeasurementError("duplicate expected sample id")
        self.sides = {
            key: {"neighbor": [], "fdb": [], "delete": []} for key in self.expected
        }
        self.late = {
            key: {"neighbor": 0, "fdb": 0, "delete": 0} for key in self.expected
        }
        self.frozen: set[str] = set()
        self.wrong_tenant = 0
        self.ambiguous_tenant = 0
        self.last_timestamp = -1
        self._fdb: dict[tuple[object, ...], str] = {}
        self._neighbor: dict[tuple[object, ...], str] = {}
        self._mac: dict[str, str] = {}
        for sample_id, row in self.expected.items():
            fdb = (
                row["vlan"],
                row["port_ifindex"],
                row["bridge_ifindex"],
                row["mac"],
            )
            neighbor = (row["family"], row["ip"], row["bridge_ifindex"], row["mac"])
            mac = str(row["mac"])
            if fdb in self._fdb or neighbor in self._neighbor or mac in self._mac:
                raise MeasurementError("duplicate planned event identity")
            self._fdb[fdb] = sample_id
            self._neighbor[neighbor] = sample_id
            self._mac[mac] = sample_id

    def add(self, event: Event) -> None:
        if event.timestamp_ns < self.last_timestamp:
            raise MeasurementError("CLOCK_MONOTONIC_RAW regression")
        self.last_timestamp = event.timestamp_ns
        if event.message == "delete":
            match = self._match(event, allow_partial=True)
            if match is not None:
                if match in self.frozen:
                    self.late[match]["delete"] += 1
                else:
                    self.sides[match]["delete"].append(event)
            return
        if (event.state & VALID_NUD) == 0 or (event.state & INVALID_NUD) != 0:
            return
        match = self._match(event)
        if match is None:
            self.wrong_tenant += 1
            return
        side = "fdb" if event.family == AF_BRIDGE else "neighbor"
        if match in self.frozen:
            self.late[match][side] += 1
        else:
            self.sides[match][side].append(event)

    def _match(self, event: Event, allow_partial: bool = False) -> str | None:
        if event.family == AF_BRIDGE:
            identity = (event.vlan, event.ifindex, event.master, event.lladdr)
            match = self._fdb.get(identity)
        else:
            identity = (event.family, event.dst, event.ifindex, event.lladdr)
            match = self._neighbor.get(identity)
        if match is not None or not allow_partial or event.lladdr is None:
            return match
        return self._mac.get(event.lladdr)

    def is_complete(self, sample_ids: list[str]) -> bool:
        return all(
            self.sides[sample_id]["neighbor"] and self.sides[sample_id]["fdb"]
            for sample_id in sample_ids
        )

    def freeze(self, sample_ids: list[str]) -> None:
        unknown = set(sample_ids) - self.expected.keys()
        if unknown:
            raise MeasurementError("cannot freeze an unknown sample")
        self.frozen.update(sample_ids)

    def rows(self) -> list[dict[str, object]]:
        rows = []
        for sample_id, expected in self.expected.items():
            neighbor = self.sides[sample_id]["neighbor"]
            fdb = self.sides[sample_id]["fdb"]
            complete = bool(neighbor and fdb)
            skew = neighbor[0].timestamp_ns - fdb[0].timestamp_ns if complete else None
            if complete:
                missing_reason = ""
            elif not neighbor and not fdb:
                missing_reason = "missing-fdb-and-neighbor"
            elif not neighbor:
                missing_reason = "missing-neighbor"
            else:
                missing_reason = "missing-fdb"
            rows.append(
                {
                    **expected,
                    "complete": complete,
                    "missing_reason": missing_reason,
                    "neighbor_ns": neighbor[0].timestamp_ns if neighbor else None,
                    "fdb_ns": fdb[0].timestamp_ns if fdb else None,
                    "skew_ns": skew,
                    "duplicate_neighbor": max(0, len(neighbor) - 1),
                    "duplicate_fdb": max(0, len(fdb) - 1),
                    "delete_events": len(self.sides[sample_id]["delete"]),
                    "late_neighbor": self.late[sample_id]["neighbor"],
                    "late_fdb": self.late[sample_id]["fdb"],
                    "late_delete": self.late[sample_id]["delete"],
                }
            )
        return rows


def percentile(values: list[int], fraction: float) -> int:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]


def _distribution(values: list[int]) -> dict[str, int | None]:
    names = ("p50_ns", "p95_ns", "p99_ns", "p99_9_ns")
    if not values:
        return {"min_ns": None, **{name: None for name in names}, "max_ns": None}
    result = {
        name: percentile(values, quantile)
        for name, quantile in zip(names, (0.5, 0.95, 0.99, 0.999))
    }
    return {"min_ns": min(values), **result, "max_ns": max(values)}


def _summary(rows: list[dict[str, object]]) -> dict[str, object]:
    complete = [row for row in rows if row["complete"]]
    signed = [int(row["skew_ns"]) for row in complete]
    directions = {
        "fdb_first": sum(value > 0 for value in signed),
        "neighbor_first": sum(value < 0 for value in signed),
        "simultaneous": sum(value == 0 for value in signed),
    }
    denominator = len(signed)
    return {
        "expected": len(rows),
        "complete": denominator,
        "missing_neighbor": sum(row["neighbor_ns"] is None for row in rows),
        "missing_fdb": sum(row["fdb_ns"] is None for row in rows),
        "directions": {
            name: {
                "count": count,
                "rate": count / denominator if denominator else None,
            }
            for name, count in directions.items()
        },
        "signed_skew": _distribution(signed),
        "absolute_skew": _distribution([abs(value) for value in signed]),
    }


def build_report(
    rows: list[dict[str, object]],
    expected_count: int,
    wrong_tenant: int,
    ambiguous_tenant: int = 0,
    acceptance: dict[str, object] | None = None,
) -> dict[str, object]:
    if len(rows) != expected_count:
        raise MeasurementError("incomplete denominator")
    if wrong_tenant != 0 or ambiguous_tenant != 0:
        raise MeasurementError("wrong-tenant or ambiguous event invalidated the run")
    if acceptance is not None:
        raise MeasurementError("acceptance requires an external predeclared statistical rule")
    return {
        "schema": 1,
        **_summary(rows),
        "duplicate_neighbor": sum(int(row["duplicate_neighbor"]) for row in rows),
        "duplicate_fdb": sum(int(row["duplicate_fdb"]) for row in rows),
        "late_neighbor": sum(int(row["late_neighbor"]) for row in rows),
        "late_fdb": sum(int(row["late_fdb"]) for row in rows),
        "late_delete": sum(int(row["late_delete"]) for row in rows),
        "wrong_tenant": 0,
        "ambiguous_tenant": 0,
        "direction": "neighbor-minus-fdb",
        "by_family": {
            "ipv4": _summary([row for row in rows if row["family"] == AF_INET]),
            "ipv6": _summary([row for row in rows if row["family"] == AF_INET6]),
        },
        "descriptive_only": True,
        "acceptance": None,
    }


def check_artifacts(directory: Path) -> None:
    total = 0
    names = {"run.json", "samples.csv", "report.json"}
    for name in names:
        path = directory / name
        if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_ARTIFACT_BYTES:
            raise MeasurementError(f"invalid or oversized artifact: {name}")
        total += path.stat().st_size
    if {path.name for path in directory.iterdir()} != names or total > MAX_ARTIFACT_BYTES:
        raise MeasurementError("artifact inventory or total size is invalid")


def _default_ports(active_limit: int) -> dict[str, list[int]]:
    return {
        "10": list(range(110, 110 + active_limit)),
        "20": list(range(210, 210 + active_limit)),
    }


def deterministic_plan(
    profile: str,
    bridge_ifindex: int = 100,
    port_ifindexes: dict[str, list[int]] | None = None,
) -> dict[str, object]:
    if profile not in CAMPAIGNS:
        raise MeasurementError("unknown campaign profile")
    active_limit = CAMPAIGNS[profile]
    ports = port_ifindexes if port_ifindexes is not None else _default_ports(active_limit)
    if set(ports) != {"10", "20"} or any(
        len(ports[str(vlan)]) != active_limit for vlan in (10, 20)
    ):
        raise MeasurementError("campaign topology does not match its active limit")
    all_ifindexes = [bridge_ifindex, *ports["10"], *ports["20"]]
    if any(type(value) is not int or value <= 0 for value in all_ifindexes):
        raise MeasurementError("campaign topology has an invalid ifindex")
    if len(set(all_ifindexes)) != len(all_ifindexes):
        raise MeasurementError("campaign topology reuses an ifindex")
    planned: list[dict[str, object]] = []
    number = 0
    for vlan in (10, 20):
        for family in (AF_INET, AF_INET6):
            family_name = "ipv4" if family == AF_INET else "ipv6"
            phase = f"vlan-{vlan}-{family_name}"
            for index in range(1000):
                number += 1
                ip = (
                    f"10.{vlan}.{index // 254}.{index % 254 + 1}"
                    if family == AF_INET
                    else f"2001:db8:{vlan:x}::{index + 1:x}"
                )
                family_octet = 4 if family == AF_INET else 6
                planned.append(
                    {
                        "sample_id": f"s{number:04d}",
                        "profile": profile,
                        "phase": phase,
                        "vlan": vlan,
                        "family": family,
                        "ip": ip,
                        "mac": (
                            f"02:{vlan:02x}:{family_octet:02x}:"
                            f"{index >> 8 & 255:02x}:{index & 255:02x}:01"
                        ),
                        "bridge_ifindex": bridge_ifindex,
                        "port_ifindex": ports[str(vlan)][index % active_limit],
                    }
                )
    return {
        "schema": 1,
        "profile": profile,
        "active_limit": active_limit,
        "censor_seconds": 5,
        "wall_seconds": 1200,
        "acceptance": None,
        "topology": {
            "bridge_ifindex": bridge_ifindex,
            "port_ifindexes": ports,
        },
        "planned": planned,
    }


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, allow_nan=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


SAMPLE_FIELDS = [
    "sample_id",
    "profile",
    "phase",
    "family",
    "vlan",
    "complete",
    "missing_reason",
    "neighbor_ns",
    "fdb_ns",
    "skew_ns",
    "duplicate_neighbor",
    "duplicate_fdb",
    "delete_events",
    "late_neighbor",
    "late_fdb",
    "late_delete",
]


def write_pairer_receipt(run: dict[str, object], pairer: Pairer, output: Path) -> None:
    if output.exists() or output.is_symlink():
        raise MeasurementError("receipt output must be fresh")
    parent = output.parent
    if not parent.is_dir() or parent.is_symlink():
        raise MeasurementError("receipt parent must be a real directory")
    rows = pairer.rows()
    planned = cast(list[dict[str, object]], run["planned"])
    report = build_report(
        rows,
        len(planned),
        pairer.wrong_tenant,
        pairer.ambiguous_tenant,
        cast(dict[str, object] | None, run["acceptance"]),
    )
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=parent))
    try:
        _write_json(staging / "run.json", run)
        with (staging / "samples.csv").open(
            "w", encoding="utf-8", newline=""
        ) as stream:
            writer = csv.DictWriter(
                stream,
                fieldnames=SAMPLE_FIELDS,
                lineterminator="\n",
                extrasaction="ignore",
            )
            writer.writeheader()
            for row in rows:
                encoded = dict(row)
                encoded["complete"] = "true" if row["complete"] else "false"
                for field in ("neighbor_ns", "fdb_ns", "skew_ns"):
                    encoded[field] = "" if row[field] is None else row[field]
                writer.writerow(encoded)
        _write_json(staging / "report.json", report)
        check_artifacts(staging)
        staging.rename(output)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def write_receipt(run: dict[str, object], events: list[Event], output: Path) -> None:
    pairer = Pairer(cast(list[dict[str, object]], run["planned"]))
    for event in events:
        pairer.add(event)
    write_pairer_receipt(run, pairer, output)


def _command(args: list[str], *, input_text: str | None = None) -> str:
    try:
        result = subprocess.run(
            args,
            check=True,
            input=input_text,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or exc.stdout.strip() or f"status {exc.returncode}"
        raise MeasurementError(f"command failed ({' '.join(args)}): {detail}") from exc
    return result.stdout


def _ifindex(name: str) -> int:
    path = Path("/sys/class/net") / name / "ifindex"
    try:
        return int(path.read_text(encoding="ascii").strip())
    except (OSError, ValueError) as exc:
        raise MeasurementError(f"cannot read interface index for {name}: {exc}") from exc


class TrafficTopology:
    """One disposable bridge namespace with fixed VLAN-specific peer ports."""

    def __init__(self, active_limit: int):
        self.active_limit = active_limit
        self.namespace = f"rbgp-raw-skew-{os.getpid()}"
        self.bridge = "rbgpskbr0"
        self.host_ports: dict[str, list[str]] = {"10": [], "20": []}
        self.peer_ports: dict[str, list[str]] = {"10": [], "20": []}
        self.before_netns = ""
        self.before_links = ""
        self.created_namespace = False
        self.created_bridge = False
        self.created_host_ports: list[str] = []
        self._port_ifindexes: dict[str, list[int]] = {"10": [], "20": []}

    def __enter__(self) -> "TrafficTopology":
        try:
            return self._setup()
        except BaseException as exc:
            try:
                self.__exit__(type(exc), exc, exc.__traceback__)
            except MeasurementError as cleanup:
                raise MeasurementError(
                    f"topology setup failed and cleanup was incomplete: {cleanup}"
                ) from exc
            raise

    def _setup(self) -> "TrafficTopology":
        if os.geteuid() != 0:
            raise MeasurementError("raw bridge skew traffic must run as root")
        for tool in ("bridge", "ip", "python3"):
            if shutil.which(tool) is None:
                raise MeasurementError(f"required traffic tool is missing: {tool}")
        self.before_netns = _command(["ip", "netns", "list"])
        self.before_links = _command(["ip", "-o", "link", "show"])
        _command(["ip", "netns", "add", self.namespace])
        self.created_namespace = True
        _command(
            [
                "ip",
                "link",
                "add",
                self.bridge,
                "type",
                "bridge",
                "vlan_filtering",
                "1",
                "vlan_default_pvid",
                "0",
            ]
        )
        self.created_bridge = True
        _command(["ip", "link", "set", self.bridge, "up"])
        for vlan in (10, 20):
            for slot in range(self.active_limit):
                host = f"rh{vlan}{slot:02d}"
                peer = f"rp{vlan}{slot:02d}"
                self.host_ports[str(vlan)].append(host)
                self.peer_ports[str(vlan)].append(peer)
                _command(["ip", "link", "add", host, "type", "veth", "peer", "name", peer])
                self.created_host_ports.append(host)
                _command(["ip", "link", "set", host, "master", self.bridge])
                _command(["ip", "link", "set", host, "up"])
                _command(["ip", "link", "set", peer, "netns", self.namespace])
                _command(
                    [
                        "ip",
                        "-n",
                        self.namespace,
                        "link",
                        "set",
                        peer,
                        "addrgenmode",
                        "none",
                    ]
                )
                _command(
                    [
                        "bridge",
                        "vlan",
                        "add",
                        "dev",
                        host,
                        "vid",
                        str(vlan),
                        "pvid",
                        "untagged",
                    ]
                )
        for vlan in (10, 20):
            _command(
                [
                    "bridge",
                    "vlan",
                    "add",
                    "dev",
                    self.bridge,
                    "vid",
                    str(vlan),
                    "untagged",
                    "self",
                ]
            )
        for address in (
            "10.10.255.254/16",
            "10.20.255.254/16",
            "2001:db8:a::ffff/64",
            "2001:db8:14::ffff/64",
        ):
            args = ["ip", "addr", "add", address, "dev", self.bridge]
            if ":" in address:
                args.append("nodad")
            _command(args)
        self._port_ifindexes = {
            vlan: [_ifindex(name) for name in names]
            for vlan, names in self.host_ports.items()
        }
        return self

    def ifindexes(self) -> tuple[int, dict[str, list[int]]]:
        bridge = _ifindex(self.bridge)
        return bridge, {key: list(value) for key, value in self._port_ifindexes.items()}

    def prepare_rows(self, rows: list[dict[str, object]]) -> None:
        commands = []
        for row in rows:
            vlan = str(row["vlan"])
            port_ifindex = int(row["port_ifindex"])
            slot = self._port_ifindexes[vlan].index(port_ifindex)
            peer = self.peer_ports[vlan][slot]
            prefix = 16 if row["family"] == AF_INET else 64
            commands.extend(
                [
                    f"link set dev {peer} down",
                    f"addr flush dev {peer}",
                    f"link set dev {peer} address {row['mac']}",
                    f"link set dev {peer} up",
                    f"addr add {row['ip']}/{prefix} dev {peer}"
                    + (" nodad" if row["family"] == AF_INET6 else ""),
                ]
            )
        _command(
            ["ip", "-n", self.namespace, "-batch", "-"],
            input_text="\n".join(commands) + "\n",
        )

    def stimulus(self, rows: list[dict[str, object]]) -> subprocess.Popen[bytes]:
        payload = []
        for row in rows:
            vlan = str(row["vlan"])
            slot = self._port_ifindexes[vlan].index(int(row["port_ifindex"]))
            payload.append(
                {
                    "family": row["family"],
                    "source": row["ip"],
                    "device": self.peer_ports[vlan][slot],
                    "target": (
                        f"10.{vlan}.255.254"
                        if row["family"] == AF_INET
                        else f"2001:db8:{int(vlan):x}::ffff"
                    ),
                }
            )
        code = (
            "import json,socket,sys,threading\n"
            "rows=json.loads(sys.argv[1])\n"
            "sockets=[]\n"
            "for row in rows:\n"
            " s=socket.socket(row['family'],socket.SOCK_DGRAM)\n"
            " s.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,(row['device']+'\\0').encode())\n"
            " s.bind((row['source'],0))\n"
            " sockets.append(s)\n"
            "barrier=threading.Barrier(len(rows)+1)\n"
            "errors=[]\n"
            "def send(index):\n"
            " try:\n"
            "  barrier.wait()\n"
            "  sockets[index].sendto(b'x',(rows[index]['target'],9))\n"
            " except BaseException as exc:\n"
            "  errors.append(repr(exc))\n"
            "threads=[threading.Thread(target=send,args=(i,)) for i in range(len(rows))]\n"
            "[thread.start() for thread in threads]\n"
            "barrier.wait()\n"
            "[thread.join() for thread in threads]\n"
            "[sock.close() for sock in sockets]\n"
            "if errors: raise RuntimeError('; '.join(errors))\n"
        )
        return subprocess.Popen(
            [
                "ip",
                "netns",
                "exec",
                self.namespace,
                "python3",
                "-c",
                code,
                json.dumps(payload, allow_nan=False, separators=(",", ":")),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

    def __exit__(self, _kind: object, _value: object, _traceback: object) -> None:
        errors = []
        for name in self.created_host_ports:
            result = subprocess.run(
                ["ip", "link", "del", name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if result.returncode != 0 and self.created_bridge:
                errors.append(result.stderr.strip() or f"port cleanup failed: {name}")
        if self.created_namespace:
            result = subprocess.run(
                ["ip", "netns", "del", self.namespace],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if result.returncode != 0:
                errors.append(result.stderr.strip() or "namespace cleanup failed")
        if self.created_bridge:
            result = subprocess.run(
                ["ip", "link", "del", self.bridge],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if result.returncode != 0:
                errors.append(result.stderr.strip() or "bridge cleanup failed")
        try:
            if _command(["ip", "netns", "list"]) != self.before_netns:
                errors.append("network namespace inventory changed")
            if _command(["ip", "-o", "link", "show"]) != self.before_links:
                errors.append("link inventory changed")
        except MeasurementError as exc:
            errors.append(str(exc))
        if errors:
            raise MeasurementError("cleanup residue: " + "; ".join(errors))


def _collect_batch(
    observer: Observer,
    pairer: Pairer,
    sample_ids: list[str],
    censor_deadline: float,
) -> None:
    while not pairer.is_complete(sample_ids):
        remaining = censor_deadline - time.monotonic()
        if remaining <= 0:
            return
        for event in observer.receive(min(remaining, 0.25)):
            pairer.add(event)


def _drain_ready(observer: Observer, pairer: Pairer) -> None:
    while observer.ready():
        for event in observer.receive():
            pairer.add(event)


def _finish_process(process: subprocess.Popen[bytes]) -> None:
    try:
        _stdout, stderr = process.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        _stdout, stderr = process.communicate()
        raise MeasurementError("traffic stimulus did not terminate")
    if process.returncode != 0:
        detail = stderr.decode(errors="replace").strip()
        raise MeasurementError(f"traffic stimulus failed: {detail or process.returncode}")


def _smoke_plan(
    bridge_ifindex: int, port_ifindexes: dict[str, list[int]]
) -> dict[str, object]:
    planned = [
        {
            "sample_id": "smoke-vlan10-v4",
            "profile": "current-kernel-smoke",
            "phase": "vlan-10-ipv4",
            "vlan": 10,
            "family": AF_INET,
            "ip": "10.10.254.1",
            "mac": "02:10:04:ff:00:01",
            "bridge_ifindex": bridge_ifindex,
            "port_ifindex": port_ifindexes["10"][0],
        },
        {
            "sample_id": "smoke-vlan20-v6",
            "profile": "current-kernel-smoke",
            "phase": "vlan-20-ipv6",
            "vlan": 20,
            "family": AF_INET6,
            "ip": "2001:db8:14::fffe",
            "mac": "02:20:06:ff:00:01",
            "bridge_ifindex": bridge_ifindex,
            "port_ifindex": port_ifindexes["20"][0],
        },
    ]
    return {
        "schema": 1,
        "profile": "current-kernel-smoke",
        "active_limit": 1,
        "censor_seconds": 5,
        "wall_seconds": 30,
        "acceptance": None,
        "topology": {
            "bridge_ifindex": bridge_ifindex,
            "port_ifindexes": port_ifindexes,
        },
        "planned": planned,
    }


def _execute(profile: str, *, smoke: bool) -> tuple[dict[str, object], Pairer]:
    active_limit = 1 if smoke else CAMPAIGNS[profile]
    wall_deadline = time.monotonic() + (30 if smoke else 1200)
    with TrafficTopology(active_limit) as topology:
        bridge_ifindex, port_ifindexes = topology.ifindexes()
        run = (
            _smoke_plan(bridge_ifindex, port_ifindexes)
            if smoke
            else deterministic_plan(profile, bridge_ifindex, port_ifindexes)
        )
        planned = cast(list[dict[str, object]], run["planned"])
        pairer = Pairer(planned)
        observer = Observer()
        try:
            phases = ["vlan-10-ipv4", "vlan-10-ipv6", "vlan-20-ipv4", "vlan-20-ipv6"]
            for phase in phases:
                phase_rows = [row for row in planned if row["phase"] == phase]
                for start in range(0, len(phase_rows), active_limit):
                    if time.monotonic() >= wall_deadline:
                        break
                    batch = phase_rows[start : start + active_limit]
                    topology.prepare_rows(batch)
                    process = topology.stimulus(batch)
                    try:
                        _collect_batch(
                            observer,
                            pairer,
                            [str(row["sample_id"]) for row in batch],
                            min(wall_deadline, time.monotonic() + 5),
                        )
                    finally:
                        pairer.freeze([str(row["sample_id"]) for row in batch])
                        _finish_process(process)
                        _drain_ready(observer, pairer)
        finally:
            observer.close()
    smoke_ids = ["smoke-vlan10-v4", "smoke-vlan20-v6"]
    if smoke and not pairer.is_complete(smoke_ids):
        raise MeasurementError("current-kernel ARP/ND smoke did not produce both pairs")
    if pairer.wrong_tenant or pairer.ambiguous_tenant:
        raise MeasurementError("wrong-tenant or ambiguous event invalidated the run")
    return run, pairer


def main() -> int:
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--self-test", action="store_true")
    modes.add_argument("--plan", choices=sorted(CAMPAIGNS))
    modes.add_argument("--campaign", choices=sorted(CAMPAIGNS))
    modes.add_argument("--current-kernel-smoke", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.self_test:
        print("raw bridge skew parser ready")
        return 0
    if args.plan:
        payload = deterministic_plan(args.plan)
        text = json.dumps(payload, allow_nan=False, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(text, encoding="utf-8")
        else:
            print(text, end="")
        return 0
    if args.output is None:
        parser.error("--campaign and --current-kernel-smoke require --output")
    run, pairer = _execute(args.campaign or "serial-1", smoke=args.current_kernel_smoke)
    write_pairer_receipt(run, pairer, args.output)
    report = json.loads((args.output / "report.json").read_text(encoding="utf-8"))
    print(json.dumps(report, allow_nan=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
