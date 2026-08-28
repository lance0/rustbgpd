#!/usr/bin/env python3
"""Measure global versus strict table-filtered IPv4 RTM_GETROUTE dumps."""

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import platform
import socket
import struct
import time
from pathlib import Path

AF_INET = 2
NETLINK_ROUTE = 0
SOL_NETLINK = 270
NETLINK_GET_STRICT_CHK = 12
RTM_NEWROUTE, RTM_GETROUTE = 24, 26
NLMSG_ERROR, NLMSG_DONE = 2, 3
NLM_F_REQUEST, NLM_F_ACK = 0x1, 0x4
NLM_F_DUMP_INTR, NLM_F_DUMP_FILTERED = 0x10, 0x20
NLM_F_CREATE, NLM_F_EXCL, NLM_F_DUMP = 0x400, 0x200, 0x300
RTA_DST, RTA_TABLE = 1, 15
RTN_BLACKHOLE = 6
RTPROT_STATIC, RTPROT_BGP = 4, 186
HDR = struct.Struct("=IHHII")
RTMSG = struct.Struct("=BBBBBBBBI")


def align4(length):
    return (length + 3) & ~3


def attribute(kind, payload):
    length = 4 + len(payload)
    return struct.pack("=HH", length, kind) + payload + bytes(align4(length) - length)


def message(kind, flags, sequence, payload):
    return HDR.pack(HDR.size + len(payload), kind, flags, sequence, 0) + payload


def route_table(payload):
    if len(payload) < RTMSG.size:
        raise RuntimeError("short RTM_NEWROUTE payload")
    table = payload[4]
    offset = RTMSG.size
    while offset + 4 <= len(payload):
        length, kind = struct.unpack_from("=HH", payload, offset)
        if length < 4 or offset + length > len(payload):
            raise RuntimeError("malformed route attribute")
        if kind & 0x3FFF == RTA_TABLE and length >= 8:
            table = struct.unpack_from("=I", payload, offset + 4)[0]
        offset += align4(length)
    return table


class Rtnetlink:
    def __init__(self, strict=False):
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        self.sock.settimeout(15)
        self.sock.bind((0, 0))
        if strict:
            self.sock.setsockopt(SOL_NETLINK, NETLINK_GET_STRICT_CHK, 1)
        self.sequence = 0

    def next_sequence(self):
        self.sequence += 1
        return self.sequence

    def receive(self):
        data, _, flags, _ = self.sock.recvmsg(1 << 20)
        if flags & socket.MSG_TRUNC:
            raise RuntimeError("truncated netlink datagram")
        offset = 0
        while offset + HDR.size <= len(data):
            length, kind, msg_flags, sequence, _ = HDR.unpack_from(data, offset)
            if length < HDR.size or offset + length > len(data):
                raise RuntimeError("malformed netlink message")
            yield kind, msg_flags, sequence, data[offset + HDR.size : offset + length]
            offset += align4(length)
        if offset != len(data):
            raise RuntimeError("trailing bytes in netlink datagram")

    def add_routes(self, rows):
        for start in range(0, len(rows), 128):
            pending = set()
            batch = []
            for table, address, protocol in rows[start : start + 128]:
                sequence = self.next_sequence()
                pending.add(sequence)
                attrs = attribute(RTA_DST, struct.pack("!I", address))
                attrs += attribute(RTA_TABLE, struct.pack("=I", table))
                body = RTMSG.pack(AF_INET, 32, 0, 0, 0, protocol, 0, RTN_BLACKHOLE, 0)
                batch.append(message(RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, sequence, body + attrs))
            blob = b"".join(batch)
            if self.sock.send(blob) != len(blob):
                raise RuntimeError("partial netlink batch send")
            while pending:
                for kind, _, sequence, payload in self.receive():
                    if kind != NLMSG_ERROR or sequence not in pending or len(payload) < 4:
                        raise RuntimeError("unexpected route-add acknowledgement")
                    error = struct.unpack_from("=i", payload)[0]
                    if error:
                        raise OSError(-error, os.strerror(-error))
                    pending.remove(sequence)

    def dump(self, table=None):
        sequence = self.next_sequence()
        body = RTMSG.pack(AF_INET, 0, 0, 0, 0, 0, 0, 0, 0)
        if table is not None:
            body += attribute(RTA_TABLE, struct.pack("=I", table))
        request = message(RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP, sequence, body)
        if self.sock.send(request) != len(request):
            raise RuntimeError("partial dump-request send")
        count, tables, flags_seen = 0, set(), 0
        while True:
            for kind, flags, reply_sequence, payload in self.receive():
                if reply_sequence != sequence:
                    raise RuntimeError("unexpected netlink reply sequence")
                flags_seen |= flags
                if flags & NLM_F_DUMP_INTR:
                    raise RuntimeError("kernel marked route dump interrupted")
                if kind == RTM_NEWROUTE:
                    count += 1
                    tables.add(route_table(payload))
                elif kind == NLMSG_ERROR:
                    error = struct.unpack_from("=i", payload)[0]
                    raise OSError(-error, os.strerror(-error))
                elif kind == NLMSG_DONE:
                    if len(payload) >= 4 and (error := struct.unpack_from("=i", payload)[0]):
                        raise OSError(-error, os.strerror(-error))
                    return count, tables, flags_seen
                else:
                    raise RuntimeError(f"unexpected netlink reply type {kind}")


def percentile(samples, percent):
    ordered = sorted(samples)
    return ordered[max(0, math.ceil(len(ordered) * percent / 100) - 1)]


def timed(dump):
    before = time.perf_counter_ns()
    result = dump()
    return time.perf_counter_ns() - before, result


def render_json(result):
    lines = ["{"]
    keys = sorted(key for key in result if key != "cells")
    for key in keys:
        lines.append(f"  {json.dumps(key)}: {json.dumps(result[key], sort_keys=True, separators=(',', ':'))},")
    lines.append('  "cells": [')
    for index, cell in enumerate(result["cells"]):
        comma = "," if index + 1 < len(result["cells"]) else ""
        lines.append("    " + json.dumps(cell, sort_keys=True, separators=(",", ":")) + comma)
    lines.extend(["  ]", "}"])
    return "\n".join(lines) + "\n"


def cpu_model():
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return "unknown"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--metadata-output", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--provenance", required=True)
    parser.add_argument("--rust-toolchain", required=True)
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    if platform.system() != "Linux" or os.geteuid() != 0:
        parser.error("Linux root/CAP_SYS_ADMIN is required")
    if len(args.source_sha) != 40 or any(c not in "0123456789abcdef" for c in args.source_sha):
        parser.error("--source-sha must be a lowercase 40-character Git SHA")
    if args.output.resolve() == args.metadata_output.resolve():
        parser.error("result and metadata paths must differ")
    args.output.unlink(missing_ok=True)
    args.metadata_output.unlink(missing_ok=True)

    before_namespace = os.readlink("/proc/self/ns/net")
    os.unshare(os.CLONE_NEWNET)
    after_namespace = os.readlink("/proc/self/ns/net")
    if before_namespace == after_namespace:
        raise RuntimeError("CLONE_NEWNET did not create a disposable namespace")

    managed_tables = 2 if args.smoke else 64
    foreign_sizes = [0, 20] if args.smoke else [0, 1000, 5000, 20000]
    table_counts = [1, 2] if args.smoke else [1, 2, 4, 8, 16, 32, 64]
    passes, warmups = (2, 1) if args.smoke else (25, 3)
    fixed_count = managed_tables * 2
    add = Rtnetlink()
    unfiltered = Rtnetlink()
    strict = Rtnetlink(strict=True)
    if strict.dump()[0] != 0:
        raise RuntimeError("new namespace did not begin with an empty IPv4 FIB")

    fixed = []
    for index in range(managed_tables):
        table = 1000 + index
        fixed.extend([(table, 0x0A000001 + index, RTPROT_BGP), (table, 0x0A010001 + index, RTPROT_STATIC)])
    add.add_routes(fixed)
    loose_count, loose_tables, _ = unfiltered.dump(1000)
    if loose_count != fixed_count or 1001 not in loose_tables:
        raise RuntimeError("non-strict table request did not expose unrelated tables")
    strict_count, strict_tables, strict_flags = strict.dump(1000)
    if strict_count != 2 or strict_tables != {1000} or not strict_flags & NLM_F_DUMP_FILTERED:
        raise RuntimeError("strict table filter cardinality/flag assertion failed")

    cells, populated = [], 0
    for foreign_size in foreign_sizes:
        rows = [(2000, 0x0B000001 + index, RTPROT_STATIC) for index in range(populated, foreign_size)]
        add.add_routes(rows)
        populated = foreign_size
        for table_count in table_counts:
            expected_global, expected_filtered = fixed_count + foreign_size, table_count * 2

            def global_dump(expected_global=expected_global):
                count, _, _ = strict.dump()
                if count != expected_global:
                    raise RuntimeError(f"global route count {count} != {expected_global}")
                return count

            def filtered_dump(table_count=table_count, expected_filtered=expected_filtered):
                count = 0
                for table in range(1000, 1000 + table_count):
                    got, tables, flags = strict.dump(table)
                    if got != 2 or tables != {table} or not flags & NLM_F_DUMP_FILTERED:
                        raise RuntimeError(f"strict route assertion failed for table {table}")
                    count += got
                if count != expected_filtered:
                    raise RuntimeError(f"filtered route count {count} != {expected_filtered}")
                return count

            for _ in range(warmups):
                global_dump()
                filtered_dump()
            global_ns, filtered_ns = [], []
            for attempt in range(passes):
                order = ((global_dump, global_ns), (filtered_dump, filtered_ns))
                if attempt % 2:
                    order = reversed(order)
                for operation, samples in order:
                    duration, _ = timed(operation)
                    samples.append(duration)
            cells.append({
                "foreign_global_rows": foreign_size,
                "managed_table_count": table_count,
                "global": {"p50_ns": percentile(global_ns, 50), "p95_ns": percentile(global_ns, 95), "returned_routes": expected_global},
                "strict_per_table": {"p50_ns": percentile(filtered_ns, 50), "p95_ns": percentile(filtered_ns, 95), "returned_routes": expected_filtered},
            })

    harness_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    environment = {"cpu_model": cpu_model(), "kernel": platform.release(), "machine": platform.machine(), "python": platform.python_version()}
    result = {
        "schema": "rustbgpd.fib-kernel-dump.v1",
        "mode": "smoke" if args.smoke else "full",
        "source_sha": args.source_sha,
        "environment": environment,
        "fixture": {"family": "ipv4", "foreign_in_each_managed_table": 1, "foreign_table": 2000, "managed_route_in_each_table": 1, "managed_tables": managed_tables, "route_shape": "blackhole /32"},
        "method": {"clock": "time.perf_counter_ns", "passes_per_cell": passes, "percentile": "nearest-rank", "warmups_per_cell": warmups},
        "preconditions": {"initial_routes": 0, "non_strict_table_request_routes": loose_count, "strict_dump_filtered_flag": True, "strict_table_request_routes": strict_count},
        "provenance": {"harness_sha256": harness_hash, "runner": args.provenance, "rust_toolchain": args.rust_toolchain},
        "cells": cells,
    }
    rendered = render_json(result)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered)
    metadata = {
        "cpu_model": environment["cpu_model"],
        "generated_utc": dt.datetime.now(dt.UTC).isoformat(),
        "harness_sha256": harness_hash,
        "kernel": environment["kernel"],
        "machine": environment["machine"],
        "measurement_toolchain": f"Python {environment['python']}",
        "namespace_isolation": "os.unshare(CLONE_NEWNET); namespace lifetime is the harness process",
        "provenance": args.provenance,
        "results_sha256": hashlib.sha256(rendered.encode()).hexdigest(),
        "rust_toolchain": args.rust_toolchain,
        "source_sha": args.source_sha,
    }
    args.metadata_output.parent.mkdir(parents=True, exist_ok=True)
    args.metadata_output.write_text("".join(f"{key}: {value}\n" for key, value in sorted(metadata.items())))


if __name__ == "__main__":
    main()
