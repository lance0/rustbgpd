#!/usr/bin/env python3
"""Independent OLD-speaker wire oracle for M94.

This deliberately contains a small BGP decoder rather than importing rustbgpd's
parser.  It acts as the OLD receiving peer or as a byte-transparent bounded
relay, giving both sides of the migration independent wire-level witnesses.
"""

from __future__ import annotations

import ipaddress
import json
import os
import select
import socket
import struct
import sys
import time
from dataclasses import dataclass


MARKER = b"\xff" * 16
AS_TRANS = 23456
ACCEPTED_PREFIX = "203.0.113.95/32"
LOOP_PREFIX = "203.0.113.94/32"
EXPECTED_PATH = [65010, 4200000194]
EXPECTED_AGGREGATOR_AS = 4200000294
SOURCE_ROUTER_ID = "10.94.0.2"


@dataclass
class Update:
    withdrawn: list[str]
    nlri: list[str]
    attrs: dict[int, list[bytes]]


class BgpReader:
    """Incremental socket reader whose partial frame survives an idle timeout."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.buffer = bytearray()

    def fill(self, length: int) -> None:
        while len(self.buffer) < length:
            part = self.sock.recv(4096)
            if not part:
                raise EOFError("BGP stream closed")
            self.buffer.extend(part)

    def read_message(self) -> tuple[int, bytes]:
        self.fill(19)
        header = self.buffer[:19]
        if header[:16] != MARKER:
            raise ValueError("invalid BGP marker")
        length, message_type = struct.unpack("!HB", header[16:19])
        if not 19 <= length <= 4096:
            raise ValueError(f"invalid BGP message length {length}")
        self.fill(length)
        body = bytes(self.buffer[19:length])
        del self.buffer[:length]
        return message_type, body


def send_message(sock: socket.socket, message_type: int, body: bytes = b"") -> None:
    sock.sendall(MARKER + struct.pack("!HB", 19 + len(body), message_type) + body)


def prefixes(data: bytes) -> list[str]:
    result = []
    offset = 0
    while offset < len(data):
        width = data[offset]
        offset += 1
        octets = (width + 7) // 8
        if width > 32 or offset + octets > len(data):
            raise ValueError("malformed IPv4 NLRI")
        packed = data[offset : offset + octets] + b"\x00" * (4 - octets)
        offset += octets
        result.append(f"{ipaddress.IPv4Address(packed)}/{width}")
    return result


def parse_update(body: bytes) -> Update:
    if len(body) < 4:
        raise ValueError("short UPDATE")
    withdrawn_len = struct.unpack("!H", body[:2])[0]
    if 2 + withdrawn_len + 2 > len(body):
        raise ValueError("truncated withdrawn routes")
    withdrawn = prefixes(body[2 : 2 + withdrawn_len])
    attrs_offset = 2 + withdrawn_len
    attrs_len = struct.unpack("!H", body[attrs_offset : attrs_offset + 2])[0]
    attrs_start = attrs_offset + 2
    attrs_end = attrs_start + attrs_len
    if attrs_end > len(body):
        raise ValueError("truncated path attributes")

    attrs: dict[int, list[bytes]] = {}
    offset = attrs_start
    while offset < attrs_end:
        if offset + 3 > attrs_end:
            raise ValueError("short path attribute header")
        flags, code = body[offset], body[offset + 1]
        offset += 2
        if flags & 0x10:
            if offset + 2 > attrs_end:
                raise ValueError("short extended attribute length")
            length = struct.unpack("!H", body[offset : offset + 2])[0]
            offset += 2
        else:
            length = body[offset]
            offset += 1
        if offset + length > attrs_end:
            raise ValueError(f"truncated path attribute {code}")
        attrs.setdefault(code, []).append(body[offset : offset + length])
        offset += length

    return Update(withdrawn, prefixes(body[attrs_end:]), attrs)


def parse_as_path(value: bytes, asn_width: int) -> list[int]:
    result = []
    offset = 0
    while offset < len(value):
        if offset + 2 > len(value):
            raise ValueError("short AS_PATH segment")
        segment_type, count = value[offset], value[offset + 1]
        offset += 2
        if segment_type != 2:
            raise ValueError(f"expected AS_SEQUENCE, got segment {segment_type}")
        needed = count * asn_width
        if offset + needed > len(value):
            raise ValueError("truncated AS_PATH segment")
        fmt = "!" + ("H" if asn_width == 2 else "I") * count
        result.extend(struct.unpack(fmt, value[offset : offset + needed]))
        offset += needed
    return result


def single_attr(update: Update, code: int) -> bytes:
    values = update.attrs.get(code, [])
    if len(values) != 1:
        raise AssertionError(f"attribute {code}: expected once, got {len(values)}")
    return values[0]


def decode_projection(update: Update) -> dict[str, object]:
    as_path = parse_as_path(single_attr(update, 2), 2)
    as4_path = parse_as_path(single_attr(update, 17), 4)
    aggregator = single_attr(update, 7)
    as4_aggregator = single_attr(update, 18)
    if len(aggregator) != 6 or len(as4_aggregator) != 8:
        raise AssertionError("invalid AGGREGATOR migration attribute length")
    aggregator_as, aggregator_ip = struct.unpack("!H4s", aggregator)
    as4_aggregator_as, as4_aggregator_ip = struct.unpack("!I4s", as4_aggregator)
    return {
        "as_path": as_path,
        "as4_path": as4_path,
        "aggregator_as": aggregator_as,
        "aggregator_router_id": str(ipaddress.IPv4Address(aggregator_ip)),
        "as4_aggregator_as": as4_aggregator_as,
        "as4_aggregator_router_id": str(ipaddress.IPv4Address(as4_aggregator_ip)),
    }


def assert_accepted_projection(update: Update) -> dict[str, object]:
    projection = decode_projection(update)
    assert projection["as_path"] == [65010, AS_TRANS], projection
    assert projection["as4_path"] == EXPECTED_PATH, projection
    assert projection["aggregator_as"] == AS_TRANS, projection
    assert projection["aggregator_router_id"] == SOURCE_ROUTER_ID, projection
    assert projection["as4_aggregator_as"] == EXPECTED_AGGREGATOR_AS, projection
    assert projection["as4_aggregator_router_id"] == SOURCE_ROUTER_ID, projection
    return projection


def parse_open(body: bytes) -> dict[str, object]:
    if len(body) < 10 or body[0] != 4:
        raise ValueError("invalid BGP OPEN")
    my_as, hold_time = struct.unpack("!HH", body[1:5])
    router_id = str(ipaddress.IPv4Address(body[5:9]))
    optional_len = body[9]
    optional = body[10 : 10 + optional_len]
    if len(optional) != optional_len:
        raise ValueError("truncated OPEN optional parameters")
    has_as4 = False
    offset = 0
    while offset < len(optional):
        if offset + 2 > len(optional):
            raise ValueError("short OPEN parameter")
        param_type, length = optional[offset], optional[offset + 1]
        value = optional[offset + 2 : offset + 2 + length]
        offset += 2 + length
        if param_type != 2:
            continue
        cap_offset = 0
        while cap_offset < len(value):
            if cap_offset + 2 > len(value):
                raise ValueError("short capability")
            code, cap_len = value[cap_offset], value[cap_offset + 1]
            cap_offset += 2
            cap_value = value[cap_offset : cap_offset + cap_len]
            cap_offset += cap_len
            if len(cap_value) != cap_len:
                raise ValueError("truncated capability")
            has_as4 |= code == 65
    return {
        "my_as": my_as,
        "hold_time": hold_time,
        "router_id": router_id,
        "advertised_as4": has_as4,
    }


def write_receipt(path: str, receipt: dict[str, object]) -> None:
    temporary = f"{path}.tmp"
    with open(temporary, "w", encoding="utf-8") as output:
        json.dump(receipt, output, sort_keys=True)
        output.write("\n")
    os.replace(temporary, path)


def old_sink(receipt_path: str) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("10.94.1.3", 179))
    listener.listen(1)
    connection, address = listener.accept()
    connection.settimeout(1.0)
    reader = BgpReader(connection)

    message_type, body = reader.read_message()
    if message_type != 1:
        raise AssertionError(f"expected OPEN, got BGP message {message_type}")
    peer_open = parse_open(body)
    assert peer_open["my_as"] == AS_TRANS, peer_open

    # Multiprotocol IPv4 capability only: deliberately omit capability 65.
    optional = b"\x02\x06\x01\x04\x00\x01\x00\x01"
    local_open = b"\x04" + struct.pack(
        "!HH4sB", 65095, 90, ipaddress.IPv4Address("10.94.1.3").packed, len(optional)
    ) + optional
    send_message(connection, 1, local_open)
    send_message(connection, 4)

    receipt: dict[str, object] = {
        "announced": False,
        "withdrawn": False,
        "negotiated_as4": False,
        "peer_open_my_as": peer_open["my_as"],
        "peer_advertised_as4": peer_open["advertised_as4"],
        "peer_address": address[0],
    }
    last_keepalive = time.monotonic()
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline and not os.path.exists("/tmp/m94-stop"):
        if time.monotonic() - last_keepalive >= 20:
            send_message(connection, 4)
            last_keepalive = time.monotonic()
        try:
            message_type, body = reader.read_message()
        except socket.timeout:
            continue
        if message_type == 4:
            continue
        if message_type != 2:
            raise AssertionError(f"unexpected BGP message {message_type}")
        update = parse_update(body)
        if ACCEPTED_PREFIX in update.nlri:
            receipt.update(assert_accepted_projection(update))
            receipt["announced"] = True
            write_receipt(receipt_path, receipt)
        if ACCEPTED_PREFIX in update.withdrawn:
            receipt["withdrawn"] = True
            write_receipt(receipt_path, receipt)

    connection.close()
    listener.close()


class SourceWireOracle:
    """Frame both relay directions and prove the ExaBGP source projection."""

    def __init__(self, receipt_path: str) -> None:
        self.receipt_path = receipt_path
        self.buffers = {"exa": bytearray(), "rust": bytearray()}
        self.opens: dict[str, dict[str, object]] = {}
        self.accepted_projection: dict[str, object] | None = None
        self.loop_path: list[int] | None = None
        self.loop_as4_path: list[int] | None = None

    def feed(self, direction: str, data: bytes) -> None:
        buffer = self.buffers[direction]
        buffer.extend(data)
        while len(buffer) >= 19:
            if buffer[:16] != MARKER:
                raise AssertionError(f"{direction}: invalid BGP marker")
            length, message_type = struct.unpack("!HB", buffer[16:19])
            if not 19 <= length <= 4096:
                raise AssertionError(f"{direction}: invalid BGP length {length}")
            if len(buffer) < length:
                return
            body = bytes(buffer[19:length])
            del buffer[:length]
            self.observe(direction, message_type, body)

    def observe(self, direction: str, message_type: int, body: bytes) -> None:
        if message_type == 1:
            opened = parse_open(body)
            if direction == "exa":
                assert opened["my_as"] == 65094, opened
                assert opened["router_id"] == SOURCE_ROUTER_ID, opened
                assert opened["advertised_as4"] is False, opened
            else:
                assert opened["my_as"] == AS_TRANS, opened
                assert opened["router_id"] == "10.94.0.1", opened
                assert opened["advertised_as4"] is True, opened
            self.opens[direction] = opened
        elif direction == "exa" and message_type == 2:
            update = parse_update(body)
            if ACCEPTED_PREFIX in update.nlri:
                self.accepted_projection = assert_accepted_projection(update)
            if LOOP_PREFIX in update.nlri:
                self.loop_path = parse_as_path(single_attr(update, 2), 2)
                self.loop_as4_path = parse_as_path(single_attr(update, 17), 4)
                assert self.loop_path == [65010, AS_TRANS], self.loop_path
                assert self.loop_as4_path == [65010, 4200000094], self.loop_as4_path
        self.maybe_write_receipt()

    def maybe_write_receipt(self) -> None:
        if (
            set(self.opens) != {"exa", "rust"}
            or self.accepted_projection is None
            or self.loop_path is None
            or self.loop_as4_path is None
        ):
            return
        write_receipt(
            self.receipt_path,
            {
                "negotiated_as4": False,
                "exa_advertised_as4": self.opens["exa"]["advertised_as4"],
                "rust_advertised_as4": self.opens["rust"]["advertised_as4"],
                "accepted_prefix": ACCEPTED_PREFIX,
                "accepted_projection": self.accepted_projection,
                "loop_prefix": LOOP_PREFIX,
                "loop_as_path": self.loop_path,
                "loop_as4_path": self.loop_as4_path,
            },
        )


def listening(address: str) -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((address, 179))
    listener.listen(1)
    return listener


def source_proxy(receipt_path: str) -> None:
    listeners = {
        listening("10.94.0.2"): "rust",
        listening("10.94.2.1"): "exa",
    }
    connections: dict[str, socket.socket] = {}
    while len(connections) != 2:
        readable, _, _ = select.select(list(listeners), [], [], 30)
        if not readable:
            raise TimeoutError("timed out accepting both source-proxy legs")
        for listener in readable:
            direction = listeners.pop(listener)
            connection, _ = listener.accept()
            connections[direction] = connection
            listener.close()

    oracle = SourceWireOracle(receipt_path)
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline and not os.path.exists("/tmp/m94-stop"):
        readable, _, _ = select.select(list(connections.values()), [], [], 1)
        for connection in readable:
            source = "exa" if connection is connections["exa"] else "rust"
            destination = connections["rust" if source == "exa" else "exa"]
            data = connection.recv(65536)
            if not data:
                raise EOFError(f"{source} source-proxy leg closed")
            oracle.feed(source, data)
            destination.sendall(data)

    for connection in connections.values():
        connection.close()


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("usage: m94_as4_oracle.py sink RECEIPT | proxy RECEIPT")
    if sys.argv[1] == "sink" and len(sys.argv) == 3:
        old_sink(sys.argv[2])
    elif sys.argv[1] == "proxy" and len(sys.argv) == 3:
        source_proxy(sys.argv[2])
    else:
        raise SystemExit("invalid arguments")


if __name__ == "__main__":
    main()
