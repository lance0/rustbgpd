#!/usr/bin/env python3
"""One-generation RFC 7854/9069 sink for the IRR BMP buffer receipt.

The sink accepts exactly one BMP v3 connection, parses frames without an
unbounded read, and keeps the accepted socket open after a complete dump so
the runner can scrape the generation's gauges before allowing teardown.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import pathlib
import select
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field

BMP_HEADER = 6
PER_PEER_HEADER = 42
MAX_FRAME_BYTES = 1 << 20
MAX_CAPTURE_BYTES = 1 << 30
DEFAULT_TIMEOUT_SECONDS = 600
EXPECTED_EORS = [(1, 1), (2, 1), (1, 128), (2, 128)]
EXPECTED_CAPABILITIES = [
    (1, b"\x00\x01\x00\x01"),
    (1, b"\x00\x02\x00\x01"),
    (1, b"\x00\x01\x00\x80"),
    (1, b"\x00\x02\x00\x80"),
    (65, struct.pack("!I", 65500)),
]


class ReceiptError(RuntimeError):
    """A protocol or receipt invariant failed."""


def atomic_text(path: pathlib.Path, text: str) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(text)
    temporary.replace(path)


def parse_listen(value: str) -> tuple[str, int]:
    host, separator, port = value.rpartition(":")
    if not separator or not host:
        raise argparse.ArgumentTypeError("listen address must be HOST:PORT")
    try:
        parsed_port = int(port)
    except ValueError as error:
        raise argparse.ArgumentTypeError("listen port must be numeric") from error
    if not 1 <= parsed_port <= 65535:
        raise argparse.ArgumentTypeError("listen port must be in 1..65535")
    return host, parsed_port


def parse_peer_header(body: bytes) -> tuple[dict[str, object], bytes]:
    if len(body) < PER_PEER_HEADER:
        raise ReceiptError("truncated BMP per-peer header")
    peer = {
        "type": body[0],
        "flags": body[1],
        "distinguisher": int.from_bytes(body[2:10], "big"),
        "address": str(ipaddress.ip_address(body[10:26])),
        "asn": int.from_bytes(body[26:30], "big"),
        "bgp_id": str(ipaddress.ip_address(body[30:34])),
    }
    return peer, body[PER_PEER_HEADER:]


def verify_loc_rib_peer(peer: dict[str, object]) -> None:
    expected = {
        "type": 3,
        "flags": 0,
        "distinguisher": 0,
        "address": "::",
        "asn": 65500,
        "bgp_id": "10.0.0.1",
    }
    if peer != expected:
        raise ReceiptError(f"unexpected Loc-RIB peer identity: {peer!r}")


def parse_open(pdu: bytes) -> list[tuple[int, bytes]]:
    if len(pdu) < 29 or pdu[:16] != b"\xff" * 16:
        raise ReceiptError("malformed fabricated OPEN header")
    length = int.from_bytes(pdu[16:18], "big")
    if length != len(pdu) or pdu[18] != 1:
        raise ReceiptError("fabricated OPEN length/type mismatch")
    body = pdu[19:]
    if body[:9] != b"\x04\xff\xdc\x00\x00\x0a\x00\x00\x01":
        raise ReceiptError("fabricated OPEN fixed fields mismatch")
    optional_len = body[9]
    optional = body[10:]
    if optional_len != len(optional):
        raise ReceiptError("fabricated OPEN optional length mismatch")
    capabilities: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(optional):
        if offset + 2 > len(optional):
            raise ReceiptError("truncated OPEN optional parameter")
        parameter_type, parameter_len = optional[offset : offset + 2]
        offset += 2
        end = offset + parameter_len
        if parameter_type != 2 or end > len(optional):
            raise ReceiptError("unexpected or truncated OPEN optional parameter")
        parameter = optional[offset:end]
        offset = end
        cap_offset = 0
        while cap_offset < len(parameter):
            if cap_offset + 2 > len(parameter):
                raise ReceiptError("truncated capability header")
            code, cap_len = parameter[cap_offset : cap_offset + 2]
            cap_offset += 2
            cap_end = cap_offset + cap_len
            if cap_end > len(parameter):
                raise ReceiptError("truncated capability payload")
            capabilities.append((code, parameter[cap_offset:cap_end]))
            cap_offset = cap_end
    return capabilities


def parse_loc_rib_peer_up(body: bytes) -> None:
    peer, payload = parse_peer_header(body)
    verify_loc_rib_peer(peer)
    if len(payload) < 20 + 2 * 29:
        raise ReceiptError("truncated Loc-RIB Peer Up")
    if payload[:20] != b"\x00" * 20:
        raise ReceiptError("Loc-RIB Peer Up local address/ports are not zero")
    offset = 20
    opens = []
    for _ in range(2):
        if offset + 19 > len(payload):
            raise ReceiptError("truncated fabricated OPEN")
        length = int.from_bytes(payload[offset + 16 : offset + 18], "big")
        if length < 29 or offset + length > len(payload):
            raise ReceiptError("invalid fabricated OPEN length")
        opens.append(payload[offset : offset + length])
        offset += length
    if opens[0] != opens[1]:
        raise ReceiptError("Loc-RIB sent/received OPENs differ")
    capabilities = parse_open(opens[0])
    if capabilities != EXPECTED_CAPABILITIES:
        raise ReceiptError(f"Loc-RIB capability roster mismatch: {capabilities!r}")
    if payload[offset:] != b"\x00\x03\x00\x06global":
        raise ReceiptError("Loc-RIB table-name TLV is not exactly global")


def parse_nlri(payload: bytes) -> list[str]:
    prefixes = []
    offset = 0
    while offset < len(payload):
        prefix_len = payload[offset]
        offset += 1
        if prefix_len > 32:
            raise ReceiptError(f"unexpected non-IPv4 NLRI length {prefix_len}")
        octets = (prefix_len + 7) // 8
        end = offset + octets
        if end > len(payload):
            raise ReceiptError("truncated IPv4 NLRI")
        packed = payload[offset:end] + b"\x00" * (4 - octets)
        offset = end
        address = ipaddress.IPv4Address(packed)
        network = ipaddress.IPv4Network((address, prefix_len), strict=False)
        if address != network.network_address:
            raise ReceiptError("IPv4 NLRI has non-zero host bits")
        prefixes.append(str(network))
    return prefixes


def parse_attributes(payload: bytes) -> list[tuple[int, bytes]]:
    attributes = []
    offset = 0
    while offset < len(payload):
        if offset + 3 > len(payload):
            raise ReceiptError("truncated path attribute header")
        flags, code = payload[offset : offset + 2]
        offset += 2
        if flags & 0x10:
            if offset + 2 > len(payload):
                raise ReceiptError("truncated extended path attribute length")
            length = int.from_bytes(payload[offset : offset + 2], "big")
            offset += 2
        else:
            length = payload[offset]
            offset += 1
        end = offset + length
        if end > len(payload):
            raise ReceiptError("truncated path attribute payload")
        attributes.append((code, payload[offset:end]))
        offset = end
    return attributes


def parse_update(pdu: bytes) -> tuple[list[str], list[str], tuple[int, int] | None]:
    if len(pdu) < 23 or pdu[:16] != b"\xff" * 16:
        raise ReceiptError("malformed BGP UPDATE header")
    length = int.from_bytes(pdu[16:18], "big")
    if length != len(pdu) or pdu[18] != 2:
        raise ReceiptError("BGP UPDATE length/type mismatch")
    body = pdu[19:]
    withdrawn_len = int.from_bytes(body[:2], "big")
    if 2 + withdrawn_len + 2 > len(body):
        raise ReceiptError("truncated BGP withdrawn-routes section")
    withdrawn = parse_nlri(body[2 : 2 + withdrawn_len])
    attr_offset = 2 + withdrawn_len
    attributes_len = int.from_bytes(body[attr_offset : attr_offset + 2], "big")
    attr_offset += 2
    attr_end = attr_offset + attributes_len
    if attr_end > len(body):
        raise ReceiptError("truncated BGP path-attributes section")
    attributes = parse_attributes(body[attr_offset:attr_end])
    announced = parse_nlri(body[attr_end:])

    if not announced and not withdrawn and not attributes:
        return announced, withdrawn, (1, 1)
    if not announced and not withdrawn and len(attributes) == 1:
        code, value = attributes[0]
        if code == 15 and len(value) == 3:
            return announced, withdrawn, (int.from_bytes(value[:2], "big"), value[2])
    if any(code in (14, 15) for code, _ in attributes):
        raise ReceiptError("unexpected MP reachability in IPv4-only receipt")
    return announced, withdrawn, None


def prefix_class(prefix: str, total_prefixes: int) -> tuple[str, int]:
    network = ipaddress.ip_network(prefix)
    if network.prefixlen != 24:
        raise ReceiptError(f"receipt prefix is not /24: {prefix}")
    a, b, c, d = network.network_address.packed
    if d != 0:
        raise ReceiptError(f"receipt prefix is not canonical: {prefix}")
    if a >= 20:
        index = ((a - 20) << 16) | (b << 8) | c
        if index < total_prefixes:
            return "base", index
    if a == 172 and 16 <= b < 24 and c < 16:
        return "churn", ((b - 16) << 4) | c
    raise ReceiptError(f"prefix outside canonical base/churn rosters: {prefix}")


@dataclass
class ReceiptState:
    total_prefixes: int
    initiation: int = 0
    loc_rib_peer_up: int = 0
    base_seen: set[int] = field(default_factory=set)
    churn_announces: int = 0
    churn_withdrawals: int = 0
    eors: list[tuple[int, int]] = field(default_factory=list)
    post_eor_churn: bool = False
    frames: int = 0

    def boundary_detail(self, prefix: str, body: bytes) -> str:
        """Failure context for a dump/live boundary breach: the offending
        prefix, its per-peer-header BMP timestamp, and where in the dump
        stream it landed (frame index, EoRs and dump rows seen so far)."""
        seconds = int.from_bytes(body[34:38], "big")
        microseconds = int.from_bytes(body[38:42], "big")
        return (
            f"prefix={prefix} bmp_timestamp={seconds}.{microseconds:06d}"
            f" frame_index={self.frames} eors_seen={len(self.eors)}"
            f" base_rows_seen={len(self.base_seen)}"
        )

    def observe(self, frame: bytes) -> None:
        self.frames += 1
        msg_type = frame[5]
        body = frame[BMP_HEADER:]
        if msg_type == 4:
            if (
                self.initiation != 0
                or self.loc_rib_peer_up != 0
                or self.base_seen
                or self.eors
                or self.post_eor_churn
            ):
                raise ReceiptError("Initiation is not the first BMP message")
            self.initiation += 1
            return
        if self.initiation != 1:
            raise ReceiptError("BMP message arrived before Initiation")
        if msg_type == 3:
            peer, _ = parse_peer_header(body)
            if peer["type"] == 3:
                if self.loc_rib_peer_up != 0 or self.base_seen or self.eors:
                    raise ReceiptError("Loc-RIB Peer Up is duplicated or out of order")
                parse_loc_rib_peer_up(body)
                self.loc_rib_peer_up += 1
            return
        if msg_type == 0:
            if self.loc_rib_peer_up != 1:
                raise ReceiptError("Loc-RIB Route Monitoring arrived before Peer Up")
            peer, update = parse_peer_header(body)
            verify_loc_rib_peer(peer)
            announced, withdrawn, eor = parse_update(update)
            if eor is not None:
                if not self.eors and len(self.base_seen) != self.total_prefixes:
                    raise ReceiptError("End-of-RIB arrived before the complete base table")
                expected_index = len(self.eors)
                if expected_index >= len(EXPECTED_EORS) or eor != EXPECTED_EORS[expected_index]:
                    raise ReceiptError(f"out-of-order or duplicate End-of-RIB: {eor!r}")
                self.eors.append(eor)
                return
            if self.eors and len(self.eors) != len(EXPECTED_EORS) and (announced or withdrawn):
                raise ReceiptError("route update appeared inside the ordered End-of-RIB sequence")
            for prefix in withdrawn:
                kind, _ = prefix_class(prefix, self.total_prefixes)
                if kind == "base":
                    raise ReceiptError(f"base-table withdrawal during dump: {prefix}")
                if len(self.eors) != len(EXPECTED_EORS):
                    raise ReceiptError(
                        "churn withdrawal appeared before dump End-of-RIB: "
                        + self.boundary_detail(prefix, body)
                    )
                self.churn_withdrawals += 1
                self.post_eor_churn = True
            for prefix in announced:
                kind, index = prefix_class(prefix, self.total_prefixes)
                if kind == "base":
                    if self.eors:
                        raise ReceiptError(f"base-table announcement after End-of-RIB: {prefix}")
                    if index in self.base_seen:
                        raise ReceiptError(f"duplicate base-table announcement: {prefix}")
                    self.base_seen.add(index)
                else:
                    if len(self.eors) != len(EXPECTED_EORS):
                        raise ReceiptError(
                            "churn announcement appeared before dump End-of-RIB: "
                            + self.boundary_detail(prefix, body)
                        )
                    self.churn_announces += 1
                    self.post_eor_churn = True
            return
        if msg_type == 2:
            peer, _ = parse_peer_header(body)
            if peer["type"] == 3:
                verify_loc_rib_peer(peer)
                raise ReceiptError("Loc-RIB Peer Down before receipt scrape")
            return
        if msg_type == 1:
            peer, _ = parse_peer_header(body)
            if peer["type"] == 3:
                if self.loc_rib_peer_up != 1:
                    raise ReceiptError("Loc-RIB Stats arrived before Peer Up")
                verify_loc_rib_peer(peer)
            return
        if msg_type == 5:
            raise ReceiptError("BMP Termination before receipt scrape")
        if msg_type not in (1, 5):
            raise ReceiptError(f"unknown BMP message type {msg_type}")

    def complete(self) -> bool:
        return (
            self.initiation == 1
            and self.loc_rib_peer_up == 1
            and len(self.base_seen) == self.total_prefixes
            and self.eors == EXPECTED_EORS
            and self.post_eor_churn
        )

    def summary(self, outcome: str, captured_bytes: int, generation_open: bool) -> dict:
        return {
            "schema": 1,
            "outcome": outcome,
            "captured_bytes": captured_bytes,
            "initiation": self.initiation,
            "loc_rib_peer_up": self.loc_rib_peer_up,
            "base_prefixes": len(self.base_seen),
            "base_duplicates": 0,
            "base_withdrawals": 0,
            "churn_announces": self.churn_announces,
            "churn_withdrawals": self.churn_withdrawals,
            "eors": [[afi, safi] for afi, safi in self.eors],
            "post_eor_churn": self.post_eor_churn,
            "complete_handshake": self.complete(),
            "generation_open_at_summary": generation_open,
        }


def recv_exact(connection: socket.socket, size: int, deadline: float) -> bytes | None:
    chunks = bytearray()
    while len(chunks) < size:
        if time.monotonic() >= deadline:
            raise ReceiptError("BMP generation exceeded the 600-second deadline")
        try:
            chunk = connection.recv(size - len(chunks))
        except socket.timeout:
            continue
        if not chunk:
            if chunks:
                raise ReceiptError("EOF inside BMP frame")
            return None
        chunks.extend(chunk)
    return bytes(chunks)


def validated_frame_length(header: bytes) -> int:
    if len(header) != BMP_HEADER:
        raise ReceiptError("truncated BMP common header")
    version = header[0]
    length = int.from_bytes(header[1:5], "big")
    if version != 3:
        raise ReceiptError(f"expected BMP v3, got v{version}")
    if not BMP_HEADER <= length <= MAX_FRAME_BYTES:
        raise ReceiptError(f"BMP frame length {length} exceeds 1 MiB bound")
    return length


def recv_frame(connection: socket.socket, deadline: float, captured: int) -> tuple[bytes | None, int]:
    header = recv_exact(connection, BMP_HEADER, deadline)
    if header is None:
        return None, captured
    length = validated_frame_length(header)
    captured += length
    if captured > MAX_CAPTURE_BYTES:
        raise ReceiptError("BMP capture exceeded 1 GiB bound")
    body = recv_exact(connection, length - BMP_HEADER, deadline)
    if body is None:
        raise ReceiptError("EOF inside BMP frame body")
    return header + body, captured


def wait_for_file(path: pathlib.Path, deadline: float) -> None:
    while not path.is_file():
        if time.monotonic() >= deadline:
            raise ReceiptError(f"timed out waiting for {path.name}")
        time.sleep(0.05)


def wait_for_scrape_release(
    connection: socket.socket,
    state: ReceiptState,
    stop_file: pathlib.Path,
    generation_open: pathlib.Path,
    deadline: float,
    captured: int,
) -> int:
    """Keep proving the completed generation is live until the scrape releases it.

    The stop-file is checked on every iteration, after at most one frame of
    pending data: continuous post-EoR churn keeps the socket readable, so a
    stop check gated on an idle socket would starve for as long as the churn
    lasts. A failure already queued ahead of the stop (FIN, Termination, a
    boundary breach) still wins, because the data branch runs first.
    """
    try:
        while True:
            if time.monotonic() >= deadline:
                raise ReceiptError(f"timed out waiting for {stop_file.name}")
            if select.select([connection], [], [], 0.05)[0]:
                frame, captured = recv_frame(connection, deadline, captured)
                if frame is None:
                    raise ReceiptError("complete generation closed before metrics scrape")
                state.observe(frame)
            if stop_file.is_file():
                return captured
    except (OSError, ReceiptError):
        generation_open.unlink(missing_ok=True)
        raise


def run_sink(args: argparse.Namespace) -> int:
    output = args.output_dir
    output.mkdir(parents=True, exist_ok=False)
    deadline = time.monotonic() + args.timeout
    state = ReceiptState(args.total_prefixes)
    generation_open = output / "generation-open"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(args.listen)
            server.listen(1)
            server.settimeout(1)
            atomic_text(output / "listening", "ready\n")
            while True:
                if time.monotonic() >= deadline:
                    raise ReceiptError("timed out waiting for sole BMP connection")
                try:
                    connection, remote = server.accept()
                    break
                except socket.timeout:
                    continue
        atomic_text(output / "accepted", f"{remote[0]}:{remote[1]}\n")
        atomic_text(generation_open, "open\n")
        with connection:
            connection.settimeout(1)
            wait_for_file(args.start_file, deadline)
            captured = 0
            while True:
                frame, captured = recv_frame(connection, deadline, captured)
                if frame is None:
                    generation_open.unlink(missing_ok=True)
                    if state.complete():
                        raise ReceiptError("complete generation closed before metrics scrape")
                    if state.initiation != 1 or state.loc_rib_peer_up != 1 or not state.base_seen:
                        raise ReceiptError("generation closed before a measurable Loc-RIB dump")
                    summary = state.summary("overflow", captured, False)
                    atomic_text(output / "summary.json", json.dumps(summary, indent=2) + "\n")
                    atomic_text(output / "ready", "overflow\n")
                    return 0
                state.observe(frame)
                if state.complete():
                    summary = state.summary("complete", captured, True)
                    atomic_text(output / "summary.json", json.dumps(summary, indent=2) + "\n")
                    atomic_text(output / "ready", "complete\n")
                    captured = wait_for_scrape_release(
                        connection,
                        state,
                        args.stop_file,
                        generation_open,
                        deadline,
                        captured,
                    )
                    generation_open.unlink(missing_ok=True)
                    return 0
    except (OSError, ReceiptError) as error:
        generation_open.unlink(missing_ok=True)
        atomic_text(output / "error.json", json.dumps({"error": str(error)}, indent=2) + "\n")
        print(f"BMP sink: {error}", file=sys.stderr)
        return 1


def bgp_header(msg_type: int, body: bytes) -> bytes:
    return b"\xff" * 16 + struct.pack("!HB", 19 + len(body), msg_type) + body


def optional_capabilities() -> bytes:
    caps = b"".join(bytes([code, len(value)]) + value for code, value in EXPECTED_CAPABILITIES)
    return bytes([2, len(caps)]) + caps


def sample_open() -> bytes:
    optional = optional_capabilities()
    body = b"\x04\xff\xdc\x00\x00\x0a\x00\x00\x01" + bytes([len(optional)]) + optional
    return bgp_header(1, body)


def sample_peer_header(*, peer_type: int = 3) -> bytes:
    return (
        bytes([peer_type, 0])
        + b"\x00" * 8
        + b"\x00" * 16
        + struct.pack("!I", 65500)
        + ipaddress.IPv4Address("10.0.0.1").packed
        + b"\x00" * 8
    )


def sample_peer_up(*, peer_type: int = 3) -> bytes:
    open_pdu = sample_open()
    body = (
        sample_peer_header(peer_type=peer_type)
        + b"\x00" * 20
        + open_pdu * 2
        + b"\x00\x03\x00\x06global"
    )
    return bytes([3]) + struct.pack("!I", BMP_HEADER + len(body)) + bytes([3]) + body


def sample_per_peer(msg_type: int, *, peer_type: int = 3) -> bytes:
    body = sample_peer_header(peer_type=peer_type)
    return bytes([3]) + struct.pack("!I", BMP_HEADER + len(body)) + bytes([msg_type]) + body


def encode_nlri(prefix: str) -> bytes:
    network = ipaddress.IPv4Network(prefix)
    octets = (network.prefixlen + 7) // 8
    return bytes([network.prefixlen]) + network.network_address.packed[:octets]


def sample_update(*, announced: str | None = None, withdrawn: str | None = None, eor=None) -> bytes:
    withdrawn_wire = encode_nlri(withdrawn) if withdrawn else b""
    attributes = b""
    announced_wire = encode_nlri(announced) if announced else b""
    if eor is not None and eor != (1, 1):
        value = struct.pack("!HB", *eor)
        attributes = bytes([0x80, 15, len(value)]) + value
    body = (
        struct.pack("!H", len(withdrawn_wire))
        + withdrawn_wire
        + struct.pack("!H", len(attributes))
        + attributes
        + announced_wire
    )
    return bgp_header(2, body)


def sample_rm(update: bytes, *, peer_type: int = 3) -> bytes:
    body = sample_peer_header(peer_type=peer_type) + update
    return bytes([3]) + struct.pack("!I", BMP_HEADER + len(body)) + bytes([0]) + body


def expect_rejected(name: str, action, contains: tuple[str, ...] = ()) -> None:
    try:
        action()
    except ReceiptError as error:
        for fragment in contains:
            if fragment not in str(error):
                raise AssertionError(f"{name}: error lacks {fragment!r}: {error}") from error
        print(f"proof:{name}")
        return
    raise AssertionError(f"mutation was accepted: {name}")


def self_test() -> int:
    init = bytes([3]) + struct.pack("!I", 6) + bytes([4])
    parse_loc_rib_peer_up(sample_peer_up()[BMP_HEADER:])

    def primed_state() -> ReceiptState:
        candidate = ReceiptState(2)
        candidate.observe(init)
        candidate.observe(sample_peer_up(peer_type=0))
        candidate.observe(sample_peer_up())
        candidate.observe(sample_per_peer(1))
        return candidate

    state = primed_state()
    state.observe(sample_rm(sample_update(announced="20.0.0.0/24")))
    state.observe(sample_rm(sample_update(announced="20.0.1.0/24")))
    for family in EXPECTED_EORS:
        state.observe(sample_rm(sample_update(eor=family)))
    state.observe(sample_rm(sample_update(announced="172.16.0.0/24")))
    assert state.complete()
    print("proof:complete-handshake")

    expect_rejected(
        "duplicate-base",
        lambda: state.observe(sample_rm(sample_update(announced="20.0.0.0/24"))),
    )
    expect_rejected(
        "base-withdrawal",
        lambda: primed_state().observe(sample_rm(sample_update(withdrawn="20.0.0.0/24"))),
    )
    expect_rejected(
        "unexpected-prefix",
        lambda: primed_state().observe(sample_rm(sample_update(announced="192.0.2.0/24"))),
    )
    expect_rejected(
        "peer-identity",
        lambda: primed_state().observe(sample_rm(sample_update(eor=(1, 1)), peer_type=0)),
    )
    before_peer_up = ReceiptState(2)
    before_peer_up.observe(init)
    before_peer_up.observe(sample_peer_up(peer_type=0))
    expect_rejected(
        "loc-rib-stats-order",
        lambda: before_peer_up.observe(sample_per_peer(1)),
    )
    expect_rejected(
        "loc-rib-peer-down",
        lambda: primed_state().observe(sample_per_peer(2)),
    )
    reordered = primed_state()
    reordered.observe(sample_rm(sample_update(announced="20.0.0.0/24")))
    reordered.observe(sample_rm(sample_update(announced="20.0.1.0/24")))
    expect_rejected(
        "eor-order",
        lambda: reordered.observe(sample_rm(sample_update(eor=(2, 1)))),
    )
    early_eor = primed_state()
    early_eor.observe(sample_rm(sample_update(announced="20.0.0.0/24")))
    expect_rejected(
        "base-before-eor",
        lambda: early_eor.observe(sample_rm(sample_update(eor=(1, 1)))),
    )
    before_eor = primed_state()
    expect_rejected(
        "dump-before-live-order",
        lambda: before_eor.observe(sample_rm(sample_update(announced="172.16.0.0/24"))),
        contains=(
            "prefix=172.16.0.0/24",
            "bmp_timestamp=0.000000",
            "frame_index=5",
            "eors_seen=0",
        ),
    )
    expect_rejected(
        "churn-withdrawal-before-eor",
        lambda: primed_state().observe(sample_rm(sample_update(withdrawn="172.16.0.0/24"))),
        contains=("prefix=172.16.0.0/24", "bmp_timestamp=", "frame_index="),
    )
    oversized = bytes([3]) + struct.pack("!I", MAX_FRAME_BYTES + 1) + bytes([0])
    expect_rejected("frame-bound", lambda: validated_frame_length(oversized))

    def prove_pre_scrape_disconnect(name: str, frame: bytes | None) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            output = root / "sink"
            start_file = root / "start"
            stop_file = root / "stop"
            seam_stop = root / "seam-stop"
            seam_open = root / "seam-generation-open"
            seam_stop.write_text("stop\n")
            seam_open.write_text("open\n")
            receiver, sender = socket.socketpair()
            receiver.settimeout(0.1)
            try:
                if frame is not None:
                    sender.sendall(frame)
                sender.close()
                wait_for_scrape_release(
                    receiver, state, seam_stop, seam_open, time.monotonic() + 1, 0
                )
            except ReceiptError:
                assert not seam_open.exists()
            else:
                raise AssertionError(f"{name}: queued failure lost to stop")
            finally:
                receiver.close()
                sender.close()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            command = [
                sys.executable, str(pathlib.Path(__file__).resolve()),
                "--listen", f"127.0.0.1:{port}", "--output-dir", str(output),
                "--start-file", str(start_file), "--stop-file", str(stop_file),
                "--total-prefixes", "2", "--timeout", "5",
            ]
            process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

            def wait_for_sink(path: pathlib.Path) -> None:
                deadline = time.monotonic() + 2
                while not path.is_file():
                    expired = time.monotonic() >= deadline
                    if process.poll() is not None or expired:
                        if process.poll() is None:
                            process.kill()
                        stdout, stderr = process.communicate(timeout=1)
                        raise AssertionError(
                            f"{name}: sink stopped before {path.name}: {stdout}{stderr}"
                        )
                    time.sleep(0.01)

            try:
                wait_for_sink(output / "listening")
                client = socket.create_connection(("127.0.0.1", port), timeout=1)
                start_file.write_text("start\n")
                frames = [init, sample_peer_up(peer_type=0), sample_peer_up(), sample_per_peer(1)]
                frames.append(sample_rm(sample_update(announced="20.0.0.0/24")))
                frames.append(sample_rm(sample_update(announced="20.0.1.0/24")))
                frames.extend(sample_rm(sample_update(eor=family)) for family in EXPECTED_EORS)
                frames.append(sample_rm(sample_update(announced="172.16.0.0/24")))
                client.sendall(b"".join(frames))
                wait_for_sink(output / "ready")
                assert (output / "generation-open").is_file()
                if frame is not None:
                    client.sendall(frame)
                else:
                    client.shutdown(socket.SHUT_RDWR)
                client.close()
                returncode = process.wait(timeout=2)
                assert returncode != 0, f"{name}: sink accepted the broken generation"
                assert not (output / "generation-open").exists()
                assert (output / "error.json").is_file()
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
        print(f"proof:{name}")

    prove_pre_scrape_disconnect("complete-fin-before-scrape", None)
    termination = bytes([3]) + struct.pack("!I", BMP_HEADER) + bytes([5])
    prove_pre_scrape_disconnect("termination-before-scrape", termination)

    def prove_stop_under_continuous_churn() -> None:
        churn_state = primed_state()
        churn_state.observe(sample_rm(sample_update(announced="20.0.0.0/24")))
        churn_state.observe(sample_rm(sample_update(announced="20.0.1.0/24")))
        for family in EXPECTED_EORS:
            churn_state.observe(sample_rm(sample_update(eor=family)))
        churn_state.observe(sample_rm(sample_update(announced="172.16.0.0/24")))
        assert churn_state.complete()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            stop = root / "stop"
            open_marker = root / "generation-open"
            open_marker.write_text("open\n")
            receiver, sender = socket.socketpair()
            receiver.settimeout(0.1)
            churn_frame = sample_rm(sample_update(withdrawn="172.16.0.0/24"))
            halt = threading.Event()

            def feed() -> None:
                # Saturate the socket: sendall blocks whenever the buffer
                # is full, so the receiver never observes an idle socket.
                while not halt.is_set():
                    try:
                        sender.sendall(churn_frame)
                    except OSError:
                        return

            feeder = threading.Thread(target=feed, daemon=True)
            feeder.start()
            try:
                time.sleep(0.2)
                stop.write_text("stop\n")
                started = time.monotonic()
                wait_for_scrape_release(
                    receiver, churn_state, stop, open_marker, time.monotonic() + 5, 0
                )
                elapsed = time.monotonic() - started
                assert elapsed < 1.0, f"stop-file starved under continuous churn: {elapsed:.2f}s"
            finally:
                halt.set()
                receiver.close()
                sender.close()
                feeder.join(timeout=1)
        print("proof:stop-under-continuous-churn")

    prove_stop_under_continuous_churn()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--listen", type=parse_listen, default=("127.0.0.1", 11019))
    parser.add_argument("--output-dir", type=pathlib.Path)
    parser.add_argument("--start-file", type=pathlib.Path)
    parser.add_argument("--stop-file", type=pathlib.Path)
    parser.add_argument("--total-prefixes", type=int, default=183040)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    for required in (args.output_dir, args.start_file, args.stop_file):
        if required is None:
            parser.error("--output-dir, --start-file, and --stop-file are required")
    if args.total_prefixes <= 0:
        parser.error("--total-prefixes must be positive")
    if not 1 <= args.timeout <= DEFAULT_TIMEOUT_SECONDS:
        parser.error("--timeout must be in 1..600")
    return run_sink(args)


if __name__ == "__main__":
    sys.exit(main())
