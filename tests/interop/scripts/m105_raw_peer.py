#!/usr/bin/env python3
"""One raw route-server client feeding the five M105 receivers."""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


MARKER = b"\xff" * 16
TYPE_OPEN = 1
TYPE_UPDATE = 2
TYPE_NOTIFICATION = 3
TYPE_KEEPALIVE = 4
CAP_MULTIPROTOCOL = 1
CAP_BGP_ROLE = 9
CAP_FOUR_OCTET_AS = 65
ROLE_ROUTE_SERVER = 1
ROLE_ROUTE_SERVER_CLIENT = 2
ATTR_OPTIONAL = 0x80
ATTR_TRANSITIVE = 0x40
ATTR_ORIGIN = 1
ATTR_AS_PATH = 2
ATTR_NEXT_HOP = 3
ATTR_COMMUNITIES = 8
ATTR_LARGE_COMMUNITIES = 32
LOCAL_AS = 64512
RAW_ADDR = "10.105.0.10"
BASELINE_PREFIX = "198.51.104.0/24"
AS_SET_PREFIX = "198.51.105.0/24"
EVENTS = Path("/tmp/m105-events.jsonl")
READY = Path("/tmp/m105-ready")
TRIGGERS = (
    (Path("/tmp/m105-send-baseline"), "baseline"),
    (Path("/tmp/m105-send-as-set"), "as_set"),
    (Path("/tmp/m105-send-withdraw"), "withdraw"),
)
STOP = Path("/tmp/m105-stop")
EXPECTED = {
    "10.105.0.1": ("rustbgpd", 65001),
    "10.105.0.2": ("bird", 65002),
    "10.105.0.3": ("openbgpd", 65003),
    "10.105.0.4": ("gobgp", 65004),
    "10.105.0.5": ("frr", 65005),
}

event_lock = threading.Lock()
sessions_lock = threading.Lock()
sessions: dict[str, "Session"] = {}
worker_errors: list[str] = []


def emit(peer: str, event: str, **fields: Any) -> None:
    row = {"peer": peer, "event": event, **fields}
    with event_lock:
        with EVENTS.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")


def message(message_type: int, body: bytes = b"") -> bytes:
    return MARKER + struct.pack("!HB", 19 + len(body), message_type) + body


def capability(code: int, value: bytes) -> bytes:
    return bytes([code, len(value)]) + value


def open_message() -> bytes:
    capabilities = b"".join(
        (
            capability(CAP_MULTIPROTOCOL, struct.pack("!HBB", 1, 0, 1)),
            capability(CAP_FOUR_OCTET_AS, struct.pack("!I", LOCAL_AS)),
            capability(CAP_BGP_ROLE, bytes([ROLE_ROUTE_SERVER_CLIENT])),
        )
    )
    optional = bytes([2, len(capabilities)]) + capabilities
    body = struct.pack(
        "!BHHIB",
        4,
        LOCAL_AS,
        90,
        int(ipaddress.IPv4Address(RAW_ADDR)),
        len(optional),
    )
    return message(TYPE_OPEN, body + optional)


def recvn(stream: socket.socket, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        chunk = stream.recv(count - len(data))
        if not chunk:
            raise EOFError("peer closed the TCP stream")
        data.extend(chunk)
    return bytes(data)


def read_message(stream: socket.socket) -> tuple[int, bytes]:
    header = recvn(stream, 19)
    if header[:16] != MARKER:
        raise RuntimeError("BGP marker mismatch")
    length, message_type = struct.unpack("!HB", header[16:19])
    if not 19 <= length <= 4096:
        raise RuntimeError(f"invalid BGP message length {length}")
    return message_type, recvn(stream, length - 19)


def parse_capabilities(body: bytes, expected_as: int) -> int | None:
    if len(body) < 10 or body[0] != 4:
        raise RuntimeError("invalid receiver OPEN")
    header_as = int.from_bytes(body[1:3], "big")
    if header_as != expected_as:
        raise RuntimeError(f"receiver OPEN AS {header_as}, expected {expected_as}")
    optional_length = body[9]
    optional = body[10 : 10 + optional_length]
    if len(optional) != optional_length:
        raise RuntimeError("truncated receiver OPEN parameters")
    capabilities: dict[int, list[bytes]] = {}
    cursor = 0
    while cursor < len(optional):
        if cursor + 2 > len(optional) or optional[cursor] != 2:
            raise RuntimeError("unexpected receiver OPEN parameter")
        length = optional[cursor + 1]
        value = optional[cursor + 2 : cursor + 2 + length]
        if len(value) != length:
            raise RuntimeError("truncated receiver capability parameter")
        cursor += 2 + length
        cap_cursor = 0
        while cap_cursor < len(value):
            if cap_cursor + 2 > len(value):
                raise RuntimeError("truncated receiver capability")
            code = value[cap_cursor]
            cap_length = value[cap_cursor + 1]
            cap_value = value[cap_cursor + 2 : cap_cursor + 2 + cap_length]
            if len(cap_value) != cap_length:
                raise RuntimeError("truncated receiver capability value")
            capabilities.setdefault(code, []).append(cap_value)
            cap_cursor += 2 + cap_length
    four_as = capabilities.get(CAP_FOUR_OCTET_AS, [])
    if four_as != [expected_as.to_bytes(4, "big")]:
        raise RuntimeError("receiver four-octet-AS capability mismatch")
    if struct.pack("!HBB", 1, 0, 1) not in capabilities.get(CAP_MULTIPROTOCOL, []):
        raise RuntimeError("receiver did not advertise IPv4 unicast")
    roles = capabilities.get(CAP_BGP_ROLE, [])
    if roles and roles != [bytes([ROLE_ROUTE_SERVER])]:
        raise RuntimeError(f"receiver advertised incompatible BGP Role {roles!r}")
    return roles[0][0] if roles else None


def nlri(prefix: str) -> bytes:
    network = ipaddress.IPv4Network(prefix)
    octets = (network.prefixlen + 7) // 8
    return bytes([network.prefixlen]) + network.network_address.packed[:octets]


def attribute(flags: int, code: int, value: bytes) -> bytes:
    if len(value) > 255:
        raise ValueError("M105 attributes use one-octet lengths")
    return bytes([flags, code, len(value)]) + value


def common_attributes(as_path: bytes) -> bytes:
    standard = struct.pack("!HH", LOCAL_AS, 105)
    large = struct.pack("!III", LOCAL_AS, 105, 1)
    return b"".join(
        (
            attribute(ATTR_TRANSITIVE, ATTR_ORIGIN, b"\x00"),
            attribute(ATTR_TRANSITIVE, ATTR_AS_PATH, as_path),
            attribute(
                ATTR_TRANSITIVE,
                ATTR_NEXT_HOP,
                ipaddress.IPv4Address(RAW_ADDR).packed,
            ),
            attribute(ATTR_OPTIONAL | ATTR_TRANSITIVE, ATTR_COMMUNITIES, standard),
            attribute(
                ATTR_OPTIONAL | ATTR_TRANSITIVE,
                ATTR_LARGE_COMMUNITIES,
                large,
            ),
        )
    )


def update(announced: str, as_path: bytes) -> bytes:
    attributes = common_attributes(as_path)
    body = b"\x00\x00" + len(attributes).to_bytes(2, "big") + attributes
    return message(TYPE_UPDATE, body + nlri(announced))


def withdrawal() -> bytes:
    withdrawn = nlri(BASELINE_PREFIX) + nlri(AS_SET_PREFIX)
    return message(TYPE_UPDATE, len(withdrawn).to_bytes(2, "big") + withdrawn + b"\x00\x00")


def reverse_update_has_prefix(body: bytes) -> bool:
    if len(body) < 4:
        return True
    withdrawn_length = int.from_bytes(body[:2], "big")
    cursor = 2 + withdrawn_length
    if cursor + 2 > len(body):
        return True
    attributes_length = int.from_bytes(body[cursor : cursor + 2], "big")
    attributes = body[cursor + 2 : cursor + 2 + attributes_length]
    announced = body[cursor + 2 + attributes_length :]
    if withdrawn_length or announced:
        return True
    cursor = 0
    while cursor < len(attributes):
        if cursor + 3 > len(attributes):
            return True
        flags = attributes[cursor]
        code = attributes[cursor + 1]
        cursor += 2
        if flags & 0x10:
            if cursor + 2 > len(attributes):
                return True
            length = int.from_bytes(attributes[cursor : cursor + 2], "big")
            cursor += 2
        else:
            length = attributes[cursor]
            cursor += 1
        value = attributes[cursor : cursor + length]
        if len(value) != length:
            return True
        cursor += length
        if code == 14 and len(value) > 5:
            next_hop_length = value[3]
            nlri_cursor = 4 + next_hop_length
            if nlri_cursor < len(value):
                nlri_cursor += 1
            if nlri_cursor < len(value):
                return True
    return False


@dataclass
class Session:
    peer: str
    stream: socket.socket
    lock: threading.Lock = field(default_factory=threading.Lock)
    alive: bool = True

    def send(self, payload: bytes) -> None:
        with self.lock:
            self.stream.sendall(payload)


def serve_connection(stream: socket.socket, remote: str) -> None:
    peer, expected_as = EXPECTED[remote]
    try:
        stream.settimeout(1)
        stream.sendall(open_message())
        saw_open = False
        saw_keepalive = False
        sent_keepalive = False
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not (saw_open and saw_keepalive):
            try:
                message_type, body = read_message(stream)
            except TimeoutError:
                continue
            if message_type == TYPE_OPEN:
                role = parse_capabilities(body, expected_as)
                emit(peer, "open", remote_as=expected_as, role=role)
                saw_open = True
                if not sent_keepalive:
                    stream.sendall(message(TYPE_KEEPALIVE))
                    sent_keepalive = True
            elif message_type == TYPE_KEEPALIVE:
                saw_keepalive = True
            elif message_type == TYPE_NOTIFICATION:
                emit(
                    peer,
                    "notification",
                    code=body[0] if body else None,
                    subcode=body[1] if len(body) > 1 else None,
                )
                raise RuntimeError("receiver sent a notification during handshake")
        if not (saw_open and saw_keepalive):
            raise RuntimeError("receiver handshake did not complete")
        session = Session(peer=peer, stream=stream)
        with sessions_lock:
            sessions[peer] = session
        emit(peer, "established", remote=remote)

        while not STOP.exists():
            try:
                message_type, body = read_message(stream)
            except TimeoutError:
                continue
            if message_type == TYPE_NOTIFICATION:
                emit(
                    peer,
                    "notification",
                    code=body[0] if body else None,
                    subcode=body[1] if len(body) > 1 else None,
                )
            elif message_type == TYPE_UPDATE:
                emit(
                    peer,
                    "reverse_update",
                    prefix_bearing=reverse_update_has_prefix(body),
                    length=len(body),
                )
    except EOFError:
        emit(peer, "closed")
    except Exception as error:  # noqa: BLE001 - errors become fixture evidence.
        emit(peer, "reader_error", detail=str(error))
        with sessions_lock:
            worker_errors.append(f"{peer}: {error}")
    finally:
        with sessions_lock:
            if peer in sessions:
                sessions[peer].alive = False
        try:
            stream.close()
        except OSError:
            pass


def snapshot_sessions() -> list[Session]:
    with sessions_lock:
        return [sessions[name] for name in sorted(sessions)]


def send_phase(phase: str) -> None:
    if phase == "baseline":
        payload = update(BASELINE_PREFIX, b"\x02\x01" + struct.pack("!I", LOCAL_AS))
    elif phase == "as_set":
        payload = update(
            AS_SET_PREFIX,
            b"\x01\x02" + struct.pack("!II", LOCAL_AS, LOCAL_AS + 1),
        )
    elif phase == "withdraw":
        payload = withdrawal()
    else:
        raise ValueError(f"unknown phase {phase}")
    current = snapshot_sessions()
    if len(current) != len(EXPECTED) or not all(item.alive for item in current):
        raise RuntimeError(f"cannot send {phase}: receiver set is not fully live")
    for session in current:
        session.send(payload)
        emit(session.peer, "send", phase=phase, bytes=len(payload))


def wait_for_trigger(path: Path, phase: str) -> None:
    next_keepalive = time.monotonic()
    while not path.exists():
        if STOP.exists():
            raise RuntimeError(f"stopped before {phase} trigger")
        if time.monotonic() >= next_keepalive:
            for session in snapshot_sessions():
                if session.alive:
                    session.send(message(TYPE_KEEPALIVE))
            next_keepalive = time.monotonic() + 15
        time.sleep(0.1)
    send_phase(phase)


def main() -> int:
    for path in (EVENTS, READY, STOP, *(item[0] for item in TRIGGERS)):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", 179))
    listener.listen(len(EXPECTED))
    listener.settimeout(0.5)
    emit("fixture", "listening", address=RAW_ADDR, receivers=len(EXPECTED))
    threads: list[threading.Thread] = []
    deadline = time.monotonic() + 120
    try:
        while time.monotonic() < deadline:
            with sessions_lock:
                if len(sessions) == len(EXPECTED):
                    break
            try:
                stream, address = listener.accept()
            except TimeoutError:
                continue
            remote = address[0]
            if remote not in EXPECTED:
                stream.close()
                emit("fixture", "unexpected_connection", remote=remote)
                continue
            thread = threading.Thread(
                target=serve_connection,
                args=(stream, remote),
                name=f"m105-{EXPECTED[remote][0]}",
                daemon=True,
            )
            thread.start()
            threads.append(thread)
        with sessions_lock:
            connected = sorted(sessions)
        if connected != sorted(peer for peer, _ in EXPECTED.values()):
            raise RuntimeError(f"receiver set incomplete: {connected}")
        READY.write_text("ready\n", encoding="utf-8")
        emit("fixture", "ready", peers=connected)
        for path, phase in TRIGGERS:
            wait_for_trigger(path, phase)
        while not STOP.exists():
            for session in snapshot_sessions():
                if session.alive:
                    session.send(message(TYPE_KEEPALIVE))
            time.sleep(5)
        with sessions_lock:
            errors = list(worker_errors)
        if errors:
            raise RuntimeError("; ".join(errors))
        emit("fixture", "stopped")
        return 0
    finally:
        listener.close()
        for session in snapshot_sessions():
            try:
                session.stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            session.stream.close()
        for thread in threads:
            thread.join(timeout=2)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:  # noqa: BLE001 - stderr is retained as evidence.
        emit("fixture", "fatal", detail=str(error))
        print(f"M105 raw peer failed: {error}", file=os.sys.stderr)
        raise
