#!/usr/bin/env python3
"""Tiny BGP speaker for M55 RFC 9234 negative cases.

The fixture intentionally sends UPDATEs that compliant FRR will not naturally
emit: a Customer-role route carrying OTC, and a malformed-length OTC attribute.
It keeps the TCP session alive long enough for the shell driver to assert that
rustbgpd drops only the announcements and leaves the session Established.
"""

from __future__ import annotations

import ipaddress
import socket
import struct
import sys
import time


MARKER = b"\xff" * 16
TYPE_OPEN = 1
TYPE_UPDATE = 2
TYPE_KEEPALIVE = 4
CAP_MULTIPROTOCOL = 1
CAP_FOUR_OCTET_AS = 65
CAP_BGP_ROLE = 9
ROLE_CUSTOMER = 3
ATTR_OPTIONAL = 0x80
ATTR_TRANSITIVE = 0x40
ATTR_ORIGIN = 1
ATTR_AS_PATH = 2
ATTR_NEXT_HOP = 3
ATTR_OTC = 35


def message(msg_type: int, body: bytes = b"") -> bytes:
    return MARKER + struct.pack("!HB", 19 + len(body), msg_type) + body


def capability(code: int, value: bytes) -> bytes:
    return bytes([code, len(value)]) + value


def optional_capabilities(caps: bytes) -> bytes:
    return bytes([2, len(caps)]) + caps


def open_message() -> bytes:
    caps = b"".join(
        [
            capability(CAP_MULTIPROTOCOL, struct.pack("!HBB", 1, 0, 1)),
            capability(CAP_FOUR_OCTET_AS, struct.pack("!I", 65007)),
            capability(CAP_BGP_ROLE, bytes([ROLE_CUSTOMER])),
        ]
    )
    optional = optional_capabilities(caps)
    body = struct.pack("!BHHIB", 4, 65007, 90, int(ipaddress.IPv4Address("10.55.6.2")), len(optional))
    body += optional
    return message(TYPE_OPEN, body)


def recvn(sock: socket.socket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise RuntimeError("short read from rustbgpd")
        data += chunk
    return data


def read_message(sock: socket.socket) -> tuple[int, bytes]:
    header = recvn(sock, 19)
    if header[:16] != MARKER:
        raise RuntimeError("bad marker from rustbgpd")
    length, msg_type = struct.unpack("!HB", header[16:19])
    return msg_type, recvn(sock, length - 19)


def nlri(prefix: str) -> bytes:
    net = ipaddress.IPv4Network(prefix)
    octets = (net.prefixlen + 7) // 8
    return bytes([net.prefixlen]) + net.network_address.packed[:octets]


def attr(flags: int, code: int, value: bytes) -> bytes:
    if len(value) > 255:
        raise ValueError("extended attributes are not needed in M55")
    return bytes([flags, code, len(value)]) + value


def path_attrs(*attrs: bytes) -> bytes:
    body = b"".join(attrs)
    return struct.pack("!H", len(body)) + body


def as_path(asn: int) -> bytes:
    # AS_SEQUENCE, one four-octet ASN.
    return bytes([2, 1]) + struct.pack("!I", asn)


def update(withdrawn: bytes, attrs: bytes, announced: bytes) -> bytes:
    body = struct.pack("!H", len(withdrawn)) + withdrawn + attrs + announced
    return message(TYPE_UPDATE, body)


def base_attrs() -> list[bytes]:
    return [
        attr(ATTR_TRANSITIVE, ATTR_ORIGIN, b"\x00"),
        attr(ATTR_TRANSITIVE, ATTR_AS_PATH, as_path(65007)),
        attr(ATTR_TRANSITIVE, ATTR_NEXT_HOP, ipaddress.IPv4Address("10.55.6.2").packed),
    ]


def send_update(sock: socket.socket, *, withdrawn: bytes = b"", announced: bytes = b"", attrs_extra: list[bytes] | None = None) -> None:
    attrs = base_attrs()
    if attrs_extra:
        attrs.extend(attrs_extra)
    sock.sendall(update(withdrawn, path_attrs(*attrs), announced))


def main() -> int:
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(("0.0.0.0", 179))
    listen.listen(1)
    listen.settimeout(120)
    sock, _ = listen.accept()
    listen.close()
    with sock:
        sock.settimeout(10)
        sock.sendall(open_message())

        saw_open = False
        saw_keepalive = False
        deadline = time.time() + 10
        while time.time() < deadline and not (saw_open and saw_keepalive):
            msg_type, body = read_message(sock)
            if msg_type == TYPE_OPEN:
                saw_open = True
                sock.sendall(message(TYPE_KEEPALIVE))
            elif msg_type == TYPE_KEEPALIVE:
                saw_keepalive = True
            elif msg_type == 3:
                code = body[0] if body else 0
                subcode = body[1] if len(body) > 1 else 0
                raise RuntimeError(f"rustbgpd rejected raw fixture OPEN with notification {code}/{subcode}")

        if not saw_open:
            raise RuntimeError("did not receive rustbgpd OPEN")

        # Accepted baseline route; later withdrawn in the malformed-OTC UPDATE
        # to prove withdrawals still apply when announcements are treated as
        # withdraw.
        send_update(sock, announced=nlri("198.51.100.57/32"))
        time.sleep(1)

        # Customer-role peer sending OTC is a semantic RFC 9234 I1 leak.
        send_update(
            sock,
            announced=nlri("198.51.100.55/32"),
            attrs_extra=[attr(ATTR_OPTIONAL | ATTR_TRANSITIVE, ATTR_OTC, struct.pack("!I", 65001))],
        )
        time.sleep(1)

        # Malformed OTC length: the announced prefix must be dropped, but the
        # withdrawal of the previously accepted baseline route must survive.
        send_update(
            sock,
            withdrawn=nlri("198.51.100.57/32"),
            announced=nlri("198.51.100.56/32"),
            attrs_extra=[attr(ATTR_OPTIONAL | ATTR_TRANSITIVE, ATTR_OTC, b"\x00\xfd\xe9")],
        )

        end = time.time() + 90
        while time.time() < end:
            sock.sendall(message(TYPE_KEEPALIVE))
            time.sleep(15)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # pragma: no cover - shell script captures stderr.
        print(f"m55 raw bgp fixture failed: {exc}", file=sys.stderr)
        raise
