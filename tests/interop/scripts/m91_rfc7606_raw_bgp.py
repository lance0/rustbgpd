#!/usr/bin/env python3
"""Tiny BGP speaker for M91 RFC 7606 malformed-attribute injection.

Sends UPDATEs that a compliant peer will never emit, one per disposition
class, so the shell driver can assert rustbgpd's revised error handling
end to end:

  phase 2 (treat-as-withdraw): malformed MED (length 3) on an UPDATE
      re-announcing the accepted baseline — every carried route must be
      handled as withdrawn while the session stays Established;
  phase 3 (attribute-discard): malformed AGGREGATOR (length 5 under
      4-octet-AS) — the announcement must survive without the attribute;
  phase 4 (session-reset, RFC 7606 §5.2): malformed MED with no NLRI —
      rustbgpd must send NOTIFICATION 3/x and reset.

Each malformed phase waits for a trigger file the driver touches
(`/tmp/m91-phase{2,3,4}`), so the driver can assert state between
phases without racing the fixture.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import struct
import sys
import time


MARKER = b"\xff" * 16
TYPE_OPEN = 1
TYPE_UPDATE = 2
TYPE_NOTIFICATION = 3
TYPE_KEEPALIVE = 4
CAP_MULTIPROTOCOL = 1
CAP_FOUR_OCTET_AS = 65
ATTR_OPTIONAL = 0x80
ATTR_TRANSITIVE = 0x40
ATTR_ORIGIN = 1
ATTR_AS_PATH = 2
ATTR_NEXT_HOP = 3
ATTR_MED = 4
ATTR_AGGREGATOR = 7

LOCAL_AS = 65091
LOCAL_IP = "10.91.1.2"
BASELINE = "198.51.100.91/32"
TAW_EXTRA = "198.51.100.92/32"
DISCARD = "198.51.100.93/32"


def message(msg_type: int, body: bytes = b"") -> bytes:
    return MARKER + struct.pack("!HB", 19 + len(body), msg_type) + body


def capability(code: int, value: bytes) -> bytes:
    return bytes([code, len(value)]) + value


def open_message() -> bytes:
    caps = b"".join(
        [
            capability(CAP_MULTIPROTOCOL, struct.pack("!HBB", 1, 0, 1)),
            capability(CAP_FOUR_OCTET_AS, struct.pack("!I", LOCAL_AS)),
        ]
    )
    optional = bytes([2, len(caps)]) + caps
    body = struct.pack(
        "!BHHIB", 4, LOCAL_AS, 90, int(ipaddress.IPv4Address(LOCAL_IP)), len(optional)
    )
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
    return bytes([flags, code, len(value)]) + value


def base_attrs() -> list[bytes]:
    # AS_SEQUENCE, one four-octet ASN.
    as_path = bytes([2, 1]) + struct.pack("!I", LOCAL_AS)
    return [
        attr(ATTR_TRANSITIVE, ATTR_ORIGIN, b"\x00"),
        attr(ATTR_TRANSITIVE, ATTR_AS_PATH, as_path),
        attr(ATTR_TRANSITIVE, ATTR_NEXT_HOP, ipaddress.IPv4Address(LOCAL_IP).packed),
    ]


def send_update(
    sock: socket.socket,
    *,
    announced: bytes = b"",
    attrs_extra: list[bytes] | None = None,
) -> None:
    attrs = base_attrs()
    if attrs_extra:
        attrs.extend(attrs_extra)
    attr_bytes = b"".join(attrs)
    body = struct.pack("!H", 0) + struct.pack("!H", len(attr_bytes)) + attr_bytes + announced
    sock.sendall(message(TYPE_UPDATE, body))


def wait_trigger(sock: socket.socket, path: str) -> None:
    """Wait for the driver's trigger file, keeping the session alive."""
    last_keepalive = time.time()
    deadline = time.time() + 300
    while not os.path.exists(path):
        if time.time() > deadline:
            raise RuntimeError(f"trigger {path} never appeared")
        if time.time() - last_keepalive > 15:
            sock.sendall(message(TYPE_KEEPALIVE))
            last_keepalive = time.time()
        time.sleep(0.2)
    print(f"trigger {path} received", flush=True)


def main() -> int:
    listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(("0.0.0.0", 179))
    listen.listen(1)
    listen.settimeout(120)
    sock, _ = listen.accept()
    listen.close()
    with sock:
        sock.settimeout(30)
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
            elif msg_type == TYPE_NOTIFICATION:
                code = body[0] if body else 0
                subcode = body[1] if len(body) > 1 else 0
                raise RuntimeError(
                    f"rustbgpd rejected raw fixture OPEN with notification {code}/{subcode}"
                )
        if not saw_open:
            raise RuntimeError("did not receive rustbgpd OPEN")

        # Phase 1: clean baseline announcement.
        send_update(sock, announced=nlri(BASELINE))
        print("phase 1: baseline announced", flush=True)

        # Phase 2: malformed MED (length 3, must be 4) re-announcing the
        # baseline plus one more prefix — RFC 7606 treat-as-withdraw.
        wait_trigger(sock, "/tmp/m91-phase2")
        send_update(
            sock,
            announced=nlri(BASELINE) + nlri(TAW_EXTRA),
            attrs_extra=[attr(ATTR_OPTIONAL, ATTR_MED, b"\x00\x00\x01")],
        )
        print("phase 2: malformed MED sent (treat-as-withdraw)", flush=True)

        # Phase 3: malformed AGGREGATOR (length 5, must be 8 under
        # 4-octet-AS) — RFC 7606 §7.7 attribute-discard, the announcement
        # survives.
        wait_trigger(sock, "/tmp/m91-phase3")
        send_update(
            sock,
            announced=nlri(DISCARD),
            attrs_extra=[
                attr(
                    ATTR_OPTIONAL | ATTR_TRANSITIVE,
                    ATTR_AGGREGATOR,
                    b"\x00\x00\xfe\x53\x01",
                )
            ],
        )
        print("phase 3: malformed AGGREGATOR sent (attribute-discard)", flush=True)

        # Phase 4: malformed MED with NO reachable NLRI — RFC 7606 §5.2
        # escalates to session reset. Expect NOTIFICATION 3/x back.
        wait_trigger(sock, "/tmp/m91-phase4")
        send_update(
            sock,
            attrs_extra=[attr(ATTR_OPTIONAL, ATTR_MED, b"\x00\x00\x01")],
        )
        print("phase 4: malformed MED with no NLRI sent (session-reset)", flush=True)
        deadline = time.time() + 60
        while time.time() < deadline:
            msg_type, body = read_message(sock)
            if msg_type == TYPE_NOTIFICATION:
                code = body[0] if body else 0
                subcode = body[1] if len(body) > 1 else 0
                print(f"phase 4: received NOTIFICATION {code}/{subcode}", flush=True)
                if code != 3:
                    raise RuntimeError(f"expected UPDATE-error NOTIFICATION, got {code}/{subcode}")
                return 0
        raise RuntimeError("no NOTIFICATION after the §5.2 UPDATE")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # pragma: no cover - shell script captures stderr.
        print(f"m91 raw bgp fixture failed: {exc}", file=sys.stderr)
        raise
