#!/usr/bin/env python3
"""Verify this lab's IPv4 Loc-RIB snapshot from raw BMPv3 messages."""
import ipaddress
import json
import struct
import sys

PREFIX = "198.51.100.0/24"


def snapshot(messages):
    if not messages:
        raise ValueError("no BMP messages")
    connection = max(m["conn"] for m in messages)
    stream = [m for m in messages if m["conn"] == connection]
    peer_up = False
    prefixes = set()
    for sequence, message in enumerate(stream):
        raw = bytes.fromhex(message["hex"])
        if (message["seq"] != sequence or len(raw) < 6 or raw[0] != 3
                or struct.unpack_from("!I", raw, 1)[0] != len(raw)):
            raise ValueError("invalid BMP framing or sequence")
        kind = raw[5]
        if sequence == 0 and kind != 4:
            raise ValueError("stream does not start with Initiation")
        if kind == 5:
            raise ValueError("BMP Termination before snapshot completion")
        if kind not in (0, 2, 3):
            continue
        if len(raw) < 48:
            raise ValueError("truncated per-peer header")
        if raw[6] != 3:
            continue
        if kind == 2:
            raise ValueError("Loc-RIB PeerDown before snapshot completion")
        if kind == 3:
            if peer_up:
                raise ValueError("repeated Loc-RIB PeerUp before snapshot completion")
            peer_up = True
            continue
        if not peer_up:
            raise ValueError("Loc-RIB RouteMonitoring precedes PeerUp")
        update = raw[48:]
        if (len(update) < 23 or update[:16] != b"\xff" * 16 or update[18] != 2
                or struct.unpack_from("!H", update, 16)[0] != len(update)):
            raise ValueError("invalid BGP UPDATE framing")
        withdrawn = struct.unpack_from("!H", update, 19)[0]
        if 23 + withdrawn > len(update):
            raise ValueError("truncated withdrawals")
        attributes = struct.unpack_from("!H", update, 21 + withdrawn)[0]
        offset = 23 + withdrawn + attributes
        if offset > len(update):
            raise ValueError("truncated attributes")
        if len(update) == 23 and not withdrawn and not attributes:
            if PREFIX not in prefixes:
                raise ValueError(f"IPv4 End-of-RIB before {PREFIX} was replayed")
            return connection, prefixes
        if withdrawn:
            raise ValueError("withdrawal inside initial Loc-RIB snapshot")
        while offset < len(update):
            bits = update[offset]
            size = (bits + 7) // 8
            offset += 1
            if bits > 32 or offset + size > len(update):
                raise ValueError("invalid IPv4 NLRI")
            address = ipaddress.IPv4Address(update[offset:offset + size].ljust(4, b"\0"))
            prefixes.add(str(ipaddress.IPv4Network((address, bits), strict=True)))
            offset += size
    raise ValueError("no complete IPv4 Loc-RIB snapshot")


if __name__ == "__main__":
    try:
        connection, prefixes = snapshot([json.loads(line) for line in sys.stdin if line.strip()])
    except (ValueError, KeyError, TypeError, struct.error) as error:
        sys.exit(f"BMP verification failed: {error}")
    print(f"BMP connection {connection}: decoded {', '.join(sorted(prefixes))}, then IPv4 End-of-RIB.")
