#!/usr/bin/env python3
"""M116 wire oracle: judge receiver-bound IPv6 MP_REACH_NLRI next hops in a tshark PDML export.

Usage: m116_wire_oracle.py PDML RECEIVER PREFIX NEXT_HOP [RECEIVER PREFIX NEXT_HOP ...]

Each <proto name="bgp"> element is one BGP message. A path attribute's own
PDML `value` is empty, so its raw bytes are rebuilt from the hex `value` and
`pos` of the leaf fields under it; every byte must be covered. MP_REACH_NLRI is
then decoded from those bytes, not from tshark's interpretation, so a 4-octet
next hop under AFI 2 is judged as sent. Prints one
PASS/FAIL line per expectation: every UPDATE announcing PREFIX to RECEIVER
must carry a 16-octet NEXT_HOP global address, or 32 octets whose second half
is link-local. Then one line covering every receiver-bound IPv6 MP_REACH_NLRI
(16 or 32 octets only) and one for NOTIFICATIONs. A malformed PDML or attribute
raises and exits non-zero.
"""

from __future__ import annotations

import ipaddress
import sys
import xml.etree.ElementTree as ET

MP_REACH = 14
IPV6_UNICAST = (2, 1)


def fields(node: ET.Element, name: str) -> list[ET.Element]:
    return [f for f in node.iter("field") if f.get("name") == name]


def need(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def raw_bytes(node: ET.Element) -> bytes:
    """Rebuild a field's bytes from the hex values and positions of its leaves."""
    start, size = int(node.get("pos", "-1")), int(node.get("size", "0"))
    need(start >= 0 and size > 0, "path attribute without position in PDML")
    buf: list[int | None] = [None] * size
    for leaf in node.iter("field"):
        value, length = leaf.get("value") or "", int(leaf.get("size", "0"))
        # Bitmask children repeat their parent's position with a non-byte value.
        if not value or len(value) != 2 * length:
            continue
        offset = int(leaf.get("pos", "-1")) - start
        need(0 <= offset and offset + length <= size, "PDML leaf outside its attribute")
        for i, byte in enumerate(bytes.fromhex(value)):
            need(buf[offset + i] in (None, byte), "conflicting PDML leaf bytes")
            buf[offset + i] = byte
    need(None not in buf, "PDML leaves do not cover the path attribute")
    return bytes(b for b in buf if b is not None)


def attribute(raw: bytes) -> tuple[int, bytes]:
    """Split one path attribute (flags, type, length, value) into code and value."""
    need(len(raw) >= 3, "truncated attribute header")
    flags, code = raw[0], raw[1]
    if flags & 0x10:
        need(len(raw) >= 4, "truncated extended attribute length")
        length, value = int.from_bytes(raw[2:4], "big"), raw[4:]
    else:
        length, value = raw[2], raw[3:]
    need(len(value) == length, f"attribute {code} length {length} != {len(value)} value octets")
    return code, value


def mp_reach(value: bytes) -> tuple[tuple[int, int], bytes, list[str]]:
    """Decode MP_REACH_NLRI into (AFI, SAFI), the raw next hop and IPv6 prefixes."""
    need(len(value) >= 5, "truncated MP_REACH_NLRI")
    family = (int.from_bytes(value[:2], "big"), value[2])
    nh_len = value[3]
    need(len(value) >= 5 + nh_len, "truncated MP_REACH_NLRI next hop")
    next_hop = value[4 : 4 + nh_len]
    nlri = value[5 + nh_len :]
    prefixes: list[str] = []
    if family != IPV6_UNICAST:
        return family, next_hop, prefixes
    cursor = 0
    while cursor < len(nlri):
        bits = nlri[cursor]
        octets = (bits + 7) // 8
        need(bits <= 128 and cursor + 1 + octets <= len(nlri), "invalid IPv6 NLRI")
        packed = nlri[cursor + 1 : cursor + 1 + octets] + b"\x00" * (16 - octets)
        prefixes.append(str(ipaddress.IPv6Network((packed, bits), strict=False)))
        cursor += 1 + octets
    return family, next_hop, prefixes


def valid_ipv6_next_hop(next_hop: bytes) -> bool:
    """RFC 2545 §3: a 16-octet global address, or global plus link-local (32)."""
    if len(next_hop) not in (16, 32):
        return False
    glob = ipaddress.IPv6Address(next_hop[:16])
    if glob.is_unspecified or glob.is_link_local or glob.ipv4_mapped is not None:
        return False
    return len(next_hop) == 16 or ipaddress.IPv6Address(next_hop[16:]).is_link_local


def show(next_hop: bytes) -> str:
    if len(next_hop) == 4:
        return str(ipaddress.IPv4Address(next_hop))
    if len(next_hop) in (16, 32):
        return "+".join(
            str(ipaddress.IPv6Address(next_hop[i : i + 16])) for i in range(0, len(next_hop), 16)
        )
    return next_hop.hex()


def judge(root: ET.Element, expected: list[tuple[str, str, str]]) -> list[str]:
    receivers = {dst for dst, _, _ in expected}
    seen: dict[tuple[str, str], list[bytes]] = {(dst, prefix): [] for dst, prefix, _ in expected}
    invalid: list[str] = []
    notifications = 0
    for packet in root.iter("packet"):
        ip = next((p for p in packet.iter("proto") if p.get("name") == "ip"), None)
        if ip is None:
            continue
        dst = fields(ip, "ip.dst")[0].get("show")
        for bgp in (p for p in packet.iter("proto") if p.get("name") == "bgp"):
            kind = fields(bgp, "bgp.type")
            if not kind:
                continue
            if kind[0].get("show") == "3":
                notifications += 1
            if kind[0].get("show") != "2" or dst not in receivers:
                continue
            for attr in fields(bgp, "bgp.update.path_attribute"):
                code, value = attribute(raw_bytes(attr))
                if code != MP_REACH:
                    continue
                family, next_hop, prefixes = mp_reach(value)
                if family != IPV6_UNICAST:
                    continue
                if not valid_ipv6_next_hop(next_hop):
                    invalid.append(f"{dst} {len(next_hop)}-octet {show(next_hop)} for {prefixes}")
                for prefix in prefixes:
                    if (dst, prefix) in seen:
                        seen[(dst, prefix)].append(next_hop)

    lines = []
    for dst, prefix, want in expected:
        hops = seen[(dst, prefix)]
        good = bool(hops) and all(
            valid_ipv6_next_hop(h) and ipaddress.IPv6Address(h[:16]) == ipaddress.IPv6Address(want)
            for h in hops
        )
        detail = (
            f"to {dst} {prefix}: {len(hops)} MP_REACH UPDATE(s), next hops "
            f"{[f'{len(h)}-octet {show(h)}' for h in hops]}"
        )
        suffix = "" if good else f"; expected a 16- or 32-octet next hop {want} in each"
        lines.append(("PASS " if good else "FAIL ") + detail + suffix)
    lines.append(
        ("PASS " if not invalid else "FAIL ")
        + f"{len(invalid)} receiver-bound IPv6 MP_REACH_NLRI with an invalid next hop"
        + (f" ({'; '.join(invalid)})" if invalid else "")
    )
    lines.append(
        ("PASS " if notifications == 0 else "FAIL ")
        + f"{notifications} NOTIFICATION message(s) captured"
    )
    return lines


def main(argv: list[str]) -> int:
    if len(argv) < 4 or (len(argv) - 1) % 3:
        print(__doc__, file=sys.stderr)
        return 2
    path, *flat = argv
    expected = [(flat[i], flat[i + 1], flat[i + 2]) for i in range(0, len(flat), 3)]
    for line in judge(ET.parse(path).getroot(), expected):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
