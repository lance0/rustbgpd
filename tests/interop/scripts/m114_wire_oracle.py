#!/usr/bin/env python3
"""M114 wire oracle: judge receiver-bound UPDATEs in a tshark PDML export.

Usage: m114_wire_oracle.py PDML SOURCE RECEIVER PREFIX NEXT_HOP [RECEIVER PREFIX NEXT_HOP ...]

Each <proto name="bgp"> element is one BGP message. The lab is IPv4 unicast
only, so any MP_REACH_NLRI or MP_UNREACH_NLRI toward a receiver is a failure
in its own right; an announcement hidden there cannot slip past the body-NLRI
checks. Prints one PASS/FAIL line per expectation, then one for MP attributes
and one for NOTIFICATIONs (see notification_verdict; SOURCE is the source
peer's address). A malformed PDML raises and exits non-zero.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET

NEXT_HOP = "3"
MP_CODES = ("14", "15")
CEASE_COLLISION = (6, 7)


def fields(node: ET.Element, name: str) -> list[ET.Element]:
    return [f for f in node.iter("field") if f.get("name") == name]


def show(node: ET.Element | None, name: str) -> str | None:
    found = fields(node, name) if node is not None else []
    return found[0].get("show") if found else None


def notification_verdict(root: ET.Element, source: str) -> str:
    """One PASS/FAIL line covering every NOTIFICATION in the capture.

    The capture is armed before rustbgpd starts, so the source peer's connection
    can collide with rustbgpd's own. A Cease / Connection Collision Resolution
    (6/7) on a source connection that had not carried KEEPALIVE or UPDATE in both
    directions is that race: it is tolerated and listed. Any other NOTIFICATION
    fails: on a receiver session, with another code, on a source connection
    that had reached Established, or without a decodable session or code.
    """
    sent: dict[frozenset, set] = {}
    tolerated: list[str] = []
    failed: list[str] = []
    for packet in root.iter("packet"):
        protos = {p.get("name"): p for p in reversed(list(packet.iter("proto")))}
        ip, tcp = protos.get("ip"), protos.get("tcp")
        src = (show(ip, "ip.src"), show(tcp, "tcp.srcport"))
        dst = (show(ip, "ip.dst"), show(tcp, "tcp.dstport"))
        senders = sent.setdefault(frozenset((src, dst)), set())
        for bgp in (p for p in packet.iter("proto") if p.get("name") == "bgp"):
            kind = show(bgp, "bgp.type")
            if kind in ("2", "4"):
                senders.add(src)
            if kind != "3":
                continue
            major = show(bgp, "bgp.notify.major_error")
            minor = next(
                (
                    f.get("show")
                    for f in bgp.iter("field")
                    if (f.get("name") or "").startswith("bgp.notify.minor_error")
                    and (f.get("show") or "").isdigit()
                ),
                None,
            )
            established = len(senders) == 2
            text = (
                f"{src[0]}:{src[1]} -> {dst[0]}:{dst[1]} code {major}/{minor} "
                + ("after" if established else "before")
                + " Established"
            )
            collision = (major, minor) == tuple(str(c) for c in CEASE_COLLISION)
            benign = source in (src[0], dst[0]) and None not in src + dst
            (tolerated if benign and collision and not established else failed).append(text)
    return (
        ("PASS " if not failed else "FAIL ")
        + f"{len(tolerated) + len(failed)} NOTIFICATION message(s) captured"
        + (f"; not tolerated: {failed}" if failed else "")
        + (f"; tolerated source collision resolution: {tolerated}" if tolerated else "")
    )


def judge(root: ET.Element, source: str, expected: list[tuple[str, str, str]]) -> list[str]:
    receivers = {dst for dst, _, _ in expected}
    seen: dict[tuple[str, str], list[tuple[int, list[str]]]] = {
        (dst, prefix): [] for dst, prefix, _ in expected
    }
    mp_updates: list[str] = []
    for packet in root.iter("packet"):
        ip = next((p for p in packet.iter("proto") if p.get("name") == "ip"), None)
        if ip is None:
            continue
        dst = fields(ip, "ip.dst")[0].get("show")
        for bgp in (p for p in packet.iter("proto") if p.get("name") == "bgp"):
            kind = fields(bgp, "bgp.type")
            if not kind:
                continue
            if kind[0].get("show") != "2" or dst not in receivers:
                continue
            codes = [f.get("show") for f in fields(bgp, "bgp.update.path_attribute.type_code")]
            if any(code in MP_CODES for code in codes):
                mp_updates.append(dst)
            prefixes = {
                f"{p.get('show')}/{n.get('show')}"
                for nlri in fields(bgp, "bgp.update.nlri")
                for p, n in zip(fields(nlri, "bgp.nlri_prefix"), fields(nlri, "bgp.prefix_length"))
            }
            next_hops = [f.get("show") for f in fields(bgp, "bgp.update.path_attribute.next_hop")]
            for key, updates in seen.items():
                if key[0] == dst and key[1] in prefixes:
                    updates.append((codes.count(NEXT_HOP), next_hops))

    lines = []
    for dst, prefix, next_hop in expected:
        updates = seen[(dst, prefix)]
        detail = (
            f"to {dst} {prefix}: {len(updates)} UPDATE(s), NEXT_HOP counts "
            f"{[u[0] for u in updates]}, next hops {sorted({h for u in updates for h in u[1]})}"
        )
        good = bool(updates) and all(u[0] == 1 and u[1] == [next_hop] for u in updates)
        suffix = "" if good else f"; expected one NEXT_HOP {next_hop} per UPDATE"
        lines.append(("PASS " if good else "FAIL ") + detail + suffix)
    lines.append(
        ("PASS " if not mp_updates else "FAIL ")
        + f"{len(mp_updates)} receiver-bound UPDATE(s) carry MP_REACH_NLRI or MP_UNREACH_NLRI"
        + (f" (to {sorted(set(mp_updates))})" if mp_updates else "")
    )
    lines.append(notification_verdict(root, source))
    return lines


def main(argv: list[str]) -> int:
    if len(argv) < 5 or (len(argv) - 2) % 3:
        print(__doc__, file=sys.stderr)
        return 2
    path, source, *flat = argv
    expected = [(flat[i], flat[i + 1], flat[i + 2]) for i in range(0, len(flat), 3)]
    for line in judge(ET.parse(path).getroot(), source, expected):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
