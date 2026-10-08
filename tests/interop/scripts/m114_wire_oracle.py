#!/usr/bin/env python3
"""M114 wire oracle: judge receiver-bound UPDATEs in a tshark PDML export.

Usage: m114_wire_oracle.py PDML RECEIVER PREFIX NEXT_HOP [RECEIVER PREFIX NEXT_HOP ...]

Each <proto name="bgp"> element is one BGP message. The lab is IPv4 unicast
only, so any MP_REACH_NLRI or MP_UNREACH_NLRI toward a receiver is a failure
in its own right; an announcement hidden there cannot slip past the body-NLRI
checks. Prints one PASS/FAIL line per expectation, then one for MP attributes
and one for NOTIFICATIONs, each decoded. A malformed PDML raises and exits
non-zero.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET

NEXT_HOP = "3"
MP_CODES = ("14", "15")


def fields(node: ET.Element, name: str) -> list[ET.Element]:
    return [f for f in node.iter("field") if f.get("name") == name]


def show(node: ET.Element | None, name: str) -> str | None:
    found = fields(node, name) if node is not None else []
    return found[0].get("show") if found else None


def notification_verdict(root: ET.Element) -> str:
    """One PASS/FAIL line covering every NOTIFICATION in the capture.

    Any NOTIFICATION fails. Each is listed with its TCP connection, direction,
    code/subcode, and whether its connection had reached Established (KEEPALIVE
    or UPDATE seen in both directions), so a failure says what was sent.
    """
    sent: dict[frozenset, set] = {}
    found: list[str] = []
    for packet in root.iter("packet"):
        protos = {p.get("name"): p for p in reversed(list(packet.iter("proto")))}
        ip, tcp = protos.get("ip"), protos.get("tcp")
        src = f"{show(ip, 'ip.src') or '?'}:{show(tcp, 'tcp.srcport') or '?'}"
        dst = f"{show(ip, 'ip.dst') or '?'}:{show(tcp, 'tcp.dstport') or '?'}"
        senders = sent.setdefault(frozenset((src, dst)), set())
        for bgp in (p for p in packet.iter("proto") if p.get("name") == "bgp"):
            kind = show(bgp, "bgp.type")
            if kind in ("2", "4"):
                senders.add(src)
            if kind != "3":
                continue
            major = show(bgp, "bgp.notify.major_error") or "?"
            minor = next(
                (
                    f.get("show")
                    for f in bgp.iter("field")
                    if (f.get("name") or "").startswith("bgp.notify.minor_error")
                    and (f.get("show") or "").isdigit()
                ),
                "?",
            )
            when = "after" if len(senders) == 2 else "before"
            found.append(f"{src} -> {dst} code {major}/{minor} {when} Established")
    return (
        ("PASS " if not found else "FAIL ")
        + f"{len(found)} NOTIFICATION message(s) captured"
        + (f": {found}" if found else "")
    )


def judge(root: ET.Element, expected: list[tuple[str, str, str]]) -> list[str]:
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
    lines.append(notification_verdict(root))
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
