#!/usr/bin/env python3
"""M115 wire oracle: judge conditional advertisement in a tshark PDML export.

Usage: m115_wire_oracle.py PDML SOURCE RECEIVER NEXT_HOP CONDITION PAYLOAD CONTROL SETTLE

The capture runs in rustbgpd's network namespace, so it holds both the
source's UPDATEs and the receiver-bound ones. Each <proto name="bgp"> element
is one BGP message; within a message, withdrawals come before announcements.
Prints one PASS/FAIL line for each of:

1. the receiver-bound event order for CONDITION and PAYLOAD is exactly
   announce CONDITION, withdraw CONDITION, announce PAYLOAD,
   announce CONDITION, withdraw PAYLOAD;
2. CONTROL is announced to the receiver exactly once and never withdrawn;
3. every receiver-bound announcement carries exactly one NEXT_HOP, NEXT_HOP;
4. PAYLOAD is announced at least SETTLE seconds after the source withdrew
   CONDITION, and withdrawn at least SETTLE seconds after the source
   re-announced it;
5. no receiver-bound UPDATE carries MP_REACH_NLRI or MP_UNREACH_NLRI;
6. no NOTIFICATION was captured.

A malformed PDML raises and exits non-zero.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET

from m114_wire_oracle import MP_CODES, NEXT_HOP, fields


def prefixes(node: ET.Element, container: str, address: str) -> list[str]:
    return [
        f"{p.get('show')}/{n.get('show')}"
        for block in fields(node, container)
        for p, n in zip(fields(block, address), fields(block, "bgp.prefix_length"))
    ]


def events(root: ET.Element) -> tuple[list[tuple], list[str], int]:
    """Route events (time, src, dst, kind, prefix, NEXT_HOP count, next hops),
    the destination of each UPDATE carrying an MP attribute, and the
    NOTIFICATION count."""
    out: list[tuple] = []
    mp_dsts: list[str] = []
    notifications = 0
    for packet in root.iter("packet"):
        ip = next((p for p in packet.iter("proto") if p.get("name") == "ip"), None)
        if ip is None:
            continue
        frame = next(p for p in packet.iter("proto") if p.get("name") == "frame")
        when = float(fields(frame, "frame.time_epoch")[0].get("show"))
        src = fields(ip, "ip.src")[0].get("show")
        dst = fields(ip, "ip.dst")[0].get("show")
        for bgp in (p for p in packet.iter("proto") if p.get("name") == "bgp"):
            kind = fields(bgp, "bgp.type")
            if not kind:
                continue
            if kind[0].get("show") == "3":
                notifications += 1
            if kind[0].get("show") != "2":
                continue
            codes = [f.get("show") for f in fields(bgp, "bgp.update.path_attribute.type_code")]
            if any(code in MP_CODES for code in codes):
                mp_dsts.append(dst)
            hops = [f.get("show") for f in fields(bgp, "bgp.update.path_attribute.next_hop")]
            for prefix in prefixes(bgp, "bgp.update.withdrawn_routes", "bgp.withdrawn_prefix"):
                out.append((when, src, dst, "withdraw", prefix, 0, []))
            for prefix in prefixes(bgp, "bgp.update.nlri", "bgp.nlri_prefix"):
                out.append((when, src, dst, "announce", prefix, codes.count(NEXT_HOP), hops))
    return out, mp_dsts, notifications


def verdict(good: bool, message: str) -> str:
    return ("PASS " if good else "FAIL ") + message


def judge(
    root: ET.Element,
    source: str,
    receiver: str,
    next_hop: str,
    condition: str,
    payload: str,
    control: str,
    settle: float,
) -> list[str]:
    all_events, mp_dsts, notifications = events(root)
    to_rx = [e for e in all_events if e[2] == receiver]
    lines = []

    order = [(e[3], e[4]) for e in to_rx if e[4] in (condition, payload)]
    want = [
        ("announce", condition),
        ("withdraw", condition),
        ("announce", payload),
        ("announce", condition),
        ("withdraw", payload),
    ]
    lines.append(
        verdict(order == want, f"to {receiver} condition/payload events {order}, expected {want}")
    )

    control_events = [e[3] for e in to_rx if e[4] == control]
    lines.append(
        verdict(
            control_events == ["announce"],
            f"to {receiver} control {control} events {control_events}",
        )
    )

    announced = [e for e in to_rx if e[3] == "announce"]
    bad = [(e[4], e[5], e[6]) for e in announced if e[5] != 1 or e[6] != [next_hop]]
    lines.append(
        verdict(
            bool(announced) and not bad,
            f"{len(announced)} announcement(s) to {receiver} carry one NEXT_HOP {next_hop}"
            + (f"; offending (prefix, count, hops) {bad}" if bad else ""),
        )
    )

    from_src = [e for e in all_events if e[1] == source and e[4] == condition]

    def gap(kind: str, trigger: str) -> float | None:
        """Seconds from the last source CONDITION `trigger` to the first receiver PAYLOAD `kind`."""
        target = next((e for e in to_rx if e[3] == kind and e[4] == payload), None)
        if target is None:
            return None
        before = [e for e in from_src if e[3] == trigger and e[0] <= target[0]]
        return target[0] - before[-1][0] if before else None

    for kind, trigger in (("announce", "withdraw"), ("withdraw", "announce")):
        delay = gap(kind, trigger)
        lines.append(
            verdict(
                delay is not None and delay >= settle,
                f"payload {kind} to {receiver} followed the source's condition {trigger} by "
                + (f"{delay:.3f}s" if delay is not None else "no matching pair")
                + f" (settle_time {settle:g}s)",
            )
        )

    mp = mp_dsts.count(receiver)
    lines.append(
        verdict(not mp, f"{mp} receiver-bound UPDATE(s) carry MP_REACH_NLRI or MP_UNREACH_NLRI")
    )
    lines.append(verdict(notifications == 0, f"{notifications} NOTIFICATION message(s) captured"))
    return lines


def main(argv: list[str]) -> int:
    if len(argv) != 8:
        print(__doc__, file=sys.stderr)
        return 2
    path, *args, settle = argv
    for line in judge(ET.parse(path).getroot(), *args, float(settle)):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
