#!/usr/bin/env python3
"""Offline checks for the M114 wire oracle on synthetic tshark PDML."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import m114_wire_oracle as oracle  # noqa: E402

ORACLE = Path(__file__).resolve().parent / "m114_wire_oracle.py"
SOURCE = "10.114.0.2"
EXPECTED = [("10.114.1.2", "198.51.100.0/24", "10.114.0.1")]


def update(*attrs: tuple[str, str | None], nlri: tuple[str, ...] = ("198.51.100.0/24",)) -> str:
    """One BGP UPDATE: attrs are (type code, next hop or None); nlri goes in the body."""
    body = "".join(
        '<field name="bgp.update.path_attribute">'
        f'<field name="bgp.update.path_attribute.type_code" show="{code}"/>'
        + (f'<field name="bgp.update.path_attribute.next_hop" show="{hop}"/>' if hop else "")
        + "</field>"
        for code, hop in attrs
    )
    prefixes = "".join(
        f'<field name="bgp.prefix_length" show="{p.split("/")[1]}"/>'
        f'<field name="bgp.nlri_prefix" show="{p.split("/")[0]}"/>'
        for p in nlri
    )
    nlri_field = f'<field name="bgp.update.nlri" show="">{prefixes}</field>' if nlri else ""
    return f'<proto name="bgp"><field name="bgp.type" show="2"/>{body}{nlri_field}</proto>'


def pdml(*messages: str, dst: str = "10.114.1.2") -> ET.Element:
    ip = f'<proto name="ip"><field name="ip.dst" show="{dst}"/></proto>'
    return ET.fromstring(f"<pdml><packet>{ip}{''.join(messages)}</packet></pdml>")


def verdicts(root: ET.Element) -> list[str]:
    return [line.split(" ", 1)[0] for line in oracle.judge(root, SOURCE, EXPECTED)]


def message(kind: int, code: int | None = None, subcode: int | None = None) -> str:
    """A BGP message; a NOTIFICATION carries code and subcode as tshark names them."""
    body = f'<field name="bgp.type" show="{kind}"/>'
    if code is not None:
        body += f'<field name="bgp.notify.major_error" show="{code}"/>'
        body += f'<field name="bgp.notify.minor_error_cease" show="{subcode}"/>'
    return f'<proto name="bgp">{body}</proto>'


def segment(src: str, sport: int, dst: str, dport: int, *messages: str) -> str:
    """One TCP segment between two BGP speakers, carrying messages."""
    return (
        '<packet><proto name="frame"><field name="frame.time_epoch" show="0"/></proto>'
        f'<proto name="ip"><field name="ip.src" show="{src}"/><field name="ip.dst" show="{dst}"/></proto>'
        f'<proto name="tcp"><field name="tcp.srcport" show="{sport}"/>'
        f'<field name="tcp.dstport" show="{dport}"/></proto>' + "".join(messages) + "</packet>"
    )


def notification_scenarios(
    local: str, source: str, receiver: str
) -> dict[str, tuple[str, list[str]]]:
    """Expected NOTIFICATION verdict and segments for each session/timing case.

    Every case keeps a source connection that reaches Established (KEEPALIVE
    both ways); the NOTIFICATION is placed on a second connection or after it.
    """
    up = [
        segment(source, 50000, local, 179, message(1)),
        segment(local, 179, source, 50000, message(1), message(4)),
        segment(source, 50000, local, 179, message(4)),
    ]
    collision = message(3, 6, 7)

    def opened(peer: str) -> list[str]:
        # rustbgpd's own connection: OPEN and KEEPALIVE out, OPEN back, no KEEPALIVE back.
        return [
            segment(local, 40000, peer, 179, message(1)),
            segment(peer, 179, local, 40000, message(1)),
            segment(local, 40000, peer, 179, message(4)),
        ]

    return {
        "pre-Established source collision": (
            "PASS",
            opened(source) + up + [segment(source, 179, local, 40000, collision)],
        ),
        "receiver collision": (
            "FAIL",
            up + opened(receiver) + [segment(receiver, 179, local, 40000, collision)],
        ),
        "post-Established source collision": (
            "FAIL",
            up + [segment(source, 50000, local, 179, collision)],
        ),
        "pre-Established source non-collision": (
            "FAIL",
            opened(source) + up + [segment(source, 179, local, 40000, message(3, 6, 2))],
        ),
        "NOTIFICATION without TCP ports": (
            "FAIL",
            up
            + [
                segment(source, 179, local, 40000, collision).replace(
                    '<proto name="tcp">', '<proto name="x">'
                )
            ],
        ),
    }


class M114WireOracleTests(unittest.TestCase):
    def test_one_expected_next_hop_passes(self) -> None:
        root = pdml(update(("1", None), ("2", None), ("3", "10.114.0.1")))
        self.assertEqual(verdicts(root), ["PASS", "PASS", "PASS"])

    def test_received_next_hop_fails(self) -> None:
        root = pdml(update(("3", "10.114.0.2")))
        self.assertEqual(verdicts(root)[0], "FAIL")

    def test_duplicate_next_hop_fails(self) -> None:
        root = pdml(update(("3", "10.114.0.1"), ("3", "10.114.0.1")))
        self.assertEqual(verdicts(root)[0], "FAIL")

    def test_missing_announcement_fails(self) -> None:
        self.assertEqual(verdicts(pdml())[0], "FAIL")

    def test_mp_reach_only_announcement_fails(self) -> None:
        root = pdml(update(("1", None), ("14", None), nlri=()))
        self.assertEqual(verdicts(root)[1], "FAIL")

    def test_mp_unreach_beside_body_announcement_fails(self) -> None:
        root = pdml(update(("3", "10.114.0.1")), update(("15", None), nlri=()))
        self.assertEqual(verdicts(root), ["PASS", "FAIL", "PASS"])

    def test_notification_fails(self) -> None:
        notification = '<proto name="bgp"><field name="bgp.type" show="3"/></proto>'
        root = pdml(update(("3", "10.114.0.1")), notification)
        self.assertEqual(verdicts(root)[2], "FAIL")

    def test_notification_scope(self) -> None:
        cases = notification_scenarios("10.114.0.1", SOURCE, "10.114.1.2")
        for name, (want, segments) in cases.items():
            with self.subTest(name):
                root = ET.fromstring(f"<pdml>{''.join(segments)}</pdml>")
                line = oracle.judge(root, SOURCE, EXPECTED)[2]
                self.assertTrue(line.startswith(want), line)
                self.assertIn("6/", line)

    def test_tolerated_notification_is_listed(self) -> None:
        segments = notification_scenarios("10.114.0.1", SOURCE, "10.114.1.2")[
            "pre-Established source collision"
        ][1]
        line = oracle.notification_verdict(
            ET.fromstring(f"<pdml>{''.join(segments)}</pdml>"), SOURCE
        )
        self.assertEqual(
            line,
            "PASS 1 NOTIFICATION message(s) captured; tolerated source collision resolution: "
            "['10.114.0.2:179 -> 10.114.0.1:40000 code 6/7 before Established']",
        )

    def test_truncated_pdml_exits_non_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "m114.pdml"
            path.write_text('<pdml><packet><proto name="ip">')
            result = subprocess.run(
                [sys.executable, str(ORACLE), str(path), SOURCE, *EXPECTED[0]],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
