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
    return [line.split(" ", 1)[0] for line in oracle.judge(root, EXPECTED)]


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

    def test_truncated_pdml_exits_non_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "m114.pdml"
            path.write_text('<pdml><packet><proto name="ip">')
            result = subprocess.run(
                [sys.executable, str(ORACLE), str(path), *EXPECTED[0]],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
