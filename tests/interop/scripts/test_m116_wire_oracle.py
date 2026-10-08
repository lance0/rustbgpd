#!/usr/bin/env python3
"""Offline checks for the M116 wire oracle on synthetic tshark PDML."""

from __future__ import annotations

import ipaddress
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import m116_wire_oracle as oracle  # noqa: E402

ORACLE = Path(__file__).resolve().parent / "m116_wire_oracle.py"
PREFIX = "2001:db8:1160::/48"
EXPECTED = [("10.116.1.2", PREFIX, "2001:db8:116::1")]
GLOBAL = ipaddress.IPv6Address("2001:db8:116::1").packed
LINK_LOCAL = ipaddress.IPv6Address("fe80::1").packed


def mp_reach(next_hop: bytes, prefix: str = PREFIX, family: bytes = b"\x00\x02\x01") -> str:
    """Hex of one MP_REACH_NLRI path attribute (optional, extended length)."""
    net = ipaddress.IPv6Network(prefix)
    nlri = bytes([net.prefixlen]) + net.network_address.packed[: (net.prefixlen + 7) // 8]
    value = family + bytes([len(next_hop)]) + next_hop + b"\x00" + nlri
    return (bytes([0x90, 14]) + len(value).to_bytes(2, "big") + value).hex()


def attr_field(hex_attr: str, pos: int = 100, cover: int | None = None) -> str:
    """A path attribute as tshark writes it: empty own value, hex leaves by position.

    Leaves are flags (with a bitmask child), type, length and the value; cover
    drops leaf bytes past that many octets to model an incomplete dissection.
    """
    raw = bytes.fromhex(hex_attr)
    header = 4 if raw[0] & 0x10 else 3
    parts = [(0, raw[:1]), (1, raw[1:2]), (2, raw[2:header]), (header, raw[header:])]
    leaves = "".join(
        f'<field name="leaf" pos="{pos + off}" size="{len(b)}" value="{b.hex()}">'
        + (f'<field name="bit" pos="{pos}" size="1" value="1"/>' if off == 0 else "")
        + "</field>"
        for off, b in parts
        if b and (cover is None or off + len(b) <= cover)
    )
    return (
        f'<field name="bgp.update.path_attribute" pos="{pos}" size="{len(raw)}" '
        f'show="" value="">{leaves}</field>'
    )


def update(*attrs: str) -> str:
    origin = (bytes([0x40, 1, 1, 0])).hex()
    body = attr_field(origin, pos=60) + "".join(attr_field(a) for a in attrs)
    return f'<proto name="bgp"><field name="bgp.type" show="2"/>{body}</proto>'


def pdml(*messages: str, dst: str = "10.116.1.2") -> ET.Element:
    ip = f'<proto name="ip"><field name="ip.dst" show="{dst}"/></proto>'
    return ET.fromstring(f"<pdml><packet>{ip}{''.join(messages)}</packet></pdml>")


def verdicts(root: ET.Element) -> list[str]:
    return [line.split(" ", 1)[0] for line in oracle.judge(root, EXPECTED)]


class M116WireOracleTests(unittest.TestCase):
    def test_sixteen_octet_global_passes(self) -> None:
        self.assertEqual(verdicts(pdml(update(mp_reach(GLOBAL)))), ["PASS", "PASS", "PASS"])

    def test_link_local_toward_off_link_receiver_fails_expectation_only(self) -> None:
        # Well formed, but RFC 2545 §3 keeps the source's link-local on its link.
        root = pdml(update(mp_reach(GLOBAL + LINK_LOCAL)))
        self.assertEqual(verdicts(root), ["FAIL", "PASS", "PASS"])

    def test_four_octet_next_hop_fails(self) -> None:
        # The pre-fix shape: an IPv6 NLRI behind an IPv4 next hop.
        root = pdml(update(mp_reach(ipaddress.IPv4Address("10.116.0.1").packed)))
        self.assertEqual(verdicts(root), ["FAIL", "FAIL", "PASS"])

    def test_four_octet_next_hop_for_unlisted_prefix_fails(self) -> None:
        root = pdml(
            update(mp_reach(GLOBAL)),
            update(mp_reach(bytes([10, 116, 0, 99]), prefix="2001:db8:1161::/48")),
        )
        self.assertEqual(verdicts(root), ["PASS", "FAIL", "PASS"])

    def test_ipv4_mapped_next_hop_fails(self) -> None:
        mapped = ipaddress.IPv6Address("::ffff:10.116.0.1").packed
        self.assertEqual(verdicts(pdml(update(mp_reach(mapped))))[:2], ["FAIL", "FAIL"])

    def test_second_half_not_link_local_fails(self) -> None:
        root = pdml(update(mp_reach(GLOBAL + GLOBAL)))
        self.assertEqual(verdicts(root)[:2], ["FAIL", "FAIL"])

    def test_other_valid_address_fails_expectation_only(self) -> None:
        other = ipaddress.IPv6Address("2001:db8:116::2").packed
        self.assertEqual(verdicts(pdml(update(mp_reach(other)))), ["FAIL", "PASS", "PASS"])

    def test_missing_announcement_fails(self) -> None:
        self.assertEqual(verdicts(pdml())[0], "FAIL")

    def test_other_receiver_does_not_count(self) -> None:
        root = pdml(update(mp_reach(GLOBAL)), dst="10.116.2.2")
        self.assertEqual(verdicts(root)[0], "FAIL")

    def test_notification_fails(self) -> None:
        notification = '<proto name="bgp"><field name="bgp.type" show="3"/></proto>'
        root = pdml(update(mp_reach(GLOBAL)), notification)
        self.assertEqual(verdicts(root), ["PASS", "PASS", "FAIL"])

    def test_attribute_length_mismatch_raises(self) -> None:
        broken = mp_reach(GLOBAL)[:-2]
        with self.assertRaises(ValueError):
            oracle.judge(pdml(update(broken)), EXPECTED)

    def test_uncovered_attribute_bytes_raise(self) -> None:
        body = attr_field(mp_reach(GLOBAL), cover=4)
        message = f'<proto name="bgp"><field name="bgp.type" show="2"/>{body}</proto>'
        with self.assertRaises(ValueError):
            oracle.judge(pdml(message), EXPECTED)

    def test_missing_position_raises(self) -> None:
        bare = (
            '<proto name="bgp"><field name="bgp.type" show="2"/>'
            '<field name="bgp.update.path_attribute" value=""/></proto>'
        )
        with self.assertRaises(ValueError):
            oracle.judge(pdml(bare), EXPECTED)

    def test_truncated_pdml_exits_non_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "m116.pdml"
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
