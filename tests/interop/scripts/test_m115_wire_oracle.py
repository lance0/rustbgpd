#!/usr/bin/env python3
"""Offline checks for the M115 wire oracle on synthetic tshark PDML."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import m115_wire_oracle as oracle  # noqa: E402
from test_m114_wire_oracle import notification_scenarios  # noqa: E402

ORACLE = Path(__file__).resolve().parent / "m115_wire_oracle.py"
SRC, RX, NH = "10.115.0.2", "10.115.1.2", "10.115.1.1"
COND, PAY, CTRL = "192.0.2.0/24", "198.51.100.0/24", "198.51.101.0/24"
ARGS = (SRC, RX, NH, COND, PAY, CTRL)


def routes(container: str, address: str, prefixes: tuple[str, ...]) -> str:
    inner = "".join(
        f'<field name="bgp.prefix_length" show="{p.split("/")[1]}"/>'
        f'<field name="{address}" show="{p.split("/")[0]}"/>'
        for p in prefixes
    )
    return f'<field name="{container}" show="">{inner}</field>' if prefixes else ""


def update(
    announce: tuple[str, ...] = (),
    withdraw: tuple[str, ...] = (),
    hops: tuple[str, ...] = (NH,),
    codes: tuple[str, ...] = (),
) -> str:
    """One BGP UPDATE; announcements get one NEXT_HOP attribute per entry in hops."""
    attrs = "".join(
        '<field name="bgp.update.path_attribute">'
        f'<field name="bgp.update.path_attribute.type_code" show="{code}"/>'
        + (f'<field name="bgp.update.path_attribute.next_hop" show="{hop}"/>' if hop else "")
        + "</field>"
        for code, hop in [(c, None) for c in codes] + ([("3", h) for h in hops] if announce else [])
    )
    return (
        '<proto name="bgp"><field name="bgp.type" show="2"/>'
        + routes("bgp.update.withdrawn_routes", "bgp.withdrawn_prefix", withdraw)
        + attrs
        + routes("bgp.update.nlri", "bgp.nlri_prefix", announce)
        + "</proto>"
    )


def packet(when: float, src: str, dst: str, *messages: str) -> str:
    return (
        f'<packet><proto name="frame"><field name="frame.time_epoch" show="{when}"/></proto>'
        f'<proto name="ip"><field name="ip.src" show="{src}"/><field name="ip.dst" show="{dst}"/></proto>'
        + "".join(messages)
        + "</packet>"
    )


def good_packets(settle_gap: float = 2.5) -> list[str]:
    """The expected run: source events at t=0,10,20,40; receiver events follow."""
    return [
        packet(0.0, SRC, "10.115.0.1", update(announce=(COND, CTRL), hops=(SRC,))),
        packet(0.1, "10.115.1.1", RX, update(announce=(COND, CTRL))),
        packet(10.0, SRC, "10.115.0.1", update(announce=(PAY,), hops=(SRC,))),
        packet(20.0, SRC, "10.115.0.1", update(withdraw=(COND,))),
        packet(20.01, "10.115.1.1", RX, update(withdraw=(COND,))),
        packet(20.0 + settle_gap, "10.115.1.1", RX, update(announce=(PAY,))),
        packet(40.0, SRC, "10.115.0.1", update(announce=(COND,), hops=(SRC,))),
        packet(40.01, "10.115.1.1", RX, update(announce=(COND,))),
        packet(40.0 + settle_gap, "10.115.1.1", RX, update(withdraw=(PAY,))),
    ]


def verdicts(packets: list[str], settle: float = 2.0) -> list[str]:
    root = ET.fromstring(f"<pdml>{''.join(packets)}</pdml>")
    return [line.split(" ", 1)[0] for line in oracle.judge(root, *ARGS, settle)]


class M115WireOracleTests(unittest.TestCase):
    def test_expected_run_passes(self) -> None:
        self.assertEqual(verdicts(good_packets()), ["PASS"] * 7)

    def test_payload_leak_while_condition_present_fails(self) -> None:
        packets = good_packets()
        packets.insert(3, packet(11.0, "10.115.1.1", RX, update(announce=(PAY,))))
        self.assertEqual(verdicts(packets)[0], "FAIL")

    def test_payload_never_withdrawn_fails(self) -> None:
        self.assertEqual(verdicts(good_packets()[:-1])[0], "FAIL")

    def test_control_churn_fails(self) -> None:
        packets = good_packets()
        packets.append(packet(41.0, "10.115.1.1", RX, update(withdraw=(CTRL,))))
        self.assertEqual(verdicts(packets)[1], "FAIL")

    def test_duplicate_next_hop_fails(self) -> None:
        packets = good_packets()
        packets[5] = packet(22.5, "10.115.1.1", RX, update(announce=(PAY,), hops=(NH, NH)))
        self.assertEqual(verdicts(packets)[2], "FAIL")

    def test_wrong_next_hop_fails(self) -> None:
        packets = good_packets()
        packets[5] = packet(22.5, "10.115.1.1", RX, update(announce=(PAY,), hops=(SRC,)))
        self.assertEqual(verdicts(packets)[2], "FAIL")

    def test_changes_before_settle_time_fail(self) -> None:
        self.assertEqual(verdicts(good_packets(settle_gap=0.5))[3:5], ["FAIL", "FAIL"])

    def test_missed_source_trigger_does_not_fall_back_to_an_earlier_one(self) -> None:
        # Without the source's condition re-announce at t=40, the payload
        # withdrawal must not be timed from the startup announce at t=0.
        packets = [p for p in good_packets() if 'show="40.0"' not in p]
        self.assertEqual(verdicts(packets)[4], "FAIL")

    def test_mp_reach_to_receiver_fails(self) -> None:
        packets = good_packets()
        packets.append(packet(50.0, "10.115.1.1", RX, update(codes=("14",))))
        self.assertEqual(verdicts(packets)[5], "FAIL")

    def test_notification_fails(self) -> None:
        notification = '<proto name="bgp"><field name="bgp.type" show="3"/></proto>'
        packets = good_packets()
        packets.append(packet(50.0, SRC, "10.115.0.1", notification))
        self.assertEqual(verdicts(packets)[6], "FAIL")

    def test_every_notification_fails_decoded(self) -> None:
        for name, (want, segments) in notification_scenarios("10.115.0.1", SRC, RX).items():
            with self.subTest(name):
                root = ET.fromstring(f"<pdml>{''.join(good_packets() + segments)}</pdml>")
                lines = oracle.judge(root, *ARGS, 2.0)
                self.assertEqual([x.split(" ", 1)[0] for x in lines[:6]], ["PASS"] * 6)
                self.assertEqual(lines[6], want)

    def test_truncated_pdml_exits_non_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "m115.pdml"
            path.write_text('<pdml><packet><proto name="ip">')
            result = subprocess.run(
                [sys.executable, str(ORACLE), str(path), *ARGS, "2"],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
