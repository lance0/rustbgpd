#!/usr/bin/env python3
"""Exercise the actual M99 embedded oracle with independent OPEN/TCP vectors."""

from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest


HERE = Path(__file__).resolve().parent
ORACLE = (HERE / "test-m99-rfc9072-extended-open.sh").read_text().split(
    "python3 - \"$PAYLOADS\" <<'PY'\n", 1
)[1].split("\nPY\n", 1)[0]
# Full production family inventory: unicast, FlowSpec, EVPN, BGP-LS,
# BGP-LS VPN, VPN, labeled unicast, and RT-Constrain.
FAMILIES = [(1, 1), (2, 1), (1, 133), (2, 133), (25, 70), (16388, 71),
            (16388, 72), (1, 128), (2, 128), (1, 4), (2, 4), (1, 132)]


def cap(code, value=b""):
    return bytes([code, len(value)]) + value


NEXT_HOP_TUPLES = bytes.fromhex("000100010002000100800002")


def maximum_caps(next_hops=NEXT_HOP_TUPLES):
    families = [afi.to_bytes(2, "big") + bytes([safi]) for afi, safi in FAMILIES]
    add_path = [family for family in families if family[2] in (1, 128, 4)]
    return b"".join([
        *(cap(1, family[:2] + b"\0" + family[2:]) for family in families),
        cap(64, bytes.fromhex("4078") + b"".join(f + b"\0" for f in families)),
        cap(71, b"".join(f + bytes.fromhex("00000e10") for f in families)),
        cap(69, b"".join(f + b"\3" for f in add_path)),
        cap(76, b"".join(f + b"\0\10" for f in add_path)),
        cap(3, bytes.fromhex("0001000101400100020001014001")),
        cap(2), cap(70), cap(6), cap(5, next_hops), cap(9, b"\1"),
        cap(65, (65001).to_bytes(4, "big")),
    ])


def open_message(capabilities, extended=False):
    parameter = b"\2" + len(capabilities).to_bytes(2 if extended else 1, "big") + capabilities
    optional = (b"\xff\xff" + len(parameter).to_bytes(2, "big") if extended
                else bytes([len(parameter)])) + parameter
    body = bytes.fromhex("04fde9005a0a630001") + optional
    return b"\xff" * 16 + (19 + len(body)).to_bytes(2, "big") + b"\1" + body


CLASSIC_CAPS = bytes.fromhex("01040001000102004600060041040000fde9")


class M99OracleTests(unittest.TestCase):
    def run_oracle(self, maximum=None, *, notification=False, split=False):
        maximum = open_message(maximum_caps(), True) if maximum is None else maximum
        small = open_message(cap(2), True)
        classic = open_message(CLASSIC_CAPS)
        directions = [("10.99.0.2", "10.99.0.1", small),
                      ("10.99.0.1", "10.99.0.2", maximum),
                      ("10.99.1.2", "10.99.1.1", classic),
                      ("10.99.1.1", "10.99.1.2", classic)]
        if notification:
            directions[1] = (*directions[1][:2], maximum + b"\xff" * 16 + bytes.fromhex("0015030200"))
        rows = []
        for stream, (source, destination, payload) in enumerate(directions):
            pieces = [(100, payload)]
            if split:
                pieces = [(120, payload[20:]), (100, payload[:20]), (100, payload[:20])]
            for sequence, piece in pieces:
                rows.append(f"{stream}\t{source}\t179\t{destination}\t50000\t{sequence}\t{piece.hex()}")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "payloads.tsv"
            path.write_text("\n".join(rows))
            return subprocess.run([sys.executable, "-c", ORACLE, str(path)],
                                  capture_output=True, text=True, check=False)

    def test_current_maximum_and_classic_with_retransmissions(self):
        self.assertEqual(len(maximum_caps()), 313)
        self.assertEqual(len(open_message(maximum_caps(), True)), 348)
        self.assertEqual(len(open_message(CLASSIC_CAPS)), 49)
        result = self.run_oracle(split=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("proof complete", result.stdout)

    def test_old_maximum_missing_vpn_tuple_is_rejected(self):
        old = open_message(maximum_caps(bytes.fromhex("000100010002")), True)
        self.assertEqual(len(old), 342)
        result = self.run_oracle(old)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected 348", result.stderr)

    def test_same_size_wrong_next_hop_tuples_are_rejected(self):
        for wrong in ("000100010002000100040002", "000100010002000200800002",
                      "000100010002000100800001"):
            with self.subTest(wrong=wrong):
                result = self.run_oracle(open_message(maximum_caps(bytes.fromhex(wrong)), True))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Extended Next Hop tuples", result.stderr)

    def test_bad_aggregate_and_notification_are_rejected(self):
        malformed = bytearray(open_message(maximum_caps(), True))
        malformed[31] -= 1
        result = self.run_oracle(bytes(malformed))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("aggregate does not consume OPEN", result.stderr)
        result = self.run_oracle(notification=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("NOTIFICATION", result.stderr)

    def test_lab_configuration_matches_maximum_and_classic_shapes(self):
        config = tomllib.loads((HERE.parent / "configs/rustbgpd-m99-rfc9072.toml").read_text())
        maximum, classic = config["neighbors"]
        self.assertEqual(set(maximum["families"]), {
            "ipv4_unicast", "ipv6_unicast", "ipv4_flowspec", "ipv6_flowspec",
            "l2vpn_evpn", "linkstate", "linkstate_vpn", "l3vpn_ipv4_unicast",
            "l3vpn_ipv6_unicast", "ipv4_labeled_unicast", "ipv6_labeled_unicast", "rtc",
        })
        self.assertTrue(maximum["graceful_restart"])
        self.assertEqual(maximum["llgr_stale_time"], 3600)
        self.assertTrue(maximum["prefix_orf_receive"])
        self.assertEqual(maximum["role"], "route_server")
        self.assertEqual(maximum["add_path"], {"receive": True, "send": True, "receive_max": 8})
        self.assertEqual(classic["families"], ["ipv4_unicast"])
        self.assertFalse(classic["graceful_restart"])


if __name__ == "__main__":
    unittest.main()
