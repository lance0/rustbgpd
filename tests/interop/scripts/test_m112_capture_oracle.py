#!/usr/bin/env python3
"""Offline negative controls for M112's packet and route-snapshot oracle."""

import base64
import copy
import ipaddress
import os
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

import m112_capture_oracle as oracle
import m112_raw_peer as source
from evpn_peer_sync_oracle import attribute
from m105_capture_oracle import update


def message(kind, body=b""):
    return b"\xff" * 16 + struct.pack("!HB", 19 + len(body), kind) + body


def reflected(body):
    _, attrs, _ = update(body)
    if 14 in attrs:
        attrs[9] = (0x80, ipaddress.IPv4Address(oracle.SOURCE_ID).packed)
        attrs[10] = (0x80, ipaddress.IPv4Address(oracle.RR_ID).packed)
        attrs[40] = (0xE0, attrs[40][1])
    encoded = b"".join(attribute(code, value, flags) for code, (flags, value) in attrs.items())
    return b"\0\0" + struct.pack("!H", len(encoded)) + encoded


def capture(*, missing_malformed_withdraw=False, survivor_churn=False,
            withdrawal_label=bytes(3), withdrawal_esi=bytes(10),
            wrong_withdrawal_key=False, wrong_announcement_label=False):
    def withdraw(mac):
        body = source.withdrawal(mac)
        nlri = source.nlri(mac)
        return body[:-len(nlri)] + nlri[:10] + withdrawal_esi + nlri[20:32] + withdrawal_label

    inbound = [body for phase in oracle.PHASES for body in source.phase_updates(phase)]
    outbound = [reflected(source.announcement(oracle.TARGET)),
                reflected(source.announcement(oracle.SURVIVOR)),
                withdraw(oracle.SURVIVOR if wrong_withdrawal_key else oracle.TARGET),
                reflected(source.announcement(oracle.TARGET)),
                withdraw(oracle.TARGET), withdraw(oracle.SURVIVOR)]
    if wrong_announcement_label:
        nlri = source.nlri(oracle.TARGET)
        outbound[0] = outbound[0].replace(nlri, nlri[:-3] + bytes(3))
    if missing_malformed_withdraw:
        del outbound[2]
    if survivor_churn:
        outbound[2:2] = [withdraw(oracle.SURVIVOR),
                         reflected(source.announcement(oracle.SURVIVOR))]
    rows = []
    for (sender, receiver), name in oracle.DIRECTIONS.items():
        opening = bytearray(source.open_body())
        opening[5:9] = ipaddress.IPv4Address(oracle.ROUTER_IDS[sender]).packed
        data = message(1, opening) + message(4)
        if name == "source_to_rr":
            data += b"".join(message(2, body) for body in inbound)
        elif name == "rr_to_sink":
            data += b"".join(message(2, body) for body in outbound)
        stream = "0" if sender in (oracle.SOURCE, oracle.RR_SOURCE) else "1"
        rows.append(f"{stream}\t{sender}\t{receiver}\t1000\t{data.hex()}")
    return rows


def observer_snapshot(macs):
    rows = []
    for mac in macs:
        _, attrs, _ = update(reflected(source.announcement(mac)))
        path = {"best": True, "family": {"afi": 25, "safi": 70},
                "sourceAsn": 65001, "sourceId": oracle.RR_ID, "neighborIp": oracle.RR_SINK,
                "nlriBinary": base64.b64encode(source.nlri(mac)).decode(),
                "pattrsBinary": [base64.b64encode(attribute(code, value, flags)).decode()
                                  for code, (flags, value) in attrs.items()]}
        rows.append({"destination": {"prefix": mac, "paths": [path]}})
    return rows


def rr_snapshot(macs):
    return [{"route_type": 2, "rd": oracle.RD, "mac": mac, "ip": "", "next_hop": oracle.SOURCE,
             "peer": oracle.SOURCE, "label": 48, "label2": 0, "tunnel_type": 0,
             "ethernet_tag": "0", "esi": bytes(10).hex(":"),
             "prefix_sid": {"raw_value": source.prefix_sid().hex(), "flags": 0xC0,
                            "services": [{"tlv_type": 6, "sids": [{"sid_value": oracle.SID,
                                "endpoint_behavior": 23, "flags": 0, "structures": [{
                                    "locator_block_length": 40, "locator_node_length": 24,
                                    "function_length": 16, "argument_length": 0,
                                    "transposition_length": 0, "transposition_offset": 0}]}]}]}}
            for mac in macs]


class M112OracleTests(unittest.TestCase):
    def test_existing_artifact_directory_is_unchanged_on_rejection(self):
        root = Path(__file__).resolve().parents[3]
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            tools = temporary / "bin"
            tools.mkdir()
            for name in ("docker", "grpcurl", "jq"):
                path = tools / name
                path.write_text("#!/bin/sh\nexit 0\n")
                path.chmod(0o755)
            receipt = temporary / "receipt"
            receipt.mkdir()
            names = ("rustbgpd.log", "gobgp.log", "source.log", "source-final.json", "exit-code.txt")
            for name in names:
                (receipt / name).write_text("retained prior receipt\n")
            result = subprocess.run(
                ["bash", "tests/interop/scripts/test-m112-srv6-l2-reflection.sh"], cwd=root,
                env={**os.environ, "PATH": f"{tools}:{os.environ['PATH']}", "CLEANUP": "0",
                     "M112_ARTIFACT_DIR": str(receipt), "M112_SOURCE_REVISION": "test-revision"},
                capture_output=True, text=True, timeout=10, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("File exists", result.stderr)
            self.assertEqual({path.name: path.read_text() for path in receipt.iterdir()},
                             {name: "retained prior receipt\n" for name in names})

    def test_literal_rfc_fixture(self):
        self.assertEqual(source.prefix_sid().hex(),
                         "0600220001001e0020010db801120001000100000000000000001700010006281810000000")
        self.assertEqual(source.nlri(oracle.TARGET)[-3:], bytes.fromhex("000030"))
        self.assertEqual(len(source.nlri(oracle.TARGET)), 35)
        self.assertEqual(oracle.service(source.prefix_sid())["endpoint_behavior"], 23)

    def test_full_transition_history(self):
        result = oracle.analyze(capture())
        self.assertEqual(result["label_hex"], "000030")
        self.assertEqual(result["reflected_actions"][oracle.TARGET],
                         ["announce", "withdraw", "announce", "withdraw"])
        self.assertEqual([event["label_hex"] for event in result["withdrawals"]["rr_to_sink"]],
                         ["000000"] * 3)
        self.assertEqual([event["label_hex"] for event in result["withdrawals"]["source_to_rr"]],
                         ["000030"] * 2)

    def test_withdrawal_uses_key_without_nonkey_label_or_esi(self):
        for label in (bytes(3), bytes.fromhex("000030"), bytes.fromhex("abcdef")):
            with self.subTest(label=label.hex()):
                result = oracle.analyze(capture(withdrawal_label=label, withdrawal_esi=b"\x01" * 10))
                for event in result["withdrawals"]["rr_to_sink"]:
                    self.assertEqual(event["label_hex"], label.hex())
                    self.assertEqual(event["esi_hex"], "01" * 10)

    def test_withdrawal_wrong_route_key_fails(self):
        with self.assertRaisesRegex(ValueError, "transition history"):
            oracle.analyze(capture(wrong_withdrawal_key=True))

    def test_announcement_label_preservation_remains_strict(self):
        with self.assertRaisesRegex(ValueError, "implicit-null label differs"):
            oracle.analyze(capture(wrong_announcement_label=True))

    def test_tcp_fragmentation_and_identical_retransmit(self):
        rows = capture()
        fields = rows.pop().split("\t")
        payload = bytes.fromhex(fields[-1])
        first = fields[:-1] + [payload[:25].hex()]
        second = fields[:3] + ["1020", payload[20:].hex()]
        rows += ["\t".join(second), "\t".join(first), "\t".join(first)]
        oracle.analyze(rows)

    def test_missing_malformed_replacement_withdrawal_fails(self):
        with self.assertRaisesRegex(ValueError, "transition history"):
            oracle.analyze(capture(missing_malformed_withdraw=True))

    def test_survivor_churn_fails_even_after_recovery(self):
        with self.assertRaisesRegex(ValueError, "transition history"):
            oracle.analyze(capture(survivor_churn=True))

    def test_extra_tcp_session_fails(self):
        rows = capture()
        fields = rows[0].split("\t")
        fields[0] = "9"
        with self.assertRaisesRegex(ValueError, "multiple TCP"):
            oracle.analyze(rows + ["\t".join(fields)])

    def test_notification_fails(self):
        rows = capture()
        rows[0] += message(3, b"\x06\0").hex()
        with self.assertRaisesRegex(ValueError, "NOTIFICATION"):
            oracle.analyze(rows)

    def test_missing_direction_fails(self):
        with self.assertRaisesRegex(ValueError, "missing captured"):
            oracle.analyze(capture()[:-1])

    def test_nested_corruption_is_the_only_malformed_control(self):
        valid, broken = source.prefix_sid(), source.prefix_sid(malformed=True)
        self.assertEqual([i for i, pair in enumerate(zip(valid, broken)) if pair[0] != pair[1]], [30])
        with self.assertRaisesRegex(ValueError, "truncated SRv6"):
            oracle.service(broken)
        _, attrs, _ = update(source.announcement(oracle.TARGET, malformed=True))
        oracle.attributes(attrs, reflected=False, malformed=True)

    def test_bad_behavior_sid_and_label_fail(self):
        for offset, value in ((26, 0x12), (10, 0xFF)):
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                raw = bytearray(source.prefix_sid())
                raw[offset] = value
                oracle.service(raw)
        bad = source.nlri(oracle.TARGET)[:-3] + bytes.fromhex("000003")
        with self.assertRaisesRegex(ValueError, "implicit-null"):
            oracle.type2s(bad)

    def test_reflected_attributes_must_keep_known_values(self):
        for code in (1, 2, 5, 9, 10, 16, 40):
            with self.subTest(code=code), self.assertRaises(ValueError):
                _, attrs, _ = update(reflected(source.announcement(oracle.TARGET)))
                attrs[code] = (attrs[code][0], attrs[code][1] + b"\0")
                oracle.attributes(attrs, reflected=True)

    def test_observer_each_phase_and_empty_stream(self):
        for phase, macs in oracle.EXPECTED.items():
            with self.subTest(phase=phase):
                result = oracle.observer(observer_snapshot(sorted(macs)), phase)
                self.assertEqual(result["macs"], sorted(macs))

    def test_observer_missing_binary_attributes_fails(self):
        rows = observer_snapshot([oracle.SURVIVOR])
        rows[0]["destination"]["paths"][0]["pattrsBinary"] = []
        with self.assertRaisesRegex(ValueError, "attribute set"):
            oracle.observer(rows, "malformed")

    def test_observer_rejects_stale_filtered_nonbest_or_wrong_source(self):
        for key, value in (("best", False), ("stale", True), ("filtered", True),
                           ("isWithdraw", True), ("isNexthopInvalid", True),
                           ("neighborIp", oracle.SOURCE)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                rows = observer_snapshot([oracle.SURVIVOR])
                rows[0]["destination"]["paths"][0][key] = value
                oracle.observer(rows, "malformed")

    def test_observer_wrong_phase_or_duplicate_fails(self):
        rows = observer_snapshot([oracle.SURVIVOR])
        with self.assertRaisesRegex(ValueError, "route set"):
            oracle.observer(rows, "baseline")
        with self.assertRaisesRegex(ValueError, "duplicate observer"):
            oracle.observer(rows + copy.deepcopy(rows), "malformed")

    def test_observer_binary_nlri_must_match_mp_reach(self):
        rows = observer_snapshot([oracle.SURVIVOR])
        rows[0]["destination"]["paths"][0]["nlriBinary"] = base64.b64encode(source.nlri(oracle.TARGET)).decode()
        with self.assertRaisesRegex(ValueError, "disagree"):
            oracle.observer(rows, "malformed")

    def test_rr_requires_correct_typed_visibility(self):
        rows = rr_snapshot([oracle.SURVIVOR])
        self.assertTrue(oracle.rr(rows, "malformed", require_typed=True)["typed_visibility_verified"])
        rows[0]["prefix_sid"]["services"][0]["sids"][0]["endpoint_behavior"] = 21
        with self.assertRaisesRegex(ValueError, "SID information"):
            oracle.rr(rows, "malformed", require_typed=True)

    def test_rr_development_mode_explicitly_reports_missing_visibility(self):
        rows = rr_snapshot([oracle.SURVIVOR])
        del rows[0]["prefix_sid"]
        self.assertFalse(oracle.rr(rows, "malformed", require_typed=False)["typed_visibility_verified"])
        with self.assertRaisesRegex(ValueError, "typed visibility is required"):
            oracle.rr(rows, "malformed", require_typed=True)


if __name__ == "__main__":
    unittest.main()
