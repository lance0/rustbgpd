#!/usr/bin/env python3
import importlib.util
import socket
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PATH = Path(__file__).with_name("raw_bridge_skew.py")
SPEC = importlib.util.spec_from_file_location("raw_bridge_skew", PATH)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)

BRIDGE = bytes.fromhex(
    "380000001c00000000000000000000000700000016000000020000000a000200"
    "02000000000100000800090063000000060005000a000000"
)
IPV4 = bytes.fromhex(
    "4c0000001c000000000000000000000002000000630000000200000008000100"
    "c000020a0a000200020000000001000008000400000000001400030000000000"
    "000000000000000001000000"
)
IPV6 = bytes.fromhex(
    "580000001c00000000000000000000000a000000630000000200000014000100"
    "20010db80010000000000000000000020a000200020000000002000008000400"
    "000000001400030000000000000000000000000001000000"
)
OVERRUN = bytes.fromhex("10000000040000000000000000000000")


def message(kind, family, ifindex, attrs=b"", seq=0, pid=0):
    body = struct.pack("=BBHiHBB", family, 0, 0, ifindex, 2, 0, 0) + attrs
    raw = struct.pack("=IHHII", 16 + len(body), kind, 0, seq, pid) + body
    return raw + bytes((-len(raw)) % 4)


class ParserTests(unittest.TestCase):
    def test_supplied_literal_bridge_ipv4_and_ipv6_vectors(self):
        bridge, ipv4, ipv6 = MOD.parse_datagram(BRIDGE + IPV4 + IPV6, 0, 0, 44)
        self.assertEqual(
            (bridge.family, bridge.ifindex, bridge.vlan, bridge.master, bridge.lladdr),
            (7, 22, 10, 99, "02:00:00:00:00:01"),
        )
        self.assertEqual(
            (ipv4.family, ipv4.ifindex, ipv4.dst, ipv4.lladdr),
            (2, 99, "192.0.2.10", "02:00:00:00:00:01"),
        )
        self.assertEqual(
            (ipv6.family, ipv6.ifindex, ipv6.dst, ipv6.lladdr),
            (10, 99, "2001:db8:10::2", "02:00:00:00:00:02"),
        )
        self.assertEqual({event.timestamp_ns for event in (bridge, ipv4, ipv6)}, {44})

    def test_delete_is_retained_as_a_distinct_message(self):
        deleted = bytearray(IPV6)
        struct.pack_into("=H", deleted, 4, MOD.RTM_DELNEIGH)
        event = MOD.parse_datagram(bytes(deleted), 0, 0, 7)[0]
        self.assertEqual((event.message, event.dst), ("delete", "2001:db8:10::2"))

    def test_fail_closed_framing_sender_sequence_overrun_and_truncation(self):
        cases = [
            (IPV4, 4, 0),
            (IPV4, 0, MOD.MSG_TRUNC),
            (message(MOD.RTM_NEWNEIGH, socket.AF_INET, 12, seq=1), 0, 0),
            (OVERRUN, 0, 0),
            (b"short", 0, 0),
            (struct.pack("=IHHII", 999, MOD.RTM_NEWNEIGH, 0, 0, 0), 0, 0),
            (IPV4[:-1], 0, 0),
        ]
        for vector, sender, flags in cases:
            with self.subTest(sender=sender, flags=flags, length=len(vector)):
                with self.assertRaises(MOD.MeasurementError):
                    MOD.parse_datagram(vector, sender, flags, 1)


class PairingTests(unittest.TestCase):
    def setUp(self):
        self.expected = [
            {
                "sample_id": "s1",
                "profile": "fixture",
                "phase": "vlan-10-ipv4",
                "vlan": 10,
                "port_ifindex": 12,
                "bridge_ifindex": 4,
                "family": socket.AF_INET,
                "ip": "192.0.2.1",
                "mac": "02:00:00:00:00:01",
            }
        ]

    def event(self, family, timestamp, **kwargs):
        fields = dict(
            message="new",
            family=family,
            ifindex=4,
            state=2,
            flags=0,
            dst=None,
            lladdr=None,
            vlan=None,
            master=None,
            nda_ifindex=None,
            timestamp_ns=timestamp,
        )
        fields.update(kwargs)
        return MOD.Event(**fields)

    def test_first_new_pairs_duplicates_and_delete_are_explicit(self):
        pairer = MOD.Pairer(self.expected)
        pairer.add(
            self.event(
                MOD.AF_BRIDGE,
                100,
                ifindex=12,
                master=4,
                vlan=10,
                lladdr="02:00:00:00:00:01",
            )
        )
        pairer.add(
            self.event(
                socket.AF_INET,
                120,
                dst="192.0.2.1",
                lladdr="02:00:00:00:00:01",
            )
        )
        pairer.add(
            self.event(
                socket.AF_INET,
                125,
                dst="192.0.2.1",
                lladdr="02:00:00:00:00:01",
            )
        )
        pairer.add(
            self.event(
                socket.AF_INET,
                130,
                message="delete",
                dst="192.0.2.1",
                lladdr="02:00:00:00:00:01",
            )
        )
        row = pairer.rows()[0]
        self.assertEqual(
            (row["skew_ns"], row["duplicate_neighbor"], row["delete_events"]),
            (20, 1, 1),
        )
        self.assertEqual(row["missing_reason"], "")

    def test_wrong_identity_clock_regression_and_invalid_nud(self):
        pairer = MOD.Pairer(self.expected)
        pairer.add(
            self.event(
                socket.AF_INET,
                100,
                state=MOD.INVALID_NUD,
                dst="198.51.100.1",
                lladdr="02:00:00:00:00:01",
            )
        )
        self.assertEqual(pairer.wrong_tenant, 0)
        pairer.add(
            self.event(
                socket.AF_INET,
                101,
                dst="198.51.100.1",
                lladdr="02:00:00:00:00:01",
            )
        )
        self.assertEqual(pairer.wrong_tenant, 1)
        with self.assertRaises(MOD.MeasurementError):
            pairer.add(
                self.event(
                    socket.AF_INET,
                    99,
                    dst="192.0.2.1",
                    lladdr="02:00:00:00:00:01",
                )
            )

    def test_duplicate_event_identity_is_rejected(self):
        duplicate = {**self.expected[0], "sample_id": "s2"}
        with self.assertRaises(MOD.MeasurementError):
            MOD.Pairer([*self.expected, duplicate])

    def test_censor_freezes_missing_sides_and_late_duplicates(self):
        pairer = MOD.Pairer(self.expected)
        pairer.add(
            self.event(
                MOD.AF_BRIDGE,
                100,
                ifindex=12,
                master=4,
                vlan=10,
                lladdr="02:00:00:00:00:01",
            )
        )
        pairer.freeze(["s1"])
        pairer.add(
            self.event(
                socket.AF_INET,
                120,
                dst="192.0.2.1",
                lladdr="02:00:00:00:00:01",
            )
        )
        pairer.add(
            self.event(
                MOD.AF_BRIDGE,
                125,
                ifindex=12,
                master=4,
                vlan=10,
                lladdr="02:00:00:00:00:01",
            )
        )
        row = pairer.rows()[0]
        self.assertFalse(row["complete"])
        self.assertEqual(row["missing_reason"], "missing-neighbor")
        self.assertEqual(row["duplicate_fdb"], 0)
        self.assertEqual((row["late_neighbor"], row["late_fdb"]), (1, 1))

    def test_report_is_descriptive_split_by_family_and_timestamp_zero_is_present(self):
        pairer = MOD.Pairer(self.expected)
        pairer.add(
            self.event(
                MOD.AF_BRIDGE,
                0,
                ifindex=12,
                master=4,
                vlan=10,
                lladdr="02:00:00:00:00:01",
            )
        )
        pairer.add(
            self.event(
                socket.AF_INET,
                30,
                dst="192.0.2.1",
                lladdr="02:00:00:00:00:01",
            )
        )
        report = MOD.build_report(pairer.rows(), 1, 0)
        self.assertTrue(report["descriptive_only"])
        self.assertEqual(report["missing_fdb"], 0)
        self.assertEqual(report["absolute_skew"]["p99_9_ns"], 30)
        self.assertEqual(report["by_family"]["ipv4"]["complete"], 1)
        self.assertEqual(report["directions"]["fdb_first"]["count"], 1)
        with self.assertRaises(MOD.MeasurementError):
            MOD.build_report(pairer.rows(), 2, 0)
        with self.assertRaises(MOD.MeasurementError):
            MOD.build_report(pairer.rows(), 1, 1)
        with self.assertRaises(MOD.MeasurementError):
            MOD.build_report(pairer.rows(), 1, 0, 0, {"w_safe_ns": 50})


class PlanAndArtifactTests(unittest.TestCase):
    def test_plan_is_exactly_split_bounded_and_globally_unique(self):
        plan = MOD.deterministic_plan("burst-32")
        rows = plan["planned"]
        self.assertEqual(len(rows), 4000)
        self.assertEqual(plan["active_limit"], 32)
        self.assertEqual(plan["censor_seconds"], 5)
        self.assertEqual(plan["wall_seconds"], 1200)
        self.assertIsNone(plan["acceptance"])
        self.assertEqual(len({row["sample_id"] for row in rows}), 4000)
        self.assertEqual(len({row["mac"] for row in rows}), 4000)
        counts = {
            (vlan, family): sum(
                row["vlan"] == vlan and row["family"] == family for row in rows
            )
            for vlan in (10, 20)
            for family in (socket.AF_INET, socket.AF_INET6)
        }
        self.assertEqual(set(counts.values()), {1000})
        with self.assertRaises(MOD.MeasurementError):
            MOD.deterministic_plan("burst-8", 100, {"10": [110], "20": [210]})

    def test_receipt_has_closed_inventory_and_explicit_missing_row(self):
        run = MOD.deterministic_plan("serial-1")
        run["planned"] = run["planned"][:1]
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "receipt"
            MOD.write_receipt(run, [], output)
            MOD.check_artifacts(output)
            sample = (output / "samples.csv").read_text().splitlines()[1]
            self.assertIn("missing-fdb-and-neighbor", sample)
            self.assertEqual(set(path.name for path in output.iterdir()), {
                "run.json", "samples.csv", "report.json"
            })


class TopologyRollbackTests(unittest.TestCase):
    def test_mid_setup_failure_deletes_only_created_objects_and_restores_inventory(self):
        topology = MOD.TrafficTopology(1)
        command_calls = []

        def fake_command(args, **_kwargs):
            command_calls.append(args)
            if args == ["ip", "netns", "list"]:
                return "base-netns\n"
            if args == ["ip", "-o", "link", "show"]:
                return "base-links\n"
            if args == ["ip", "link", "set", "rh1000", "master", "rbgpskbr0"]:
                raise MOD.MeasurementError("injected mid-setup failure")
            return ""

        completed = lambda args, **_kwargs: __import__("subprocess").CompletedProcess(
            args, 0, "", ""
        )
        with mock.patch.object(MOD.os, "geteuid", return_value=0), mock.patch.object(
            MOD.shutil, "which", return_value="/fixture/tool"
        ), mock.patch.object(MOD, "_command", side_effect=fake_command), mock.patch.object(
            MOD.subprocess, "run", side_effect=completed
        ) as cleanup:
            with self.assertRaisesRegex(MOD.MeasurementError, "injected mid-setup failure"):
                topology.__enter__()

        cleanup_commands = [call.args[0] for call in cleanup.call_args_list]
        self.assertEqual(
            cleanup_commands,
            [
                ["ip", "link", "del", "rh1000"],
                ["ip", "netns", "del", topology.namespace],
                ["ip", "link", "del", topology.bridge],
            ],
        )
        self.assertEqual(topology.created_host_ports, ["rh1000"])
        self.assertNotIn(["ip", "link", "del", "rh1001"], cleanup_commands)
        self.assertGreaterEqual(command_calls.count(["ip", "netns", "list"]), 2)
        self.assertGreaterEqual(command_calls.count(["ip", "-o", "link", "show"]), 2)


if __name__ == "__main__":
    unittest.main()
