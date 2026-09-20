#!/usr/bin/env python3
"""Focused membership evidence regressions; no daemon or sockets required."""
import copy
import gzip
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch

import membership_churn as cell
import check_membership_cell as gate


class MembershipTests(unittest.TestCase):
    def test_each_generation_references_exact_roster_and_two_datasets(self):
        with tempfile.TemporaryDirectory(prefix="mc-", dir="/tmp") as directory:
            run = Path(directory)
            with patch.dict(os.environ, {"GEN_DUALSTACK": "1"}, clear=True):
                subprocess.run(["python3", str(Path(__file__).with_name("gen-scenario.py")),
                                "20", str(run), "1790", "16"], check=True, capture_output=True)
                cell.prepare(run, 20, 11440, 4)
            for generation in range(5):
                config = tomllib.loads((run / f"config-{generation}.toml").read_text())
                members = cell.roster(20, generation)
                self.assertEqual({n["address"] for n in config["neighbors"]}, {cell.address(i) for i in members})
                self.assertEqual(set(config["policy"]["datasets"]), cell.dataset_names(members))
                self.assertEqual(len(config["policy"]["rpol_files"]), 23)
                self.assertEqual(sum("md5_password" in n for n in config["neighbors"]), 1)
                for member, neighbor in zip(members, config["neighbors"], strict=True):
                    self.assertTrue(neighbor["ttl_security"])
                    self.assertEqual(neighbor["import_policy_chain"], [f"client-{member}"])
                    policy = (run / f"members/client-{member}.rpol").read_text()
                    self.assertIn(f"route.origin-as in client-{member}-origins", policy)
                    self.assertIn(f"route.prefix in client-{member}-prefixes", policy)
                    for kind in ("prefixes", "origins"):
                        path = config["policy"]["datasets"][f"client-{member}-{kind}"]["path"]
                        self.assertTrue((run / path).read_text().strip())
                    # Keep each compilation unit below the compiler's dataset budget.
                    self.assertEqual(policy.count("dataset "), 2)
                if generation:
                    previous = cell.dataset_names(cell.roster(20, generation - 1))
                    self.assertEqual(len(previous - set(config["policy"]["datasets"])), 4)

    def test_duplicate_nlri_and_wrong_family_cannot_complete_receiver(self):
        receiver = cell.Receiver(20, False, 1790, 2)
        receiver.established = True
        v4 = b"\x18\x14\x00\x00" * 2
        cell.apply_update(b"\0\0\0\0" + v4, receiver.inventories, 2)
        self.assertEqual(receiver.inventories[4], {0})
        self.assertFalse(receiver.complete())
        cell.apply_update(b"\0\0\0\0\x18\x14\x00\x01", receiver.inventories, 2)
        self.assertFalse(receiver.complete())
        value = b"\x00\x02\x01\x10" + bytes(16) + b"\0" + b"\x30\x30\x01\0\0\0\0\x30\x30\x01\0\0\0\x01"
        attribute = bytes([128, 14, len(value)]) + value
        cell.apply_update(b"\0\0" + struct.pack("!H", len(attribute)) + attribute, receiver.inventories, 2)
        self.assertTrue(receiver.complete())
        # A subsequent base withdrawal must clear completion again.
        cell.apply_update(b"\0\x04\x18\x14\0\0\0\0", receiver.inventories, 2)
        self.assertFalse(receiver.complete())

    def test_churn_prefixes_do_not_count_as_base_inventory(self):
        self.assertEqual(cell.nlri_indices(b"\x18\xac\x10\0", 4, 200200), [])
        self.assertEqual(cell.nlri_indices(b"\x30\x30\x02\0\0\0\0", 6, 200200), [])

    def test_joining_base_inventory_requires_current_export_marker(self):
        def update(markers):
            value = b"".join(struct.pack("!I", (65400 << 16) | marker) for marker in markers)
            attribute = bytes([192, 8, len(value)]) + value
            return b"\0\0" + struct.pack("!H", len(attribute)) + attribute + b"\x18\x14\0\0"
        for markers in ([], [1000], [1000, 2000]):
            with self.subTest(markers=markers), self.assertRaises(ValueError):
                cell.apply_update(update(markers), {4: set(), 6: set()}, 2, 2000)
        inventories = {4: set(), 6: set()}
        cell.apply_update(update([2000]), inventories, 2, 2000)
        self.assertEqual(inventories[4], {0})

    def test_malformed_updates_fail_closed(self):
        for body in (b"", b"\0\x05\0\0", b"\0\0\0\x05", b"\0\0\0\0\x18\x14",
                     b"\0\0\0\x03\x80\x0e\x08"):
            with self.subTest(body=body), self.assertRaises(ValueError):
                cell.apply_update(body, {4: set(), 6: set()}, 10)

    def test_both_open_capabilities_are_required(self):
        def message(caps):
            options = bytes([2, len(caps)]) + caps
            return struct.pack("!BHH4sB", 4, 65000, 180, b"\x0a\0\0\1", len(options)) + options
        v4 = b"\x01\x04\0\x01\0\x01"
        v6 = b"\x01\x04\0\x02\0\x01"
        cell.check_open(message(v4 + v6))
        with self.assertRaises(ValueError):
            cell.check_open(message(v4))
        with self.assertRaises(ValueError):
            cell.check_open(message(v4 + v6)[:-1])

    def test_tcp_identity_flaps_and_uptime_are_independent_gates(self):
        original = {"127.1.0.1": {"socket": ["0100007F:06FE", "0100017F:A123", "12345"], "flaps": 0, "uptime": 100}}
        cell.check_continuity(original, copy.deepcopy(original))
        for field, value in (("socket", ["0100007F:06FE", "0100017F:A123", "67890"]),
                             ("flaps", 1), ("uptime", 1)):
            changed = copy.deepcopy(original)
            changed["127.1.0.1"][field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError):
                cell.check_continuity(original, changed)

    def test_snapshot_honors_omitted_false_stale_field(self):
        row = {"address": cell.address(0), "state": "Established", "uptime_seconds": 100, "flap_count": 0}
        proc = "header\n0: 0100007F:06FE 0100017F:ABCD 01 0:0 00:0 0 1000 0 12345\n"
        with patch.object(cell, "cli", return_value=[row]), patch.object(Path, "read_text", return_value=proc):
            _, core = cell.snapshot(Path("/unused"), "rbgp", 1790, 1)
            self.assertEqual(core[cell.address(0)]["socket"], ["0100007F:06FE", "0100017F:ABCD", "12345"])
            row["stale"] = True
            with self.assertRaises(AssertionError):
                cell.snapshot(Path("/unused"), "rbgp", 1790, 1)


class GateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        historical = Path(__file__).resolve().parents[3] / "docs/perf/artifacts/ixp-dualstack-final-campaign-2026-09/200-50-P"
        self.daemon = self.root / "rustbgpd"
        self.daemon.mkdir()
        for filename in ("driver.exit", "driver.log"):
            (self.root / filename).write_bytes((historical / filename).read_bytes())
        for filename in ("status", "reloadstall.log", "probes.csv", "queries.csv", "rss.csv", "vmhwm", "quiet.tsv"):
            (self.daemon / filename).write_bytes((historical / "rustbgpd" / filename).read_bytes())
        (self.daemon / "daemon.log").write_bytes(gzip.decompress((historical / "rustbgpd/daemon.log.gz").read_bytes()))
        self.scenario = self.daemon / "scenario"
        self.scenario.mkdir()
        # Synthetic supplemental evidence tests gate behavior only. The existing
        # historical wire/probe receipt is copied unchanged into this tempdir.
        self.core = {cell.address(i): {"socket": ["local", str(i), str(i + 100)], "flaps": 0, "uptime": 100} for i in range(200)}
        for generation in range(5):
            names = sorted(cell.dataset_names(cell.roster(200, generation)))
            receipt = {"generation": generation, "members": sorted(cell.address(i) for i in cell.roster(200, generation)),
                       "datasets": names, "dataset_status": [{"name": name, "records": 1, "last_error": None} for name in names],
                       "core": self.core, "stage_to_join_seconds": 1 if generation else None,
                       "joining": [{"address": cell.address(200 + generation * 2 + offset), "md5": offset == 0,
                                    "export_marker": f"65400:{2000 if generation % 2 else 1000}",
                                    "ipv4": 57200, "ipv6": 57200} for offset in (0, 1)]}
            cell.write_json(self.scenario / f"membership-{generation}.json", receipt)
            cell.write_json(self.scenario / f"before-{generation}.json", self.core)
            (self.scenario / f"metrics-{generation}.txt").write_text("".join(
                f'bgp_policy_dataset_loaded_timestamp_seconds{{dataset="{name}"}} 1\n' for name in names))
        (self.scenario / "membership-finish").mkdir()
        (self.scenario / "membership-finish/ack").write_text("membership gates passed\n")

    def check(self):
        return gate.check(self.root, 200, 114400, 57200, 170, 0)

    def test_positive_and_independent_missing_inventory_and_continuity_failures(self):
        self.assertTrue(self.check()["pass"], self.check()["errors"])
        path = self.scenario / "membership-2.json"
        original = json.loads(path.read_text())
        for mutate in (lambda row: row["joining"][0].update(ipv6=57199),
                       lambda row: row["core"][cell.address(0)].update(flaps=1),
                       lambda row: row["dataset_status"].pop(),
                       lambda row: row.update(stage_to_join_seconds=61)):
            row = copy.deepcopy(original)
            mutate(row)
            cell.write_json(path, row)
            self.assertFalse(self.check()["pass"])
        cell.write_json(path, original)
        (self.scenario / "metrics-2.txt").write_text('bgp_policy_dataset_loaded_timestamp_seconds{dataset="client-200-origins"} 1\n')
        self.assertFalse(self.check()["pass"])

    def test_core_loss_cannot_hide_behind_an_intentional_member_departure(self):
        log = self.daemon / "daemon.log"
        events = [json.loads(line) for line in log.read_text().splitlines() if line.startswith("{")]
        reload = next(event for event in events if event["fields"].get("message") == "reload route classified")
        event = {"timestamp": reload["timestamp"], "level": "INFO", "fields": {"message": "session down", "peer": cell.address(0)}}
        with log.open("a") as stream:
            stream.write(json.dumps(event) + "\n")
        self.assertFalse(self.check()["pass"])


if __name__ == "__main__":
    unittest.main()
