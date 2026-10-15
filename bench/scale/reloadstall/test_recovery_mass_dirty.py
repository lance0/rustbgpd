#!/usr/bin/env python3
"""Negative controls for the real-daemon qualification instrument."""

import argparse
import copy
import fcntl
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import socket
import sys
import tempfile
import tomllib
import time
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("mass_dirty", Path(__file__).with_name("recovery_mass_dirty.py"))
receipt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(receipt)


class MassDirtyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rmd-test-")
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_harness_evidence_does_not_wait_for_protocol_consumption(self):
        read_fd, write_fd = os.pipe()
        try:
            capacity = fcntl.fcntl(write_fd, fcntl.F_GETPIPE_SZ)
        finally:
            os.close(read_fd)
            os.close(write_fd)
        line = 'mass_dirty_readiness {"status":200,"deadline_ms":250,"elapsed_seconds":null}\n'
        count = max(1024 * 1024, capacity * 4) // len(line) + 1
        script = (f"import sys; sys.stdout.write({line!r} * {count}); "
                  "sys.stdout.flush(); print('mass_dirty_ready {\"complete\":true}', flush=True)")
        path = self.root / "harness.log"
        with path.open("w") as log, (self.root / "harness.stderr").open("w") as errors:
            child = receipt.start_harness([sys.executable, "-c", script], log, errors)
            try:
                # No stdout consumer exists while the producer fills more than
                # an actual pipe's capacity. This must finish independently.
                self.assertEqual(child.wait(timeout=5), 0)
                with path.open() as records:
                    self.assertEqual(receipt.read_record(child, records, "mass_dirty_ready", time.monotonic() + 5),
                                     {"complete": True})
                self.assertEqual(path.read_text().splitlines(), [line.rstrip()] * count +
                                 ['mass_dirty_ready {"complete":true}'])
            finally:
                receipt.stop_owned(child)
                if child.stdin is not None:
                    child.stdin.close()
                if child.stdout is not None:
                    child.stdout.close()

    def test_harness_tail_waits_for_partial_records_and_fails_on_death_or_deadline(self):
        child = mock.Mock(returncode=None)
        child.poll.return_value = None
        records = mock.Mock()
        records.readline.side_effect = ['mass_dirty_ready {', '', '"complete":true}\n']
        with mock.patch.object(receipt.time, "sleep") as wait:
            self.assertEqual(receipt.read_record(child, records, "mass_dirty_ready", time.monotonic() + 5),
                             {"complete": True})
        wait.assert_called_once()
        child.returncode = 7
        child.poll.return_value = 7
        with self.assertRaisesRegex(ValueError, "harness exited before"):
            receipt.read_record(child, io.StringIO('mass_dirty_ready {'), "mass_dirty_ready", time.monotonic() + 5)
        with self.assertRaisesRegex(TimeoutError, "fixed leg deadline"):
            receipt.read_record(child, io.StringIO(''), "mass_dirty_ready", time.monotonic() - 1)

    def test_fixture_snapshot_skips_socket_and_preserves_initiating_error(self):
        source = self.root / "fixture-source"
        source.mkdir()
        (source / "config.toml").write_text("configuration")
        (source / "data").mkdir()
        (source / "data" / "generation.list").write_text("64500\n")
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(source / "grpc.sock"))
            with self.assertRaisesRegex(RuntimeError, "initiating reload failure"):
                try:
                    raise RuntimeError("initiating reload failure")
                finally:
                    receipt.copy_fixture(source, self.root / "fixture-snapshot")
        self.assertEqual((self.root / "fixture-snapshot/config.toml").read_text(), "configuration")
        self.assertEqual((self.root / "fixture-snapshot/data/generation.list").read_text(), "64500\n")
        self.assertFalse((self.root / "fixture-snapshot/grpc.sock").exists())

    def test_readiness_covers_each_full_operation_with_bracket_probes_and_no_gaps(self):
        def fixture():
            probes = [{"sequence": index + 1, "status": 200, "deadline_ms": 250,
                       "elapsed_seconds": .01, "started_monotonic_seconds": float(100 + index),
                       "finished_monotonic_seconds": 100.01 + index} for index in range(7)]
            records = {"mass_dirty_exit": [{"status": "PASS", "readiness_samples": 7, "readiness_deadline_ms": 250}],
                       "mass_dirty_readiness": probes}
            operations = [{"trigger_monotonic_seconds": start, "drain_monotonic_seconds": start + .1,
                           "resume_monotonic_seconds": start + .2, "fold_monotonic_seconds": start + 2,
                           "trigger_to_drain_seconds": .1, "drain_to_resume_seconds": .1,
                           "resume_to_observed_fold_seconds": 1.8, "trigger_to_fold_seconds": 2}
                          for start in (100.5, 103.5)]
            return records, operations

        records, operations = fixture()
        self.assertEqual(receipt.readiness_coverage(records, operations, False),
                         [{"sample_count": 4, "max_start_gap_seconds": 1.0}] * 2)
        for mutation in ("before-b", "after-a", "gap", "sequence", "backward", "nonfinite", "late", "phase", "duration"):
            with self.subTest(mutation=mutation):
                records, operations = fixture()
                probes = records["mass_dirty_readiness"]
                if mutation in ("before-b", "after-a"):
                    probes.pop(0 if mutation == "before-b" else -1)
                    for index, probe in enumerate(probes):
                        probe["sequence"] = index + 1
                    records["mass_dirty_exit"][0]["readiness_samples"] = len(probes)
                elif mutation == "gap":
                    probes[1]["started_monotonic_seconds"] += .3
                    probes[1]["finished_monotonic_seconds"] += .3
                elif mutation == "sequence":
                    probes[1]["sequence"] = 1
                elif mutation == "backward":
                    probes[1]["started_monotonic_seconds"] = 99
                elif mutation == "nonfinite":
                    probes[1]["finished_monotonic_seconds"] = float("nan")
                elif mutation == "late":
                    probes[1]["finished_monotonic_seconds"] += .251
                elif mutation == "phase":
                    operations[0]["resume_monotonic_seconds"] = 99
                else:
                    operations[0]["trigger_to_fold_seconds"] = 1
                with self.assertRaises(ValueError):
                    receipt.readiness_coverage(records, operations, False)

    def test_identical_daemons_fail_even_with_matching_binary_roster(self):
        binaries = self.root / "bin"
        binaries.mkdir()
        for name, contents in (("rustbgpd-candidate", "same daemon"), ("rustbgpd-flat", "same daemon"),
                               ("reloadstall", "observer"), ("rbgp", "client")):
            (binaries / name).write_text(contents)
        (self.root / "binaries.sha256").write_text("".join(
            f"{receipt.digest(path)}  {path}\n" for path in sorted(binaries.iterdir())))
        with self.assertRaisesRegex(ValueError, "candidate and flat daemon binaries are identical"):
            receipt.verified_binaries(self.root)

    def manifest(self, correctness=True, cohort="no-refusal"):
        cpus = sorted(os.sched_getaffinity(0))
        if len(cpus) < 2:
            self.skipTest("requires two assigned CPUs")
        root = self.root / "campaign"
        args = argparse.Namespace(output=str(root), head="a" * 40, profile="full-vpn", cohort=cohort,
                                  daemon_cpus=str(cpus[0]), harness_cpus=str(cpus[1]), correctness_only=correctness)
        return root, receipt.init(args)

    def test_fixed_policy_and_raw_family_split(self):
        for profile, pressure in (("full-uc", False), ("full-vpn", False), ("full-uc", True), ("full-vpn", True)):
            scenario = self.root / f"{profile}-{pressure}"
            hashes = receipt.generate(scenario, profile, 12, 17986, 19186, pressure=pressure)
            self.assertEqual(scenario.stat().st_mode & 0o777, 0o700)
            config = tomllib.loads((scenario / "config.toml").read_text())
            self.assertEqual(config["config_epoch"], 2)
            self.assertTrue(config["global"]["ebgp_requires_policy"])
            self.assertEqual(len(config["neighbors"]), 13)
            self.assertFalse(config["neighbors"][0]["route_reflector_client"])
            self.assertTrue(all(row["route_reflector_client"] for row in config["neighbors"][1:]))
            expected = ["l3vpn_ipv4_unicast", "l3vpn_ipv6_unicast"] if profile == "full-vpn" else ["ipv4_unicast", "ipv6_unicast"]
            self.assertEqual(config["neighbors"][0]["families"], expected)
            policy = (scenario / "member.rpol").read_text()
            self.assertIn("route.origin-as in generation_b", policy)
            self.assertNotIn("peer.asn", policy)
            self.assertEqual("route.prefix in denied" in policy, pressure)
            before = receipt.digest(scenario / "member.rpol")
            stimulus = receipt.wire_stimulus()
            origins = [int(value) for value in (scenario / "generation.list").read_text().splitlines()]
            self.assertEqual(origins, [stimulus["origin_base"] + 2 * chunk + 1
                                       for chunk in range(stimulus["origin_cardinality"])])
            self.assertEqual(len(origins), 15375)
            self.assertNotIn(64512, origins)
            self.assertEqual(set(hashes), {"config.toml", "member.rpol", "generation.list"})
            self.assertEqual(receipt.digest(scenario / "member.rpol"), before)
            self.assertEqual(hashes["member.rpol"], before)
            self.assertEqual(receipt.profile_shape(profile), [1_000_000, 230_000])

    def test_source_derivation_changes_only_full_capture_boolean(self):
        source = self.root / "update_groups.rs"
        before = ("    fn capture_group_admitted_keys_inner(\n"
                  "        let captured = ledger.capture_full_old_with_checkpoint(\n"
                  "            peer, hint, &group.table, !group.stages_vpn(), uc, vpn, checkpoint,\n"
                  "        );\n    }\n"
                  "    pub(in crate::manager) fn prepare_empty_group_recovery_admission() {\n"
                  "        let still_shared = !group.stages_vpn();\n    }\n")
        source.write_text(before)
        metadata = receipt.derive_flat(source, self.root / "derivation.json")
        self.assertEqual(source.read_text(), before.replace("&group.table, !group.stages_vpn(),", "&group.table, false,", 1))
        self.assertTrue(metadata["vpn_full_old_already_flat"])
        self.assertEqual(metadata["expression_before"], "!group.stages_vpn()")
        with self.assertRaisesRegex(ValueError, "guard anchor drift"):
            receipt.derive_flat(source, self.root / "second.json")

    def test_derivation_refuses_old_sorted_candidate_instead_of_relabeling_it(self):
        source = self.root / "old.rs"
        source.write_text("    fn capture_group_admitted_keys_inner(\nlet shared = ledger.with_ordered_capture();\n    pub(in crate::manager) fn prepare_empty_group_recovery_admission")
        with self.assertRaisesRegex(ValueError, "helper anchor drift"):
            receipt.derive_flat(source, self.root / "derivation.json")

    def test_cohorts_resources_and_bars_are_frozen_before_results(self):
        root, manifest = self.manifest(correctness=False, cohort="cap-pressure")
        self.assertEqual(manifest["receivers"], 24)
        self.assertEqual(manifest["limits"]["daemon_bytes"], 10 * 1024 ** 3)
        self.assertEqual(manifest["limits"]["harness_bytes"], 2 * 1024 ** 3)
        self.assertEqual(manifest["limits"]["readiness_deadline_ms"], 250)
        self.assertEqual(manifest["limits"]["convergence_relative"], 1.10)
        self.assertEqual(manifest["limits"]["convergence_absolute_seconds"], .030)
        self.assertIn("ingress fill, cold capture and dirty witness", manifest["primary_convergence"])
        manifest["receivers"] = 12
        receipt.write_json(root / "campaign.json", manifest)
        with self.assertRaisesRegex(ValueError, "campaign changed"):
            receipt.load_manifest(root)

    def test_cpu_overlap_is_refused(self):
        cpu = str(next(iter(os.sched_getaffinity(0))))
        args = argparse.Namespace(output=str(self.root / "bad"), head="a" * 40, profile="full-uc", cohort="no-refusal",
                                  daemon_cpus=cpu, harness_cpus=cpu, correctness_only=True)
        with self.assertRaisesRegex(ValueError, "overlap"):
            receipt.init(args)

    def test_manifest_cannot_omit_or_reorder_required_operations(self):
        root, original = self.manifest(correctness=False)
        mutations = ({"schedule": []}, {"schedule": ["flat"]},
                     {"schedule": ["flat"] * 6}, {"schedule": original["schedule"][::-1]},
                     {"repetitions": 0}, {"repetitions": True}, {"correctness_only": True},
                     {"correctness_only": "false"}, {"schema": "unqualified"},
                     {"inputs": {}}, {"support_inputs": {}}, {"profile": "unknown"},
                     {"cohort": "unknown"}, {"head": "not-a-source"})
        for change in mutations:
            with self.subTest(change=change):
                receipt.write_json(root / "campaign.json", {**original, **change})
                (root / "campaign.sha256").write_text(receipt.digest(root / "campaign.json") + "\n")
                with self.assertRaises(ValueError):
                    receipt.load_manifest(root)

    def test_dirty_witness_requires_actual_each_peer_and_unchanged_group(self):
        def row(index):
            return {"state": "Established", "slow_peer": False, "outbound_resync_pending": True,
                    "update_group": "group:7", "update_group_recovery_fallback": "", "address": receipt.peer(index)}
        with mock.patch.object(receipt, "command", side_effect=[json.dumps(row(1)), json.dumps(row(2))]):
            actual = receipt.neighbor_witness("rbgp", "unix:///owned.sock", 2, pending=True)
            self.assertEqual(len(actual), 2)
        omitted = row(1)
        omitted.pop("slow_peer")
        with mock.patch.object(receipt, "command", side_effect=[json.dumps(omitted), json.dumps(row(2))]):
            receipt.neighbor_witness("rbgp", "unix:///owned.sock", 2, pending=True)
        for invalid in ({**row(1), "slow_peer": True}, {**row(1), "slow_peer": 0},
                        {**row(1), "address": receipt.peer(2)}):
            with mock.patch.object(receipt, "command", return_value=json.dumps(invalid)), self.assertRaises(ValueError):
                receipt.neighbor_witness("rbgp", "unix:///owned.sock", 2, pending=True)
        bad = row(2)
        bad["outbound_resync_pending"] = False
        with mock.patch.object(receipt, "command", side_effect=[json.dumps(row(1)), json.dumps(bad)]):
            with self.assertRaisesRegex(ValueError, "actual dirty"):
                receipt.neighbor_witness("rbgp", "unix:///owned.sock", 2, pending=True)
        with mock.patch.object(receipt, "command", side_effect=[json.dumps(row(1)), json.dumps(row(2))]):
            with self.assertRaisesRegex(ValueError, "group identity"):
                receipt.neighbor_witness("rbgp", "unix:///owned.sock", 2, expected=[(receipt.peer(1), "group:6"), (receipt.peer(2), "group:6")], pending=True)

    def test_all_fallback_causes_are_required(self):
        text = "\n".join(f'bgp_update_group_recovery_fallback_total{{cause="{cause}"}} 0' for cause in receipt.CAUSES)
        self.assertEqual(receipt.fallback(text), dict.fromkeys(receipt.CAUSES, 0))
        with self.assertRaisesRegex(ValueError, "missing/invalid metric"):
            receipt.fallback(text.replace('cause="missing_proof"', 'cause="other"'))

    def test_held_episode_receipt_binds_raw_current_state_and_both_sweeps(self):
        identities = [(receipt.peer(i), "group:7") for i in (1, 2)]

        def row(index, begin):
            return {"peer": receipt.peer(index), "group": "group:7", "pending": True, "dirty_seconds": 3,
                    "query_begin_monotonic_seconds": begin, "query_end_monotonic_seconds": begin + .1,
                    "raw": {"address": receipt.peer(index), "state": "Established", "update_group": "group:7",
                            "outbound_resync_pending": True, "outbound_dirty_seconds": 3}}

        sweeps = [[row(1, 10), row(2, 10.2)], [row(1, 10.5), row(2, 10.7)]]
        witness = {"sweeps": sweeps, "overlap": [receipt.dirty_overlap(rows) for rows in sweeps],
                   "stable_overlap": receipt.dirty_overlap([item for rows in sweeps for item in rows]),
                   "source": {"address": receipt.peer(0), "state": "Established", "outbound_resync_pending": False}}
        operation = {"trigger_monotonic_seconds": 8, "drain_monotonic_seconds": 9, "resume_monotonic_seconds": 12}
        # The conservative interval begins before trigger; its intersection
        # with this operation still supplies a valid common dirty instant.
        receipt.validate_held_witness(witness, identities, False, operation)
        for mutation in ("pending", "raw-age", "source", "overlap", "clock", "epoch-reset", "shifted", "reused-b", "sweep-order"):
            altered = copy.deepcopy(witness)
            bounds = operation
            if mutation == "source":
                altered["source"]["outbound_resync_pending"] = True
            elif mutation == "overlap":
                altered["stable_overlap"]["begin_monotonic_seconds"] += .1
            elif mutation == "raw-age":
                altered["sweeps"][0][0]["raw"]["outbound_dirty_seconds"] = 2
            elif mutation == "clock":
                altered["sweeps"][0][0]["query_begin_monotonic_seconds"] = None
            elif mutation == "pending":
                altered["sweeps"][0][0]["pending"] = False
            elif mutation == "shifted":
                for rows in altered["sweeps"]:
                    for item in rows:
                        item["query_begin_monotonic_seconds"] += 20
                        item["query_end_monotonic_seconds"] += 20
                altered["overlap"] = [receipt.dirty_overlap(rows) for rows in altered["sweeps"]]
                altered["stable_overlap"] = receipt.dirty_overlap([item for rows in altered["sweeps"] for item in rows])
            elif mutation == "reused-b":
                bounds = {"trigger_monotonic_seconds": 18, "drain_monotonic_seconds": 19, "resume_monotonic_seconds": 22}
            elif mutation == "sweep-order":
                altered["sweeps"][0][0]["query_begin_monotonic_seconds"] = 10.4
                altered["sweeps"][0][0]["query_end_monotonic_seconds"] = 10.5
                altered["overlap"][0] = receipt.dirty_overlap(altered["sweeps"][0])
                altered["stable_overlap"] = receipt.dirty_overlap([item for rows in altered["sweeps"] for item in rows])
            else:
                altered["sweeps"][1] = [row(1, 20), row(2, 20.2)]
                altered["overlap"][1] = receipt.dirty_overlap(altered["sweeps"][1])
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                receipt.validate_held_witness(altered, identities, False, bounds)

    def test_retained_fixture_files_are_verified_independently_of_top_level_raw_hashes(self):
        _, manifest = self.manifest(cohort="cap-pressure")
        for mutation in ("config.toml", "member.rpol", "generation.list", "missing-roster", "extra-roster"):
            with self.subTest(mutation=mutation):
                leg, row = self.small_leg(manifest)
                receipt.validate_leg(leg, manifest, row)
                if mutation in receipt.FIXTURE_INPUTS:
                    path = leg / "fixture" / mutation
                    path.write_text(path.read_text() + "\nchanged retained input\n")
                    expected = "retained fixture input changed"
                else:
                    path = leg / "fixture.sha256.json"
                    hashes = json.loads(path.read_text())
                    if mutation == "missing-roster":
                        hashes.pop("generation.list")
                    else:
                        hashes["unrelated"] = "a" * 64
                    receipt.write_json(path, hashes)
                    expected = "fixture input roster differs"
                row["raw_sha256"] = self.raw_hashes(leg)
                with self.assertRaisesRegex(ValueError, expected):
                    receipt.validate_leg(leg, manifest, row)

    def test_metric_duplicate_and_nonfinite_refused(self):
        for text in ("metric 1\nmetric 1", "metric NaN", "metric -1"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                receipt.metric(text, "metric")

    def test_cleanup_signals_only_verified_held_child_and_waits(self):
        child = mock.Mock(pid=123, qualification_starttime=77)
        child.poll.return_value = None
        child.wait.side_effect = [subprocess.TimeoutExpired("owned", 15), 0]
        with mock.patch.object(receipt, "child_starttime", return_value=77), mock.patch.object(receipt.os, "killpg") as groups:
            receipt.stop_owned(child)
        child.terminate.assert_called_once_with()
        child.kill.assert_called_once_with()
        self.assertEqual(child.wait.call_count, 2)
        groups.assert_not_called()
        child.reset_mock()
        with mock.patch.object(receipt, "child_starttime", return_value=78):
            with self.assertRaisesRegex(ValueError, "identity changed"):
                receipt.stop_owned(child)
        child.terminate.assert_not_called()
        child.kill.assert_not_called()
        child.pid = -123
        with self.assertRaisesRegex(ValueError, "invalid owned child PID"):
            receipt.stop_owned(child)

    def test_recovery_charge_requires_all_integer_gauges_without_capping_attempted_peak(self):
        valid = ("bgp_update_group_recovery_entries 0\n"
                 "bgp_update_group_recovery_bytes 1024\n"
                 "bgp_update_group_recovery_peak_bytes 600000000\n")
        self.assertEqual(receipt.recovery_charge(valid)["peak_bytes"], 600_000_000)
        for broken in (valid.replace("bgp_update_group_recovery_entries 0\n", ""),
                       valid.replace("bytes 1024", "bytes NaN"),
                       valid.replace("entries 0", "entries 0.5"),
                       valid.replace("bytes 1024", "bytes -1")):
            with self.subTest(broken=broken), self.assertRaises(ValueError):
                receipt.recovery_charge(broken)

    def test_missing_or_failed_driver_cannot_finalize_green(self):
        root, _ = self.manifest()
        self.assertEqual(receipt.finalize(root)["status"], "INVALID")
        (root / "driver.exit").write_text("1\n")
        self.assertEqual(receipt.finalize(root)["status"], "INVALID")
        (root / "driver.exit").write_text("0\n")
        self.assertEqual(receipt.finalize(root)["status"], "INVALID")

    def test_actual_broken_fold_is_rejected_even_with_pass_status(self):
        _, manifest = self.manifest(cohort="cap-pressure")
        leg, row = self.small_leg(manifest)
        receipt.validate_leg(leg, manifest, row)
        for mutation in ("missing-withdraw", "dirty-cleared", "group-replaced", "no-readiness", "timing-in-correctness", "retained-proof", "retained-charge", "held-proof-empty", "source-dirty", "missing-churn-drain", "dirty-proof-missing"):
            with self.subTest(mutation=mutation):
                # A failed subtest must not leak mutated raw evidence into the
                # next control, including intentional predicate-removal runs.
                leg, row = self.small_leg(manifest)
                altered = copy.deepcopy(row)
                if mutation == "timing-in-correctness":
                    altered["operations"][0]["trigger_to_fold_seconds"] = 1.0
                else:
                    if mutation == "missing-withdraw":
                        records = (leg / "harness.log").read_text().replace('"withdrawals": 16', '"withdrawals": 15')
                        (leg / "harness.log").write_text(records)
                    elif mutation == "dirty-cleared":
                        path = leg / "daemon-window-b.jsonl"
                        values = path.read_text().replace('"dirty": true', '"dirty": false', 1)
                        path.write_text(values)
                    elif mutation == "group-replaced":
                        values = json.loads((leg / "neighbors-settled-a.json").read_text())
                        values[0]["group"] = "group:8"
                        receipt.write_json(leg / "neighbors-settled-a.json", values)
                    elif mutation == "held-proof-empty":
                        path = leg / "metrics-paused-b.prom"
                        path.write_text(path.read_text().replace(f"recovery_entries {altered['operations'][0]['recovery_paused']['entries']}", "recovery_entries 0"))
                        altered["operations"][0]["recovery_paused"] = {
                            **altered["operations"][0]["recovery_paused"], "entries": 0}
                    elif mutation == "source-dirty":
                        path = leg / "source-settled-a.json"
                        values = json.loads(path.read_text())
                        values["outbound_resync_pending"] = True
                        receipt.write_json(path, values)
                    elif mutation == "missing-churn-drain":
                        path = leg / "harness.log"
                        path.write_text(path.read_text().replace('"writer_drained": true', '"writer_drained": false', 1))
                    elif mutation == "dirty-proof-missing":
                        path = leg / "neighbors-paused-b.json"
                        values = json.loads(path.read_text())
                        values["stable_overlap"]["proved"] = False
                        receipt.write_json(path, values)
                    elif mutation in ("retained-proof", "retained-charge"):
                        path = leg / "metrics-settled-a.prom"
                        field, old, new = ("entries", 0, 1) if mutation == "retained-proof" else ("bytes", 1024, 1025)
                        path.write_text(path.read_text().replace(f"recovery_{field} {old}", f"recovery_{field} {new}"))
                        altered["operations"][1]["recovery_settled"] = {
                            **altered["operations"][1]["recovery_settled"], field: new}
                    else:
                        text = (leg / "harness.log").read_text().replace('"readiness_samples": 1', '"readiness_samples": 0')
                        (leg / "harness.log").write_text(text)
                expected_error = "settled recovery charge did not return to empty baseline" if mutation in ("retained-proof", "retained-charge") else ".*"
                altered["raw_sha256"] = self.raw_hashes(leg)
                with self.assertRaisesRegex(ValueError, expected_error):
                    receipt.validate_leg(leg, manifest, altered)

    def test_fallback_deltas_use_each_churn_baseline(self):
        _, manifest = self.manifest(cohort="cap-pressure")
        for cause in receipt.CAUSES:
            with self.subTest(cause=cause):
                leg, row = self.small_leg(manifest)
                self.set_fallback_chain(leg, row, cause, [0, 0, 7, 7, 7, 7, 7])
                receipt.validate_leg(leg, manifest, row)
                self.assertEqual([operation["fallback_deltas"][cause] for operation in row["operations"]], [7, 0])
                row["operations"][1]["fallback_deltas"][cause] = 7
                with self.assertRaisesRegex(ValueError, "fallback derivation differs"):
                    receipt.validate_leg(leg, manifest, row)

    def test_fallback_counters_cannot_decrease_between_consecutive_snapshots(self):
        _, manifest = self.manifest(cohort="cap-pressure")
        for cause in receipt.CAUSES:
            for edge in range(1, 7):
                with self.subTest(cause=cause, edge=edge):
                    leg, row = self.small_leg(manifest)
                    counts = [0] * 7
                    counts[edge - 1] = 3
                    counts[edge:] = [2] * (7 - edge)
                    self.set_fallback_chain(leg, row, cause, counts)
                    with self.assertRaisesRegex(ValueError, "fallback counter regressed"):
                        receipt.validate_leg(leg, manifest, row)

    def test_no_refusal_cannot_hide_fallback_before_churn(self):
        _, manifest = self.manifest()
        leg, row = self.small_leg(manifest)
        self.set_fallback_chain(leg, row, "daemon_limit", [0, 7, 7, 7, 7, 7, 7])
        with self.assertRaisesRegex(ValueError, "no-refusal.*fallback"):
            receipt.validate_leg(leg, manifest, row)

    def test_operation_log_evidence_cannot_be_reused_from_another_generation(self):
        _, manifest = self.manifest(cohort="cap-pressure")
        leg, row = self.small_leg(manifest)
        receipt.validate_leg(leg, manifest, row)
        cursors = row["operations"][1]["daemon_log_bytes"]
        full_log = (leg / "daemon.log").read_bytes()
        replacement = b'{"fields":{"message":"no resync in A"}}\n'
        changed = full_log[:cursors["resume"]] + replacement + full_log[cursors["end"]:]
        cursors["end"] = cursors["resume"] + len(replacement)
        (leg / "daemon.log").write_bytes(changed)
        (leg / "daemon-operation-a.jsonl").write_bytes(changed[cursors["start"]:cursors["end"]])
        for prefix in ("daemon-window", "dirty-receipts"):
            suffix = "jsonl" if prefix == "daemon-window" else "json"
            (leg / f"{prefix}-a.{suffix}").write_bytes((leg / f"{prefix}-b.{suffix}").read_bytes())
        row["raw_sha256"] = self.raw_hashes(leg)
        with self.assertRaisesRegex(ValueError, "post-resume log slice differs"):
            receipt.validate_leg(leg, manifest, row)

    def test_operation_log_byte_cursors_are_required_ordered_and_exact(self):
        _, manifest = self.manifest(cohort="cap-pressure")
        for mutation in ("missing", "missing-end", "bool", "float", "negative", "reversed", "out-of-bounds", "overlap", "shifted", "operation-bytes"):
            with self.subTest(mutation=mutation):
                leg, row = self.small_leg(manifest)
                operation = row["operations"][1]
                cursors = operation["daemon_log_bytes"]
                expected = "daemon log byte cursors"
                if mutation == "missing":
                    del operation["daemon_log_bytes"]
                elif mutation == "missing-end":
                    del cursors["end"]
                elif mutation == "bool":
                    cursors["start"] = True
                elif mutation == "float":
                    cursors["resume"] = float(cursors["resume"])
                elif mutation == "negative":
                    cursors["start"] = -1
                elif mutation == "reversed":
                    cursors["resume"] = cursors["start"] - 1
                elif mutation == "out-of-bounds":
                    cursors["end"] = len((leg / "daemon.log").read_bytes()) + 1
                elif mutation == "overlap":
                    cursors["start"] = row["operations"][0]["daemon_log_bytes"]["start"]
                elif mutation == "shifted":
                    cursors["start"] += 1
                else:
                    (leg / "daemon-operation-a.jsonl").write_bytes(b"different operation\n")
                    expected = "operation log slice differs"
                row["raw_sha256"] = self.raw_hashes(leg)
                with self.assertRaisesRegex(ValueError, expected):
                    receipt.validate_leg(leg, manifest, row)

    def test_raw_evidence_hash_roster_cannot_omit_any_file(self):
        _, manifest = self.manifest(cohort="cap-pressure")
        leg, row = self.small_leg(manifest)
        self.assertIn("daemon.log", row["raw_sha256"])
        (leg / "result.json").write_text("{}\n")
        receipt.validate_leg(leg, manifest, row)
        for omitted in (None, *sorted(row["raw_sha256"])):
            with self.subTest(omitted=omitted):
                leg, row = self.small_leg(manifest)
                if omitted is None:
                    row["raw_sha256"].clear()
                else:
                    del row["raw_sha256"][omitted]
                with self.assertRaisesRegex(ValueError, "raw evidence hash roster differs"):
                    receipt.validate_leg(leg, manifest, row)

    def test_omitted_daemon_digest_cannot_hide_unrelated_log_tampering(self):
        _, manifest = self.manifest(cohort="cap-pressure")
        leg, row = self.small_leg(manifest)
        path = leg / "daemon.log"
        original = path.read_bytes()
        changed = original.replace(b'"startup"', b'"changed"', 1)
        self.assertNotEqual(original, changed)
        self.assertEqual(len(original), len(changed))
        path.write_bytes(changed)
        del row["raw_sha256"]["daemon.log"]
        with self.assertRaisesRegex(ValueError, "raw evidence hash roster differs"):
            receipt.validate_leg(leg, manifest, row)

    def test_complete_hash_roster_does_not_make_consumed_files_optional(self):
        _, manifest = self.manifest(cohort="cap-pressure")
        leg, row = self.small_leg(manifest)
        for name in sorted(row["raw_sha256"]):
            with self.subTest(missing=name):
                leg, row = self.small_leg(manifest)
                (leg / name).unlink()
                row["raw_sha256"] = self.raw_hashes(leg)
                expected = ValueError if name == "config-check.log" else FileNotFoundError
                with self.assertRaises(expected):
                    receipt.validate_leg(leg, manifest, row)

    def raw_hashes(self, leg):
        return {path.name: receipt.digest(path) for path in leg.iterdir() if path.is_file() and path.name != "result.json"}

    def set_fallback_chain(self, leg, row, cause, counts):
        self.assertEqual(len(counts), 7)
        phases = ("initial", "before-b", "paused-b", "settled-b", "before-a", "paused-a", "settled-a")
        metric = f'bgp_update_group_recovery_fallback_total{{cause="{cause}"}}'
        for phase, count in zip(phases, counts, strict=True):
            path = leg / f"metrics-{phase}.prom"
            path.write_text("\n".join(f"{metric} {count}" if line.startswith(metric + " ") else line
                                      for line in path.read_text().splitlines()) + "\n")
        row["fallback_initial"][cause] = counts[0]
        for index, before in enumerate((1, 4)):
            row["operations"][index]["fallback_before"][cause] = counts[before]
            row["operations"][index]["fallback_deltas"][cause] = counts[before + 2] - counts[before]
        row["raw_sha256"] = self.raw_hashes(leg)

    def small_leg(self, manifest):
        leg = self.root / "small-leg"
        leg.mkdir(exist_ok=True)
        row = {"daemon_exit": 0, "harness_exit": 0, "config_check_exit": 0, "raw_sha256": {}, "operations": []}
        charge = {"entries": 0, "bytes": 1024, "peak_bytes": 2048}
        held_charge = {"entries": manifest["receivers"] * sum(manifest["family_keys"]),
                       "bytes": manifest["receivers"] * sum(manifest["family_keys"]) * 32 + 1024}
        held_charge["peak_bytes"] = held_charge["bytes"]
        row["recovery_initial"] = charge
        row["fallback_initial"] = dict.fromkeys(receipt.CAUSES, 0)
        fixture = leg / "fixture"
        fixture.mkdir(exist_ok=True)
        for name in receipt.FIXTURE_INPUTS:
            (fixture / name).write_text(f"original {name}\n")
        receipt.write_json(leg / "fixture.sha256.json", {name: receipt.digest(fixture / name) for name in receipt.FIXTURE_INPUTS})
        (leg / "config-check.log").write_text("strict config validation passed\n")
        stimulus = manifest["wire_stimulus"]
        ready = {"family_keys": manifest["family_keys"], "receivers": 2,
                 "bitmap_bytes": 2 * sum((count + 63) // 64 * 8 * 3 for count in manifest["family_keys"]),
                 "correctness_only": True, **{key: stimulus[key] for key in
                    ("batch_size", "origin_cardinality", "baseline_eor_messages", "receiver_receive_buffer_bytes")}}
        lines = ["mass_dirty_ready " + json.dumps(ready)]
        peers = [{"peer": receipt.peer(i), "group": "group:7", "pending": False} for i in (1, 2)]
        source = {"address": receipt.peer(0), "state": "Established", "outbound_resync_pending": False}
        receipt.write_json(leg / "source-initial.json", source)
        receipt.write_json(leg / "neighbors-initial.json", peers)
        def metrics(charge):
            return ("bgp_update_group_regroups_total 0\n" +
                    "\n".join(f'bgp_update_group_recovery_fallback_total{{cause="{cause}"}} 0' for cause in receipt.CAUSES) + "\n" +
                    "\n".join(f"bgp_update_group_recovery_{key} {value}" for key, value in charge.items()))
        (leg / "metrics-initial.prom").write_text(metrics(charge))
        daemon_log = bytearray(b'{"fields":{"message":"startup"}}\n')
        for generation in ("b", "a"):
            lines.append("mass_dirty_paused " + json.dumps({"generation": generation, "receivers": 2}))
            lines.append("mass_dirty_sent " + json.dumps({"generation": generation, "family_keys": manifest["family_keys"],
                "announcement_messages": stimulus["origin_cardinality"], "eor_messages": stimulus["origin_cardinality"],
                "origin_cardinality": stimulus["origin_cardinality"], "writer_drained": True, "drained_monotonic_seconds": None}))
            wire = {"generation": generation, "receivers": 2, "withdrawals": manifest["receivers"] * manifest["withdrawals_per_receiver"], "exact_fold": True,
                    "sessions_continuous": True, "resume_to_fold_p50_seconds": None, "resume_to_fold_max_seconds": None}
            lines.append("mass_dirty_complete " + json.dumps(wire))
            operation = {**wire, "fallback_before": dict.fromkeys(receipt.CAUSES, 0),
                         "fallback_deltas": dict.fromkeys(receipt.CAUSES, 0), "trigger_to_fold_seconds": None,
                         "recovery_paused": held_charge, "recovery_settled": {**charge, "peak_bytes": held_charge["peak_bytes"]},
                         "trigger_to_drain_seconds": None, "drain_to_resume_seconds": None, "resume_to_observed_fold_seconds": None,
                         "trigger_monotonic_seconds": None, "drain_monotonic_seconds": None,
                         "resume_monotonic_seconds": None, "fold_monotonic_seconds": None,
                         "readiness_coverage": {"sample_count": None, "max_start_gap_seconds": None}}
            row["operations"].append(operation)
            dirty = [{"message": "outbound routes resynced", "peer": item["peer"], "dirty": True, "force": False,
                      "generation": generation} for item in peers]
            start = len(daemon_log)
            daemon_log.extend(json.dumps({"fields": {"message": "held π", "generation": generation}}, ensure_ascii=False).encode() + b"\n")
            resume = len(daemon_log)
            window = ("\n".join(json.dumps({"fields": item}) for item in dirty) + "\n").encode()
            daemon_log.extend(window)
            end = len(daemon_log)
            operation["daemon_log_bytes"] = {"start": start, "resume": resume, "end": end}
            (leg / f"daemon-operation-{generation}.jsonl").write_bytes(daemon_log[start:end])
            (leg / f"daemon-window-{generation}.jsonl").write_bytes(window)
            daemon_log.extend(json.dumps({"fields": {"message": "settled", "generation": generation}}).encode() + b"\n")
            receipt.write_json(leg / f"dirty-receipts-{generation}.json", dirty)
            intervals = {"begin_monotonic_seconds": None, "end_monotonic_seconds": None, "proved": True}
            sweep = [{**item, "pending": True, "dirty_seconds": 2, "query_begin_monotonic_seconds": None,
                      "query_end_monotonic_seconds": None,
                      "raw": {"address": item["peer"], "state": "Established", "update_group": item["group"],
                              "outbound_resync_pending": True, "outbound_dirty_seconds": 2}} for item in peers]
            receipt.write_json(leg / f"neighbors-paused-{generation}.json",
                               {"sweeps": [sweep, sweep], "overlap": [intervals, intervals], "stable_overlap": intervals, "source": source})
            receipt.write_json(leg / f"neighbors-settled-{generation}.json", peers)
            receipt.write_json(leg / f"source-settled-{generation}.json", source)
            (leg / f"metrics-before-{generation}.prom").write_text(metrics(charge if generation == "b" else operation["recovery_settled"]))
            (leg / f"metrics-paused-{generation}.prom").write_text(metrics(held_charge))
            (leg / f"metrics-settled-{generation}.prom").write_text(metrics(operation["recovery_settled"]))
        lines.append("mass_dirty_exit " + json.dumps({"readiness_samples": 1, "readiness_deadline_ms": 250, "status": "PASS"}))
        lines.append("mass_dirty_readiness " + json.dumps({"sequence": 1, "status": 200, "deadline_ms": 250, "elapsed_seconds": None,
                                                          "started_monotonic_seconds": None, "finished_monotonic_seconds": None}))
        (leg / "harness.log").write_text("\n".join(lines) + "\n")
        (leg / "daemon.log").write_bytes(daemon_log)
        row["raw_sha256"] = self.raw_hashes(leg)
        return leg, row

    def test_real_dirty_receipt_target_set_cannot_be_fabricated_from_trigger(self):
        fields = [{"message": "outbound routes resynced", "peer": receipt.peer(i), "dirty": True, "force": False} for i in (1, 2)]
        text = lambda values: "\n".join(json.dumps({"fields": value}) for value in values)
        self.assertEqual(len(receipt.dirty_receipts(text(fields), 2)), 2)
        for bad in (fields[:1], fields + [{**fields[0], "peer": receipt.peer(3)}],
                    [{**fields[0], "dirty": False}, fields[1]], [{**fields[0], "force": True}, fields[1]]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                receipt.dirty_receipts(text(bad), 2)

    def test_dirty_episode_intersection_rejects_sequential_or_recreated_debt(self):
        def row(peer, begin, end, age):
            return {"peer": peer, "pending": True, "dirty_seconds": age,
                    "query_begin_monotonic_seconds": begin, "query_end_monotonic_seconds": end}
        actual = [row("one", 10.0, 10.1, 2), row("two", 10.5, 10.6, 2)]
        self.assertEqual(receipt.dirty_overlap(actual),
                         {"begin_monotonic_seconds": 8.6, "end_monotonic_seconds": 10.0, "proved": True})
        # Exact touching boundary is a real guaranteed common instant.
        self.assertTrue(receipt.dirty_overlap([row("one", 10, 10, 0), row("two", 11, 11, 1)])["proved"])
        for rows in ([row("one", 10, 10.1, 1), row("two", 12, 12.1, 1)],
                     actual + [row("one", 20, 20.1, 1), row("two", 20.5, 20.6, 1)],
                     [{**actual[0], "pending": False}, actual[1]],
                     [{**actual[0], "dirty_seconds": -1}, actual[1]],
                     [{**actual[0], "dirty_seconds": True}, actual[1]],
                     [row("one", 10, 10.1, 0)],
                     [row("one", float("nan"), 10.1, 1)]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                receipt.dirty_overlap(rows)



if __name__ == "__main__":
    unittest.main()
