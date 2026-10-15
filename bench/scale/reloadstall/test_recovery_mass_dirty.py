#!/usr/bin/env python3
"""Negative controls for the real-daemon qualification instrument."""

import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
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

    def manifest(self, correctness=True, cohort="no-refusal"):
        cpus = sorted(os.sched_getaffinity(0))
        if len(cpus) < 2:
            self.skipTest("requires two assigned CPUs")
        root = self.root / "campaign"
        args = argparse.Namespace(output=str(root), head="a" * 40, profile="full-vpn", cohort=cohort,
                                  daemon_cpus=str(cpus[0]), harness_cpus=str(cpus[1]), correctness_only=correctness)
        return root, receipt.init(args)

    def test_fixed_policy_and_raw_family_split(self):
        for profile in ("full-uc", "full-vpn"):
            scenario = self.root / profile
            hashes = receipt.generate(scenario, profile, 12, 17986, 19186)
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
            before = receipt.digest(scenario / "member.rpol")
            (scenario / "generation.list").write_text((scenario / "generation-b.list").read_text())
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
        self.assertIn("capture, settlement and dirty witness", manifest["primary_convergence"])
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
        for mutation in ("missing-withdraw", "dirty-cleared", "group-replaced", "no-readiness", "timing-in-correctness", "retained-proof", "retained-charge"):
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
                with self.assertRaisesRegex(ValueError, expected_error):
                    receipt.validate_leg(leg, manifest, altered)

    def small_leg(self, manifest):
        leg = self.root / "small-leg"
        leg.mkdir(exist_ok=True)
        row = {"daemon_exit": 0, "harness_exit": 0, "config_check_exit": 0, "raw_sha256": {}, "operations": []}
        charge = {"entries": 0, "bytes": 1024, "peak_bytes": 2048}
        row["recovery_initial"] = charge
        row["fallback_initial"] = dict.fromkeys(receipt.CAUSES, 0)
        (leg / "config-check.log").write_text("strict config validation passed\n")
        ready = {"family_keys": [160, 40], "receivers": 2, "bitmap_bytes": 2 * (3 + 1) * 8 * 3, "correctness_only": True}
        lines = ["mass_dirty_ready " + json.dumps(ready)]
        peers = [{"peer": receipt.peer(i), "group": "group:7", "pending": False} for i in (1, 2)]
        receipt.write_json(leg / "neighbors-initial.json", peers)
        metrics = ("bgp_update_group_regroups_total 0\n" +
                   "\n".join(f'bgp_update_group_recovery_fallback_total{{cause="{cause}"}} 0' for cause in receipt.CAUSES) + "\n" +
                   "\n".join(f"bgp_update_group_recovery_{key} {value}" for key, value in charge.items()))
        (leg / "metrics-initial.prom").write_text(metrics)
        for generation in ("b", "a"):
            lines.append("mass_dirty_paused " + json.dumps({"generation": generation, "receivers": 2}))
            wire = {"generation": generation, "receivers": 2, "withdrawals": 16, "exact_fold": True,
                    "sessions_continuous": True, "resume_to_fold_p50_seconds": None, "resume_to_fold_max_seconds": None}
            lines.append("mass_dirty_complete " + json.dumps(wire))
            operation = {**wire, "fallback_deltas": dict.fromkeys(receipt.CAUSES, 0), "trigger_to_fold_seconds": None,
                         "recovery_paused": charge, "recovery_settled": charge,
                         "trigger_to_settlement_seconds": None, "settlement_to_resume_seconds": None, "resume_to_observed_fold_seconds": None}
            row["operations"].append(operation)
            dirty = [{"message": "outbound routes resynced", "peer": item["peer"], "dirty": True, "force": False} for item in peers]
            (leg / f"daemon-window-{generation}.jsonl").write_text("\n".join(json.dumps({"fields": item}) for item in dirty) + "\n")
            receipt.write_json(leg / f"dirty-receipts-{generation}.json", dirty)
            for phase, pending in (("paused", False), ("settled", False)):
                receipt.write_json(leg / f"neighbors-{phase}-{generation}.json", [{**item, "pending": pending} for item in peers])
                (leg / f"metrics-{phase}-{generation}.prom").write_text(metrics)
        lines.append("mass_dirty_exit " + json.dumps({"readiness_samples": 1, "readiness_deadline_ms": 250, "status": "PASS"}))
        lines.append("mass_dirty_readiness " + json.dumps({"status": 200, "deadline_ms": 250, "elapsed_seconds": None}))
        (leg / "harness.log").write_text("\n".join(lines) + "\n")
        return leg, row

    def test_real_dirty_receipt_target_set_cannot_be_fabricated_from_trigger(self):
        fields = [{"message": "outbound routes resynced", "peer": receipt.peer(i), "dirty": True, "force": False} for i in (1, 2)]
        text = lambda values: "\n".join(json.dumps({"fields": value}) for value in values)
        self.assertEqual(len(receipt.dirty_receipts(text(fields), 2)), 2)
        for bad in (fields[:1], fields + [{**fields[0], "peer": receipt.peer(3)}],
                    [{**fields[0], "dirty": False}, fields[1]], [{**fields[0], "force": True}, fields[1]]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                receipt.dirty_receipts(text(bad), 2)

    def test_source_order_requires_real_mark_loop_before_staging(self):
        source = ("    fn reevaluate_peer_export_policies_synchronously(\n"
                  "for peer in targets { self.mark_outbound_dirty(peer); }\n"
                  "self.stage_group_prefixes(); self.distribute_changes();\n"
                  "    /// Mark a peer's outbound channel dirty\n")
        self.assertEqual(len(receipt.source_order_proof(source)), 64)
        with self.assertRaises(ValueError):
            receipt.source_order_proof(source.replace("self.mark_outbound_dirty(peer);", ""))
        for body in ("self.mark_outbound_dirty(peer); self.stage_group_prefixes(); self.distribute_changes();",
                     "if allowed { self.mark_outbound_dirty(peer); }",
                     "self.mark_outbound_dirty(peer); break;",
                     "if !allowed { continue; } self.mark_outbound_dirty(peer);"):
            with self.subTest(body=body), self.assertRaises(ValueError):
                receipt.source_order_proof(source.replace("self.mark_outbound_dirty(peer);", body))


if __name__ == "__main__":
    unittest.main()
