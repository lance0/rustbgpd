#!/usr/bin/env python3
"""Adversarial receipt fixtures; never read host cgroups or start a workload."""

from __future__ import annotations

import copy
import json
import os
import shutil
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import patch

import recovery_memory as receipt


class RecoveryReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def scope(self) -> Path:
        path = self.root / "scope"
        path.mkdir()
        for name, value in {
            "memory.current": "123",
            "memory.peak": "456",
            "memory.max": "max",
            "memory.swap.max": "0",
            "memory.swap.current": "0",
            "memory.swap.peak": "0",
            "memory.stat": "anon 100\nfile 20\nfile_mapped 10\n",
            "memory.events": "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n",
        }.items():
            (path / name).write_text(value.rstrip() + "\n", encoding="utf-8")
        return path

    def samples(
        self,
        role: str = "candidate",
        cell: str = "peer-down",
        profile: str = "smoke-uc",
        clients: int = 2,
    ) -> list[dict]:
        if cell == "widen" and profile == "smoke-uc":
            profile = "smoke-vpn"
        seed, additions = receipt.PROFILES[profile]
        additions = additions if cell == "widen" else (0, 0, 0, 0)
        rows = []
        for phase in receipt.PHASES:
            cg = {name: 0 for name in receipt.SCALARS}
            cg.update(
                {
                    "memory.current": 123,
                    "memory.peak": 456,
                    "memory.stat.anon": 100,
                    "memory.stat.file": 20,
                    "memory.stat.file_mapped": 10,
                    "memory.events.oom": 0,
                    "memory.events.oom_kill": 0,
                    "memory.events.oom_group_kill": 0,
                }
            )
            held = phase in ("retained", "operation_end")
            terminal = phase == "settled" and cell == "peer-down"
            metrics = {"bgp_update_group_residue_entries": 0}
            if role != "baseline":
                metrics.update(dict.fromkeys(receipt.GAUGES, 0))
                metrics[receipt.GAUGES[0]] = (
                    clients * sum(a + b for a, b in zip(seed, additions)) if held else 0
                )
                metrics[receipt.GAUGES[1]] = 4096 if held else 56
                metrics[receipt.GAUGES[2]] = 4096
                metrics["bgp_evpn_recovery_provenance_exhausted_total"] = 0
            families = {
                name: {
                    "present": 0
                    if terminal
                    else clients * (seed[f] + (additions[f] if phase == "settled" else 0)),
                    "announces": clients * (seed[f] + (additions[f] if phase == "settled" else 0)),
                    "withdrawals": clients * seed[f] if terminal else 0,
                }
                for f, name in enumerate(receipt.FAMILIES)
            }
            rows.append(
                {
                    "schema": "rustbgpd.recovery-memory.v2",
                    "profile": profile,
                    "cell": cell,
                    "phase": phase,
                    "clients": clients,
                    "seed": dict(zip(receipt.FAMILIES, seed)),
                    "additions": dict(zip(receipt.FAMILIES, additions)),
                    "receiver_queue_capacity": 8,
                    "receiver_bitmap_bytes": clients
                    * sum((a + b + 63) // 64 * 8 for a, b in zip(seed, additions)),
                    "families": families,
                    "folded_routes": sum(row["present"] for row in families.values()),
                    "announces": sum(row["announces"] for row in families.values()),
                    "withdrawals": sum(row["withdrawals"] for row in families.values()),
                    "dirty_peers": clients if held else 0,
                    "group_dirty_members": clients if held else 0,
                    "fallback_causes": {
                        "peer_limit": 0,
                        "daemon_limit": 0,
                        "allocation_failure": 0,
                        "missing_proof": 0,
                    },
                    "metrics": metrics,
                    "cgroup": cg,
                }
            )
        return rows

    def log(
        self,
        rows: list[dict],
        cell: str = "peer-down",
        complete: bool = True,
        role: str = "candidate",
    ) -> Path:
        source = (
            receipt.BASELINE
            if role == "baseline"
            else receipt.INTERMEDIATE
            if role == "intermediate"
            else "a" * 40
        )
        identity = {
            "pid": 10,
            "start_ticks": 123,
            "cgroup": "/sys/fs/cgroup/test.scope",
            "source_sha": source,
            "instrumentation_sha256": "d" * 64,
        }
        lines = ["recovery_identity " + json.dumps(identity)]
        lines += ["recovery_sample " + json.dumps(row) for row in rows]
        if complete:
            row = rows[-1]
            expected = {
                name: 0 if cell == "peer-down" else row["seed"][name] + row["additions"][name]
                for name in receipt.FAMILIES
            }
            lines.append(
                "recovery_complete "
                + json.dumps(
                    {
                        "cell": cell,
                        "profile": row["profile"],
                        "expected_families_per_receiver": expected,
                        "actual_receivers": row["clients"],
                    }
                )
            )
        path = self.root / "harness.log"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def validate(self, rows: list[dict], role: str = "candidate", cell: str = "peer-down") -> dict:
        return receipt.validate_log(
            self.log(rows, cell, role=role), role, cell, rows[0]["clients"], rows[0]["profile"]
        )

    def test_valid_scope_retains_bytes(self) -> None:
        self.assertEqual(receipt.scope_values(self.scope())["memory.peak"], 456)

    def test_missing_cgroup_capability_fails(self) -> None:
        scope = self.scope()
        (scope / "memory.peak").unlink()
        with self.assertRaises(OSError):
            receipt.scope_values(scope)

    def test_swap_fence_failure_is_rejected(self) -> None:
        scope = self.scope()
        (scope / "memory.swap.max").write_text("max\n", encoding="utf-8")
        with self.assertRaisesRegex(receipt.InvalidReceipt, "capability"):
            receipt.scope_values(scope)

    def test_nonzero_fenced_swap_is_rejected(self) -> None:
        scope = self.scope()
        (scope / "memory.swap.max").write_text("1\n", encoding="utf-8")
        with self.assertRaisesRegex(receipt.InvalidReceipt, "fence"):
            receipt.scope_values(scope)

    def test_actual_swap_is_rejected(self) -> None:
        scope = self.scope()
        (scope / "memory.swap.peak").write_text("1\n", encoding="utf-8")
        with self.assertRaisesRegex(receipt.InvalidReceipt, "actual swap"):
            receipt.scope_values(scope)

    def test_oom_is_rejected_and_raw_files_are_retained(self) -> None:
        scope = self.scope()
        (scope / "memory.events").write_text(
            "oom 1\noom_kill 0\noom_group_kill 0\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(receipt.InvalidReceipt, "OOM"):
            receipt.snapshot_scope(scope, self.root / "failed")
        self.assertIn("oom 1", (self.root / "failed/memory.events").read_text(encoding="utf-8"))

    def test_missing_oom_field_is_rejected(self) -> None:
        scope = self.scope()
        (scope / "memory.events").write_text("oom 0\noom_kill 0\n", encoding="utf-8")
        with self.assertRaisesRegex(receipt.InvalidReceipt, "missing memory.events"):
            receipt.scope_values(scope)

    def test_valid_cells_and_baseline_absence_are_explicit(self) -> None:
        for cell in receipt.CELLS:
            for role in ("baseline", "candidate"):
                with self.subTest(cell=cell, role=role):
                    result = self.validate(self.samples(role, cell), role, cell)
                    self.assertEqual(
                        result["recovery_gauges"],
                        "absent-baseline" if role == "baseline" else "required-present",
                    )
                    self.assertEqual(
                        result["evpn_reset_counter"],
                        "absent" if role == "baseline" else "present-inactive-zero",
                    )

    def test_candidate_missing_gauge_is_not_a_zero(self) -> None:
        rows = self.samples()
        del rows[1]["metrics"][receipt.GAUGES[1]]
        with self.assertRaisesRegex(receipt.InvalidReceipt, receipt.GAUGES[1]):
            self.validate(rows)

    def test_nonconvergence_is_rejected(self) -> None:
        rows = self.samples()
        rows[-1]["folded_routes"] = 1
        with self.assertRaisesRegex(receipt.InvalidReceipt, "nonconverged"):
            self.validate(rows)

    def test_inferred_dirty_overlap_is_rejected(self) -> None:
        rows = self.samples()
        rows[1]["group_dirty_members"] = 1
        with self.assertRaisesRegex(receipt.InvalidReceipt, "actual simultaneous"):
            self.validate(rows)

    def test_missing_completion_is_rejected(self) -> None:
        with self.assertRaisesRegex(receipt.InvalidReceipt, "completion"):
            receipt.validate_log(
                self.log(self.samples(), complete=False), "candidate", "peer-down", 2, "smoke-uc"
            )

    def test_extra_withdrawals_are_rejected(self) -> None:
        rows = self.samples()
        rows[-1]["withdrawals"] += 1
        with self.assertRaisesRegex(receipt.InvalidReceipt, "aggregate/family"):
            self.validate(rows)

    def test_wrong_shape_and_duplicate_barriers_are_rejected(self) -> None:
        rows = self.samples()
        rows[0]["seed"]["ipv4_unicast"] += 1
        with self.assertRaisesRegex(receipt.InvalidReceipt, "shape"):
            self.validate(rows)
        rows = self.samples()
        rows.insert(1, copy.deepcopy(rows[0]))
        with self.assertRaisesRegex(receipt.InvalidReceipt, "phase barriers"):
            self.validate(rows)

    def test_fallback_causes_cannot_be_hidden_in_a_sum(self) -> None:
        rows = self.samples()
        rows[1]["metrics"]["bgp_update_group_recovery_fallback_total"] = 1
        with self.assertRaisesRegex(receipt.InvalidReceipt, "causes"):
            self.validate(rows)

    def test_family_counts_cannot_be_exchanged_without_changing_total(self) -> None:
        rows = self.samples(profile="smoke-vpn")
        rows[-1]["families"]["vpnv4"]["withdrawals"] -= 1
        rows[-1]["families"]["vpnv6"]["withdrawals"] += 1
        with self.assertRaisesRegex(receipt.InvalidReceipt, "withdrawal inventory"):
            self.validate(rows)

    def test_candidate_full_table_requires_all_logical_keys(self) -> None:
        rows = self.samples(profile="full-vpn", clients=4)
        self.validate(rows)
        rows[1]["metrics"][receipt.GAUGES[0]] -= 1
        with self.assertRaisesRegex(receipt.InvalidReceipt, "complete admitted"):
            self.validate(rows)

    def test_dirty_widen_requires_admitted_additions_not_only_desired_rows(self) -> None:
        rows = self.samples(cell="widen", profile="smoke-mixed")
        self.validate(rows, cell="widen")
        rows[1]["metrics"][receipt.GAUGES[0]] = 400
        with self.assertRaisesRegex(receipt.InvalidReceipt, "complete admitted"):
            self.validate(rows, cell="widen")

    def test_candidate_budget_fallback_cannot_qualify_even_after_convergence(self) -> None:
        rows = self.samples()
        rows[1]["fallback_causes"]["peer_limit"] = 1
        rows[1]["metrics"]["bgp_update_group_recovery_fallback_total"] = 1
        with self.assertRaisesRegex(receipt.InvalidReceipt, "fallback disqualifies"):
            self.validate(rows)

    def test_unchanged_policy_withdraw_announce_flap_is_not_end_state_parity(self) -> None:
        rows = self.samples(cell="dataset-reevaluate", profile="smoke-vpn")
        rows[-1]["families"]["vpnv4"]["withdrawals"] = 1
        rows[-1]["families"]["vpnv4"]["announces"] += 1
        rows[-1]["withdrawals"] = 1
        rows[-1]["announces"] += 1
        with self.assertRaisesRegex(receipt.InvalidReceipt, "unchanged-policy flap"):
            self.validate(rows, cell="dataset-reevaluate")

    def test_full_intermediate_control_requires_actual_refusal(self) -> None:
        rows = self.samples(role="intermediate", profile="full-vpn", clients=4)
        with self.assertRaisesRegex(receipt.InvalidReceipt, "refusal control did not refuse"):
            self.validate(rows, role="intermediate")
        for row in rows:
            row["fallback_causes"]["peer_limit"] = 4
            row["metrics"]["bgp_update_group_recovery_fallback_total"] = 4
        self.validate(rows, role="intermediate")

    def test_pilot_is_explicit_feasibility_not_100_member_qualification(self) -> None:
        self.assertTrue(all(case["clients"] == 4 for case in receipt.campaign_cases("pilot")))
        self.assertEqual(
            {case["clients"] for case in receipt.campaign_cases("qualified")}, {100, 256}
        )
        self.assertEqual(
            receipt.campaign_cases("qualified", ["mixed-widen"]),
            [{"profile": "mixed-widen", "clients": 100, "cell": "widen"}],
        )

    def observer_tree(self) -> Path:
        for name, anchor, indent in (
            ("crates/rib/src/update.rs", receipt.VARIANT, "    "),
            ("crates/rib/src/manager/mod.rs", receipt.HANDLER, "            "),
        ):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            header = receipt.RIB_UPDATE_DECLARATION + "\n" if name.endswith("update.rs") else ""
            path.write_text(header + indent + "#[cfg(test)]\n" + anchor + "\n", encoding="utf-8")
        return self.root

    def test_observer_transformation_is_minimal_and_idempotent(self) -> None:
        tree = self.observer_tree()
        receipt.instrument_observer(tree)
        original = (tree / "crates/rib/src/update.rs").read_bytes()
        receipt.instrument_observer(tree)
        self.assertEqual((tree / "crates/rib/src/update.rs").read_bytes(), original)
        self.assertIn(receipt.VARIANT.encode(), original)
        self.assertIn(receipt.BENCH_ACKNOWLEDGEMENT.encode(), original)
        self.assertIn(b'#[cfg(any(test, feature = "bench-internals"))]', original)

    def test_observer_drift_refuses_both_changes(self) -> None:
        tree = self.observer_tree()
        update = tree / "crates/rib/src/update.rs"
        original = update.read_bytes()
        manager = tree / "crates/rib/src/manager/mod.rs"
        manager.write_text(
            manager.read_text(encoding="utf-8").replace("self.dirty_peers.len()", "0"),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(receipt.InvalidReceipt, "observer body"):
            receipt.instrument_observer(tree)
        self.assertEqual(update.read_bytes(), original)

    def test_credit_transaction_drift_refuses_both_instrumentation_changes(self) -> None:
        tree = self.observer_tree()
        receipt.instrument_observer(tree)
        update = tree / "crates/rib/src/update.rs"
        original = update.read_bytes()
        manager = tree / "crates/rib/src/manager/mod.rs"
        manager.write_text(
            manager.read_text(encoding="utf-8").replace(
                "self.handle_update(*update);", "drop(update);"
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(receipt.InvalidReceipt, "credit transaction body"):
            receipt.instrument_observer(tree)
        self.assertEqual(update.read_bytes(), original)

    def test_missing_credit_acknowledgement_alias_refuses_partial_instrumentation(self) -> None:
        tree = self.observer_tree()
        receipt.instrument_observer(tree)
        update = tree / "crates/rib/src/update.rs"
        update.write_text(
            update.read_text(encoding="utf-8").replace(receipt.BENCH_ACKNOWLEDGEMENT + "\n\n", ""),
            encoding="utf-8",
        )
        original = update.read_bytes()
        with self.assertRaisesRegex(receipt.InvalidReceipt, "acknowledgement alias"):
            receipt.instrument_observer(tree)
        self.assertEqual(update.read_bytes(), original)

    def test_wrong_credit_acknowledgement_alias_refuses_both_changes(self) -> None:
        tree = self.observer_tree()
        receipt.instrument_observer(tree)
        update = tree / "crates/rib/src/update.rs"
        update.write_text(
            update.read_text(encoding="utf-8").replace(
                receipt.BENCH_ACKNOWLEDGEMENT,
                receipt.BENCH_ACKNOWLEDGEMENT.replace("Mutex<", "RwLock<"),
            ),
            encoding="utf-8",
        )
        manager = tree / "crates/rib/src/manager/mod.rs"
        original = manager.read_bytes()
        with self.assertRaisesRegex(receipt.InvalidReceipt, "acknowledgement alias"):
            receipt.instrument_observer(tree)
        self.assertEqual(manager.read_bytes(), original)

    def test_driver_refuses_dev_host_before_any_host_probe(self) -> None:
        env = dict(os.environ)
        for name in (
            "GITHUB_ACTIONS",
            "RUNNER_ENVIRONMENT",
            "RUNNER_OS",
            "RECOVERY_MEMORY_RUNNER_ENVIRONMENT",
        ):
            env.pop(name, None)
        output = self.root / "must-not-exist"
        result = subprocess.run(
            [
                "bash",
                str(Path(__file__).with_name("compare-recovery-memory.sh")),
                "--head",
                "0" * 40,
                "--output-dir",
                str(output),
            ],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("fresh GitHub-hosted", result.stderr)
        self.assertFalse(output.exists())

    def test_settled_charge_must_restore_empty_proof_header(self) -> None:
        rows = self.samples()
        self.assertEqual(self.validate(rows)["samples"][-1]["metrics"][receipt.GAUGES[1]], 56)
        rows[-1]["metrics"][receipt.GAUGES[1]] = 4096
        with self.assertRaisesRegex(receipt.InvalidReceipt, "restore the initial"):
            self.validate(rows)

    def test_phase_peaks_cannot_decrease(self) -> None:
        rows = self.samples()
        rows[1]["cgroup"]["memory.peak"] = 999
        with self.assertRaisesRegex(receipt.InvalidReceipt, "decreasing phase"):
            self.validate(rows)

    def test_end_peak_must_cover_before_and_every_phase(self) -> None:
        rows = self.samples()
        for row in rows[1:]:
            row["cgroup"]["memory.peak"] = 999
        with self.assertRaisesRegex(receipt.InvalidReceipt, "high-water"):
            receipt.check_peak_coverage({"memory.peak": 456}, rows, {"memory.peak": 456})
        with self.assertRaisesRegex(receipt.InvalidReceipt, "high-water"):
            receipt.check_peak_coverage({"memory.peak": 1000}, [], {"memory.peak": 456})

    def campaign(self) -> Path:
        root = self.root / "campaign"
        root.mkdir()
        entries = []
        for name in receipt.INSTRUMENT_INPUTS:
            path = root / "frozen-instrumentation" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(name, encoding="utf-8")
            entries.append(receipt.file_digest(path) + "  " + name)
        inputs = root / "instrumentation.sha256"
        inputs.write_text("\n".join(entries) + "\n", encoding="utf-8")
        instrumentation = receipt.file_digest(inputs)
        manifest = {
            "schema": "rustbgpd.recovery-memory.campaign.v2",
            "baseline": receipt.BASELINE,
            "intermediate": receipt.INTERMEDIATE,
            "candidate": "a" * 40,
            "instrumentation_manifest_sha256": instrumentation,
            "phase": "qualified",
            "profiles": ["ipv4-100k"],
            "cases": receipt.campaign_cases("qualified", ["ipv4-100k"]),
            "build_jobs": 4,
            "comparators": ["baseline", "intermediate"],
            "order_per_cell": ["control", "candidate", "candidate", "control"],
        }
        receipt.write_json(root / "manifest.json", manifest)
        for role, digest in (
            ("baseline", "b" * 64),
            ("intermediate", "d" * 64),
            ("candidate", "c" * 64),
        ):
            for name, value in (
                ("sha", manifest[role]),
                ("build.exit", "0"),
                ("binary.sha256", digest),
                ("build.log", "build command"),
                ("build-inputs.sha256", "retained build inputs"),
                ("instrumentation.patch", "frozen overlay"),
                ("observer.patch", "two gates"),
            ):
                (root / f"{role}-{name}" if name != "sha" else root / f"{role}.sha").write_text(
                    value + "\n", encoding="utf-8"
                )
        for name in ("host-oom.before", "host-oom.after"):
            (root / name).write_text("0\n", encoding="utf-8")
        raw_scope = self.scope()
        ordinal = 0
        legs = (
            (case, comparator, leg, role)
            for case in manifest["cases"]
            for comparator in ("baseline", "intermediate")
            for leg, role in enumerate((comparator, "candidate", "candidate", comparator), 1)
        )
        for case, comparator, leg, role in legs:
            cell, profile, clients = case["cell"], case["profile"], case["clients"]
            ordinal += 1
            directory = root / f"{profile}-{cell}-{comparator}-{leg}-{role}"
            directory.mkdir()
            cgroup = f"/sys/fs/cgroup/test-{ordinal}.scope"

            def process(
                pid, parent, executable, digest, start_ticks=123 + ordinal, member_path=cgroup
            ):
                return {
                    "pid": pid,
                    "parent_pid": parent,
                    "start_ticks": start_ticks,
                    "executable": executable,
                    "exe_sha256": digest,
                    "cgroup": "0::" + member_path.removeprefix("/sys/fs/cgroup") + "\n",
                }

            launcher = process(1000 + ordinal, 1, "/usr/bin/bash", "e" * 64)
            checker = process(2000 + ordinal, launcher["pid"], "/usr/bin/python3.12", "f" * 64)
            workload = process(
                3000 + ordinal,
                checker["pid"],
                f"/build/{role}/rrharness",
                "b" * 64
                if role == "baseline"
                else "d" * 64
                if role == "intermediate"
                else "c" * 64,
            )
            identity = {
                "pid": workload["pid"],
                "start_ticks": workload["start_ticks"],
                "cgroup": cgroup,
                "source_sha": manifest[role],
                "instrumentation_sha256": instrumentation,
            }
            for name, value in (
                ("launcher-process.json", launcher),
                ("scope-process.json", checker),
                ("binary-process.json", workload),
                (
                    "status.json",
                    {
                        "exit": 0,
                        "timeout": False,
                        "cgroup_valid": True,
                        "ownership_valid": True,
                    },
                ),
            ):
                receipt.write_json(directory / name, value)
            (directory / "cgroup-path.txt").write_text(cgroup + "\n", encoding="utf-8")
            (directory / "launcher.exit").write_text("0\n", encoding="utf-8")
            ownership = []
            for phase, processes in (
                ("before", [launcher, checker]),
                ("active", [launcher, checker, workload]),
                ("after", [launcher, checker]),
            ):
                members = [row["pid"] for row in processes]
                ownership.append(
                    {
                        "phase": phase,
                        "members": members,
                        "cgroup_procs_raw": "\n".join(map(str, members)) + "\n",
                        "processes": processes,
                        "descendants": [],
                    }
                )
            (directory / "ownership.jsonl").write_text(
                "\n".join(map(json.dumps, ownership)) + "\n", encoding="utf-8"
            )
            rows = self.samples(role, cell, profile, clients)
            lines = ["recovery_identity " + json.dumps(identity)]
            lines.extend("recovery_sample " + json.dumps(row) for row in rows)
            lines.append(
                "recovery_complete "
                + json.dumps(
                    {
                        "cell": cell,
                        "profile": profile,
                        "actual_receivers": clients,
                        "expected_families_per_receiver": dict(
                            zip(
                                receipt.FAMILIES,
                                (0, 0, 0, 0)
                                if cell == "peer-down"
                                else receipt.PROFILES[profile][0],
                            )
                        ),
                    }
                )
            )
            (directory / "harness.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
            for phase in ("before", "after"):
                shutil.copytree(raw_scope, directory / phase)
        return root

    def test_campaign_binds_all_distinct_owned_workloads(self) -> None:
        root = self.campaign()
        receipt.summarize(root)
        result = json.loads((root / "comparison.json").read_text(encoding="utf-8"))
        self.assertEqual(len(result["rows"]), 16)

    def test_historical_failure_is_retained_without_a_comparison_claim(self) -> None:
        root = self.campaign()
        path = root / "ipv4-100k-dataset-reevaluate-baseline-1-baseline/harness.log"
        lines = path.read_text(encoding="utf-8").splitlines()
        lines = [line for line in lines if not line.startswith("recovery_complete ")]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        receipt.summarize(root)
        result = json.loads((root / "comparison.json").read_text(encoding="utf-8"))
        self.assertFalse(result["rows"][0]["strict_validation"]["passed"])
        self.assertIsNone(result["summaries"][0]["candidate_to_control_mean_peak_ratio"])
        self.assertEqual(result["candidate_failures"], [])

    def test_candidate_failure_remains_red_and_comparison_artifact_is_retained(self) -> None:
        root = self.campaign()
        path = root / "ipv4-100k-dataset-reevaluate-baseline-2-candidate/harness.log"
        lines = path.read_text(encoding="utf-8").splitlines()
        path.write_text(
            "\n".join(line for line in lines if not line.startswith("recovery_complete ")) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(receipt.InvalidReceipt, "candidate qualification failed"):
            receipt.summarize(root)
        result = json.loads((root / "comparison.json").read_text(encoding="utf-8"))
        self.assertEqual(len(result["rows"]), 16)
        self.assertEqual(len(result["candidate_failures"]), 1)

    def test_historical_route_failure_does_not_excuse_phase_swap(self) -> None:
        root = self.campaign()
        path = root / "ipv4-100k-dataset-reevaluate-baseline-1-baseline/harness.log"
        lines = path.read_text(encoding="utf-8").splitlines()
        samples = [
            json.loads(line.removeprefix("recovery_sample "))
            for line in lines
            if line.startswith("recovery_sample ")
        ]
        samples[1]["cgroup"]["memory.swap.current"] = 1
        path.write_text(
            lines[0]
            + "\n"
            + "\n".join("recovery_sample " + json.dumps(row) for row in samples)
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(receipt.InvalidReceipt, "phase swap"):
            receipt.summarize(root)

    def test_wrong_executed_binary_hash_is_rejected(self) -> None:
        root = self.campaign()
        path = root / "ipv4-100k-dataset-reevaluate-baseline-2-candidate/binary-process.json"
        process = json.loads(path.read_text(encoding="utf-8"))
        process["exe_sha256"] = "d" * 64
        receipt.write_json(path, process)
        with self.assertRaisesRegex(receipt.InvalidReceipt, "executed binary digest"):
            receipt.summarize(root)

    def test_wrong_compiled_original_source_is_rejected(self) -> None:
        root = self.campaign()
        path = root / "ipv4-100k-dataset-reevaluate-baseline-2-candidate/harness.log"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                '"source_sha": "' + "a" * 40, '"source_sha": "' + "b" * 40
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(receipt.InvalidReceipt, "compiled role source"):
            receipt.summarize(root)

    def test_foreign_scoped_member_is_rejected(self) -> None:
        root = self.campaign()
        path = root / "ipv4-100k-dataset-reevaluate-baseline-2-candidate/ownership.jsonl"
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        rows[1]["members"].append(99999)
        rows[1]["cgroup_procs_raw"] += "99999\n"
        path.write_text("\n".join(map(json.dumps, rows)) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(receipt.InvalidReceipt, "foreign"):
            receipt.summarize(root)

    def test_populated_descendant_is_rejected(self) -> None:
        root = self.campaign()
        path = root / "ipv4-100k-dataset-reevaluate-baseline-2-candidate/ownership.jsonl"
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        rows[1]["descendants"] = [{"path": "child", "procs": "99999\n", "threads": "99999\n"}]
        path.write_text("\n".join(map(json.dumps, rows)) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(receipt.InvalidReceipt, "populated descendant"):
            receipt.summarize(root)

    def test_end_snapshot_cannot_underreport_retained_peak(self) -> None:
        root = self.campaign()
        (root / "ipv4-100k-dataset-reevaluate-baseline-2-candidate/after/memory.peak").write_text(
            "455\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(receipt.InvalidReceipt, "high-water"):
            receipt.summarize(root)

    def test_reusing_a_scope_for_another_leg_is_rejected(self) -> None:
        root = self.campaign()
        directory = root / "ipv4-100k-dataset-reevaluate-baseline-2-candidate"
        for path in directory.rglob("*"):
            if path.is_file():
                path.write_text(
                    path.read_text(encoding="utf-8").replace("/test-2.scope", "/test-1.scope"),
                    encoding="utf-8",
                )
        with self.assertRaisesRegex(receipt.InvalidReceipt, "reused scope"):
            receipt.summarize(root)

    def test_reusing_a_workload_start_identity_is_rejected(self) -> None:
        root = self.campaign()
        directory = root / "ipv4-100k-dataset-reevaluate-baseline-2-candidate"
        process_path = directory / "binary-process.json"
        process = json.loads(process_path.read_text(encoding="utf-8"))
        process.update({"pid": 3001, "start_ticks": 124})
        receipt.write_json(process_path, process)
        path = directory / "harness.log"
        lines = path.read_text(encoding="utf-8").splitlines()
        identity = json.loads(lines[0].removeprefix("recovery_identity "))
        identity.update({"pid": 3001, "start_ticks": 124})
        lines[0] = "recovery_identity " + json.dumps(identity)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        path = directory / "ownership.jsonl"
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        for row in rows:
            if row["phase"] == "active":
                row["members"][-1] = 3001
                row["cgroup_procs_raw"] = row["cgroup_procs_raw"].replace("3002", "3001")
                row["processes"][-1] = process
        path.write_text("\n".join(map(json.dumps, rows)) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(receipt.InvalidReceipt, "reused scope or workload"):
            receipt.summarize(root)

    def test_wrong_instrumentation_identity_is_rejected(self) -> None:
        root = self.campaign()
        path = root / "ipv4-100k-dataset-reevaluate-baseline-2-candidate/harness.log"
        lines = path.read_text(encoding="utf-8").splitlines()
        identity = json.loads(lines[0].removeprefix("recovery_identity "))
        identity["instrumentation_sha256"] = "e" * 64
        lines[0] = "recovery_identity " + json.dumps(identity)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(receipt.InvalidReceipt, "compiled role source/instrumentation"):
            receipt.summarize(root)

    def test_live_ownership_capture_skips_root_and_deduplicates_equal_samples(self) -> None:
        scope = self.scope()
        (scope / "cgroup.procs").write_text("10\n20\n", encoding="utf-8")
        expected = {
            pid: {
                "pid": pid,
                "start_ticks": 123,
                "executable": "/usr/bin/tool",
                "cgroup": "0::" + str(scope) + "\n",
            }
            for pid in (10, 20)
        }
        with patch.object(receipt, "proc_identity", side_effect=lambda pid: expected[pid].copy()):
            sample = receipt.capture_ownership(scope, self.root, expected, "before")
            (scope / "cgroup.procs").write_text("20\n10\n", encoding="utf-8")
            receipt.capture_ownership(scope, self.root, expected, "before", previous=sample)
        self.assertEqual(
            len((self.root / "ownership.jsonl").read_text(encoding="utf-8").splitlines()), 1
        )

    def test_changed_process_start_identity_is_rejected(self) -> None:
        root = self.campaign()
        path = root / "ipv4-100k-dataset-reevaluate-baseline-2-candidate/ownership.jsonl"
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        rows[1]["processes"][-1]["start_ticks"] += 1
        path.write_text("\n".join(map(json.dumps, rows)) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(receipt.InvalidReceipt, "identity or membership changed"):
            receipt.summarize(root)


if __name__ == "__main__":
    unittest.main()
