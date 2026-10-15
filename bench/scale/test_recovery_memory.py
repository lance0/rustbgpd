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
import textwrap
import time
import unittest
from unittest.mock import Mock, patch

import recovery_memory as receipt


class RecoveryReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def scope(self) -> Path:
        path = self.root / "scope"
        path.mkdir(exist_ok=True)
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
        pulse_family = next(f for f, n in enumerate(seed) if n)
        if cell == "unsynchronized-dirty":
            additions = tuple(clients if f == pulse_family else 0 for f in range(4))
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
                if held and cell == "unsynchronized-dirty":
                    metrics[receipt.GAUGES[0]] = clients * sum(seed) + clients * (clients - 1) // 2
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
            if held and cell == "unsynchronized-dirty":
                families[receipt.FAMILIES[pulse_family]]["present"] += clients * (clients - 1) // 2
                families[receipt.FAMILIES[pulse_family]]["announces"] += clients * (clients - 1) // 2
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

    def completion(self, row: dict, cell: str) -> dict:
        return {
            "cell": cell,
            "profile": row["profile"],
            "expected_families_per_receiver": {
                name: 0 if cell == "peer-down" else row["seed"][name] + row["additions"][name]
                for name in receipt.FAMILIES
            },
            "actual_receivers": row["clients"],
        }

    def sample_lines(self, rows: list[dict]) -> list[str]:
        lines = []
        first = rows[0]
        for row in rows:
            if row["phase"] == "retained" and row["cell"] == "unsynchronized-dirty":
                clients, seed = first["clients"], first["seed"]
                family = next(name for name in receipt.FAMILIES if seed[name])
                for index in range(clients):
                    paused = index + 1
                    progress = {
                        "pass": index, "clients": clients, "profile": first["profile"],
                        "dirty_peers": paused, "group_dirty_members": paused,
                        "paused_families": {name: paused * seed[name] + (paused * (paused - 1) // 2 if name == family else 0) for name in receipt.FAMILIES},
                        "active_families": {name: (clients - paused) * (seed[name] + (paused if name == family else 0)) for name in receipt.FAMILIES},
                    }
                    lines.append("recovery_unsynchronized " + json.dumps(progress))
            lines.append("recovery_sample " + json.dumps(row))
        return lines

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
        lines += self.sample_lines(rows)
        if complete:
            lines.append("recovery_complete " + json.dumps(self.completion(rows[-1], cell)))
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

    def test_unsynchronized_receipt_requires_exact_actual_old_proofs(self) -> None:
        for profile in ("smoke-uc", "smoke-vpn"):
            with self.subTest(profile=profile):
                rows = self.samples(cell="unsynchronized-dirty", profile=profile, clients=4)
                self.validate(rows, cell="unsynchronized-dirty")
                changed = copy.deepcopy(rows)
                changed[1]["metrics"][receipt.GAUGES[0]] += 1
                with self.assertRaisesRegex(receipt.InvalidReceipt, "complete admitted"):
                    self.validate(changed, cell="unsynchronized-dirty")
                changed = copy.deepcopy(rows)
                changed[1]["fallback_causes"]["daemon_limit"] = 1
                changed[1]["metrics"]["bgp_update_group_recovery_fallback_total"] = 1
                with self.assertRaisesRegex(receipt.InvalidReceipt, "disqualifies"):
                    self.validate(changed, cell="unsynchronized-dirty")

    def test_unsynchronized_pass_barriers_reject_missing_duplicate_and_synchronized_shortcuts(self) -> None:
        rows = self.samples(cell="unsynchronized-dirty", clients=4)
        original = self.log(rows, "unsynchronized-dirty").read_text().splitlines()
        locations = [i for i, line in enumerate(original) if line.startswith("recovery_unsynchronized ")]
        for mutation in ("missing", "duplicate", "all-dirty", "desired-instead-of-old", "before-population", "after-retained"):
            lines = original.copy()
            position = locations[1]
            if mutation == "missing":
                del lines[position]
            elif mutation == "duplicate":
                lines[position] = lines[locations[0]]
            elif mutation in ("all-dirty", "desired-instead-of-old"):
                progress = json.loads(lines[position].removeprefix("recovery_unsynchronized "))
                if mutation == "all-dirty":
                    progress["dirty_peers"] = progress["group_dirty_members"] = 4
                else:
                    progress["paused_families"]["ipv4_unicast"] += 2
                lines[position] = "recovery_unsynchronized " + json.dumps(progress)
            else:
                line = lines.pop(position)
                lines.insert(1 if mutation == "before-population" else len(lines) - 1, line)
            path = self.root / "bad-unsynchronized.log"
            path.write_text("\n".join(lines) + "\n")
            with self.subTest(mutation=mutation), self.assertRaises(receipt.InvalidReceipt):
                receipt.validate_log(path, "candidate", "unsynchronized-dirty", 4, "smoke-uc")

    def test_pilot_is_explicit_feasibility_not_100_member_qualification(self) -> None:
        self.assertTrue(all(case["clients"] == 4 for case in receipt.campaign_cases("pilot")))
        self.assertEqual(
            {case["clients"] for case in receipt.campaign_cases("qualified")}, {100, 256}
        )
        self.assertEqual(
            receipt.campaign_cases("qualified", ["mixed-widen"]),
            [{"profile": "mixed-widen", "clients": 100, "cell": "widen"}],
        )

    def test_cell_selector_keeps_the_closed_qualified_roster(self) -> None:
        full = receipt.campaign_cases("qualified")
        self.assertEqual(len(full), 10)
        split = [
            selected
            for case in full
            for selected in receipt.campaign_cases("qualified", [case["profile"]], case["cell"])
        ]
        self.assertEqual(
            sorted(split, key=lambda row: (row["profile"], row["cell"])),
            sorted(full, key=lambda row: (row["profile"], row["cell"])),
        )
        self.assertEqual(
            receipt.campaign_cases("qualified", ["full-vpn"], "peer-down"),
            [{"profile": "full-vpn", "cell": "peer-down", "clients": 100}],
        )

    def test_unsupported_or_empty_cell_selection_is_refused(self) -> None:
        for phase, profiles, cell in (
            ("qualified", ["full-uc"], "widen"),
            ("qualified", ["mixed-widen"], "peer-down"),
            ("pilot", ["full-vpn"], "widen"),
            ("qualified", [], "all"),
            ("qualified", ["full-uc"], "unknown"),
        ):
            with self.subTest(phase=phase, profiles=profiles, cell=cell):
                with self.assertRaises(receipt.InvalidReceipt):
                    receipt.campaign_cases(phase, profiles, cell)

    def test_one_cell_campaign_retains_eight_complete_abba_legs(self) -> None:
        root = self.campaign(selected_cell="peer-down")
        receipt.summarize(root)
        result = json.loads((root / "comparison.json").read_text(encoding="utf-8"))
        self.assertEqual(len(result["rows"]), 8)
        self.assertTrue(all(row["cell"] == "peer-down" for row in result["rows"]))
        self.assertEqual(len(result["summaries"]), 2)
        self.assertEqual(sum(len(row["samples"]) for row in result["rows"]), 32)

    def test_tampered_or_missing_manifest_cell_is_not_a_partial_green(self) -> None:
        root = self.campaign(selected_cell="peer-down")
        path = root / "manifest.json"
        original = json.loads(path.read_text(encoding="utf-8"))
        for selected in (None, "dataset-reevaluate", "widen", "all"):
            changed = copy.deepcopy(original)
            if selected is None:
                del changed["selected_cell"]
            else:
                changed["selected_cell"] = selected
            receipt.write_json(path, changed)
            with self.subTest(selected=selected):
                with self.assertRaises(receipt.InvalidReceipt):
                    receipt.summarize(root)

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

    def campaign(self, profile: str = "ipv4-100k", selected_cell: str = "all") -> Path:
        root = self.root / f"campaign-{profile}"
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
            "profiles": [profile],
            "selected_cell": selected_cell,
            "cases": receipt.campaign_cases("qualified", [profile], selected_cell),
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
            if role == "intermediate" and profile in ("full-uc", "full-vpn", "mixed-widen"):
                for row in rows[1:]:
                    row["fallback_causes"]["peer_limit"] = clients
                    row["metrics"]["bgp_update_group_recovery_fallback_total"] = clients
                    row["metrics"][receipt.GAUGES[0]] = 0
            lines = ["recovery_identity " + json.dumps(identity)]
            lines.extend(self.sample_lines(rows))
            lines.append("recovery_complete " + json.dumps(self.completion(rows[-1], cell)))
            (directory / "harness.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
            for phase in ("before", "after"):
                shutil.copytree(raw_scope, directory / phase)
        return root

    def test_campaign_binds_all_distinct_owned_workloads(self) -> None:
        root = self.campaign()
        receipt.summarize(root)
        result = json.loads((root / "comparison.json").read_text(encoding="utf-8"))
        self.assertEqual(len(result["rows"]), 16)

    def test_full_widening_campaigns_include_the_terminal_additions(self) -> None:
        for profile in ("full-vpn", "mixed-widen"):
            with self.subTest(profile=profile):
                root = self.campaign(profile)
                receipt.summarize(root)
                result = json.loads((root / "comparison.json").read_text(encoding="utf-8"))
                widened = [row for row in result["rows"] if row["cell"] == "widen"]
                self.assertEqual(len(widened), 8)
                self.assertTrue(all(row["strict_validation"]["passed"] for row in widened))
                self.assertEqual(result["candidate_failures"], [])

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

    def assert_failure_envelope(self, root: Path, status: int, *, scan: bool = False) -> None:
        self.assertTrue((root / "comparison.json").exists(), "structured failure envelope missing")
        result = json.loads((root / "comparison.json").read_text(encoding="utf-8"))
        self.assertFalse(result["qualification_passed"])
        self.assertEqual(result["driver_invocation_exit"], status)
        for field in (("samples", "comparisons") if scan else ("rows", "summaries")):
            self.assertEqual(result[field], [])
        self.assertTrue(result["candidate_failures"])
        self.assertNotIn("ratio", json.dumps(result))

    def test_failure_finalization_retains_absent_or_incomplete_evidence(self) -> None:
        for failure in ("absent", "missing-leg", "early-build", "timeout"):
            with self.subTest(failure=failure):
                if failure == "absent":
                    root = self.root / "not-started"
                else:
                    root = self.campaign()
                    leg = root / "ipv4-100k-dataset-reevaluate-baseline-1-baseline"
                    if failure == "missing-leg":
                        shutil.rmtree(leg)
                    elif failure == "early-build":
                        (root / "candidate-build.exit").write_text("1\n", encoding="utf-8")
                        (root / "candidate-binary.sha256").unlink()
                    else:
                        status = json.loads((leg / "status.json").read_text(encoding="utf-8"))
                        status["timeout"] = True
                        receipt.write_json(leg / "status.json", status)
                    with self.assertRaises((receipt.InvalidReceipt, OSError)):
                        receipt.summarize(root)
                with self.assertRaisesRegex(receipt.InvalidReceipt, "raw evidence is unqualified"):
                    receipt.summarize_failed(root, 124)
                self.assert_failure_envelope(root, 124)
                shutil.rmtree(root)

    def test_complete_campaign_cannot_qualify_a_failed_invocation(self) -> None:
        root = self.campaign()
        receipt.summarize(root)
        result = json.loads((root / "comparison.json").read_text(encoding="utf-8"))
        self.assertTrue(all(row["all_strict_checks_passed"] for row in result["summaries"]))
        self.assertTrue(
            all(
                row["candidate_to_control_mean_peak_ratio"] is not None
                for row in result["summaries"]
            )
        )
        with self.assertRaisesRegex(receipt.InvalidReceipt, "exit 137"):
            receipt.summarize_failed(root, 137)
        self.assert_failure_envelope(root, 137)

    def test_failure_finalization_cli_stays_red_for_timeout_and_kill(self) -> None:
        for status in (124, 137):
            with self.subTest(status=status):
                root = self.root / str(status)
                result = subprocess.run(
                    [
                        shutil.which("python3"),
                        str(Path(receipt.__file__).resolve()),
                        "summarize",
                        str(root),
                        "--failed-driver-exit",
                        str(status),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 1)
                self.assert_failure_envelope(root, status)

    def test_failure_finalization_refuses_a_success_status(self) -> None:
        root = self.root / "successful"
        with self.assertRaisesRegex(receipt.InvalidReceipt, "nonzero"):
            receipt.summarize_failed(root, 0)
        self.assertFalse(root.exists())

    def workflow_script(self, name: str) -> str:
        workflow = Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml"
        step = workflow.read_text(encoding="utf-8").split(f"      - name: {name}\n", 1)[1]
        script = step.split("        run: |\n", 1)[1].split("\n      - ", 1)[0]
        return textwrap.dedent(script)

    def run_workflow_failure(self, status: int, *, expired: bool = False, mode: str = "memory") -> Path:
        commands = self.root / f"commands-{status}-{expired}"
        commands.mkdir()
        timeout_command = commands / "timeout"
        timeout_command.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "if sys.argv[1:3] == ['--signal=TERM', '--kill-after=30s']:\n"
            "    with open(os.environ['MOCK_DRIVER_ARGUMENTS'], 'w') as output:\n"
            "        json.dump(sys.argv[1:], output)\n"
            "    sys.exit(int(os.environ['MOCK_DRIVER_EXIT']))\n"
            "os.execv(os.environ['REAL_TIMEOUT'], [os.environ['REAL_TIMEOUT'], *sys.argv[1:]])\n",
            encoding="utf-8",
        )
        timeout_command.chmod(0o755)
        temporary = self.root / f"runner-{status}-{expired}"
        temporary.mkdir()
        arguments = temporary / "driver-arguments.json"
        environment = dict(
            os.environ,
            PATH=str(commands) + os.pathsep + os.environ["PATH"],
            REAL_TIMEOUT=shutil.which("timeout"),
            MOCK_DRIVER_EXIT=str(status),
            MOCK_DRIVER_ARGUMENTS=str(arguments),
            RUNNER_TEMP=str(temporary),
            GITHUB_SHA="a" * 40,
            RECOVERY_MEMORY_DRIVER_DEADLINE=str(time.monotonic() + (-1 if expired else 6600)),
            RECOVERY_MEMORY_PHASE="qualified",
            RECOVERY_RECEIPT_MODE=mode,
            RECOVERY_MEMORY_PROFILE="full-vpn",
            RECOVERY_MEMORY_CELL="capture-scan" if mode == "scan" else "widen",
        )
        result = subprocess.run(
            [
                "bash",
                "--noprofile",
                "--norc",
                "-e",
                "-o",
                "pipefail",
                "-c",
                self.workflow_script("Run frozen-source cgroup memory comparison"),
            ],
            cwd=Path(__file__).resolve().parents[2],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        expected_status = 124 if expired else status
        self.assertEqual(result.returncode, expected_status, result.stderr)
        evidence = temporary / "update-group-recovery-memory"
        self.assertEqual(
            (evidence / "driver-invocation.exit").read_text().strip(), str(expected_status)
        )
        self.assertEqual((evidence / "failure-summary.exit").read_text().strip(), "1")
        self.assert_failure_envelope(evidence / "campaign", expected_status, scan=mode == "scan")
        if expired:
            self.assertFalse(arguments.exists())
        else:
            invocation = json.loads(arguments.read_text(encoding="utf-8"))
            self.assertGreater(int(invocation[2].removesuffix("s")), 0)
            self.assertLessEqual(int(invocation[2].removesuffix("s")), 6600)
            self.assertEqual(invocation[3:5], ["bash", "bench/scale/compare-recovery-memory.sh"])
        return evidence

    def test_workflow_finalizes_timeout_and_kill_preserving_original_exit(self) -> None:
        for status in (124, 137):
            with self.subTest(status=status):
                self.run_workflow_failure(status)

    def test_workflow_expired_setup_budget_does_not_start_driver(self) -> None:
        self.run_workflow_failure(124, expired=True)

    def test_scan_workflow_finalizes_failure_preserving_original_exit(self) -> None:
        for status, expired in ((124, False), (137, False), (124, True)):
            with self.subTest(status=status, expired=expired):
                self.run_workflow_failure(status, expired=expired, mode="scan")

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

    def owned_capture(self, members: tuple[int, ...]) -> tuple[Path, dict, Mock]:
        scope = self.scope()
        (scope / "cgroup.procs").write_text(
            "".join(f"{pid}\n" for pid in members), encoding="utf-8"
        )
        expected = {
            pid: {
                "pid": pid,
                "start_ticks": 123,
                "executable": "/usr/bin/tool",
                "cgroup": "0::" + str(scope) + "\n",
            }
            for pid in (10, 20, 30)
        }
        child = Mock(pid=30)
        child.poll.return_value = None
        child.wait.return_value = 0
        return scope, expected, child

    def test_missing_child_wait_proves_exit_before_fresh_after_capture(self) -> None:
        scope, expected, child = self.owned_capture((10, 20))
        with patch.object(receipt, "proc_identity", side_effect=lambda pid: expected[pid].copy()):
            sample = receipt.capture_ownership(scope, self.root, expected, "active", child)
        child.wait.assert_called_once_with(timeout=0.25)
        self.assertEqual(sample["phase"], "after")
        self.assertEqual(sample["members"], [10, 20])
        self.assertEqual(set(expected), {10, 20, 30})

    def test_absent_live_child_cannot_be_classified_as_exited(self) -> None:
        scope, expected, child = self.owned_capture((10, 20))
        child.wait.side_effect = subprocess.TimeoutExpired("owned-child", 0.25)
        with self.assertRaisesRegex(receipt.InvalidReceipt, "did not exit"):
            receipt.capture_ownership(scope, self.root, expected, "active", child)

    def test_child_stat_disappearance_waits_then_rereads_membership(self) -> None:
        scope, expected, child = self.owned_capture((10, 20, 30))

        def identity(pid: int) -> dict:
            if pid == 30:
                (scope / "cgroup.procs").write_text("10\n20\n", encoding="utf-8")
                raise FileNotFoundError("owned child stat disappeared")
            return expected[pid].copy()

        with patch.object(receipt, "proc_identity", side_effect=identity):
            sample = receipt.capture_ownership(scope, self.root, expected, "active", child)
        child.wait.assert_called_once_with(timeout=0.25)
        self.assertEqual(sample["phase"], "after")
        self.assertEqual(sample["members"], [10, 20])

    def test_child_stat_disappearance_without_exit_proof_is_rejected(self) -> None:
        scope, expected, child = self.owned_capture((10, 20, 30))
        child.wait.side_effect = subprocess.TimeoutExpired("owned-child", 0.25)
        with patch.object(receipt, "proc_identity", side_effect=FileNotFoundError("stat vanished")):
            with self.assertRaisesRegex(receipt.InvalidReceipt, "did not exit"):
                receipt.capture_ownership(scope, self.root, expected, "active", child)

    def test_missing_other_owner_stat_is_not_excused_by_child_exit(self) -> None:
        scope, expected, child = self.owned_capture((10, 20, 30))

        def identity(pid: int) -> dict:
            if pid == 10:
                (scope / "cgroup.procs").write_text("20\n", encoding="utf-8")
                raise FileNotFoundError("launcher stat disappeared")
            return expected[pid].copy()

        with patch.object(receipt, "proc_identity", side_effect=identity):
            with self.assertRaisesRegex(receipt.InvalidReceipt, "foreign or missing"):
                receipt.capture_ownership(scope, self.root, expected, "active", child)
        child.wait.assert_called_once_with(timeout=0.25)

    def test_exit_proof_does_not_excuse_foreign_or_missing_remaining_owner(self) -> None:
        for members in ((10, 20, 99), (10,)):
            with self.subTest(members=members):
                scope, expected, child = self.owned_capture((10, 20))

                def exited(*, timeout: float, scope=scope, members=members) -> int:
                    self.assertEqual(timeout, 0.25)
                    (scope / "cgroup.procs").write_text(
                        "".join(f"{pid}\n" for pid in members), encoding="utf-8"
                    )
                    return 0

                child.wait.side_effect = exited
                with patch.object(
                    receipt,
                    "proc_identity",
                    side_effect=lambda pid, scope=scope: {
                        "pid": pid,
                        "start_ticks": 123,
                        "executable": "/usr/bin/tool",
                        "cgroup": "0::" + str(scope) + "\n",
                    },
                ):
                    with self.assertRaisesRegex(receipt.InvalidReceipt, "foreign or missing"):
                        receipt.capture_ownership(scope, self.root, expected, "active", child)

    def test_exit_reread_rejects_populated_descendant_and_changed_identity(self) -> None:
        for failure in ("descendant", "identity"):
            with self.subTest(failure=failure):
                scope, expected, child = self.owned_capture((10, 20))

                def exited(*, timeout: float, scope=scope, failure=failure) -> int:
                    self.assertEqual(timeout, 0.25)
                    if failure == "descendant":
                        descendant = scope / "nested"
                        descendant.mkdir()
                        (descendant / "cgroup.procs").write_text("99\n", encoding="utf-8")
                        (descendant / "cgroup.threads").write_text("99\n", encoding="utf-8")
                    return 0

                def identity(pid: int, expected=expected, failure=failure) -> dict:
                    row = expected[pid].copy()
                    if failure == "identity":
                        row["start_ticks"] += 1
                    return row

                child.wait.side_effect = exited
                with patch.object(receipt, "proc_identity", side_effect=identity):
                    with self.assertRaises(receipt.InvalidReceipt):
                        receipt.capture_ownership(scope, self.root, expected, "active", child)
                if failure == "descendant":
                    shutil.rmtree(scope / "nested")

    def test_initial_bad_ownership_cannot_be_hidden_by_exit_reread(self) -> None:
        for failure in ("descendant", "missing-owner"):
            with self.subTest(failure=failure):
                members = (10, 20) if failure == "descendant" else (10,)
                scope, expected, child = self.owned_capture(members)
                if failure == "descendant":
                    descendant = scope / "nested"
                    descendant.mkdir()
                    (descendant / "cgroup.procs").write_text("99\n", encoding="utf-8")
                    (descendant / "cgroup.threads").write_text("99\n", encoding="utf-8")

                def exited(*, timeout: float, scope=scope, failure=failure) -> int:
                    self.assertEqual(timeout, 0.25)
                    if failure == "descendant":
                        shutil.rmtree(scope / "nested")
                    else:
                        (scope / "cgroup.procs").write_text("10\n20\n", encoding="utf-8")
                    return 0

                child.wait.side_effect = exited
                with patch.object(
                    receipt,
                    "proc_identity",
                    side_effect=lambda pid, expected=expected: expected[pid].copy(),
                ):
                    with self.assertRaises(receipt.InvalidReceipt):
                        receipt.capture_ownership(scope, self.root, expected, "active", child)
                child.wait.assert_not_called()
                if failure == "descendant":
                    shutil.rmtree(scope / "nested")

    def test_changed_process_start_identity_is_rejected(self) -> None:
        root = self.campaign()
        path = root / "ipv4-100k-dataset-reevaluate-baseline-2-candidate/ownership.jsonl"
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        rows[1]["processes"][-1]["start_ticks"] += 1
        path.write_text("\n".join(map(json.dumps, rows)) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(receipt.InvalidReceipt, "identity or membership changed"):
            receipt.summarize(root)


class RecoveryScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_scan_scope_preserves_only_required_identity_after_sanitized_sudo(self):
        source = Path(__file__).with_name("compare-recovery-memory.sh").read_text()
        functions = source[source.index("record_command() {"):source.index("# Probe actual scope")]
        start = source.index('    launch_scope "recovery-scan-')
        launch = source[start:source.index("    printf ", start)]
        fake_bin = self.root / "bin"
        fake_bin.mkdir()
        sudo = fake_bin / "sudo"
        sudo.write_text(textwrap.dedent("""\
            #!/bin/bash
            [[ $1 == systemd-run ]] || exit 1
            shift
            while [[ $# -gt 0 && $1 != -- ]]; do shift; done
            [[ ${1:-} == -- ]] || exit 1
            shift
            exec env -i PATH="$PATH" "$@"
            """))
        sudo.chmod(0o755)
        driver = self.root / "child.sh"
        driver.write_text(textwrap.dedent("""\
            #!/bin/bash
            [[ $1 == --scope-scan && $# == 7 ]] || exit 1
            env > "$3/child-environment"
            """))
        for override in (False, True):
            with self.subTest(override=override):
                output = self.root / str(override)
                (output / "scan").mkdir(parents=True)
                (output / "candidate-binary.sha256").write_text("a" * 64 + "\n")
                environment = dict(os.environ, PATH=f"{fake_bin}:{os.environ['PATH']}",
                                   GITHUB_ACTIONS="true", RUNNER_ENVIRONMENT="github-hosted",
                                   RUNNER_OS="Linux", UNRELATED_PARENT_ONLY="must-not-leak")
                environment.pop("RECOVERY_MEMORY_RUNNER_ENVIRONMENT", None)
                if override:
                    environment.update(RECOVERY_MEMORY_RUNNER_ENVIRONMENT="github-hosted",
                                       RUNNER_ENVIRONMENT="must-not-pass-through")
                result = subprocess.run(
                    ["bash", "-c", functions + '\noutput=$1; work_root=$1; driver=$2; '
                     'profile=evpn-soak; status=0\n' + launch + '\nexit "$status"',
                     "scan-fixture", str(output), str(driver)],
                    env=environment, capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                child = dict(line.split("=", 1) for line in
                             (output / "scan/child-environment").read_text().splitlines())
                identity_names = ("GITHUB_ACTIONS", "RECOVERY_MEMORY_RUNNER_ENVIRONMENT",
                                  "RUNNER_ENVIRONMENT", "RUNNER_OS", "UNRELATED_PARENT_ONLY")
                self.assertEqual({name: child[name] for name in identity_names if name in child},
                                 {"GITHUB_ACTIONS": "true",
                                  "RECOVERY_MEMORY_RUNNER_ENVIRONMENT": "github-hosted"})

    def rows(self, profile="evpn-soak"):
        keys = receipt.SCAN_PROFILES[profile]
        return [dict(schema=receipt.SCAN_SCHEMA, profile=profile, keys=keys, records=records,
                     layout=layout, arm=arm, leg=leg, measured=True, old_keys=keys,
                     additions=records if layout == "older-sparse" and arm == "shared" else 0,
                     shape_callbacks=keys * (keys.bit_length() + 1) if arm == "shared" else keys,
                     comparisons=keys * keys.bit_length() if arm == "shared" else 0,
                     proof_keys=keys, shared=arm == "shared", retained_bytes=8192,
                     peak_bytes=9000, empty_bytes=56, settled_bytes=56, refusal=None,
                     phases={"shape": {"wall_ns": 1000, "cpu_ticks": 1},
                             "capture": {"wall_ns": 2000, "cpu_ticks": 2}})
                for records in (2, 64, 480) for layout in ("dense", "older-sparse")
                for leg, arm in enumerate(("flat", "shared", "shared", "flat"))]

    def log(self, rows):
        profile = rows[0]["profile"]
        lines = ["recovery_identity " + json.dumps({"pid": 123, "start_ticks": 456}),
                 "recovery_scan_environment " + json.dumps({"schema": receipt.SCAN_SCHEMA,
                    "cpu_ticks_per_second": 100,
                    "phase_passes": "independent shape and capture invocations",
                    "credit_scope": "logical daemon ledger reservation; excludes input fixtures, allocator overhead and RSS"})]
        lines += ["recovery_scan " + json.dumps(row) for row in rows]
        lines += ["recovery_scan_complete " + json.dumps({"profile": profile, "cells": 6, "legs": 24})]
        path = self.root / "scan.log"
        path.write_text("\n".join(lines) + "\n")
        return path

    def campaign(self, rows):
        # Reuse the complete process/cgroup fixture, replacing scan inputs only.
        fixture = RecoveryReceiptTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        root = fixture.campaign(selected_cell="peer-down")
        name = "bench/scale/rrharness/src/recovery_scan.rs"
        path = root / "frozen-instrumentation" / name
        path.write_text(name)
        inputs = root / "instrumentation.sha256"
        inputs.write_text(inputs.read_text() + receipt.file_digest(path) + "  " + name + "\n")
        manifest = {
            "schema": "rustbgpd.recovery-scan.campaign.v1", "candidate": "a" * 40,
            "instrumentation_manifest_sha256": receipt.file_digest(inputs),
            "profile": rows[0]["profile"], "build_jobs": 4,
            "order_per_cell": ["flat", "shared", "shared", "flat"],
        }
        receipt.write_json(root / "manifest.json", manifest)
        directory = root / "scan"
        shutil.copytree(root / "ipv4-100k-peer-down-baseline-2-candidate", directory)
        process = json.loads((directory / "binary-process.json").read_text())
        identity = {
            "pid": process["pid"], "start_ticks": process["start_ticks"],
            "cgroup": (directory / "cgroup-path.txt").read_text().strip(),
            "source_sha": manifest["candidate"],
            "instrumentation_sha256": manifest["instrumentation_manifest_sha256"],
        }
        lines = self.log(rows).read_text().splitlines()
        lines[0] = "recovery_identity " + json.dumps(identity)
        (directory / "harness.log").write_text("\n".join(lines) + "\n")
        return root

    def summarize_campaign(self, root):
        return subprocess.run(
            ["python3", str(Path(receipt.__file__).resolve()), "summarize-scan", str(root)],
            capture_output=True, text=True, check=False, timeout=10,
        )

    def test_scan_summary_qualifies_complete_profiles_with_unresolved_cpu_ratios(self):
        for profile in receipt.SCAN_PROFILES:
            with self.subTest(profile=profile):
                rows = self.rows(profile)
                for row in rows:
                    for phase in row["phases"].values():
                        phase["cpu_ticks"] = 0
                root = self.campaign(rows)
                result = self.summarize_campaign(root)
                self.assertEqual(result.returncode, 0, result.stderr)
                summary = json.loads((root / "comparison.json").read_text())
                self.assertTrue(summary.get("qualification_passed", False))
                self.assertTrue(json.loads(result.stdout)["qualification_passed"])
                self.assertEqual(len(summary["samples"]), 24)
                self.assertEqual(len(summary["comparisons"]), 6)
                self.assertTrue(all(cell["eligible"] for cell in summary["comparisons"]))
                for cell in summary["comparisons"]:
                    self.assertIsNone(cell["shared_over_flat"]["capture"]["cpu_ticks"])
                    self.assertEqual(cell["shared_over_flat"]["capture"]["wall_ns"], 1.0)

    def test_scan_summary_refuses_any_missing_comparison_and_preserves_raw(self):
        for refused in ((1,), (0, 1, 2, 3), tuple(range(24))):
            with self.subTest(refused=refused):
                rows = self.rows()
                for index in refused:
                    rows[index].update(refusal="peer_limit", proof_keys=0, phases={})
                root = self.campaign(rows)
                raw = (root / "scan/harness.log").read_bytes()
                result = self.summarize_campaign(root)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("all 6 scan cells", result.stderr)
                summary = json.loads((root / "comparison.json").read_text())
                self.assertFalse(summary["qualification_passed"])
                self.assertEqual(len(summary["samples"]), 24)
                self.assertEqual(sum(row["refusal"] is not None for row in summary["samples"]), len(refused))
                self.assertEqual(len(summary["comparisons"]), 6)
                self.assertTrue(any(not cell["eligible"] for cell in summary["comparisons"]))
                self.assertEqual((root / "scan/harness.log").read_bytes(), raw)
                finalized = subprocess.run(
                    ["python3", str(Path(receipt.__file__).resolve()), "summarize-scan",
                     str(root), "--failed-driver-exit", str(result.returncode)],
                    capture_output=True, text=True, check=False, timeout=10,
                )
                self.assertEqual(finalized.returncode, 1, finalized.stdout + finalized.stderr)
                envelope = json.loads((root / "comparison.json").read_text())
                self.assertFalse(envelope["qualification_passed"])
                self.assertEqual(envelope["driver_invocation_exit"], result.returncode)
                self.assertEqual(envelope["samples"], [])
                self.assertEqual(envelope["comparisons"], [])
                self.assertNotIn("ratio", json.dumps(envelope))
                diagnostic = root / "unqualified-comparison.json"
                self.assertTrue(diagnostic.exists(), "completed refusal diagnostics missing after finalization")
                self.assertEqual(json.loads(diagnostic.read_text()), summary)
                self.assertEqual((root / "scan/harness.log").read_bytes(), raw)

    def test_scan_summary_rejects_incomplete_matrix_or_proof(self):
        for failure in ("missing-leg", "wrong-proof"):
            with self.subTest(failure=failure):
                rows = self.rows()
                if failure == "missing-leg":
                    rows.pop()
                else:
                    rows[1]["proof_keys"] = 0
                root = self.campaign(rows)
                result = self.summarize_campaign(root)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertFalse((root / "comparison.json").exists())

    def test_scan_profiles_and_same_runtime_paired_ratios(self):
        for profile in receipt.SCAN_PROFILES:
            result = receipt.validate_scan_log(self.log(self.rows(profile)), profile)
            self.assertEqual(24, len(result["samples"]))
            self.assertEqual(6, len(result["comparisons"]))
            self.assertTrue(all(row["eligible"] for row in result["comparisons"]))
            self.assertEqual(1.0, result["comparisons"][0]["shared_over_flat"]["shape"]["wall_ns"])

    def test_scan_rejects_false_proof_work_and_measurement_claims(self):
        cases = [(1, "old_keys", 0), (1, "proof_keys", 1), (1, "comparisons", 0),
                 (0, "comparisons", 1), (0, "shared", True), (1, "shared", False),
                 (1, "shape_callbacks", 0), (1, "measured", False), (1, "settled_bytes", 57),
                 (5, "additions", 0), (0, "phases", {}), (1, "leg", 0),
                 (1, "refusal", "unrecognized")]
        for index, field, value in cases:
            with self.subTest(field=field, value=value):
                rows = self.rows()
                rows[index][field] = value
                with self.assertRaises(receipt.InvalidReceipt):
                    receipt.validate_scan_log(self.log(rows), "evpn-soak")
        with self.assertRaises(receipt.InvalidReceipt):
            receipt.validate_scan_log(self.log(self.rows()[:-1]), "evpn-soak")

    def test_scan_refusal_is_retained_without_a_ratio(self):
        rows = self.rows()
        rows[1].update(refusal="peer_limit", proof_keys=0, phases={})
        result = receipt.validate_scan_log(self.log(rows), "evpn-soak")
        self.assertEqual("peer_limit", result["samples"][1]["refusal"])
        self.assertFalse(result["comparisons"][0]["eligible"])
        self.assertIsNone(result["comparisons"][0]["shared_over_flat"])

    def test_failed_scan_invocation_erases_complete_ratios_or_missing_manifest(self):
        for completed in (False, True):
            with self.subTest(completed=completed):
                root = self.root / str(completed)
                raw = None
                if completed:
                    root.mkdir()
                    log = self.log(self.rows())
                    raw = log.read_bytes()
                    shutil.copyfile(log, root / "harness.log")
                    result = receipt.validate_scan_log(log, "evpn-soak")
                    self.assertTrue(all(c["eligible"] for c in result["comparisons"]))
                    self.assertTrue(all(c["shared_over_flat"] for c in result["comparisons"]))
                    receipt.write_json(root / "comparison.json", result)
                result = subprocess.run(
                    ["python3", str(Path(receipt.__file__).resolve()), "summarize-scan",
                     str(root), "--failed-driver-exit", "137"],
                    capture_output=True, text=True, check=False, timeout=10,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue((root / "comparison.json").exists(), "structured failure envelope missing")
                envelope = json.loads((root / "comparison.json").read_text())
                self.assertFalse(envelope.get("qualification_passed", True))
                self.assertEqual(envelope["schema"], receipt.SCAN_SCHEMA)
                self.assertEqual(envelope["driver_invocation_exit"], 137)
                self.assertEqual(envelope["samples"], [])
                self.assertEqual(envelope["comparisons"], [])
                self.assertTrue(envelope["candidate_failures"])
                self.assertNotIn("ratio", json.dumps(envelope))
                self.assertEqual(result.returncode, 1)
                if raw is not None:
                    self.assertEqual((root / "harness.log").read_bytes(), raw)

    def test_scan_zero_tick_denominator_has_no_cpu_ratio(self):
        rows = self.rows()
        for row in rows:
            row["phases"]["shape"]["cpu_ticks"] = 0
        result = receipt.validate_scan_log(self.log(rows), "evpn-soak")
        self.assertIsNone(result["comparisons"][0]["shared_over_flat"]["shape"]["cpu_ticks"])

    def test_independent_shape_can_exceed_capture_without_fake_tick_minimum(self):
        rows = self.rows()
        for row in rows:
            row["phases"]["shape"].update(wall_ns=3000, cpu_ticks=1)
            row["phases"]["capture"].update(wall_ns=2000, cpu_ticks=0)
        result = receipt.validate_scan_log(self.log(rows), "evpn-soak")
        self.assertTrue(all(row["eligible"] for row in result["comparisons"]))
        self.assertIsNone(result["comparisons"][0]["shared_over_flat"]["capture"]["cpu_ticks"])

    def test_memory_entrypoint_derivation_is_exact_and_verifiable(self):
        path = self.root / "frozen-instrumentation/bench/scale/rrharness/src/main.rs"
        path.parent.mkdir(parents=True)
        original = "// fixture\n" + "".join(receipt.SCAN_DISPATCH) + "// memory path\n"
        path.write_text(original)
        metadata = self.root / "memory-entrypoint-derivation.json"
        receipt.normalize_memory_entrypoint(path, metadata)
        digest = receipt.hashlib.sha256(metadata.read_bytes()).hexdigest()
        receipt.validate_memory_derivation(self.root, digest)
        self.assertEqual("// fixture\n// memory path\n", path.read_text())
        path.write_text(path.read_text() + "// unrelated removal\n")
        with self.assertRaises(receipt.InvalidReceipt):
            receipt.validate_memory_derivation(self.root, digest)

    def test_memory_entrypoint_missing_duplicate_or_mutated_anchor_fails_closed(self):
        original = "".join(receipt.SCAN_DISPATCH)
        for block in receipt.SCAN_DISPATCH:
            for broken in (original.replace(block, ""), original + block,
                           original.replace(block, block.replace("recovery_scan", "wrong_scan"))):
                with self.subTest(block=block, broken=broken):
                    path = self.root / "main.rs"
                    path.write_text(broken)
                    with self.assertRaises(receipt.InvalidReceipt):
                        receipt.normalize_memory_entrypoint(path, self.root / "derivation.json")
                    self.assertEqual(broken, path.read_text())

    def test_live_memory_entrypoint_derives_without_other_source_changes(self):
        source = Path(__file__).parent / "rrharness/src/main.rs"
        path = self.root / "main.rs"
        original = source.read_text()
        path.write_text(original)
        receipt.normalize_memory_entrypoint(path, self.root / "derivation.json")
        expected = original
        for block in receipt.SCAN_DISPATCH:
            expected = expected.replace(block, "", 1)
        self.assertEqual(expected, path.read_text())


if __name__ == "__main__":
    unittest.main()
