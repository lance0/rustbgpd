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
import sys
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

    def control_api_tree(self, swaps: bool) -> tuple[Path, Path]:
        update = self.root / "crates/rib/src/update.rs"
        update.parent.mkdir(parents=True, exist_ok=True)
        field = "        swaps: Option<Vec<DatasetSwap>>,\n" if swaps else ""
        update.write_text(
            "pub enum RibUpdate {\n    ReevaluatePeerExportPolicies {\n"
            "        peers: Vec<IpAddr>,\n" + field
            + "        reply: oneshot::Sender<()>,\n    },\n    ConditionalSwaps {\n"
            "        swaps: (),\n    },\n}\n",
            encoding="utf-8",
        )
        harness = self.root / "bench/scale/rrharness/src/recovery_memory.rs"
        harness.parent.mkdir(parents=True, exist_ok=True)
        request = ("            .send(RibUpdate::ReevaluatePeerExportPolicies {\n"
                   "                peers: vec![peer],\n" + receipt.HARNESS_SWAPS
                   + "                reply,\n            })\n")
        harness.write_text(request + "\n" + request, encoding="utf-8")
        return self.root, harness

    def test_control_api_drops_default_swaps_only_for_historical_requests(self) -> None:
        tree, harness = self.control_api_tree(swaps=True)
        original = harness.read_text(encoding="utf-8")
        receipt.derive_control_api(tree)
        self.assertEqual(harness.read_text(encoding="utf-8"), original)
        tree, harness = self.control_api_tree(swaps=False)
        receipt.derive_control_api(tree)
        derived = harness.read_text(encoding="utf-8")
        self.assertEqual(derived, original.replace(receipt.HARNESS_SWAPS, ""))
        self.assertNotIn("swaps", derived)

    def test_control_api_refuses_non_default_swaps_for_historical_requests(self) -> None:
        tree, harness = self.control_api_tree(swaps=False)
        harness.write_text(
            harness.read_text(encoding="utf-8").replace("swaps: None", "swaps: Some(vec![])", 1),
            encoding="utf-8",
        )
        original = harness.read_bytes()
        with self.assertRaisesRegex(receipt.InvalidReceipt, "non-default dataset swaps"):
            receipt.derive_control_api(tree)
        self.assertEqual(harness.read_bytes(), original)

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

    def run_workflow_failure(self, status: int, *, expired: bool = False, mode: str = "memory",
                             old_order: str = "sorted") -> Path:
        commands = self.root / f"commands-{status}-{expired}-{old_order}"
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
        temporary = self.root / f"runner-{status}-{expired}-{old_order}"
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
            RECOVERY_SCAN_OLD_ORDER=old_order,
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
            self.assertEqual("--shuffled-old" in invocation,
                             mode == "scan" and old_order == "shuffled")
        return evidence

    def test_workflow_finalizes_timeout_and_kill_preserving_original_exit(self) -> None:
        for status in (124, 137):
            with self.subTest(status=status):
                self.run_workflow_failure(status)

    def test_workflow_expired_setup_budget_does_not_start_driver(self) -> None:
        self.run_workflow_failure(124, expired=True)

    def test_scan_workflow_finalizes_failure_preserving_original_exit(self) -> None:
        for old_order in ("sorted", "shuffled"):
            for status, expired in ((124, False), (137, False), (124, True)):
                with self.subTest(status=status, expired=expired, old_order=old_order):
                    self.run_workflow_failure(status, expired=expired, mode="scan", old_order=old_order)

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

    def test_scope_scan_forwards_the_old_order_flag(self):
        source = Path(__file__).with_name("compare-recovery-memory.sh").read_text()
        scoped = source[source.index('if [[ ${1:-} == --scope-worker'):source.index('\n[[ $# -ge 4')]
        fixture = ('set -euo pipefail\n'
                   'daemon_scope_cgroup() { printf /fixture.scope; }\n'
                   'record_scope_peak() { :; }\n'
                   'python3() { printf "%s\\n" "$@"; }\n'
                   'fail() { exit 1; }\nchecker=fixture-checker\n')
        for shuffled in (False, True):
            with self.subTest(shuffled=shuffled):
                options = ["--shuffled-old"] if shuffled else []
                result = subprocess.run(
                    ["bash", "-c", fixture + scoped, "scope-fixture", "--scope-scan",
                     "/binary", "/output", "capture-scan", "a" * 64, "full-uc", "1", *options],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), ["fixture-checker", "run-scope",
                    "/binary", "/output", "capture-scan", "/fixture.scope", "a" * 64,
                    "full-uc", "1", "--scan", *options])

    def test_run_scope_forwards_order_to_the_actual_harness_command(self):
        for shuffled in (False, True):
            with self.subTest(shuffled=shuffled):
                output = self.root / str(shuffled)
                checker = {"pid": 1, "executable": str(Path(sys.executable).resolve())}
                launcher = {"pid": 2, "executable": str(Path(shutil.which("bash")).resolve())}
                with (patch.object(receipt, "proc_identity", side_effect=[checker, launcher]),
                      patch.object(receipt, "snapshot_scope"),
                      patch.object(receipt, "capture_ownership"),
                      patch.object(receipt.subprocess, "Popen", side_effect=RuntimeError("stop before spawn"))):
                    with self.assertRaisesRegex(RuntimeError, "stop before spawn"):
                        receipt.run_scope(Path("/binary"), output, "capture-scan", Path("/fixture.scope"),
                                          "a" * 64, "full-uc", 1, scan=True, shuffled_old=shuffled)
                self.assertEqual(json.loads((output / "command.json").read_text()),
                                 ["/binary", "recovery-scan", "full-uc"] +
                                 (["--shuffled-old"] if shuffled else []))

    def test_scan_order_is_pinned_across_manifest_environment_and_every_sample(self):
        for old_order in ("sorted", "shuffled"):
            with self.subTest(old_order=old_order):
                rows = self.rows(old_order=old_order)
                root = self.campaign(rows)
                result = self.summarize_campaign(root)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads((root / "comparison.json").read_text())["old_order"], old_order)
                for bad_order in (None, "random", "shuffled" if old_order == "sorted" else "sorted"):
                    manifest = json.loads((root / "manifest.json").read_text())
                    manifest["old_order"] = bad_order
                    receipt.write_json(root / "manifest.json", manifest)
                    self.assertEqual(self.summarize_campaign(root).returncode, 1)
                for bad_row in (0, 1, 23):
                    broken = self.rows(old_order=old_order)
                    broken[bad_row]["old_order"] = "shuffled" if old_order == "sorted" else None
                    with self.assertRaisesRegex(receipt.InvalidReceipt, "scan shape/order/mode mismatch"):
                        receipt.validate_scan_log(self.log(broken, old_order), "evpn-soak", old_order)
                path = self.log(rows)
                text = path.read_text().replace('"old_order": "' + old_order + '"',
                                                '"old_order": "random"', 1)
                path.write_text(text)
                with self.assertRaisesRegex(receipt.InvalidReceipt, "environment OLD order mismatch"):
                    receipt.validate_scan_log(path, "evpn-soak", old_order)

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
            [[ $1 == --scope-scan && ( $# == 7 || $# == 8 ) ]] || exit 1
            env > "$3/child-environment"
            printf '%s\n' "$@" > "$3/child-arguments"
            """))
        for override, shuffled in ((False, False), (False, True), (True, False), (True, True)):
            with self.subTest(override=override, shuffled=shuffled):
                output = self.root / str((override, shuffled))
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
                     'profile=evpn-soak; status=0; scan_options=(); '
                     '[[ $3 != shuffled ]] || scan_options=(--shuffled-old)\n' + launch + '\nexit "$status"',
                     "scan-fixture", str(output), str(driver), "shuffled" if shuffled else "sorted"],
                    env=environment, capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                child = dict(line.split("=", 1) for line in
                             (output / "scan/child-environment").read_text().splitlines())
                self.assertEqual("--shuffled-old" in
                                 (output / "scan/child-arguments").read_text().splitlines(), shuffled)
                identity_names = ("GITHUB_ACTIONS", "RECOVERY_MEMORY_RUNNER_ENVIRONMENT",
                                  "RUNNER_ENVIRONMENT", "RUNNER_OS", "UNRELATED_PARENT_ONLY")
                self.assertEqual({name: child[name] for name in identity_names if name in child},
                                 {"GITHUB_ACTIONS": "true",
                                  "RECOVERY_MEMORY_RUNNER_ENVIRONMENT": "github-hosted"})

    def rows(self, profile="evpn-soak", old_order="sorted"):
        keys = receipt.SCAN_PROFILES[profile]
        rows = []
        for records in (2, 64, 480):
            for layout in ("dense", "older-sparse"):
                sparse = records if layout == "older-sparse" else 0
                for leg, arm in enumerate(("flat", "candidate", "candidate", "flat")):
                    shared = arm == "candidate" and profile != "full-vpn"
                    comparisons = (keys if profile == "full-uc" else 2 * keys) if shared else 0
                    slots = keys + sparse // 2 if profile == "full-uc" else 0
                    rows.append(dict(
                        schema=receipt.SCAN_SCHEMA, profile=profile, old_order=old_order,
                        vpn_negotiated=profile == "full-vpn", keys=keys, records=records, layout=layout, arm=arm, leg=leg,
                        measured=True, old_keys=keys, additions=sparse if shared else 0,
                        shape_callbacks=(slots if profile == "full-uc" else keys) + comparisons,
                        comparison_counter_scope="ordered-evpn-checkpoints-minus-old-visits" if profile == "evpn-soak" else "typed-full-old-shape",
                        comparisons=comparisons, mismatches=sparse if shared and profile == "full-uc" else 0,
                        source_slots=slots,
                        selected_strategy=("uc-slab-shared" if profile == "full-uc" else "evpn-sort-shared") if shared else "exact-flat",
                        selection_reason="explicit-flat-control" if arm == "flat" else ("vpn-negotiated" if profile == "full-vpn" else "eligible"),
                        cold_anchor_strategy="not-measured" if profile == "evpn-soak" else ("uc-slab-shared" if profile == "full-uc" else "exact-flat"),
                        cold_anchor_unavailable_reason="evpn-not-production-cold-path" if profile == "evpn-soak" else None,
                        proof_keys=keys, shared=shared, retained_bytes=8192, peak_bytes=9000,
                        empty_bytes=56, settled_bytes=56, refusal=None,
                        phases={"shape": {"wall_ns": 1000, "cpu_ticks": 1},
                                "capture": {"wall_ns": 2000, "cpu_ticks": 2},
                                "cold_anchor_capture": None if profile == "evpn-soak" else {"wall_ns": 3000, "cpu_ticks": 3}},
                    ))
        return rows

    def log(self, rows, old_order=None):
        profile = rows[0]["profile"]
        lines = ["recovery_identity " + json.dumps({"pid": 123, "start_ticks": 456}),
                 "recovery_scan_environment " + json.dumps({"schema": receipt.SCAN_SCHEMA,
                    "old_order": rows[0]["old_order"] if old_order is None else old_order,
                    "cpu_ticks_per_second": 100,
                    "phase_passes": "shape independently invoked; cold anchor and warm capture are separate intervals",
                    "fixture_lineage": "common families use one actual AdjRibOut; order is insertion order; sparse mutation reuses and appends slots",
                    "cold_scope": "common anchor begin/full helper/seal; identical policy before both warm arms; no attributable cold arm ratio; EVPN cold unmeasured",
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
            "schema": "rustbgpd.recovery-scan.campaign.v3", "candidate": "a" * 40,
            "instrumentation_manifest_sha256": receipt.file_digest(inputs),
            "profile": rows[0]["profile"], "old_order": rows[0]["old_order"], "build_jobs": 4,
            "order_per_cell": ["flat", "candidate", "candidate", "flat"],
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
                        if phase is not None:
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
                    self.assertIsNone(cell["candidate_over_flat"]["capture"]["cpu_ticks"])
                    self.assertEqual(cell["candidate_over_flat"]["capture"]["wall_ns"], 1.0)

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


    def test_scan_v3_requires_the_actual_selected_production_strategy(self):
        for profile, reason in (("full-uc", "missing-index"), ("full-uc", "slot-churn"),
                                ("full-vpn", "eligible")):
            with self.subTest(profile=profile, reason=reason):
                rows = self.rows(profile)
                row = rows[1]
                if profile == "full-uc":
                    row.update(selected_strategy="exact-flat", selection_reason=reason, shared=False,
                               additions=0, comparisons=0, shape_callbacks=row["source_slots"])
                else:
                    row.update(selected_strategy="uc-slab-shared", selection_reason=reason, shared=True)
                root = self.campaign(rows)
                completed = self.summarize_campaign(root)
                self.assertEqual(completed.returncode, 1, completed.stderr)
                result = json.loads((root / "comparison.json").read_text())
                self.assertFalse(result["qualification_passed"])
                self.assertIsNone(result["comparisons"][0]["candidate_over_flat"])
                self.assertIsNone(result["samples"][1]["refusal"])

    def test_scan_v3_reports_flat_vpn_and_separates_common_cold_anchor_policy(self):
        for profile in receipt.SCAN_PROFILES:
            with self.subTest(profile=profile):
                rows = self.rows(profile)
                result = receipt.validate_scan_log(self.log(rows), profile)
                for cell in result["comparisons"]:
                    self.assertEqual(set(cell["candidate_over_flat"]), {"shape", "capture"})
                if profile == "full-vpn":
                    self.assertTrue(all(not row["shared"] and row["selected_strategy"] == "exact-flat"
                                        for row in rows))
                else:
                    for bad in ("cold-policy", "unavailable-zero", "unavailable-fabricated", "slab-lineage"):
                        if bad == "unavailable-fabricated" and profile != "evpn-soak":
                            continue
                        broken = self.rows(profile)
                        if bad == "cold-policy":
                            broken[1]["cold_anchor_strategy"] = "exact-flat"
                        elif bad.startswith("unavailable"):
                            broken[1]["phases"]["cold_anchor_capture"] = {
                                "wall_ns": 0 if bad == "unavailable-zero" else 1, "cpu_ticks": 0}
                        else:
                            broken[5]["source_slots"] += 1
                            broken[5]["shape_callbacks"] += 1
                        with self.assertRaises(receipt.InvalidReceipt):
                            receipt.validate_scan_log(self.log(broken), profile)

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
            self.assertEqual(1.0, result["comparisons"][0]["candidate_over_flat"]["shape"]["wall_ns"])

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

    def test_scan_v3_rejects_binary_search_work_and_historical_schema(self):
        keys = receipt.SCAN_PROFILES["evpn-soak"]
        rows = self.rows()
        rows[1]["comparisons"] = keys * keys.bit_length()
        rows[1]["shape_callbacks"] = keys + rows[1]["comparisons"]
        with self.assertRaisesRegex(receipt.InvalidReceipt, "non-linear classification"):
            receipt.validate_scan_log(self.log(rows), "evpn-soak")
        rows = self.rows()
        rows[1]["schema"] = "rustbgpd.recovery-scan.v2"
        with self.assertRaisesRegex(receipt.InvalidReceipt, "scan shape/order/mode mismatch"):
            receipt.validate_scan_log(self.log(rows), "evpn-soak")

    def test_scan_v3_pins_typed_common_and_derived_evpn_comparison_scopes(self):
        for profile in receipt.SCAN_PROFILES:
            rows = self.rows(profile)
            rows[1]["comparison_counter_scope"] = "callbacks-minus-keys"
            with self.assertRaisesRegex(receipt.InvalidReceipt, "counter scope differs"):
                receipt.validate_scan_log(self.log(rows), profile)
        # Losing the OLD-visit or the per-comparison checkpoint must not
        # become an apparently cheaper measurement of the unchanged EVPN walk.
        rows = self.rows()
        keys = receipt.SCAN_PROFILES["evpn-soak"]
        rows[1].update(comparisons=keys, shape_callbacks=2 * keys)
        with self.assertRaisesRegex(receipt.InvalidReceipt, "missing sorted merge work"):
            receipt.validate_scan_log(self.log(rows), "evpn-soak")

    def test_scan_refusal_is_retained_without_a_ratio(self):
        rows = self.rows()
        rows[1].update(refusal="peer_limit", proof_keys=0, phases={})
        result = receipt.validate_scan_log(self.log(rows), "evpn-soak")
        self.assertEqual("peer_limit", result["samples"][1]["refusal"])
        self.assertFalse(result["comparisons"][0]["eligible"])
        self.assertIsNone(result["comparisons"][0]["candidate_over_flat"])

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
                    self.assertTrue(all(c["candidate_over_flat"] for c in result["comparisons"]))
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
        self.assertIsNone(result["comparisons"][0]["candidate_over_flat"]["shape"]["cpu_ticks"])

    def test_independent_shape_can_exceed_capture_without_fake_tick_minimum(self):
        rows = self.rows()
        for row in rows:
            row["phases"]["shape"].update(wall_ns=3000, cpu_ticks=1)
            row["phases"]["capture"].update(wall_ns=2000, cpu_ticks=0)
        result = receipt.validate_scan_log(self.log(rows), "evpn-soak")
        self.assertTrue(all(row["eligible"] for row in result["comparisons"]))
        self.assertIsNone(result["comparisons"][0]["candidate_over_flat"]["capture"]["cpu_ticks"])

    def test_memory_entrypoint_derivation_is_exact_and_verifiable(self):
        path = self.root / "frozen-instrumentation/bench/scale/rrharness/src/main.rs"
        path.parent.mkdir(parents=True)
        original = "// fixture\n" + "".join(receipt.COMPONENT_DISPATCH) + "// memory path\n"
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
        original = "".join(receipt.COMPONENT_DISPATCH)
        for block in receipt.COMPONENT_DISPATCH:
            for broken in (original.replace(block, ""), original + block,
                           original.replace(block, block.replace("recovery_", "wrong_"))):
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
        for block in receipt.COMPONENT_DISPATCH:
            expected = expected.replace(block, "", 1)
        self.assertEqual(expected, path.read_text())

    def test_memory_entrypoint_legacy_scan_only_normalizes(self):
        path = self.root / "main.rs"
        original = "// legacy v2 fixture\n" + "".join(receipt.SCAN_DISPATCH) + "// memory path\n"
        path.write_text(original)
        metadata = self.root / "derivation.json"
        receipt.normalize_memory_entrypoint(path, metadata)
        self.assertEqual(path.read_text(), "// legacy v2 fixture\n// memory path\n")
        self.assertEqual(json.loads(metadata.read_text())["removed_exact_snippets"], list(receipt.SCAN_DISPATCH))

    def test_memory_entrypoint_legacy_v2_derivation_replays(self):
        path = self.root / "frozen-instrumentation/bench/scale/rrharness/src/main.rs"
        path.parent.mkdir(parents=True)
        original = "// legacy v2 fixture\n" + "".join(receipt.SCAN_DISPATCH) + "// memory path\n"
        derived = original
        for block in receipt.SCAN_DISPATCH:
            derived = derived.replace(block, "", 1)
        patch = "".join(receipt.difflib.unified_diff(original.splitlines(True), derived.splitlines(True),
                      fromfile="committed/main.rs", tofile="memory/main.rs"))
        path.write_text(derived)
        metadata = self.root / "memory-entrypoint-derivation.json"
        metadata.with_suffix(".source.rs").write_text(original)
        metadata.with_suffix(".patch").write_text(patch)
        receipt.write_json(metadata, {"source_sha256": receipt.hashlib.sha256(original.encode()).hexdigest(),
                          "derived_sha256": receipt.hashlib.sha256(derived.encode()).hexdigest(),
                          "patch_sha256": receipt.hashlib.sha256(patch.encode()).hexdigest(),
                          "removed_exact_snippets": list(receipt.SCAN_DISPATCH)})
        receipt.validate_memory_derivation(self.root, receipt.file_digest(metadata))

    def test_memory_entrypoint_rejects_resealed_partial_mixed_or_unknown_metadata(self):
        path = self.root / "frozen-instrumentation/bench/scale/rrharness/src/main.rs"
        path.parent.mkdir(parents=True)
        path.write_text("".join(receipt.COMPONENT_DISPATCH))
        metadata = self.root / "memory-entrypoint-derivation.json"
        receipt.normalize_memory_entrypoint(path, metadata)
        original = json.loads(metadata.read_text())
        for snippets in (list(receipt.SCAN_DISPATCH), list(receipt.COMPONENT_DISPATCH[:-1]),
                         [*receipt.COMPONENT_DISPATCH, receipt.COMPONENT_DISPATCH[0]],
                         ["unknown component dispatch"], list(reversed(receipt.COMPONENT_DISPATCH))):
            with self.subTest(snippets=snippets):
                receipt.write_json(metadata, {**original, "removed_exact_snippets": snippets})
                with self.assertRaises(receipt.InvalidReceipt):
                    receipt.validate_memory_derivation(self.root, receipt.file_digest(metadata))


class RetirementReceiptTests(unittest.TestCase):
    def setUp(self):
        self.fixture = RecoveryReceiptTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root

    def with_readiness(self, row):
        measured, keys = row["measured"], row["keys"]
        target = ("private_outbound_cleanup" if row["cell"].startswith("retirement-adj-out-") else
                  "regroup_baseline_cleanup" if row["cell"].startswith("retirement-regroup-") else
                  "received_cleanup_including_gc")
        owners = {}
        for name in ("received_cleanup_including_gc", "private_outbound_cleanup", "regroup_baseline_cleanup"):
            active, overlap = name == target, name == target and keys > 0
            owners[name] = {"owners": int(active), "invalid_owners": 0,
                            "callbacks": keys + 2 if active else 0, "body_callbacks": keys if active else 0,
                            "admitted": int(overlap), "serviced": int(overlap), "replied": int(overlap),
                            "body_replied": int(overlap),
                            "overlap": overlap, "eligible": measured and overlap,
                            "max_checkpoint_interval_ns": 20_000_000 if measured and active else None,
                            "max_eligible_opportunity_gap_ns": 40_000_000 if measured and active else None,
                            "service_budget_ns": 25_000_000 if measured and active else None}
        row["readiness"] = {"probe": {"attempts": 3, "admitted": 3, "replied": 3, "errors": 0,
                                      "max_inflight": 1, "before_capture_replies": 1, "after_barrier_replies": 1,
                                      "max_reserve_wait_ns": 1 if measured else None,
                                      "max_enqueue_reply_ns": 100 if measured else None,
                                      "max_attempt_reply_ns": 101 if measured else None,
                                      "max_refill_gap_ns": 10 if measured else None}, "owners": owners}
        return row

    def test_retirement_readiness_distinguishes_callback_gap_opportunity_and_reply_latency(self):
        for cell in receipt.RETIREMENT_CELLS:
            for measured in (False, True):
                with self.subTest(cell=cell, measured=measured):
                    row = self.with_readiness(self.row(cell=cell, measured=measured))
                    receipt.validate_retirement_log(self.log(row), "full-vpn", cell, measured=measured,
                                                     readiness_required=True)
        # A legitimate 40 ms eligible-opportunity gap is not the 25 ms callback bar.

    def test_retirement_readiness_rejects_missing_evidence_and_probe_failures(self):
        row = self.row()
        with self.assertRaisesRegex(receipt.InvalidReceipt, "missing retirement readiness"):
            receipt.validate_retirement_log(self.log(row), "full-vpn", "retirement-full", readiness_required=True)
        for field, value in (("errors", 1), ("max_inflight", 2), ("before_capture_replies", 0),
                             ("after_barrier_replies", 0), ("admitted", 2), ("replied", 2),
                             ("max_enqueue_reply_ns", 102), ("max_attempt_reply_ns", 200_000_001)):
            with self.subTest(field=field):
                row = self.with_readiness(self.row())
                row["readiness"]["probe"][field] = value
                with self.assertRaises(receipt.InvalidReceipt):
                    receipt.validate_retirement_log(self.log(row), "full-vpn", "retirement-full")

    def test_retirement_readiness_rejects_false_owner_or_body_and_missing_real_overlap(self):
        for field, value in (("owners", 0), ("owners", 2), ("invalid_owners", 1),
                             ("body_callbacks", 1_229_999), ("callbacks", 1_230_001),
                             ("admitted", 0), ("replied", 0), ("serviced", 0), ("body_replied", 0),
                             ("overlap", False), ("eligible", False),
                             ("max_checkpoint_interval_ns", 25_000_001), ("service_budget_ns", 26_000_000)):
            with self.subTest(field=field):
                row = self.with_readiness(self.row())
                row["readiness"]["owners"]["received_cleanup_including_gc"][field] = value
                with self.assertRaises(receipt.InvalidReceipt):
                    receipt.validate_retirement_log(self.log(row), "full-vpn", "retirement-full")
        row = self.with_readiness(self.row())
        owner = row["readiness"]["owners"]["received_cleanup_including_gc"]
        owner.update(admitted=0, serviced=0, replied=0, body_replied=0, overlap=False, eligible=False)
        with self.assertRaisesRegex(receipt.InvalidReceipt, "lacks real in-owner"):
            receipt.validate_retirement_log(self.log(row), "full-vpn", "retirement-full")

    def test_retirement_readiness_boundary_only_replies_cannot_qualify_full_cleanup(self):
        row = self.with_readiness(self.row())
        owner = row["readiness"]["owners"]["received_cleanup_including_gc"]
        # Preserve the full real body count and healthy boundary admissions/
        # replies. Neither forced entry nor final-exit service proves body overlap.
        owner.update(admitted=2, serviced=2, replied=2, body_replied=0, overlap=False, eligible=False)
        with self.assertRaisesRegex(receipt.InvalidReceipt, "nonforced cleanup callback"):
            receipt.validate_retirement_log(self.log(row), "full-vpn", "retirement-full")

    def test_retirement_readiness_rejects_owner_replies_without_interior_probe(self):
        for measured in (False, True):
            with self.subTest(measured=measured):
                row = self.with_readiness(self.row(measured=measured))
                # Both producer replies are the required before/after probes;
                # neither can also prove a reply inside the cleanup owner.
                row["readiness"]["probe"].update(attempts=2, admitted=2, replied=2)
                with self.assertRaisesRegex(receipt.InvalidReceipt, "owner replies exceed interior"):
                    receipt.validate_retirement_log(self.log(row), "full-vpn", "retirement-full",
                                                     measured=measured)

    def test_retirement_readiness_sums_replies_across_owners(self):
        row = self.with_readiness(self.row())
        owners = row["readiness"]["owners"]
        # A separate, empty cleanup owner can answer a request too. Its reply
        # still consumes a distinct producer request outside the two sentinels.
        owners["private_outbound_cleanup"].update(
            owners=1, callbacks=2, admitted=1, serviced=1, replied=1,
            max_checkpoint_interval_ns=20_000_000,
            max_eligible_opportunity_gap_ns=40_000_000, service_budget_ns=25_000_000)
        with self.assertRaisesRegex(receipt.InvalidReceipt, "owner replies exceed interior"):
            receipt.validate_retirement_log(self.log(row), "full-vpn", "retirement-full")
        row["readiness"]["probe"].update(attempts=4, admitted=4, replied=4)
        receipt.validate_retirement_log(self.log(row), "full-vpn", "retirement-full")

    def test_retirement_readiness_rejects_owner_admissions_without_interior_probe(self):
        for count in (1, 2):
            with self.subTest(owners=count):
                row = self.with_readiness(self.row(cell="retirement-empty"))
                total = count + 1  # One fewer interior request than claimed admissions.
                row["readiness"]["probe"].update(attempts=total, admitted=total, replied=total)
                names = ("received_cleanup_including_gc", "private_outbound_cleanup")
                for name in names[:count]:
                    row["readiness"]["owners"][name].update(
                        owners=1, callbacks=2, admitted=1, serviced=1,
                        max_checkpoint_interval_ns=20_000_000,
                        max_eligible_opportunity_gap_ns=40_000_000, service_budget_ns=25_000_000)
                with self.assertRaisesRegex(receipt.InvalidReceipt, "owner admissions exceed interior"):
                    receipt.validate_retirement_log(self.log(row), "full-vpn", "retirement-empty")

    def test_retirement_readiness_accepts_empty_boundaries_and_preowner_service(self):
        row = self.with_readiness(self.row(cell="retirement-empty"))
        row["readiness"]["probe"].update(attempts=2, admitted=2, replied=2)
        receipt.validate_retirement_log(self.log(row), "full-vpn", "retirement-empty")
        # An interior request queued before owner entry counts as serviced,
        # without claiming in-owner admission or delivery.
        row["readiness"]["probe"].update(attempts=3, admitted=3, replied=3)
        row["readiness"]["owners"]["received_cleanup_including_gc"]["serviced"] = 1
        receipt.validate_retirement_log(self.log(row), "full-vpn", "retirement-empty")

    def test_retirement_readiness_correctness_requires_null_all_clocks_and_never_qualifies(self):
        for section, field in (("probe", "max_refill_gap_ns"), ("probe", "max_enqueue_reply_ns"),
                               ("received_cleanup_including_gc", "max_checkpoint_interval_ns"),
                               ("received_cleanup_including_gc", "max_eligible_opportunity_gap_ns"),
                               ("received_cleanup_including_gc", "service_budget_ns")):
            with self.subTest(section=section, field=field):
                row = self.with_readiness(self.row(measured=False))
                destination = row["readiness"]["probe"] if section == "probe" else row["readiness"]["owners"][section]
                destination[field] = 1
                with self.assertRaises(receipt.InvalidReceipt):
                    receipt.validate_retirement_log(self.log(row), "full-vpn", "retirement-full", measured=False)

    def test_retirement_v3_campaign_requires_readiness_and_preserves_v1_v2(self):
        root = self.campaign(receiver_cases=True, readiness=True)
        receipt.summarize_retirement(root)
        self.assertEqual(json.loads((root / "comparison.json").read_text())["schema"], "rustbgpd.retirement-timing.v3")
        directory = root / "retirement-regroup-full-1-candidate"
        lines = (directory / "harness.log").read_text().splitlines()
        row = json.loads(lines[-1].removeprefix("retirement_receipt "))
        del row["readiness"]
        lines[-1] = "retirement_receipt " + json.dumps(row)
        (directory / "harness.log").write_text("\n".join(lines) + "\n")
        receipt.write_json(directory / "raw-sha256.json", receipt.retirement_raw_hashes(directory))
        with self.assertRaisesRegex(receipt.InvalidReceipt, "missing retirement readiness"):
            receipt.summarize_retirement(root)

    def row(self, profile="full-vpn", cell="retirement-full", measured=True):
        if cell not in receipt.RETIREMENT_CELLS[:2]:
            return self.receiver_row(profile, cell, measured)
        seed = receipt.PROFILES[profile][0] if cell == "retirement-full" else (0, 0, 0, 0)
        keys = sum(seed)
        families = lambda settled: {name: {"present": 0 if settled else n, "announces": n,
                                          "withdrawals": n if settled else 0}
                                    for name, n in zip(receipt.FAMILIES, seed, strict=True)}
        vpn = keys > 0 and "vpn" in profile
        return {"profile": profile, "cell": cell, "measured": measured, "receivers": 1, "keys": keys,
                "initial": families(False), "settled": families(True),
                "vpn_stage": {"calls": int(vpn), "keys": keys if vpn else 0, "groups": int(vpn),
                              "elapsed_ns": 100 if vpn and measured else None},
                "adj_rib_in": {"calls": 1, "keys": keys, "groups": 0,
                               "elapsed_ns": 200 if measured else None},
                "operation_to_barrier_ns": 500 if measured else None}

    def receiver_row(self, profile, cell, measured=True):
        private = cell.startswith("retirement-adj-out-")
        full = cell.endswith("-full")
        original = receipt.PROFILES[profile][0]
        seed = tuple(int(count > 0) for count in original) if private else (original if full else (0,) * 4)
        keys = sum(original) if full else 0
        first = next(index for index, count in enumerate(original) if count)
        def families(settled):
            return {family: {"present": count, "announces": count + (4 if settled and not private and index == first else 0),
                             "withdrawals": 4 if settled and not private and index == first else 0}
                    for index, (family, count) in enumerate(zip(receipt.FAMILIES, seed, strict=True))}
        zero = {"present": 0, "announces": 0, "withdrawals": 0}
        evpn = {"present": keys, "announces": max(keys, 1), "withdrawals": int(not full)} if private else zero
        def phase(active, retired):
            return {"calls": int(active), "keys": retired, "groups": 0,
                    "elapsed_ns": 100 if measured and active else None}
        return {"profile": profile, "cell": cell, "measured": measured, "receivers": 2, "keys": keys,
                "initial": {name: families(False) for name in ("target", "witness")},
                "settled": {name: families(True) for name in ("target", "witness")},
                "private_evpn": {boundary: {name: evpn.copy() for name in ("target", "witness")}
                                 for boundary in ("initial", "settled")},
                "preparation": {"inputs": 0 if private else 8, "target_queue_capacity": 8 if private else 0,
                                "dirty_peers": int(not private), "group_dirty_members": int(not private),
                                "regroup_baselines": int(not private)},
                "survivors": {"target_group_before": "group:0", "witness_group_before": "group:0",
                              "target_group_after": "", "witness_group_after": "group:0",
                              "source_group_before": "group:1", "source_group_after": "group:1",
                              "source_fold": dict.fromkeys(receipt.FAMILIES, zero), "source_evpn_fold": zero,
                              "selected": list(seed), "evpn_received_best": [keys if private else 0] * 2,
                              "health": [0] * 6},
                "vpn_stage": phase(False, 0), "adj_rib_in": phase(False, 0),
                "adj_rib_out": phase(True, keys if private else 0),
                "regroup_baseline": phase(not private, keys if not private else 0),
                "operation_to_barrier_ns": 500 if measured else None}

    def log(self, row, path=None, identity=None):
        path = path or self.root / "retirement.log"
        prefix = ""
        if row["measured"]:
            prefix = "recovery_identity " + json.dumps(identity or {"pid": 123, "start_ticks": 456}) + "\n"
        path.write_text(prefix + "retirement_receipt " + json.dumps(row) + "\n")
        return path

    def campaign(self, profile="full-vpn", receiver_cases=False, readiness=False):
        root = self.fixture.campaign(selected_cell="peer-down")
        template = root / "ipv4-100k-peer-down-baseline-2-candidate"
        names = {*receipt.INSTRUMENT_INPUTS, *receipt.RETIREMENT_INPUTS}
        if readiness:
            names.add(receipt.RETIREMENT_READINESS_INPUT)
        maps = {}
        inputs = []
        repository = Path(receipt.__file__).resolve().parents[2]
        for name in sorted(names):
            path = root / "frozen-instrumentation" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((repository / name).read_bytes())
            maps[name] = receipt.file_digest(path)
            inputs.append(maps[name] + "  " + name + "\n")
        maps.update({name: "d" * 64 for name in ("Cargo.toml", "Cargo.lock", "crates/rib/Cargo.toml")})
        (root / "instrumentation.sha256").write_text("".join(inputs))
        instrumentation = receipt.file_digest(root / "instrumentation.sha256")
        manifest = {"schema": "rustbgpd.retirement-timing.campaign.v3" if readiness else "rustbgpd.retirement-timing.campaign.v2" if receiver_cases else "rustbgpd.retirement-timing.campaign.v1", "candidate": "a" * 40,
                    "instrumentation_manifest_sha256": instrumentation, "profile": profile,
                    "order": list(receipt.RETIREMENT_ORDER),
                    "cells": list(receipt.RETIREMENT_CELLS if receiver_cases else receipt.RETIREMENT_CELLS[:2]),
                    "memory_max": receipt.RETIREMENT_LIMIT}
        receipt.write_json(root / "manifest.json", manifest)
        receipt.write_json(root / "committed-inputs.json", maps)
        receipt.write_json(root / "cleanup-proof.json", {"candidate_worktree_exit": 0,
                           "old_drop_worktree_exit": 0, "scratch_remove_exit": 0})
        receipt.write_json(root / "retirement-preflight.json", {"available_bytes": receipt.RETIREMENT_LIMIT,
                           "minimum_bytes": receipt.RETIREMENT_LIMIT, "memory_max": receipt.RETIREMENT_LIMIT, "swap_max": 0})
        (root / "driver.exit").write_text("0\n")
        original = (root / "frozen-instrumentation" / receipt.RETIREMENT_SOURCE).read_text()
        control = receipt.retirement_control(original)
        (root / "old-drop-source.rs").write_text(control)
        (root / "bin").mkdir()
        for role in ("candidate", "old-drop"):
            role_map = maps.copy()
            if role == "old-drop":
                role_map[receipt.RETIREMENT_SOURCE] = receipt.hashlib.sha256(control.encode()).hexdigest()
            for suffix in ("inputs", "inputs-after"):
                receipt.write_json(root / f"{role}-{suffix}.json", role_map)
            (root / f"{role}-build.log").write_text("Compiling rustbgpd-rib v0.0.0\n")
            (root / f"{role}-build.exit").write_text("0\n")
            (root / "bin" / role).write_text(role)
            (root / f"{role}-binary.sha256").write_text(receipt.file_digest(root / "bin" / role) + "\n")
        ordinal = 0
        for cell in manifest["cells"]:
            for leg, role in enumerate(receipt.RETIREMENT_ORDER):
                directory = root / f"{cell}-{leg}-{role}"
                shutil.copytree(template, directory)
                process = json.loads((directory / "binary-process.json").read_text())
                process.update(executable=str(root / "bin" / role), exe_sha256=receipt.file_digest(root / "bin" / role))
                owners = {name: json.loads((directory / name).read_text())
                          for name in ("launcher-process.json", "scope-process.json")}
                owners["binary-process.json"] = process
                cgroup = f"/sys/fs/cgroup/retirement-{ordinal}.scope"
                mapping = {item["pid"]: 10000 + ordinal * 3 + index
                           for index, item in enumerate(owners.values())}
                fresh = {}
                for index, (name, item) in enumerate(owners.items()):
                    old_pid = item["pid"]
                    item = {**item, "pid": mapping[old_pid],
                            "parent_pid": mapping.get(item["parent_pid"], item["parent_pid"]),
                            "start_ticks": 50000 + ordinal * 3 + index,
                            "cgroup": "0::" + cgroup.removeprefix("/sys/fs/cgroup") + "\n"}
                    fresh[old_pid] = item
                    receipt.write_json(directory / name, item)
                process = json.loads((directory / "binary-process.json").read_text())
                (directory / "cgroup-path.txt").write_text(cgroup + "\n")
                ownership = [json.loads(line) for line in (directory / "ownership.jsonl").read_text().splitlines()]
                for record in ownership:
                    record["processes"] = [fresh[item["pid"]] for item in record["processes"]]
                    record["members"] = [mapping[pid] for pid in record["members"]]
                    record["cgroup_procs_raw"] = "".join(f"{pid}\n" for pid in record["members"])
                (directory / "ownership.jsonl").write_text("\n".join(map(json.dumps, ownership)) + "\n")
                identity = {"pid": process["pid"], "start_ticks": process["start_ticks"],
                            "cgroup": (directory / "cgroup-path.txt").read_text().strip(),
                            "source_sha": manifest["candidate"], "instrumentation_sha256": instrumentation}
                row = self.row(profile, cell)
                if readiness:
                    self.with_readiness(row)
                self.log(row, directory / "harness.log", identity)
                receipt.write_json(directory / "command.json", [process["executable"], "recovery-retirement", cell, profile])
                for boundary in ("before", "after"):
                    (directory / boundary / "memory.max").write_text(str(receipt.RETIREMENT_LIMIT))
                receipt.write_json(directory / "raw-sha256.json", receipt.retirement_raw_hashes(directory))
                ordinal += 1
        return root

    def test_retirement_full_and_empty_log_contracts_and_null_correctness_clocks(self):
        for profile in ("full-uc", "full-vpn"):
            for cell in ("retirement-empty", "retirement-full"):
                for measured in (False, True):
                    with self.subTest(profile=profile, cell=cell, measured=measured):
                        row = self.row(profile, cell, measured)
                        result = receipt.validate_retirement_log(self.log(row), profile, cell, measured=measured)
                        self.assertEqual(result["sample"], row)

    def test_retirement_rejects_missing_or_wrong_cardinality(self):
        for phase in ("vpn_stage", "adj_rib_in"):
            for field, value in (("calls", 0), ("keys", 0), ("keys", 1_229_999), ("keys", True)):
                with self.subTest(phase=phase, field=field, value=value):
                    row = self.row()
                    row[phase][field] = value
                    with self.assertRaises(receipt.InvalidReceipt):
                        receipt.validate_retirement_log(self.log(row), "full-vpn", "retirement-full")

    def test_retirement_rejects_clock_leaks_and_uncontained_or_missing_phases(self):
        for measured, path, value in (
            (False, ("vpn_stage", "elapsed_ns"), 100),
            (True, ("adj_rib_in", "elapsed_ns"), None),
            (True, ("vpn_stage", "elapsed_ns"), 0),
            (True, ("vpn_stage", "elapsed_ns"), 600),
        ):
            with self.subTest(measured=measured, value=value):
                row = self.row(measured=measured)
                row[path[0]][path[1]] = value
                with self.assertRaises(receipt.InvalidReceipt):
                    receipt.validate_retirement_log(self.log(row), "full-vpn", "retirement-full", measured=measured)

    def test_retirement_control_changes_only_the_existing_stage_retirement(self):
        source = Path(receipt.__file__).resolve().parents[2] / receipt.RETIREMENT_SOURCE
        original = source.read_text()
        changed = receipt.retirement_control(original)
        self.assertIn("        drop(vpn_group_stage);\n", changed)
        self.assertEqual(changed.split("        drop(vpn_group_stage);\n", 1)[1],
                         original.split("        crate::adj_rib_out::release_hash_map(&mut vpn_group_stage, &mut checkpoint);\n", 1)[1])
        with self.assertRaises(receipt.InvalidReceipt):
            receipt.retirement_control(changed)

    def test_retirement_complete_campaign_replays_all_eight_actual_shape_legs(self):
        root = self.campaign()
        receipt.summarize_retirement(root)
        result = json.loads((root / "comparison.json").read_text())
        self.assertEqual(result["status"], "COMPLETE")
        self.assertEqual(len(result["samples"]), 8)
        self.assertEqual(len(result["summaries"]), 4)
        self.assertNotIn("qualification_passed", result)

    def test_receiver_retirement_full_empty_folds_and_null_correctness_clocks(self):
        for profile in ("full-uc", "full-vpn", "smoke-uc", "smoke-vpn"):
            for cell in receipt.RETIREMENT_CELLS[2:]:
                for measured in (False, True):
                    if measured and profile.startswith("smoke-"):
                        continue
                    with self.subTest(profile=profile, cell=cell, measured=measured):
                        row = self.row(profile, cell, measured)
                        result = receipt.validate_retirement_log(self.log(row), profile, cell, measured=measured)
                        self.assertEqual(result["sample"], row)

    def test_receiver_retirement_rejects_header_only_full_inventory_and_clock_leaks(self):
        for cell, phase in (("retirement-adj-out-full", "adj_rib_out"),
                            ("retirement-regroup-full", "regroup_baseline")):
            for field, value in (("calls", 0), ("keys", 0), ("keys", 1_229_999),
                                 ("keys", True), ("groups", 1), ("elapsed_ns", 0), ("elapsed_ns", None)):
                with self.subTest(cell=cell, field=field, value=value):
                    row = self.row(cell=cell)
                    row[phase][field] = value
                    with self.assertRaises(receipt.InvalidReceipt):
                        receipt.validate_retirement_log(self.log(row), "full-vpn", cell)
            row = self.row(cell=cell, measured=False)
            row[phase]["elapsed_ns"] = 100
            with self.assertRaisesRegex(receipt.InvalidReceipt, "clock"):
                receipt.validate_retirement_log(self.log(row), "full-vpn", cell, measured=False)

    def test_receiver_retirement_requires_actual_eight_message_dirty_baseline(self):
        for field, value in (("inputs", 7), ("target_queue_capacity", 1), ("dirty_peers", 0),
                             ("group_dirty_members", 0), ("regroup_baselines", 0)):
            with self.subTest(field=field):
                row = self.row(cell="retirement-regroup-full")
                row["preparation"][field] = value
                with self.assertRaisesRegex(receipt.InvalidReceipt, "preparation"):
                    receipt.validate_retirement_log(self.log(row), "full-vpn", row["cell"])

    def test_receiver_retirement_preserves_sources_witnesses_and_exact_preparation_fold(self):
        for field, value in (("target_group_after", "group:0"), ("witness_group_after", "group:2"),
                             ("source_group_after", ""), ("source_group_after", "group:2"),
                             ("health", [1, 0, 0, 0, 0, 0]),
                             ("selected", [0, 0, 0, 0])):
            with self.subTest(field=field):
                row = self.row(cell="retirement-regroup-full")
                row["survivors"][field] = value
                with self.assertRaises(receipt.InvalidReceipt):
                    receipt.validate_retirement_log(self.log(row), "full-vpn", row["cell"])
        for receiver in ("target", "witness"):
            row = self.row(cell="retirement-regroup-full")
            row["settled"][receiver]["vpnv4"]["withdrawals"] -= 1
            with self.assertRaisesRegex(receipt.InvalidReceipt, "wire inventory"):
                receipt.validate_retirement_log(self.log(row), "full-vpn", row["cell"])

    def test_private_evpn_receipt_cannot_masquerade_as_full_uc_or_vpn(self):
        for profile in ("full-uc", "full-vpn"):
            row = self.row(profile, "retirement-adj-out-full")
            self.assertEqual(sum(part["present"] for part in row["initial"]["target"].values()), 2)
            first = next(family for family, n in zip(receipt.FAMILIES, receipt.PROFILES[profile][0], strict=True) if n)
            row["initial"]["target"][first]["present"] = 1_000_000
            with self.assertRaisesRegex(receipt.InvalidReceipt, "wire inventory"):
                receipt.validate_retirement_log(self.log(row), profile, row["cell"])
        for boundary in ("initial", "settled"):
            for receiver in ("target", "witness"):
                row = self.row(cell="retirement-adj-out-empty")
                row["private_evpn"][boundary][receiver]["announces"] = 0
                with self.assertRaisesRegex(receipt.InvalidReceipt, "EVPN exact fold"):
                    receipt.validate_retirement_log(self.log(row), "full-vpn", row["cell"])
        row = self.row(cell="retirement-adj-out-full")
        row["survivors"]["evpn_received_best"] = [0, 0]
        with self.assertRaisesRegex(receipt.InvalidReceipt, "selected/source"):
            receipt.validate_retirement_log(self.log(row), "full-vpn", row["cell"])

    def test_retirement_v2_campaign_requires_all_twenty_four_actual_shape_legs(self):
        root = self.campaign(receiver_cases=True)
        receipt.summarize_retirement(root)
        result = json.loads((root / "comparison.json").read_text())
        self.assertEqual(result["schema"], "rustbgpd.retirement-timing.v2")
        self.assertEqual(result["status"], "COMPLETE")
        self.assertEqual(len(result["samples"]), 24)
        self.assertEqual(len(result["summaries"]), 8)
        self.assertTrue(all(item["observations"] == 2 for item in result["summaries"]))
        self.assertIn("receiver cleanup is identical in both arms", result["scope"])
        shutil.rmtree(root / "retirement-adj-out-full-1-candidate")
        with self.assertRaisesRegex(receipt.InvalidReceipt, "roster"):
            receipt.summarize_retirement(root)

    def test_retirement_v2_rejects_resealed_false_regroup_cardinality(self):
        root = self.campaign(receiver_cases=True)
        directory = root / "retirement-regroup-full-1-candidate"
        path = directory / "harness.log"
        lines = path.read_text().splitlines()
        row = json.loads(lines[-1].removeprefix("retirement_receipt "))
        row["regroup_baseline"].update(calls=0, keys=0)
        lines[-1] = "retirement_receipt " + json.dumps(row)
        path.write_text("\n".join(lines) + "\n")
        receipt.write_json(directory / "raw-sha256.json", receipt.retirement_raw_hashes(directory))
        with self.assertRaisesRegex(receipt.InvalidReceipt, "cardinality"):
            receipt.summarize_retirement(root)

    def test_retirement_accepts_ansi_cargo_compile_logs_without_rewriting_them(self):
        root = self.campaign()
        logs = {}
        for role in ("candidate", "old-drop"):
            path = root / f"{role}-build.log"
            logs[path] = (
                "\x1b[1m\x1b[92m   Compiling\x1b[0m rustbgpd-rib v0.77.0 "
                f"(/fixture/{role}/crates/rib)\n"
            ).encode()
            path.write_bytes(logs[path])
        receipt.summarize_retirement(root)
        self.assertEqual(json.loads((root / "comparison.json").read_text())["status"], "COMPLETE")
        for path, original in logs.items():
            self.assertEqual(path.read_bytes(), original)

    def test_retirement_compile_log_still_requires_rib_compilation_and_zero_exit(self):
        root = self.campaign()
        for role in ("candidate", "old-drop"):
            path = root / f"{role}-build.log"
            original = path.read_bytes()
            for line in (
                "\x1b[1m\x1b[92m       Fresh\x1b[0m rustbgpd-rib v0.77.0\n",
                "\x1b[1m\x1b[92m   Compiling\x1b[0m rustbgpd-wire v0.25.0\n",
                "\x1b[1m\x1b[92m   Compiling\x1b[0m rustbgpd-rib-helper v0.1.0\n",
                "warning: Compiling rustbgpd-rib v0.77.0\n",
            ):
                with self.subTest(role=role, line=line):
                    path.write_text(line)
                    with self.assertRaisesRegex(receipt.InvalidReceipt, "RIB build missing or failed"):
                        receipt.summarize_retirement(root)
            path.write_text("\x1b[1m\x1b[92m   Compiling\x1b[0m rustbgpd-rib v0.77.0\n")
            exit_path = root / f"{role}-build.exit"
            exit_path.write_text("1\n")
            with self.subTest(role=role, exit=1), self.assertRaisesRegex(
                receipt.InvalidReceipt, "RIB build missing or failed"
            ):
                receipt.summarize_retirement(root)
            exit_path.write_text("0\n")
            path.write_bytes(original)
        (root / "driver.exit").write_text("1\n")
        with self.assertRaisesRegex(receipt.InvalidReceipt, "driver/cleanup failed"):
            receipt.summarize_retirement(root)

    def test_retirement_rejects_resealed_duplicate_leg_scope_or_workload(self):
        root = self.campaign()
        source = root / "retirement-full-1-candidate"
        target = root / "retirement-full-2-candidate"
        original = {str(path.relative_to(target)): path.read_bytes()
                    for path in target.rglob("*") if path.is_file()}
        source_process = json.loads((source / "binary-process.json").read_text())
        source_cgroup = (source / "cgroup-path.txt").read_text().strip()
        for kind in ("copied-leg", "scope-only", "workload-only"):
            with self.subTest(kind=kind):
                for name, data in original.items():
                    (target / name).write_bytes(data)
                if kind == "copied-leg":
                    shutil.rmtree(target)
                    shutil.copytree(source, target)
                else:
                    process = json.loads((target / "binary-process.json").read_text())
                    old_pid = process["pid"]
                    ownership = [json.loads(line) for line in (target / "ownership.jsonl").read_text().splitlines()]
                    if kind == "scope-only":
                        (target / "cgroup-path.txt").write_text(source_cgroup + "\n")
                        for name in ("launcher-process.json", "scope-process.json", "binary-process.json"):
                            item = json.loads((target / name).read_text())
                            item["cgroup"] = "0::" + source_cgroup.removeprefix("/sys/fs/cgroup") + "\n"
                            receipt.write_json(target / name, item)
                        for record in ownership:
                            for item in record["processes"]:
                                item["cgroup"] = "0::" + source_cgroup.removeprefix("/sys/fs/cgroup") + "\n"
                    else:
                        process.update(pid=source_process["pid"], start_ticks=source_process["start_ticks"])
                        receipt.write_json(target / "binary-process.json", process)
                        for record in ownership:
                            record["processes"] = [process if item["pid"] == old_pid else item
                                                   for item in record["processes"]]
                            record["members"] = [process["pid"] if pid == old_pid else pid for pid in record["members"]]
                            record["cgroup_procs_raw"] = "".join(f"{pid}\n" for pid in record["members"])
                    (target / "ownership.jsonl").write_text("\n".join(map(json.dumps, ownership)) + "\n")
                    lines = (target / "harness.log").read_text().splitlines()
                    identity = json.loads(lines[0].removeprefix("recovery_identity "))
                    if kind == "scope-only":
                        identity["cgroup"] = source_cgroup
                    else:
                        identity.update(pid=source_process["pid"], start_ticks=source_process["start_ticks"])
                    lines[0] = "recovery_identity " + json.dumps(identity)
                    (target / "harness.log").write_text("\n".join(lines) + "\n")
                receipt.write_json(target / "raw-sha256.json", receipt.retirement_raw_hashes(target))
                with self.assertRaisesRegex(receipt.InvalidReceipt, "reused scope or workload identity"):
                    receipt.summarize_retirement(root)

    def test_retirement_campaign_rejects_raw_source_resource_and_cleanup_tampering(self):
        root = self.campaign()
        directory = root / "retirement-full-1-candidate"
        for path, replacement in (
            (directory / "harness.log", ""),
            (root / "old-drop-source.rs", "wrong control"),
            (directory / "raw-sha256.json", "{}"),
            (root / "cleanup-proof.json", "{}"),
            (root / "old-drop-inputs-after.json", "{}"),
            (root / "committed-inputs.json", "{}"),
        ):
            with self.subTest(path=path):
                original = path.read_bytes()
                path.write_text(replacement)
                try:
                    with self.assertRaises(receipt.InvalidReceipt):
                        receipt.summarize_retirement(root)
                finally:
                    path.write_bytes(original)
        path = directory / "before/memory.max"
        path.write_text("max")
        receipt.write_json(directory / "raw-sha256.json", receipt.retirement_raw_hashes(directory))
        with self.assertRaisesRegex(receipt.InvalidReceipt, "memory limit"):
            receipt.summarize_retirement(root)

    def test_retirement_failed_driver_emits_no_timing_verdict(self):
        receipt.summarize_retirement(self.root, 137)
        result = json.loads((self.root / "comparison.json").read_text())
        self.assertEqual(result["status"], "INVALID")
        self.assertEqual(result["samples"], [])
        self.assertNotIn("summaries", result)

    def test_retirement_failed_setup_creates_missing_campaign_receipt(self):
        root = self.root / "not-created" / "campaign"
        result = subprocess.run(
            [sys.executable, str(Path(receipt.__file__).resolve()), "summarize-retirement",
             str(root), "--failed-driver-exit", "124"],
            capture_output=True, text=True, check=False, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        envelope = json.loads((root / "comparison.json").read_text())
        self.assertEqual(envelope["status"], "INVALID")
        self.assertEqual(envelope["driver_invocation_exit"], 124)
        self.assertEqual(envelope["samples"], [])
        self.assertNotIn("summaries", envelope)

    def retirement_scope_startup(self, active_phase):
        scope = self.fixture.scope()
        (scope / "memory.max").write_text(str(receipt.RETIREMENT_LIMIT))
        output = self.root / active_phase
        events = []
        child = None

        class Acknowledgment:
            def write(self, data):
                self_test.assertEqual(events, ["held", "identity", "active"])
                self_test.assertEqual(data, b"1")
                events.append("ack")
                child.returncode = 0  # The empty control finishes immediately on release.
                return len(data)

            def flush(self):
                self_test.assertEqual(events[-1], "ack")

            def close(self):
                pass

        class Child:
            pid = 3

            def __init__(self, held):
                self.stdin = Acknowledgment() if held else None
                self.returncode = None if held else 0
                self.killed = False
                self.reaped = False
                events.append("held" if held else "exited")

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                if self.stdin is not None:
                    self.stdin.close()

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                self_test.assertIsNotNone(self.returncode, "wait before ownership ACK")
                self.reaped = True
                return self.returncode

            def kill(self):
                self.killed = True
                self.returncode = -9

        self_test = self
        checker = {"pid": 1, "executable": str(Path(sys.executable).resolve())}
        launcher = {"pid": 2, "executable": str(Path(shutil.which("bash")).resolve())}
        identities = [checker, launcher]

        def identity(_pid, **_kwargs):
            if identities:
                return identities.pop(0)
            if child.returncode is not None:
                raise FileNotFoundError("fast empty control exited before identity capture")
            events.append("identity")
            return {"pid": 3, "parent_pid": 1, "exe_sha256": "a" * 64}

        def spawn(_command, **kwargs):
            nonlocal child
            child = Child(kwargs.get("stdin") == subprocess.PIPE)
            return child

        def ownership(_scope, _output, _owned, phase, *_args):
            if phase == "active":
                self.assertEqual(events, ["held", "identity"])
                self.assertIsNone(child.returncode, "child released before active capture")
                events.append("active")
                return {"phase": active_phase}
            return {"phase": phase}

        with (patch.object(receipt, "proc_identity", side_effect=identity),
              patch.object(receipt, "snapshot_scope"),
              patch.object(receipt, "capture_ownership", side_effect=ownership),
              patch.object(receipt.subprocess, "Popen", side_effect=spawn)):
            if active_phase == "active":
                receipt.run_scope(Path("/binary"), output, "retirement-empty", scope,
                                  "a" * 64, "full-uc", 1, retirement=True)
                self.assertEqual(events, ["held", "identity", "active", "ack"])
                self.assertFalse(child.killed)
            else:
                with self.assertRaisesRegex(receipt.InvalidReceipt, "active.*ownership"):
                    receipt.run_scope(Path("/binary"), output, "retirement-empty", scope,
                                      "a" * 64, "full-uc", 1, retirement=True)
                self.assertNotIn("ack", events)
                self.assertTrue(child.killed)
        self.assertTrue(child.reaped)

    def test_retirement_scope_holds_fast_child_until_identity_and_active_ownership(self):
        for active_phase in ("active", "after"):
            with self.subTest(active_phase=active_phase):
                self.retirement_scope_startup(active_phase)

    def test_retirement_rejects_identical_binaries_with_different_digest_whitespace(self):
        root = self.campaign()
        shutil.copyfile(root / "bin/candidate", root / "bin/old-drop")
        digest = receipt.file_digest(root / "bin/candidate")
        (root / "old-drop-binary.sha256").write_text(digest + "\n\n")
        self.assertNotEqual((root / "candidate-binary.sha256").read_text(),
                            (root / "old-drop-binary.sha256").read_text())
        for cell in ("retirement-empty", "retirement-full"):
            for leg in (0, 3):
                directory = root / f"{cell}-{leg}-old-drop"
                process = json.loads((directory / "binary-process.json").read_text())
                process["exe_sha256"] = digest
                receipt.write_json(directory / "binary-process.json", process)
                ownership = [json.loads(line) for line in (directory / "ownership.jsonl").read_text().splitlines()]
                for record in ownership:
                    record["processes"] = [process if item["pid"] == process["pid"] else item
                                           for item in record["processes"]]
                (directory / "ownership.jsonl").write_text("\n".join(map(json.dumps, ownership)) + "\n")
                receipt.write_json(directory / "raw-sha256.json", receipt.retirement_raw_hashes(directory))
        with self.assertRaisesRegex(receipt.InvalidReceipt, "same binary"):
            receipt.summarize_retirement(root)

    def test_retirement_full_replay_rejects_false_empty_phase_with_consistent_hashes(self):
        root = self.campaign()
        directory = root / "retirement-full-1-candidate"
        path = directory / "harness.log"
        lines = path.read_text().splitlines()
        row = json.loads(lines[-1].removeprefix("retirement_receipt "))
        row["vpn_stage"].update(calls=0, keys=0)
        lines[-1] = "retirement_receipt " + json.dumps(row)
        path.write_text("\n".join(lines) + "\n")
        receipt.write_json(directory / "raw-sha256.json", receipt.retirement_raw_hashes(directory))
        with self.assertRaisesRegex(receipt.InvalidReceipt, "cardinality"):
            receipt.summarize_retirement(root)

    def test_actual_retirement_exit_handler_preserves_failure_and_checks_cleanup(self):
        wrapper = Path(receipt.__file__).with_name("compare-recovery-memory.sh").read_text()
        begin = wrapper.index("finish_retirement() {\n")
        end = wrapper.index("trap finish EXIT\n", begin)
        handler = wrapper[begin:end]
        setup = r'''
set -euo pipefail
output=$TEST_OUTPUT
work_root=$TEST_SCRATCH
repository=unused
checker=unused
git() {
    [[ ! -e $output/driver.exit ]] || exit 92
    if [[ ${*: -1} == */candidate ]]; then return "$TEST_CANDIDATE"; fi
    return "$TEST_OLD"
}
rm() { [[ ! -e $output/driver.exit ]] || exit 93; return "$TEST_REMOVE"; }
awk() { printf '0\n'; return "$TEST_AWK"; }
python3() { return 0; }
'''
        for initial, candidate, old, removal, observer, expected in (
            (0, 0, 0, 0, 0, 0), (0, 7, 0, 0, 0, 1),
            (0, 0, 8, 0, 0, 1), (0, 0, 0, 9, 0, 1),
            (0, 0, 0, 0, 11, 1), (23, 0, 0, 0, 11, 23),
        ):
            with self.subTest(initial=initial, candidate=candidate, old=old, removal=removal, observer=observer):
                output = self.root / f"handler-{initial}-{candidate}-{old}-{removal}-{observer}"
                output.mkdir()
                scratch = output / "scratch"
                scratch.mkdir()
                result = subprocess.run(["bash", "-c", setup + handler +
                                        '\ntrap finish_retirement EXIT\nexit "$TEST_INITIAL"\n'],
                    env=os.environ | {"TEST_OUTPUT": str(output), "TEST_SCRATCH": str(scratch),
                                      "TEST_INITIAL": str(initial), "TEST_CANDIDATE": str(candidate),
                                      "TEST_OLD": str(old), "TEST_REMOVE": str(removal), "TEST_AWK": str(observer)},
                    text=True, capture_output=True, timeout=5, check=False)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                self.assertEqual((output / "driver.exit").read_text(), f"{expected}\n")
                self.assertEqual((output / "scratch-retained.txt").exists(), expected != 0)


if __name__ == "__main__":
    unittest.main()
