#!/usr/bin/env python3
"""Mutation proofs for the fail-closed cargo-fuzz inventory gate."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_fuzz_target_inventory as inventory


def exact_inventory() -> dict[str, tuple[str, ...]]:
    return dict(inventory.EXPECTED_TARGETS)


class FuzzTargetInventoryTests(unittest.TestCase):
    def test_repository_inventory_is_exact(self) -> None:
        actual = inventory.repository_inventory()
        self.assertEqual(actual, inventory.EXPECTED_TARGETS)
        self.assertEqual(
            sum(len(targets) for targets in actual.values()),
            inventory.EXPECTED_COUNT,
        )
        self.assertEqual(
            actual["crates/mrt"],
            ("snapshot_reader_drain", "warm_bundle_manifest"),
        )
        self.assertEqual(actual["crates/bfd"], ("decode_bfd_control",))
        self.assertEqual(actual["crates/rpki"], ("decode_rtr_pdu",))

    def test_every_single_manifest_target_omission_is_rejected(self) -> None:
        for crate, targets in inventory.EXPECTED_TARGETS.items():
            for omitted in targets:
                with self.subTest(crate=crate, omitted=omitted):
                    mutated = exact_inventory()
                    mutated[crate] = tuple(
                        target for target in targets if target != omitted
                    )
                    with self.assertRaisesRegex(
                        inventory.InventoryError, "targets differ"
                    ):
                        inventory.validate_inventory(
                            mutated,
                            inventory.EXPECTED_TARGETS,
                            tuple(inventory.EXPECTED_TARGETS),
                        )

    def test_every_single_source_target_omission_is_rejected(self) -> None:
        for crate, targets in inventory.EXPECTED_TARGETS.items():
            for omitted in targets:
                with self.subTest(crate=crate, omitted=omitted):
                    mutated = exact_inventory()
                    mutated[crate] = tuple(
                        target for target in targets if target != omitted
                    )
                    with self.assertRaisesRegex(
                        inventory.InventoryError, "sources differ"
                    ):
                        inventory.validate_inventory(
                            inventory.EXPECTED_TARGETS,
                            mutated,
                            tuple(inventory.EXPECTED_TARGETS),
                        )

    def test_unexpected_fuzz_crate_is_rejected(self) -> None:
        with self.assertRaisesRegex(inventory.InventoryError, "fuzz crate set differs"):
            inventory.validate_inventory(
                inventory.EXPECTED_TARGETS,
                inventory.EXPECTED_TARGETS,
                (*inventory.EXPECTED_TARGETS, "crates/injected"),
            )

    def test_duplicate_global_target_name_is_rejected(self) -> None:
        mutated = exact_inventory()
        wire_targets = list(mutated["crates/wire"])
        wire_targets[0] = "parse_rt"
        mutated["crates/wire"] = tuple(sorted(wire_targets))
        with mock.patch.object(inventory, "EXPECTED_TARGETS", mutated):
            with self.assertRaisesRegex(
                inventory.InventoryError, "globally unique"
            ):
                inventory.validate_inventory(mutated, mutated, tuple(mutated))

    def test_empty_enumeration_is_rejected(self) -> None:
        def empty_runner(*args, **kwargs):
            del args, kwargs
            return subprocess.CompletedProcess(
                args=[], returncode=0, stdout=json.dumps({"packages": []}), stderr=""
            )

        with self.assertRaisesRegex(inventory.InventoryError, "no binary targets"):
            inventory.enumerate_manifest_targets("crates/mrt", runner=empty_runner)

    def test_failed_enumeration_is_rejected(self) -> None:
        def failed_runner(*args, **kwargs):
            del args, kwargs
            return subprocess.CompletedProcess(
                args=[], returncode=42, stdout="", stderr="injected metadata failure"
            )

        with self.assertRaisesRegex(
            inventory.InventoryError, "injected metadata failure"
        ):
            inventory.enumerate_manifest_targets("crates/mrt", runner=failed_runner)

    def test_redirected_manifest_target_is_rejected(self) -> None:
        def redirected_runner(*args, **kwargs):
            del args, kwargs
            target = (
                inventory.ROOT / "crates/mrt/fuzz/fuzz_targets/snapshot_reader_drain.rs"
            )
            metadata = {
                "packages": [
                    {
                        "targets": [
                            {
                                "name": "warm_bundle_manifest",
                                "kind": ["bin"],
                                "src_path": str(target),
                            }
                        ]
                    }
                ]
            }
            return subprocess.CompletedProcess(
                args=[], returncode=0, stdout=json.dumps(metadata), stderr=""
            )

        with self.assertRaisesRegex(inventory.InventoryError, "points to"):
            inventory.enumerate_manifest_targets("crates/mrt", runner=redirected_runner)

    def test_every_hosted_builder_crate_omission_is_rejected(self) -> None:
        builder = (inventory.ROOT / "fuzz/build-fuzzers.sh").read_text()
        workflow = (inventory.ROOT / ".github/workflows/fuzz.yml").read_text()
        for crate in inventory.EXPECTED_TARGETS:
            with self.subTest(crate=crate):
                mutated = builder.replace(f" {crate}", "", 1)
                with self.assertRaisesRegex(
                    inventory.InventoryError, "builder fuzz-crate roster"
                ):
                    inventory.validate_pipeline_enrollment(mutated, workflow)

    def test_hosted_options_copy_omission_is_rejected(self) -> None:
        builder = (inventory.ROOT / "fuzz/build-fuzzers.sh").read_text()
        workflow = (inventory.ROOT / ".github/workflows/fuzz.yml").read_text()
        mutated = builder.replace(
            'cp "fuzz/$name.options" "$OUT/$name.options"', "cp omitted", 1
        )
        with self.assertRaisesRegex(inventory.InventoryError, "target options"):
            inventory.validate_pipeline_enrollment(mutated, workflow)

    def test_new_nightly_campaign_omission_is_rejected(self) -> None:
        builder = (inventory.ROOT / "fuzz/build-fuzzers.sh").read_text()
        workflow = (inventory.ROOT / ".github/workflows/fuzz.yml").read_text()
        for crate, (target, _) in inventory.CAMPAIGN_BOUNDS.items():
            with self.subTest(crate=crate):
                mutated = workflow.replace(
                    f"grep -Fxq {target}", "grep -Fxq omitted", 1
                )
                with self.assertRaisesRegex(inventory.InventoryError, "does not require"):
                    inventory.validate_pipeline_enrollment(builder, mutated)

    def test_new_campaign_bound_drift_is_rejected(self) -> None:
        builder = (inventory.ROOT / "fuzz/build-fuzzers.sh").read_text()
        workflow = (inventory.ROOT / ".github/workflows/fuzz.yml").read_text()
        for crate, (_, max_len) in inventory.CAMPAIGN_BOUNDS.items():
            with self.subTest(crate=crate):
                mutated = workflow.replace(
                    f"-max_len={max_len}", f"-max_len={max_len + 1}", 1
                )
                with self.assertRaisesRegex(inventory.InventoryError, "max_len"):
                    inventory.validate_pipeline_enrollment(builder, mutated)

    def test_new_campaign_artifact_omission_is_rejected(self) -> None:
        builder = (inventory.ROOT / "fuzz/build-fuzzers.sh").read_text()
        workflow = (inventory.ROOT / ".github/workflows/fuzz.yml").read_text()
        for crate in inventory.CAMPAIGN_BOUNDS:
            with self.subTest(crate=crate):
                mutated = workflow.replace(f"{crate}/fuzz/artifacts/", "omitted/", 1)
                with self.assertRaisesRegex(inventory.InventoryError, "failure artifacts"):
                    inventory.validate_pipeline_enrollment(builder, mutated)

    def test_new_campaign_options_and_harness_bounds_are_load_bearing(self) -> None:
        builder = (inventory.ROOT / "fuzz/build-fuzzers.sh").read_text()
        workflow = (inventory.ROOT / ".github/workflows/fuzz.yml").read_text()
        read_text = Path.read_text

        for crate, (target, max_len) in inventory.CAMPAIGN_BOUNDS.items():
            options = inventory.ROOT / crate / "fuzz" / f"{target}.options"
            harness = inventory.ROOT / crate / f"fuzz/fuzz_targets/{target}.rs"

            def changed_options(path, *args, **kwargs):
                if path == options:
                    return f"[libfuzzer]\nmax_len = {max_len + 1}\n"
                return read_text(path, *args, **kwargs)

            with self.subTest(crate=crate, guard="hosted-options"):
                with mock.patch.object(Path, "read_text", changed_options):
                    with self.assertRaisesRegex(inventory.InventoryError, "must set"):
                        inventory.validate_pipeline_enrollment(builder, workflow)

            def removed_harness_guard(path, *args, **kwargs):
                text = read_text(path, *args, **kwargs)
                if path == harness:
                    return text.replace(f"data.len() > {max_len:_}", "false", 1)
                return text

            with self.subTest(crate=crate, guard="harness-bound"):
                with mock.patch.object(Path, "read_text", removed_harness_guard):
                    with self.assertRaisesRegex(inventory.InventoryError, "must reject"):
                        inventory.validate_pipeline_enrollment(builder, workflow)

    def test_every_pinned_seed_omission_and_byte_change_is_rejected(self) -> None:
        for path, expected in inventory.EXPECTED_SEEDS.items():
            with self.subTest(path=path, mutation="omitted"):
                mutated = dict(inventory.EXPECTED_SEEDS)
                del mutated[path]
                with self.assertRaisesRegex(inventory.InventoryError, "missing"):
                    inventory.validate_seed_corpus(mutated)
            with self.subTest(path=path, mutation="changed"):
                mutated = dict(inventory.EXPECTED_SEEDS)
                mutated[path] = expected + b"changed"
                with self.assertRaisesRegex(inventory.InventoryError, "bytes differ"):
                    inventory.validate_seed_corpus(mutated)


if __name__ == "__main__":
    unittest.main()
