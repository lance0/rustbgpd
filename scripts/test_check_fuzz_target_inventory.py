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


if __name__ == "__main__":
    unittest.main()
