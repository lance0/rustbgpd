#!/usr/bin/env python3
"""Adversarial tests for the LAN-393 Criterion matrix validator."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("validate-lan393-criterion.py")
SPEC = importlib.util.spec_from_file_location("lan393_criterion", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
criterion = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = criterion
SPEC.loader.exec_module(criterion)


def write_case(root: Path, full_id: str, run_name: str, point: float) -> None:
    directory = root / full_id.replace("/", "_") / run_name
    directory.mkdir(parents=True)
    (directory / "benchmark.json").write_text(
        json.dumps({"full_id": full_id}) + "\n", encoding="utf-8"
    )
    (directory / "estimates.json").write_text(
        json.dumps(
            {
                "mean": {
                    "confidence_interval": {
                        "confidence_level": 0.95,
                        "lower_bound": point * 0.99,
                        "upper_bound": point * 1.01,
                    },
                    "point_estimate": point,
                    "standard_error": point * 0.001,
                }
            }
        )
        + "\n",
        encoding="utf-8",
    )


def populate(root: Path, run_name: str, *, candidate: bool = False) -> None:
    for full_id in criterion.EXPECTED_IDS:
        if "/noop" in full_id:
            point = 100.0 if not candidate else 101.0
        elif criterion.MANAGER_GROUP in full_id:
            point = 150.0 if not candidate else 70.0
        else:
            point = 1_000.0 if not candidate else 1_010.0
        write_case(root, full_id, run_name, point)


class CriterionValidatorTests(unittest.TestCase):
    def test_exact_matrix_and_both_gates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            populate(root, "lan393-baseline")
            base = criterion.inventory(root, "lan393-baseline")
            self.assertTrue(criterion.gate_baseline(base)["manager_proceed_pass"])

            populate(root, "new", candidate=True)
            head = criterion.inventory(root, "new")
            self.assertTrue(criterion.gate_candidate(base, head)["candidate_acceptance_pass"])

    def test_missing_extra_duplicate_and_nonfinite_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            populate(root, "lan393-baseline")
            victim = next(root.glob("**/lan393-baseline/benchmark.json"))
            victim.unlink()
            with self.assertRaises(SystemExit):
                criterion.inventory(root, "lan393-baseline")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            populate(root, "lan393-baseline")
            write_case(root, "unexpected/case", "lan393-baseline", 1.0)
            with self.assertRaises(SystemExit):
                criterion.inventory(root, "lan393-baseline")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            populate(root, "lan393-baseline")
            duplicate = root / "duplicate" / "lan393-baseline"
            duplicate.mkdir(parents=True)
            original = next(root.glob("**/lan393-baseline/benchmark.json"))
            (duplicate / "benchmark.json").write_bytes(original.read_bytes())
            (duplicate / "estimates.json").write_bytes(
                original.with_name("estimates.json").read_bytes()
            )
            with self.assertRaises(SystemExit):
                criterion.inventory(root, "lan393-baseline")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            populate(root, "lan393-baseline")
            estimates = next(root.glob("**/lan393-baseline/estimates.json"))
            data = json.loads(estimates.read_text(encoding="utf-8"))
            data["mean"]["point_estimate"] = float("nan")
            estimates.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(SystemExit):
                criterion.inventory(root, "lan393-baseline")

    def test_candidate_gate_rejects_regressions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            populate(root, "lan393-baseline")
            populate(root, "new", candidate=True)
            base = criterion.inventory(root, "lan393-baseline")
            head = criterion.inventory(root, "new")
            self.assertTrue(criterion.gate_candidate(base, head)["candidate_acceptance_pass"])

            key = f"{criterion.MANAGER_GROUP}/route_added/noop"
            regressed = dict(head)
            regressed[key] = criterion.Estimate(point=110.0, lower=109.0, upper=111.0)
            self.assertFalse(
                criterion.gate_candidate(base, regressed)["candidate_acceptance_pass"]
            )


if __name__ == "__main__":
    unittest.main()
