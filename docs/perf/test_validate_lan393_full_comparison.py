#!/usr/bin/env python3
"""Tests for the LAN-393 combined full-daemon verdict."""

from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("validate-lan393-full-comparison.py")
SPEC = importlib.util.spec_from_file_location("lan393_full_comparison", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
comparison = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(comparison)


HEADER = comparison.RESULT_HEADER


def write_json(path: Path, value: dict[str, object]) -> None:
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


def write_result(path: Path, cpu: float, memory: float) -> None:
    row = ["0"] * 25
    row[12] = str(cpu)
    row[13] = str(memory)
    with path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(HEADER)
        writer.writerow(row)


def write_manifest(root: Path, name: str) -> None:
    target = root / f"{name}.data"
    target.write_text("bound\n", encoding="utf-8")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    (root / name).write_text(f"{digest}  {target.name}\n", encoding="utf-8")


def populate(root: Path) -> None:
    write_json(root / "microbench-baseline-verdict.json", {"manager_proceed_pass": True})
    write_json(root / "microbench-candidate-verdict.json", {"candidate_acceptance_pass": True})
    for phase in ("baseline", "candidate"):
        for mode in ("enabled", "disabled"):
            (root / f"full-daemon-{phase}-{mode}-completion.txt").write_text(
                "phase_complete=1\n", encoding="utf-8"
            )
            write_json(
                root / f"full-daemon-{phase}-{mode}-perf-attribution.json",
                {
                    "baseline_proceed_pass": phase == "baseline" and mode == "enabled",
                    "ehm_producer_samples": 0 if mode == "disabled" else 10,
                },
            )
            write_result(
                root / f"full-daemon-{phase}-{mode}-bgperf-result.csv",
                100.0 if phase == "baseline" else 102.0,
                1.0 if phase == "baseline" else 1.02,
            )
    for manifest in (
        "microbench-baseline-SHA256SUMS",
        "microbench-candidate-SHA256SUMS",
        "full-daemon-baseline-enabled-SHA256SUMS",
        "full-daemon-baseline-disabled-SHA256SUMS",
        "full-daemon-candidate-enabled-SHA256SUMS",
    ):
        write_manifest(root, manifest)


class FullComparisonTests(unittest.TestCase):
    def test_baseline_and_candidate_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            populate(root)
            self.assertTrue(comparison.baseline(root)["overall_proceed_pass"])
            self.assertTrue(comparison.candidate(root)["candidate_acceptance_pass"])

    def test_default_regression_and_partial_receipt_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            populate(root)
            write_result(root / "full-daemon-candidate-disabled-bgperf-result.csv", 106.0, 1.0)
            self.assertFalse(comparison.candidate(root)["candidate_acceptance_pass"])
            (root / "full-daemon-baseline-enabled-completion.txt").unlink()
            with self.assertRaises(SystemExit):
                comparison.candidate(root)

    def test_malformed_header_and_empty_manifest_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            populate(root)
            rows = list(
                csv.reader(
                    (root / "full-daemon-candidate-disabled-bgperf-result.csv")
                    .read_text(encoding="utf-8")
                    .splitlines()
                )
            )
            rows[0][12] = "wrong cpu field"
            with (root / "full-daemon-candidate-disabled-bgperf-result.csv").open(
                "w", encoding="utf-8", newline=""
            ) as output:
                csv.writer(output, lineterminator="\n").writerows(rows)
            with self.assertRaises(SystemExit):
                comparison.candidate(root)

            (root / "microbench-baseline-SHA256SUMS").write_text("", encoding="utf-8")
            with self.assertRaises(SystemExit):
                comparison.baseline(root)

    def test_boolean_sample_count_does_not_alias_zero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            populate(root)
            write_json(
                root / "full-daemon-baseline-disabled-perf-attribution.json",
                {"ehm_producer_samples": False},
            )
            with self.assertRaises(SystemExit):
                comparison.baseline(root)


if __name__ == "__main__":
    unittest.main()
