#!/usr/bin/env python3
"""Adversarial tests for the LAN-395 rrharness receipt parser."""

from __future__ import annotations

import csv
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from parse_rrharness import EXPECTED_SHAPES, RESULT_FIELDS  # noqa: E402


SCRIPT = HERE / "parse_rrharness.py"
FIXTURES = HERE / "fixtures"


class RrHarnessParserTests(unittest.TestCase):
    def run_parser(self, *args: str, success: bool = True) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if success and result.returncode != 0:
            self.fail(f"parser failed: {result.stderr}")
        if not success and result.returncode == 0:
            self.fail("parser unexpectedly accepted invalid input")
        return result

    def parse_cell(self, directory: Path, log_text: str, *, mode: str = "flood") -> Path:
        log = directory / "cell.log"
        folded = directory / "cell.folded"
        classified = directory / "cell.cpu.tsv"
        output = directory / "cell.csv"
        log.write_text(log_text, encoding="utf-8")
        folded.write_bytes((FIXTURES / "cpu.folded").read_bytes())
        classified.write_bytes((FIXTURES / "cpu.expected.tsv").read_bytes())
        self.run_parser(
            "parse",
            "--mode",
            mode,
            "--variant",
            "base",
            "--commit",
            "a" * 40,
            "--repetition",
            "1",
            "--pair-order",
            "base-first",
            "--run-position",
            "first",
            "--log",
            str(log),
            "--folded",
            str(folded),
            "--classified",
            str(classified),
            "--output",
            str(output),
        )
        return output

    def test_parses_strict_flood_cell(self) -> None:
        with tempfile.TemporaryDirectory() as directory_text:
            output = self.parse_cell(
                Path(directory_text),
                """# flood clients=256 prefixes=100000 secs=20
rss_established_mib 100
cold_staged_s 1.250
cold_drained_s 0.750
rss_converged_mib 200
sustained_blocks 42
sustained_window_s 20.000
mgr_cpu_s 10.000
mgr_busy_frac 0.500
rss_end_mib 210
""",
            )
            with output.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["rate_name"], "blocks_per_s")
            self.assertEqual(rows[0]["rate"], "2.100000000")
            self.assertEqual(rows[0]["total_samples"], "105")

    def test_parses_strict_churn_cell_and_checks_printed_rate(self) -> None:
        with tempfile.TemporaryDirectory() as directory_text:
            directory = Path(directory_text)
            output = self.parse_cell(
                directory,
                """# churn clients=1000 candidates=1000 prefixes=3000 secs=20
rss_established_mib 100
prime_s 2.000
rss_primed_mib 200
waves 42
waves_per_s 2.10
window_s 20.000
mgr_cpu_s 10.000
mgr_busy_frac 0.500
rss_end_mib 210
""",
                mode="churn",
            )
            self.assertTrue(output.is_file())
            bad = (directory / "cell.log").read_text(encoding="utf-8").replace(
                "waves_per_s 2.10", "waves_per_s 3.10"
            )
            (directory / "cell.log").write_text(bad, encoding="utf-8")
            output.unlink()
            self.run_parser(
                "parse",
                "--mode",
                "churn",
                "--variant",
                "base",
                "--commit",
                "a" * 40,
                "--repetition",
                "1",
                "--pair-order",
                "base-first",
                "--run-position",
                "first",
                "--log",
                str(directory / "cell.log"),
                "--folded",
                str(directory / "cell.folded"),
                "--classified",
                str(directory / "cell.cpu.tsv"),
                "--output",
                str(output),
                success=False,
            )
            self.assertFalse(output.exists())

    def test_rejects_unknown_duplicate_missing_and_nonfinite_metrics(self) -> None:
        valid = """# flood clients=256 prefixes=100000 secs=20
rss_established_mib 100
cold_staged_s 1.250
cold_drained_s 0.750
rss_converged_mib 200
sustained_blocks 42
sustained_window_s 20.000
mgr_cpu_s 10.000
mgr_busy_frac 0.500
rss_end_mib 210
"""
        mutations = (
            valid + "surprise 1\n",
            valid + "rss_end_mib 211\n",
            valid.replace("cold_drained_s 0.750\n", ""),
            valid.replace("mgr_cpu_s 10.000", "mgr_cpu_s NaN"),
            valid.replace("mgr_busy_frac 0.500", "mgr_busy_frac 1.500"),
            valid.replace("# flood", "# flood\n# flood", 1),
        )
        with tempfile.TemporaryDirectory() as directory_text:
            directory = Path(directory_text)
            folded = directory / "cell.folded"
            classified = directory / "cell.cpu.tsv"
            folded.write_bytes((FIXTURES / "cpu.folded").read_bytes())
            classified.write_bytes((FIXTURES / "cpu.expected.tsv").read_bytes())
            for index, text in enumerate(mutations):
                with self.subTest(index=index):
                    log = directory / f"bad-{index}.log"
                    output = directory / f"bad-{index}.csv"
                    log.write_text(text, encoding="utf-8")
                    self.run_parser(
                        "parse",
                        "--mode",
                        "flood",
                        "--variant",
                        "base",
                        "--commit",
                        "a" * 40,
                        "--repetition",
                        "1",
                        "--pair-order",
                        "base-first",
                        "--run-position",
                        "first",
                        "--log",
                        str(log),
                        "--folded",
                        str(folded),
                        "--classified",
                        str(classified),
                        "--output",
                        str(output),
                        success=False,
                    )
                    self.assertFalse(output.exists())

    def write_matrix(
        self, path: Path, raw_dir: Path, *, head_multiplier: float = 1.16
    ) -> None:
        raw_dir.mkdir()
        rows: list[dict[str, object]] = []
        for mode, clients, candidates, prefixes, seconds in sorted(EXPECTED_SHAPES):
            for repetition in (1, 2):
                pair_order = "base-first" if repetition == 1 else "head-first"
                for variant in ("base", "head"):
                    cell = (
                        f"{mode}-{clients}-{candidates}-{prefixes}-"
                        f"rep{repetition}-{variant}"
                    )
                    folded = raw_dir / f"{cell}.folded"
                    classified = raw_dir / f"{cell}.cpu.tsv"
                    folded.write_text(f"folded {cell}\n", encoding="utf-8")
                    classified.write_text(f"classified {cell}\n", encoding="utf-8")
                    (raw_dir / f"{cell}.log").write_text("validated log\n", encoding="utf-8")
                    (raw_dir / f"{cell}.stderr").write_bytes(b"")
                    rows.append(
                        {
                            "variant": variant,
                            "commit": ("a" if variant == "base" else "b") * 40,
                            "mode": mode,
                            "clients": clients,
                            "candidates": candidates,
                            "prefixes": prefixes,
                            "seconds": seconds,
                            "repetition": repetition,
                            "pair_order": pair_order,
                            "run_position": (
                                "first"
                                if (pair_order, variant)
                                in (("base-first", "base"), ("head-first", "head"))
                                else "second"
                            ),
                            "rate_name": "blocks_per_s" if mode == "flood" else "waves_per_s",
                            "rate": 100.0 if variant == "base" else 100.0 * head_multiplier,
                            "rss_established_mib": 1,
                            "rss_converged_mib": 1,
                            "rss_end_mib": 1,
                            "setup_s": 1,
                            "window_s": 20,
                            "work_units": 100,
                            "mgr_cpu_s": 10,
                            "mgr_busy_frac": 0.5,
                            "folded_sha256": hashlib.sha256(folded.read_bytes()).hexdigest(),
                            "classified_sha256": hashlib.sha256(
                                classified.read_bytes()
                            ).hexdigest(),
                            "total_samples": 100,
                        }
                    )
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=RESULT_FIELDS, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)

    def test_complete_counterbalanced_matrix_passes_literal_gates(self) -> None:
        with tempfile.TemporaryDirectory() as directory_text:
            directory = Path(directory_text)
            matrix = directory / "matrix.csv"
            raw_dir = directory / "raw"
            comparison = directory / "comparison.csv"
            self.write_matrix(matrix, raw_dir)
            self.run_parser(
                "compare",
                "--input",
                str(matrix),
                "--raw-dir",
                str(raw_dir),
                "--output",
                str(comparison),
            )
            with comparison.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 8)
            self.assertEqual({row["verdict"] for row in rows}, {"pass"})

    def test_matrix_rejects_gate_miss_and_partial_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory_text:
            directory = Path(directory_text)
            matrix = directory / "matrix.csv"
            raw_dir = directory / "raw"
            comparison = directory / "comparison.csv"
            self.write_matrix(matrix, raw_dir, head_multiplier=1.14)
            self.run_parser(
                "compare",
                "--input",
                str(matrix),
                "--raw-dir",
                str(raw_dir),
                "--output",
                str(comparison),
                success=False,
            )
            self.assertIn("fail-improvement", comparison.read_text(encoding="utf-8"))
            lines = matrix.read_text(encoding="utf-8").splitlines()
            matrix.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
            comparison.unlink()
            self.run_parser(
                "compare",
                "--input",
                str(matrix),
                "--raw-dir",
                str(raw_dir),
                "--output",
                str(comparison),
                success=False,
            )
            self.assertFalse(comparison.exists())

    def test_matrix_rejects_tampered_numeric_and_hash_evidence(self) -> None:
        mutations = {
            "nonfinite rate": ("rate", "NaN"),
            "impossible busy fraction": ("mgr_busy_frac", "1.5"),
            "short window": ("window_s", "19.9"),
            "invalid folded digest": ("folded_sha256", "not-a-digest"),
            "zero samples": ("total_samples", "0"),
        }
        with tempfile.TemporaryDirectory() as directory_text:
            directory = Path(directory_text)
            original = directory / "original.csv"
            raw_dir = directory / "raw"
            self.write_matrix(original, raw_dir)
            with original.open(newline="", encoding="utf-8") as handle:
                base_rows = list(csv.DictReader(handle))
            for index, (case, (field, value)) in enumerate(mutations.items()):
                with self.subTest(case=case):
                    rows = [dict(row) for row in base_rows]
                    rows[0][field] = value
                    matrix = directory / f"tampered-{index}.csv"
                    comparison = directory / f"tampered-{index}-comparison.csv"
                    with matrix.open("w", newline="", encoding="utf-8") as handle:
                        writer = csv.DictWriter(
                            handle, fieldnames=RESULT_FIELDS, lineterminator="\n"
                        )
                        writer.writeheader()
                        writer.writerows(rows)
                    self.run_parser(
                        "compare",
                        "--input",
                        str(matrix),
                        "--raw-dir",
                        str(raw_dir),
                        "--output",
                        str(comparison),
                        success=False,
                    )
                    self.assertFalse(comparison.exists())

    def test_flood_256_literal_five_percent_regression_budget(self) -> None:
        with tempfile.TemporaryDirectory() as directory_text:
            directory = Path(directory_text)
            matrix = directory / "matrix.csv"
            raw_dir = directory / "raw"
            comparison = directory / "comparison.csv"
            self.write_matrix(matrix, raw_dir)
            with matrix.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            for row in rows:
                if row["mode"] == "flood" and row["clients"] == "256" and row["variant"] == "head":
                    row["rate"] = "95.000000000"
            with matrix.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=RESULT_FIELDS, lineterminator="\n")
                writer.writeheader()
                writer.writerows(rows)
            self.run_parser(
                "compare",
                "--input",
                str(matrix),
                "--raw-dir",
                str(raw_dir),
                "--output",
                str(comparison),
            )
            self.assertIn("-5.000000,0.0,5.0,pass", comparison.read_text(encoding="utf-8"))
            for row in rows:
                if row["mode"] == "flood" and row["clients"] == "256" and row["variant"] == "head":
                    row["rate"] = "94.999000000"
            with matrix.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=RESULT_FIELDS, lineterminator="\n")
                writer.writeheader()
                writer.writerows(rows)
            comparison.unlink()
            self.run_parser(
                "compare",
                "--input",
                str(matrix),
                "--raw-dir",
                str(raw_dir),
                "--output",
                str(comparison),
                success=False,
            )
            self.assertIn("fail-regression", comparison.read_text(encoding="utf-8"))

    def test_matrix_rejects_retained_profile_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory_text:
            directory = Path(directory_text)
            matrix = directory / "matrix.csv"
            raw_dir = directory / "raw"
            comparison = directory / "comparison.csv"
            self.write_matrix(matrix, raw_dir)
            folded = next(raw_dir.glob("*.folded"))
            folded.write_text("mutated after parse\n", encoding="utf-8")
            self.run_parser(
                "compare",
                "--input",
                str(matrix),
                "--raw-dir",
                str(raw_dir),
                "--output",
                str(comparison),
                success=False,
            )
            self.assertFalse(comparison.exists())


if __name__ == "__main__":
    unittest.main()
