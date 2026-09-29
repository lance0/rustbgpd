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

from parse_rrharness import (  # noqa: E402
    EXPECTED_SHAPES,
    LEGACY_RESULT_FIELDS,
    RESULT_FIELDS,
    read_results,
)


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

    def parse_cell(
        self,
        directory: Path,
        log_text: str,
        *,
        mode: str = "flood",
        cgroup_text: str | None = None,
        success: bool = True,
    ) -> Path:
        extra: list[str] = []
        if cgroup_text is not None:
            cgroup = directory / "cell.cgroup"
            cgroup.write_text(cgroup_text, encoding="utf-8")
            extra = ["--cgroup", str(cgroup)]
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
            *extra,
            success=success,
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

    FLOOD_LOG = """# flood clients=256 prefixes=100000 secs=20
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

    def test_cgroup_readout_fills_trailing_columns_and_requires_swap_fence(self) -> None:
        valid = "cg_peak_bytes 314572800\ncg_settled_current_bytes 209715200\ncg_swap_max 0\n"
        with tempfile.TemporaryDirectory() as directory_text:
            directory = Path(directory_text)
            output = self.parse_cell(directory, self.FLOOD_LOG, cgroup_text=valid)
            with output.open(newline="", encoding="utf-8") as handle:
                reader = csv.DictReader(handle)
                self.assertEqual(tuple(reader.fieldnames or ())[-2:], ("cg_peak_mib", "cg_settled_current_mib"))
                row = next(reader)
            self.assertEqual(row["cg_peak_mib"], "300.000")
            self.assertEqual(row["cg_settled_current_mib"], "200.000")
            # Without a scope the columns exist but are blank.
            row = next(csv.DictReader(self.parse_cell(directory, self.FLOOD_LOG).open(encoding="utf-8")))
            self.assertEqual((row["cg_peak_mib"], row["cg_settled_current_mib"]), ("", ""))
            for bad in (
                valid.replace("cg_swap_max 0", "cg_swap_max max"),
                valid.replace("cg_settled_current_bytes 209715200", "cg_settled_current_bytes "),
                valid.replace("cg_peak_bytes 314572800\n", ""),
                valid + "cg_peak_bytes 1\n",
            ):
                with self.subTest(bad=bad):
                    (directory / "cell.csv").unlink(missing_ok=True)
                    output = self.parse_cell(directory, self.FLOOD_LOG, cgroup_text=bad, success=False)
                    self.assertFalse(output.exists())

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
        self,
        path: Path,
        raw_dir: Path,
        *,
        head_multiplier: float = 1.16,
        fields: tuple[str, ...] = RESULT_FIELDS,
        cg_peak: object = 512,
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
                            "cg_peak_mib": cg_peak,
                            "cg_settled_current_mib": 256,
                        }
                    )
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle, fieldnames=fields, lineterminator="\n", extrasaction="ignore"
            )
            writer.writeheader()
            writer.writerows(rows)

    def test_results_round_trip_cgroup_columns_by_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory_text:
            directory = Path(directory_text)
            current = directory / "current.csv"
            self.write_matrix(current, directory / "current-raw")
            rows = read_results(current)
            self.assertEqual({(row["cg_peak_mib"], row["cg_settled_current_mib"]) for row in rows}, {("512", "256")})
            self.assertTrue(all(None not in row for row in rows), "unnamed extra fields")
            legacy = directory / "legacy.csv"
            self.write_matrix(legacy, directory / "legacy-raw", fields=LEGACY_RESULT_FIELDS)
            self.assertTrue(all("cg_peak_mib" not in row for row in read_results(legacy)))
            # A pre-change header with post-change rows leaves the cgroup values unnamed.
            text = current.read_text(encoding="utf-8").split("\n", 1)[1]
            (directory / "mixed.csv").write_text(",".join(LEGACY_RESULT_FIELDS) + "\n" + text, encoding="utf-8")
            with self.assertRaises(ValueError):
                read_results(directory / "mixed.csv")

    def test_matrix_accepts_legacy_header_and_rejects_bad_cgroup_column(self) -> None:
        with tempfile.TemporaryDirectory() as directory_text:
            directory = Path(directory_text)
            for name, kwargs, success in (
                ("legacy", {"fields": LEGACY_RESULT_FIELDS}, True),
                ("blank", {"cg_peak": ""}, True),
                ("text", {"cg_peak": "lots"}, False),
                ("negative", {"cg_peak": -1}, False),
            ):
                with self.subTest(name=name):
                    matrix = directory / f"{name}.csv"
                    raw_dir = directory / f"{name}-raw"
                    self.write_matrix(matrix, raw_dir, **kwargs)
                    self.run_parser(
                        "compare",
                        "--input",
                        str(matrix),
                        "--raw-dir",
                        str(raw_dir),
                        "--output",
                        str(directory / f"{name}-comparison.csv"),
                        success=success,
                    )

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

    def test_no_gates_keeps_rows_advisory_and_writes_rung_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory_text:
            directory = Path(directory_text)
            matrix = directory / "matrix.csv"
            raw_dir = directory / "raw"
            comparison = directory / "comparison.csv"
            summary = directory / "summary.csv"
            # 1.14 misses the pinned 15% gate; without gates it is just a reading.
            self.write_matrix(matrix, raw_dir, head_multiplier=1.14)
            result = self.run_parser(
                "compare",
                "--input",
                str(matrix),
                "--raw-dir",
                str(raw_dir),
                "--output",
                str(comparison),
                "--summary",
                str(summary),
                "--no-gates",
            )
            with comparison.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual({row["verdict"] for row in rows}, {"advisory"})
            with summary.open(newline="", encoding="utf-8") as handle:
                rungs = list(csv.DictReader(handle))
            self.assertEqual(len(rungs), 4)
            self.assertEqual({row["reading"] for row in rungs}, {"head-faster"})
            self.assertEqual({row["repetitions"] for row in rungs}, {"2"})
            self.assertEqual({row["head_improvement_percent_mean"] for row in rungs}, {"14.000"})
            self.assertIn("head-faster", result.stdout)

    def test_max_regression_passes_flat_matrix_on_every_rung(self) -> None:
        with tempfile.TemporaryDirectory() as directory_text:
            directory = Path(directory_text)
            matrix = directory / "matrix.csv"
            raw_dir = directory / "raw"
            comparison = directory / "comparison.csv"
            # Flat head misses the pinned 15% gates; the uniform regression
            # gate replaces them, so a flat matrix passes.
            self.write_matrix(matrix, raw_dir, head_multiplier=1.0)
            self.run_parser(
                "compare",
                "--input",
                str(matrix),
                "--raw-dir",
                str(raw_dir),
                "--output",
                str(comparison),
                "--max-regression",
                "10",
            )
            with comparison.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 8)
            self.assertEqual({row["verdict"] for row in rows}, {"pass"})
            self.assertEqual({row["maximum_regression_percent"] for row in rows}, {"10.0"})
            self.assertEqual({row["required_improvement_percent"] for row in rows}, {"0.0"})

    def test_max_regression_fails_regressing_matrix_on_1000_client_rungs(self) -> None:
        with tempfile.TemporaryDirectory() as directory_text:
            directory = Path(directory_text)
            matrix = directory / "matrix.csv"
            raw_dir = directory / "raw"
            comparison = directory / "comparison.csv"
            # A 31% head regression: exactly the shape the pinned gates gave
            # 1000-client rungs no budget to fail on.
            self.write_matrix(matrix, raw_dir, head_multiplier=0.69)
            self.run_parser(
                "compare",
                "--input",
                str(matrix),
                "--raw-dir",
                str(raw_dir),
                "--output",
                str(comparison),
                "--max-regression",
                "10",
                success=False,
            )
            with comparison.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual({row["verdict"] for row in rows}, {"fail-regression"})
            self.assertIn("1000", {row["clients"] for row in rows})

    def test_max_regression_rejects_no_gates_combo_and_bad_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory_text:
            directory = Path(directory_text)
            matrix = directory / "matrix.csv"
            raw_dir = directory / "raw"
            comparison = directory / "comparison.csv"
            self.write_matrix(matrix, raw_dir)
            invalid = (
                ("--no-gates", "--max-regression", "10"),
                ("--max-regression", "0"),
                ("--max-regression", "-5"),
                ("--max-regression", "NaN"),
                ("--max-regression", "fast"),
            )
            for extra in invalid:
                with self.subTest(extra=extra):
                    self.run_parser(
                        "compare",
                        "--input",
                        str(matrix),
                        "--raw-dir",
                        str(raw_dir),
                        "--output",
                        str(comparison),
                        *extra,
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
