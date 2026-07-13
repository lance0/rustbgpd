#!/usr/bin/env python3
"""Adversarial tests for the pinned LAN-395 Criterion receipt validator."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "validate_lan395_criterion.py"
BASE = "a" * 40
HEAD = "b" * 40
PRODUCTION_DIFF = "c" * 64
TOOLING = "d" * 40


class Lan395CriterionValidatorTests(unittest.TestCase):
    def estimate_path(
        self,
        run_dir: Path,
        policy: str,
        peers: int,
        attempt: int,
        variant: str,
    ) -> Path:
        return (
            run_dir
            / "criterion"
            / "distribute_fanout"
            / policy
            / str(peers)
            / f"attempt-{attempt}-{variant}"
            / "estimates.json"
        )

    def estimate(
        self,
        point: float,
        low: float,
        high: float,
        *,
        confidence: float = 0.95,
        standard_error: float = 0.1,
    ) -> dict[str, object]:
        return {
            "median": {
                "confidence_interval": {
                    "confidence_level": confidence,
                    "lower_bound": low,
                    "upper_bound": high,
                },
                "point_estimate": point,
                "standard_error": standard_error,
            }
        }

    def write_estimate(
        self,
        path: Path,
        point: float,
        low: float,
        high: float,
        *,
        confidence: float = 0.95,
        standard_error: float = 0.1,
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                self.estimate(
                    point,
                    low,
                    high,
                    confidence=confidence,
                    standard_error=standard_error,
                ),
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    def write_fixture(self, root: Path) -> tuple[Path, Path, Path]:
        run_dir = root / "private-run-root"
        run_dir.mkdir()
        (run_dir / "target-base").mkdir()
        (run_dir / "target-head").mkdir()
        (run_dir / "criterion").mkdir()
        metadata = run_dir / "metadata.txt"
        metadata.write_text(
            "\n".join(
                (
                    "run_id=PRIVATE-RUN-ID-SENTINEL",
                    "base_ref=private/base-ref",
                    f"base_sha={BASE}",
                    "head_ref=private/head-ref",
                    f"head_sha={HEAD}",
                    "package=rustbgpd-transport",
                    "bench=fanout",
                    "filter=distribute_fanout",
                    "features=bench-internals",
                    "core=5",
                    "attempts=2",
                    "fail_on_regression=0",
                    "regression_threshold_pct=3",
                    "regression_max_stddev_pct=10",
                    "verdict_min_attempts=3",
                    "governor=performance",
                    "use_taskset=1",
                    f"base_target_dir={run_dir / 'target-base'}",
                    f"head_target_dir={run_dir / 'target-head'}",
                    f"criterion_dir={run_dir / 'criterion'}",
                    "",
                    "Linux PRIVATE-HOST-SENTINEL 6.0",
                    "rustc 1.97.0",
                    "username=PRIVATE-USER-SENTINEL",
                    "password=PRIVATE-CREDENTIAL-SENTINEL",
                    "pid=987654",
                )
            )
            + "\n",
            encoding="utf-8",
        )
        pin = root / "lan395-run-pin.env"
        pin.write_text(
            "\n".join(
                (
                    "schema=rustbgpd.lan395-run-pin.v1",
                    f"base_commit={BASE}",
                    f"head_commit={HEAD}",
                    f"production_diff_sha256={PRODUCTION_DIFF}",
                    f"tooling_commit={TOOLING}",
                )
            )
            + "\n",
            encoding="utf-8",
        )
        for policy in ("no_policy", "with_policy"):
            for peers in (1, 8, 64, 256):
                for attempt in (1, 2):
                    self.write_estimate(
                        self.estimate_path(run_dir, policy, peers, attempt, "base"),
                        100.0,
                        99.0,
                        101.0,
                    )
                    if peers in (64, 256):
                        head = (80.0, 79.0, 81.0)
                    elif peers == 1:
                        head = (102.0, 101.0, 103.0)
                    else:
                        head = (95.0, 94.0, 96.0)
                    self.write_estimate(
                        self.estimate_path(run_dir, policy, peers, attempt, "head"),
                        *head,
                    )
        return run_dir, pin, root / "sanitized-receipt"

    def run_validator(
        self,
        run_dir: Path,
        pin: Path,
        output: Path,
        *,
        success: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--run-dir",
                str(run_dir),
                "--pin",
                str(pin),
                "--output-dir",
                str(output),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if success and result.returncode != 0:
            self.fail(f"validator failed: {result.stderr}")
        if not success and result.returncode == 0:
            self.fail("validator unexpectedly accepted invalid input")
        return result

    def test_valid_matrix_writes_complete_sanitized_atomic_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            run_dir, pin, output = self.write_fixture(root)
            self.run_validator(run_dir, pin, output)
            self.assertEqual(
                {path.name for path in output.iterdir()},
                {
                    "COMPLETED",
                    "SHA256SUMS",
                    "criterion-attempts.csv",
                    "criterion-gates.json",
                    "criterion-inputs.sha256",
                },
            )
            with (output / "criterion-attempts.csv").open(
                newline="", encoding="utf-8"
            ) as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 16)
            self.assertEqual(
                len((output / "criterion-inputs.sha256").read_text().splitlines()),
                32,
            )
            gates = json.loads((output / "criterion-gates.json").read_text())
            self.assertEqual(gates["overall_verdict"], "pass")
            self.assertEqual(len(gates["ci_gates"]), 8)
            self.assertTrue(all(row["passed"] for row in gates["ci_gates"]))
            completed = (output / "COMPLETED").read_text(encoding="utf-8")
            self.assertTrue(completed.endswith("criterion_gates_passed=1\n"))
            for line in (output / "SHA256SUMS").read_text().splitlines():
                digest, name = line.split("  ", 1)
                self.assertEqual(
                    hashlib.sha256((output / name).read_bytes()).hexdigest(), digest
                )
            retained = "".join(
                path.read_text(encoding="utf-8") for path in output.iterdir()
            )
            self.assertNotIn(str(run_dir), retained)
            self.assertNotIn("PRIVATE-RUN-ID-SENTINEL", retained)
            self.assertNotIn("PRIVATE-HOST-SENTINEL", retained)
            self.assertNotIn("PRIVATE-USER-SENTINEL", retained)
            self.assertNotIn("PRIVATE-CREDENTIAL-SENTINEL", retained)
            self.assertNotIn("987654", retained)

    def test_every_policy_attempt_ci_gate_is_fail_closed(self) -> None:
        cases = [
            (policy, peers, attempt)
            for policy in ("no_policy", "with_policy")
            for peers in (64, 256)
            for attempt in (1, 2)
        ]
        for index, (policy, peers, attempt) in enumerate(cases):
            with self.subTest(policy=policy, peers=peers, attempt=attempt):
                with tempfile.TemporaryDirectory() as root_text:
                    root = Path(root_text)
                    run_dir, pin, output = self.write_fixture(root)
                    self.write_estimate(
                        self.estimate_path(run_dir, policy, peers, attempt, "head"),
                        100.0,
                        99.0,
                        101.0,
                    )
                    self.run_validator(run_dir, pin, output, success=False)
                    self.assertFalse(output.exists(), index)

    def test_ci_upper_bound_is_strictly_below_zero(self) -> None:
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            run_dir, pin, output = self.write_fixture(root)
            target = self.estimate_path(run_dir, "no_policy", 64, 1, "head")
            self.write_estimate(target, 98.0, 97.0, 99.0)
            self.run_validator(run_dir, pin, output, success=False)
            self.assertFalse(output.exists())
            self.write_estimate(target, 98.0, 97.0, 98.999)
            self.run_validator(run_dir, pin, output)
            self.assertTrue(output.is_dir())

    def test_one_peer_mean_delta_has_strict_five_percent_ceiling(self) -> None:
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            run_dir, pin, output = self.write_fixture(root)
            for attempt in (1, 2):
                self.write_estimate(
                    self.estimate_path(run_dir, "no_policy", 1, attempt, "head"),
                    104.999,
                    104.0,
                    106.0,
                )
            self.run_validator(run_dir, pin, output)
            gates = json.loads((output / "criterion-gates.json").read_text())
            no_policy = next(
                gate for gate in gates["one_peer_gates"] if gate["policy"] == "no_policy"
            )
            self.assertEqual(no_policy["mean_delta_percent"], 4.999)

        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            run_dir, pin, output = self.write_fixture(root)
            for attempt in (1, 2):
                self.write_estimate(
                    self.estimate_path(run_dir, "with_policy", 1, attempt, "head"),
                    105.0,
                    104.0,
                    106.0,
                )
            self.run_validator(run_dir, pin, output, success=False)
            self.assertFalse(output.exists())

    def test_missing_extra_and_symlinked_inputs_fail_without_receipt(self) -> None:
        for case in ("missing", "extra", "symlink"):
            with self.subTest(case=case):
                with tempfile.TemporaryDirectory() as root_text:
                    root = Path(root_text)
                    run_dir, pin, output = self.write_fixture(root)
                    target = self.estimate_path(run_dir, "no_policy", 64, 1, "base")
                    if case == "missing":
                        target.unlink()
                    elif case == "extra":
                        (
                            run_dir
                            / "criterion/distribute_fanout/no_policy/64"
                            / "attempt-3-base"
                        ).mkdir()
                    else:
                        source = self.estimate_path(run_dir, "with_policy", 64, 1, "base")
                        target.unlink()
                        target.symlink_to(source)
                    self.run_validator(run_dir, pin, output, success=False)
                    self.assertFalse(output.exists())

    def test_metadata_is_exactly_bound_to_campaign_and_pin(self) -> None:
        mutations = (
            ("package=rustbgpd-transport", "package=rustbgpd-rib"),
            ("features=bench-internals", "features=bench-internals,other"),
            ("features=bench-internals", "features= bench-internals"),
            ("core=5", "core=4"),
            ("governor=performance", "governor=powersave"),
            ("use_taskset=1", "use_taskset=0"),
            ("attempts=2", "attempts=3"),
            (f"base_sha={BASE}", f"base_sha={'e' * 40}"),
            ("filter=distribute_fanout", "filter=no_policy"),
        )
        for old, new in mutations:
            with self.subTest(replacement=new):
                with tempfile.TemporaryDirectory() as root_text:
                    root = Path(root_text)
                    run_dir, pin, output = self.write_fixture(root)
                    metadata = run_dir / "metadata.txt"
                    metadata.write_text(
                        metadata.read_text(encoding="utf-8").replace(old, new, 1),
                        encoding="utf-8",
                    )
                    self.run_validator(run_dir, pin, output, success=False)
                    self.assertFalse(output.exists())

    def test_metadata_requires_blank_delimiter_after_exact_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            run_dir, pin, output = self.write_fixture(root)
            metadata = run_dir / "metadata.txt"
            metadata.write_text(
                metadata.read_text(encoding="utf-8").replace(
                    f"criterion_dir={run_dir / 'criterion'}\n\nLinux",
                    f"criterion_dir={run_dir / 'criterion'}\nLinux",
                    1,
                ),
                encoding="utf-8",
            )
            self.run_validator(run_dir, pin, output, success=False)
            self.assertFalse(output.exists())

    def test_pin_is_exact_and_canonical(self) -> None:
        mutations = (
            ("schema=rustbgpd.lan395-run-pin.v1", "schema=wrong"),
            (f"head_commit={HEAD}", f"head_commit={BASE}"),
            (f"tooling_commit={TOOLING}", "tooling_commit=short"),
            (f"tooling_commit={TOOLING}\n", f"tooling_commit={TOOLING}\nextra=value\n"),
        )
        for old, new in mutations:
            with self.subTest(replacement=new):
                with tempfile.TemporaryDirectory() as root_text:
                    root = Path(root_text)
                    run_dir, pin, output = self.write_fixture(root)
                    pin.write_text(
                        pin.read_text(encoding="utf-8").replace(old, new, 1),
                        encoding="utf-8",
                    )
                    self.run_validator(run_dir, pin, output, success=False)
                    self.assertFalse(output.exists())

    def test_malformed_duplicate_nonfinite_and_invalid_estimates_fail(self) -> None:
        invalid_documents = (
            (
                '{"median":{"point_estimate":100,"point_estimate":101,'
                '"standard_error":1,"confidence_interval":'
                '{"confidence_level":0.95,"lower_bound":99,"upper_bound":102}}}\n'
            ),
            (
                '{"median":{"point_estimate":NaN,"standard_error":1,'
                '"confidence_interval":{"confidence_level":0.95,'
                '"lower_bound":99,"upper_bound":102}}}\n'
            ),
            (
                '{"median":{"point_estimate":Infinity,"standard_error":1,'
                '"confidence_interval":{"confidence_level":0.95,'
                '"lower_bound":99,"upper_bound":102}}}\n'
            ),
            json.dumps(self.estimate(True, 99.0, 101.0)) + "\n",
            json.dumps(self.estimate("100", 99.0, 101.0)) + "\n",
            json.dumps(self.estimate(100.0, 99.0, 101.0, confidence=0.90)) + "\n",
            json.dumps(self.estimate(0.0, 0.0, 1.0)) + "\n",
            json.dumps(self.estimate(100.0, 101.0, 102.0)) + "\n",
            json.dumps(self.estimate(100.0, 99.0, 101.0, standard_error=-1.0)) + "\n",
            "not-json\n",
        )
        for index, document in enumerate(invalid_documents):
            with self.subTest(index=index):
                with tempfile.TemporaryDirectory() as root_text:
                    root = Path(root_text)
                    run_dir, pin, output = self.write_fixture(root)
                    target = self.estimate_path(run_dir, "no_policy", 8, 1, "base")
                    target.write_text(document, encoding="utf-8")
                    self.run_validator(run_dir, pin, output, success=False)
                    self.assertFalse(output.exists())

    def test_input_hashes_bind_the_exact_parsed_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            run_dir, pin, output = self.write_fixture(root)
            target = self.estimate_path(run_dir, "no_policy", 8, 1, "base")
            relative = target.relative_to(run_dir).as_posix()
            before = hashlib.sha256(target.read_bytes()).hexdigest()
            self.run_validator(run_dir, pin, output)
            hashes = {
                tuple(line.split("  ", 1))
                for line in (output / "criterion-inputs.sha256").read_text().splitlines()
            }
            self.assertIn((before, relative), hashes)
            target.write_bytes(target.read_bytes() + b" \n")
            self.assertNotEqual(hashlib.sha256(target.read_bytes()).hexdigest(), before)

    def test_existing_output_is_never_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as root_text:
            root = Path(root_text)
            run_dir, pin, output = self.write_fixture(root)
            output.mkdir()
            marker = output / "owned"
            marker.write_text("keep\n", encoding="utf-8")
            self.run_validator(run_dir, pin, output, success=False)
            self.assertEqual(marker.read_text(encoding="utf-8"), "keep\n")


if __name__ == "__main__":
    unittest.main()
