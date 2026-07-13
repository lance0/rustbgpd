#!/usr/bin/env python3
"""Adversarial probes for the LAN-393 receipt validators."""

from __future__ import annotations

import argparse
import contextlib
import csv
import importlib.util
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("validate-lan393-receipt.py")
SPEC = importlib.util.spec_from_file_location("lan393_receipt", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
receipt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(receipt)


BASELINE = "1" * 40
CANDIDATE = "2" * 40
BGPERF2 = receipt.BGPERF2_COMMIT


SCENARIO = """\
<%
# The real scenario has helper imports here.
%>
local_prefix: 10.10.0.0/16
monitor:
  as: 1001
  check-points: [200000]
  local-address: 10.10.0.2
  router-id: 10.10.0.2
policy: {}
target:
  as: 1000
  local-address: 10.10.255.254
  router-id: 10.10.255.254
  single-table: false
testers:
- name: tester
  type: bird
  neighbors:
    10.10.0.3:
      as: 1003
      check-points: 100000
      count: 100000
      filter: {in: []}
      local-address: 10.10.0.3
      paths: ${gen_paths(100000)}
      router-id: 10.10.0.3
    10.10.0.4:
      as: 1004
      check-points: 100000
      count: 100000
      filter: {in: []}
      local-address: 10.10.0.4
      paths: ${gen_paths(100000)}
      router-id: 10.10.0.4
"""


def successful_result() -> list[str]:
    return [
        "rustbgpd",
        "rustbgpd",
        "rustbgpd 0.51.0",
        "2",
        "100000",
        "200000",
        "200000",
        "1",
        "10",
        "1",
        "9",
        "12.34",
        "100",
        "1.0",
        "50",
        "8.0",
        "",
        "2026-07-13",
        "8",
        "16GB",
        "0",
        "0",
        "",
        "",
        "",
    ]


class ReceiptValidatorTests(unittest.TestCase):
    def bgperf_files(
        self,
        root: Path,
        *,
        row: list[str] | None = None,
        phase: str = "baseline",
        mode: str = "enabled",
    ) -> argparse.Namespace:
        scenario = root / f"full-daemon-{phase}-{mode}-scenario.yaml"
        log = root / "bgperf.log"
        result = root / "result.csv"
        run_receipt_dir = root / f"lan393-{phase}-{mode}"
        source_tester_logs = run_receipt_dir / "tester"
        source_tester_logs.mkdir(parents=True)
        source_scenario = run_receipt_dir / "scenario.yaml"
        tester_logs = root / f"full-daemon-{phase}-{mode}-tester-logs"
        tester_logs.mkdir()
        # The pinned helper intentionally excludes NEXT_HOP RMT diagnostics.
        (source_tester_logs / "10.10.0.3.log").write_text(
            "RMT route ignored: NEXT_HOP is not directly reachable\n",
            encoding="utf-8",
        )
        (source_tester_logs / "10.10.0.4.log").write_text(
            "BIRD ready\n", encoding="utf-8"
        )
        for source in source_tester_logs.glob("*.log"):
            shutil.copyfile(source, tester_logs / source.name)
        source_scenario.write_text(SCENARIO, encoding="utf-8")
        shutil.copyfile(source_scenario, scenario)
        buffer = io.StringIO()
        csv.writer(buffer, lineterminator="\n").writerow(
            successful_result() if row is None else row
        )
        log.write_text("progress\n" + buffer.getvalue(), encoding="utf-8")
        return argparse.Namespace(
            log=log,
            scenario=scenario,
            result=result,
            phase=phase,
            mode=mode,
            bench_name=f"lan393-{phase}-{mode}",
            run_receipt_dir=run_receipt_dir,
            source_scenario=source_scenario,
            source_tester_log_dir=source_tester_logs,
            tester_log_dir=tester_logs,
        )

    def test_identity_accepts_bound_baseline_and_distinct_candidate(self) -> None:
        receipt.validate_identity(
            argparse.Namespace(
                phase="baseline",
                source_head=BASELINE,
                baseline_commit=BASELINE,
                baseline_ref_commit=BASELINE,
                candidate_commit=None,
                candidate_baseline_ancestor=None,
            )
        )
        receipt.validate_identity(
            argparse.Namespace(
                phase="candidate",
                source_head=CANDIDATE,
                baseline_commit=BASELINE,
                baseline_ref_commit=BASELINE,
                candidate_commit=CANDIDATE,
                candidate_baseline_ancestor="true",
            )
        )

    def test_wrong_head_and_equal_candidate_fail_closed(self) -> None:
        with self.assertRaises(SystemExit):
            receipt.validate_identity(
                argparse.Namespace(
                    phase="baseline",
                    source_head=CANDIDATE,
                    baseline_commit=BASELINE,
                    baseline_ref_commit=BASELINE,
                    candidate_commit=None,
                    candidate_baseline_ancestor=None,
                )
            )
        with self.assertRaises(SystemExit):
            receipt.validate_identity(
                argparse.Namespace(
                    phase="candidate",
                    source_head=BASELINE,
                    baseline_commit=BASELINE,
                    baseline_ref_commit=BASELINE,
                    candidate_commit=BASELINE,
                    candidate_baseline_ancestor="true",
                )
            )

    def test_profile_barrier_retains_evidence_without_publishing_pid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / "profile-ready.private"
            output = root / "profile-ready.txt"
            raw.write_text("48291\n", encoding="ascii")
            receipt.validate_barrier(
                argparse.Namespace(raw=raw, expected_pid="48291", output=output)
            )
            retained = output.read_text(encoding="ascii")
            self.assertEqual(retained, "barrier_reached=1\n")
            self.assertNotIn("48291", retained)

    def test_profile_barrier_rejects_mismatch_and_malformed_input(self) -> None:
        for raw_value, expected in (
            ("48291\n", "48292"),
            ("48291\nextra\n", "48291"),
            ("48291", "48291"),
            ("0\n", "0"),
            ("not-a-pid\n", "48291"),
        ):
            with (
                self.subTest(raw=raw_value, expected=expected),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                raw = root / "profile-ready.private"
                raw.write_text(raw_value, encoding="ascii")
                with self.assertRaises(SystemExit):
                    receipt.validate_barrier(
                        argparse.Namespace(
                            raw=raw,
                            expected_pid=expected,
                            output=root / "profile-ready.txt",
                        )
                    )

    def test_candidate_without_proven_ancestry_fails_closed(self) -> None:
        for ancestry in (None, "false"):
            with self.subTest(ancestry=ancestry), self.assertRaises(SystemExit):
                receipt.validate_identity(
                    argparse.Namespace(
                        phase="candidate",
                        source_head=CANDIDATE,
                        baseline_commit=BASELINE,
                        baseline_ref_commit=BASELINE,
                        candidate_commit=CANDIDATE,
                        candidate_baseline_ancestor=ancestry,
                    )
                )

    def test_bgperf_success_is_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.bgperf_files(root)
            receipt.validate_bgperf(args)
            rows = list(
                csv.reader(args.result.read_text(encoding="utf-8").splitlines())
            )
            self.assertEqual(rows[1][5:7], ["200000", "200000"])
            self.assertEqual(rows[1][20:23], ["0", "0", ""])

    def test_failed_output_and_wrong_workload_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = successful_result()
            row[22] = "FAILED"
            args = self.bgperf_files(root, row=row)
            with self.assertRaises(SystemExit):
                receipt.validate_bgperf(args)

            changed_scenario = SCENARIO.replace(
                "check-points: [200000]", "check-points: [198000]"
            )
            args.source_scenario.write_text(changed_scenario, encoding="utf-8")
            args.scenario.write_text(changed_scenario, encoding="utf-8")
            args.log.write_text(
                io.StringIO(",".join(successful_result()) + "\n").getvalue(),
                encoding="utf-8",
            )
            with self.assertRaises(SystemExit):
                receipt.validate_bgperf(args)

    def test_nonfinite_negative_and_inconsistent_metrics_fail_closed(self) -> None:
        for index, value in ((11, "nan"), (12, "-1"), (13, "inf"), (14, "101")):
            with self.subTest(index=index, value=value), tempfile.TemporaryDirectory() as directory:
                row = successful_result()
                row[index] = value
                with self.assertRaises(SystemExit):
                    receipt.validate_bgperf(self.bgperf_files(Path(directory), row=row))

        with tempfile.TemporaryDirectory() as directory:
            row = successful_result()
            row[8] = "5"
            row[10] = "9"
            with self.assertRaises(SystemExit):
                receipt.validate_bgperf(self.bgperf_files(Path(directory), row=row))

    def test_stale_default_logs_are_not_receipt_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = successful_result()
            # Model the pinned helper counting stale /tmp/bgperf2 logs. The
            # compatibility field must be retained but cannot decide success.
            row[20] = "7"
            args = self.bgperf_files(root, row=row)
            stale_default = root / "tmp" / "bgperf2" / "tester"
            stale_default.mkdir(parents=True)
            (stale_default / "10.10.0.3.log").write_text(
                "RMT stale unrelated failure\n", encoding="utf-8"
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                receipt.validate_bgperf(args)
            normalized = list(
                csv.reader(args.result.read_text(encoding="utf-8").splitlines())
            )
            self.assertEqual(normalized[1][20], "0")
            self.assertIn("adapter_tester_errors_ignored=7", output.getvalue())

    def test_actual_run_scoped_bird_error_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self.bgperf_files(Path(directory))
            (args.source_tester_log_dir / "10.10.0.4.log").write_text(
                "RMT Hold timer expired\n", encoding="utf-8"
            )
            (args.tester_log_dir / "10.10.0.4.log").write_text(
                "RMT Hold timer expired\n", encoding="utf-8"
            )

            with self.assertRaises(SystemExit):
                receipt.validate_bgperf(args)

    def test_source_log_inventory_rejects_extra_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self.bgperf_files(Path(directory))
            (args.source_tester_log_dir / "unexpected.log").symlink_to(
                args.source_tester_log_dir / "10.10.0.3.log"
            )
            with self.assertRaises(SystemExit):
                receipt.validate_bgperf(args)

    def test_run_scoped_directories_reject_symlink_components(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self.bgperf_files(Path(directory))
            real_tester = args.run_receipt_dir / "real-tester"
            args.source_tester_log_dir.rename(real_tester)
            args.source_tester_log_dir.symlink_to(real_tester, target_is_directory=True)
            with self.assertRaises(SystemExit):
                receipt.validate_bgperf(args)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.bgperf_files(root)
            real_run = root / "real-run"
            args.run_receipt_dir.rename(real_run)
            args.run_receipt_dir.symlink_to(real_run, target_is_directory=True)
            with self.assertRaises(SystemExit):
                receipt.validate_bgperf(args)

    def test_run_scoped_scenario_must_be_regular_and_byte_identical(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self.bgperf_files(Path(directory))
            args.scenario.unlink()
            args.scenario.symlink_to(args.source_scenario)
            with self.assertRaises(SystemExit):
                receipt.validate_bgperf(args)

        with tempfile.TemporaryDirectory() as directory:
            args = self.bgperf_files(Path(directory))
            real_source_scenario = args.run_receipt_dir / "scenario-real.yaml"
            args.source_scenario.rename(real_source_scenario)
            args.source_scenario.symlink_to(real_source_scenario)
            with self.assertRaises(SystemExit):
                receipt.validate_bgperf(args)

        with tempfile.TemporaryDirectory() as directory:
            args = self.bgperf_files(Path(directory))
            args.scenario.write_text("target: stale\n", encoding="utf-8")
            with self.assertRaises(SystemExit):
                receipt.validate_bgperf(args)

    def test_source_log_inventory_rejects_fifo_and_extra_regular_log(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self.bgperf_files(Path(directory))
            (args.source_tester_log_dir / "10.10.0.4.log").unlink()
            os.mkfifo(args.source_tester_log_dir / "10.10.0.4.log")
            with self.assertRaises(SystemExit):
                receipt.validate_bgperf(args)

        with tempfile.TemporaryDirectory() as directory:
            args = self.bgperf_files(Path(directory))
            (args.source_tester_log_dir / "unexpected.log").write_text(
                "BIRD ready\n", encoding="utf-8"
            )
            with self.assertRaises(SystemExit):
                receipt.validate_bgperf(args)

    def test_source_and_retained_log_content_must_match(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self.bgperf_files(Path(directory))
            (args.source_tester_log_dir / "10.10.0.4.log").write_text(
                "BIRD changed after copy\n", encoding="utf-8"
            )
            with self.assertRaises(SystemExit):
                receipt.validate_bgperf(args)

    def test_bird_timeout_field_is_explicitly_unsupported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.bgperf_files(root)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                receipt.validate_bgperf(args)
            self.assertIn(
                "tester_timeout_evidence=unsupported_by_pinned_bird_adapter",
                output.getvalue(),
            )

        with tempfile.TemporaryDirectory() as directory:
            row = successful_result()
            row[21] = "1"
            args = self.bgperf_files(Path(directory), row=row)
            with self.assertRaises(SystemExit):
                receipt.validate_bgperf(args)

    def test_tester_logs_are_bound_to_phase_and_bench_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = self.bgperf_files(Path(directory))
            args.bench_name = "lan393-candidate-enabled"
            with self.assertRaises(SystemExit):
                receipt.validate_bgperf(args)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.bgperf_files(root)
            wrong_dir = root / "full-daemon-candidate-enabled-tester-logs"
            args.tester_log_dir.rename(wrong_dir)
            args.tester_log_dir = wrong_dir
            with self.assertRaises(SystemExit):
                receipt.validate_bgperf(args)

    def image_files(self, root: Path, *, revision: str = BASELINE) -> argparse.Namespace:
        labels = {
            "org.opencontainers.image.revision": revision,
            "org.rustbgpd.bgperf2.revision": BGPERF2,
            "org.opencontainers.image.base.name": receipt.DEBIAN_RUNTIME_IMAGE,
            "org.opencontainers.image.base.digest": receipt.DEBIAN_RUNTIME_IMAGE.split(
                "sha256:", 1
            )[1],
            "org.rustbgpd.bgperf2.builder-base.digest": receipt.RUST_BUILDER_IMAGE.split(
                "sha256:", 1
            )[1],
            "org.rustbgpd.bgperf2.rust-toolchain": "1.95",
            "org.rustbgpd.lan393.profile-phase": "baseline",
            "org.rustbgpd.lan393.event-history-mode": "enabled",
        }
        inspect = root / "inspect.json"
        inspect.write_text(
            json.dumps([{"Id": "sha256:" + "a" * 64, "Config": {"Labels": labels}}]),
            encoding="utf-8",
        )
        builder = root / "builder.txt"
        builder.write_text(
            "\n".join(
                [
                    f"rustbgpd_commit={BASELINE}",
                    f"bgperf2_commit={BGPERF2}",
                    f"builder_base={receipt.RUST_BUILDER_IMAGE}",
                    "rustc 1.95.0 (test)",
                    "cargo 1.95.0 (test)",
                    "libprotoc 3.21.12",
                    "protobuf-compiler=3.21.12-3",
                ]
            ),
            encoding="utf-8",
        )
        runtime = root / "runtime.txt"
        runtime.write_text(
            "\n".join(
                [
                    f"rustbgpd_commit={BASELINE}",
                    f"bgperf2_commit={BGPERF2}",
                    f"runtime_base={receipt.DEBIAN_RUNTIME_IMAGE}",
                    "iproute2=6.1.0-3",
                ]
            ),
            encoding="utf-8",
        )
        return argparse.Namespace(
            inspect=inspect,
            builder_provenance=builder,
            runtime_provenance=runtime,
            source_commit=BASELINE,
            bgperf2_commit=BGPERF2,
            phase="baseline",
            mode="enabled",
        )

    def test_image_labels_and_provenance_are_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt.validate_image(self.image_files(Path(directory)))

    def test_wrong_image_revision_label_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(SystemExit):
                receipt.validate_image(
                    self.image_files(Path(directory), revision=CANDIDATE)
                )


if __name__ == "__main__":
    unittest.main()
