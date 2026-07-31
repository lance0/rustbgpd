#!/usr/bin/env python3

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.check_ci_scale_split_contract import _jobs, aggregate_shell, check


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ".github/workflows/ci.yml"


class ScaleSplitContractTests(unittest.TestCase):
    def mutate(self, old: str, new: str = "", occurrence: int = 0) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / WORKFLOW
            target.parent.mkdir(parents=True)
            shutil.copy2(ROOT / WORKFLOW, target)
            text = target.read_text()
            start = 0
            for _ in range(occurrence + 1):
                index = text.find(old, start)
                self.assertNotEqual(
                    -1, index, f"missing occurrence {occurrence}: {old}"
                )
                start = index + len(old)
            target.write_text(text[:index] + new + text[index + len(old) :])
            self.assertTrue(check(root), f"mutation stayed green: {old}")

    def test_live_contract(self) -> None:
        self.assertEqual([], check(ROOT))

    def test_destructive_roster_and_preserved_bodies(self) -> None:
        cases = (
            ("  core:\n", "  renamed_core:\n"),
            ("  scale_receipts:\n", "  renamed_scale:\n"),
            ("  check:\n", "  renamed_check:\n"),
            ("  msrv:\n", "  renamed_msrv:\n"),
            ("  evpn_bum_filter_kernel:\n", "  renamed_evpn:\n"),
            ("timeout-minutes: 45", "timeout-minutes: 44"),
            ("key: msrv-1.95", "key: msrv-drift"),
            ("IMAGE_TAG: rustbgpd-netns-tests:latest", "IMAGE_TAG: drift"),
            ("branches: [main]", "branches: [other]"),
            ("permissions:\n  contents: read", "permissions:\n  contents: write"),
        )
        for old, new in cases:
            with self.subTest(seam=old):
                self.mutate(old, new)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / WORKFLOW
            target.parent.mkdir(parents=True)
            shutil.copy2(ROOT / WORKFLOW, target)
            text = target.read_text()
            core_start = text.index("  core:\n")
            scale_start = text.index("  scale_receipts:\n")
            check_start = text.index("  check:\n", scale_start)
            core = text[core_start:scale_start]
            scale = text[scale_start:check_start]
            target.write_text(text[:core_start] + scale + core + text[check_start:])
            self.assertTrue(check(root), "job-order mutation stayed green")

    def test_destructive_extracted_step_and_setup(self) -> None:
        step_name = "- name: Check standalone scale harnesses and receipt classifiers"
        cases = (
            ("name: scale / receipt checks", "name: changed"),
            ("timeout-minutes: 30", "timeout-minutes: 29"),
            ("components: rustfmt, clippy", "components: rustfmt"),
            ("uses: ./.github/actions/install-protobuf", "uses: ./changed", 1),
            ("sudo apt-get install -y ripgrep", "sudo apt-get install -y grep"),
            (
                "cargo fmt --manifest-path bench/scale/rrharness/Cargo.toml -- --check",
                "true",
            ),
            (
                "cargo test --manifest-path bench/scale/rrtransport/Cargo.toml --locked",
                "true",
            ),
            ("python3 bench/tests/test_verify_mrt_growth_campaign.py", "true"),
            (step_name, f"{step_name}\n      {step_name}"),
        )
        for case in cases:
            old, new, *occurrence = case
            with self.subTest(seam=old):
                self.mutate(old, new, occurrence[0] if occurrence else 0)
        for pin, occurrence in (
            ("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", 1),
            ("dtolnay/rust-toolchain@2c7215f132e9ebf062739d9130488b56d53c060c", 1),
            ("Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32", 1),
        ):
            with self.subTest(pin=pin):
                self.mutate(pin, "changed@main", occurrence)

    def test_destructive_aggregate_seams(self) -> None:
        cases = (
            ("name: check", "name: changed"),
            ("timeout-minutes: 5", "timeout-minutes: 6"),
            ("if: ${{ always() }}", "if: ${{ success() }}"),
            ("needs: [core, scale_receipts]", "needs: [core]"),
            ("CORE_RESULT: ${{ needs.core.result }}", "CORE_RESULT: success"),
            (
                "SCALE_RECEIPTS_RESULT: ${{ needs.scale_receipts.result }}",
                "SCALE_RECEIPTS_RESULT: success",
            ),
            ("printf 'core=%s\\n' \"$CORE_RESULT\"", "true"),
            (
                '[[ "$CORE_RESULT" != "success" || "$SCALE_RECEIPTS_RESULT" != "success" ]]',
                "[[ false ]]",
            ),
        )
        for old, new in cases:
            with self.subTest(seam=old):
                self.mutate(old, new)

    def test_aggregate_shell_truth_table(self) -> None:
        workflow = (ROOT / WORKFLOW).read_text()
        shell = aggregate_shell(_jobs(workflow)["check"])
        self.assertTrue(shell)

        def run(core=None, scale=None):
            env = os.environ.copy()
            env.pop("CORE_RESULT", None)
            env.pop("SCALE_RECEIPTS_RESULT", None)
            if core is not None:
                env["CORE_RESULT"] = core
            if scale is not None:
                env["SCALE_RECEIPTS_RESULT"] = scale
            return subprocess.run(
                ["bash", "-c", shell], env=env, capture_output=True, text=True
            )

        self.assertEqual(0, run("success", "success").returncode)
        for bad in ("failure", "cancelled", "skipped", ""):
            with self.subTest(child="core", result=bad):
                self.assertNotEqual(0, run(bad, "success").returncode)
            with self.subTest(child="scale_receipts", result=bad):
                self.assertNotEqual(0, run("success", bad).returncode)
        self.assertNotEqual(0, run(None, "success").returncode)
        self.assertNotEqual(0, run("success", None).returncode)


if __name__ == "__main__":
    unittest.main()
