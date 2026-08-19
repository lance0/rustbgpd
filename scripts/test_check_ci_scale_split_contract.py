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
                self.assertNotEqual(-1, index, f"missing occurrence: {old}")
                start = index + len(old)
            target.write_text(text[:index] + new + text[index + len(old) :])
            self.assertTrue(check(root), f"mutation stayed green: {old}")

    def test_live_contract(self) -> None:
        self.assertEqual([], check(ROOT))

    def test_semantic_mutations_fail_closed(self) -> None:
        cases = (
            ("  v064_validator:\n", "  renamed_validator:\n"),
            ("  core:\n", "  renamed_core:\n"),
            ("  core_tests:\n", "  renamed_core_tests:\n"),
            ("  scale_receipts:\n", "  renamed_scale:\n"),
            ("  check:\n", "  renamed_check:\n"),
            ("  msrv:\n", "  renamed_msrv:\n"),
            ("  evpn_bum_filter_kernel:\n", "  renamed_evpn:\n"),
            ("- run: cargo test --workspace", "- run: true"),
            ("- run: cargo doc --workspace --lib --no-deps", "- run: true"),
            ('RUSTDOCFLAGS: "-D warnings"', 'RUSTDOCFLAGS: ""'),
            ("if: ${{ always() }}", "if: ${{ success() }}"),
            (
                "needs: [v064_validator, core, core_tests, scale_receipts]",
                "needs: [core]",
            ),
            (
                "V064_VALIDATOR_RESULT: ${{ needs.v064_validator.result }}",
                "V064_VALIDATOR_RESULT: success",
            ),
            ("CORE_RESULT: ${{ needs.core.result }}", "CORE_RESULT: success"),
            (
                "CORE_TESTS_RESULT: ${{ needs.core_tests.result }}",
                "CORE_TESTS_RESULT: success",
            ),
            (
                "SCALE_RECEIPTS_RESULT: ${{ needs.scale_receipts.result }}",
                "SCALE_RECEIPTS_RESULT: success",
            ),
            (
                '[[ "$V064_VALIDATOR_RESULT" != "success" || "$CORE_RESULT" != '
                '"success" || "$CORE_TESTS_RESULT" != "success" || '
                '"$SCALE_RECEIPTS_RESULT" != "success" ]]',
                "[[ false ]]",
            ),
        )
        for old, new in cases:
            with self.subTest(seam=old):
                self.mutate(old, new)

    def test_aggregate_shell_truth_table(self) -> None:
        shell = aggregate_shell(_jobs((ROOT / WORKFLOW).read_text())["check"])
        self.assertTrue(shell)

        def run(values):
            env = os.environ.copy()
            for name in ("V064_VALIDATOR", "CORE", "CORE_TESTS", "SCALE_RECEIPTS"):
                env.pop(f"{name}_RESULT", None)
            for name, value in values.items():
                if value is not None:
                    env[f"{name}_RESULT"] = value
            return subprocess.run(["bash", "-c", shell], env=env, capture_output=True)

        names = ("V064_VALIDATOR", "CORE", "CORE_TESTS", "SCALE_RECEIPTS")
        good = {name: "success" for name in names}
        self.assertEqual(0, run(good).returncode)
        for name in good:
            for bad in ("failure", "cancelled", "skipped", "", None):
                values = good | {name: bad}
                with self.subTest(child=name, result=bad):
                    self.assertNotEqual(0, run(values).returncode)


if __name__ == "__main__":
    unittest.main()
