#!/usr/bin/env python3

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.check_ci_scale_split_contract import WORKFLOWS, _jobs, aggregate_shell, check

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ".github/workflows/ci.yml"


class ScaleSplitContractTests(unittest.TestCase):
    def copy_workflows(self, root: Path) -> None:
        for workflow in WORKFLOWS:
            target = root / workflow
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / workflow, target)

    def mutate(
        self,
        old: str,
        new: str = "",
        occurrence: int = 0,
        workflow: str = WORKFLOW,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_workflows(root)
            target = root / workflow
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

    def test_comments_toolchain_selector_and_new_workflow_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_workflows(root)
            target = root / WORKFLOW
            target.write_text(
                "# cargo check --workspace\n"
                + target.read_text().replace(
                    "cargo check --locked -p rustbgpd-rib",
                    "cargo +1.95 check --locked -p rustbgpd-rib",
                    1,
                )
            )
            self.assertEqual([], check(root))
            added = root / ".github/workflows/new.yml"
            added.write_text("jobs:\n  new:\n    steps:\n      - run: cargo +1.95 check --workspace\n")
            self.assertIn("command is missing --locked", "\n".join(check(root)))
            added.write_text(added.read_text().replace("check --workspace", "check --locked --locked --workspace"))
            self.assertIn("command has duplicate --locked", "\n".join(check(root)))
            added.unlink()
            target.write_text(target.read_text() + "\n      - run: cargo check --workspace -- --locked \\\n")
            self.assertIn("command has --locked after Cargo's -- separator", "\n".join(check(root)))

    def test_lockfile_fidelity_mutations_fail_closed(self) -> None:
        cases = (
            (
                WORKFLOW,
                "cargo clippy --locked --workspace --all-targets",
                "cargo clippy --workspace --all-targets",
            ),
            (
                ".github/workflows/update-group-fault.yml",
                'listing="$(cargo test --locked -p rustbgpd-rib --lib "$test_name" -- --ignored --exact --list)"',
                'listing="$(cargo test -p rustbgpd-rib --lib "$test_name" -- --ignored --exact --list)" --locked',
            ),
            (
                WORKFLOW,
                "cargo check --locked -p rustbgpd-rib --features bench-internals --benches",
                "cargo check -p rustbgpd-rib --features bench-internals --benches; echo --locked",
            ),
            (
                WORKFLOW,
                "cargo test --locked -p rustbgpd --no-default-features --features bench-internals --test policy_set_store_allocation shared_set_batch_allocations_do_not_scale_per_peer -- --exact",
                "cargo test -p rustbgpd --no-default-features --features bench-internals --test policy_set_store_allocation shared_set_batch_allocations_do_not_scale_per_peer -- --locked --exact",
            ),
            (
                WORKFLOW,
                "bench/scale/rrharness/Cargo.toml --locked",
                "bench/scale/rrharness/Cargo.toml",
            ),
            (
                WORKFLOW,
                "bench/scale/rrtransport/Cargo.toml --locked -- smoke",
                "bench/scale/renamed/Cargo.toml --locked -- smoke",
            ),
            (
                WORKFLOW,
                "- run: cargo test --locked --workspace",
                "- run: cargo test --locked --workspace\n      - run: cargo check --workspace",
            ),
            (
                WORKFLOW,
                "cargo build --locked -p rs-config-render",
                "true",
            ),
        )
        for workflow, old, new in cases:
            with self.subTest(workflow=workflow, seam=old):
                self.mutate(old, new, workflow=workflow)

    def test_semantic_mutations_fail_closed(self) -> None:
        cases = (
            ("  v064_validator:\n", "  renamed_validator:\n"),
            ("  core:\n", "  renamed_core:\n"),
            ("  core_tests:\n", "  renamed_core_tests:\n"),
            ("  scale_receipts:\n", "  renamed_scale:\n"),
            ("  check:\n", "  renamed_check:\n"),
            ("  msrv:\n", "  renamed_msrv:\n"),
            ("  evpn_bum_filter_kernel:\n", "  renamed_evpn:\n"),
            ("- run: cargo test --locked --workspace", "- run: true"),
            ("- run: cargo doc --locked --workspace --lib --no-deps", "- run: true"),
            (
                "- run: cargo clippy --locked -p rustbgpd-wire --all-targets --features tokio-codec -- -D warnings",
                "- run: true",
            ),
            (
                "- run: cargo test --locked -p rustbgpd-wire --features tokio-codec",
                "- run: true",
            ),
            (
                "- run: cargo doc --locked -p rustbgpd-wire --lib --no-deps --features tokio-codec",
                "- run: true",
            ),
            ('RUSTDOCFLAGS: "-D warnings"', 'RUSTDOCFLAGS: ""'),
            (
                "- name: Wire crate README freshness gate",
                "- name: Unchecked wire README",
            ),
            (
                'git diff "$base"...HEAD -- crates/wire/Cargo.toml',
                'git diff "$base"...HEAD -- crates/wire/README.md',
            ),
            (
                'git diff "$base"...HEAD -- crates/wire/README.md',
                'git diff "$base"...HEAD -- crates/wire/NOTES.md',
            ),
            (r"'^\+version\s*='", r"'^version\s*='"),
            ("              exit 1", "              true"),
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
