#!/usr/bin/env python3

import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import tomllib
import unittest
from pathlib import Path
from unittest import mock

from scripts import check_ci_scale_split_contract as contract
from scripts.check_ci_scale_split_contract import (
    RETIRED_PRIVILEGED_WORKFLOW,
    WORKFLOWS,
    _jobs,
    aggregate_shell,
    check,
)

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ".github/workflows/ci.yml"


class ScaleSplitContractTests(unittest.TestCase):
    def copy_workflows(self, root: Path) -> None:
        for workflow in {*WORKFLOWS, "Cargo.toml", *(name for name, _ in contract.MSRV_PINS)}:
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

    def test_msrv_bump_names_every_stale_pin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_workflows(root)
            manifest = root / "Cargo.toml"
            msrv = tomllib.loads(manifest.read_text())["workspace"]["package"]["rust-version"]
            manifest.write_text(manifest.read_text().replace(f'rust-version = "{msrv}"', 'rust-version = "9.99"'))
            failures = check(root)
            self.assertEqual(len(contract.MSRV_PINS), len(failures), failures)
            for name, _ in contract.MSRV_PINS:
                self.assertTrue(any(failure.startswith(f"{name}: MSRV pin") for failure in failures))
            for name in {name for name, _ in contract.MSRV_PINS}:
                path = root / name
                path.write_text(path.read_text().replace(msrv, "9.99"))
            self.assertEqual([], check(root))

    def test_each_msrv_pin_is_required_and_checked_independently(self) -> None:
        for name, pattern in contract.MSRV_PINS:
            for replacement in ["9.99", ""]:
                with self.subTest(file=name, pattern=pattern, replacement=replacement):
                    with tempfile.TemporaryDirectory() as temporary:
                        root = Path(temporary)
                        self.copy_workflows(root)
                        path = root / name
                        text = path.read_text()
                        match = re.search(pattern, text)
                        self.assertIsNotNone(match)
                        path.write_text(text[:match.start(1)] + replacement + text[match.end(1):])
                        self.assertTrue(any(failure.startswith(f"{name}: MSRV pin") for failure in check(root)))

    def test_gate_msrv_uses_the_installed_toolchain_name(self) -> None:
        recipe = (ROOT / "justfile").read_text().split("gate-msrv:\n", 1)[1].split("\n#", 1)[0]
        recipe = textwrap.dedent(recipe)
        cases = (
            ("1.95", "1.95-x86_64-unknown-linux-gnu (default)\n", "1.95-x86_64-unknown-linux-gnu"),
            ("1.95", "1.95.0-x86_64-unknown-linux-gnu\n", "1.95.0-x86_64-unknown-linux-gnu"),
            ("1.95", "1.95.1-x86_64-unknown-linux-gnu\n", "1.95.1-x86_64-unknown-linux-gnu"),
            ("1.95.1", "1.95.0-x86_64-unknown-linux-gnu\n1.95.1-x86_64-unknown-linux-gnu\n", "1.95.1-x86_64-unknown-linux-gnu"),
            ("1.95", "1.950.0-x86_64-unknown-linux-gnu\nnightly-x86_64-unknown-linux-gnu\n", None),
            ("1.95.1", "1.95.0-x86_64-unknown-linux-gnu\n", None),
        )
        for msrv, installed, expected in cases:
            with self.subTest(msrv=msrv, installed=installed):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    (root / "Cargo.toml").write_text(f'[workspace.package]\nrust-version = "{msrv}"\n')
                    (root / "scripts").mkdir()
                    (root / "scripts/build-lock.sh").write_text('exec "$@"\n')
                    for name, body in {
                        "rustup": 'printf "%s" "$MSRV_INSTALLED"',
                        "cargo": 'printf "%s\\n" "$@" > "$MSRV_CAPTURE"',
                    }.items():
                        executable = root / name
                        executable.write_text(f"#!/bin/sh\n{body}\n")
                        executable.chmod(0o755)
                    capture = root / "invocation"
                    result = subprocess.run(
                        ["bash", "-c", recipe], cwd=root, capture_output=True, text=True,
                        env=os.environ | {"PATH": f"{root}:{os.environ['PATH']}", "MSRV_INSTALLED": installed, "MSRV_CAPTURE": str(capture)},
                    )
                    if expected is None:
                        self.assertEqual(127, result.returncode, result.stderr)
                        self.assertFalse(capture.exists())
                        self.assertIn(f"rustup toolchain install {msrv}", result.stderr)
                    else:
                        self.assertEqual(0, result.returncode, result.stderr)
                        self.assertEqual([f"+{expected}", "check", "--locked", "--workspace", "--all-targets"], capture.read_text().splitlines())

    def test_retired_privileged_workflow_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_workflows(root)
            retired = root / RETIRED_PRIVILEGED_WORKFLOW
            retired.write_text(
                "on:\n  workflow_dispatch:\n"
                "jobs:\n  netns:\n    steps:\n"
                "      - run: bash crates/evpn-linux/tests/docker/run-netns-tests.sh all\n"
            )
            self.assertIn(
                f"retired workflow must stay absent: {RETIRED_PRIVILEGED_WORKFLOW}",
                "\n".join(check(root)),
            )

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
                "bench/scale/Cargo.toml --workspace --locked",
                "bench/scale/Cargo.toml --workspace",
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
            (
                WORKFLOW,
                "cargo build --manifest-path bench/scale/Cargo.toml --locked -p reloadstall",
                "true",
            ),
        )
        for workflow, old, new in cases:
            with self.subTest(workflow=workflow, seam=old):
                self.mutate(old, new, workflow=workflow)

    def test_added_locked_command_passes_and_blind_extractor_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_workflows(root)
            target = root / WORKFLOW
            target.write_text(
                target.read_text().replace(
                    "- run: cargo test --locked --workspace",
                    "- run: cargo test --locked --workspace\n"
                    "      - run: cargo check --locked -p rustbgpd-api",
                    1,
                )
            )
            self.assertEqual([], check(root))
        # A command regex that matches nothing sees no workflow at all.
        with mock.patch.object(contract, "CARGO_COMMAND", re.compile(r"(?!)")):
            failures = "\n".join(check(ROOT))
        self.assertIn("root Cargo commands removed", failures)
        self.assertIn("standalone Cargo command inventory", failures)

    def test_semantic_mutations_fail_closed(self) -> None:
        cases = (
            ("  core:\n", "  renamed_core:\n"),
            ("  core_tests:\n", "  renamed_core_tests:\n"),
            ("  scale_receipts:\n", "  renamed_scale:\n"),
            ("  check:\n", "  renamed_check:\n"),
            ("  msrv:\n", "  renamed_msrv:\n"),
            ("  evpn_bum_filter_kernel:\n", "  renamed_evpn:\n"),
            ("- run: cargo test --locked --workspace", "- run: true"),
            ("- run: cargo doc --locked --workspace --lib --bin rustbgpd --bin rbgp --no-deps --document-private-items", "- run: true"),
            ("--lib --bin rustbgpd --bin rbgp", "--bin rustbgpd --bin rbgp"),
            ("--bin rustbgpd --bin rbgp", "--bin rbgp"),
            ("--bin rustbgpd --bin rbgp", "--bin rustbgpd"),
            ("--document-private-items", ""),
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
            ("if: ${{ always() }}", "if: ${{ success() }}"),
            (
                "needs: [core, core_tests, scale_receipts]",
                "needs: [core]",
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
                '[[ "$CORE_RESULT" != "success" || "$CORE_TESTS_RESULT" != '
                '"success" || "$SCALE_RECEIPTS_RESULT" != "success" ]]',
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
            for name in ("CORE", "CORE_TESTS", "SCALE_RECEIPTS"):
                env.pop(f"{name}_RESULT", None)
            for name, value in values.items():
                if value is not None:
                    env[f"{name}_RESULT"] = value
            return subprocess.run(["bash", "-c", shell], env=env, capture_output=True)

        names = ("CORE", "CORE_TESTS", "SCALE_RECEIPTS")
        good = {name: "success" for name in names}
        self.assertEqual(0, run(good).returncode)
        for name in good:
            for bad in ("failure", "cancelled", "skipped", "", None):
                values = good | {name: bad}
                with self.subTest(child=name, result=bad):
                    self.assertNotEqual(0, run(values).returncode)


if __name__ == "__main__":
    unittest.main()
