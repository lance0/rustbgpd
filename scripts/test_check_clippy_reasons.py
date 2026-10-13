#!/usr/bin/env python3
"""Mutation proofs for the clippy-suppression reason ratchet."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-clippy-reasons.py")
REPO = SCRIPT.parent.parent
SPEC = importlib.util.spec_from_file_location("check_clippy_reasons", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


def run_checker(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        check=False,
        capture_output=True,
        text=True,
    )


def check_source(text: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / "lib.rs"
        source.write_text(text, encoding="utf-8")
        return run_checker(str(source))


class ClippyReasonTests(unittest.TestCase):
    def test_cfg_attr_suppression_without_reason_is_rejected(self) -> None:
        for source in (
            "#[cfg_attr(test, allow(clippy::unwrap_used))]\nfn f() {}\n",
            "#[cfg_attr(not(test), expect(clippy::needless_pass_by_value))]\nfn f() {}\n",
            "#![cfg_attr(test, allow(clippy::unwrap_used))]\n",
            "#[cfg_attr(\n    feature = \"x\",\n    expect(clippy::too_many_lines)\n)]\nfn f() {}\n",
            # Another nested attribute's reason does not cover this one.
            '#[cfg_attr(test, allow(dead_code, reason = "fixture"), allow(clippy::unwrap_used))]\n'
            "fn f() {}\n",
        ):
            with self.subTest(source=source):
                result = check_source(source)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn("lib.rs:1: missing reason", result.stdout)

    def test_cfg_attr_suppression_with_reason_is_accepted(self) -> None:
        for source in (
            '#[cfg_attr(test, allow(clippy::unwrap_used, reason = "fixture"))]\nfn f() {}\n',
            "#[cfg_attr(\n    not(test),\n    expect(\n        clippy::needless_pass_by_value,\n"
            '        reason = "the test variant moves a receiver in"\n    )\n)]\nfn f() {}\n',
            "#[cfg_attr(test, allow(dead_code))]\nfn f() {}\n",
            "#[cfg_attr(test, deny(clippy::unwrap_used))]\nfn f() {}\n",
            '#[cfg_attr(feature = "clippy::x", derive(Debug))]\nstruct S;\n',
            '#[cfg_attr(feature = "clippy::x", allow(dead_code))]\nfn f() {}\n',
            '#[cfg_attr(test, allow(clippy::unwrap_used, reason = "a (b) c"), allow(dead_code))]\n'
            "fn f() {}\n",
        ):
            with self.subTest(source=source):
                result = check_source(source)
                self.assertEqual(result.returncode, 0, result.stdout)

    def test_nonexistent_explicit_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.rs"
            result = run_checker(str(missing))

        self.assertEqual(result.returncode, 2)
        self.assertIn(str(missing), result.stderr)

    def test_crate_level_suppression_without_reason_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "lib.rs"
            source.write_text(
                "#![allow(clippy::module_name_repetitions)]\n", encoding="utf-8"
            )
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(source)],
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.returncode, 1)
        self.assertIn("missing reason", result.stdout)
        self.assertIn("#![allow(clippy::module_name_repetitions)]", result.stdout)
        self.assertNotIn("unterminated", result.stdout)

    def test_workspace_source_roots_include_daemon_and_all_workspace_packages(self) -> None:
        roots = checker.workspace_source_roots(REPO)
        for path in (
            REPO / "src",
            REPO / "crates/evpn-linux/src",
            REPO / "bench/evpn-load/src",
            REPO / "tools/rs-config-render/src",
        ):
            with self.subTest(path=path):
                self.assertIn(path, roots)

    def test_default_discovery_rejects_a_new_workspace_source_root_without_reason(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "src").mkdir()
            (repo / "Cargo.toml").write_text(
                "[package]\nname = \"reason-ratchet-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
                encoding="utf-8",
            )
            (repo / "src/lib.rs").write_text(
                "#[allow(clippy::too_many_lines)]\npub fn fixture() {}\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, str(SCRIPT)],
                cwd=repo,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.returncode, 1)
        self.assertIn("src/lib.rs:1: missing reason", result.stdout)

    def test_metadata_failure_reports_cargo_diagnostic_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "Cargo.toml").write_text("[package\n", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT)],
                cwd=repo,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.returncode, 2)
        self.assertIn("cargo metadata failed:", result.stderr)
        self.assertIn("Cargo.toml:1:9", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_existing_ratcheted_source_is_clean(self) -> None:
        self.assertEqual(
            checker.missing_reasons(REPO / "crates/telemetry/src/metrics.rs"),
            [],
        )


if __name__ == "__main__":
    unittest.main()
