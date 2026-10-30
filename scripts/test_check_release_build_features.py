#!/usr/bin/env python3
"""Mutation proofs for the release build feature guard."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_release_build_features as guard


SHIPPED = "-p rustbgpd -p rustbgpctl -p rs-config-render -p birdwatcher-adapter"


def workflow(build: str) -> str:
    return f"""jobs:
  build:
    steps:
      - name: Build release binaries
        run: cargo build --locked {build} --release --features rustbgpd/jemalloc --target ${{{{ matrix.target }}}}

      - name: Package binaries
        run: |
          cargo build --locked -p rustbgpctl -p rustbgpd
"""


def tree(rib: str, transport: str) -> str:
    root = "/src/rustbgpd"
    return "\n".join(
        (
            f"default,jemalloc|rustbgpd v0.80.1 ({root})",
            f"{transport}|rustbgpd-transport v0.80.1 ({root}/crates/transport)",
            f"{rib}|rustbgpd-rib v0.80.1 ({root}/crates/rib)",
            f"{rib}|rustbgpd-rib v0.80.1 ({root}/crates/rib) (*)",
            "|bytes v1.10.1",
            "",
        )
    )


class ReleaseBuildArgsTest(unittest.TestCase):
    def test_extracts_package_set_without_profile_or_matrix_target(self) -> None:
        self.assertEqual(
            guard.release_build_args(workflow(SHIPPED)),
            ["--locked", *SHIPPED.split(), "--features", "rustbgpd/jemalloc"],
        )

    def test_keeps_workspace_selection_so_the_tree_sees_it(self) -> None:
        self.assertIn("--workspace", guard.release_build_args(workflow("--workspace")))

    def test_missing_or_ambiguous_build_fails_closed(self) -> None:
        for text in ("jobs: {}\n", workflow(SHIPPED) + workflow(SHIPPED)):
            with self.subTest(text=text), self.assertRaises(ValueError):
                guard.release_build_args(text)

    def test_this_repository_release_build_selects_the_shipped_packages(self) -> None:
        args = guard.release_build_args(guard.RELEASE_WORKFLOW.read_text())
        self.assertNotIn("--workspace", args)
        for package in SHIPPED.split()[1::2]:
            self.assertIn(package, args)


class ViolationsTest(unittest.TestCase):
    def test_clean_tree_passes(self) -> None:
        self.assertEqual(guard.violations(guard.enabled_features(tree("", ""))), [])

    def test_bench_internals_on_rib_or_transport_fails(self) -> None:
        for rib, transport in (
            ("bench-internals", "bench-internals"),
            ("bench-internals", ""),
            ("", "bench-internals"),
            ("default,bench-internals", ""),
        ):
            with self.subTest(rib=rib, transport=transport):
                errors = guard.violations(guard.enabled_features(tree(rib, transport)))
                self.assertTrue(errors)
                self.assertTrue(all("bench-internals" in error for error in errors))

    def test_output_without_the_guarded_crates_fails_closed(self) -> None:
        for text in ("", "rustbgpd-rib v0.80.1 [bench-internals]\n"):
            with self.subTest(text=text):
                errors = guard.violations(guard.enabled_features(text))
                self.assertEqual(len(errors), len(guard.REQUIRED_PACKAGES))


class MainTest(unittest.TestCase):
    def run_main(self, returncode: int, stdout: str) -> int:
        result = subprocess.CompletedProcess([], returncode, stdout, "boom")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "release.yml"
            path.write_text(workflow(SHIPPED))
            with (
                mock.patch.object(guard.subprocess, "run", return_value=result),
                mock.patch("sys.stdout"),
                mock.patch("sys.stderr"),
            ):
                return guard.main(["--workflow", str(path)])

    def test_clean_tree_passes(self) -> None:
        self.assertEqual(self.run_main(0, tree("", "")), 0)

    def test_failed_or_empty_cargo_tree_fails(self) -> None:
        for returncode, stdout in ((101, ""), (101, tree("", "")), (0, ""), (0, "\n")):
            with self.subTest(returncode=returncode, stdout=stdout):
                self.assertEqual(self.run_main(returncode, stdout), 1)

    def test_bench_internals_fails(self) -> None:
        self.assertEqual(self.run_main(0, tree("bench-internals", "")), 1)


if __name__ == "__main__":
    unittest.main()
