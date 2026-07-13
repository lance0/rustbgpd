#!/usr/bin/env python3
"""Static fail-closed contract tests for the retained shell driver."""

from __future__ import annotations

import unittest
from pathlib import Path


RUNNER = Path(__file__).with_name("run-receipt.sh")


class RunnerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = RUNNER.read_text(encoding="utf-8")

    def test_terminal_signal_traps_reach_exit_cleanup(self) -> None:
        for fragment in (
            "trap cleanup EXIT",
            "trap 'on_signal 130' INT",
            "trap 'on_signal 143' TERM",
            "terminate_pid_bounded harness \"$harness_pid\" 5",
            "terminate_pid_bounded health-probe \"$health_pid\" 12",
            "terminate_pid_bounded daemon \"$daemon_pid\" 30",
            "kill -KILL -- \"$target\"",
        ):
            self.assertIn(fragment, self.source)

    def test_every_long_running_stage_has_its_backstop(self) -> None:
        for fragment in (
            "readonly build_timeout_seconds=1800",
            "readonly generation_timeout_seconds=60",
            "readonly harness_timeout_seconds=4200",
            "--kill-after=30s \"$build_timeout_seconds\"",
            "--kill-after=5s \"$generation_timeout_seconds\"",
            "--kill-after=30s \"$harness_timeout_seconds\"",
        ):
            self.assertIn(fragment, self.source)

    def test_measurement_processes_use_empty_whitelisted_environments(self) -> None:
        self.assertIn("runtime_environment=(env -i LC_ALL=C TZ=UTC)", self.source)
        self.assertIn(
            'daemon_command=(setsid "${runtime_environment[@]}" RUST_LOG=info',
            self.source,
        )
        self.assertIn(
            '"${runtime_environment[@]}" "$cli_bin" --addr', self.source
        )
        self.assertIn('"${runtime_environment[@]}" "${harness_payload[@]}"', self.source)

    def test_exact_source_build_fence_runs_before_cargo(self) -> None:
        fence = self.source.index(
            'python3 "$source_root/bench/scale/reloadstall/build_fence.py"'
        )
        build = self.source.index('build_daemon_cli=(')
        self.assertLess(fence, build)

    def test_build_uses_exact_toolchain_and_does_not_inherit_ambient_path(self) -> None:
        self.assertIn(
            "readonly required_toolchain=1.95.0-x86_64-unknown-linux-gnu",
            self.source,
        )
        self.assertIn("readonly build_path=/usr/bin:/bin", self.source)
        self.assertIn('PATH="$build_path"', self.source)
        self.assertNotIn('PATH="$PATH"', self.source)
        self.assertIn('RUSTUP_TOOLCHAIN="$required_toolchain"', self.source)
        self.assertIn('RUSTC="$rustc_command" RUSTDOC="$rustdoc_command"', self.source)
        self.assertIn(
            'rustc_command=$(rustup which --toolchain "$required_toolchain" rustc)',
            self.source,
        )
        self.assertNotIn("RUSTC=/usr/bin/rustc", self.source)

    def test_commit_object_and_complete_tree_are_reverified(self) -> None:
        for fragment in (
            'git cat-file commit "$source_sha" >"$source_commit_object"',
            'git hash-object -t commit "$source_commit_object"',
            '--expected-tree "$source_tree" --require-immutable',
            'find "$source_root" -exec chmod a-w {} +',
            "source_tree_verification=pre-build,post-build,measurement-boundary,post-run",
        ):
            self.assertIn(fragment, self.source)


if __name__ == "__main__":
    unittest.main()
