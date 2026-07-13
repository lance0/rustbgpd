#!/usr/bin/env python3
"""Static fail-closed contract tests for the retained shell driver."""

from __future__ import annotations

import os
import subprocess
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
            'terminate_pid_bounded harness "$harness_pid" 5',
            'terminate_pid_bounded health-probe "$health_pid" 12',
            'terminate_pid_bounded daemon "$daemon_pid" 30',
            'kill -KILL -- "$target"',
        ):
            self.assertIn(fragment, self.source)

    def test_every_long_running_stage_has_its_backstop(self) -> None:
        for fragment in (
            "readonly build_timeout_seconds=1800",
            "readonly generation_timeout_seconds=60",
            "readonly harness_timeout_seconds=4200",
            '--kill-after=30s "$build_timeout_seconds"',
            '--kill-after=5s "$generation_timeout_seconds"',
            '--kill-after=30s "$harness_timeout_seconds"',
        ):
            self.assertIn(fragment, self.source)

    def test_measurement_processes_use_empty_whitelisted_environments(self) -> None:
        self.assertIn("runtime_environment=(env -i LC_ALL=C TZ=UTC)", self.source)
        self.assertIn(
            'daemon_command=(setsid "${runtime_environment[@]}" RUST_LOG=info',
            self.source,
        )
        self.assertIn('"${runtime_environment[@]}" "$cli_bin" --addr', self.source)
        self.assertIn(
            '"${runtime_environment[@]}" "${harness_payload[@]}"', self.source
        )

    def test_exact_source_build_fence_runs_before_cargo(self) -> None:
        fence = self.source.index(
            'python3 "$source_root/bench/scale/reloadstall/build_fence.py"'
        )
        build = self.source.index("build_daemon_cli=(")
        self.assertLess(fence, build)

    def test_build_uses_exact_toolchain_and_does_not_inherit_ambient_path(self) -> None:
        self.assertIn(
            "readonly required_toolchain=1.95.0-x86_64-unknown-linux-gnu",
            self.source,
        )
        self.assertIn("readonly runner_path=/usr/bin:/bin", self.source)
        self.assertIn("readonly build_path=$runner_path", self.source)
        self.assertIn('PATH="$build_path"', self.source)
        self.assertNotIn('PATH="$PATH"', self.source)
        self.assertIn('RUSTUP_TOOLCHAIN="$required_toolchain"', self.source)
        self.assertIn('RUSTC="$rustc_command" RUSTDOC="$rustdoc_command"', self.source)
        self.assertIn(
            'readonly rustup_command="$invoking_home/.cargo/bin/rustup"',
            self.source,
        )
        self.assertIn('"$rustup_command" which', self.source)
        self.assertIn('"$rustc_command" -V', self.source)
        self.assertIn('"$cargo_command" -V', self.source)
        self.assertIn('"$rustdoc_command" -V', self.source)
        self.assertNotIn("command -v rustup", self.source)
        self.assertNotIn("rustup which", self.source)
        self.assertNotIn("RUSTC=/usr/bin/rustc", self.source)

    def test_runner_rejects_inherited_shell_function_selection(self) -> None:
        self.assertTrue(self.source.startswith("#!/bin/bash -p\n"))
        self.assertIn("initial_functions=$(declare -F)", self.source)
        self.assertIn("inherited shell functions are forbidden", self.source)
        self.assertIn(
            "exported shell functions and shell startup hooks are forbidden",
            self.source,
        )

        environment = os.environ.copy()
        environment["BASH_FUNC_rustup%%"] = "() { echo fake; }"
        completed = subprocess.run(
            [RUNNER, "--help"],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn(
            "exported shell functions and shell startup hooks are forbidden",
            completed.stderr,
        )

    def test_runner_rejects_sourcing(self) -> None:
        completed = subprocess.run(
            ["/bin/bash", "-p", "-c", f"source {RUNNER} --help"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("must be executed directly, not sourced", completed.stderr)

    def test_runner_rejects_inherited_aliases(self) -> None:
        completed = subprocess.run(
            [
                "/bin/bash",
                "-p",
                "-c",
                f"alias git=false; source {RUNNER} --help",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("inherited shell aliases are forbidden", completed.stderr)
        self.assertIn("git", completed.stderr)

    def test_runner_rejects_shell_startup_hooks(self) -> None:
        for variable in ("BASH_ENV", "ENV"):
            with self.subTest(variable=variable):
                environment = os.environ.copy()
                environment[variable] = "/tmp/receipt-shell-startup"
                completed = subprocess.run(
                    [RUNNER, "--help"],
                    check=False,
                    capture_output=True,
                    text=True,
                    env=environment,
                )
                self.assertEqual(completed.returncode, 2)
                self.assertIn("shell startup hooks are forbidden", completed.stderr)
                self.assertIn(variable, completed.stderr)

    def test_unprivileged_bash_interpreter_is_rejected(self) -> None:
        completed = subprocess.run(
            ["/bin/bash", RUNNER, "--help"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("privileged shell mode", completed.stderr)

    def test_runner_does_not_trust_ambient_path(self) -> None:
        environment = os.environ.copy()
        environment["PATH"] = "/tmp/shadow"
        completed = subprocess.run(
            [RUNNER, "--help"],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("policy reload-stall receipt", completed.stdout)

    def test_commit_object_and_complete_tree_are_reverified(self) -> None:
        for fragment in (
            'cat-file commit "$retained_source_ref" >"$source_commit_object"',
            '"$git_command" hash-object',
            "bundle create",
            'bundle verify "$source_bundle"',
            "fetch --quiet",
            '--expected-tree "$source_tree" --require-immutable',
            'find "$source_root" -exec chmod a-w {} +',
            "source_tree_verification=pre-build,post-build,measurement-boundary,post-run",
        ):
            self.assertIn(fragment, self.source)

    def test_canonical_evidence_uses_exact_object_ids(self) -> None:
        for fragment in (
            "readonly source_remote=https://github.com/lance0/rustbgpd.git",
            '"+$canonical_baseline_commit:$retained_baseline_ref"',
            '"+$source_sha:$retained_source_ref"',
            "proof=exact-sha-live-fetch-and-retained-bundle",
        ):
            self.assertIn(fragment, self.source)
        self.assertNotIn(
            '"+$canonical_candidate_context_ref:$retained_source_ref"', self.source
        )


if __name__ == "__main__":
    unittest.main()
