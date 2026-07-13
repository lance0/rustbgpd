#!/usr/bin/env -S /usr/bin/python3 -I -S
"""Static fail-closed contract tests for the retained shell driver."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


RUNNER = Path(__file__).with_name("run-receipt.sh")
RELOADSTALL_ROOT = RUNNER.parent
PYTHON_ENVIRONMENT = [
    "/usr/bin/env",
    "-i",
    "LC_ALL=C",
    "TZ=UTC",
    "HOME=/nonexistent",
    "PATH=/usr/bin:/bin",
    "PYTHONDONTWRITEBYTECODE=1",
]


def isolated_python(
    script: Path, *arguments: str, environment: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    extra = [f"{name}={value}" for name, value in sorted((environment or {}).items())]
    return subprocess.run(
        [
            *PYTHON_ENVIRONMENT,
            *extra,
            "/usr/bin/python3",
            "-I",
            "-S",
            str(script.resolve()),
            *arguments,
        ],
        check=False,
        capture_output=True,
        text=True,
    )


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
            '"$source_root/bench/scale/reloadstall/build_fence.py"'
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

    def test_canonical_baseline_is_current_integrated_main(self) -> None:
        self.assertIn(
            "readonly canonical_baseline_commit="
            "aacb3a89527759b610bead421c80612f04d04826",
            self.source,
        )

    def test_every_authoritative_python_path_is_absolute_and_isolated(self) -> None:
        for fragment in (
            "readonly python_command=/usr/bin/python3",
            "/usr/bin/env -i LC_ALL=C TZ=UTC HOME=/nonexistent",
            'python_invocation=("${python_environment[@]}" "$python_command" -I -S)',
            '"$source_root/bench/scale/reloadstall/build_fence.py"',
            '"$source_root/bench/scale/reloadstall/process_fence.py"',
            '"$source_root/bench/scale/reloadstall/gen-scenario.py"',
            '"$python_command" -I -S - "$output_dir/invocation.json"',
            '"$python_command" -I -S - "$output_dir/manifest.json"',
            '"$source_root/bench/scale/reloadstall/validate_receipt.py" "$output_dir"',
        ):
            self.assertIn(fragment, self.source)
        self.assertNotIn("\npython3 ", self.source)
        self.assertNotIn("\n  python3 ", self.source)

    def test_process_fence_uses_only_the_pinned_restricted_container(self) -> None:
        for fragment in (
            "readonly docker_command=/usr/bin/docker",
            "readonly process_fence_image_digest='sha256:"
            "f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3'",
            'readonly process_fence_image="rust:1.95-trixie@$process_fence_image_digest"',
            "readonly process_fence_image_id=$process_fence_image_digest",
            '"$docker_command" image inspect',
            "pinned process-fence image is unavailable locally",
            "pinned process-fence image identity mismatch",
            '"${docker_environment[@]}" "$docker_command" run --rm --pull=never',
            "--network none --pid host --read-only --cap-drop ALL --cap-add SYS_PTRACE",
            "--security-opt apparmor=unconfined --security-opt no-new-privileges",
            '--mount "type=bind,src=/proc,dst=/host-proc,readonly"',
            "dst=/process_fence.py,readonly",
            '"$process_fence_image" /usr/bin/python3 -I -S /process_fence.py',
            "--proc-root /host-proc",
            '--runner-pid "$$"',
        ):
            self.assertIn(fragment, self.source)
        process_fence = self.source.split("process_fence=(", 1)[1].split(
            ")\ncapture_busy()", 1
        )[0]
        self.assertEqual(process_fence.count("--mount"), 2)
        self.assertNotIn("docker pull", self.source)

    def test_sitecustomize_cannot_bypass_authority_commands(self) -> None:
        with tempfile.TemporaryDirectory(prefix="reloadstall-sitecustomize-") as raw:
            root = Path(raw)
            marker = root / "startup-ran"
            (root / "sitecustomize.py").write_text(
                "import os\n"
                f"open({str(marker)!r}, 'w', encoding='utf-8').write('ran')\n"
                "os._exit(0)\n",
                encoding="utf-8",
            )
            hostile = {"PYTHONPATH": str(root), "PYTHONSTARTUP": str(root / "x.py")}

            build = isolated_python(
                RELOADSTALL_ROOT / "build_fence.py",
                "--environment-only",
                environment={**hostile, "RUSTFLAGS": "-C target-cpu=native"},
            )
            self.assertEqual(build.returncode, 2, build.stderr)
            self.assertIn("RUSTFLAGS", build.stderr)

            proc = root / "proc"
            process = proc / "4242"
            process.mkdir(parents=True)
            (process / "stat").write_text(
                "4242 (cargo) S 1 0 0 0 0 0\n", encoding="utf-8"
            )
            (process / "comm").write_text("cargo\n", encoding="utf-8")
            (process / "cmdline").write_bytes(b"/usr/bin/cargo\0build\0")
            (process / "cwd").symlink_to("/tmp")
            (process / "exe").symlink_to("/usr/bin/cargo")
            process_scan = isolated_python(
                RELOADSTALL_ROOT / "process_fence.py",
                "--proc-root",
                str(proc),
                "--root",
                "/work/rustbgpd-policy-reload-receipt",
                environment=hostile,
            )
            self.assertEqual(process_scan.returncode, 1, process_scan.stderr)
            self.assertIn("known-executable:cargo", process_scan.stdout)

            missing = isolated_python(
                RELOADSTALL_ROOT / "validate_receipt.py",
                str(root / "missing-receipt"),
                environment=hostile,
            )
            self.assertEqual(missing.returncode, 1, missing.stderr)
            self.assertIn('"accepted": false', missing.stdout)

            bad_receipt = root / "bad-receipt"
            bad_receipt.mkdir()
            bad = isolated_python(
                RELOADSTALL_ROOT / "validate_receipt.py",
                str(bad_receipt),
                environment=hostile,
            )
            self.assertEqual(bad.returncode, 1, bad.stderr)
            self.assertIn('"accepted": false', bad.stdout)

            generation = isolated_python(
                RELOADSTALL_ROOT / "gen-scenario.py", environment=hostile
            )
            self.assertNotEqual(generation.returncode, 0)
            self.assertIn("gen-scenario.py <n_peers>", generation.stderr)
            self.assertFalse(marker.exists(), "sitecustomize executed under -I -S")


if __name__ == "__main__":
    unittest.main()
