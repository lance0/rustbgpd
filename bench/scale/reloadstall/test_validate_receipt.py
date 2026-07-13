#!/usr/bin/env python3
"""Adversarial unit tests for the retained reload-stall receipt validator."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import validate_receipt as validator


RUNTIME = validator.RUNTIME_DIR
OUTPUT = validator.OUTPUT_DIR
REPO = validator.REPO_ROOT
SOURCE = validator.SOURCE_ROOT
TARGET = validator.BUILD_TARGET
ARCHIVE_FILES = {
    "bench/scale/reloadstall/build_fence.py": b"# build fence fixture\n",
    "bench/scale/reloadstall/gen-scenario.py": b"# generator fixture\n",
    "bench/scale/reloadstall/process_fence.py": b"# process fence fixture\n",
    "bench/scale/reloadstall/src/main.rs": b"// harness fixture\n",
    "bench/scale/reloadstall/run-receipt.sh": b"# runner fixture\n",
    "bench/scale/reloadstall/validate_receipt.py": b"# validator fixture\n",
}


def fixture_git(repository: Path, *arguments: str, environment=None) -> bytes:
    if environment is None:
        environment = validator.GIT_ENVIRONMENT
    completed = subprocess.run(
        [validator.GIT, "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        env=environment,
    )
    return completed.stdout


def source_evidence(
    raw: str, *, candidate_message: str = "fixture candidate"
) -> tuple[str, str, str, bytes, bytes, bytes, Path]:
    """Create exact-SHA retained refs and evidence fetched from one Git repo."""
    repository = Path(raw) / "repository"
    repository.mkdir()
    fixture_git(repository, "init", "--quiet", "--initial-branch=main")
    for relative, content in ARCHIVE_FILES.items():
        path = repository / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    baseline_path = repository / "bench/scale/reloadstall/validate_receipt.py"
    baseline_path.write_bytes(b"# baseline validator fixture\n")
    fixture_git(repository, "add", "--all")
    environment = validator.GIT_ENVIRONMENT.copy()
    environment.update(
        {
            "GIT_AUTHOR_NAME": "Receipt Fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+00:00",
            "GIT_COMMITTER_NAME": "Receipt Fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+00:00",
        }
    )
    fixture_git(
        repository,
        "commit",
        "--quiet",
        "-m",
        "fixture baseline",
        environment=environment,
    )
    baseline = fixture_git(repository, "rev-parse", "HEAD").decode().strip()
    fixture_git(
        repository,
        "switch",
        "--quiet",
        "-c",
        validator.CANONICAL_CANDIDATE_CONTEXT_REF.removeprefix("refs/heads/"),
    )
    baseline_path.write_bytes(
        ARCHIVE_FILES["bench/scale/reloadstall/validate_receipt.py"]
    )
    fixture_git(repository, "add", "--all")
    candidate_environment = environment.copy()
    candidate_environment["GIT_AUTHOR_DATE"] = "2000-01-02T00:00:00+00:00"
    candidate_environment["GIT_COMMITTER_DATE"] = "2000-01-02T00:00:00+00:00"
    fixture_git(
        repository,
        "commit",
        "--quiet",
        "-m",
        candidate_message,
        environment=candidate_environment,
    )
    commit = fixture_git(repository, "rev-parse", "HEAD").decode().strip()
    tree = fixture_git(repository, "rev-parse", "HEAD^{tree}").decode().strip()
    commit_payload = fixture_git(repository, "cat-file", "commit", "HEAD")
    fixture_git(repository, "update-ref", validator.RETAINED_BASELINE_REF, baseline)
    fixture_git(repository, "update-ref", validator.RETAINED_SOURCE_REF, commit)
    archive = Path(raw) / "source.tar"
    bundle = Path(raw) / "source.bundle"
    fixture_git(
        repository,
        "archive",
        "--format=tar",
        f"--output={archive}",
        validator.RETAINED_SOURCE_REF,
    )
    fixture_git(
        repository,
        "bundle",
        "create",
        str(bundle),
        validator.RETAINED_BASELINE_REF,
        validator.RETAINED_SOURCE_REF,
    )
    return (
        baseline,
        commit,
        tree,
        commit_payload,
        archive.read_bytes(),
        bundle.read_bytes(),
        repository,
    )


SOURCE_REPOSITORY_TEMP = tempfile.TemporaryDirectory(prefix="reloadstall-fixture-repo-")
(
    BASELINE_COMMIT,
    COMMIT,
    TREE,
    COMMIT_PAYLOAD,
    ARCHIVE_BYTES,
    BUNDLE_BYTES,
    CANONICAL_FETCH_REPOSITORY,
) = source_evidence(SOURCE_REPOSITORY_TEMP.name)


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def source_archive() -> bytes:
    return ARCHIVE_BYTES


def policy(reject: str, community: str) -> str:
    return validator.expected_policy(reject, community)


def config() -> str:
    rows = [
        "[global]",
        "asn = 65500",
        'router_id = "10.0.0.1"',
        "listen_port = 1790",
        f'runtime_state_dir = "{RUNTIME}"',
        "",
        "[global.telemetry]",
        'log_format = "json"',
        "",
        "[global.telemetry.grpc_uds]",
        f'path = "{RUNTIME}/grpc.sock"',
        "",
        "[security.grpc]",
        'enforcement = "legacy"',
        "",
        "[policy]",
        'rpol_files = ["member.rpol"]',
        'import_chain = ["member-in"]',
        'export_chain = ["member-out"]',
        "",
    ]
    for index in range(validator.PEERS):
        rows.extend(
            [
                "[[neighbors]]",
                f'address = "127.1.{index // 200}.{index % 200 + 1}"',
                f"remote_asn = {64_512 + index}",
                "route_server_client = true",
                'families = ["ipv4_unicast"]',
                "hold_time = 180",
                "",
            ]
        )
    return "\n".join(rows)


def harness_log() -> str:
    rows = [
        "# reloadstall peers=700 prefixes=400400 per_peer=572 pid=<DAEMON_PID>",
        "established 700 at 0.6s",
        "converged (>= 399828/observer) at 3.4s rss_mib=815",
        "control_maxgap_ms: p50=19.00 p95=30.00 max=42.00 (n=700)",
        "control_rss_mib 815",
    ]
    for reload_index, (community, community_value) in enumerate(
        zip(validator.COMMUNITIES, validator.COMMUNITY_VALUES, strict=True), 1
    ):
        generation = "b" if reload_index % 2 else "a"
        rows.extend(
            [
                f"reload {reload_index} SIGHUP wall_us={reload_index}00 policy=<RUNTIME_DIR>/gen-{generation}.rpol",
                f"reload {reload_index} current_generation_complete "
                f"contract={validator.CONTRACT} community={community} "
                "observers=700/700 active_prefixes_per_observer=399828 target=399828",
                f"reload {reload_index} completion_s: p50=154.00 p95=290.00 max=309.00 (n=700)",
                f"reload {reload_index} maxgap_ms: p50=744.00 p95=760.00 max=820.00 (n=700)",
                f"reload {reload_index} first_update_ms: p50=1.00 p95=2.00 max=3.00 (n=700)",
                f"reload {reload_index} rss_mib before=815 after=900 comms_sample=[{community_value}]",
                f"reload {reload_index} current_generation_verified "
                f"contract={validator.CONTRACT} community={community} "
                "observers=700/700 active_prefixes_per_observer=399828 target=399828",
                f"reload {reload_index} sessions_up 700/700",
            ]
        )
    rows.extend(
        [
            "defects parse_errors=0 base_withdrawals=0 marker_conflicts=0 route_identity_defects=0",
            "done rss_mib=1303",
        ]
    )
    return "\n".join(rows) + "\n"


def daemon_log() -> str:
    rows = [
        json.dumps(
            {"fields": {"message": "session established", "peer": f"peer-{index}"}},
            sort_keys=True,
        )
        for index in range(validator.PEERS)
    ]
    rows.extend(
        json.dumps({"fields": {"message": "config reload complete"}}, sort_keys=True)
        for _ in range(validator.RELOADS)
    )
    return "\n".join(rows) + "\n"


def resign(root: Path) -> None:
    rows = []
    for path in sorted(
        (
            path
            for path in root.rglob("*")
            if path.is_file() and not path.is_symlink() and path.name != "SHA256SUMS"
        ),
        key=lambda path: path.relative_to(root).as_posix(),
    ):
        relative = path.relative_to(root).as_posix()
        rows.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {relative}")
    write(root / "SHA256SUMS", "\n".join(rows) + "\n")


def make_receipt(root: Path) -> None:
    generation_a = policy("192.0.2.0/24", "65500:1000")
    generation_b = policy("198.51.100.0/24", "65500:2000")
    archive_bytes = source_archive()
    archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()
    bundle_sha256 = hashlib.sha256(BUNDLE_BYTES).hexdigest()
    files = {
        "build.log": "build ok\n",
        "daemon.log": daemon_log(),
        "governors.tsv": (
            "wall_ns\tpolicy\tgovernor\n"
            "2\t/sys/devices/system/cpu/cpufreq/policy0\tperformance\n"
        ),
        "harness.log": harness_log(),
        "health-errors.log": "",
        "health.tsv": "wall_ns\telapsed_us\texit_code\n1\t100\t0\n",
        "load-before.tsv": "wall_ns\tload_one\n4\t0.5\n",
        "processes.tsv": (
            "wall_ns\tprocess\tpid\tcommand\n3\t<none>\t<none>\t<none>\n"
        ),
        "provenance.txt": (
            f"source_commit={COMMIT}\nsource_tree={TREE}\n"
            f"source_commit_object_sha={COMMIT}\n"
            f"source_archive_sha256={archive_sha256}\n"
            f"source_bundle_sha256={bundle_sha256}\n"
            "source_remote=https://github.com/lance0/rustbgpd.git\n"
            "canonical_baseline_context_ref="
            f"{validator.CANONICAL_BASELINE_CONTEXT_REF}\n"
            f"canonical_baseline_commit={BASELINE_COMMIT}\n"
            "canonical_candidate_context_ref="
            f"{validator.CANONICAL_CANDIDATE_CONTEXT_REF}\n"
            f"canonical_source_commit={COMMIT}\n"
            f"canonical_source_tree={TREE}\n"
            "canonical_membership_proof=exact-sha-live-fetch-and-retained-bundle\n"
            "build_source_root=<SOURCE_ROOT>\nbuild_target_dir=<BUILD_TARGET>\n"
            "host_lock=<HOST_LOCK>\nruntime_dir=<RUNTIME_DIR>\n"
            "output_dir=<OUTPUT_DIR>\n"
            f"cargo_command=<RUSTUP_HOME>/toolchains/{validator.REQUIRED_TOOLCHAIN}/bin/cargo\n"
            f"cargo_resolved=<RUSTUP_HOME>/toolchains/{validator.REQUIRED_TOOLCHAIN}/bin/cargo\n"
            f"rustc_command=<RUSTUP_HOME>/toolchains/{validator.REQUIRED_TOOLCHAIN}/bin/rustc\n"
            f"rustc_resolved=<RUSTUP_HOME>/toolchains/{validator.REQUIRED_TOOLCHAIN}/bin/rustc\n"
            "rustup_command=<HOME>/.cargo/bin/rustup\n"
            "rustup_resolved=<HOME>/.cargo/bin/rustup\n"
            "rustdoc_command=<RUSTUP_HOME>/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/rustdoc\n"
            "rustdoc_resolved=<RUSTUP_HOME>/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/rustdoc\n"
            f"active_toolchain={validator.REQUIRED_TOOLCHAIN}\n"
            f"required_toolchain={validator.REQUIRED_TOOLCHAIN}\n"
            f"rustc_sysroot=<RUSTUP_HOME>/toolchains/{validator.REQUIRED_TOOLCHAIN}\n"
            "allowed_cargo_config=<SOURCE_ROOT>/.cargo/config.toml\n"
            "external_cargo_configs=<none>\n"
            "build_override_fence=clear\n"
            "source_tree_verification=pre-build,post-build,measurement-boundary,post-run\n"
            "build_environment=env -i LC_ALL=C TZ=UTC HOME=<BUILD_HOME> CARGO_HOME=<CARGO_HOME> RUSTUP_HOME=<RUSTUP_HOME> PATH=/usr/bin:/bin "
            f"RUSTUP_TOOLCHAIN={validator.REQUIRED_TOOLCHAIN} CARGO_TARGET_DIR=<BUILD_TARGET> "
            "RUSTC=<RUSTC_COMMAND> RUSTDOC=<RUSTDOC_COMMAND>\n"
            "daemon_environment=env -i LC_ALL=C TZ=UTC RUST_LOG=info\n"
            "harness_environment=env -i LC_ALL=C TZ=UTC\n"
            "health_environment=env -i LC_ALL=C TZ=UTC\n"
            "rustc 1.95.0 (fixture)\ncargo 1.95.0 (fixture)\n"
            "rustdoc 1.95.0 (fixture)\n"
            f"root_Cargo.lock_sha256={'4' * 64}\n"
            f"reloadstall_Cargo.lock_sha256={'5' * 64}\n"
            f"cargo_tool_sha256={'6' * 64}\n"
            f"rustc_tool_sha256={'7' * 64}\n"
            f"rustdoc_tool_sha256={'8' * 64}\n"
            f"rustup_tool_sha256={'9' * 64}\n"
            f"rustbgpd_sha256={'1' * 64}\nrbgp_sha256={'2' * 64}\n"
            f"reloadstall_sha256={'3' * 64}\n"
            "environment_RUSTFLAGS=<unset>\n"
            "environment_RUSTDOCFLAGS=<unset>\n"
            "environment_CARGO_ENCODED_RUSTFLAGS=<unset>\n"
            "environment_CARGO_INCREMENTAL=<unset>\n"
            "environment_CARGO_TARGET_DIR=<unset>\n"
        ),
        "scenario/config.toml": config(),
        "scenario/gen-a.rpol": generation_a,
        "scenario/gen-b.rpol": generation_b,
        "scenario/member.initial.rpol": generation_a,
        "scenario/member.final.rpol": generation_a,
        "source-status.txt": "",
        "sources/canonical-refs.txt": (
            f"remote={validator.CANONICAL_REMOTE}\n"
            f"baseline_commit={BASELINE_COMMIT}\n"
            f"baseline_context_ref={validator.CANONICAL_BASELINE_CONTEXT_REF}\n"
            f"source_commit={COMMIT}\n"
            f"source_tree={TREE}\n"
            f"candidate_context_ref={validator.CANONICAL_CANDIDATE_CONTEXT_REF}\n"
            "proof=exact-sha-live-fetch-and-retained-bundle\n"
        ),
        "sources/canonical-fetch.txt": (
            "command=env -i LC_ALL=C TZ=UTC HOME=/nonexistent PATH=/usr/bin:/bin "
            "GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null "
            "GIT_TERMINAL_PROMPT=0 /usr/bin/git -C <CANONICAL_REPO> fetch "
            f"--no-tags --force {validator.CANONICAL_REMOTE} "
            f"+{BASELINE_COMMIT}:{validator.RETAINED_BASELINE_REF} "
            f"+{COMMIT}:{validator.RETAINED_SOURCE_REF}\n"
            "fetch=success\n"
            "fsck=success\n"
            f"baseline_commit={BASELINE_COMMIT}\n"
            f"source_commit={COMMIT}\n"
            f"source_tree={TREE}\n"
        ),
        "sources/build_fence.py": ARCHIVE_FILES[
            "bench/scale/reloadstall/build_fence.py"
        ].decode(),
        "sources/gen-scenario.py": ARCHIVE_FILES[
            "bench/scale/reloadstall/gen-scenario.py"
        ].decode(),
        "sources/process_fence.py": ARCHIVE_FILES[
            "bench/scale/reloadstall/process_fence.py"
        ].decode(),
        "sources/reloadstall-main.rs": ARCHIVE_FILES[
            "bench/scale/reloadstall/src/main.rs"
        ].decode(),
        "sources/run-receipt.sh": ARCHIVE_FILES[
            "bench/scale/reloadstall/run-receipt.sh"
        ].decode(),
        "sources/validate_receipt.py": ARCHIVE_FILES[
            "bench/scale/reloadstall/validate_receipt.py"
        ].decode(),
    }
    for relative, text in files.items():
        write(root / relative, text)
    (root / "sources/source.tar").write_bytes(archive_bytes)
    (root / "sources/source.bundle").write_bytes(BUNDLE_BYTES)
    (root / "sources/source.commit").write_bytes(COMMIT_PAYLOAD)
    invocation = {
        "source_commit": COMMIT,
        "build_cwd": SOURCE,
        "build_environment": {
            "CARGO_TARGET_DIR": TARGET,
            "LC_ALL": "C",
            "TZ": "UTC",
            "HOME": "<BUILD_HOME>",
            "CARGO_HOME": "<CARGO_HOME>",
            "RUSTUP_HOME": "<RUSTUP_HOME>",
            "PATH": "/usr/bin:/bin",
            "RUSTUP_TOOLCHAIN": validator.REQUIRED_TOOLCHAIN,
            "RUSTC": "<RUSTC_COMMAND>",
            "RUSTDOC": "<RUSTDOC_COMMAND>",
            "allowed_cargo_config": f"{SOURCE}/.cargo/config.toml",
            "external_cargo_configs": "rejected",
        },
        "process_fence_environment": {"PYTHONDONTWRITEBYTECODE": "1"},
        "runtime_environments": {
            "daemon": {"LC_ALL": "C", "TZ": "UTC", "RUST_LOG": "info"},
            "harness": {"LC_ALL": "C", "TZ": "UTC"},
            "health": {"LC_ALL": "C", "TZ": "UTC"},
        },
        "health_probe": {"timeout_seconds": 10, "interval_milliseconds": 50},
        "commands": {
            "canonical_fetch": [
                "/usr/bin/git",
                "-C",
                "<CANONICAL_REPO>",
                "fetch",
                "--no-tags",
                "--force",
                validator.CANONICAL_REMOTE,
                f"+{BASELINE_COMMIT}:{validator.RETAINED_BASELINE_REF}",
                f"+{COMMIT}:{validator.RETAINED_SOURCE_REF}",
            ],
            "archive": [
                "/usr/bin/git",
                "-C",
                "<CANONICAL_REPO>",
                "archive",
                "--format=tar",
                f"--output={OUTPUT}/sources/source.tar",
                validator.RETAINED_SOURCE_REF,
            ],
            "commit_object": [
                "/usr/bin/git",
                "-C",
                "<CANONICAL_REPO>",
                "cat-file",
                "commit",
                validator.RETAINED_SOURCE_REF,
            ],
            "bundle": [
                "/usr/bin/git",
                "-C",
                "<CANONICAL_REPO>",
                "bundle",
                "create",
                f"{OUTPUT}/sources/source.bundle",
                validator.RETAINED_BASELINE_REF,
                validator.RETAINED_SOURCE_REF,
            ],
            "extract": [
                "tar",
                "--extract",
                f"--file={OUTPUT}/sources/source.tar",
                f"--directory={SOURCE}",
                "--no-same-owner",
                "--no-same-permissions",
            ],
            "build_daemon_cli": [
                "timeout",
                "--foreground",
                "--signal=TERM",
                "--kill-after=30s",
                "1800",
                "<CARGO_COMMAND>",
                "build",
                "--release",
                "--locked",
                "--package",
                "rustbgpd",
                "--bin",
                "rustbgpd",
                "--package",
                "rustbgpctl",
                "--bin",
                "rbgp",
            ],
            "build_harness": [
                "timeout",
                "--foreground",
                "--signal=TERM",
                "--kill-after=30s",
                "1800",
                "<CARGO_COMMAND>",
                "build",
                "--release",
                "--locked",
                "--manifest-path",
                "bench/scale/reloadstall/Cargo.toml",
            ],
            "build_fence": [
                "python3",
                f"{SOURCE}/bench/scale/reloadstall/build_fence.py",
                "--source-root",
                SOURCE,
                "--cargo-home",
                "<CARGO_HOME>",
                "--expected-tree",
                "<SOURCE_TREE>",
                "--require-immutable",
            ],
            "generate": [
                "timeout",
                "--foreground",
                "--signal=TERM",
                "--kill-after=5s",
                "60",
                "python3",
                f"{SOURCE}/bench/scale/reloadstall/gen-scenario.py",
                "700",
                RUNTIME,
                "1790",
            ],
            "process_fence": [
                "python3",
                f"{SOURCE}/bench/scale/reloadstall/process_fence.py",
                "--root",
                REPO,
                "--root",
                SOURCE,
                "--root",
                TARGET,
            ],
            "daemon": [
                "setsid",
                "env",
                "-i",
                "LC_ALL=C",
                "TZ=UTC",
                "RUST_LOG=info",
                f"{TARGET}/release/rustbgpd",
                f"{RUNTIME}/config.toml",
            ],
            "health": [
                "timeout",
                "--foreground",
                "--signal=TERM",
                "--kill-after=1s",
                "10",
                "env",
                "-i",
                "LC_ALL=C",
                "TZ=UTC",
                f"{TARGET}/release/rbgp",
                "--addr",
                f"unix://{RUNTIME}/grpc.sock",
                "health",
            ],
            "harness": [
                "setsid",
                "timeout",
                "--foreground",
                "--signal=TERM",
                "--kill-after=30s",
                "4200",
                "env",
                "-i",
                "LC_ALL=C",
                "TZ=UTC",
                f"{TARGET}/release/reloadstall",
                "700",
                "400400",
                "1790",
                "<DAEMON_PID>",
                f"{RUNTIME}/member.rpol",
                f"{RUNTIME}/gen-a.rpol",
                f"{RUNTIME}/gen-b.rpol",
                "4",
                "30",
            ],
            "validate": [
                "python3",
                f"{SOURCE}/bench/scale/reloadstall/validate_receipt.py",
                OUTPUT,
            ],
        },
    }
    write(
        root / "invocation.json",
        json.dumps(invocation, indent=2, sort_keys=True) + "\n",
    )
    manifest = {
        "schema": validator.SCHEMA,
        "status": "complete",
        "source": {
            "commit": COMMIT,
            "head": COMMIT,
            "tree": TREE,
            "archive_sha256": archive_sha256,
            "bundle_sha256": bundle_sha256,
            "remote": "https://github.com/lance0/rustbgpd.git",
            "canonical": {
                "baseline_commit": BASELINE_COMMIT,
                "baseline_context_ref": validator.CANONICAL_BASELINE_CONTEXT_REF,
                "candidate_context_ref": validator.CANONICAL_CANDIDATE_CONTEXT_REF,
                "source_commit": COMMIT,
                "proof": "exact-sha-live-fetch-and-retained-bundle",
            },
            "clean": True,
        },
        "runtime_dir": RUNTIME,
        "output_dir": OUTPUT,
        "timeouts_seconds": {
            "build_each": 1800,
            "scenario_generation": 60,
            "harness_outer": 4200,
            "stub_connect_open": 15,
            "overall_establishment": 120,
            "initial_convergence": 120,
            "per_reload": 900,
            "quiesce": 20,
        },
        "scenario": {
            "peers": 700,
            "prefixes": 400400,
            "per_peer": 572,
            "expected_unique_prefixes_per_observer": 399828,
            "reloads": 4,
            "control_seconds": 30,
            "listen_port": 1790,
            "completion_contract": validator.CONTRACT,
            "generation_communities": list(validator.COMMUNITIES),
        },
        "environment": {
            "host_lock": "<HOST_LOCK>",
            "load_one": 0.5,
            "required_governor": "performance",
            "process_gate": "clear",
            "preflight_started_wall_ns": 1,
            "preflight_completed_wall_ns": 5,
            "process_wall_ns": 3,
            "load_wall_ns": 4,
            "governor_policy_count": 1,
            "daemon_start_wall_ns": 6,
        },
        "result": {
            "harness_exit": 0,
            "daemon_alive_after_harness": True,
            "daemon_exit": 0,
            "health_samples": 1,
            "health_failures": 0,
            "parse_errors": 0,
            "base_withdrawals": 0,
            "marker_conflicts": 0,
            "route_identity_defects": 0,
        },
    }
    write(root / "manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    resign(root)


class ReceiptValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name) / "receipt"
        self.root.mkdir()
        make_receipt(self.root)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def assert_invalid(self, fragment: str) -> None:
        with self.assertRaisesRegex(validator.ReceiptError, fragment):
            validator.validate_receipt(
                self.root,
                canonical_remote=str(CANONICAL_FETCH_REPOSITORY),
                expected_baseline_commit=BASELINE_COMMIT,
            )

    def mutate_text(self, relative: str, old: str, new: str) -> None:
        path = self.root / relative
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text)
        write(path, text.replace(old, new, 1))
        resign(self.root)

    def mutate_json(self, relative: str, callback) -> None:
        path = self.root / relative
        value = json.loads(path.read_text(encoding="utf-8"))
        callback(value)
        write(path, json.dumps(value, indent=2, sort_keys=True) + "\n")
        resign(self.root)

    def test_valid_receipt_is_accepted(self) -> None:
        result = validator.validate_receipt(
            self.root,
            canonical_remote=str(CANONICAL_FETCH_REPOSITORY),
            expected_baseline_commit=BASELINE_COMMIT,
        )
        self.assertTrue(result["accepted"])
        self.assertEqual(result["shape"], "700x400400")

    def test_checksum_tamper_fails(self) -> None:
        with (self.root / "harness.log").open("a", encoding="utf-8") as handle:
            handle.write("tamper\n")
        self.assert_invalid("checksum mismatch")

    def test_duplicate_checksum_entry_fails(self) -> None:
        sums = self.root / "SHA256SUMS"
        first = sums.read_text(encoding="utf-8").splitlines()[0]
        with sums.open("a", encoding="utf-8") as handle:
            handle.write(first + "\n")
        self.assert_invalid("duplicate checksum")

    def test_symlinked_artifact_fails(self) -> None:
        path = self.root / "sources/run-receipt.sh"
        path.unlink()
        path.symlink_to("/etc/hosts")
        self.assert_invalid("symlinks are forbidden")

    def test_symlinked_receipt_root_fails(self) -> None:
        linked_root = Path(self.tempdir.name) / "receipt-link"
        linked_root.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(
            validator.ReceiptError, "root must not be a symlink"
        ):
            validator.validate_receipt(
                linked_root,
                canonical_remote=str(CANONICAL_FETCH_REPOSITORY),
                expected_baseline_commit=BASELINE_COMMIT,
            )

    def test_forged_validation_json_is_rejected(self) -> None:
        write(self.root / "validation.json", '{"accepted": false, "error": "forged"}\n')
        resign(self.root)
        self.assert_invalid("unexpected unvalidated artifacts")

    def test_source_archive_tamper_fails_even_when_resigned(self) -> None:
        archive = self.root / "sources/source.tar"
        archive.write_bytes(archive.read_bytes() + b"tamper")
        resign(self.root)
        self.assert_invalid("source archive SHA-256")

    def test_source_bundle_tamper_fails_even_when_resigned(self) -> None:
        bundle = self.root / "sources/source.bundle"
        bundle.write_bytes(bundle.read_bytes() + b"tamper")
        resign(self.root)
        self.assert_invalid("source bundle SHA-256")

    def test_retained_source_copy_must_match_archive(self) -> None:
        write(self.root / "sources/process_fence.py", "# replacement\n")
        resign(self.root)
        self.assert_invalid("retained source copy does not match archive")

    def test_source_archive_tree_must_match_manifest(self) -> None:
        self.mutate_json(
            "manifest.json", lambda value: value["source"].update(tree="b" * 40)
        )
        self.mutate_text(
            "sources/canonical-refs.txt",
            f"source_tree={TREE}",
            f"source_tree={'b' * 40}",
        )
        self.mutate_text(
            "sources/canonical-fetch.txt",
            f"source_tree={TREE}",
            f"source_tree={'b' * 40}",
        )
        self.assert_invalid("source bundle tree")

    def test_retained_commit_object_tamper_fails_even_when_resigned(self) -> None:
        path = self.root / "sources/source.commit"
        path.write_bytes(
            path.read_bytes().replace(b"fixture candidate", b"forged candidate")
        )
        resign(self.root)
        self.assert_invalid("source bundle commit object")

    def test_self_consistent_synthetic_commit_absent_from_bundle_is_rejected(
        self,
    ) -> None:
        synthetic_payload = COMMIT_PAYLOAD.replace(
            b"fixture candidate", b"synthetic candidate"
        )
        claimed = validator.git_object_id("commit", synthetic_payload).hex()
        (self.root / "sources/source.commit").write_bytes(synthetic_payload)
        self.mutate_json(
            "manifest.json",
            lambda value: (
                value["source"].update(commit=claimed, head=claimed),
                value["source"]["canonical"].update(source_commit=claimed),
            ),
        )
        self.mutate_text(
            "sources/canonical-refs.txt",
            f"source_commit={COMMIT}",
            f"source_commit={claimed}",
        )
        self.assert_invalid("source bundle retained refs")

    def test_nonexistent_manifest_commit_is_rejected_by_bundle_head(self) -> None:
        claimed = "a" * 40
        self.mutate_json(
            "manifest.json",
            lambda value: (
                value["source"].update(commit=claimed, head=claimed),
                value["source"]["canonical"].update(source_commit=claimed),
            ),
        )
        self.assert_invalid("source bundle retained refs")

    def test_unapproved_baseline_commit_is_rejected(self) -> None:
        self.mutate_json(
            "manifest.json",
            lambda value: value["source"]["canonical"].update(baseline_commit="a" * 40),
        )
        self.assert_invalid("manifest.source.canonical.baseline_commit")

    def test_self_consistent_synthetic_graph_absent_from_canonical_is_rejected(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="reloadstall-synthetic-") as temporary:
            (
                synthetic_baseline,
                synthetic_commit,
                synthetic_tree,
                synthetic_payload,
                synthetic_archive,
                synthetic_bundle,
                _,
            ) = source_evidence(temporary, candidate_message="synthetic candidate")
            self.assertEqual(synthetic_baseline, BASELINE_COMMIT)
            self.assertEqual(synthetic_tree, TREE)
            self.assertNotEqual(synthetic_commit, COMMIT)

            archive_digest = hashlib.sha256(synthetic_archive).hexdigest()
            bundle_digest = hashlib.sha256(synthetic_bundle).hexdigest()
            (self.root / "sources/source.commit").write_bytes(synthetic_payload)
            (self.root / "sources/source.tar").write_bytes(synthetic_archive)
            (self.root / "sources/source.bundle").write_bytes(synthetic_bundle)
            self.mutate_text(
                "sources/canonical-refs.txt",
                f"source_commit={COMMIT}",
                f"source_commit={synthetic_commit}",
            )
            canonical_fetch = self.root / "sources/canonical-fetch.txt"
            write(
                canonical_fetch,
                canonical_fetch.read_text(encoding="utf-8").replace(
                    COMMIT, synthetic_commit
                ),
            )
            provenance = self.root / "provenance.txt"
            provenance_text = provenance.read_text(encoding="utf-8")
            provenance_text = provenance_text.replace(COMMIT, synthetic_commit)
            provenance_text = provenance_text.replace(
                hashlib.sha256(ARCHIVE_BYTES).hexdigest(), archive_digest
            )
            provenance_text = provenance_text.replace(
                hashlib.sha256(BUNDLE_BYTES).hexdigest(), bundle_digest
            )
            write(provenance, provenance_text)

            def update_invocation(value) -> None:
                value["source_commit"] = synthetic_commit
                value["commands"]["canonical_fetch"][
                    -1
                ] = f"+{synthetic_commit}:{validator.RETAINED_SOURCE_REF}"

            self.mutate_json("invocation.json", update_invocation)

            def update_manifest(value) -> None:
                source = value["source"]
                source.update(
                    commit=synthetic_commit,
                    head=synthetic_commit,
                    archive_sha256=archive_digest,
                    bundle_sha256=bundle_digest,
                )
                source["canonical"]["source_commit"] = synthetic_commit

            self.mutate_json("manifest.json", update_manifest)
            self.assert_invalid("live canonical ref fetch")

    def test_live_canonical_fetch_failure_is_rejected(self) -> None:
        with self.assertRaisesRegex(validator.ReceiptError, "live canonical ref fetch"):
            validator.validate_receipt(
                self.root,
                canonical_remote=str(self.root / "missing-canonical.git"),
                expected_baseline_commit=BASELINE_COMMIT,
            )

    def test_short_source_revision_fails_even_when_resigned(self) -> None:
        self.mutate_json(
            "manifest.json", lambda value: value["source"].update(commit="abc")
        )
        self.assert_invalid("full lowercase commit SHA")

    def test_dirty_source_fails(self) -> None:
        write(self.root / "source-status.txt", " M src/main.rs\n")
        resign(self.root)
        self.assert_invalid("source-status.txt must be empty")

    def test_wrong_shape_header_fails(self) -> None:
        self.mutate_text("harness.log", "peers=700", "peers=699")
        self.assert_invalid("shape header")

    def test_missing_current_generation_proof_fails(self) -> None:
        self.mutate_text(
            "harness.log", "current_generation_complete", "generation_complete"
        )
        self.assert_invalid("reload 1 current generation completion")

    def test_missing_post_quiesce_current_state_proof_fails(self) -> None:
        self.mutate_text(
            "harness.log", "current_generation_verified", "generation_verified"
        )
        self.assert_invalid("reload 1 post-quiesce current generation")

    def test_stale_generation_marker_fails(self) -> None:
        self.mutate_text("harness.log", "community=65500:2000", "community=65500:1000")
        self.assert_invalid("reload 1 current generation completion")

    def test_partial_observer_stats_fail(self) -> None:
        self.mutate_text(
            "harness.log",
            "reload 2 completion_s: p50=154.00 p95=290.00 max=309.00 (n=700)",
            "reload 2 completion_s: p50=154.00 p95=290.00 max=309.00 (n=699)",
        )
        self.assert_invalid("completion observer count")

    def test_one_second_stall_boundary_fails(self) -> None:
        self.mutate_text(
            "harness.log",
            "reload 3 maxgap_ms: p50=744.00 p95=760.00 max=820.00",
            "reload 3 maxgap_ms: p50=744.00 p95=760.00 max=1000.00",
        )
        self.assert_invalid("violates the precommitted")

    def test_nonzero_defect_counter_fails(self) -> None:
        self.mutate_text("harness.log", "base_withdrawals=0", "base_withdrawals=1")
        self.assert_invalid("zero-defect counters")

    def test_timeout_marker_fails_despite_success_manifest(self) -> None:
        with (self.root / "harness.log").open("a", encoding="utf-8") as handle:
            handle.write("reload 4 TIMEOUT waiting for re-advertisement\n")
        resign(self.root)
        self.assert_invalid("failure marker")

    def test_missing_daemon_establishment_fails(self) -> None:
        rows = (self.root / "daemon.log").read_text(encoding="utf-8").splitlines()
        write(self.root / "daemon.log", "\n".join(rows[1:]) + "\n")
        resign(self.root)
        self.assert_invalid("exactly 700 one-time peer establishments")

    def test_duplicate_daemon_establishment_fails(self) -> None:
        rows = (self.root / "daemon.log").read_text(encoding="utf-8").splitlines()
        rows[1] = rows[0]
        write(self.root / "daemon.log", "\n".join(rows) + "\n")
        resign(self.root)
        self.assert_invalid("exactly 700 one-time peer establishments")

    def test_notification_in_run_window_fails(self) -> None:
        with (self.root / "daemon.log").open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps({"fields": {"message": "BGP NOTIFICATION sent"}}) + "\n"
            )
        resign(self.root)
        self.assert_invalid("forbidden run-window event")

    def test_missing_daemon_reload_completion_fails(self) -> None:
        rows = (self.root / "daemon.log").read_text(encoding="utf-8").splitlines()
        rows.pop()
        write(self.root / "daemon.log", "\n".join(rows) + "\n")
        resign(self.root)
        self.assert_invalid("exactly 4 completed reloads")

    def test_health_failure_fails(self) -> None:
        self.mutate_text("health.tsv", "1\t100\t0", "1\t100\t1")
        self.assert_invalid("health probe failed")

    def test_nonempty_health_stderr_fails(self) -> None:
        write(self.root / "health-errors.log", "connection reset\n")
        resign(self.root)
        self.assert_invalid("health-errors.log must be empty")

    def test_config_missing_peer_fails(self) -> None:
        path = self.root / "scenario/config.toml"
        text = path.read_text(encoding="utf-8")
        marker = "[[neighbors]]"
        last = text.rfind(marker)
        self.assertGreater(last, 0)
        write(path, text[:last])
        resign(self.root)
        self.assert_invalid("exactly 700 neighbors")

    def test_config_extra_top_level_mapping_fails(self) -> None:
        path = self.root / "scenario/config.toml"
        write(path, path.read_text(encoding="utf-8") + "\n[extra]\nvalue = 1\n")
        resign(self.root)
        self.assert_invalid("config keys")

    def test_config_extra_global_mapping_fails(self) -> None:
        self.mutate_text(
            "scenario/config.toml", "asn = 65500", "asn = 65500\nworkers = 4"
        )
        self.assert_invalid("config.global keys")

    def test_config_extra_neighbor_mapping_fails(self) -> None:
        self.mutate_text(
            "scenario/config.toml", "hold_time = 180", "hold_time = 180\npassive = true"
        )
        self.assert_invalid("neighbor 0 keys")

    def test_config_policy_mapping_mismatch_fails(self) -> None:
        self.mutate_text(
            "scenario/config.toml",
            'export_chain = ["member-out"]',
            'export_chain = ["member-out", "extra"]',
        )
        self.assert_invalid("config.policy")

    def test_config_grpc_mapping_extra_fails(self) -> None:
        self.mutate_text(
            "scenario/config.toml",
            f'path = "{RUNTIME}/grpc.sock"',
            f'path = "{RUNTIME}/grpc.sock"\nmode = 438',
        )
        self.assert_invalid("grpc_uds keys")

    def test_policy_extra_term_fails(self) -> None:
        self.mutate_text(
            "scenario/gen-a.rpol",
            "    term default { accept }",
            "    term unexpected { accept }\n    term default { accept }",
        )
        self.assert_invalid("generation A")

    def test_identical_policy_generations_fail(self) -> None:
        write(
            self.root / "scenario/gen-b.rpol",
            (self.root / "scenario/gen-a.rpol").read_text(encoding="utf-8"),
        )
        resign(self.root)
        self.assert_invalid("generation B")

    def test_invocation_shape_mismatch_fails(self) -> None:
        def mutate(value) -> None:
            value["commands"]["harness"][11] = "699"

        self.mutate_json("invocation.json", mutate)
        self.assert_invalid("commands.harness")

    def test_unlocked_build_invocation_fails(self) -> None:
        def mutate(value) -> None:
            value["commands"]["build_harness"].remove("--locked")

        self.mutate_json("invocation.json", mutate)
        self.assert_invalid("build_harness")

    def test_build_timeout_mismatch_fails(self) -> None:
        def mutate(value) -> None:
            value["commands"]["build_harness"][4] = "1799"

        self.mutate_json("invocation.json", mutate)
        self.assert_invalid("build_harness")

    def test_build_toolchain_override_fails(self) -> None:
        self.mutate_json(
            "invocation.json",
            lambda value: value["build_environment"].update(RUSTUP_TOOLCHAIN="stable"),
        )
        self.assert_invalid("invocation.build_environment")

    def test_build_rustc_shadow_fails(self) -> None:
        self.mutate_json(
            "invocation.json",
            lambda value: value["build_environment"].update(RUSTC="/usr/bin/rustc"),
        )
        self.assert_invalid("invocation.build_environment")

    def test_resolved_rustup_shadow_fails(self) -> None:
        self.mutate_text(
            "provenance.txt",
            "rustup_command=<HOME>/.cargo/bin/rustup",
            "rustup_command=/tmp/shadow/rustup",
        )
        self.assert_invalid("provenance.txt rustup_command")

    def test_build_path_shadow_fails(self) -> None:
        self.mutate_json(
            "invocation.json",
            lambda value: value["build_environment"].update(
                PATH="/tmp/shadow:/usr/bin:/bin"
            ),
        )
        self.assert_invalid("invocation.build_environment")

    def test_commit_object_capture_invocation_mismatch_fails(self) -> None:
        self.mutate_json(
            "invocation.json",
            lambda value: value["commands"]["commit_object"].pop(),
        )
        self.assert_invalid("commands.commit_object")

    def test_harness_outer_timeout_mismatch_fails(self) -> None:
        def mutate(value) -> None:
            value["commands"]["harness"][5] = "4199"

        self.mutate_json("invocation.json", mutate)
        self.assert_invalid("commands.harness")

    def test_runtime_environment_extra_fails(self) -> None:
        def mutate(value) -> None:
            value["runtime_environments"]["daemon"]["LD_PRELOAD"] = "/tmp/x.so"

        self.mutate_json("invocation.json", mutate)
        self.assert_invalid("runtime_environments")

    def test_high_load_fails(self) -> None:
        self.mutate_text("load-before.tsv", "4\t0.5", "4\t2.0")
        self.assert_invalid("does not prove load_one")

    def test_non_performance_governor_fails(self) -> None:
        self.mutate_text("governors.tsv", "performance", "powersave")
        self.assert_invalid("non-performance")

    def test_stale_governor_snapshot_fails(self) -> None:
        self.mutate_text(
            "governors.tsv",
            "2\t/sys/devices/system/cpu/cpufreq/policy0\tperformance",
            "6\t/sys/devices/system/cpu/cpufreq/policy0\tperformance",
        )
        self.assert_invalid("governor row")

    def test_nonempty_process_snapshot_fails(self) -> None:
        self.mutate_text(
            "processes.tsv",
            "3\t<none>\t<none>\t<none>",
            "3\tcargo\t1234\tcargo build",
        )
        self.assert_invalid("unsanitized daemon PID|empty-set sentinel")

    def test_build_log_private_home_path_fails(self) -> None:
        self.mutate_text("build.log", "build ok", "/home/alice/rustbgpd build ok")
        self.assert_invalid("private home path")

    def test_build_log_absolute_checkout_path_fails(self) -> None:
        self.mutate_text(
            "build.log", "build ok", "/srv/private/rustbgpd/target build ok"
        )
        self.assert_invalid("absolute checkout path")

    def test_provenance_numeric_pid_fails(self) -> None:
        self.mutate_text(
            "provenance.txt",
            "runtime_dir=<RUNTIME_DIR>",
            "runtime_dir=<RUNTIME_DIR>\npid=1234",
        )
        self.assert_invalid("unsanitized daemon PID")

    def test_provenance_whitespace_daemon_pid_fails(self) -> None:
        self.mutate_text(
            "provenance.txt",
            "runtime_dir=<RUNTIME_DIR>",
            "runtime_dir=<RUNTIME_DIR>\ndaemon pid 1234",
        )
        self.assert_invalid("unsanitized daemon PID")

    def test_manifest_timeout_mismatch_fails(self) -> None:
        self.mutate_json(
            "manifest.json",
            lambda value: value["timeouts_seconds"].update(harness_outer=4199),
        )
        self.assert_invalid("timeouts_seconds")

    def test_malformed_binary_hash_fails(self) -> None:
        self.mutate_text(
            "provenance.txt",
            "rustbgpd_sha256=" + "1" * 64,
            "rustbgpd_sha256=not-a-hash",
        )
        self.assert_invalid("one exact rustbgpd_sha256")

    def test_daemon_start_too_late_fails(self) -> None:
        self.mutate_json(
            "manifest.json",
            lambda value: value["environment"].update(
                daemon_start_wall_ns=1_000_000_006
            ),
        )
        self.assert_invalid("start within 1 second")

    def test_governor_policy_count_mismatch_fails(self) -> None:
        self.mutate_json(
            "manifest.json",
            lambda value: value["environment"].update(governor_policy_count=2),
        )
        self.assert_invalid("governor policy count")

    def test_config_raw_runtime_path_fails(self) -> None:
        self.mutate_text("scenario/config.toml", RUNTIME, "/tmp/rls.private")
        self.assert_invalid("raw temporary path")

    def test_unvalidated_archive_surface_fails(self) -> None:
        (self.root / "raw-logs.tar.gz").write_bytes(b"private archive")
        resign(self.root)
        self.assert_invalid("unexpected unvalidated artifacts")


if __name__ == "__main__":
    unittest.main()
