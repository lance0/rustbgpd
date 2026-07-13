#!/usr/bin/env python3
"""Adversarial unit tests for the retained reload-stall receipt validator."""

from __future__ import annotations

import hashlib
import io
import json
import tempfile
import tarfile
import unittest
from pathlib import Path

import validate_receipt as validator


COMMIT = "a" * 40
RUNTIME = validator.RUNTIME_DIR
OUTPUT = validator.OUTPUT_DIR
REPO = validator.REPO_ROOT
SOURCE = validator.SOURCE_ROOT
TARGET = validator.BUILD_TARGET
ARCHIVE_FILES = {
    "bench/scale/reloadstall/gen-scenario.py": b"# generator fixture\n",
    "bench/scale/reloadstall/process_fence.py": b"# process fence fixture\n",
    "bench/scale/reloadstall/src/main.rs": b"// harness fixture\n",
    "bench/scale/reloadstall/run-receipt.sh": b"# runner fixture\n",
    "bench/scale/reloadstall/validate_receipt.py": b"# validator fixture\n",
}


def archive_tree() -> str:
    tree = {}
    for path, content in ARCHIVE_FILES.items():
        node = tree
        parts = path.split("/")
        for component in parts[:-1]:
            node = node.setdefault(component, {})
        node[parts[-1]] = ("100644", validator.git_object_id("blob", content))
    return validator.git_tree_id(tree).hex()


TREE = archive_tree()


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def source_archive() -> bytes:
    output = io.BytesIO()
    with tarfile.open(
        fileobj=output,
        mode="w",
        format=tarfile.PAX_FORMAT,
        pax_headers={"comment": COMMIT},
    ) as archive:
        for path, content in ARCHIVE_FILES.items():
            info = tarfile.TarInfo(path)
            info.mode = 0o644
            info.mtime = 0
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return output.getvalue()


def policy(reject: str, community: str) -> str:
    return f"""policy member-in {{
    term drop-blocked {{ if route.prefix == {reject} {{ reject }} }}
    term default {{ accept }}
}}
policy member-out {{
    term tag {{ add community {community}; accept }}
}}
"""


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
                f"reload {reload_index} unique_generation_complete "
                f"contract={validator.CONTRACT} community={community} "
                "observers=700/700 unique_prefixes_per_observer=399828 target=399828",
                f"reload {reload_index} completion_s: p50=154.00 p95=290.00 max=309.00 (n=700)",
                f"reload {reload_index} maxgap_ms: p50=744.00 p95=760.00 max=820.00 (n=700)",
                f"reload {reload_index} first_update_ms: p50=1.00 p95=2.00 max=3.00 (n=700)",
                f"reload {reload_index} rss_mib before=815 after=900 comms_sample=[{community_value}]",
                f"reload {reload_index} sessions_up 700/700",
            ]
        )
    rows.append("done rss_mib=1303")
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
            if path.is_file()
            and not path.is_symlink()
            and path.name != "SHA256SUMS"
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
            f"source_archive_sha256={archive_sha256}\n"
            "source_remote=https://github.com/lance0/rustbgpd.git\n"
            "build_source_root=<SOURCE_ROOT>\nbuild_target_dir=<BUILD_TARGET>\n"
            "host_lock=<HOST_LOCK>\nruntime_dir=<RUNTIME_DIR>\n"
            "output_dir=<OUTPUT_DIR>\n"
            "rustc 1.95.0\ncargo 1.95.0\n"
            f"root_Cargo.lock_sha256={'4' * 64}\n"
            f"reloadstall_Cargo.lock_sha256={'5' * 64}\n"
            f"rustbgpd_sha256={'1' * 64}\nrbgp_sha256={'2' * 64}\n"
            f"reloadstall_sha256={'3' * 64}\n"
            "environment_RUSTFLAGS=<unset>\n"
            "environment_CARGO_ENCODED_RUSTFLAGS=<unset>\n"
            "environment_CARGO_TARGET_DIR=<unset>\n"
        ),
        "scenario/config.toml": config(),
        "scenario/gen-a.rpol": generation_a,
        "scenario/gen-b.rpol": generation_b,
        "scenario/member.initial.rpol": generation_a,
        "scenario/member.final.rpol": generation_a,
        "source-status.txt": "",
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
    invocation = {
        "source_commit": COMMIT,
        "build_cwd": SOURCE,
        "build_environment": {"CARGO_TARGET_DIR": TARGET},
        "process_fence_environment": {"PYTHONDONTWRITEBYTECODE": "1"},
        "daemon_environment": {"RUST_LOG": "info"},
        "health_probe": {"timeout_seconds": 10, "interval_milliseconds": 50},
        "commands": {
            "archive": [
                "git",
                "archive",
                "--format=tar",
                f"--output={OUTPUT}/sources/source.tar",
                COMMIT,
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
                "cargo",
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
                "cargo",
                "build",
                "--release",
                "--locked",
                "--manifest-path",
                "bench/scale/reloadstall/Cargo.toml",
            ],
            "generate": [
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
            "daemon": [f"{TARGET}/release/rustbgpd", f"{RUNTIME}/config.toml"],
            "health": [
                f"{TARGET}/release/rbgp",
                "--addr",
                f"unix://{RUNTIME}/grpc.sock",
                "health",
            ],
            "harness": [
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
            "remote": "https://github.com/lance0/rustbgpd.git",
            "clean": True,
        },
        "runtime_dir": RUNTIME,
        "output_dir": OUTPUT,
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
            validator.validate_receipt(self.root)

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
        result = validator.validate_receipt(self.root)
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
        with self.assertRaisesRegex(validator.ReceiptError, "root must not be a symlink"):
            validator.validate_receipt(linked_root)

    def test_forged_validation_json_is_rejected(self) -> None:
        write(self.root / "validation.json", '{"accepted": false, "error": "forged"}\n')
        resign(self.root)
        self.assert_invalid("unexpected unvalidated artifacts")

    def test_source_archive_tamper_fails_even_when_resigned(self) -> None:
        archive = self.root / "sources/source.tar"
        archive.write_bytes(archive.read_bytes() + b"tamper")
        resign(self.root)
        self.assert_invalid("source archive SHA-256")

    def test_retained_source_copy_must_match_archive(self) -> None:
        write(self.root / "sources/process_fence.py", "# replacement\n")
        resign(self.root)
        self.assert_invalid("retained source copy does not match archive")

    def test_source_archive_tree_must_match_manifest(self) -> None:
        self.mutate_json(
            "manifest.json", lambda value: value["source"].update(tree="b" * 40)
        )
        self.assert_invalid("source archive Git tree")

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

    def test_missing_unique_generation_proof_fails(self) -> None:
        self.mutate_text(
            "harness.log", "unique_generation_complete", "generation_complete"
        )
        self.assert_invalid("reload 1 unique generation")

    def test_stale_generation_marker_fails(self) -> None:
        self.mutate_text("harness.log", "community=65500:2000", "community=65500:1000")
        self.assert_invalid("reload 1 unique generation")

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

    def test_identical_policy_generations_fail(self) -> None:
        write(
            self.root / "scenario/gen-b.rpol",
            (self.root / "scenario/gen-a.rpol").read_text(encoding="utf-8"),
        )
        resign(self.root)
        self.assert_invalid("generation B does not carry")

    def test_invocation_shape_mismatch_fails(self) -> None:
        def mutate(value) -> None:
            value["commands"]["harness"][1] = "699"

        self.mutate_json("invocation.json", mutate)
        self.assert_invalid("does not pin the 700x400,400 shape")

    def test_unlocked_build_invocation_fails(self) -> None:
        def mutate(value) -> None:
            value["commands"]["build_harness"].remove("--locked")

        self.mutate_json("invocation.json", mutate)
        self.assert_invalid("build_harness")

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
