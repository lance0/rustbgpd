#!/usr/bin/env python3
"""Fail-closed validator for a LAN-350 reload-stall receipt bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
import tarfile
import tomllib
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any


SCHEMA = "rustbgpd-reloadstall-receipt-v1"
PEERS = 700
PREFIXES = 400_400
PER_PEER = 572
EXPECTED = PREFIXES - PER_PEER
RELOADS = 4
CONTROL_SECS = 30
PORT = 1790
CONTRACT = "unique-prefix-generation-community-v1"
COMMUNITIES = ("65500:2000", "65500:1000", "65500:2000", "65500:1000")
RUNTIME_DIR = "<RUNTIME_DIR>"
OUTPUT_DIR = "<OUTPUT_DIR>"
REPO_ROOT = "<REPO_ROOT>"
SOURCE_ROOT = "<SOURCE_ROOT>"
BUILD_TARGET = "<BUILD_TARGET>"
HOST_LOCK = "<HOST_LOCK>"
DAEMON_PID = "<DAEMON_PID>"
COMMUNITY_VALUES = tuple(
    (int(community.split(":")[0]) << 16) | int(community.split(":")[1])
    for community in COMMUNITIES
)

REQUIRED_FILES = {
    "build.log",
    "daemon.log",
    "governors.tsv",
    "harness.log",
    "health-errors.log",
    "health.tsv",
    "invocation.json",
    "load-before.tsv",
    "manifest.json",
    "processes.tsv",
    "provenance.txt",
    "scenario/config.toml",
    "scenario/gen-a.rpol",
    "scenario/gen-b.rpol",
    "scenario/member.final.rpol",
    "scenario/member.initial.rpol",
    "source-status.txt",
    "sources/gen-scenario.py",
    "sources/process_fence.py",
    "sources/reloadstall-main.rs",
    "sources/run-receipt.sh",
    "sources/source.tar",
    "sources/validate_receipt.py",
}
UNSUMMED_FILES = {"SHA256SUMS"}
SOURCE_FILES = {
    "sources/gen-scenario.py",
    "sources/process_fence.py",
    "sources/reloadstall-main.rs",
    "sources/run-receipt.sh",
    "sources/source.tar",
    "sources/validate_receipt.py",
}
PUBLIC_DYNAMIC_TEXT_FILES = REQUIRED_FILES - SOURCE_FILES
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
STATS_RE = re.compile(
    r"^(?P<label>.+): p50=(?P<p50>[0-9]+(?:\.[0-9]+)?) "
    r"p95=(?P<p95>[0-9]+(?:\.[0-9]+)?) "
    r"max=(?P<max>[0-9]+(?:\.[0-9]+)?) \(n=(?P<n>[0-9]+)\)$"
)


class ReceiptError(ValueError):
    """Receipt does not satisfy the acceptance contract."""


def fail(message: str) -> None:
    raise ReceiptError(message)


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        fail(f"cannot read UTF-8 artifact {path.name}: {exc}")
    raise AssertionError("unreachable")


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(read_text(path))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path.name}: {exc}")
    if not isinstance(value, dict):
        fail(f"{path.name} must contain a JSON object")
    return value


def require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def require_exact(value: Any, expected: Any, label: str) -> None:
    if value != expected:
        fail(f"{label}: expected {expected!r}, got {value!r}")


def validate_file_inventory(root: Path) -> set[str]:
    if not root.is_dir():
        fail(f"receipt path is not a directory: {root}")
    files: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            fail(f"symlinks are forbidden in receipt bundles: {relative}")
        if path.is_file():
            files.add(relative)
        elif not path.is_dir():
            fail(f"non-regular artifact is forbidden: {relative}")
    missing = REQUIRED_FILES - files
    if missing:
        fail(f"required artifacts missing: {', '.join(sorted(missing))}")
    if "SHA256SUMS" not in files:
        fail("SHA256SUMS is missing")
    unexpected = files - REQUIRED_FILES - UNSUMMED_FILES
    if unexpected:
        fail(f"unexpected unvalidated artifacts: {', '.join(sorted(unexpected))}")
    return files


def validate_checksums(root: Path, files: set[str]) -> None:
    rows = read_text(root / "SHA256SUMS").splitlines()
    if not rows:
        fail("SHA256SUMS is empty")
    seen: dict[str, str] = {}
    for line_number, line in enumerate(rows, 1):
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            fail(f"malformed SHA256SUMS line {line_number}")
        digest, relative = match.groups()
        if relative.startswith("/") or ".." in Path(relative).parts:
            fail(f"unsafe checksum path: {relative}")
        if relative in UNSUMMED_FILES:
            fail(f"checksum file must not list {relative}")
        if relative in seen:
            fail(f"duplicate checksum entry: {relative}")
        path = root / relative
        if not path.is_file() or path.is_symlink():
            fail(f"checksum entry is not a regular file: {relative}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != digest:
            fail(f"checksum mismatch for {relative}")
        seen[relative] = digest
    expected = files - UNSUMMED_FILES
    if set(seen) != expected:
        missing = expected - set(seen)
        extra = set(seen) - expected
        fail(
            "checksum inventory mismatch: "
            f"missing={sorted(missing)} extra={sorted(extra)}"
        )
    if list(seen) != sorted(seen):
        fail("SHA256SUMS entries must be sorted by path")


def git_object_id(kind: str, payload: bytes) -> bytes:
    framed = f"{kind} {len(payload)}\0".encode() + payload
    # SHA-1 is the object format of the 40-hex Git repository under test, not a
    # password or signature primitive.
    return hashlib.sha1(framed, usedforsecurity=False).digest()


def git_tree_id(entries: dict[str, Any]) -> bytes:
    rendered: list[tuple[bytes, bytes]] = []
    for name, value in entries.items():
        encoded_name = name.encode("utf-8")
        if isinstance(value, dict):
            mode = b"40000"
            object_id = git_tree_id(value)
            sort_key = encoded_name + b"/"
        else:
            mode_text, object_id = value
            mode = mode_text.encode("ascii")
            sort_key = encoded_name
        rendered.append((sort_key, mode + b" " + encoded_name + b"\0" + object_id))
    payload = b"".join(row for _, row in sorted(rendered, key=lambda row: row[0]))
    return git_object_id("tree", payload)


def validate_source_archive(root: Path, manifest: dict[str, Any]) -> None:
    archive_path = root / "sources/source.tar"
    archive_digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    source = require_mapping(manifest["source"], "manifest.source")
    require_exact(
        archive_digest,
        source["archive_sha256"],
        "source archive SHA-256",
    )

    copies = {
        "bench/scale/reloadstall/gen-scenario.py": "sources/gen-scenario.py",
        "bench/scale/reloadstall/process_fence.py": "sources/process_fence.py",
        "bench/scale/reloadstall/src/main.rs": "sources/reloadstall-main.rs",
        "bench/scale/reloadstall/run-receipt.sh": "sources/run-receipt.sh",
        "bench/scale/reloadstall/validate_receipt.py": "sources/validate_receipt.py",
    }
    tree: dict[str, Any] = {}
    seen: set[str] = set()
    retained_contents: dict[str, bytes] = {}
    try:
        with tarfile.open(archive_path, mode="r:") as archive:
            require_exact(
                archive.pax_headers.get("comment"),
                source["commit"],
                "source archive commit marker",
            )
            for member in archive.getmembers():
                relative = PurePosixPath(member.name)
                if relative.is_absolute() or not relative.parts or ".." in relative.parts:
                    fail(f"unsafe source archive path: {member.name!r}")
                name = relative.as_posix().rstrip("/")
                if member.isdir():
                    continue
                if name in seen:
                    fail(f"duplicate source archive entry: {name}")
                seen.add(name)
                if member.isfile():
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        fail(f"cannot read source archive member: {name}")
                    content = extracted.read()
                    mode = "100755" if member.mode & 0o111 else "100644"
                elif member.issym():
                    content = member.linkname.encode("utf-8")
                    mode = "120000"
                else:
                    fail(f"unsupported source archive member type: {name}")

                node = tree
                for component in relative.parts[:-1]:
                    existing = node.get(component)
                    if existing is None:
                        existing = {}
                        node[component] = existing
                    if not isinstance(existing, dict):
                        fail(f"source archive file/directory collision: {name}")
                    node = existing
                leaf = relative.parts[-1]
                if leaf in node:
                    fail(f"source archive file/directory collision: {name}")
                node[leaf] = (mode, git_object_id("blob", content))
                if name in copies:
                    retained_contents[name] = content
    except (OSError, tarfile.TarError) as exc:
        fail(f"cannot read exact source archive: {exc}")

    require_exact(
        git_tree_id(tree).hex(),
        source["tree"],
        "source archive Git tree",
    )
    missing = set(copies) - set(retained_contents)
    if missing:
        fail(f"source archive is missing retained inputs: {sorted(missing)}")
    for archive_name, receipt_name in copies.items():
        if retained_contents[archive_name] != (root / receipt_name).read_bytes():
            fail(f"retained source copy does not match archive: {receipt_name}")


def validate_publication_safety(root: Path, files: set[str]) -> None:
    """Reject host/user/PID material on every dynamic retained text surface."""
    checkout_path = re.compile(
        r"(?<![<\w])/(?:[^/\s\"'<>]+/)+rustbgpd(?:-[^/\s\"'<>]*)?/"
    )
    forbidden_patterns = (
        (
            re.compile(r"(?:/(?:home|Users)/[^/\s\"'<>]+|/root)(?:/|(?=[\s\"']|$))"),
            "private home path",
        ),
        (
            re.compile(r"/tmp/(?:rls|rustbgpd-reload-receipt)\.[^/\s\"'<>]+"),
            "raw temporary path",
        ),
        (checkout_path, "absolute checkout path"),
        (re.compile(r"(?i)\bpid(?:=|[\"']?\s*:\s*)[0-9]+\b"), "unsanitized daemon PID"),
    )
    resolved_root = str(root)
    public_files = set(PUBLIC_DYNAMIC_TEXT_FILES)
    for relative in sorted(public_files):
        text = read_text(root / relative)
        if resolved_root in text:
            fail(f"{relative} contains the unsanitized receipt output path")
        for pattern, label in forbidden_patterns:
            if pattern.search(text):
                fail(f"{relative} contains {label}")


def validate_manifest(root: Path) -> dict[str, Any]:
    manifest = load_json(root / "manifest.json")
    require_exact(manifest.get("schema"), SCHEMA, "manifest.schema")
    require_exact(manifest.get("status"), "complete", "manifest.status")

    source = require_mapping(manifest.get("source"), "manifest.source")
    commit = source.get("commit")
    tree = source.get("tree")
    archive_sha256 = source.get("archive_sha256")
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        fail("manifest.source.commit must be a full lowercase commit SHA")
    if not isinstance(tree, str) or not COMMIT_RE.fullmatch(tree):
        fail("manifest.source.tree must be a full lowercase tree SHA")
    if not isinstance(archive_sha256, str) or not SHA256_RE.fullmatch(archive_sha256):
        fail("manifest.source.archive_sha256 must be a lowercase SHA-256")
    require_exact(source.get("head"), commit, "manifest.source.head")
    require_exact(source.get("clean"), True, "manifest.source.clean")
    require_exact(
        source.get("remote"),
        "https://github.com/lance0/rustbgpd.git",
        "manifest.source.remote",
    )
    if read_text(root / "source-status.txt") != "":
        fail("source-status.txt must be empty for a retained receipt")

    scenario = require_mapping(manifest.get("scenario"), "manifest.scenario")
    required_scenario = {
        "peers": PEERS,
        "prefixes": PREFIXES,
        "per_peer": PER_PEER,
        "expected_unique_prefixes_per_observer": EXPECTED,
        "reloads": RELOADS,
        "control_seconds": CONTROL_SECS,
        "listen_port": PORT,
        "completion_contract": CONTRACT,
        "generation_communities": list(COMMUNITIES),
    }
    for key, expected in required_scenario.items():
        require_exact(scenario.get(key), expected, f"manifest.scenario.{key}")

    environment = require_mapping(manifest.get("environment"), "manifest.environment")
    load_one = environment.get("load_one")
    if not isinstance(load_one, (int, float)) or isinstance(load_one, bool):
        fail("manifest.environment.load_one must be numeric")
    if not math.isfinite(float(load_one)) or float(load_one) >= 2.0:
        fail("manifest.environment.load_one must be finite and below 2.0")
    require_exact(
        environment.get("required_governor"),
        "performance",
        "manifest.environment.required_governor",
    )
    require_exact(
        environment.get("process_gate"), "clear", "manifest.environment.process_gate"
    )
    require_exact(
        environment.get("host_lock"), HOST_LOCK, "manifest.environment.host_lock"
    )
    for key in (
        "preflight_started_wall_ns",
        "preflight_completed_wall_ns",
        "process_wall_ns",
        "load_wall_ns",
        "governor_policy_count",
        "daemon_start_wall_ns",
    ):
        value = environment.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            fail(f"manifest.environment.{key} must be a positive integer")

    result = require_mapping(manifest.get("result"), "manifest.result")
    require_exact(result.get("harness_exit"), 0, "manifest.result.harness_exit")
    require_exact(
        result.get("daemon_alive_after_harness"),
        True,
        "manifest.result.daemon_alive_after_harness",
    )
    require_exact(result.get("daemon_exit"), 0, "manifest.result.daemon_exit")
    samples = result.get("health_samples")
    if not isinstance(samples, int) or isinstance(samples, bool) or samples < 1:
        fail("manifest.result.health_samples must be a positive integer")
    require_exact(result.get("health_failures"), 0, "manifest.result.health_failures")
    return manifest


def validate_preflight(root: Path, manifest: dict[str, Any]) -> None:
    environment = require_mapping(manifest["environment"], "manifest.environment")
    started = environment["preflight_started_wall_ns"]
    completed = environment["preflight_completed_wall_ns"]
    if completed < started or completed - started > 5_000_000_000:
        fail("measurement-boundary preflight must complete within 5 seconds")
    daemon_start = environment["daemon_start_wall_ns"]
    if not completed <= daemon_start <= completed + 1_000_000_000:
        fail("daemon must start within 1 second of the final preflight")

    governor_rows = read_text(root / "governors.tsv").splitlines()
    if governor_rows[:1] != ["wall_ns\tpolicy\tgovernor"] or len(governor_rows) < 2:
        fail("governors.tsv must contain a header and at least one policy")
    governor_timestamps: list[int] = []
    governor_policies: set[str] = set()
    for row in governor_rows[1:]:
        fields = row.split("\t")
        if (
            len(fields) != 3
            or not fields[0].isdigit()
            or not started <= int(fields[0]) <= completed
            or fields[2] != "performance"
        ):
            fail(f"non-performance or malformed governor row: {row!r}")
        timestamp = int(fields[0])
        policy = fields[1]
        if not re.fullmatch(r"/sys/devices/system/cpu/cpufreq/policy[0-9]+", policy):
            fail(f"malformed governor policy path: {policy!r}")
        if policy in governor_policies:
            fail(f"duplicate governor policy row: {policy!r}")
        governor_timestamps.append(timestamp)
        governor_policies.add(policy)
    require_exact(
        environment["governor_policy_count"],
        len(governor_policies),
        "manifest governor policy count",
    )

    load_rows = read_text(root / "load-before.tsv").splitlines()
    if len(load_rows) != 2 or load_rows[0] != "wall_ns\tload_one":
        fail("load-before.tsv must contain exactly one preflight sample")
    load_fields = load_rows[1].split("\t")
    if len(load_fields) != 2 or not load_fields[0].isdigit():
        fail("malformed load-before.tsv sample")
    try:
        load_one = float(load_fields[1])
    except ValueError as exc:
        fail(f"malformed load-before.tsv load: {exc}")
    if not math.isfinite(load_one) or load_one >= 2.0:
        fail("load-before.tsv does not prove load_one < 2.0")
    load_wall_ns = int(load_fields[0])
    if load_wall_ns != environment["load_wall_ns"]:
        fail("manifest/load-before timestamp mismatch")
    if not started <= load_wall_ns <= completed:
        fail("load sample is outside the measurement-boundary preflight")
    manifest_load = environment["load_one"]
    if float(manifest_load) != load_one:
        fail("manifest/load-before load sample mismatch")

    process_rows = read_text(root / "processes.tsv").splitlines()
    if len(process_rows) != 2 or process_rows[0] != "wall_ns\tprocess\tpid\tcommand":
        fail("processes.tsv must prove an empty competing-process set")
    process_fields = process_rows[1].split("\t")
    if (
        len(process_fields) != 4
        or not process_fields[0].isdigit()
        or process_fields[1:] != ["<none>", "<none>", "<none>"]
    ):
        fail("processes.tsv must contain the explicit empty-set sentinel")
    process_wall_ns = int(process_fields[0])
    if process_wall_ns != environment["process_wall_ns"]:
        fail("manifest/processes timestamp mismatch")
    if not started <= process_wall_ns <= load_wall_ns <= completed:
        fail("process/load samples are not ordered inside the final preflight")
    if max(governor_timestamps) > process_wall_ns:
        fail("governor/process samples are not ordered inside the final preflight")


def validate_invocation(root: Path, manifest: dict[str, Any]) -> None:
    invocation = load_json(root / "invocation.json")
    require_exact(
        invocation.get("source_commit"),
        manifest["source"]["commit"],
        "invocation.source_commit",
    )
    runtime_dir = manifest.get("runtime_dir")
    output_dir = manifest.get("output_dir")
    require_exact(runtime_dir, RUNTIME_DIR, "manifest.runtime_dir")
    require_exact(output_dir, OUTPUT_DIR, "manifest.output_dir")
    require_exact(invocation.get("build_cwd"), SOURCE_ROOT, "invocation.build_cwd")
    require_exact(
        invocation.get("build_environment"),
        {"CARGO_TARGET_DIR": BUILD_TARGET},
        "invocation.build_environment",
    )

    commands = require_mapping(invocation.get("commands"), "invocation.commands")
    for name in (
        "archive",
        "build_daemon_cli",
        "build_harness",
        "extract",
        "generate",
        "process_fence",
        "daemon",
        "health",
        "harness",
        "validate",
    ):
        argv = commands.get(name)
        if (
            not isinstance(argv, list)
            or not argv
            or not all(isinstance(item, str) and item for item in argv)
        ):
            fail(f"invocation.commands.{name} must be a non-empty argv array")
    require_exact(
        commands["build_daemon_cli"],
        [
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
        "invocation.commands.build_daemon_cli",
    )
    require_exact(
        commands["build_harness"],
        [
            "cargo",
            "build",
            "--release",
            "--locked",
            "--manifest-path",
            "bench/scale/reloadstall/Cargo.toml",
        ],
        "invocation.commands.build_harness",
    )
    require_exact(
        invocation.get("daemon_environment"),
        {"RUST_LOG": "info"},
        "invocation.daemon_environment",
    )
    require_exact(
        invocation.get("health_probe"),
        {"timeout_seconds": 10, "interval_milliseconds": 50},
        "invocation.health_probe",
    )
    require_exact(
        invocation.get("process_fence_environment"),
        {"PYTHONDONTWRITEBYTECODE": "1"},
        "invocation.process_fence_environment",
    )
    require_exact(
        commands["archive"],
        [
            "git",
            "archive",
            "--format=tar",
            f"--output={OUTPUT_DIR}/sources/source.tar",
            manifest["source"]["commit"],
        ],
        "invocation.commands.archive",
    )
    require_exact(
        commands["extract"],
        [
            "tar",
            "--extract",
            f"--file={OUTPUT_DIR}/sources/source.tar",
            f"--directory={SOURCE_ROOT}",
            "--no-same-owner",
            "--no-same-permissions",
        ],
        "invocation.commands.extract",
    )
    require_exact(
        commands["process_fence"],
        [
            "python3",
            f"{SOURCE_ROOT}/bench/scale/reloadstall/process_fence.py",
            "--root",
            REPO_ROOT,
            "--root",
            SOURCE_ROOT,
            "--root",
            BUILD_TARGET,
        ],
        "invocation.commands.process_fence",
    )
    require_exact(
        commands["validate"],
        [
            "python3",
            f"{SOURCE_ROOT}/bench/scale/reloadstall/validate_receipt.py",
            OUTPUT_DIR,
        ],
        "invocation.commands.validate",
    )

    harness = commands["harness"]
    if Path(harness[0]).name != "reloadstall" or harness[1:4] != [
        str(PEERS),
        str(PREFIXES),
        str(PORT),
    ]:
        fail("harness invocation does not pin the 700x400,400 shape")
    if len(harness) != 10 or harness[4] != DAEMON_PID:
        fail("harness invocation has the wrong argument contract")
    expected_tail = [
        f"{runtime_dir}/member.rpol",
        f"{runtime_dir}/gen-a.rpol",
        f"{runtime_dir}/gen-b.rpol",
        str(RELOADS),
        str(CONTROL_SECS),
    ]
    if harness[5:] != expected_tail:
        fail("harness invocation does not use the generated policy inputs")

    daemon = commands["daemon"]
    if daemon != [f"{BUILD_TARGET}/release/rustbgpd", f"{runtime_dir}/config.toml"]:
        fail("daemon invocation does not use the generated config")
    health = commands["health"]
    if health != [
        f"{BUILD_TARGET}/release/rbgp",
        "--addr",
        f"unix://{runtime_dir}/grpc.sock",
        "health",
    ]:
        fail("health invocation is not pinned to the generated UDS")
    generate = commands["generate"]
    if generate != [
        "python3",
        f"{SOURCE_ROOT}/bench/scale/reloadstall/gen-scenario.py",
        str(PEERS),
        runtime_dir,
        str(PORT),
    ]:
        fail("scenario-generator invocation does not pin the acceptance shape")
    if harness[0] != f"{BUILD_TARGET}/release/reloadstall":
        fail("harness invocation does not use the retained build path")

    rendered = read_text(root / "provenance.txt")
    for required in (
        f"source_commit={manifest['source']['commit']}",
        f"source_tree={manifest['source']['tree']}",
        f"source_archive_sha256={manifest['source']['archive_sha256']}",
        "source_remote=https://github.com/lance0/rustbgpd.git",
        "build_source_root=<SOURCE_ROOT>",
        "build_target_dir=<BUILD_TARGET>",
        "host_lock=<HOST_LOCK>",
        "runtime_dir=<RUNTIME_DIR>",
        "output_dir=<OUTPUT_DIR>",
        "rustc ",
        "cargo ",
        "rustbgpd_sha256=",
        "rbgp_sha256=",
        "reloadstall_sha256=",
        "environment_RUSTFLAGS=<unset>",
        "environment_CARGO_ENCODED_RUSTFLAGS=<unset>",
        "environment_CARGO_TARGET_DIR=<unset>",
    ):
        if required not in rendered:
            fail(f"provenance.txt is missing {required!r}")
    for hash_name in (
        "root_Cargo.lock_sha256",
        "reloadstall_Cargo.lock_sha256",
        "rustbgpd_sha256",
        "rbgp_sha256",
        "reloadstall_sha256",
    ):
        matches = re.findall(
            rf"^{re.escape(hash_name)}=([0-9a-f]{{64}})$", rendered, re.M
        )
        if len(matches) != 1:
            fail(f"provenance.txt must contain one exact {hash_name}")


def expected_stub_addr(index: int) -> str:
    return f"127.1.{index // 200}.{index % 200 + 1}"


def validate_scenario(root: Path, manifest: dict[str, Any]) -> None:
    try:
        config = tomllib.loads(read_text(root / "scenario/config.toml"))
    except tomllib.TOMLDecodeError as exc:
        fail(f"generated config is invalid TOML: {exc}")
    global_config = require_mapping(config.get("global"), "config.global")
    require_exact(global_config.get("listen_port"), PORT, "config.global.listen_port")
    runtime_dir = manifest["runtime_dir"]
    require_exact(
        global_config.get("runtime_state_dir"),
        runtime_dir,
        "config.global.runtime_state_dir",
    )
    telemetry = require_mapping(
        global_config.get("telemetry"), "config.global.telemetry"
    )
    require_exact(telemetry.get("log_format"), "json", "config telemetry log_format")
    uds = require_mapping(telemetry.get("grpc_uds"), "config grpc_uds")
    require_exact(uds.get("path"), f"{runtime_dir}/grpc.sock", "config grpc_uds path")
    neighbors = config.get("neighbors")
    if not isinstance(neighbors, list) or len(neighbors) != PEERS:
        fail(f"generated config must contain exactly {PEERS} neighbors")
    for index, neighbor_value in enumerate(neighbors):
        neighbor = require_mapping(neighbor_value, f"config.neighbors[{index}]")
        require_exact(
            neighbor.get("address"),
            expected_stub_addr(index),
            f"neighbor {index} address",
        )
        require_exact(
            neighbor.get("remote_asn"), 64_512 + index, f"neighbor {index} remote_asn"
        )
        require_exact(
            neighbor.get("route_server_client"),
            True,
            f"neighbor {index} route_server_client",
        )
        require_exact(
            neighbor.get("families"), ["ipv4_unicast"], f"neighbor {index} families"
        )
        require_exact(neighbor.get("hold_time"), 180, f"neighbor {index} hold_time")

    generation_a = read_text(root / "scenario/gen-a.rpol")
    generation_b = read_text(root / "scenario/gen-b.rpol")
    initial = read_text(root / "scenario/member.initial.rpol")
    final = read_text(root / "scenario/member.final.rpol")
    if initial != generation_a or final != generation_a:
        fail(
            "four-reload policy parity requires initial and final live policy == generation A"
        )
    for label, policy, community, reject in (
        ("A", generation_a, "65500:1000", "192.0.2.0/24"),
        ("B", generation_b, "65500:2000", "198.51.100.0/24"),
    ):
        if policy.count(f"add community {community}") != 1:
            fail(f"generation {label} does not carry exactly one expected community")
        if policy.count(f"route.prefix == {reject}") != 1:
            fail(f"generation {label} does not carry exactly one expected reject term")
    if generation_a == generation_b:
        fail("policy generations must differ")


def one_line(lines: list[str], pattern: re.Pattern[str] | str, label: str) -> str:
    regex = re.compile(pattern) if isinstance(pattern, str) else pattern
    matches = [line for line in lines if regex.fullmatch(line)]
    if len(matches) != 1:
        fail(f"expected exactly one {label} line, found {len(matches)}")
    return matches[0]


def stats(lines: list[str], label: str) -> dict[str, float | int]:
    line = one_line(lines, re.compile(re.escape(label) + r": .+"), label)
    match = STATS_RE.fullmatch(line)
    if not match:
        fail(f"malformed stats line for {label}")
    values: dict[str, float | int] = {
        "p50": float(match.group("p50")),
        "p95": float(match.group("p95")),
        "max": float(match.group("max")),
        "n": int(match.group("n")),
    }
    if not all(math.isfinite(float(values[key])) for key in ("p50", "p95", "max")):
        fail(f"non-finite stats in {label}")
    if not 0 <= float(values["p50"]) <= float(values["p95"]) <= float(values["max"]):
        fail(f"unordered stats in {label}")
    return values


def validate_harness_log(root: Path) -> None:
    text = read_text(root / "harness.log")
    for forbidden in (
        "TIMEOUT",
        "FAIL:",
        "stub ",
        "failed to deliver SIGHUP",
        "daemon UPDATE decode error",
    ):
        if forbidden in text:
            fail(f"harness log contains failure marker {forbidden!r}")
    if re.search(r"pid=[0-9]+", text):
        fail("harness.log contains an unsanitized daemon PID")
    lines = text.splitlines()
    one_line(
        lines,
        rf"# reloadstall peers={PEERS} prefixes={PREFIXES} per_peer={PER_PEER} pid=<DAEMON_PID>",
        "shape header",
    )
    one_line(lines, rf"established {PEERS} at [0-9]+(?:\.[0-9]+)?s", "established")
    one_line(
        lines,
        rf"converged \(>= {EXPECTED}/observer\) at [0-9]+(?:\.[0-9]+)?s rss_mib=[0-9]+",
        "convergence",
    )
    control = stats(lines, "control_maxgap_ms")
    require_exact(control["n"], PEERS, "control observer count")
    one_line(lines, r"control_rss_mib [0-9]+", "control RSS")

    for reload_index, (community, community_value) in enumerate(
        zip(COMMUNITIES, COMMUNITY_VALUES, strict=True), 1
    ):
        policy = "gen-b.rpol" if reload_index % 2 else "gen-a.rpol"
        one_line(
            lines,
            rf"reload {reload_index} SIGHUP wall_us=[0-9]+ policy=<RUNTIME_DIR>/{policy}",
            f"reload {reload_index} SIGHUP",
        )
        one_line(
            lines,
            rf"reload {reload_index} unique_generation_complete "
            rf"contract={CONTRACT} community={community} observers={PEERS}/{PEERS} "
            rf"unique_prefixes_per_observer={EXPECTED} target={EXPECTED}",
            f"reload {reload_index} unique generation",
        )
        completion = stats(lines, f"reload {reload_index} completion_s")
        gap = stats(lines, f"reload {reload_index} maxgap_ms")
        first = stats(lines, f"reload {reload_index} first_update_ms")
        for label, row in (("completion", completion), ("gap", gap), ("first", first)):
            require_exact(
                row["n"], PEERS, f"reload {reload_index} {label} observer count"
            )
        if float(gap["max"]) >= 1_000.0:
            fail(
                f"reload {reload_index} violates the precommitted <1s worst-observer stall gate"
            )
        rss_line = one_line(
            lines,
            rf"reload {reload_index} rss_mib before=[0-9]+ after=[0-9]+ comms_sample=\[[^]]*\]",
            f"reload {reload_index} RSS/community",
        )
        if not re.search(
            rf"comms_sample=\[[^]]*\b{community_value}\b[^]]*\]$", rss_line
        ):
            fail(f"reload {reload_index} lacks the expected delivered community sample")
        one_line(
            lines,
            rf"reload {reload_index} sessions_up {PEERS}/{PEERS}",
            f"reload {reload_index} session continuity",
        )
    one_line(lines, r"done rss_mib=[0-9]+", "completion")


def daemon_message(event: dict[str, Any]) -> tuple[str, str]:
    fields = event.get("fields")
    if not isinstance(fields, dict):
        fields = {}
    message = fields.get("message", event.get("message", ""))
    peer = fields.get("peer", "")
    return str(message), str(peer)


def validate_daemon_log(root: Path) -> None:
    established_peers: list[str] = []
    reload_completions = 0
    for line_number, line in enumerate(read_text(root / "daemon.log").splitlines(), 1):
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            fail(f"daemon.log line {line_number} is not JSON: {exc}")
        if not isinstance(event, dict):
            fail(f"daemon.log line {line_number} is not a JSON object")
        message, peer = daemon_message(event)
        lowered = message.lower()
        if message == "session established":
            if not peer:
                fail(f"daemon establishment line {line_number} lacks a peer")
            established_peers.append(peer)
        if message == "config reload complete":
            reload_completions += 1
        for forbidden in (
            "bgp notification",
            "hold timer expired",
            "hold-timer expired",
            "send hold timer expired",
            "panicked at",
            "fatal",
        ):
            if forbidden in lowered:
                fail(f"daemon log contains forbidden run-window event {forbidden!r}")
    if len(established_peers) != PEERS or len(set(established_peers)) != PEERS:
        fail(
            f"daemon must prove exactly {PEERS} one-time peer establishments; "
            f"events={len(established_peers)} unique={len(set(established_peers))}"
        )
    if reload_completions != RELOADS:
        fail(
            f"daemon must log exactly {RELOADS} completed reloads, got {reload_completions}"
        )


def validate_health(root: Path, manifest: dict[str, Any]) -> None:
    rows = read_text(root / "health.tsv").splitlines()
    if rows[:1] != ["wall_ns\telapsed_us\texit_code"] or len(rows) < 2:
        fail("health.tsv must contain successful probe samples")
    failures = 0
    for row in rows[1:]:
        fields = row.split("\t")
        if len(fields) != 3 or not all(field.isdigit() for field in fields):
            fail(f"malformed health.tsv row: {row!r}")
        if int(fields[1]) <= 0:
            fail("health probe elapsed_us must be positive")
        failures += int(fields[2]) != 0
    if failures:
        fail(f"health probe failed {failures} times during the measurement window")
    if read_text(root / "health-errors.log") != "":
        fail("health-errors.log must be empty when every control query succeeds")
    result = require_mapping(manifest["result"], "manifest.result")
    require_exact(
        result["health_samples"], len(rows) - 1, "manifest health sample count"
    )
    require_exact(result["health_failures"], failures, "manifest health failure count")


def validate_receipt(path: str | Path) -> dict[str, Any]:
    requested_root = Path(path)
    if requested_root.is_symlink():
        fail("receipt root must not be a symlink")
    try:
        root = requested_root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        fail(f"cannot resolve receipt root: {exc}")
    files = validate_file_inventory(root)
    validate_checksums(root, files)
    validate_publication_safety(root, files)
    manifest = validate_manifest(root)
    validate_source_archive(root, manifest)
    validate_preflight(root, manifest)
    validate_invocation(root, manifest)
    validate_scenario(root, manifest)
    validate_harness_log(root)
    validate_daemon_log(root)
    validate_health(root, manifest)
    return {
        "accepted": True,
        "schema": SCHEMA,
        "source_commit": manifest["source"]["commit"],
        "shape": f"{PEERS}x{PREFIXES}",
        "completion_contract": CONTRACT,
        "reloads": RELOADS,
        "stall_gate_ms": 1_000,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt_dir", help="completed receipt bundle directory")
    args = parser.parse_args(argv)
    try:
        result = validate_receipt(args.receipt_dir)
    except ReceiptError as exc:
        print(json.dumps({"accepted": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
