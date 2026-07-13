#!/usr/bin/env -S /usr/bin/python3 -I -S
"""Fail-closed validator for a policy reload-stall receipt bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import subprocess
import sys
import tarfile
import tempfile
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
CONTRACT = "current-state-generation-community-v2"
REQUIRED_TOOLCHAIN = "1.95.0-x86_64-unknown-linux-gnu"
COMMUNITIES = ("65500:2000", "65500:1000", "65500:2000", "65500:1000")
RUNTIME_DIR = "<RUNTIME_DIR>"
OUTPUT_DIR = "<OUTPUT_DIR>"
REPO_ROOT = "<REPO_ROOT>"
SOURCE_ROOT = "<SOURCE_ROOT>"
BUILD_TARGET = "<BUILD_TARGET>"
HOST_LOCK = "<HOST_LOCK>"
DAEMON_PID = "<DAEMON_PID>"
GIT = "/usr/bin/git"
CANONICAL_REMOTE = "https://github.com/lance0/rustbgpd.git"
CANONICAL_BASELINE_COMMIT = "aacb3a89527759b610bead421c80612f04d04826"
CANONICAL_BASELINE_CONTEXT_REF = "refs/heads/main"
CANONICAL_CANDIDATE_CONTEXT_REF = "refs/heads/perf/policy-reload-durable-receipt"
RETAINED_BASELINE_REF = "refs/receipt/baseline"
RETAINED_SOURCE_REF = "refs/receipt/source"
GIT_ENVIRONMENT = {
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "HOME": "/nonexistent",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
    "TZ": "UTC",
}
PYTHON_ENVIRONMENT = {
    "HOME": "/nonexistent",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
    "PYTHONDONTWRITEBYTECODE": "1",
    "TZ": "UTC",
}
PYTHON_INVOCATION = [
    "/usr/bin/env",
    "-i",
    "LC_ALL=C",
    "TZ=UTC",
    "HOME=/nonexistent",
    "PATH=/usr/bin:/bin",
    "PYTHONDONTWRITEBYTECODE=1",
    "/usr/bin/python3",
    "-I",
    "-S",
]
PROCESS_FENCE_IMAGE_DIGEST = (
    "sha256:f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3"
)
PROCESS_FENCE_IMAGE = f"rust:1.95-trixie@{PROCESS_FENCE_IMAGE_DIGEST}"
PROCESS_FENCE_IMAGE_ID = PROCESS_FENCE_IMAGE_DIGEST
PROCESS_FENCE_REPO_DIGEST = f"rust@{PROCESS_FENCE_IMAGE_DIGEST}"
PROCESS_FENCE_ENVIRONMENT = {
    "architecture": "amd64",
    "image": PROCESS_FENCE_IMAGE,
    "image_id": PROCESS_FENCE_IMAGE_ID,
    "os": "linux",
    "repo_digest": PROCESS_FENCE_REPO_DIGEST,
}
DOCKER_INVOCATION = [
    "/usr/bin/env",
    "-i",
    "LC_ALL=C",
    "TZ=UTC",
    "HOME=/nonexistent",
    "PATH=/usr/bin:/bin",
    "/usr/bin/docker",
]
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
    "sources/build_fence.py",
    "sources/canonical-fetch.txt",
    "sources/canonical-refs.txt",
    "sources/gen-scenario.py",
    "sources/process_fence.py",
    "sources/reloadstall-main.rs",
    "sources/run-receipt.sh",
    "sources/source.commit",
    "sources/source.bundle",
    "sources/source.tar",
    "sources/validate_receipt.py",
}
UNSUMMED_FILES = {"SHA256SUMS"}
SOURCE_FILES = {
    "sources/build_fence.py",
    "sources/canonical-refs.txt",
    "sources/gen-scenario.py",
    "sources/process_fence.py",
    "sources/reloadstall-main.rs",
    "sources/run-receipt.sh",
    "sources/source.commit",
    "sources/source.bundle",
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


def run_git(arguments: list[str], *, label: str) -> bytes:
    try:
        completed = subprocess.run(
            [GIT, *arguments],
            check=False,
            capture_output=True,
            env=GIT_ENVIRONMENT,
        )
    except OSError as exc:
        fail(f"cannot execute trusted Git for {label}: {exc}")
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        fail(f"Git {label} failed: {detail or f'exit {completed.returncode}'}")
    return completed.stdout


def bundle_heads(bundle_path: Path) -> dict[str, str]:
    rendered = run_git(
        ["bundle", "list-heads", str(bundle_path)], label="bundle head listing"
    ).decode("ascii", errors="strict")
    result: dict[str, str] = {}
    for line in rendered.splitlines():
        fields = line.split(" ", 1)
        if len(fields) != 2 or not COMMIT_RE.fullmatch(fields[0]):
            fail(f"malformed source bundle head: {line!r}")
        commit, ref = fields
        if ref in result:
            fail(f"duplicate source bundle ref: {ref}")
        result[ref] = commit
    return result


def validate_source_bundle(root: Path, manifest: dict[str, Any]) -> None:
    bundle_path = root / "sources/source.bundle"
    source = require_mapping(manifest["source"], "manifest.source")
    canonical = require_mapping(source["canonical"], "manifest.source.canonical")
    require_exact(
        hashlib.sha256(bundle_path.read_bytes()).hexdigest(),
        source["bundle_sha256"],
        "source bundle SHA-256",
    )
    require_exact(
        bundle_heads(bundle_path),
        {
            RETAINED_BASELINE_REF: canonical["baseline_commit"],
            RETAINED_SOURCE_REF: source["commit"],
        },
        "source bundle retained refs",
    )
    require_exact(
        read_text(root / "sources/canonical-refs.txt"),
        (
            f"remote={CANONICAL_REMOTE}\n"
            f"baseline_commit={canonical['baseline_commit']}\n"
            f"baseline_context_ref={CANONICAL_BASELINE_CONTEXT_REF}\n"
            f"source_commit={source['commit']}\n"
            f"source_tree={source['tree']}\n"
            f"candidate_context_ref={CANONICAL_CANDIDATE_CONTEXT_REF}\n"
            "proof=exact-sha-live-fetch-and-retained-bundle\n"
        ),
        "retained canonical refs",
    )
    require_exact(
        read_text(root / "sources/canonical-fetch.txt"),
        (
            "command=env -i LC_ALL=C TZ=UTC HOME=/nonexistent PATH=/usr/bin:/bin "
            "GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null "
            "GIT_TERMINAL_PROMPT=0 /usr/bin/git -C <CANONICAL_REPO> fetch "
            f"--no-tags --force {CANONICAL_REMOTE} "
            f"+{canonical['baseline_commit']}:{RETAINED_BASELINE_REF} "
            f"+{source['commit']}:{RETAINED_SOURCE_REF}\n"
            "fetch=success\n"
            "fsck=success\n"
            f"baseline_commit={canonical['baseline_commit']}\n"
            f"source_commit={source['commit']}\n"
            f"source_tree={source['tree']}\n"
        ),
        "retained canonical fetch evidence",
    )

    with tempfile.TemporaryDirectory(prefix="reloadstall-bundle-") as temporary:
        repository = Path(temporary) / "fresh.git"
        run_git(["init", "--bare", "--quiet", str(repository)], label="repository init")
        run_git(
            ["-C", str(repository), "bundle", "verify", str(bundle_path)],
            label="bundle verification",
        )
        run_git(
            [
                "-C",
                str(repository),
                "fetch",
                "--quiet",
                str(bundle_path),
                f"{RETAINED_BASELINE_REF}:refs/imported/baseline",
                f"{RETAINED_SOURCE_REF}:refs/imported/source",
            ],
            label="fresh-repository bundle import",
        )
        imported_commit = (
            run_git(
                ["-C", str(repository), "rev-parse", "refs/imported/source"],
                label="imported commit lookup",
            )
            .decode("ascii")
            .strip()
        )
        imported_baseline = (
            run_git(
                ["-C", str(repository), "rev-parse", "refs/imported/baseline"],
                label="imported baseline lookup",
            )
            .decode("ascii")
            .strip()
        )
        imported_tree = (
            run_git(
                ["-C", str(repository), "rev-parse", "refs/imported/source^{tree}"],
                label="imported tree lookup",
            )
            .decode("ascii")
            .strip()
        )
        require_exact(imported_commit, source["commit"], "source bundle commit")
        require_exact(
            imported_baseline,
            canonical["baseline_commit"],
            "source bundle baseline commit",
        )
        require_exact(imported_tree, source["tree"], "source bundle tree")
        require_exact(
            run_git(
                ["-C", str(repository), "cat-file", "commit", "refs/imported/source"],
                label="imported commit read",
            ),
            (root / "sources/source.commit").read_bytes(),
            "source bundle commit object",
        )
        run_git(
            ["-C", str(repository), "fsck", "--full", "--strict"],
            label="fresh-repository object verification",
        )


def validate_live_canonical_membership(
    manifest: dict[str, Any], *, fetch_remote: str = CANONICAL_REMOTE
) -> None:
    source = require_mapping(manifest["source"], "manifest.source")
    canonical = require_mapping(source["canonical"], "manifest.source.canonical")
    with tempfile.TemporaryDirectory(prefix="reloadstall-canonical-") as temporary:
        repository = Path(temporary) / "canonical.git"
        run_git(
            ["init", "--bare", "--quiet", str(repository)],
            label="canonical repository init",
        )
        run_git(
            [
                "-C",
                str(repository),
                "fetch",
                "--no-tags",
                "--force",
                fetch_remote,
                f"+{canonical['baseline_commit']}:{RETAINED_BASELINE_REF}",
                f"+{source['commit']}:{RETAINED_SOURCE_REF}",
            ],
            label="live canonical ref fetch",
        )
        live_baseline = (
            run_git(
                [
                    "-C",
                    str(repository),
                    "rev-parse",
                    f"{RETAINED_BASELINE_REF}^{{commit}}",
                ],
                label="live canonical baseline lookup",
            )
            .decode("ascii")
            .strip()
        )
        live_candidate = (
            run_git(
                [
                    "-C",
                    str(repository),
                    "rev-parse",
                    f"{RETAINED_SOURCE_REF}^{{commit}}",
                ],
                label="live canonical candidate lookup",
            )
            .decode("ascii")
            .strip()
        )
        live_tree = (
            run_git(
                ["-C", str(repository), "rev-parse", f"{RETAINED_SOURCE_REF}^{{tree}}"],
                label="live canonical candidate tree lookup",
            )
            .decode("ascii")
            .strip()
        )
        require_exact(
            live_baseline,
            canonical["baseline_commit"],
            "live canonical baseline commit",
        )
        require_exact(
            live_candidate, source["commit"], "live canonical candidate commit"
        )
        require_exact(live_tree, source["tree"], "live canonical candidate tree")
        run_git(
            ["-C", str(repository), "fsck", "--full", "--strict"],
            label="live canonical object verification",
        )


def validate_source_archive(root: Path, manifest: dict[str, Any]) -> None:
    archive_path = root / "sources/source.tar"
    archive_digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    source = require_mapping(manifest["source"], "manifest.source")
    commit_payload = (root / "sources/source.commit").read_bytes()
    require_exact(
        git_object_id("commit", commit_payload).hex(),
        source["commit"],
        "retained Git commit object",
    )
    first_line = commit_payload.splitlines()[:1]
    if len(first_line) != 1 or not first_line[0].startswith(b"tree "):
        fail("retained Git commit object lacks a tree header")
    try:
        commit_tree = first_line[0][len(b"tree ") :].decode("ascii")
    except UnicodeDecodeError as exc:
        fail(f"retained Git commit tree is not ASCII: {exc}")
    require_exact(commit_tree, source["tree"], "retained commit/tree binding")
    require_exact(
        archive_digest,
        source["archive_sha256"],
        "source archive SHA-256",
    )

    copies = {
        "bench/scale/reloadstall/build_fence.py": "sources/build_fence.py",
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
                if (
                    relative.is_absolute()
                    or not relative.parts
                    or ".." in relative.parts
                ):
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
        (
            re.compile(r"(?i)\b(?:daemon\s+)?pid(?:\s*(?:=|:)\s*|\s+)[0-9]+\b"),
            "unsanitized daemon PID",
        ),
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


def validate_manifest(
    root: Path, *, expected_baseline_commit: str = CANONICAL_BASELINE_COMMIT
) -> dict[str, Any]:
    manifest = load_json(root / "manifest.json")
    require_exact(manifest.get("schema"), SCHEMA, "manifest.schema")
    require_exact(manifest.get("status"), "complete", "manifest.status")

    source = require_mapping(manifest.get("source"), "manifest.source")
    commit = source.get("commit")
    tree = source.get("tree")
    archive_sha256 = source.get("archive_sha256")
    bundle_sha256 = source.get("bundle_sha256")
    if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
        fail("manifest.source.commit must be a full lowercase commit SHA")
    if not isinstance(tree, str) or not COMMIT_RE.fullmatch(tree):
        fail("manifest.source.tree must be a full lowercase tree SHA")
    if not isinstance(archive_sha256, str) or not SHA256_RE.fullmatch(archive_sha256):
        fail("manifest.source.archive_sha256 must be a lowercase SHA-256")
    if not isinstance(bundle_sha256, str) or not SHA256_RE.fullmatch(bundle_sha256):
        fail("manifest.source.bundle_sha256 must be a lowercase SHA-256")
    require_exact(source.get("head"), commit, "manifest.source.head")
    require_exact(source.get("clean"), True, "manifest.source.clean")
    require_exact(
        source.get("remote"),
        CANONICAL_REMOTE,
        "manifest.source.remote",
    )
    canonical = require_mapping(source.get("canonical"), "manifest.source.canonical")
    require_exact(
        canonical.get("baseline_context_ref"),
        CANONICAL_BASELINE_CONTEXT_REF,
        "manifest.source.canonical.baseline_context_ref",
    )
    baseline_commit = canonical.get("baseline_commit")
    if not isinstance(baseline_commit, str) or not COMMIT_RE.fullmatch(baseline_commit):
        fail("manifest.source.canonical.baseline_commit must be a full lowercase SHA")
    require_exact(
        baseline_commit,
        expected_baseline_commit,
        "manifest.source.canonical.baseline_commit",
    )
    require_exact(
        canonical.get("candidate_context_ref"),
        CANONICAL_CANDIDATE_CONTEXT_REF,
        "manifest.source.canonical.candidate_context_ref",
    )
    require_exact(
        canonical.get("source_commit"),
        commit,
        "manifest.source.canonical.source_commit",
    )
    require_exact(
        canonical.get("proof"),
        "exact-sha-live-fetch-and-retained-bundle",
        "manifest.source.canonical.proof",
    )
    if read_text(root / "source-status.txt") != "":
        fail("source-status.txt must be empty for a retained receipt")
    require_exact(
        manifest.get("timeouts_seconds"),
        {
            "build_each": 1800,
            "scenario_generation": 60,
            "harness_outer": 4200,
            "stub_connect_open": 15,
            "overall_establishment": 120,
            "initial_convergence": 120,
            "per_reload": 900,
            "quiesce": 20,
        },
        "manifest.timeouts_seconds",
    )

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
    require_exact(result.get("parse_errors"), 0, "manifest.result.parse_errors")
    require_exact(result.get("base_withdrawals"), 0, "manifest.result.base_withdrawals")
    require_exact(result.get("marker_conflicts"), 0, "manifest.result.marker_conflicts")
    require_exact(
        result.get("route_identity_defects"),
        0,
        "manifest.result.route_identity_defects",
    )
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
        {
            "CARGO_TARGET_DIR": BUILD_TARGET,
            "LC_ALL": "C",
            "TZ": "UTC",
            "HOME": "<BUILD_HOME>",
            "CARGO_HOME": "<CARGO_HOME>",
            "RUSTUP_HOME": "<RUSTUP_HOME>",
            "PATH": "/usr/bin:/bin",
            "RUSTUP_TOOLCHAIN": REQUIRED_TOOLCHAIN,
            "RUSTC": "<RUSTC_COMMAND>",
            "RUSTDOC": "<RUSTDOC_COMMAND>",
            "allowed_cargo_config": f"{SOURCE_ROOT}/.cargo/config.toml",
            "external_cargo_configs": "rejected",
        },
        "invocation.build_environment",
    )
    require_exact(
        invocation.get("runtime_environments"),
        {
            "daemon": {"LC_ALL": "C", "TZ": "UTC", "RUST_LOG": "info"},
            "harness": {"LC_ALL": "C", "TZ": "UTC"},
            "health": {"LC_ALL": "C", "TZ": "UTC"},
        },
        "invocation.runtime_environments",
    )

    commands = require_mapping(invocation.get("commands"), "invocation.commands")
    for name in (
        "archive",
        "bundle",
        "canonical_fetch",
        "commit_object",
        "build_daemon_cli",
        "build_fence",
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
        "invocation.commands.build_daemon_cli",
    )
    require_exact(
        commands["build_harness"],
        [
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
        "invocation.commands.build_harness",
    )
    require_exact(
        invocation.get("health_probe"),
        {"timeout_seconds": 10, "interval_milliseconds": 50},
        "invocation.health_probe",
    )
    require_exact(
        invocation.get("process_fence_environment"),
        PROCESS_FENCE_ENVIRONMENT,
        "invocation.process_fence_environment",
    )
    require_exact(
        commands["build_fence"],
        [
            *PYTHON_INVOCATION,
            f"{SOURCE_ROOT}/bench/scale/reloadstall/build_fence.py",
            "--source-root",
            SOURCE_ROOT,
            "--cargo-home",
            "<CARGO_HOME>",
            "--expected-tree",
            "<SOURCE_TREE>",
            "--require-immutable",
        ],
        "invocation.commands.build_fence",
    )
    require_exact(
        commands["canonical_fetch"],
        [
            "/usr/bin/git",
            "-C",
            "<CANONICAL_REPO>",
            "fetch",
            "--no-tags",
            "--force",
            CANONICAL_REMOTE,
            f"+{manifest['source']['canonical']['baseline_commit']}:{RETAINED_BASELINE_REF}",
            f"+{manifest['source']['commit']}:{RETAINED_SOURCE_REF}",
        ],
        "invocation.commands.canonical_fetch",
    )
    require_exact(
        commands["archive"],
        [
            "/usr/bin/git",
            "-C",
            "<CANONICAL_REPO>",
            "archive",
            "--format=tar",
            f"--output={OUTPUT_DIR}/sources/source.tar",
            RETAINED_SOURCE_REF,
        ],
        "invocation.commands.archive",
    )
    require_exact(
        commands["commit_object"],
        [
            "/usr/bin/git",
            "-C",
            "<CANONICAL_REPO>",
            "cat-file",
            "commit",
            RETAINED_SOURCE_REF,
        ],
        "invocation.commands.commit_object",
    )
    require_exact(
        commands["bundle"],
        [
            "/usr/bin/git",
            "-C",
            "<CANONICAL_REPO>",
            "bundle",
            "create",
            f"{OUTPUT_DIR}/sources/source.bundle",
            RETAINED_BASELINE_REF,
            RETAINED_SOURCE_REF,
        ],
        "invocation.commands.bundle",
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
            *DOCKER_INVOCATION,
            "run",
            "--rm",
            "--pull=never",
            "--network",
            "none",
            "--pid",
            "host",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "SYS_PTRACE",
            "--security-opt",
            "apparmor=unconfined",
            "--security-opt",
            "no-new-privileges",
            "--mount",
            "type=bind,src=/proc,dst=/host-proc,readonly",
            "--mount",
            f"type=bind,src={SOURCE_ROOT}/bench/scale/reloadstall/process_fence.py,dst=/process_fence.py,readonly",
            PROCESS_FENCE_IMAGE,
            "/usr/bin/python3",
            "-I",
            "-S",
            "/process_fence.py",
            "--proc-root",
            "/host-proc",
            "--runner-pid",
            "<RUNNER_PID>",
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
            *PYTHON_INVOCATION,
            f"{SOURCE_ROOT}/bench/scale/reloadstall/validate_receipt.py",
            OUTPUT_DIR,
        ],
        "invocation.commands.validate",
    )

    require_exact(
        commands["generate"],
        [
            "timeout",
            "--foreground",
            "--signal=TERM",
            "--kill-after=5s",
            "60",
            *PYTHON_INVOCATION,
            f"{SOURCE_ROOT}/bench/scale/reloadstall/gen-scenario.py",
            str(PEERS),
            runtime_dir,
            str(PORT),
        ],
        "invocation.commands.generate",
    )
    require_exact(
        commands["daemon"],
        [
            "setsid",
            "env",
            "-i",
            "LC_ALL=C",
            "TZ=UTC",
            "RUST_LOG=info",
            f"{BUILD_TARGET}/release/rustbgpd",
            f"{runtime_dir}/config.toml",
        ],
        "invocation.commands.daemon",
    )
    require_exact(
        commands["health"],
        [
            "timeout",
            "--foreground",
            "--signal=TERM",
            "--kill-after=1s",
            "10",
            "env",
            "-i",
            "LC_ALL=C",
            "TZ=UTC",
            f"{BUILD_TARGET}/release/rbgp",
            "--addr",
            f"unix://{runtime_dir}/grpc.sock",
            "health",
        ],
        "invocation.commands.health",
    )
    require_exact(
        commands["harness"],
        [
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
            f"{BUILD_TARGET}/release/reloadstall",
            str(PEERS),
            str(PREFIXES),
            str(PORT),
            DAEMON_PID,
            f"{runtime_dir}/member.rpol",
            f"{runtime_dir}/gen-a.rpol",
            f"{runtime_dir}/gen-b.rpol",
            str(RELOADS),
            str(CONTROL_SECS),
        ],
        "invocation.commands.harness",
    )

    rendered = read_text(root / "provenance.txt")
    for required in (
        f"source_commit={manifest['source']['commit']}",
        f"source_tree={manifest['source']['tree']}",
        f"source_commit_object_sha={manifest['source']['commit']}",
        f"source_archive_sha256={manifest['source']['archive_sha256']}",
        f"source_bundle_sha256={manifest['source']['bundle_sha256']}",
        f"source_remote={CANONICAL_REMOTE}",
        f"canonical_baseline_context_ref={CANONICAL_BASELINE_CONTEXT_REF}",
        f"canonical_baseline_commit={manifest['source']['canonical']['baseline_commit']}",
        f"canonical_candidate_context_ref={CANONICAL_CANDIDATE_CONTEXT_REF}",
        f"canonical_source_commit={manifest['source']['commit']}",
        f"canonical_source_tree={manifest['source']['tree']}",
        "canonical_membership_proof=exact-sha-live-fetch-and-retained-bundle",
        "build_source_root=<SOURCE_ROOT>",
        "build_target_dir=<BUILD_TARGET>",
        "host_lock=<HOST_LOCK>",
        "runtime_dir=<RUNTIME_DIR>",
        "output_dir=<OUTPUT_DIR>",
        "rustc 1.95.0 ",
        "cargo 1.95.0 ",
        "rustdoc 1.95.0 ",
        "rustbgpd_sha256=",
        "rbgp_sha256=",
        "reloadstall_sha256=",
        "allowed_cargo_config=<SOURCE_ROOT>/.cargo/config.toml",
        "external_cargo_configs=<none>",
        "build_override_fence=clear",
        "source_tree_verification=pre-build,post-build,measurement-boundary,post-run",
        f"required_toolchain={REQUIRED_TOOLCHAIN}",
        f"active_toolchain={REQUIRED_TOOLCHAIN}",
        "build_environment=env -i LC_ALL=C TZ=UTC HOME=<BUILD_HOME> "
        "CARGO_HOME=<CARGO_HOME> RUSTUP_HOME=<RUSTUP_HOME> PATH=/usr/bin:/bin "
        f"RUSTUP_TOOLCHAIN={REQUIRED_TOOLCHAIN} CARGO_TARGET_DIR=<BUILD_TARGET> "
        "RUSTC=<RUSTC_COMMAND> RUSTDOC=<RUSTDOC_COMMAND>",
        "python_environment=env -i LC_ALL=C TZ=UTC HOME=/nonexistent "
        "PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -I -S",
        "daemon_environment=env -i LC_ALL=C TZ=UTC RUST_LOG=info",
        "harness_environment=env -i LC_ALL=C TZ=UTC",
        "health_environment=env -i LC_ALL=C TZ=UTC",
        "environment_RUSTFLAGS=<unset>",
        "environment_RUSTDOCFLAGS=<unset>",
        "environment_CARGO_ENCODED_RUSTFLAGS=<unset>",
        "environment_CARGO_INCREMENTAL=<unset>",
        "environment_CARGO_TARGET_DIR=<unset>",
    ):
        if required not in rendered:
            fail(f"provenance.txt is missing {required!r}")
    expected_process_fence_values = {
        "process_fence_image": PROCESS_FENCE_IMAGE,
        "process_fence_image_id": PROCESS_FENCE_IMAGE_ID,
        "process_fence_image_repo_digest": PROCESS_FENCE_REPO_DIGEST,
        "process_fence_image_os": "linux",
        "process_fence_image_architecture": "amd64",
    }
    for name, expected_value in expected_process_fence_values.items():
        matches = re.findall(rf"^{name}=(\S+)$", rendered, re.M)
        if len(matches) != 1:
            fail(f"provenance.txt must contain one exact {name}")
        require_exact(matches[0], expected_value, f"provenance.txt {name}")
    toolchain_root = f"<RUSTUP_HOME>/toolchains/{REQUIRED_TOOLCHAIN}"
    expected_tool_values = {
        "cargo_command": f"{toolchain_root}/bin/cargo",
        "cargo_resolved": f"{toolchain_root}/bin/cargo",
        "rustc_command": f"{toolchain_root}/bin/rustc",
        "rustc_resolved": f"{toolchain_root}/bin/rustc",
        "rustup_command": "<HOME>/.cargo/bin/rustup",
        "rustup_resolved": "<HOME>/.cargo/bin/rustup",
        "rustdoc_command": f"{toolchain_root}/bin/rustdoc",
        "rustdoc_resolved": f"{toolchain_root}/bin/rustdoc",
        "active_toolchain": REQUIRED_TOOLCHAIN,
        "rustc_sysroot": toolchain_root,
    }
    for tool_name, expected_value in expected_tool_values.items():
        matches = re.findall(rf"^{tool_name}=(\S.*)$", rendered, re.M)
        if len(matches) != 1:
            fail(f"provenance.txt must contain one resolved {tool_name}")
        require_exact(matches[0], expected_value, f"provenance.txt {tool_name}")
    for hash_name in (
        "root_Cargo.lock_sha256",
        "reloadstall_Cargo.lock_sha256",
        "cargo_tool_sha256",
        "rustc_tool_sha256",
        "rustdoc_tool_sha256",
        "rustup_tool_sha256",
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


def expected_policy(reject_prefix: str, community: str) -> str:
    return f"""# reload-stall policy generation - generated by gen-scenario.py.
#
# member-in rejects one out-of-table prefix ({reject_prefix} is outside the
# announced 20.0.0.0-26.x base table), so the import chain is content-real:
# reinstalled per peer, 700 Route Refreshes fire, 400k routes re-enter the
# new chain, but output-neutral - no announced route's verdict changes.
# member-out tags every advertised route with the generation community the
# harness samples to confirm which generation is live at the receiver.
policy member-in {{
    term drop-blocked {{ if route.prefix == {reject_prefix} {{ reject }} }}
    term default {{ accept }}
}}

policy member-out {{
    term tag {{ add community {community}; accept }}
}}
"""


def validate_scenario(root: Path, manifest: dict[str, Any]) -> None:
    try:
        config = tomllib.loads(read_text(root / "scenario/config.toml"))
    except tomllib.TOMLDecodeError as exc:
        fail(f"generated config is invalid TOML: {exc}")
    require_exact(
        set(config), {"global", "neighbors", "policy", "security"}, "config keys"
    )
    global_config = require_mapping(config.get("global"), "config.global")
    require_exact(
        set(global_config),
        {"asn", "listen_port", "router_id", "runtime_state_dir", "telemetry"},
        "config.global keys",
    )
    require_exact(global_config.get("asn"), 65_500, "config.global.asn")
    require_exact(global_config.get("router_id"), "10.0.0.1", "config.global.router_id")
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
    require_exact(set(telemetry), {"grpc_uds", "log_format"}, "config telemetry keys")
    require_exact(telemetry.get("log_format"), "json", "config telemetry log_format")
    uds = require_mapping(telemetry.get("grpc_uds"), "config grpc_uds")
    require_exact(set(uds), {"path"}, "config grpc_uds keys")
    require_exact(uds.get("path"), f"{runtime_dir}/grpc.sock", "config grpc_uds path")
    require_exact(
        config.get("security"),
        {"grpc": {"enforcement": "legacy"}},
        "config.security",
    )
    require_exact(
        config.get("policy"),
        {
            "rpol_files": ["member.rpol"],
            "import_chain": ["member-in"],
            "export_chain": ["member-out"],
        },
        "config.policy",
    )
    neighbors = config.get("neighbors")
    if not isinstance(neighbors, list) or len(neighbors) != PEERS:
        fail(f"generated config must contain exactly {PEERS} neighbors")
    for index, neighbor_value in enumerate(neighbors):
        neighbor = require_mapping(neighbor_value, f"config.neighbors[{index}]")
        require_exact(
            set(neighbor),
            {"address", "families", "hold_time", "remote_asn", "route_server_client"},
            f"neighbor {index} keys",
        )
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
        require_exact(policy, expected_policy(reject, community), f"generation {label}")
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
            rf"reload {reload_index} current_generation_complete "
            rf"contract={CONTRACT} community={community} observers={PEERS}/{PEERS} "
            rf"active_prefixes_per_observer={EXPECTED} target={EXPECTED}",
            f"reload {reload_index} current generation completion",
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
            rf"reload {reload_index} current_generation_verified "
            rf"contract={CONTRACT} community={community} observers={PEERS}/{PEERS} "
            rf"active_prefixes_per_observer={EXPECTED} target={EXPECTED}",
            f"reload {reload_index} post-quiesce current generation",
        )
        one_line(
            lines,
            rf"reload {reload_index} sessions_up {PEERS}/{PEERS}",
            f"reload {reload_index} session continuity",
        )
    one_line(
        lines,
        r"defects parse_errors=0 base_withdrawals=0 marker_conflicts=0 route_identity_defects=0",
        "zero-defect counters",
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


def validate_receipt(
    path: str | Path,
    *,
    canonical_remote: str = CANONICAL_REMOTE,
    expected_baseline_commit: str = CANONICAL_BASELINE_COMMIT,
) -> dict[str, Any]:
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
    manifest = validate_manifest(
        root, expected_baseline_commit=expected_baseline_commit
    )
    validate_source_bundle(root, manifest)
    validate_source_archive(root, manifest)
    validate_live_canonical_membership(manifest, fetch_remote=canonical_remote)
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
