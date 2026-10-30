#!/usr/bin/env python3
"""Fail-closed path classifier for the Interop and Kernel lab rosters."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PULL_REQUEST = "pull_request"
FUZZ_ROOTS = (
    "crates/bfd/fuzz",
    "crates/cli/fuzz",
    "crates/evpn/fuzz",
    "crates/mrt/fuzz",
    "crates/policy/fuzz",
    "crates/rpki/fuzz",
    "crates/wire/fuzz",
)
FUZZ_FILES = frozenset(
    {
        ".github/workflows/clusterfuzzlite.yml",
        ".github/workflows/fuzz.yml",
        "fuzz/build-fuzzers.sh",
        "fuzz/oss-fuzz/Dockerfile",
        "fuzz/oss-fuzz/build.sh",
        "fuzz/oss-fuzz/project.yaml",
        "fuzz/rust-nightly.txt",
        "scripts/check_fuzz_target_inventory.py",
        "scripts/test_check_fuzz_target_inventory.py",
        "scripts/fuzz_corpus_cache.py",
        "scripts/test_fuzz_corpus_cache.py",
        "scripts/check_fuzz_toolchain_pin.py",
        "scripts/test_check_fuzz_toolchain_pin.py",
    }
)
PACKAGE_ROOTS = ("packaging",)
PACKAGE_FILES = frozenset(
    {
        ".github/workflows/release.yml",
        ".github/workflows/release-install-contract.yml",
        ".github/workflows/release-build-features.yml",
        "scripts/build-packages.sh",
        "scripts/check_release_build_features.py",
        "scripts/test_check_release_build_features.py",
        "scripts/check_release_install_contract.py",
        "scripts/test_check_release_install_contract.py",
    }
)
SHA = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
# The classifier job checks out one commit. A pull request fetches its base and
# head at each depth in turn until their merge base is complete; past the last
# depth it fails closed instead of diffing against a truncated history.
FETCH_DEPTHS = (64, 256, 1024)


class ClassificationError(RuntimeError):
    """The complete PR diff could not be classified."""


def _under(path: str, roots: Sequence[str]) -> bool:
    return any(path == root or path.startswith(f"{root}/") for root in roots)


def _well_formed(path: str) -> bool:
    parts = path.split("/")
    return (
        bool(path)
        and not path.startswith("/")
        and all(
            part not in {"", ".", ".."} and not any(ord(char) < 32 for char in part)
            for part in parts
        )
    )


def _documentation(path: str) -> bool:
    return path.endswith(".md") or path == "docs" or path.startswith("docs/")


def classify_paths(paths: Sequence[str]) -> tuple[bool, str]:
    """Return ``(run_labs, reason)`` for one complete PR path set."""
    if not paths:
        return True, "empty diff"
    if any(not _well_formed(path) for path in paths):
        return True, "malformed path"

    material = tuple(path for path in paths if not _documentation(path))
    if not material:
        return False, "documentation only"
    if all(path in FUZZ_FILES or _under(path, FUZZ_ROOTS) for path in material):
        return False, "standalone fuzz only"
    if all(path in PACKAGE_FILES or _under(path, PACKAGE_ROOTS) for path in material):
        return False, "release/package only"
    return True, "mixed or lab-relevant paths"


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, check=False)


def _shallow_commits(repo: Path) -> frozenset[str]:
    path = _git(repo, "rev-parse", "--git-path", "shallow").stdout.decode().strip()
    shallow = repo / path
    return frozenset(shallow.read_text().split()) if shallow.is_file() else frozenset()


def _merge_base_complete(repo: Path, base: str, head: str) -> bool:
    """Whether every commit between base/head and each merge base is present.

    A shallow commit on either side could hide a newer merge base, and Git
    would then diff against an older common ancestor without complaint. Each
    candidate is checked on its own: a boundary at or below one candidate can
    hide that another candidate is its ancestor, not a second merge base.
    """
    bases = _git(repo, "merge-base", "--all", base, head)
    if bases.returncode != 0 or not bases.stdout.split():
        return False
    shallow = _shallow_commits(repo)
    for candidate in bases.stdout.decode().split():
        sides = _git(repo, "rev-list", base, head, "--not", candidate)
        if sides.returncode != 0 or shallow & set(sides.stdout.decode().split()):
            return False
    return True


def ensure_merge_base(repo: Path, base: str, head: str) -> None:
    """Deepen a shallow checkout until the base...head merge base is complete."""
    if not _shallow_commits(repo):
        return
    for depth in FETCH_DEPTHS:
        fetch = _git(
            repo, "fetch", "--quiet", "--no-tags", f"--depth={depth}", "origin", base, head
        )
        if fetch.returncode != 0:
            detail = fetch.stderr.decode("utf-8", errors="replace").strip()
            raise ClassificationError(detail or f"git fetch exited {fetch.returncode}")
        if _merge_base_complete(repo, base, head):
            return
    raise ClassificationError(
        f"no complete merge base within {FETCH_DEPTHS[-1]} commits of base and head"
    )


def changed_paths(repo: Path, base: str, head: str) -> tuple[str, ...]:
    """Read the complete three-dot PR diff without API file-count limits."""
    if not SHA.fullmatch(base) or not SHA.fullmatch(head):
        raise ClassificationError("pull request base/head must be full commit IDs")
    ensure_merge_base(repo, base, head)
    result = subprocess.run(
        [
            "git",
            "diff",
            "--no-ext-diff",
            "--no-renames",
            "--name-only",
            "-z",
            f"{base}...{head}",
            "--",
        ],
        cwd=repo,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ClassificationError(detail or f"git diff exited {result.returncode}")
    if result.stdout and not result.stdout.endswith(b"\0"):
        raise ClassificationError("git diff returned malformed path framing")
    try:
        return (
            tuple(
                path.decode("utf-8")
                for path in result.stdout.removesuffix(b"\0").split(b"\0")
            )
            if result.stdout
            else ()
        )
    except UnicodeDecodeError as error:
        raise ClassificationError(
            f"git diff returned a non-UTF-8 path: {error}"
        ) from error


def classify_event(
    event: str, base: str, head: str, repo: Path = ROOT, draft: bool = False
) -> tuple[bool, str]:
    """Only pull requests may take the narrow lab-independent skip path.

    A draft pull request skips the labs whatever it changes: they run once it
    is marked ready for review (a ``ready_for_review`` run on the same head).
    """
    if event != PULL_REQUEST:
        return True, f"{event or 'unknown'} event"
    if draft:
        return False, "draft pull request; labs run when it is marked ready"
    return classify_paths(changed_paths(repo, base, head))


def main() -> int:
    try:
        run_labs, reason = classify_event(
            os.environ.get("EVENT_NAME", ""),
            os.environ.get("BASE_SHA", ""),
            os.environ.get("HEAD_SHA", ""),
            # Anything but an explicit "true" runs the labs.
            draft=os.environ.get("PR_DRAFT") == "true",
        )
        output = os.environ.get("GITHUB_OUTPUT")
        if not output:
            raise ClassificationError("GITHUB_OUTPUT is not set")
        with Path(output).open("a", encoding="utf-8") as handle:
            handle.write(f"run_labs={'true' if run_labs else 'false'}\n")
        print(f"run_labs={str(run_labs).lower()} ({reason})")
        return 0
    except (ClassificationError, OSError) as error:
        print(f"heavy-lab path classification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
