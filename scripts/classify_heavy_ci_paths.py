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
        "scripts/check_fuzz_toolchain_pin.py",
        "scripts/test_check_fuzz_toolchain_pin.py",
    }
)
PACKAGE_ROOTS = ("packaging",)
PACKAGE_FILES = frozenset(
    {
        ".github/workflows/release.yml",
        ".github/workflows/release-install-contract.yml",
        "scripts/build-packages.sh",
        "scripts/check_release_install_contract.py",
        "scripts/test_check_release_install_contract.py",
    }
)
SHA = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")


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


def changed_paths(repo: Path, base: str, head: str) -> tuple[str, ...]:
    """Read the complete three-dot PR diff without API file-count limits."""
    if not SHA.fullmatch(base) or not SHA.fullmatch(head):
        raise ClassificationError("pull request base/head must be full commit IDs")
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
    event: str, base: str, head: str, repo: Path = ROOT
) -> tuple[bool, str]:
    """Only pull requests may take the narrow lab-independent skip path."""
    if event != PULL_REQUEST:
        return True, f"{event or 'unknown'} event"
    return classify_paths(changed_paths(repo, base, head))


def main() -> int:
    try:
        run_labs, reason = classify_event(
            os.environ.get("EVENT_NAME", ""),
            os.environ.get("BASE_SHA", ""),
            os.environ.get("HEAD_SHA", ""),
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
