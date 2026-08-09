#!/usr/bin/env python3
"""Fail closed when public documentation cites a private tracker issue ID.

The published doc surface — everything under `docs/` plus the top-level
public markdown — is read by people who have no access to the project's
issue tracker. A bare `LAN-123` in that text is an unresolvable reference:
it names evidence the reader cannot reach and cannot even identify. The
project convention is to name the thing directly, link the ADR, or cite the
GitHub PR number instead.

The surface is discovered from the tracked tree rather than a maintained
file list, so a doc added tomorrow is covered the day it lands instead of
passing vacuously. An empty scan set is itself a failure: a guard that
cannot fail is worse than no guard.

Sealed perf-receipt artifacts are exempt. Their bytes are pinned by a
`SHA256SUMS`, so editing the prose would invalidate published evidence
checksums; they are frozen captures, not living documentation. The
exemption is derived from the seal files themselves rather than a hand-kept
list, so it narrows automatically as receipts age out and cannot be widened
by editing this guard.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

# Anything under `docs/`, plus the top-level files a first-time reader lands
# on. CHANGELOG.md and ROADMAP.md are deliberately out of scope: the
# changelog's released sections are historical records that must not be
# rewritten, and the roadmap tracks unshipped work whose only public name is
# often the tracker item itself.
SCANNED_PREFIXES = ("docs/",)
SCANNED_FILES = frozenset(
    {
        "README.md",
        "ARCHITECTURE.md",
        "CONTRIBUTING.md",
        "KNOWN_ISSUES.md",
        "SECURITY.md",
        "SUPPORT.md",
    }
)

# Binary blobs and compressed captures carry no reviewable prose.
SKIPPED_SUFFIXES = frozenset({".gz", ".png", ".svg", ".zst", ".bin"})

TRACKER_ID = re.compile(r"\bLAN-\d+\b")

SEAL_NAME = "SHA256SUMS"


class TrackerIdGuardError(RuntimeError):
    """The public documentation surface could not be enumerated."""


def tracked_files() -> list[Path]:
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as error:
        raise TrackerIdGuardError(f"cannot list tracked files: {error}")
    if result.returncode != 0:
        detail = result.stderr.strip() or f"git ls-files exited {result.returncode}"
        raise TrackerIdGuardError(f"cannot list tracked files: {detail}")
    paths = [ROOT / name for name in result.stdout.split("\0") if name]
    if not paths:
        raise TrackerIdGuardError("cannot list tracked files: the tracked tree is empty")
    return paths


def sealed_paths(paths: list[Path]) -> set[str]:
    """Return every repository-relative path pinned by a tracked SHA256SUMS."""
    sealed: set[str] = set()
    for path in paths:
        if path.name != SEAL_NAME:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for line in text.splitlines():
            _, separator, name = line.partition("  ")
            if not separator:
                continue
            entry = (path.parent / name.strip()).resolve()
            try:
                sealed.add(entry.relative_to(ROOT).as_posix())
            except ValueError:
                continue
    return sealed


def discover_documents() -> dict[str, str]:
    """Map each public documentation file to its text."""
    paths = tracked_files()
    sealed = sealed_paths(paths)
    documents: dict[str, str] = {}
    for path in paths:
        relative = path.relative_to(ROOT).as_posix()
        if relative not in SCANNED_FILES and not relative.startswith(SCANNED_PREFIXES):
            continue
        if relative in sealed or path.suffix in SKIPPED_SUFFIXES:
            continue
        try:
            documents[relative] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
    if not documents:
        raise TrackerIdGuardError(
            "no public documentation was discovered, so the walk is broken: "
            "the repository ships a docs/ tree and a top-level README"
        )
    return dict(sorted(documents.items()))


def audit_document(relative: str, text: str) -> list[str]:
    """Report every private tracker ID cited by `relative`."""
    failures: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        for match in TRACKER_ID.finditer(line):
            failures.append(
                f"{relative}:{number} cites the private tracker ID "
                f"{match.group(0)!r}, which an external reader cannot resolve; "
                "name the thing directly, link the ADR, or cite the PR number"
            )
    return failures


def main() -> int:
    try:
        documents = discover_documents()
    except TrackerIdGuardError as error:
        print(f"public tracker ID check failed: {error}", file=sys.stderr)
        return 1

    failures = [
        failure
        for relative, text in documents.items()
        for failure in audit_document(relative, text)
    ]
    if failures:
        for failure in failures:
            print(f"public tracker ID check failed: {failure}", file=sys.stderr)
        return 1

    print(
        f"public tracker ID check passed: {len(documents)} public documents "
        "cite no private tracker IDs"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
