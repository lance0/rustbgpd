#!/usr/bin/env python3
"""Require release notes for emitted Prometheus family additions and removals.

The baseline is the newest release tag reachable from HEAD, and its family
inventory comes from that tag's tree, read with that tag's own
`check-metric-consumers.py`. The notes are every `CHANGELOG.md` entry above
that release's heading, plus every pending `changelog.d/` fragment. Nothing
here names a release, so cutting a tag needs no edit to this checker.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parents[1]
CHANGELOG = ROOT / "CHANGELOG.md"
RELEASE_TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")

# Exceptions are deliberately source-controlled and empty by default. A metric
# may be added here only with a specific public-contract reason; stale, unknown,
# or already-documented exceptions fail closed.
RELEASE_NOTE_EXCEPTIONS: dict[str, str] = {}


def load_script(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


METRIC_CHECK = load_script(ROOT / "scripts/check-metric-consumers.py", "metric_consumer_contract")
ASSEMBLER = load_script(ROOT / "scripts/assemble-changelog.py", "assemble_changelog")


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=root, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise ValueError(f"git {' '.join(args)}: {result.stderr.strip()}")
    return result.stdout


def previous_release(root: Path = ROOT) -> str:
    """Return the highest strict `vMAJOR.MINOR.PATCH` tag reachable from HEAD.

    Pre-release and other tags are ignored, and so is any release tag HEAD does
    not contain. With none left (a shallow or tagless checkout) the check fails
    closed rather than guessing a baseline.
    """
    versions = [
        (tuple(map(int, match.groups())), tag)
        for tag in git(root, "tag", "--merged", "HEAD", "--list", "v*").split()
        if (match := RELEASE_TAG.fullmatch(tag))
    ]
    if not versions:
        raise ValueError(
            "no vMAJOR.MINOR.PATCH release tag is reachable from HEAD; "
            "the check needs history and release tags"
        )
    return max(versions)[1]


def release_inventory(tag: str, root: Path = ROOT) -> set[str]:
    """Return the families `tag` shipped, as that release's own parser saw them."""
    with tempfile.TemporaryDirectory() as scratch:
        tree = Path(scratch) / "tree"
        git(root, "worktree", "add", "--quiet", "--detach", str(tree), f"{tag}^{{commit}}")
        try:
            module = load_script(
                tree / "scripts/check-metric-consumers.py", f"metric_consumer_contract_{tag}"
            )
            return set(module.workspace_metric_inventory())
        finally:
            git(root, "worktree", "remove", "--force", str(tree))


def notes_since(changelog: str, release: str) -> str:
    """Return every CHANGELOG entry written after `release`: the text above its heading.

    On a release commit that includes the new, not yet tagged version section;
    afterwards it is `[Unreleased]` alone. The release's own section and every
    older one are excluded, so they cannot document a later change.
    """
    version = release.removeprefix("v")
    headings = list(
        re.finditer(rf"^## \[{re.escape(version)}\][^\n]*$", changelog, re.MULTILINE)
    )
    if len(headings) != 1:
        raise ValueError(
            f"expected one CHANGELOG section for {version}, found {len(headings)}"
        )
    return changelog[: headings[0].start()]


def target_notes(changelog: str, root: Path, release: str) -> str:
    """The notes under review: entries since `release` plus every pending fragment.

    A fragment under `changelog.d/` becomes an `[Unreleased]` entry at release
    preparation, so a note there documents the family as well as one already in
    the section. A malformed fragment fails here, before release preparation.
    """
    notes = notes_since(changelog, release)
    return notes + "".join(fragment.body for fragment in ASSEMBLER.load_fragments(root))


def metric_delta(
    baseline: set[str], current: set[str]
) -> tuple[set[str], set[str]]:
    """Return family additions and removals; a rename appears in both sets."""
    return current - baseline, baseline - current


def validate_release_notes(
    baseline: set[str],
    current: set[str],
    section: str,
    exceptions: dict[str, str] | None = None,
) -> tuple[set[str], set[str]]:
    added, removed = metric_delta(baseline, current)
    changed = added | removed
    documented = set(METRIC_CHECK.METRIC_TOKEN.findall(section))
    exceptions = RELEASE_NOTE_EXCEPTIONS if exceptions is None else exceptions

    unknown = set(exceptions) - changed
    if unknown:
        raise ValueError(
            "metric release-note exceptions are stale or not changed: "
            + ", ".join(sorted(unknown))
        )
    empty_reasons = sorted(
        name
        for name, reason in exceptions.items()
        if not isinstance(reason, str) or len(reason.strip()) < 20
    )
    if empty_reasons:
        raise ValueError(
            "metric release-note exceptions need specific reasons: "
            + ", ".join(empty_reasons)
        )
    redundant = set(exceptions) & documented
    if redundant:
        raise ValueError(
            "metric release-note exceptions are now documented and must be removed: "
            + ", ".join(sorted(redundant))
        )

    missing = changed - documented - set(exceptions)
    if missing:
        missing_added = sorted(missing & added)
        missing_removed = sorted(missing & removed)
        details: list[str] = []
        if missing_added:
            details.append("added=" + ", ".join(missing_added))
        if missing_removed:
            details.append("removed=" + ", ".join(missing_removed))
        raise ValueError(
            "release notes since the previous release omit changed metric families: "
            + "; ".join(details)
        )
    return added, removed


def main() -> int:
    try:
        release = previous_release()
        baseline = release_inventory(release)
        current = set(METRIC_CHECK.workspace_metric_inventory())
        notes = target_notes(CHANGELOG.read_text(encoding="utf-8"), ROOT, release)
        added, removed = validate_release_notes(baseline, current, notes)
    except (OSError, ValueError) as error:
        print(f"metric release-note check: {error}", file=sys.stderr)
        return 1
    print(
        f"metric release-note check: {release} -> HEAD: {len(added)} added, "
        f"{len(removed)} removed; all changed families documented"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
