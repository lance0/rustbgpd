#!/usr/bin/env python3
"""Require release notes for emitted Prometheus family additions and removals."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
import tomllib
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parents[1]
BASELINE_RELEASE = "v0.66.0"
BASELINE_COMMIT = "5873768daaeb197d7b5a7f531efd7feb5535e258"
TARGET_RELEASE = "0.67.0"
BASELINE = ROOT / "scripts/fixtures/metric-release-notes/v0.66.0.json"
CHANGELOG = ROOT / "CHANGELOG.md"
CARGO_MANIFEST = ROOT / "Cargo.toml"
METRIC_NAME = re.compile(r"[A-Za-z_:][A-Za-z0-9_:]*")

# Exceptions are deliberately source-controlled and empty by default. A metric
# may be added here only with a specific public-contract reason; stale, unknown,
# or already-documented exceptions fail closed.
RELEASE_NOTE_EXCEPTIONS: dict[str, str] = {}


def load_metric_checker() -> ModuleType:
    path = ROOT / "scripts/check-metric-consumers.py"
    spec = importlib.util.spec_from_file_location("metric_consumer_contract", path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load metric inventory checker {path.relative_to(ROOT)}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


METRIC_CHECK = load_metric_checker()


def parse_baseline(text: str) -> set[str]:
    """Parse the pinned released-family manifest without consulting git history."""
    try:
        document = json.loads(text)
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid metric baseline JSON: {error.msg}") from error
    if not isinstance(document, dict) or set(document) != {
        "release",
        "source_commit",
        "families",
    }:
        raise ValueError(
            "metric baseline must contain only release, source_commit, and families"
        )
    if document["release"] != BASELINE_RELEASE:
        raise ValueError(
            f"metric baseline release must be {BASELINE_RELEASE}, "
            f"got {document['release']!r}"
        )
    if document["source_commit"] != BASELINE_COMMIT:
        raise ValueError(
            f"metric baseline commit must be {BASELINE_COMMIT}, "
            f"got {document['source_commit']!r}"
        )
    families = document["families"]
    if not isinstance(families, list) or not families:
        raise ValueError("metric baseline families must be a nonempty list")
    if any(
        not isinstance(name, str) or METRIC_NAME.fullmatch(name) is None
        for name in families
    ):
        raise ValueError("metric baseline contains an invalid family name")
    if families != sorted(set(families)):
        raise ValueError("metric baseline families must be sorted and unique")
    return set(families)


def workspace_version(manifest: bytes) -> str:
    try:
        version = tomllib.loads(manifest.decode("utf-8"))["workspace"]["package"][
            "version"
        ]
    except (KeyError, TypeError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ValueError("cannot read workspace package version") from error
    if not isinstance(version, str) or re.fullmatch(r"\d+\.\d+\.\d+", version) is None:
        raise ValueError(f"workspace package version is not a release version: {version!r}")
    return version


def validate_target_release(version: str) -> None:
    if version != TARGET_RELEASE:
        raise ValueError(
            f"workspace release changed from {TARGET_RELEASE} to {version}; roll the "
            "metric baseline and target release together"
        )


def release_section(changelog: str, version: str) -> str:
    """Return exactly one versioned changelog section, excluding adjacent releases."""
    header = re.compile(rf"^## \[{re.escape(version)}\](?:[^\n]*)$", re.MULTILINE)
    matches = list(header.finditer(changelog))
    if len(matches) != 1:
        raise ValueError(
            f"expected one CHANGELOG section for {version}, found {len(matches)}"
        )
    start = matches[0].end()
    following = re.search(r"^## \[[^\]\n]+\](?:[^\n]*)$", changelog[start:], re.MULTILINE)
    end = len(changelog) if following is None else start + following.start()
    section = changelog[start:end]
    if not section.strip():
        raise ValueError(f"CHANGELOG section for {version} is empty")
    return section


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
            "current release CHANGELOG section omits changed metric families: "
            + "; ".join(details)
        )
    return added, removed


def main() -> int:
    try:
        baseline = parse_baseline(BASELINE.read_text(encoding="utf-8"))
        current = set(METRIC_CHECK.workspace_metric_inventory())
        version = workspace_version(CARGO_MANIFEST.read_bytes())
        validate_target_release(version)
        section = release_section(CHANGELOG.read_text(encoding="utf-8"), version)
        added, removed = validate_release_notes(baseline, current, section)
    except (OSError, ValueError) as error:
        print(f"metric release-note check: {error}", file=sys.stderr)
        return 1
    print(
        "metric release-note check: "
        f"{BASELINE_RELEASE} -> v{version}: {len(added)} added, "
        f"{len(removed)} removed; all changed families documented"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
