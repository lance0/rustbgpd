#!/usr/bin/env python3
"""Run locally the checks that otherwise first fail on a release commit.

Hosted CI is where a release commit usually meets these for the first time,
some of them only after the tag is pushed:

  - the metric release-note contract (`public-docs-contract.yml`);
  - the published-crate README freshness gate (`ci.yml`), which hosted CI
    diffs against the pull request base or the pushed range. Here the base is
    `git merge-base origin/main HEAD`, or `--base`;
  - each independently versioned crate whose manifest is ahead of
    `docs/reference/published-crate-versions.json`: its `CHANGELOG.md` must
    open with that version, and on a release commit the heading must be dated
    and the crate README must no longer call the version prepared;
  - on a release commit, the root `CHANGELOG.md` section that `release.yml`
    extracts for the workspace version.

The mode is `release` when the root `[Unreleased]` section is empty (it was
rolled into a version section) and `staging` otherwise; `--mode` overrides the
detection. Release-only checks are reported as skipped in staging mode, never
relaxed. `--heavy` adds the advisory audit, the release build, and the
multi-package publish dry-run.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RECORD = "docs/reference/published-crate-versions.json"
# The two wordings the release checklist names for a not-yet-published version.
PREPARED_PHRASES = ("prepared in the source checkout", "source checkout prepares")
SECTION = re.compile(r"(?m)^## \[[^\]\n]+\][^\n]*$")
DATE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")


class PreflightError(Exception):
    """The tree cannot be inspected, as opposed to failing a check."""


def read(root: Path, relative: str) -> str:
    try:
        return (root / relative).read_text(encoding="utf-8")
    except OSError as error:
        raise PreflightError(f"cannot read {relative}: {error.strerror}") from error


def section_body(changelog: str, name: str) -> str | None:
    """Return the body under `## [name]`, as `release.yml` extracts it."""
    heading = re.search(rf"(?m)^## \[{re.escape(name)}\][^\n]*$", changelog)
    if heading is None:
        return None
    rest = changelog[heading.end() :]
    following = SECTION.search(rest)
    return rest if following is None else rest[: following.start()]


def detect_mode(changelog: str) -> str:
    return "staging" if (section_body(changelog, "Unreleased") or "").strip() else "release"


def workspace_version(root: Path) -> str:
    try:
        return tomllib.loads(read(root, "Cargo.toml"))["workspace"]["package"]["version"]
    except (KeyError, TypeError, tomllib.TOMLDecodeError) as error:
        raise PreflightError("cannot read [workspace.package] version") from error


def publishable_crates(root: Path) -> dict[str, tuple[str, str]]:
    """Map crate directory name to (package name, version), as semver-checks derives it."""
    crates = {}
    for manifest in sorted(root.glob("crates/*/Cargo.toml")):
        try:
            package = tomllib.loads(manifest.read_text(encoding="utf-8"))["package"]
            if "publish" not in package:
                crates[manifest.parent.name] = (package["name"], package["version"])
        except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError) as error:
            raise PreflightError(f"cannot read {manifest.relative_to(root)}") from error
    if not crates:
        raise PreflightError("no publishable crate found under crates/")
    return crates


def pending_crates(root: Path) -> dict[str, tuple[str, str]]:
    """Return the publishable crates whose manifest differs from the published record."""
    try:
        record = json.loads(read(root, RECORD))
    except json.JSONDecodeError as error:
        raise PreflightError(f"{RECORD} is not valid JSON") from error
    crates = publishable_crates(root)
    if not isinstance(record, dict) or set(record) != set(crates):
        raise PreflightError(
            f"{RECORD} must list exactly the publishable crates {sorted(crates)}"
        )
    return {crate: meta for crate, meta in crates.items() if meta[1] != record[crate]}


def command_errors(root: Path, argv: list[str]) -> list[str]:
    result = subprocess.run(argv, cwd=root, check=False)
    shown = " ".join(argv[1:] if argv[0] == sys.executable else argv)
    return [] if result.returncode == 0 else [f"`{shown}` exited {result.returncode}"]


def metric_release_note_errors(root: Path) -> list[str]:
    return command_errors(
        root, [sys.executable, "-m", "unittest", "scripts/test_check_metric_release_notes.py"]
    ) + command_errors(root, [sys.executable, "scripts/check_metric_release_notes.py"])


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=root, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise PreflightError(f"git {' '.join(args)}: {result.stderr.strip()}")
    return result.stdout


def diff_base(root: Path, base: str | None) -> str:
    if base is not None:
        return git(root, "rev-parse", "--verify", f"{base}^{{commit}}").strip()
    try:
        return git(root, "merge-base", "origin/main", "HEAD").strip()
    except PreflightError as error:
        raise PreflightError(f"{error}; pass --base <commit>") from error


def readme_freshness_errors(root: Path, base: str) -> list[str]:
    """Mirror ci.yml's "Published crate README freshness gate" for `base...HEAD`."""
    errors = []
    for crate in publishable_crates(root):
        manifest = git(root, "diff", f"{base}...HEAD", "--", f"crates/{crate}/Cargo.toml")
        if re.search(r"(?m)^\+version\s*=", manifest) and not git(
            root, "diff", f"{base}...HEAD", "--", f"crates/{crate}/README.md"
        ):
            errors.append(
                f"crates/{crate}/Cargo.toml bumps the version since {base[:12]} but "
                f"crates/{crate}/README.md is untouched; hosted CI rejects that diff"
            )
    return errors


def crate_heading_errors(root: Path, pending: dict[str, tuple[str, str]]) -> list[str]:
    errors = []
    for crate, (_, version) in pending.items():
        heading = top_heading(root, crate)
        if not re.match(rf"## \[?{re.escape(version)}\]?(?:\s|$)", heading):
            errors.append(
                f"crates/{crate}/CHANGELOG.md opens with {heading!r}, not the "
                f"manifest version {version}"
            )
    return errors


def top_heading(root: Path, crate: str) -> str:
    changelog = read(root, f"crates/{crate}/CHANGELOG.md")
    return next((line for line in changelog.splitlines() if line.startswith("## ")), "")


def crate_release_errors(root: Path, pending: dict[str, tuple[str, str]]) -> list[str]:
    errors = []
    for crate in pending:
        heading = top_heading(root, crate)
        if "unreleased" in heading.casefold() or not DATE.search(heading):
            errors.append(
                f"crates/{crate}/CHANGELOG.md heading {heading!r} needs the release "
                "date in place of `Unreleased`"
            )
        readme = " ".join(read(root, f"crates/{crate}/README.md").split()).casefold()
        for phrase in PREPARED_PHRASES:
            if phrase in readme:
                errors.append(
                    f"crates/{crate}/README.md still says {phrase!r}; it is the "
                    "crates.io landing page for the version about to publish"
                )
    return errors


def root_changelog_errors(root: Path) -> list[str]:
    version = workspace_version(root)
    body = section_body(read(root, "CHANGELOG.md"), version)
    if body is None:
        return [
            f"CHANGELOG.md has no `## [{version}]` heading (no leading `v`); "
            "release.yml fails closed after the tag is pushed"
        ]
    return [] if body.strip() else [f"CHANGELOG.md section `## [{version}]` is empty"]


def heavy_commands(pending: dict[str, tuple[str, str]]) -> list[list[str]]:
    lock = ["bash", "scripts/build-lock.sh"]
    # The build is release.yml's, for the host target only.
    build = "cargo build --locked --workspace --release --features rustbgpd/jemalloc"
    commands = [["cargo", "audit"], [*lock, *build.split()]]
    if pending:
        # Only versions ahead of the registry can be published; together, so a
        # dependent resolves a wire version that is not registry-visible yet.
        packages = [arg for name, _ in pending.values() for arg in ("-p", name)]
        commands.append(
            [*lock, "cargo", "publish", "--locked", "--dry-run", "--all-features", *packages]
        )
    return commands


def preflight(
    root: Path, mode: str, base: str | None, heavy: bool
) -> tuple[str, list[tuple[str, str, list[str]]]]:
    """Return the resolved mode and one (status, check, errors) row per check."""
    if mode == "auto":
        mode = detect_mode(read(root, "CHANGELOG.md"))
    release = mode == "release"
    pending = pending_crates(root)
    named = ", ".join(f"{crate} {meta[1]}" for crate, meta in pending.items()) or "none"
    base = diff_base(root, base)
    head = git(root, "rev-parse", "HEAD").strip()
    span = "no commits to compare" if base == head else f"{base[:12]}...HEAD"
    checks = [
        ("metric release notes", True, lambda: metric_release_note_errors(root)),
        (
            f"published-crate README freshness ({span})",
            True,
            lambda: readme_freshness_errors(root, base),
        ),
        (
            f"pending crate changelog headings ({named})",
            True,
            lambda: crate_heading_errors(root, pending),
        ),
        (
            f"pending crate changelog dates and README wording ({named})",
            release,
            lambda: crate_release_errors(root, pending),
        ),
        (
            f"root CHANGELOG section for workspace {workspace_version(root)}",
            release,
            lambda: root_changelog_errors(root),
        ),
    ]
    rows = []
    for name, enabled, check in checks:
        errors = check() if enabled else []
        status = "FAIL" if errors else "ok" if enabled else "skipped [release-only]"
        rows.append((status, name, errors))
    for command in heavy_commands(pending):
        name = " ".join(command[2:] if command[0] == "bash" else command)
        errors = command_errors(root, command) if heavy else []
        rows.append(("FAIL" if errors else "ok" if heavy else "skipped [--heavy]", name, errors))
    return mode, rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--mode", choices=("auto", "staging", "release"), default="auto")
    parser.add_argument("--base", help="diff base for the README freshness check")
    parser.add_argument("--heavy", action="store_true", help="also audit, build, and dry-run")
    parser.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        mode, rows = preflight(args.root, args.mode, args.base, args.heavy)
    except PreflightError as error:
        print(f"release preflight: {error}", file=sys.stderr)
        return 1
    print(f"release preflight: mode={mode}" + (" (detected)" if args.mode == "auto" else ""))
    for status, name, errors in rows:
        print(f"  {status}: {name}", flush=True)
        for error in errors:
            print(f"      {error}", file=sys.stderr)
    failed = sum(status == "FAIL" for status, _, _ in rows)
    skipped = sum(status.startswith("skipped [release") for status, _, _ in rows)
    if skipped:
        print(
            f"release preflight: {skipped} release-only checks skipped; "
            "use --mode release on the release commit"
        )
    print(f"release preflight: {'FAILED' if failed else 'passed'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
