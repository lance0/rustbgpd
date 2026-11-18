#!/usr/bin/env python3
"""Fail closed when a fuzz-toolchain consumer stops reading the reviewed pin.

`fuzz/rust-nightly.txt` names the single reviewed nightly. The scheduled
campaign, the OSS-Fuzz image, and the ClusterFuzzLite image all install from
it. Nothing else stops an edit from reintroducing a floating toolchain, and
the regression stays invisible until an upstream compiler break takes the
campaign down and the failure reads as if it came from this repository.

Consumers are discovered from the tracked tree rather than a maintained list,
so a fourth integration is covered the day it lands instead of passing
vacuously. An empty discovery set is itself a failure: a guard that cannot
fail is worse than no guard.

Every tracked file that runs `cargo fuzz build` or `cargo fuzz run`, whether
or not it selects a toolchain, must run `fuzz/seed-fuzz-lockfiles.sh` earlier
in the file. The fuzz crates are separate workspaces with no tracked
lockfile, so without the seed every build takes the newest release of every
dependency, and one that needs a newer std than the pin breaks the campaign
the same way a floating compiler does. The seed script owns the source,
destination and coverage; this check owns that a line invokes it as a
command before the first build. It compares line order within a file, so it
does not prove the seed and the build share a workflow step or recipe, that
the invocation is unconditional (an `if` or a `false &&` guard still passes),
or that the seed precedes other resolving commands such as `cargo fetch`.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PIN_PATH = "fuzz/rust-nightly.txt"

# Prose cannot install a toolchain, and the pin file is the source of truth
# rather than a consumer of it.
SKIPPED_SUFFIXES = frozenset({".md"})

# This guard and its mutation proofs quote sample toolchain selections as
# data. They describe consumers instead of being ones, so they are the only
# paths exempt from discovery.
SKIPPED_PATHS = frozenset(
    {
        PIN_PATH,
        "scripts/check_fuzz_toolchain_pin.py",
        "scripts/test_check_fuzz_toolchain_pin.py",
    }
)

# A consumer is a file that both lives on a fuzzing path and selects a Rust
# toolchain. Either signal alone sweeps in inventory checks and unrelated
# build scripts.
FUZZ_MARKER = re.compile(r"cargo[-\s]+fuzz")
TOOLCHAIN_MARKERS = (
    re.compile(r"RUSTUP_TOOLCHAIN"),
    re.compile(r"rustup\s+toolchain\s+install"),
    re.compile(r"dtolnay/rust-toolchain"),
    re.compile(r"""cargo\s+["']?\+"""),
)

# Each rule matches a toolchain selection that does not come from the pin.
# A SHA-pinned `dtolnay/rust-toolchain` plus an expression-valued input is
# the sanctioned workflow form; `cargo "+$var"` is a pin-derived selector.
VIOLATION_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"dtolnay/rust-toolchain@(?![0-9a-f]{40}(?:\s|$))\S+"),
        "selects an unpinned action or a toolchain in the action ref; use "
        "a full commit SHA and pass the pinned value as its "
        "toolchain input",
    ),
    (
        re.compile(r"^\s*toolchain:[ \t]*(?!\$\{\{)\S+"),
        f"hardcodes a toolchain input; pass the value read from {PIN_PATH}",
    ),
    (
        re.compile(r"""cargo\s+["']?\+(?!\$)[^\s"']+"""),
        "overrides the pin with an explicit cargo toolchain selector; export "
        f"RUSTUP_TOOLCHAIN from {PIN_PATH} instead",
    ),
    (
        re.compile(r"nightly-\d{4}-\d{2}-\d{2}"),
        f"hardcodes a nightly date; read it from {PIN_PATH}",
    ),
    (
        re.compile(
            r"""\b(?:toolchain\s*[=:]|RUSTUP_TOOLCHAIN(?:\s*[=:]|\s))"""
            r"""\s*["']?nightly\b"""
        ),
        f"assigns a floating nightly; read the toolchain from {PIN_PATH}",
    ),
)

SEED_SCRIPT = "fuzz/seed-fuzz-lockfiles.sh"
# The seed script must be the command word: at the start of a line (bare, as
# a workflow `run:` value, or after a Dockerfile `RUN`) or after `&&`, `||`,
# `;` or `(`, optionally through `bash`/`sh` and a `$var/` root prefix. A step
# name, an `echo`, or any other argument position does not run it.
SEED_INVOCATION = re.compile(
    r"""(?:^\s*(?:-\s+)?(?:run:\s*|RUN\s+)?|(?:&&|\|\||;|\()\s*)"""
    r"""(?:(?:ba)?sh\s+)?"?(?:\$\{?\w+\}?/)?"""
    + re.escape(SEED_SCRIPT)
    + r""""?(?=\s|$|[;&|)])"""
)
# Any toolchain selector may sit between `cargo` and `fuzz`, including one
# with spaces such as `"+$(cat fuzz/rust-nightly.txt)"`.
FUZZ_BUILD = re.compile(r"\bcargo\b.*\bfuzz\s+(?:build|run)\b")
# Python sources quote fuzz commands as checker data rather than running them.
BUILD_SKIPPED_SUFFIXES = SKIPPED_SUFFIXES | {".py"}


def strip_comment(line: str) -> str:
    """Drop a shell, YAML, Dockerfile, or justfile `#` comment from `line`.

    A comment that names the pin file does not read it, and one that quotes
    a floating toolchain does not select it. A `#` starts a comment only at
    the start of the line or after whitespace, outside quotes, so `"#"`,
    `$#`, and `${#var}` stay code.
    """
    quote = ""
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
        elif char == "\\" and quote != "'":
            escaped = True
        elif quote:
            if char == quote:
                quote = ""
        elif char in "'\"":
            quote = char
        elif char == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index]
    return line


class PinGuardError(RuntimeError):
    """The fuzz-toolchain consumers could not be enumerated."""


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
        raise PinGuardError(f"cannot list tracked files: {error}")
    if result.returncode != 0:
        detail = result.stderr.strip() or f"git ls-files exited {result.returncode}"
        raise PinGuardError(f"cannot list tracked files: {detail}")
    paths = [ROOT / name for name in result.stdout.split("\0") if name]
    if not paths:
        raise PinGuardError("cannot list tracked files: the tracked tree is empty")
    return paths


def discover_consumers() -> dict[str, str]:
    """Map each discovered fuzz-toolchain consumer to its text."""
    consumers: dict[str, str] = {}
    for path in tracked_files():
        relative = path.relative_to(ROOT).as_posix()
        if relative in SKIPPED_PATHS or path.suffix in SKIPPED_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if not FUZZ_MARKER.search(text):
            continue
        if any(marker.search(text) for marker in TOOLCHAIN_MARKERS):
            consumers[relative] = text
    if not consumers:
        raise PinGuardError(
            "no fuzz-toolchain consumer was discovered, so the walk is broken: "
            "the scheduled campaign and the hosted builder images each select "
            "a Rust toolchain on a fuzzing path"
        )
    return dict(sorted(consumers.items()))


def audit_consumer(relative: str, text: str) -> list[str]:
    """Report every way `relative` stops taking its toolchain from the pin."""
    failures: list[str] = []
    code = [strip_comment(line) for line in text.splitlines()]
    if not any(PIN_PATH in line for line in code):
        failures.append(
            f"{relative} selects a Rust toolchain for fuzzing but no longer "
            f"reads {PIN_PATH}"
        )
    for number, line in enumerate(code, start=1):
        for pattern, reason in VIOLATION_RULES:
            match = pattern.search(line)
            if match:
                failures.append(f"{relative}:{number} {reason}: {match.group(0)!r}")
    return failures


def discover_fuzz_builds() -> dict[str, str]:
    """Map each tracked file that runs `cargo fuzz build|run` to its text.

    Independent of toolchain markers: a helper that inherits the toolchain
    still resolves the fuzz workspace's dependencies.
    """
    builds: dict[str, str] = {}
    for path in tracked_files():
        relative = path.relative_to(ROOT).as_posix()
        if relative in SKIPPED_PATHS or path.suffix in BUILD_SKIPPED_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if any(FUZZ_BUILD.search(strip_comment(line)) for line in text.splitlines()):
            builds[relative] = text
    if not builds:
        raise PinGuardError(
            "no fuzz build path was discovered, so the walk is broken: the "
            "scheduled campaign and the hosted builder script run cargo fuzz"
        )
    return dict(sorted(builds.items()))


def audit_build_path(relative: str, text: str) -> list[str]:
    """Require `SEED_SCRIPT` to run before the file's first fuzz build."""
    code = [strip_comment(line) for line in text.splitlines()]
    first_build = next(
        (index for index, line in enumerate(code) if FUZZ_BUILD.search(line)), None
    )
    if first_build is None:
        return []
    if any(SEED_INVOCATION.search(line) for line in code[:first_build]):
        return []
    return [
        f"{relative}:{first_build + 1} builds fuzz targets without first running "
        f"{SEED_SCRIPT}, so the fuzz workspace resolves unreviewed dependency "
        "versions"
    ]


def main() -> int:
    try:
        consumers = discover_consumers()
        builds = discover_fuzz_builds()
    except PinGuardError as error:
        print(f"fuzz toolchain pin check failed: {error}", file=sys.stderr)
        return 1

    failures = [
        failure
        for relative, text in consumers.items()
        for failure in audit_consumer(relative, text)
    ] + [
        failure
        for relative, text in builds.items()
        for failure in audit_build_path(relative, text)
    ]
    if failures:
        for failure in failures:
            print(f"fuzz toolchain pin check failed: {failure}", file=sys.stderr)
        return 1

    print(
        f"fuzz toolchain pin check passed: {len(consumers)} consumers take the "
        f"toolchain from {PIN_PATH}"
    )
    for relative in consumers:
        print(f"  {relative}")
    print(f"fuzz lockfile seed check passed: {len(builds)} build paths run {SEED_SCRIPT} first")
    for relative in builds:
        print(f"  {relative}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
