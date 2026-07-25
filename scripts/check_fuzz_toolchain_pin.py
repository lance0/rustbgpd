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
# `dtolnay/rust-toolchain@master` plus an expression-valued `toolchain:` input
# is the sanctioned workflow form; `cargo "+$var"` is a pin-derived selector.
VIOLATION_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"dtolnay/rust-toolchain@(?!master(?:\b|$))\S+"),
        "selects a toolchain in the action ref; use "
        "dtolnay/rust-toolchain@master and pass the pinned value as its "
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
)


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
    if PIN_PATH not in text:
        failures.append(
            f"{relative} selects a Rust toolchain for fuzzing but no longer "
            f"reads {PIN_PATH}"
        )
    for number, line in enumerate(text.splitlines(), start=1):
        for pattern, reason in VIOLATION_RULES:
            match = pattern.search(line)
            if match:
                failures.append(f"{relative}:{number} {reason}: {match.group(0)!r}")
    return failures


def main() -> int:
    try:
        consumers = discover_consumers()
    except PinGuardError as error:
        print(f"fuzz toolchain pin check failed: {error}", file=sys.stderr)
        return 1

    failures = [
        failure
        for relative, text in consumers.items()
        for failure in audit_consumer(relative, text)
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
