#!/usr/bin/env python3
"""Fail when the release build resolves a bench-only feature.

The `bench/scale` harnesses are workspace members that enable
`rustbgpd-transport/bench-internals`, which turns on
`rustbgpd-rib/bench-internals`. A `cargo build --workspace` unifies those
features into the shipped daemon, so the tarball, deb and rpm binaries carry
bench instrumentation and its INFO logs. This check reads the exact
`cargo build ... --release` command from the release workflow, resolves its
features with `cargo tree` for every target, and fails if any package has
`bench-internals` enabled.

It fails closed: a missing or ambiguous build command, a `cargo tree` error,
or output that no longer lists the RIB and transport crates is a failure, not
a pass.
"""

from __future__ import annotations

import argparse
import re
import shlex
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RELEASE_WORKFLOW = ROOT / ".github/workflows/release.yml"
BENCH_FEATURE = "bench-internals"
# Crates that must appear in the resolved graph. If cargo's output format
# changes and nothing parses, the check must not pass vacuously.
REQUIRED_PACKAGES = ("rustbgpd-rib", "rustbgpd-transport")
TREE_FORMAT = "{f}|{p}"


def release_build_args(workflow: str) -> list[str]:
    """Return the package and feature arguments of the release build."""
    commands = [
        match.group(1)
        for match in re.finditer(r"(?m)^\s+run: (cargo build .*)$", workflow)
        if " --release" in match.group(1)
    ]
    if len(commands) != 1:
        raise ValueError(
            f"expected one `cargo build ... --release` run step, found {len(commands)}"
        )
    command = re.sub(r"\s--target \$\{\{[^}]*\}\}", "", commands[0])
    args = shlex.split(command)[2:]
    # `cargo tree` has no profile flags; the profile does not change features.
    return [arg for arg in args if arg != "--release"]


def enabled_features(tree: str) -> dict[str, set[str]]:
    """Map each package name in `cargo tree --format '{f}|{p}'` output to its features."""
    packages: dict[str, set[str]] = {}
    for line in tree.splitlines():
        features, sep, package = line.partition("|")
        if not sep or not package.strip():
            continue
        name = package.split()[0]
        packages.setdefault(name, set()).update(f for f in features.split(",") if f)
    return packages


def violations(packages: dict[str, set[str]]) -> list[str]:
    errors = [
        f"{name} has {BENCH_FEATURE} enabled"
        for name, features in sorted(packages.items())
        if BENCH_FEATURE in features
    ]
    errors += [
        f"{name} missing from cargo tree output; cannot verify its features"
        for name in REQUIRED_PACKAGES
        if name not in packages
    ]
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail when the release build resolves a bench-only feature."
    )
    parser.add_argument("--workflow", type=Path, default=RELEASE_WORKFLOW)
    args = parser.parse_args(argv)
    try:
        build_args = release_build_args(args.workflow.read_text())
    except (OSError, ValueError) as error:
        print(f"release build features: {error}", file=sys.stderr)
        return 1
    command = [
        "cargo", "tree", *build_args,
        "--target", "all", "--edges", "normal",
        "--prefix", "none", "--format", TREE_FORMAT,
    ]
    print("+", shlex.join(command))
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        print("release build features: cargo tree failed", file=sys.stderr)
        return 1
    errors = violations(enabled_features(result.stdout))
    if errors:
        print("release build features failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"release build features OK: no {BENCH_FEATURE} in the shipped package set")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
