#!/usr/bin/env python3
"""Validate that a dev-image build consumed only cached dependencies."""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

COOK_COMMAND = "cargo chef cook --workspace --profile ci --recipe-path recipe.json"
BUILD_COMMAND = "cargo build --workspace --profile ci"
STEP_HEADER = re.compile(
    r"^(?P<id>#\d+) \[(?P<label>[^]]+)] RUN (?P<command>.*)$", re.MULTILINE
)


def _workspace_crates(root: Path) -> set[str]:
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    manifests = [root / "Cargo.toml"]
    for member in manifest["workspace"]["members"]:
        manifests.extend(root.glob(f"{member}/Cargo.toml"))
    crates = set()
    for path in manifests:
        package = tomllib.loads(path.read_text()).get("package")
        if package:
            crates.add(package["name"])
    return crates


def _step(log: str, stage: str, command: str) -> tuple[str, list[str]] | None:
    for match in STEP_HEADER.finditer(log):
        label = match.group("label").split()
        if stage in label and command in match.group("command"):
            step_id = match.group("id")
            lines = [
                line for line in log.splitlines() if line.startswith(f"{step_id} ")
            ]
            return step_id, lines
    return None


def validate_log(log: str, workspace_crates: set[str]) -> list[str]:
    errors: list[str] = []
    cook = _step(log, "builder-deps", COOK_COMMAND)
    if cook is None:
        errors.append("dependency cook step is missing")
    elif not any(re.fullmatch(rf"{re.escape(cook[0])} CACHED", line) for line in cook[1]):
        errors.append("dependency cook was not restored from cache")

    source = _step(log, "builder", BUILD_COMMAND)
    if source is None:
        errors.append("workspace source-build step is missing")
        return errors
    step_id, lines = source
    if any(re.fullmatch(rf"{re.escape(step_id)} CACHED", line) for line in lines):
        errors.append("workspace source-build step was cached instead of executed")
    if not any(line.startswith(f"{step_id} DONE ") for line in lines):
        errors.append("workspace source-build step did not complete")

    compiled = []
    for line in lines:
        match = re.search(r"\bCompiling ([\w-]+) v", line)
        if match:
            compiled.append(match.group(1))
    workspace_compiles = [crate for crate in compiled if crate in workspace_crates]
    external_compiles = [crate for crate in compiled if crate not in workspace_crates]
    if not workspace_compiles:
        errors.append("workspace source build compiled no workspace crates")
    if external_compiles:
        errors.append(
            "workspace source build recompiled external crates: "
            + ", ".join(sorted(set(external_compiles)))
        )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "log", nargs="?", type=Path, help="plain BuildKit log; stdin if omitted"
    )
    parser.add_argument("--workspace-root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    log = args.log.read_text() if args.log else sys.stdin.read()
    errors = validate_log(log, _workspace_crates(args.workspace_root))
    if errors:
        print("CI image cache-handoff validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("CI image cache-handoff validation OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
