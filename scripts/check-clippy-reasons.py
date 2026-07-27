#!/usr/bin/env python3
"""Require reasons on ratcheted clippy allow/expect attributes."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys


ATTRIBUTE_HEAD = re.compile(r"#!?\[\s*(?:allow|expect)\s*\(")
REASON = re.compile(r"\breason\s*=")


def workspace_source_roots(repo: pathlib.Path) -> list[pathlib.Path]:
    """Return all workspace package source directories from Cargo metadata.

    Target source paths, rather than a maintained crate list, include the daemon,
    every workspace crate, tools, and workspace benchmark packages as they are
    added. Test and bench targets are deliberately excluded: this ratchet covers
    production source trees, while their owning package's ``src`` tree remains in
    scope.
    """
    result = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=repo,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or "cargo exited without an error message"
        raise RuntimeError(f"cargo metadata failed:\n{detail}")
    metadata = json.loads(result.stdout)
    workspace_members = set(metadata["workspace_members"])
    roots: set[pathlib.Path] = set()
    for package in metadata["packages"]:
        if package["id"] not in workspace_members:
            continue
        package_dir = pathlib.Path(package["manifest_path"]).parent
        source_dir = package_dir / "src"
        for target in package["targets"]:
            if set(target["kind"]).isdisjoint({"test", "bench", "example"}):
                source_path = pathlib.Path(target["src_path"])
                roots.add(source_dir if source_path.is_relative_to(source_dir) else source_path)
    return sorted(roots)


def rust_files(paths: list[pathlib.Path]) -> list[pathlib.Path]:
    files: set[pathlib.Path] = set()
    for path in paths:
        if path.is_file():
            if path.suffix == ".rs":
                files.add(path)
            continue
        if path.is_dir():
            files.update(path.rglob("*.rs"))
    return sorted(files)


def find_attribute_end(text: str, start: int) -> int | None:
    in_string = False
    escaped = False
    depth = 0
    body_start = start + (3 if text.startswith("#![", start) else 2)
    for idx in range(body_start, len(text)):
        ch = text[idx]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
        elif ch in "([":
            depth += 1
        elif ch == ")":
            depth = max(depth - 1, 0)
        elif ch == "]":
            if depth == 0:
                return idx
            depth -= 1
    return None


def missing_reasons(path: pathlib.Path) -> list[tuple[int, str]]:
    text = path.read_text(encoding="utf-8")
    misses: list[tuple[int, str]] = []
    offset = 0
    while True:
        match = ATTRIBUTE_HEAD.search(text, offset)
        if match is None:
            break
        start = match.start()
        end = find_attribute_end(text, start)
        if end is None:
            line = text.count("\n", 0, start) + 1
            misses.append((line, "unterminated clippy allow/expect attribute"))
            break
        attr = text[start : end + 1]
        if "clippy::" in attr and REASON.search(attr) is None:
            line = text.count("\n", 0, start) + 1
            first_line = attr.splitlines()[0].strip()
            misses.append((line, first_line))
        offset = end + 1
    return misses


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Require reason = \"...\" on ratcheted clippy allow/expect attributes."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=pathlib.Path,
        default=None,
        help="Rust files or directories to check (default: Cargo workspace production roots)",
    )
    args = parser.parse_args()

    try:
        paths = args.paths or workspace_source_roots(pathlib.Path.cwd())
    except RuntimeError as error:
        print(error, file=sys.stderr)
        return 2

    failures: list[str] = []
    for file in rust_files(paths):
        for line, attr in missing_reasons(file):
            failures.append(f"{file}:{line}: missing reason on {attr}")

    if failures:
        print("clippy allow/expect attributes in ratcheted paths need reason = \"...\":")
        for failure in failures:
            print(f"  {failure}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
