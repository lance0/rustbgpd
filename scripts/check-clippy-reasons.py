#!/usr/bin/env python3
"""Require reasons on ratcheted clippy allow/expect attributes."""

from __future__ import annotations

import argparse
import pathlib
import re
import sys


DEFAULT_PATHS = (
    "crates/cli/src",
    "crates/event-history/src",
    "crates/api/src",
    "crates/rib/src",
    "crates/fsm/src",
    "crates/policy/src",
    "crates/rpki/src",
    "crates/evpn/src",
    "crates/transport/src",
    "crates/wire/src",
    "crates/bmp/src",
)
ATTRIBUTE_HEAD = re.compile(r"#!?\[\s*(?:allow|expect)\s*\(")
REASON = re.compile(r"\breason\s*=")


def rust_files(paths: list[pathlib.Path]) -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    for path in paths:
        if path.is_file():
            if path.suffix == ".rs":
                files.append(path)
            continue
        if path.is_dir():
            files.extend(sorted(path.rglob("*.rs")))
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
        default=[pathlib.Path(path) for path in DEFAULT_PATHS],
        help=(
            "Rust files or directories to check "
            f"(default: {', '.join(DEFAULT_PATHS)})"
        ),
    )
    args = parser.parse_args()

    failures: list[str] = []
    for file in rust_files(args.paths):
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
