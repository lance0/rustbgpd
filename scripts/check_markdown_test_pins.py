#!/usr/bin/env python3
"""Keep the list of Markdown files read by Rust tests honest, and select them.

The main CI lane ignores `**/*.md`, so a docs-only change to a file that a
Rust test reads (with `include_str!`, `read_to_string`, a table of paths
joined onto the manifest directory, ...) would otherwise merge without the
test running. `.github/markdown-test-pins.json` records every such file and
the Rust sources that read it; the unfiltered public-docs lane uses it to run
the owning test targets when a change touches a listed file.

Read sites are found by shape, not by call: every whole string literal in a
tracked `.rs` file that names a `.md` path is resolved against the source
file's directory (`include_str!`), its package directory
(`CARGO_MANIFEST_DIR`), and the repository root. Each resolved
(source, Markdown) pair must be classified exactly once in the list, either as
`pinned` (the test reads it) or `not_read` (the literal only mentions the path,
for example an expected error string). A `"*.md"` literal marks a source that
scans every tracked Markdown file; those sources are listed in `all_markdown`.
A new read site, a stale entry, or an unresolved literal fails the check.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIST = Path(".github/markdown-test-pins.json")
MARKDOWN_LITERAL = re.compile(r'"/?([A-Za-z0-9_.][A-Za-z0-9_./-]*\.md)"')
ALL_MARKDOWN_LITERAL = '"*.md"'
MOD_DECLARATION = re.compile(r"^(?:pub(?:\([a-z]+\))?\s+)?mod\s+(\w+)\s*;")


class PinError(Exception):
    """The list or a read site could not be classified."""


def tracked(root: Path, pattern: str) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--", pattern],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise PinError(f"git ls-files {pattern} failed: {result.stderr.decode().strip()}")
    return sorted(path for path in result.stdout.decode().split("\0") if path)


def package_dir(root: Path, source: str) -> str:
    parent = Path(source).parent
    while True:
        manifest = root / parent / "Cargo.toml"
        if manifest.is_file() and "package" in tomllib.loads(manifest.read_text()):
            return parent.as_posix()
        if parent == Path("."):
            raise PinError(f"{source} is not inside a Cargo package")
        parent = parent.parent


def resolve(source: str, package: str, literal: str, markdown: set[str]) -> set[str]:
    candidates = {
        os.path.normpath(os.path.join(base, literal))
        for base in (os.path.dirname(source), package, ".")
    }
    found = candidates & markdown
    if not found and "/" in literal:
        found = {path for path in markdown if path.endswith("/" + literal)}
    return found


def scan(root: Path) -> tuple[dict[tuple[str, str], None], set[str], list[str]]:
    """Return resolved (source, markdown) pairs, all-Markdown scanners, errors."""
    markdown = set(tracked(root, "*.md"))
    pairs: dict[tuple[str, str], None] = {}
    scanners: set[str] = set()
    errors = []
    for source in tracked(root, "*.rs"):
        text = (root / source).read_text(encoding="utf-8")
        if ALL_MARKDOWN_LITERAL in text:
            scanners.add(source)
        literals = sorted(set(MARKDOWN_LITERAL.findall(text)))
        if not literals:
            continue
        package = package_dir(root, source)
        for literal in literals:
            found = resolve(source, package, literal, markdown)
            if not found:
                errors.append(f"{source}: cannot resolve Markdown literal {literal!r}")
            for path in found:
                pairs[(source, path)] = None
    return pairs, scanners, errors


def load_list(root: Path) -> dict:
    return json.loads((root / LIST).read_text(encoding="utf-8"))


def listed_pairs(entries: dict[str, list[str]]) -> set[tuple[str, str]]:
    return {(source, path) for path, sources in entries.items() for source in sources}


def check(root: Path) -> list[str]:
    pairs, scanners, errors = scan(root)
    data = load_list(root)
    pinned = listed_pairs(data.get("pinned", {}))
    not_read = listed_pairs(data.get("not_read", {}))
    found = set(pairs)
    for source, path in sorted(pinned & not_read):
        errors.append(f"{LIST}: {path} read by {source} is both pinned and not_read")
    for source, path in sorted(found - pinned - not_read):
        errors.append(
            f"{source} names {path}, which is not in {LIST}; add it under `pinned` "
            "if the test reads it, or `not_read` if it only mentions the path"
        )
    for source, path in sorted((pinned | not_read) - found):
        errors.append(f"{LIST}: {path} is listed for {source}, which no longer names it")
    listed_scanners = set(data.get("all_markdown", []))
    for source in sorted(scanners - listed_scanners):
        errors.append(
            f"{source} scans every Markdown file but is not in `all_markdown`; prefer a "
            "check in scripts/check_markdown_claims.py so documentation changes compile no Rust"
        )
    for source in sorted(listed_scanners - scanners):
        errors.append(f"{LIST}: all_markdown lists {source}, which no longer scans *.md")
    for source in sorted({source for source, _ in pinned} | listed_scanners):
        try:
            target(root, source)
        except PinError as error:
            errors.append(str(error))
    return errors


def default_modules(text: str) -> set[str]:
    """Return `mod name;` declarations not gated behind a Cargo feature."""
    modules = set()
    attributes: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("#["):
            attributes.append(line)
            continue
        match = MOD_DECLARATION.match(line)
        if match and not any("feature" in attribute for attribute in attributes):
            modules.add(match.group(1))
        attributes = []
    return modules


def target(root: Path, source: str) -> tuple[str, str]:
    """Return (package name, cargo test target selector) compiling `source`."""
    package = package_dir(root, source)
    manifest = tomllib.loads((root / package / "Cargo.toml").read_text())
    name = manifest["package"]["name"]
    parts = Path(source).relative_to(package).parts
    if len(parts) == 2 and parts[0] == "tests":
        return name, f"--test {Path(parts[1]).stem}"
    if parts[0] != "src" or len(parts) < 2:
        raise PinError(f"{source}: cannot derive the cargo test target")
    top = Path(parts[1]).stem
    lib = root / package / "src/lib.rs"
    has_main = (root / package / "src/main.rs").is_file()
    if top != "main" and (
        not has_main or (lib.is_file() and top in default_modules(lib.read_text()))
    ):
        return name, "--lib"
    if not has_main:
        raise PinError(f"{source}: cannot derive the cargo test target")
    bins = [b["name"] for b in manifest.get("bin", []) if b.get("path") == "src/main.rs"]
    return name, f"--bin {bins[0] if bins else name}"


def select(root: Path, changed: list[str]) -> list[str]:
    """Return one `cargo test` argument line per package for the changed paths."""
    data = load_list(root)
    pinned = data.get("pinned", {})
    sources = {source for path in changed for source in pinned.get(path, [])}
    if any(path.endswith(".md") for path in changed):
        sources.update(data.get("all_markdown", []))
    selectors: dict[str, set[str]] = {}
    for source in sources:
        name, selector = target(root, source)
        selectors.setdefault(name, set()).add(selector)
    return [f"-p {name} {' '.join(sorted(selectors[name]))}" for name in sorted(selectors)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--select",
        action="store_true",
        help="read changed paths on stdin and print the cargo test arguments to run",
    )
    args = parser.parse_args()
    try:
        if args.select:
            for line in select(ROOT, sys.stdin.read().splitlines()):
                print(line)
            return 0
        errors = check(ROOT)
    except PinError as error:
        errors = [str(error)]
    if errors:
        print("\n".join(f"markdown test pin check failed: {e}" for e in errors), file=sys.stderr)
        return 1
    print(f"markdown test pin check passed: {LIST} matches every Rust Markdown read site")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
