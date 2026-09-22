#!/usr/bin/env python3
"""Merge the per-change fragments under `changelog.d/` into `CHANGELOG.md`.

Every pull request that changes something user-visible adds one Markdown file
to `changelog.d/` instead of editing the `[Unreleased]` section, so concurrent
branches never conflict on the changelog. Release preparation runs this script
once: the fragments are grouped by category in the changelog's fixed category
order, sorted by file name inside a category, appended after the entries the
`[Unreleased]` section already holds, and deleted. The result is an ordinary
reviewed `[Unreleased]` section, which the release commit then rolls into the
version section that `release.yml` extracts.

A fragment is `### <Category>` on its first line, then one or more `- ` bullets
in the changelog's hard-wrapped style; continuation lines are indented by two
spaces and are kept byte-for-byte, except that a link target written relative
to `changelog.d/` (`](../docs/...)`) loses its leading `../` so it resolves from
the root `CHANGELOG.md`. `changelog.d/README.md` documents the format.

The script refuses, naming the file, a fragment whose first line is not a known
category, an empty fragment, a body line that is neither a bullet, a
continuation, nor blank, an unresolved merge-conflict marker, a stray file that
is not a `.md` fragment, and a bullet already present in `[Unreleased]` or in
another fragment. `--check` validates and assembles in memory without writing.
With no fragments present the script changes nothing.

Usage:
  python3 scripts/assemble-changelog.py            # merge and delete fragments
  python3 scripts/assemble-changelog.py --check    # validate only
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[1]
FRAGMENT_DIR = "changelog.d"
README = "README.md"
CHANGELOG = "CHANGELOG.md"
UNRELEASED = "Unreleased"
# The subsection order of a release section in CHANGELOG.md.
CATEGORIES = (
    "Security",
    "Added",
    "Changed",
    "Removed",
    "Fixed",
    "Documentation",
    "Upgrade notes",
)
SECTION = re.compile(r"(?m)^## \[[^\]\n]+\][^\n]*$")
SUBSECTION = re.compile(r"(?m)^### [^\n]*$")
CONFLICT_MARKER = re.compile(r"(?m)^(?:<{7}|={7}|>{7}|\|{7})(?:\s|$)")
# A link target relative to `changelog.d/`, which becomes root-relative.
FRAGMENT_RELATIVE_LINK = re.compile(r"\]\(\.\./")


class Fragment(NamedTuple):
    name: str
    category: str
    body: str  # the bullets, without surrounding blank lines, newline-terminated


def parse_fragment(name: str, text: str) -> Fragment:
    if CONFLICT_MARKER.search(text):
        raise ValueError(f"{name}: unresolved merge-conflict marker")
    lines = text.split("\n")
    heading = lines[0].rstrip("\r")
    category = heading[4:] if heading.startswith("### ") else None
    if category not in CATEGORIES:
        raise ValueError(
            f"{name}: first line must be one of "
            + ", ".join(f"`### {c}`" for c in CATEGORIES)
            + f", got {heading!r}"
        )
    body = "\n".join(lines[1:]).strip("\n")
    if not body.strip():
        raise ValueError(f"{name}: no bullet under `{heading}`")
    if not body.startswith("- "):
        raise ValueError(f"{name}: body must start with a `- ` bullet")
    for number, line in enumerate(body.split("\n"), start=2):
        if line.strip() and not (line.startswith("- ") or line.startswith("  ")):
            raise ValueError(
                f"{name}:{number}: expected a `- ` bullet or an indented "
                f"continuation line, got {line!r}"
            )
    return Fragment(name, category, FRAGMENT_RELATIVE_LINK.sub("](", body) + "\n")


def load_fragments(root: Path) -> list[Fragment]:
    """Return every fragment under `changelog.d/`, sorted by file name."""
    directory = root / FRAGMENT_DIR
    if not directory.is_dir():
        return []
    fragments = []
    for path in sorted(directory.iterdir()):
        if path.name == README:
            continue
        if path.suffix != ".md" or not path.is_file():
            raise ValueError(f"{FRAGMENT_DIR}/{path.name}: not a `.md` fragment")
        fragments.append(parse_fragment(f"{FRAGMENT_DIR}/{path.name}", path.read_text("utf-8")))
    return fragments


def bullets(body: str) -> list[str]:
    """Split a subsection body into whitespace-normalized bullets."""
    found: list[list[str]] = []
    for line in body.split("\n"):
        if line.startswith("- "):
            found.append([line])
        elif found and line.strip():
            found[-1].append(line)
    return [" ".join(" ".join(item).split()) for item in found]


def split_unreleased(changelog: str) -> tuple[str, str, str]:
    """Return (text through the heading line, section body, rest of the file)."""
    heading = re.search(rf"(?m)^## \[{UNRELEASED}\][^\n]*\n", changelog)
    if heading is None:
        raise ValueError(f"{CHANGELOG}: no `## [{UNRELEASED}]` section")
    rest = changelog[heading.end() :]
    following = SECTION.search(rest)
    end = len(rest) if following is None else following.start()
    return changelog[: heading.end()], rest[:end], rest[end:]


def subsections(body: str) -> tuple[str, list[tuple[str, str]]]:
    """Split a section body into its preamble and `(category, bullets)` pairs."""
    matches = list(SUBSECTION.finditer(body))
    preamble = body[: matches[0].start()] if matches else body
    parts = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        parts.append((match.group()[4:].rstrip(), body[match.end() : end].strip("\n")))
    return preamble.strip("\n"), parts


def assemble(changelog: str, fragments: list[Fragment]) -> str:
    """Return the changelog with the fragments merged into `[Unreleased]`."""
    head, body, tail = split_unreleased(changelog)
    if not fragments:
        return changelog
    preamble, parts = subsections(body)
    seen: dict[str, str] = {}
    for category, text in parts:
        for bullet in bullets(text):
            seen.setdefault(bullet, f"[{UNRELEASED}] `### {category}`")
    for fragment in fragments:
        for bullet in bullets(fragment.body):
            if bullet in seen:
                raise ValueError(
                    f"{fragment.name}: bullet already present in {seen[bullet]}: {bullet[:60]!r}"
                )
            seen[bullet] = fragment.name
    for category in CATEGORIES:
        addition = "".join(f.body for f in fragments if f.category == category)
        if not addition:
            continue
        for index, (existing, text) in enumerate(parts):
            if existing == category:
                parts[index] = (category, f"{text}\n{addition}".strip("\n"))
                break
        else:
            rank = CATEGORIES.index(category)
            position = next(
                (
                    i
                    for i, (existing, _) in enumerate(parts)
                    if existing in CATEGORIES and CATEGORIES.index(existing) > rank
                ),
                len(parts),
            )
            parts.insert(position, (category, addition.strip("\n")))
    rendered = "\n" + (f"{preamble}\n\n" if preamble else "")
    rendered += "".join(f"### {category}\n\n{text}\n\n" for category, text in parts)
    return head + rendered + tail


def run(root: Path, check: bool) -> str:
    fragments = load_fragments(root)
    changelog_path = root / CHANGELOG
    assembled = assemble(changelog_path.read_text("utf-8"), fragments)
    if not fragments:
        return "no changelog fragments to assemble"
    counts = ", ".join(
        f"{c}: {n}" for c in CATEGORIES if (n := sum(f.category == c for f in fragments))
    )
    if check:
        return f"{len(fragments)} changelog fragments assemble cleanly ({counts})"
    changelog_path.write_text(assembled, "utf-8")
    for fragment in fragments:
        (root / fragment.name).unlink()
    return f"assembled {len(fragments)} changelog fragments into [{UNRELEASED}] ({counts})"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="validate without writing")
    parser.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        print(f"changelog fragments: {run(args.root, args.check)}")
    except (OSError, ValueError) as error:
        print(f"changelog fragments: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
