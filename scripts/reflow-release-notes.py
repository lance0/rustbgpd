#!/usr/bin/env python3
"""Reflow extracted CHANGELOG release notes for the GitHub release body.

`CHANGELOG.md` is hard-wrapped (~72-80 columns) on purpose: it keeps review
quality high and diffs small (one logical edit is not a whole-paragraph
rewrite). GitHub renders release-note bodies with comment-style Markdown,
where a single newline becomes a hard line break (``<br>``) — so the
hard-wrapped text stacks raggedly on the release page ("cramming"), even
though the same file reads cleanly in-tree.

This script un-hard-wraps each paragraph / list item into a single line so
GitHub soft-wraps it cleanly on the release page, while conservatively
preserving everything that carries meaning across line breaks:

  - blank lines (paragraph / section separators), verbatim;
  - ATX headings (``#`` .. ``######``), verbatim;
  - fenced code blocks (``` ``` ``` / ``~~~``), every line verbatim;
  - table rows (lines starting with ``|``), verbatim;
  - list-item boundaries, including nested bullets (indentation preserved);
  - joining ONLY continuation lines within the same paragraph / list item.

It does not touch `CHANGELOG.md`; it runs at publish time on the already
extracted section (see `.github/workflows/release.yml`).

Usage:
  python3 scripts/reflow-release-notes.py < notes.raw.md > notes.md
  python3 scripts/reflow-release-notes.py --selftest   # check fixtures
"""

from __future__ import annotations

import difflib
import pathlib
import re
import sys

# A list item: optional indent, a bullet (-, *, +) or ordered marker (1. / 1)),
# then at least one space. Indentation is captured so nested bullets keep it.
LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+\S")
HEADING = re.compile(r"^#{1,6}\s")
TABLE_ROW = re.compile(r"^\s*\|")
FENCE = re.compile(r"^\s*(`{3,}|~{3,})")


def reflow(text: str) -> str:
    """Reflow release-note Markdown per the conservative rules above."""
    lines = text.split("\n")
    out: list[str] = []
    buf: str | None = None  # current logical (joined) line being built

    def flush() -> None:
        nonlocal buf
        if buf is not None:
            out.append(buf)
            buf = None

    in_fence = False
    fence_token = ""
    for line in lines:
        if in_fence:
            out.append(line)
            # A closing fence is the same kind (` or ~), >= 3 long, and the
            # only thing on the line (CommonMark). Be strict so a stray short
            # run of fence chars inside the block does not end it early.
            close = FENCE.match(line)
            if (
                close
                and close.group(1)[0] == fence_token[0]
                and line.strip() == close.group(1).strip()
            ):
                in_fence = False
            continue

        fence = FENCE.match(line)
        if fence:
            flush()
            in_fence = True
            fence_token = fence.group(1)
            out.append(line)
            continue

        if line.strip() == "":
            flush()
            out.append(line)
            continue

        if HEADING.match(line) or TABLE_ROW.match(line):
            flush()
            out.append(line)
            continue

        if LIST_ITEM.match(line):
            # New list item (including a nested bullet) starts a fresh logical
            # line; keep its original indentation + marker.
            flush()
            buf = line.rstrip()
            continue

        # Continuation line: join into the current paragraph / list item.
        if buf is None:
            buf = line.rstrip()
        else:
            buf = f"{buf} {line.strip()}"

    flush()
    return "\n".join(out)


def _selftest() -> int:
    fixtures = pathlib.Path(__file__).parent / "fixtures" / "release-notes"
    inputs = sorted(fixtures.glob("*.in.md"))
    if not inputs:
        print(f"selftest: no fixtures found under {fixtures}", file=sys.stderr)
        return 1
    failures = 0
    for src in inputs:
        expected_path = src.with_name(src.name[: -len(".in.md")] + ".expected.md")
        got = reflow(src.read_text())
        want = expected_path.read_text()
        if got != want:
            failures += 1
            print(f"selftest: MISMATCH for {src.name}", file=sys.stderr)
            diff = difflib.unified_diff(
                want.splitlines(keepends=True),
                got.splitlines(keepends=True),
                fromfile=f"{expected_path.name} (expected)",
                tofile=f"{src.name} (reflowed)",
            )
            sys.stderr.writelines(diff)
        else:
            print(f"selftest: ok {src.name}")
    return 1 if failures else 0


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return _selftest()
    sys.stdout.write(reflow(sys.stdin.read()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
