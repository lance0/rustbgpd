#!/usr/bin/env python3
"""Assert every repo path named in docs/RELEASE_CHECKLIST.md exists in the tree.

A trigger list that names a path which no longer exists never fires: the
release gate it guards silently passes. This extracts every path-shaped
token from the document -- backticked prose paths in the trigger lists, and
bare paths inside the fenced reproduction blocks -- and checks each against
the working tree. Bare tokens are read only inside fenced code blocks, so
prose such as "docs/test improvements" is not mistaken for a path.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOTS = r"(?:src|crates|tests|docs|scripts|bench|examples|\.github|fuzz)"
BACKTICKED = re.compile(r"`([^`\s]+)`")
BARE = re.compile(rf"(?<![\w/`.-])({ROOTS}/[\w./-]*[\w/])")
IS_PATH = re.compile(rf"^{ROOTS}/")

DOCUMENT = Path("docs") / "RELEASE_CHECKLIST.md"


def named_paths(document: str) -> dict[str, list[int]]:
    """Map each path-shaped token in `document` to the lines naming it."""
    found: dict[str, list[int]] = {}
    in_fence = False
    for number, line in enumerate(document.splitlines(), start=1):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        tokens = [match.group(1) for match in BACKTICKED.finditer(line)]
        if in_fence:
            tokens += [match.group(1) for match in BARE.finditer(line)]
        for token in tokens:
            if IS_PATH.match(token):
                found.setdefault(token, []).append(number)
    return found


def check(root: Path) -> tuple[int, list[str]]:
    """Return (paths checked, errors) for the checklist under `root`."""
    document = (root / DOCUMENT).read_text(encoding="utf-8")
    found = named_paths(document)
    if not found:
        return 0, [
            f"no paths were extracted from {DOCUMENT.as_posix()}, "
            "so the parse is broken"
        ]
    errors = []
    for token, lines in sorted(found.items()):
        if not (root / token.rstrip("/")).exists():
            where = ",".join(str(number) for number in lines)
            errors.append(
                f"{DOCUMENT.as_posix()}:{where} names `{token}`, which does "
                "not exist in the tree; the gate it triggers can never fire"
            )
    return len(found), errors


def main() -> int:
    if len(sys.argv) > 2:
        raise SystemExit(f"usage: {Path(sys.argv[0]).name} [REPO_ROOT]")
    default = Path(__file__).resolve().parents[1]
    root = Path(sys.argv[1]) if len(sys.argv) == 2 else default
    checked, errors = check(root)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(
        f"release checklist path check passed: all {checked} named "
        "trigger paths exist"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
