#!/usr/bin/env python3
"""Fail when a benchmark driver is missing from `just bench-list`.

A driver is a tracked script under bench/ or docs/perf/ (artifacts and tests
excluded) named run-*, compare-* or *_cell.sh. Each must be named in the
`bench-list` recipe, with a recipe or in its list of drivers without one, and
every script path that recipe names must exist.

Usage: check_bench_inventory.py [JUSTFILE]
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DRIVER = re.compile(r"(^|/)(run-[^/]*\.(sh|py)|compare-[^/]*\.sh|[^/]*_cell\.sh)$")
PATH = re.compile(r"\b(?:bench|docs/perf)/[\w./-]+\.(?:sh|py)\b")


def drivers(root: Path) -> set[str]:
    files = subprocess.run(["git", "ls-files", "bench", "docs/perf"], cwd=root, check=True,
                           capture_output=True, text=True).stdout.split()
    return {f for f in files if DRIVER.search(f) and "/tests/" not in f and "/artifacts/" not in f}


def listed(justfile_text: str) -> set[str]:
    """Script paths named in the bench-list recipe body."""
    match = re.search(r"^bench-list:\n((?:[ \t]+.*\n|\n)+)", justfile_text, re.M)
    if match is None:
        raise SystemExit("justfile has no bench-list recipe")
    return set(PATH.findall(match.group(1)))


def problems(root: Path, justfile_text: str) -> list[str]:
    names = listed(justfile_text)
    found = [f"driver not in bench-list: {path}" for path in sorted(drivers(root) - names)]
    found += [f"bench-list names a missing file: {path}" for path in sorted(names)
              if not (root / path).is_file()]
    return found


def main(argv: list[str]) -> int:
    justfile = Path(argv[1]) if len(argv) > 1 else ROOT / "justfile"
    found = problems(ROOT, justfile.read_text(encoding="utf-8"))
    for problem in found:
        print(problem)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
