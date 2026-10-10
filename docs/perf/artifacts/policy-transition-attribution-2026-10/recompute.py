#!/usr/bin/env python3
"""Re-run the as-run analyzer on this bundle and check every published verdict.

1. Q1-Q4 as first run (Q4 skipped by its cutoff): must reproduce
   verdict-q1-q3.txt byte for byte.
2. The later Q4-only run, with the progress log as it stood: must reproduce
   verdict-q4-as-run.txt (SKIPPED, from the stale `q4 skipped` line).
3. The same Q4-only run with that stale line removed: must reproduce
   verdict-q4-reanalysis.txt (PASS).
4. Q1's clock comparison quoted in the receipt: per reload, the cohort clock
   agrees with the RIB clock within 35 ms on all 24 pre2952 reloads and on 6
   of 24 post2952 reloads; on the other 18 the cohort clock reads 238-315 ms
   against a RIB clock of 55-60 ms.

The analyzer reads OUT/j2-identity.txt for the requested questions and
OUT/j2-progress.txt for the skip marker, so each pass writes those two files
into a scratch copy. Exit 0 when all four checks pass.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PASSES = (
    ("q1 q2 q3 q4", False, "verdict-q1-q3.txt", 4),
    ("q4", False, "verdict-q4-as-run.txt", 0),
    ("q4", True, "verdict-q4-reanalysis.txt", 0),
)


def main() -> int:
    failures = 0
    progress = (HERE / "progress.txt").read_text()
    for qs, drop_stale, expected, want_rc in PASSES:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "bundle"
            shutil.copytree(HERE, out)
            (out / "j2-identity.txt").write_text(f"J2 qs='{qs}'\n")
            lines = progress.splitlines(keepends=True)
            if drop_stale:
                lines = [line for line in lines if "q4 skipped" not in line]
            (out / "j2-progress.txt").write_text("".join(lines))
            run = subprocess.run([sys.executable, str(out / "analyze.py"), str(out)],
                                 capture_output=True, text=True)
            same = run.stdout == (HERE / expected).read_text()
            ok = same and run.returncode == want_rc
            print(f"{'ok  ' if ok else 'FAIL'} qs='{qs}' stale_line={'removed' if drop_stale else 'kept'} "
                  f"rc={run.returncode} (want {want_rc}) output {'matches' if same else 'differs from'} {expected}")
            failures += not ok
    failures += not q1_clocks()
    return 1 if failures else 0


def q1_clocks() -> bool:
    rows = {"pre2952": [], "post2952": []}
    for arm in rows:
        for run in (1, 2):
            for x in json.loads((HERE / "q1" / f"{arm}-r{run}" / "summary.json").read_text())["reloads"]:
                rows[arm].append((x["rib_transition"]["elapsed_ms"], x["phase_timing"]["cohort_rib_transition_us"] / 1000))
    pre_ok = len(rows["pre2952"]) == 24 and all(c - r <= 35 for r, c in rows["pre2952"])
    apart = [(r, c) for r, c in rows["post2952"] if c - r > 35]
    post_ok = (len(rows["post2952"]) == 24 and len(apart) == 18
               and (round(min(c for _, c in apart)), round(max(c for _, c in apart))) == (238, 315)
               and (min(r for r, _ in apart), max(r for r, _ in apart)) == (55, 60)
               and (round(min(c - r for r, c in apart)), round(max(c - r for r, c in apart))) == (178, 258))
    ok = pre_ok and post_ok
    print(f"{'ok  ' if ok else 'FAIL'} q1 clocks: pre agree 24/24={pre_ok}; post apart 18/24 at 238-315 ms vs 55-60 ms={post_ok}")
    return ok


if __name__ == "__main__":
    sys.exit(main())
