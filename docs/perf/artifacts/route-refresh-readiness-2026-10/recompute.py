#!/usr/bin/env python3
"""Recompute every number in the route-refresh readiness receipt from this bundle.

Reads cells/*/cell.log (harness and daemon exit codes), daemon-events.csv
(ROUTE-REFRESH requests and readiness-probe failures extracted from each
daemon log) and cells/*/reloadstall.log (converged_rejoin_csv rows). Prints
the per-arm table and exits non-zero if any value differs from the receipt.
"""

from __future__ import annotations

import csv
import re
import statistics as st
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXPECTED = {
    "base": {"cells": 4, "passing": 1, "misses": 3, "gap": (211, 227), "cell_medians": (215, 223)},
    "fix": {"cells": 4, "passing": 4, "misses": 0, "gap": (231, 246), "cell_medians": (237, 243)},
}
SURVIVOR_GAP_MS = (118.5, 126.6)  # every completed round, both arms


def main() -> int:
    arms = defaultdict(lambda: {"cells": 0, "passing": 0, "misses": 0, "gaps": [], "medians": []})
    passed = {}
    for cell in sorted((HERE / "cells").iterdir()):
        arm = cell.name.split("-")[0]
        m = re.search(r"harness_rc=(\d+) daemon_rc=(\d+)", (cell / "cell.log").read_text())
        passed[cell.name] = m is not None and m.groups() == ("0", "0")
        arms[arm]["cells"] += 1
        arms[arm]["passing"] += passed[cell.name]
    times = defaultdict(list)
    cell_misses = defaultdict(int)
    for row in csv.DictReader((HERE / "daemon-events.csv").open()):
        if row["event"] == "readiness_probe_failed":
            arms[row["arm"]]["misses"] += 1
            cell_misses[row["cell"]] += 1
        else:
            times[(row["arm"], row["cell"])].append(datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00")))
    for (arm, _), ts in sorted(times.items()):
        # Back-to-back requests from the two observers: the gap is one replay's actor time.
        gaps = [(b - a).total_seconds() * 1000 for a, b in zip(ts, ts[1:]) if (b - a).total_seconds() < 0.5]
        arms[arm]["gaps"] += gaps
        arms[arm]["medians"].append(st.median(gaps))
    survivor = []
    for log in sorted((HERE / "cells").glob("*/reloadstall.log")):
        for line in log.read_text().splitlines():
            if line.startswith("converged_rejoin_csv,"):
                survivor.append(float(line.split(",")[7]))

    # Each failing cell has exactly one readiness miss and each passing cell none.
    bad = {c: cell_misses[c] for c in passed if cell_misses[c] != (0 if passed[c] else 1)}
    bad.update({c: n for c, n in cell_misses.items() if c not in passed})
    ok = not bad
    print(f"{'ok  ' if ok else 'FAIL'} per-cell misses match harness results"
          + (f": mismatched {bad}" if bad else ""))
    for arm, want in EXPECTED.items():
        a = arms[arm]
        got = {"cells": a["cells"], "passing": a["passing"], "misses": a["misses"],
               "gap": (round(min(a["gaps"])), round(max(a["gaps"]))),
               "cell_medians": (round(min(a["medians"])), round(max(a["medians"])))}
        match = got == want
        ok &= match
        print(f"{'ok  ' if match else 'FAIL'} {arm}: {got['passing']}/{got['cells']} cells pass, "
              f"{got['misses']} readiness misses, replay gap {got['gap'][0]}-{got['gap'][1]} ms "
              f"(cell medians {got['cell_medians'][0]}-{got['cell_medians'][1]})")
    got = (round(min(survivor), 1), round(max(survivor), 1))
    match = got == SURVIVOR_GAP_MS and len(survivor) == 16
    ok &= match
    print(f"{'ok  ' if match else 'FAIL'} survivor max gap {min(survivor):.1f}-{max(survivor):.1f} ms "
          f"over {len(survivor)} completed rounds")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
