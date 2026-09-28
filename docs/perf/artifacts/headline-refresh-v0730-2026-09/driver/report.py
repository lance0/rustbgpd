#!/usr/bin/env python3
# Adapted for publication: absolute scratch, checkout, repository and home paths
# are replaced with SCRATCH, WORKTREES, REPO, BGPERF2 and HOME. Otherwise as run.
"""report.py <bundle>: per-cell ranges and medians per arm from summary.csv."""
import csv, statistics as st, sys
from collections import defaultdict
rows = list(csv.DictReader(open(f"{sys.argv[1]}/summary.csv")))
V = defaultdict(list)
for r in rows:
    ph = r["phase"]
    if ph in ("matrix-s2", "matrix-s3") and r["metric"] in ("established", "cold_convergence"):
        ph = "matrix-s1"
    V[(ph, r["metric"], r["arm"])].append(float(r["value"]))
for r in csv.DictReader(open(f"{sys.argv[1]}/establishment-span.csv")):
    if r["first_to_700th_established_s"]:
        V[("matrix-s1", "establish_span", r["arm"])].append(float(r["first_to_700th_established_s"]))
arms = ["v0.73.0", "v0.72.0", "v0.68.0", "v0.68.0-daemon/v0.72.0-harness"]
keys = sorted({(p, m) for p, m, a in V})
for p, m in keys:
    cells = []
    for a in arms:
        v = V.get((p, m, a))
        cells.append(f"{min(v):.4g}–{max(v):.4g} (med {st.median(v):.4g}, n={len(v)})" if v else "-")
    print(f"{p:10s} {m:28s} | " + " | ".join(cells))
