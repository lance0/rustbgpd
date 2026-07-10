#!/usr/bin/env python3
"""Post-hoc analyzer for the GR-restart intern-gc soak.

Reads the CSV emitted by run-soak-gr-restart-intern-gc.sh and emits a
JSON verdict against the soak-specific gates:

  - intern table size (bgp_rib_attr_intern_global_size) slope per hour < 1.0
    (the intern table should not grow across restart cycles; a positive
    slope indicates gc_intern_table is not reclaiming stranded sets)
  - RSS slope (steady state, MB/hour) < 1.0
  - peak RSS < 512 MB
  - at least one restart cycle recorded
  - BGP established observed in the final 3 samples (session recovered)

Stdlib only. Exit code 0 on pass, 1 on any gate failure, 2 on
harness/input error.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from typing import Optional


def safe_float(value: str | None) -> Optional[float]:
    if value is None or value in ("", "NaN", "nan"):
        return None
    try:
        parsed = float(value)
    except ValueError:
        return None
    return parsed if math.isfinite(parsed) else None


def linreg(xs: list[float], ys: list[float]) -> float:
    if len(xs) < 2:
        return float("nan")
    mx = sum(xs) / len(xs)
    my = sum(ys) / len(ys)
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    den = sum((x - mx) ** 2 for x in xs)
    if den == 0:
        return float("nan")
    return num / den


def analyze(rows: list[dict[str, str]]) -> dict:
    elapsed = []
    rss = []
    intern = []
    established_final = []
    max_cycles = 0

    for row in rows:
        e = safe_float(row.get("elapsed_sec"))
        r = safe_float(row.get("rss_mb"))
        i = safe_float(row.get("intern_size"))
        if e is not None:
            elapsed.append(e)
            if r is not None:
                rss.append((e, r))
            if i is not None:
                intern.append((e, i))
        c = safe_float(row.get("restart_cycles"))
        if c is not None:
            max_cycles = max(max_cycles, int(c))
        est = row.get("bgp_established")
        established_final.append(est)

    # Convert to hours for slope-per-hour.
    rss_slope = linreg([e / 3600 for e, _ in rss], [r for _, r in rss]) if rss else float("nan")
    intern_slope = (
        linreg([e / 3600 for e, _ in intern], [v for _, v in intern])
        if intern
        else float("nan")
    )

    peak_rss = max((r for _, r in rss), default=float("nan"))

    # Last 3 samples established?
    tail = established_final[-3:] if established_final else []
    final_established = tail.count("1") > 0 if tail else False

    gates = {
        "intern_slope_per_hour": {
            "value": intern_slope if not math.isnan(intern_slope) else None,
            "limit": 1.0,
            "pass": (not math.isnan(intern_slope)) and intern_slope < 1.0,
        },
        "rss_slope_per_hour": {
            "value": rss_slope if not math.isnan(rss_slope) else None,
            "limit": 1.0,
            "pass": (not math.isnan(rss_slope)) and rss_slope < 1.0,
        },
        "peak_rss_mb": {
            "value": peak_rss if not math.isnan(peak_rss) else None,
            "limit": 512.0,
            "pass": (not math.isnan(peak_rss)) and peak_rss < 512.0,
        },
        "restart_cycles": {
            "value": max_cycles,
            "limit": 1,
            "pass": max_cycles >= 1,
        },
        "final_session_established": {
            "value": final_established,
            "pass": final_established,
        },
    }

    all_pass = all(g["pass"] for g in gates.values())
    return {
        "verdict": "pass" if all_pass else "fail",
        "restart_cycles": max_cycles,
        "rss_slope_per_hour": rss_slope if not math.isnan(rss_slope) else None,
        "intern_slope_per_hour": intern_slope if not math.isnan(intern_slope) else None,
        "peak_rss_mb": peak_rss if not math.isnan(peak_rss) else None,
        "samples": len(rows),
        "gates": gates,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze GR-restart intern-gc soak")
    parser.add_argument("run_dir", help="Soak run directory containing samples.csv")
    parser.add_argument("--output", help="Write verdict JSON to this path")
    args = parser.parse_args()

    csv_path = f"{args.run_dir}/samples.csv"
    try:
        with open(csv_path, newline="") as f:
            rows = list(csv.DictReader(f))
    except OSError as e:
        print(f"error reading {csv_path}: {e}", file=sys.stderr)
        return 2

    if not rows:
        print("error: samples.csv is empty", file=sys.stderr)
        return 2

    result = analyze(rows)
    out = json.dumps(result, indent=2)
    print(out)
    if args.output:
        with open(args.output, "w") as f:
            f.write(out)
    return 0 if result["verdict"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
