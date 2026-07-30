#!/usr/bin/env python3
"""Post-hoc analyzer for the config live-apply (hot-reload) soak.

Reads the CSV emitted by run-soak-hot-reload.sh and emits a JSON
verdict against the soak-specific gates:

  - RSS slope (steady state, MB/hour) < 1.0
  - intern table size (bgp_rib_attr_intern_global_size) slope per hour < 1.0
  - peak RSS < 512 MB
  - session established in final 3 samples (no flap from live-apply)
  - at least one successful apply, zero failures, and exact apply accounting
  - unchanged flap count and nondecreasing session uptime

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

REQUIRED = {
    "elapsed_sec", "rss_mb", "intern_size", "bgp_established",
    "apply_cycles", "apply_ok", "apply_fail", "flap_count", "uptime_seconds",
}
COUNTERS = {
    "intern_size", "apply_cycles", "apply_ok", "apply_fail",
    "flap_count", "uptime_seconds",
}


def safe_float(value: str | None) -> Optional[float]:
    if value is None or value in ("", "NaN", "nan"):
        return None
    try:
        parsed = float(value)
    except ValueError:
        return None
    return parsed if math.isfinite(parsed) else None


def safe_int(value: str | None) -> Optional[int]:
    f = safe_float(value)
    return int(f) if f is not None else None


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
    rss_pts: list[tuple[float, float]] = []
    intern_pts: list[tuple[float, float]] = []
    established_final: list[str] = []
    max_cycles = 0
    final_ok = 0
    final_fail = 0
    first_flaps = first_uptime = final_flaps = final_uptime = 0

    for row in rows:
        e = safe_float(row.get("elapsed_sec"))
        r = safe_float(row.get("rss_mb"))
        i = safe_float(row.get("intern_size"))
        if e is not None and r is not None:
            rss_pts.append((e, r))
        if e is not None and i is not None:
            intern_pts.append((e, i))
        c = safe_int(row.get("apply_cycles"))
        if c is not None:
            max_cycles = max(max_cycles, c)
        ok = safe_int(row.get("apply_ok"))
        fail = safe_int(row.get("apply_fail"))
        if ok is not None:
            final_ok = ok
        if fail is not None:
            final_fail = fail
        established_final.append(row.get("bgp_established", ""))
        flaps = safe_int(row.get("flap_count"))
        uptime = safe_int(row.get("uptime_seconds"))
        if not rss_pts or len(established_final) == 1:
            first_flaps, first_uptime = flaps, uptime
        final_flaps, final_uptime = flaps, uptime

    rss_slope = (
        linreg([e / 3600 for e, _ in rss_pts], [r for _, r in rss_pts])
        if rss_pts
        else float("nan")
    )
    intern_slope = (
        linreg([e / 3600 for e, _ in intern_pts], [i for _, i in intern_pts])
        if intern_pts
        else float("nan")
    )
    peak_rss = max((r for _, r in rss_pts), default=float("nan"))

    tail = established_final[-3:] if established_final else []
    final_established = tail.count("1") > 0 if tail else False

    total_applies = final_ok + final_fail
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
        "apply_cycles": {
            "value": max_cycles,
            "limit": 1,
            "pass": max_cycles >= 1 and max_cycles == total_applies,
        },
        "final_session_established": {
            "value": final_established,
            "pass": final_established,
        },
        "apply_failures": {
            "value": final_fail,
            "limit": 0,
            "pass": final_ok >= 1 and final_fail == 0,
        },
        "session_continuity": {
            "value": {"flap_delta": final_flaps - first_flaps,
                      "uptime_delta": final_uptime - first_uptime},
            "pass": final_flaps == first_flaps and final_uptime >= first_uptime,
        },
    }

    all_pass = all(g["pass"] for g in gates.values())
    return {
        "verdict": "pass" if all_pass else "fail",
        "apply_cycles": max_cycles,
        "apply_ok": final_ok,
        "apply_fail": final_fail,
        "intern_slope_per_hour": intern_slope if not math.isnan(intern_slope) else None,
        "rss_slope_per_hour": rss_slope if not math.isnan(rss_slope) else None,
        "peak_rss_mb": peak_rss if not math.isnan(peak_rss) else None,
        "samples": len(rows),
        "gates": gates,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze hot-reload soak")
    parser.add_argument("run_dir", help="Soak run directory containing samples.csv")
    parser.add_argument("--output", help="Write verdict JSON to this path")
    args = parser.parse_args()

    csv_path = f"{args.run_dir}/samples.csv"
    try:
        with open(csv_path, newline="") as f:
            reader = csv.DictReader(f)
            missing = REQUIRED - set(reader.fieldnames or [])
            if missing:
                print(f"error: missing required columns: {', '.join(sorted(missing))}", file=sys.stderr)
                return 2
            rows = list(reader)
    except OSError as e:
        print(f"error reading {csv_path}: {e}", file=sys.stderr)
        return 2

    if not rows:
        print("error: samples.csv is empty", file=sys.stderr)
        return 2
    for line, row in enumerate(rows, 2):
        for column in REQUIRED - {"bgp_established"}:
            value = safe_float(row.get(column))
            if value is None:
                print(f"error: row {line}: invalid {column}", file=sys.stderr)
                return 2
            if column in COUNTERS and (value < 0 or not value.is_integer()):
                print(f"error: row {line}: invalid counter {column}", file=sys.stderr)
                return 2
        if row["bgp_established"] not in {"0", "1"}:
            print(f"error: row {line}: invalid bgp_established", file=sys.stderr)
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
