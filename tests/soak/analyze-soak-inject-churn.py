#!/usr/bin/env python3
"""Post-hoc analyzer for the gRPC inject-churn soak.

Reads samples.csv, run.json and rustbgpd.log from the matching runner
and emits a JSON verdict against the soak-specific gates:

  - RSS slope (steady state, MB/hour) < 1.0
  - intern table size (bgp_rib_attr_intern_global_size) slope per hour < 1.0
  - peak RSS < 512 MB
  - session established in the final CSV sample (no flap)
  - churn cycles meet 50% of the configured post-warmup cadence (at least one)
  - final consumer route count exactly matches the live target
  - unchanged flap count and nondecreasing session uptime
  - valid daemon log with no ERROR records

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

from flagship_daemon_log import analyze_daemon_log, unique_members

REQUIRED = {
    "elapsed_sec", "rss_mb", "intern_size", "live_target", "frr_route_count",
    "bgp_established", "churn_cycles", "add_total", "del_total",
    "flap_count", "uptime_seconds",
}
COUNTERS = REQUIRED - {"elapsed_sec", "rss_mb", "bgp_established"}


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


def analyze(rows: list[dict[str, str]], minimum_cycles: int) -> dict:
    rss_pts: list[tuple[float, float]] = []
    intern_pts: list[tuple[float, float]] = []
    established_final: list[str] = []
    max_cycles = 0
    first_flaps = first_uptime = final_flaps = final_uptime = 0
    final_target = final_routes = 0

    for row in rows:
        e = safe_float(row.get("elapsed_sec"))
        r = safe_float(row.get("rss_mb"))
        i = safe_float(row.get("intern_size"))
        if e is not None and r is not None:
            rss_pts.append((e, r))
        if e is not None and i is not None:
            intern_pts.append((e, i))
        c = safe_float(row.get("churn_cycles"))
        if c is not None:
            max_cycles = max(max_cycles, int(c))
        established_final.append(row.get("bgp_established", ""))
        flaps = int(safe_float(row.get("flap_count")))
        uptime = int(safe_float(row.get("uptime_seconds")))
        if len(established_final) == 1:
            first_flaps, first_uptime = flaps, uptime
        final_flaps, final_uptime = flaps, uptime
        final_target = int(safe_float(row.get("live_target")))
        final_routes = int(safe_float(row.get("frr_route_count")))

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

    final_established = bool(established_final) and established_final[-1] == "1"

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
        "churn_cycles": {
            "value": max_cycles,
            "limit": minimum_cycles,
            "pass": max_cycles >= minimum_cycles,
        },
        "final_session_established": {
            "value": final_established,
            "pass": final_established,
        },
        "final_consumer_convergence": {
            "value": {"target": final_target, "routes": final_routes},
            "pass": final_target > 0 and final_routes == final_target,
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
        "churn_cycles": max_cycles,
        "intern_slope_per_hour": intern_slope if not math.isnan(intern_slope) else None,
        "rss_slope_per_hour": rss_slope if not math.isnan(rss_slope) else None,
        "peak_rss_mb": peak_rss if not math.isnan(peak_rss) else None,
        "samples": len(rows),
        "gates": gates,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze inject-churn soak")
    parser.add_argument("run_dir",
                        help="Soak run directory containing samples.csv, run.json and rustbgpd.log")
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

    try:
        with open(f"{args.run_dir}/run.json", encoding="utf-8") as stream:
            meta = json.load(stream, object_pairs_hook=unique_members)
        if not isinstance(meta, dict):
            raise ValueError("run.json must be an object")
        for key in ("soak_seconds", "churn_interval_sec", "warmup_sec"):
            value = meta.get(key)
            minimum = 0 if key == "warmup_sec" else 1
            if type(value) is not int or value < minimum:
                raise ValueError(f"run.json has invalid {key}")
        if meta["warmup_sec"] >= meta["soak_seconds"]:
            raise ValueError("warmup_sec must be less than soak_seconds")
        active_seconds = meta["soak_seconds"] - meta["warmup_sec"]
    except (OSError, ValueError) as exc:
        print(f"error reading run metadata: {exc}", file=sys.stderr)
        return 2
    # Integer ceiling preserves the documented fractional window floor.
    denominator = 2 * meta["churn_interval_sec"]
    minimum_cycles = max(1, (active_seconds + denominator - 1) // denominator)

    result = analyze(rows, minimum_cycles)
    result["gates"]["daemon_log"] = analyze_daemon_log(args.run_dir)
    result["verdict"] = "pass" if all(g["pass"] for g in result["gates"].values()) else "fail"
    out = json.dumps(result, indent=2)
    print(out)
    if args.output:
        with open(args.output, "w") as f:
            f.write(out)
    return 0 if result["verdict"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
