#!/usr/bin/env python3
"""Post-hoc analyzer for M67 link-drain churn soak runs.

Reads the CSV emitted by run-m67-link-drain-churn-soak.sh and produces a JSON
verdict for the soak-specific gates:

  - no recorded harness failures,
  - vtep sessions to both PEs stay Established on every sample,
  - container restart counters stay flat,
  - the run observes both drained and recovered phases,
  - pe1/pe2 DF role and link-drain gauges transition through the expected states,
  - every blackout sample was actually measured (no -1 unmeasured sentinel),
  - measured blackout and recovery-release samples remain under their bounds,
  - PE/VTEP RSS peak and post-warmup slope stay below configured caps.

Stdlib only. Exit code 0 on pass, 1 on gate failure, 2 on harness/input error.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from typing import Iterable


def safe_float(value: str | None) -> float | None:
    if value is None or value in ("", "NaN", "unknown", "unreachable"):
        return None
    try:
        parsed = float(value)
    except ValueError:
        return None
    return parsed if math.isfinite(parsed) else None


def safe_int(value: str | None) -> int | None:
    parsed = safe_float(value)
    if parsed is None:
        return None
    return int(parsed)


def linreg(xs: list[float], ys: list[float]) -> float:
    if len(xs) < 2:
        return float("nan")
    mean_x = sum(xs) / len(xs)
    mean_y = sum(ys) / len(ys)
    numerator = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    denominator = sum((x - mean_x) ** 2 for x in xs)
    if denominator == 0:
        return float("nan")
    return numerator / denominator


def numeric_values(rows: Iterable[dict[str, str]], key: str) -> list[float]:
    values: list[float] = []
    for row in rows:
        value = safe_float(row.get(key))
        if value is not None:
            values.append(value)
    return values


def is_all_one(rows: list[dict[str, str]], key: str) -> bool:
    return all(row.get(key) == "1" for row in rows)


def is_flat(rows: list[dict[str, str]], key: str) -> bool:
    values = [safe_int(row.get(key)) for row in rows]
    values = [value for value in values if value is not None]
    return bool(values) and len(set(values)) == 1


def slope_mb_per_hour(rows: list[dict[str, str]], key: str) -> float:
    points: list[tuple[float, float]] = []
    for row in rows:
        elapsed = safe_float(row.get("elapsed_sec"))
        value = safe_float(row.get(key))
        if elapsed is not None and value is not None:
            points.append((elapsed / 3600.0, value))
    if len(points) < 5:
        return float("nan")
    xs = [point[0] for point in points]
    ys = [point[1] for point in points]
    return linreg(xs, ys)


def peak(rows: list[dict[str, str]], key: str) -> float:
    values = numeric_values(rows, key)
    return max(values) if values else float("nan")


def latest_int(rows: list[dict[str, str]], key: str) -> int | None:
    for row in reversed(rows):
        value = safe_int(row.get(key))
        if value is not None:
            return value
    return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("samples_csv")
    parser.add_argument("--output", help="optional path to write JSON verdict")
    parser.add_argument("--min-cycles", type=int, default=1)
    parser.add_argument("--mem-slope-fail", type=float, default=1.5,
                        help="MB/hour above which memory-slope gate fails")
    parser.add_argument("--mem-peak-fail", type=float, default=512.0,
                        help="MB above which peak-RSS gate fails")
    parser.add_argument("--warmup-sec", type=int, default=300,
                        help="elapsed seconds discarded before RSS slope")
    parser.add_argument("--min-slope-seconds", type=int, default=1800,
                        help="minimum runtime before enforcing RSS slope")
    parser.add_argument("--blackout-bound-ms", type=int, default=30000)
    parser.add_argument("--release-bound-ms", type=int, default=30000)
    args = parser.parse_args()

    try:
        with open(args.samples_csv, newline="") as handle:
            rows = list(csv.DictReader(handle))
    except OSError as exc:
        print(f"ERROR: cannot read {args.samples_csv}: {exc}", file=sys.stderr)
        sys.exit(2)

    if len(rows) < 3:
        print("ERROR: too few sample rows for analysis (need >= 3)", file=sys.stderr)
        sys.exit(2)

    elapsed_values = [safe_int(row.get("elapsed_sec")) or 0 for row in rows]
    runtime_sec = max(elapsed_values) - min(elapsed_values)
    max_cycle = max((safe_int(row.get("cycle")) or 0) for row in rows)
    phases = {row.get("phase", "") for row in rows}
    steady_rows = [
        row for row in rows
        if (safe_int(row.get("elapsed_sec")) or 0) >= args.warmup_sec
    ]
    slope_enforced = runtime_sec >= args.min_slope_seconds and len(steady_rows) >= 5
    if len(steady_rows) < 5:
        # Short smoke runs still get a verdict; use the whole window and make the
        # report explicit that slope confidence is low.
        steady_rows = rows
        slope_window = "full_run_short_smoke"
    else:
        slope_window = f"post_{args.warmup_sec}s"

    blackout_samples = numeric_values(rows, "blackout_ms")
    release_samples = numeric_values(rows, "release_ms")
    latest_failures = latest_int(rows, "failures")

    slopes = {
        "pe1": slope_mb_per_hour(steady_rows, "pe1_rss_mb"),
        "pe2": slope_mb_per_hour(steady_rows, "pe2_rss_mb"),
        "vtep": slope_mb_per_hour(steady_rows, "vtep_rss_mb"),
    }
    peaks = {
        "pe1": peak(rows, "pe1_rss_mb"),
        "pe2": peak(rows, "pe2_rss_mb"),
        "vtep": peak(rows, "vtep_rss_mb"),
    }

    gates: list[dict[str, object]] = []

    def gate(name: str, passed: bool, detail: str) -> None:
        gates.append({"name": name, "pass": bool(passed), "detail": detail})

    gate("no_harness_failures", latest_failures == 0,
         f"latest failures={latest_failures}")
    gate("minimum_cycles", max_cycle >= args.min_cycles,
         f"observed {max_cycle} cycle(s), required {args.min_cycles}")
    gate("sessions_stayed_established",
         is_all_one(rows, "pe1_session_established")
         and is_all_one(rows, "pe2_session_established"),
         "all sampled vtep neighbor states remained Established")
    gate("restart_counts_flat",
         is_flat(rows, "pe1_restart_count")
         and is_flat(rows, "pe2_restart_count")
         and is_flat(rows, "vtep_restart_count"),
         "docker restart counters did not change")
    gate("drained_and_recovered_phases_observed",
         "drained" in phases and "recovered" in phases,
         f"phases={sorted(phases)}")
    gate("link_drain_toggled",
         "1" in {row.get("pe1_link_drain") for row in rows}
         and "0" in {row.get("pe1_link_drain") for row in rows},
         "pe1 link-drain gauge observed both 1 and 0")
    gate("pe2_promoted_and_demoted",
         "1" in {row.get("pe2_df") for row in rows}
         and "0" in {row.get("pe2_df") for row in rows}
         and "1" in {row.get("pe2_nondf") for row in rows},
         "pe2 DF role transitioned during drain and recovered after")
    gate("operator_reason_never_set",
         all(row.get("pe1_operator_drain") in ("0", "") for row in rows),
         "link churn did not accidentally hold the operator drain reason")
    valid_blackouts = [sample for sample in blackout_samples if sample >= 0]
    unmeasured_blackouts = len(blackout_samples) - len(valid_blackouts)
    gate("blackout_measured",
         bool(blackout_samples) and unmeasured_blackouts == 0,
         f"{unmeasured_blackouts} unmeasured blackout sample(s) of "
         f"{len(blackout_samples)} (a -1 sentinel means the prober produced "
         f"<2 replies, so the blackout could not be measured)")
    gate("blackout_bounded",
         bool(valid_blackouts)
         and max(valid_blackouts) < args.blackout_bound_ms,
         f"max blackout={max(valid_blackouts) if valid_blackouts else None}ms cap={args.blackout_bound_ms}ms")
    gate("release_bounded",
         bool(release_samples)
         and max(release_samples) < args.release_bound_ms,
         f"max release={max(release_samples) if release_samples else None}ms cap={args.release_bound_ms}ms")

    for node, slope in slopes.items():
        if slope_enforced:
            gate(f"{node}_rss_slope",
                 not math.isnan(slope) and slope < args.mem_slope_fail,
                 f"{slope:.3f} MB/h vs cap {args.mem_slope_fail} ({slope_window})")
        else:
            gate(f"{node}_rss_slope",
                 True,
                 f"skipped: runtime {runtime_sec}s < {args.min_slope_seconds}s "
                 f"or fewer than 5 post-warmup samples ({slope_window}; "
                 f"observed {slope:.3f} MB/h)")
    for node, value in peaks.items():
        gate(f"{node}_rss_peak",
             not math.isnan(value) and value < args.mem_peak_fail,
             f"{value:.1f} MB vs cap {args.mem_peak_fail}")

    verdict_pass = all(item["pass"] for item in gates)
    result = {
        "samples_csv": args.samples_csv,
        "row_count": len(rows),
        "runtime_sec": runtime_sec,
        "max_cycle": max_cycle,
        "phases": sorted(phases),
        "blackout_ms": {
            "max": max(valid_blackouts) if valid_blackouts else None,
            "unmeasured": unmeasured_blackouts,
            "samples": blackout_samples,
        },
        "release_ms": {
            "max": max(release_samples) if release_samples else None,
            "samples": release_samples,
        },
        "rss_slope_mb_per_hour": slopes,
        "rss_peak_mb": peaks,
        "slope_window": slope_window,
        "slope_enforced": slope_enforced,
        "gates": gates,
        "verdict": "pass" if verdict_pass else "fail",
    }

    text = json.dumps(result, indent=2)
    print(text)
    if args.output:
        with open(args.output, "w") as handle:
            handle.write(text + "\n")

    sys.exit(0 if verdict_pass else 1)


if __name__ == "__main__":
    main()
