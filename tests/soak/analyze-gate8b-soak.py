#!/usr/bin/env python3
"""Post-hoc analyzer for Gate 8b soak runs.

Reads the per-minute CSV emitted by run-gate8b-soak.sh and
produces a JSON verdict against Gate 8b-specific gates:

  - Memory slope (per PE, MB/hour) < 1.5 (less strict than M33's
    1.0 because the segment orchestrator + reconciler add a small
    steady-state working set we accept)
  - Peak resident memory per PE < 512 MB
  - DF role-change counters: pe1 + pe2 counters monotonically
    advance (no reset → no daemon restart), and the run must include
    at least one PE2-running sample and one PE2-stopped sample.

The BUM flag state is reported for diagnostics, but not currently
gated: with the default modulo election in this topology PE1 remains
DF when PE2 is up and when PE2 is down. Exercising a real DF↔Non-DF
flag transition requires a separate preference-flip topology.

Stdlib only. Mirrors `analyze-soak.py`'s shape so the operator-
facing output is consistent.

Exit code 0 on pass, 1 on any gate failure, 2 on harness errors.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys


def linreg(xs, ys):
    n = len(xs)
    if n < 2:
        return float("nan")
    mx = sum(xs) / n
    my = sum(ys) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    den = sum((x - mx) ** 2 for x in xs)
    if den == 0:
        return float("nan")
    return num / den


def percentile(vs, p):
    if not vs:
        return float("nan")
    s = sorted(vs)
    k = (len(s) - 1) * p
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return s[f]
    return s[f] + (s[c] - s[f]) * (k - f)


def safe_float(v):
    if v is None or v in ("", "NaN", "unknown", "unreachable"):
        return None
    try:
        x = float(v)
    except (TypeError, ValueError):
        return None
    return x if math.isfinite(x) else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("samples_csv")
    ap.add_argument("--mem-slope-fail", type=float, default=1.5,
                    help="MB/hour above which memory-slope gate fails")
    ap.add_argument("--mem-peak-fail", type=float, default=512.0,
                    help="MB above which peak-RSS gate fails")
    ap.add_argument("--warmup-frac", type=float, default=0.05,
                    help="fraction of run discarded from slope regression")
    ap.add_argument("--output", default=None,
                    help="optional path to write the JSON verdict")
    args = ap.parse_args()

    try:
        with open(args.samples_csv) as f:
            rows = list(csv.DictReader(f))
    except OSError as e:
        print(f"ERROR: cannot read {args.samples_csv}: {e}", file=sys.stderr)
        sys.exit(2)

    if len(rows) < 5:
        print("ERROR: too few sample rows for analysis (need >= 5)", file=sys.stderr)
        sys.exit(2)

    elapsed = [int(r["elapsed_sec"]) for r in rows]
    runtime_sec = elapsed[-1] - elapsed[0]
    warmup_cutoff = elapsed[0] + int(runtime_sec * args.warmup_frac)
    steady = [(i, r) for i, r in enumerate(rows) if int(r["elapsed_sec"]) >= warmup_cutoff]

    def column(rs, key, post=safe_float):
        return [(int(r["elapsed_sec"]) / 3600, post(r[key])) for _, r in rs]

    def slope_mb_per_hour(rs, key):
        pts = [(t, v) for t, v in column(rs, key) if v is not None]
        if len(pts) < 5:
            return float("nan")
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        return linreg(xs, ys)

    def peak(rs, key):
        vs = [v for _, v in column(rs, key) if v is not None]
        return max(vs) if vs else float("nan")

    pe1_slope = slope_mb_per_hour(steady, "pe1_rss_mb")
    pe2_slope = slope_mb_per_hour(steady, "pe2_rss_mb")
    pe1_peak = peak(enumerate(rows), "pe1_rss_mb")
    pe2_peak = peak(enumerate(rows), "pe2_rss_mb")

    # DF transition counter monotonicity. A reset implies daemon
    # restart inside the run window — that's a fail. The claim is only
    # meaningful over actual numeric samples: a run whose counter column
    # is entirely missing/non-numeric (NaN, "unreachable", empty) proves
    # nothing and must fail, not pass vacuously.
    def monotone_gate(key):
        prev = None
        numeric = 0
        for r in rows:
            v = safe_float(r[key])
            if v is None:
                continue
            numeric += 1
            if prev is not None and v < prev:
                return False, f"counter reset detected in {key} (daemon restart)"
            prev = v
        if numeric < 2:
            return False, (
                f"only {numeric} numeric sample(s) in {key} — samples "
                "missing/non-numeric, cannot claim monotonicity"
            )
        return True, (
            f"monotone over {numeric} numeric samples "
            "(no counter reset = no daemon restart)"
        )

    pe1_mono, pe1_mono_detail = monotone_gate("pe1_df_changes")
    pe2_mono, pe2_mono_detail = monotone_gate("pe2_df_changes")
    pe1_total_changes = next(
        (safe_float(r["pe1_df_changes"]) for r in reversed(rows)
         if safe_float(r["pe1_df_changes"]) is not None),
        None,
    )

    # BUM-flag observability: under this topology's default modulo
    # election, PE1 remains DF with PE2 up and with PE2 down. Keep
    # the observed state in the report for diagnostics, but do not
    # gate on a DF↔Non-DF flag transition here. That needs a separate
    # preference-flip topology.
    pe1_flag_states = {r["pe1_bum_flags"] for r in rows if r["pe1_bum_flags"]}
    pe2_running_samples = sum(1 for r in rows if r["pe2_running"] == "1")
    pe2_stopped_samples = sum(1 for r in rows if r["pe2_running"] == "0")

    gates = []

    def gate(name, ok, detail):
        gates.append({"name": name, "pass": bool(ok), "detail": detail})

    gate("pe1_memory_slope",
         not math.isnan(pe1_slope) and pe1_slope < args.mem_slope_fail,
         f"{pe1_slope:.3f} MB/h vs cap {args.mem_slope_fail}")
    gate("pe2_memory_slope",
         not math.isnan(pe2_slope) and pe2_slope < args.mem_slope_fail,
         f"{pe2_slope:.3f} MB/h vs cap {args.mem_slope_fail}")
    gate("pe1_peak_memory",
         not math.isnan(pe1_peak) and pe1_peak < args.mem_peak_fail,
         f"{pe1_peak:.1f} MB vs cap {args.mem_peak_fail}")
    gate("pe2_peak_memory",
         not math.isnan(pe2_peak) and pe2_peak < args.mem_peak_fail,
         f"{pe2_peak:.1f} MB vs cap {args.mem_peak_fail}")
    gate("pe1_df_changes_monotone", pe1_mono, pe1_mono_detail)
    gate("pe2_df_changes_monotone", pe2_mono, pe2_mono_detail)
    gate("ran_through_at_least_one_full_flip_cycle",
         pe2_running_samples > 0 and pe2_stopped_samples > 0,
         f"pe2 running={pe2_running_samples} stopped={pe2_stopped_samples}")

    verdict_pass = all(g["pass"] for g in gates)
    out = {
        "samples_csv": args.samples_csv,
        "row_count": len(rows),
        "runtime_hours": runtime_sec / 3600,
        "pe1_memory_slope_mb_per_h": pe1_slope,
        "pe2_memory_slope_mb_per_h": pe2_slope,
        "pe1_peak_rss_mb": pe1_peak,
        "pe2_peak_rss_mb": pe2_peak,
        "pe1_total_df_role_changes": pe1_total_changes,
        "pe1_observed_flag_states": sorted(pe1_flag_states),
        "pe2_running_samples": pe2_running_samples,
        "pe2_stopped_samples": pe2_stopped_samples,
        "gates": gates,
        "verdict": "pass" if verdict_pass else "fail",
    }

    text = json.dumps(out, indent=2)
    print(text)
    if args.output:
        with open(args.output, "w") as f:
            f.write(text + "\n")

    sys.exit(0 if verdict_pass else 1)


if __name__ == "__main__":
    main()
