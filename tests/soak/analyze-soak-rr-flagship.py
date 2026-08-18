#!/usr/bin/env python3
"""Post-hoc analyzer for the route-reflector flagship soak.

Reads samples.csv + cycles.log + run.json emitted by
run-soak-rr-flagship.sh and emits a JSON verdict against the
precommitted gates in docs/soaks/soak-acceptance-gates.md (scenario 11):

  - minimum sample count (>= 0.9 x soak_seconds / sample_interval)
  - session floor: every post-warmup sample fully Established (this
    scenario has no deliberate teardowns, so there are no exceptions)
  - flap budget exact: session-flap delta over the run == 0
  - terminal reflected-delivery exact: the engine's
    rr_terminal_receipt shows min_unique == max_unique == expected ==
    run.json expected_nonself, all sessions up, zero parse errors —
    the load-bearing correctness gate
  - churn-cycle floor: final churn_cycles >= run.json churn_cycle_floor
  - max-prefix flat: bgp_max_prefix_exceeded_total stays 0 (no bounds
    are configured; any latch is a spurious enforcement)
  - counter monotonicity: bgp_messages_sent_total never decreases
  - readyz availability, split at the terminal-refresh window (the
    engine's rr_terminal refresh marker in cycles.log): hold-window
    samples need 200 within 250 ms; terminal-window samples need any
    recorded HTTP response (the documented fail-closed 503 is the
    expected busy signal under the refresh avalanche; a timeout or
    refusal — code 0 — still fails); and the runner's
    terminal_readyz recovered_ms line must be present with
    recovered_ms <= 60000 (200 within 250 ms restored no later than
    60 s after the terminal receipt)
  - RSS peak ceiling; late-window RSS/intern slope (evaluated only when
    the late window spans >= --min-slope-seconds)
  - no ABORT record in cycles.log

Stdlib only. Exit code 0 on pass, 1 on any gate failure, 2 on
harness/input error.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import sys
from datetime import datetime, timezone
from typing import Optional

REQUIRED = {
    "timestamp", "elapsed_sec", "rss_mb", "intern_size", "established",
    "flaps_total", "msgs_sent_total", "max_prefix_exceeded_total",
    "readyz_code", "readyz_ms",
}
COUNTERS = {
    "intern_size", "established", "flaps_total", "msgs_sent_total",
    "max_prefix_exceeded_total", "readyz_code",
}

RSS_PEAK_LIMIT_MB = 1024.0
RSS_LATE_SLOPE_LIMIT = 10.0     # MB/h over the late window
INTERN_LATE_SLOPE_LIMIT = 100.0  # entries/h over the late window
READYZ_MS_LIMIT = 250.0
READYZ_RECOVERY_LIMIT_MS = 60000

CYCLE_RE = re.compile(r"^\[(?P<ts>[0-9T:\-]+Z)\] (?P<body>.*)$")
HOLD_RE = re.compile(
    r"^rr_hold elapsed_s=(?P<elapsed>\d+) churn_cycles=(?P<cycles>\d+) "
    r"sessions_up=(?P<up>\d+) rss_mib=(?P<rss>\d+)$"
)
TERMINAL_START_RE = re.compile(r"^rr_terminal refresh wall_us=\d+$")
RECOVERY_RE = re.compile(r"^terminal_readyz recovered_ms=(?P<ms>\d+)$")
RECEIPT_RE = re.compile(r"^rr_terminal_receipt,(?P<fields>.+)$")


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
    if f is None or not f.is_integer():
        return None
    return int(f)


def parse_ts(value: str) -> float:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    ).timestamp()


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


def parse_receipt(fields: str) -> dict[str, int]:
    """`key=value` pairs of the engine's rr_terminal_receipt line."""
    out: dict[str, int] = {}
    for pair in fields.split(","):
        key, _, value = pair.partition("=")
        parsed = safe_int(value)
        if parsed is not None:
            out[key.strip()] = parsed
    return out


def parse_cycles(lines: list[str]) -> dict:
    """Structured view of cycles.log: hold trace, terminal-window start
    marker, terminal receipt, readyz recovery record, abort records."""
    holds: list[dict[str, int]] = []
    receipts: list[dict[str, int]] = []
    aborts: list[str] = []
    terminal_start: Optional[float] = None
    recoveries: list[int] = []
    for raw in lines:
        m = CYCLE_RE.match(raw.strip())
        if not m:
            continue
        body = m.group("body")
        if body.startswith("ABORT:"):
            aborts.append(body)
            continue
        h = HOLD_RE.match(body)
        if h:
            holds.append({k: int(v) for k, v in h.groupdict().items()})
            continue
        if terminal_start is None and TERMINAL_START_RE.match(body):
            terminal_start = parse_ts(m.group("ts"))
            continue
        rec = RECOVERY_RE.match(body)
        if rec:
            recoveries.append(int(rec.group("ms")))
            continue
        r = RECEIPT_RE.match(body)
        if r:
            receipts.append(parse_receipt(r.group("fields")))
    return {"holds": holds, "receipts": receipts, "aborts": aborts,
            "terminal_start": terminal_start, "recoveries": recoveries}


def check_receipt(receipts: list[dict[str, int]], meta: dict) -> list[str]:
    """Defects in the terminal reflected-delivery receipt (empty = clean)."""
    if not receipts:
        return ["missing rr_terminal_receipt"]
    if len(receipts) > 1:
        return [f"{len(receipts)} terminal receipts (expected exactly 1)"]
    receipt = receipts[0]
    defects = []
    expected = meta["expected_nonself"]
    checks = {
        "peers": meta["peers"],
        "prefixes": meta["total_prefixes"],
        "per_peer": meta["routes_per_peer"],
        "expected": expected,
        "min_unique": expected,
        "max_unique": expected,
        "sessions_up": meta["peers"],
        "parse_errors": 0,
    }
    for key, want in checks.items():
        if receipt.get(key) != want:
            defects.append(f"{key}={receipt.get(key)} expected {want}")
    return defects


def analyze(rows: list[dict[str, str]], cycles: dict, meta: dict,
            min_slope_seconds: float) -> dict:
    peers = meta["peers"]
    warmup = meta["warmup_sec"]

    # Per-row series.
    elapsed = [float(r["elapsed_sec"]) for r in rows]
    rss = [float(r["rss_mb"]) for r in rows]
    intern = [int(r["intern_size"]) for r in rows]
    established = [int(r["established"]) for r in rows]
    flaps = [int(r["flaps_total"]) for r in rows]
    msgs = [int(r["msgs_sent_total"]) for r in rows]
    exceeded = [int(r["max_prefix_exceeded_total"]) for r in rows]
    readyz_code = [int(r["readyz_code"]) for r in rows]
    readyz_ms = [float(r["readyz_ms"]) for r in rows]

    floor_violations = [
        {"elapsed_sec": row_elapsed, "established": established[i]}
        for i, row_elapsed in enumerate(elapsed)
        if row_elapsed >= warmup and established[i] != peers
    ]

    receipt_defects = check_receipt(cycles["receipts"], meta)

    holds = cycles["holds"]
    final_churn = None
    if cycles["receipts"]:
        final_churn = cycles["receipts"][0].get("churn_cycles")
    elif holds:
        final_churn = holds[-1]["cycles"]
    churn_monotone_breaks = sum(
        1 for a, b in zip(holds, holds[1:]) if b["cycles"] < a["cycles"]
    )

    monotone_breaks = sum(1 for a, b in zip(msgs, msgs[1:]) if b < a)
    flat_intervals = [
        {
            "from_timestamp": previous["timestamp"],
            "to_timestamp": current["timestamp"],
            "value": int(previous["msgs_sent_total"]),
        }
        for previous, current, previous_value, current_value
        in zip(rows, rows[1:], msgs, msgs[1:])
        if current_value == previous_value
    ]

    # readyz split (gates doc scenario 11): strict 200-within-250ms on
    # hold-window samples; samples inside the terminal-refresh window
    # (at/after the engine's rr_terminal refresh marker) only need a
    # recorded HTTP response — the fail-closed 503 is the documented
    # busy signal under the refresh avalanche, but a timeout/refusal
    # (code 0) still fails. Recovery (200 within 250ms again <= 60s
    # after the receipt) is evidenced by the runner's terminal_readyz
    # recovered_ms line.
    terminal_start = cycles["terminal_start"]
    in_terminal = [
        terminal_start is not None and parse_ts(r["timestamp"]) >= terminal_start
        for r in rows
    ]
    readyz_hold_bad = sum(
        1 for i, (code, ms) in enumerate(zip(readyz_code, readyz_ms))
        if not in_terminal[i] and (code != 200 or ms > READYZ_MS_LIMIT)
    )
    readyz_terminal_no_response = sum(
        1 for i, code in enumerate(readyz_code)
        if in_terminal[i] and code == 0
    )
    recovered_ms = cycles["recoveries"][0] if cycles["recoveries"] else None

    peak_rss = max(rss) if rss else float("nan")

    # Late window: final 25 % of the elapsed span.
    span = elapsed[-1] if elapsed else 0.0
    late_start = 0.75 * span
    late = [(e, r, i2) for e, r, i2 in zip(elapsed, rss, intern)
            if e >= late_start]
    late_span = late[-1][0] - late[0][0] if len(late) >= 2 else 0.0
    slope_evaluated = late_span >= min_slope_seconds
    rss_slope = linreg([e / 3600 for e, _, _ in late],
                       [r for _, r, _ in late]) if slope_evaluated else None
    intern_slope = linreg([e / 3600 for e, _, _ in late],
                          [i2 for _, _, i2 in late]) if slope_evaluated else None

    expected_samples = 0.9 * meta["soak_seconds"] / meta["sample_interval_sec"]

    gates = {
        "min_samples": {
            "value": len(rows),
            "limit": expected_samples,
            "pass": len(rows) >= expected_samples,
        },
        "session_floor": {
            "value": {"violations": len(floor_violations),
                      "first": floor_violations[:5]},
            "pass": not floor_violations,
        },
        "flap_budget": {
            "value": (flaps[-1] - flaps[0]) if flaps else None,
            "limit": 0,
            "pass": bool(flaps) and flaps[-1] - flaps[0] == 0,
        },
        "terminal_delivery_exact": {
            "value": {"receipt": cycles["receipts"][:1],
                      "defects": receipt_defects},
            "pass": not receipt_defects,
        },
        "churn_cycle_floor": {
            "value": {"final": final_churn,
                      "monotone_breaks": churn_monotone_breaks},
            "limit": meta["churn_cycle_floor"],
            "pass": (final_churn is not None
                     and final_churn >= meta["churn_cycle_floor"]
                     and churn_monotone_breaks == 0),
        },
        "max_prefix_flat": {
            "value": exceeded[-1] if exceeded else None,
            "limit": 0,
            "pass": bool(exceeded) and max(exceeded) == 0,
        },
        "msgs_sent_monotone": {
            "value": {
                "breaks": monotone_breaks,
                "flats": len(flat_intervals),
                "first_flat": flat_intervals[0] if flat_intervals else None,
            },
            "pass": monotone_breaks == 0 and not flat_intervals,
        },
        "readyz": {
            "value": {
                "hold_bad_samples": readyz_hold_bad,
                "terminal_window_samples": sum(in_terminal),
                "terminal_no_response": readyz_terminal_no_response,
                "recovered_ms": recovered_ms,
                "limit_ms": READYZ_MS_LIMIT,
                "recovery_limit_ms": READYZ_RECOVERY_LIMIT_MS,
            },
            "pass": (readyz_hold_bad == 0
                     and readyz_terminal_no_response == 0
                     and recovered_ms is not None
                     and recovered_ms <= READYZ_RECOVERY_LIMIT_MS),
        },
        "rss_peak_mb": {
            "value": peak_rss if not math.isnan(peak_rss) else None,
            "limit": RSS_PEAK_LIMIT_MB,
            "pass": (not math.isnan(peak_rss)) and peak_rss < RSS_PEAK_LIMIT_MB,
        },
        "rss_late_slope_per_hour": {
            "value": rss_slope,
            "limit": RSS_LATE_SLOPE_LIMIT,
            "pass": True if not slope_evaluated
            else (rss_slope is not None and not math.isnan(rss_slope)
                  and rss_slope < RSS_LATE_SLOPE_LIMIT),
            "note": None if slope_evaluated else (
                f"late window {late_span:.0f}s < {min_slope_seconds:.0f}s: "
                "not evaluated (precommitted for >= 24 h windows)"
            ),
        },
        "intern_late_slope_per_hour": {
            "value": intern_slope,
            "limit": INTERN_LATE_SLOPE_LIMIT,
            "pass": True if not slope_evaluated
            else (intern_slope is not None and not math.isnan(intern_slope)
                  and intern_slope < INTERN_LATE_SLOPE_LIMIT),
            "note": None if slope_evaluated else (
                f"late window {late_span:.0f}s < {min_slope_seconds:.0f}s: "
                "not evaluated (precommitted for >= 24 h windows)"
            ),
        },
        "no_abort": {
            "value": cycles["aborts"],
            "pass": not cycles["aborts"],
        },
    }

    all_pass = all(g["pass"] for g in gates.values())
    return {
        "verdict": "pass" if all_pass else "fail",
        "samples": len(rows),
        "hold_lines": len(holds),
        "final_churn_cycles": final_churn,
        "terminal_receipt_defects": receipt_defects,
        "peak_rss_mb": peak_rss if not math.isnan(peak_rss) else None,
        "rss_late_slope_per_hour": rss_slope,
        "intern_late_slope_per_hour": intern_slope,
        "slope_window_evaluated": slope_evaluated,
        "gates": gates,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze the route-reflector flagship soak")
    parser.add_argument("run_dir",
                        help="Run directory (samples.csv, cycles.log, run.json)")
    parser.add_argument("--output", help="Write verdict JSON to this path")
    parser.add_argument("--min-slope-seconds", type=float, default=3600.0,
                        help="Minimum late-window span before the slope gates "
                             "are evaluated (default 3600)")
    args = parser.parse_args()

    try:
        with open(f"{args.run_dir}/run.json", encoding="utf-8") as f:
            meta = json.load(f)
        with open(f"{args.run_dir}/samples.csv", newline="",
                  encoding="utf-8") as f:
            reader = csv.DictReader(f)
            missing = REQUIRED - set(reader.fieldnames or [])
            if missing:
                print("error: missing required columns: "
                      + ", ".join(sorted(missing)), file=sys.stderr)
                return 2
            rows = list(reader)
        with open(f"{args.run_dir}/cycles.log", encoding="utf-8") as f:
            cycle_lines = f.readlines()
    except OSError as e:
        print(f"error reading run dir: {e}", file=sys.stderr)
        return 2

    for key in ("peers", "routes_per_peer", "total_prefixes",
                "expected_nonself", "churn_cycle_floor", "warmup_sec",
                "sample_interval_sec", "soak_seconds"):
        if not isinstance(meta.get(key), int):
            print(f"error: run.json missing integer {key}", file=sys.stderr)
            return 2

    if not rows:
        print("error: samples.csv is empty", file=sys.stderr)
        return 2
    for line, row in enumerate(rows, 2):
        for column in REQUIRED - {"timestamp"}:
            value = safe_float(row.get(column))
            if value is None:
                print(f"error: row {line}: invalid {column}", file=sys.stderr)
                return 2
            if column in COUNTERS and (value < 0 or not value.is_integer()):
                print(f"error: row {line}: invalid counter {column}",
                      file=sys.stderr)
                return 2
        try:
            parse_ts(row["timestamp"])
        except ValueError:
            print(f"error: row {line}: invalid timestamp", file=sys.stderr)
            return 2

    cycles = parse_cycles(cycle_lines)
    result = analyze(rows, cycles, meta, args.min_slope_seconds)
    out = json.dumps(result, indent=2)
    print(out)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
    return 0 if result["verdict"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
