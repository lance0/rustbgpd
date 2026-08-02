#!/usr/bin/env python3
"""Post-hoc analyzer for M33 soak runs.

Reads the per-minute CSV emitted by run-m33-soak.sh, drops NaN rows from
the regression but counts them toward the gates, skips the warmup window,
and emits a JSON verdict to stdout (and optionally to --output).

Stdlib only — no numpy.

Gates (defaults, all CLI-overridable):
  - memory slope (steady state, MB/hour) < 1.0      fail / < 0.5 clean
  - peak resident memory (MB)             < 512
  - session flap delta                    == 0
  - outbound route drop delta             == 0
  - gRPC health failures                  == 0
  - all three BGP sessions established in final sample
  - daemon unhealthy in final 3 samples   false
  - process restart detected              false (counter monotonicity)

Exit code 0 on pass, 1 on any gate failure, 2 on harness-level errors
(missing CSV, malformed input).
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from typing import Optional


def linreg(xs: list[float], ys: list[float]) -> tuple[float, float]:
    """Ordinary least-squares slope + intercept. Returns (NaN, NaN) when undefined."""
    n = len(xs)
    if n < 2:
        return float("nan"), float("nan")
    mx = sum(xs) / n
    my = sum(ys) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    den = sum((x - mx) ** 2 for x in xs)
    if den == 0:
        return float("nan"), my
    slope = num / den
    intercept = my - slope * mx
    return slope, intercept


def percentile(vs: list[float], p: float) -> float:
    if not vs:
        return float("nan")
    s = sorted(vs)
    k = (len(s) - 1) * p
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return s[f]
    return s[f] + (s[c] - s[f]) * (k - f)


def safe_int(s: Optional[str]) -> Optional[int]:
    if s is None or s in ("", "NaN"):
        return None
    try:
        return int(float(s))
    except (TypeError, ValueError):
        return None


def safe_float(s: Optional[str]) -> Optional[float]:
    if s is None or s in ("", "NaN"):
        return None
    try:
        v = float(s)
    except (TypeError, ValueError):
        return None
    return v if math.isfinite(v) else None


def first_nonnone_int(rows: list[dict], col: str) -> int:
    for r in rows:
        v = safe_int(r.get(col))
        if v is not None:
            return v
    return 0


def last_nonnone_int(rows: list[dict], col: str) -> int:
    for r in reversed(rows):
        v = safe_int(r.get(col))
        if v is not None:
            return v
    return 0


def detect_restart(rows: list[dict]) -> bool:
    """Any decrease in bgp_messages_sent_total between consecutive non-NaN
    samples implies the daemon process restarted (counters reset)."""
    prev: Optional[int] = None
    for r in rows:
        v = safe_int(r.get("msgs_sent_total"))
        if v is None:
            continue
        if prev is not None and v < prev:
            return True
        prev = v
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("csv", help="path to samples.csv")
    ap.add_argument(
        "--monitor-json", help="optional path to monitor.json (informational)"
    )
    ap.add_argument(
        "--warmup-sec",
        type=int,
        default=600,
        help="skip samples with uptime_sec < this for the regression (default 600)",
    )
    ap.add_argument(
        "--soak-hours",
        type=float,
        default=24.0,
        help="declared soak duration in hours, recorded in the report",
    )
    ap.add_argument(
        "--slope-fail-mb-per-hour",
        type=float,
        default=1.0,
        help="memory slope >= this MB/h fails the gate (default 1.0)",
    )
    ap.add_argument(
        "--slope-clean-mb-per-hour",
        type=float,
        default=0.5,
        help="memory slope < this MB/h is reported as clean (default 0.5)",
    )
    ap.add_argument(
        "--mem-max-fail-mb",
        type=float,
        default=512.0,
        help="peak RSS >= this MB fails the gate (default 512)",
    )
    ap.add_argument(
        "--output", help="write report JSON to this path in addition to stdout"
    )
    args = ap.parse_args()

    try:
        with open(args.csv, newline="") as fh:
            reader = csv.DictReader(fh)
            fieldnames = reader.fieldnames or []
            rows = list(reader)
    except FileNotFoundError:
        print(f"ERROR: CSV not found: {args.csv}", file=sys.stderr)
        return 2

    # Every column the gates read must be present in the header. A missing
    # column would otherwise read as None everywhere and let the gates pass
    # vacuously (deltas of 0, zero gRPC failures, no restart).
    expected_columns = (
        "uptime_sec",
        "mem_mb",
        "grpc_ok",
        "bgp_sessions_established",
        "session_flaps_total",
        "outbound_drops_total",
        "msgs_sent_total",
        "msgs_recv_total",
    )
    missing = [c for c in expected_columns if c not in fieldnames]
    if missing:
        print(
            f"ERROR: CSV is missing expected column(s): {', '.join(missing)}",
            file=sys.stderr,
        )
        return 2

    if not rows:
        print("ERROR: CSV is empty", file=sys.stderr)
        return 2

    total_samples = len(rows)

    # Steady-state samples for the regression: skip warmup, drop NaN memory.
    steady_pairs: list[tuple[float, float]] = []
    for r in rows:
        u = safe_int(r.get("uptime_sec"))
        m = safe_float(r.get("mem_mb"))
        if u is None or m is None:
            continue
        if u < args.warmup_sec:
            continue
        steady_pairs.append((u / 3600.0, m))

    xs = [p[0] for p in steady_pairs]
    ys = [p[1] for p in steady_pairs]
    slope_mb_per_hour, intercept_mb = linreg(xs, ys)

    # All-sample memory stats (non-NaN), useful for percentiles + max.
    all_mem = [
        safe_float(r.get("mem_mb"))
        for r in rows
        if safe_float(r.get("mem_mb")) is not None
    ]
    all_mem = [v for v in all_mem if v is not None]
    mem_max = max(all_mem) if all_mem else float("nan")
    mem_p50 = percentile(all_mem, 0.50)
    mem_p99 = percentile(all_mem, 0.99)
    mem_first = all_mem[0] if all_mem else float("nan")
    mem_last = all_mem[-1] if all_mem else float("nan")

    # Counter deltas — first to last non-NaN sample.
    flap_first = first_nonnone_int(rows, "session_flaps_total")
    flap_last = last_nonnone_int(rows, "session_flaps_total")
    flap_delta = flap_last - flap_first

    drop_first = first_nonnone_int(rows, "outbound_drops_total")
    drop_last = last_nonnone_int(rows, "outbound_drops_total")
    drop_delta = drop_last - drop_first

    msgs_sent_first = first_nonnone_int(rows, "msgs_sent_total")
    msgs_sent_last = last_nonnone_int(rows, "msgs_sent_total")
    msgs_recv_first = first_nonnone_int(rows, "msgs_recv_total")
    msgs_recv_last = last_nonnone_int(rows, "msgs_recv_total")

    # gRPC health rollup.
    grpc_failures = sum(1 for r in rows if r.get("grpc_ok") == "0")

    terminal_sessions = rows[-1].get("bgp_sessions_established")
    terminal_sessions_healthy = terminal_sessions == "1"
    if terminal_sessions_healthy:
        terminal_sessions_reason = "all 3 BGP sessions established"
    elif terminal_sessions == "0":
        terminal_sessions_reason = "one or more of 3 BGP sessions not established"
    else:
        terminal_sessions_reason = (
            f"terminal BGP session evidence unavailable or invalid: {terminal_sessions!r}"
        )

    # Daemon unhealthy at end: last 3 samples with grpc_ok==0 OR mem_mb==NaN.
    tail = rows[-3:]
    daemon_unhealthy_at_end = len(tail) >= 1 and all(
        r.get("grpc_ok") == "0" or safe_float(r.get("mem_mb")) is None for r in tail
    )

    restart_detected = detect_restart(rows)

    # Gate evaluation.
    fails: list[str] = []
    if math.isnan(slope_mb_per_hour):
        fails.append("insufficient steady-state samples for memory regression")
    elif slope_mb_per_hour >= args.slope_fail_mb_per_hour:
        fails.append(
            f"memory slope {slope_mb_per_hour:.3f} MB/h >= "
            f"{args.slope_fail_mb_per_hour} MB/h fail threshold"
        )
    if not math.isnan(mem_max) and mem_max >= args.mem_max_fail_mb:
        fails.append(
            f"peak memory {mem_max:.1f} MB >= {args.mem_max_fail_mb} MB fail threshold"
        )
    if flap_delta > 0:
        fails.append(f"{flap_delta} session flap(s) accumulated during soak")
    if drop_delta > 0:
        fails.append(f"{drop_delta} outbound route drop(s) during soak")
    if grpc_failures > 0:
        fails.append(f"gRPC health failed on {grpc_failures}/{total_samples} samples")
    if not terminal_sessions_healthy:
        fails.append(terminal_sessions_reason)
    if daemon_unhealthy_at_end:
        fails.append("daemon unhealthy in final 3 samples (likely crashed)")
    if restart_detected:
        fails.append(
            "process restart detected (msgs_sent_total non-monotonic) — soak invalid"
        )

    # Verdict tier.
    if fails:
        verdict = "fail"
    elif (
        not math.isnan(slope_mb_per_hour)
        and slope_mb_per_hour < args.slope_clean_mb_per_hour
        and flap_delta == 0
        and drop_delta == 0
        and grpc_failures == 0
        and terminal_sessions_healthy
        and not daemon_unhealthy_at_end
        and not restart_detected
    ):
        verdict = "clean"
    else:
        verdict = "pass"

    # Optional informational summary from monitor.json.
    monitor_summary = None
    if args.monitor_json:
        try:
            with open(args.monitor_json) as fh:
                m = json.load(fh)
            monitor_summary = {
                "converged": m.get("converged"),
                "initial_convergence_sec": m.get("initial_convergence_sec"),
                "final_count": m.get("final_count"),
                "total_announcements": m.get("total_announcements"),
                "total_withdrawals": m.get("total_withdrawals"),
                "updates_received": m.get("updates_received"),
            }
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            monitor_summary = None

    report = {
        "verdict": verdict,
        "failures": fails,
        "soak_hours": args.soak_hours,
        "warmup_sec": args.warmup_sec,
        "samples_total": total_samples,
        "samples_steady": len(steady_pairs),
        "memory": {
            "slope_mb_per_hour": None
            if math.isnan(slope_mb_per_hour)
            else slope_mb_per_hour,
            "intercept_mb": None if math.isnan(intercept_mb) else intercept_mb,
            "first_mb": None if math.isnan(mem_first) else mem_first,
            "last_mb": None if math.isnan(mem_last) else mem_last,
            "max_mb": None if math.isnan(mem_max) else mem_max,
            "p50_mb": None if math.isnan(mem_p50) else mem_p50,
            "p99_mb": None if math.isnan(mem_p99) else mem_p99,
        },
        "session_flap_delta": flap_delta,
        "outbound_drop_delta": drop_delta,
        "messages": {
            "sent_first": msgs_sent_first,
            "sent_last": msgs_sent_last,
            "sent_delta": msgs_sent_last - msgs_sent_first,
            "recv_first": msgs_recv_first,
            "recv_last": msgs_recv_last,
            "recv_delta": msgs_recv_last - msgs_recv_first,
        },
        "grpc_health_failures": grpc_failures,
        "terminal_session_health": {
            "healthy": terminal_sessions_healthy,
            "value": terminal_sessions,
            "reason": terminal_sessions_reason,
        },
        "daemon_unhealthy_at_end": daemon_unhealthy_at_end,
        "restart_detected": restart_detected,
        "thresholds": {
            "slope_fail_mb_per_hour": args.slope_fail_mb_per_hour,
            "slope_clean_mb_per_hour": args.slope_clean_mb_per_hour,
            "mem_max_fail_mb": args.mem_max_fail_mb,
        },
        "monitor": monitor_summary,
    }

    rendered = json.dumps(report, indent=2)
    print(rendered)
    if args.output:
        try:
            with open(args.output, "w") as fh:
                fh.write(rendered + "\n")
        except OSError as e:
            print(f"ERROR: could not write {args.output}: {e}", file=sys.stderr)
            return 2

    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
