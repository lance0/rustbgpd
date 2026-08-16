#!/usr/bin/env python3
"""Post-hoc analyzer for the route-server flagship soak.

Reads samples.csv + cycles.log + run.json emitted by
run-soak-rs-flagship.sh and emits a JSON verdict against the
precommitted gates in docs/soaks/soak-acceptance-gates.md (scenario 10):

  - minimum sample count (>= 0.9 x soak_seconds / sample_interval)
  - session floor: every post-warmup sample fully Established, except the
    designated member inside declared trip windows
  - reload accounting exact: issued == barrier-verified complete,
    complete >= 0.9 x planned
  - trip accounting exact: executed == planned, full evidence chain per
    cycle (breach counter, hold-down countdown, bounded re-establish,
    headroom sanity), zero unexpected latch-offs
  - exceeded-counter exact: final bgp_max_prefix_exceeded_total == trips
  - flap budget exact: session-flap delta == trips (one per teardown)
  - counter monotonicity: bgp_messages_sent_total never decreases
  - readyz availability: 200 within 250 ms on every sample
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

RSS_PEAK_LIMIT_MB = 3072.0
RSS_LATE_SLOPE_LIMIT = 10.0     # MB/h over the late window
INTERN_LATE_SLOPE_LIMIT = 100.0  # entries/h over the late window
READYZ_MS_LIMIT = 250.0
REESTABLISH_GRACE_SEC = 60

CYCLE_RE = re.compile(
    r"^\[(?P<ts>[0-9T:\-]+Z)\] (?P<body>.*)$"
)


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


def parse_cycles(lines: list[str]) -> dict:
    """Structured view of cycles.log: reload counts, per-trip evidence,
    trip windows (epoch seconds), abort records."""
    reload_issued: set[int] = set()
    reload_complete: set[int] = set()
    trips: dict[int, dict] = {}
    aborts: list[str] = []
    for raw in lines:
        m = CYCLE_RE.match(raw.strip())
        if not m:
            continue
        ts = parse_ts(m.group("ts"))
        body = m.group("body")
        if body.startswith("ABORT:"):
            aborts.append(body)
            continue
        r = re.match(r"^reload (\d+) issued$", body)
        if r:
            reload_issued.add(int(r.group(1)))
            continue
        r = re.match(r"^reload (\d+) complete$", body)
        if r:
            reload_complete.add(int(r.group(1)))
            continue
        r = re.match(r"^trip (\d+) (.+)$", body)
        if not r:
            continue
        n = int(r.group(1))
        rest = r.group(2)
        trip = trips.setdefault(n, {})
        if rest == "announce_over":
            trip["announce_over"] = ts
        elif rest == "torn_down":
            trip["torn_down"] = ts
        elif rest == "reestablished":
            trip["reestablished"] = ts
        elif rest == "reannounced":
            trip["reannounced"] = ts
        else:
            e = re.match(r"^exceeded_total=(\d+)$", rest)
            if e:
                trip["exceeded_total"] = int(e.group(1))
                continue
            e = re.match(r"^countdown_ms=(\d+) action=(\S+)$", rest)
            if e:
                trip["countdown_ms"] = int(e.group(1))
                trip["countdown_action"] = e.group(2)
                continue
            e = re.match(r"^complete usage=(\d+) limit=(\d+) headroom=(\d+)$", rest)
            if e:
                trip["complete"] = ts
                trip["usage"] = int(e.group(1))
                trip["limit"] = int(e.group(2))
                trip["headroom"] = int(e.group(3))
    return {
        "reload_issued": reload_issued,
        "reload_complete": reload_complete,
        "trips": trips,
        "aborts": aborts,
    }


def check_trip(n: int, trip: dict, meta: dict) -> list[str]:
    """Evidence-chain defects for one trip cycle (empty = clean)."""
    defects = []
    for key in ("announce_over", "torn_down", "reestablished", "reannounced",
                "complete"):
        if key not in trip:
            defects.append(f"missing {key}")
    if trip.get("exceeded_total") != n:
        defects.append(
            f"exceeded_total={trip.get('exceeded_total')} expected {n}"
        )
    if trip.get("countdown_action") != "restart":
        defects.append(f"countdown action={trip.get('countdown_action')}")
    countdown = trip.get("countdown_ms")
    restart_ms = meta["trip_restart_seconds"] * 1000
    if countdown is None or not 0 < countdown <= restart_ms:
        defects.append(f"countdown_ms={countdown} outside (0, {restart_ms}]")
    if "torn_down" in trip and "reestablished" in trip:
        held = trip["reestablished"] - trip["torn_down"]
        bound = meta["trip_restart_seconds"] + REESTABLISH_GRACE_SEC
        if held > bound:
            defects.append(f"re-establish took {held:.0f}s > {bound}s bound")
    if "usage" in trip:
        if trip["usage"] != meta["routes_per_peer"]:
            defects.append(f"usage={trip['usage']} != routes_per_peer")
        if trip["limit"] != meta["max_prefixes"]:
            defects.append(f"limit={trip['limit']} != max_prefixes")
        if trip["usage"] + trip["headroom"] != trip["limit"]:
            defects.append("usage + headroom != limit")
    return defects


def analyze(rows: list[dict[str, str]], cycles: dict, meta: dict,
            min_slope_seconds: float) -> dict:
    peers = meta["peers"]
    warmup = meta["warmup_sec"]
    planned_reloads = meta["planned_reloads"]
    planned_trips = meta["planned_trips"]
    grace = meta["sample_interval_sec"]

    trips = cycles["trips"]
    executed_trips = sorted(n for n, t in trips.items() if "complete" in t)
    trip_windows = [
        (t["announce_over"] - grace, t["reestablished"] + grace)
        for t in trips.values()
        if "announce_over" in t and "reestablished" in t
    ]

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
    stamps = [parse_ts(r["timestamp"]) for r in rows]

    def in_trip_window(ts: float) -> bool:
        return any(lo <= ts <= hi for lo, hi in trip_windows)

    floor_violations = []
    for i, row_elapsed in enumerate(elapsed):
        if row_elapsed < warmup:
            continue
        if established[i] == peers:
            continue
        if established[i] == peers - 1 and in_trip_window(stamps[i]):
            continue
        floor_violations.append(
            {"elapsed_sec": row_elapsed, "established": established[i]}
        )

    issued = len(cycles["reload_issued"])
    complete = len(cycles["reload_complete"])

    trip_defects = {
        n: check_trip(n, trips.get(n, {}), meta)
        for n in range(1, planned_trips + 1)
    }
    trip_defects = {n: d for n, d in trip_defects.items() if d}

    monotone_breaks = sum(
        1 for a, b in zip(msgs, msgs[1:]) if b < a
    )
    readyz_bad = sum(
        1 for code, ms in zip(readyz_code, readyz_ms)
        if code != 200 or ms > READYZ_MS_LIMIT
    )

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
        "reload_accounting": {
            "value": {"issued": issued, "complete": complete,
                      "planned": planned_reloads},
            "pass": issued == complete and complete >= 0.9 * planned_reloads,
        },
        "trip_accounting": {
            "value": {"executed": len(executed_trips),
                      "planned": planned_trips,
                      "defects": trip_defects},
            "pass": len(executed_trips) == planned_trips and not trip_defects,
        },
        "exceeded_exact": {
            "value": exceeded[-1] if exceeded else None,
            "limit": len(executed_trips),
            "pass": bool(exceeded) and exceeded[-1] == len(executed_trips),
        },
        "flap_budget": {
            "value": (flaps[-1] - flaps[0]) if flaps else None,
            "limit": len(executed_trips),
            "pass": bool(flaps) and flaps[-1] - flaps[0] == len(executed_trips),
        },
        "msgs_sent_monotone": {
            "value": {"breaks": monotone_breaks},
            "pass": monotone_breaks == 0,
        },
        "readyz": {
            "value": {"bad_samples": readyz_bad,
                      "limit_ms": READYZ_MS_LIMIT},
            "pass": readyz_bad == 0,
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
        "reloads_issued": issued,
        "reloads_complete": complete,
        "trips_executed": len(executed_trips),
        "trips_planned": planned_trips,
        "peak_rss_mb": peak_rss if not math.isnan(peak_rss) else None,
        "rss_late_slope_per_hour": rss_slope,
        "intern_late_slope_per_hour": intern_slope,
        "slope_window_evaluated": slope_evaluated,
        "gates": gates,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze the route-server flagship soak")
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

    for key in ("peers", "routes_per_peer", "planned_reloads", "planned_trips",
                "warmup_sec", "sample_interval_sec", "soak_seconds",
                "trip_restart_seconds", "max_prefixes"):
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
