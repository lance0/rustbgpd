#!/usr/bin/env python3
"""Post-hoc analyzer for the route-server flagship soak.

Reads samples.csv + cycles.log + run.json + management-plane-load.jsonl emitted by
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
  - management-plane load brackets the measured window, retains every
    operation, completes >= 90% of scheduled probes, misses no cadence,
    and records zero HTTP/CLI/timeout/JSON/schema/cardinality failures
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
MANAGEMENT_OPERATIONS = ("metrics", "neighbor", "policy_stats", "rib_prefix")
MANAGEMENT_RECORD_LIMIT = 4096
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

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


def finite_number(value: object) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    parsed = float(value)
    return parsed if math.isfinite(parsed) else None


def expected_management_route_prefix(routes_per_peer: object) -> Optional[str]:
    """Recompute stub 1's first /24 using reloadstall's Rust mapping."""
    if (
        isinstance(routes_per_peer, bool)
        or not isinstance(routes_per_peer, int)
        or routes_per_peer <= 0
    ):
        return None
    first = 20 + (routes_per_peer >> 16)
    if first > 255:
        return None
    second = (routes_per_peer >> 8) & 0xFF
    third = routes_per_peer & 0xFF
    return f"{first}.{second}.{third}.0/24"


def analyze_management_load(raw: bytes, meta: dict) -> dict:
    """Validate bounded JSONL evidence without trusting its terminal summary."""
    schema_errors: list[str] = []
    failures: list[dict] = []
    starts: list[dict] = []
    summaries: list[dict] = []
    operations: dict[str, list[dict]] = {
        operation: [] for operation in MANAGEMENT_OPERATIONS
    }

    if not raw.endswith(b"\n"):
        schema_errors.append("JSONL does not end with a complete record")
    lines = raw.splitlines()
    records: list[dict] = []
    for line_number, encoded in enumerate(lines, 1):
        if len(encoded) > MANAGEMENT_RECORD_LIMIT:
            schema_errors.append(f"line {line_number}: record exceeds bound")
            continue
        try:
            record = json.loads(encoded)
        except (UnicodeDecodeError, json.JSONDecodeError):
            schema_errors.append(f"line {line_number}: malformed JSON")
            continue
        if not isinstance(record, dict):
            schema_errors.append(f"line {line_number}: record is not an object")
            continue
        if any(key in record for key in ("payload", "stdout", "stderr")):
            schema_errors.append(f"line {line_number}: retained response payload")
        records.append(record)
        kind = record.get("record")
        if kind == "start":
            starts.append(record)
        elif kind == "summary":
            summaries.append(record)
        elif kind == "operation":
            operation = record.get("operation")
            if operation not in operations:
                schema_errors.append(
                    f"line {line_number}: unknown operation {operation!r}"
                )
                continue
            scheduled = finite_number(record.get("scheduled_monotonic"))
            started = finite_number(record.get("started_monotonic"))
            completed = finite_number(record.get("completed_monotonic"))
            duration = finite_number(record.get("duration_ms"))
            byte_count = record.get("bytes")
            if (
                scheduled is None or started is None or completed is None
                or duration is None or duration < 0
                or not scheduled <= started <= completed
                or abs(duration - (completed - started) * 1000) > 2.0
                or isinstance(byte_count, bool)
                or not isinstance(byte_count, int) or byte_count < 0
                or not isinstance(record.get("sha256"), str)
                or SHA256_RE.fullmatch(record["sha256"]) is None
                or not isinstance(record.get("result"), str)
                or (record.get("exit") is not None
                    and (isinstance(record["exit"], bool)
                         or not isinstance(record["exit"], int)))
            ):
                schema_errors.append(
                    f"line {line_number}: invalid bounded operation record"
                )
                continue
            operations[operation].append(record)
            if record["result"] != "ok":
                failures.append({
                    "operation": operation,
                    "result": record["result"],
                    "exit": record.get("exit"),
                })
            elif operation == "metrics" and record.get("exit") != 200:
                failures.append({
                    "operation": operation,
                    "result": "invalid_http_success",
                    "exit": record.get("exit"),
                })
            elif operation != "metrics" and record.get("exit") != 0:
                failures.append({
                    "operation": operation,
                    "result": "invalid_cli_success",
                    "exit": record.get("exit"),
                })
            elif byte_count == 0:
                failures.append({
                    "operation": operation,
                    "result": "empty_success",
                    "exit": record.get("exit"),
                })
        else:
            schema_errors.append(f"line {line_number}: unknown record type {kind!r}")

    if len(starts) != 1:
        schema_errors.append(f"expected one start record, found {len(starts)}")
    if len(summaries) != 1:
        schema_errors.append(f"expected one terminal summary, found {len(summaries)}")
    if records and records[0].get("record") != "start":
        schema_errors.append("start record is not first")
    if records and records[-1].get("record") != "summary":
        schema_errors.append("terminal summary is not last")

    expected_intervals = {
        "metrics": meta.get("management_metrics_interval_sec"),
        "neighbor": meta.get("management_cli_interval_sec"),
        "policy_stats": meta.get("management_cli_interval_sec"),
        "rib_prefix": meta.get("management_cli_interval_sec"),
    }
    expected_timeout = meta.get("management_timeout_sec")
    expected_peers = meta.get("peers")
    expected_prefix = meta.get("management_route_prefix")
    derived_prefix = expected_management_route_prefix(meta.get("routes_per_peer"))
    for operation, interval in expected_intervals.items():
        parsed = finite_number(interval)
        if parsed is None or parsed <= 0:
            schema_errors.append(
                f"run metadata has invalid {operation} interval"
            )
    parsed_timeout = finite_number(expected_timeout)
    if parsed_timeout is None or parsed_timeout <= 0:
        schema_errors.append("run metadata has invalid management timeout")
    if (
        isinstance(expected_peers, bool) or not isinstance(expected_peers, int)
        or expected_peers <= 0
    ):
        schema_errors.append("run metadata has invalid peer cardinality")
    if derived_prefix is None:
        schema_errors.append(
            "run metadata routes_per_peer cannot map to a management route prefix"
        )
    elif expected_prefix != derived_prefix:
        schema_errors.append(
            "run metadata management route prefix mismatches stub 1 first route"
        )
    started_at = None
    summary_end = None
    stop_requested = None
    summary_scheduled = {operation: 0 for operation in MANAGEMENT_OPERATIONS}
    summary_completed = {operation: 0 for operation in MANAGEMENT_OPERATIONS}
    summary_missed = {operation: 0 for operation in MANAGEMENT_OPERATIONS}

    if len(starts) == 1:
        start = starts[0]
        started_at = finite_number(start.get("started_monotonic"))
        if (
            started_at is None
            or start.get("operations") != list(MANAGEMENT_OPERATIONS)
            or start.get("interval_seconds") != expected_intervals
            or start.get("timeout_seconds") != expected_timeout
            or start.get("peer_count") != expected_peers
            or start.get("route_prefix") != expected_prefix
        ):
            schema_errors.append("start record does not match run metadata")

    if len(summaries) == 1:
        summary = summaries[0]
        summary_start = finite_number(summary.get("started_monotonic"))
        stop_requested = finite_number(summary.get("stop_requested_monotonic"))
        summary_end = finite_number(summary.get("completed_monotonic"))
        duration = finite_number(summary.get("duration_ms"))
        if (
            summary_start is None or stop_requested is None
            or summary_end is None or duration is None
            or not summary_start <= stop_requested <= summary_end
            or abs(duration - (summary_end - summary_start) * 1000) > 2.0
            or summary.get("operation") != "summary"
            or summary.get("exit") != 0
            or summary.get("result") != "clean_sigterm"
            or summary.get("signal") != "SIGTERM"
            or summary.get("bytes") != 0
            or SHA256_RE.fullmatch(str(summary.get("sha256", ""))) is None
            or summary.get("interval_seconds") != expected_intervals
            or summary.get("timeout_seconds") != expected_timeout
            or summary.get("peer_count") != expected_peers
            or summary.get("route_prefix") != expected_prefix
            or started_at is None or abs(summary_start - started_at) > 0.001
        ):
            schema_errors.append("terminal summary is invalid or mismatches metadata")
        for field, target in (
            ("scheduled", summary_scheduled),
            ("completed", summary_completed),
            ("missed", summary_missed),
        ):
            value = summary.get(field)
            if not isinstance(value, dict) or set(value) != set(MANAGEMENT_OPERATIONS):
                schema_errors.append(f"terminal summary has invalid {field} counts")
                continue
            for operation in MANAGEMENT_OPERATIONS:
                count = value[operation]
                if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                    schema_errors.append(
                        f"terminal summary has invalid {field}.{operation}"
                    )
                else:
                    target[operation] = count

    count_mismatches = []
    coverage = {}
    cadence_defects = []
    for operation in MANAGEMENT_OPERATIONS:
        observed = len(operations[operation])
        if summary_completed[operation] != observed:
            count_mismatches.append(
                f"{operation}: summary completed={summary_completed[operation]} "
                f"observed={observed}"
            )
        if summary_scheduled[operation] != (
            summary_completed[operation] + summary_missed[operation]
        ):
            count_mismatches.append(f"{operation}: scheduled != completed + missed")
        scheduled = summary_scheduled[operation]
        ratio = observed / scheduled if scheduled else 0.0
        coverage[operation] = {
            "scheduled": scheduled,
            "completed": observed,
            "ratio": ratio,
        }
        if summary_missed[operation] != 0:
            cadence_defects.append(
                f"{operation}: missed={summary_missed[operation]}"
            )
        interval = finite_number(expected_intervals.get(operation))
        if started_at is not None and stop_requested is not None and interval and interval > 0:
            schedules = [
                finite_number(record.get("scheduled_monotonic"))
                for record in operations[operation]
            ]
            if schedules and schedules[0] is not None:
                if abs(schedules[0] - started_at) > 0.002:
                    cadence_defects.append(
                        f"{operation}: first schedule does not start with load"
                    )
                for previous, current in zip(schedules, schedules[1:]):
                    if (
                        previous is None or current is None
                        or abs((current - previous) - interval) > 0.002
                    ):
                        cadence_defects.append(
                            f"{operation}: scheduled interval drift"
                        )
                        break
            active_lifetime = stop_requested - started_at
            expected_floor = max(
                1,
                math.floor(max(0.0, active_lifetime - 0.1) / interval) + 1,
            )
            if scheduled < expected_floor:
                cadence_defects.append(
                    f"{operation}: scheduled={scheduled} expected>={expected_floor}"
                )

    measured_start = finite_number(meta.get("measured_start_monotonic"))
    measured_end = finite_number(meta.get("measured_end_monotonic"))
    brackets = (
        started_at is not None and stop_requested is not None
        and summary_end is not None
        and measured_start is not None and measured_end is not None
        and started_at <= measured_start <= measured_end
        <= stop_requested <= summary_end
    )

    return {
        "management_evidence": {
            "value": {"errors": schema_errors[:20], "count_mismatches": count_mismatches},
            "pass": not schema_errors and not count_mismatches,
        },
        "management_lifetime": {
            "value": {
                "load_start": started_at,
                "measured_start": measured_start,
                "measured_end": measured_end,
                "stop_requested": stop_requested,
                "load_end": summary_end,
            },
            "pass": brackets,
        },
        "management_operations": {
            "value": {operation: len(records) for operation, records in operations.items()},
            "pass": all(operations[operation] for operation in MANAGEMENT_OPERATIONS),
        },
        "management_completion": {
            "value": coverage,
            "limit": 0.9,
            "pass": all(item["ratio"] >= 0.9 for item in coverage.values()),
        },
        "management_cadence": {
            "value": cadence_defects,
            "pass": not cadence_defects,
        },
        "management_failures": {
            "value": {"count": len(failures), "first": failures[:20]},
            "pass": not failures,
        },
    }


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

    load_file = meta.get("management_load_file")
    if load_file != "management-plane-load.jsonl":
        print("error: run.json has invalid management_load_file", file=sys.stderr)
        return 2
    try:
        with open(f"{args.run_dir}/{load_file}", "rb") as f:
            management_raw = f.read()
    except OSError as e:
        print(f"error reading management-plane evidence: {e}", file=sys.stderr)
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
    result["gates"].update(analyze_management_load(management_raw, meta))
    result["verdict"] = (
        "pass" if all(gate["pass"] for gate in result["gates"].values())
        else "fail"
    )
    out = json.dumps(result, indent=2)
    print(out)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
    return 0 if result["verdict"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
