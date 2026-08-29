#!/usr/bin/env python3
"""Load-bearing gate contracts for the route-server flagship soak analyzer."""

import csv
import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).parent
ANALYZER = HERE / "analyze-soak-rs-flagship.py"
ANALYZER_SPEC = importlib.util.spec_from_file_location("rs_soak_analyzer", ANALYZER)
assert ANALYZER_SPEC is not None and ANALYZER_SPEC.loader is not None
analyzer = importlib.util.module_from_spec(ANALYZER_SPEC)
ANALYZER_SPEC.loader.exec_module(analyzer)
T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)

FIELDS = [
    "timestamp", "elapsed_sec", "rss_mb", "intern_size", "established",
    "flaps_total", "msgs_sent_total", "max_prefix_exceeded_total",
    "readyz_code", "readyz_ms",
]


def ts(elapsed):
    return (T0 + timedelta(seconds=elapsed)).strftime("%Y-%m-%dT%H:%M:%SZ")


def cline(elapsed, body):
    return f"[{ts(elapsed)}] {body}"


def smoke_meta(**over):
    meta = {
        "peers": 12, "routes_per_peer": 50, "total_prefixes": 600,
        "soak_seconds": 240, "sample_interval_sec": 30, "warmup_sec": 30,
        "planned_reloads": 4, "planned_trips": 2, "trip_every": 2,
        "max_prefixes": 100, "trip_restart_seconds": 20,
        "management_load_file": "management-plane-load.jsonl",
        "management_metrics_interval_sec": 30,
        "management_cli_interval_sec": 60,
        "management_timeout_sec": 5,
        "management_route_prefix": "20.0.50.0/24",
    }
    meta.update(over)
    meta.setdefault("measured_start_monotonic", 1000.1)
    meta.setdefault(
        "measured_end_monotonic",
        meta["measured_start_monotonic"] + meta["soak_seconds"],
    )
    return meta


def trip_block(n, start, restart_sec=20, exceeded=None, holddown=None):
    """Full evidence chain for one trip starting at `start` elapsed sec."""
    exceeded = n if exceeded is None else exceeded
    holddown = restart_sec if holddown is None else holddown
    down = start + 1
    up = down + holddown
    return [
        cline(start, f"trip {n} announce_over"),
        cline(down, f"trip {n} torn_down"),
        cline(down + 1, f"trip {n} exceeded_total={exceeded}"),
        cline(down + 2, f"trip {n} countdown_ms={restart_sec * 1000 - 1000} "
                        "action=restart"),
        cline(up, f"trip {n} reestablished"),
        cline(up + 1, f"trip {n} reannounced"),
        cline(up + 4, f"trip {n} complete usage=50 limit=100 headroom=50"),
    ]


def smoke_cycles():
    lines = []
    for r, at in ((1, 40), (2, 55), (3, 130), (4, 200)):
        lines.append(cline(at, f"reload {r} issued"))
        lines.append(cline(at + 5, f"reload {r} complete"))
    lines += trip_block(1, 60)
    lines += trip_block(2, 150)
    return lines


def smoke_rows():
    rows = []
    for i, elapsed in enumerate(range(0, 241, 30)):
        # Trip 1 window covers elapsed 60; trip 2 covers 150: the dip at 60
        # is the designated member's declared teardown.
        established = 11 if elapsed == 60 else 12
        flaps = 0 if elapsed < 60 else (1 if elapsed < 150 else 2)
        exceeded = 0 if elapsed < 60 else (1 if elapsed < 150 else 2)
        rows.append({
            "timestamp": ts(elapsed), "elapsed_sec": str(elapsed),
            "rss_mb": "100.0", "intern_size": "1000",
            "established": str(established), "flaps_total": str(flaps),
            "msgs_sent_total": str(1000 + i * 500),
            "max_prefix_exceeded_total": str(exceeded),
            "readyz_code": "200", "readyz_ms": "5.0",
        })
    return rows


def long_meta():
    return smoke_meta(soak_seconds=86400, sample_interval_sec=3600,
                      warmup_sec=300, planned_reloads=48, planned_trips=6,
                      trip_every=8, management_metrics_interval_sec=3600,
                      management_cli_interval_sec=7200,
                      measured_end_monotonic=87400.1)


def long_cycles():
    lines = []
    for r in range(1, 49):
        at = r * 1700
        lines.append(cline(at, f"reload {r} issued"))
        lines.append(cline(at + 10, f"reload {r} complete"))
    for n in range(1, 7):
        lines += trip_block(n, n * 14000 + 100)
    return lines


def long_rows(rss_of=None):
    rows = []
    for i, elapsed in enumerate(range(0, 86401, 3600)):
        rss = 1000.0 if rss_of is None else rss_of(elapsed)
        trips_done = min(6, max(0, (elapsed - 100) // 14000))
        rows.append({
            "timestamp": ts(elapsed), "elapsed_sec": str(elapsed),
            "rss_mb": f"{rss:.1f}", "intern_size": "1000",
            "established": "12", "flaps_total": str(trips_done),
            "msgs_sent_total": str(10_000 + i * 5000),
            "max_prefix_exceeded_total": str(trips_done),
            "readyz_code": "200", "readyz_ms": "5.0",
        })
    return rows


def management_jsonl(meta, *, missing_operation=None, early=False,
                     missed=False, failure=None, terminal=True,
                     truncated=False, cadence_gap=False):
    operations = ("metrics", "neighbor", "policy_stats", "rib_prefix")
    start = meta["measured_start_monotonic"] - 0.1
    end = (meta["measured_end_monotonic"] - 1.0 if early
           else meta["measured_end_monotonic"] + 0.1)
    intervals = {
        "metrics": meta["management_metrics_interval_sec"],
        "neighbor": meta["management_cli_interval_sec"],
        "policy_stats": meta["management_cli_interval_sec"],
        "rib_prefix": meta["management_cli_interval_sec"],
    }
    records = [{
        "record": "start", "started_monotonic": start,
        "operations": list(operations), "interval_seconds": intervals,
        "timeout_seconds": meta["management_timeout_sec"],
        "peer_count": meta["peers"],
        "route_prefix": meta["management_route_prefix"],
    }]
    completed = {}
    scheduled = {}
    missed_counts = {operation: 0 for operation in operations}
    digest = hashlib.sha256(b"{}").hexdigest()
    for operation in operations:
        interval = intervals[operation]
        count = max(1, int(max(0.0, end - start - 0.1) // interval) + 1)
        if operation == missing_operation:
            count = 0
        completed[operation] = count
        scheduled[operation] = count
        for index in range(count):
            due = start + index * interval
            if cadence_gap and operation == "metrics" and index == 1:
                due += interval / 2
            result = failure if failure and operation == failure[0] else "ok"
            if isinstance(result, tuple):
                result = result[1]
            records.append({
                "record": "operation",
                "scheduled_monotonic": due,
                "started_monotonic": due + 0.001,
                "completed_monotonic": due + 0.002,
                "operation": operation,
                "duration_ms": 1.0,
                "exit": 200 if operation == "metrics" else 0,
                "result": result,
                "bytes": 2,
                "sha256": digest,
            })
    if missed:
        missed_count = int(missed)
        scheduled["metrics"] += missed_count
        missed_counts["metrics"] = missed_count
    if terminal:
        records.append({
            "record": "summary", "started_monotonic": start,
            "stop_requested_monotonic": end - 0.05,
            "completed_monotonic": end, "operation": "summary",
            "duration_ms": (end - start) * 1000, "exit": 0,
            "result": "clean_sigterm", "bytes": 0,
            "sha256": hashlib.sha256(b"").hexdigest(),
            "signal": "SIGTERM", "scheduled": scheduled,
            "completed": completed, "missed": missed_counts,
            "interval_seconds": intervals,
            "timeout_seconds": meta["management_timeout_sec"],
            "peer_count": meta["peers"],
            "route_prefix": meta["management_route_prefix"],
        })
    raw = b"".join(
        (json.dumps(record, separators=(",", ":")) + "\n").encode()
        for record in records
    )
    return raw + (b'{"record":' if truncated else b"")


def run_analyzer(rows, cycles, meta, fields=FIELDS, management=None):
    with tempfile.TemporaryDirectory() as tmp:
        run_dir = Path(tmp)
        with (run_dir / "samples.csv").open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields,
                                    extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        (run_dir / "cycles.log").write_text("\n".join(cycles) + "\n")
        (run_dir / "run.json").write_text(json.dumps(meta))
        evidence = management_jsonl(meta) if management is None else management
        (run_dir / "management-plane-load.jsonl").write_bytes(evidence)
        result = subprocess.run(
            ["python3", str(ANALYZER), str(run_dir)],
            text=True, capture_output=True, check=False,
        )
    payload = json.loads(result.stdout) if result.stdout else None
    return result, payload


class RsFlagshipAnalyzerContracts(unittest.TestCase):
    def test_management_prefix_matches_reloadstall_mapping(self):
        cases = {
            50: "20.0.50.0/24",
            255: "20.0.255.0/24",
            256: "20.1.0.0/24",
            400: "20.1.144.0/24",
            65535: "20.255.255.0/24",
            65536: "21.0.0.0/24",
            15466495: "255.255.255.0/24",
        }
        for routes_per_peer, prefix in cases.items():
            with self.subTest(routes_per_peer=routes_per_peer):
                self.assertEqual(
                    analyzer.expected_management_route_prefix(routes_per_peer),
                    prefix,
                )

    def test_management_prefix_rejects_invalid_route_counts(self):
        for routes_per_peer in (True, 0, -1, 1.0, "400", 15466496):
            with self.subTest(routes_per_peer=routes_per_peer):
                self.assertIsNone(
                    analyzer.expected_management_route_prefix(routes_per_peer)
                )

    def test_clean_smoke_run_passes_with_slope_gates_annotated(self):
        result, payload = run_analyzer(smoke_rows(), smoke_cycles(),
                                       smoke_meta())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(payload["verdict"], "pass")
        # The in-window session dip is the declared trip teardown, not a
        # floor violation.
        self.assertTrue(payload["gates"]["session_floor"]["pass"])
        # Short windows must not silently green-light the slope gates:
        # they pass only with the explicit not-evaluated annotation.
        self.assertFalse(payload["slope_window_evaluated"])
        self.assertIn("not evaluated",
                      payload["gates"]["rss_late_slope_per_hour"]["note"])

    def test_session_dip_outside_trip_window_fails(self):
        rows = smoke_rows()
        rows[-1]["established"] = "11"
        result, payload = run_analyzer(rows, smoke_cycles(), smoke_meta())
        self.assertEqual(result.returncode, 1)
        self.assertFalse(payload["gates"]["session_floor"]["pass"])

    def test_two_members_down_inside_trip_window_fails(self):
        rows = smoke_rows()
        rows[2]["established"] = "10"  # elapsed 60, inside trip 1's window
        result, payload = run_analyzer(rows, smoke_cycles(), smoke_meta())
        self.assertEqual(result.returncode, 1)
        self.assertFalse(payload["gates"]["session_floor"]["pass"])

    def test_missing_countdown_evidence_fails(self):
        cycles = [l for l in smoke_cycles() if "trip 2 countdown_ms" not in l]
        result, payload = run_analyzer(smoke_rows(), cycles, smoke_meta())
        self.assertEqual(result.returncode, 1)
        gate = payload["gates"]["trip_accounting"]
        self.assertFalse(gate["pass"])
        self.assertIn("2", gate["value"]["defects"])

    def test_incomplete_reload_accounting_fails(self):
        cycles = [l for l in smoke_cycles() if "reload 4 complete" not in l]
        result, payload = run_analyzer(smoke_rows(), cycles, smoke_meta())
        self.assertEqual(result.returncode, 1)
        self.assertFalse(payload["gates"]["reload_accounting"]["pass"])

    def test_spurious_latch_off_breaks_exact_exceeded_accounting(self):
        rows = smoke_rows()
        rows[-1]["max_prefix_exceeded_total"] = "3"
        result, payload = run_analyzer(rows, smoke_cycles(), smoke_meta())
        self.assertEqual(result.returncode, 1)
        self.assertFalse(payload["gates"]["exceeded_exact"]["pass"])

    def test_msgs_sent_regression_fails_as_restart_detection(self):
        rows = smoke_rows()
        rows[5]["msgs_sent_total"] = "1"
        result, payload = run_analyzer(rows, smoke_cycles(), smoke_meta())
        self.assertEqual(result.returncode, 1)
        self.assertFalse(payload["gates"]["msgs_sent_monotone"]["pass"])

    def test_rss_over_ceiling_fails(self):
        rows = smoke_rows()
        rows[4]["rss_mb"] = "4000.0"
        result, payload = run_analyzer(rows, smoke_cycles(), smoke_meta())
        self.assertEqual(result.returncode, 1)
        self.assertFalse(payload["gates"]["rss_peak_mb"]["pass"])

    def test_reestablish_over_bound_fails(self):
        cycles = []
        for r, at in ((1, 40), (2, 55), (3, 130), (4, 200)):
            cycles.append(cline(at, f"reload {r} issued"))
            cycles.append(cline(at + 5, f"reload {r} complete"))
        cycles += trip_block(1, 60)
        # Trip 2 re-establishes 200 s after teardown: past the
        # restart_seconds + 60 s bound.
        cycles += trip_block(2, 150, holddown=200)
        result, payload = run_analyzer(smoke_rows(), cycles, smoke_meta())
        self.assertEqual(result.returncode, 1)
        self.assertFalse(payload["gates"]["trip_accounting"]["pass"])

    def test_abort_record_fails(self):
        cycles = smoke_cycles() + [cline(230, "ABORT: daemon died mid-soak")]
        result, payload = run_analyzer(smoke_rows(), cycles, smoke_meta())
        self.assertEqual(result.returncode, 1)
        self.assertFalse(payload["gates"]["no_abort"]["pass"])

    def test_management_load_missing_operation_fails(self):
        meta = smoke_meta()
        result, payload = run_analyzer(
            smoke_rows(), smoke_cycles(), meta,
            management=management_jsonl(meta, missing_operation="policy_stats"),
        )
        self.assertEqual(result.returncode, 1)
        self.assertFalse(payload["gates"]["management_operations"]["pass"])

    def test_management_load_rejects_old_stub_zero_and_mismatched_prefixes(self):
        for prefix in ("20.0.0.0/24", "20.0.51.0/24"):
            with self.subTest(prefix=prefix):
                meta = smoke_meta(management_route_prefix=prefix)
                result, payload = run_analyzer(
                    smoke_rows(), smoke_cycles(), meta,
                    management=management_jsonl(meta),
                )
                self.assertEqual(result.returncode, 1)
                gate = payload["gates"]["management_evidence"]
                self.assertFalse(gate["pass"])
                self.assertTrue(
                    any("mismatches stub 1" in error
                        for error in gate["value"]["errors"])
                )

    def test_management_load_early_death_fails_lifetime_bracket(self):
        meta = smoke_meta()
        result, payload = run_analyzer(
            smoke_rows(), smoke_cycles(), meta,
            management=management_jsonl(meta, early=True),
        )
        self.assertEqual(result.returncode, 1)
        self.assertFalse(payload["gates"]["management_lifetime"]["pass"])

    def test_management_load_missed_cadence_fails(self):
        meta = smoke_meta()
        result, payload = run_analyzer(
            smoke_rows(), smoke_cycles(), meta,
            management=management_jsonl(meta, missed=True),
        )
        self.assertEqual(result.returncode, 1)
        self.assertFalse(payload["gates"]["management_cadence"]["pass"])

    def test_management_load_schedule_gap_fails_even_when_counts_match(self):
        meta = smoke_meta()
        result, payload = run_analyzer(
            smoke_rows(), smoke_cycles(), meta,
            management=management_jsonl(meta, cadence_gap=True),
        )
        self.assertEqual(result.returncode, 1)
        self.assertFalse(payload["gates"]["management_cadence"]["pass"])

    def test_management_load_below_ninety_percent_completion_fails(self):
        meta = smoke_meta()
        result, payload = run_analyzer(
            smoke_rows(), smoke_cycles(), meta,
            management=management_jsonl(meta, missed=2),
        )
        self.assertEqual(result.returncode, 1)
        self.assertFalse(payload["gates"]["management_completion"]["pass"])

    def test_management_load_truncated_jsonl_fails(self):
        meta = smoke_meta()
        result, payload = run_analyzer(
            smoke_rows(), smoke_cycles(), meta,
            management=management_jsonl(meta, truncated=True),
        )
        self.assertEqual(result.returncode, 1)
        self.assertFalse(payload["gates"]["management_evidence"]["pass"])

    def test_management_load_missing_terminal_summary_fails(self):
        meta = smoke_meta()
        result, payload = run_analyzer(
            smoke_rows(), smoke_cycles(), meta,
            management=management_jsonl(meta, terminal=False),
        )
        self.assertEqual(result.returncode, 1)
        self.assertFalse(payload["gates"]["management_evidence"]["pass"])

    def test_management_operation_failure_dispositions_fail(self):
        for disposition in (
            "http_status", "empty", "cli_exit", "timeout", "json",
            "schema", "cardinality", "route",
        ):
            with self.subTest(disposition=disposition):
                meta = smoke_meta()
                result, payload = run_analyzer(
                    smoke_rows(), smoke_cycles(), meta,
                    management=management_jsonl(
                        meta, failure=("neighbor", disposition)
                    ),
                )
                self.assertEqual(result.returncode, 1)
                self.assertFalse(
                    payload["gates"]["management_failures"]["pass"]
                )

    def test_missing_column_is_input_error(self):
        fields = [f for f in FIELDS if f != "max_prefix_exceeded_total"]
        result, _ = run_analyzer(smoke_rows(), smoke_cycles(), smoke_meta(),
                                 fields=fields)
        self.assertEqual(result.returncode, 2)
        self.assertIn("max_prefix_exceeded_total", result.stderr)

    def test_long_window_evaluates_slopes_and_passes_when_flat(self):
        result, payload = run_analyzer(long_rows(), long_cycles(), long_meta())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(payload["slope_window_evaluated"])
        self.assertTrue(payload["gates"]["rss_late_slope_per_hour"]["pass"])

    def test_long_window_late_leak_fails_slope_gate(self):
        def leaking(elapsed):
            return 1000.0 + max(0, elapsed - 64800) / 3600 * 20.0

        result, payload = run_analyzer(long_rows(rss_of=leaking),
                                       long_cycles(), long_meta())
        self.assertEqual(result.returncode, 1)
        self.assertFalse(payload["gates"]["rss_late_slope_per_hour"]["pass"])


if __name__ == "__main__":
    unittest.main()
