#!/usr/bin/env python3
"""Load-bearing gate contracts for the route-reflector flagship soak analyzer."""

import csv
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).parent
ANALYZER = HERE / "analyze-soak-rr-flagship.py"
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
        "peers": 12, "routes_per_peer": 20, "total_prefixes": 240,
        "expected_nonself": 220, "soak_seconds": 240,
        "sample_interval_sec": 30, "warmup_sec": 30,
        # 240 s x 64 nominal cycles/s x 0.5 (the runner's formula).
        "churn_cycle_floor": 7680,
    }
    meta.update(over)
    return meta


def receipt_line(elapsed, **over):
    fields = {
        "peers": 12, "prefixes": 240, "per_peer": 20, "expected": 220,
        "min_unique": 220, "max_unique": 220, "sessions_up": 12,
        "parse_errors": 0, "churn_cycles": 15000,
    }
    fields.update(over)
    joined = ",".join(f"{k}={v}" for k, v in fields.items())
    return cline(elapsed, f"rr_terminal_receipt,{joined}")


def smoke_cycles(receipt_over=None, with_receipt=True, terminal_at=245,
                 recovered_ms=2100):
    lines = []
    for minute in range(5):
        elapsed = minute * 60
        lines.append(cline(elapsed, (
            f"rr_hold elapsed_s={elapsed} churn_cycles={elapsed * 60} "
            "sessions_up=12 rss_mib=200"
        )))
    if terminal_at is not None:
        lines.append(cline(terminal_at, "rr_terminal refresh wall_us=123456"))
    if with_receipt:
        lines.append(receipt_line(250, **(receipt_over or {})))
    if recovered_ms is not None:
        lines.append(cline(252, f"terminal_readyz recovered_ms={recovered_ms}"))
    return lines


def smoke_rows():
    rows = []
    for i, elapsed in enumerate(range(0, 241, 30)):
        rows.append({
            "timestamp": ts(elapsed), "elapsed_sec": str(elapsed),
            "rss_mb": "200.0", "intern_size": "1000",
            "established": "12", "flaps_total": "0",
            "msgs_sent_total": str(1000 + i * 500),
            "max_prefix_exceeded_total": "0",
            "readyz_code": "200", "readyz_ms": "5.0",
        })
    return rows


def long_meta():
    return smoke_meta(soak_seconds=86400, sample_interval_sec=3600,
                      warmup_sec=300, churn_cycle_floor=86400 * 32)


def long_cycles():
    lines = []
    for minute in range(0, 1441, 10):
        elapsed = minute * 60
        lines.append(cline(elapsed, (
            f"rr_hold elapsed_s={elapsed} churn_cycles={elapsed * 60} "
            "sessions_up=12 rss_mib=500"
        )))
    lines.append(cline(86450, "rr_terminal refresh wall_us=987654"))
    lines.append(receipt_line(86500, churn_cycles=86400 * 60))
    lines.append(cline(86505, "terminal_readyz recovered_ms=4800"))
    return lines


def long_rows(rss_of=None):
    rows = []
    for i, elapsed in enumerate(range(0, 86401, 3600)):
        rss = 500.0 if rss_of is None else rss_of(elapsed)
        rows.append({
            "timestamp": ts(elapsed), "elapsed_sec": str(elapsed),
            "rss_mb": f"{rss:.1f}", "intern_size": "1000",
            "established": "12", "flaps_total": "0",
            "msgs_sent_total": str(10_000 + i * 5000),
            "max_prefix_exceeded_total": "0",
            "readyz_code": "200", "readyz_ms": "5.0",
        })
    return rows


def run_analyzer(rows, cycles, meta, fields=FIELDS):
    with tempfile.TemporaryDirectory() as tmp:
        run_dir = Path(tmp)
        with (run_dir / "samples.csv").open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields,
                                    extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        (run_dir / "cycles.log").write_text("\n".join(cycles) + "\n")
        (run_dir / "run.json").write_text(json.dumps(meta))
        result = subprocess.run(
            ["python3", str(ANALYZER), str(run_dir)],
            text=True, capture_output=True, check=False,
        )
    payload = json.loads(result.stdout) if result.stdout else None
    return result, payload


class RrFlagshipAnalyzerContracts(unittest.TestCase):
    def test_clean_smoke_run_passes_with_slope_gates_annotated(self):
        result, payload = run_analyzer(smoke_rows(), smoke_cycles(),
                                       smoke_meta())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(payload["verdict"], "pass")
        self.assertTrue(payload["gates"]["terminal_delivery_exact"]["pass"])
        # Short windows must not silently green-light the slope gates:
        # they pass only with the explicit not-evaluated annotation.
        self.assertFalse(payload["slope_window_evaluated"])
        self.assertIn("not evaluated",
                      payload["gates"]["rss_late_slope_per_hour"]["note"])

    def test_any_post_warmup_session_dip_fails(self):
        rows = smoke_rows()
        rows[-2]["established"] = "11"
        result, payload = run_analyzer(rows, smoke_cycles(), smoke_meta())
        self.assertEqual(result.returncode, 1)
        self.assertFalse(payload["gates"]["session_floor"]["pass"])

    def test_nonzero_flap_delta_fails(self):
        rows = smoke_rows()
        rows[-1]["flaps_total"] = "1"
        result, payload = run_analyzer(rows, smoke_cycles(), smoke_meta())
        self.assertEqual(result.returncode, 1)
        self.assertFalse(payload["gates"]["flap_budget"]["pass"])

    def test_short_terminal_delivery_fails(self):
        cycles = smoke_cycles(receipt_over={"min_unique": 219})
        result, payload = run_analyzer(smoke_rows(), cycles, smoke_meta())
        self.assertEqual(result.returncode, 1)
        gate = payload["gates"]["terminal_delivery_exact"]
        self.assertFalse(gate["pass"])
        self.assertIn("min_unique=219 expected 220", gate["value"]["defects"])

    def test_missing_terminal_receipt_fails(self):
        cycles = smoke_cycles(with_receipt=False)
        result, payload = run_analyzer(smoke_rows(), cycles, smoke_meta())
        self.assertEqual(result.returncode, 1)
        gate = payload["gates"]["terminal_delivery_exact"]
        self.assertFalse(gate["pass"])
        self.assertIn("missing rr_terminal_receipt", gate["value"]["defects"])
        # Churn evidence falls back to the last hold line (the receipt
        # gate alone fails the run).
        self.assertEqual(payload["final_churn_cycles"], 240 * 60)

    def test_terminal_parse_errors_fail(self):
        cycles = smoke_cycles(receipt_over={"parse_errors": 3})
        result, payload = run_analyzer(smoke_rows(), cycles, smoke_meta())
        self.assertEqual(result.returncode, 1)
        self.assertFalse(payload["gates"]["terminal_delivery_exact"]["pass"])

    def test_churn_below_floor_fails(self):
        cycles = smoke_cycles(receipt_over={"churn_cycles": 100})
        result, payload = run_analyzer(smoke_rows(), cycles, smoke_meta())
        self.assertEqual(result.returncode, 1)
        self.assertFalse(payload["gates"]["churn_cycle_floor"]["pass"])

    def test_spurious_max_prefix_latch_fails(self):
        rows = smoke_rows()
        rows[4]["max_prefix_exceeded_total"] = "1"
        result, payload = run_analyzer(rows, smoke_cycles(), smoke_meta())
        self.assertEqual(result.returncode, 1)
        self.assertFalse(payload["gates"]["max_prefix_flat"]["pass"])

    def test_msgs_sent_regression_fails_as_restart_detection(self):
        rows = smoke_rows()
        rows[5]["msgs_sent_total"] = "1"
        result, payload = run_analyzer(rows, smoke_cycles(), smoke_meta())
        self.assertEqual(result.returncode, 1)
        self.assertFalse(payload["gates"]["msgs_sent_monotone"]["pass"])

    def test_msgs_sent_flat_interval_fails_with_exact_first_interval(self):
        rows = smoke_rows()
        rows[5]["msgs_sent_total"] = rows[4]["msgs_sent_total"]
        result, payload = run_analyzer(rows, smoke_cycles(), smoke_meta())
        self.assertEqual(result.returncode, 1)
        self.assertTrue(payload["gates"]["terminal_delivery_exact"]["pass"])
        gate = payload["gates"]["msgs_sent_monotone"]
        self.assertFalse(gate["pass"])
        self.assertEqual(gate["value"]["breaks"], 0)
        self.assertEqual(gate["value"]["flats"], 1)
        self.assertEqual(gate["value"]["first_flat"], {
            "from_timestamp": ts(120),
            "to_timestamp": ts(150),
            "value": 3000,
        })

    def test_hold_window_readyz_503_fails(self):
        # Strictness where the operational claim lives: any non-200 (or
        # >250ms) sample before the terminal-refresh marker fails.
        rows = smoke_rows()
        rows[4]["readyz_code"] = "503"
        rows[4]["readyz_ms"] = "208.0"
        result, payload = run_analyzer(rows, smoke_cycles(), smoke_meta())
        self.assertEqual(result.returncode, 1)
        gate = payload["gates"]["readyz"]
        self.assertFalse(gate["pass"])
        self.assertEqual(gate["value"]["hold_bad_samples"], 1)

    def test_hold_window_slow_200_fails(self):
        rows = smoke_rows()
        rows[4]["readyz_ms"] = "300.0"
        result, payload = run_analyzer(rows, smoke_cycles(), smoke_meta())
        self.assertEqual(result.returncode, 1)
        self.assertFalse(payload["gates"]["readyz"]["pass"])

    def test_terminal_window_503_passes(self):
        # The refresh avalanche may saturate the core actors; a
        # fail-closed 503 inside the terminal-refresh window is the
        # documented busy signal, not a gate failure.
        rows = smoke_rows()
        rows[-1]["readyz_code"] = "503"
        rows[-1]["readyz_ms"] = "208.0"
        cycles = smoke_cycles(terminal_at=235)
        result, payload = run_analyzer(rows, cycles, smoke_meta())
        self.assertEqual(result.returncode, 0, result.stderr)
        gate = payload["gates"]["readyz"]
        self.assertTrue(gate["pass"])
        self.assertEqual(gate["value"]["terminal_window_samples"], 1)

    def test_terminal_window_no_response_fails(self):
        # A timeout/refusal (curl records code 000) is not fail-closed
        # busyness — the endpoint must respond even mid-avalanche.
        rows = smoke_rows()
        rows[-1]["readyz_code"] = "000"
        rows[-1]["readyz_ms"] = "5000.0"
        cycles = smoke_cycles(terminal_at=235)
        result, payload = run_analyzer(rows, cycles, smoke_meta())
        self.assertEqual(result.returncode, 1)
        gate = payload["gates"]["readyz"]
        self.assertFalse(gate["pass"])
        self.assertEqual(gate["value"]["terminal_no_response"], 1)

    def test_missing_recovery_line_fails(self):
        cycles = smoke_cycles(recovered_ms=None)
        result, payload = run_analyzer(smoke_rows(), cycles, smoke_meta())
        self.assertEqual(result.returncode, 1)
        gate = payload["gates"]["readyz"]
        self.assertFalse(gate["pass"])
        self.assertIsNone(gate["value"]["recovered_ms"])

    def test_recovery_over_60s_fails(self):
        cycles = smoke_cycles(recovered_ms=61000)
        result, payload = run_analyzer(smoke_rows(), cycles, smoke_meta())
        self.assertEqual(result.returncode, 1)
        self.assertFalse(payload["gates"]["readyz"]["pass"])

    def test_rss_over_ceiling_fails(self):
        rows = smoke_rows()
        rows[4]["rss_mb"] = "1500.0"
        result, payload = run_analyzer(rows, smoke_cycles(), smoke_meta())
        self.assertEqual(result.returncode, 1)
        self.assertFalse(payload["gates"]["rss_peak_mb"]["pass"])

    def test_abort_record_fails(self):
        cycles = smoke_cycles() + [cline(230, "ABORT: daemon died mid-soak")]
        result, payload = run_analyzer(smoke_rows(), cycles, smoke_meta())
        self.assertEqual(result.returncode, 1)
        self.assertFalse(payload["gates"]["no_abort"]["pass"])

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
            return 500.0 + max(0, elapsed - 64800) / 3600 * 20.0

        result, payload = run_analyzer(long_rows(rss_of=leaking),
                                       long_cycles(), long_meta())
        self.assertEqual(result.returncode, 1)
        self.assertFalse(payload["gates"]["rss_late_slope_per_hour"]["pass"])


if __name__ == "__main__":
    unittest.main()
