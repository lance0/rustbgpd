#!/usr/bin/env python3
"""Load-bearing contracts for Gate 8b terminal recovery evidence."""

import csv
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).parent
FIELDS = [
    "elapsed_sec", "pe1_rss_mb", "pe2_rss_mb", "pe1_df_changes",
    "pe2_df_changes", "pe1_bum_flags", "pe2_running",
    "pe1_session_established", "pe2_session_established",
    "pe1_established_seen", "pe2_established_seen",
]


def healthy_rows():
    rows = []
    for elapsed, running in enumerate(("1", "0", "0", "1", "1", "1")):
        rows.append({
            "elapsed_sec": str(elapsed * 3600),
            "pe1_rss_mb": "10", "pe2_rss_mb": "10",
            "pe1_df_changes": str(elapsed), "pe2_df_changes": str(elapsed),
            "pe1_bum_flags": "df", "pe2_running": running,
            "pe1_session_established": "1",
            "pe2_session_established": running,
            "pe1_established_seen": "9", "pe2_established_seen": "9",
        })
    return rows


def run_analyzer(fields, rows):
    with tempfile.TemporaryDirectory() as tmp:
        samples = Path(tmp) / "samples.csv"
        with samples.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        result = subprocess.run(
            ["python3", str(HERE / "analyze-gate8b-soak.py"), str(samples)],
            text=True, capture_output=True, check=False,
        )
        report = json.loads(result.stdout) if result.stdout else None
        return result, report


class Gate8bRecoveryContract(unittest.TestCase):
    def test_terminal_recovery_gate_passes_with_deliberate_down_rows(self):
        result, report = run_analyzer(FIELDS, healthy_rows())
        self.assertEqual(result.returncode, 0, result.stderr)
        terminal = next(g for g in report["gates"]
                        if g["name"] == "terminal_sessions_recovered")
        self.assertTrue(terminal["pass"])

    def test_terminal_clauses_fail_independently(self):
        cases = (
            ("pe2_running", "0"),
            ("pe1_session_established", "0"),
            ("pe1_session_established", "NaN"),
            ("pe1_session_established", ""),
            ("pe1_session_established", None),
            ("pe2_session_established", "0"),
            ("pe2_session_established", "NaN"),
            ("pe2_session_established", ""),
            ("pe2_session_established", None),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value):
                rows = healthy_rows()
                if value is None:
                    rows[-1].pop(field)
                else:
                    rows[-1][field] = value
                rows[-1]["pe1_established_seen"] = "99"
                rows[-1]["pe2_established_seen"] = "99"
                result, report = run_analyzer(FIELDS, rows)
                self.assertEqual(result.returncode, 1)
                failed = [g for g in report["gates"] if not g["pass"]]
                self.assertEqual([g["name"] for g in failed],
                                 ["terminal_sessions_recovered"])
                self.assertIn("current=", failed[0]["detail"])

    def test_missing_current_headers_are_input_errors(self):
        for field in ("pe1_session_established", "pe2_session_established"):
            with self.subTest(field=field):
                fields = [name for name in FIELDS if name != field]
                result, report = run_analyzer(fields, healthy_rows())
                self.assertEqual(result.returncode, 2)
                self.assertIsNone(report)
                self.assertIn(field, result.stderr)

    def test_shared_helper_orders_recovery_before_one_evidence_row(self):
        helper = HERE / "gate8b-terminal-recovery.sh"
        body = r'''
events=$(mktemp); PE2_RUNNING=$INITIAL
recover() { echo recover >>"$events"; [ "$MODE" != fail ] || return 7; PE2_RUNNING=1; }
sample() { echo "sample:$PE2_RUNNING" >>"$events"; [ "$MODE" != sample-fail ] || return 8; }
gate8b_terminal_recovery "$PE2_RUNNING" recover sample
rc=$?; cat "$events"; exit "$rc"
'''
        for mode, initial, code, events in (
            ("up", "1", 0, ["sample:1"]),
            ("recover", "0", 0, ["recover", "sample:1"]),
            ("fail", "0", 7, ["recover", "sample:0"]),
            ("sample-fail", "1", 8, ["sample:1"]),
        ):
            with self.subTest(mode=mode):
                result = subprocess.run(
                    ["bash", "-c", f"source {helper}\nMODE={mode} INITIAL={initial}\n{body}"],
                    text=True, capture_output=True, check=False,
                )
                self.assertEqual(result.returncode, code)
                self.assertEqual(result.stdout.splitlines(), events)

    def test_runners_bind_terminal_helper_and_current_state(self):
        base = (HERE / "run-gate8b-soak.sh").read_text()
        mac = (HERE / "run-gate8b-mac-churn-soak.sh").read_text()
        columns = "pe2_running,pe1_session_established,pe2_session_established"
        for source in (base, mac):
            self.assertIn(columns, source)
            self.assertEqual(source.count("gate8b_terminal_recovery \"$PE2_RUNNING\""), 1)
            self.assertLess(source.rindex("done\n"), source.index("gate8b_terminal_recovery \"$PE2_RUNNING\""))
            sample = source[source.index("sample_row() {"):source.index("\n}\n", source.index("sample_row() {"))]
            self.assertEqual(sample.count('prom_scrape "$PE1_NAME"'), 1)
            self.assertEqual(sample.count('prom_scrape "$PE2_NAME"'), 1)
        self.assertIn("restart_pe2 || return", base)
        self.assertIn("reattach_pe2_log", base)
        self.assertIn("start_pe2_daemon || return", mac)
        self.assertIn("verify_topology_link || return", mac)
        self.assertIn('prom_established_total "$PE1_PROM"', mac)
        self.assertNotIn("pe_established_total", mac)


if __name__ == "__main__":
    unittest.main()
