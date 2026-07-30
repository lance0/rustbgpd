#!/usr/bin/env python3
"""Cheap fail-closed contracts for the intern/churn soak evidence."""

import csv
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).parent


def run_analyzer(name, fields, rows):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "samples.csv"
        with path.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
        return subprocess.run(
            ["python3", str(HERE / name), tmp],
            text=True, capture_output=True, check=False,
        )


BASE = {
    "timestamp": "2026-01-01T00:00:00Z",
    "rss_mb": "10", "intern_size": "5", "bgp_established": "1",
}


class AnalyzerContracts(unittest.TestCase):
    def test_gr_requires_ordered_positive_phase_and_clear(self):
        fields = [*BASE, "elapsed_sec", "gr_active_peers", "gr_stale_routes",
                  "restart_cycles"]
        rows = [
            {**BASE, "elapsed_sec": "0", "gr_active_peers": "0",
             "gr_stale_routes": "0", "restart_cycles": "0"},
            {**BASE, "elapsed_sec": "3600", "gr_active_peers": "1",
             "gr_stale_routes": "2", "restart_cycles": "0"},
            {**BASE, "elapsed_sec": "7200", "gr_active_peers": "0",
             "gr_stale_routes": "0", "restart_cycles": "1"},
        ]
        result = run_analyzer("analyze-soak-gr-restart.py", fields, rows)
        self.assertEqual(result.returncode, 0, result.stderr)
        rows[1]["gr_active_peers"] = rows[1]["gr_stale_routes"] = "0"
        result = run_analyzer("analyze-soak-gr-restart.py", fields, rows)
        self.assertEqual(result.returncode, 1)

    def test_hot_reload_requires_exact_success_and_continuity(self):
        fields = [*BASE, "elapsed_sec", "apply_cycles", "apply_ok", "apply_fail",
                  "flap_count", "uptime_seconds"]
        rows = [
            {**BASE, "elapsed_sec": "0", "apply_cycles": "0", "apply_ok": "0",
             "apply_fail": "0", "flap_count": "3", "uptime_seconds": "10"},
            {**BASE, "elapsed_sec": "3600", "apply_cycles": "1", "apply_ok": "1",
             "apply_fail": "0", "flap_count": "3", "uptime_seconds": "3610"},
        ]
        result = run_analyzer("analyze-soak-hot-reload.py", fields, rows)
        self.assertEqual(result.returncode, 0, result.stderr)
        rows[-1]["apply_cycles"], rows[-1]["apply_fail"] = "2", "1"
        self.assertEqual(
            run_analyzer("analyze-soak-hot-reload.py", fields, rows).returncode, 1
        )
        rows[-1]["apply_cycles"], rows[-1]["apply_fail"] = "1", "0"
        rows[-1]["flap_count"] = "4"
        self.assertEqual(
            run_analyzer("analyze-soak-hot-reload.py", fields, rows).returncode, 1
        )

    def test_injection_requires_exact_final_consumer_and_continuity(self):
        fields = [*BASE, "elapsed_sec", "live_target", "frr_route_count",
                  "churn_cycles", "add_total", "del_total", "flap_count",
                  "uptime_seconds"]
        rows = [
            {**BASE, "elapsed_sec": "0", "live_target": "1024",
             "frr_route_count": "0", "churn_cycles": "0", "add_total": "1024",
             "del_total": "0", "flap_count": "0", "uptime_seconds": "10"},
            {**BASE, "elapsed_sec": "3600", "live_target": "1024",
             "frr_route_count": "1024", "churn_cycles": "1", "add_total": "1049",
             "del_total": "25", "flap_count": "0", "uptime_seconds": "3610"},
        ]
        result = run_analyzer("analyze-soak-inject-churn.py", fields, rows)
        self.assertEqual(result.returncode, 0, result.stderr)
        rows[-1]["frr_route_count"] = "0"
        self.assertEqual(
            run_analyzer("analyze-soak-inject-churn.py", fields, rows).returncode, 1
        )
        rows[-1]["frr_route_count"], rows[-1]["flap_count"] = "1024", "1"
        self.assertEqual(
            run_analyzer("analyze-soak-inject-churn.py", fields, rows).returncode, 1
        )

    def test_missing_or_malformed_required_evidence_is_input_error(self):
        cases = [
            ("analyze-soak-gr-restart.py", "gr_stale_routes",
             ["elapsed_sec", "rss_mb", "intern_size", "gr_active_peers",
              "gr_stale_routes", "bgp_established", "restart_cycles"]),
            ("analyze-soak-hot-reload.py", "flap_count",
             ["elapsed_sec", "rss_mb", "intern_size", "bgp_established",
              "apply_cycles", "apply_ok", "apply_fail", "flap_count",
              "uptime_seconds"]),
            ("analyze-soak-inject-churn.py", "frr_route_count",
             ["elapsed_sec", "rss_mb", "intern_size", "live_target",
              "frr_route_count", "bgp_established", "churn_cycles",
              "add_total", "del_total", "flap_count", "uptime_seconds"]),
        ]
        for analyzer, required, fields in cases:
            with self.subTest(analyzer=analyzer):
                row = {field: "0" for field in fields}
                present = [field for field in fields if field != required]
                result = run_analyzer(
                    analyzer, present, [{field: row[field] for field in present}]
                )
                self.assertEqual(result.returncode, 2)
                row[required] = "not-a-number"
                result = run_analyzer(analyzer, fields, [row])
                self.assertEqual(result.returncode, 2)

    def test_injection_commands_propagate_failure(self):
        script = HERE / "run-soak-inject-churn.sh"
        command = f"""
source {script!s}
docker() {{ return 17; }}
rb_inject_add 10.0.0.0/24
"""
        result = subprocess.run(
            ["bash", "-c", command], text=True, capture_output=True, check=False
        )
        self.assertEqual(result.returncode, 17)

    def test_runners_are_sourceable_and_end_with_analyzer_gate(self):
        for script in (
            "run-soak-gr-restart-intern-gc.sh",
            "run-soak-hot-reload.sh",
            "run-soak-inject-churn.sh",
        ):
            with self.subTest(script=script):
                path = HERE / script
                result = subprocess.run(
                    ["bash", "-c", f"source {path!s}"],
                    text=True, capture_output=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                text = path.read_text()
                self.assertRegex(text, r'python3 .*analyze-soak-.* --output ')
                self.assertIn('BASH_SOURCE[0]', text)

    def test_runner_commands_are_load_bearing(self):
        inject = (HERE / "run-soak-inject-churn.sh").read_text()
        self.assertNotRegex(
            inject, r'rbgp .* rib (?:add|delete).*?(?:\|\| true)',
        )
        self.assertIn('count=$(frr_route_count)', inject)
        hot = (HERE / "run-soak-hot-reload.sh").read_text()
        self.assertIn(
            'docker cp "$CANDIDATE_TOML" "$RUSTBGPD:/tmp/candidate.toml"',
            hot,
        )
        self.assertIn('run_apply_cycle "$cycles"', hot)
        gr = (HERE / "run-soak-gr-restart-intern-gc.sh").read_text()
        self.assertIn('frrinit.sh stop >/dev/null', gr)
        self.assertIn('frrinit.sh start >/dev/null', gr)
        self.assertNotIn('frrinit.sh stop >/dev/null 2>&1 || true', gr)
        self.assertNotIn('frrinit.sh start >/dev/null 2>&1 || true', gr)


if __name__ == "__main__":
    unittest.main()
