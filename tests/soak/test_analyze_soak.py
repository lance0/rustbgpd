#!/usr/bin/env python3
"""Load-bearing terminal-health contracts for the M33 soak analyzer."""

import csv
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).parent
FIELDS = [
    "uptime_sec", "mem_mb", "grpc_ok", "session_flaps_total",
    "outbound_drops_total", "msgs_sent_total", "msgs_recv_total",
    "bgp_sessions_established",
]


def run_analyzer(states, *, terminal=None, omit_header=False):
    rows = []
    for index, state in enumerate(states):
        rows.append({
            "uptime_sec": str(index * 3600), "mem_mb": "10",
            "grpc_ok": "1", "session_flaps_total": "0",
            "outbound_drops_total": "0", "msgs_sent_total": str(index + 1),
            "msgs_recv_total": str(index + 1),
            "bgp_sessions_established": state,
        })
    if terminal is not None:
        rows[-1]["bgp_sessions_established"] = terminal
    fields = [f for f in FIELDS if not (omit_header and f == "bgp_sessions_established")]
    with tempfile.TemporaryDirectory() as tmp:
        samples = Path(tmp) / "samples.csv"
        with samples.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        result = subprocess.run(
            ["python3", str(HERE / "analyze-soak.py"), str(samples),
             "--warmup-sec", "0"],
            text=True, capture_output=True, check=False,
        )
    payload = json.loads(result.stdout) if result.stdout else None
    return result, payload


def run_runner_session_classifier(values):
    runner = (HERE / "run-m33-soak.sh").read_text()
    marker = "    awk '\n"
    start = runner.index(marker) + len(marker)
    end = runner.index("\n    ' <<<\"$body\"", start)
    metrics = "\n".join(
        f'bgp_peer_session_established{{interface="",peer="192.0.2.{index}"}} {value}'
        for index, value in enumerate(values, 1)
    )
    result = subprocess.run(
        ["awk", runner[start:end]],
        input=metrics,
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout.split()[-1]


class M33AnalyzerContracts(unittest.TestCase):
    # Destructive proof: replacing final-row equality with a tail-any predicate
    # makes terminal_down, NaN, blank, and malformed evidence return zero.
    def test_terminal_sample_alone_declares_session_health(self):
        cases = (
            ("recovered", ["0", "1", "1"], 0),
            ("terminal_down", ["1", "1", "0"], 1),
            ("missing_evidence", ["1", "1", "NaN"], 1),
            ("blank_evidence", ["1", "1", ""], 1),
            ("malformed_evidence", ["1", "1", "wat"], 1),
        )
        for name, states, expected in cases:
            with self.subTest(name=name):
                result, payload = run_analyzer(states)
                self.assertEqual(result.returncode, expected, result.stderr)
                health = payload["terminal_session_health"]
                self.assertEqual(health["healthy"], expected == 0)
                self.assertTrue(health["reason"])

    def test_missing_session_health_header_is_input_error(self):
        result, _ = run_analyzer(["1", "1", "1"], omit_header=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("bgp_sessions_established", result.stderr)

    # Destructive proof: changing the production series cardinality, binary
    # validation, or all-established comparison breaks at least one case.
    def test_runner_classifies_exact_three_binary_session_gauges(self):
        cases = (
            ("all_up", ["1", "1", "1"], "1"),
            ("one_down", ["1", "0", "1"], "0"),
            ("missing", ["1", "1"], "NaN"),
            ("extra", ["1", "1", "1", "1"], "NaN"),
            ("malformed", ["1", "wat", "1"], "NaN"),
            ("non_binary", ["1", "2", "1"], "NaN"),
            ("non_finite", ["1", "+Inf", "1"], "NaN"),
        )
        for name, values, expected in cases:
            with self.subTest(name=name):
                self.assertEqual(run_runner_session_classifier(values), expected)

    # Destructive proof: removing the scrape, header, sampler assignment, or
    # analyzer requirement breaks one of these independent bindings.
    def test_runner_and_analyzer_bind_terminal_session_evidence(self):
        runner = (HERE / "run-m33-soak.sh").read_text()
        analyzer = (HERE / "analyze-soak.py").read_text()
        self.assertIn('/^bgp_peer_session_established\\{/', runner)
        self.assertIn("sessions != 3", runner)
        self.assertIn("bgp_sessions_established\" > \"$CSV\"", runner)
        self.assertIn("read -r rib_loc adj_out flaps drops sent recv sessions_ok", runner)
        self.assertIn('"bgp_sessions_established",', analyzer)


if __name__ == "__main__":
    unittest.main()
