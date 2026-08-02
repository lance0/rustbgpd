#!/usr/bin/env python3
"""Fail-closed contracts for the M67 link-drain soak analyzer."""

import csv
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).parent
FIELDS = [
    "elapsed_sec", "cycle", "phase", "pe1_rss_mb", "pe2_rss_mb",
    "vtep_rss_mb", "pe1_session_established", "pe2_session_established",
    "pe1_restart_count", "pe2_restart_count", "vtep_restart_count",
    "pe1_link_drain", "pe1_operator_drain", "pe2_df", "pe2_nondf",
    "blackout_ms", "release_ms", "failures",
]
BASE_ROWS = [
    {
        "elapsed_sec": "0", "cycle": "0", "phase": "drained",
        "pe1_rss_mb": "10", "pe2_rss_mb": "10", "vtep_rss_mb": "10",
        "pe1_restart_count": "0", "pe2_restart_count": "0",
        "vtep_restart_count": "0", "pe1_link_drain": "1",
        "pe1_operator_drain": "0", "pe2_df": "1", "pe2_nondf": "0",
        "blackout_ms": "100", "release_ms": "", "failures": "0",
    },
    {
        "elapsed_sec": "10", "cycle": "1", "phase": "recovered",
        "pe1_rss_mb": "10", "pe2_rss_mb": "10", "vtep_rss_mb": "10",
        "pe1_restart_count": "0", "pe2_restart_count": "0",
        "vtep_restart_count": "0", "pe1_link_drain": "0",
        "pe1_operator_drain": "0", "pe2_df": "0", "pe2_nondf": "1",
        "blackout_ms": "", "release_ms": "100", "failures": "0",
    },
    {
        "elapsed_sec": "20", "cycle": "1", "phase": "idle",
        "pe1_rss_mb": "10", "pe2_rss_mb": "10", "vtep_rss_mb": "10",
        "pe1_restart_count": "0", "pe2_restart_count": "0",
        "vtep_restart_count": "0", "pe1_link_drain": "0",
        "pe1_operator_drain": "0", "pe2_df": "0", "pe2_nondf": "1",
        "blackout_ms": "", "release_ms": "", "failures": "0",
    },
]


def run_analyzer(pe1_states, pe2_states):
    rows = [dict(row) for row in BASE_ROWS]
    for row, pe1, pe2 in zip(rows, pe1_states, pe2_states):
        row["pe1_session_established"] = pe1
        row["pe2_session_established"] = pe2
    with tempfile.TemporaryDirectory() as tmp:
        samples = Path(tmp) / "samples.csv"
        with samples.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        result = subprocess.run(
            ["python3", str(HERE / "analyze-m67-link-drain-soak.py"),
             str(samples)],
            text=True, capture_output=True, check=False,
        )
    return result, json.loads(result.stdout)


class M67AnalyzerContracts(unittest.TestCase):
    # Destructive proof: deleting the terminal gate makes both terminal-down
    # cases return 0; deleting either peer clause breaks its matching case.
    def test_terminal_sessions_must_both_be_established(self):
        cases = (
            ("recovered", ["0", "0", "1"], ["0", "0", "1"], True),
            ("pe1_terminal_down", ["1", "0", "0"], ["1", "1", "1"], False),
            ("pe2_terminal_down", ["1", "1", "1"], ["1", "0", "0"], False),
        )
        for scenario, pe1_states, pe2_states, expected_pass in cases:
            with self.subTest(scenario=scenario):
                result, payload = run_analyzer(pe1_states, pe2_states)
                gates = {gate["name"]: gate for gate in payload["gates"]}
                self.assertEqual(result.returncode, 0 if expected_pass else 1,
                                 result.stderr)
                self.assertTrue(gates["sessions_stayed_established"]["pass"])
                if expected_pass:
                    self.assertTrue(all(gate["pass"] for gate in gates.values()), payload)
                else:
                    self.assertFalse(gates["sessions_established_at_end"]["pass"])
                    self.assertTrue(all(
                        gate["pass"] for name, gate in gates.items()
                        if name != "sessions_established_at_end"
                    ), payload)


if __name__ == "__main__":
    unittest.main()
