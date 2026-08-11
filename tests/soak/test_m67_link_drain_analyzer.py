#!/usr/bin/env python3
"""Fail-closed contracts for the M67 link-drain soak analyzer."""

import csv
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).parent
ORACLE = HERE / "m67-vtep-route-oracles.sh"
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


class M67VtepRouteOracleContracts(unittest.TestCase):
    def run_shell(self, body):
        return subprocess.run(
            ["bash", "-c", body, "bash", str(ORACLE)],
            text=True, capture_output=True, check=False,
        )

    def test_source_is_inert(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                ["bash", "-c", r'''
                    set -u
                    cd "$2"
                    docker() { return 99; }
                    before=$(trap -p)
                    source "$1"
                    [ "$(trap -p)" = "$before" ]
                    [ "$(find . -mindepth 1 -print -quit)" = "" ]
                    [ "$(declare -F | awk '{print $3}' | sort)" = \
                      "docker
vtep_route_count
vtep_routes
wait_vtep_routes_at_least
wait_vtep_routes_gone" ]
                ''', "bash", str(ORACLE), tmp],
                text=True, capture_output=True, check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")

    def test_route_oracle_matrix(self):
        result = self.run_shell(r'''
            set -euo pipefail
            source "$1"
            sleep() { :; }
            case_name=""
            counter=$(mktemp)
            trap 'rm -f "$counter"' EXIT
            printf '0\n' >"$counter"

            vtep_ctl() {
                case "$case_name" in
                    exit42) printf '[]\n'; return 42 ;;
                    malformed) printf '[\n' ;;
                    object) printf '{"route":1}\n' ;;
                    null) printf 'null\n' ;;
                    scalar) printf '7\n' ;;
                    nonobject) printf '[{"up":true},7]\n' ;;
                    multiple) printf '[]\n[]\n' ;;
                    empty) printf '[]\n' ;;
                    routes) printf '[{"up":true},{"up":false}]\n' ;;
                    transient|nonmatch_failure)
                        seen=$(<"$counter")
                        printf '%s\n' "$((seen + 1))" >"$counter"
                        if [ "$seen" -eq 0 ]; then
                            if [ "$case_name" = transient ]; then
                                printf '[]\n'; return 42
                            fi
                            printf '[]\n'; return 0
                        fi
                        printf '[]\n'
                        if [ "$case_name" = transient ]; then return 0; fi
                        return 42 ;;
                    *) return 99 ;;
                esac
            }

            expect() {
                want_rc=$1 want_out=$2 want_err=$3
                shift 3
                out=$(mktemp) err=$(mktemp)
                set +e
                "$@" >"$out" 2>"$err"
                rc=$?
                set -e
                [ "$rc" -eq "$want_rc" ]
                [ "$(cat "$out")" = "$want_out" ]
                if [ "$want_err" = yes ]; then [ -s "$err" ]; else [ ! -s "$err" ]; fi
                rm -f "$out" "$err"
            }
            sample_field() { printf 'x,%s,y\n' "$(vtep_route_count 2 192.0.2.1)"; }

            for case_name in exit42 malformed object null scalar nonobject multiple; do
                expect 2 "" yes vtep_routes 2 192.0.2.1
            done
            case_name=exit42
            expect 2 "" yes vtep_route_count 2 192.0.2.1 true
            expect 2 "" yes wait_vtep_routes_at_least 2 192.0.2.1 true 1 1
            expect 2 "" yes wait_vtep_routes_gone 2 192.0.2.1 true 1
            case_name=empty
            expect 0 '[]' no vtep_routes 2 192.0.2.1
            expect 0 0 no vtep_route_count 2 192.0.2.1 true
            expect 0 "" no wait_vtep_routes_gone 2 192.0.2.1 true 1
            case_name=routes
            expect 0 1 no vtep_route_count 2 192.0.2.1 '.up == true'
            expect 0 "" no wait_vtep_routes_at_least 2 192.0.2.1 '.up == true' 1 1
            expect 1 "" no wait_vtep_routes_gone 2 192.0.2.1 true 1
            expect 2 "" yes vtep_route_count 2 192.0.2.1 'invalid('
            case_name=transient; printf '0\n' >"$counter"
            expect 0 "" yes wait_vtep_routes_gone 2 192.0.2.1 true 2
            case_name=nonmatch_failure; printf '0\n' >"$counter"
            expect 2 "" yes wait_vtep_routes_at_least 2 192.0.2.1 true 1 2
            case_name=exit42
            expect 0 'x,,y' yes sample_field
        ''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
