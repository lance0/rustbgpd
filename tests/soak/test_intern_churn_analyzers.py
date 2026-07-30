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
        result = run_analyzer("analyze-soak-hot-reload.py", fields, rows)
        self.assertFalse(json.loads(result.stdout)["gates"]["apply_failures"]["pass"])
        self.assertTrue(json.loads(result.stdout)["gates"]["apply_cycles"]["pass"])
        rows[-1]["apply_cycles"], rows[-1]["apply_fail"] = "1", "0"
        rows[-1]["flap_count"] = "4"
        self.assertEqual(
            run_analyzer("analyze-soak-hot-reload.py", fields, rows).returncode, 1
        )
        rows[-1]["flap_count"], rows[-1]["apply_cycles"] = "3", "2"
        result = run_analyzer("analyze-soak-hot-reload.py", fields, rows)
        self.assertFalse(json.loads(result.stdout)["gates"]["apply_cycles"]["pass"])
        self.assertTrue(json.loads(result.stdout)["gates"]["apply_failures"]["pass"])
        rows[-1]["apply_cycles"] = rows[-1]["apply_ok"] = "0"
        result = run_analyzer("analyze-soak-hot-reload.py", fields, rows)
        self.assertFalse(json.loads(result.stdout)["gates"]["apply_failures"]["pass"])

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
                for invalid in ("-1", "1.5"):
                    row[required] = invalid
                    self.assertEqual(run_analyzer(analyzer, fields, [row]).returncode, 2)

    def bash(self, script, body):
        return subprocess.run(
            ["bash", "-c", f"source {HERE / script}\n{body}"],
            text=True, capture_output=True, check=False,
        )

    def test_gr_runner_requires_complete_ordered_restart(self):
        # The restart kills only bgpd (never the container's PID 1) and
        # supervises the comeback itself when watchfrr abandons the
        # daemon: kill -> GR-positive evidence + sample -> explicit
        # watchfrr restart (bgpd observed not running) -> established ->
        # stale-clear evidence + sample.
        body = r'''
state=$(mktemp); events=$(mktemp); echo 0 >"$state"
docker() { case "$*" in
 *killall*bgpd*) echo kill >>"$events";;
 *watchfrr.sh\ restart*) echo supervise >>"$events";;
esac; }
sleep() { :; }; wait_established() { echo established >>"$events"; }
cycle_log() { :; }
prom_scrape() { n=$(cat "$state"); echo $((n+1)) >"$state"; if [ "$n" = 0 ]; then
 echo positive >>"$events"
 echo "bgp_gr_active_peers 1"; echo "bgp_gr_stale_routes 2"
else echo clear >>"$events"; echo "bgp_gr_active_peers 0"; echo "bgp_gr_stale_routes 0"; fi; }
sample_row() { echo "sample:$2" >>"$events"; }
restart_frr_bgpd 7 0; cat "$events"
'''
        result = self.bash("run-soak-gr-restart-intern-gc.sh", body)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            "kill", "positive", "sample:0", "supervise", "established",
            "clear", "sample:0",
        ])

    def test_hot_runner_cp_plan_and_apply_fail_closed(self):
        body = r'''
CANDIDATE_TOML=/tmp/candidate; cycle_log() { :; }; write_candidate_toml() { :; }
docker() {
 case "$MODE:$*" in
 cp:cp*) return 11;;
 malformed:*config\ plan*) echo '{bad';;
 missing:*config\ plan*) echo '{}';;
 exit2:*config\ plan*) printf '{\n "runtime_snapshot_token": "token"\n}\n'; return 2;;
 apply:*config\ plan*) printf '{\n "runtime_snapshot_token": "token"\n}\n';;
 apply:*config\ apply*) return 13;;
 good:*config\ plan*) printf '{\n "runtime_snapshot_token": "token"\n}\n';;
 esac
}
run_apply_cycle 1
'''
        for mode, code in (("cp", 11), ("malformed", 1), ("missing", 2), ("exit2", 0),
                           ("apply", 1), ("good", 0)):
            with self.subTest(mode=mode):
                result = self.bash("run-soak-hot-reload.sh", f"MODE={mode}\n{body}")
                self.assertEqual(result.returncode, code, result.stderr)

    def test_injection_mutates_counts_only_after_commands_succeed(self):
        body = r'''
CHURN_BATCH=1; LIVE_SET_FILE=$(mktemp); echo 1 >"$LIVE_SET_FILE"
d=$(mktemp); a=$(mktemp); echo 1 >"$d"; echo 2 >"$a"
rb_inject_del() { [ "$MODE" != del ]; }
rb_inject_add() { [ "$MODE" != add ]; }
churn_log() { :; }
trap 'tr -d "\n" <"$LIVE_SET_FILE"' EXIT
run_churn_cycle "$d" "$a"
'''
        for mode, expected in (("del", "1"), ("add", "")):
            result = self.bash("run-soak-inject-churn.sh", f"MODE={mode}\n{body}")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, expected)
        result = self.bash("run-soak-inject-churn.sh", "docker() { return 17; }\nrb_inject_add x")
        self.assertEqual(result.returncode, 17)
        result = self.bash("run-soak-inject-churn.sh", "docker() { return 18; }\nrb_inject_del x")
        self.assertEqual(result.returncode, 18)

    def test_frr_query_and_final_analyzer_failures_propagate(self):
        result = self.bash(
            "run-soak-inject-churn.sh",
            "frr_vtysh() { return 19; }\nfrr_route_count",
        )
        self.assertNotEqual(result.returncode, 0)
        for script in ("gr-restart-intern-gc", "hot-reload", "inject-churn"):
            result = self.bash(
                f"run-soak-{script}.sh", "python3() { return 23; }\nrun_analyzer"
            )
            self.assertEqual(result.returncode, 23)

    def test_neighbor_state_failure_after_output_propagates(self):
        body = r'''SAMPLES_CSV=/dev/null; LIVE_TARGET_PREFIXES=1
prom_scrape() { echo metric; }; container_rss_mb() { echo 1; }
prom_extract_sum() { echo 1; }; frr_route_count() { echo 1; }
frr_established_seen() { return 0; }; neighbor_state() { echo "0 10"; return 19; }
sample_row 0 0 0 0'''
        for script in ("hot-reload", "inject-churn"):
            self.assertEqual(self.bash(f"run-soak-{script}.sh", body).returncode, 19)

if __name__ == "__main__":
    unittest.main()
