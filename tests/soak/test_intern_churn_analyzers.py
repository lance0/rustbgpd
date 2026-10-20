#!/usr/bin/env python3
"""Cheap fail-closed contracts for the intern/churn soak evidence."""

import csv
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).parent


RUN_META = {
    "soak_seconds": 7200, "warmup_sec": 0,
    "restart_interval_sec": 7200, "apply_interval_sec": 7200, "churn_interval_sec": 7200,
}
DAEMON_RECORD = {
    "timestamp": "2026-01-01T00:00:00Z", "level": "INFO",
    "target": "rustbgpd", "fields": {"message": "daemon started"},
}
CLEAN_LOG = json.dumps(DAEMON_RECORD) + "\n"


def run_analyzer(name, fields, rows, metadata=RUN_META, daemon_log=CLEAN_LOG):
    with tempfile.TemporaryDirectory() as tmp:
        if metadata is not None:
            (Path(tmp) / "run.json").write_text(json.dumps(metadata))
        if daemon_log is not None:
            (Path(tmp) / "rustbgpd.log").write_text(daemon_log)
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
    def window_cases(self):
        # 101 seconds gives fractional floors, proving that rounding down
        # cannot accept a cycle short of the precommitted inequality.
        metadata = {"soak_seconds": 101, "warmup_sec": 20}
        for name, interval, cycle, floor, extra in (
            ("gr-restart", "restart_interval_sec", "restart_cycles", 9,
             {"gr_active_peers": "0", "gr_stale_routes": "0"}),
            ("hot-reload", "apply_interval_sec", "apply_cycles", 10,
             {"apply_ok": "10", "apply_fail": "0", "flap_count": "0",
              "uptime_seconds": "101"}),
            ("inject-churn", "churn_interval_sec", "churn_cycles", 5,
             {"live_target": "1", "frr_route_count": "1", "add_total": "5",
              "del_total": "4", "flap_count": "0", "uptime_seconds": "101"}),
        ):
            final = {**BASE, **extra, "elapsed_sec": "101", cycle: str(floor)}
            first = {**final, "elapsed_sec": "0", cycle: "0"}
            if name == "gr-restart":
                first.update(gr_active_peers="1", gr_stale_routes="1")
            elif name == "hot-reload":
                first["apply_ok"] = "0"
            yield f"analyze-soak-{name}.py", [first, final], {**metadata, interval: 10}, cycle, floor

    def test_window_cycle_floors_are_enforced(self):
        for analyzer, rows, metadata, cycle, floor in self.window_cases():
            with self.subTest(analyzer=analyzer):
                result = run_analyzer(analyzer, rows[0], rows, metadata)
                self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
                self.assertEqual(json.loads(result.stdout)["gates"][cycle]["limit"], floor)
                rows[-1][cycle] = str(floor - 1)
                if cycle == "apply_cycles":
                    rows[-1]["apply_ok"] = str(floor - 1)
                result = run_analyzer(analyzer, rows[0], rows, metadata)
                self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
                gates = json.loads(result.stdout)["gates"]
                self.assertFalse(gates[cycle]["pass"])
                self.assertTrue(all(g["pass"] for key, g in gates.items() if key != cycle))

    def test_daemon_errors_and_missing_evidence_fail_each_analyzer(self):
        warning = json.dumps({**DAEMON_RECORD, "level": "WARN"}) + "\n"
        error = json.dumps({**DAEMON_RECORD, "level": "ERROR"}) + "\n"
        for analyzer, rows, metadata, _, _ in self.window_cases():
            for log, accepted in ((CLEAN_LOG + warning, True),
                                  (CLEAN_LOG + error, False),
                                  (CLEAN_LOG + "malformed\n", False),
                                  (None, False), ("", False)):
                with self.subTest(analyzer=analyzer, log=log):
                    result = run_analyzer(analyzer, rows[0], rows, metadata, log)
                    self.assertEqual(result.returncode, 0 if accepted else 1, result.stderr)
                    gates = json.loads(result.stdout)["gates"]
                    self.assertEqual(gates["daemon_log"]["pass"], accepted)
                    self.assertTrue(all(g["pass"] for key, g in gates.items()
                                        if key != "daemon_log"))
                    if log == CLEAN_LOG + error:
                        self.assertEqual(gates["daemon_log"]["value"]["errors"], 1)

    def test_invalid_window_metadata_is_input_error(self):
        for analyzer, rows, metadata, _, _ in self.window_cases():
            for invalid in (None, [], {}, {**metadata, "soak_seconds": 0},
                            {**metadata, "soak_seconds": True},
                            {**metadata, "soak_seconds": "101"},
                            {**metadata, "warmup_sec": -1},
                            {**metadata, "warmup_sec": 1.5}):
                with self.subTest(analyzer=analyzer, metadata=invalid):
                    result = run_analyzer(analyzer, rows[0], rows, invalid)
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            interval = next(key for key in metadata if key.endswith("interval_sec"))
            for invalid in (0, -1, True, 1.5):
                with self.subTest(analyzer=analyzer, interval=invalid):
                    result = run_analyzer(analyzer, rows[0], rows, {**metadata, interval: invalid})
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            if "inject-churn" in analyzer:
                result = run_analyzer(analyzer, rows[0], rows, {**metadata, "warmup_sec": 101})
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

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

    # Destructive proof: restoring tail.count("1") > 0 makes the terminal-down
    # cases return 0 instead of 1.
    def test_terminal_established_requires_final_sample_up(self):
        cases = [
            (
                "analyze-soak-gr-restart.py",
                [*BASE, "elapsed_sec", "gr_active_peers", "gr_stale_routes",
                 "restart_cycles"],
                [
                    {**BASE, "elapsed_sec": "0", "gr_active_peers": "0",
                     "gr_stale_routes": "0", "restart_cycles": "0"},
                    {**BASE, "elapsed_sec": "3600", "gr_active_peers": "1",
                     "gr_stale_routes": "2", "restart_cycles": "0"},
                    {**BASE, "elapsed_sec": "7200", "gr_active_peers": "0",
                     "gr_stale_routes": "0", "restart_cycles": "1"},
                ],
            ),
            (
                "analyze-soak-hot-reload.py",
                [*BASE, "elapsed_sec", "apply_cycles", "apply_ok", "apply_fail",
                 "flap_count", "uptime_seconds"],
                [
                    {**BASE, "elapsed_sec": "0", "apply_cycles": "0", "apply_ok": "0",
                     "apply_fail": "0", "flap_count": "3", "uptime_seconds": "10"},
                    {**BASE, "elapsed_sec": "3600", "apply_cycles": "1", "apply_ok": "1",
                     "apply_fail": "0", "flap_count": "3", "uptime_seconds": "3610"},
                    {**BASE, "elapsed_sec": "7200", "apply_cycles": "1", "apply_ok": "1",
                     "apply_fail": "0", "flap_count": "3", "uptime_seconds": "7210"},
                ],
            ),
            (
                "analyze-soak-inject-churn.py",
                [*BASE, "elapsed_sec", "live_target", "frr_route_count",
                 "churn_cycles", "add_total", "del_total", "flap_count",
                 "uptime_seconds"],
                [
                    {**BASE, "elapsed_sec": "0", "live_target": "1024",
                     "frr_route_count": "0", "churn_cycles": "0", "add_total": "1024",
                     "del_total": "0", "flap_count": "0", "uptime_seconds": "10"},
                    {**BASE, "elapsed_sec": "3600", "live_target": "1024",
                     "frr_route_count": "1024", "churn_cycles": "1", "add_total": "1049",
                     "del_total": "25", "flap_count": "0", "uptime_seconds": "3610"},
                    {**BASE, "elapsed_sec": "7200", "live_target": "1024",
                     "frr_route_count": "1024", "churn_cycles": "1", "add_total": "1049",
                     "del_total": "25", "flap_count": "0", "uptime_seconds": "7210"},
                ],
            ),
        ]
        scenarios = (
            ("three_up", ["1", "1", "1"], True),
            ("recovered", ["0", "1", "1"], True),
            ("two_up", ["1", "1"], True),
            ("down_for_two", ["1", "0", "0"], False),
            ("terminal_down", ["1", "1", "0"], False),
        )
        for analyzer, fields, valid_rows in cases:
            for scenario, states, expected_pass in scenarios:
                with self.subTest(analyzer=analyzer, scenario=scenario):
                    rows = [dict(row) for row in valid_rows[-len(states):]]
                    for row, state in zip(rows, states):
                        row["bgp_established"] = state
                    result = run_analyzer(analyzer, fields, rows)
                    payload = json.loads(result.stdout)
                    target = payload["gates"]["final_session_established"]
                    self.assertEqual(result.returncode, 0 if expected_pass else 1,
                                     result.stderr)
                    self.assertEqual(target["pass"], expected_pass)
                    self.assertTrue(all(
                        gate["pass"] for name, gate in payload["gates"].items()
                        if expected_pass or name != "final_session_established"
                    ), payload)

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

    def bash_functions(self, script, names, body):
        source = (HERE / script).read_text()
        functions = []
        for name in names:
            start = source.index(f"{name}() {{")
            end = source.index("\n}\n", start) + 3
            functions.append(source[start:end])
        return subprocess.run(["bash", "-c", "\n".join([*functions, body])],
                              text=True, capture_output=True, check=False)

    def test_gate8b_recovery_transitions_fail_closed(self):
        base = r'''
PE2_NAME=pe2; PE2_RUNNING=0
docker() { case "$MODE:$1" in start:start) return 11;; setup:exec) return 12;; esac; }
wait_current_established() { [ "$MODE" != established ]; }
restart_pe2; rc=$?; printf '%s' "$PE2_RUNNING"; exit "$rc"
'''
        for mode, code, state in (("start", 11, "0"), ("setup", 12, "0"),
                                  ("established", 1, "0"), ("good", 0, "1")):
            with self.subTest(runner="base", mode=mode):
                result = self.bash_functions(
                    "run-gate8b-soak.sh", ("restart_pe2",), f"MODE={mode}\n{base}"
                )
                self.assertEqual((result.returncode, result.stdout), (code, state))
        wait = r'''
clock=$(mktemp); echo 0 >"$clock"; BGP_ESTABLISHED_TIMEOUT_SEC=2
date() { n=$(cat "$clock"); echo "$n"; echo $((n + 1)) >"$clock"; }
prom_scrape() { :; }; prom_extract() { [ "$MODE" = current ] && echo 1 || echo 0; }
sleep() { :; }; log() { :; }
wait_current_established pe2
'''
        for mode, code in (("current", 0), ("down", 1)):
            with self.subTest(runner="base-wait", mode=mode):
                result = self.bash_functions("run-gate8b-soak.sh", ("wait_current_established",), f"MODE={mode}\n{wait}")
                self.assertEqual(result.returncode, code)
        stop = r'''
KILL_MODE=term; PE2_NAME=pe2; PE2_RUNNING=1
docker() { case "$MODE:$*" in stop:*kill*) return 1;; transport:*printf\ running*) return 2;; unknown:*printf\ running*) echo unknown;; running:*printf\ running*) echo running;; *:*printf\ running*) echo stopped;; esac; }
sleep() { :; }; log() { :; }
stop_pe2_daemon; rc=$?; printf '%s' "$PE2_RUNNING"; exit "$rc"
'''
        start = r'''
VNI=100; PE2_NAME=pe2; PE2_RUNNING=0
docker() { [ "$MODE" != start ]; }
wait_established_post_flip() { [ "$MODE" != established ]; }
start_pe2_daemon; rc=$?; printf '%s' "$PE2_RUNNING"; exit "$rc"
'''
        for mode, functions, body, code, state in (
            ("stop", ("flip_stop_daemon", "stop_pe2_daemon"), stop, 1, "1"),
            ("transport", ("flip_stop_daemon", "stop_pe2_daemon"), stop, 2, "1"),
            ("unknown", ("flip_stop_daemon", "stop_pe2_daemon"), stop, 1, "1"),
            ("running", ("flip_stop_daemon", "stop_pe2_daemon"), stop, 1, "1"),
            ("good", ("flip_stop_daemon", "stop_pe2_daemon"), stop, 0, "0"),
            ("start", ("flip_start_daemon", "start_pe2_daemon"), start, 1, "0"),
            ("established", ("flip_start_daemon", "start_pe2_daemon"), start, 1, "0"),
            ("good", ("flip_start_daemon", "start_pe2_daemon"), start, 0, "1")):
            with self.subTest(runner="mac", mode=mode, function=functions[-1]):
                result = self.bash_functions(
                    "run-gate8b-mac-churn-soak.sh", functions, f"MODE={mode}\n{body}"
                )
                self.assertEqual((result.returncode, result.stdout), (code, state))

    def test_gate8b_recovery_callers_preserve_ordering(self):
        base = (HERE / "run-gate8b-soak.sh").read_text()
        restart = base[base.index("restart_pe2() {"):base.index("\n}\n", base.index("restart_pe2() {"))]
        self.assertIn("if ! restart_pe2; then", base)
        for before, after in (("docker start", "docker exec"),
                              ("docker exec", "wait_current_established"),
                              ("wait_current_established", "PE2_RUNNING=1")):
            self.assertLess(restart.index(before), restart.index(after))
        self.assertIn("bgp_peer_session_established", base)
        mac = (HERE / "run-gate8b-mac-churn-soak.sh").read_text()
        for call in ("stop_pe2_daemon", "start_pe2_daemon"):
            self.assertIn(f"if ! {call}; then", mac)
        self.assertLess(mac.index("flip_stop_daemon \"$PE2_NAME\""), mac.index("PE2_RUNNING=0"))
        self.assertLess(mac.index("wait_established_post_flip \"$PE2_NAME\""), mac.index("PE2_RUNNING=1"))

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

    def test_hot_runner_uses_positional_config_candidates(self):
        # Load-bearing: restoring either runner call to the retired alias
        # makes this structural fence red before a multi-hour soak starts.
        source = (HERE / "run-soak-hot-reload.sh").read_text()
        self.assertNotIn("--from-file", source)
        self.assertIn("config plan \\\n        /tmp/candidate.toml -j)", source)
        self.assertIn("config apply \\\n        /tmp/candidate.toml", source)

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

LEASE_META = {
    "soak_seconds": 120, "warmup_sec": 0, "churn_interval_sec": 7200,
    "lease_mode": 1, "lease_owners": 2, "lease_keys_per_owner": 4,
    "lease_seconds": 10, "lease_renew_sec": 3, "lease_flap_interval_sec": 60,
}
LEASE_FIELDS = ["timestamp", "rss_mb", "intern_size", "bgp_established",
                "elapsed_sec", "live_target", "frr_route_count", "churn_cycles",
                "add_total", "del_total", "flap_count", "uptime_seconds"]
LEASE_ROWS = [
    {**BASE, "elapsed_sec": str(elapsed), "live_target": "8", "frr_route_count": "8",
     "churn_cycles": str(cycles), "add_total": "8", "del_total": "0",
     "flap_count": "0", "uptime_seconds": str(10 + elapsed)}
    for elapsed, cycles in ((0, 0), (120, 1))
]
# The banner a daemon with both gRPC listeners prints (TCP, then UDS).
DUAL_LISTENER_LOG = (
    "  rustbgpd 0.79.0 | AS 65001 | router-id 10.0.0.1\n"
    "  |- 1 peers (1 eBGP)\n"
    "  |- grpc: tcp://0.0.0.0:50051 (token auth)\n"
    "  |- grpc: unix:///var/lib/rustbgpd/grpc.sock\n"
    "  |- metrics: http://0.0.0.0:9179/metrics\n"
    "\n" + CLEAN_LOG
)
# Owner 1 is healthy; owner 2 flaps once: its last renewal was sent at 103.0
# and answered at 103.1, so its lease ends in [113.0, 113.1] and FRR must
# have lost every key by 118.1.
LEASE_EVENTS = """\
100.0 soak-lease-1 controller_start pid=11
100.0 soak-lease-2 controller_start pid=12
101.0 soak-lease-1 added gen=77:1
101.5 soak-lease-2 added gen=77:2
103.1 soak-lease-1 renew renewed
103.1 soak-lease-2 renew renewed
106.1 soak-lease-1 renew renewed
106.5 soak-lease-2 flap_stop gen=77:2 t0=103.0 t1=103.1
113.6 soak-lease-2 frr_gone drop=113.4 at=113.6
113.7 soak-lease-2 stale_renew refused phase=expired
114.0 soak-lease-2 added gen=77:3
114.1 soak-lease-2 stale_renew refused phase=superseded
114.5 soak-lease-2 frr_back drop=none at=114.5
117.0 soak-lease-2 renew renewed
220.0 soak-lease-1 controller_exit rc=0
220.0 soak-lease-2 controller_exit rc=0
"""


def lease_sample(elapsed, counts=(4, 4), owners=("soak-lease-1", "soak-lease-2")):
    leases = [{"owner": o, "generation": {"incarnation": "77", "sequence": "1"},
               "leaseSeconds": 10, "leaseRemainingMs": 9000} for o in owners]
    return json.dumps({"elapsed_sec": elapsed, "frr_counts": list(counts),
                       "leases": leases})


LEASE_SAMPLES = "\n".join([lease_sample(0), lease_sample(60), lease_sample(120)]) + "\n"
READYZ = "epoch,code,seconds\n" + "".join(f"{100 + i},200,0.001\n" for i in range(60))


def run_lease_analyzer(events=LEASE_EVENTS, samples=LEASE_SAMPLES, readyz=READYZ,
                       metadata=LEASE_META):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "run.json").write_text(json.dumps(metadata))
        (root / "rustbgpd.log").write_text(DUAL_LISTENER_LOG)
        with (root / "samples.csv").open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=LEASE_FIELDS)
            writer.writeheader()
            writer.writerows(LEASE_ROWS)
        for name, text in (("lease-events.log", events),
                           ("lease-samples.jsonl", samples), ("readyz.csv", readyz)):
            if text is not None:
                (root / name).write_text(text)
        return subprocess.run(
            ["python3", str(HERE / "analyze-soak-inject-churn.py"), tmp],
            text=True, capture_output=True, check=False,
        )


class LeaseModeContracts(unittest.TestCase):
    def test_clean_lease_run_passes(self):
        result = run_lease_analyzer()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        gates = json.loads(result.stdout)["gates"]
        self.assertEqual(gates["lease_flap_expiry"]["value"]["cycles"], 1)
        self.assertEqual(gates["lease_stale_renewals_refused"]["value"]["by_phase"],
                         {"expired": {"attempts": 1, "refused": 1},
                          "superseded": {"attempts": 1, "refused": 1}})

    def test_lease_gates_are_skipped_without_lease_mode(self):
        result = run_lease_analyzer(events=None, samples=None, readyz=None,
                                    metadata={**LEASE_META, "lease_mode": 0})
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertNotIn("readyz", json.loads(result.stdout)["gates"])

    def test_seeded_defects_fail_exactly_their_gate(self):
        events = LEASE_EVENTS
        cases = {
            # A renewal at a superseded generation was accepted, as when
            # the daemon skips the generation check.
            "stale_renewal_accepted": ("lease_stale_renewals_refused", {
                "events": events.replace("stale_renew refused phase=superseded",
                                         "stale_renew renewed phase=superseded")}),
            # A renewal resurrected an expired lease.
            "expired_renewal_accepted": ("lease_stale_renewals_refused", {
                "events": events.replace("stale_renew refused phase=expired",
                                         "stale_renew renewed phase=expired")}),
            "stale_renewal_errored": ("lease_stale_renewals_refused", {
                "events": events.replace("stale_renew refused phase=expired",
                                         "stale_renew error phase=expired")}),
            "stale_renewal_skipped": ("lease_flap_expiry", {
                "events": events.replace("114.1 soak-lease-2 stale_renew refused phase=superseded\n", "")}),
            # A healthy owner's prefixes went missing at FRR.
            "healthy_prefixes_missing": ("lease_healthy_presence", {
                "samples": LEASE_SAMPLES + lease_sample(120, counts=(3, 4)) + "\n"}),
            "healthy_lease_missing": ("lease_healthy_presence", {
                "samples": lease_sample(60, owners=("soak-lease-2",)) + "\n"}),
            "no_presence_samples": ("lease_healthy_presence", {"samples": ""}),
            "expiry_late": ("lease_flap_expiry", {
                "events": events.replace("at=113.6", "at=118.2")}),
            "expiry_never": ("lease_flap_expiry", {
                "events": events.replace("drop=113.4 at=113.6", "drop=none timeout")}),
            "expiry_early": ("lease_flap_expiry", {
                "events": events.replace("drop=113.4", "drop=112.9")}),
            "never_back": ("lease_flap_expiry", {
                "events": events.replace("frr_back drop=none at=114.5", "frr_back drop=none timeout")}),
            "incomplete_cycle": ("lease_flap_expiry", {
                "events": events.replace("114.5 soak-lease-2 frr_back drop=none at=114.5\n", "")}),
            "no_cycles": ("lease_flap_expiry", {
                "events": "".join(line + "\n" for line in events.splitlines()
                                  if "flap_stop" not in line and "frr_" not in line)}),
            "generation_reused": ("lease_generation_increase", {
                "events": events.replace("added gen=77:3", "added gen=77:2")}),
            "generation_new_incarnation": ("lease_generation_increase", {
                "events": events.replace("added gen=77:3", "added gen=78:3")}),
            "healthy_renewal_refused": ("lease_renewals", {
                "events": events.replace("106.1 soak-lease-1 renew renewed",
                                         "106.1 soak-lease-1 renew refused")}),
            "controller_failed": ("lease_controllers", {
                "events": events.replace("soak-lease-1 controller_exit rc=0",
                                         "soak-lease-1 controller_exit rc=1")}),
            "controller_exit_missing": ("lease_controllers", {
                "events": events.replace("220.0 soak-lease-1 controller_exit rc=0\n", "")}),
            "readyz_503": ("readyz", {"readyz": READYZ + "200,503,0.201\n"}),
            "readyz_unreachable": ("readyz", {"readyz": READYZ + "200,000,5.0\n"}),
            "readyz_too_few": ("readyz", {"readyz": "epoch,code,seconds\n100,200,0.001\n"}),
        }
        for name, (target, kwargs) in cases.items():
            with self.subTest(name):
                result = run_lease_analyzer(**kwargs)
                self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
                gates = json.loads(result.stdout)["gates"]
                self.assertFalse(gates[target]["pass"], gates[target])
                self.assertEqual([k for k, g in gates.items() if not g["pass"]], [target])

    def test_missing_or_malformed_lease_evidence_is_input_error(self):
        cases = {
            "no_events": {"events": None},
            "no_samples": {"samples": None},
            "no_readyz": {"readyz": None},
            "unknown_owner": {"events": LEASE_EVENTS + "1.0 someone renew renewed\n"},
            "bad_timestamp": {"events": LEASE_EVENTS + "x soak-lease-1 renew renewed\n"},
            "short_counts": {"samples": json.dumps(
                {"elapsed_sec": 0, "frr_counts": [4], "leases": []}) + "\n"},
            "bad_json": {"samples": "{\n"},
            "readyz_header": {"readyz": "epoch,code\n1,200\n"},
            "readyz_code": {"readyz": READYZ + "1,abc,0.1\n"},
            "lease_meta": {"metadata": {**LEASE_META, "lease_seconds": 0}},
            "lease_mode": {"metadata": {**LEASE_META, "lease_mode": "1"}},
        }
        for name, kwargs in cases.items():
            with self.subTest(name):
                result = run_lease_analyzer(**kwargs)
                self.assertEqual(result.returncode, 2, result.stderr + result.stdout)


if __name__ == "__main__":
    unittest.main()
