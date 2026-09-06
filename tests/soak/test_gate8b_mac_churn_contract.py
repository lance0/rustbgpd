#!/usr/bin/env python3
"""Fresh Gate 8b MAC-only evidence must fail closed independently of memory gates."""

import csv
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).parent
COUNTER = "evpn_duplicate_mac_moves_total"


class MacChurnProof(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.scrapes = self.directory / "scrapes"
        self.scrapes.mkdir()
        self.rows = []
        for i in range(13):
            elapsed = i * 50
            running = i not in (3, 4, 8, 9)
            row = {
                "ts_unix": str(1000 + elapsed), "elapsed_sec": str(elapsed),
                "pe2_running": str(int(running)),
                "pe1_session_established": "1",
                "pe2_session_established": str(int(running)),
                "pe1_scrape_ok": "1", "pe2_scrape_ok": str(int(running)),
                "pe1_local_origs": str(i), "pe2_local_origs": str(i),
                "pe1_fdb_extern_learn": str(i), "pe2_fdb_extern_learn": str(i),
                "churn_adds_total": str(i * 3), "churn_dels_total": str(i),
                "churn_moves_total": str(i),
                "pe1_rss_mb": "NaN", "pe2_rss_mb": "NaN",
                "pe1_df_changes": "NaN", "pe2_df_changes": "NaN",
                "pe1_bum_flags": "df",
            }
            self.rows.append(row)
            for pe in ("pe1", "pe2"):
                epoch = 900 if pe == "pe1" or i < 5 else 1200 if i < 10 else 1450
                self.path(i, pe).write_text(f"process_start_time_seconds {epoch}\n")
        self.metadata = {"mac_churn_proof": 1, "image_id": "sha256:test",
                         "pe2_image_id": "sha256:test", "sample_interval_sec": 50,
                         "bgp_timeout_sec": 100}
        for name, content in (("active-start-unix", "1000"), ("active-end-unix", "1600"),
                              ("cleanup.exit", "0"), ("pe1.log", "started\n"),
                              ("pe2.log", "started\n")):
            (self.directory / name).write_text(content)

    def path(self, index, pe="pe1"):
        return self.scrapes / f"{1000 + index * 50}-{pe}.prom"

    def analyze(self):
        path = self.directory / "samples.csv"
        with path.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(self.rows[0]))
            writer.writeheader()
            writer.writerows(self.rows)
        (self.directory / "run.json").write_text(json.dumps(self.metadata))
        result = subprocess.run(["python3", str(HERE / "analyze-gate8b-soak.py"),
                                 str(path), "--mac-churn-proof"],
                                capture_output=True, text=True, check=False)
        self.assertTrue(result.stdout, result.stderr)
        return result.returncode, json.loads(result.stdout)

    def test_success_records_lazy_absence_and_planned_restart_epochs(self):
        code, report = self.analyze()
        self.assertEqual(code, 0, report)
        self.assertEqual(report["active_seconds"], 600)
        self.assertEqual(report["process_epochs"], {"pe1": [900], "pe2": [900, 1200, 1450]})
        self.assertEqual(report["samples"][0]["pe1"]["counters"][COUNTER],
                         {"present": False, "series": 0, "total": 0})
        self.assertEqual(report["samples"][3]["pe2"],
                         {"available": False, "reason": "planned_stop"})

    def test_nonzero_second_series_is_not_hidden_by_zero_first_series(self):
        with self.path(1).open("a") as stream:
            stream.write(f'{COUNTER}{{vni="100",mac="a"}} 0\n'
                         f'{COUNTER}{{vni="100",mac="b"}} 1\n')
        code, report = self.analyze()
        self.assertEqual(code, 1)
        self.assertIn("duplicate MAC/IP activity", report["error"])

    def test_labeled_and_tab_separated_process_samples_are_valid(self):
        for sample in ("process_start_time_seconds\t900\n",
                       'process_start_time_seconds{scope="test"} 900\n',
                       'process_start_time_seconds{scope="test"}\t900\n'):
            with self.subTest(sample=sample):
                self.path(1).write_text(sample)
                code, report = self.analyze()
                self.assertEqual(code, 0, report)

    def test_all_duplicate_families_are_zero_controls(self):
        for family in ("evpn_duplicate_mac_threshold_exceeded_total",
                       "evpn_duplicate_ip_moves_total", "evpn_duplicate_ip_threshold_exceeded_total"):
            with self.subTest(family=family):
                self.path(1).write_text(f'process_start_time_seconds 900\n{family}{{vni="100"}} 1\n')
                self.assertEqual(self.analyze()[0], 1)

    def test_bad_scrapes_fail_instead_of_becoming_zero(self):
        for value in ("", "HTTP error", "process_start_time_seconds NaN\n",
                      f"process_start_time_seconds 900\n{COUNTER}{{bad\n",
                      f"process_start_time_seconds 900\n{COUNTER}  NaN\n",
                      f"process_start_time_seconds 900\n{COUNTER}\n",
                      f"process_start_time_seconds 900\n{COUNTER}\tbroken\n"):
            with self.subTest(value=value):
                self.path(1).write_text(value)
                self.assertEqual(self.analyze()[0], 1)
        self.path(1).unlink()
        self.assertEqual(self.analyze()[0], 1)

    def test_failed_http_scrape_with_plausible_body_still_fails(self):
        self.rows[1]["pe1_scrape_ok"] = "0"
        self.assertEqual(self.analyze()[0], 1)

    def test_short_churn_cannot_borrow_terminal_recovery_time(self):
        (self.directory / "active-end-unix").write_text("1599")
        self.assertEqual(self.analyze()[0], 1)

    def test_stalled_and_reset_churn_fail(self):
        for value in ("0", "-1"):
            with self.subTest(value=value):
                for key in ("churn_adds_total", "churn_dels_total", "churn_moves_total"):
                    self.rows[1][key] = value
                self.assertEqual(self.analyze()[0], 1)

    def test_origination_is_a_required_positive_control(self):
        for row in self.rows:
            row["pe2_local_origs"] = "NaN"
        self.assertEqual(self.analyze()[0], 1)

    def test_unplanned_and_missing_restart_epochs_fail(self):
        self.path(1).write_text("process_start_time_seconds 901\n")
        self.assertEqual(self.analyze()[0], 1)
        self.path(1).write_text("process_start_time_seconds 900\n")
        self.path(5, "pe2").write_text("process_start_time_seconds 900\n")
        self.assertEqual(self.analyze()[0], 1)

    def test_terminal_recovery_and_cleanup_are_required(self):
        self.rows[-1]["pe2_session_established"] = "0"
        self.assertEqual(self.analyze()[0], 1)
        self.rows[-1]["pe2_session_established"] = "1"
        (self.directory / "cleanup.exit").write_text("1")
        self.assertEqual(self.analyze()[0], 1)

    def test_missing_actual_log_and_image_mismatch_fail(self):
        (self.directory / "pe1.log").unlink()
        self.assertEqual(self.analyze()[0], 1)
        (self.directory / "pe1.log").write_text("started\n")
        self.metadata["pe2_image_id"] = "sha256:other"
        self.assertEqual(self.analyze()[0], 1)

    def test_runner_places_clock_after_readiness_and_reaps_churn(self):
        source = (HERE / "run-gate8b-mac-churn-soak.sh").read_text()
        self.assertLess(source.index("if ! wait_established;"), source.index('START_UNIX="$(date +%s)"'))
        self.assertIn('prom_sum "$PE1_PROM" evpn_duplicate_mac_moves_total', source)
        self.assertIn('if ! wait "$CHURN_PID";', source)
        self.assertIn('docker cp "$PE2_NAME:/var/log/rustbgpd.log"', source)
        self.assertIn('--name "$LAB_NAME" --cleanup', source)

    def test_cleanup_requires_successful_owned_resource_lists(self):
        source = (HERE / "run-gate8b-mac-churn-soak.sh").read_text()
        cleanup = "cleanup() {" + source.split("cleanup() {", 1)[1].split("\ntrap cleanup EXIT", 1)[0]
        binaries = self.directory / "bin"
        binaries.mkdir()
        tools = {
            "docker": """#!/bin/sh
case "$1" in
  cp) exit 0 ;;
  ps) [ "$CASE" != containers-error ] || exit 1
      [ "$CASE" != containers-remain ] || echo owned-pe ;;
  network) [ "$CASE" != networks-error ] || exit 1
           [ "$CASE" != networks-remain ] || echo "$LAB_NAME" ;;
  *) exit 99 ;;
esac
exit 0
""",
            "containerlab": "#!/bin/sh\nexit 0\n",
            "sudo": '#!/bin/sh\nexec "$@"\n',
        }
        for name, text in tools.items():
            executable = binaries / name
            executable.write_text(text)
            executable.chmod(0o755)
        for case in ("clean", "containers-error", "networks-error", "containers-remain", "networks-remain"):
            with self.subTest(case=case):
                environment = dict(os.environ, PATH=f"{binaries}:{os.environ['PATH']}", CASE=case,
                                   RUN_DIR=str(self.directory), LAB_NAME="gate8b-proof-test",
                                   PE1_NAME="owned-pe1", PE2_NAME="owned-pe2", CHURN_PID="",
                                   PE1_TAIL_PID="", PE2_TAIL_PID="", PE1_LOG="unused", PE2_LOG="unused",
                                   CLEANUP="1", MAC_CHURN_PROOF="1", TOPOLOGY="unused")
                result = subprocess.run(["bash", "-c", "log() { :; }\n" + cleanup + "\ncleanup"],
                                        env=environment, text=True, capture_output=True, check=False)
                self.assertEqual(result.returncode, 0 if case == "clean" else 4,
                                 result.stdout + result.stderr)
                self.assertEqual((self.directory / "cleanup.exit").read_text().strip(),
                                 "0" if case == "clean" else "1")

    def test_counter_reader_observes_old_value_until_atomic_rename(self):
        source = (HERE / "run-gate8b-mac-churn-soak.sh").read_text()
        function = "counter_incr() {" + source.split("counter_incr() {", 1)[1].split("\n}\n", 1)[0] + "\n}"
        counter = self.directory / "counter"
        counter.write_text("7\n")
        # Inspect the reader's view exactly before mv publishes the new value.
        body = function + '\nmv() { test "$(cat "$2")" = 7 || exit 99; command mv "$@"; }\ncounter_incr "$1" 3'
        result = subprocess.run(["bash", "-c", body, "counter-test", str(counter)],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(counter.read_text().strip(), "10")
        self.assertFalse(counter.with_suffix(".tmp").exists())

    def test_local_add_removes_only_matching_remote_master_ownership(self):
        source = (HERE / "run-gate8b-mac-churn-soak.sh").read_text()
        function = "fdb_add_pe() {" + source.split("fdb_add_pe() {", 1)[1].split("\n}\n", 1)[0] + "\n}"
        binaries = self.directory / "bin"
        binaries.mkdir()
        bridge = binaries / "bridge"
        bridge.write_text("""#!/bin/sh
printf '%s\n' "$*" >> "$COMMAND_LOG"
case "$2" in
  show) [ "$CASE" != dump-error ] || exit 1; printf '%s\n' "$FDB_ROWS" ;;
  del) [ "$CASE" != delete-error ] || exit 1 ;;
esac
""")
        bridge.chmod(0o755)
        remote = "02:aa:00:00:00:01 vlan 1 extern_learn master br100"
        cases = (("remote", remote, True),
                 ("self", "02:aa:00:00:00:01 dst 10.0.0.2 self extern_learn", False),
                 ("other-mac", remote.replace(":01", ":02"), False),
                 ("other-bridge", remote.replace("br100", "br1000"), False),
                 ("local", remote.replace("extern_learn ", ""), False),
                 ("dump-error", remote, False), ("delete-error", remote, True))
        for case, rows, delete in cases:
            with self.subTest(case=case):
                trace = self.directory / "commands"
                trace.write_text("")
                environment = dict(os.environ, PATH=f"{binaries}:{os.environ['PATH']}",
                                   COMMAND_LOG=str(trace), CASE=case, FDB_ROWS=rows)
                prefix = """container_for_pe() { echo owned-pe; }
container_is_running() { return 0; }
churn_log() { :; }
docker() { shift 2; "$@"; }
CE_PORT=ce100a VNI=100
"""
                result = subprocess.run(["bash", "-c", prefix + function +
                                         "\nfdb_add_pe 1 02:aa:00:00:00:01"],
                                        env=environment, capture_output=True, text=True, check=False)
                expected = ["fdb show dev vxlan100"]
                if delete:
                    expected.append("fdb del 02:aa:00:00:00:01 dev vxlan100 master")
                if not case.endswith("-error"):
                    expected.append("fdb add 02:aa:00:00:00:01 dev ce100a master static")
                self.assertEqual(trace.read_text().splitlines(), expected)
                self.assertEqual(result.returncode, 1 if case.endswith("-error") else 0,
                                 result.stderr)

    def test_full_combined_pool_forces_delete_from_larger_pool(self):
        source = (HERE / "run-gate8b-mac-churn-soak.sh").read_text()
        function = "churn_step() {" + source.split("churn_step() {", 1)[1].split("\n}\n", 1)[0] + "\n}"
        for first, second, expected in ((134, 122, 1), (122, 134, 2)):
            with self.subTest(first=first, second=second):
                body = f"""pool_size() {{ if [ "$1" = 1 ]; then echo {first}; else echo {second}; fi; }}
churn_batch_add() {{ echo add; }}
churn_batch_del() {{ echo "delete $1 $2"; }}
churn_batch_mobility() {{ echo move; }}
CHURN_BATCH_SIZE=16 MAC_POOL_SIZE=256 POOL_MIN=64 POOL_MAX=192 MOBILITY_FRACTION=100
""" + function + "\nchurn_step"
                result = subprocess.run(["bash", "-c", body], text=True, capture_output=True,
                                        check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), f"delete {expected} 16")

    def test_shared_lab_is_rejected_before_any_docker_action(self):
        binaries = self.directory / "bin"
        binaries.mkdir()
        marker = self.directory / "docker-called"
        for name in ("docker", "containerlab"):
            executable = binaries / name
            executable.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 99\n")
            executable.chmod(0o755)
        environment = dict(os.environ, PATH=f"{binaries}:{os.environ['PATH']}",
                           MAC_CHURN_PROOF="1", LAB_NAME="gate8b-soak", CLEANUP="1",
                           TOPOLOGY_OVERRIDE="unused", RUN_DIR_OVERRIDE=str(self.directory / "run"),
                           RUSTBGPD_HOST_LOCK=str(self.directory / "host.lock"))
        result = subprocess.run(["bash", str(HERE / "run-gate8b-mac-churn-soak.sh")],
                                env=environment, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
