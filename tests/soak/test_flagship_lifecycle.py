#!/usr/bin/env python3
"""Subprocess contracts for flagship runner stop ownership."""

import gzip
import json
import os
import signal
import socket
import subprocess
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

HERE = Path(__file__).parent
LIFECYCLE = HERE / "flagship-lifecycle.sh"
RUNNERS = ("run-soak-rs-flagship.sh", "run-soak-rr-flagship.sh")


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_for(path):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {path}")


def wait_for_children(path, expected):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if path.exists() and len(path.read_text().split()) == expected:
            return
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {expected} children in {path}")


def process_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def terminate_group(group, process):
    try:
        os.killpg(group, signal.SIGTERM)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)
    if process.stdout:
        process.stdout.close()
    if process.stderr:
        process.stderr.close()


class FlagshipLifecycleContracts(unittest.TestCase):
    def test_engine_exit_before_finish_barrier_aborts_and_reaps_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            script, run_dir, _port, environment = self.write_actual_main_stub(
                directory, "run-soak-rs-flagship.sh",
            )
            engine = directory / "repo/bench/scale/target/release/reloadstall"
            engine.write_text(
                '#!/usr/bin/env bash\n'
                'printf "%s\\n" "$$" >>"$STUB_RUN_DIR/children"\n'
                'printf "converged (stub)\\n"\nsleep 2\nexit 1\n'
            )
            process = subprocess.Popen(
                ["bash", str(script), str(HERE / "run-soak-rs-flagship.sh"),
                 str(directory / "repo"), str(run_dir)],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment, start_new_session=True,
            )
            try:
                stdout, stderr = process.communicate(timeout=12)
                self.assertEqual(process.returncode, 1, stdout + stderr)
                self.assertIn("engine exited before final evidence acknowledgement", stdout)
                self.assertFalse((run_dir / "verdict.json").exists())
                self.assertFalse((run_dir / "engine-finish/ack").exists())
                self.assertIn("clean_sigterm", (run_dir / "management-plane-load.jsonl").read_text())
                self.assertEqual((run_dir / "cleanup.complete").read_text().splitlines()[0], "status=failed")
                children = [int(pid) for pid in (run_dir / "children").read_text().split()]
                self.assertTrue(all(not process_alive(pid) for pid in children))
            finally:
                terminate_group(process.pid, process)

    def test_natural_finish_holds_sessions_until_last_management_probe_drains(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            script, run_dir, _port, environment = self.write_actual_main_stub(
                directory, "run-soak-rs-flagship.sh",
            )
            engine = directory / "repo/bench/scale/target/release/reloadstall"
            engine.write_text(textwrap.dedent("""\
                #!/usr/bin/env python3
                import os
                from pathlib import Path
                import time
                root = Path(os.environ["STUB_RUN_DIR"])
                with (root / "children").open("a") as output:
                    output.write(f"{os.getpid()}\\n")
                print("converged (stub)", flush=True)
                while not (root / "probe-held").exists():
                    time.sleep(0.01)
                configured = os.environ.get("RELOADSTALL_EVIDENCE_DIR")
                if configured is None:
                    (root / "engine-withdraw").write_text(str(time.monotonic()))
                    raise SystemExit(0)
                finish = Path(configured)
                finish.mkdir()
                (finish / "ready").write_text("ready\\n")
                deadline = time.monotonic() + 12
                while not (finish / "ack").exists():
                    if time.monotonic() > deadline:
                        raise SystemExit(1)
                    time.sleep(0.01)
                (root / "engine-withdraw").write_text(str(time.monotonic()))
                """))
            management = directory / "held-management.py"
            management.write_text(textwrap.dedent("""\
                import os
                from pathlib import Path
                import signal
                import sys
                import time
                root = Path(os.environ["STUB_RUN_DIR"])
                with (root / "children").open("a") as output:
                    output.write(f"{os.getpid()}\\n")
                def stop(_signum, _frame):
                    (root / "stop-requested").write_text(str(time.monotonic()))
                signal.signal(signal.SIGTERM, stop)
                (root / "probe-held").touch()
                while not (root / "release-probe").exists():
                    time.sleep(0.01)
                (root / "management-drained").write_text(str(time.monotonic()))
                Path(sys.argv[1]).write_text('{"result":"clean_sigterm"}\\n')
                """))
            original = script.read_text()
            # Keep the actual runner main and cleanup; replace only external
            # processes and the unrelated full-window analyzer fixture.
            script.write_text(original.rsplit("main\n", 1)[0] + textwrap.dedent("""\
                start_management_load() {
                    command python3 "$STUB_MANAGEMENT" "$MANAGEMENT_LOAD_JSONL" &
                    MANAGEMENT_LOAD_PID=$!
                }
                python3() {
                    if [[ $1 == */analyze-soak-rs-flagship.py ]]; then
                        printf '{}' >"$RUN_DIR/verdict.json"
                    else
                        command python3 "$@"
                    fi
                }
                main
                """))
            environment["STUB_MANAGEMENT"] = str(management)
            process = subprocess.Popen(
                ["bash", str(script), str(HERE / "run-soak-rs-flagship.sh"),
                 str(directory / "repo"), str(run_dir)],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment, start_new_session=True,
            )
            try:
                wait_for(run_dir / "stop-requested")
                self.assertTrue((run_dir / "engine-finish/ready").exists())
                self.assertFalse((run_dir / "engine-withdraw").exists())
                self.assertFalse((run_dir / "engine-finish/ack").exists())
                (run_dir / "release-probe").touch()
                stdout, stderr = process.communicate(timeout=15)
                self.assertEqual(process.returncode, 0, stdout + stderr)
                meta = json.loads((run_dir / "run.json").read_text())
                ordered = [
                    meta["measured_end_monotonic"],
                    float((run_dir / "stop-requested").read_text()),
                    float((run_dir / "management-drained").read_text()),
                    meta["engine_finish_release_monotonic"],
                    float((run_dir / "engine-withdraw").read_text()),
                ]
                self.assertEqual(ordered, sorted(ordered))
                self.assertEqual((run_dir / "cleanup.complete").read_text().splitlines()[0], "status=normal")
                children = [int(pid) for pid in (run_dir / "children").read_text().split()]
                self.assertTrue(all(not process_alive(pid) for pid in children))
            finally:
                (run_dir / "release-probe").touch()
                terminate_group(process.pid, process)

    def write_actual_main_stub(self, directory, runner):
        root = directory / "repo"
        fake_bin = directory / "bin"
        port = free_port()
        (root / "target/release").mkdir(parents=True)
        (root / "bench/scale/reloadstall").mkdir(parents=True)
        fake_bin.mkdir()
        for path, content in {
            root / "target/release/rustbgpd": textwrap.dedent("""\
                #!/usr/bin/env python3
                import os
                import socket
                import sys
                import time
                if "--check" in sys.argv:
                    raise SystemExit(0)
                with open(os.path.join(os.environ["STUB_RUN_DIR"], "children"), "a", encoding="utf-8") as output:
                    output.write(f"{os.getpid()}\\n")
                sock = socket.socket()
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("127.0.0.1", int(os.environ["STUB_PORT"])))
                sock.listen()
                while True:
                    time.sleep(1)
                """),
            root / "target/release/rbgp": "#!/usr/bin/env bash\nexit 0\n",
            root / "bench/scale/target/release/reloadstall": (
                "#!/usr/bin/env bash\nprintf '%s\\n' \"$$\" >>\"$STUB_RUN_DIR/children\"\nprintf 'converged (stub)\\n'\nexec sleep 300\n"
            ),
            root / "bench/scale/reloadstall/gen-scenario.py": textwrap.dedent("""\
                #!/usr/bin/env python3
                import pathlib
                import sys
                directory = pathlib.Path(sys.argv[2])
                directory.mkdir(parents=True, exist_ok=True)
                for name in ("config.toml", "member.rpol", "gen-a.rpol", "gen-b.rpol"):
                    (directory / name).write_text("stub\\n")
                """),
            fake_bin / "cargo": "#!/usr/bin/env bash\nexit 0\n",
            fake_bin / "curl": textwrap.dedent("""\
                #!/usr/bin/env bash
                for argument in "$@"; do
                    [[ $argument == -w ]] && { printf '200 0.001\\n'; exit 0; }
                done
                cat <<'EOF'
                bgp_rib_attr_intern_global_size 1
                bgp_peer_session_established 9
                bgp_session_flaps_total 0
                bgp_messages_sent_total 1
                bgp_max_prefix_exceeded_total 0
                EOF
                """),
            fake_bin / "ss": "#!/usr/bin/env bash\nexit 0\n",
            fake_bin / "git": "#!/usr/bin/env bash\nprintf stub-head\\n\n",
        }.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            path.chmod(0o755)

        run_dir = directory / "run"
        script = directory / "actual-main-stub.sh"
        script.write_text(textwrap.dedent("""\
            #!/usr/bin/env bash
            source "$1"
            REPO_ROOT=$2
            RUN_DIR=$3
            SAMPLES_CSV="$RUN_DIR/samples.csv"
            SOAK_LOG="$RUN_DIR/soak.log"
            CYCLES_LOG="$RUN_DIR/cycles.log"
            RUN_JSON="$RUN_DIR/run.json"
            RUSTBGPD_LOG="$RUN_DIR/rustbgpd.log"
            RELOADSTALL_LOG="$RUN_DIR/reloadstall.log"
            MANAGEMENT_LOAD_JSONL="$RUN_DIR/management-plane-load.jsonl"
            MANAGEMENT_LOAD_LOG="$RUN_DIR/management-plane-load.log"
            DOCTOR_BUNDLE="$RUN_DIR/doctor-bundle.tar.gz"
            METRICS_SNAPSHOTS_GZ="$RUN_DIR/metrics-snapshots.txt.gz"
            PROM_TMP="$RUN_DIR/.metrics.prom"
            require_fd_headroom() { RUSTBGPD_NOFILE_SOFT_JSON=65536; }
            if declare -F start_management_load >/dev/null; then
                start_management_load() {
                    python3 - "$MANAGEMENT_LOAD_JSONL" <<'PY' &
            import os
            import signal
            import sys
            import time
            def stop(_signum, _frame):
                with open(sys.argv[1], "w", encoding="utf-8") as output:
                    output.write('{"record":"summary","result":"clean_sigterm"}\\n')
                raise SystemExit(0)
            with open(os.path.join(os.environ["STUB_RUN_DIR"], "children"), "a", encoding="utf-8") as output:
                output.write(f"{os.getpid()}\\n")
            signal.signal(signal.SIGTERM, stop)
            while True:
                time.sleep(1)
            PY
                    MANAGEMENT_LOAD_PID=$!
                }
            fi
            main
            """))
        script.chmod(0o755)
        environment = os.environ | {
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "RUSTBGPD_HOST_LOCK": str(directory / "host.lock"),
            "SOAK_PEERS": "9",
            "SOAK_ROUTES_PER_PEER": "1",
            "SOAK_SECONDS": "60",
            "RELOAD_INTERVAL_SEC": "60",
            "TRIP_INTERVAL_SEC": "60",
            "TRIP_RESTART_SECONDS": "10",
            "TRIP_FINAL_QUIESCE_SEC": "30",
            "CONVERGE_CAP_SEC": "5",
            "STUB_RUN_DIR": str(run_dir),
            "STUB_PORT": str(port),
        }
        return script, run_dir, port, environment

    def write_stub(self, directory):
        port = free_port()
        script = directory / "runner-stub.sh"
        script.write_text(textwrap.dedent("""\
            #!/usr/bin/env bash
            source "$1"
            RUN_DIR=$2
            SOAK_LOG="$RUN_DIR/soak.log"
            PROM_TMP="$RUN_DIR/.metrics.prom"
            LISTEN_PORT=$3
            H_PID=""
            DAEMON_PID=""
            MANAGEMENT_LOAD_PID=""
            SCEN=""
            mkdir -p "$RUN_DIR"
            start_flagship_lifecycle
            acquire_rustbgpd_host_lock
            trap cleanup EXIT
            trap 'RUN_INTERRUPTED=1; exit 143' TERM
            python3 - "$LISTEN_PORT" <<'PY' &
            import socket
            import sys
            import time
            sock = socket.socket()
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", int(sys.argv[1])))
            sock.listen()
            while True:
                time.sleep(1)
            PY
            DAEMON_PID=$!
            sleep 300 &
            H_PID=$!
            if declare -F stop_management_load >/dev/null; then
                python3 - "$RUN_DIR/management-plane-load.jsonl" <<'PY' &
            import signal
            import sys
            import time
            def stop(_signum, _frame):
                with open(sys.argv[1], "w", encoding="utf-8") as output:
                    output.write('{"record":"summary","result":"clean_sigterm"}\\n')
                raise SystemExit(0)
            signal.signal(signal.SIGTERM, stop)
            while True:
                time.sleep(1)
            PY
                MANAGEMENT_LOAD_PID=$!
            fi
            printf '%s %s %s\\n' "$DAEMON_PID" "$H_PID" "$MANAGEMENT_LOAD_PID" >"$RUN_DIR/children"
            if [[ $4 == normal ]]; then
                printf '{}\\n' >"$RUN_DIR/verdict.json"
                exit 0
            fi
            while :; do sleep 1; done
            """))
        script.chmod(0o755)
        environment = os.environ | {
            "RUSTBGPD_HOST_LOCK": str(directory / "host.lock"),
        }
        return script, port, environment

    def start_stub(self, directory, runner, mode):
        script, port, environment = self.write_stub(directory)
        process = subprocess.Popen(
            ["bash", str(script), str(HERE / runner), str(directory / "run"),
             str(port), mode],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
            start_new_session=True,
        )
        return process, port, environment, process.pid

    def test_stop_targets_the_actual_runner_and_waits_for_cleanup(self):
        for runner in RUNNERS:
            with self.subTest(runner=runner), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                script, run_dir, port, environment = self.write_actual_main_stub(directory, runner)
                outer = subprocess.Popen(
                    ["bash", "-c", 'bash "$1" "$2" "$3" "$4" & sleep 300', "outer",
                     str(script), str(HERE / runner), str(directory / "repo"), str(run_dir)],
                    text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    env=environment, start_new_session=True,
                )
                outer_pgid = os.getpgid(outer.pid)
                try:
                    identity = run_dir / "runner.identity"
                    wait_for(identity)
                    wait_for_children(run_dir / "children", 3 if runner.startswith("run-soak-rs") else 2)
                    wait_for(run_dir / "metrics-snapshots.txt.gz")
                    actual_pid = int(identity.read_text().split()[0])
                    self.assertNotEqual(outer.pid, actual_pid)
                    outer.terminate()
                    outer.wait(timeout=5)
                    self.assertTrue(process_alive(actual_pid))
                    self.assertFalse((run_dir / "cleanup.complete").exists())

                    result = subprocess.run(
                        ["bash", str(LIFECYCLE), "stop", str(run_dir)],
                        text=True, capture_output=True, check=False, timeout=25,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertFalse(process_alive(actual_pid))
                    children = [int(pid) for pid in (run_dir / "children").read_text().split() if pid]
                    self.assertTrue(all(not process_alive(pid) for pid in children))
                    self.assertEqual(
                        subprocess.run(
                            ["flock", "-n", str(directory / "host.lock"), "true"],
                            check=False,
                        ).returncode,
                        0,
                    )
                    with socket.socket() as listener:
                        listener.bind(("127.0.0.1", port))
                    if runner.startswith("run-soak-rs"):
                        self.assertIn("clean_sigterm", (run_dir / "management-plane-load.jsonl").read_text())
                    self.assertFalse((run_dir / "verdict.json").exists())
                    with gzip.open(run_dir / "metrics-snapshots.txt.gz", "rt", encoding="utf-8") as retained:
                        snapshot = retained.read()
                    self.assertRegex(snapshot, r"\A# snapshot \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ elapsed_sec=\d+\n")
                    self.assertIn("\nbgp_peer_session_established 9\n", snapshot)
                    self.assertEqual(
                        (run_dir / "cleanup.complete").read_text().splitlines()[0],
                        "status=interrupted",
                        (run_dir / "soak.log").read_text(),
                    )
                    first_log = (run_dir / "soak.log").read_bytes()
                    time.sleep(0.1)
                    self.assertEqual((run_dir / "soak.log").read_bytes(), first_log)
                finally:
                    if (run_dir / "runner.identity").exists() and not (run_dir / "cleanup.complete").exists():
                        subprocess.run(["bash", str(LIFECYCLE), "stop", str(run_dir)], check=False, timeout=15)
                    try:
                        os.killpg(outer_pgid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    outer.wait(timeout=5)

    def test_normal_exit_marks_cleanup_after_log_drain(self):
        for runner in RUNNERS:
            with self.subTest(runner=runner), tempfile.TemporaryDirectory() as tmp:
                process, port, _environment, group = self.start_stub(Path(tmp), runner, "normal")
                try:
                    process.wait(timeout=10)
                    run_dir = Path(tmp) / "run"
                    self.assertEqual((run_dir / "cleanup.complete").read_text().splitlines()[0], "status=normal")
                    self.assertTrue((run_dir / "verdict.json").exists())
                    with socket.socket() as listener:
                        listener.bind(("127.0.0.1", port))
                finally:
                    terminate_group(group, process)

    def test_failed_tee_refuses_a_quiesced_cleanup_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            fake_bin = directory / "bin"
            fake_bin.mkdir()
            tee = fake_bin / "tee"
            tee.write_text("#!/usr/bin/env bash\ncat >/dev/null\nexit 1\n")
            tee.chmod(0o755)
            script, port, environment = self.write_stub(directory)
            environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
            process = subprocess.Popen(
                ["bash", str(script), str(HERE / "run-soak-rs-flagship.sh"),
                 str(directory / "run"), str(port), "normal"],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
                start_new_session=True,
            )
            try:
                process.wait(timeout=10)
                marker = (directory / "run" / "cleanup.complete").read_text()
                self.assertEqual(process.returncode, 1)
                self.assertIn("status=log_write_failed", marker)
                self.assertIn("exit_status=1", marker)
                self.assertNotEqual(
                    subprocess.run(
                        ["bash", "-c", 'source "$1"; flagship_cleanup_drained "$2"',
                         "lifecycle", str(LIFECYCLE), str(directory / "run")],
                        check=False,
                    ).returncode,
                    0,
                )
            finally:
                terminate_group(process.pid, process)

    def test_repeated_stop_waits_for_a_slow_log_writer(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            fake_bin = directory / "bin"
            fake_bin.mkdir()
            tee = fake_bin / "tee"
            tee.write_text(
                "#!/usr/bin/env bash\n"
                "output=${!#}\n"
                "cat >>\"$output\"\n"
                "sleep 0.5\n"
            )
            tee.chmod(0o755)
            script, port, environment = self.write_stub(directory)
            environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
            process = subprocess.Popen(
                ["bash", str(script), str(HERE / "run-soak-rs-flagship.sh"),
                 str(directory / "run"), str(port), "interrupt"],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
                start_new_session=True,
            )
            try:
                identity = directory / "run" / "runner.identity"
                wait_for(identity)
                wait_for(directory / "run" / "children")
                process.send_signal(signal.SIGTERM)
                time.sleep(0.05)
                process.send_signal(signal.SIGTERM)
                time.sleep(0.1)
                self.assertFalse((directory / "run" / "cleanup.complete").exists())
                self.assertEqual(process.wait(timeout=5), 143)
                self.assertEqual(
                    (directory / "run" / "cleanup.complete").read_text().splitlines()[0],
                    "status=interrupted",
                )
            finally:
                terminate_group(process.pid, process)

    def assert_failed_snapshot_append_rolls_back(self, runner, directory):
        archive = directory / "metrics-snapshots.txt.gz"
        body = directory / "metrics.prom"
        body.write_text("bgp_peer_session_established 9\n")
        fake_bin = directory / "bin"
        fake_bin.mkdir()
        # A gzip that emits a member header, then fails like a write error.
        broken_gzip = fake_bin / "gzip"
        broken_gzip.write_text(
            "#!/usr/bin/env bash\n"
            "cat >/dev/null\n"
            "printf '\\x1f\\x8b\\x08\\x00\\x00\\x00\\x00\\x00\\x00\\x03partial'\n"
            "exit 1\n"
        )
        broken_gzip.chmod(0o755)

        def append(timestamp, elapsed, path=None):
            environment = os.environ.copy()
            if path:
                environment["PATH"] = f"{path}:{environment['PATH']}"
            return subprocess.run(
                ["bash", "-c",
                 'source "$1"; METRICS_SNAPSHOTS_GZ=$2; PROM_TMP=$3; prom_snapshot "$4" "$5"',
                 "snapshot", str(HERE / runner), str(archive), str(body), timestamp, elapsed],
                text=True, capture_output=True, check=False, env=environment,
            )

        def snapshots():
            self.assertEqual(subprocess.run(["gzip", "-t", str(archive)], check=False).returncode, 0)
            with gzip.open(archive, "rt", encoding="utf-8") as retained:
                return retained.read().count("# snapshot ")

        self.assertNotEqual(append("2026-01-01T00:00:00Z", "0", fake_bin).returncode, 0)
        self.assertFalse(archive.exists())
        self.assertEqual(append("2026-01-01T00:00:00Z", "0").returncode, 0)
        self.assertEqual(append("2026-01-01T00:00:10Z", "10").returncode, 0)
        intact = archive.read_bytes()
        self.assertEqual(snapshots(), 2)

        self.assertNotEqual(append("2026-01-01T00:00:20Z", "20", fake_bin).returncode, 0)
        self.assertEqual(snapshots(), 2)
        self.assertEqual(archive.read_bytes(), intact)

        self.assertEqual(append("2026-01-01T00:00:30Z", "30").returncode, 0)
        self.assertEqual(snapshots(), 3)

    def test_failed_snapshot_append_leaves_the_archive_readable(self):
        for runner in RUNNERS:
            with self.subTest(runner=runner), tempfile.TemporaryDirectory() as tmp:
                self.assert_failed_snapshot_append_rolls_back(runner, Path(tmp))

    def test_stale_identity_refuses_to_signal_an_unrelated_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            run_dir.mkdir()
            unrelated = subprocess.Popen(["sleep", "30"])
            try:
                start = subprocess.check_output(
                    ["bash", "-c", 'source "$1"; flagship_proc_start_ticks "$2"',
                     "lifecycle", str(LIFECYCLE), str(unrelated.pid)], text=True,
                ).strip()
                boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
                (run_dir / "runner.identity").write_text(
                    f"{unrelated.pid} {boot} {int(start) + 1}\n"
                )
                result = subprocess.run(
                    ["bash", str(LIFECYCLE), "stop", str(run_dir)],
                    text=True, capture_output=True, check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(process_alive(unrelated.pid))
            finally:
                unrelated.terminate()
                unrelated.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
