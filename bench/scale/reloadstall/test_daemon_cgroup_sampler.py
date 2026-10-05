#!/usr/bin/env python3
"""Small parsing checks for the high-frequency daemon cgroup sampler."""
import importlib.util
import fcntl
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "sampler", Path(__file__).with_name("sample-daemon-cgroup.py")
)
sampler = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sampler)


class SamplerTests(unittest.TestCase):
    def test_proc_comm_parentheses_do_not_shift_cpu_or_identity(self):
        fields = ["S", *["0"] * 19]
        fields[11], fields[12], fields[19] = "17", "5", "12345"
        self.assertEqual(sampler.proc_stat("71 (daemon ) worker) " + " ".join(fields)), (12345, 22))

    def test_stat_requires_real_distinct_fields(self):
        values = sampler.key_values("anon 2048\nsock 4096\n")
        self.assertEqual((int(values["anon"]), int(values["sock"])), (2048, 4096))
        with self.assertRaises(ValueError):
            sampler.key_values("anon 2048\nanon 4096\n")
        with self.assertRaises(KeyError):
            sampler.key_values("anon 2048\n")["sock"]
        with self.assertRaises(ValueError):
            int(sampler.key_values("sock missing\n")["sock"])
        with self.assertRaises(ValueError):
            int(sampler.key_values("sock\n")["sock"])

    def test_proc_status_allows_empty_optional_fields(self):
        values = sampler.key_values("VmRSS: 4096 kB\nx86_Thread_features:\nState: S (sleeping)\n")
        self.assertEqual(values, {"VmRSS": "4096", "x86_Thread_features": "", "State": "S"})

    def test_daemon_scope_requires_sole_process_and_live_memory_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root, pid = Path(directory), os.getpid()
            proc, cgroup = root / "proc", root / "cgroup/daemon.scope"
            proc.mkdir()
            cgroup.mkdir(parents=True)
            fields = ["S", *["0"] * 19]
            fields[19] = "12345"
            (proc / "stat").write_text(f"{pid} (daemon) " + " ".join(fields))
            (proc / "status").write_text("State: S\nVmRSS: 4096 kB\nVmHWM: 8192 kB\n")
            (proc / "cgroup").write_text("0::/daemon.scope\n")
            (cgroup / "memory.swap.max").write_text("0\n")
            paths = {f"/proc/{pid}": proc, "/sys/fs/cgroup": cgroup.parent}
            with patch.object(sampler, "Path", side_effect=lambda value: paths[value]):
                (cgroup / "cgroup.procs").write_text(f"{pid}\n{pid + 1}\n")
                with self.assertRaisesRegex(ValueError, "sole process"):
                    sampler.sample(pid, root / "out.csv", 0.025)
                (cgroup / "cgroup.procs").write_text(f"{pid}\n")
                with self.assertRaises(FileNotFoundError):
                    sampler.sample(pid, root / "out.csv", 0.025)


class LegWrapperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repo"
        reload = self.repo / "bench/scale/reloadstall"
        matrix = self.repo / "bench/scale/matrix"
        reload.mkdir(parents=True)
        matrix.mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        self.script = reload / "run-unsent-leg.sh"
        shutil.copyfile(Path(__file__).with_name(self.script.name), self.script)
        for binary in ["target/release/rustbgpd", "target/scale/reloadstall"]:
            path = self.repo / binary
            path.parent.mkdir(parents=True)
            path.write_text("#!/bin/sh\nexit 0\n")
            path.chmod(0o755)
        self.sampler = reload / "sample-daemon-cgroup.py"
        self.sampler.write_text(
            "import sys\nfrom pathlib import Path\n"
            "Path(sys.argv[sys.argv.index('--out')+1]).write_text('header\\n1\\n')\n"
        )
        self.runner = matrix / "run-matrix.sh"
        self.out = Path(self.temp.name) / "out"

    def run_status(self, status, code, env=None):
        self.runner.write_text(
            'mkdir -p "$ARTIFACTS_DIR/rustbgpd"\n'
            'while [ ! -f "$(dirname "$ARTIFACTS_DIR")/cgroup-fast.csv" ]; do sleep 0.01; done\n'
            f'echo {status} >"$ARTIFACTS_DIR/rustbgpd/status"\nexit {code}\n'
        )
        return subprocess.run(
            ["bash", str(self.script), str(self.out), "unset"], env=env,
            capture_output=True, timeout=10
        )

    def test_success_requires_successful_runner_and_cell(self):
        self.assertEqual(self.run_status("pass", 0).returncode, 0)

    def test_cleanup_never_signals_the_sampler_after_wait(self):
        hook, trace = Path(self.temp.name) / "bash-env", Path(self.temp.name) / "kills"
        hook.write_text('kill() { printf "%s\\n" "$*" >>"$WRAPPER_TEST_KILLS"; builtin kill "$@"; }\n')
        env = dict(os.environ, BASH_ENV=str(hook), WRAPPER_TEST_KILLS=str(trace))
        for code, content in [(0, "header\n1\n"), (7, "header\n1\n"), (7, "")]:
            with self.subTest(code=code, trace=bool(content)):
                self.out = Path(self.temp.name) / f"out-{code}-{bool(content)}"
                trace.write_text("")
                self.sampler.write_text(
                    "import os, sys\nfrom pathlib import Path\n"
                    "out=Path(sys.argv[sys.argv.index('--out')+1])\n"
                    "out.with_name('sampler.pid').write_text(str(os.getpid()))\n"
                    f"out.write_text({content!r})\nsys.exit({code})\n"
                )
                result = self.run_status("pass", 0, env)
                pid = (self.out / "sampler.pid").read_text()
                attempts = [line for line in trace.read_text().splitlines() if pid in line.split()]
                self.assertEqual(len(attempts), 0 if content else 1)
                if code == 0:
                    self.assertEqual(result.returncode, 0)
                else:
                    self.assertNotEqual(result.returncode, 0)

    def test_header_only_sampler_trace_is_not_evidence(self):
        self.sampler.write_text(
            "import sys\nfrom pathlib import Path\n"
            "Path(sys.argv[sys.argv.index('--out')+1]).write_text('header\\n')\n"
        )
        self.assertNotEqual(self.run_status("pass", 0).returncode, 0)

    def test_runner_failure_is_not_masked_by_pass_status(self):
        self.assertNotEqual(self.run_status("pass", 3).returncode, 0)
        self.assertEqual((self.out / "runner.exit").read_text().strip(), "3")

    def test_failed_cell_is_not_masked_by_runner_success(self):
        self.assertNotEqual(self.run_status("fail", 0).returncode, 0)

    def test_interruption_releases_owned_descendants_lock(self):
        lock, ready = Path(self.temp.name) / "lock", Path(self.temp.name) / "ready"
        self.runner.write_text(
            'exec 9>"$WRAPPER_TEST_LOCK"\nflock 9\n'
            'sleep 300 &\necho "$!" >"$WRAPPER_TEST_READY"\nwait\n'
        )
        env = dict(os.environ, WRAPPER_TEST_LOCK=str(lock), WRAPPER_TEST_READY=str(ready),
                   UNSENT_CLEANUP_TIMEOUT_SECS="1")
        child = subprocess.Popen(
            ["bash", str(self.script), str(self.out), "unset"], env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.monotonic() + 5
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(ready.exists(), "owned runner did not start")
            child.terminate()
            self.assertEqual(child.wait(timeout=40), 143)
            with lock.open("w") as stream:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()

    def test_term_ignoring_group_is_killed_before_waiting(self):
        ready = Path(self.temp.name) / "ready"
        self.runner.write_text('trap "" TERM\nsleep 300 &\necho "$!" >"$WRAPPER_TEST_READY"\nwait\n')
        env = dict(os.environ, WRAPPER_TEST_READY=str(ready), UNSENT_CLEANUP_TIMEOUT_SECS="1")
        child = subprocess.Popen(["bash", str(self.script), str(self.out), "unset"], env=env,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 5
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(ready.exists(), "owned runner did not start")
            child.terminate()
            self.assertEqual(child.wait(timeout=5), 143)
            self.assertEqual((self.out / "runner.exit").read_text().strip(), "137")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()


if __name__ == "__main__":
    unittest.main()
