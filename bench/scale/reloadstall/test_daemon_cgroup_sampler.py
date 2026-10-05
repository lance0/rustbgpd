#!/usr/bin/env python3
"""Small parsing checks for the high-frequency daemon cgroup sampler."""
import importlib.util
import fcntl
import json
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
readback_spec = importlib.util.spec_from_file_location(
    "readback", Path(__file__).with_name("check-unsent-readback.py")
)
readback = importlib.util.module_from_spec(readback_spec)
readback_spec.loader.exec_module(readback)


def log_line(message, peer, **fields):
    return json.dumps({"fields": {"message": message, "peer": peer, **fields}})


def readback_line(peer, requested, actual):
    return log_line(readback.READBACK, peer, requested=requested, actual=actual)


def established_line(peer):
    return log_line(readback.ESTABLISHED, peer, peer_asn=64512)


class ReadbackTests(unittest.TestCase):
    def test_every_established_session_needs_its_own_matching_readback(self):
        positive = [readback_line("p1", "Some(65536)", 65536), established_line("p1"),
                    readback_line("p2", "Some(65536)", 65536), established_line("p2"),
                    # A reconnect gets a fresh writer and a fresh readback.
                    readback_line("p1", "Some(65536)", 65536), established_line("p1")]
        self.assertEqual(readback.check(positive, "65536"), [])
        unset = [readback_line("p1", "None", 0), established_line("p1")]
        self.assertEqual(readback.check(unset, "unset"), [])

    def test_featureless_daemon_fails_a_positive_arm(self):
        self.assertTrue(readback.check([established_line("p1")], "65536"))
        self.assertTrue(readback.check([established_line("p1")], "unset"))

    def test_partial_or_mismatched_readback_fails(self):
        for lines, threshold in [
            # Reconnect reuses the first connection's readback.
            ([readback_line("p1", "Some(65536)", 65536), established_line("p1"),
              established_line("p1")], "65536"),
            # One of two sessions lacks readback.
            ([readback_line("p1", "Some(65536)", 65536), established_line("p1"),
              established_line("p2")], "65536"),
            # Kernel value differs from the request.
            ([readback_line("p1", "Some(65536)", 131072), established_line("p1")], "65536"),
            # Readback without its value.
            ([log_line(readback.READBACK, "p1", requested="Some(65536)"),
              established_line("p1")], "65536"),
            # The unset arm applied a threshold.
            ([readback_line("p1", "Some(65536)", 65536), established_line("p1")], "unset"),
            # Readback for another peer does not cover this one.
            ([readback_line("p2", "Some(65536)", 65536), established_line("p1")], "65536"),
            # No session at all is not evidence.
            ([readback_line("p1", "Some(65536)", 65536)], "65536"),
        ]:
            with self.subTest(lines=lines, threshold=threshold):
                self.assertTrue(readback.check(lines, threshold))


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
        checker = "check-unsent-readback.py"
        shutil.copyfile(Path(__file__).with_name(checker), reload / checker)
        (self.repo / ".gitignore").write_text("/target\n")
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
        self.runner.write_text("exit 0\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "base")
        self.out = Path(self.temp.name) / "out"
        self.daemon_log = "\n".join([readback_line("p1", "None", 0), established_line("p1")])

    def git(self, *args, cwd=None):
        return subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
            cwd=cwd or self.repo, check=True, capture_output=True,
        )

    def run_status(self, status, code, env=None, threshold="unset"):
        log = self.repo.parent / "daemon.log"
        log.write_text(self.daemon_log + "\n" if self.daemon_log is not None else "")
        self.runner.write_text(
            'mkdir -p "$ARTIFACTS_DIR/rustbgpd"\n'
            'while [ ! -f "$(dirname "$ARTIFACTS_DIR")/cgroup-fast.csv" ]; do sleep 0.01; done\n'
            + (f'cp "{log}" "$ARTIFACTS_DIR/rustbgpd/daemon.log"\n'
               if self.daemon_log is not None else "")
            + f'echo {status} >"$ARTIFACTS_DIR/rustbgpd/status"\nexit {code}\n'
        )
        return subprocess.run(
            ["bash", str(self.script), str(self.out), threshold], env=env,
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

    def test_positive_arm_requires_live_readback_evidence(self):
        self.daemon_log = "\n".join([readback_line("p1", "Some(65536)", 65536),
                                     established_line("p1")])
        self.assertEqual(self.run_status("pass", 0, threshold="65536").returncode, 0)

    def test_featureless_daemon_fails_a_positive_leg(self):
        self.daemon_log = established_line("p1")
        self.assertNotEqual(self.run_status("pass", 0, threshold="65536").returncode, 0)
        self.assertEqual((self.out / "readback.exit").read_text().strip(), "1")

    def test_missing_or_partial_readback_fails_the_leg(self):
        for name, log in [("missing", None),
                          ("partial", "\n".join([readback_line("p1", "Some(65536)", 65536),
                                                 established_line("p1"),
                                                 established_line("p2")]))]:
            with self.subTest(name):
                self.out = Path(self.temp.name) / f"out-{name}"
                self.daemon_log = log
                self.assertNotEqual(self.run_status("pass", 0, threshold="65536").returncode, 0)
                self.assertNotEqual((self.out / "readback.exit").read_text().strip(), "0")

    def test_provenance_reproduces_staged_unstaged_and_untracked_changes(self):
        tracked = self.repo / "bench/scale/reloadstall/tracked.txt"
        staged = self.repo / "bench/scale/reloadstall/staged.txt"
        tracked.write_text("base\n")
        staged.write_text("base\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "fixture")
        tracked.write_text("unstaged edit\n")
        staged.write_text("staged edit\n")
        self.git("add", str(staged))
        (self.repo / "untracked.bin").write_bytes(b"\x00new\xff")
        index_before = self.git("diff", "--cached", "--name-only").stdout
        self.assertEqual(self.run_status("pass", 0).returncode, 0)
        # The capture leaves the operator's own index untouched.
        self.assertEqual(self.git("diff", "--cached", "--name-only").stdout, index_before)
        clone = Path(self.temp.name) / "clone"
        self.git("clone", "-q", str(self.repo), str(clone))
        head = (self.out / "experiment.head").read_text().strip()
        self.git("checkout", "-q", head, cwd=clone)
        self.git("apply", str(self.out / "experiment.diff"), cwd=clone)
        for path in [tracked, staged, self.repo / "untracked.bin"]:
            relative = path.relative_to(self.repo)
            self.assertEqual((clone / relative).read_bytes(), path.read_bytes(), relative)

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
