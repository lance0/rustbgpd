#!/usr/bin/env python3
"""Small parsing checks for the high-frequency daemon cgroup sampler."""
import importlib.util
import copy
import fcntl
import json
import os
from pathlib import Path
import shutil
import signal
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
netem_spec = importlib.util.spec_from_file_location(
    "netem", Path(__file__).with_name("receiver-netem.py")
)
netem = importlib.util.module_from_spec(netem_spec)
netem_spec.loader.exec_module(netem)


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


class ContainerOwnershipTests(unittest.TestCase):
    def test_full_cid_image_binary_cgroup_and_caps_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root, cid, pid = Path(directory), "a" * 64, 123
            exe = root / "daemon"
            exe.touch()
            proc, cgroup = root / "proc", root / "cgroups" / f"docker-{cid}.scope"
            proc.mkdir()
            cgroup.mkdir(parents=True)
            (proc / "exe").symlink_to(exe)
            (proc / "stat").write_text("123 (daemon) S " + "0 " * 18 + "42")
            (proc / "cgroup").write_text(f"0::/{cgroup.name}\n")
            (cgroup / "memory.max").write_text("1024")
            data = {"Id": cid, "Image": "sha256:" + "b" * 64,
                    "State": {"Pid": pid, "Running": True},
                    "HostConfig": {"NetworkMode": "none", "PidMode": "",
                                   "Memory": 1024, "MemorySwap": 1024}}
            paths = {f"/proc/{pid}": proc, "/sys/fs/cgroup": cgroup.parent}
            with patch.object(sampler, "Path", side_effect=lambda value: paths[value]):
                with patch.object(sampler.subprocess, "check_output", return_value=json.dumps([data])):
                    owner = sampler.container_owner(cid, data["Image"], exe)
                    self.assertEqual(owner["starttime"], 42)
                    self.assertEqual(owner["kind"], "container-daemon-only")
                    self.assertEqual(owner["binary_inode"], exe.stat().st_ino)
                    with self.assertRaisesRegex(ValueError, "full container ID"):
                        sampler.container_owner(cid[:12], data["Image"], exe)
                for section, key, value in [(None, "Id", "c" * 64),
                                            (None, "Image", "sha256:" + "c" * 64),
                                            ("State", "Running", False),
                                            ("HostConfig", "MemorySwap", -1),
                                            ("HostConfig", "NetworkMode", "host"),
                                            ("HostConfig", "PidMode", "host")]:
                    bad = copy.deepcopy(data)
                    (bad if section is None else bad[section])[key] = value
                    with self.subTest(key=key), patch.object(
                            sampler.subprocess, "check_output", return_value=json.dumps([bad])):
                        with self.assertRaises(ValueError):
                            sampler.container_owner(cid, data["Image"], exe)
                (proc / "cgroup").write_text("0::/unowned.scope\n")
                with patch.object(sampler.subprocess, "check_output", return_value=json.dumps([data])):
                    with self.assertRaisesRegex(ValueError, "exact owned container"):
                        sampler.container_owner(cid, data["Image"], exe)

    def test_sampling_rejects_mixed_descendant_swap_and_reused_pid(self):
        with tempfile.TemporaryDirectory() as directory:
            root, pid = Path(directory), 123
            proc, cgroup = root / "proc", root / "group"
            proc.mkdir()
            cgroup.mkdir()
            stat = "123 (daemon) S " + "0 " * 18 + "42"
            (proc / "stat").write_text(stat)
            (proc / "cgroup").write_text("0::" + str(cgroup))
            (cgroup / "memory.swap.max").write_text("0")
            (cgroup / "cgroup.procs").write_text(str(pid))
            owner = {"starttime": 42, "cgroup": str(cgroup)}
            sampler.verify_container_membership(proc, cgroup, pid, owner)
            for path, bad, message in [
                    (cgroup / "cgroup.procs", "123 124", "sole process"),
                    (cgroup / "memory.swap.max", "max", "swap fenced"),
                    (proc / "stat", stat[:-2] + "43", "ownership changed"),
                    (proc / "cgroup", "0::/other", "ownership changed")]:
                good = path.read_text()
                path.write_text(bad)
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, message):
                    sampler.verify_container_membership(proc, cgroup, pid, owner)
                path.write_text(good)
            child = cgroup / "child"
            child.mkdir()
            (child / "cgroup.procs").write_text("124")
            with self.assertRaisesRegex(ValueError, "populated descendants"):
                sampler.verify_container_membership(proc, cgroup, pid, owner)


class NetemTests(unittest.TestCase):
    def snapshot(self):
        return {"qdisc": [{"kind": "netem", "dev": netem.DEVICE,
                            "options": {"delay": {"delay": 0.01}},
                            "drops": 0, "packets": 42}],
                "filters": [{"kind": "flower", "protocol": "ip", "pref": priority,
                             "options": {"keys": {"eth_type": "ipv4", "ip_proto": "tcp", "src_ip": src,
                                                   "dst_ip": dst},
                                         "actions": [{"kind": "mirred", "mirred_action": "redirect",
                                                      "direction": "egress", "to_dev": netem.DEVICE,
                                                      "stats": {"drops": 0, "packets": 21}}]}}
                            for priority, (src, dst) in enumerate(netem.FLOWS, 10)]}

    def test_queue_filters_live_traffic_and_rtt_must_all_match(self):
        netem.verify(self.snapshot(), 20, traffic=True)
        netem.verify_rtt("rtt:20.03/0.15", 20)
        for mutate in [
                lambda d: d["qdisc"].clear(),
                lambda d: d["qdisc"][0].update(drops=1),
                lambda d: d["qdisc"][0].update(packets=0),
                lambda d: d["qdisc"][0]["options"]["delay"].update(delay=0),
                lambda d: d["filters"].pop(),
                lambda d: d["filters"][0]["options"]["keys"].update(dst_ip="127.0.0.1"),
                lambda d: d["filters"][0]["options"]["keys"].update(ip_proto="udp"),
                lambda d: d["filters"][0]["options"]["actions"][0]["stats"].update(packets=0),
                lambda d: d["filters"][0]["options"]["actions"][0]["stats"].update(drops=1)]:
            data = self.snapshot()
            mutate(data)
            with self.assertRaises(ValueError):
                netem.verify(data, 20, traffic=True)
        for text in ["", "rtt:0.01/0.005"]:
            with self.assertRaisesRegex(ValueError, "TCP RTT evidence"):
                netem.verify_rtt(text, 20)

    def test_iproute_classifier_headers_are_not_extra_rules(self):
        data = self.snapshot()
        data["filters"] = [entry for rule in data["filters"]
                           for entry in ({key: value for key, value in rule.items() if key != "options"}, rule)]
        netem.verify(data, 20, traffic=True)

    def test_host_namespace_is_rejected_before_network_commands(self):
        host = str(Path("/proc/self/ns/net").readlink())
        with self.assertRaisesRegex(ValueError, "host network namespace"):
            netem.private_namespace(host)


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

    def test_netem_ss_failure_cleans_native_descendants_and_stubborn_sampler(self):
        lock, ready = Path(self.temp.name) / "lock", Path(self.temp.name) / "ready"
        tools_dir = self.repo.parent / "tools"
        tools_dir.mkdir()
        fixture = NetemTests().snapshot()
        for queue in fixture["qdisc"]: queue.update(packets=0)
        for rule in fixture["filters"]: rule["options"]["actions"][0]["stats"]["packets"] = 0
        for name, body in {
            "ip": "#!/bin/sh\nexit 0\n",
            "tc": "#!/usr/bin/env python3\nimport json,sys\ndata=" + repr(fixture) +
                  "\nprint(json.dumps(data['qdisc' if 'qdisc' in sys.argv else 'filters']))\n",
            "ss": "#!/usr/bin/env python3\nimport os,time\nfrom pathlib import Path\n"
                  "deadline=time.monotonic()+5\n"
                  "while not Path(os.environ['WRAPPER_TEST_READY']).exists():\n"
                  " if time.monotonic()>deadline: raise RuntimeError('descendant handshake missing')\n"
                  " time.sleep(.01)\nraise SystemExit(7)\n",
        }.items():
            file = tools_dir / name
            file.write_text(body)
            file.chmod(0o755)
        shutil.copyfile(Path(__file__).with_name("receiver-netem.py"), self.script.with_name("receiver-netem.py"))
        descendant = self.repo.parent / "descendant.py"
        descendant.write_text(
            "import os,signal,time\nfrom pathlib import Path\n"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            "Path(os.environ['WRAPPER_TEST_READY']).write_text(str(os.getpid()))\n"
            "time.sleep(300)\n")
        self.runner.write_text('exec 9>"$WRAPPER_TEST_LOCK"\nflock 9\n'
                               f'python3 "{descendant}" &\nwait\n')
        self.sampler.write_text(
            "import signal,sys,time\nfrom pathlib import Path\n"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            "Path(sys.argv[sys.argv.index('--out')+1]).write_text('header\\n1\\n')\n"
            "time.sleep(300)\n")
        child = subprocess.Popen(
            ["bash", str(self.script), str(self.out), "unset", "20", "--inside-netns"],
            env=dict(os.environ, PATH=f"{tools_dir}:{os.environ['PATH']}",
                     RELOADSTALL_HOST_NETNS="net:[0]", WRAPPER_TEST_LOCK=str(lock),
                     WRAPPER_TEST_READY=str(ready), UNSENT_CLEANUP_TIMEOUT_SECS="1"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            _stdout, stderr = child.communicate(timeout=12)
            self.assertNotEqual(child.returncode, 0)
            self.assertTrue(ready.exists(), stderr)
            self.assertEqual((self.out / "sampler.exit").read_text().strip(), "137")
            self.assertIn("returned non-zero exit status 7", (self.out / "runner.log").read_text())
            proc = Path(f"/proc/{ready.read_text()}/stat")
            self.assertTrue(not proc.exists() or proc.read_text().split(") ")[1].startswith("Z"))
            with lock.open("w") as stream:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            # A deliberately broken wrapper must not leak the regression's processes.
            groups = [child.pid]
            if (self.out / "runner.pid").exists():
                groups.append(int((self.out / "runner.pid").read_text()))
            for group in groups:
                try:
                    os.killpg(group, signal.SIGKILL)
                except ProcessLookupError:
                    pass
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

class ContainerCellTests(unittest.TestCase):
    """Exercise the real container branch with a stateful Docker CLI stand-in."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.cdir = self.root / "matrix/rustbgpd"
        self.cdir.mkdir(parents=True)
        self.tools = self.root / "tools"
        self.tools.mkdir()
        (self.tools / "gen-scenario.py").write_text("import os,sys; sys.exit(int(os.environ.get('TEST_GENERATOR_EXIT','0')))\n")
        self.trace = self.root / "docker.trace"
        self.env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}",
                        TEST_ROOT=str(self.root), UNSENT_CLEANUP_TIMEOUT_SECS="1")
        docker = self.bin / "docker"
        docker.write_text('''#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path
root=Path(os.environ['TEST_ROOT']); args=sys.argv[1:]
with (root/'docker.trace').open('a') as f: f.write(json.dumps(args)+'\\n')
image='sha256:'+'c'*64
states=root/'states'; states.mkdir(exist_ok=True)
def read(ref):
    for path in states.iterdir():
        data=json.loads(path.read_text())
        if ref in (data['Id'],data['Name'].lstrip('/')): return path,data
    print("Error response from daemon: No such container: "+ref, file=sys.stderr)
    sys.exit(1)
def save(path,data): path.write_text(json.dumps(data))
cmd=args[0]
if cmd=='create':
    role=Path(args[args.index('--cidfile')+1]).stem
    cid=('a' if role=='daemon' else 'b')*64
    name=args[args.index('--name')+1]; label=args[args.index('--label')+1].split('=',1)[1]
    data={'Id':cid,'Name':'/'+name,'Image':image,'Config':{'Labels':{'rustbgpd.unsent-owner':label}},
          'State':{'Running':False,'ExitCode':0,'OOMKilled':False}}
    save(states/cid,data)
    if os.environ.get('TEST_INTERRUPT_CREATE') and role=='receiver':
        (root/'ready').touch(); time.sleep(300)
    Path(args[args.index('--cidfile')+1]).write_text(cid)
elif cmd=='start':
    path,data=read(args[1]);data['State']['Running']=True;save(path,data)
    if data['Id'].startswith('b'): (root/'ready').touch()
elif cmd=='inspect':
    if os.environ.get('TEST_INSPECT_UNAVAILABLE'):
        print('Cannot connect to the Docker daemon',file=sys.stderr); sys.exit(1)
    if os.environ.get('TEST_INSPECT_TIMEOUT'): time.sleep(30)
    path,data=read(args[-1])
    print(data['Id'] if '--format' in args else json.dumps([data]))
elif cmd=='wait':
    path,data=read(args[1])
    if os.environ.get('TEST_BLOCK_RECEIVER'):
        while data['State']['Running']:
            time.sleep(.01); data=json.loads(path.read_text())
    else:
        data['State']['Running']=False
        data['State']['ExitCode']=int(os.environ.get('TEST_RECEIVER_EXIT','0'));save(path,data)
    print(data['State']['ExitCode'])
elif cmd in ('stop','kill'):
    path,data=read(args[-1])
    if cmd=='stop' and os.environ.get('TEST_IGNORE_TERM') and data['State']['Running']:
        sys.exit(1)
    if cmd=='kill': data['State']['ExitCode']=137
    data['State']['Running']=False;save(path,data)
    if data['Id'].startswith('a'): (root/'daemon-stopped').touch()
elif cmd=='logs': print('retained workload log')
elif cmd=='rm':
    path,data=read(args[-1]); path.unlink()
else: sys.exit(2)
''')
        docker.chmod(0o755)
        (self.tools / "sample-daemon-cgroup.py").write_text('''import os,sys,time
from pathlib import Path
root=Path(os.environ['TEST_ROOT'])
out=Path(sys.argv[sys.argv.index('--out')+1])
out.write_text('epoch_us,monotonic_ns,read_us,vmrss_kib\\n1,1,1,4096\\n')
while not (root/'daemon-stopped').exists():
    if os.environ.get('TEST_SAMPLER_FAIL') and (root/'ready').exists(): sys.exit(7)
    time.sleep(.01)
''')
        matrix = Path(__file__).parents[1] / "matrix/run-matrix.sh"
        source = matrix.read_text()
        function = source[source.index("run_container_cell() ("):source.index("# run_cell <cell>:")]
        self.script = self.root / "cell.sh"
        self.script.write_text('''set -u
REPO=$TEST_ROOT
RSTALL=$TEST_ROOT/tools
HARNESS=$TEST_ROOT/reloadstall
ART=$TEST_ROOT/matrix
RELOADSTALL_CONTAINER_IMAGE_ID=sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
RELOADSTALL_CONTAINER_MEMORY_BYTES=1073741824
RELOADSTALL_UNSENT_RTT_MS=20
RELOADSTALL_HOST_NETNS='net:[1]'
N_PEERS=12 TOTAL=1200 PORT=1790 CONTROL_SECS=1 CHANGED_PEERS='' RSS_LIMIT_KIB=1048576
RELOADS=${RELOADS:-2}
recheck_cell_provenance() { return 0; }
write_cell_provenance() { return 0; }
provenance_sha256_file() { echo fake-binary-hash; }
''' + function + '\ntrap "wait; exit 143" TERM\nrun_container_cell "$ART/rustbgpd" "$TEST_ROOT/scenario"\n')

    def commands(self):
        return [json.loads(line) for line in self.trace.read_text().splitlines()]

    def assert_cleanup_order(self):
        commands = self.commands()
        stopped = [args[-1] for args in commands if args[0] == "stop"]
        self.assertEqual(stopped, ["b" * 64, "a" * 64])
        self.assertFalse(list((self.root / "states").iterdir()))
        for role in ("receiver", "daemon"):
            self.assertTrue((self.cdir / f"{role}.final.json").is_file())
            self.assertTrue((self.cdir / f"{role}.log").is_file())

    def test_receiver_success_and_failure_keep_status_and_cleanup(self):
        for exit_code in (0, 7):
            with self.subTest(exit_code=exit_code):
                if exit_code:
                    (self.root / "daemon-stopped").unlink()
                    self.trace.unlink()
                    for file in self.cdir.glob("*.cid"): file.unlink()
                result = subprocess.run(["bash", str(self.script)], env=dict(
                    self.env, TEST_RECEIVER_EXIT=str(exit_code)), capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 0 if exit_code == 0 else 1, result.stderr)
                self.assertEqual((self.cdir / "receiver.exit").read_text().strip(), str(exit_code))
                self.assert_cleanup_order()

    def test_external_file_and_command_options_fail_before_host_lock_or_containers(self):
        matrix = Path(__file__).parents[1] / "matrix/run-matrix.sh"
        lock = self.root / "host.lock"
        with lock.open("w") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            for name in ("RELOADSTALL_OVERLAP_FILE", "RELOADSTALL_EVIDENCE_DIR",
                         "RELOADSTALL_PRE_CHURN_EVIDENCE_DIR", "RELOADSTALL_RECEIVED_VIEW_FILE",
                         "RELOADSTALL_STAGE_CMD"):
                for value in ("", "/outside/receiver/mounts"):
                    with self.subTest(name=name, value=value):
                        result = subprocess.run(["bash", str(matrix), "rustbgpd"], env=dict(
                            self.env, RELOADSTALL_CONTAINER_IMAGE_ID="sha256:" + "c" * 64,
                            RELOADSTALL_UNSENT_RTT_MS="20", RUSTBGPD_HOST_LOCK=str(lock),
                            **{name: value}), capture_output=True, text=True, timeout=5)
                        self.assertEqual(result.returncode, 2, result.stderr)
                        self.assertIn(f"container RTT mode does not support {name}", result.stderr)
                        self.assertNotIn("host.lock", result.stderr)
                        self.assertFalse(self.trace.exists(), "Docker ran before admission rejection")

    def test_reload_metrics_address_is_owned_and_omitted_without_reloads(self):
        for reloads in (0, 2):
            with self.subTest(reloads=reloads):
                if reloads:
                    (self.root / "daemon-stopped").unlink()
                    self.trace.unlink()
                    for file in self.cdir.glob("*.cid"): file.unlink()
                result = subprocess.run(["bash", str(self.script)], env=dict(
                    self.env, RELOADS=str(reloads), RELOADSTALL_RELOAD_METRICS_ADDR="127.0.0.1:9999"),
                    capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                receiver = next(args for args in self.commands() if args[0] == "create"
                                and args[args.index("--cidfile") + 1].endswith("receiver.cid"))
                forwarded = [receiver[i + 1] for i, arg in enumerate(receiver) if arg == "-e"]
                metrics = [value for value in forwarded if value.startswith("RELOADSTALL_RELOAD_METRICS_ADDR")]
                self.assertEqual(metrics, ["RELOADSTALL_RELOAD_METRICS_ADDR=127.0.0.1:9179"] if reloads else [])
                self.assertEqual(receiver[-2], str(reloads))
                self.assert_cleanup_order()

    def test_sampler_failure_aborts_receiver_and_preserves_failure(self):
        result = subprocess.run(["bash", str(self.script)], env=dict(
            self.env, TEST_SAMPLER_FAIL="1", TEST_BLOCK_RECEIVER="1"),
            capture_output=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / "sampler.exit").read_text().strip(), "7")
        self.assert_cleanup_order()

    def test_unavailable_docker_is_not_treated_as_no_owned_container(self):
        result = subprocess.run(["bash", str(self.script)], env=dict(
            self.env, TEST_GENERATOR_EXIT="1", TEST_INSPECT_UNAVAILABLE="1"),
            capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.cdir / "cleanup.exit").read_text().strip(), "1")
        self.assertIn("Cannot connect", (self.cdir / "daemon.lookup.stderr").read_text())
        self.assertFalse(any(args[0] == "rm" for args in self.commands()))

    def test_inspect_timeout_is_bounded_and_fails_cleanup(self):
        started = time.monotonic()
        result = subprocess.run(["bash", str(self.script)], env=dict(
            self.env, TEST_GENERATOR_EXIT="1", TEST_INSPECT_TIMEOUT="1"),
            capture_output=True, timeout=25)
        self.assertNotEqual(result.returncode, 0)
        self.assertLess(time.monotonic() - started, 24)
        self.assertEqual((self.cdir / "daemon.lookup.exit").read_text().strip(), "124")
        self.assertEqual((self.cdir / "cleanup.exit").read_text().strip(), "1")
        self.assertFalse(any(args[0] == "rm" for args in self.commands()))

    def test_interruption_recovers_create_identity_and_kills_term_ignoring_containers(self):
        self.env.update(TEST_BLOCK_RECEIVER="1", TEST_INTERRUPT_CREATE="1", TEST_IGNORE_TERM="1")
        child = subprocess.Popen(["bash", str(self.script)], env=self.env, start_new_session=True,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 10
            while not (self.root / "ready").exists() and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertTrue((self.root / "ready").exists())
            os.killpg(child.pid, signal.SIGTERM)
            self.assertNotEqual(child.wait(timeout=10), 0)
            self.assert_cleanup_order()
            self.assertTrue(any(args[0] == "kill" for args in self.commands()))
            self.assertEqual((self.cdir / "daemon.exit-state").read_text().strip(), "137\tfalse\tfalse")
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()


if __name__ == "__main__":
    unittest.main()
