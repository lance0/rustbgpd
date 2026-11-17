"""The credit-cell runner, driven with a stand-in binary and scope launcher."""

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

RUNNER = Path(__file__).resolve().parent / "run-credit-cells.sh"


def executable(path: Path, body: str) -> Path:
    path.write_text("#!/usr/bin/env bash\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


class Runner(unittest.TestCase):
    def run_runner(
        self, root: Path, exit_code: int, *cells: str, body: str = 'exit "$STAND_IN_EXIT"\n'
    ) -> int:
        shims = root / "bin"
        shims.mkdir(exist_ok=True)
        # The scope launcher runs the command after `--` in place.
        executable(
            shims / "systemd-run",
            'while [ "$1" != -- ]; do shift; done; shift; exec "$@"\n',
        )
        # One binary for every call: the exit code comes from the environment.
        binary = executable(root / "rrtransport", body)
        env = dict(
            os.environ,
            PATH=f"{shims}:{os.environ['PATH']}",
            RUSTBGPD_HOST_LOCK=str(root / "host.lock"),
            STAND_IN_EXIT=str(exit_code),
        )
        return subprocess.run(
            ["bash", str(RUNNER), "--correctness-only", str(binary), str(root / "out"), *cells],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        ).returncode

    def test_seeded_stale_result_is_cleared_before_a_failed_rerun(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            out = root / "out"
            out.mkdir()
            # An earlier successful run left results behind.
            (out / "exhaust-unicast.json").write_text('{"mode": "measured"}')
            (out / "paused-evpn.json").write_text('{"mode": "measured"}')
            (out / "paused-exit.json").write_text('{"oom": true}')
            self.assertEqual(self.run_runner(root, 1, "exhaust-unicast", "paused"), 1)
            self.assertFalse((out / "exhaust-unicast.json").exists())
            self.assertFalse((out / "paused-evpn.json").exists())
            marker = json.loads((out / "paused-exit.json").read_text())
            self.assertEqual(marker, {"cell": "paused", "exit": 1, "oom": False})
            self.assertTrue((out / "exhaust-unicast-exit.json").exists())

    def test_successful_rerun_clears_an_old_exit_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            out = root / "out"
            out.mkdir()
            (out / "paused-exit.json").write_text('{"oom": true}')
            self.assertEqual(self.run_runner(root, 0, "paused"), 0)
            self.assertFalse((out / "paused-exit.json").exists())

    def test_seeded_provenance_lists_every_invocation(self):
        # Without a per-invocation cell list the analyzer cannot tell an
        # attempted cell that left nothing from one never run.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(self.run_runner(root, 0, "paused"), 0)
            self.assertEqual(self.run_runner(root, 1, "fill-vpn", "probes"), 1)
            lines = [
                json.loads(line)
                for line in (root / "out" / "provenance.jsonl").read_text().splitlines()
            ]
            self.assertEqual(
                [line["cells"] for line in lines], [["paused"], ["fill-vpn", "probes"]]
            )
            self.assertEqual(len({line["sha256"] for line in lines}), 1)
            self.assertEqual({line["measured"] for line in lines}, {0})

    def test_interrupted_rerun_leaves_no_stale_result_for_a_later_cell(self):
        # The run dies during its first cell. The second cell is listed in
        # the new provenance line, so its old result must already be gone.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            out = root / "out"
            out.mkdir()
            for name in ("probes.json", "fill-vpn.json", "fill-vpn-exit.json"):
                (out / name).write_text('{"mode": "measured"}')
            # The stand-in's parent is the runner (the scope shim execs it).
            body = 'kill -KILL "$PPID"\n'
            self.assertNotEqual(self.run_runner(root, 0, "probes", "fill-vpn", body=body), 0)
            lines = (out / "provenance.jsonl").read_text().splitlines()
            self.assertEqual(json.loads(lines[-1])["cells"], ["probes", "fill-vpn"])
            for name in ("probes.json", "fill-vpn.json", "fill-vpn-exit.json"):
                self.assertFalse((out / name).exists(), name)

    def test_unknown_cell_is_refused_before_provenance(self):
        # A refused invocation must not list cells it never attempted.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(self.run_runner(root, 0, "probes"), 0)
            self.assertEqual(self.run_runner(root, 0, "paused", "bogus"), 2)
            lines = (root / "out" / "provenance.jsonl").read_text().splitlines()
            self.assertEqual([json.loads(line)["cells"] for line in lines], [["probes"]])

    def test_each_burst_cell_runs_its_own_trigger(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            body = 'echo "$1 $2" >>"$(dirname "$0")/calls"\n'
            self.assertEqual(self.run_runner(root, 0, "restart-evpn", "exhaust-evpn", body=body), 0)
            calls = (root / "calls").read_text().splitlines()
            self.assertEqual(calls, ["credit-restart evpn", "credit-exhaust evpn"])


if __name__ == "__main__":
    unittest.main()
