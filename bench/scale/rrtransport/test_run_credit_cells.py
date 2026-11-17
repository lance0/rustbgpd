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
    def run_runner(self, root: Path, exit_code: int, *cells: str) -> int:
        shims = root / "bin"
        shims.mkdir(exist_ok=True)
        # The scope launcher runs the command after `--` in place.
        executable(
            shims / "systemd-run",
            'while [ "$1" != -- ]; do shift; done; shift; exec "$@"\n',
        )
        binary = executable(root / "rrtransport", f"exit {exit_code}\n")
        env = dict(
            os.environ,
            PATH=f"{shims}:{os.environ['PATH']}",
            RUSTBGPD_HOST_LOCK=str(root / "host.lock"),
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


if __name__ == "__main__":
    unittest.main()
