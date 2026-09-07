"""Exercise the build mutex with real processes and an isolated lock file."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class BuildLockTest(unittest.TestCase):
    def test_serialization_release_and_command_status(self):
        script = str(Path(__file__).with_name("build-lock.sh").resolve())
        with tempfile.TemporaryDirectory() as directory:
            env = {**os.environ, "RUSTBGPD_BUILD_LOCK": f"{directory}/build.lock"}
            holder = subprocess.Popen(
                ["bash", script, "bash", "-c", "echo ready; read -r release"],
                env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
            )
            self.addCleanup(holder.stdout.close)
            self.addCleanup(holder.stdin.close)
            waiter = None
            try:
                self.assertEqual(holder.stdout.readline(), "ready\n")
                waiter = subprocess.Popen(["bash", script, "true"], env=env)
                with self.assertRaises(subprocess.TimeoutExpired):
                    waiter.wait(timeout=0.2)
                # Separate artifact directories must not block each other.
                separate = {**env, "RUSTBGPD_BUILD_LOCK": f"{directory}/other.lock"}
                subprocess.run(["bash", script, "true"], env=separate, check=True, timeout=5)
                holder.kill()
                holder.wait(timeout=5)
                self.assertEqual(waiter.wait(timeout=5), 0)
                result = subprocess.run(
                    ["bash", script, "bash", "-c", "exit 23"], env=env, timeout=5,
                )
                self.assertEqual(result.returncode, 23)
            finally:
                for process in (holder, waiter):
                    if process is not None and process.poll() is None:
                        process.kill()
                        process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
