"""Exercise the hook pass cache with real git repositories and a counting command."""

import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

SCRIPT = str(Path(__file__).with_name("hook-once.sh").resolve())


class HookOnceTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.tmp = Path(directory.name)
        self.repo = self.tmp / "repo"
        self.count = self.tmp / "count"
        self.counter = self.tmp / "counter.sh"
        # Appends one line per invocation and exits with the given status.
        self.counter.write_text('echo run >>"$1"\nexit "$2"\n')
        self.env = {
            **os.environ,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "test",
            "GIT_AUTHOR_EMAIL": "test@example.invalid",
            "GIT_COMMITTER_NAME": "test",
            "GIT_COMMITTER_EMAIL": "test@example.invalid",
        }
        self.env.pop("HOOK_ONCE_DISABLE", None)
        self.repo.mkdir()
        self.git("init", "-q")
        (self.repo / "lib.rs").write_text("fn main() {}\n")
        self.commit("first")
        self.cache = self.repo / ".git" / "hook-pass-cache"

    def git(self, *args, cwd=None):
        subprocess.run(["git", *args], cwd=cwd or self.repo, env=self.env, check=True)

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)

    def hook(self, name="clippy", status=0, cwd=None, **env):
        result = subprocess.run(
            ["bash", SCRIPT, name, "--", "bash", str(self.counter), str(self.count), str(status)],
            cwd=cwd or self.repo, env={**self.env, **env},
            capture_output=True, text=True, timeout=60,
        )
        return result

    def runs(self):
        return len(self.count.read_text().splitlines()) if self.count.exists() else 0

    def stamps(self):
        return sorted(p.name for p in self.cache.iterdir()) if self.cache.exists() else []

    def test_records_a_pass_and_skips_the_same_tree(self):
        first = self.hook()
        self.assertEqual(first.returncode, 0, first.stdout)
        self.assertEqual(self.runs(), 1)
        self.assertEqual(len(self.stamps()), 1)
        second = self.hook()
        self.assertEqual(second.returncode, 0)
        self.assertEqual(self.runs(), 1)
        tree = subprocess.run(
            ["git", "rev-parse", "HEAD^{tree}"], cwd=self.repo, env=self.env,
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        self.assertIn(f"clippy already passed for tree {tree[:12]}; skipping", second.stdout)

    def test_failing_command_records_nothing(self):
        failed = self.hook(status=7)
        self.assertEqual(failed.returncode, 7)
        self.assertIn("clippy failed (exit 7)", failed.stdout)
        self.assertEqual(self.stamps(), [])
        self.assertEqual(self.hook(status=7).returncode, 7)
        self.assertEqual(self.runs(), 2)
        self.assertEqual(self.stamps(), [])

    def test_new_tree_runs_again(self):
        self.hook()
        (self.repo / "lib.rs").write_text("fn main() { let _ = 1; }\n")
        self.commit("second")
        self.hook()
        self.assertEqual(self.runs(), 2)
        self.assertEqual(len(self.stamps()), 2)

    def test_dirty_working_tree_runs_and_records_nothing(self):
        dirty_states = {
            "modified": lambda: (self.repo / "lib.rs").write_text("broken\n"),
            "staged": lambda: self.git("add", "lib.rs"),
            "untracked": lambda: (
                self.git("reset", "-q", "--hard"),
                (self.repo / "extra.rs").write_text("broken\n"),
            ),
        }
        for runs, (state, make_dirty) in enumerate(dirty_states.items(), start=1):
            with self.subTest(state=state):
                make_dirty()
                result = self.hook()
                self.assertEqual(result.returncode, 0)
                self.assertIn("without the pass cache", result.stdout)
                self.assertEqual(self.runs(), runs)
                self.assertEqual(self.stamps(), [])

    def test_check_name_and_command_are_part_of_the_key(self):
        self.hook(name="clippy")
        self.hook(name="doc")
        self.assertEqual(self.runs(), 2)
        other_command = subprocess.run(
            ["bash", SCRIPT, "clippy", "--", "bash", str(self.counter), str(self.count), "0", "x"],
            cwd=self.repo, env=self.env, capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(other_command.returncode, 0)
        self.assertEqual(self.runs(), 3)
        self.assertEqual(len(self.stamps()), 3)

    def test_disable_forces_a_run_and_keeps_recording(self):
        self.hook()
        forced = self.hook(HOOK_ONCE_DISABLE="1")
        self.assertEqual(forced.returncode, 0)
        self.assertIn("recorded", forced.stdout)
        self.assertEqual(self.runs(), 2)
        self.assertEqual(len(self.stamps()), 1)
        self.hook()
        self.assertEqual(self.runs(), 2)

    def test_stamps_are_shared_by_worktrees_of_the_clone(self):
        self.hook()
        other = self.tmp / "other"
        self.git("worktree", "add", "-q", "--detach", str(other))
        self.assertFalse((other / "hook-pass-cache").exists())
        skipped = self.hook(cwd=other)
        self.assertIn("skipping", skipped.stdout)
        self.assertEqual(self.runs(), 1)

    def test_stamps_older_than_fourteen_days_are_pruned(self):
        self.hook()
        (stamp,) = self.stamps()
        old = time.time() - 15 * 86400
        os.utime(self.cache / stamp, (old, old))
        self.hook()
        self.assertEqual(self.runs(), 2)
        self.assertEqual(self.stamps(), [stamp])

    def test_usage_error(self):
        result = subprocess.run(
            ["bash", SCRIPT, "clippy", "true"], cwd=self.repo, env=self.env,
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
