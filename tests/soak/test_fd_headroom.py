#!/usr/bin/env python3
"""Contracts for the bare-host soak file-descriptor headroom guard.

The defect this guards: a 1000-peer flagship daemon launched from a stock
login shell inherits its 1024 soft `RLIMIT_NOFILE`, exhausts it on peer
sockets, and every later `accept()` on the metrics listener fails with
EMFILE. Nothing client-side notices — the scrapes that are served still
return 200 — so the whole gate battery reports green on a crippled run.
"""

import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).parent
HELPER = HERE / "fd-headroom.sh"
RUNNERS = ("run-soak-rs-flagship.sh", "run-soak-rr-flagship.sh")


def run_guard(script, *, hard_limit=None, env_target=None):
    """Run `script` in a bash shell, optionally under a lowered hard limit."""
    # `ulimit -n` sets soft and hard together; lowering the hard limit alone
    # is rejected while the soft limit still sits above it.
    prologue = f"ulimit -n {hard_limit}; " if hard_limit is not None else ""
    target = f"SOAK_NOFILE_SOFT={env_target}; export SOAK_NOFILE_SOFT; " if env_target else ""
    return subprocess.run(
        ["bash", "-c", f'{prologue}{target}source "$1"; {script}',
         "fd-headroom-test", str(HELPER)],
        text=True, capture_output=True, check=False,
    )


class FdHeadroomContracts(unittest.TestCase):
    def test_guard_raises_the_soft_limit_the_shipped_units_pin(self):
        result = run_guard('require_fd_headroom; ulimit -n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip().splitlines()[-1], "65536")

    def test_raised_limit_is_inherited_by_the_forked_daemon(self):
        # `ulimit` applies to the calling process, so the guard must never be
        # called from a subshell: the daemon inherits the runner's own limit.
        result = run_guard('require_fd_headroom >/dev/null; bash -c "ulimit -n"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "65536")

    def test_guard_fails_closed_when_the_hard_limit_is_too_low(self):
        result = run_guard('require_fd_headroom', hard_limit=512)
        self.assertEqual(result.returncode, 2)
        self.assertIn("file-descriptor headroom too low", result.stderr)
        self.assertIn("512", result.stderr)
        self.assertIn("refusing to soak", result.stderr)

    def test_guard_fails_closed_one_descriptor_below_the_target(self):
        result = run_guard('require_fd_headroom', hard_limit=65535)
        self.assertEqual(result.returncode, 2)
        result = run_guard('require_fd_headroom', hard_limit=65536)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_guard_rejects_a_nonsense_target(self):
        for target in ("0", "-1", "abc", "65536x", "1 2"):
            with self.subTest(target=target):
                result = run_guard('require_fd_headroom', env_target=f"'{target}'")
                self.assertEqual(result.returncode, 2)

    def test_run_json_scalar_is_null_until_the_guard_measures_one(self):
        result = run_guard('printf %s "$RUSTBGPD_NOFILE_SOFT_JSON"')
        self.assertEqual(result.stdout, "null")
        result = run_guard(
            'require_fd_headroom >/dev/null; printf %s "$RUSTBGPD_NOFILE_SOFT_JSON"'
        )
        self.assertEqual(result.stdout, "65536")

    def test_both_bare_host_runners_guard_before_launching_a_daemon(self):
        for name in RUNNERS:
            with self.subTest(runner=name):
                runner = (HERE / name).read_text()
                self.assertIn('source "$SOAK_SCRIPT_DIR/fd-headroom.sh"', runner)
                main = runner.split("main() {", 1)[1]
                guard = main.index("require_fd_headroom")
                self.assertLess(guard, main.index('"$DAEMON" --check'))
                self.assertLess(guard, main.index("write_run_json"))
                self.assertIn(
                    '"nofile_soft": %s,\\n\' "$RUSTBGPD_NOFILE_SOFT_JSON"', runner
                )


if __name__ == "__main__":
    sys.exit(not unittest.main(exit=False).result.wasSuccessful())
