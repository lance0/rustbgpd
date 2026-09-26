#!/usr/bin/env python3
"""Exercise the shared interop traps in Bash without a running lab."""

from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[3]
LIBRARY = ROOT / "tests/interop/scripts/test-lib.sh"
OVERRIDES = {
    "test-m43-tcp-ao-bird.sh": "_m43_cleanup_on_exit",
    "test-m96-ixp-manager-activation-frr.sh": "cleanup",
    "test-m97-ixp-manager-authenticated-lifecycle.sh": "cleanup",
    "test-m99-rfc9072-extended-open.sh": "m99_on_exit",
    "test-m100-partial-receiver.sh": "m100_on_exit",
    "test-m101-routeserver-bird332.sh": "m101_on_exit",
    "test-m102-routeserver-openbgpd92.sh": "on_exit",
    "test-m105-live-as-set.sh": "m105_on_exit",
}
SETUP = r'''
exec 3>&2
TOPO=m1-frr
SCRIPT_DIR=$(dirname "$1")
CLEANUP=$2
docker() { return 0; }
grpcurl() { return 0; }
jq() { return 0; }
containerlab() {
    echo CLEANUP >&3
    return 41
}
source "$1"
'''


class InteropSignalCleanupTests(unittest.TestCase):
    def run_shell(self, ending, cleanup):
        return subprocess.run(
            ["bash", "-c", SETUP + ending, "test", str(LIBRARY), str(cleanup)],
            cwd=ROOT, capture_output=True, text=True, timeout=10, check=False,
        )

    def test_signals_terminate_once_with_cleanup_opt_in(self):
        for cleanup in (0, 1):
            for signal, status in (("INT", 130), ("TERM", 143), ("HUP", 129)):
                with self.subTest(cleanup=cleanup, signal=signal):
                    result = self.run_shell(
                        f"kill -{signal} $$\necho AFTER_SIGNAL\nexit 0\n", cleanup
                    )
                    self.assertEqual(result.returncode, status)
                    self.assertNotIn("AFTER_SIGNAL", result.stdout)
                    self.assertEqual(result.stderr.count("CLEANUP"), cleanup)

    def test_normal_status_survives_failed_cleanup(self):
        for cleanup in (0, 1):
            for status in (0, 37):
                with self.subTest(cleanup=cleanup, status=status):
                    result = self.run_shell(f"exit {status}\n", cleanup)
                    self.assertEqual(result.returncode, status)
                    self.assertEqual(result.stderr.count("CLEANUP"), cleanup)

    def test_exit_only_override_retains_signal_status(self):
        result = self.run_shell(
            "trap 'echo LOCAL_CLEANUP >&2; _cleanup_on_exit' EXIT\n"
            "kill -TERM $$\necho AFTER_SIGNAL\n", 1
        )
        self.assertEqual(result.returncode, 143)
        self.assertNotIn("AFTER_SIGNAL", result.stdout)
        self.assertEqual(result.stderr.splitlines(), ["LOCAL_CLEANUP", "CLEANUP"])

    def test_lab_registrations_preserve_shared_signal_exits(self):
        for driver, handler in OVERRIDES.items():
            registration = next(
                line for line in (LIBRARY.parent / driver).read_text().splitlines()
                if line.startswith(f"trap {handler} EXIT")
            )
            # Exercise each driver's actual registration while replacing its
            # lab-specific cleanup effects with a marker and shared cleanup.
            setup = f'{handler}() {{ echo LOCAL_CLEANUP >&2; _cleanup_on_exit; }}\n'
            for signal, status in (("INT", 130), ("TERM", 143), ("HUP", 129)):
                with self.subTest(driver=driver, signal=signal):
                    result = self.run_shell(
                        setup + registration + f"\nkill -{signal} $$\necho AFTER_SIGNAL\n", 1
                    )
                    self.assertEqual(result.returncode, status)
                    self.assertNotIn("AFTER_SIGNAL", result.stdout)
                    self.assertEqual(result.stderr.splitlines(), ["LOCAL_CLEANUP", "CLEANUP"])


if __name__ == "__main__":
    unittest.main()
