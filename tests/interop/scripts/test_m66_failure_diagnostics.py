#!/usr/bin/env python3
"""Exercise M66's real diagnostic functions and traps without a running lab."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
DRIVER = ROOT / "tests/interop/scripts/test-m66-evpn-es-drain-handover.sh"
SOURCE = DRIVER.read_text()
# Run the driver's initialization, shared helpers, and traps, stopping before
# the live phase. The wrong-group case also executes its actual assertion block.
SETUP = SOURCE.split("# Phase 1 — bring-up:", 1)[0]
WRONG_GROUP = SOURCE.split('member_id=$(nh_id_for_via "$PE1_IP")', 1)[1]
WRONG_GROUP = 'member_id=$(nh_id_for_via "$PE1_IP")' + WRONG_GROUP.split(
    '\nping_burst_ok "baseline', 1
)[0]

STUB = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

name = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["M66_COMMANDS"], "a") as log:
    log.write(json.dumps([name, *args]) + "\n")
if name == "containerlab":
    print("CLEANUP", file=sys.stderr)
    sys.exit(41)  # A cleanup failure must not replace the original status.
if name != "docker" or args[0] == "inspect":
    sys.exit(0)
node, command = args[1], args[2:]
if node.endswith("-pe1"):
    print("missing daemon: " + node, file=sys.stderr)
    sys.exit(19)
if command == ["ip", "nexthop", "show"]:
    print("id 369 via 10.0.2.2 fdb\nid 370 via 10.0.1.2 fdb\nid 827 group 369 fdb")
elif command == ["ip", "-j", "nexthop", "show"]:
    print('[{"id":369,"via":"10.0.2.2","fdb":true},'
          '{"id":827,"group":[{"id":369}],"fdb":true}]')
elif command == ["bridge", "-j", "fdb", "show"]:
    print('[{"mac":"02:00:00:00:00:01","dev":"vxlan100",'
          '"nhid":827,"flags":["self"],"state":"permanent"}]')
elif command[-3:] == ["evpn", "nexthops", "-j"]:
    print('{"groups":[{"group_id":827,"ref_macs":["ce-mac","other-mac"]}]}')
elif command[-2:] == ["evpn", "-j"]:
    print('[{"route_type":1},{"route_type":2,"mac":"ce-mac"},'
          '{"route_type":2,"mac":"other-mac"}]')
elif command == ["cat", "/var/log/rustbgpd.log"]:
    print("first daemon log line\nlast daemon log line")
else:
    print("[]")
'''


class M66FailureDiagnosticsTests(unittest.TestCase):
    def run_driver(self, ending):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for tool in ("docker", "grpcurl", "jq", "containerlab"):
                path = directory / tool
                path.write_text(STUB)
                path.chmod(0o755)
            commands = directory / "commands.jsonl"
            environment = {
                **os.environ,
                "PATH": f"{directory}:{os.environ['PATH']}",
                "M66_COMMANDS": str(commands),
                "CLEANUP": "1",
            }
            # bash -c's $0 locates the real shared library via SCRIPT_DIR.
            result = subprocess.run(
                ["bash", "-c", SETUP + ending, str(DRIVER)],
                cwd=ROOT, env=environment, capture_output=True, text=True,
                timeout=10, check=False,
            )
            calls = [json.loads(line) for line in commands.read_text().splitlines()]
            return result, calls

    def assert_full_dump(self, result, calls):
        for suffix in ("vtep", "pe1", "pe2"):
            node = f"clab-m66-evpn-es-drain-handover-{suffix}"
            self.assertEqual(result.stderr.count(f"{node} full EVPN RIB"), 1)
            self.assertIn(f"{node} owned nexthops and ref_macs", result.stderr)
            for command in (["bridge", "-j", "fdb", "show"],
                            ["ip", "-j", "nexthop", "show"],
                            ["cat", "/var/log/rustbgpd.log"]):
                self.assertIn(["docker", "exec", node, *command], calls)
        self.assertIn('"ref_macs":["ce-mac","other-mac"]', result.stderr)
        self.assertIn('"route_type":1', result.stderr)
        self.assertIn('"route_type":2,"mac":"other-mac"', result.stderr)
        self.assertIn('[{"id":369,"via":"10.0.2.2","fdb":true},'
                      '{"id":827,"group":[{"id":369}],"fdb":true}]', result.stderr)
        self.assertIn('[{"mac":"02:00:00:00:00:01","dev":"vxlan100",'
                      '"nhid":827,"flags":["self"],"state":"permanent"}]',
                      result.stderr)
        self.assertIn("missing daemon:", result.stderr)
        self.assertIn("[cleanup] containerlab destroy", result.stdout)
        self.assertEqual(calls[-1][0], "containerlab")
        self.assertEqual(result.stderr.count("first daemon log line"), 2)
        self.assertEqual(result.stderr.count("last daemon log line"), 2)

    def test_nonzero_exit_survives_missing_daemon_and_failed_cleanup(self):
        result, calls = self.run_driver("unset GRPC_ADDR\nexit 37\n")
        self.assertEqual(result.returncode, 37)
        self.assert_full_dump(result, calls)

    def test_ledger_failure_dumps_without_changing_zero_exit(self):
        result, calls = self.run_driver('fail "already recorded"\nexit 0\n')
        self.assertEqual(result.returncode, 0)
        self.assert_full_dump(result, calls)

    def test_wrong_group_dumps_immediately_and_only_once(self):
        result, calls = self.run_driver(
            'group_id=827\n' + WRONG_GROUP + '\necho AFTER_MISMATCH >&2\nexit 37\n'
        )
        self.assertEqual(result.returncode, 37)
        self.assert_full_dump(result, calls)
        self.assertLess(result.stderr.index("last daemon log line"),
                        result.stderr.index("AFTER_MISMATCH"))

    def test_success_keeps_cleanup_without_dumping(self):
        result, calls = self.run_driver("exit 0\n")
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("M66 failure:", result.stderr)
        self.assertEqual(calls[-1][0], "containerlab")

    def test_signals_exit_after_one_dump_and_cleanup(self):
        for signal, status in (("INT", 130), ("TERM", 143), ("HUP", 129)):
            with self.subTest(signal=signal):
                result, calls = self.run_driver(
                    f"kill -{signal} $$\necho AFTER_SIGNAL\nexit 0\n"
                )
                self.assertEqual(result.returncode, status)
                self.assertNotIn("AFTER_SIGNAL", result.stdout)
                self.assert_full_dump(result, calls)
                self.assertEqual(sum(call[0] == "containerlab" for call in calls), 1)


if __name__ == "__main__":
    unittest.main()
