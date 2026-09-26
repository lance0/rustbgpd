#!/usr/bin/env python3
"""Exercise M67's actual mode selection and both fresh-topology assertions."""

import os
from pathlib import Path
import re
import subprocess
import unittest


SOURCE = Path(__file__).with_name("test-m67-evpn-link-drain-failover.sh").read_text()
MODE = re.search(r"^RERUN=.*?(?=\n\n)", SOURCE, re.MULTILINE | re.DOTALL).group()
ASSERTIONS = re.findall(r'^if \[ "\$RERUN" -eq 1 \]; then\n.*?^fi$', SOURCE,
                        re.MULTILINE | re.DOTALL)


class M67RerunModeTests(unittest.TestCase):
    def run_checks(self, *, rerun=None, ci="false", actions="false", routes=0, members="11"):
        self.assertEqual(len(ASSERTIONS), 2)
        env = {k: v for k, v in os.environ.items() if k not in ("M67_RERUN", "CI", "GITHUB_ACTIONS")}
        env.update(CI=ci, GITHUB_ACTIONS=actions)
        if rerun is not None:
            env["M67_RERUN"] = rerun
        script = r'''
set -eu
failures=0
PE1=pe1
PE1_IP=10.0.1.2
PE2_IP=10.0.2.2
CE_MAC=02:ce:ce:ce:ce:01
group_id=7
member_id=11
standby_id=12
log() { echo "INFO $*"; }
ok() { echo "PASS $*"; }
fail() { failures=$((failures + 1)); echo "FAIL $*"; }
rb_nh() { :; }
# A fresh startup drain may leave this series present at zero.
prom_scrape() { echo 'evpn_es_drained{esi="segment",reason="link"} 0'; }
'''
        script += MODE + f"\nt2_pe2={routes}\nmembers='{members}'\n"
        script += "\n".join(ASSERTIONS) + '\n[ "$failures" -eq 0 ]\n'
        return subprocess.run(["bash", "-c", script], env=env, text=True,
                              capture_output=True, timeout=5, check=False)

    def test_metric_present_cannot_skip_default_negative_observations(self):
        for rerun in (None, "0"):
            for routes, members in ((1, "11"), (0, "12")):
                with self.subTest(rerun=rerun, routes=routes, members=members):
                    result = self.run_checks(rerun=rerun, routes=routes, members=members)
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertIn("FAIL", result.stdout)
                    self.assertNotIn("pin skipped", result.stdout)

    def test_fresh_success_counts_both_assertions(self):
        result = self.run_checks(ci="true", actions="true")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("PASS "), 2)
        self.assertNotIn("pin skipped", result.stdout)

    def test_manual_reuse_requires_explicit_opt_in(self):
        result = self.run_checks(rerun="1", routes=1, members="12")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("pin skipped"), 2)

    def test_invalid_mode_and_hosted_opt_in_fail(self):
        for rerun, ci, actions in (("", "false", "false"), ("2", "false", "false"),
                                  ("true", "false", "false"), ("1", "true", "false"),
                                  ("1", "false", "true")):
            with self.subTest(rerun=rerun, ci=ci, actions=actions):
                result = self.run_checks(rerun=rerun, ci=ci, actions=actions)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertNotIn("PASS", result.stdout)
                self.assertNotIn("pin skipped", result.stdout)


if __name__ == "__main__":
    unittest.main()
