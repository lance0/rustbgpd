#!/usr/bin/env python3
"""Check M38's shared verdict and metric readers without a live lab."""

from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


DRIVER = Path(__file__).with_name("test-m38-evpn-df-election.sh")
SOURCE = DRIVER.read_text()
HELPERS, TESTS = SOURCE.split("# Wait for the segment orchestrator", 1)
READINESS = TESTS.split('echo "Waiting up to 60s for initial DF election', 1)[0]
ROOT = DRIVER.resolve().parents[3]


class M38LedgerTests(unittest.TestCase):
    def run_script(self, body):
        script = r'''
docker() { [ "${1:-}" = inspect ]; }
grpcurl() { :; }
sleep() { :; }
CLEANUP=0
'''
        return subprocess.run(
            ["bash", "-c", script + HELPERS + body, str(DRIVER.resolve())],
            cwd=ROOT, text=True, capture_output=True, timeout=10, check=False,
        )

    def test_failed_candidate_wait_counts_toward_shared_verdict(self):
        result = self.run_script(r'''
grpc_list_evpn() {
    if [ "$1" = "$PE1" ]; then
        echo '{"routes":[]}'
    else
        echo '{"routes":[{},{}]}'
    fi
}
''' + "# Wait for the segment orchestrator" + READINESS + "print_summary\n")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("PE1 LocRib has both Type 4 ES candidates", result.stdout)
        self.assertIn("PE2 LocRib has both Type 4 ES candidates", result.stdout)
        self.assertIn("Results: 1 passed, 1 failed", result.stdout)

    def test_metric_readers_drain_large_scrapes_and_keep_exact_first_match(self):
        esi = "00:00:00:00:00:00:00:00:00:01"
        for helper, metric, extra, arguments in (
            ("prom_df_role", "evpn_df_role", ',role="df"', '"$PE1" df'),
            ("prom_df_role_changes", "evpn_df_role_changes_total", "", '"$PE2"'),
        ):
            with self.subTest(helper=helper), tempfile.TemporaryDirectory() as directory:
                data = Path(directory) / "metrics"
                drained = Path(directory) / "drained"
                data.write_text(
                    f'{metric}{{esi="{esi}",vni="1000"{extra}}} 9\n'
                    f'{metric}{{esi="{esi}",vni="100"{extra}}} 1\n'
                    f'{metric}{{esi="{esi}",vni="100"{extra}}} 2\n'
                    + "unrelated_metric 0\n" * 100_000
                )
                result = self.run_script(
                    f"prom_scrape() {{ cat {shlex.quote(str(data))} "
                    f"&& touch {shlex.quote(str(drained))}; }}\n"
                    f"{helper} {arguments}\n"
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(result.stdout, "1\n")
                self.assertTrue(drained.exists(), "metric reader closed the producer early")


if __name__ == "__main__":
    unittest.main()
