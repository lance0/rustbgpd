#!/usr/bin/env python3
"""Offline controls for the M121 kernel FDB nexthop probe verdicts."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import m121_fdb_nhg_probe as probe

# The extack text a rejecting kernel returns, as iproute2 prints it.
REJECTED = 'Error: A nexthop fdb cannot be dynamic.\n'


def fake_kernel(dynamic_error=None, static_error=None, setup_error=None, static_raise=None):
    """Return a runner that installs rows unless told to fail, and its call log."""
    calls, rows = [], []

    def runner(argv):
        calls.append(argv)
        if setup_error and setup_error in argv:
            return 2, '', 'Error: Unknown device type.\n'
        if 'fdb' in argv and 'replace' in argv:
            mac, state = argv[argv.index('replace') + 1], argv[-3]
            if state == 'permanent' and static_raise:
                raise static_raise
            error = dynamic_error if state == 'dynamic' else static_error
            if error:
                return 255, '', error
            rows.append(dict(mac=mac, nhid=int(argv[-1]), flags=['self', 'extern_learn']))
        if argv[-3:] == ['show', 'dev', 'vx100']:
            return 0, json.dumps(rows), ''
        return 0, '', ''
    return runner, calls


def reported(record):
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(GITHUB_OUTPUT=str(Path(tmp, 'out')), GITHUB_STEP_SUMMARY=str(Path(tmp, 'summary')))
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = probe.report(record, env)
        return code, Path(env['GITHUB_OUTPUT']).read_text(), Path(env['GITHUB_STEP_SUMMARY']).read_text(), stderr.getvalue()


class ProbeVerdictTests(unittest.TestCase):
    def test_installed_dynamic_row_is_supported_and_runs_the_lab(self):
        runner, calls = fake_kernel()
        record = probe.probe(runner, ns='t')
        self.assertEqual(record['verdict'], 'supported')
        self.assertEqual(record['rustbgpd_static']['result'], 'supported')
        code, output, summary, stderr = reported(record)
        self.assertEqual((code, output), (0, 'verdict=supported\n'))
        self.assertNotIn('skipped', summary + stderr)
        self.assertEqual(calls[-1], ['ip', 'netns', 'del', 't'])

    def test_known_rejection_skips_with_a_warning_and_summary_line(self):
        runner, calls = fake_kernel(dynamic_error=REJECTED)
        record = probe.probe(runner, ns='t')
        self.assertEqual(record['verdict'], 'rejected')
        self.assertEqual(record['frr_dynamic']['stderr'], REJECTED.strip())
        code, output, summary, stderr = reported(record)
        self.assertEqual((code, output), (0, 'verdict=rejected\n'))
        self.assertIn(f'::warning title=M121 skipped::kernel {record["kernel"]} rejects VXLAN FDB '
                      'nexthop entries (known kernel defect; upstream fix 7308ef8b4a67)', stderr)
        self.assertIn('M121 skipped', summary)
        self.assertEqual(calls[-1], ['ip', 'netns', 'del', 't'])

    def test_static_form_is_report_only(self):
        runner, _ = fake_kernel(static_error=REJECTED)
        record = probe.probe(runner, ns='t')
        self.assertEqual(record['verdict'], 'supported')
        self.assertEqual(record['rustbgpd_static']['result'], 'rejected')
        runner, _ = fake_kernel(dynamic_error=REJECTED, static_error='Error: Invalid argument.\n')
        self.assertEqual(probe.probe(runner, ns='t')['verdict'], 'rejected')

    def test_static_form_failure_never_changes_the_verdict(self):
        # A static-form timeout, failed show or bad JSON must stay inside
        # rustbgpd_static; the FRR verdict alone decides skip or run.
        failures = [subprocess.TimeoutExpired(['bridge'], 30), RuntimeError('bridge fdb show failed'),
                    json.JSONDecodeError('Expecting value', '', 0)]
        for dynamic_error, verdict in ((REJECTED, 'rejected'), (None, 'supported')):
            for failure in failures:
                with self.subTest(verdict=verdict, failure=type(failure).__name__):
                    runner, calls = fake_kernel(dynamic_error=dynamic_error, static_raise=failure)
                    record = probe.probe(runner, ns='t')
                    self.assertEqual(record['verdict'], verdict)
                    self.assertEqual(record['rustbgpd_static']['result'], 'error')
                    self.assertIn(str(failure), record['rustbgpd_static']['error'])
                    self.assertEqual(reported(record)[:2], (0, f'verdict={verdict}\n'))
                    self.assertEqual(calls[-1], ['ip', 'netns', 'del', 't'])

    def test_other_failures_fail_the_job_instead_of_skipping(self):
        # An unrelated refusal, an exit 0 without the row, and a broken setup
        # must not become a silent skip.
        cases = [fake_kernel(dynamic_error='Error: Nexthop id does not exist.\n')[0]]
        silent, _ = fake_kernel()
        cases.append(lambda argv: (0, '[]', '') if argv[-3:] == ['show', 'dev', 'vx100'] else silent(argv))
        broken, broken_calls = fake_kernel(setup_error='vxlan')
        cases.append(broken)
        for runner in cases:
            record = probe.probe(runner, ns='t')
            self.assertEqual(record['verdict'], 'error')
            code, output, _, stderr = reported(record)
            self.assertEqual((code, output), (1, 'verdict=error\n'))
            self.assertIn('::error title=M121 kernel probe::', stderr)
        self.assertEqual(broken_calls[-1], ['ip', 'netns', 'del', 't'])

    def test_forms_match_the_frr_and_rustbgpd_netlink_states(self):
        self.assertEqual(probe.fdb_command('t', 'm', 'dynamic')[-6:],
                         ['self', 'master', 'extern_learn', 'dynamic', 'nhid', probe.GROUP])
        self.assertEqual([state for _, state in probe.FORMS.values()], ['dynamic', 'permanent'])


if __name__ == '__main__':
    unittest.main()
