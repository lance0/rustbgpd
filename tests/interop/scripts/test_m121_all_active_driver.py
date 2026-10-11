#!/usr/bin/env python3
"""Bounded host/controller command-channel failure controls; no live containers."""
import contextlib
import io
import json
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import Mock, patch

import m121_all_active_frr as driver


class OperatorAuthTests(unittest.TestCase):
    def test_rendered_cells_keep_authenticated_operator_access(self):
        template = (Path(__file__).resolve().parents[1] / 'configs/rustbgpd-m121-pe.toml').read_text()
        for cell in driver.CELLS:
            with self.subTest(cell=cell):
                config = tomllib.loads(driver.render_config(template, cell))
                listener = config['global']['telemetry']['grpc_tcp']
                self.assertEqual(listener['token_file'], '/run/rustbgpd/grpc-test-only-operator.token')
                self.assertEqual(listener['principal'], 'rustbgpd://operator/test-only')
                security = config['security']['grpc']
                self.assertEqual(security['enforcement'], 'tier')
                self.assertEqual(security['roles'][listener['principal']], 'operator')

    def test_controller_mounts_and_uses_the_shared_read_only_token(self):
        source = (Path(__file__).resolve().parents[1] / 'm121-evpn-all-active-frr.clab.yml').read_text()
        controller = re.search(r'(?ms)^    controller:\n(.*?)(?=^    \S|\Z)', source)
        self.assertIsNotNone(controller)
        lines = controller.group(1).splitlines()
        token = '/run/rustbgpd/grpc-test-only-operator.token'
        self.assertIn(f'        - ../fixtures/grpc-test-only-operator.token:{token}:ro', lines)
        self.assertIn(f'        RUSTBGPD_TOKEN_FILE: {token}', lines)


class HistoricalComparisonTests(unittest.TestCase):
    def test_explicit_option_only(self):
        self.assertFalse(driver.historical_comparison_enabled('0'))
        self.assertTrue(driver.historical_comparison_enabled('1'))
        for value in ['', 'true', 'false', '2', True, 1]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                driver.historical_comparison_enabled(value)

    def test_strict_original_mapping_and_reordered_seed_lists(self):
        driver.verify_historical_flows(driver.BASELINE_A, driver.BASELINE_B, True)
        driver.verify_historical_flows(driver.BASELINE_A[::-1], driver.BASELINE_B[::-1], True)

    def test_same_counts_with_different_mapping_fail_only_strict_comparison(self):
        a, b = driver.BASELINE_A.copy(), driver.BASELINE_B.copy()
        a[0], b[0] = b[0], a[0]
        driver.verify_historical_flows(a, b, False)
        with self.assertRaisesRegex(AssertionError, 'immutable baseline'):
            driver.verify_historical_flows(a, b, True)


class CommandBridgeTests(unittest.TestCase):
    def request(self):
        return dict(node='a', args=['vtysh', '-c', 'show version'], timeout=30)

    def test_reject_unknown_node_verb_and_injected_show(self):
        for key, value in [('node', 'unrelated-container'), ('args', ['sh', '-c', 'true']),
                           ('args', ['vtysh', '-c', 'show version\nconfigure terminal']),
                           ('timeout', 0), ('timeout', 61), ('timeout', True)]:
            request = self.request()
            request[key] = value
            with self.subTest(key=key, value=value), patch.object(driver.subprocess, 'run') as run:
                with self.assertRaises(AssertionError):
                    driver.execute_frr_request(request)
                run.assert_not_called()

    def test_nonzero_exit_and_output_propagate(self):
        result = subprocess.CompletedProcess([], 7, 'partial output\n', 'failure\n')
        with patch.object(driver.subprocess, 'run', return_value=result) as run:
            response = driver.execute_frr_request(self.request())
        self.assertEqual(response, dict(exit=7, stdout='partial output\n', stderr='failure\n'))
        self.assertEqual(run.call_args.args[0][:3], ['docker', 'exec', 'clab-m121-evpn-all-active-frr-a'])

    def test_subprocess_timeout_is_explicit_failure(self):
        with patch.object(driver.subprocess, 'run', side_effect=subprocess.TimeoutExpired('docker', 30)):
            self.assertEqual(driver.execute_frr_request(self.request())['exit'], 124)

    def test_unexpected_channel_eof_fails(self):
        with patch.object(driver.sys, 'stdin', io.StringIO('')), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, 'channel closed'):
                driver.frr_run('a', 'vtysh', '-c', 'show version')

    def test_controller_rejects_host_nonzero_and_retains_evidence(self):
        response = dict(exit=7, stdout='partial output', stderr='failure')
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(driver, 'OUT', Path(directory)), \
                 patch.object(driver.sys, 'stdin', io.StringIO(json.dumps(response) + '\n')), \
                 contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError, 'failure'):
                    driver.frr_run('a', 'vtysh', '-c', 'show version')
            log = json.loads(Path(directory, 'commands.jsonl').read_text())
            self.assertEqual(log['exit'], 7)


class HostLoopTests(unittest.TestCase):
    def process(self, rows, exit_code):
        process = Mock()
        process.stdout = iter(rows)
        process.returncode = None
        process.poll.side_effect = lambda: process.returncode
        def waited(**_kw):
            process.returncode = exit_code
            return exit_code
        process.wait.side_effect = waited
        return process

    def test_invalid_request_closes_channel_terminates_driver_and_stops_frr(self):
        process = self.process([json.dumps(dict(node='other', args=['vtysh', '-c', 'show version'], timeout=30))], 143)
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(driver.os.environ, FRR_PIDS='{"a":10,"r":11}', M121_HOST_OUT=directory), \
             patch.object(driver.subprocess, 'Popen', return_value=process), \
             patch.object(driver.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')) as run:
            with self.assertRaises(AssertionError):
                driver.host_run()
            self.assertEqual(json.loads(Path(directory, 'controller-exit.json').read_text())['exit'], 143)
        process.stdin.close.assert_called_once()
        process.wait.assert_called_once()
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(commands[0][:4], ['docker', 'exec', 'clab-m121-evpn-all-active-frr-controller', 'python3'])
        self.assertEqual([command[2] for command in commands[1:]],
                         ['clab-m121-evpn-all-active-frr-a', 'clab-m121-evpn-all-active-frr-r'])
        self.assertTrue(all(command[-1] == 'stop' for command in commands[1:]))

    def test_frr_error_reaches_controller_and_failed_exit_is_reaped(self):
        request = dict(node='a', args=['vtysh', '-c', 'show version'], timeout=30)
        process = self.process([json.dumps(request)], 7)
        responses = [subprocess.CompletedProcess([], 7, '', 'FRR failed'),
                     subprocess.CompletedProcess([], 0, '', ''), subprocess.CompletedProcess([], 0, '', '')]
        with patch.dict(driver.os.environ, FRR_PIDS='{"a":10,"r":11}', M121_HOST_OUT=''), \
             patch.object(driver.subprocess, 'Popen', return_value=process), \
             patch.object(driver.subprocess, 'run', side_effect=responses) as run:
            with self.assertRaises(SystemExit) as failure:
                driver.host_run()
        self.assertEqual(failure.exception.code, 7)
        self.assertEqual(json.loads(process.stdin.write.call_args.args[0])['exit'], 7)
        process.stdin.close.assert_called_once()
        process.wait.assert_called_once()
        self.assertEqual([call.args[0][-1] for call in run.call_args_list[-2:]], ['stop', 'stop'])

    def test_unexpected_controller_eof_is_not_success(self):
        process = self.process([], 9)
        with patch.dict(driver.os.environ, FRR_PIDS='{"a":10,"r":11}', M121_HOST_OUT=''), \
             patch.object(driver.subprocess, 'Popen', return_value=process), \
             patch.object(driver.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')) as run:
            with self.assertRaises(SystemExit) as failure:
                driver.host_run()
        self.assertEqual(failure.exception.code, 9)
        process.stdin.close.assert_called_once()
        process.wait.assert_called_once()
        self.assertEqual([call.args[0][-1] for call in run.call_args_list], ['stop', 'stop'])


if __name__ == '__main__':
    unittest.main()
