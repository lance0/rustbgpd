#!/usr/bin/env python3
"""Offline driver controls for command failures, carrier timing and provenance."""
import ast
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


class CarrierRecoveryTests(unittest.TestCase):
    def recover(self, carrier_hold, full_readiness=6.25, response_duration=0.0):
        clock = [0.0]
        def sleep(seconds):
            clock[0] += seconds
        def wait(predicate, description):
            if description == 'actual Rust attachment-circuit carrier return':
                clock[0] += 10
            elif description == 'recovered EAD-per-EVI, preference roles and actual two-member NHG':
                clock[0] = max(clock[0], 10 + full_readiness)
            self.assertTrue(predicate())
        def ctl(*args):
            if clock[0] >= 10:
                clock[0] += response_duration
            return dict(segments=[dict(drained=clock[0] < 10 + carrier_hold)])
        def ns(node, *args):
            if node == 'ce' and args == ('ip', '-j', 'link', 'show', 'bond0'):
                return json.dumps([dict(address=driver.PEER_MAC)])
            return json.dumps([dict(flags=['LOWER_UP'])])
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(driver, 'OUT', Path(directory)))
            stack.enter_context(patch.object(driver.time, 'monotonic', side_effect=lambda: clock[0]))
            stack.enter_context(patch.object(driver.time, 'sleep', side_effect=sleep))
            stack.enter_context(patch.object(driver, 'wait', side_effect=wait))
            stack.enter_context(patch.object(driver, 'ns', side_effect=ns))
            stack.enter_context(patch.object(driver, 'ctl', side_effect=ctl))
            stack.enter_context(patch.object(driver, 'frr', return_value='{}'))
            for name in ('ready', 'nhg', 'peer_only_ready'):
                stack.enter_context(patch.object(driver, name, return_value=True))
            for name in ('learn', 'snapshot', 'capture'):
                stack.enter_context(patch.object(driver, name))
            for name in ('verify_frr_es_routes', 'verify_frr_peer_originated'):
                stack.enter_context(patch(f'm121_all_active_oracle.{name}'))
            stack.enter_context(patch('m121_all_active_oracle.verify_discovery', return_value=dict(a=[10], b=[11])))
            stack.enter_context(patch('evpn_frr_peer_sync.verify_delivery'))
            try:
                return driver.carrier_cycle(100, [11])
            finally:
                self.hold_samples = json.loads(Path(directory, 'carrier-recovery-hold.json').read_text())

    def test_delayed_carrier_return_cannot_count_toward_recovery_hold(self):
        with self.assertRaisesRegex(AssertionError, 'recovery delay'):
            self.recover(3.5, full_readiness=5.25)
        self.assertEqual(self.hold_samples[-1]['carrier_observation_elapsed_seconds'], 3.5)
        self.assertFalse(self.hold_samples[-1]['state']['segments'][0]['drained'])

    def test_recovery_receipt_measures_from_observed_carrier_return(self):
        self.assertEqual(self.recover(5)['carrier_observation_elapsed_seconds'], 6.25)

    def test_rpc_completed_after_hold_boundary_does_not_require_drained(self):
        self.assertEqual(self.recover(5, response_duration=.125)['carrier_observation_elapsed_seconds'], 6.25)
        self.assertGreaterEqual(self.hold_samples[-1]['carrier_observation_elapsed_seconds'], 5)
        self.assertFalse(self.hold_samples[-1]['state']['segments'][0]['drained'])

    def test_rpc_spanning_entire_hold_does_not_prove_deep_drained_sample(self):
        with self.assertRaisesRegex(AssertionError, 'no deep recovery-hold sample'):
            self.recover(5, response_duration=5.1)


class HostMetadataTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / 'repo'
        self.out = Path(self.directory.name)
        repository = Path(__file__).resolve().parents[3]
        subprocess.run(['git', 'clone', '--quiet', '--shared', '--no-checkout', str(repository), str(self.root)],
                       check=True, capture_output=True)
        # Reuse existing commits; this fixture never creates a commit or runs hooks.
        self.git('sparse-checkout', 'set', '--no-cone', *('/' + name for name in driver.HARNESS_INPUTS), '/Cargo.toml')
        self.git('checkout', '--quiet', 'HEAD')

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args], text=True)

    def metadata(self):
        check_output = subprocess.check_output
        def command(args, **kwargs):
            if args[:2] == ['docker', 'inspect']:
                return json.dumps([dict(Config=dict(Image='fixture:tag'), Image='sha256:fixture')]).encode()
            return check_output(args, **kwargs)
        with patch.object(driver.subprocess, 'check_output', side_effect=command):
            driver.record_host_metadata(self.root, self.out, 'm121-fixture')
        return json.loads((self.out / 'host-metadata.json').read_text())

    def test_every_harness_input_mutation_changes_its_hash_and_dirty_evidence(self):
        baseline = self.metadata()
        self.assertEqual(baseline['harness_status'], '')
        for name in driver.HARNESS_INPUTS:
            with self.subTest(path=name):
                path = self.root / name
                original = path.read_bytes()
                path.write_bytes(original + b'\n# provenance mutation\n')
                changed = self.metadata()
                self.assertNotEqual(changed['harness_sha256'][name], baseline['harness_sha256'][name])
                self.assertIn(name, changed['harness_diff'])
                self.assertIn(name, changed['harness_status'])
                self.assertEqual([key for key in baseline['harness_sha256']
                                  if changed['harness_sha256'][key] != baseline['harness_sha256'][key]], [name])
                path.write_bytes(original)

    def test_runtime_staged_harness_and_untracked_inputs_are_recorded(self):
        for name in ('src/m121-untracked.rs', 'tests/interop/scripts/m121-untracked.py'):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('untracked input\n')
        with (self.root / 'Cargo.toml').open('a') as file:
            file.write('\n# modified runtime input\n')
        name = 'tests/interop/configs/rustbgpd-m121-pe.toml'
        with (self.root / name).open('a') as file:
            file.write('\n# staged harness input\n')
        self.git('add', name)
        metadata = self.metadata()
        self.assertIn('?? src/m121-untracked.rs', metadata['runtime_status'])
        self.assertIn('?? tests/interop/scripts/m121-untracked.py', metadata['harness_status'])
        self.assertIn('Cargo.toml', metadata['runtime_diff'])
        self.assertIn(name, metadata['harness_diff'])
        self.assertIn('M  ' + name, metadata['harness_status'])

    def test_manifest_covers_transitive_local_python_imports(self):
        scripts = Path(__file__).resolve().parent
        pending = [scripts / 'm121_all_active_frr.py']
        visited = set()
        while pending:
            path = pending.pop()
            if path in visited:
                continue
            visited.add(path)
            self.assertIn('tests/interop/scripts/' + path.name, driver.HARNESS_INPUTS)
            for node in ast.walk(ast.parse(path.read_text())):
                names = ([node.module] if isinstance(node, ast.ImportFrom)
                         else [alias.name for alias in node.names] if isinstance(node, ast.Import) else [])
                for name in names:
                    candidate = scripts / (name + '.py')
                    if candidate.is_file():
                        pending.append(candidate)


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
