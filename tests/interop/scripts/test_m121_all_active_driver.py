#!/usr/bin/env python3
"""Offline driver controls for command failures, carrier timing and provenance."""
import ast
import contextlib
import io
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
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


class RustOriginTests(unittest.TestCase):
    def test_requires_and_retains_frr_sync_state_before_wire_proof(self):
        fixture = json.loads((Path(__file__).resolve().parents[2] /
                              'fixtures/m121-frr-synchronized-proxy.json').read_text())
        mac = fixture['mac']
        for inactive, active in ((True, True), (False, True), (True, False)):
            with self.subTest(inactive=inactive, active=active), tempfile.TemporaryDirectory() as directory:
                state = {mac: dict(type='local', intf='es0', esi=driver.ESI,
                                   localInactive=inactive, peerActive=active)}
                def frr(node, command, state=state):
                    if node == 'a':
                        self.assertEqual(command, f'show evpn mac vni 100 mac {mac} json')
                        return json.dumps(state)
                    return json.dumps(fixture['frr_routes'])
                with patch.object(driver, 'OUT', Path(directory)), \
                     patch.object(driver, 'learn'), patch.object(driver, 'ctl', return_value=fixture['rust_routes']), \
                     patch.object(driver, 'frr', side_effect=frr), patch.object(driver, 'nhg', return_value=True), \
                     patch.object(driver, 'wait', side_effect=lambda check, _: check()), \
                     patch.object(driver, 'snapshot'), patch.object(driver, 'stop_captures'), \
                     patch('m121_all_active_wire.verify_pcap', return_value={'type2': 1}) as wire:
                    if inactive and active:
                        bgp = ('rust-bgp', Mock(poll=Mock(return_value=None)), None)
                        driver.rust_origin(100, 100, bgp)
                        self.assertEqual(wire.call_count, 2)
                        self.assertGreater(wire.call_args_list[0].kwargs['timeout'], 0)
                        self.assertNotIn('timeout', wire.call_args_list[1].kwargs)
                    else:
                        with self.assertRaises(AssertionError):
                            driver.rust_origin(100, 100, None)
                        wire.assert_not_called()
                self.assertEqual(json.loads(Path(directory, 'rust-origin-frr-sync.json').read_text()), state)


class CaptureCompletionTests(unittest.TestCase):
    def test_tcpdump_requests_immediate_delivery(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(driver, 'OUT', Path(directory)), \
             patch.object(driver, 'CAPTURES', []), patch.object(driver.subprocess, 'Popen') as popen:
            item = driver.start_capture('bgp', 'b', 'any', ['tcp', 'port', '179'])
            try:
                self.assertIn('--immediate-mode', popen.call_args.args[0])
                self.assertIn('-U', popen.call_args.args[0])
            finally:
                item[2].close()

    def test_partial_oracle_and_tshark_reads_retry_before_success(self):
        clock = [0.0]
        process = Mock(poll=Mock(return_value=None))
        failures = [ValueError('missing proxy'),
                    subprocess.CalledProcessError(2, ['tshark'], stderr='partial record')]
        with patch.object(driver, 'OUT', Path('/receipt')), \
             patch.object(driver.time, 'monotonic', side_effect=lambda clock=clock: clock[0]), \
             patch.object(driver.time, 'sleep', side_effect=lambda seconds, clock=clock: clock.__setitem__(0, clock[0]+seconds)), \
             patch('m121_all_active_wire.verify_pcap', side_effect=[*failures, {'type2': 1}]) as verify:
            driver.wait_bgp_capture(('rust-bgp', process, None), 100, 100)
        self.assertEqual([c.kwargs['timeout'] for c in verify.call_args_list], [30, 29.75, 29.5])
        process.send_signal.assert_not_called()

    def test_permanent_missing_evidence_or_timeout_hits_total_deadline(self):
        for error in (ValueError('missing proxy'), subprocess.TimeoutExpired('tshark', 30)):
            clock = [0.0]
            def verify(*args, error=error, clock=clock, **kwargs):
                if isinstance(error, subprocess.TimeoutExpired):
                    clock[0] += kwargs['timeout']
                raise error
            with self.subTest(error=error), patch.object(driver, 'OUT', Path('/receipt')), \
                 patch.object(driver.time, 'monotonic', side_effect=lambda clock=clock: clock[0]), \
                 patch.object(driver.time, 'sleep', side_effect=lambda seconds, clock=clock: clock.__setitem__(0, clock[0]+seconds)), \
                 patch('m121_all_active_wire.verify_pcap', side_effect=verify):
                with self.assertRaisesRegex(AssertionError, 'timed out waiting for complete BGP capture'):
                    driver.wait_bgp_capture(('rust-bgp', Mock(poll=Mock(return_value=None)), None), 100, 100)
                self.assertEqual(clock[0], 30)

    def test_capture_exit_before_or_during_success_is_fatal(self):
        for statuses in ([0], [None, 0]):
            with self.subTest(statuses=statuses), patch.object(driver, 'OUT', Path('/receipt')), \
                 patch('m121_all_active_wire.verify_pcap', return_value={'type2': 1}):
                process = Mock(poll=Mock(side_effect=statuses))
                with self.assertRaisesRegex(RuntimeError, 'tcpdump rust-bgp exited'):
                    driver.wait_bgp_capture(('rust-bgp', process, None), 100, 100)


class DaemonStopTests(unittest.TestCase):
    def test_confirmed_stop_precedes_body_and_resume_survives_body_failure(self):
        process = Mock(pid=123, returncode=None)
        stopped = (signal.SIGSTOP << 8) | 0x7f
        events = []
        with patch.object(driver, 'DAEMON', process), \
             patch.object(driver.os, 'waitpid', return_value=(123, stopped)) as waitpid, \
             patch.object(driver, 'event', side_effect=lambda name, **_: events.append(name)):
            with self.assertRaisesRegex(ValueError, 'carrier failure'):
                with driver.pause_owned_daemon():
                    self.assertEqual(process.send_signal.call_args.args, (signal.SIGSTOP,))
                    self.assertEqual(events, ['daemon_stop_confirmed_for_carrier'])
                    raise ValueError('carrier failure')
        waitpid.assert_called_once_with(123, os.WUNTRACED | os.WNOHANG)
        self.assertEqual([c.args[0] for c in process.send_signal.call_args_list], [signal.SIGSTOP, signal.SIGCONT])
        self.assertEqual(events[-1], 'daemon_resume_requested_after_carrier')

    def test_failed_signal_or_exited_child_still_attempts_resume(self):
        for exited in (False, True):
            process = Mock(pid=123, returncode=None)
            if not exited:
                process.send_signal.side_effect = [RuntimeError('stop failed'), None]
            with self.subTest(exited=exited), patch.object(driver, 'DAEMON', process), \
                 patch.object(driver.os, 'waitpid', return_value=(123, 7 << 8)), patch.object(driver, 'event'):
                with self.assertRaises(RuntimeError):
                    with driver.pause_owned_daemon():
                        self.fail('unconfirmed stop must not enter carrier operation')
            self.assertEqual([c.args[0] for c in process.send_signal.call_args_list], [signal.SIGSTOP, signal.SIGCONT])
            if exited:
                self.assertEqual(process.returncode, 7)

    def test_missing_stop_confirmation_is_bounded_and_resumes(self):
        process = Mock(pid=123, returncode=None)
        clock = [0.0]
        with patch.object(driver, 'DAEMON', process), patch.object(driver, 'event'), \
             patch.object(driver.os, 'waitpid', return_value=(0, 0)), \
             patch.object(driver.time, 'monotonic', side_effect=lambda clock=clock: clock[0]), \
             patch.object(driver.time, 'sleep', side_effect=lambda seconds, clock=clock: clock.__setitem__(0, clock[0]+seconds)):
            with self.assertRaisesRegex(RuntimeError, 'stop handshake exceeded'):
                with driver.pause_owned_daemon():
                    self.fail('unconfirmed stop must not enter carrier operation')
        self.assertLess(clock[0], 5.02)
        self.assertEqual(process.send_signal.call_args.args, (signal.SIGCONT,))

    def test_actual_owned_child_stop_and_resume(self):
        process = subprocess.Popen([sys.executable, '-c',
                                    'import sys; print("ready", flush=True); print(sys.stdin.readline().strip(), flush=True)'],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            self.assertTrue(select.select([process.stdout], [], [], 5)[0], 'child failed to start')
            self.assertEqual(process.stdout.readline().strip(), 'ready')
            with patch.object(driver, 'DAEMON', process), patch.object(driver, 'event'):
                with driver.pause_owned_daemon():
                    self.assertIn('T (stopped)', Path(f'/proc/{process.pid}/status').read_text())
                    process.stdin.write('resumed\n')
                    process.stdin.flush()
                    self.assertFalse(select.select([process.stdout], [], [], 0)[0])
            self.assertTrue(select.select([process.stdout], [], [], 5)[0], 'owned child was not resumed')
            self.assertEqual(process.stdout.readline().strip(), 'resumed')
            self.assertEqual(process.wait(timeout=5), 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            process.stdin.close()
            process.stdout.close()


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


class FrrVersionTests(unittest.TestCase):
    def test_pinned_release_and_observed_container_banner(self):
        for version in ('10.7.1', '10.7.1_git'):
            driver.verify_frr_version(f'FRRouting {version} (a) on Linux(6.17.0-1022-azure).\n')

    def test_other_releases_and_unrecognized_suffixes_are_rejected(self):
        for version in ('10.7.10', '10.7.2', '10.7.1_gitfoo', '10.7.1_git_git', '10.7.1-dev', '10.7.1.1'):
            with self.subTest(version=version), self.assertRaises(AssertionError):
                driver.verify_frr_version(f'FRRouting {version} (a) on Linux.\n')


class NamespaceCleanupTests(unittest.TestCase):
    def test_frr_nodes_preserve_the_pinned_images_init_entrypoint(self):
        source = (Path(__file__).resolve().parents[1] / 'm121-evpn-all-active-frr.clab.yml').read_text()
        for node in ('a', 'r'):
            section = re.search(rf'(?ms)^    {node}:\n(.*?)(?=^    \S|\Z)', source).group(1)
            self.assertNotIn('entrypoint:', section)
            self.assertIn('      cmd: /bin/sleep infinity', section)
            self.assertIn('      image: quay.io/frrouting/frr:10.7.1', section)

    def test_parent_namespace_mount_is_initialized_before_sibling_handles(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(driver, 'NETNS_ROOT', Path(directory)), \
             patch.object(driver, 'NAMESPACE_HANDLES', {}), \
             patch.object(driver, 'PIDS', dict(a=101, r=102)), \
             patch.object(driver, 'run', return_value='') as run:
            driver.setup_namespaces()
            commands = [call.args for call in run.call_args_list]
            self.assertEqual(commands[:3], [('ip', 'netns', 'add', node) for node in ('b', 'ce', 'hr')])
            self.assertEqual(commands[3:], [('mount', '--bind', f'/hostproc/{pid}/ns/net', str(Path(directory, node)))
                                           for node, pid in [('a', 101), ('r', 102)]])
            self.assertEqual(driver.NAMESPACE_HANDLES, dict(a=True, r=True))

    def cleanup_context(self, stack, directory):
        stack.enter_context(patch.object(driver, 'OUT', Path(directory)))
        stack.enter_context(patch.object(driver, 'NETNS_ROOT', Path(directory)))
        stack.enter_context(patch.object(driver, 'DAEMON', None))
        stack.enter_context(patch.object(driver, 'cleanup_diagnostics'))
        stack.enter_context(patch.object(driver, 'stop_captures'))
        stack.enter_context(patch.object(driver, 'ns'))

    def test_partial_bind_failure_removes_only_successfully_mounted_handles(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            self.cleanup_context(stack, directory)
            stack.enter_context(patch.object(driver, 'NAMESPACE_HANDLES', {}))
            stack.enter_context(patch.object(driver, 'PIDS', dict(a=101, r=102)))
            def setup_command(*args):
                if args[:2] == ('mount', '--bind') and args[2] == '/hostproc/102/ns/net':
                    raise RuntimeError('second mount failed')
                return ''
            with patch.object(driver, 'run', side_effect=setup_command):
                with self.assertRaisesRegex(RuntimeError, 'second mount failed'):
                    driver.setup_namespaces()
            self.assertEqual(driver.NAMESPACE_HANDLES, dict(a=True, r=False))
            with patch.object(driver, 'run', return_value='') as run, patch.object(driver, 'frr_run'):
                driver.cleanup()
            self.assertEqual([call.args for call in run.call_args_list if call.args[0] == 'umount'],
                             [('umount', str(Path(directory, 'a')))])
            self.assertEqual(driver.NAMESPACE_HANDLES, {})
            self.assertFalse(Path(directory, 'a').exists())
            self.assertFalse(Path(directory, 'r').exists())

    def test_stop_and_first_unmount_failures_do_not_skip_other_owned_cleanup(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            self.cleanup_context(stack, directory)
            stack.enter_context(patch.object(driver, 'NAMESPACE_HANDLES', dict(a=True, r=True)))
            for node in ('a', 'r'):
                Path(directory, node).touch()
            def command(*args, **kwargs):
                if args == ('umount', str(Path(directory, 'a'))):
                    raise RuntimeError('first unmount failed')
                return 'a\n' if args == ('ip', 'netns', 'list') else ''
            with patch.object(driver, 'run', side_effect=command) as run, \
                 patch.object(driver, 'frr_run', side_effect=[RuntimeError('stop timed out'), '']) as frr:
                with self.assertRaises(AssertionError):
                    driver.cleanup()
            self.assertEqual([call.args[0] for call in frr.call_args_list], ['a', 'r'])
            self.assertTrue(all(call.kwargs.get('check', True) for call in frr.call_args_list))
            self.assertIn(('umount', str(Path(directory, 'r'))), [call.args for call in run.call_args_list])
            self.assertEqual(driver.NAMESPACE_HANDLES, dict(a=True))
            errors = json.loads(Path(directory, 'cleanup.json').read_text())['errors']
            self.assertTrue(any('stop timed out' in error for error in errors))
            self.assertTrue(any('first unmount failed' in error for error in errors))
            self.assertTrue(any('owned namespace handles remain' in error for error in errors))

    def test_cleanup_failure_preserves_the_original_failure(self):
        primary = ValueError('original proof failure')
        with patch.object(driver, 'cleanup', side_effect=RuntimeError('cleanup failure')):
            with self.assertRaises(ValueError) as failure:
                try:
                    raise primary
                finally:
                    driver.cleanup_preserving_error()
        self.assertIs(failure.exception, primary)
        self.assertIn('cleanup failure', primary.__notes__[0])

    def test_cleanup_failure_after_success_is_still_fatal(self):
        with patch.object(driver, 'cleanup', side_effect=RuntimeError('cleanup failure')):
            with self.assertRaisesRegex(RuntimeError, 'cleanup failure'):
                driver.cleanup_preserving_error()


class BumWitnessTests(unittest.TestCase):
    ES = ' DF status: {} \n'

    def run_bum(self, winner, frr_status='non-df', a_flood=True):
        calls = []
        def frr(node, command):
            self.assertEqual((node, command), ('a', 'show evpn es detail'))
            calls.append('witness')
            return self.ES.format(frr_status)
        def ns(node, *args):
            if args[:3] == ('bridge', '-j', 'fdb'):
                return json.dumps([dict(mac='00:00:00:00:00:00', dst=ip) for ip in ('10.211.0.1', '10.211.0.2')])
            self.assertEqual((node, args[-1]), ('a', 'es0'))
            return json.dumps([dict(ifname='es0', flood=a_flood, mcast_flood=a_flood, bcast_flood=a_flood)])
        packets = {'bum-a-vx100': [121], 'bum-b-vx100': [121], 'bum-ce-cea': [121],
                   'bum-ce-ceb': [121] if winner == 'b' else [],
                   'bum-ce-bond0': [121, 121] if winner == 'b' else [121]}
        def capture(*args, **kwargs):
            calls.append('capture')
            return packets
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(driver, 'OUT', Path(directory)), patch.object(driver, 'frr', side_effect=frr), \
             patch.object(driver, 'ns', side_effect=ns), patch.object(driver, 'snapshot'), \
             patch.object(driver, 'wait', side_effect=lambda check, _: check()), \
             patch.object(driver, 'capture', side_effect=capture):
            return driver.bum(100, winner), calls

    def test_frr_non_df_cells_check_the_witness_around_the_packet_proof(self):
        for winner, copies in (('b', 2), (None, 1)):
            with self.subTest(winner=winner):
                result, calls = self.run_bum(winner)
                self.assertEqual(calls, ['witness', 'capture', 'witness'])
                self.assertEqual((result['ce_cea'], result['ce_bond0']), (1, copies))
                self.assertEqual(result['frr_non_enforcement_witness'],
                                 dict(flood=True, mcast_flood=True, bcast_flood=True))

    def test_frr_df_cell_has_no_witness(self):
        result, calls = self.run_bum('a')
        self.assertEqual((calls, result['frr_non_enforcement_witness']), (['capture'], None))

    def test_frr_filtering_port_turns_the_cell_red_before_sending(self):
        with self.assertRaisesRegex(AssertionError, 'non-enforcement witness'):
            self.run_bum('b', a_flood=False)


class CarrierRecoveryTests(unittest.TestCase):
    def recover(self, carrier_hold, full_readiness=6.25, response_duration=0.0):
        clock = [0.0]
        process = Mock(pid=123, poll=Mock(return_value=None))
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
                self.assertEqual(process.send_signal.call_args.args, (signal.SIGCONT,))
                clock[0] += response_duration
            return dict(segments=[dict(drained=clock[0] < 10 + carrier_hold)])
        def ns(node, *args):
            if node == 'b' and args == ('ip', 'link', 'set', 'ac', 'up'):
                self.assertEqual(process.send_signal.call_args.args, (signal.SIGSTOP,))
            if node == 'ce' and args == ('ip', '-j', 'link', 'show', 'bond0'):
                return json.dumps([dict(address=driver.PEER_MAC)])
            return json.dumps([dict(flags=['LOWER_UP'])])
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(driver, 'OUT', Path(directory)))
            stack.enter_context(patch.object(driver, 'DAEMON', process))
            stack.enter_context(patch.object(driver.os, 'waitpid', return_value=(123, (signal.SIGSTOP << 8) | 0x7f)))
            stack.enter_context(patch.object(driver.time, 'monotonic', side_effect=lambda clock=clock: clock[0]))
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
        result = self.recover(5)
        self.assertEqual(result['carrier_observation_elapsed_seconds'], 6.25)
        self.assertIn('controlled daemon resume', result['timing_scope'])
        self.assertIn('not natural timer latency', result['timing_scope'])

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

    def test_only_fixed_sync_mac_and_vnis_are_allowed(self):
        result = subprocess.CompletedProcess([], 0, '{}', '')
        for vni in (100, 101, 102):
            for mac in (driver.RUST_MAC, driver.PEER_MAC):
                request = self.request()
                request['args'] = ['vtysh', '-c', f'show evpn mac vni {vni} mac {mac} json']
                with self.subTest(vni=vni, mac=mac), patch.object(driver.subprocess, 'run', return_value=result) as run:
                    if vni in (100, 101) and mac == driver.RUST_MAC:
                        self.assertEqual(driver.execute_frr_request(request)['exit'], 0)
                        run.assert_called_once()
                    else:
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
