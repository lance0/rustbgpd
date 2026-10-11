#!/usr/bin/env python3
"""Positive first, then plausible broken selected evidence must fail."""
import base64
import copy
import gzip
import hashlib
import json
from pathlib import Path
import unittest

import recompute as receipt


ROOT = Path(__file__).resolve().parent


class Controls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = receipt.load(ROOT)
        cls.expected = json.loads((ROOT / 'summary.json').read_text())
        # Establish a complete positive before any negative is counted.
        assert receipt.compute(*cls.original) == cls.expected
        receipt.main(ROOT)

    def setUp(self):
        self.records, self.responses, self.provenance, self.features = copy.deepcopy(self.original)
        self.leg = self.records['baseline-r1']

    def reject(self):
        with self.assertRaises((AssertionError, ValueError, KeyError)):
            result = receipt.compute(self.records, self.responses, self.provenance, self.features)
            assert result == self.expected, 'changed evidence cannot reproduce the stored summary'

    def test_full_phase_dictionary_binding(self):
        self.leg['phases'][0]['fields']['cohort_prestage_session_apply_us'] += 100000
        self.reject()

    def test_phase_components_add_up(self):
        self.leg['phases'][0]['fields']['total_us'] += 1000
        self.leg['native_summary']['reloads'][0]['phase_timing']['total_us'] += 1000
        self.reject()

    def test_selected_boundary_timestamps(self):
        for key in ('starts', 'commits', 'phases', 'completes'):
            with self.subTest(boundary=key):
                self.setUp()
                self.leg[key][0]['timestamp'] = '2026-10-11T08:43:17.000000Z'
                self.reject()

    def test_committed_outcome_required(self):
        self.leg['commits'][0]['fields']['outcome'] = 'fallback'
        self.leg['native_summary']['reloads'][0]['rib_transition']['outcome'] = 'fallback'
        self.reject()

    def test_missing_reload(self):
        self.leg['wire'].pop()
        self.reject()

    def test_missing_pair(self):
        self.leg['probes'].pop(1)
        self.reject()

    def test_failed_or_slow_call(self):
        for key, value in (('exit', 1), ('duration_ms', 2000.01)):
            with self.subTest(field=key):
                self.setUp()
                raw = next(p for p in self.leg['probes'] if p['reload'] == 1
                           and p['phase'] == 'pair' and p['op'] == 'policy_stats')
                call = next(p for p in self.leg['native_summary']['reloads'][0]['calls']
                            if p['phase'] == 'pair' and p['op'] == 'policy_stats')
                raw[key] = call[key] = value
                self.reject()

    def test_complete_reply_body_shape(self):
        raw = next(p for p in self.leg['probes'] if p['op'] == 'neighbor')
        response = self.responses[f"baseline-r1/{raw['stdout']}"]
        body = json.loads(gzip.decompress(base64.b64decode(response['gzip_base64'])))
        body.pop()
        payload = json.dumps(body).encode()
        compressed = gzip.compress(payload, mtime=0)
        raw['body_sha256'] = hashlib.sha256(payload).hexdigest()
        response['gzip_base64'] = base64.b64encode(compressed).decode()
        response['compressed_sha256'] = hashlib.sha256(compressed).hexdigest()
        self.reject()

    def test_compressed_body_digest(self):
        next(iter(self.responses.values()))['compressed_sha256'] = '0' * 64
        self.reject()

    def test_malformed_audit_cannot_shrink_stages(self):
        audit = self.leg['audits'][0]['fields']
        audit['request_summary'] = 'stage=export elapsed_ms=0 broken'
        call = next(p for p in self.leg['native_summary']['reloads'][0]['calls']
                    if p['phase'] == 'pair' and p['op'] == 'policy_stats')
        call['audit']['request_summary'] = audit['request_summary']
        self.reject()

    def test_native_flat_criterion_recomputed(self):
        self.leg['native_summary']['flat']['limit_ms'] += 1
        self.reject()

    def test_native_failure_or_missing_finish(self):
        for change in ('native_exit', 'missing_finish'):
            with self.subTest(change=change):
                self.setUp()
                if change == 'native_exit':
                    self.provenance['native_exits']['logs/abba-wrapper.exit'] = 143
                else:
                    self.provenance['window_finish'] = ''
                self.reject()

    def test_quiet_gate_not_bypassed(self):
        self.provenance['legs']['baseline-r1']['quiet_samples'][1]['load1'] = '2.01'
        self.reject()

    def test_wire_quantile_order(self):
        self.leg['wire'][0]['completion_p50_s'] = '4.000000'
        self.reject()

    def test_wire_parser_failure(self):
        self.leg['wire'][0]['parse_errors'] = '1'
        self.reject()

    def test_missing_actual_closure_unit(self):
        capture = self.features['candidate']
        key = next(k for k in capture['normal_units'] if k != capture['entry'])
        capture['normal_units'].pop(key)
        capture['including_build_units'].pop(key)
        self.reject()

    def test_changed_actual_feature(self):
        capture = self.features['candidate']
        key = capture['entry']
        for scope in ('normal_units', 'including_build_units'):
            capture[scope][key]['features'] = '["default"]'
        self.reject()

    def test_missing_including_build_only_unit(self):
        capture = self.features['candidate']
        key = next(k for k in capture['including_build_units'] if k not in capture['normal_units'])
        capture['including_build_units'].pop(key)
        self.reject()

    def test_changed_build_environment(self):
        capture = self.features['candidate']
        key = next(k for k, unit in capture['including_build_units'].items()
                   if k not in capture['normal_units']
                   and any('RerunIfEnvChanged' in item for item in unit['local']))
        item = next(item for item in capture['including_build_units'][key]['local']
                    if 'RerunIfEnvChanged' in item)
        item['RerunIfEnvChanged']['val'] = 'changed-build-input'
        self.reject()

    def test_changed_actual_dependency_identity(self):
        capture = self.features['candidate']
        for scope in ('normal_units', 'including_build_units'):
            capture[scope][capture['entry']]['deps'][0][0] += 1
        self.reject()

    def test_equal_bench_internals_arms_still_rejected(self):
        for capture in self.features.values():
            for scope in ('normal_units', 'including_build_units'):
                capture[scope][capture['entry']]['features'] = '["bench-internals", "default"]'
        self.reject()


if __name__ == '__main__':
    unittest.main(verbosity=2)
