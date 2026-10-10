#!/usr/bin/env python3
"""Positive reproduction and plausible invalid-evidence controls."""
import copy
import json
import pathlib
import shutil
import tempfile
import unittest

import recompute

ROOT = pathlib.Path(__file__).resolve().parent


class ReceiptChecks(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name)
        for path in ROOT.iterdir():
            if path.is_file():
                shutil.copyfile(path, self.root / path.name)

    def change(self, file, mutate):
        path = self.root / file
        data = json.loads(path.read_text())
        mutate(data)
        path.write_text(json.dumps(data))

    def reject_record(self, mutate):
        self.change('initial-records.json', lambda records: mutate(records[0]))
        with self.assertRaises((AssertionError, KeyError)):
            recompute.compute(self.root)

    def reject_proof(self, mutate):
        self.change('provenance.json', lambda proof: mutate(proof['campaigns']['initial']))
        with self.assertRaises((AssertionError, KeyError)):
            recompute.compute(self.root)

    def test_reproduces_all_rows_and_feature_controls(self):
        recompute.features(self.root)
        summary, table = recompute.compute(self.root)
        self.assertEqual(summary, json.loads((ROOT / 'initial-summary.json').read_text()))
        self.assertEqual(table, (ROOT / 'initial-correlation.csv').read_text())
        self.assertEqual(summary['baseline']['all']['actor_ms']['n'], 16)
        self.assertEqual(summary['candidate']['remaining']['actor_ms']['n'], 12)

    def test_retains_wire_penalty_and_stats_outlier(self):
        summary, _ = recompute.compute(self.root)
        for subset in ('all', 'remaining'):
            self.assertGreater(summary['candidate'][subset]['wire_completion_p50_s']['median'], summary['baseline'][subset]['wire_completion_p50_s']['median'])
        self.assertGreater(summary['candidate']['all']['pair_policy_stats_ms']['max'], 58)
        self.assertGreater(summary['baseline']['all']['cohort_ms']['max'], summary['candidate']['all']['cohort_ms']['max'])

    def test_phase_mean_decomposition_is_additive(self):
        summary, _ = recompute.compute(self.root)
        for arm in ('baseline', 'candidate'):
            fields = ['before_phase_ms', 'after_phase_ms'] + [key.removesuffix('_us') + '_ms' for key in recompute.COMPONENTS]
            total = sum(summary[arm]['all'][key]['mean'] for key in fields)
            self.assertAlmostEqual(total, summary[arm]['all']['daemon_complete_ms']['mean'], places=5)

    def test_final_reproduces_all_rows_and_feature_controls(self):
        recompute.features(self.root, 'final')
        summary, table = recompute.compute(self.root, 'final')
        self.assertEqual(summary, json.loads((ROOT / 'final-summary.json').read_text()))
        self.assertEqual(table, (ROOT / 'final-correlation.csv').read_text())
        self.assertEqual(summary['candidate']['all']['actor_ms']['n'], 16)
        self.assertEqual(summary['candidate']['first_two']['actor_ms']['n'], 4)
        self.assertEqual(summary['candidate']['remaining']['actor_ms']['n'], 12)

    def test_final_retains_remaining_cohort_median_reversal(self):
        summary, _ = recompute.compute(self.root, 'final')
        self.assertGreater(summary['candidate']['remaining']['cohort_ms']['median'], summary['baseline']['remaining']['cohort_ms']['median'])
        self.assertLess(summary['candidate']['remaining']['cohort_ms']['mean'], summary['baseline']['remaining']['cohort_ms']['mean'])
        self.assertGreater(summary['candidate']['all']['wire_completion_p50_s']['median'], summary['baseline']['all']['wire_completion_p50_s']['median'])
        self.assertLess(summary['candidate']['all']['wire_completion_p95_s']['median'], summary['baseline']['all']['wire_completion_p95_s']['median'])

    def test_rejects_failed_final_pair(self):
        self.change('final-records.json', lambda records: records[0]['calls'][0].__setitem__('exit', 1))
        with self.assertRaises(AssertionError):
            recompute.compute(self.root, 'final')

    def test_rejects_wrong_final_source(self):
        self.change('provenance.json', lambda proof: proof['campaigns']['final']['arms']['candidate'].__setitem__('source_commit', '0' * 40))
        with self.assertRaises(AssertionError):
            recompute.compute(self.root, 'final')

    def test_rejects_unmatched_final_library_features(self):
        self.change('final-feature-audit.json', lambda audit: next(iter(audit['units']['candidate'].values()))['configuration'].__setitem__('features', '["different"]'))
        with self.assertRaises(AssertionError):
            recompute.features(self.root, 'final')

    def test_rejects_probe_outside_process(self):
        self.reject_record(lambda row: row['calls'][0].__setitem__('completed_wall', row['calls'][0]['completed_wall'] + 1000))

    def test_rejects_wrong_refreshed_input_count(self):
        self.reject_proof(lambda proof: proof['arms']['candidate']['cache_freshness'].__setitem__('input_count', 0))

    def test_rejects_missing_reload(self):
        self.change('initial-records.json', lambda rows: rows.pop())
        with self.assertRaises(AssertionError):
            recompute.compute(self.root)

    def test_rejects_duplicate_reload(self):
        self.change('initial-records.json', lambda rows: rows.__setitem__(1, copy.deepcopy(rows[0])))
        with self.assertRaises(AssertionError):
            recompute.compute(self.root)

    def test_rejects_phase_component_mismatch(self):
        self.reject_record(lambda row: row['events']['phase']['fields'].__setitem__('cohort_prestage_session_apply_us', 1))

    def test_rejects_fallback(self):
        self.reject_record(lambda row: row['events']['rib']['fields'].__setitem__('outcome', 'fallback'))

    def test_rejects_wrong_boundary_label(self):
        self.reject_record(lambda row: row['events']['complete']['fields'].__setitem__('message', 'later settlement'))

    def test_rejects_failed_pair_call(self):
        self.reject_record(lambda row: row['calls'][0].__setitem__('exit', 1))

    def test_rejects_missing_probe(self):
        self.reject_record(lambda row: row['calls'].pop())

    def test_rejects_deadline_miss(self):
        self.reject_record(lambda row: row['calls'][0].__setitem__('duration_ms', 2001))

    def test_rejects_pair_coverage_mismatch(self):
        self.reject_record(lambda row: row['calls'][0].__setitem__('started_wall', row['calls'][0]['started_wall'] + 1))

    def test_rejects_incomplete_stats_audit(self):
        self.reject_record(lambda row: next(call for call in row['calls'] if call['op'] == 'policy_stats')['audit'].__setitem__('request_summary', 'stage=export elapsed_ms=0 budget_ms=1999 rpc_elapsed_ms=0 code=Ok'))

    def test_rejects_wire_quantile_inversion(self):
        self.reject_record(lambda row: row['wire'].__setitem__('completion_p50_s', '100'))

    def test_rejects_unmatched_package_selection(self):
        self.reject_proof(lambda proof: proof['arms']['candidate'].__setitem__('command', 'cargo build --release --locked -j 4 -p rustbgpd'))

    def test_rejects_failed_outer_process(self):
        self.reject_proof(lambda proof: proof.__setitem__('outer_process_exit', 143))

    def test_rejects_missing_window_finish(self):
        self.reject_proof(lambda proof: proof.pop('window_finish'))

    def test_rejects_failed_native_verdict(self):
        self.reject_proof(lambda proof: proof['runs']['candidate-r1']['native'].__setitem__('verdict', 'FAIL'))

    def test_rejects_wrong_source(self):
        self.reject_proof(lambda proof: proof['arms']['candidate'].__setitem__('source_commit', '0' * 40))

    def test_rejects_wrong_daemon_binary(self):
        self.reject_proof(lambda proof: proof['arms']['candidate']['binaries']['rustbgpd'].__setitem__('sha256', '0' * 64))

    def test_rejects_unmatched_library_features(self):
        self.change('feature-audit.json', lambda audit: next(iter(audit['units']['candidate'].values()))['configuration'].__setitem__('features', '["different"]'))
        with self.assertRaises(AssertionError):
            recompute.features(self.root)

    def test_rejects_missing_library_unit(self):
        self.change('feature-audit.json', lambda audit: audit['units']['baseline'].pop(next(iter(audit['units']['baseline']))))
        with self.assertRaises(AssertionError):
            recompute.features(self.root)

    def test_rejects_wrong_graph_hash(self):
        self.change('feature-audit.json', lambda audit: audit['resolved_graphs']['arms']['candidate'].__setitem__('normalized_sha256', '0' * 64))
        with self.assertRaises(AssertionError):
            recompute.features(self.root)

    def test_rejects_aborted_trap_record_as_success(self):
        self.change('invalid-build-confound.json', lambda history: history.__setitem__('whole_window_success', True))
        with self.assertRaises(AssertionError):
            recompute.features(self.root)


if __name__ == '__main__':
    unittest.main()
