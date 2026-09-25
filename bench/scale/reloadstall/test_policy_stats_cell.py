#!/usr/bin/env python3
"""Focused checks for the policy-stats cell's audit parser and flat verdict."""
import unittest

from policy_stats_cell import classify_stats_call, flat_verdict, parse_summary, percentile, run_verdict

SUMMARY = ('stage=export elapsed_ms=597 budget_ms=1999 rpc_elapsed_ms=598 code=Ok; '
           'stage=import elapsed_ms=1471 budget_ms=1401 rpc_elapsed_ms=2070 code=DeadlineExceeded '
           'admission_ms=300 collection_ms=1171 publications=812/1000 yields=31')


class ParseSummary(unittest.TestCase):
    def test_stages_and_import_substages(self):
        export, imported = parse_summary(SUMMARY)
        self.assertEqual((export['stage'], export['elapsed_ms'], export['code']), ('export', 597, 'Ok'))
        self.assertNotIn('admission_ms', export)
        self.assertEqual(imported['code'], 'DeadlineExceeded')
        self.assertEqual((imported['admission_ms'], imported['collection_ms'], imported['publications_read'],
                          imported['publications_selected'], imported['yields']), (300, 1171, 812, 1000, 31))

    def test_pending_admission(self):
        (stage,) = parse_summary('stage=import elapsed_ms=2000 budget_ms=2000 rpc_elapsed_ms=2001 '
                                 'code=DeadlineExceeded admission=pending')
        self.assertEqual(stage['admission'], 'pending')
        self.assertNotIn('admission_ms', stage)

    def test_malformed_segment_raises(self):
        with self.assertRaises(ValueError):
            parse_summary(COMPLETE.replace('stage=datasets', 'stage=datasets garbage'))
        with self.assertRaises(ValueError):
            parse_summary(COMPLETE + '; peer=10.0.0.1')


COMPLETE = ('stage=export elapsed_ms=75 budget_ms=1999 rpc_elapsed_ms=75 code=Ok; '
            'stage=import elapsed_ms=138 budget_ms=1924 rpc_elapsed_ms=214 code=Ok '
            'admission_ms=0 collection_ms=138 publications=1000/1000 yields=970; '
            'stage=datasets elapsed_ms=38 budget_ms=1785 rpc_elapsed_ms=252 code=Ok')
FLAT = {'pass': True}


class CompleteStageSet(unittest.TestCase):
    def verdict(self, summary, result='handler_ok'):
        _, total, reason = classify_stats_call(summary, result)
        invalid = [reason] if reason else []
        return run_verdict([], invalid, FLAT), total, reason

    def test_complete_call_passes(self):
        self.assertEqual(self.verdict(COMPLETE), ('PASS', 251, None))

    def test_missing_stage_is_invalid(self):
        without_datasets = COMPLETE.rsplit(';', 1)[0]
        verdict, total, reason = self.verdict(without_datasets)
        self.assertEqual(verdict, 'INVALID')
        self.assertIsNone(total)
        self.assertIn('incomplete', reason)

    def test_malformed_segment_is_invalid(self):
        verdict, total, reason = self.verdict(COMPLETE.replace('elapsed_ms=38', 'elapsed_ms=3.8'))
        self.assertEqual(verdict, 'INVALID')
        self.assertIsNone(total)
        self.assertIn('malformed', reason)

    def test_import_without_substages_is_invalid(self):
        bare = COMPLETE.replace(' admission_ms=0 collection_ms=138 publications=1000/1000 yields=970', '')
        self.assertEqual(self.verdict(bare)[0], 'INVALID')

    def test_deadline_miss_stops_stages_and_stays_valid(self):
        verdict, total, reason = self.verdict(SUMMARY, result='handler_deadline_exceeded')
        self.assertIsNone(reason)
        self.assertEqual(total, 597 + 1471)
        self.assertEqual(run_verdict(['R1 pair policy_stats failed'], [], FLAT), 'FAIL')

    def test_stage_after_failure_is_invalid(self):
        after = SUMMARY + '; stage=datasets elapsed_ms=0 budget_ms=0 rpc_elapsed_ms=2070 code=Ok'
        self.assertEqual(self.verdict(after, result='handler_deadline_exceeded')[0], 'INVALID')


class FlatVerdict(unittest.TestCase):
    def test_boundary(self):
        self.assertTrue(flat_verdict([250], [100, 100, 200])['pass'])   # limit 2*100+50
        self.assertFalse(flat_verdict([251], [100, 100, 200])['pass'])

    def test_missing_samples_fail(self):
        self.assertFalse(flat_verdict([], [100])['pass'])
        self.assertFalse(flat_verdict([100], [])['pass'])

    def test_percentile_nearest_rank(self):
        self.assertEqual(percentile(list(range(1, 21)), 95), 19)
        self.assertEqual(percentile([5], 50), 5)
        self.assertIsNone(percentile([], 50))


if __name__ == '__main__':
    unittest.main()
