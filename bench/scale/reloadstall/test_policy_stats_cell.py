#!/usr/bin/env python3
"""Focused checks for the policy-stats cell's audit parser and flat verdict."""
import unittest

from policy_stats_cell import flat_verdict, parse_summary, percentile

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

    def test_unparseable_segment_is_dropped(self):
        self.assertEqual(parse_summary('peer=10.0.0.1; garbage'), [])


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
