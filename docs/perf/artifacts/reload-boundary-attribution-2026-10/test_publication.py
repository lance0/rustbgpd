import csv
import tempfile
import unittest
from pathlib import Path
from read_publication import FIELDS, HEADER, read


def fixture():
    wall = 10**18
    rows = [['clock', wall, wall+2, 500], HEADER,
            ['group', 1, 300, 3, 3, 0, 1, 1234],
            ['chunk', 1, 0, '10.0.0.1', 1, 100, 100, 120],
            ['chunk', 1, 1, '10.0.0.2', 1, 100, 100, 120],
            ['chunk', 1, 2, '10.0.0.3', 1, 100, 200, 210]]
    for peer, values in [
        ('10.0.0.1', [70,75,80,1,0,0,0,0,90,95,1,1000,1100,0]),
        ('10.0.0.2', [70,75,80,0,1,125,126,127,130,131,0,1000,1100,0]),
        ('10.0.0.3', [100,105,110,0,1,115,117,118,119,120,0,1000,1100,0]),
    ]:
        rows.append(['member', 1, peer, *values])
    rows.append(['clock_end', 600, wall+601, 602])
    return rows


class TraceTests(unittest.TestCase):
    def evaluate(self, rows):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'trace.csv'
            with path.open('w') as out:
                csv.writer(out).writerows(rows)
            return read(path, members=3, rounds=1, min_routes=300)

    def rejected(self, mutate, message):
        rows = fixture()
        mutate(rows)
        with self.assertRaisesRegex(ValueError, message):
            self.evaluate(rows)

    def member(self, rows, peer=2):
        return next(row for row in rows if row[0] == 'member' and row[2] == f'10.0.0.{peer}')

    def set_field(self, rows, field, value, peer=2):
        self.member(rows, peer)[3 + FIELDS.index(field)] = value

    def test_precise_ordinal_and_producer_before_publication(self):
        result = self.evaluate(fixture())
        self.assertEqual(result['rows'][0]['ordinal'], 1)
        self.assertLess(result['rows'][0]['admission_after'], result['rows'][0]['publication_before'])
        self.assertTrue(result['clock']['stable'])

    def test_overlapping_publication_snapshot_is_valid(self):
        result = self.evaluate(fixture())
        consumer = result['rows'][2]
        self.assertLess(consumer['snapshot_after'], consumer['publication_after'])
        self.assertEqual(consumer['eligible_ready_to_advance_bounds_ms'][0], 0)

    def test_wrong_source_same_length(self):
        def mutate(rows):
            rows[3][3], rows[4][3] = rows[4][3], rows[3][3]
        self.rejected(mutate, 'first source-excluding')

    def test_own_source_chunk_rejected(self):
        self.rejected(lambda rows: self.set_field(rows, 'ordinal', 0, peer=1), 'first source-excluding')

    def test_plausible_next_chunk_rejected(self):
        self.rejected(lambda rows: self.set_field(rows, 'ordinal', 1), 'first source-excluding')

    def test_inventory_mismatch_rejected(self):
        self.rejected(lambda rows: self.set_field(rows, 'invalid', 1), 'inventory')

    def test_missing_member_rejected(self):
        self.rejected(lambda rows: rows.remove(self.member(rows)), 'peer coverage')

    def test_duplicate_member_rejected(self):
        self.rejected(lambda rows: rows.append(self.member(rows).copy()), 'duplicate identity')

    def test_duplicate_group_rejected(self):
        self.rejected(lambda rows: rows.append(rows[2].copy()), 'duplicate identity')

    def test_missing_chunk_rejected(self):
        self.rejected(lambda rows: rows.pop(5), 'chunk ordinals')

    def test_fifo_same_batch_wrong_length_rejected(self):
        self.rejected(lambda rows: self.set_field(rows, 'byte_end', 1101), 'FIFO length')

    def test_missing_producer_rejected(self):
        self.rejected(lambda rows: self.set_field(rows, 'producer', 0, peer=1), 'producer ownership')

    def test_follower_cannot_use_producer_timestamp_exception(self):
        self.rejected(lambda rows: self.set_field(rows, 'poll', 0), 'only elected')

    def test_snapshot_before_publication_rejected(self):
        def mutate(rows):
            for field, value in [('poll',81), ('snapshot_before',82), ('snapshot_after',83), ('admission_before',84), ('admission_after',85)]:
                self.set_field(rows, field, value)
        self.rejected(mutate, 'not yet published')

    def test_swapped_clock_columns_rejected(self):
        self.rejected(lambda rows: rows[0].__setitem__(slice(1,4), [500, 10**18, 10**18+2]), 'clock columns')

    def test_clock_step_retained_but_unqualified(self):
        rows = fixture()
        rows[-1][2] += 1_000_000
        self.assertFalse(self.evaluate(rows)['clock']['stable'])

    def test_buffer_overflow_rejected(self):
        self.rejected(lambda rows: rows[2].__setitem__(5, 1), 'overflow')

    def test_reordered_rows_cannot_make_later_chunk_first(self):
        def mutate(rows):
            rows[3], rows[4] = rows[4], rows[3]
            self.set_field(rows, 'ordinal', 1)
        self.rejected(mutate, 'first source-excluding')

    def test_chunk_row_order_not_an_identity(self):
        rows = fixture()
        rows[3], rows[4] = rows[4], rows[3]
        self.assertEqual(self.evaluate(rows)['rows'][0]['ordinal'], 1)


if __name__ == '__main__':
    unittest.main()
