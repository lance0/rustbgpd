"""Check that a plausible displaced reload bracket cannot be silently accepted."""

import unittest
from decimal import Decimal

from analyze import FIELDS, partition


class PartitionTest(unittest.TestCase):
    def test_partition_conserves_counters_and_rejects_displaced_boundary(self):
        samples = [dict.fromkeys(FIELDS, "0") for _ in range(13)]
        for i, sample in enumerate(samples):
            sample.update(epoch_us=str(i * 1_000_000), monotonic_ns=str(i * 1_000_000_000),
                          cpu_seconds=str(i / 2), voluntary_switches=str(i * 10),
                          threads_read="12")
        brackets = [{"reload": str(i + 1),
                     "cpu_window_start_epoch_us": str((2 * i + 1) * 1_000_000),
                     "cpu_window_end_epoch_us": str((2 * i + 2) * 1_000_000)}
                    for i in range(4)]
        rows = partition("01-A", samples, brackets)
        self.assertEqual(len(rows), 10)
        self.assertEqual(sum(Decimal(row["delta_cpu_seconds"]) for row in rows[:9]), Decimal("6"))
        self.assertEqual(sum(Decimal(row["delta_voluntary_switches"]) for row in rows[:9]), Decimal("120"))
        self.assertEqual(rows[-1]["delta_cpu_seconds"], "5.0")
        brackets[1]["cpu_window_start_epoch_us"] = "2999999"
        with self.assertRaisesRegex(ValueError, "boundary absent"):
            partition("01-A", samples, brackets)


if __name__ == "__main__":
    unittest.main()
