### Documentation

- Add a dated 2026-10-19 bgperf2 comparator spot-check to the
  [benchmark page](../docs/benchmarks.md#2026-10-19-comparator-spot-check):
  unreleased rustbgpd against BIRD 2.19.3, BIRD 3.3.3 and GoBGP 4.10.0 on
  three of the five import shapes, two runs per cell. Both BIRD lines had a
  lower median total time than rustbgpd at 10 peers × 1,000 prefixes, so the
  v0.68.0 campaign's "lowest median total time in all five shapes" statement
  is now scoped to that 2026-08-30 campaign.
