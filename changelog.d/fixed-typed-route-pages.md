### Fixed

- Use existing prefix lookups and family indexes for exact-prefix and
  family-only route pages, preserving filtered totals, row ordering, and
  continuation tokens. Advertised counts, high-exclusion views, cold Best
  indexes, and dirty Advertised baselines can still require table-sized work.
