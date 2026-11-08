### Fixed

- Use existing prefix lookups and family indexes for exact-prefix and
  family-only route pages, preserving filtered totals, row ordering, and
  continuation tokens. Family totals come from maintained counters, except
  that an update-group member's Advertised total still visits that member's
  export rejections. High-exclusion views, cold Best indexes, and dirty
  Advertised baselines can still require table-sized work.
