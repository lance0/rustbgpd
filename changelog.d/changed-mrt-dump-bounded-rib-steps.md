### Changed

- MRT dumps no longer copy the whole Adj-RIB-In in one RIB step. The table is
  read about 4,096 routes at a time with ordinary route processing in
  between, so a periodic or on-demand dump does not delay UPDATE handling
  and queries for the length of the table. The file format, file names,
  metrics and configuration are unchanged, and a quiescent table produces
  the same bytes as before.
  **Operator-visible:** a dump is no longer one instant of the whole table.
  Each unicast prefix record is still a point-in-time view across all
  neighbors, but different prefixes can be read seconds apart, and the
  record timestamp is now the start of the walk. See
  [What one dump shows](../docs/reference/configuration.md#what-one-dump-shows).
