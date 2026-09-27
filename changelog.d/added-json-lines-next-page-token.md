### Added

- `rbgp --json-lines rib`, `rib received` and `rib advertised` accept
  `--page-token` with `--limit`. The `rbgp-rib` end record carries a
  `next_page_token` to continue from, empty once the walk is complete, and
  the stream format advances to version 1.1 for this additive field.
  Automatic paging without `--limit`, page bounds, and the failure of a
  continuation the daemon rejects after a table change are unchanged; a
  token is not a durable checkpoint.
