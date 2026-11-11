### Fixed

- Settle End-of-RIB markers after shutdown flushes their last owed withdrawals,
  preserving withdrawal-before-marker ordering and avoiding a false missed-release
  warning. Deferred marker settlement now deduplicates peers once per drain.
