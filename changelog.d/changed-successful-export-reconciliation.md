### Changed

- Skip redundant per-route rejection reconciliation when every exact-export
  probe succeeds and the peer has no rejected routes, including initial-table
  exports. Exact wire validation and table-before-End-of-RIB ordering remain
  enforced.
