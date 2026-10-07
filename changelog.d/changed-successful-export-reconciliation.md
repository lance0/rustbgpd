### Changed

- Skip redundant per-route rejection reconciliation when every exact-export
  probe succeeds and the peer has no rejected routes, including initial-table
  exports. Exact wire validation and table-before-End-of-RIB ordering remain
  enforced. In a measured 700-peer, 400,400-prefix ordinary flap workload, the
  first-survivor UPDATE p50 fell from 130.086 to 106.426 ms; see the
  [qualification receipt](../docs/perf/initial-table-reconciliation-2026-10.md)
  for scope, returning-peer completion and withdrawal-tail diagnostics.
