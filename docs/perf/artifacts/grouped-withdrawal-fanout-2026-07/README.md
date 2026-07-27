# Grouped withdrawal fanout baseline artifacts

This compact package records the passing LAN-671 measurement at exact commit
`f55d6c5f1a300b0b2c5a8797469165eb1351e62c`. Its source was the
post-preflight exact-commit Criterion archive. Earlier runs and a distinct
top-level Criterion output were rejected.

- `provenance.env` pins the code, toolchain, host class, CPU pin, governor,
  preflight summary, workload, and claim boundary.
- `preflight.tsv` is the exact passing host-fence row.
- `results.csv` retains Criterion's exact median point estimate and bootstrap
  95% confidence interval for every fleet size.
- `samples.csv` losslessly flattens every Criterion linear sample as iteration
  count, total measured nanoseconds, and their quotient.
- `source-json-hashes.tsv` identifies the exact Criterion `benchmark.json`,
  `estimates.json`, and `sample.json` inputs without retaining private paths.
- `SHA256SUMS` authenticates every other file in this package.

The benchmark covers direct manager dispatch through bounded route-chunk
processing, Loc-RIB recompute, grouped distribution, authoritative Adj-RIB-Out
commit, metric refresh, and bounded-channel enqueue. It uses a synthetic
unregistered legacy source session (`session_id = 0`). Manager-channel dequeue,
Tokio scheduling, session-writer work, socket I/O, and network I/O are
excluded.

This is an absolute measurement-only baseline. It has no optimization,
control, delta, regression, full-pipeline, or end-to-end network claim.
