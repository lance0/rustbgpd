# Grouped withdrawal exact-probe skip artifacts

This compact package records the LAN-672 A/B/B/A campaign comparing the
immediate harness parent `143d571078f92cfc75ce048d7062883994250078`
with production candidate `6e23412ffa552dab325183aaaec2dba9510b9232`.
The benchmark source is byte-identical across those revisions.

- `provenance.env` pins the revisions, source hash, environment, workload,
  order, and claim boundary.
- `preflight.tsv` retains the quiet-host fence before every attempt.
- `results.csv` retains Criterion's median point estimate, bootstrap 95%
  confidence interval, sample count, iterations, and measured time.
- `samples.csv` losslessly flattens all 160 Criterion linear samples.
- `source-json-hashes.tsv` identifies every source `benchmark.json`,
  `estimates.json`, and `sample.json`.
- `SHA256SUMS` authenticates every other file in this directory.

The measured interval covers direct manager dispatch through bounded
route-chunk processing, Loc-RIB recompute, grouped distribution,
authoritative Adj-RIB-Out commit, metric refresh, and bounded-channel
enqueue. Manager-channel dequeue, Tokio scheduling, fixture setup,
session-writer work, socket I/O, and network I/O are excluded.

The result supports a grouped-withdrawal manager-path claim at 64, 256, and
1,000 members. The 8-member result is retained but not claimed because its
delta is comparable to the same-revision spread. This is not a full-daemon,
convergence, or network-throughput receipt.
