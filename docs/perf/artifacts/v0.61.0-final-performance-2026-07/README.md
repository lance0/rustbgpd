# v0.61.0 final performance receipt artifacts

This compact archive pins the absolute release-tip performance baseline
documented in
[`v0.61.0-final-performance-2026-07.md`](../../v0.61.0-final-performance-2026-07.md).
It contains three accepted real-daemon route-server runs and one accepted
single-revision Criterion archive. It is not an A/B optimization receipt and
supports no CPU delta claim.

## Contents

- `route-runs/` contains exactly three accepted 1,000-peer × 400-BASE-route
  runs. Each retains source and shape provenance, quiet-host admission, process
  and jemalloc summaries, the raw settled process-status fields, path-scrubbed
  daemon/harness binary hashes, exact settled gate aggregates, a sanitized
  harness summary, exit status, and the deterministic-gzip 1 Hz RSS stream.
- `criterion/results.tsv` is an exact compact derivative for the 71 saved
  median estimates: benchmark identity, median point estimate, median 95%
  confidence interval, sample count, and sampling mode.
- `criterion/derive_criterion.py` is the deterministic extractor that
  reproduced `results.tsv` byte-for-byte from the accepted saved-baseline tree.
- `criterion/accepted-receipt.env` pins the literal baseline name, source,
  logical CPU, equal before/after swap-page counters, and successful status.
- `criterion/rejected-attempt.env` records the orchestration decision that
  excluded the earlier attempt. That directory did not retain its own
  before/after swap-page counters, so the note is not a self-contained proof of
  the observed delta. None of that attempt's estimates or medians are retained.
- `criterion/binary-hashes.tsv` retains the three benchmark executable hashes
  with build paths removed.
- `environment.txt` records the shared host and toolchain shape without a host
  name or user identity.
- `manifest.json`, `verify.py`, `verification.txt`,
  `verifier-red-proofs.txt`, and `SHA256SUMS` make the acceptance boundary
  machine-checkable.

Observed process-tree RSS and jemalloc gauges are separate measurements.
`steady_rss_mib_median_post_convergence` comes from the retained 1 Hz stream;
the four allocator gauges are point samples from the daemon. Do not subtract
or compare them as though they were the same quantity.

The full Prometheus snapshots are intentionally omitted. The compact
`settled-gates.env` files retain the exact sample counts, sums, and maxima used
by the acceptance gate without retaining per-peer runtime addresses.

All large streams use deterministic gzip (`gzip -n -9`).
`SHA256SUMS` covers every retained file except itself.
