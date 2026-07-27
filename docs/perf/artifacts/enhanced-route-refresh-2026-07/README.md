# Enhanced Route Refresh inventory artifacts

This is the compact, sanitized evidence for
[`enhanced-route-refresh-2026-07.md`](../../enhanced-route-refresh-2026-07.md).
The full raw receipt remains private under `target/enhanced-route-refresh/`;
daemon logs, raw Prometheus scrapes, API responses, generated runtime config,
process identifiers, and host paths are intentionally not retained here.

## Contents

- `provenance.env` pins the measured commit/tree, production base, build
  profile, allocator, fleet shape, and sampling interval.
- `binaries.sha256` records the three measured binaries by repository-relative
  label.
- `phase-results.tsv` is the exact validator output for every accepted phase.
  Actor histogram values are cumulative; operation durations are their adjacent
  deltas.
- `memory-boundaries.tsv` records exact jemalloc and process-memory boundaries.
  Each action's kernel high-water mark was reset immediately after its `pre`
  row.
- `sampled-peaks.tsv` contains maxima from action samplers configured with a
  25 ms inter-scrape sleep. The
  timeout-completion sampler ran only for the final 30 seconds of the
  independent five-minute window so metric polling did not perturb the idle
  retained interval.
- `SHA256SUMS` binds these retained bytes.

Verify from this directory:

```text
sha256sum -c SHA256SUMS
```

The source driver is
[`bench/scale/enhanced-route-refresh/`](../../../../bench/scale/enhanced-route-refresh/).
Regenerate the receipt rather than treating these compact derivatives as a
replayable raw run.

## Scope

The observed shape is one real Enhanced Route Refresh peer and exactly 100,000
IPv4 unicast routes. There is no 1M run in this package and no 1M result should
be inferred from it.
