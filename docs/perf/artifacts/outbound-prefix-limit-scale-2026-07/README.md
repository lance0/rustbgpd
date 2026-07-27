# Grouped outbound prefix-limit scale artifacts

This is the compact, sanitized evidence for
[`outbound-prefix-limit-scale-2026-07.md`](../../outbound-prefix-limit-scale-2026-07.md).
The full raw receipt remains private under
`target/outbound-prefix-limit-scale/`; daemon logs, raw Prometheus scrapes,
generated configs, process identifiers, timestamps, commands, and host paths
are intentionally not retained here.

## Contents

- `provenance.env` pins the measured commit/tree, production base, real daemon
  profile, allocator, fixed fleet, and toolchain.
- `binaries.sha256` records the measured binaries by repository-relative
  label.
- `campaign.csv` is the immutable six-cell summary emitted by the harness.
- `paired-results.tsv` records the adjacent same-SHA control subtraction used
  by the report.
- `memory-boundaries.tsv` retains each exact jemalloc and `/proc` phase
  boundary.
- `sampled-peaks.tsv` records the maxima from the independent one-second RSS
  sampler.
- `SHA256SUMS` binds these retained bytes.

Verify from this directory:

```text
sha256sum -c SHA256SUMS
```

The source driver is
[`bench/scale/outbound-prefix-limit-scale/`](../../../../bench/scale/outbound-prefix-limit-scale/).
Regenerate the receipt rather than treating these compact derivatives as a
replayable raw run.

## Scope and variance

The observed shape is one real source, exactly 400,000 IPv4 unicast routes,
and paired unlimited/limited fleets of 1, 10, and 100 members sharing exactly
one update group. Each candidate withholds 64 additional routes and then
recovers them after limit removal.

There is one cell per variant and fleet size, so this package does not provide
a statistical run-to-run variance estimate. `paired-results.tsv` subtracts the
immediately adjacent unlimited same-SHA control; raw boundary values remain in
`campaign.csv` and `memory-boundaries.tsv`.
