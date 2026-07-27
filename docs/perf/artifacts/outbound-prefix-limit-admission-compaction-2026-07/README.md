# Grouped outbound prefix-limit admission compaction artifacts

This compact, sanitized package supports
[`outbound-prefix-limit-admission-compaction-2026-07.md`](../../outbound-prefix-limit-admission-compaction-2026-07.md).
The private raw campaign remains under `target/`. Generated configurations,
daemon and harness logs, Prometheus scrapes, process-status snapshots, RSS
timestamps, process IDs, host identity, command lines, and absolute paths are
intentionally not retained.

## Contents

- `provenance.env` pins the literal parent/candidate relationship, source and
  harness trees, fixed fleet, allocator, build profile, and sanitized host
  shape.
- `binaries.sha256` identifies the measured parent daemon, candidate daemon,
  and shared harness without retaining build paths.
- `campaign.csv` is the exact six-cell summary emitted by the campaign
  aggregator, normalized only from CRLF to LF.
- `comparison.csv` is the exact three-row acceptance comparison emitted by the
  aggregator, normalized only from CRLF to LF.
- `apply-memory.tsv` independently derives every apply and recovered-minus-
  baseline allocator/RSS delta from the six raw summaries.
- `memory-boundaries.tsv` retains every exact allocator and `/proc` phase
  boundary from the six raw summaries.
- `behavior-summary.tsv` records the independently audited assertion totals
  and high-level behavior outcomes. Full per-peer assertion logs remain
  private.
- `SHA256SUMS` binds these retained bytes.

Verify from this directory:

```text
sha256sum -c SHA256SUMS
```

## Claim boundary

The acceptance gate uses only the baseline-to-applied change in
`jemalloc_allocated_bytes`. `active`, `resident`, mapped bytes, point RSS, and
sampled RSS/HWM are separate diagnostics. The campaign contains no
object-lifetime heap profile and does not establish an exact retained-heap
owner delta.

There is one cell per revision and fleet size. The package therefore does not
provide a run-to-run variance estimate or authorize an extrapolation beyond
100 members and 400,000 IPv4 routes.
