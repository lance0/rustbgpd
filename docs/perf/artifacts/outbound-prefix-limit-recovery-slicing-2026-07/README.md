# Outbound prefix-limit recovery slicing artifacts

This compact, sanitized package supports
[`outbound-prefix-limit-recovery-slicing-2026-07.md`](../../outbound-prefix-limit-recovery-slicing-2026-07.md).
The private raw receipt stays under `target/outbound-prefix-limit-scale/`.
Daemon logs, raw Prometheus scrapes, generated configuration, process IDs,
timestamps, command lines, host names, and paths are intentionally excluded.

## Contents

- `provenance.env` identifies the measured revision, fleet, route shape, and
  control/candidate arrangement without retaining host-specific metadata.
- `binaries.sha256` identifies the measured daemon and harness under
  repository-relative labels.
- `campaign.csv` is the six-cell summary emitted by the harness.
- `SHA256SUMS` binds these retained bytes.

Verify from this directory:

```text
sha256sum -c SHA256SUMS
```

The campaign used one source, 400,000 IPv4 unicast routes, and 1, 10, or 100
homogeneous members in one update group. Each candidate withheld 64 routes,
then removed the limit; the same-SHA controls performed the corresponding
unlimited reloads. This is one fixed campaign, not a run-to-run variance
estimate. It measures actor-occupancy and latency isolation from slicing; it
does not claim reduced total replay work.
