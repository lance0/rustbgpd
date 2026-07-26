# Fanout metrics-handle benchmark artifacts

This directory retains the evidence for
[`../../fanout-metrics-handle-2026-07.md`](../../fanout-metrics-handle-2026-07.md).

- `same-sha-summary.md`: generated six-pair control summary with repository-
  relative evidence paths.
- `before-after-summary.md`: generated six-pair control/target summary with
  repository-relative evidence paths.
- `attempt-medians.tsv`: every retained Criterion median and its 95%
  confidence bounds, without display rounding. `delta_percent` is
  `(head_median_ns / base_median_ns - 1) * 100`.
- `aggregate.tsv`: exact across-attempt means, delta standard deviation, and
  min/max by campaign and fleet size.
- `metadata.txt`: revisions, binary hashes, fleet, boundary, and sanitized
  host/toolchain metadata.
- `red-proof.txt`: the focused destructive test failure and restored result.
- `SHA256SUMS`: integrity hashes for every other retained file.

Full Criterion HTML, sample distributions, compiler logs, and Cargo target
trees are intentionally not checked in. The exact medians and confidence
bounds used by the summary are retained in the TSV; the reproduction commands
rebuild the full Criterion tree.
