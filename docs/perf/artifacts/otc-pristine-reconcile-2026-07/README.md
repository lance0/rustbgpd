# Pristine OTC reconciliation benchmark artifacts

This directory retains the evidence for
[`../../otc-pristine-reconcile-2026-07.md`](../../otc-pristine-reconcile-2026-07.md).

- `same-sha-summary.md`: sanitized six-pair identical-binary control summary.
- `before-after-summary.md`: sanitized six-pair immediate-parent A/B summary.
- `attempt-medians.tsv`: every Criterion median and 95% confidence bound,
  without display rounding.
- `aggregate.tsv`: exact across-attempt means, delta standard deviation, and
  min/max by campaign and fleet size.
- `metadata.txt`: revisions, binary hashes, fleet, boundary, and sanitized
  host/toolchain metadata.
- `commands.txt`: exact reproduction commands.
- `red-proof.txt`: focused destructive-test failure and restored result.
- `SHA256SUMS`: integrity hashes for every other retained file.

Full Criterion HTML, sample distributions, compiler logs, and Cargo target
trees are intentionally not checked in. The exact inputs to every published
number are retained in the TSV.
