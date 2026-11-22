# v0.84.0 release qualification: curated evidence

Supports [the receipt](../../release-qualification-v0840-2026-11.md), which compares candidate `5f5ca6a312d1bdf7094440ae363495574a6ddecc` with v0.83.0 (`3686a4b67a555db16fa9a3825867f77d0cedb5b3`).

| File | Contents | SHA-256 |
|---|---|---|
| `reload-stall.json` | Shape, protocol, every point (outcomes, actor turns, completion, cgroup peak, generation-phase records), ABBA means and verdict ratios | `723bc86187d860e6d2e782ff5d25cdfb82367e3ee369c0fdf4d828e75cd00720` |
| `rrharness.json` | Shapes, protocol, per-shape ratios with per-step values, and every cell's cost, cgroup peak and swap readout | `614539b82f6457ff8e5b1338be820e90f5fbe41ab3e9f13c6c4c2c2749900192` |
| `criterion-summary.md` | All 166 paired Criterion cells with A/A, threshold, ABBA, confirmation and verdict | `55bf3ec1314f38b61cd6535bc0dea86e488c0c2f4b657795b411b96e97807d7b` |
| `SHA256SUMS` | Every measured binary: both daemons, both rrharness builds, the shared `reloadstall` harness, and the Criterion executables (A1 and A2 are the two control builds, B the candidate) | `05530c128aea430263493908dbdb29fe9ea74f8c58f02a31749d8738114e5f79` |

The 2026-11-22 v0.84.0 qualification campaign ran locally; there is no hosted run or public raw-log URL. It retains the per-run logs, Criterion estimates, the frozen bars and the summarizer scripts outside the published set, so the commit SHAs above and the `SHA256SUMS` in this directory identify what ran. The Criterion ratios use the median point estimate; reload-stall memory is the scope's `memory.peak` divided by 1024 (KiB), and rrharness memory is in MiB.
