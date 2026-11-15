# v0.83.0 release qualification: curated evidence

Supports [the receipt](../../release-qualification-v0830-2026-11.md), which compares candidate `6aeeaa2e088ef3d4e4ed5aff663e22cd3a82b6c4` with v0.82.0 (`608dcaea0902272474bd2a25bcf30bff3dd3153b`).

| File | Contents | SHA-256 |
|---|---|---|
| `reload-stall.json` | Shape, protocol, every point (outcomes, actor turns, completion, cgroup peak, control-window RSS, generation-phase records, rejection text), ABBA means and verdict ratios | `622ebb3b725db2c6b541acf8ffaf6f19123fbbf9ec53a82b9ecd432ed51983fa` |
| `rrharness.json` | Shapes, protocol, per-shape ratios with per-step values, and every cell's cost, cgroup peak and swap readout | `266e7030fa965c4f504b36d0e860b77308f80ab440822562d0d6c4dd67baa840` |
| `criterion-summary.md` | All 162 paired Criterion cells with A/A, threshold, ABBA, confirmation and verdict, plus the candidate-only cells | `28ca9049e40982957850e9dba96073f0fe7b1f7a362d7ed936e678b1325b9ea9` |
| `reloadstall-harness-adapt.diff` | The one-function harness change that reads either name of the reload-outcome label | `5de20b94ce640ecf9adb00bb1c1b97c6239cf392ffcd1b9f58b10a4e06fc6afb` |
| `SHA256SUMS` | Every measured binary: both daemons, both rrharness builds, the shared `reloadstall` harness, and the Criterion executables (A1 and A2 are the two control builds, B the candidate) | `c57e0dc911ce54e287d9182e43e3272fb5c9c0d268074e54ccfaf44637ae42d1` |

The campaign ran locally; there is no hosted run or public raw-log URL. Raw per-run logs, Criterion estimates and scripts remain in the campaign directory outside the published set. The Criterion ratios use the median point estimate; reload-stall memory is the scope's `memory.peak` divided by 1024 (KiB), and rrharness memory is in MiB.
