# RIB criterion noise-floor artifacts

These are the retained artifacts for
[`rib-criterion-noise-floor-2026-07.md`](../../rib-criterion-noise-floor-2026-07.md).
All four runs are `bench/compare-criterion.sh` comparisons on the primary
measurement host, pinned to core 8 with the `performance` governor, six
alternating A/B attempts each.

Output-directory paths were sanitized to `$OUT` and the host identifier was
removed from the kernel line; the toolchain, CPU model, pinning, and verdict
configuration are retained verbatim.

## Runs

| Directory | Base → head | Purpose |
|---|---|---|
| `runs/control-adj-rib-in-same-sha` | `515659b1` → `515659b1` | Same-SHA floor for `adj_rib_in_insert` |
| `runs/control-pipeline-bulk-same-sha` | `515659b1` → `515659b1` | Same-SHA floor for `rib_pipeline` and `bulk_initial_load` |
| `runs/llgr-tag-guard-isolated` | `12c63b7c` → `5e2ae925` | The isolated LLGR tag-lookup guard, the receipt's one CPU claim |
| `runs/v0.60.0-to-head` | `7d9313e9` → `515659b1` | Release-to-head sweep; source of the unattributed `rib_pipeline` observation |

## Contents

Each run directory holds:

- `summary.md` — the comparison summary as the tool produced it: per-benchmark
  base and head medians, mean delta, across-attempt stddev, min..max, the
  last-run 95% confidence interval, and the tool's own verdict. The receipt's
  tables are read from these.
- `metadata.txt` — base and head refs and resolved SHAs, package, bench target,
  filter, core, attempt count, verdict thresholds, governor and taskset state,
  kernel, `rustc`/`cargo` versions, and CPU model.
- `estimates.tsv` — a derived per-attempt table of the Criterion point
  estimates behind every delta in `summary.md`: one row per
  (benchmark, attempt, base/head) with the median, mean, and the mean's 95%
  confidence bounds in nanoseconds.

The tool's own verdict column is advisory and uses a fixed 3% / 10%-stddev
rule; it is not the receipt's standard. The receipt reads each delta against
the same-SHA control for that exact benchmark and size, which is why one row
the tool labels `improvement` (`adj_rib_in_insert/500000`) is published as
suggestive data rather than a claim.

`SHA256SUMS` covers the retained, sanitized bytes.
