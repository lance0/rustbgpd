# Load-bearing proof map

## Executed unit-test mutations

All commands used the standalone manifest and the fully qualified test name
with `--exact`. Each mutation was restored before the next run.

| Test | Destructive mutation | Observed red |
|---|---|---|
| `tests::fixed_shape_is_not_silently_shrinkable` | Changed `TABLE_ROUTES` from 400,000 to 399,999 | Failed `left: 399999`, `right: 400000` |
| `tests::source_batches_cover_the_first_and_last_prefix_with_real_encoding` | Replaced the source batch with an empty NLRI vector | Failed `!parsed.announced.is_empty()` |
| `tests::bitmap_counts_unique_routes_without_retaining_prefix_objects` | Removed the unique-count increment when setting a new bitmap bit | Failed `left: 0`, `right: 2` |
| `tests::proc_status_keeps_point_rss_and_high_water_distinct` | Read `VmHWM` from the `VmRSS` row | Failed with parsed `vm_hwm_kib: 700`, expected `900` |
| `tests::metric_parser_requires_exact_name_and_group_label` | Stopped accepting the `{...}` label block in `labelled_samples` | Failed with zero group series, expected one |

After restoration, all five tests pass together; standalone fmt, check, and
Clippy with warnings denied also pass.

## Real-daemon campaign gates

These are precommitted before the loaded campaign. The production break that
makes each class red is explicit:

| Gate class | Production or harness break that makes it red |
|---|---|
| Fixed fleet/table provenance | Change any shape constant or run a fleet size outside 1/10/100; the fixed-shape unit gate or argument parser refuses it |
| Literal-parent and immutable-harness provenance | Compare any commit other than `HEAD^`, or change the benchmark subtree in the candidate; the driver refuses the campaign before building |
| Binary provenance | Build a detached worktree at any commit/tree other than the recorded parent/candidate pair; the worktree assertion fails before its binary digest is accepted |
| Real production transaction | Skip SIGHUP's outbound-prefix-limit Apply; the `apply` histogram count delta is zero instead of exactly one in both variants |
| First-cap materialization | Skip installing either variant's group cap; every finite-limit row is absent after Apply |
| One shared update group | Put any member on a private/different path or include the source; the sole group-series count and per-peer group-id equality fail |
| Withholding | Bypass admission or admit beyond the cap; candidate wire counts exceed 400,000 and blocked counters do not reach 64 per member |
| Recovery | Suppress scheduling/draining recovery; the recovery histogram count stays flat and members remain at 400,000 |
| Every-member delivery | Recover only a subset; at least one member bitmap remains below 400,064 |
| Real wire decode | Use a stubbed encoder or emit malformed/unknown NLRI; non-vacuity, decode-error, or unexpected-prefix checks fail |
| Memory attribution | Omit jemalloc collection or conflate point RSS with high-water RSS; required metric collection or the strict `/proc` parser fails |
| Allocated-memory improvement | Make the candidate materialization delta exceed half the parent delta; the campaign aggregator exits non-zero for that fleet size |

No allocated-memory row is accepted unless every path and behavior gate in its
scenario is green. RSS and timing remain report-only.
