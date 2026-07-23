# MRT snapshot allocation control artifacts

Status: **standalone control retained and checksummed**.

This directory holds the sanitized, exact-revision harness control for
[`../../mrt-snapshot-allocation-2026-07.md`](../../mrt-snapshot-allocation-2026-07.md).
The quiet-host run at `d2872d0cf9648ffe0be764eab712f5d8933d021e`
completed the full two-shape protocol and passed its path, semantic-reader,
deterministic-byte, noise, matrix, allocator-equation, and privacy gates.

## Retained result

| Shape | Timing median | CV | Output bytes | Allocation calls | Requested bytes | Growth misses | Peak overhead bytes |
|-------|--------------:|---:|-------------:|-----------------:|----------------:|--------------:|--------------------:|
| `ixp-700` | 458,231,764 ns | 0.359% | 33,642,720 | 12,815,613 | 114,530,702,750,252 | 6,809,607 | 3,262,777 |
| `dual-full-feed` | 749,038,496 ns | 0.367% | 58,058,046 | 22,422,420 | 302,204,009,708,208 | 10,410,415 | 6,406,665 |

The exact timing ranges are 457,056,262..462,023,035 ns and
747,046,999..754,241,036 ns. CV is population standard deviation divided by
the mean. `validation.txt` retains the timing and diagnostic UTC preflights,
load, governor, affinity, no-competing-work result, closed-matrix validation,
and seven isolated mutation-red results. Requested bytes is a cumulative
allocator request sum, not RSS or simultaneous live memory. The control
demonstrates enough allocation churn to justify a separately measured
bounded-growth candidate; it does not claim that candidate's speedup in
advance.

## `control.jsonl` record contract

The file is newline-delimited JSON containing exactly 16 sample objects and no
metadata object. Every row has this top-level field inventory:

- `schema_version`: currently `1`;
- `variant`: `"control"`;
- `commit`: the exact 40-character lowercase hexadecimal harness revision;
- `mode`: `"timing"` or `"diagnostic"`;
- `shape`: `"ixp-700"` or `"dual-full-feed"`;
- `smoke`: `false` in the retained control;
- `warmup_count`: `2`;
- `sample_index`: 1 through 7 for timing, 1 for diagnostic;
- `path_count`, `prefix_count`, and `source_count`;
- `output_len_bytes`, `output_capacity_bytes`, and `decoded_entry_count`;
- `elapsed_ns`: an integer for timing and null for diagnostic;
- `raw_sha256` and `semantic_sha256`: lowercase SHA-256 hex digests in both
  modes;
- `allocator`: null for timing and an object for diagnostic; and
- `growth`: null for timing and an object for diagnostic.

The diagnostic `allocator` object contains `alloc_calls`,
`alloc_zeroed_calls`, `realloc_calls`, `dealloc_calls`, `requested_bytes`,
`baseline_live_requested_bytes`, `final_live_requested_bytes`,
`peak_live_requested_bytes`, `peak_live_delta_bytes`, and
`peak_live_overhead_bytes`. The delta is the tracked peak during the encode
window minus the tracked-live baseline at the start of that window; overhead
then subtracts the retained output length from the delta. "Total allocator
calls" in the parent acceptance rules means `alloc_calls +
alloc_zeroed_calls + realloc_calls`; deallocation is a lifecycle/accounting
check.

The diagnostic `growth` object contains only
`top_level_unbounded_capacity_misses`. Child-buffer and bounded warm-buffer
exclusion are guarded by codec unit tests, not reported as per-run counters.

All counts, sizes, indices, and durations are finite non-negative integers. The
control matrix contains seven retained timing samples and one retained
diagnostic sample for each shape. Its two warmups per shape are executed but not
retained as rows. Diagnostic timing is never used as performance evidence.

Start the full campaign with an absent `control.jsonl`. The timing command
creates/appends 14 rows and the diagnostic command appends two; validate the
exact 16-row matrix before creating the checksum. Publication must reject
missing, duplicate, extra, or malformed rows; path/source drift;
decoded-content mismatch; reader failure; an absent top-level growth signal;
non-deterministic diagnostic bytes; or privacy-sensitive data. The validator or
retained command log that enforces those conditions must itself carry isolated
revert-red proof before results are committed.

## Integrity and privacy

`SHA256SUMS` covers the final sanitized `control.jsonl` and `validation.txt`
using relative paths. Verify it from this directory:

```bash
sha256sum -c SHA256SUMS
```

Never publish hostnames, usernames, home/worktree/target paths, lock paths,
PIDs, raw process arguments, credentials, remote URLs with embedded identity,
or environment dumps. Record tool and executable versions, CPU model/count,
kernel, memory, governor, affinity, load, and safe process basenames only.

The interpretation and predeclared GO/HOLD thresholds live in the parent
receipt. Validation rejected seven isolated in-memory mutations: a missing
matrix row, extra schema field, fleet-count drift, broken allocator peak delta,
missing growth signal, timing CV above 5%, and an injected hostname. The final
unmutated artifact then passed and was checksummed.

This standalone control is feasibility evidence, not a future candidate's
timing comparator. A candidate campaign must rerun its immediate-parent control
under the documented four-block ABBA order and retain a separate comparison
artifact/schema extension.
