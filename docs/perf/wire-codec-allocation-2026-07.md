# Wire-codec allocation receipt (July 2026)

## Decision

Ship the two narrow wire-codec changes. Reusing one path-attribute value
scratch per public encoder call improves the measured `attr_encode/rich/11`
fixture by 28.34%. Replacing two temporary validation `HashSet`s with one
stack-resident 256-entry presence table improves the measured
`validate_update` fixture by 90.57%. All six target attempts favor each
change, while the matching six-pair same-SHA controls straddle zero.

These are microbenchmark and allocation-request results for two exact fixtures,
not whole-daemon CPU, convergence, or memory claims. The timing suite uses the
ordinary Criterion build with no allocation probe. The separate diagnostic
build wraps Rust's `System` allocator and counts successful `GlobalAlloc`
`alloc`, `alloc_zeroed`, and `realloc` requests only while the public codec call
is active.

## Source stack

The campaign measured three consecutive commits:

- H `643900e76d1101a50974dcdac1c1e2b36c7991cc`: allocation diagnostic
  harness, immediately after `e68e8e5b3253f90773732ddd0c481011a1a5514a`;
- S `ed3b7a72fde7d69eff51d334e7feb65d698bae60`: reuse one
  invocation-local path-attribute value scratch; and
- P `f95d894069216662c33e9c109e2891d12fb8350f`: reuse the validation
  presence table for duplicate and mandatory-attribute checks.

H keeps the normal Criterion target probe-free with a feature gate. Under
`codec-allocation-diagnostics`, the same bench target becomes a deterministic
diagnostic executable. Fixture construction, the caller's 1,024-byte output
reservation, round-trip checks, and receipt formatting are outside the
measurement window. The window contains exactly one public codec call per
operation.

S does not make path-attribute encoding allocation-free. It replaces the
per-attribute value `Vec` with one scratch `Vec` per
`encode_path_attributes()` invocation, clearing and reusing its capacity
between attributes. Scratch growth and shape-specific side storage such as
Large-Community deduplication remain. Compatibility attributes retain their
separate bounded buffers.

P replaces the duplicate-type `HashSet` and mandatory-presence `HashSet` with
one `[bool; 256]`, indexed by the full `u8` path-attribute type space. It does
not alter validation ordering, error disposition, or the other validation
passes.

## Fixtures and measured boundary

Both diagnostics run 10,000 operations:

| Fixture | Shape | Wire length | Digest | Measured public call |
|---|---:|---:|---|---|
| `attr_encode/rich/11` | 11 attributes | 631 B | `fnv1a64:96bb16b5bb7cbf8b` | `encode_path_attributes` |
| `validate_update` | 6 attributes | 53 B | `fnv1a64:1fbab958f3d35d0b` | `validate_update_attributes` |

The rich fixture includes 128 standard communities, which force an
extended-length attribute header, plus the other rich-path shapes in the
existing Criterion suite. The validation fixture is the existing valid
typical six-attribute eBGP shape: ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF, MED,
and COMMUNITIES.

The diagnostic's `requested_bytes` is the requested layout size for successful
`alloc` / `alloc_zeroed` calls plus the requested new size for successful
`realloc` calls. It is not RSS, jemalloc accounting, retained, live, or peak
heap, allocator overhead, deallocation volume, or whole-daemon memory. The
zero-allocation result below applies only to the exact valid six-attribute
fixture; it is not a claim that every validation input or error path is
allocation-free.

## Timing result

Each comparison used `bench/compare-criterion.sh`: CPU 8 pinned, the
`performance` governor, normal 3-second Criterion warmup, 5-second measurement,
100 samples, and six alternating pairs (odd base-first, even head-first).

| Comparison | Base mean | Head mean | Mean delta | Stddev | Six-pair envelope | Last-pair 95% CI | Verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| H vs H, `attr_encode/rich/11` | 484.9 ns | 486.7 ns | +0.39% | 2.28% | -3.54%..+2.73% | -0.91%..-0.21% | noise |
| H vs S, `attr_encode/rich/11` | 492.1 ns | 352.6 ns | **-28.34%** | 0.88% | -29.39%..-27.01% | -29.94%..-28.71% | improvement |
| S vs S, `validate_update` | 156.3 ns | 156.2 ns | -0.06% | 0.35% | -0.74%..+0.30% | -0.10%..+0.16% | noise |
| S vs P, `validate_update` | 156.2 ns | 14.7 ns | **-90.57%** | 0.58% | -90.87%..-89.42% | -90.85%..-90.82% | improvement |

The comparison driver's “base median (mean)” and “head median (mean)” columns
are the means of the six per-attempt medians. The unrounded per-attempt median
estimates and their raw Criterion samples remain in the archive. The
same-SHA controls are benchmark-specific envelopes, not a transferable host
noise percentage.

## Allocation-request result

The primary H, S, and P rows are byte-for-byte repeatable against H-a/H-b and
S-a/S-b respectively. S-control is a separately rebuilt S negative control.

| Revision | Fixture | Operations | Allocation requests | Requested bytes | Requests/op | Requested bytes/op |
|---|---|---:|---:|---:|---:|---:|
| H | `attr_encode/rich/11` | 10,000 | 210,000 | 12,280,000 | 21 | 1,228 |
| S | `attr_encode/rich/11` | 10,000 | 80,000 | 10,840,000 | 8 | 1,084 |
| P | `attr_encode/rich/11` | 10,000 | 80,000 | 10,840,000 | 8 | 1,084 |
| H | `validate_update` | 10,000 | 20,000 | 960,000 | 2 | 96 |
| S | `validate_update` | 10,000 | 20,000 | 960,000 | 2 | 96 |
| P | `validate_update` | 10,000 | 0 | 0 | 0 | 0 |

For this rich encoder fixture, S removes 130,000 of 210,000 requests
(61.90%) and 1,440,000 of 12,280,000 requested bytes (11.73%). P leaves that
fixture exactly unchanged. For this valid validation fixture, P removes all
20,000 requests and 960,000 requested bytes; S leaves it exactly unchanged.
Those two unchanged paths are negative controls, not inferred results.

## Correctness fences and red proofs

Five focused production tests are load-bearing:

- replacing the invocation scratch with a fresh per-attribute `Vec` makes
  `encoder_clears_and_reuses_value_scratch` red on pointer/capacity reuse;
- ignoring an opaque attribute's extended-length flag makes
  `encoder_preserves_opaque_extended_length_header` red on exact bytes;
- clearing previously emitted output before an AS_SET error makes
  `encoder_retains_partial_output_before_as_set_error` red;
- folding the 256-entry presence table so type 255 aliases another type makes
  `duplicate_scan_returns_full_non_dropping_presence_table` red; and
- moving the duplicate scan behind other attribute checks makes
  `duplicate_error_precedes_other_attribute_errors` red.

The diagnostic harness also has a destructive proof: changing the emitted
operation count from 10,000 to 9,999 makes the receipt's `jq` gate reject both
rows. The retained allocation gates additionally require identical fixtures,
strictly lower H-to-S encoder requests and requested bytes, exact-zero S-to-P
validation requests and requested bytes, and exact equality on both negative
controls. Exact commands and outcomes are in
[`red-proofs.md`](artifacts/wire-codec-allocation-2026-07/red-proofs.md).

## Scope and limits

The timing result covers two public synchronous codec functions on one CPU and
one toolchain. It excludes UPDATE framing, NLRI, policy, RIB work, fanout,
session writers, sockets, and network I/O. No fleet shape or daemon was run, so
there is no peer-count, route-count, CPU-utilization, or convergence claim.

The allocation diagnostic uses atomic counters around `System`, deliberately
separate from the timing build. It counts successful request events and
requested bytes, not allocator behavior after those requests. Output capacity
is preallocated to isolate function-internal temporary storage; a caller that
lets the output `Vec` grow will incur additional allocation requests outside
this receipt's intended question.

The compact, sanitized evidence archive and browsable tables are under
[`artifacts/wire-codec-allocation-2026-07/`](artifacts/wire-codec-allocation-2026-07/).
The archive retains all 48 timing logs, 48 estimate files, 48 sample files,
four timing metadata/summary/validation sets, eight allocation
diagnostic/metadata/stderr sets, the campaign gates and completion marker, and
the combined red-proof receipt, plus its internal checksum manifest. Build
trees, worktrees, binaries, Criterion HTML/SVG reports, `new` baselines, and
duplicated driver logs are intentionally excluded.

## Reproduction

Run the four pinned comparisons and the allocation diagnostics exactly as
listed in
[`commands.txt`](artifacts/wire-codec-allocation-2026-07/commands.txt).
The artifact README documents archive extraction, internal and external hash
verification, member counts, safety checks, and the deterministic tar recipe.
