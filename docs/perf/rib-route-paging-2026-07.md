# RIB route-paging materialization receipt — 2026-07

LAN-391 identified two independent costs in bounded unicast route listings:
every page scans its complete scope, and a grouped advertised-route page also
cloned the complete member view before that scan. This first tranche measures
both costs and removes only the grouped full-view clone. It deliberately does
not add an always-on ordered index or change the opaque cursor contract.

No raw traversal artifact is retained yet. This document records the corrected
methodology and landing gates; the paired CSV will be added only after the
pinned matrix completes on an otherwise idle host.

## Pinned comparison

| Variant | Commit | Behavior |
|---|---|---|
| Baseline | `5f6dd2960933c356eeda53625caf7f8b91f77a7c` | Committed rewritten manager-level benchmark baseline, with repeated scan + grouped full materialization |
| Borrowed grouped view | `ef0b6260313638e126d57c847f7990da991faa16` | The grouped page scans the filtered group iterator directly; legacy full-snapshot/refresh callers still materialize |

The paired driver accepts only the full baseline and candidate commit IDs in
the table above. It overlays one canonical benchmark and bench-support source
byte-for-byte into detached baseline and optimized worktrees, records their
combined SHA-256, archives both sources plus the comparison driver and both
commits' production paging sources under a verified `SHA256SUMS` manifest, and
refuses source drift. The normalized diff of the two production paging files
must match SHA-256
`558cf2ebc9101ca722b3d733a4dc2f4a91859a08e16ab6c7258844e99930ec87`.
Each scope/route/page/repetition cell runs in a fresh process.
Pair order alternates between baseline-first and optimized-first across
repetitions so allocator, cache, and thermal history do not always favor one
side. Both refs must resolve to the pinned commits and the baseline must be an
ancestor of the optimized commit. Anchored executable-line and iterator-body
guards require the materialized call only at the baseline and the borrowed
grouped view only at the head. Exact commit and production-diff pins reject
extra changes even inside an allowed implementation file; the changed-file
allowlist remains a secondary audit fence. After the canonical overlays, every
tracked Cargo manifest and lockfile, build script, Cargo config, and optional
Rust toolchain selector must be byte-identical between worktrees. Those inputs
include the workspace profiles in the root `Cargo.toml` and the RIB benchmark
declaration in `crates/rib/Cargo.toml`. Uncommitted production changes are
deliberately excluded. The driver also refuses a nonempty output directory so
retained evidence cannot mix runs.

Each process constructs a real `RibManager`, two identical RR-client update-
group members, and a 100k- or 400k-route group table outside the timed region.
Every sixteenth route is sourced by the queried member, so member-specific
split horizon makes the grouped-advertised fixture observably distinct from the
best-route control. The process traverses one scope from an empty cursor to
completion at page size 100 or 1,000. Every page validates the current total,
row cap, strict key order, and cursor progress; the traversal emits a stable
ordered-route-key checksum. The driver requires baseline and optimized rows,
page counts, and checksums to match before retaining the matrix.

Per-page timings include oneshot construction, the synchronous production
handler call, and immediate reply retrieval. They are a conservative upper-
bound proxy for the handler's manager-task occupancy, not actor scheduling or
end-to-end gRPC latency. Complete-traversal timing also includes the small
harness-side ordering/checksum loop.

The existing x86-64 memory profile pins `size_of::<Route>()` at 120 bytes. On
the old path, materializing a 400k grouped view clones roughly 48 MB of `Route`
payload into a temporary `Vec` per page, before capacity rounding and allocator
bookkeeping. Repeating that operation 4,000 times at page size 100 implies
roughly 192 GB of route-struct copy volume; 400 pages at page size 1,000 imply
roughly 19.2 GB. These are structural estimates, not measured allocation-byte
or memory-bandwidth counters. The borrowed view adds no persistent index or
per-route memory and removes that temporary full-view materialization while
leaving the repeated table scan for a measured continuation tranche.

## Planned host and command

| Field | Value |
|---|---|
| Host | `lancebox`, to be otherwise idle during retained samples |
| Kernel | Linux `6.17.0-35-generic` x86_64 |
| CPU | AMD Ryzen Threadripper 7970X 32-Cores, 64 logical CPUs, one NUMA node |
| Pinned core | `5` |
| Governor | `performance` (`amd-pstate-epp`) |
| Rust | `rustc 1.97.0 (2d8144b78 2026-07-07)`, LLVM 22.1.6 |
| Repetitions | two paired complete traversals per matrix cell, counterbalanced by execution order; each traversal contributes 100–4,000 handler-boundary samples before split-horizon row reduction |

```bash
bench/compare-route-paging.sh \
  --base 5f6dd2960933c356eeda53625caf7f8b91f77a7c \
  --head ef0b6260313638e126d57c847f7990da991faa16 \
  --routes 100000,400000 \
  --page-sizes 100,1000 \
  --repetitions 2 \
  --core 5
```

The driver records the exact refs, pinned commits, normalized production-diff
hash, canonical harness hash, individual source hashes, compile-input manifest
hash, CPU pinning, pair order, and every one-row-per-process raw output under
`raw/` beside the combined CSV. The exact harness, bench-support module,
driver, baseline/optimized production paging sources, and common Cargo/build
inputs used for the run are retained under `measurement-sources/` with checked
hash manifests.

## Results

| Scope | Routes | Page | Baseline complete | Borrowed complete | Speedup | Baseline p99 | Borrowed p99 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Best control | 100,000 | 100 | TBD | TBD | TBD | TBD | TBD |
| Best control | 100,000 | 1,000 | TBD | TBD | TBD | TBD | TBD |
| Best control | 400,000 | 100 | TBD | TBD | TBD | TBD | TBD |
| Best control | 400,000 | 1,000 | TBD | TBD | TBD | TBD | TBD |
| Grouped advertised | 100,000 | 100 | TBD | TBD | TBD | TBD | TBD |
| Grouped advertised | 100,000 | 1,000 | TBD | TBD | TBD | TBD | TBD |
| Grouped advertised | 400,000 | 100 | TBD | TBD | TBD | TBD | TBD |
| Grouped advertised | 400,000 | 1,000 | TBD | TBD | TBD | TBD | TBD |

The tranche landing gate is at least 1.25x faster grouped 400k complete
traversal at both page sizes, no grouped p99 regression, and no more than 3%
regression in the best control or existing route-churn benchmark. Below 1.10x
at either 400k grouped shape is a stop condition.

## Correctness fence

- Grouped pages match the legacy full snapshot at page sizes 1, 100, and
  1,000, including split-horizon removal and the member-local exact-export
  rejection overlay.
- A mutation between pages cannot repeat a key at or behind the cursor. A
  withdrawal ahead disappears, an insertion ahead remains eligible, and an
  insertion behind the cursor is intentionally left to the live change
  stream rather than backfilled.
- Filtering, cursor identity `(prefix, source peer, path_id)`, current-table
  totals, `has_more`, the 1,000-row cap, and cancellation-before-scan are
  unchanged.

## Decision

TBD after the pinned matrix. This tranche cannot close LAN-391 unless the full
10x complete-traversal and at-most-5ms handler-boundary p99 proxy gates
unexpectedly pass. The remaining repeated full-table scan is measured here so
a later continuation can weigh its memory and ingest cost against an ordered
index or equivalent resumable continuation.
