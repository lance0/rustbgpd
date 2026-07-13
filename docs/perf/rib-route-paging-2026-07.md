# RIB route-paging materialization receipt — 2026-07

LAN-391 identified two independent costs in bounded unicast route listings:
every page scans its complete scope, and a grouped advertised-route page also
cloned the complete member view before that scan. This first tranche measures
both costs and removes only the grouped full-view clone. It deliberately does
not add an always-on ordered index or change the opaque cursor contract.

The complete retained matrix is checked in under
[`artifacts/rib-route-paging-2026-07/`](artifacts/rib-route-paging-2026-07/).
The combined CSV, metadata, and cell-by-cell host preflights are unpacked for
review. The compressed exact driver output carries its original top-level
`SHA256SUMS` over all 64 raw one-process rows, build and execution logs,
metadata, and the nested exact-source manifest. The separate route-churn
control summary is retained beside it as
[`rib-route-paging-2026-07-route-churn-control.md`](artifacts/rib-route-paging-2026-07-route-churn-control.md).

## Pinned comparison

| Variant | Commit | Behavior |
|---|---|---|
| Baseline | `50399dac696507a827480be4a9dcfef49e1682b3` | Committed rewritten manager-level benchmark baseline, with repeated scan + grouped full materialization |
| Borrowed grouped view | `d12cbaae37a9779ccc58617189253450b57c8fa4` | The grouped page scans the filtered group iterator directly; legacy full-snapshot/refresh callers still materialize |

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

A retained run also requires a clean invoking checkout and acquires the shared
`${RUSTBGPD_HOST_LOCK:-$HOME/.local/state/rustbgpd-host.lock}` nonblockingly
before it creates either build. Contention exits 75. Both pinned worktrees are
prebuilt with `cargo bench --locked --no-run` into separate target directories,
one Cargo job at a time, and the two build logs are retained. Immediately before
each fresh-process cell, the driver directly launches the resolved prebuilt
executable and records its SHA-256; Cargo cannot rebuild after the idle check.
The driver polls for at most 30 seconds until the one-minute load is below 2.0,
no other `cargo`, `rustc`, `rrharness`, or `route_paging` process is visible,
and pinned CPU 5 reports the `performance` governor. It writes every attempt's
UTC, load, governor, process count/snapshot, and pass/wait state to
`cell-preflight.tsv`; a timeout exits 75 rather than producing a partial result
that looks authoritative. The cooperative host lock and point-in-time
preflight reduce known interference but do not prove whole-host isolation.

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

## Measured host and command

| Field | Value |
|---|---|
| Host | `<BENCH_HOST>`; cooperating rustbgpd soak/bench work excluded by the shared host lock |
| Kernel | Linux `6.17.0-35-generic` x86_64 |
| CPU | AMD Ryzen Threadripper 7970X 32-Cores, 64 logical CPUs, one NUMA node |
| Pinned core | `5` |
| Governor | `performance` (`amd-pstate-epp`) |
| Rust | `rustc 1.97.0 (2d8144b78 2026-07-07)`, LLVM 22.1.6 |
| Repetitions | four paired complete traversals per matrix cell, counterbalanced by execution order; each traversal contributes 100–4,000 handler-boundary samples before split-horizon row reduction |

```bash
bench/compare-route-paging.sh \
  --base 50399dac696507a827480be4a9dcfef49e1682b3 \
  --head d12cbaae37a9779ccc58617189253450b57c8fa4 \
  --routes 100000,400000 \
  --page-sizes 100,1000 \
  --repetitions 4 \
  --core 5
```

The driver records the exact refs, pinned commits, normalized production-diff
hash, canonical harness hash, individual source hashes, compile-input manifest
hash, invoking HEAD and dirty state, evidence class, lock policy/digest, idle thresholds,
CPU pinning, pair order, and every one-row-per-process raw output under `raw/`
beside the combined CSV. It also retains the separate baseline/optimized build
logs and per-cell preflight TSV. The exact harness, bench-support module,
driver, invoking status snapshot, baseline/optimized production paging sources,
and common Cargo/build inputs used for the run are retained under
`measurement-sources/` with checked hash manifests. `--no-taskset` is explicitly
mechanics-only; a dirty checkout requires the additional
`--allow-dirty-mechanics` override and cannot produce retained evidence.
The lock record does not retain the host username or absolute home directory.
A successful matrix finishes by checking a top-level `SHA256SUMS` over the
CSVs, build/execution logs, per-cell preflight, metadata, and nested source
manifest.

## Results

| Scope | Routes | Page | Baseline complete | Borrowed complete | Speedup | Baseline p99 | Borrowed p99 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Best control | 100,000 | 100 | 707.516 ms | 718.700 ms | 0.984x | 0.811 ms | 0.864 ms |
| Best control | 100,000 | 1,000 | 105.553 ms | 106.261 ms | 0.993x | 1.574 ms | 1.600 ms |
| Best control | 400,000 | 100 | 10,914.062 ms | 10,990.322 ms | 0.993x | 3.281 ms | 3.203 ms |
| Best control | 400,000 | 1,000 | 1,330.935 ms | 1,360.392 ms | 0.978x | 3.785 ms | 3.893 ms |
| Grouped advertised | 100,000 | 100 | 2,072.276 ms | 678.350 ms | 3.055x | 2.529 ms | 0.919 ms |
| Grouped advertised | 100,000 | 1,000 | 224.267 ms | 97.561 ms | 2.299x | 3.252 ms | 1.224 ms |
| Grouped advertised | 400,000 | 100 | 98,644.701 ms | 10,558.903 ms | 9.342x | 29.410 ms | 3.518 ms |
| Grouped advertised | 400,000 | 1,000 | 10,021.423 ms | 1,239.376 ms | 8.086x | 29.980 ms | 3.994 ms |

The tranche landing gate is at least 1.25x faster grouped 400k complete
traversal at both page sizes, no grouped p99 regression, and no more than 3%
regression in the best control or existing route-churn benchmark. Below 1.10x
at either 400k grouped shape is a stop condition.

All complete-traversal values and page p99 values above are medians of the
four counterbalanced repetitions. The grouped landing gates pass with
9.342x/8.086x complete-traversal speedups and 88.04%/86.68% lower p99 at 400k.
Best-control complete traversal moved by +0.67% to +2.21%, within the 3% gate.
The 100k/page-100 best-control p99 median moved from 0.811 ms to 0.864 ms; that
unchanged code path's four paired deltas were noisy rather than one-directional
and its complete traversal remained +1.58%. The independent four-attempt
`route_churn/10k_base_1k_churn` control measured -1.17% mean with a
`noise` verdict (-3.48%..+0.02%).

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

Land the borrowed grouped-view tranche. It removes the dominant temporary
full-view clone without changing the cursor contract or adding persistent
memory, clears every tranche gate, and leaves the best-scope control within the
declared complete-traversal envelope.

Do not close LAN-391. The 400k grouped p99 proxy is now below 5 ms, but the
complete-traversal speedups are 9.342x and 8.086x rather than the issue's full
10x gate. The residual cost is the measured repeated full-table scan shared by
grouped and best scopes. A continuation should evaluate an ordered index or
equivalent resumable continuation against its ingest and memory cost; it must
retain the opaque cursor and mutation semantics fenced above.
