# Benchmarks

Micro-benchmarks using [Criterion](https://github.com/bheisler/criterion.rs) 0.8,
compiled with `--release` (LTO, codegen-units=1). Numbers below are meant
for relative comparison and regression tracking, not absolute guarantees.

**Last measured: 2026-05-29 (current `main`, shipping as v0.32.0)**

| Field | Value |
|-------|-------|
| Hardware | AMD Ryzen Threadripper 7970X (32 cores / 64 threads) |
| Kernel | Linux 6.17.0-20-generic |
| rustc | 1.95.0 (2026-04-14) |
| Criterion | 0.8 |
| Measurement state | **RIB Operations** re-measured pinned (`performance` governor, `taskset -c 8`, 4 alternating A/B attempts) comparing the `v0.31.0` tag to current `main`; absolute numbers below are the `main` medians |

The RIB Operations numbers below are the current-`main` medians from a pinned
`v0.31.0 → main` comparison run (the cumulative effect of the scale/memory
sprint: the `SmallVec` prefix index, `FxHash` route maps, and multi-chunk
distribution coalescing). Each row's per-benchmark delta versus `v0.31.0` is
noted inline. The v0.32.0 inbound-UPDATE changes (single-pass attribute
extraction + attribute-`Arc` sharing) are transport-crate only, so the RIB
criterion and allocator-tracked `memory_profile` numbers are **unchanged**
(re-confirmed on current `main`) and stand as-is. The **end-to-end bgperf2
cross-stack comparison was fully re-run on current `main`** for v0.32.0 — all
three daemons (rustbgpd, BIRD, GoBGP) on the same host — replacing the prior
v0.4.2 snapshot. See *End-to-End System Benchmarks* below.

## Secondary measurement environment — self-hosted VPS bench runner

The `Criterion Bench Compare` workflow (`.github/workflows/bench.yml`)
runs on a dedicated VPS registered as a `[self-hosted, rustbgpd-bench]`
runner. Numbers from CI dispatches are produced in this environment,
not the primary host described above. Two environments give us A/B
deltas on PRs without coupling them to a single machine.

| Field | Value |
|-------|-------|
| Hardware | Virtualized x86_64 guest on bare-metal Intel host (4 vCPU, ~3.8 GiB RAM, 2 GiB swap, 30 GB disk) |
| Kernel | Linux 6.8.0-117-generic |
| OS | Ubuntu 24.04.4 LTS |
| rustc | 1.95.0 (matches the primary host) |
| Criterion | 0.8 |
| Pinning | `taskset -c <core>` (set by the workflow input; default core 0) |
| cpufreq governor | **Not available** — virtualized CPU does not expose `cpufreq` sysfs, so `--require-performance` is set to `false` for runs on this host |

**Empirical noise floor: ~11% spread.** Five sequential pinned runs at
the same `main` SHA (2026-05-28 calibration on `adj_rib_in_insert/10000`)
produced medians of 8.232 ms, 8.446 ms, 8.693 ms, 8.979 ms, and
9.212 ms — a max-minus-min spread of 11.2% of the mean. This is the
floor every CI delta must clear before the signal exceeds the noise.

**Hardware speed ratio: ~2.2× slower than the primary host.** Wire
`validate_update` measures 323 ns here vs 133 ns on the primary host;
`adj_rib_in_insert/10000` median is ~8.7 ms vs ~4.0 ms. The ratio is
consistent across crates, so the **scaling shape is preserved** — what
matters for regression tracking — even though absolute numbers differ.

**Advisory regression bands** (not enforced in code; applied by the
reviewer reading the workflow summary). The 11% same-SHA noise floor is
the lower bound; inter-SHA comparisons add base/head cache-warming bias
on top, so single-dispatch results are wider than the floor suggests.
Empirical reverify against the PR #295 +12% regression (2026-05-28,
two single-dispatch comparisons) **could not surface the signal** —
deltas swung between −2.7% and +2.0% on the 10k case across two runs.

For **single-dispatch** (`attempts=1`) comparisons:

| Delta | Interpretation |
|-------|----------------|
| < ~20% | Inside single-dispatch noise + bias band. Do not act on it without re-dispatching with more attempts. |
| ≥ 20% | Advisory regression. Investigate before merge. |

For **multi-attempt** (`attempts ≥ 3`, the workflow default) comparisons,
the table also reports across-attempt stddev and min..max. Sub-15%
signal is gradable once stddev is in single digits and min..max brackets
the mean cleanly. A formal post-attempts threshold is deferred until
empirical data accumulates from real PR dispatches.

A pass/fail gate is deferred until a host with full `cpufreq` governor
control is available (the virtualized CPU here does not expose
`performance` mode). Until then, the workflow output is reviewer input,
not a merge gate.

### Host coexistence: bench vs. soak

The VPS bench runner is also planned to run rustbgpd's soak suite.
Both workloads acquire an exclusive `flock` on
`$HOME/.local/state/rustbgpd-host.lock` before doing real work — the
bench script via `bench/compare-criterion.sh` directly, the soak
runners via the shared `tests/soak/host-lock.sh` helper. A bench
dispatch refuses to start while a soak is active and a soak refuses to
start while a bench is mid-attempt; either workload fails fast with a
clear error rather than producing useless numbers next to a busy host.
Local dev boxes without that XDG state directory skip the locking
entirely so this doesn't change anything for laptops / dev boxes that
aren't shared with a bench runner. The sudo / `$HOME` trap (running soak as
root moves the lock to `/root/...` and bypasses the guard) is covered
in `tests/soak/README.md` under "Host mutex".

## Running

```bash
# All benchmarks (every package's benches; the targets live in different
# crates, so a bare --bench cannot resolve them — run them per-package below
# or use no args to sweep the whole workspace)
cargo bench

# Wire codec only
cargo bench -p rustbgpd-wire --bench codec

# RIB only
cargo bench -p rustbgpd-rib --bench rib_ops

# Root-daemon FIB projection internals
cargo bench --features bench-internals --bench fib_projection

# Policy chain eval + the explain-snapshot clone cost
cargo bench -p rustbgpd-policy --bench policy_eval
cargo bench -p rustbgpd-policy --bench explain_snapshot

# Specific group
cargo bench -p rustbgpd-rib --bench rib_ops -- "adj_rib_in_insert"
```

HTML reports are generated to `target/criterion/`.

## Comparing Two Refs

Use `bench/compare-criterion.sh` when judging a performance PR locally. It
creates detached worktrees for the baseline and head refs, runs both with a
shared Criterion target directory, and writes a Markdown summary plus raw
Criterion artifacts under `target/bench-compare/`.

It requires `bash`, `git`, `cargo`, `python3`, and `taskset` from util-linux.

```bash
bench/compare-criterion.sh \
  --base origin/main \
  --head HEAD \
  --core 8 \
  --package rustbgpd-rib \
  --bench rib_ops \
  --filter adj_rib_in_insert
```

For pinned runs, put the selected CPU into the `performance` governor first
where the host allows it:

```bash
sudo cpupower frequency-set -g performance
```

The script records the observed governor, CPU model, kernel, rustc version,
commit SHAs, logs, and raw Criterion artifact path. Treat unpinned runs as
directional only.

## Manual CI Workflow

`.github/workflows/bench.yml` exposes the same comparison as a manual
`Criterion Bench Compare` workflow. It targets a `[self-hosted,
rustbgpd-bench]` runner and is intentionally not wired to normal pull-request
events yet. Enable PR-triggered benchmark comments only after the replacement
runner exists and its run-to-run noise floor is measured.

## Reading the comparison output (for PR review)

With `--attempts ≥ 2` the summary table has one row per benchmark with
these columns:

| Column | What it is | How to read it |
|---|---|---|
| `attempts` | `n/N` — successful attempts over requested | `n < N` means some attempts failed to produce a baseline; treat the row as low-confidence. |
| `base median (mean)` / `head median (mean)` | per-ref median, averaged across attempts | The absolute numbers; useful for sanity (right order of magnitude?) more than for the verdict. |
| `mean delta` | head-vs-base, averaged across attempts (**+ = head slower = regression**) | The headline. Sign convention is fixed regardless of which ref ran first. |
| `stddev` | spread of the per-attempt deltas | **The confidence signal.** Single-digit-% stddev → the mean delta is trustworthy. Large stddev → the host was noisy; the mean is soft. |
| `min..max` | range of per-attempt deltas | If this brackets `0` (e.g. `-3%..+4%`), the sign of the mean delta is not reliable — it's inside the noise. |
| `last-run 95% CI` | conservatively propagated from the last attempt's saved median CIs | Wider than Criterion's own change CI by construction; a sanity bound, not the primary signal. |

### The grading rule (reviewer guidance, not a CI gate)

This is **reviewer guidance, applied per benchmark row — not CI
policy**; nothing auto-fails. It is deliberately a *rule* rather than a
flat percentage: the VPS runner's same-SHA noise floor is ~11% and
small benchmarks carry several points of spread depending on shape, so
a magnitude-only threshold would both miss real small regressions and
cry wolf on noisy ones. Read `stddev` and `min..max` **before** the
mean delta.

```
ONE benchmark row (attempts = N, N ≥ 3 recommended)
│
│ attempts n/N with n < N ? ───────────► LOW CONFIDENCE: re-dispatch (don't grade)
│ no
│ min..max straddles 0 ? ──────────────► NOISE: not actionable (sign unreliable)
│ no  (entirely one side of 0)
│ stddev ≥ ~10% (≈ same-SHA noise floor) ? ─► INCONCLUSIVE: re-dispatch, more attempts
│ no  (single-digit stddev)
▼ CONFIRMED SIGNAL
│
├─ mean delta < 0 (faster) ────────────► IMPROVEMENT: note it, no gate
│
└─ mean delta > 0 (slower) → CONFIRMED REGRESSION
       ├─ < ~3%, explained by the PR ──► ACCEPTABLE: mention the tradeoff, proceed
       ├─ < ~3%, unexplained, hot path ─► INVESTIGATE anyway
       └─ ≥ ~3%, or unexplained ────────► BLOCK + investigate before merge
```

| Result | Action |
|---|---|
| `min..max` straddles 0 | noise — not actionable |
| `stddev` ≥ ~10% (≈ same-SHA noise floor) | inconclusive — rerun with more attempts |
| confirmed improvement | note it, no gate |
| confirmed regression < ~3% | acceptable if explained by the PR; mention the tradeoff |
| confirmed regression < ~3% but unexplained in a hot path | investigate anyway |
| confirmed regression ≥ ~3% | block + investigate before merge |

> **Confirmed regression** means `min..max` is entirely above zero and
> `stddev` is below the same-SHA noise floor. Regressions under ~3% may
> be accepted when the PR explains the tradeoff; regressions at or above
> ~3%, or unexplained regressions in a hot path, should block pending
> investigation.

**Worked example** — the first multi-attempt comparison on the VPS
runner (`rib_ops`, `v0.30.0` → `main`, 3 attempts; the span includes
the `shrink route clone payload` change):

- `route_churn/10k+1k`: `-7.31%`, stddev 1.5%, `-8.9%..-5.9%` → a
  **confirmed improvement** (one side of 0, tight) — the methodology
  surfacing the real win.
- `adj_rib_in_insert/100000`: `+2.84%`, stddev 5.0%, `-1.4%..+8.4%` →
  **noise** (straddles 0), not actionable despite the positive mean.

That run is why this is a rule and not a number: the same comparison
held a real −7% signal and a +2.8% non-signal side by side. The
guidance is reviewer input, not a merge gate (see the
[secondary measurement environment](#secondary-measurement-environment--self-hosted-vps-bench-runner)
for the noise-floor rationale).

## Wire Codec

The wire codec (`rustbgpd-wire`) is the hot path for every inbound and outbound
UPDATE. It uses a two-phase design: `decode()` is O(1) framing only, `parse()`
is O(n) structural decode.

### NLRI Encode / Decode

| Prefixes | Decode | Encode | Per-prefix decode |
|----------|--------|--------|-------------------|
| 1 | 21 ns | 12 ns | 21 ns |
| 10 | 94 ns | 30 ns | 9.4 ns |
| 100 | 620 ns | 237 ns | 6.2 ns |
| 500 | 2.77 µs | 1.06 µs | 5.5 ns |

NLRI encoding is a tight `memcpy` loop. Decoding adds masking and validation.
At 500 prefixes, decode throughput is ~180M prefixes/sec.

### UPDATE Build / Parse

Full UPDATE message construction and structural parsing, including path
attributes and NLRI.

| Prefixes | Build | Parse | Per-prefix parse |
|----------|-------|-------|------------------|
| 1 | 154 ns | 147 ns | 147 ns |
| 10 | 206 ns | 205 ns | 20 ns |
| 100 | 487 ns | 798 ns | 8.0 ns |
| 500 | 1.50 µs | 3.11 µs | 6.2 ns |

At 500 prefixes, parse throughput is ~161M prefixes/sec. The fixed cost
(~130 ns) is attribute decode; marginal cost per prefix is ~6 ns.

### Path Attributes

| Set | Decode | Encode |
|-----|--------|--------|
| Typical (6 attrs) | 117 ns | 91 ns |
| Rich (8 attrs, large communities) | 166 ns | 169 ns |

"Typical" = Origin, AS_PATH (3 ASNs), NextHop, LocalPref, MED, Communities (2).

### Validation

| Benchmark | Time |
|-----------|------|
| `validate_update` (typical attrs) | 133 ns |

## RIB Operations

The RIB data structures (`rustbgpd-rib`) are pure synchronous structs with no
async or locking overhead. `RibManager` owns them in a single tokio task.
Both `AdjRibIn` and `AdjRibOut` use trie-backed secondary prefix indexes
(`prefix_trie::PrefixMap`) for fast per-prefix lookup, avoiding the O(N)
full-scans that dominated earlier versions.

### Best-Path Comparison

1000 pairwise `best_path_cmp()` calls per iteration. The 10-step tiebreak
(stale, RPKI, LOCAL_PREF, AS_PATH len, ORIGIN, MED, eBGP pref, CLUSTER_LIST,
ORIGINATOR_ID, peer addr) is the inner loop of best-path selection.

| Scenario | Time (1000 calls) | Per-call | vs v0.31.0 |
|----------|-------------------|----------|------------|
| Equal routes (full tiebreak) | 19.8 µs | 19.8 ns | +6.1% |
| LOCAL_PREF differs (early exit) | 5.22 µs | 5.22 ns | +0.6% (noise) |
| Different peers (full tiebreak) | 19.7 µs | 19.7 ns | +5.8% |

Early exit at LOCAL_PREF is ~3.8× faster than a full tiebreak. In typical eBGP
deployments most comparisons resolve at LOCAL_PREF or AS_PATH length, so the
common path (`local_pref_diff`) is unaffected. The full-ladder paths regressed
~6% from `v0.31.0` — small in absolute terms (~1 ns/comparison) and dwarfed by
the −40–62% insert/pipeline wins below. It is consistent across two hosts (the
self-hosted VPS A/B measured +1.4% / +2.3% ± noise), so it is real but minor;
flagged for follow-up.

### Adj-RIB-In Insert

Bulk insert into a fresh `AdjRibIn` (HashMap keyed by `(Prefix, path_id)` plus a
trie-backed secondary prefix index).

| Routes | Time | Throughput | vs v0.31.0 |
|--------|------|------------|------------|
| 10,000 | 2.36 ms | 4.2M routes/sec | −34.2% |
| 100,000 | 31.6 ms | 3.2M routes/sec | −39.8% |
| 500,000 | 89.5 ms | 5.6M routes/sec | −49.3% |

The scale/memory sprint roughly halved insert time at scale. The biggest
contributors are the inlined `SmallVec<[u32; 1]>` Adj-RIB-In prefix index
(no per-prefix `HashSet` allocation in the common no-Add-Path case) and the
`FxHash` route maps (a faster non-cryptographic hasher for the internal,
`max_prefixes`-bounded keys). A full Internet table (900k prefixes) now inserts
in ~160 ms. The secondary prefix index keeps `iter_prefix()` at bounded depth, so
the full pipeline below stays linear at scale. The prefix index has since moved
from `HashMap` to a trie (`prefix_trie::PrefixMap`) — this trims RIB index memory
(see *Memory Footprint*) and improved insert a further ~8% in a quick A/B; the
table above is the pre-trie pinned baseline, with a pinned re-measure of the trie
delta deferred to the next quiet-runner bench pass.

### Loc-RIB Recompute

Best-path selection for a single prefix with N candidate routes.

| Candidates | Time | vs v0.31.0 |
|------------|------|------------|
| 1 | 38 ns | −37.1% |
| 2 | 50 ns | −30.9% |
| 4 | 88 ns | −19.5% |
| 8 | 167 ns | −9.5% |

Linear in candidate count, as expected. With Add-Path or multiple peers
advertising the same prefix, each additional candidate adds ~18 ns
(one `best_path_cmp` call). The single-candidate case (the common one) is
fastest now that the map lookup uses `FxHash`; the delta shrinks as candidate
count grows and `best_path_cmp` (slightly slower — see above) dominates.

### Full Pipeline

End-to-end: insert routes from 2 peers into Adj-RIB-In, recompute best path
for every prefix, install into Adj-RIB-Out. This exercises the real hot path
without async/channel overhead.

| Prefixes (×2 peers) | Time | Per-prefix | vs v0.31.0 |
|----------------------|------|------------|------------|
| 1,000 | 306 µs | 306 ns | −61.9% |
| 10,000 | 3.37 ms | 0.34 µs | −61.5% |
| 50,000 | 39.0 ms | 0.78 µs | −49.2% |

Scaling is roughly linear (O(N)) thanks to the secondary prefix index. The
scale/memory sprint roughly halved the end-to-end pipeline on top of that
(`SmallVec` index + `FxHash` + coalesced multi-chunk distribution). Versus the
ancient pre-index O(N²) era the 50 k pipeline took 7.1 s; it is 39 ms now.

Extrapolating linearly, a full Internet table (900 k prefixes × 2 peers) would
complete the pipeline in ~0.7 s.

### Distribution Fanout (route-reflector / route-server scale)

The stage *after* the pipeline: when best paths change, the `RibManager` must
re-advertise them to every peer. Unlike the bench above (bare structs), the
`fanout` bench drives the real manager `distribute_changes` hot path — per-peer
export-policy evaluation + Adj-RIB-Out staging + bounded-channel send — fanning a
batch of **64 changed best paths** out to N peers. It is gated behind the
`bench-internals` feature (a synthetic peer-registration + Loc-RIB-seed driver,
not reachable in a normal build). Each measured pass is a *first* advertise
(empty Adj-RIB-Out, so the equality-suppression fast path never fires) — the
conservative upper bound on per-peer cost.

Run it with:

```bash
cargo bench -p rustbgpd-rib --features bench-internals --bench fanout
```

| Peers (N) | No export policy | With export policy | Per (peer × prefix) |
|-----------|------------------|--------------------|---------------------|
| 1   | 12.4 µs | 14.8 µs | ~194 / ~231 ns |
| 8   | 93.2 µs | 110 µs  | ~182 / ~215 ns |
| 64  | 719 µs  | 847 µs  | ~176 / ~207 ns |
| 256 | 2.92 ms | 3.46 ms | ~178 / ~211 ns |

Fanout is cleanly **O(peers × changed prefixes)** — the per-advertisement cost
holds at **~178 ns** across the whole range. The representative export chain
(an eight-statement scalar-guard chain — seven `LOCAL_PREF`-range misses then a
catch-all permit, so every route is evaluated against all eight) adds a flat
**~18%** (~33 ns/advertisement) — real but *not* dominant: the fanout machinery
(Loc-RIB lookup, route clone, Adj-RIB-Out insert, `OutboundRouteUpdate` build,
channel send) is the other ~84%. Export-policy eval only dominates for *heavy*
chains (AS_PATH regex / large-community scans), not the cheap scalar-guard
filter measured here.

For sizing: a route server with 256 clients absorbing a 64-prefix churn burst
spends ~3 ms of single-threaded fanout; a full-table resync (≈100 k prefixes ×
256 peers) extrapolates to ~4.5 s. Reducing that is a per-advertisement-cost or
coalescing problem, not a parallelism one — distribution is single-task by design
(`RibManager` owns all RIB state in one tokio task). These are a
same-host (7970X) quick criterion run (reduced sampling); a pinned re-measure is
deferred to the next quiet-runner pass, and any future fanout optimization is
gated on this baseline.

### Bulk Initial Load

Cold single-peer table load into pre-sized Adj-RIB-In / Loc-RIB /
Adj-RIB-Out. This is the benchmark shape to use when judging full-table
convergence changes; it intentionally separates initial table load from the
two-peer `rib_pipeline` micro-benchmark above.

Run it with:

```bash
cargo bench -p rustbgpd-rib --bench rib_ops -- "bulk_initial_load"
```

| Routes | Time | vs v0.31.0 |
|--------|------|------------|
| 10,000 | 1.54 ms | −57.3% |
| 100,000 | 39.2 ms | −50.5% |

Cold table load benefits the most from the sprint — the `SmallVec` prefix
index removes a per-prefix `HashSet` allocation on every insert, and the
coalesced distribution flushes one outbound batch instead of one per chunk.

### Route Churn

10,000 base routes from peer 1, then 1,000 route announcements from peer 2
followed by 1,000 withdrawals, with best-path recomputation at each step.

| Benchmark | Time | vs v0.31.0 |
|-----------|------|------------|
| 10k base + 1k announce/withdraw cycle | 254 µs | −59.4% |

A 1 k-prefix churn event reconverges in ~0.25 ms, including both the announce
and withdraw phases — −59% from `v0.31.0` (the sprint's index + hasher wins on
the lookup-heavy churn path).

## Memory Footprint

Measured using a tracking global allocator that counts every `alloc` and
`dealloc`. Run with:
`cargo test -p rustbgpd-rib --test memory_profile -- --nocapture`

### Type Sizes (stack)

| Type | Size |
|------|------|
| `Route` | 120 bytes |
| `Prefix` | 18 bytes |
| `PathAttribute` | 112 bytes |
| `AsPath` | 24 bytes |
| `AsPathSegment` | 32 bytes |
| `AdjRibIn` | 280 bytes |
| `LocRib` | 96 bytes |

`PathAttribute` grew from 72 to 112 bytes since the v0.30-era figures (new
attribute variants). It is interned per peer, so the per-route impact is
amortized to near zero (see below), but it does raise the per-unique-attribute-
set heap cost.

`Route.attributes` is `Arc<Vec<PathAttribute>>` — cloning a route between
Adj-RIB-In, Loc-RIB, and Adj-RIB-Out shares the attribute allocation via
reference counting. Mutation uses `Arc::make_mut()` (copy-on-write).

Path attribute interning in `AdjRibIn` deduplicates identical attribute sets
across routes from the same peer. A `HashSet<Arc<Vec<PathAttribute>>>` intern
table maps each unique attribute set to a shared `Arc`. Routes with identical
attributes (common in bulk advertisements) share one heap allocation instead of
each having their own copy.

### Per-Route Heap Allocation

| Attribute set | Heap | Stack | Total |
|---------------|------|-------|-------|
| Typical (6 attrs, 3-ASN path, 2 communities) | 764 B | 120 B | 884 B |
| Rich (8 attrs, 5-ASN+SET path, 5 communities, ORIGINATOR_ID, CLUSTER_LIST) | 1056 B | 120 B | 1176 B |

These are per-unique-attribute-set costs. With interning, routes sharing the
same attributes pay only the 120-byte `Route` stack cost plus an 8-byte `Arc`
pointer.

### AdjRibIn at Scale (single peer, typical attrs)

| Routes | Resident | Per-route |
|--------|----------|-----------|
| 10,000 | 3.0 MB | 318 B |
| 100,000 | 24.3 MB | 254 B |

Per-route cost is ~250-320 bytes including HashMap overhead, prefix index, and
intern table. At 100k the resident set is ~9% lower than the v0.30-era 26.7 MB,
from the inlined `SmallVec` prefix index (no per-prefix `HashSet`). Attribute
interning shares one ~764-byte allocation across all routes with identical
attributes; a typical peer's full table has only a handful of unique attribute
sets (~50-200), so the attribute heap cost is amortized to near zero per route.

> **Harness limitation (high N):** the `memory_profile` test does not scale
> cleanly past ~100k in its current form — its 500k and 900k cases report
> near-identical resident (a measurement artifact, not a RIB property; the
> v0.30-era 500k/900k figures had the same non-scaling). The 10k/100k rows are
> the trustworthy structural numbers; fixing the harness to scale is tracked as
> a separate perf-infra task. For real full-table memory at scale, see the
> bgperf2 end-to-end RSS below.

### Full RIB: 2 Peers + LocRib (typical attrs)

| Prefixes | Total memory | Per-prefix |
|----------|-------------|------------|
| 100,000 | 60.6 MB | 635 B |

(Was 66.6 MB / 698 B before the trie-backed prefix indexes landed — see the
*prefix-index migration* note below.) This is the **RIB-only, allocator-tracked**
structural memory (2× Adj-RIB-In +
Loc-RIB); each prefix stores Route instances with `Arc` sharing of attributes
across copies, and attribute interning within each `AdjRibIn` shares one
allocation across routes with identical attributes. It is **distinct from the
full-process RSS** below — it excludes the daemon's operational surfaces
(event-history, gRPC, telemetry, BFD, the tokio runtime, allocator arenas).
500k/900k are omitted under the harness limitation noted above; this RIB-only
profile remains the regression-tracking surface for RIB data-structure changes,
while bgperf2 RSS (below) is the operator-facing full-daemon number.

> **Correction (whole-daemon dhat profile, 2026-06-02).** A full-daemon dhat
> heap profile at 2 peers × 100k (`profile='dhat'` bgperf2 build, SIGTERM at the
> flood peak) shows the live-at-peak heap (~308 MB tracked, dhat build) is
> **~76% RIB map/index bucket storage**, broken down by allocation site as:
> Adj-RIB-Out route map **~86 MB** + its prefix index ~29 MB, Loc-RIB best-path
> map ~57 MB, Adj-RIB-In route map ~48 MB + its prefix index ~16 MB. API / event
> / metrics operational surfaces were **negligible (<1 MB)**. **This corrects the
> framing below:** the `memory_profile` micro-bench above (60.6 MB) is
> **Adj-RIB-In + Loc-RIB only, on synthetic routes — it excludes Adj-RIB-Out**,
> which the profile shows is the *single largest* component. So the gap between
> that 60.6 MB and full-daemon RSS is mostly **more RIB storage** (the
> advertised-route maps plus real per-route data), not operational surfaces. The
> durable memory cost is the three-layer route-storage model (Adj-RIB-In +
> Loc-RIB + Adj-RIB-Out) and its prefix-keyed `hashbrown` bucket arrays — the
> target for any future memory work, not the runtime or operational surfaces.

> **Prefix-index migration (trie-backed indexes).** The first measured fix
> targeting the bucket-array overhead above: the two prefix-keyed *indexes* —
> `AdjRibIn::prefix_index` and `AdjRibOut::prefix_path_ids` (each `Prefix →
> SmallVec<[path_id]>`) — moved from `hashbrown::HashMap` to a family-split
> `prefix_trie::PrefixMap`. In the dhat breakdown above these are the ~16 MB
> Adj-RIB-In + ~29 MB Adj-RIB-Out index components (that profile predates the
> change). Measured impact (`memory_profile`, allocator-tracked): Full-RIB
> 100k **66.6 → 60.6 MB (−9%)**, 500k **−14%**; Adj-RIB-In alone **−12% / −19%**
> at 100k / 500k; and `adj_rib_in_insert` got **~8% faster** (compact trie nodes
> vs hash buckets, no rehash) with best-path comparison unchanged — a clean win,
> no read-path regression. The **Loc-RIB best-path map** (~57 MB above) was also
> prototyped on the trie and gave a larger memory win, but it **regressed the
> lookup-hot `loc_rib_recompute` ~2.6× (36 → 95 ns)** — Loc-RIB lookups dominate
> best-path recompute, so that swap was **deferred**. Loc-RIB-specific compaction
> that avoids the per-lookup trie-descent tax is tracked as follow-up.

### Optimization History

| Version | Full RIB (900k x 2 peers) | Per-prefix | vs GoBGP |
|---------|--------------------------|------------|----------|
| Pre-Arc (`Vec<PathAttribute>`) | 1.80 GB | 2.1 KB | 4-9x less |
| Arc sharing (v0.4.2) | 1.41 GB | 1.6 KB | 6-11x less |
| Arc + interning | 547 MB | 637 B | 15-29x less |

The 900k×2 figures are the historical allocator-tracked journey; the 547 MB row
is the last reliable one before the `memory_profile` harness stopped scaling
past ~100k (see the limitation note above). RIB-structure regression tracking
now uses the 100k allocator profile; full-daemon RSS at scale uses bgperf2.

### Optimization History (end-to-end, bgperf2 2p/100k)

| Change | Memory | Convergence |
|--------|--------|-------------|
| Pre-AdjRibOut index | 168 MB | 71s |
| + AdjRibOut secondary prefix index | 415 MB | 12s |
| + Skip unnecessary Arc deep clones (v0.4.x-era) | 257 MB | 11s |
| + AdjRibOut capacity hints (v0.30-era) | ~260 MB | 11s |
| v0.31.0-era — event-history **on** (daemon default then) | ~439 MB | ~11s |
| v0.31.0-era — event-history off | ~344 MB | ~11s |
| **v0.32.0 — event-history off (daemon default now)** | **~284 MB** | ~11s |
| **v0.32.0 — event-history on (opt-in)** | **~346 MB** | ~11s |

**v0.32.0 cut 2p/100k full-daemon RSS ~21%** (event-history on: ~439 → ~346 MB,
median of 337 / 346 / 369; off: ~344 → ~284 MB, of 280 / 289). The only code
delta versus the v0.31.0-era rows is the inbound-UPDATE attribute-`Arc` sharing
(PR #326): eliminating the per-NLRI attribute-vector deep-clones during the
route flood lowers the (jemalloc) allocator high-water mark, and since jemalloc
retains freed arenas the lower peak shows up directly as lower steady-state RSS.
Clean before/after on the same harness and host.

**The bgperf2 rows are not apples-to-apples with the v0.4.x/v0.30-era rows
above** — they are *full-daemon* process RSS, not the RIB-only figure, and are
**not a RIB memory regression** (RIB-only structural memory at 100k actually
improved ~9% — see above). Since the ~257–260 MB era the daemon gained
substantial always-available operational surfaces (BFD, gNMI, ASPA, BGP
roles/OTC, the explain cache) and `PathAttribute` grew 72→112 B. The single
biggest contributor is the durable **event-history outbox** (ADR-0072), which
persists every route event to SQLite: enabling it
(`[event_history].enabled = true`) adds **~62 MB** RSS (~284 → ~346 MB) **and
roughly doubles peak CPU** (~115% → ~239%). Convergence is unchanged at ~11s
(≈2s route-flood; the outbox is not on the convergence-critical path). Criterion
and the RIB-only `memory_profile` above remain the regression-tracking surfaces
for RIB data-structure changes.

> **Operator note — the event-history outbox is opt-in as of v0.32.0.** That
> always-on cost (~62 MB RSS + roughly double the peak CPU at 2p/100k) is
> exactly why: the outbox now defaults to `[event_history].enabled = false`, so
> the lean numbers above are the default. Deployments that want restart-safe
> event replay set `enabled = true` and accept the cost. See ADR-0072 and the
> two deployment profiles in `docs/OPERATIONS.md`.

The Arc deep-clone fix (`RouteModifications::is_empty()` guard) was the biggest
memory win: `Arc::make_mut()` was called unconditionally on every route in
`distribute_single_best_prefix()`, forcing deep clone of `Vec<PathAttribute>`
even when no export policy modifications were configured. With the guard, ~85%
of routes share the same `Arc` across LocRib and AdjRibOut — no deep copy.

Capacity hints (pre-sizing AdjRibOut/LocRib HashMaps) were tested and shown to
be neutral on steady-state RSS, confirming the remaining HashMap overhead is
structural (power-of-2 rounding), not rehash churn.

Remaining memory is HashMap bucket arrays (~78%) and actual Route data (~19%).
No obvious accidental overhead remains.

### Shared `RouteData` — measured and rejected

Splitting `Route` into a shared immutable `RouteData` (referenced from each RIB)
plus a thin per-RIB wrapper was evaluated against a `>=25%`-of-RR-heap gate and
**rejected**. In the route-reflector fanout shape the realistic, policy-robust
split (identity fields shared; attributes + next-hop kept per-copy so per-client
export policy still shares the identity) recovers only **11–13% of RIB heap
under transparent policy and ~5% under per-client rewrite** — well below the
gate, for the largest `&Route`-consumer blast radius in the codebase. A naive
`Arc<Route>` whole-shell share would reach ~31–37%, but that is unachievable:
`is_stale` / `is_llgr_stale` and `validation_state` / `aspa_state` mutate per
RIB, so the full shell can never be shared. Reproducible harness:
`cargo test -p rustbgpd-rib --test route_data_sharing_profile -- --ignored --nocapture`.

## Interpretation

**Wire codec** — The codec is not a bottleneck. Parsing a full-size UPDATE (500
prefixes, typical attributes) takes 3.1us. At 1 Gbps line rate, BGP UPDATE
arrival rate is far lower than decode capacity. The two-phase decode/parse
design means sessions that only need header inspection (keepalives, most
notifications) pay no attribute decode cost.

**RIB insert** — Bulk insert now ranges from ~3.2M routes/sec at 100k rows to
~5.6M routes/sec at 500k rows. A 900k-prefix Internet table extrapolates to
~160ms for the insert step, well within acceptable convergence time for
route-server deployments.

**Best-path selection** — Full-ladder comparisons are ~19.8ns each. Even an
8-candidate Add-Path selection completes in ~167ns per prefix, and the common
early-exit path is much cheaper. Best-path is not a bottleneck.

**Pipeline scaling** — With the secondary prefix index, the pipeline scales
linearly. 50k prefixes x 2 peers completes in 39ms. Extrapolated full-table
(900k) would take ~0.7s for a complete 2-peer recomputation — well within
operational requirements.

**Route churn** — A 1k-prefix announce/withdraw cycle completes in ~254us.
Real-world churn involves far fewer prefixes per UPDATE (typically 1-50), so
per-event reconvergence is effectively instant.

## End-to-End System Benchmarks

Measured using [bgperf2](https://github.com/netenglabs/bgperf2), a Docker-based
BGP benchmarking harness. Each test runs a target daemon, N BIRD tester peers
(each advertising P prefixes), and a GoBGP monitor peer that observes convergence.
The monitor's accepted route count is the ground truth for completion.

**Environment:** AMD Ryzen Threadripper 7970X (32 cores / 64 threads), 125 GB
RAM, Linux 6.17, Docker 27.x. All daemons run in containers on the same host.

**Methodology:** Convergence time is measured from first prefix received by the
monitor to all expected prefixes received. The test harness waits for 5 seconds
of stability before declaring completion. Total time includes session
establishment.

### Results

Re-run on current `main` (shipping as **v0.32.0**) on 2026-05-29 — all three
daemons on the same host, same harness. Versions: **BIRD 2.18**
(`branch.master.0ee9f93`), **GoBGP 4.3.0**, **rustbgpd** current `main` (the
container self-reports `0.31.0`, the pre-release-bump workspace version).
"Convergence" is the route-flood time (monitor first-prefix → all-received);
"Total time" includes session establishment. RSS is the max of the target
container; 2p/100k is the median of 3 (rustbgpd eh-on) / 2 (eh-off) runs. The
rustbgpd 10k/20k columns were measured with **event-history enabled** (the
opt-in config); at those scales the on/off difference is within noise. The
2p/100k row shows **both** the v0.32.0 default (event-history off) and the
opt-in (on).

**Re-confirmed 2026-06-02** on current `main` (post-v0.33.0, default
**event-history off**), same host — this is a no-regression check, not a new set
of headline numbers:

- **Total time is flat** vs the v0.32.0 figures (8.3s / 8.3s / 12.2s across
  10p×1k / 2p×10k / 2p×100k).
- **2p×100k event-history-off RSS holds within noise** — ~291 MB vs the ~284 MB
  below.
- **Max-CPU peaks trended lower** across all three configs, but bgperf2 samples
  peak CPU coarsely (one reading per second), so treat that as advisory, not a
  measured improvement.
- The small-scale **10k/20k RSS cells below were measured event-history-*on***
  and are left unchanged here — they are not apples-to-apples with a default
  eh-off run, so refreshing them would require converting the whole table to a
  single eh-off mode.

> **The earlier "2.3× less memory than GoBGP" framing no longer holds — and was
> based on a stale GoBGP figure.** GoBGP 4.3.0 measures **~200 MB** at 2p/100k
> here (and measured 198 MB in the prior March run); the old 578 MB was a much
> older snapshot. On *full-daemon RSS*, rustbgpd (~346 MB on / ~284 MB off) now
> uses **more** than GoBGP (~203 MB) and far more than BIRD (~30 MB) at this
> scale. The whole-daemon dhat profile (see the *Memory Footprint* correction)
> attributes that to **RIB route-storage map/index bucket arrays** — the
> three-layer Adj-RIB-In + Loc-RIB + Adj-RIB-Out model, with Adj-RIB-Out the
> largest single piece — **not** operational surfaces, which the profile shows
> are negligible (<1 MB). The event-history outbox adds the on-vs-off RSS delta
> when enabled (opt-in, default-off), but the structural cost is the route maps.
> BIRD's radix-tree RIB with global attribute deduplication is what makes it an
> order of magnitude leaner on this same data.

#### 10 peers × 1,000 prefixes (10k total)

| | BIRD 2.18 | GoBGP 4.3.0 | rustbgpd (main / v0.32.0) |
|---|---|---|---|
| Convergence | 1s | 2s | 1s |
| Max CPU | 2% | 118% | 14% |
| Max RSS | 10 MB | 55 MB | 94 MB |
| Total time | 9s | 10s | 8s |

#### 2 peers × 10,000 prefixes (20k total)

| | BIRD 2.18 | GoBGP 4.3.0 | rustbgpd (main / v0.32.0) |
|---|---|---|---|
| Convergence | 1s | 2s | 1s |
| Max CPU | 1% | 78% | 13% |
| Max RSS | 10 MB | 45 MB | 79 MB |
| Total time | 9s | 10s | 8s |

#### 2 peers × 100,000 prefixes (200k total)

| | BIRD 2.18 | GoBGP 4.3.0 | rustbgpd (main / v0.32.0) |
|---|---|---|---|
| Convergence | 2s | 5s | 2s |
| Max CPU | 10% | 598% | 115% default (239% eh-on) |
| Max RSS | 30 MB | 203 MB | 284 MB default (346 MB eh-on) |
| Total time | 13s | 16s | 12s |

### Understanding the Numbers

**Session establishment.** The total-time rows above reflect post-fast-retry
`main`, re-measured 2026-05-30 on the same host. rustbgpd dials the passive
BIRD testers, which bind their listeners ~1-2s after rustbgpd starts, so the
first outbound TCP dial is refused. Before the fast-retry change, that first
refusal armed a ~10s backoff timer (`connect_retry_secs` base × exponential),
so rustbgpd sat idle until the timer fired even though the testers were ready
within ~2s — establishment took ~10s. `main` now retries the first two refused
dials at a 1s floor before resuming the exponential curve, catching the testers
almost immediately; unreachable peers that wait for the TCP connect timeout, and
OPEN-validation / NOTIFICATION failures, still use the slower guards so
misconfigured peers do not hot-loop. A controlled same-host before/after at
10 peers × 1,000 prefixes (both event-history off, isolating the FSM change from
the v0.32.0 event-history default flip) measured total time **16.7s → 8.3s**
(establishment ~10s → ~2s).

**Route processing.** At 10k and below, convergence completes in 2 seconds —
matching GoBGP and within 1 second of BIRD. At 200k prefixes, rustbgpd
converges in 2 seconds (monitor time), competitive with BIRD (2s) and faster
than GoBGP (5s). The key optimizations were: (1) secondary prefix index in
`AdjRibOut` converting per-prefix lookup from O(N) to O(1), and (2) skipping
unnecessary `Arc::make_mut()` deep clones in the distribution path when no
export policy modifications are configured.

**CPU efficiency.** rustbgpd uses a single-threaded RIB (single tokio task,
no locks). At 200k scale it peaks at ~115% CPU by default and ~239% with the
(opt-in) event-history outbox enabled (RIB + transport + the SQLite outbox
writer) — so the durable outbox roughly doubles peak flood CPU when on. GoBGP
peaks far higher (~598%, goroutine-per-peer + GC); BIRD is the most efficient
at ~10% CPU, reflecting decades of C optimization with a radix-tree RIB.

**Memory.** *Full-daemon RSS* at 2p/100k is ~284 MB by default / ~346 MB with
the opt-in event-history outbox — **both above GoBGP's ~203 MB** and far more
than BIRD's ~30 MB at this scale. A whole-daemon dhat heap profile
(2026-06-02; see the *Memory Footprint* correction) attributes that RSS to
**RIB route-storage map/index bucket arrays — ~76% of the live-at-peak heap** —
across the three-layer Adj-RIB-In + Loc-RIB + Adj-RIB-Out model, with Adj-RIB-Out
the single largest piece (~115 MB across its route map + prefix index). API /
event / metrics operational surfaces were **negligible (<1 MB)**. The opt-in
event-history outbox adds the on-vs-off RSS delta when enabled (~62 MB), but the
default-off structural cost is the route maps, **not** operational surfaces. The
earlier 60.6 MB "RIB-only is lean" figure is a synthetic Adj-RIB-In + Loc-RIB
micro-bench that excludes Adj-RIB-Out and so undercounts full-daemon route
storage. BIRD's radix-tree RIB with global attribute deduplication is what makes
it an order of magnitude leaner on this same data. At full-table scale (900k
prefixes, RIB-only micro-bench) rustbgpd's Adj-RIB-In + Loc-RIB is ~533 MB vs
GoBGP's published 8–16+ GB.

**gRPC under load.** A priority query channel separates read-only gRPC queries
from the route-processing pipeline, ensuring management API requests are
serviced between route batches even during bulk loading. At 100k+ scale, the
API remains responsive rather than blocking behind thousands of queued route
updates.

### Comparison Summary

| Metric | BIRD | GoBGP | rustbgpd |
|--------|------|-------|----------|
| Architecture | Single-threaded C, radix tree | Go, goroutine-per-peer | Single-threaded Rust, HashMap RIB |
| Route processing (200k) | 2s | 5s | 2s |
| CPU model | 1 core, very efficient | Multi-core, GC overhead | 1-2 cores, no GC |
| Memory model | Radix tree, minimal overhead | Go heap, GC managed | Arc sharing, attribute interning |
| Full-daemon RSS (200k) | 30 MB | 203 MB | 284 MB default / 346 MB eh-on |
| RIB-only memory (200k, allocator-tracked) | n/a | n/a | 60.6 MB |
| RIB-only (900k, micro-bench) | ~325 MB (published, 30 peers) | 8-16+ GB (published) | ~533 MB (2 peers + Loc-RIB) |
| API during load | Responsive (no RIB contention) | Responsive (concurrent) | Responsive (priority query channel) |

BIRD is the clear performance leader — 30+ years of optimization in a
purpose-built C codebase is hard to beat. On **convergence**, rustbgpd is
competitive: it floods 200k prefixes in ~2 seconds (monitor time), matching
BIRD and beating GoBGP (5s). On **full-daemon memory**, rustbgpd is no longer
the leader it was at v0.4.2 — ~284 MB by default (346 MB with the opt-in outbox)
at 2p/100k is above GoBGP's ~203 MB. The whole-daemon dhat profile (2026-06-02;
see the *Memory Footprint* correction) attributes this to **RIB route-storage
map/index bucket arrays** (~76% of the live-at-peak heap) across the three-layer
Adj-RIB-In + Loc-RIB + Adj-RIB-Out model — **not** operational surfaces
(negligible) or runtime threads (a worker-thread cap measured RSS-neutral). So
the headroom for full-daemon RSS is **compact prefix-keyed RIB storage** —
reducing `hashbrown` bucket overhead across those maps and prefix indexes — not
operational-surface trimming. Note this does not contradict the rejected
shared-`RouteData` refactor (below): that shared the Route *payload*, which is
the minority cost; the dominant cost is the maps' bucket arrays, so the open
lever is the map/index *data structure*, not payload sharing. BIRD's radix-tree
RIB with global attribute deduplication stays an order of magnitude leaner on
the same data.

## EVPN RR Scale (M33)

> **Scope note:** the M33 numbers in this section are
> **RR-only** — empty `[[evpn_instances]]`, no kernel-side dataplane
> reconciler, no local-MAC originator, no notify_loop draining
> RTNLGRP_NEIGH. v0.14.0 (Gate 7b) added the FDB programmer and
> v0.15.0 (Gate 7b+1) added the originator + IMET emitter +
> `RTNLGRP_NEIGH` subscriber. VTEP-mode scale numbers (originator
> emitting Type 2 from kernel learns, reconciler programming
> remote MACs into the bridge FDB, all with mobility churn) are
> tracked as alpha-soak follow-up — see
> [`docs/evpn-alpha-soak.md`](evpn-alpha-soak.md). Don't read M33
> numbers as a VTEP-mode baseline.

Measured with the in-tree `bench/evpn-load` generator: two synthetic
iBGP testers advertise Type 2 MAC/IP routes into a rustbgpd Route
Reflector, which reflects them to a third peer (the monitor). Tester
and monitor both listen on port 179 and let the rustbgpd RR dial in
(rustbgpd's neighbor model always actively dials configured peers, so
listen-and-accept avoids a TCP collision deadlock). The monitor runs
the same wire codec as the daemon, tracks live EVPN Type 2 keys in a
`HashSet<EvpnRouteKey>`, and reports both `initial_convergence_sec`
(first time the live set reaches the expected count) and
`stable_convergence_sec` (first time the live set stays at the
expected count for `stable_sec` continuous seconds — later than
initial when churn is running, since each withdraw+re-advertise resets
the stable window). Since the testers and monitor are built directly
on `rustbgpd-wire`, no third-party daemon is in the measurement path
— rustbgpd's RR scale is what gets exercised.

**Harness:** `tests/interop/m33-evpn-scale.clab.yml`

**Shape:**

- 2 testers × 25,000 Type 2 routes = 50,000 reflected total
- Bulk rate: 5,000 routes/sec per tester
- Churn phase: 60 seconds of 1,000 rps withdraw + re-advertise
  (sliding window over each tester's MAC space)

**Assertions:**

| Assertion | Target | Observed |
|-----------|--------|----------|
| Initial convergence to 50k reflected routes | < 60 s | **5.1 s** |
| Stable convergence (count steady ≥ 5 s after churn ends) | logged | **~70 s** |
| Post-churn count (distinct keys) | within ±tester batch (40) of 50,000 | **50,000 — exactly on this run** |
| Withdrawal events observed during churn | ≥ ½·`CHURN_RATE`·`CHURN_DURATION` (≥ 30,000) | **57,120** |
| `ListEvpnRoutes` matches observer's view | ≥ 50,000 Type 2 | **50,000** |
| Tester peers stay Established, zero flaps | both up | **both up, 0 flaps** |
| RR process stays healthy | yes | **yes — `GetHealth` passes post-run** |
| Peak RR memory (soft ceiling 2 GB) | < 2 GB | **79 MB** |

Observed wire-level traffic (bulk + churn phases combined):

| Counter | Observed |
|---------|----------|
| Total announce events (incl. churn re-advertises) | ~107,000 |
| Total withdraw events (incl. churn) | ~57,000 |
| UPDATE messages received by monitor | ~4,100 |

Note: the announce/withdraw counters include idempotent re-advertises
during churn, so they are larger than the steady-state route count.
`final_count` (50,000) is the distinct-key cardinality.

Measurement environment: AMD Ryzen 9 7950X (64 logical cores), 125 GB
RAM, Linux 6.17, Docker 27.x, containerlab. Single
`rustbgpd:dev` container per node, all four nodes on the same host.
Numbers reproduce within ±10% across runs.

**Notes on methodology:**

- All routes share one RD (`65000:1`), ethernet-tag `0`, VNI `100`.
  MACs are deterministic (`02:00:00:XX:YY:ZZ` with 24 bits = route
  index), so runs are exactly repeatable.
- ESI is zero — Gate 4 / M32 already validated the multi-homing
  attribute pipeline; Gate 5 / M33 isolates scale of the reflection
  hot path.
- The IETF draft [Benchmarking Methodology for EVPN][evpn-bmwg]
  proposes much larger targets (32k EVIs, 2M MACs, 24 h soak).
  M33 is scoped to the production-ready-at-fabric-scale claim
  (10k+ MACs); larger-scale harness work is future roadmap.

[evpn-bmwg]: https://datatracker.ietf.org/doc/html/draft-kishjac-bmwg-evpntest-00

## Running End-to-End Benchmarks

End-to-end system benchmarks use [bgperf2](https://github.com/netenglabs/bgperf2),
a Docker-based BGP benchmarking harness. bgperf2 lives outside the rustbgpd repo.

### Prerequisites

- Docker running
- bgperf2 checked out (e.g. `~/projects/bgperf2`)
- Python virtualenv with bgperf2 dependencies

### Build the Docker image

```bash
cd /path/to/bgperf2
source .venv/bin/activate
python -c "
from rustbgpd import RustBGPd
RustBGPd.build_image(force=True, nocache=True)
"
```

**Critical:** Always use `nocache=True` when rebuilding. Without it, Docker
caches the builder stage and reuses stale binaries. This has caused phantom
benchmark results in the past.

### Run a benchmark

```bash
# Clean up any leftover containers
docker rm -f $(docker ps -aq --filter "name=bgperf") 2>/dev/null
docker network rm bgperf-net bgperf2-br 2>/dev/null

# Run: 2 peers, 100k prefixes each (200k total)
python bgperf2.py bench -t rustbgpd -n 2 -p 100000

# Other scenarios
python bgperf2.py bench -t rustbgpd -n 10 -p 1000    # 10 peers, 1k each
python bgperf2.py bench -t rustbgpd -n 2 -p 10000     # 2 peers, 10k each

# Compare against other daemons
python bgperf2.py bench -t bird -n 2 -p 100000
python bgperf2.py bench -t gobgp -n 2 -p 100000
```

Output is a CSV line with convergence time, max CPU, max memory, etc.

### Heap profiling with dhat

rustbgpd has a feature-gated dhat heap profiler. To capture a heap profile:

```bash
# Build with dhat profiling (slower, ~2x overhead)
python -c "
from rustbgpd import RustBGPd
RustBGPd.build_image(force=True, nocache=True, profile='dhat')
"

# Run the benchmark in the background
python bgperf2.py bench -t rustbgpd -n 2 -p 100000 &

# Wait for convergence (~40s with dhat overhead)
sleep 50

# Send SIGTERM to rustbgpd to trigger profile dump
# Note: pgrep/kill may not exist in the container; use /proc scanning
docker exec bgperf_rustbgpd_target bash -c '
for p in /proc/[0-9]*/cmdline; do
  if grep -ql rustbgpd "$p" 2>/dev/null; then
    pid=$(echo "$p" | cut -d/ -f3)
    kill -TERM "$pid"
  fi
done'

# Wait for profile write, then extract
sleep 8
docker cp bgperf_rustbgpd_target:/root/config/dhat-heap.json ./dhat-heap.json
```

View the profile at https://nnethercote.github.io/dh_view/dh_view.html

### Gotchas

- **Docker image caching.** Always `nocache=True`. Stale binaries produce
  misleading results.
- **Container cleanup.** bgperf2 sometimes leaves containers running after the
  benchmark script exits. Clean up with `docker rm -f $(docker ps -aq --filter "name=bgperf")`.
- **PID 1 in Docker.** The `exec` in the startup script doesn't always replace
  bash as PID 1. rustbgpd may be a child process (e.g. PID 7). Use `/proc`
  scanning to find the right PID for SIGTERM.
- **Variance.** RSS measurements vary ~10-15% between runs due to allocator
  behavior and timing. Run 2-3 times and take the median.
- **dhat overhead.** dhat wraps every allocation, adding ~2x CPU overhead and
  ~40% memory overhead. The tracked heap numbers are accurate but RSS will be
  higher than production builds.
