# Benchmarks

Micro-benchmarks using [Criterion](https://github.com/bheisler/criterion.rs) 0.8,
compiled with `--release` (LTO, codegen-units=1). Numbers below are meant
for relative comparison and regression tracking, not absolute guarantees.

**Last measured: 2026-05-27 (v0.30.0)**

| Field | Value |
|-------|-------|
| Hardware | AMD Ryzen Threadripper 7970X (32 cores / 64 threads) |
| Kernel | Linux 6.17.0-20-generic |
| rustc | 1.95.0 (2026-04-14) |
| Criterion | 0.8 |
| Measurement state | Unpinned unless noted — no `isolcpus`, no `cpufreq` governor pinning; light background load (`scaling_cur_freq` ~51% at run time) |

Empirical run-to-run variance for the smaller benches on this box has been
observed up to ~30% in this unpinned state — re-runs at the same commit can
drift this much. Expect tighter results from a pinned, quiesced measurement
state. The non-criterion **Memory Footprint**, **Optimization History**, and
**End-to-End System Benchmarks** sections below have not been re-measured for
v0.30.0 — they reflect the release in which they were last refreshed.

The **Adj-RIB-In Insert** regression check below was re-run in a pinned state
(`performance` governor, `taskset -c 8`) after a small route-layout fix.

## Secondary measurement environment — self-hosted VPS bench runner

The `Criterion Bench Compare` workflow (`.github/workflows/bench.yml`)
runs on a dedicated VPS registered as a `[self-hosted, rustbgpd-bench]`
runner. Numbers from CI dispatches are produced in this environment,
not the primary host described above. Two environments give us A/B
deltas on PRs without coupling them to a single machine.

| Field | Value |
|-------|-------|
| Hardware | Virtualized x86_64 guest on bare-metal Intel host (2 vCPU, ~1.9 GiB RAM, 2 GiB swap, 30 GB disk) |
| Kernel | Linux 6.8.0-117-generic |
| OS | Ubuntu 24.04.2 LTS |
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
entirely so this doesn't change anything for laptop /
Threadripper-style hosts. The sudo / `$HOME` trap (running soak as
root moves the lock to `/root/...` and bypasses the guard) is covered
in `tests/soak/README.md` under "Host mutex".

## Running

```bash
# All benchmarks
cargo bench --bench codec --bench rib_ops --bench policy_eval

# Wire codec only
cargo bench -p rustbgpd-wire --bench codec

# RIB only
cargo bench -p rustbgpd-rib --bench rib_ops

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
│ stddev ≥ ~ same-SHA noise floor
│         (~10–11%) ? ─────────────────► INCONCLUSIVE: re-dispatch, more attempts
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
Both `AdjRibIn` and `AdjRibOut` use secondary prefix indexes for O(1)
per-prefix lookup, avoiding the O(N) full-scans that dominated earlier versions.

### Best-Path Comparison

1000 pairwise `best_path_cmp()` calls per iteration. The 10-step tiebreak
(stale, RPKI, LOCAL_PREF, AS_PATH len, ORIGIN, MED, eBGP pref, CLUSTER_LIST,
ORIGINATOR_ID, peer addr) is the inner loop of best-path selection.

| Scenario | Time (1000 calls) | Per-call |
|----------|-------------------|----------|
| Equal routes (full tiebreak) | 18.2 µs | 18.2 ns |
| LOCAL_PREF differs (early exit) | 4.95 µs | 4.95 ns |
| Different peers (full tiebreak) | 18.4 µs | 18.4 ns |

Early exit at LOCAL_PREF is ~3.7× faster than a full tiebreak. In typical eBGP
deployments most comparisons resolve at LOCAL_PREF or AS_PATH length.

### Adj-RIB-In Insert

Bulk insert into a fresh `AdjRibIn` (HashMap keyed by `(Prefix, path_id)` plus
secondary prefix index).

| Routes | Time | Throughput |
|--------|------|------------|
| 10,000 | 3.60 ms | 2.8M routes/sec |
| 100,000 | 54.1 ms | 1.8M routes/sec |
| 500,000 | 178 ms | 2.8M routes/sec |

Throughput is ~1.8-2.8M routes/sec across scale (vs 4.5M without the prefix
index). The trade-off is worthwhile: insert is ~1.8× slower, but
`iter_prefix()` goes from O(N) to O(1), making the full pipeline 25-86× faster
at scale. A full Internet table (900k prefixes) inserts in ~350 ms.

Pinned follow-up measurements confirmed the previous small-N regression was
real, not noise: current `main` measured 3.98 ms median at 10 k versus
3.56 ms at v0.24.0 (+11.9%). The cause was per-clone `Route` size growth from
the RFC 8950 unnumbered `next_hop_scope` field. Boxing the rare scope payload
reduces `Route` from 136 bytes to 120 bytes and brings the 10 k insert median
back to 3.60 ms, within 1.2% of the v0.24.0 baseline. The 500 k insert median
stays flat against current `main` within measurement noise.

### Loc-RIB Recompute

Best-path selection for a single prefix with N candidate routes.

| Candidates | Time |
|------------|------|
| 1 | 75 ns |
| 2 | 85 ns |
| 4 | 119 ns |
| 8 | 196 ns |

Linear in candidate count, as expected. With Add-Path or multiple peers
advertising the same prefix, each additional candidate adds ~17 ns
(one `best_path_cmp` call).

### Full Pipeline

End-to-end: insert routes from 2 peers into Adj-RIB-In, recompute best path
for every prefix, install into Adj-RIB-Out. This exercises the real hot path
without async/channel overhead.

| Prefixes (×2 peers) | Time | Per-prefix |
|----------------------|------|------------|
| 1,000 | 783 µs | 783 ns |
| 10,000 | 9.64 ms | 0.96 µs |
| 50,000 | 80.7 ms | 1.61 µs |

Scaling is roughly linear (O(N)) thanks to the secondary prefix index.
Previous versions used an O(N) scan per prefix in `iter_prefix()`, making the
full pipeline O(N²) — the 50 k benchmark took 7.1 s vs 81 ms now (**~88×
improvement**).

Extrapolating linearly, a full Internet table (900 k prefixes × 2 peers) would
complete the pipeline in ~1.5 s.

### Bulk Initial Load

Cold single-peer table load into pre-sized Adj-RIB-In / Loc-RIB /
Adj-RIB-Out. This is the benchmark shape to use when judging full-table
convergence changes; it intentionally separates initial table load from the
two-peer `rib_pipeline` micro-benchmark above.

Run it with:

```bash
cargo bench -p rustbgpd-rib --bench rib_ops -- "bulk_initial_load"
```

The v0.30.0 baseline has not been pinned yet. Record numbers here only after
running through the pinned compare workflow described above.

### Route Churn

10,000 base routes from peer 1, then 1,000 route announcements from peer 2
followed by 1,000 withdrawals, with best-path recomputation at each step.

| Benchmark | Time |
|-----------|------|
| 10k base + 1k announce/withdraw cycle | 633 µs |

A 1 k-prefix churn event reconverges in under 1 ms, including both the
announce and withdraw phases. This is ~44× faster than the pre-index version
(27.9 ms).

## Memory Footprint

Measured using a tracking global allocator that counts every `alloc` and
`dealloc`. Run with:
`cargo test -p rustbgpd-rib --test memory_profile -- --nocapture`

### Type Sizes (stack)

| Type | Size |
|------|------|
| `Route` | 120 bytes |
| `Prefix` | 18 bytes |
| `PathAttribute` | 72 bytes |
| `AsPath` | 24 bytes |
| `AdjRibIn` | 264 bytes |
| `LocRib` | 96 bytes |

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
| Typical (6 attrs, 3-ASN path, 2 communities) | 524 B | 120 B | 644 B |
| Rich (8 attrs, 5-ASN+SET path, 5 communities, ORIGINATOR_ID, CLUSTER_LIST) | 736 B | 120 B | 856 B |

These are per-unique-attribute-set costs. With interning, routes sharing the
same attributes pay only the 120-byte `Route` stack cost plus an 8-byte `Arc`
pointer.

### AdjRibIn at Scale (single peer, typical attrs)

| Routes | Resident | Per-route |
|--------|----------|-----------|
| 10,000 | 3.3 MB | 340 B |
| 100,000 | 26.7 MB | 279 B |
| 500,000 | 203 MB | 426 B |
| 900,000 | 217 MB | 252 B |

Per-route cost is ~252-426 bytes including HashMap overhead, prefix index, and
intern table. The dramatic reduction from pre-interning numbers (776-950 B/route)
comes from sharing the ~524-byte attribute allocation across all routes with
identical attributes. A typical peer's full table has only a handful of unique
attribute sets (~50-200), so the attribute heap cost is effectively amortized
to near zero per route.

### Full RIB: 2 Peers + LocRib (typical attrs)

| Prefixes | Total memory | Per-prefix |
|----------|-------------|------------|
| 100,000 | 68 MB | 707 B |
| 500,000 | 519 MB | 1.1 KB |
| 900,000 | 547 MB | 637 B |

A full Internet table (900k prefixes) with 2 peers and best-path selection uses
**547 MB**. Each prefix stores 3 Route instances (2x Adj-RIB-In + 1x Loc-RIB)
with `Arc` sharing across all three copies. Path attribute interning within each
`AdjRibIn` further reduces memory by sharing attribute allocations across routes
with identical attributes. This is **15-29x less than GoBGP** (8-16+ GB) and
approaching BIRD (~325 MB for 30 peers).

### Optimization History

| Version | Full RIB (900k x 2 peers) | Per-prefix | vs GoBGP |
|---------|--------------------------|------------|----------|
| Pre-Arc (`Vec<PathAttribute>`) | 1.80 GB | 2.1 KB | 4-9x less |
| Arc sharing (v0.4.2) | 1.41 GB | 1.6 KB | 6-11x less |
| Arc + interning (current) | 547 MB | 637 B | 15-29x less |

### Optimization History (end-to-end, bgperf2 2p/100k)

| Change | Memory | Convergence |
|--------|--------|-------------|
| Pre-AdjRibOut index | 168 MB | 71s |
| + AdjRibOut secondary prefix index | 415 MB | 12s |
| + Skip unnecessary Arc deep clones | 257 MB | 11s |
| + AdjRibOut capacity hints | ~260 MB | 11s |

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

## Interpretation

**Wire codec** — The codec is not a bottleneck. Parsing a full-size UPDATE (500
prefixes, typical attributes) takes 3.3us. At 1 Gbps line rate, BGP UPDATE
arrival rate is far lower than decode capacity. The two-phase decode/parse
design means sessions that only need header inspection (keepalives, most
notifications) pay no attribute decode cost.

**RIB insert** — Bulk insert at 2.6M routes/sec means a full Internet table
loads in ~350ms. This is well within acceptable convergence time for
route-server deployments.

**Best-path selection** — At 18.5ns per comparison, even 8-candidate Add-Path
selection completes in 213ns per prefix. Best-path is not a bottleneck.

**Pipeline scaling** — With the secondary prefix index, the pipeline scales
linearly. 50k prefixes x 2 peers completes in 82ms. Extrapolated full-table
(900k) would take ~1.5s for a complete 2-peer recomputation — well within
operational requirements.

**Route churn** — Sub-millisecond reconvergence for 1k-prefix flap events.
Real-world churn involves far fewer prefixes per UPDATE (typically 1-50),
so per-event reconvergence is effectively instant.

## End-to-End System Benchmarks

Measured using [bgperf2](https://github.com/netenglabs/bgperf2), a Docker-based
BGP benchmarking harness. Each test runs a target daemon, N BIRD tester peers
(each advertising P prefixes), and a GoBGP monitor peer that observes convergence.
The monitor's accepted route count is the ground truth for completion.

**Environment:** AMD Ryzen 9 7950X (64 logical cores), 125 GB RAM, Linux 6.17,
Docker 27.x. All daemons run in containers on the same host.

**Methodology:** Convergence time is measured from first prefix received by the
monitor to all expected prefixes received. The test harness waits for 5 seconds
of stability before declaring completion. Total time includes session
establishment.

### Results

Benchmarks run at v0.4.2; the RIB hot-path has been unchanged through v0.24.0
in ways that would invalidate these numbers, but the runs themselves have not
been re-executed against current main. Fresh runs against the v0.24.0 main and
under EVPN VTEP / IRB modes are tracked as follow-up work; treat the numbers
below as directional rather than current.

#### 10 peers x 1,000 prefixes (10k total)

| | BIRD 2.18 | GoBGP 4.3.0 | rustbgpd 0.4.2 |
|---|---|---|---|
| Convergence | 1s | 2s | 2s |
| Max CPU | 9% | 10% | 18% |
| Max Memory | 2 MB | 188 MB | 80 MB |
| Total time | 2s | 3s | 11s |

#### 2 peers x 10,000 prefixes (20k total)

| | BIRD 2.18 | GoBGP 4.3.0 | rustbgpd 0.4.2 |
|---|---|---|---|
| Convergence | 1s | 2s | 2s |
| Max CPU | 9% | 10% | 18% |
| Max Memory | 1 MB | 89 MB | 62 MB |
| Total time | 2s | 3s | 11s |

#### 2 peers x 100,000 prefixes (200k total)

| | BIRD 2.18 | GoBGP 4.3.0 | rustbgpd 0.4.2 |
|---|---|---|---|
| Convergence | 2s | 5s | 2s |
| Max CPU | 13% | 16% | 112% |
| Max Memory | 7 MB | 578 MB | 257 MB |
| Total time | 3s | 6s | 11s |

### Understanding the Numbers

**Session establishment.** rustbgpd's ConnectRetryTimer defaults to 5 seconds
(reduced from the RFC 4271 suggested 30 seconds). When BIRD tester peers start
after rustbgpd, the first outbound connection attempt fails and the retry fires
within 5 seconds. Total establishment overhead is ~9 seconds, compared to 1-2
seconds for BIRD (accepts inbound immediately) and GoBGP (passive neighbor
mode). Further improvement would require listen-mode-first startup.

**Route processing.** At 10k and below, convergence completes in 2 seconds —
matching GoBGP and within 1 second of BIRD. At 200k prefixes, rustbgpd
converges in 2 seconds (monitor time), competitive with BIRD (2s) and faster
than GoBGP (5s). The key optimizations were: (1) secondary prefix index in
`AdjRibOut` converting per-prefix lookup from O(N) to O(1), and (2) skipping
unnecessary `Arc::make_mut()` deep clones in the distribution path when no
export policy modifications are configured.

**CPU efficiency.** rustbgpd uses a single-threaded RIB (single tokio task,
no locks). At 200k scale it peaks at 112% CPU (RIB + transport tasks). BIRD
is the most efficient at 13% CPU, reflecting decades of C optimization with a
radix-tree RIB.

**Memory.** rustbgpd uses 257 MB for 200k routes (2 peers + Loc-RIB +
Adj-RIB-Out), **2.3x less than GoBGP** (578 MB). Remaining memory is
dominated by HashMap bucket arrays (~78% of tracked heap) and Route struct
data (~19%). BIRD uses 7 MB — still an order of magnitude less, reflecting
its compact radix-tree representation. At full-table scale (900k prefixes,
micro-bench), rustbgpd uses 547 MB for Adj-RIB-In + Loc-RIB vs GoBGP's
published 8-16+ GB.

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
| Memory (200k routes) | 7 MB | 578 MB | 257 MB |
| Memory (900k, micro-bench) | ~325 MB (published, 30 peers) | 8-16+ GB (published) | 547 MB (2 peers + Loc-RIB) |
| API during load | Responsive (no RIB contention) | Responsive (concurrent) | Responsive (priority query channel) |

BIRD is the clear performance leader — 30+ years of optimization in a
purpose-built C codebase is hard to beat. rustbgpd converges 200k prefixes in
2 seconds (monitor time), matching BIRD and beating GoBGP (5s). Memory at
257 MB is 2.3x less than GoBGP (578 MB); at full-table scale (900k,
micro-bench) the gap widens further (547 MB vs 8-16 GB). The remaining memory
is structural — HashMap bucket arrays and Route data — with no obvious
accidental overhead. Further memory reduction would require shared route
storage across RIB views or alternative data structures.

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
- bgperf2 checked out (e.g. `/home/lance/projects/bgperf2`)
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
