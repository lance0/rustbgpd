# Benchmarks

Micro-benchmarks using [Criterion](https://github.com/bheisler/criterion.rs) 0.8,
compiled with `--release` (LTO, codegen-units=1). Numbers below are meant
for relative comparison and regression tracking, not absolute guarantees.
For the consolidated operator-facing proof index that rolls benchmark, memory,
interop, dataplane, and soak receipts together, see
[`OPERATIONAL_PROOF.md`](OPERATIONAL_PROOF.md).

jemalloc is the default allocator feature, so a plain
`cargo build --release` produces the same allocator configuration as the
published artifacts — the GHCR runtime image and the release tarballs
(which have built with jemalloc since v0.50.0+; earlier releases shipped
a CI-profile, glibc-malloc build). This matters for memory numbers: an
8-cycle policy-reload probe at 200 peers × 115k prefixes showed
stock-glibc RSS climbing 301→555 MiB and 295→639 MiB across two runs
without returning memory (live bytes flat — allocator arena retention of
reload transients), while the identical workload under jemalloc
oscillated at 270–330 MiB and returned memory via background decay.
Daemon RSS figures measured on glibc builds before 2026-07-17 overstate
steady-state RSS relative to the shipped binary. A stock-glibc build
remains available via `--no-default-features`.

**Last measured:** RIB Operations pinned A/B: 2026-05-29; same-host
current-main reconfirmation and memory attribution correction: 2026-06-02;
structured high-N RIB memory profile: 2026-06-08; authoritative exact-export
distribution fanout A/B, update-group recovery, and grouped exact-precommit
fast path: 2026-07-13; revision-pinned production-exact manager CPU and
full-daemon DHAT rebaseline: 2026-07-13; structured high-N RIB memory
profile refresh (RouteSlab + attribute interning correction): 2026-07-17.

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

**Empirical noise floor: ~11% spread on this host, at this one shape.**
Five sequential pinned runs at the same `main` SHA (2026-05-28
calibration on `adj_rib_in_insert/10000`) produced medians of 8.232 ms,
8.446 ms, 8.693 ms, 8.979 ms, and 9.212 ms — a max-minus-min spread of
11.2% of the mean.

**Do not carry that 11.2% to other hosts or other shapes.** The floor is
a property of a (host, benchmark, size) triple, not a global constant.
Same-SHA controls on the primary host (2026-07-25, six alternating
attempts, `performance` governor, `taskset -c 8`) measured
`adj_rib_in_insert/10000` at 1.44% — roughly eight times tighter than
this runner's figure for the identical shape — while
`adj_rib_in_insert/100000` on that same host measured 16.76%, and
`rib_pipeline/1000` measured 0.55%. Applied as one number, an 11.2%
floor hides real regressions at the tight shapes and manufactures
phantom ones at the noisy shapes. Read the floor from a same-SHA control
on the host doing the measuring, at the shape being measured; the
per-shape figures and the method are in
[`perf/rib-criterion-noise-floor-2026-07.md`](perf/rib-criterion-noise-floor-2026-07.md).

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
# Default-feature benchmarks. A bare `cargo bench` runs only the targets that
# build with default features (codec, rib_ops, policy_eval, explain_snapshot,
# validate); the five `bench-internals`-gated targets (fanout, inbound_attrs,
# fib_projection, route_paging, event_history_producer) are skipped and must
# be run explicitly with `--features bench-internals` as shown below.
cargo bench

# Wire codec only
cargo bench -p rustbgpd-wire --bench codec

# RIB only
cargo bench -p rustbgpd-rib --bench rib_ops

# Root-daemon FIB projection internals (requires bench-internals)
cargo bench --features bench-internals --bench fib_projection

# Inbound UPDATE attribute-clone churn (requires bench-internals)
cargo bench -p rustbgpd-transport --features bench-internals --bench inbound_attrs

# Manager fanout with the authoritative exact export probe
cargo bench -p rustbgpd-transport --features bench-internals --bench fanout

# RPKI origin-validation microbench (RFC 6811)
cargo bench -p rustbgpd-rpki --bench validate

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

When a pull request claims a durable performance gain, check in a receipt under
`docs/perf/` with the exact refs, environment, command, sampling parameters,
confidence bounds, and correctness fence. Also check in a compact
machine-readable CSV or JSON summary and index the receipt from
[`RECEIPTS.md`](RECEIPTS.md). A PR description or raw files left only under
`target/criterion/` are useful review evidence, but they are not a durable
project receipt.

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
| `verdict` | optional script classifier for CI tripwires | `regression` only when enough attempts completed, `min..max` is entirely positive, stddev is below the configured ceiling, mean delta crosses the configured threshold, and the last run's propagated 95% CI is entirely above zero. Other informational labels are `ci-straddles-zero` (all-positive deltas above threshold but the last-run CI straddles zero — advisory, does not fail the gate), `noise`, `improvement`, `positive-under-threshold`, `inconclusive-noisy`, `insufficient-attempts`, and `missing`. |

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

`bench/compare-criterion.sh --fail-on-regression` codifies the confident
regression branch for unattended use. The nightly release-baseline workflow
enables it with the default `--verdict-min-attempts 3` and
`--regression-threshold-pct 3` plus `--regression-max-stddev-pct 10`: rows
whose `min..max` straddles zero remain advisory/noise, high-stddev rows remain
inconclusive, all-positive rows whose last-run 95% CI straddles zero stay
advisory (`ci-straddles-zero`), and a confirmed row at or above the threshold
whose last-run 95% CI is entirely above zero makes the workflow fail for human
review.

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

1000 pairwise `best_path_cmp()` calls per iteration. The 11-step tiebreak
(stale, RPKI, ASPA, LOCAL_PREF, AS_PATH len, ORIGIN, MED, eBGP pref,
CLUSTER_LIST, ORIGINATOR_ID, peer addr) is the inner loop of best-path
selection.

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

The benchmark now belongs to the transport crate so it can install a distinct
authoritative `SessionExportEncoder` for every synthetic peer without creating
a RIB-to-transport dependency cycle. Run it with:

```bash
cargo bench -p rustbgpd-transport --features bench-internals --bench fanout
```

The `adj_rib_out_family_gauge` group is the allocation-sensitive steady-state
control. It keeps persistent homogeneous route-server fleets at 8, 64, 256,
and 1,000 peers, drains the prewarm advertisement, and alternates a wire-visible
MED across all 64 routes before each measured pass. Route mutation, Loc-RIB
recompute, receipt assertions, and receiver draining stay outside accumulated
time. The measured interval covers manager distribution, the real exact-export
probe and compatible grouped reuse, authoritative Adj-RIB-Out commit, metric
refresh, and bounded-channel enqueue; it does not include session-writer or
network I/O. In-code receipts require one update group, one full real probe per
changed route, compatible reuse for every remaining member, one successful
route-bearing commit and enqueue per peer, no dirty or ungrouped fallback, and
exact family-gauge values. The immediately preceding harness commit is the
unchanged-behavior control (seven family refreshes per peer); the optimized
target refreshes only the touched family while retaining all seven eager-zero
series from PeerUp onward.

The pinned July 2026 control/target receipt is retained in
[`docs/perf/adj-rib-out-family-gauge-2026-07.md`](perf/adj-rib-out-family-gauge-2026-07.md).
At 256 and 1,000 peers it improves the measured actor/probe/commit/enqueue
interval by 11.69% and 14.98%, respectively; both mean-change 95% confidence
intervals exclude zero.

The July 2026 receipt compares the first real-probe baseline against ordered
batch probing with the live prepared-attribute memo key:

| Peers | No policy baseline → memo | Change | Policy baseline → memo | Change |
|-------|---------------------------|--------|------------------------|--------|
| 1 | 45.970 → 35.488 µs | -22.3% | 49.477 → 39.558 µs | -20.3% |
| 8 | 252.770 → 173.382 µs | -31.7% | 256.996 → 181.819 µs | -29.3% |
| 64 | 1.920 → 1.328 ms | -30.5% | 1.919 → 1.326 ms | -30.9% |
| 256 | 7.795 → 5.283 ms | -31.3% | 7.778 → 6.407 ms | -18.3% |

All Criterion mean-change 95% confidence intervals are entirely below zero.

That memo still left the exact probe scaling per peer. A second pinned campaign
compares current `main`'s permissive benchmark, the pre-cache real-probe head,
and successful-length reuse across provably wire-equivalent members of the one
update group exercised by this benchmark:

| Peers | No policy: `main` / pre-cache / optimized | Optimized vs pre-cache | Policy: `main` / pre-cache / optimized | Optimized vs pre-cache |
|-------|--------------------------------------------|------------------------|-----------------------------------------|------------------------|
| 1 | 21.148 / 36.395 / 35.908 µs | -1.84% | 24.494 / 40.012 / 39.993 µs | -0.98% |
| 8 | 56.415 / 180.416 / 94.704 µs | -47.33% | 62.745 / 183.181 / 102.689 µs | -43.99% |
| 64 | 318.064 µs / 1.382 ms / 543.301 µs | -60.98% | 356.086 µs / 1.369 ms / 584.361 µs | -57.50% |
| 256 | 1.251 / 5.886 / 2.068 ms | -64.28% | 1.372 / 5.341 / 2.234 ms | -58.31% |

At 256 peers this reduces the overhead relative to the permissive control from
4.706x to 1.653x without policy (82.37% of the excess recovered), and from
3.893x to 1.629x with policy (78.28% recovered). This is one update group's
64-route IPv4 first-advertise burst, not a resync or full-table measurement.

The reuse cache lives for one distribution pass, requires the same group and
pointer-identical shared unicast payload slices, and retains at most eight
wire-equivalence cohorts per group. Transport proves equivalence by full
normalized session-profile equality excluding only owner, generation, and the
message ceiling; the target re-applies its own ceiling and generation. Only
cardinality-correct all-success batches are retained. Default-refusing
snapshots, non-shared/resync/exception payloads, and mixed-family envelopes
remain on the ordinary exact-probe path.

A third pinned campaign removes the remaining eager per-member bookkeeping on
the common clean grouped path. Candidate keys and the group's prior advertised
set are now materialized only when a failed probe or existing rejection
overlay needs reconciliation:

| Peers | No policy baseline → optimized | Change | Policy baseline → optimized | Change |
|-------|--------------------------------|--------|-----------------------------|--------|
| 1 | 42.11 → 38.84 µs | -7.76% | 46.48 → 42.83 µs | -7.85% |
| 8 | 103.96 → 79.11 µs | -23.90% | 111.87 → 86.48 µs | -22.69% |
| 64 | 573.75 → 377.92 µs | -34.13% | 615.84 → 416.22 µs | -32.41% |
| 256 | 2.19 → 1.39 ms | -36.27% | 2.33 → 1.55 ms | -33.46% |

The complementary manager-level rrharness reproduced the scaling result in
both counterbalanced repetitions: +197%..+200% for 256-peer flood,
+280%..+282% for 1,000-peer flood, +480%..+491% for 256×256 churn, and
+639%..+649% for 1,000×1,000 churn. All 16 cells passed the load/governor/no-
competitor preflight. The strict Criterion receipt has 16 rows and 32 exact
input hashes; every required 64/256-peer conservative 95% CI stayed below zero,
and both one-peer shapes improved rather than consuming the 5% regression
allowance.

This fast path does not skip per-target ceiling/generation checks. It is used
only when every probe succeeds for a clean grouped member with no rejection
overlay. Failures, overlays, resync/regroup, VPN or mixed-family envelopes, and
non-shared payloads retain the ordinary exact reconciliation path.

The full environments, commands, commit IDs, confidence intervals, correctness
fences, and checked-in artifacts for all three campaigns are in the
[`exact-export fanout receipt`](perf/exact-export-fanout-2026-07.md).

The previous 2026-06 numbers used a permissive benchmark stub and did not time
the exact export probe; they are superseded rather than a valid A/B baseline.
The first optimization still built one exact `UpdateMessage` per candidate and
only shared prepared attributes. The cohort optimization builds one exact
message per shared route and compatible cohort, then rechecks the encoded
length against each target's ceiling. It preserves the exact correctness gate,
but must not be described as performing a full exact encode per peer.

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

> **Run provenance (2026-07-17).** Clean build (`cargo clean` first) at HEAD
> `96c1d6e9`, `RUSTBGPD_RIB_MEMORY_PROFILE=full cargo test -p rustbgpd-rib
> --features bench-internals --test memory_profile memory_profile_high_n --
> --ignored --nocapture`, on the pinned bench host. These figures replace an
> older set that predated the RouteSlab migration (LAN-335) and the
> `PathAttribute` enum growth to 208 bytes — see the correction note under the
> at-scale tables below.

Measured using a tracking global allocator that counts every `alloc` and
`dealloc`. The normal test compiles and schema-checks the harness; the ignored
high-N profile emits JSONL rows for the comparison script.

```bash
# Compile/schema guard
cargo test -p rustbgpd-rib --features bench-internals --test memory_profile

# Manual full profile (100k / 500k / 900k)
RUSTBGPD_RIB_MEMORY_PROFILE=full \
  cargo test -p rustbgpd-rib --features bench-internals \
  --test memory_profile memory_profile_high_n -- --ignored --nocapture

# A/B summary against another ref
bench/compare-rib-memory.sh --base origin/main --head HEAD --profile quick
```

### Type Sizes (stack)

| Type | Size |
|------|------|
| `Route` | 128 bytes |
| `Prefix` | 18 bytes |
| `PathAttribute` | 208 bytes |
| `AsPath` | 24 bytes |
| `AsPathSegment` | 32 bytes |
| `AdjRibIn` | 1336 bytes |
| `LocRib` | 1008 bytes |

`PathAttribute` grew from 112 to 208 bytes since the last figures in this
doc: new attribute variants (RFC 6514 `PmsiTunnel`, RFC 9234
`OnlyToCustomer`) plus larger payloads on the existing variants that now
carry the newer RIB families (VPN, labeled-unicast, RT-Constrain, EVPN,
BGP-LS). It is interned (globally, across all peers — LAN-336), so the
per-route impact is amortized to near zero (see below), but it does raise
the per-unique-attribute-set heap cost.

`AdjRibIn` (1032 → 1336 bytes) and `LocRib` (96 → 1008 bytes) grew the same
way — each struct picked up a route map and/or secondary index per added RIB
family (VPN, labeled-unicast, RT-Constrain, EVPN, BGP-LS, FlowSpec; see
`crates/rib/src/adj_rib_in.rs` and `crates/rib/src/loc_rib.rs`). Confirmed
via `std::mem::size_of` against the current struct definitions; these two
rows aren't in the allocator-tracked harness JSON.

`Route.attributes` is `Arc<Vec<PathAttribute>>` — cloning a route between
Adj-RIB-In, Loc-RIB, and Adj-RIB-Out shares the attribute allocation via
reference counting. Mutation uses `Arc::make_mut()` (copy-on-write).

Path attribute interning deduplicates identical attribute sets across routes
from ALL peers: a single RIB-manager-owned `AttrInternTable` (LAN-336, the
analog of BIRD's `rta` cache) maps each unique attribute set to a shared
`Arc`. Routes with identical attributes — bulk advertisements from one peer,
or the same route re-advertised by multiple RR clients — share one heap
allocation instead of one copy per route or per peer.

### Per-Route Heap Allocation

> **Not re-measured this pass.** `PathAttribute` grew 112 → 208 bytes
> (confirmed above), which changes the per-attribute-set heap totals below,
> but the nested-allocation breakdown (the `AsPath` segment `Vec`, the
> `Communities` `Vec<u32>`, etc.) needs a fresh dhat pass to attribute
> correctly. Treat the two rows below as stale pending that re-measure.

| Attribute set | Heap | Stack | Total |
|---------------|------|-------|-------|
| Typical (6 attrs, 3-ASN path, 2 communities) | 764 B | 128 B | 892 B |
| Rich (8 attrs, 5-ASN+SET path, 5 communities, ORIGINATOR_ID, CLUSTER_LIST) | 1056 B | 128 B | 1184 B |

These are per-unique-attribute-set costs. With interning, routes sharing the
same attributes pay only the 128-byte `Route` stack cost plus an 8-byte `Arc`
pointer.

### AdjRibIn at Scale (single peer, typical attrs)

| Routes | Live heap | Per-route | Route-map capacity |
|--------|----------:|----------:|--------------------:|
| 100,000 | 15.3 MiB | 160 B | 100,000 |
| 500,000 | 73.5 MiB | 154 B | 500,000 |
| 900,000 | 134.9 MiB | 157 B | 900,000 |

Since LAN-335, `AdjRibIn` route storage is a dense `RouteSlab`
(`crates/rib/src/slab.rs`), not a power-of-2-rounded `HashMap` — capacity now
equals the exact route count, and the old rounded-plateau curve no longer
applies. Per-route cost includes the slab, the trie-backed prefix index, and
the intern table; this pass doesn't break out a separate prefix-index byte
count (see the run-provenance note above the Type Sizes table).

### Full RIB: 2 Peers + LocRib (typical attrs)

| Prefixes | Live heap | Per-prefix | Route copies | Route-map capacity |
|----------|----------:|-----------:|-------------:|--------------------:|
| 100,000 | 51.9 MiB | 544 B | 300,000 | 314,688 |
| 500,000 | 316.6 MiB | 663 B | 1,500,000 | 1,917,504 |
| 900,000 | 439.7 MiB | 512 B | 2,700,000 | 2,717,504 |

Route-map capacity is now a composite: two dense (`RouteSlab`, exact)
Adj-RIB-In capacities plus one rounded (`HashMap`) Loc-RIB capacity — LAN-335
only converted the per-peer Adj-RIB tables to a dense slab; Loc-RIB is
deliberately kept `HashMap`-backed (its lookup-hot best-path recompute
regressed on both compact-storage candidates tried — see
`crates/rib/src/loc_rib.rs`). This is the **RIB-only, allocator-tracked**
structural memory (2× Adj-RIB-In +
Loc-RIB); each prefix stores Route instances with `Arc` sharing of attributes
across copies, and global attribute interning shares one allocation across
routes with identical attributes, whichever peers they came from. It is **distinct from the
full-process RSS** below — it excludes the daemon's operational surfaces
(event-history, gRPC, telemetry, BFD, the tokio runtime, allocator arenas).

### RR / Route-Server Fanout Shape: 2 In + LocRib + 2 Out

| Prefixes | Live heap | Per-prefix | Route copies | Route-map capacity |
|----------|----------:|-----------:|-------------:|--------------------:|
| 100,000 | 82.6 MiB | 865 B | 500,000 | 514,688 |
| 500,000 | 463.7 MiB | 972 B | 2,500,000 | 2,917,504 |
| 900,000 | 709.5 MiB | 826 B | 4,500,000 | 4,517,504 |

Route-map capacity here is a composite of four dense (`RouteSlab`, exact)
Adj-RIB-In/Adj-RIB-Out capacities plus one rounded (`HashMap`) Loc-RIB
capacity, for the same reason as the Full RIB table above. This is the
structural memory shape closest to the dhat finding below: received
routes, best paths, and advertised-route maps are all present. It still excludes
full-daemon surfaces and allocator RSS behavior, so bgperf2 remains the
operator-facing process-memory number. The A/B review rule for this harness is
deliberately coarse: flag a row for review only when head grows by at least
**+5% and +32 MiB** for the same shape/size; smaller movement is recorded but
treated as allocator/map-capacity noise unless the PR is memory-targeted.

> **Correction — LAN-335 RouteSlab + attribute interning (2026-07-17).** The
> three tables above replace an older, larger set of numbers this doc carried
> for several releases; those older numbers overstated real memory use. For
> example, at 500k: Full RIB was previously reported as 484.0 MiB (now 316.6
> MiB, real) and RR/Fanout was previously reported as 815.0 MiB (now 463.7
> MiB, real). The drop is the dense `RouteSlab` storage (LAN-335) replacing
> per-route `HashMap` buckets in `AdjRibIn`/`AdjRibOut`, plus the existing
> benefit from global attribute interning (LAN-336) — not a regression in
> either direction; actual daemon memory footprint is better than this doc
> previously claimed.

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
>
> **Superseded (2026-07):** this profile predates the update-groups arc. The
> revision-pinned rebaseline in
> [`docs/perf/rib-rebaseline-2026-07-13.md`](perf/rib-rebaseline-2026-07-13.md)
> shows per-peer Adj-RIB-Out is now 0.05% (grouped peers share one group
> table). At the 210,338,877-byte live-heap peak, the group table is 22.06%,
> Loc-RIB 21.06%, Adj-RIB-In route storage 15.95%, the two prefix tries 16.37%,
> and the announcing-peers index 7.10%. The retained derivative, exact image
> identity, same-process bgperf row, and checksums make those the authoritative
> attribution values.

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

**Methodology:** "Convergence" is the harness `elapsed` column — monitor start
to all expected prefixes received — so it includes the wait for the first
prefix as well as the flood. "Total time" additionally includes session
establishment and harness setup. The harness prints memory labelled "MB" but
computes it 1024-based; the tables below convert it and label the result
**MiB**. RSS is the maximum resident set of the target container over the run.

### Results

**Re-measured 2026-07-26** (UTC; the harness records the host's local date as
2026-07-25) at commit `515659b1` — the code now on `main`, which has since moved
only through documentation changes. This run widened the field from three
daemons to **four** and added the two route-server shapes, which had never been
published. The full write-up, with per-run values behind every median, the
per-second establishment progressions, the disclosed harness defects, and the
retained artifacts, is the [cross-stack bgperf2
receipt](perf/competitive-bgperf2-2026-07.md).

**The target reports `rustbgpd 0.60.0` in the raw rows because the v0.61.0
version bump had not happened when the campaign ran.** The binary is the
v0.61.0 candidate; only the version string is behind.

Medians of 3 runs per cell, 6 for 10p × 1k. Versions: **rustbgpd** at
`515659b1`, **BIRD 2.18** (`branch.master.0ee9f93bd076`), **GoBGP 4.3.0**,
**FRR 10.7.0-dev** (an unpinned development build — every cell reported a
distinct build identifier). **Same-host caveat:** all four daemons, the BIRD
tester fleet, and the GoBGP monitor ran in containers on the one host described
above, so every target competes with the load generators that drive it. This is
a comparison under identical conditions, not an absolute figure for any daemon.

| Shape | rustbgpd | BIRD 2.18 | GoBGP 4.3.0 | FRR 10.7.0-dev |
|---|---|---|---|---|
| 10p × 1k | conv 2 s · total **8.23 s** · 7% · 37.9 MiB | conv 2 s · total 9.20 s · 2% · **8.2 MiB** | conv 3 s · total 10.32 s · 126% · 38.9 MiB | conv 3 s · total 10.27 s · 4% · 27.6 MiB |
| 2p × 10k | conv 2 s · total **8.26 s** · 7% · 48.1 MiB | conv 2 s · total 9.24 s · 1% · **9.2 MiB** | conv 3 s · total 10.34 s · 88% · 44.0 MiB | conv 3 s · total 9.31 s · 5% · 36.9 MiB |
| 2p × 100k | conv 3 s · total **12.32 s** · 41% · 212.0 MiB | conv 3 s · total 13.22 s · 6% · **27.6 MiB** | conv 6 s · total 16.49 s · 565% · 202.8 MiB | conv 4 s · total 13.39 s · 94% · 228.4 MiB |
| 30p × 1k *(new)* | conv 3 s · total **9.83 s** · 22% · 108.5 MiB | conv 3 s · total 10.87 s · 14% · **11.3 MiB** | conv 4 s · total 11.84 s · 897% · 68.6 MiB | conv 4 s · total 10.85 s · 11% · 51.2 MiB |
| 100p × 1k *(new)* | conv **3 s** · total **11.79 s** · 122% · 212.0 MiB | conv 5 s · total 15.22 s · 101% · **32.8 MiB** | conv 20 s · total 28.50 s · 1281% · 193.5 MiB | conv 7 s · total 16.01 s · 68% · 134.1 MiB |

**rustbgpd is fastest on total time at all five shapes**, and at 100 peers it
converges in 3 s against FRR's 7 s, BIRD's 5 s, and GoBGP's 20 s — the largest
separation in the campaign, at the shape rustbgpd is designed for.

> **rustbgpd is last on memory of all four daemons at 100p × 1k — its own
> target deployment.** 212.0 MiB against GoBGP's 193.5 MiB (1.10×), FRR's
> 134.1 MiB (1.58×), and BIRD's 32.8 MiB (6.46×). Against BIRD the ratio runs
> **4.6×–9.6× across every shape**, worst at 30p × 1k. This is the standing
> memory position, and it did not improve in this campaign.

> **Do not quote rustbgpd's RSS at these shapes as a single value.** It was the
> noisiest figure in the campaign: 86.0 / 108.5 / 131.1 MiB at 30p × 1k (a 42%
> spread) and 180.2 / 212.0 / 230.4 MiB at 100p × 1k (24%). GoBGP and FRR span
> 0.8–7.9% at the same shapes. A reader who reproduces and measures 131 MiB at
> 30 peers has not found a regression — that value is inside the measured
> range. The spread is published, not explained.

**Memory tracks peers, not routes.** 100p × 1k is 100,000 routes and 2p × 100k
is 200,000 routes, and both measure 212.0 MiB. Half the routes, identical
resident set: at route-server shapes memory is dominated by per-peer state
rather than route count. The *computed* marginal cost over the 10 → 100 peer
span is ~1.93 MiB/peer for rustbgpd against BIRD's ~0.27 MiB/peer (GoBGP ~1.72,
FRR ~1.18) — an upper bound for all four, since prefix totals also grow tenfold
across that span. **Any projection beyond 100 peers is *extrapolated*** and
assumes a linearity this campaign did not demonstrate; the 42% spread at the
midpoint says the curve needs measuring. The 1,000-peer receipts
([`perf/scale-receipt-2026-07.md`](perf/scale-receipt-2026-07.md),
[`perf/route-server-1000-2026-07.md`](perf/route-server-1000-2026-07.md)) are
the evidence at that scale.

**OpenBGPD could not be collected — a bgperf2 harness defect, not a daemon
result.** The harness launches `/usr/local/sbin/bgpd` while the image ships
binaries at `/usr/sbin/`, so the harness config never loads and the image's own
entrypoint runs with zero neighbors; `monitor.py wait_established()` is an
unbounded loop and hung about 11 minutes before the attempt was killed. The
comparison is therefore four-way. Root cause and retained evidence are in the
[receipt](perf/competitive-bgperf2-2026-07.md#openbgpd-could-not-be-collected--harness-defect-not-a-daemon-result).
The [IXP receipt matrix](perf/ixp-matrix-2026-07.md) carries a head-to-head
OpenBGPD 9.1 comparison through a different harness.

One BIRD cell needed a third run: 100p × 1k total measured 24.51 s, then
15.17 s, then 15.22 s, and the published median is 15.22 s. The outlier is a
harness startup artifact — the monitor-wait column read 9 s in that run against
0 s in the other two, and the difference is 9.34 s — not a BIRD result; BIRD's
convergence column read 5 s in all three runs.

**Deltas against the 2026-07-09 v0.50.0 three-way run** (same host and harness,
event-history off in both): the three shared shapes are flat to slightly better
on time (10p × 1k total 8.3 → 8.23 s, 2p × 10k 8.3 → 8.26 s, 2p × 100k
12.1 → 12.32 s) and 2p/100k RSS moved 246 → 212.0 MiB. The earlier run's memory
figures were reported in 1000-based MB against this run's MiB, so small
differences there are partly unit conversion; the shape of the result is
unchanged. BIRD and GoBGP versions are identical across the two runs.

### Understanding the Numbers

**Session establishment.** rustbgpd dials the passive BIRD testers, which bind
their listeners ~1-2s after rustbgpd starts, so the first outbound TCP dial is
refused. Before the fast-retry change, that first refusal armed a ~10s backoff
timer (`connect_retry_secs` base × exponential), so rustbgpd sat idle until the
timer fired even though the testers were ready within ~2s — establishment took
~10s. `main` now retries the first two refused dials at a 1s floor before
resuming the exponential curve, catching the testers almost immediately;
unreachable peers that wait for the TCP connect timeout, and OPEN-validation /
NOTIFICATION failures, still use the slower guards so misconfigured peers do not
hot-loop. A controlled same-host before/after at 10 peers × 1,000 prefixes
measured total time **16.7s → 8.3s** (establishment ~10s → ~2s).

**Establishment versus flood at 100 peers.** Splitting convergence into "time to
the monitor's first prefix" and "time from first prefix to all 100,000"
separates session setup from route processing. The split was measured
identically in all three runs for rustbgpd, BIRD, and GoBGP: rustbgpd reaches
its first prefix at 1 s and the full 100,000 at 2 s, in one step; BIRD ramps
1 s → 4 s; GoBGP climbs linearly for seventeen seconds, 1 s → 18 s. FRR is the
opposite shape — its monitor count stays at zero through second 4, then the
whole table lands in a single sample at second 6. FRR spends its time before
the flood; rustbgpd does neither.

**Route processing.** At 10k and below, convergence completes in 2 seconds,
matching BIRD and ahead of GoBGP and FRR. At 200k prefixes rustbgpd converges
in 3 seconds, matching BIRD, ahead of FRR (4s) and GoBGP (6s). The key
optimizations were: (1) secondary prefix index in `AdjRibOut` converting
per-prefix lookup from O(N) to O(1), and (2) skipping unnecessary
`Arc::make_mut()` deep clones in the distribution path when no export policy
modifications are configured.

**CPU efficiency.** rustbgpd uses a single-threaded RIB (single tokio task, no
locks). It peaks at ~41% at 2p/100k and ~122% at 100p/1k. GoBGP peaks far
higher (565% and 1281%, goroutine-per-peer + GC). BIRD is the most efficient
below 100 peers, reflecting decades of C optimization with a radix-tree RIB;
at 100 peers BIRD and rustbgpd are close (101% vs 122%). FRR sits between.

**Memory.** *Full-daemon RSS* at 2p/100k is 212.0 MiB — above GoBGP's
202.8 MiB, below FRR's 228.4 MiB, and far above BIRD's 27.6 MiB. At 100p/1k
rustbgpd is last of the four. A whole-daemon dhat heap profile (2026-06-02; see
the *Memory Footprint* correction) attributes that RSS to **RIB route-storage
map/index bucket arrays — ~76% of the live-at-peak heap** — across the
three-layer Adj-RIB-In + Loc-RIB + Adj-RIB-Out model, with Adj-RIB-Out the
single largest piece. API / event / metrics operational surfaces were
**negligible (<1 MB)**. The opt-in event-history outbox adds RSS when enabled,
but the default-off structural cost is the route maps, **not** operational
surfaces. The earlier 60.6 MB "RIB-only is lean" figure is a synthetic
Adj-RIB-In + Loc-RIB micro-bench that excludes Adj-RIB-Out and so undercounts
full-daemon route storage. BIRD's radix-tree RIB with global attribute
deduplication is what makes it an order of magnitude leaner on this same data.
At full-table scale (900k prefixes, RIB-only micro-bench) rustbgpd's
Adj-RIB-In + Loc-RIB is ~533 MB vs GoBGP's published 8–16+ GB.

**gRPC under load.** A priority query channel separates read-only gRPC queries
from the route-processing pipeline, ensuring management API requests are
serviced between route batches even during bulk loading. At 100k+ scale, the
API remains responsive rather than blocking behind thousands of queued route
updates.

### Comparison Summary

| Metric | BIRD | GoBGP | FRR | rustbgpd |
|--------|------|-------|-----|----------|
| Architecture | Single-threaded C, radix tree | Go, goroutine-per-peer | Multi-daemon C (`bgpd` + `zebra`) | Single-threaded Rust, HashMap RIB |
| Total time (100p × 1k) | 15.22 s | 28.50 s | 16.01 s | **11.79 s** |
| Convergence (100p × 1k) | 5 s | 20 s | 7 s | **3 s** |
| Convergence (2p × 100k) | 3 s | 6 s | 4 s | **3 s** |
| CPU model | 1 core, very efficient | Multi-core, GC overhead | 1-2 cores | 1-2 cores, no GC |
| Memory model | Radix tree, global attribute dedup | Go heap, GC managed | Per-daemon route storage | Arc sharing, attribute interning |
| Full-daemon RSS (2p × 100k) | **27.6 MiB** | 202.8 MiB | 228.4 MiB | 212.0 MiB |
| Full-daemon RSS (100p × 1k) | **32.8 MiB** | 193.5 MiB | 134.1 MiB | 212.0 MiB *(last of four)* |
| Marginal MiB/peer, 10 → 100p (*computed*) | **0.27** | 1.72 | 1.18 | 1.93 |
| API during load | Responsive (no RIB contention) | Responsive (concurrent) | Responsive | Responsive (priority query channel) |

**Time:** rustbgpd is the fastest of the four on total time at every shape
measured, and its convergence lead widens with peer count rather than with
route count — 3 s against 5 / 7 / 20 s at 100 peers. That is the route-server
shape, and it is where the update-group work shows.

**Memory:** rustbgpd is not competitive with BIRD anywhere (4.6×–9.6×), sits
just above GoBGP at 100 peers, and is last of the four at that shape. BIRD is
30+ years of optimization in a purpose-built C codebase with a radix-tree RIB
and global attribute deduplication; that gap is structural, not a tuning
oversight. The open lever for rustbgpd remains **compact prefix-keyed RIB
storage** — reducing `hashbrown` bucket overhead across the route maps and
prefix indexes — plus whatever explains the 42% run-to-run RSS spread at 30
peers, which is not yet understood. Note this does not contradict the rejected
shared-`RouteData` refactor (above): that shared the Route *payload*, which is
the minority cost; the dominant cost is the maps' bucket arrays, so the open
lever is the map/index *data structure*, not payload sharing.

Historical progression of these figures across releases is in [Optimization
History (end-to-end, bgperf2 2p/100k)](#optimization-history-end-to-end-bgperf2-2p100k)
above.

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
