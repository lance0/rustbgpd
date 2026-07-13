# Exact-export fanout optimization receipt — 2026-07

Status: **PASS**. This receipt captures two pinned campaigns for LAN-361. The
first made the fanout benchmark exercise the authoritative per-session exact
export probe and then reused the live writer's complete prepared-attribute
memo key during an ordered precommit batch. The second measured the regression
against the old permissive benchmark and recovered most of that excess by
sharing successful exact-probe lengths across provably wire-equivalent members
of one update group.

The extracted Criterion data is checked in as
[`artifacts/exact-export-fanout-2026-07.csv`](artifacts/exact-export-fanout-2026-07.csv).
Negative change values mean the optimized revision is faster than that
campaign's baseline.

## Campaign 1: ordered prepared-attribute memo

### Compared revisions

| Role | Commit | Meaning |
|------|--------|---------|
| Baseline | `ce2e621e8b8a30fdb17d7f18844db44f9136c1ab` | Real transport encoder installed per benchmark peer; exact probe active; no batch attribute memo |
| Optimized | `833400be647e601f35c6b0764bc8001ff5b8d126` | Ordered batch probe plus the live prepared-attribute cache key |

The older distribution-fanout table in this repository measured a permissive
benchmark stub and therefore did not include exact export preparation. It is
historical only and must not be used as this optimization's baseline.

### Environment and method

| Field | Value |
|-------|-------|
| Host | AMD Ryzen Threadripper 7970X, 32 cores / 64 threads |
| Kernel | Linux 6.17.0-35-generic x86_64 |
| rustc | 1.97.0 (2026-07-07) |
| Criterion | 0.8 |
| Build | release profile, LTO, codegen-units=1 |
| Pinning | `taskset -c 2`; CPU 2 governor observed as `performance` |
| Shape | 64 first-advertise IPv4 best paths; 1, 8, 64, or 256 established iBGP/RR peers |
| Sampling | 1 s warmup, 3 s requested measurement, 30 samples |

The baseline and head ran from detached worktrees against a shared Criterion
target directory. Criterion stored the raw local samples under
`target/criterion/distribute_fanout/`; the checked-in CSV preserves the
baseline/head median estimates, their 95% confidence intervals, and the
Criterion mean-change estimate with its 95% confidence interval.

```bash
# Run at ce2e621e and save the real-probe baseline.
taskset -c 2 cargo bench -p rustbgpd-transport \
  --features bench-internals --bench fanout -- \
  --warm-up-time 1 --measurement-time 3 --sample-size 30 \
  --save-baseline exact-unmemoized --noplot

# Run at 833400be using the same CARGO_TARGET_DIR.
taskset -c 2 cargo bench -p rustbgpd-transport \
  --features bench-internals --bench fanout -- \
  --warm-up-time 1 --measurement-time 3 --sample-size 30 \
  --baseline exact-unmemoized --noplot
```

### Results

Baseline and optimized columns are Criterion medians. Delta is Criterion's
mean-change estimate; every confidence interval is entirely below zero
(`p < 0.05`).

| Shape | Baseline median | Optimized median | Mean change (95% CI) |
|-------|-----------------|------------------|----------------------|
| no policy / 1 peer | 45.970 µs | 35.488 µs | -22.3% (-23.2%..-21.2%) |
| no policy / 8 peers | 252.770 µs | 173.382 µs | -31.7% (-32.3%..-31.2%) |
| no policy / 64 peers | 1.920 ms | 1.328 ms | -30.5% (-31.8%..-29.2%) |
| no policy / 256 peers | 7.795 ms | 5.283 ms | -31.3% (-32.6%..-29.5%) |
| policy / 1 peer | 49.477 µs | 39.558 µs | -20.3% (-20.8%..-19.9%) |
| policy / 8 peers | 256.996 µs | 181.819 µs | -29.3% (-29.8%..-28.7%) |
| policy / 64 peers | 1.919 ms | 1.326 ms | -30.9% (-31.3%..-30.5%) |
| policy / 256 peers | 7.778 ms | 6.407 ms | -18.3% (-19.4%..-17.4%) |

Two earlier reduced-sampling repetitions placed the 64- and 256-peer gains in
the 26%..32% range. The pinned 30-sample run is the durable receipt; even its
smallest measured improvement (policy at 256 peers) remains well beyond the
documented benchmark runner noise bands.

### Correctness fence

This is deliberately not a full encoded-result cache:

- every candidate still constructs the exact one-route `UpdateMessage` and
  checks the immutable snapshot's negotiated ceiling;
- only unicast prepared attributes are shared, using the same complete key as
  live outbound grouping (attribute Arc identity, family, route next hop,
  origin, peer router ID, iBGP/eBGP mode, local IPv4, and full policy next-hop
  override);
- prefix, path ID, selected/link-local next hop, Add-Path, GShut, and profile
  generation remain in the per-route exact builder or pinned snapshot;
- non-unicast families retain scalar exact probing;
- batch/scalar equivalence, mixed-family result ordering, malformed batch
  cardinality fallback, and cache-key dimensions are regression-tested.

A richer full-result prototype was rejected after this smaller change produced
the measured gain. It required a larger wire-shape/invalidation key and did not
justify that additional correctness surface.

## Campaign 2: update-group probe recovery

The real exact probe remained a per-peer operation after the attribute memo,
so its cost scaled with fanout even when update-group members shared one staged
payload. This campaign compares current `main`'s permissive benchmark, the
pre-cache LAN-361 head, and the wire-equivalence cohort optimization.

### Compared revisions

| Role | Commit | Meaning |
|------|--------|---------|
| Control | `18bb288b` | Current `main`; permissive/no-op benchmark encoder, so exact export preparation is not measured |
| Pre-cache | `3ac1e733` | Real per-session exact probe plus the ordered prepared-attribute memo from campaign 1; still probes every route for every peer |
| Optimized | `8931046e421a833e0e63f35a7838ee45691412c3` | Pass-local successful-length reuse across compatible members of one update group |

The `main` control is useful for quantifying the remaining benchmark overhead,
but it is not a correctness-equivalent implementation baseline: production
sessions require the exact export gate.

### Environment and method

| Field | Value |
|-------|-------|
| Host | AMD Ryzen Threadripper 7970X, 32 cores / 64 threads |
| Kernel | Linux 6.17.0-35-generic x86_64 |
| rustc | 1.97.0 (2026-07-07) |
| Criterion | 0.8 |
| Build | release profile, LTO, codegen-units=1 |
| Pinning | `taskset -c 5` |
| Shape | One update group; 64-route IPv4 unicast first-advertise burst; 1, 8, 64, or 256 established iBGP/RR peers |
| Sampling | 1 s warmup, 2 s requested measurement, 30 samples |

This is a first-advertise distribution microbenchmark. It is not a resync or
full-table convergence measurement. The three revisions ran from pinned
worktrees on the same host and toolchain. The `main` control used its own
default target directory. Pre-cache and optimized ran sequentially with the
same exact-exportability target directory, so Criterion's default previous-run
comparison produced the optimized-versus-pre-cache change estimate. To
reproduce that comparison, run the last two commands in order without another
run replacing `target/criterion/distribute_fanout/` between them.

```bash
# At 18bb288b (the benchmark still lived in the RIB crate).
taskset -c 5 cargo bench -p rustbgpd-rib \
  --features bench-internals --bench fanout -- \
  --warm-up-time 1 --measurement-time 2 --sample-size 30 \
  --noplot

# At 3ac1e733, run the real-probe pre-cache revision. Reuse this same
# absolute target directory for the optimized worktree below.
taskset -c 5 env CARGO_TARGET_DIR=/path/to/shared-target \
  cargo bench -p rustbgpd-transport \
  --features bench-internals --bench fanout -- \
  --warm-up-time 1 --measurement-time 2 --sample-size 30 \
  --noplot

# At 8931046e, use the same target directory immediately afterward.
taskset -c 5 env CARGO_TARGET_DIR=/path/to/shared-target \
  cargo bench -p rustbgpd-transport \
  --features bench-internals --bench fanout -- \
  --warm-up-time 1 --measurement-time 2 --sample-size 30 \
  --noplot
```

### Results

Control, pre-cache, and optimized columns are Criterion medians. Mean change is
the Criterion estimate for optimized versus pre-cache; every confidence
interval is entirely below zero.

| Shape | `main` control | Pre-cache | Optimized | Optimized vs pre-cache mean change (95% CI) |
|-------|---------------:|----------:|----------:|--------------------------------------------:|
| no policy / 1 peer | 21.148 µs | 36.395 µs | 35.908 µs | -1.84% (-2.74%..-1.23%) |
| no policy / 8 peers | 56.415 µs | 180.416 µs | 94.704 µs | -47.33% (-47.48%..-47.17%) |
| no policy / 64 peers | 318.064 µs | 1.382 ms | 543.301 µs | -60.98% (-61.43%..-60.59%) |
| no policy / 256 peers | 1.251 ms | 5.886 ms | 2.068 ms | -64.28% (-64.82%..-63.70%) |
| policy / 1 peer | 24.494 µs | 40.012 µs | 39.993 µs | -0.98% (-2.08%..-0.12%) |
| policy / 8 peers | 62.745 µs | 183.181 µs | 102.689 µs | -43.99% (-44.09%..-43.87%) |
| policy / 64 peers | 356.086 µs | 1.369 ms | 584.361 µs | -57.50% (-57.86%..-57.23%) |
| policy / 256 peers | 1.372 ms | 5.341 ms | 2.234 ms | -58.31% (-58.54%..-58.14%) |

At 256 peers, the exact-probe overhead relative to the permissive control fell
from 4.706x to 1.653x without policy, recovering 82.37% of the excess. With
policy it fell from 3.893x to 1.629x, recovering 78.28%. The optimization is
nearly neutral at one peer and grows with fanout, matching its intended update-
group sharing scope. The checked-in CSV contains all three median confidence
intervals and the optimized-versus-pre-cache mean-change confidence intervals.

### Correctness fence

This optimization does not skip the exact export gate. It reuses only a
successful source probe's encoded length, then applies the target snapshot's
negotiated maximum and generation:

- the cache is local to one `distribute_changes` pass and keyed first by update-
  group ID;
- eligibility requires pointer-identical shared unicast announce and aligned
  next-hop-override `Arc` slices; resync, exception, and other independently
  built per-peer vectors cannot match by content;
- the transport compares the full normalized `SessionExportProfile`, excluding
  only owner ID, generation, and the Extended Messages ceiling. Every other
  current or future profile field participates through derived full-struct
  equality;
- the target snapshot re-applies its own 4K/64K maximum and generation to each
  reused encoded length;
- at most eight compatibility cohorts are retained per update-group ID;
- only cardinality-correct, all-success source batches are cached. A probe
  failure or malformed batch produces no reusable length;
- the trait default refuses reuse, so unknown snapshot implementations remain
  on the ordinary exact-probe path; and
- non-shared unicast, resync/exception payloads, and mixed-family envelopes are
  probed normally. Non-unicast families remain outside this cache.

The optimized benchmark therefore measures one real exact encoding per shared
route and compatible cohort, plus a target-owned ceiling/generation recheck per
member. It must not be described as performing a full exact encode per peer.
