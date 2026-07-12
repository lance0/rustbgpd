# Exact-export fanout memo receipt — 2026-07

Status: **PASS**. This receipt captures the LAN-361 follow-up that made the
fanout benchmark exercise the authoritative per-session exact export probe,
then reused the live writer's complete prepared-attribute memo key during an
ordered precommit batch.

The extracted Criterion data is checked in as
[`artifacts/exact-export-fanout-2026-07.csv`](artifacts/exact-export-fanout-2026-07.csv).
Negative change values mean the optimized head is faster.

## Compared revisions

| Role | Commit | Meaning |
|------|--------|---------|
| Baseline | `ce2e621e8b8a30fdb17d7f18844db44f9136c1ab` | Real transport encoder installed per benchmark peer; exact probe active; no batch attribute memo |
| Optimized | `833400be647e601f35c6b0764bc8001ff5b8d126` | Ordered batch probe plus the live prepared-attribute cache key |

The older distribution-fanout table in this repository measured a permissive
benchmark stub and therefore did not include exact export preparation. It is
historical only and must not be used as this optimization's baseline.

## Environment and method

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

## Results

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

## Correctness fence

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
