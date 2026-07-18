# Exact-export fanout optimization receipt — 2026-07

Status: **PASS**. This receipt captures four pinned exact-export campaigns. The
first made the fanout benchmark exercise the authoritative per-session exact
export probe and then reused the live writer's complete prepared-attribute
memo key during an ordered precommit batch. The second measured the regression
against the old permissive benchmark and recovered most of that excess by
sharing successful exact-probe lengths across provably wire-equivalent members
of one update group.

The extracted Criterion data for the first two campaigns is checked in as
[`artifacts/exact-export-fanout-2026-07.csv`](artifacts/exact-export-fanout-2026-07.csv).
Negative change values mean the optimized revision is faster than that
campaign's baseline. Campaign 3 retains its complete sealed rrharness receipt
and sanitized Criterion matrix under
[`artifacts/grouped-exact-precommit-2026-07/`](artifacts/grouped-exact-precommit-2026-07/).
Campaign 4 retains its complete normalized Criterion matrix and production
transition counters under
[`artifacts/ixp-exact-export-cohorts-2026-07/`](artifacts/ixp-exact-export-cohorts-2026-07/).

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
pre-cache attribute-memo head from campaign 1, and the wire-equivalence
cohort optimization.

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

## Campaign 3: grouped exact-precommit fast path

Campaign 2 removed redundant exact encoding across compatible update-group
members, but the common all-success path still rebuilt every candidate key,
walked the group's advertised-state delta for every peer, and allocated a
per-peer prior set that was used only when a probe failed. The grouped
fast-path continuation defers that work until the rejection fallback actually
needs it and keeps the clean grouped path keyless.

### Compared revisions

| Role | Commit | Meaning |
|------|--------|---------|
| Baseline | `b2ec55f21364978f26662b1ec35fd47ddcfce9a6` | Current exact-export grouped path after campaign 2; eagerly materializes candidate keys and prior advertised state per member |
| Optimized | `ea579bea4ad6602dc719a1664441f04330c5ef64` | Defers keys and group-prior materialization until a rejection fallback; preserves the shared exact-length cohort cache |
| Tooling | `e6c6ea75819869cb2cd188711891459f8991d51d` | Fail-closed rrharness comparator and strict Criterion receipt validator |
| Pin | `deb52f7b92f7f633714573a86f0eaeb22bb94bad` | Exact refs, normalized production diff, and reviewed tooling pin |

The normalized production diff SHA-256 is
`363ca576015ced26223b72b109acede0b88c1859db4cffb5c702d3d95ba236c4`.

### Environment and method

| Field | Value |
|-------|-------|
| Host | AMD Ryzen Threadripper 7970X, 32 cores / 64 threads |
| Kernel | Linux 6.17.0-35-generic x86_64 |
| rustc / Cargo | 1.97.0 (2026-07-07) |
| Criterion | 0.8 |
| Build | Criterion: workspace release (`lto=true`, `codegen-units=1`); rrharness: standalone release (`debug=1`) built with `--locked --jobs 1` |
| Pinning | `taskset -c 5`; CPU 5 governor observed as `performance` |
| Isolation | shared host lock; every rrharness cell required load below 2.0 and zero competing build/performance processes |
| Ordering | two repetitions, counterbalanced base-first then head-first |

Two complementary measurements are retained:

- the manager-level rrharness runs 16 fresh processes: flood at 256 and 1,000
  peers over 100,000 prefixes, and churn at 256×256 and 1,000×1,000 peers over
  3,000 prefixes, for 20 seconds per cell;
- Criterion runs the 64-route first-advertise `distribute_fanout` matrix at 1,
  8, 64, and 256 peers, with and without export policy, in two alternating
  attempts. The strict gate requires every 64/256-peer conservative 95% CI
  upper bound below zero and a one-peer mean regression below 5%.

The rrharness run started at `2026-07-13T09:46:41Z` and sealed at
`09:57:49Z`. All 16 preflights passed with one-minute load from 1.21 to 1.72,
the `performance` governor, and no competing process. The Criterion campaign
started immediately afterward from the same exact pin.

The pin commit must be the invoking checkout; both drivers reject dirty or
different source state:

```bash
git switch --detach deb52f7b92f7f633714573a86f0eaeb22bb94bad

bench/scale/compare-rrharness.sh \
  --base b2ec55f21364978f26662b1ec35fd47ddcfce9a6 \
  --head ea579bea4ad6602dc719a1664441f04330c5ef64 \
  --core 5 \
  --output-dir target/rrharness-compare/reproduction

bench/compare-criterion.sh \
  --base b2ec55f21364978f26662b1ec35fd47ddcfce9a6 \
  --head ea579bea4ad6602dc719a1664441f04330c5ef64 \
  --core 5 \
  --package rustbgpd-transport \
  --bench fanout \
  --features bench-internals \
  --filter distribute_fanout \
  --attempts 2 \
  --require-performance \
  --lan395-gate-out target/lan395-criterion-receipt
```

### Results

The rrharness values are head throughput improvement over baseline. Both
counterbalanced repetitions pass their shape-specific acceptance gates.

| Shape | Repetition 1 | Repetition 2 | Gate |
|-------|-------------:|-------------:|------|
| flood / 256 peers / 100k prefixes | +197.04% | +199.53% | no repetition worse than -5% |
| flood / 1,000 peers / 100k prefixes | +279.87% | +281.84% | every repetition at least +15% |
| churn / 256×256 peers / 3k prefixes | +480.28% | +491.15% | every repetition at least +15% |
| churn / 1,000×1,000 peers / 3k prefixes | +638.60% | +648.86% | every repetition at least +15% |

The Criterion columns below are the median across the two attempts; change is
the mean of the two paired median deltas. Every 64/256-peer per-attempt
conservative 95% CI upper bound is below zero.

| Shape | Baseline median | Optimized median | Mean change |
|-------|----------------:|-----------------:|------------:|
| no policy / 1 peer | 42.11 µs | 38.84 µs | -7.76% |
| no policy / 8 peers | 103.96 µs | 79.11 µs | -23.90% |
| no policy / 64 peers | 573.75 µs | 377.92 µs | -34.13% |
| no policy / 256 peers | 2.19 ms | 1.39 ms | -36.27% |
| policy / 1 peer | 46.48 µs | 42.83 µs | -7.85% |
| policy / 8 peers | 111.87 µs | 86.48 µs | -22.69% |
| policy / 64 peers | 615.84 µs | 416.22 µs | -32.41% |
| policy / 256 peers | 2.33 ms | 1.55 ms | -33.46% |

### Correctness and evidence fence

The optimization changes no BGP wire form and does not weaken exact export:

- every grouped member still receives a target-owned ceiling and generation
  recheck of a successful exact encoded length;
- the keyless path is available only to an ordinary clean grouped member when
  every probe succeeds and the peer has no rejection overlay;
- any rejection, existing overlay, resync, regroup, VPN or other non-unicast
  payload, mixed-family envelope, malformed batch, or non-shared payload takes
  the ordinary fallback;
- fallback materializes the staged prior at most once, maintains the sparse
  rejection overlay, and emits any withdrawal owed for a previously advertised
  route; and
- focused regressions pin shared payload/snapshot fencing, cached failure with
  an owed withdrawal, and overlay fallback retaining an unrelated family.

The retained artifacts fail closed too. The rrharness archive includes its
reviewed source snapshot, production patch/hash, exact refs and binary hashes,
raw rows, folded profiles and reclassification hashes, preflights, execution
order, final manifest, checksum envelope, and `COMPLETED` marker. The Criterion
receipt retains exactly five whitelisted files with 16 rows and 32 reconciled
input hashes. Retained Python bytecode is disabled; the final source inventory
is NUL-safe and exact; ignored and binary files are scanned for private values
after the final parser reconciliation; scanner errors reject the seal.

Two earlier measurement attempts are not publication evidence. The first was
never sealed after a generic privacy rule matched reviewed source vocabulary.
The second passed and sealed, but independent review found an ignored Python
bytecode file containing a private path. Both were rejected; only the clean
third rrharness run and matching final-pin Criterion run are retained.

## Campaign 4: IXP eBGP classification cohorts

Campaign 2's full-profile equality was intentionally conservative, but its
snapshot retained the negotiated remote ASN even though outbound encoding used
that value only to derive eBGP versus iBGP behavior. Homogeneous RR members
therefore reused one exact result as measured above, while real route-server
clients in distinct ASNs appeared wire-incompatible. Once eight remote-ASN
profiles filled the pass-local cohort cap, later clients repeated the complete
probe. The cap remains a useful bound for genuinely different wire profiles;
remote ASN identity was the false dimension.

### Compared revisions and method

| Role | Commit | Meaning |
|------|--------|---------|
| Fixture baseline | `a47c618ebb7cdf9c99a48e6bd7ed753f42cac664` | Adds matched manager/transport eBGP route-server clients while retaining raw remote ASN in the exact-export profile |
| Optimized | `828e7a7f7be2a27d2556341320fe2dfc036d7e1a` | Stores only the wire-relevant eBGP/iBGP classification |

The established RR benchmark is unchanged and remains valid evidence for its
homogeneous RR workload. This complementary matrix models ordinary first
advertise to eBGP route-server clients with the same local address,
capabilities, route-server mode, and grouping inputs. One population assigns
AS 65001 to every client; the other assigns a different remote ASN to each
client. The transition matrix changes one export-policy community over 4,096
routes. These fixtures are groupable plain single-best peers; per-client-best
and Add-Path peers remain ungrouped and receive no shared-cohort benefit. Every
cell ran on the same pinned CPU and release binary settings; the aggregate
Criterion estimates, paired change confidence intervals, commands, and
environment are retained in the campaign artifact directory.

### Results

Distinct-ASN first-advertise fanout converges on the already-fast homogeneous
case after removing the false profile dimension:

| Clients | Distinct-ASN baseline | Optimized | Criterion mean change (95% CI) |
|--------:|----------------------:|----------:|--------------------------------:|
| 8 | 149.111 us | 77.700 us | -47.34% (-48.48%..-46.19%) |
| 64 | 1.026 ms | 376.547 us | -63.35% (-63.67%..-62.95%) |
| 256 | 4.038 ms | 1.419 ms | -64.70% (-65.31%..-64.00%) |

Optimized homogeneous medians were 76.207 us, 378.012 us, and 1.431 ms at 8,
64, and 256 clients. Their paired mean changes were -2.10%, -1.21%, and +0.38%;
the first two improve slightly and the 256-client interval crosses zero, so the
optimization does not trade the existing first-advertise fast case for IXP
recovery.

The clean policy-transition result removes the route-times-peer probe shape:

| Routes / clients | Distinct-ASN baseline | Optimized | Full probes before / after | Criterion mean change (95% CI) |
|-----------------:|----------------------:|----------:|---------------------------:|--------------------------------:|
| 4,096 / 64 | 49.206 ms | 3.464 ms | 262,144 / 4,096 | -93.00% (-93.14%..-92.87%) |
| 4,096 / 700 | 510.332 ms | 7.604 ms | 2,867,200 / 4,096 | -98.51% (-98.54%..-98.49%) |

The 700-client production receipt also drops from 3,599 actor polls to 803.
The optimized distinct-ASN receipt matches the homogeneous plan count, probe
count, shell count, and poll count exactly. This is microbenchmark evidence,
not the loaded-reload acceptance campaign described in the policy-transition
receipt.

The homogeneous 700-client transition showed no detected change (-1.60% mean,
-4.34%..+1.01%). The homogeneous 64-client transition also showed no detected
change (+1.07% mean, -0.72%..+2.67%). Both cells are retained alongside the
distinct-ASN cell's removal of 258,048 redundant full probes.

### Correctness fence

`SessionExportProfile` now captures a boolean eBGP/iBGP classification from
the negotiated ASN (with the configured ASN as the pre-negotiation fallback)
instead of retaining remote ASN identity. Owner, generation, and Extended
Messages ceiling normalization is unchanged. Full derived-struct equality
still includes local ASN and router ID, role, route-server mode,
remove-private-AS mode, cluster and next-hop inputs, every negotiated family
capability, local socket address, scoped-link-local mode, and GShut state.
Target-owned message ceiling and generation checks still run for every member.

A byte-level regression constructs distinct-remote-ASN profiles in both
route-server and ordinary eBGP modes, proves their complete encoded UPDATEs are
identical, and proves successful-length reuse. The ordinary arm additionally
asserts that local-AS prepend and next-hop rewriting ran. The same test changes
the target to iBGP, observes different bytes, and requires reuse to fail. The
eight-cohort bound is unchanged for profiles that differ on a real wire input.

A separate live-capture canary configures dynamic `remote_asn = 0`, then proves
that the negotiated ASN classifies an eBGP session as eBGP and a same-AS
session as iBGP. This prevents the configured wildcard fallback from replacing
live negotiated truth.
