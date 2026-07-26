# RIB criterion noise floor and the LLGR tag-lookup guard — 2026-07

This receipt establishes what a RIB criterion delta has to clear before it
means anything on the primary measurement host, and publishes the one CPU claim
that clears it. The finding that matters more than the claim is that **the
noise floor is per-shape and per-host** — a single global percentage is
misleading in both directions.

All numbers are *measured* on the primary host described in
[`BENCHMARKS.md`](../BENCHMARKS.md): AMD Ryzen Threadripper 7970X, `performance`
governor, `taskset -c 8`, six alternating A/B attempts per comparison (odd
attempts base-first, even attempts head-first, so first-vs-second bias
cancels). Every comparison below is a `bench/compare-criterion.sh` run.

## The noise floor is per-shape

Two same-SHA control runs at `515659b191b7fde91a1a1c9f973e7c8ae3731086` measure
the host against itself. Base and head are the same commit, so every non-zero
number is noise by construction.

| Benchmark | Across-attempt stddev |
|---|---:|
| `adj_rib_in_insert/10000` | 1.44% |
| `adj_rib_in_insert/100000` | **16.76%** |
| `adj_rib_in_insert/500000` | 6.62% |
| `rib_pipeline/1000` | 0.55% |
| `rib_pipeline/10000` | 1.40% |
| `rib_pipeline/50000` | 2.52% |
| `bulk_initial_load/10000` | 1.67% |
| `bulk_initial_load/100000` | 4.05% |

The spread across shapes is over thirtyfold, on one host, in one sitting, at
one commit. `adj_rib_in_insert/100000` is the outlier: its same-SHA control
swung −17.20%..+25.44% while `/10000` stayed inside −0.30%..+3.50%.

Alongside the host figures, [`BENCHMARKS.md`](../BENCHMARKS.md) records a
single ~11.2% empirical floor calibrated on the secondary virtualized bench
runner, at `adj_rib_in_insert/10000`. That same shape measures 1.44% here. Used
as one global number, an 11.2% floor does both harmful things at once:

- **It hides real regressions at `/10000`,** where the true floor is roughly
  eight times tighter, so a genuine several-percent regression is dismissed as
  noise.
- **It manufactures phantom ones at `/100000`,** where the true floor is
  higher, so ordinary variance reads as signal.

A floor is a property of a (host, benchmark, size) triple. Read it from a
same-SHA control on the host doing the measuring, at the shape being measured.

## The one CPU claim

Isolated to `5e2ae925^` versus `5e2ae925` (skip the LLGR tag lookup when no
tags are held), so no other commit in the range can contribute:

> `AdjRibIn::insert` improved 2.35% at 10,000 routes on the measured host; six
> isolated attempts were negative and separated from same-SHA variability.

Supporting evidence: across-attempt stddev 0.61%, min..max −3.35%..−1.50%,
against the same-SHA floor of 1.44% at that shape. Every attempt is on the same
side of zero and the whole range sits below the control's range.

The claim is scoped to `AdjRibIn::insert` at 10,000 routes on this host. It is
not a convergence claim, not a `rib_pipeline` claim, and not a claim about any
other size.

`adj_rib_in_insert/500000` measured −14.24% with stddev 4.87% in the same run.
That is recorded here as **suggestive receipt data, not a claim**: its best case
(−5.03%) falls inside the same-SHA control's own range (−8.78%..+8.22%), so the
measurement cannot separate it from that shape's noise. `/100000` is not quoted
at all — its control stddev of 16.76% makes any delta at that size
uninterpretable.

## Open observation: an unattributed `rib_pipeline` improvement

Comparing the `v0.60.0` tag to the current head measured `rib_pipeline` at
−1.57% / −2.34% / −3.05% for 1,000 / 10,000 / 50,000 routes. Two of those three
exceed their same-SHA floors (0.55% / 1.40% / 2.52%), so something in the range
is real.

It is **not** the LLGR tag-lookup guard. The isolated `5e2ae925^`→`5e2ae925`
run measured `rib_pipeline` at −0.69% / −0.01% / −0.06% — nothing, at all three
sizes.

The improvement is therefore unattributed. It is recorded rather than bisected:
a favourable unexplained delta is not a release blocker, and the receipt's job
is to keep it from later being claimed for whichever commit is convenient.

## Reproduce and artifacts

```console
bench/compare-criterion.sh \
    --base 5e2ae925^ --head 5e2ae925 \
    --core 8 --attempts 6 --require-performance \
    --package rustbgpd-rib --bench rib_ops \
    --filter 'rib_pipeline|adj_rib_in_insert'
```

Pointing `--base` and `--head` at the same SHA reproduces a control run. The
[retained artifact set](artifacts/rib-criterion-noise-floor-2026-07/README.md)
holds each run's sanitized comparison summary, its pinning and toolchain
metadata, and a per-attempt table of the Criterion point estimates every delta
above is derived from.

## Limitations

- Six attempts per comparison. That is enough to separate a tight effect like
  the 2.35% row from a 1.44% floor; it is not enough to resolve anything at a
  shape whose control stddev is in double digits.
- Microbenchmark deltas describe the benchmarked function on this host. Nothing
  here measures end-to-end convergence, and no claim is generalized to it.
- The floors are a snapshot. Re-measure the control after a toolchain, kernel,
  or hardware change rather than carrying these percentages forward.
