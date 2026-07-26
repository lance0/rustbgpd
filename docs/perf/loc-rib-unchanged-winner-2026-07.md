# Loc-RIB unchanged-winner clone experiment — 2026-07

This receipt records a rejected optimization and the benchmark added to grade
it. `LocRib::recompute` selected the best route with `.cloned()` before checking
whether the installed winner had changed. Moving that clone into the changed
branch looked mechanically cheaper, but the measured result was size-dependent
and regressed the largest fixture. The production change was reverted.

## Scope and path proof

`loc_rib_recompute/no_change/{1000,10000,50000}` seeds one installed route per
prefix outside the timed routine. The timed routine recomputes each prefix from
the identical single candidate and asserts that every call returns `false`.
That assertion is the in-code proof that the no-insert path was exercised.

The benchmark source is byte-identical between the immediate-parent control
`35b33a5d0ca901e15e995aaff5aff1e31038e88b` and target
`80b34f3af806a4cca378e570e436adaa261b3211`:

```text
crates/rib/benches/rib_ops.rs
sha256 4d4b0718c39e6f8011f9f94534d0c6881b8813310ea456fe85b79cecb2bc265d
```

Reverting the target restores the eager clone while leaving the benchmark
unchanged. The immediate-parent comparison is therefore the destructive proof
for the proposed optimization.

## Method

Both the same-SHA control and production A/B used the primary host described in
[`BENCHMARKS.md`](../BENCHMARKS.md): AMD Ryzen Threadripper 7970X, Linux
6.17.0-35-generic, Rust 1.97.0, the `performance` governor, CPU 5 pinned with
`taskset`, and six alternating attempts. Odd attempts ran base first and even
attempts ran head first.

The fixture is one in-memory Loc-RIB with one unchanged candidate per installed
prefix. It has no daemon, sockets, policy, fanout, or convergence component.
Before the proposed change, each unchanged recompute cloned one `Route` shell
and its owned/reference-counted fields before discarding it.

## Same-SHA floor

The control points both sides at `35b33a5d`:

| Routes | Mean delta | Stddev | Min..max |
|---:|---:|---:|---:|
| 1,000 | -0.62% | 1.37% | -2.34%..+1.10% |
| 10,000 | -0.23% | 0.44% | -0.84%..+0.28% |
| 50,000 | +0.21% | 0.38% | -0.22%..+0.76% |

All three rows are noise by construction.

## Immediate-parent A/B

| Routes | Mean delta | Stddev | Min..max | Verdict |
|---:|---:|---:|---:|---|
| 1,000 | -10.50% | 0.88% | -11.83%..-9.32% | improvement |
| 10,000 | -6.93% | 0.29% | -7.29%..-6.64% | improvement |
| 50,000 | **+3.88%** | 0.91% | **+2.34%..+4.79%** | regression |

The 50,000-route row is slower in every attempt and its full range lies above
the matching same-SHA ceiling of +0.76%. The optimization therefore fails the
all-shapes gate and is not a performance gain. No end-to-end or production
claim follows from the smaller microbenchmark wins.

The retained [artifact set](artifacts/loc-rib-unchanged-winner-2026-07/README.md)
contains sanitized summaries, commands, environment metadata, and source
checksums. It also retains the control and candidate patches needed to recreate
the measured source trees from permanent mainline commit `aea3d413`, so the
receipt does not depend on topic-branch commits surviving a squash merge. It
exists to prevent the same plausible optimization from being reintroduced on
the strength of the smaller fixtures alone.
