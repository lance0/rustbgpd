# Shared source-ordering campaign — 2026-07

Status: **NO-GO**. A source-bucketed ordering prototype cleared its intended
400,000-route / 1,000-source speedup target, but breached the retained
one-source regression ceiling. The prototype and its 544-line measurement
harness were discarded. This receipt preserves the negative result so the
same tradeoff is not rediscovered without addressing the guardrail.

The paired Criterion estimates are checked in as
[`artifacts/shared-source-ordering-2026-07-paired.csv`](artifacts/shared-source-ordering-2026-07-paired.csv).
The production-path and semantic-oracle receipts are in
[`artifacts/shared-source-ordering-2026-07-validation.csv`](artifacts/shared-source-ordering-2026-07-validation.csv).
Negative deltas mean the candidate was faster.

## Compared revisions

| Role | Commit | Meaning |
|------|--------|---------|
| Control | `0f32b4b7e8e650ae1d4eb71cdaa2e0afdd792716` | Exact pre-change comparison sort plus the temporary real-envelope harness |
| Candidate | `5d8bdf2e92beda746e7a6206fb1d3a294c2c39aa` | Bucket route indices by source, sort only source keys, and retain a separate one-source scan path |

Neither revision is part of the final change. The final branch contains this
receipt only; runtime behavior is unchanged from `main`.

## Fleet and timed envelope

Each retained cell used one real route-server `PeerSession`, its immutable
`SessionExportProfile`, and the production progressive shared encoder. The
fixture contained either 65,536 or 400,000 IPv4 `/32` routes distributed
round-robin across 1, 8, 256, or 1,000 source peers. Each source had its own
`ORIGIN`, `AS_PATH`, and `NEXT_HOP` attributes. The target session negotiated
IPv4 unicast without Add-Path or Extended Messages.

The timed operation included index allocation and ordering, attribute
preparation, grouping, wire encoding, progressive publication, and the elected
member's send path. A live route-count-sized writer channel received every
published chunk; it was large enough that saturation was not part of this
measurement. Route construction, channel draining, wire decoding, checksums,
and semantic comparison against the ordinary per-session encoder remained
outside the timer.

This is an elected-member encoder microbenchmark, not an end-to-end RIB actor,
whole update-group fanout, or convergence result. Source count models the
number of route-server members contributing best paths; it is not a claim that
1,000 session tasks were active during the sample.

## Method and provenance

| Field | Value |
|-------|-------|
| CPU | AMD Ryzen Threadripper 7970X, 32 cores / 64 threads |
| Kernel | Linux 6.17.0-35-generic x86_64 |
| rustc / Cargo | 1.97.0 / 1.97.0 |
| Criterion | 0.8.2 |
| Build | workspace bench profile: optimized, LTO, `codegen-units=1` |
| Pinning | `taskset -c 5`; CPU 5 governor `performance`; SMT sibling CPU 37 |
| Sampling | four paired attempts; 10 samples; Criterion's 3 s warm-up and 5 s requested measurement per cell |
| Order | attempts 1 and 3 control-first; attempts 2 and 4 candidate-first |
| Host fence | shared rustbgpd host lock held; initial load 0.24 / 0.30 / 0.84; no competing Cargo, rustc, benchmark, or soak process at preflight |

The canonical driver created detached worktrees for the two exact commits,
used separate Cargo target directories, and stored uniquely named Criterion
baselines in one explicit Criterion directory. Separate targets prevent
cross-revision artifact reuse. The initial preflight and shared lock exclude
known local benchmark interference; they are not a claim that the entire host
was otherwise isolated.

```bash
bench/compare-criterion.sh \
  --base 0f32b4b7e8e650ae1d4eb71cdaa2e0afdd792716 \
  --head 5d8bdf2e92beda746e7a6206fb1d3a294c2c39aa \
  --core 5 \
  --features bench-internals \
  --package rustbgpd-transport \
  --bench shared_source_ordering \
  --attempts 4 \
  --require-performance \
  --out-dir target/lan519-shared-source-ordering
```

Raw Criterion state and command logs were retained locally for review. They
are not published because generic driver metadata contains machine-specific
paths and identity. The checked-in CSVs contain the complete paired median
estimates, confidence bounds, validation receipts, and no hostname or absolute
path.

## Path and correctness receipts

Every validation run and timed sample asserted that the production shared
encoder completed, used a live writer channel, emitted every expected prefix
exactly once, kept chunks source-contiguous, and decoded to the same
prefix/attribute map as the ordinary encoder. The candidate additionally
reported the exact `SingleSource` or `Bucketed { sources, indices }` branch
from inside the timed production call.

All eight shapes produced identical control/candidate route counts, source-run
counts, chunk counts, encoded-byte counts, and semantic checksums in all four
attempts. Multi-source wire checksums differ because the old unstable
equal-key sort and the buckets choose different orders for distinct prefixes
from the same source. The decoded prefix/attribute maps and their ordered
semantic checksums are identical.

Before measurement, the temporary harness was proven load-bearing by applying
each production/evidence break and observing the focused regression fail:

- bypassing the shared encoder broke the shared-path/terminal receipt;
- replacing the candidate bucket helper with the control comparison sort
  broke the candidate branch receipt;
- restoring table-order traversal broke the exact source-run assertion;
- omitting or duplicating an index broke expected-prefix cardinality; and
- perturbing shared output relative to the ordinary encoder broke the decoded
  prefix/attribute-map oracle.

The harness and tests were removed after the no-go decision: retaining more
than 500 lines of off-by-default benchmark plumbing for a rejected candidate
would impose permanent maintenance without a shipped optimization. This final
docs-and-data change adds no test or gate, so mutation proof is N/A for the
final diff.

## Results and gate

The table reports the arithmetic mean of four paired Criterion median deltas,
matching `compare-criterion.sh`. The spread is the sample standard deviation
and minimum-to-maximum range across the four paired deltas. The final interval
is the driver's conservative propagation of the fourth attempt's independent
median confidence intervals.

| Routes | Sources | Control median mean | Candidate median mean | Mean delta | Stddev | Paired range | Last-run propagated 95% CI |
|-------:|--------:|--------------------:|----------------------:|-----------:|-------:|-------------:|---------------------------:|
| 65,536 | 1 | 2.673 ms | 2.746 ms | +2.729% | 1.902% | +0.663%..+4.799% | +0.240%..+1.102% |
| 65,536 | 8 | 3.959 ms | 2.934 ms | -25.877% | 2.505% | -27.497%..-22.161% | -27.935%..-26.061% |
| 65,536 | 256 | 4.267 ms | 3.065 ms | -28.156% | 4.754% | -31.873%..-21.306% | -31.818%..-28.236% |
| 65,536 | 1,000 | 5.116 ms | 3.900 ms | -23.766% | 3.039% | -26.529%..-19.450% | -27.207%..-25.308% |
| 400,000 | 1 | 17.740 ms | 18.679 ms | **+5.298%** | 3.332% | +2.661%..+10.130% | +2.255%..+3.427% |
| 400,000 | 8 | 67.773 ms | 19.760 ms | -70.844% | 0.174% | -71.014%..-70.623% | -71.341%..-70.651% |
| 400,000 | 256 | 66.950 ms | 19.993 ms | -70.136% | 0.411% | -70.432%..-69.532% | -70.376%..-70.117% |
| 400,000 | 1,000 | 48.849 ms | 19.917 ms | **-59.220%** | 1.359% | -60.728%..-57.531% | -59.302%..-58.410% |

The predeclared gate required both:

1. at least 5% improvement at 400,000 routes / 1,000 sources; and
2. no more than 3% regression at either retained one-source shape.

The target passed by a wide margin, and 65,536/1 remained within the guard at
+2.729%. The 400,000/1 shape regressed +5.298%, with every paired attempt
positive (+4.746%, +10.130%, +3.654%, +2.661%). The overall result is therefore
**NO-GO**, independent of the multi-source wins. No performance claim or
production change ships from this campaign.

## Cost disclosure

The control allocates one `Vec<usize>` for the ordered indices: about 3.05 MiB
at 400,000 routes. The candidate retained that final vector and also stored all
400,000 indices across source buckets, about another 3.05 MiB, plus one vector
header per source, hash-table storage, and capacity slack. Its ordering memory
was therefore O(N + S), roughly 6.1 MiB of index payload at the full-table
shape versus 3.05 MiB for the control.

Candidate timings conservatively included a benchmark-only thread-local branch
receipt and an O(S) bucket-cardinality sum. Those costs do not excuse the
one-source failure: that path did not build buckets, and the predeclared guard
applied to the measured complete envelope.
