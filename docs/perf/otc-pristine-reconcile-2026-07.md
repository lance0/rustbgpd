# Pristine OTC reconciliation receipt (July 2026)

## Decision

Return before allocating or walking per-peer OTC reconciliation state when a
distribution pass produced no OTC-blocked routes and the peer has neither
current nor pending OTC-blocked state. A peer in that exact pristine state has
nothing to reconcile. Any current state, pending state, or newly blocked route
continues through the existing prefix-by-prefix transition unchanged.

The control test counts visits inside the production reconciliation loop. For
one homogeneous route-server update group and 64 changed routes, the target
changes the pristine case from `64 * peers` visits to zero:

| Peers | Control median (mean) | Target median (mean) | Mean change | Across-attempt range |
|------:|----------------------:|---------------------:|------------:|---------------------:|
| 1 | 30.94 us | 28.98 us | -6.32% | -7.54% to -4.59% |
| 8 | 58.27 us | 43.47 us | -25.41% | -25.61% to -25.00% |
| 64 | 281.77 us | 164.15 us | -41.74% | -41.99% to -41.58% |
| 256 | 1.07 ms | 595.46 us | -44.12% | -44.42% to -43.85% |
| 1,000 | 4.21 ms | 2.40 ms | -42.95% | -43.23% to -42.36% |

Every attempt at every shape favors the target, and every A/B range clears the
corresponding same-SHA range. The one-peer result is now a bounded supporting
claim: its immediate identical-binary control is centered at -0.17% with a
range that crosses zero, while all six A/B attempts are between -7.54% and
-4.59%.

This is not a whole-daemon convergence claim. It measures a persistent
64-route distribution pass through the single-threaded RIB actor, real
exact-export encoder, group reuse, authoritative Adj-RIB-Out commit, gauge
refresh, and bounded-channel enqueue. At 1,000 peers the measured interval is
about 1.81 ms shorter on this host. Route construction, Loc-RIB recompute,
receiver drains, session writers, sockets, and network I/O are outside it.

## Control and target

- Stack base: `58f7f8c675c7b86908968df29a2a009ea999d483`, the exact
  reviewed head of the grouped Adj-RIB-Out allocation change.
- Control and harness:
  `ff055f75233f5fcbfa2dd12c7976c87489ee55fa`. It adds the
  test-only visit counter, load-bearing tests, and symmetric benchmark-local
  pristine-eligibility receipt while preserving the unconditional
  reconciliation loop.
- Target: `8526b27e839bf1eb3974f2df2d7a7745a8b00f70`. It makes the
  already-measured pristine boolean available to normal builds and returns
  before reconciliation when it is true.

The same-SHA base and head benchmark binaries were byte-identical
(`e5210c7f781e0ca4c9356cd5ce5e14aa0741ce2e6152120530bffd1d187a397b`).
The A/B control binary has the same hash; the target binary is
`8f40081d031202d88f2f032e73895d7d4bd1ccce048cb74753dae2816b85cda8`.
If the stack base changes, these measurements are stale and must be rerun.

The visit counter is `cfg(test)` only, is incremented inside the actual prefix
loop, and is absent from the `bench-internals` binaries used for measurement.
Both benchmark binaries do compile the same once-per-peer pristine-eligibility
counter. Its post-interval assertion proves that every target invocation used
the exact boolean consumed by the early return.

## Noise floor

The harness commit was compared with itself for six alternating pairs
immediately before A/B:

| Peers | Mean pseudo-delta | Standard deviation | Across-attempt range |
|------:|------------------:|-------------------:|---------------------:|
| 1 | -0.17% | 0.63% | -1.28% to +0.46% |
| 8 | -0.27% | 0.76% | -1.31% to +0.92% |
| 64 | -0.93% | 1.40% | -2.86% to +0.78% |
| 256 | -1.38% | 1.57% | -2.97% to +0.73% |
| 1,000 | -1.33% | 1.82% | -3.52% to +0.90% |

Every same-SHA range crosses zero. The 64/256/1,000-peer target gains are tens
of percentage points beyond same-shape drift; the 1- and 8-peer target ranges
also clear their controls.

## Fleet and measured boundary

Each fixture has one homogeneous route-server update group with 1, 8, 64, 256,
or 1,000 members in remote AS 65001, no export policy, and no pre-existing OTC
blocked state. It prewarms an advertisement, then alternates MED 50/51 across
64 IPv4 `/24` routes carrying `ORIGIN`, a three-ASN `AS_PATH`, `NEXT_HOP`,
`LOCAL_PREF=100`, and MED.

Each timed iteration contains:

- manager distribution on the single-threaded RIB actor;
- one real `SessionExportEncoder` exact-export probe per changed route;
- compatible encoded-result reuse across the remaining group members;
- authoritative Adj-RIB-Out commit and one unicast-family gauge refresh per
  peer; and
- one bounded-channel enqueue per peer.

The harness asserts one group, zero dirty or ungrouped peers, 64 exact-probe
candidates, `64 * (peers - 1)` cache reuses, one successful commit and enqueue
per peer, the exact gauge mask/value, one real session snapshot per envelope,
and exactly one 64-route envelope per receiver. Those assertions and receiver
drains run outside the accumulated interval.

Criterion used a 3-second warmup, 5-second measurement, and 10 samples. Both
campaigns ran six attempts with odd attempts control-first and even attempts
target-first, separate Cargo target directories, one shared Criterion
directory, logical CPU 8, the `performance` governor, and the repository host
lock.

Four persistent development containers remained up. Their combined CPU was
low at both preflights, but a globally quiet host is not asserted. The
cooperative lock excluded another rustbgpd benchmark campaign, and the
immediate same-SHA run records the ambient variance actually observed.

## Load-bearing proofs

The Criterion fixture resets the receipt before each timed interval and
asserts afterward that all N peers satisfied the exact pristine boolean used
by the target return. This proves the optimized branch ran in the measured
binary without placing the assertion itself inside the interval.

`distribution_skips_pristine_otc_prefix_visits` sends 64 real routes through
four grouped peers, proves grouping, exact route delivery, one metrics clone,
four commits, and four enqueues, then asserts zero OTC prefix visits and empty
current/pending maps. Removing only the production early return made it fail:

```text
assertion `left == right` failed
  left: 256
 right: 0
```

`otc_reconcile_non_pristine_state_uses_prefix_loop_and_clears_exactly` seeds a
newly blocked route, proves current and pending state plus one loop visit, then
reconciles an empty result and proves the second visit clears both maps. This
keeps the fast path from swallowing the state-removal case.

Restoring the target returned both tests to green and left the worktree clean.
The benchmark's real-path assertions are also load-bearing: bypassing the
encoder breaks probe counts; breaking grouping breaks membership or reuse;
and a missed commit, enqueue, session snapshot, or route envelope makes the
fixture fail.

## Reproduction

From the target worktree, with no competing benchmark or lab:

```bash
bench/compare-criterion.sh \
  --base ff055f75233f5fcbfa2dd12c7976c87489ee55fa \
  --head ff055f75233f5fcbfa2dd12c7976c87489ee55fa \
  --package rustbgpd-transport --bench fanout \
  --features bench-internals --filter adj_rib_out_family_gauge \
  --core 8 --attempts 6 --require-performance \
  --out-dir target/otc-pristine-reconcile-same-sha-v2

bench/compare-criterion.sh \
  --base ff055f75233f5fcbfa2dd12c7976c87489ee55fa \
  --head 8526b27e839bf1eb3974f2df2d7a7745a8b00f70 \
  --package rustbgpd-transport --bench fanout \
  --features bench-internals --filter adj_rib_out_family_gauge \
  --core 8 --attempts 6 --require-performance \
  --out-dir target/otc-pristine-reconcile-before-after-v2
```

Exact per-attempt medians and confidence bounds, sanitized environment
metadata, summaries, the destructive proof, and checksums are retained under
[`artifacts/otc-pristine-reconcile-2026-07/`](artifacts/otc-pristine-reconcile-2026-07/).
