# Fanout metrics-handle lifetime receipt (July 2026)

## Decision

Clone the immutable `BgpMetrics` handle once per distribution pass, not once
per peer. The generated `Clone` traverses the complete 153-field value. The
same shared registry handles are valid for every member in a synchronous
fanout pass, so repeating that work at peer cardinality bought no isolation or
correctness.

The bounded downside is one clone on a pass that reaches distribution with no
outbound peer, or whose peers all exit before the old clone site; the previous
placement could perform zero. Measured route-bearing fleets change from N
whole-`BgpMetrics` clone invocations to one. No exact count of internal Arc
operations or copied bytes is claimed.

Against the immediately preceding control commit, six alternating Criterion
pairs measured the following changes:

| Peers | Control median (mean) | Target median (mean) | Mean change | Across-attempt range |
|------:|----------------------:|---------------------:|------------:|---------------------:|
| 1 | 30.71 us | 30.91 us | +0.65% | -1.11% to +3.18% |
| 8 | 63.80 us | 58.59 us | -8.16% | -8.97% to -6.32% |
| 64 | 332.36 us | 281.11 us | -15.42% | -15.97% to -14.67% |
| 256 | 1.27 ms | 1.06 ms | -16.32% | -16.93% to -15.87% |
| 1,000 | 4.99 ms | 4.19 ms | -15.93% | -16.52% to -15.01% |

The one-peer row is the predeclared negative control: both revisions perform
one clone, and its result is noise. The gain strengthens with fanout and every
8/64/256/1,000-peer attempt favors the target.

This is not a whole-daemon convergence claim. It is a steady-state,
route-server-shaped measurement of one 64-route distribution pass. At 1,000
peers the measured interval is about 0.80 ms shorter on this host; socket
writes, network I/O, route construction, Loc-RIB recompute, receipt checks, and
receiver drains are outside the interval.

## Control and target

- Stack base: `58f7f8c675c7b86908968df29a2a009ea999d483`, the exact
  reviewed head of the grouped Adj-RIB-Out allocation change. The benchmark
  depends on that grouped-member construction behavior.
- Control and harness: `a91394e8d7c5781aa3a7da12808053ec5f6e83d6`.
  It adds the one-peer row and a mechanically coupled test counter while
  preserving the production clone at its existing per-peer location.
- Target: `6e1cf047ed406572614e65a828b584478c740cf4`. It moves that
  same helper outside the peer loop and changes no benchmark code.

The same-SHA base and head binaries were byte-identical
(`5626ba659ce57ccb958c52085d239ab27f616468b06ac27dac4b5add309d31af`).
The control binary in the A/B campaign has the same hash; the target binary is
`c76ea149a255ab63ac6892aa4ca953919bf9aad5b11bea5fdedefbb9b700b9df`.
If the stack base changes, these measurements are stale and must be rerun.

## Noise floor

The same harness commit was compared with itself for six alternating pairs
immediately before the A/B campaign:

| Peers | Mean pseudo-delta | Standard deviation | Across-attempt range |
|------:|------------------:|-------------------:|---------------------:|
| 1 | -3.84% | 3.11% | -6.11% to +1.74% |
| 8 | -2.40% | 1.67% | -4.65% to +0.41% |
| 64 | -0.43% | 0.51% | -1.19% to +0.21% |
| 256 | -0.35% | 0.75% | -1.57% to +0.65% |
| 1,000 | -0.03% | 0.92% | -1.77% to +0.70% |

The 64/256/1,000-peer target ranges are entirely negative and more than an
order of magnitude larger than the corresponding same-SHA mean drift. The
8-peer gain also clears its same-SHA range. The one-peer result is deliberately
not claimed.

## Fleet and measured boundary

Each persistent fixture has one homogeneous route-server update group with
1, 8, 64, 256, or 1,000 members, all in remote AS 65001 and with no export
policy. Its channels hold 72 envelopes. It prewarms the first advertisement,
then alternates MED 50/51 across 64 IPv4 `/24` routes carrying `ORIGIN`, a
three-ASN `AS_PATH`, `NEXT_HOP`, `LOCAL_PREF=100`, and MED. Each measured
iteration contains:

- manager distribution on the single-threaded RIB actor;
- one real `SessionExportEncoder` exact-export probe for each changed route;
- compatible exact-length reuse across remaining group members;
- authoritative Adj-RIB-Out commit and one unicast-family gauge refresh per
  peer; and
- one bounded-channel enqueue per peer.

The harness asserts one group, zero ungrouped or dirty peers, 64 exact-probe
candidates, `64 * (peers - 1)` cache reuses, one successful commit and enqueue
per peer, the exact unicast gauge mask/value, one real session snapshot per
envelope, and exactly one route-bearing envelope per receiver. These
assertions run outside the accumulated interval.

Criterion used its standard 3-second warmup, 5-second measurement, and 10
samples. Both campaigns ran six attempts with odd attempts control-first and
even attempts target-first, separate Cargo target directories, one shared
Criterion directory, `taskset` on logical CPU 8, the `performance` governor,
and the repository host lock.

At the preflight immediately before the campaigns, four persistent LibreNMS
development containers were up; each reported no more than 0.37% CPU (0.65%
combined). The cooperative host lock prevented another rustbgpd benchmark
campaign, but this is not asserted to be a globally quiet host. The immediate
same-SHA campaign prices the observed ambient variance instead of assuming it
away.

## Load-bearing proofs

The focused manager test drives four grouped peers through a real
route-bearing distribution, proves four commits and enqueues, drains all four
updates, and reads a `cfg(test)` counter of whole-`BgpMetrics` clone
invocations. That counter is incremented by the helper that performs the
actual `BgpMetrics::clone()`.

Moving the production helper back inside the peer loop was injected after the
target commit. The test failed exactly:

```text
assertion `left == right` failed
  left: 4
 right: 1
```

Restoring the target returned the test to green and left `git diff
--exit-code` clean. The benchmark assertions are also load-bearing: bypassing
the real encoder makes probe counts red; breaking grouping makes membership
or reuse red; equality suppression or a dropped send makes commit/enqueue
counts red; a missing session snapshot or extra envelope makes receiver checks
red.

## Reproduction

From the target worktree, with no competing benchmark or lab:

```bash
bench/compare-criterion.sh \
  --base a91394e8d7c5781aa3a7da12808053ec5f6e83d6 \
  --head a91394e8d7c5781aa3a7da12808053ec5f6e83d6 \
  --package rustbgpd-transport --bench fanout \
  --features bench-internals --filter adj_rib_out_family_gauge \
  --core 8 --attempts 6 --require-performance \
  --out-dir target/fanout-metrics-same-sha

bench/compare-criterion.sh \
  --base a91394e8d7c5781aa3a7da12808053ec5f6e83d6 \
  --head 6e1cf047ed406572614e65a828b584478c740cf4 \
  --package rustbgpd-transport --bench fanout \
  --features bench-internals --filter adj_rib_out_family_gauge \
  --core 8 --attempts 6 --require-performance \
  --out-dir target/fanout-metrics-before-after
```

Exact per-attempt medians and 95% bounds, sanitized environment metadata,
summaries, the destructive proof, and checksums are retained under
[`artifacts/fanout-metrics-handle-2026-07/`](artifacts/fanout-metrics-handle-2026-07/).
