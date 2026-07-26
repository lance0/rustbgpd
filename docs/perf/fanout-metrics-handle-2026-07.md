# Fanout metrics-handle lifetime receipt (July 2026)

## Decision

Clone the immutable `BgpMetrics` handle once per distribution pass, not once
per outbound peer. The generated clone traverses the complete metrics value;
all members in one synchronous pass use the same shared registry handles, so
repeating that clone at peer cardinality bought no isolation or correctness.

The bounded downside is one clone on a distribution pass that reaches this
point but has no peer that would have reached the former clone site. A
route-bearing pass changes from one clone per peer to one clone total. No
internal Arc-operation or copied-byte count is claimed.

## Result

Against the immediately preceding control commit, six counterbalanced pairs
measured:

| Peers | Control median (mean) | Target median (mean) | Mean change | Across-attempt range |
|------:|----------------------:|---------------------:|------------:|---------------------:|
| 1 | 30.64 us | 30.80 us | +0.52% | -1.37% to +2.01% |
| 8 | 63.63 us | 58.44 us | -8.16% | -8.53% to -8.00% |
| 64 | 332.39 us | 285.51 us | -14.10% | -14.76% to -13.32% |
| 256 | 1.27 ms | 1.08 ms | -15.04% | -15.54% to -14.50% |
| 1,000 | 5.01 ms | 4.28 ms | -14.51% | -14.84% to -13.93% |

The one-peer row is the predeclared negative control: both revisions perform
one clone. Its result is noise and **no one-peer improvement is claimed**.
Every 8/64/256/1,000-peer attempt favors the target and clears the
corresponding same-SHA variability.

This is not a whole-daemon convergence claim. At 1,000 peers the measured
interval is about 0.73 ms shorter on this host for one 64-route steady-state
distribution pass. Session writers, socket/network I/O, route construction,
Loc-RIB replacement/recompute, receipt checks, and receiver drains are outside
that interval.

## Control and noise floor

- Settled stack base: `ffc13f6e12e3da56b84b2245474eeaf550e6b80e`.
- Control/harness: `c933a0da8156af5e56da4e9544141170e40c7e8f`.
- Target: `067663e532191bc5b3f8828e7ad659633e37f2bd`.

The same-SHA control immediately preceded the A/B:

| Peers | Mean pseudo-delta | Standard deviation | Across-attempt range |
|------:|------------------:|-------------------:|---------------------:|
| 1 | -0.00% | 0.47% | -0.65% to +0.60% |
| 8 | -0.12% | 0.84% | -1.04% to +1.18% |
| 64 | +0.06% | 0.40% | -0.66% to +0.53% |
| 256 | +0.11% | 0.43% | -0.54% to +0.79% |
| 1,000 | -0.45% | 0.85% | -1.82% to +0.48% |

Its nominal base/head benchmark binaries are byte-identical. The same binary
is the A/B control; the target binary has a distinct retained hash. If the
stack base changes, the receipt is stale and must be rerun.

## Fleet and measured boundary

Each fixture has one homogeneous route-server update group with 1, 8, 64,
256, or 1,000 members. It prewarms the first advertisement, then alternates
MED 50/51 across 64 IPv4 routes. Every timed iteration includes:

- synchronous RIB actor distribution;
- one real `SessionExportEncoder` exact-export probe per changed route;
- compatible exact-length reuse across remaining group members;
- authoritative Adj-RIB-Out commits and one unicast-family gauge write per
  peer; and
- one bounded-channel enqueue per peer.

Assertions after every timed iteration prove one group, zero fallback/dirty
peers, 64 real exact-probe candidates, `64 * (peers - 1)` compatible reuses,
one successful commit/enqueue/gauge write per peer, exact unicast gauge
values, and every peer satisfying the pristine OTC predicate. Receiver drains
then prove exactly one route-bearing envelope per peer outside timed work.

Criterion used 3-second warmups, 5-second measurements, 10 samples, and six
attempts: odd base-first, even target-first. Both sides used separate Cargo
target directories, logical CPU 8 under the `performance` governor, and the
repository host lock. The complete four-campaign chain lasted 4,013 seconds
with rustc 1.97.0.

## Load-bearing proof

Moving the production clone back inside the peer loop, without changing the
test, makes `distribution_clones_metrics_once_per_pass` fail with `left: 4`,
`right: 1`. Restoring pass scope returns it to green. The exact fresh mutation
receipt is retained in
[`artifacts/fanout-source-stack-2026-07/metrics-red-proof.txt`](artifacts/fanout-source-stack-2026-07/metrics-red-proof.txt).

## Artifacts and reproduction

Commands, generated summaries, exact attempt/aggregate tables, original raw
hashes, sanitized hashes, binary/script provenance, all 48 logs, and all 240
estimate plus 240 sample baselines are retained under
[`artifacts/fanout-source-stack-2026-07/`](artifacts/fanout-source-stack-2026-07/).
The deterministic evidence archive is 152,532 bytes with SHA-256
`8f5cd6d16048aab5a2f988e5d5e4b77389157f1f6a6002705df3f4fc3a0a6fdf`.
