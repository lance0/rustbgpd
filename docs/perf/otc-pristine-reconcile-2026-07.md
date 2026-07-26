# Pristine OTC reconciliation receipt (July 2026)

## Decision

Return before the per-prefix RFC 9234 OTC reconciliation loop when all three
inputs prove there is nothing to reconcile:

- the current staging pass produced no blocked routes;
- the peer has no current blocked-route map; and
- the peer has no pending blocked-route map.

Any new, current, or pending blocked state still takes the existing full
reconciliation path. The fast path therefore removes an empty-state table
walk; it does not change which routes are blocked, retained for diagnostics,
promoted, or cleared.

## Result

Against the immediately preceding control commit, six counterbalanced pairs
measured:

| Peers | Control median (mean) | Target median (mean) | Mean change | Across-attempt range |
|------:|----------------------:|---------------------:|------------:|---------------------:|
| 1 | 31.14 us | 28.90 us | -7.17% | -7.86% to -6.15% |
| 8 | 58.65 us | 43.47 us | -25.88% | -26.34% to -25.15% |
| 64 | 282.85 us | 163.77 us | -42.09% | -43.06% to -41.61% |
| 256 | 1.07 ms | 592.96 us | -44.61% | -45.60% to -44.11% |
| 1,000 | 4.21 ms | 2.38 ms | -43.57% | -44.53% to -42.96% |

All six attempts at every shape favor the target, and every target range
clears its same-SHA range. The result grows with peers because the removed
64-prefix scan was performed once for every member.

This is not a whole-daemon convergence claim and does not measure a peer with
active OTC-blocked diagnostic state. It is the exact pristine case the early
return recognizes, during one 64-route steady-state grouped distribution
pass.

## Control and noise floor

- Settled stack base: `ffc13f6e12e3da56b84b2245474eeaf550e6b80e`.
- Control/harness: `6a5d19b854c9f16cbde7b0cc5956ba4182f05e2c`.
- Target: `bf14cdd64c8a99f85a959c755120bd10df947025`.

The same-SHA control immediately preceded the A/B:

| Peers | Mean pseudo-delta | Standard deviation | Across-attempt range |
|------:|------------------:|-------------------:|---------------------:|
| 1 | -0.00% | 0.85% | -1.08% to +1.07% |
| 8 | +0.04% | 1.67% | -1.93% to +2.54% |
| 64 | +0.07% | 1.19% | -1.19% to +2.31% |
| 256 | +0.15% | 1.57% | -1.75% to +2.95% |
| 1,000 | +0.38% | 0.97% | -0.99% to +2.00% |

Every same-SHA range crosses zero. Its two benchmark binaries are
byte-identical; the same control binary begins the A/B, while the target
binary has a distinct retained hash.

## Fleet and measured boundary

The benchmark fleet and timing boundary are shared with the adjacent
metrics-handle receipt: one homogeneous route-server update group, 64 changed
IPv4 routes, 1/8/64/256/1,000 peers, one real `SessionExportEncoder` probe per
changed route, compatible group reuse, authoritative commits, family-gauge
writes, and bounded-channel enqueues. Assertions after every timed iteration
prove that every peer satisfies the exact production pristine predicate.

The control preserves the old prefix loop while exposing the same predicate
counter as the target; the counter is outside the timed production loop and
is compiled into the `bench-internals` binaries symmetrically. The target's
test-only loop-visit counter is not compiled into either benchmark binary.

Criterion used 3-second warmups, 5-second measurements, 10 samples, six
alternating attempts, logical CPU 8, the `performance` governor, and the
repository host lock. rustc was 1.97.0 and the complete four-campaign chain
took 4,013 seconds.

## Load-bearing proofs

Deleting only the production early return makes the four-peer, 64-route
pristine test fail with `left: 256`, `right: 0`. Restoring it returns that
test to green. A separate non-pristine regression keeps current and pending
blocked state populated, drives the real prefix loop, and proves exact
clearing. Deleting the production cleanup of an empty current blocked-route
map makes that test fail on the stale peer entry. The fresh receipts are
[`artifacts/fanout-source-stack-2026-07/otc-red-proof.txt`](artifacts/fanout-source-stack-2026-07/otc-red-proof.txt).

## Artifacts and reproduction

Commands, generated summaries, exact attempt/aggregate tables, original raw
hashes, sanitized hashes, binary/script provenance, all 48 logs, and all 240
estimate plus 240 sample baselines are retained under
[`artifacts/fanout-source-stack-2026-07/`](artifacts/fanout-source-stack-2026-07/).
The deterministic evidence archive is 152,532 bytes with SHA-256
`8f5cd6d16048aab5a2f988e5d5e4b77389157f1f6a6002705df3f4fc3a0a6fdf`.
