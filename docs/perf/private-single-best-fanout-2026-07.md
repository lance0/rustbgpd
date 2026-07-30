# Private single-best fanout

Date: 2026-07-30

## Boundary

This result covers the RIB manager's clean, ungrouped, private single-best
export path. The fixture uses 64 changed IPv4 unicast routes, one route-bearing
envelope per peer, real policy encoders and transport snapshots, neighbor-set
peer context with a miss, default permit, and a MED 50 seed replaced by MED 51.
Peer counts are 1, 8, 64, and 256.

The optimized path borrows the already-computed `best_changed` prefixes when a
peer has no resolved ORR policy, per-client-best selection, or negotiated
Add-Path send requirement. Peers requiring any of those behaviors retain the
existing affected-prefix scan.

## Semantic receipts

For `P` peers, both revisions produce exactly `P` batches, commits, enqueues,
family-gauge writes, and pristine-OTC candidates; `64P` private routes,
candidates, and nonzero encodings; one routes-received dispatch; no withdrawal;
and `[64, 0, 0, 0, 0, 0, 0]` for the first peer's family inventory. There are
no update groups, grouped routes, dirty peers, or cache reuses.

The instrumented parent records `64P` extra prefix scans: 64, 512, 4,096, and
16,384. The candidate records zero. A compiled mutation that restored the scan
failed the retained zero-scan receipt at 256 peers with 16,384 observed scans.

## Measurement

Criterion ran six alternating-order attempts per side on an exclusive
performance-governor core. A fresh same-SHA control preceded the A/B run.
Values below are means across attempt medians; deltas are candidate versus
instrumented parent.

| peers | control delta | parent | candidate | A/B delta | range |
|---:|---:|---:|---:|---:|---:|
| 1 | -0.46% | 26.29 us | 25.26 us | -3.93% | -6.26%..-2.51% |
| 8 | -0.16% | 159.62 us | 152.21 us | -4.63% | -7.15%..-3.69% |
| 64 | +0.01% | 1.24 ms | 1.18 ms | -4.56% | -7.17%..-3.47% |
| 256 | -0.18% | 4.97 ms | 4.74 ms | -4.47% | -7.20%..-3.45% |

At 8, 64, and 256 peers, all six A/B attempts favor the candidate, the final
propagated 95% confidence interval is below zero, and the mean improvement
exceeds the most favorable same-SHA attempt. Mean absolute savings are 7.41 us,
56.50 us, and 222.75 us, or 926, 883, and 870 ns per peer. That 1.06 ratio
supports linear absolute scaling over the claimed peer counts.

## Inference boundary

The result claims a manager-path improvement at 8, 64, and 256 peers and linear
absolute scaling over those points. The one-peer result is explicitly
unclaimed because its roughly 1 us absolute difference is floor-sensitive.
No daemon, convergence, network, or full-table result is claimed.

The benchmark is intentionally a clean-path proof. It does not change or
measure ORR, per-client-best, or Add-Path send behavior.

## Reproduction and retained evidence

The measurement used harness `454a83b0f700a5d2488d9aefd684678d34fe54ad`
and candidate `b9f805a0abe6c0cac79b55af89ed866c7ffa10fb`. The two source patches were
rebased onto `f5568242047ffbbd32d940dcbcdaec922564d6e2` as
`775d47a662f2b7828528a2fe25e5a2a8e63daf56` and
`232fb0fcd7231f21c8ac355878b56f47378b37b0`; stable patch IDs and byte-level
diff hashes are retained in the manifest.

See [`artifacts/private-single-best-fanout-2026-07/`](artifacts/private-single-best-fanout-2026-07/)
for sanitized summaries, exact compressed Criterion estimates, checksums, the
counter red proof, and the deterministic verifier.
