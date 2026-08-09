# Grouped withdrawal exact-probe skip receipt (July 2026)

Status: **MEASURED OPTIMIZATION** at production commit
`6e23412ffa552dab325183aaaec2dba9510b9232`, compared with its literal
immediate harness parent
`143d571078f92cfc75ce048d7062883994250078`.

## Change and claim

Exact-export precommit validates announcement wire forms. A withdrawal-only
envelope has no announcement candidates, but the manager still called the
batch probe once per member and reconciled an empty sparse-rejection overlay.
The candidate skips only that empty announcement precommit. It still acquires
and attaches the immutable session snapshot used for transport
owner/generation fencing and withdrawal preparation, retires prior exact
rejections, commits Adj-RIB-Out state, refreshes gauges, and enqueues the exact
withdrawal inventory.

At a fixed 64-route withdrawal, the two-attempt mean of the Criterion median
improved by 6.80% at 64 members, 8.41% at 256 members, and 9.33% at 1,000
members. Both paired attempts favored the candidate at those sizes, while the
same-revision median spread stayed between 0.17% and 0.71%. The 8-member
delta is retained but not claimed.

This is a direct production-manager-path result, not a full-daemon,
convergence, session-writer, socket, or network-throughput claim.

## Measurement contract

The benchmark is the `grouped_withdrawal_fanout` fixture from the
[grouped withdrawal fanout baseline](grouped-withdrawal-fanout-2026-07.md):

- one synthetic unregistered source using the production legacy-producer
  `session_id = 0` compatibility path;
- 64 deterministic IPv4 `/24` routes;
- one homogeneous route-server update group with 8, 64, 256, or 1,000
  established members;
- no export policy, Add-Path, ORF, per-client best, or dirty fallback;
- one negotiated IPv4-unicast family; and
- one bounded outbound channel per member.

Each persistent fixture first advertises the full inventory through the
production manager and drains one setup envelope per member. The timer starts
immediately before one production `RibUpdate::RoutesReceived` withdrawal and
ends after direct dispatch, bounded route-chunk processing, Loc-RIB recompute,
grouped distribution, authoritative commit, metric refresh, and
bounded-channel enqueue. Re-advertisement and receipt checks are outside the
accumulated interval.

The benchmark source has SHA-256
`e8091b1778ca14d0e56cfec15f1c24e97adb91fa1db061db9ffcdbe9de502e9f`
at both measured revisions. The parent-only `per-peer` environment value
changes the post-timer assertion from zero to the known parent count; it does
not alter the measured interval.

## Load-bearing correctness fence

Every timed iteration still proves:

- setup used one real 64-candidate exact probe and compatible grouped reuse;
- the timed dispatch carried all 64 withdrawals through one update group;
- no private or dirty fallback occurred;
- every member retained a concrete, nonzero-owner transport snapshot;
- exact-probe candidates, nonzero lengths, and cache reuses were zero during
  the withdrawal;
- the parent recorded one empty batch per member while the candidate recorded
  zero;
- every member committed and enqueued exactly once;
- every outbound envelope contained the exact unique withdrawal inventory;
  and
- the final grouped and private Adj-RIB-Out inventories were empty.

The default-zero benchmark assertion fails on the immediate parent with
`left: 8, right: 0` at the first fleet shape. A focused post-OTC unit test also
turns a blocked announcement into an owed withdrawal and fails if unconditional
precommit is restored: the observed batch count becomes two instead of one.
The mixed announce/withdraw control still records one nonempty exact batch,
and existing grouped rejection tests retain fail-closed overlay coverage.

## Environment and order

- Linux `6.17.0-35-generic`, x86-64;
- AMD Ryzen Threadripper 7970X, logical CPU 63;
- all observed governors `performance`;
- rustc `1.97.0` (`2d8144b7880597b6e6d3dfd63a9a9ef`);
- Criterion `0.8.2`, linear sampling, 10 samples, default 3-second warmup and
  5-second measurement;
- shared rustbgpd host lock held for the full campaign;
- preflight load below 2.0 and no competing build, benchmark, daemon, or soak
  process before every attempt; and
- counterbalanced order: parent A, candidate A, candidate B, parent B.

## Results

Values are Criterion median point estimates. `Same-SHA` is the signed change
between the two attempts of that revision; `A/B delta` compares corresponding
parent and candidate attempts.

| Members | Parent A | Parent B | Parent same-SHA | Candidate A | Candidate B | Candidate same-SHA | A delta | B delta | Mean delta |
|--------:|---------:|---------:|----------------:|------------:|------------:|-------------------:|--------:|--------:|-----------:|
| 8 | 60.220 µs | 60.297 µs | +0.13% | 59.572 µs | 59.007 µs | -0.95% | -1.08% | -2.14% | -1.61% |
| 64 | 166.712 µs | 167.595 µs | +0.53% | 156.349 µs | 155.235 µs | -0.71% | -6.22% | -7.38% | -6.80% |
| 256 | 553.597 µs | 552.479 µs | -0.20% | 507.078 µs | 505.941 µs | -0.22% | -8.40% | -8.42% | -8.41% |
| 1,000 | 2.231 ms | 2.228 ms | -0.17% | 2.017 ms | 2.026 ms | +0.46% | -9.61% | -9.05% | -9.33% |

At 8 members, the candidate delta is only about 1.7 times the larger
same-revision spread and the A-attempt confidence intervals overlap, so no
small-fleet improvement is claimed. At 64, 256, and 1,000 members, both paired
deltas exceed the corresponding same-revision spread by a wide margin and
the parent/candidate 95% intervals do not overlap.

## Artifacts

The compact package under
[`docs/perf/artifacts/grouped-withdrawal-probe-skip-2026-07/`](artifacts/grouped-withdrawal-probe-skip-2026-07/)
retains all 160 linear samples, exact medians and bootstrap intervals, source
JSON hashes, quiet-host preflights, provenance, and a checksum envelope. It
contains no hostname, username, private path, PID, or command-line snapshot.
