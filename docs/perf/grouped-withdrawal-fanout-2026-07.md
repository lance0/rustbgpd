# Grouped withdrawal fanout receipt (July 2026)

Status: **MEASURED BASELINE** (LAN-671) at exact commit
`f55d6c5f1a300b0b2c5a8797469165eb1351e62c`. This is an absolute,
measurement-only baseline. It has no optimization, control, before/after
comparison, delta, regression, or end-to-end network claim.

Only the post-preflight exact-commit Criterion archive described below is
admissible. Earlier runs, including a distinct top-level Criterion output, are
rejected.

## Measurement contract

The benchmark group is `grouped_withdrawal_fanout`. Its disclosed fleet shape
is:

- one synthetic, unregistered source carrying eBGP-origin route metadata and
  using the production legacy-producer `session_id = 0` compatibility branch;
- 64 deterministic IPv4 `/24` routes withdrawn in stable prefix order;
- one homogeneous route-server update group;
- 8, 64, 256, or 1,000 established members, each with the same remote ASN;
- no export policy, Add-Path, ORF, per-client best, or dirty-resync fallback;
- one negotiated IPv4-unicast family; and
- a bounded outbound channel with capacity for 72 envelopes.

Each persistent fixture pre-advertises the complete inventory through the
production manager, verifies and drains exactly one setup envelope per member,
then starts the timer immediately before one production
`RibUpdate::RoutesReceived` withdrawal. The interval ends after direct manager
dispatch, bounded route-chunk processing, Loc-RIB recompute, grouped
distribution, authoritative Adj-RIB-Out commit, metric refresh, and
bounded-channel enqueue finish. Manager-channel dequeue, Tokio actor
scheduling, re-advertisement, receipt checks, and channel inspection stay
outside accumulated time. Session-writer, socket, and network I/O are not
measured.

## Correctness fence

Every timed iteration fails unless all of these remain true:

- immediately before counters reset and the timer starts, the isolated setup
  receipt reports 64 group-owned unicast routes, a first-member IPv4 gauge of
  64, one update group containing every member, zero private/dirty fallback,
  one real 64-candidate exact-probe batch, `64 * (members - 1)` compatible
  reuse hits, one successful commit/enqueue per member, and concrete
  transport-session snapshots with nonzero owners and the negotiated classic
  message ceiling;
- the reset receipt records exactly one accepted production
  `RoutesReceived` dispatch carrying all 64 withdrawals;
- all members remain in one update group, with zero private and dirty members;
- the final group-owned and private unicast Adj-RIB-Out inventories are both
  empty, and the first member's seven family gauges are all zero;
- every member records one successful route-bearing commit and enqueue; and
- every receiver yields exactly one withdrawal envelope whose 64 unique route
  identities equal the pre-advertised inventory, with no announcement or
  non-unicast payload.

The checks are load-bearing. Omitting pre-advertisement fails the nonzero
group-owned route and first-member gauge assertions. Bypassing group ownership
fails the group/private inventory and membership assertions. Bypassing metric
accounting fails the setup gauge/write receipt. Bypassing the real encoder
fails the exact-probe batch/candidate/reuse or concrete-snapshot receipt.
Dropping a setup commit or enqueue fails the per-member setup counters.
Bypassing `RoutesReceived` on the timed pass fails the dispatcher counter.
Dropping or duplicating a withdrawal envelope fails the per-peer count or
inventory check. Private/dirty fallback or a residual advertised prefix fails
the membership or final folded Adj-RIB-Out receipt.

## Pinned environment and run

- measured tree: `fe956c9dd60e366ee4870cb23c0c5779ce899026`;
- rustc: `1.97.0 (2d8144b78 2026-07-07)`, commit
  `2d8144b7880597b6e6d3dfd63a9a9efae3f533d3`;
- cargo: `1.97.0`; Criterion: `0.8.2`;
- kernel: Linux `6.17.0-35-generic`, `x86_64`;
- CPU: AMD Ryzen Threadripper 7970X 32-Cores, 64 logical CPUs;
- pin: logical CPU 63 (`taskset -c 63`);
- scaling governor: `performance`; and
- exact-commit preflight at `2026-07-27T08:03:21Z`: 1-minute load `1.15`
  against a `2.0` maximum, zero competing benchmark processes, status `pass`.

The host lock and preflight wrapped this command shape:

```bash
source docs/perf/event-history-host-fence.sh
event_history_acquire_host_lock
PREFLIGHT="$RUN/preflight.tsv"
event_history_init_host_preflight_log "$PREFLIGHT"
event_history_wait_for_idle grouped-withdrawal-f55d6c5f "$PREFLIGHT"

CRITERION_HOME="$CRITERION_OUT" taskset -c 63 \
  cargo bench -p rustbgpd-transport --features bench-internals --bench fanout \
  -- grouped_withdrawal_fanout --noplot
```

The run used Criterion linear sampling with 10 samples per fleet size. Passing
completion also means every in-code correctness receipt above held on every
timed iteration.

## Results

The estimate is Criterion's median point estimate; bounds are its bootstrap
95% confidence interval. With 10 samples, retain the exact bounds and raw
samples rather than interpreting small differences as stable effects.

| Routes | Members | Median | 95% confidence interval |
|-------:|--------:|-------:|------------------------:|
| 64 | 8 | 61.914497 µs | 61.496437–62.056793 µs |
| 64 | 64 | 169.058598 µs | 168.426092–170.919917 µs |
| 64 | 256 | 558.397745 µs | 554.388080–559.376800 µs |
| 64 | 1,000 | 2.194817 ms | 2.169139–2.222355 ms |

The compact, sanitized evidence package is in
[`artifacts/grouped-withdrawal-fanout-2026-07/`](artifacts/grouped-withdrawal-fanout-2026-07/README.md).
It retains the exact estimates, all 40 `(iterations, total time)` samples,
source-JSON hashes, preflight, environment, and package checksums without a
hostname, absolute path, or process identifier.

These values cover only the direct manager seam described in the measurement
contract: a synthetic unregistered legacy source session and the production
manager/update-group path through bounded-channel enqueue. They exclude
manager-channel dequeue, Tokio scheduling, session-writer work, socket I/O,
and network I/O. They must not be presented as full-pipeline or end-to-end
latency.
