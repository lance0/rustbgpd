# Grouped withdrawal fanout receipt (July 2026)

Status: **UNMEASURED SCAFFOLD** (LAN-671). No timing result or performance
conclusion is retained here yet. Populate the environment, commit, Criterion
estimates, and artifact paths only after a host-fenced run passes every
in-code correctness receipt. Any Criterion output collected before the
pre-timer populated-state receipt landed is rejected and must be rerun.

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

## Deferred host-fenced run

Use one shared host lock and retain the Criterion output plus environment and
preflight evidence before making any performance claim:

```bash
source docs/perf/event-history-host-fence.sh
event_history_acquire_host_lock
PREFLIGHT=/path/to/new-preflight.tsv
event_history_init_host_preflight_log "$PREFLIGHT"
event_history_wait_for_idle grouped-withdrawal-before-bench "$PREFLIGHT"

taskset -c <isolated-cpu> \
  cargo bench -p rustbgpd-transport --features bench-internals --bench fanout \
  -- grouped_withdrawal_fanout --noplot
```

Reject any run that loses its CPU/governor/load preflight or trips an in-code
receipt. Record the exact command, git commit, rustc/Criterion versions, host,
kernel, CPU pin, governor, samples, warmup and measurement duration, and raw
artifact paths here.

## Results

Pending. Do not treat this scaffold as benchmark evidence.

| Routes | Members | Estimate | 95% CI | Artifact |
|-------:|--------:|---------:|-------:|----------|
| 64 | 8 | pending | pending | pending |
| 64 | 64 | pending | pending | pending |
| 64 | 256 | pending | pending | pending |
| 64 | 1,000 | pending | pending | pending |
