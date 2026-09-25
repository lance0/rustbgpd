# ADR-0136: Owner-Published Counter Reads

**Status:** Proposed
**Date:** 2026-09-25

This record makes the owners of policy hit counters publish which counter
instances they have installed, so `GetPolicyStats` reads those live atomics
directly instead of messaging the RIB manager or the peer manager. It extends
[ADR-0132](0132-operator-read-path.md) and
[ADR-0133](0133-installed-import-counter-reads.md) rather than reversing them:
reads keep their deadline and get no priority, and route work never waits for
a read. Neighbor reads, readiness, explain and route listings are unchanged.

## Context

Every installed policy chain owns one `PolicyHitCounters`
(`crates/policy/src/eval.rs`): an `AtomicU64` per term plus evaluation and
error counts, incremented with `Relaxed` `fetch_add` by the evaluating task.
The last error sits behind a mutex that readers acquire with `try_lock`.
Import chains belong to session tasks, which publish an installed-policy
descriptor through a `watch` channel since ADR-0133
(`crates/transport/src/handle.rs`). Export chains belong to the RIB manager's
per-peer export map and global fallback slot (`crates/rib/src/manager/mod.rs`).
Update-group members share their group's chain instance
(`update_groups/membership.rs`), so their rows report the same counters. An
ungrouped peer receives a fresh instance each time its session registers,
because the session hands the RIB a cloned chain. Export rows report
`policy_generation = 0`, so that reset is invisible today.

The counter values are therefore shared memory already. What remains
actor-bound is the roster: which instance is installed for which peer.
`GetPolicyStats` (`crates/api/src/policy_service.rs`) obtains it through up to
four sequential stages under one absolute two-second deadline. Peer validation
and datasets query the peer manager's operator lane. Export queries the RIB
summary lane, which is served between work units, from a frozen projection
during synchronous replacement, and not at all between the `CommitMembers`
batches of a grouped transition
([ADR-0105](0105-grouped-export-policy-transition.md)). Import queries the
operator lane, whose collector (`src/peer_manager/mod.rs`) reads up to 64
publications concurrently and calls `consume_budget()` per peer, policy and
term. With Tokio's budget of 128 units per poll, the flagship shape of 1,000
peers with one two-term import policy spends about 4,000 units, so a fleet
read yields about 31 times into a run queue shared with 1,000 session tasks.

The v0.72.0 route-server flagship soak
([receipt](../soaks/soak-rs-flagship-24h-2026-09-24.md)) failed its management
gate on one of 17,556 `policy stats --direction both` calls, inside a
reload's post-commit window:

```text
stage=export elapsed_ms=597 budget_ms=1999 rpc_elapsed_ms=598 code=Ok;
stage=import elapsed_ms=1471 budget_ms=1401 rpc_elapsed_ms=2070 code=DeadlineExceeded
```

The export stage waited for the RIB actor to load a few atomics. The import
stage read atomics that were already published; its time went to the path
around them. Neither wait buys consistency the counters need. The handler also
replied 70 ms after its deadline, because it could not run until the runtime
scheduled it again. That residual is runtime scheduling, and this design does
not remove it.

The soak host is not the isolated release cell, where the daemon's own cores
completed all 24 calls in 301–492 ms
([receipt](../perf/artifacts/installed-import-counters-isolated-2026-09-13/README.md)).
ADR-0132 made persistent publication conditional on a residual isolated-cell
failure, and the pre-v1 architecture review parked a counter registry on the
same condition. That condition is not met. The project chooses to make the
change before v1 anyway, for counters only, because the remaining delay is
created by the read path itself and "live" has a precise, cheap meaning for
atomics. The separate-read-owner, process-separation and neighbor-summary
candidates are not reopened.

## Decision drivers

Operator reads are not first-class: no read priority, no read-driven credit,
and no owner waiting behind a reader or a reader's lock. A read returns a
bounded answer or a bounded failure under the unchanged absolute deadline,
all-or-error responses and cancellation. Success means a live observation of
owner-published values, never a copy made by a timer or an earlier request.
Stale roster entries must be impossible by construction. The design reuses
`arc-swap`, `tokio::sync::watch` and `std` atomics, enforces its rules with
Rust privacy rather than new checkers, and splits no module for size.

## Options considered

| Option | Verdict |
|---|---|
| Tune admission, the collector cap or the budget | Rejected: a cap of 1,000 already failed the co-pinned cell, and tuning cannot remove the export stage's RIB wait. |
| Remove the collector's per-term yields only | Rejected: both actor hops remain. Its synchronous capture pass is kept below. |
| Publish an import roster only | Rejected alone: export, peer validation and datasets still queue on actors. It is the first slice. |
| Registry with explicit register and deregister calls | Rejected: a second map with independent writers is the stale-entry class. |
| Periodic snapshot cache | Rejected: success would report values up to one period old as if live, and owners would pay for reads that never happen. |
| Per-term Prometheus series | Rejected: peer-by-term cardinality, series cleanup through a hand-maintained reap list, and it still needs a roster for the gRPC response. |
| **Owner-published rosters, rebuilt in full at one publication point** | **Selected.** |

## Decision

### Data model

A counter instance describes itself. It carries its immutable term labels and
a process-wide instance id, drawn at creation from one monotonic `AtomicU64`
sequence starting at 1. The same id means the same monotonic counters; a new id
means the numbers restarted. The ADR-0133 import descriptor then keeps the
session identity, install generation and counter handle, without its own label
copy.

The RIB owns the **export roster**: a version, a map from peer to an installed
instance or "explicitly disabled", and the optional global fallback instance.
It is exactly the projection of the RIB's per-peer export map and global slot.
Per-peer requests apply the RIB's existing rule: the per-peer entry if present,
otherwise the fallback.

The peer manager owns the **import roster**: a version, a map from managed
peer to its current session's publication receiver and session identity, an
address index for peer validation, and the bound dataset handles with their
configured paths. It is exactly the projection of the peer table and dataset
bindings. Dataset status is already published through `ArcSwap` inside each
`DatasetHandle` (`crates/policy/src/datasets.rs`).

Each roster is an immutable value in an `ArcSwap` cell. A `watch` borrow holds
a read lock that can block the producer, so a reader thread preempted during a
borrow could make the RIB or peer manager wait. `arc-swap` readers and writers
are lock-free, so a descheduled reader cannot block a publisher. Import
descriptors keep their `watch` channel, which carries their pending and closed
states; readers hold that borrow only to clone one `Arc`.

A handler takes one `load_full()` per roster. This returns an owned `Arc`,
safe across an await, rather than a `Guard`. The handler captures every row in
one synchronous pass of `Relaxed` loads, awaits only import publications that
are still Pending, and then renders. Capture does not yield, so the sampling
window is as short as the loop and involves no trips through the run queue.

### Lifecycle and ownership

A roster is never edited in place. It is rebuilt from the owner's
authoritative state at one publication point, and Rust privacy prevents
bypassing that point. A projection cannot hold an entry its source lacks, so
the published roster can lag its source but cannot diverge from it.

In the peer manager, the peer table becomes a small type in its own module
with private fields, including the current-session handle inside each managed
peer. Its only mutating methods, `insert`, `remove`, `drain` and
`replace_handle`, republish before returning, so code outside the module
cannot swap a handle without publishing. Dataset-binding changes, including
the existing wholesale configuration replacements, go through one setter that
also republishes. This adds a type; it does not split the module.

In the RIB, the per-peer export map and global slot move behind a small type
whose mutable accessors advance a change version. The run loop republishes
when that version differs from the last published one. It checks in one place:
after a completed top-level unit, and not while a grouped transition is
between `CommitMembers` batches. Pre-commit phases do not change committed
chains (ADR-0105).

| Transition | Roster effect |
|---|---|
| Session flap with task retained | Import publication persists. The RIB removes the export entry at peer down; at peer up an ungrouped peer installs a new instance and a grouped peer rejoins its group's instance. |
| Session task exit (shutdown, replacement, notification respawn) | The old receiver closes. Until the table replaces or removes it, a fleet read fails `UNAVAILABLE`, as today. |
| Inbound collision or notification replacement | `replace_handle` republishes with the new handle in the same actor step. |
| Peer deletion, dynamic accept or expiry | `remove` or `insert` republishes. |
| Update-group join, leave or regroup | The export version advances and republishes at the end of the unit; an emptied group's instance is freed when its last roster or reader drops. |
| Policy reload or rollback | See generation semantics. |
| Daemon shutdown | `drain` republishes an empty roster, and dropping the owner closes the cell. |

A guard in each owner closes its cell when the owner is dropped, whether it
exits normally or unwinds. A read of a closed cell returns `UNAVAILABLE`, so a
stopped publisher never appears as success with frozen numbers. The daemon
already shuts down when the RIB task exits; the guard covers the interval
before that and embedders.

Readers retain at most one roster per owner per in-flight request and release
it on completion, failure or cancellation. Retired rosters are therefore
bounded by in-flight statistics requests. Releasing a 1,000-peer roster costs
about a thousand `Arc` decrements, and releasing the last reference to an
instance costs the same as today's chain replacement.

### What a successful read means

Every numeric value is a `Relaxed` load made during the request, from the
instance the owner's roster designated when the request loaded it. Each atomic
has one modification order, and sequential requests are ordered by the reply,
so an instance's counters never go backwards across reads. Instance selection
reflects the owner's last completed operation. During a long synchronous RIB
operation a read reports live counters of the instances installed before it,
which is fresher than the frozen projection served in that interval today.

A response is not a row-level or fleet-level snapshot. Evaluation counts, term
hits, rows and the two rosters are sampled separately, and a `both` response
can straddle an export commit and a session install. This is the mixed
observation contract ADR-0132 allowed.

Success does not show that the RIB manager, the peer manager or a session is
making progress. A stalled RIB evaluates no routes, and its unchanged counters
are reported truthfully. Readiness and health continue to test live progress.
This extends ADR-0133's counter-availability rule to both directions.

### Generation semantics

Each row carries its own instance identity. Import rows keep the session-local
install generation, which starts at 0 and advances on every install, including
a content-equal reinstall. Export rows report the counter-instance id in
`policy_generation`. It is nonzero and replaces the constant 0. For ungrouped
peers it exposes the counter reset at each session registration that exists
today but cannot be seen.

Each roster load yields one publication. The RIB republishes only at the end of
an operation, so a grouped clean transition switches its whole cohort once, at
the terminal `CommitMembers` batch. A reader sees all members on old instances
or all on new ones. There is no fleet-wide policy generation. Sessions install
import chains one at a time and do evaluate under a mix during a reload.
Per-peer export replacements also complete one peer at a time. A single swap
per reload would either delay publication past sessions already evaluating
under new chains or claim a generation that is not installed.

| Change | Import rows | Export rows |
|---|---|---|
| Forward policy apply (SIGHUP or API) | each session republishes at its install; generations may differ within one response | each per-peer replacement republishes when it completes; a grouped transition republishes once at its terminal commit |
| Content-equal reapply | generation advances, as in ADR-0133 | where the RIB skips an equal replacement, the id is unchanged |
| Rejected-reload rollback | restored sessions advance their generation; a failed restore shows the chain actually installed | authoritative restore republishes when it completes; a partial restore shows the chains actually installed |
| Dataset refresh | unchanged; status stays per handle, and binding changes republish the import roster | unchanged |

### Failure and deadline semantics

The shared absolute deadline, the audit summary's stage names, all-or-error
responses, deterministic ordering and cancellation are unchanged. After
migration a request can still time out when the handler is scheduled late,
because polling, rendering, encoding and writing compete for runtime workers;
removing that wait would require read priority. It also waits, under the
deadline, for an import publication that is still Pending or a cold error lock
that is busy. The dataset handle's `last_error` moves from a blocking `lock()`
to the same `try_lock` shape. It returns `UNAVAILABLE` when a selected session
publication closed, counters are poisoned or mismatched, or a roster cell is
closed; opt-in partial results under churn stay deferred on their existing
triggers. An unmanaged peer returns `NOT_FOUND` from the import roster, and a
listener built without a roster returns `FAILED_PRECONDITION`.

The following no longer cause a failure: queueing in the RIB mailbox or summary
lane, the `CommitMembers` fence, peer-manager operator admission and its
fences, and the collector cap and its forced yields. Audit fields that measure
an actor wait are removed along with that wait rather than reported as zero.

### Scope exclusions

Neighbor rows stay on their current path. A `ListNeighbors` row joins
session-owned counters with session state (FSM state, negotiated parameters,
query-time TCP-AO inspection) and RIB-computed views (advertised counts,
export permit and deny counts, outbound limits). Publishing only the counters
removes no wait, because the row still needs a live session query, and the v1
contract already defines `stale` for an unavailable observation. Advertised
counts for update-group members are derived from the shared group table.
Maintaining a per-member atomic would add work per route change per member.
Reopen this only for a retained isolated-cell failure attributed to collecting
session state.

`GetHealth` and `/readyz` exist to prove live progress. Explain,
rejected-route, `TestPolicy`, route-listing and periodic BMP reads use tables
or caches, not these counters. The direct session `QueryImportPolicyTermHits`
command and the `/metrics` scrape are unchanged.

## Cost and measurement

The increment path is unchanged. Each instance has one writer at a time, a
session for import and the RIB for export. An occasional operator read adds
negligible cache-line traffic, so per-core or sharded counters are not
selected. The design adds three costs. Export counters are created at
install, which moves chain compilation there; today a statistics read can
compile a chain inside the RIB actor, and ADR-0133 accepted the same move for
import. Each chain-changing operation or peer-table mutation rebuilds its
roster in O(peers), so a serial reload of 1,000 ungrouped peers makes about a
million `Arc` clones in total. Each request makes O(rows × terms) loads, paid
by the reader.

Targets at 1,000 peers are publication ≤ 100 µs and capture ≤ 1 ms with two
terms per peer. New microbenchmarks also record 10,000 peers, and capture with
32 terms and 256-byte labels. The existing hot-path Criterion groups
`policy_chain_eval`, `policy_predicate_eval`, `export_policy_eval`,
`rib_pipeline`, `route_churn` and `fanout` must stay within noise
before and after each slice. `just gate-contract` covers bench smoke. Reload
transition and settlement durations at 1,000 peers are compared before and
after. The ADR-0133 allocation probe is extended to export instances. If
rebuild misses its target at a real shape, batch publication per operation;
incremental roster editing is not an acceptable fallback.

## Migration slices

Each slice ships independently with its own proof.

0. **Baseline.** Record the audit's stage and sub-stage timing and the
   isolated-cell measurement on current main.
1. **Self-describing counter instances.** Move labels and the instance id into
   the counter instance, drop the import descriptor's label copy, and create
   export counters at install. There is no operator-visible change. Proof:
   hot-path benches and the allocation probe.
2. **Import roster.** The peer manager publishes the import roster with the
   dataset bindings, and peer validation, import and datasets read it. Delete
   the collector, its concurrency cap, and the operator-lane
   `QueryImportPolicyTermHits`, `QueryPolicyDatasets` and, if otherwise unused,
   `HasPeerAddress`, recording each removed wait-site matrix row. Move dataset
   error reads to `try_lock`. In
   [`v1-stable-contract.md`](../reference/v1-stable-contract.md) and the
   `GetPolicyStats` rows of [`api.md`](../reference/api.md), state that
   success does not show the peer manager is responsive.
3. **Export roster.** The RIB publishes the export roster, and the export
   stage reads it. Export rows report the instance id. Delete
   `ExportPolicyTermHits` from the summary lane and its part of the temporary
   projection, which keeps neighbor snapshots. Delete
   `QueryExportPolicyTermHits` if unused. This slice updates the
   `policy_generation` comment in `proto/rustbgpd.proto`, and extends the v1
   contract and `api.md` wording to the RIB. It also adds a `### Changed`
   changelog fragment and a `### Upgrade notes` fragment. The upgrade note
   explains that export generations become nonzero and change whenever the
   counters restart, including at each session registration of an ungrouped
   peer.
4. **Qualification.** Run the isolated cell and the next flagship soak with
   the management gate unchanged, update the known-issue entry to its
   qualified scope, and move this record to Accepted with evidence links.

## Proof plan

Each regression must fail once with its slice reverted, and that output must
be retained.

- **Held owners.** A `both` request with datasets succeeds while the peer
  manager's operator and ordinary lanes are never polled; before slice 2 it
  returns `DEADLINE_EXCEEDED`. An export request succeeds while a real RIB has
  a full, unpolled mailbox, and while it is parked between `CommitMembers`
  batches; before slice 3 both return `DEADLINE_EXCEEDED`.
- **Stale entries.** The real owner is driven through each case: peer
  deletion; notification and collision replacement, where the read succeeds
  on the new handle without `SessionGone`; dynamic accept and expiry;
  regrouping and group emptying; reload and partial rollback; and shutdown.
  After each, the published roster equals the owner's projection, and a
  retired instance's `Weak` no longer upgrades once readers drop. Test builds
  check "published equals projection" after every RIB unit and peer-table
  method. The red proof removes one version advance or republication.
- **Semantics.** An increment with no intervening owner operation is visible
  to the next read, and sequential reads never decrease. Reads between
  `CommitMembers` batches see only pre-commit instances; publishing per batch
  must fail this. Dropping the RIB makes export return `UNAVAILABLE`; removing
  the closing guard must fail this. A reader holding a loaded roster across an
  await does not delay republication.
- **Latency flat through reloads.** Use the isolated release cell: 1,000 peers
  with 400 IPv4 prefixes each, and the generator on separate cores. Run 12
  reloads in both directions, with probes in the −220 to 0 ms commit band and
  at least six complete pairs. Add one quiescent probe per reload well after
  settlement. Every call must complete within the external two-second
  criterion with all 1,000 import and export rows. The in-band maximum of the
  summed stage `elapsed_ms` must stay within twice the quiescent median plus
  50 ms. Record slice 0 and the final slice with the same placement, and keep
  every call, offset and audit line. Co-pinned runs remain diagnostic.
- **Soak.** The next flagship soak passes `management_failures` with the gate
  unchanged. A soak covers only the tag it ran on.

## Consequences

Once delivered and qualified, `GetPolicyStats` reads owner-published live
counters without queueing behind the RIB manager or peer manager. It returns a
bounded answer or bounded failure, and its remaining latency depends on
runtime scheduling and response size. It still does not promise that reads
never time out, an atomic snapshot, actor-free neighbor reads, or latency
beyond measured receipts.

Operators see nonzero export generations, export statistics that succeed
while the RIB is busy or fenced, and success that no longer implies actor
responsiveness. The costs are two publication points, compilation at install,
an O(peers) rebuild per publication, and instance selection that lags a long
RIB operation by design. The collector, three peer-manager operator queries,
the export summary query and its projection part, and their wait-site rows
are removed. ADR-0132's admission, neighbor projection, executor handoff and
live readiness remain, as does ADR-0133's session-owned import publication.

This record settles ADR-0132's five publication conditions: observation
semantics (what a successful read means), generation and joins (one load per
roster, explicitly mixed owners), failure and lifecycle (projection, closing
guards, actual installation after a partial restore), bounded work and
retention (outside the increment path, bounded by in-flight reads), and
unchanged live gates (readiness and health unchanged; a bypassing read records
no lane-wait sample).

## Prior art

None of these sources is a latency measurement, and thread placement alone
does not settle read latency.

| Source | Counter storage and read path |
|---|---|
| [BIRD 3.1.8](https://gitlab.nic.cz/labs/bird/-/raw/v3.1.8/nest/protocol.h) | Plain `u32` channel statistics; `show protocols` takes the protocol loop's lock and stalls that loop while reading ([io-loop.c](https://gitlab.nic.cz/labs/bird/-/raw/v3.1.8/sysdep/unix/io-loop.c)). |
| [FRR 10.7.1](https://raw.githubusercontent.com/FRRouting/frr/frr-10.7.1/bgpd/bgpd.h) | `_Atomic` peer message counters are still read on the main thread; gRPC waits on the main thread without a timeout ([northbound_grpc.cpp](https://raw.githubusercontent.com/FRRouting/frr/frr-10.7.1/lib/northbound_grpc.cpp)). |
| [GoBGP 4.9.0](https://raw.githubusercontent.com/osrg/gobgp/v4.9.0/pkg/server/server.go) | Atomic session counters are read inside `mgmtOperation` under the exclusive lock, without using the caller's context. |
| [OpenBGPD 9.2](https://raw.githubusercontent.com/openbgpd-portable/openbgpd-openbsd/openbgpd-9.2/src/usr.sbin/bgpd/control.c) | `show neighbor` round-trips through the RDE loop with no priority. |
| [Arista EOS](https://www.arista.com/assets/data/pdf/EOSWhitepaper.pdf) | Agents publish state, including counters, to Sysdb for other readers. |
| [SONiC](https://github.com/sonic-net/sonic-sairedis/blob/202411/syncd/FlexCounter.cpp) | Polled `COUNTERS_DB` cache, 1 s default port interval; the rejected cache model. |
| [Juniper JTI](https://www.juniper.net/documentation/us/en/software/junos/interfaces-telemetry/topics/concept/junos-telemetry-interface-reporting-intervals-guidelines.html) | Periodic export at intervals in multiples of 2 s. |
| [Prometheus client_golang 1.23.2](https://github.com/prometheus/client_golang/blob/v1.23.2/prometheus/counter.go) | Atomic counters read at collection time; [rust-prometheus 0.14](https://github.com/tikv/rust-prometheus/tree/v0.14.0/src) takes read locks during collection. |
| [Envoy 1.35](https://github.com/envoyproxy/envoy/blob/v1.35.0/source/docs/stats.md) | One shared atomic per counter; scopes keyed by unique incrementing IDs. |
| [Linux 6.12 `u64_stats_sync`](https://elixir.bootlin.com/linux/v6.12/source/include/linux/u64_stats_sync.h) | No cross-counter consistency; [seqlock readers can spin while a writer is preempted](https://docs.kernel.org/locking/seqlock.html). |
| [arc-swap 1.9.2](https://docs.rs/arc-swap/1.9.2/arc_swap/docs/performance/index.html) | Lock-free readers and writers; [load related fields once](https://docs.rs/arc-swap/1.9.2/arc_swap/docs/patterns/index.html). |
| [Tokio 1.53.1 `watch`](https://docs.rs/tokio/1.53.1/tokio/sync/watch/struct.Receiver.html#method.borrow) | Outstanding borrows can block the producer. |
| [Rust Atomics and Locks](https://marabos.nl/atomics/memory-ordering.html) | Each atomic has a total modification order; separately updated `Relaxed` counters can be mutually inconsistent. |

Every surveyed daemon reads counters on the owner thread, through its queue or
under its lock, even when the counters are atomics. Reading published atomics
directly applies the Prometheus-client and Envoy model to a gRPC surface.
