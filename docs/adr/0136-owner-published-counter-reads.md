# ADR-0136: Owner-Published Counter Reads

**Status:** Proposed
**Date:** 2026-09-25

This record proposes that the owners of policy hit counters publish the set
of counter instances they have installed, and that `GetPolicyStats` reads
those instances directly instead of sending a message to the RIB or
peer-manager actor. It extends [ADR-0132](0132-operator-read-path.md) and
[ADR-0133](0133-installed-import-counter-reads.md) and does not reverse
them: reads keep their deadlines and get no priority, and route work never
waits for a read. Neighbor counters, readiness, route listings and explain
stay on their current paths. Nothing here is implemented yet.

## Context

### The counters are already live atomics

Every installed policy chain owns one
[`PolicyHitCounters`](0096-policy-language.md) instance: one `AtomicU64`
per term, plus evaluation and error counts. The owning evaluator increments
these with `Relaxed` `fetch_add` on the route path, and the stats surface
reads them with `Relaxed` loads. The last error sits behind a mutex on the
cold path, and readers use `try_lock` on it. The same counter types serve
both directions:

- **Import.** The chain belongs to the session task that evaluates UPDATEs.
  Since ADR-0133, the session publishes a descriptor for its installed
  import chain through a `watch` channel. The descriptor holds the session
  identity, the install generation, the term labels and the counter handle.
- **Export.** The chain belongs to the RIB manager, in its per-peer export
  map and its global fallback slot. Members of an update group
  ([ADR-0098](0098-update-groups.md)) share the group's single chain
  instance, so every member's row reports the same counters. An ungrouped
  peer gets a new instance, starting from zero, each time its session
  registers with the RIB. Export rows report `policy_generation = 0`
  ("untracked"), so that reset cannot be seen.

The counter *values* are therefore shared memory already. What stays
actor-bound is the **roster**: the answer to "which counter instance is
installed for which peer right now". A statistics read today must ask an
actor for that answer.

### How a fleet read spends its time today

`GetPolicyStats` runs up to four stages under one absolute two-second
deadline: peer validation, export, import and datasets.

- **Peer validation** (single-peer requests only) asks the peer manager's
  operator lane whether the address is a managed peer.
- **Export** sends `ExportPolicyTermHits` to the RIB on its summary lane.
  The RIB answers between work units. During synchronous replacement it
  answers from a temporary frozen projection. During a grouped transition's
  `CommitMembers` batches ([ADR-0105](0105-grouped-export-policy-transition.md))
  it is fenced. The work in the reply is small: walk the export map and
  load atomics. The wait is queueing behind route work.
- **Import** sends `QueryImportPolicyTermHits` to the peer manager's operator
  lane. The manager clones one publication receiver per peer and spawns a
  collector. The collector reads up to 64 publications concurrently and
  calls `consume_budget()` once per peer, per policy and per term. Tokio's
  cooperative budget is 128 units per task poll. At the flagship shape
  (1,000 peers, one import policy of two terms each) a fleet read therefore
  spends about 4,000 units and is forced to yield about 31 times. Each yield
  puts the collector at the back of a run queue shared by 1,000 session
  tasks. During a reload's re-advertisement burst, every one of those tasks
  is busy.
- **Datasets** sends `QueryPolicyDatasets` to the same operator lane. Dataset
  status itself is already published through `ArcSwap` in each
  `DatasetHandle`, but the list of bound handles is actor state.

The v0.72.0 route-server flagship soak
([receipt](../soaks/soak-rs-flagship-24h-2026-09-24.md)) failed its
management gate on one of 17,556 `policy stats --direction both` calls. The
call landed in a reload's post-commit window, while 1,000 sessions were
re-sending. Its audit summary reads:

```text
stage=export elapsed_ms=597 budget_ms=1999 rpc_elapsed_ms=598 code=Ok;
stage=import elapsed_ms=1471 budget_ms=1401 rpc_elapsed_ms=2070 code=DeadlineExceeded
```

The export half is time spent waiting for the RIB actor. The import half
reads counters that were already atomics, so its delay comes from the path
around them. The handler also replied 70 ms after the deadline had passed:
the collector checks the deadline only between cooperative turns, so the
handler cannot run until the runtime schedules it again. That residual is
runtime scheduling, not actor queueing, and it matters for what this
design can promise (see [Failure and deadline semantics](#failure-and-deadline-semantics)).

The same soak shape passed on v0.71.0 with a slowest read of 1,969 ms. On
the isolated-generator control cell, the daemon has its own cores and all
24 calls completed in 301–492 ms
([receipt](../perf/artifacts/installed-import-counters-isolated-2026-09-13/README.md)).
The shared soak host is not the release cell. The failure is still
self-inflicted in a precise sense: neither half of the wait buys any
consistency the counters need.

### Relation to earlier decisions

ADR-0132 made persistent publication conditional. It asked for a residual
failure that bounded admission and projection could not address, and for a
follow-up that settles five contracts: observation semantics, generation
and joins, failure and lifecycle, bounded work and retention, and unchanged
live gates. ADR-0133 then moved the import numbers to session-owned
publication. It kept the peer-manager roster hop and the collector.

The pre-v1 architecture review parked a persistent counter publication
until after v1. Its reopen condition was a retained failure on the isolated
release cell. That condition has not been met; the v0.72.0 failure is on
the shared soak host. The project now chooses to make the change before v1
anyway, because:

- the remaining import delay is caused by the read path itself;
- the export delay is pure queueing for a few atomic loads;
- the change can be scoped to counters, where "live" has a precise and
  cheap meaning.

This record makes that decision for counters only. It does not reopen the
separate-read-owner, process-separation or neighbor-summary candidates.

## Decision drivers

1. **Operator reads are not first-class.** No read priority, no read-driven
   credit or throttling, no dedicated read runtime. Route work must not wait
   for a read, not even briefly, including behind a reader's lock.
2. **Bounded answer or bounded failure.** The existing absolute two-second
   deadline, all-or-error responses and cancellation stay.
3. **Success means a live observation.** A successful counter read reports
   values loaded during that request from the instance its owner currently
   publishes as installed. It never serves a copy made earlier by a timer or
   by another request.
4. **Stale entries must be impossible by construction.** A roster must not
   become a second collection whose entries can outlive their owner. That is
   the stale-collection-entry class, and it recurs in this codebase whenever
   a map has more than one writer.
5. **Keep it boring.** Use primitives already in the workspace (`arc-swap`
   1.9.2, `tokio::sync::watch`, `std` atomics). Add no new crate. Do not
   split large modules for size.
6. **Cheap shape-telegraphing over contract machinery.** Where a rule can be
   enforced by Rust privacy or ownership, enforce it there, not with a
   checker script.

## Options considered

### A — Status quo with admission tuning

Tune the existing path: raise the collector's concurrency cap, add
admission at more waits, or lengthen the budget.

A co-pinned comparison already raised the cap from 64 to 1,000 and still
failed. A longer deadline was declined when the release
cell was chosen. Admission tuning cannot remove the export stage's wait for
the RIB actor, or the actor hop itself. **Rejected.**

### B — Yield-chunking only

Keep both actor hops, but have the collector capture numbers in one pass
without per-term cooperative yields.

This removes most of the roughly 31 forced trips through the run queue. It
still needs the peer-manager hop and its fences, and the export stage still
waits for the RIB. It fixes the part of the import time that the collector
adds, and nothing else. **Rejected as a complete answer.** Its useful core,
a synchronous capture pass, is part of the selected read shape below.

### C — Direct roster reads for import only

The peer manager publishes its roster, and the handler reads the import
publications directly. This removes the hop, the collector and the forced
yields.

The export stage would still queue behind the RIB, and in the failing call
that was 597 ms of the budget. Peer validation and datasets would still
queue on the peer-manager lane. **Insufficient alone; it is one slice of the
selected design.**

### D — Owner-published counter rosters for both directions (selected)

Each owner publishes an immutable roster of the counter instances it has
installed, through one `ArcSwap` cell. The RIB owns the export roster. The
peer manager owns the import roster, together with the dataset bindings. A
read loads each roster once and reads the live atomics through it.

This option has two forms:

- **A registry with explicit register and deregister calls** at each
  lifecycle site. **Rejected.** Such a registry is a second map with
  independent writers, which is exactly the stale-entry class. The
  hand-maintained Prometheus per-peer reap list in `telemetry` shows the
  maintenance cost of this form.
- **A projection.** Each publication is rebuilt in full from the owner's
  authoritative map, at a single publication point that Rust privacy makes
  unavoidable. **Selected.** A projection cannot hold an entry that its
  source lacks, so it can differ from the source only in timing, never in
  content.

### E — Periodic snapshot cache

A timer copies the counter values into a published table, and reads serve
the table. SONiC works this way: syncd's flex-counter thread polls into
`COUNTERS_DB`, with a default port interval of 1 s, and `show` reads the
database. **Rejected.**

- **It breaks driver 3.** A successful read would report values up to one
  period old and be indistinguishable from a live read. That is the "stale
  cache posing as success" risk that ADR-0132 and ADR-0133 already
  identified.
- **It spends owner time on reads that may never happen.** Owners copy
  numbers every period whether or not anyone reads them.
- **It still needs the roster.** It adds a freshness contract, a way to
  detect a stopped publisher, and retention of the copies on top of it.

Since the values are already atomics, a cache has only costs and no benefit
here.

### F — Serve counters as Prometheus series

Expose per-peer, per-term hit counts through the existing `/metrics`
registry, which is already read at scrape time without an actor hop.
**Rejected.**

- **Cardinality.** Peers × terms breaks the Prometheus instrumentation
  guidance on label cardinality.
- **Scrape locks.** The `prometheus` 0.14 `MetricVec` takes a read lock on
  its children map for every scrape. Creating or deleting a series takes
  the write lock on the same map.
- **Hand-maintained cleanup.** Removing series depends on the manual reap
  list.
- **It does not serve the gRPC contract.** `GetPolicyStats` still needs a
  roster.

The internal lesson is still useful: reading owner-maintained atomics at
read time is already how this daemon serves `/metrics`.

## Decision

Select option D in its projection form.

### Scope: which reads move

| Read | Moves? | Reason |
|---|---|---|
| `GetPolicyStats` export stage | yes | the values are already atomics; the wait was for the roster |
| `GetPolicyStats` import stage | yes | the values are already session-published; the peer-manager hop and collector add the delay |
| `GetPolicyStats` peer validation | yes | "is this a managed peer?" is a roster lookup |
| `GetPolicyStats` datasets stage | yes | the binding list is a roster, and dataset status is already `ArcSwap`-published |
| `ListNeighbors`, `GetNeighborState`, gNMI neighbor tree | no | see [Neighbor counters](#neighbor-counters-are-not-selected) |
| `GetHealth`, `/readyz` | no | they exist to prove live actor progress; a published value cannot do that |
| `policy explain`, `rib received --rejected` | no | these read session-local decision caches and reject stores, not counters |
| `TestPolicy`, route listings, explain, lookups | no | they read RIB tables, not counters; pages stay version-fenced |
| periodic BMP statistics | no | already bounded independent inputs; different counters |
| direct session `QueryImportPolicyTermHits` command | no change | it remains a session-queue read for its existing callers |
| `/metrics` scrape | no change | already reads atomics at scrape time |

Once its read moves, `GetPolicyStats` no longer sends any message to the
RIB manager or the peer manager. It still reads session publications, and
it still depends on runtime scheduling for its own task.

### Data model

**Counter instances describe themselves.** A counter instance carries its
immutable term labels and a process-wide **instance id** together with its
atomics. The id is taken from one monotonic `AtomicU64` sequence starting
at 1 when the instance is created. Creating an instance already requires
the compiled chain, which holds the labels. ADR-0133's import descriptor
then no longer needs its own copy of the labels. Its roster entry needs
only the counter handle and the session's install generation.

The instance id is the counter-reset identity. The same id means the same
monotonic counters. A different id means the numbers restarted. Unique ids
guard against a new object being mistaken for a deleted one; Envoy keys its
stat scopes the same way.

**Export roster (owner: RIB manager).** The roster is an immutable value:

- a version;
- a map from peer to either an installed instance handle or "explicitly
  disabled";
- the optional global fallback instance handle.

It is exactly the projection of the RIB's per-peer export map and global
slot. Update-group members point to their group's shared instance. The RIB
publishes it through an `ArcSwap` cell that the API service holds. For a
peer filter, the roster applies the RIB's existing lookup rule: the
per-peer entry if one exists, otherwise the global fallback.

**Import roster (owner: peer manager).** The roster is an immutable value:

- a version;
- a map from managed peer to its current session's publication receiver
  (the ADR-0133 `watch` receiver) and session identity;
- an address index used for peer validation;
- the bound dataset handles, with their configured paths.

It is exactly the projection of the peer manager's peer table and dataset
bindings.

**Why `ArcSwap` and not `watch` for the rosters.** A `watch` borrow holds a
read lock, and Tokio documents that long borrows can block the producer. If
the operating system preempts a reader's thread while it holds that lock,
the RIB or peer manager could wait on a read — the tail case that driver 1
forbids. `arc-swap` readers and writers are both lock-free, so a descheduled
reader cannot block a publisher. The crate is already a workspace dependency,
used by the API and policy crates. Import descriptors keep their existing
`watch` channel, which needs its pending and closed states. Readers still
hold that borrow only long enough to clone one `Arc`, as today.

**How a handler reads.** For each roster it needs, the handler:

1. takes one `load_full()`, which gives an owned `Arc` held across any
   await, not a `Guard`;
2. captures every row in a single synchronous pass of `Relaxed` loads into
   an owned buffer;
3. renders the response after the capture.

For import, only publications that are still Pending are awaited, under
the original deadline. Rendering may yield. Capture does not yield, so the
window in which the numbers are sampled stays as short as the loop and has
no forced trips through the run queue. At 1,000 peers with two terms each,
capture is on the order of microseconds. That is well inside the rule of
thumb a Tokio maintainer gives for async code, "no more than 10 to 100
microseconds between each `.await`"
([Ryhl, "Async: What is blocking?"](https://ryhl.io/blog/async-what-is-blocking/)).
The ceiling is linear in rows. The budget is under
[Hot-path and publication cost](#hot-path-and-publication-cost).

### What "live" means

A successful response has these properties:

- **Values are loaded during this request.** Every numeric value is a
  `Relaxed` load performed after the request started, from the instance the
  owner's roster designated when this request loaded it. No value is copied
  from an earlier request or a timer.
- **Each instance's counters never go backwards across reads.** Each atomic
  has a single modification order. Two sequential requests are ordered by
  the reply and the next request, so a later read of the same instance
  never sees a smaller value.
- **Instance selection reflects the owner's last completed operation.**
  Import publications change at each session's install, before
  acknowledgement (ADR-0133). The import roster changes at each peer-table
  mutation. The export roster changes when a RIB operation that changed an
  installed chain completes, never partway through one (see below). During
  a long synchronous RIB operation, a read reports the live counters of the
  instances installed before that operation. Today's temporary projection
  serves frozen numeric copies in the same interval, so this is strictly
  fresher.
- **These are not guaranteed.** Consistency within a row (evaluations
  compared with the sum of term hits, or one term compared with another),
  across rows, or between the export and import rosters. A response is not
  an atomic fleet snapshot, as the stable contract already says. Individual
  counters are consistent; groups of counters are not. The same holds for
  every live-atomic design surveyed below.
- **Success does not imply owner responsiveness.** A successful read does
  not show that the RIB manager, the peer manager or a session is making
  progress. A stalled RIB evaluates no routes, so its counters stay still,
  and they are reported truthfully as unchanged. Readiness and health keep
  checking live progress. This extends ADR-0133's "counter availability,
  not session responsiveness" to both directions.
- **A stopped publisher is visible, not frozen.** Each roster cell is
  created in the open state. A guard in the owner closes the cell when the
  owner is dropped, whether it exits normally or unwinds. A read of a
  closed roster returns `UNAVAILABLE`; a stopped RIB is not reported as
  success with frozen numbers. The daemon already shuts down when the RIB
  task exits. This rule covers the interval before that, and embedders.

### Generation semantics

The design has three identities and one deliberate absence:

1. **Row instance identity.** Import rows keep their session-local install
   generation. It starts at 0 and advances on every install, including a
   content-equal reinstall. Export rows now report the export instance id,
   which is nonzero, where they reported 0 before.
2. **Roster version.** Each publisher's version is monotonic. A read loads
   each roster exactly once, so every row from one owner comes from one
   published version.
3. **Owner operation boundary.** The RIB republishes the export roster only
   at the end of an actor unit that changed an installed chain. It never
   republishes inside a unit. For a grouped clean transition, it
   republishes only at the terminal `CommitMembers` batch. A reader
   therefore sees the whole cohort on its old instances, or the whole
   cohort on its new ones, and never a mix.
4. **No fleet policy generation.** A response does not promise that every
   row reflects one reload. Sessions install import chains one at a time,
   and they really do evaluate routes under a mix of chains while a reload
   is in progress. Per-peer export replacements complete one peer at a
   time. A single fleet-wide swap would require delaying publication until
   every session acknowledged. That would misreport sessions already
   evaluating under their new chain, or claim a generation that is not
   installed. Rows carry their own identities, so a consumer can see the
   mix.

| Transition | Import rows | Export rows |
|---|---|---|
| SIGHUP or API forward policy apply | each session republishes at its install; generations advance per session and may differ within a response | a per-peer replacement republishes when it completes; a grouped clean transition republishes once at its terminal commit |
| Content-equal reapply | session generation advances (unchanged from ADR-0133) | where the RIB skips an equal replacement, the id is unchanged |
| Rejected-reload rollback | restored sessions republish with an advanced generation; a failed restore shows the chain actually installed | authoritative restore republishes when it completes; a partial restore shows the chains actually installed, never a complete prior generation |
| Session flap (task retained) | chain and generation retained | the RIB drops the peer's entry on session down, and the row disappears; at session up an ungrouped peer installs a new instance, and a grouped peer joins its group's instance; the id changes when the counters really restarted |
| Update-group regroup | not applicable | the member's entry moves to the destination group's instance and the id changes; an emptied group's instance is reclaimed when the last roster or reader drops it |
| Dataset refresh | not applicable | not applicable; dataset status stays per handle (`ArcSwap`), and binding changes republish the import roster |

The export and import rosters are loaded independently. A `both` response
can therefore straddle an export commit and a session install. That is the
mixed observation contract ADR-0132 allowed for, stated explicitly here.

### Lifecycle: how stale entries become impossible

A roster is never edited in place. It is rebuilt in full from the owner's
authoritative state at a publication point, and Rust privacy prevents
bypassing that point:

- **Peer manager.** The peer table becomes a small type in its own module.
  Its fields are private, and so is the current-session handle inside each
  managed peer. Its only mutating methods are `insert`, `remove`, `drain`
  and `replace_handle`, and each one republishes the import roster before
  returning. A module outside the table cannot swap a handle without
  publishing, because the compiler rejects the write. Changes to the bound
  dataset handles go through one setter that republishes as well. The
  existing wholesale configuration replacements route through that setter.

  This adds one small type. It does not split the peer-manager module for
  size.
- **RIB manager.** The per-peer export map and global slot move behind a
  small type whose mutable accessors advance a change version. The run loop
  republishes when the version differs from the last published one. It
  checks at one place: after a completed top-level unit, and not while a
  clean transition is between `CommitMembers` batches. Pre-commit phases do
  not change committed chains (ADR-0105).

These are the transitions the lifecycle must cover, and what each does:

| Transition | Effect on the rosters |
|---|---|
| Session teardown, task retained | none; the import publication persists, and the export entry follows RIB peer down and up as above |
| Session task exit (shutdown, replacement, notification respawn) | the old receiver closes; until the table replaces or removes it, a fleet read fails `UNAVAILABLE`, as today |
| Inbound collision replacement, notification respawn | `replace_handle` republishes with the new handle in the same actor step |
| Peer deletion | `remove` republishes; readers holding the previous roster finish with its entries, as they do today with a snapshotted target list |
| Dynamic peer accept or expiry | `insert` or `remove` republishes |
| Update-group regroup, join or leave | the export version advances; published at the end of the unit |
| Policy reload, rollback | as in the generation table |
| Daemon shutdown | `drain` republishes an empty roster, and dropping the owner closes the cell |

Readers can keep retired rosters and instances alive. Each in-flight
request holds at most one roster per owner and drops it when it finishes,
fails or is cancelled. The number of retained rosters is therefore bounded
by the number of in-flight statistics requests. A retired roster is freed
wherever its last reference drops. At 1,000 peers that is about a thousand
`Arc` decrements. When the dropped roster held the last reference to an
instance, dropping that instance costs the same as it does today when a
chain is replaced.

### Hot-path and publication cost

The increment path does not change. Route evaluation already performs one
`Relaxed` `fetch_add` per matched term, plus one per evaluation. Each
instance has one writer task at a time: a session for import, the RIB for
export. An operator read every few seconds adds cache-line traffic that is
negligible next to continuous contention. Per-core or sharded counters are
not selected: there is no multi-writer contention to remove, and an exact
read would have to walk every shard.

This design adds four costs:

- **Eager instance creation.** Creating counters for an export chain at
  install compiles the chain there, instead of at its first evaluation or
  first statistics read. Today a statistics read can trigger that
  compilation inside the RIB actor. ADR-0133 accepted the same move for
  import.
- **Labels per instance.** Import labels move into the instance instead of
  being copied into the descriptor. Export pays for labels once per chain
  instance, which means once per update group, not once per member.
- **Roster rebuild per publication.** The rebuild is O(peers): a new map of
  `Arc` handles, once per completed chain-changing operation or peer-table
  mutation. A serial reload of 1,000 ungrouped peers republishes 1,000
  times, which is about a million `Arc` clones for the whole reload.
- **Read capture.** O(rows × terms) loads per request, paid by the reader.

Measurement plan. Run each before and after on one quiet host, following
the existing Criterion workflow:

- The existing hot-path groups must stay within noise:
  - `policy_chain_eval/*` and `policy_predicate_eval/*` (`crates/policy`);
  - `export_policy_eval/*`, `rib_pipeline` and `route_churn`
    (`crates/rib`);
  - `fanout` (`crates/transport`).
- New microbenchmarks with proposed budgets:
  - roster rebuild and publish at 1,000 and 10,000 peers: budget ≤ 100 µs
    at 1,000;
  - read capture at 1,000 peers × two terms, and at 1,000 peers × 32 terms
    with 256-byte labels: budget ≤ 1 ms for the first.
- `just gate-contract` for bench smoke.
- The 1,000-peer reload's
  `bgp_rib_policy_transition_last_duration_milliseconds` and settlement
  times, compared before and after, to show that republishing does not
  lengthen a reload.
- Allocation accounting for instance creation, extending ADR-0133's
  reproducible probe to export chains.

If rebuild cost exceeds its budget at a real shape, the next step is to
batch publication per reload operation. It is not to switch to incremental
editing, which would reintroduce the stale-entry class.

### Failure and deadline semantics

The shared absolute two-second deadline, the stage names in the audit
summary, all-or-error responses, deterministic ordering and cancellation
all stay. After migration, a request can still fail in these ways:

- **The handler task is not scheduled soon enough.** The v0.72.0 handler
  replied 70 ms late. The same can happen here when the runtime is
  saturated: while the task waits to be polled, while it renders, and while
  the response is encoded and written. This is CPU contention, not
  queueing, and fixing it would mean giving reads priority.
- **An import publication is still Pending.** A session task that has not
  finished constructing is awaited under the deadline (unchanged).
- **The cold error lock is busy.** The read yields and retries under the
  deadline (unchanged). The dataset handle's `last_error` moves from a
  blocking `lock()` to the same `try_lock` shape, so a reader cannot park a
  runtime worker on it.
- **`UNAVAILABLE`.** A selected session's publication has closed, as today
  (the opt-in partial-result contract stays deferred). Counters are
  poisoned or their shape does not match. A roster cell is closed.
- **`NOT_FOUND`** for an unmanaged peer, answered from the import roster;
  **`FAILED_PRECONDITION`** on a listener built without a roster, as today
  for a listener without the RIB.

The following no longer cause a request to fail:

- waiting in the RIB mailbox or summary lane;
- the `CommitMembers` fence;
- peer-manager operator-lane admission and its fences;
- the collector's concurrency cap and its forced cooperative yields.

Of the audit summary's sub-stage fields, those that measure an actor
admission wait are removed with that wait. They do not report a synthetic
zero, because a zero would claim a measurement.

### Neighbor counters are not selected

`ListNeighbors` rows combine several kinds of state:

- session-owned counters, which are plain fields in the session task:
  UPDATE and NOTIFICATION totals, flap count, accepted-prefix counts, and
  import permit and deny counts;
- session state: FSM state, negotiated parameters, and a TCP-AO socket
  inspection taken at query time;
- RIB-computed views: advertised counts, export permit and deny counts,
  and outbound limit state.

Publishing only the counters would remove no wait, because the row still
needs a live session query for the rest. An unavailable observation already
has an explicit `stale` meaning in the v1 contract.

Two more obstacles stand in the way:

- An advertised count is not a stored counter. For update-group members it
  is derived from the shared group table. Keeping a per-member atomic would
  add work for every route change for every member, which is a real cost on
  the hot path.
- The isolated release cell's neighbor reads met the two-second criterion.

**Excluded.** Reopen this only for a retained failure on the isolated cell
that is attributed to collecting session state. A follow-up would then
decide on a session-published state descriptor and cover the RIB-view
fields separately.

### Migration slices

Each slice is its own change, ships independently, and has its own proof.
Slices 2 and 3 do not depend on each other. Slice 3 removes the larger
share of the observed failure.

0. **Baseline.** On current main, before slice 1, record the audit's
   stage and sub-stage timing and the isolated-cell measurement below.
1. **Self-describing counter instances.** Move labels and the instance id
   into the counter instance, and drop the copy in ADR-0133's import
   descriptor. Create export counters at install. No behavior an operator
   can see changes. Proof: the hot-path Criterion groups above, and the
   allocation probe.
2. **Export roster.** The RIB publishes the export roster, and the export
   stage reads it. Export rows report the instance id. Delete
   `ExportPolicyTermHits` from the summary lane and its part of the
   temporary projection; the projection keeps neighbor snapshots. Delete
   `QueryExportPolicyTermHits` if nothing else uses it. Update the proto
   comment, the API reference and the v1 contract wording.
3. **Import roster.** The peer manager publishes the import roster with
   the dataset bindings. Peer validation, import and datasets read it.
   Delete the operator-lane `QueryImportPolicyTermHits`, `HasPeerAddress`
   (if unused elsewhere) and `QueryPolicyDatasets` queries, the collector
   and its concurrency cap. Remove their wait-site matrix rows, noting each
   removal. Move the dataset error read to `try_lock`.
4. **Qualification and closeout.** Run the isolated-cell measurement and
   the next flagship soak with the management gate unchanged. Update the
   known-issue entry to the qualified scope. Move this record to Accepted
   with evidence links.

### Test and proof plan

Every regression below must fail when its slice's change is reverted once,
with the failing output retained. A test that cannot fail proves nothing.

**The central regressions.**

- A `GetPolicyStats` request with export direction succeeds within budget
  while a real RIB manager is held so that it cannot serve the request.
  Two holds are needed: its mailbox full and never polled, and a unit
  parked mid-`CommitMembers`. Before slice 2 both return
  `DEADLINE_EXCEEDED`.
- A `GetPolicyStats` request with direction `both` and datasets succeeds
  while the peer manager's operator and ordinary lanes are never polled.
  Before slice 3 it returns `DEADLINE_EXCEEDED`.

**Stale-entry regressions.** Each of these drives the real owner:

- peer deletion;
- notification respawn and inbound collision replacement, where the read
  must succeed on the new handle and must not return `SessionGone`;
- dynamic accept and expiry;
- update-group regroup and group emptying;
- policy reload and a partial rollback;
- daemon shutdown.

After each one, the published roster equals the projection of the owner's
current state. A retired instance's `Weak` handle no longer upgrades once
the last reader drops. In test builds, the invariant "published roster
equals projection" is checked after every RIB unit and every peer-table
method. The red proof removes one version advance or one republication, and
the invariant must fail.

**Semantic regressions.**

- **No cache.** Increment a counter with no owner operation in between;
  the next read must see the new value.
- **Monotonic.** Across sequential reads of one instance, values never
  decrease.
- **Cohort atomicity.** Reads between `CommitMembers` batches see only
  pre-commit instances. Negative control: publishing after each batch must
  fail this test.
- **Closed publisher.** Dropping the RIB manager makes the export stage
  return `UNAVAILABLE`. Negative control: without the closing guard, the
  read returns frozen values as success, and the test must fail.
- **Reader never blocks a publisher.** A reader holding a loaded roster
  across an await does not delay republication.

**Latency flat through reloads.** Use the isolated release cell:

- 1,000 peers with 400 IPv4 prefixes each;
- the daemon on its own cores and the generator on separate cores;
- 12 reloads in both directions;
- probes in the −220 to 0 ms commit-relative band, with a floor of six
  complete pairs;
- the external two-second criterion.

Add one quiescent `GetPolicyStats` probe per reload, well after settlement,
as the comparison population. Record before (slice 0) and after, with the
same binaries and placement except for the change. Proposed predeclared
acceptance:

- every call completes within the unchanged external criterion;
- all 1,000 import and 1,000 export rows are present;
- the in-band calls' backend time (the summed stage `elapsed_ms`) has a
  maximum of at most twice the quiescent calls' median, plus 50 ms.

Retain every call, offset and audit line. A co-pinned run stays diagnostic
only.

**Soak.** The next flagship soak must pass its `management_failures` gate
with the gate unchanged. A soak covers only the tag it ran on.

## Consequences

**What the project can claim once the slices are delivered and qualified:**

- `GetPolicyStats` reads live counters that their owners published. It
  does not queue behind the RIB manager or the peer manager.
- It has a bounded answer or a bounded failure within its deadline.
- Its remaining latency depends on runtime scheduling and response size,
  not on route work in the actors.

**What the project must not claim:**

- that reads never time out;
- an atomic fleet or per-row snapshot;
- actor-free neighbor reads;
- a latency figure beyond the receipts that measured it;
- a ranking against other daemons.

**Behavior changes an operator can see:**

- Export rows gain a nonzero `policy_generation`, the instance id, so
  export counter resets become visible.
- Export statistics succeed while the RIB is busy, fenced or stalled.
- A statistics success no longer implies that any actor is responsive.
  The v1 contract text changes from "not that the session command loop is
  responsive" to cover the RIB and peer manager too.

**Negative costs:**

- Two publication points to maintain.
- Chain compilation moves earlier, into install.
- An O(peers) rebuild per publication.
- During a long RIB operation, instance selection lags by the length of
  that operation, by design.

**Removed code:**

- the import collector and its cap;
- three peer-manager operator queries;
- the export summary query and its part of the temporary projection;
- the related wait-site matrix rows.

ADR-0132's selected admission, projection (for neighbor snapshots),
executor handoff and live readiness remain. ADR-0133's session-owned
import publication remains; only its label copy moves. The partial-result
option for fleet statistics under churn stays deferred with its existing
triggers.

### ADR-0132 publication conditions

1. **Observation semantics.** Settled in
   [What "live" means](#what-live-means). The publication triggers are the
   owner's operation boundaries, a stopped publisher closes its cell, and
   `stale` behavior does not become cached success.
2. **Generation and joins.** Settled in
   [Generation semantics](#generation-semantics). One load per roster;
   rows from different owners are explicitly mixed.
3. **Failure and lifecycle.** Settled in
   [Lifecycle](#lifecycle-how-stale-entries-become-impossible). A partial
   restore shows the actual installation, and incarnation identity comes
   from the session handle and its publication.
4. **Bounded work and retention.** Settled in
   [Hot-path and publication cost](#hot-path-and-publication-cost). Rebuild
   and reclamation run outside the increment path, and retention is bounded
   by in-flight reads.
5. **Unchanged live gates.** Readiness and health are unchanged. A
   bypassing read records no lane-wait sample, and it records no `unfenced`
   sample either.

## Prior art

These sources show how others store and read counters. None of them is a
latency measurement, and where a thread runs does not settle read latency.

- **BIRD 3.1.8.**
  - Channel import and export statistics are plain `u32` fields, incremented
    with `++` on the route path
    ([`nest/protocol.h`](https://gitlab.nic.cz/labs/bird/-/raw/v3.1.8/nest/protocol.h)
    lines 639–659;
    [`nest/rt-table.c`](https://gitlab.nic.cz/labs/bird/-/raw/v3.1.8/nest/rt-table.c)).
  - `show protocols all` runs in the main loop and enters the protocol's
    loop lock (`PROTO_LOCKED_FROM_MAIN`, `nest/protocol.h` lines 300–310;
    `birdloop_enter` in
    [`sysdep/unix/io-loop.c`](https://gitlab.nic.cz/labs/bird/-/raw/v3.1.8/sysdep/unix/io-loop.c)).
  - The read therefore waits for the protocol loop's current time-budgeted
    run, and it stalls that loop while it holds the lock.
  - Route export uses a lock-free journal with RCU readers instead
    ([`nest/rt-export.c`](https://gitlab.nic.cz/labs/bird/-/raw/v3.1.8/nest/rt-export.c)).
  - The design series explains the trade-off: direct access to another
    domain "blocks the appropriate loop"
    ([BIRD journey to threads, chapter 3](https://en.blog.nic.cz/2022/02/09/bird-journey-to-threads-chapter-3-parallel-execution-and-message-passing/)).
- **FRR 10.7.1.**
  - Peer message counters are `_Atomic`, because an I/O pthread writes them
    ([`bgpd/bgpd.h`](https://raw.githubusercontent.com/FRRouting/frr/frr-10.7.1/bgpd/bgpd.h)
    lines 2029–2041).
  - `show bgp neighbors` still reads them on the main thread
    ([`bgpd/bgp_vty.c`](https://raw.githubusercontent.com/FRRouting/frr/frr-10.7.1/bgpd/bgp_vty.c)).
  - Route-map and prefix-list hit counters are plain integers on the main
    thread. A route-map clear records a baseline instead of zeroing the
    counter
    ([`lib/routemap.c`](https://raw.githubusercontent.com/FRRouting/frr/frr-10.7.1/lib/routemap.c)).
  - The gRPC northbound runs on its own pthread, but it hands each request
    to the main thread and waits without a timeout
    ([`lib/northbound_grpc.cpp`](https://raw.githubusercontent.com/FRRouting/frr/frr-10.7.1/lib/northbound_grpc.cpp)
    lines 154–165).
- **GoBGP 4.9.0.**
  - Session counters use `atomic.AddUint64`
    ([`pkg/server/fsm.go`](https://raw.githubusercontent.com/osrg/gobgp/v4.9.0/pkg/server/fsm.go)).
  - `ListPeer` still reads them inside `mgmtOperation`, which queues a
    closure on one management channel and runs it under the exclusive side
    of the shared lock. It does not consult the caller's context
    ([`pkg/server/server.go`](https://raw.githubusercontent.com/osrg/gobgp/v4.9.0/pkg/server/server.go)
    lines 270–283 and 395–440).
  - No policy hit counters were found.
- **OpenBGPD 9.2.**
  - Message statistics live in the session engine and prefix statistics in
    the RDE, as plain fields in single-threaded processes.
  - `bgpctl show neighbor` round-trips through the RDE's control pipe,
    which is drained in the same poll loop as route traffic
    ([`control.c`](https://raw.githubusercontent.com/openbgpd-portable/openbgpd-openbsd/openbgpd-9.2/src/usr.sbin/bgpd/control.c),
    [`rde.c`](https://raw.githubusercontent.com/openbgpd-portable/openbgpd-openbsd/openbgpd-9.2/src/usr.sbin/bgpd/rde.c)).
  - Large dumps are time-sliced (10 ms per pass) with XON/XOFF credit
    ([`rde_rib.c`](https://raw.githubusercontent.com/openbgpd-portable/openbgpd-openbsd/openbgpd-9.2/src/usr.sbin/bgpd/rde_rib.c)).
- **Arista EOS.**
  - Agents publish state into Sysdb, which the EOS white paper says holds
    "all internal state, including low-level counters". Other agents read
    subscribed views instead of messaging the owner
    ([EOS white paper](https://www.arista.com/assets/data/pdf/EOSWhitepaper.pdf);
    [EosSdk: Understanding EOS and Sysdb](https://github.com/aristanetworks/EosSdk/wiki/Understanding-EOS-and-Sysdb)).
  - This is precedent for owner publication, through replicated state
    rather than shared atomics.
- **SONiC.**
  - Counters are polled into `COUNTERS_DB` by syncd's flex-counter thread
    ([`FlexCounter.cpp`](https://github.com/sonic-net/sonic-sairedis/blob/202411/syncd/FlexCounter.cpp)).
    The default port interval is 1 s, and the configurable range is
    100–30,000 ms
    ([`portsorch.cpp`](https://github.com/sonic-net/sonic-swss/blob/202411/orchagent/portsorch.cpp);
    [`counterpoll`](https://github.com/sonic-net/sonic-utilities/blob/202411/counterpoll/main.py)).
  - `show interfaces counters` reads the database and never syncd
    ([`portstat.py`](https://github.com/sonic-net/sonic-utilities/blob/202411/utilities_common/portstat.py)).
  - This is the periodic cache of option E: readers are decoupled from the
    owner, but values can be up to one interval old.
- **Juniper JTI.**
  - Native sensors export from the data plane at a configured interval, in
    multiples of 2 s
    ([overview](https://www.juniper.net/documentation/us/en/software/junos/interfaces-telemetry/topics/concept/junos-telemetry-interface-oveview.html);
    [reporting intervals](https://www.juniper.net/documentation/us/en/software/junos/interfaces-telemetry/topics/concept/junos-telemetry-interface-reporting-intervals-guidelines.html)).
  - This is periodic export, not a live read.
- **Prometheus clients.**
  - `client_golang` counters are atomic words, read at collection time with
    no hop through the incrementing goroutine
    ([`counter.go` v1.23.2](https://github.com/prometheus/client_golang/blob/v1.23.2/prometheus/counter.go)).
  - The Rust `prometheus` 0.14 counters are `AtomicU64` with `Relaxed`
    increments, but `gather()` and `MetricVec` collection take read locks,
    which series creation and deletion contend for
    ([rust-prometheus v0.14.0](https://github.com/tikv/rust-prometheus/tree/v0.14.0/src)).
  - Counters reset only by restarting, and `rate()` treats a decrease as a
    reset ([metric types](https://prometheus.io/docs/concepts/metric_types/);
    [functions](https://prometheus.io/docs/prometheus/latest/querying/functions/)).
  - Label cardinality should stay small
    ([instrumentation](https://prometheus.io/docs/practices/instrumentation/)).
- **Envoy 1.35.**
  - Each counter is one shared `std::atomic<uint64_t>` that every worker
    increments. Thread-local caches hold pointers, not per-worker values,
    and only sink export is periodic
    ([`allocator_impl.cc`](https://github.com/envoyproxy/envoy/blob/v1.35.0/source/common/stats/allocator_impl.cc)).
  - Scopes are owned by their callers, the store keeps weak references,
    and scope cache keys use a unique incrementing ID so that a reused
    address does not alias a deleted scope
    ([`stats.md`](https://github.com/envoyproxy/envoy/blob/v1.35.0/source/docs/stats.md)).
- **Linux kernel 6.12.**
  - `percpu_counter_read` is approximate, and an exact sum takes a lock and
    walks every CPU
    ([`percpu_counter.h`](https://elixir.bootlin.com/linux/v6.12/source/include/linux/percpu_counter.h)).
  - `u64_stats_sync` exists for tearing on 32-bit hosts, and it gives no
    consistency across counters
    ([`u64_stats_sync.h`](https://elixir.bootlin.com/linux/v6.12/source/include/linux/u64_stats_sync.h)).
  - Seqlock readers can spin while a writer is preempted
    ([seqlock](https://docs.kernel.org/locking/seqlock.html)).
  - RCU readers see "either the old or the new version"
    ([What is RCU](https://docs.kernel.org/RCU/whatisRCU.html)).
- **arc-swap 1.9.2.**
  - Readers are lock-free, and writers are lock-free
    ([performance](https://docs.rs/arc-swap/1.9.2/arc_swap/docs/performance/index.html)).
  - Guards are not for holding across async yield points
    ([limitations](https://docs.rs/arc-swap/1.9.2/arc_swap/docs/limitations/index.html)).
  - Related fields should come from exactly one load
    ([patterns](https://docs.rs/arc-swap/1.9.2/arc_swap/docs/patterns/index.html)).
- **Tokio 1.53.1.**
  - `watch` borrows hold a read lock that can block the producer
    ([`Receiver::borrow`](https://docs.rs/tokio/1.53.1/tokio/sync/watch/struct.Receiver.html#method.borrow)).
  - The cooperative budget forces a yield after 128 units per poll
    ([`task::coop`](https://docs.rs/tokio/1.53.1/tokio/task/coop/index.html)).
- **Relaxed atomics.**
  - Each atomic has a total modification order, so one observer never sees
    a single counter go backwards.
  - Separately updated `Relaxed` counters can be mutually inconsistent
    ([Rust Atomics and Locks, ch. 2–3](https://marabos.nl/atomics/memory-ordering.html)).
  - Cache-line contention costs appear under continuous concurrent stores
    ([ch. 7](https://marabos.nl/atomics/hardware.html)).

In the sources surveyed, every daemon reads counters on the owning thread,
through its queue, or under its lock, even where the counters are atomics.
Reading published atomics directly is the Prometheus-client and Envoy model
applied to a gRPC surface. This observation describes those sources; it is
not a comparative claim about daemon behavior.
