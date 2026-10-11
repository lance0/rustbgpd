# ADR-0132: Operator Reads During Configuration Transactions

**Status:** Accepted
**Date:** 2026-09-12

This record selects typed admission for live operator reads, cooperative
RIB backlog draining, and temporary summaries during synchronous policy
replacement. The implementation is integrated; final phase coverage and
qualifying soak remain outstanding. Persistent publication remains conditional;
read deadlines and live readiness requirements remain unchanged.

## Context

The peer manager ([ADR-0017](0017-peer-manager-channel-based-ownership.md))
and RIB manager ([ADR-0013](0013-single-task-rib-manager.md)) own much of the
state used by operator reads. Neighbor snapshots, policy statistics, route
queries, and core readiness send messages to these actors. Other surfaces,
such as FIB-route and blackhole-discard status snapshots, already bypass
them; this record concerns the reads that still depend on these owners.

An actor can own a configuration operation longer than a read's deadline.
A read queued behind that operation can time out even though the daemon is
making progress. Admitting reads during safe waits removes that particular
queueing delay. It does not remove session-task collection, synchronous RIB
work, or contention for the runtime workers.

### Budget boundaries

The relevant constants live in `src/peer_manager/mod.rs` and the API
service modules listed below. A budget is meaningful only with its scope:

| Constant | Value | Scope |
|---|---:|---|
| `PEER_QUERY_TIMEOUT` | 100 ms | one bounded session-state query; also used for specific BMP query stages |
| `EXPLAIN_QUERY_TIMEOUT` | 500 ms | a session's import-explain reply |
| `PEER_MANAGER_READ_TIMEOUT` | 2 s | send and reply in the bounded `actor_read` peer-manager helpers |
| `POLICY_STATS_AGGREGATE_TIMEOUT` | 2 s | one absolute deadline shared by every backend stage of `GetPolicyStats` |
| `RIB_SNAPSHOT_TIMEOUT` | 2 s | the neighbor service's separate RIB snapshot stage |
| `CORE_READINESS_DEADLINE` | 200 ms | peer-manager `Ping` followed by RIB `LocRibCount` for the core check; the health snapshot substitutes readiness `ListPeers` for `Ping` |
| `PEER_POLICY_UPDATE_TIMEOUT` | 500 ms | one per-session policy mutation, not a read budget |
| `RIB_REPLY_TIMEOUT` | 5 s | bounded single-peer RIB policy, outbound-refresh, and replay-scheduling steps; outbound refresh shares one absolute deadline across capacity and reply |
| `RIB_BATCH_REPLY_TIMEOUT` | 2 min | batched authoritative export-policy apply and the rollback aggregate |
| `MAX_HEALTHY_POLICY_TRANSITION_AGE` | 30 s | transition age after which RIB readiness reports a stall, not a cancellation deadline |
| `MAX_PRECOMMIT_POLICY_TRANSITION_OWNERSHIP` | 60 s | pre-commit ownership before fail-closed handoff |
| `OWNED_NEIGHBOR_ACTOR_TIMEOUT`, `OWNED_POLICY_ACTOR_TIMEOUT`, `OWNED_PEER_GROUP_ACTOR_TIMEOUT`, `PEER_MANAGER_MUTATION_TIMEOUT` | 10 min | the corresponding owned API mutation |
| `OWNED_SETTLEMENT_BUDGET` | 30 min | persisted runtime-config settlement |
| `CONFIG_OPERATION_TIMEOUT` | 30 min | config-service diff, plan, and effective-config requests; mutations use settlement callbacks |

The two-minute aggregate and thirty-minute settlement budgets are 60 and
900 times the two-second read budget. A justified long owner budget is not
a reason to restart the read budget after admission or extend it through a
reload. Neighbor responses have separate peer-manager and RIB stages; the
policy-stats RPC instead shares one absolute deadline across its stages.

`rib_manager_read` is deliberately unbounded in `crates/api/src/actor_read.rs`;
callers such as neighbor snapshots and policy statistics add their own
bounds. RIB-manager-backed listing and explain calls without such a wrapper
rely on caller cancellation. The CLI's `READ_RPC_TIMEOUT` bounds its unary
read calls to 30 seconds; arbitrary API clients need not use that bound.
This existing choice is an input to the design, not a newly discovered bug
or permission to add a blanket server timeout.

### What the reload investigations established

- Forward reloads originally held reads behind per-session policy work and
  destination preparation. Admission at safe waits reduced that delay.
- The cohort export-policy transition also fenced reads before its commit
  batches. [PR #2456](https://github.com/lance0/rustbgpd/pull/2456) admitted
  the peer-manager operator lane during the forward cohort wait and RIB
  general queries between pre-commit polls. RIB commit batches retain their
  consistency fence.
- Residual post-commit latency requires separate attribution. In the local
  driven-probe experiment, co-pinning the load engine with the daemon
  inflated latency; separating their cores put the measured probes inside
  budget. Session collection during re-advertisement remained a substantial
  part of the delay. [PR #2459](https://github.com/lance0/rustbgpd/pull/2459)
  instruments RIB dispatch and does not change scheduling. Its elapsed-work
  and unattributed intervals are not CPU-time measurements or complete RPC
  latency, and they establish no general latency bound.
- Code review found rollback waits that unnecessarily fenced peer-manager
  reads. [PR #2460](https://github.com/lance0/rustbgpd/pull/2460) narrows that
  peer-manager admission problem. Complete neighbor and export-statistics
  RPCs also need the RIB, whose synchronous restoration requires the narrow
  summary contract below. A failed session restoration can leave mixed
  installed policies; admission cannot establish complete recovery.

The wait-site matrix records exercised admitting and fenced waits. Typed
`OperatorReadAdmission` makes admission a deliberate call-site choice;
`Fenced { reason, .. }` requires an explanation. Neither a nonempty reason
nor a matrix entry proves that a long fence meets an operator deadline.
The remaining fences, summary capture cost, and session-collection tail still
need evidence.

## Options

### A — Continue fixing individual admission sites

This preserves current read semantics and keeps each patch small, but a new
wait can repeat the same omission. It is not the recommended baseline.

### B — Typed admission with an exercised wait-site matrix

Every transaction wait states whether it admits operator reads. Prefer
admission when the read can report defined state without exposing an
incomplete mutation. A fence identifies the state that cannot safely be
read and the transition that releases it. Existing helpers continue to
prioritize a completed owner future and do not poll the ordinary mutation
channel mid-transaction.

Use `OperatorReadAdmission` and the existing matrix. The enum already
requires a reason for a fence; an additional reason-checking script would
add little. The matrix must exercise the production wait and distinguish
readiness, operator reads, and mutations. A test proving that a read stays
fenced is a consistency regression, not proof of acceptable availability.

B is the selected baseline for live peer-manager reads. It preserves
deadlines and existing observations while making the dependency explicit.
The temporary RIB projection below handles synchronous replacement; B alone
cannot solve synchronous actor work or session fan-out contention.

### C — Persistent published summaries for selected reads

A publisher exposes immutable observations through a shared handle. A read
loads one observation and avoids the owner queue for the fields it covers.
Configuration rows, RIB-owned counters, and small RIB summaries are initial
candidates. Full route tables and session-derived observations require
separate cost and consistency decisions.

An atomic pointer swap makes one published object consistent for readers;
it does not make separately sampled session replies or independently
published peer-manager and RIB objects one atomic fleet snapshot. A
collector could cache session replies, or sessions could publish their own
observations. Both need an explicit acquisition, identity, freshness, and
failure contract before they can replace today's live collection.

C remains conditional. It does not automatically remove the observed import
collection delay, and it does not make complete neighbor responses
actor-independent while their session fields are still queried live.

### D — A separate read task

A read task could own a view fed by snapshots or deltas. It adds ownership,
feed ordering, lag, and recovery rules. It is not required to read an
immutable shared summary, and moving a queue into another task does not
itself remove contention. Defer it until a measured requirement cannot be
met by a direct published view.

### E — Process separation

Separating session, RIB, and control work gives stronger fault and privilege
isolation, with substantial boundary and serialization changes. It does
not by itself make RIB-owned reads independent of RIB work. It is outside
this decision; no process split is selected for the read-latency issue.

## Selected ownership and observation contract

### Live peer-manager reads

Admission travels on `PolicySnapshotContext` and is explicit at each owner
entry. `Served` permits bounded operator work while the owner awaits a safe
step; `Fenced { reason }` names a concrete inconsistent state. Ordinary
mutations stay behind the transaction. The matrix drives the actual wait,
including a full destination queue, rather than a similar helper path.

| Wait or entry | Admission and observation |
|---|---|
| SIGHUP forward policy application; API `apply_policy_impact_snapshot` and `refresh_policies_for_config_classified` | served at safe waits; configuration and session observations may come from different points in the operation |
| Read-only preflight, cohort selection, clean-state retries, retained-route proofs | served; read-only work does not justify a transaction-wide fence |
| Individual session policy or hot-knob acknowledgement | fenced until matching manager bookkeeping; serve a bounded batch between completed serial steps |
| Post-acknowledgement per-peer RIB export replacement | inherit the owner's admission after session and manager bookkeeping agree |
| Batched authoritative apply and rollback waits | inherit the owner's admission through capacity and reply waits |
| API policy publication-failure compensation | served; restoration order alone does not make live observations invalid |
| SIGHUP policy/dataset compensation | served while earlier restoration steps succeeded; fenced after an earlier ambiguous restoration |
| SIGHUP honor-only `set_honor_graceful_shutdown` and `set_honor_blackhole` fan-outs | served after each import acknowledgement and matching bookkeeping; desired configuration and ordinary commands retain their existing ordering |
| Outbound refresh and graceful-shutdown refresh | served; a hot-knob caller retains its fence until manager metadata is updated |
| Outbound replay scheduling | served during the exact-session wait; preserve session identity, cancellation, and the existing five-second scheduling bound |

The conditional compensation fence protects a specific counterexample.
Restored session knobs can be acknowledged, then a RIB refresh can fail
before `managed.transport_config` is updated. A neighbor response during a
later restoration could combine fresh session data with incorrect
`remove_private_as` or `max_prefix_action`. Prior restoration failures keep
that later policy/dataset replay fenced. A successfully restored peer must
use its replacement session handle, never its predecessor's handle.

Honor-only SIGHUP stages use the two setters above. Candidate classification
rejects combinations with policy/dataset generation edits; generation unwind
does not invoke those setters. Honor flags change implicit import tails
without changing the transport metadata exposed beside live session state.
Desired honor flags and global-chain reads remain on the ordinary lane.
This admission choice does not extend to arbitrary hot-knob restoration;
its acknowledgement/bookkeeping and ambiguous-restoration fences remain.

Other mixed observations are already part of the live contract. ConfigService
stages candidate configuration before applying policy; catalog mutations
adopt configuration after convergence. SIGHUP restores configuration and
datasets before chains, while API publication rollback restores chains
before staged configuration. None is one atomic prior-generation fleet
snapshot, and a partial rollback must not be described as a complete restore.

Serial step limits still accumulate for the owner: 1,000 state probes at
100 ms have a theoretical 100-second ceiling, and 1,000 hot-apply
acknowledgements at 500 ms have a 500-second ceiling per changed direction,
before outer ownership limits. Serving reads between successful steps avoids
one fleet-sized read fence. These ceilings are not measured healthy timings.

Outbound refresh uses one absolute five-second deadline across channel
capacity and acknowledgement. Replay scheduling preserves its own five-second
bound. Their expiration is polled inside the read-serving helper: an operator
read already consumed by that helper keeps its reply and remaining budget.
Returning the owner result can therefore include that read's remainder;
these bounds do not promise wall-clock return at exactly five seconds.

### Other users of live peer observations

gNMI neighbor snapshots use the operator `ListPeers` path on TLS and Unix
listeners and for dial-out. Get, subscription bootstrap, SAMPLE and heartbeat
reconciliation retain live session fields and the existing two-second
admission/reply budget. Snapshot failure still returns the error or terminates
the subscription; dial-out retains its reconnection behavior. Constructors
without an operator sender preserve the ordinary-lane fallback.

The periodic BMP timer joins its independent session, peer-RIB and Loc-RIB
collections under their existing 100 ms input budgets. Both RIB inputs bound
channel admission and reply together, so a full live RIB mailbox cannot leave
the peer manager indefinitely awaiting Loc-RIB admission. Unavailable values
are omitted. Loc-RIB emission still precedes the per-peer reports, using the
existing nonblocking output and source-drop counters. This overlaps waits;
it does not create an atomic cross-source snapshot or a hard whole-tick
wall-clock bound including rendering and executor scheduling.

### Cooperative backlog draining

`RibManager::drain_ready_updates` applies one existing actor unit per call:
the oldest pending route chunk, or one primary update when no older chunk
remains. It then services readiness and the existing bounded query budgets
where the ownership fence permits, yields to the executor, and reports
progress. GR, LLGR, refresh and selection timers, destination prestaging,
and deferred initial registration await this shared helper and continue to
defer their own work while the accepted primary backlog remains.

This preserves route-payload FIFO before a later EoR or timer release.
Acquiring a clean transition still defers general-query admission to that
transition's own pre-commit seams; batched commit retains its fence. Route
pages still invalidate across intervening chunks. The correction prevents
an aggregate drain from exhausting every queued chunk before serving reads.
It does not bound an individual actor unit or guarantee two-second reads or
destination-prestage completion under sustained input.

### Temporary RIB summaries

The daemon wires a bounded `RibSummaryQuery` channel accepting only
`ExportPolicyTermHits` and `NeighborRibSnapshots`. Outside synchronous
replacement, the RIB answers through its existing query handlers and clean
transition admission seams; batched commit keeps its fence. Service
constructors without the optional lane retain the ordinary RIB path; a
configured lane that closes returns unavailable instead of silently falling
back behind the general-query fence. API admission and reply share their
existing caller deadline.

Before the outer synchronous single-peer replacement, authoritative apply,
authoritative restore, or export-only dataset reevaluation mutates outbound
state, capture one owned projection. Nested replacement and restoration reuse
it. The projection contains numeric export-term observations, neighbor
advertised counts, policy counters and outbound diagnostics, plus the values
needed for update-group comparisons. It preserves explicit-disabled-policy
versus global-fallback behavior, requested peer order, unknown-peer behavior,
and selection-deferral diagnostics. It retains no compiled policy chains,
shared mutable counters, route tables, or per-peer advertised tables.

Existing checkpoints serve readiness first from the unchanged Loc-RIB
count, then at most `QUERY_BUDGET_PER_CHUNK` frozen summary requests. General
queries and mutations remain fenced while canonical chains, memberships and
tables are being changed. At completion, restore the normal summary receiver
and retire projection rows incrementally, serving completed canonical
summaries and readiness during retirement. A canceled summary reader does
not cancel the owning repair. The projection ends with the outer operation;
readers receive owned rows and cannot pin a persistent publication generation.

Capture must finish before frozen summaries can be served. Readiness remains
serviceable during capture, but response construction scales with requested
rows and terms. Advertised-count overlays can require rejected-route scans,
and active selection-deferral snapshots count family waiters per peer. A
bounded queue and request batch do not impose a universal capture cost or
two-second RPC guarantee. Measure capture, retirement, and retained
bytes at the actual workload shape.

This keeps synchronous fallback coverage for dirty/private tables, Add-Path,
ORR and non-unicast cases. Replacing the whole mechanism with the clean
transition kernel would also require redesigning its ineligible fallbacks
and rollback mutation order. The narrow projection avoids that larger change.

### Executor handoff

A real API-to-RIB regression showed that sending both summary replies was
insufficient: the last-woken RPC remained unscheduled while the synchronous
RIB operation continued. Tokio 1.53.1 documents a local LIFO slot that other
workers cannot steal from. The outer capture/work/retirement scope therefore
uses one runtime-flavor-aware `block_in_place` on the daemon's multi-thread
runtime. It keeps exclusive RIB mutation ownership while allowing independent
RPC tasks to run. See the pinned [runtime scheduling documentation](https://docs.rs/tokio/1.53.1/tokio/runtime/index.html)
and [`block_in_place` contract](https://docs.rs/tokio/1.53.1/tokio/task/fn.block_in_place.html).

Current-thread embedders retain synchronous execution because that runtime
cannot perform the handoff. Work sharing the same task also remains suspended.
The synchronous repair was already not canceled by dropping an RPC; the
handoff does not make it cancellable or change its terminal acknowledgement.
No separate read owner, per-checkpoint task, or new dependency is introduced.

## Surface classification

This inventory describes the implemented design; supporting evidence is
recorded under validation below. It is not a count of RPCs or a promise that
every actor-owned table should be copied. **Actor-owned** means
the relevant owner has the state from which a summary could be produced.
**Session-derived** requires a session observation under the current design.
**Mixed** joins these sources. Readiness checks also require live progress.

| Surface | Current path and budget | State and publication boundary |
|---|---|---|
| `neighbor` / `ListNeighbors`, `GetNeighborState` | operator `ListPeers` / `GetPeerState`, then typed RIB `NeighborRibSnapshots`; separate 2 s stages | mixed: live peer/session observations plus RIB summaries frozen during synchronous replacement; no shared generation pin |
| `dynamic-neighbor list` / `ListDynamicNeighbors` | peer-manager `ListDynamicRanges`; 2 s | actor-owned configured ranges |
| `policy stats --direction export` | typed RIB `ExportPolicyTermHits`; shared 2 s RPC deadline | numeric installed-chain observations frozen during synchronous replacement; persistent publication is not selected |
| `policy stats --direction import` | operator `QueryImportPolicyTermHits`, concurrent session collection under the remainder of the same deadline | session-derived import-chain term counters |
| policy-stats peer validation and datasets | operator `HasPeerAddress`, `QueryPolicyDatasets`; same deadline | actor-owned peer membership and dataset bindings |
| `policy explain --direction import` | peer manager to one session; 2 s outer, 500 ms inner | session-local decision cache |
| `rib received PEER --rejected` | peer manager to one session; 2 s outer, 500 ms inner | session-local reject retention |
| `doctor` validation posture | `GetValidationPolicyPosture`; 2 s | actor-owned resolved policies and dynamic ranges |
| policy, neighbor-set, policy-chain, and peer-group catalog reads | peer-manager catalog queries; 2 s | actor-owned configuration |
| `policy test` / `TestPolicy` | versioned RIB route snapshot and operator `ListPeers`; 2 s peer-manager stage, no fixed RIB helper deadline | mixed: policy context uses effective remote ASN, which prefers session-negotiated ASN, plus configured group and RIB routes; config-only rows are not equivalent |
| session and policy event history | peer-manager bounded-ring queries; 2 s | actor-owned retained event rings |
| config diff, plan, effective config | config-service request helper; 30 min | actor-owned configuration; planning also resolves policies and datasets |
| gNMI neighbor tree | operator `ListPeers`; 2 s per snapshot | mixed live peer-manager and session observations on listeners and dial-out; no common generation pin |
| `health` / `GetHealth` | readiness `ListPeers`, then RIB `LocRibCount`; one 200 ms deadline | mixed session snapshot and live actor response; a cached inventory cannot replace the live-readiness requirement |
| `/readyz`, core watchdog check | readiness `Ping`, then RIB `LocRibCount`; one 200 ms deadline | live actor progress and RIB transition-age check |
| received, best, advertised unicast listings | RIB `QueryRoutesPage`; version-fenced pages, no fixed helper deadline | actor-owned tables; remain actor-served outside the temporary summary scope |
| best-path explain and lookup | RIB explain/lookup; no fixed helper deadline | actor-owned best routes and candidates; remain actor-served |
| advertised/export explain | RIB `ExplainAdvertisedRoute`; no fixed helper deadline | classification depends on carrying all dry-run inputs, including installed export chain and advertised state; excluded from the initial summary scope |
| EVPN, FlowSpec, BGP-LS, VPN, labeled, RTC, topology and ORR reads | family-specific RIB queries; no fixed helper deadline | actor-owned tables or cached topology state; assess each surface separately |
| route and EVPN event history | RIB bounded-ring queries; no fixed helper deadline | actor-owned retained event rings |
| `WatchEvents` | actor subscription messages; bounded admission | receiver acquisition, not a state snapshot; existing broadcast behavior remains |
| periodic BMP statistics | concurrent session, peer-RIB and Loc-RIB queries, each under its existing 100 ms input budget | mixed independent observations; both RIB queries bound send plus reply; nonblocking output and omission on unavailable data |
| BMP/MRT dumps and warm checkpoint capture | RIB snapshot queries and explicit capture paths | actor-owned tables; warm capture also needs session generations, so the combined surface is mixed |

The source paths are `crates/api/src/*_service.rs`,
`crates/api/src/health_probe.rs`, `src/peer_manager/snapshot.rs`,
`crates/api/src/peer_types.rs`, and `crates/rib/src/update.rs`.
`GetPolicyStats` has up to four sequential backend stages: validation,
export, import, and datasets. Its shared absolute deadline must remain
shared even if an individual stage moves to a published view.

Daemon-internal FIB, blackhole, and EVPN reconciliation is outside this
operator-read decision. Its existing ownership and generation rules are
not changed by classifying the public read surfaces.

## Conditions before adopting persistent publication

First demonstrate a residual read-deadline failure that the bounded
admission/projection design cannot safely address. A follow-up must name the
exact fields and consumers it moves and settle these contracts:

1. **Observation semantics.** Distinguish committed configuration from
   observed session state and counters. Define publication triggers, maximum
   age, stale/missing data, and what happens if the publisher stops. A row
   published only at configuration commit can be arbitrarily old during a
   long period without configuration changes. Existing `stale` behavior
   must not silently turn into cached success.
2. **Generation and joins.** Identify the actual switch point. Independent
   peer-manager and RIB loads can straddle a commit; either publish a joined
   object, match generation identifiers with bounded behavior on mismatch,
   or explicitly preserve a mixed observation contract. A reader pins one
   object for the fields whose consistency it relies on.
3. **Failure and lifecycle.** Define startup, peer replacement/removal,
   successful rollback, partial rollback failure, and fail-closed behavior.
   A failed restore must not publish a complete prior generation as if all
   sessions installed it. Session observations need incarnation identity so
   late replies cannot revive an old connection's state.
4. **Bounded work and retention.** Define publication cadence, reader
   lifetime, retained-generation cost, and where final destruction runs.
   Readers can retain several different old generations across repeated
   publications; current-plus-previous is not a general bound. Publication
   or final reference release must not introduce a new long actor turn.
5. **Unchanged live gates and measurement.** Core readiness still checks
   actor progress and stalled transitions. Read deadlines start at their existing boundaries;
   no admission-time reset, retry-based success, or reload exemption is
   introduced by caching. A successful summary read cannot establish that
   its owner or session is currently responsive. A read that bypasses the
   peer-manager operator lane produces no lane-wait sample; it is not an
   `unfenced` sample.

Today's live collection can observe different session policy generations
within a response. C could instead report committed configuration alongside
explicitly aged session observations. Neither this record nor an atomic
swap chooses that product contract automatically.

## Cost and validation

At the retained [1,000-peer route-server shape](../perf/route-server-1000-2026-07.md),
a compact persistent peer-summary generation is plausibly on the order of
a few MiB. That hypothesis does not measure the selected temporary projection.
Heap strings, family/limit vectors, session blocks, indexes, and retained
old generations all contribute. Copying 400,000 Loc-RIB routes is a different
cost class; materializing every peer's full advertised table loses the
benefit of shared update-group state. Neither table copy is required for
the temporary projection, and both remain outside the decision.

Use the [memory attribution protocol](../perf/memory-attribution-2026-08.md)
for an A/B at the actual target shape: repeated runs, cgroup peak memory,
swap disabled, and matched workload and CPU allocation. Establish variance
at that shape instead of transferring an older campaign's noise floor.
Measure retained generations, allocation/reclamation work, and publication
latency as well as peak bytes. Compare reload and read latency distributions;
an unchanged median alone cannot clear a long-tail regression.

Keep the existing readiness and management acceptance gates. Drive reads
across prestaging, session apply, pre-commit polls, commit, post-commit
re-advertisement, successful rollback, and failed rollback. Anchor probes to
phase markers or systematically vary their offsets; a fixed polling cadence
can repeatedly miss the unsafe interval. Include slow or replaced sessions
and failed compensation after acknowledged session changes. If persistent
publication is later adopted, include readers retaining several generations.

### Measurement boundaries

`bgp_peer_manager_operator_query_wait_seconds{seam}` measures send-to-service
wall time, including bounded-channel admission. Its label is the current
command's policy marker or the latest completed marked command overlapping
the wait; intervening ordinary commands preserve that marker, including
trailing command work. A wait crossing several phases is recorded once,
not divided by cause. Timed-out callers still count if their reads are later
serviced; canceled sends and reads never drained do not. It excludes service
execution and reply delivery, so it is neither RPC latency nor a timeout rate.

The post-commit RIB trace ends at the first query dispatch, including a
frozen summary dispatched inside synchronous replacement. The temporary
context owns the pending trace and returns it if no frozen dispatch consumes
it. `busy_us` counts completed units of the instrumented work classes; an
owner still executing at interior dispatch has not completed its unit, so
that time remains in `unattributed_us`. Both are elapsed time, not CPU time
or RPC completion. Correlate them with external reads and phase records.
Counts on fenced seams depend on arrival timing and cannot quantify phase load.

### Integration evidence

The wait-site matrix, post-commit dispatch trace, peer-manager rollback
admission, operator-wait telemetry and outbound wait bounds are recorded in
[#2458](https://github.com/lance0/rustbgpd/pull/2458),
[#2459](https://github.com/lance0/rustbgpd/pull/2459),
[#2460](https://github.com/lance0/rustbgpd/pull/2460),
[#2461](https://github.com/lance0/rustbgpd/pull/2461), and
[#2464](https://github.com/lance0/rustbgpd/pull/2464).

API policy-entry and TestPolicy admission are in
[#2463](https://github.com/lance0/rustbgpd/pull/2463). Shared drain fairness
originates in [#2465](https://github.com/lance0/rustbgpd/pull/2465) and is
composition-tested with RIB summaries in
[#2466](https://github.com/lance0/rustbgpd/pull/2466). Remaining policy, dataset
and honor-only admission are in [#2467](https://github.com/lance0/rustbgpd/pull/2467),
gNMI snapshots in [#2468](https://github.com/lance0/rustbgpd/pull/2468), and
periodic BMP collection in [#2469](https://github.com/lance0/rustbgpd/pull/2469).
These changes are merged; final phase coverage and qualifying soak remain
separate acceptance requirements.

Focused local RIB tests exercise frozen values inside real apply, restore,
and export-only reevaluation work. A complete neighbor/export-stat API-to-RIB
test passes while a second restore probe, terminal acknowledgement and an
ordinary RIB query remain held. Disabling checkpoint summary service fails
the real RIB interior assertion. Disabling only the executor handoff consumes
both summary requests but leaves the neighbor RPC unfinished. Separate
frozen-value tests mutate canonical policy and neighbor inputs while requiring
pre-operation values. These deterministic local proofs do not establish
full-fleet latency or measured capture cost.

Two baseline regressions poll the real RIB `run()` future with an expired
selection timer and a 3,072-route backlog. Both demonstrate that general
reads waited for all routes before the shared drain correction. Focused
validation after the correction includes destination-prestage fairness,
route-before-EoR and timer ordering, GR/LLGR, refresh, page invalidation and
clean-transition fence controls. These prove the shared scheduling defect;
they do not identify the cause of a particular historical soak timeout.

The honor-only regressions exercise both actual setter entries, held
acknowledgements, and successful eight-peer walks with 400 ms per-peer steps.
The earlier fenced entries fail the read assertions; admission fixes both
owners while preserving the per-step fence. gNMI tests cover live snapshots
through the shared constructor and a real held policy owner. BMP tests hold
the actual timer arm against a full live RIB mailbox and verify that bounded
collection returns the peer manager to dispatch without a false-zero report.

The [native honor-only cell](../perf/artifacts/honor-policy-waits-2026-09-12/README.md)
at clean `bb27ca009` exercises both setters with 1,000 healthy peers. Initial
200 ms probe spacing misses the interiors of the approximately 84–86 ms
owner-duration brackets. A denser two-stream follow-up records approximately
149–158 ms brackets and 27 calls starting and finishing inside the walks,
completing in 11.684–23.225 ms; all 1,223 calls succeed.
These observations establish healthy-fleet behavior for that revision and
schedule, without qualifying the final combined runtime candidate.

### Paired native rollback observation

The retained [1,000-peer rollback pair](../perf/artifacts/rib-summary-rollback-2026-09-12/README.md)
uses 400,000 base IPv4 prefixes and one peer without Route Refresh. Both runs
commit a 1,000-peer cohort, reject the deferred import refresh, and complete
authoritative restoration. Candidate `fcd9dc87f` passes all 1,106 timed calls;
the baseline `122c0f40d` with trace-only markers passes all 1,098. All calls
complete within two seconds. Eight candidate calls start inside the frozen
summary interval and complete in 18.814–38.489 ms.

This pair establishes native rollback behavior and interior read progress.
It reproduces no baseline deadline failure and establishes no general
speedup. Capture takes 2,678 µs and retirement 689 µs for 1,000 peers,
1,000 policies, 1,000 terms and one group; those elapsed scopes include
checkpoint/read service. Process RSS is sampled every 100 ms, with no sample
inside capture or retirement. It cannot identify projection allocation bytes
or guarantee a transient peak. The receipt states the differing marker
boundaries, ordinary churn, executable identities and teardown exclusions.

The pair predates the later fairness, policy-admission, gNMI and BMP changes;
it does not qualify the final runtime candidate. The final phase sweep and
qualifying soak remain required. Keep the fleet policy-statistics issue open
until those pass, with the existing zero-failure management criterion. A
passing older run does not qualify later runtime changes.

## Prior art and its limits

[OpenBGPD's design paper](https://www.openbsd.org/papers/asiabsdcon2009-bgpd.pdf)
describes session/RDE process separation and a separate control pipe. It also
reports that long RDE table dumps blocked control commands. It supports
isolation of some work, not a universal read-availability guarantee.

The [BIRD 3.3.2 guide](https://bird.nic.cz/doc/bird-3.3.2.html) assigns CLI and
reconfiguration to the main thread and BGP plus table maintenance to worker
groups. Thread placement alone does not establish the synchronization or
latency contract of every CLI query.

[FRR's process-architecture guide](https://docs.frrouting.org/projects/dev-guide/en/latest/process-architecture.html)
describes per-thread event loops and a dedicated keepalive thread. Its
example still runs control-socket and BGP processing callbacks on the main
thread. The [FRR RCU guide](https://docs.frrouting.org/projects/dev-guide/en/latest/rcu.html)
is a useful precedent for immutable publication and deferred reclamation,
not evidence that all BGP operator reads already use that design.

[`arc-swap`](https://docs.rs/arc-swap/1.9.2/arc_swap/struct.ArcSwapAny.html)
is one Rust mechanism for atomic publication of reference-counted objects;
it is already available in the workspace, but the temporary projection does
not use it. Its consistency guidance recommends loading once for related
fields. A seqlock is not equivalent for this purpose:
[sequence-counter readers can retry while a writer is preempted](https://docs.kernel.org/locking/seqlock.html),
so it does not provide the same independence from a long-running writer.

## Decision

Use typed admission and the exercised wait-site matrix for live peer-manager
reads. Cooperatively drain primary work through the existing read and yield
seams. Use a temporary value-only RIB projection and one outer executor
handoff for synchronous policy replacement and export-only reevaluation.
Preserve mutation ordering, atomic clean-transition commit, live readiness,
caller deadlines, and truthful partial-restoration observations.

Persistent publication is conditional on a measured remaining problem and
its field-level contract. Complete neighbor responses and import policy
statistics still depend on session tasks. Paged tables and explain remain
actor-served; a separate read owner and process split are not selected.

## Amendment (2026-10-10): reads overlapping reload completion

**Status of this amendment:** accepted and implemented.

### Problem

A neighbor read admitted at a transaction wait is answered in place:
`await_with_readiness` runs the admitted `ListPeers` handler to completion
before it polls the owner's future again. That handler fans out one
`QueryState` to every session and joins all replies, and the owner cannot
continue in the meantime. When the read overlaps the RIB commit of a cohort
export-policy transition, the sessions answer during the following
re-advertisement and shared encoding, so the reload waits for the slowest
session reply even though the RIB reply is already ready.

On the default policy-stats cell (1,000 peers, 400,000 IPv4 prefixes, eight
reloads per process, two processes per arm, one same-host window), the read
pair starts about 55 ms before commit once the fenced transition is shorter
than the cell's 110 ms read lead. Main at `310276878` completes SIGHUP in a
pooled median of 808.5 ms against 742.3 ms for the #2952 parent. Additive
per-reload means attribute the difference to the wait after the RIB reply
(20.9 → 74.6 ms) rather than to the RIB transition (204.4 → 55.5 ms). The
parent binary has the same delay when its read is placed at the same offset:
the median rises to 911.9 ms, and seven of 16 reloads wait more than 100 ms
after the RIB commit. This is a read-admission interlock, not added RIB work.
Neither the shared-encoding yield nor further RIB work can remove it: the
owner waits for a read that it does not need.

### Options considered

- **C, persistent publication**, would remove the session dependency only
  if sessions published their own observations. That needs the acquisition,
  identity and freshness contract listed above for every session field, and
  it changes `stale` from "unavailable now" to an aged observation. That is
  more than this problem requires.
- **D, a separate read owner**, would move the queue into another task
  without changing what the owner must wait for. It also adds feed ordering
  and lag rules.
- **F, ordered detached collection (selected).** The owner admits the read,
  captures the manager half of every row, and enqueues every session query
  before resuming. A per-read task completes the join and replies. No view
  outlives the read and no persistent publisher is introduced.

### Selected contract

This applies only to `ListPeers` reads admitted by `await_with_readiness` or
`await_with_readiness_budget` (the operator arm at transaction waits). The
ordinary lane, readiness `ListPeers`, `GetPeerState` and the other operator
queries keep their current in-place behavior.

**Admission point.** When the operator arm receives `ListPeers`, the owner
does three things synchronously, with no await between them:

1. It records the operator-wait observation, as it does today.
2. It captures, for every peer in `PeerTable` order, the values that
   `build_peer_info` takes from the manager. These are `ManagedPeerState`
   fields, the RFC 8212 statuses and posture, and max-prefix latch errors
   and deadlines. It also captures each peer's command sender.
3. It calls `try_reserve` on every session command channel and then sends one
   `QueryState` through each permit.

If any channel is full (it already holds eight commands), the owner drops
all of its permits and serves the read in place, exactly as before. It does
the same when the detached-read limit below is reached. These are the only
conditions that select the old path. A closed channel is not a fallback:
that session's row is reported unavailable, which is what the in-place
fan-out reports when its send fails.

**Row semantics.** Every field that comes from the manager has its value at
the admission point. Every field that comes from a session has the value at
the moment that session dequeues the query. That moment is after admission
and before the session executes any command the owner enqueues after
admission. Session command channels are FIFO, and the shared-group and
replay read pumps preserve that order: a deferred non-read command blocks
later commands, and only canceled reads are discarded.

The table below covers a read admitted before a cohort RIB commit:

| Field source | Value reported |
|---|---|
| Manager configuration, transport metadata, installed-chain RFC 8212 status, dynamic provenance, latch | pre-commit admission value. Before every cohort wait, the cohort has already applied its sessions and updated their bookkeeping, so these already describe the target policy |
| Session FSM, negotiated state, effective max-prefix and Add-Path limits, role | the session's own state before any later owner command. A cohort commit sends no session command, so these are unchanged by the commit |
| Session counters (`updates_sent`, `messages_sent`, prefix counts, policy permit/deny counts) | live at the dequeue, so they can include post-commit re-advertisement. The in-place contract already allows this, because the RIB drives delivery independently of the peer manager |
| RIB stage (`NeighborRibSnapshots`) | unchanged: a separate stage with no shared generation pin |

**A torn configuration row is not possible.** ADR-0132 admits reads only
where manager bookkeeping agrees with every acknowledged session command:
per-session acknowledgements remain fenced until bookkeeping. The owner
changes a session's configuration only through commands on that session's
channel. Any such command is therefore ordered after the read's query, and
the session reports the state that matches the captured manager half. The
implementation must enumerate every `Served` wait and keep in place any
wait that spans an unacknowledged session configuration command. The
replay-scheduling wait spans `ReplayOutbound`, which changes no row field
and qualifies.

Two outcomes that already exist cover the remaining cases:

- **Unavailable session state.** A session that does not answer within
  `PEER_QUERY_TIMEOUT` of admission, or whose task has exited, yields
  `stale=true` with admission-time manager values. A peer that is removed or
  replaced after admission still answers the queued query before its later
  shutdown command. If the old task is aborted first, the row is stale. A
  replacement handle never answers the old read.
- **Membership at admission.** The read contains exactly the peers present at
  admission. A peer added after admission is absent.

### Ownership, cancellation and shutdown

The peer manager owns a `JoinSet` of detached collections. It holds at most
as many as the operator lane's capacity and reaps finished entries at each
admission. Each task owns:

- the API reply sender;
- the captured rows;
- the per-session reply receivers;
- one absolute deadline: admission plus `PEER_QUERY_TIMEOUT`.

The owner never awaits these tasks during a transaction or an ordinary step.

- **Caller cancellation.** The task selects on `reply.closed()` and returns,
  which drops the session receivers. Sessions already skip canceled
  `QueryState` commands through `is_canceled_read`.
- **Reply loss and panics.** If a task panics or is aborted, its reply sender
  drops. The API returns its existing unavailable status for a dropped
  peer-manager reply, and the owner logs the join error at reap.
- **Shutdown.** Dropping the peer manager aborts the set. An in-flight read
  receives the same dropped-reply error instead of delaying shutdown. Today
  such a read delays shutdown until its fan-out returns. No read can keep the
  owner or a session handle alive past the manager's teardown.
- **Owner budgets.** A detached read never extends the wait that admitted it,
  and `await_with_readiness_budget` charges it no service time. Reads served
  in place keep the existing charging rules.

### Compatibility surfaces

- **Protobuf, CLI and gNMI.** No field, type, status code or deadline changes,
  and `stale` keeps its meaning (an unavailable observation). The
  observation point changes for `ListNeighbors`, the gNMI neighbor tree and
  `TestPolicy`'s peer stage when they run during a configuration
  transaction. Before, the manager half was read after the fan-out, while
  the owner was frozen. Now it is read at admission, and the owner may finish
  the transaction before the reply is sent.
- **Ordering.** A neighbor read can now complete after
  `config reload complete`. Its rows describe manager state at admission.
- **Documentation.** The neighbor section of `docs/reference/api.md` states
  the observation point. Every `Served` row of the wait-site matrix above
  now detaches an admitted `ListPeers` when it can; reads drained between
  serial acknowledgements (`drain_operator_queries`) remain in place.
- **Upgrade and changelog.** An upgrade note covers clients that correlate
  neighbor reads with reload completion, and a `Changed` entry covers reload
  completion no longer waiting for an overlapping neighbor read.
- **Metrics.** `bgp_peer_manager_operator_query_wait_seconds` keeps its
  admission-time sample.

### Regression plan

Extend `src/peer_manager/tests/wait_sites.rs` with held sessions and the
held-RIB fixture. Use explicit channel handshakes on paused time, with no
sleeps.

1. Drive a cohort transaction to `ReplacePeerExportPolicies`, then hold it.
2. Send `ListPeers`. Observe one `QueryState` arrive on every session, and
   hold the first session's reply.
3. Release the cohort reply as `Committed`. Assert that the owner returns its
   committed result while the `ListPeers` reply is still pending.
4. Have the owner enqueue a configuration command to the held session after
   the transaction, such as a hot-knob update. Assert that the session
   dequeues it only after answering the held query. Answer the query with
   the pre-command state.
5. Assert that the reply rows pair the admission-time manager values with
   that pre-command session state. Assert that no row is stale.

Prove the regression is red by restoring in-place service for the operator
arm: step 3 must fail. Add companion tests for the edge cases:

- a full session channel at admission serves the read in place, and the
  owner waits;
- the detached limit falls back to in-place service;
- caller cancellation drops the queries;
- peer-manager drop with a read in flight returns the dropped-reply error
  without hanging;
- a peer replaced after admission yields a stale row, not a reply from the
  replacement handle.

Update the existing matrix cases that asserted that the owner waits for an
admitted `ListPeers`; that wait is no longer the contract.

### Acceptance measurement

Build the #2952 parent (`3bbc1576`), the merge-base main and the candidate
with the same locked package command and toolchain, and use one common
`rbgp`. Run the unchanged default policy-stats cell with the default
`PAIR_LEAD=0.110`, eight reloads per process and two processes per arm.
Use the balanced order P, M, C, C, M, P in one window, under the canonical
host lock, with the quiet gate before each leg and no concurrent builds.

The candidate passes when:

- every cell has a native PASS, with no read deadline miss or call over two
  seconds;
- its pooled SIGHUP→complete median is at or below the parent's pooled
  median in the same window;
- its logged RIB transition median stays within a few milliseconds of main's
  (about 55 ms).

Report process medians and ranges, the additive per-reload means and the
neighbor RPC distribution. The read moves off the reload path but still
competes for the daemon CPUs, so its own duration is not expected to fall.

The expected margin is small. In the attribution window, main's prestage
round trip is about 138 ms longer than the parent's, because the inventory
probe moved unfenced into prestage. Main's fenced transition is about 149 ms
shorter. Removing the continuation wait is therefore expected to bring main
to approximately the parent's completion, not clearly below it. If the
candidate misses the bar by less than that window's spread, the next
question is the unfenced prestage probe cost. That separate decision must
not be answered by relaxing this bar.
