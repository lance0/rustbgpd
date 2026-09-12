# ADR-0132: Operator Reads During Configuration Transactions

**Status:** Proposed
**Date:** 2026-09-12

This record recommends typed read admission and the wait-site test matrix as
our baseline. Published summaries remain a conditional follow-up design;
this ADR does not adopt a new read-consistency contract or change deadlines.

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
| `RIB_REPLY_TIMEOUT` | 5 s | one single-peer RIB policy step |
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
  peer-manager admission problem. RIB restoration remains synchronous and
  fenced; a failed session restoration can leave mixed installed policies.
  The bounded admission improvement does not establish rollback-wide read
  availability or complete recovery of every session.

The wait-site matrix records exercised admitting and fenced waits. Typed
`OperatorReadAdmission` makes admission a deliberate call-site choice;
`Fenced { reason, .. }` requires an explanation. Neither a nonempty reason
nor a matrix entry proves that a long fence meets an operator deadline.
The remaining fences and the session-collection tail still need evidence.

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

B is the recommended present baseline. It preserves deadlines and current
read semantics while making the remaining dependency visible. It cannot
solve synchronous actor work or session fan-out contention by itself.

### C — Published summaries for selected reads

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
this proposal; no process split is recommended for the read-latency issue.

## Surface classification

This is an inventory of actor-backed surfaces, not a count of RPCs or a
promise that every actor-owned table should be copied. **Actor-owned** means
the relevant owner has the state from which a summary could be produced.
**Session-derived** requires a session observation under the current design.
**Mixed** joins these sources. Readiness checks also require live progress.

| Surface | Current path and budget | State and publication boundary |
|---|---|---|
| `neighbor` / `ListNeighbors`, `GetNeighborState` | operator `ListPeers` / `GetPeerState`, then RIB `QueryNeighborRibSnapshots`; separate 2 s stages | mixed: peer configuration, bounded session-state collection, and RIB outbound summaries; complete responses still need session observations |
| `dynamic-neighbor list` / `ListDynamicNeighbors` | peer-manager `ListDynamicRanges`; 2 s | actor-owned configured ranges |
| `policy stats --direction export` | RIB `QueryExportPolicyTermHits`; shared 2 s RPC deadline | actor-owned export-chain term counters; publication cadence and counter-reset semantics need definition |
| `policy stats --direction import` | operator `QueryImportPolicyTermHits`, concurrent session collection under the remainder of the same deadline | session-derived import-chain term counters |
| policy-stats peer validation and datasets | operator `HasPeerAddress`, `QueryPolicyDatasets`; same deadline | actor-owned peer membership and dataset bindings |
| `policy explain --direction import` | peer manager to one session; 2 s outer, 500 ms inner | session-local decision cache |
| `rib received PEER --rejected` | peer manager to one session; 2 s outer, 500 ms inner | session-local reject retention |
| `doctor` validation posture | `GetValidationPolicyPosture`; 2 s | actor-owned resolved policies and dynamic ranges |
| policy, neighbor-set, policy-chain, and peer-group catalog reads | peer-manager catalog queries; 2 s | actor-owned configuration |
| `policy test` / `TestPolicy` | plain-lane `ListPeers`, then RIB route pages; 2 s peer-manager stage, no fixed RIB helper deadline | mixed: policy context uses effective remote ASN, which prefers session-negotiated ASN, plus configured group and RIB routes; config-only rows are not equivalent |
| session and policy event history | peer-manager bounded-ring queries; 2 s | actor-owned retained event rings |
| config diff, plan, effective config | config-service request helper; 30 min | actor-owned configuration; planning also resolves policies and datasets |
| gNMI neighbor tree | plain-lane `ListPeers`; 2 s per poll | mixed peer-manager and session observations |
| `health` / `GetHealth` | readiness `ListPeers`, then RIB `LocRibCount`; one 200 ms deadline | mixed session snapshot and live actor response; a cached inventory cannot replace the live-readiness requirement |
| `/readyz`, core watchdog check | readiness `Ping`, then RIB `LocRibCount`; one 200 ms deadline | live actor progress and RIB transition-age check |
| received, best, advertised unicast listings | RIB `QueryRoutesPage`; version-fenced pages, no fixed helper deadline | actor-owned tables; remain actor-served in the proposed summary scope |
| best-path explain and lookup | RIB explain/lookup; no fixed helper deadline | actor-owned best routes and candidates; remain actor-served |
| advertised/export explain | RIB `ExplainAdvertisedRoute`; no fixed helper deadline | classification depends on carrying all dry-run inputs, including installed export chain and advertised state; excluded from the initial summary scope |
| EVPN, FlowSpec, BGP-LS, VPN, labeled, RTC, topology and ORR reads | family-specific RIB queries; no fixed helper deadline | actor-owned tables or cached topology state; assess each surface separately |
| route and EVPN event history | RIB bounded-ring queries; no fixed helper deadline | actor-owned retained event rings |
| `WatchEvents` | actor subscription messages; bounded admission | receiver acquisition, not a state snapshot; existing broadcast behavior remains |
| periodic BMP statistics | session queries and RIB statistics | mixed; per-peer RIB query bounds send plus reply to 100 ms, while Loc-RIB statistics currently bound the reply only and await send without that timeout |
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

## Conditions before adopting published summaries

A follow-up proposal must name the exact fields and consumers it moves and
settle these contracts before implementation:

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
5. **Unchanged live gates.** Core readiness still checks actor progress and
   stalled transitions. Read deadlines start at their existing boundaries;
   no admission-time reset, retry-based success, or reload exemption is
   introduced by caching. A successful summary read cannot establish that
   its owner or session is currently responsive.

Today's live collection can observe different session policy generations
within a response. C could instead report committed configuration alongside
explicitly aged session observations. Neither this record nor an atomic
swap chooses that product contract automatically.

## Cost and verification

At the retained [1,000-peer route-server shape](../perf/route-server-1000-2026-07.md),
a compact peer-summary generation is plausibly on the order of a few MiB.
That is a sizing hypothesis, not a measurement of a selected representation.
Heap strings, family/limit vectors, session blocks, indexes, and retained
old generations all contribute. Copying 400,000 Loc-RIB routes is a different
cost class; materializing every peer's full advertised table loses the
benefit of shared update-group state. Neither table copy is required for
initial summary publication, and both remain outside the recommendation.

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
and readers that retain observations across several publications.

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
no dependency is selected here. Its consistency guidance recommends loading
once for related fields. A seqlock is not equivalent for this purpose:
[sequence-counter readers can retry while a writer is preempted](https://docs.kernel.org/locking/seqlock.html),
so it does not provide the same independence from a long-running writer.

## Decision (proposed)

Use B as the baseline: typed admission with reasons, the existing wait-site
matrix, and measured follow-through on remaining fences. Preserve the atomic
RIB commit, live readiness checks, ordinary mutation ordering, and current
read deadlines.

Develop C only for explicitly selected summary fields after the contracts
and measurements above are satisfied. Complete neighbor responses and import
policy statistics are not declared solved by publishing actor-owned fields.
Paged tables and explain surfaces remain actor-served. D is deferred and E
is outside the proposed scope.

This recommendation makes the read dependency reviewable without promising
that admission alone fixes every wait. It also keeps a later publication
change small enough to evaluate against the actual remaining latency.
