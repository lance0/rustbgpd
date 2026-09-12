# ADR-0132: Where Operator Reads Live — Admission at Each Wait Site Versus a Published Read Generation

**Status:** Proposed
**Date:** 2026-09-12

This record is a draft for the maintainer to accept, amend, or reject. The
option analysis and the surface classification are verified against the
source tree at the date above; the recommendation at the end is the
drafter's, pending the maintainer's decision.

## Context

### The structure

Two single-task actors own the daemon's operator-visible state: the peer
manager ([ADR-0017](0017-peer-manager-channel-based-ownership.md)) and the
RIB manager ([ADR-0013](0013-single-task-rib-manager.md)). Every operator
read — `rbgp neighbor`, `rbgp policy stats`, a route listing, the readiness
probe — is a message into one or both of those actors, answered from the
actor's own turn.

A long operation that the actor owns (a policy reload, a cohort export-policy
transition, a rollback of a rejected reload) holds the actor's turn for
seconds. A short read that arrives during that window queues behind it. The
read's own deadline is shorter than the owner's, so the deadline kills the
read before the owner finishes. This is priority inversion: the low-latency
request waits on the high-latency one, and the only observable outcome is
`DEADLINE_EXCEEDED` on a healthy daemon.

### The budget asymmetry

The generator is two budget classes that were never reconciled. Each is
individually reasoned in its doc comment; nothing relates them.

Read budgets, verified in source:

| Constant | Value | Where | Bounds |
|---|---:|---|---|
| `PEER_QUERY_TIMEOUT` | 100 ms | `src/peer_manager/mod.rs` | one per-session `query_state` round trip inside a peer-manager read |
| `EXPLAIN_QUERY_TIMEOUT` | 500 ms | `src/peer_manager/mod.rs` | one `ExplainImportPolicy` session round trip |
| `PEER_POLICY_UPDATE_TIMEOUT` | 500 ms | `src/peer_manager/mod.rs` | one per-session policy hot-apply |
| `ORF_RIB_REPLY_TIMEOUT` | 500 ms | `crates/transport/src/session/io.rs` | a session's ORF reply from the RIB |
| `POLICY_STATS_AGGREGATE_TIMEOUT` | 2 s | `crates/api/src/policy_service.rs` | every backend stage of one `GetPolicyStats`, shared absolute deadline |
| `PEER_MANAGER_READ_TIMEOUT` | 2 s | `crates/api/src/actor_read.rs` | admission plus reply of every peer-manager read |
| `RIB_SNAPSHOT_TIMEOUT` | 2 s | `crates/api/src/neighbor_service.rs` | the neighbor service's RIB snapshot stage |
| `CORE_READINESS_DEADLINE` | 200 ms | `crates/api/src/health_probe.rs` | the readiness probe's two actor pings together |

Owner budgets, verified in source:

| Constant | Value | Where | Bounds |
|---|---:|---|---|
| `RIB_REPLY_TIMEOUT` | 5 s | `src/peer_manager/mod.rs` | one single-peer RIB policy step |
| `RIB_BATCH_REPLY_TIMEOUT` | 2 min | `src/peer_manager/mod.rs` | the batched authoritative export-policy apply, and the whole rollback aggregate |
| `MAX_HEALTHY_POLICY_TRANSITION_AGE` | 30 s | `crates/rib/src/manager/mod.rs` | how long a clean policy transition may own the RIB before readiness reports it stalled |
| `MAX_PRECOMMIT_POLICY_TRANSITION_OWNERSHIP` | 60 s (2× the above) | `crates/rib/src/manager/mod.rs` | pre-commit ownership before the fail-closed handoff |
| `OWNED_NEIGHBOR_ACTOR_TIMEOUT` | 10 min | `crates/api/src/neighbor_service.rs` | an owned neighbor mutation |
| `OWNED_POLICY_ACTOR_TIMEOUT` | 10 min | `crates/api/src/policy_service.rs` | an owned policy mutation |
| `OWNED_PEER_GROUP_ACTOR_TIMEOUT` | 10 min | `crates/api/src/peer_group_service.rs` | an owned peer-group mutation |
| `PEER_MANAGER_MUTATION_TIMEOUT` | 10 min | `crates/api/src/server.rs` | a generic peer-manager mutation |
| `OWNED_SETTLEMENT_BUDGET` | 30 min | `crates/api/src/runtime_config_settlement.rs` | settlement of a persisted runtime-config change |
| `CONFIG_OPERATION_TIMEOUT` | 30 min | `crates/api/src/config_service.rs` | config-service reads and writes alike |

The ratio between the two classes is between 60× (2 s against 2 min) and
900× (2 s against 30 min). A read budgeted at 2 s can only succeed during an
owner operation if the actor deliberately admits it mid-operation. Nothing
in the type system or the actor loop says whether it does.

The client side adds a third figure that is not a real bound: `rbgp`'s
`READ_RPC_TIMEOUT` is 30 s (`crates/cli/src/connection.rs`), and
`rib_manager_read` in `crates/api/src/actor_read.rs` is deliberately
unbounded server-side. Every `RibService` listing and explain RPC therefore
waits on the client deadline alone; a wedged RIB actor hangs those RPCs for
30 s rather than returning `DEADLINE_EXCEEDED`.

### Four instances in four weeks

Described by mechanism. Each was found only when a read happened to land in
the window, and each fix was local to the site that failed.

1. **A reload stalled 2 s reads for about 3.1 s.** A forward policy reload
   held the peer manager through its per-session hot-apply steps; neighbor
   and policy-stats reads queued behind them. Raising the read budget did
   not clear the failure: the owner's step is bounded per session
   (`PEER_POLICY_UPDATE_TIMEOUT`) but the walk is O(peers), so the stall
   grows with the fleet, not with any constant a read could be raised to.
   The fix admitted reads at the seams between steps (the readiness lane,
   then the operator lane during destination prestaging).
2. **The cohort RIB transition fenced reads until commit.** After every
   cohort session already ran its new chains, the peer manager awaited the
   cohort's batched RIB reply with only the readiness lane admitted, and the
   RIB served no general query while a clean policy transition was owned.
   At 1,000 peers the transition runs about 0.7–2 s, so a read arriving more
   than about 0.8 s before the commit exhausted its 2 s budget. The commit
   "serve operator reads during the cohort rib transition" (`50d161bbe`)
   admits the operator-read lane while the forward reload owner awaits that
   reply, and lets the RIB serve one general-query budget between its
   pre-commit transition polls from the pre-commit state.
3. **Reads arriving during the commit batches pay a post-commit tail.** The
   RIB's commit batches keep their fence — the commit is the single switch
   point. A read that lands inside them waits for the commit and then for
   the backlog the commit accumulated; the observed tail is about 1 s at
   the flagship shape. A fix is in preparation.
4. **A rejected reload's rollback awaits its RIB aggregate with reads
   fenced.** Found by code read, not by a probe: `restore_resolved_policies`
   and `register_policy_rollback_rib` (`src/peer_manager/policy.rs`) await
   `RestorePeerExportPoliciesAuthoritatively` under a rollback budget
   anchored at `RIB_BATCH_REPLY_TIMEOUT` (2 min) using the readiness-only
   helper. The generation-level unwind replays the prior policies through a
   path that hardcodes operator reads off. A rejected reload is exactly when
   an operator is most likely to be looking. A fix is in preparation.

### The current approach: admission at each wait site

The peer-manager actor has four wait helpers in `src/peer_manager/mod.rs`,
all `biased` toward the owned future so a probe flood cannot delay a
completed step, and none of which polls the ordinary command channel, so
mutations stay strictly behind the transaction:

- `await_with_readiness` — admits the readiness lane
  (`PeerManagerReadinessQuery::{Ping, ListPeers}`) only.
- `await_with_readiness_and_operator_reads(_, allow)` — also admits the
  operator lane (`PeerManagerOperatorQuery::*`) when `allow` is true.
- `await_with_readiness_budget` — readiness only, with a budget charged only
  while genuinely waiting on the step, not while servicing a query.
- `await_with_readiness_and_operator_budget(_, _, allow)` — the budgeted
  form with conditional operator admission.

Verified inventory of non-test call sites at this date: **21**. Seventeen
admit the readiness lane only (thirteen in `src/peer_manager/policy.rs`,
one in `src/peer_manager/mod.rs`, one in `src/peer_manager/lifecycle.rs`,
plus the two budgeted readiness-only waits around per-peer hot-apply and
dataset export re-evaluation). Four admit operator reads, all in
`src/peer_manager/policy.rs`: destination prestaging, the cohort RIB reply
wait, and the send and reply of the batched authoritative apply. All four
are conditional on a flag that is `true` on exactly one path — the forward
SIGHUP generation in `src/peer_manager/generation.rs`. Every other entry
point, including the gRPC transaction executor and every rollback, passes
`false` or has no flag at all.

On the RIB side, `crates/rib/src/manager/mod.rs` serves general queries
between pre-commit transition polls (`QUERY_BUDGET_PER_CHUNK` = 8 per
chunk; the poll itself strides until `FLUSH_POLL_BUDGET` = 25 ms elapses)
and fences them during the commit batches.

Each of these rules is individually correct and individually documented.
What is missing is an invariant: there is no statement of *which* waits must
admit reads, so a new wait defaults to the fenced form, and the next fence
that matters is found the same way the last four were — by a read arriving
in the window. The operator lane itself is narrow (five variants) and only
two services are wired to it (`NeighborService`, `PolicyService`, via
`with_operator_queries` in `crates/api/src/server.rs`); `PolicyService.TestPolicy`
uses the plain command lane for the same `ListPeers` class of read that
`GetPolicyStats` sends through the operator lane, so `rbgp policy test` can
be fenced behind a reload that `rbgp policy stats` passes through. That is
not a bug in either site; it is what per-site admission produces.

### Prior art

The three daemons this project is routinely compared against all removed the
reader's dependency on the owner structurally, in three different ways. None
manages it with per-site admission.

**OpenBGPD** splits the daemon into three processes. The manual page states
it plainly: "The session engine of bgpd is responsible for maintaining the
TCP session with each neighbor. Updates are passed to the Route Decision
Engine (RDE) where the paths are filtered and used to compute a Routing
Information Base (RIB). The parent process is responsible for keeping the
RIB in sync with the kernel routing table"
([bgpd(8)](https://man.openbsd.org/bgpd)). The 2009 design paper describes
the `imsg` framework over socketpairs between the processes, that
"Keepalives are directly generated by the session engine to ensure that
even high load on the RDE does not result in a session drop", and that
"The control messages issued by bgpctl use a second pipe so that large
backlogs are not holding these messages up for too long"
([AsiaBSDCon 2009](https://www.openbsd.org/papers/asiabsdcon2009-bgpd.pdf)).
The same paper is candid that separation alone does not remove the
inversion for RIB-owned state: because the RDE was allowed to block for a
long time, that "blocks almost all bgpctl commands as well and so affects
the responsiveness of bgpctl. This is one of the hot topics that I try to
solve in the near feature." Session-state reads are answered by the session
engine independently of RDE load; RIB reads still cross into the RDE. Later
bgpd releases added explicit flow-control messages between the engines;
that is not verified against source for this draft and is not relied on.

**BIRD 3.x** keeps the control plane on the main thread and moves protocol
work to worker thread groups. The user's guide: "There is one main thread,
taking care about startup, shutdown, (re)configuration, CLI and several
protocols which have not yet been updated to run in other threads", and
"Default thread group is `worker`. This group runs (by default) BGP, BMP,
MRT, Pipe and RPKI. Also the routing table maintenance routines run in
these threads" ([BIRD user's guide](https://bird.nic.cz/doc/latest/),
thread setup). The CLI never waits on a BGP session's turn because it does
not share one.

**FRR** runs one event loop per daemon and adds concurrency by giving each
pthread its own loop: "The fundamental pattern used in FRR daemons is an
event loop", and it is "safe to schedule events on a `threadmaster`
belonging both to the calling thread as well as *any other pthread*"
([process architecture](https://docs.frrouting.org/projects/dev-guide/en/latest/process-architecture.html)).
Its keepalive thread deliberately bypasses the scheduler because the
scheduler's overhead is significant relative to the task. For read-heavy
shared state FRR uses RCU, where "data structures are always consistent for
reading" and "reading never blocks / takes a lock"; writers copy, publish
with a release store, and defer freeing until no reader can still hold the
old version ([RCU](https://docs.frrouting.org/projects/dev-guide/en/latest/rcu.html)).
The page notes the limits that apply here too: it is "designed for
read-heavy workloads where objects are updated relatively rarely", and the
old object stays resident during the grace period.

**In Rust**, the published-generation shape is what
[`arc-swap`](https://docs.rs/arc-swap) provides: "a container for an `Arc`
that can be changed atomically", for data that is "often read and seldom
updated"; `load()` is lock-free and never waits on a `store()`. The crate
documentation directs readers to its own limitations and performance
sections before adopting it. `left-right` (two copies, readers on one,
writer on the other, swapped on publish) and a seqlock (readers retry when
a write raced them) are the alternatives; both trade write cost or reader
retries for the same property — a reader never waits on the owner.

## Options

### A — Status quo: admission at each wait site

Keep the four helpers and the flag. Add operator admission to a wait when a
read is found to fail behind it.

- **Cost.** None up front. Each instance costs a reproduction, a fix, and a
  regression test, and the instance is found by a soak or an operator, not
  by review.
- **What it buys.** Exact control: every admission is a deliberate,
  documented decision about which mixed state a read may observe.
- **What it does not.** An invariant. The set of admitting sites is the set
  of sites that have already failed. Nothing prevents the twenty-second
  wait from defaulting to fenced, and nothing tells a reviewer that it
  should not.

### B — Keep admission, add the invariant and enforce it

State the rule: **a transaction wait admits operator reads unless it has a
per-session mutation in flight against the state a read would report.** The
readiness-only wait becomes the variant that must justify itself. Each
readiness-only site carries a one-line reason adjacent to the call — the
repository already enforces exactly this shape for lint allowances
(`scripts/check-clippy-reasons.py` requires `reason =` on every ratcheted
`allow`/`expect`), so the checker is a sibling of an existing one, not a new
kind of gate. The wait-site test matrix in preparation is the other half:
one test per wait site that parks the owner, sends a read, and asserts
either that it is served or that the site's stated reason names why not.

- **Cost.** A checker script with companion tests, reasons on seventeen
  sites, the matrix. No runtime change to the read path.
- **What it buys.** Turns the current seventeen-and-four into a rule with a
  ratchet. Instance 4 (rollback) would have failed the matrix on the day it
  was written, because the rollback aggregate has no per-session mutation
  in flight — the sessions already run the restored chains. Instance 2
  would have failed for the same reason.
- **What it does not.** Change the fact that a read still enters the
  actor's turn. The post-commit backlog (instance 3) is not an admission
  question: the read is admitted and waits anyway, because commit batches
  are the switch point. B cannot express "this read does not need the
  actor at all."

### C — A published snapshot for the read surfaces

The actor publishes a generation of the read-facing state on an
`arc-swap`-style handle at defined points (commit, settle, rollback
complete, periodic). Reads that can be answered from a generation never
enter the actor. This is the RCU shape from FRR, in Rust, scoped to the
surfaces classified below as snapshot-able.

- **Cost.** A copy per generation of whatever the generation carries; the
  cost question is worked in "The cost of C" below. A new definition of
  what a read observes during a transition (below, "The semantics
  question"). Per-session counters cannot be published by the actor at all
  because the actor does not own them — sessions would have to publish
  their own rows, or those surfaces stay live.
- **What it buys.** For the snapshot-able surfaces, the inversion becomes
  structurally impossible: there is no wait to admit. Instance 3 (the
  post-commit tail) disappears for those surfaces because a read never
  queues behind the commit. The read budgets stop being the wrong class of
  number, because they no longer race an owner.
- **What it does not.** Cover the live surfaces — `policy stats
  --direction import`, `policy explain --direction import`, `rib received
  --rejected`, the readiness `Ping` (which is by definition a question
  about the actor's liveness). It also does not make a generation cheap for
  the full route tables; see the cost section.

### D — A separate read path or task with its own view

A dedicated read task owns a view that the actors feed with deltas or with
generations; RPC handlers talk only to the view. This is the BIRD/FRR shape
(control-plane thread that never runs on the protocol's loop).

- **Cost.** C's cost plus a task, a feed protocol, and a second consistency
  contract (the view lags the actor by the feed's latency). If the feed is
  deltas, the view re-implements the actor's bookkeeping for every surface;
  if the feed is generations, D is C with a task in front of it.
- **What it buys.** A single place to reason about read consistency and
  read budgets, and a natural home for surfaces that combine both actors
  (`rbgp neighbor` joins peer-manager rows with RIB outbound rows today in
  two 2 s stages).
- **What it does not.** Remove the need for C underneath: a view task with
  no published generation behind it is just a third actor with the same
  queue. D is worth its cost only after C exists and the joined surfaces
  measurably need it.

### E — Process separation, OpenBGPD style

Split session engine, RIB engine, and control into processes with message
passing between them.

- **Cost.** A rewrite of every boundary in this daemon, a serialization
  format for every message that crosses one, and — as OpenBGPD's own paper
  records — the RIB-side inversion survives the split, because RIB reads
  still cross into the RIB engine.
- **What it buys.** Privilege separation and crash isolation, neither of
  which is the problem this record is about.
- **What it does not.** Fit a solo project or this daemon's design lineage
  (ADR-0013, ADR-0017: single-task actors over channels). Listed so it is
  declined on the record rather than left unconsidered. **Declined.**

## Surface classification

Every operator read surface that enters the peer-manager or RIB actor, from
the gRPC services in `crates/api/src/` and the internal periodic readers.
Query types are `PeerManagerOperatorQuery::*` and `PeerManagerCommand::*`
(`crates/api/src/peer_types.rs`), `PeerManagerReadinessQuery::*`, and
`RibUpdate::*` / `RibReadinessQuery::*` (`crates/rib/src/update.rs`).

Classification:

- **Snapshot-able** — answerable from a published generation of state the
  actor owns, with the generation's staleness as the only semantic change.
- **Live** — must reach a session task, or asks about the actor itself.
  State the actor does not own cannot appear in a generation the actor
  publishes.
- **Mixed** — one RPC that joins both.

| Surface (CLI / RPC) | Actor | Query | Budget | State read | Class |
|---|---|---|---|---|---|
| `rbgp neighbor` / `NeighborService.ListNeighbors` | both | operator `ListPeers`; RIB `QueryNeighborRibSnapshots` | 2 s + 2 s | peer table and config; per-session `query_state` fan-out (100 ms each) for counters and negotiated state; RIB per-peer advertised counts, update-group state, outbound limits | mixed |
| `rbgp neighbor ADDR` / `GetNeighborState` | both | operator `GetPeerState`; RIB `QueryNeighborRibSnapshots` | 2 s + 2 s | as above, one peer | mixed |
| `rbgp dynamic-neighbor list` / `ListDynamicNeighbors` | peer manager | `ListDynamicRanges` | 2 s | configured ranges | snapshot-able |
| `rbgp policy stats --direction export` / `GetPolicyStats` export stage | RIB | `QueryExportPolicyTermHits` | shared 2 s | export-chain term counters, **owned by the RIB actor** | snapshot-able |
| `rbgp policy stats --direction import` / `GetPolicyStats` import stage | peer manager → sessions | operator `QueryImportPolicyTermHits` (spawned collector, `buffer_unordered` fan-out of `PeerCommand::QueryImportPolicyTermHits`) | remainder of the same 2 s | import-chain term counters, **owned by each session task** | live |
| `GetPolicyStats` peer validation and datasets stages | peer manager | operator `HasPeerAddress`, `QueryPolicyDatasets` | remainder of the same 2 s | peer key map; dataset bindings | snapshot-able |
| `rbgp policy explain --direction import` / `ExplainImportPolicy` | peer manager → one session | `ExplainImportPolicy` (awaited inline in the actor loop) | 2 s outer, `EXPLAIN_QUERY_TIMEOUT` 500 ms inner | session-local import-decision cache | live |
| `rbgp rib received ADDR --rejected` / `ListRejectedRoutes` | peer manager → one session | `ListRejectedRoutes` (inline) | 2 s outer, 500 ms inner | session-local reject-retention store | live |
| `rbgp doctor` posture / `GetValidationPolicyPosture` | peer manager | `GetValidationPolicyPosture` | 2 s | resolved policies and ranges | snapshot-able |
| `rbgp policy list\|get`, `neighbor-set list\|get`, `policy chain show`, `peer-group list\|get` (seven RPCs) | peer manager | `ListPolicies`, `GetPolicy`, `ListNeighborSets`, `GetNeighborSet`, `GetGlobalPolicyChains`, `GetNeighborPolicyChains`, `ListPeerGroups`/`GetPeerGroup` | 2 s | the catalog in the current config | snapshot-able |
| `rbgp policy test` / `TestPolicy` | both | `ListPeers` (plain lane, fans out `query_state`); RIB `QueryRoutesPage` | 2 s; RIB unbounded (client 30 s) | peer ASN and group context; Adj-RIB-In or Loc-RIB pages | snapshot-able (the fan-out serves only ASN/group context, which the config owns) |
| `rbgp events sessions\|policy` / `ListSessionEvents`, `ListPolicyEvents` | peer manager | `QuerySessionEventHistory`, `QueryPolicyEventHistory` | 2 s | actor-owned bounded rings | snapshot-able |
| `rbgp config diff\|plan\|effective` / `DiffRuntimeConfig`, `PlanConfigTransaction`, `GetEffectiveConfig` | peer manager | `DiffRuntimeConfig`, `PlanConfigTransaction`, `EffectiveRuntimeConfig` | `CONFIG_OPERATION_TIMEOUT` 30 min | current config snapshot (plan also resolves policy and datasets) | snapshot-able; already budgeted in the owner class, so not part of the inversion |
| gNMI `Get`/`Subscribe` OpenConfig neighbor tree | peer manager | `ListPeers` (plain lane, fans out) | 2 s per poll | as `ListNeighbors`, peer-manager half | mixed |
| `rbgp health` / `GetHealth`, `/readyz`, systemd watchdog | both | readiness `Ping` or `ListPeers`; `RibReadinessQuery::LocRibCount` | `CORE_READINESS_DEADLINE` 200 ms for both halves | actor liveness; Loc-RIB count | live (`Ping` asks whether the actor is alive; a generation cannot answer that) |
| `rbgp rib received\|best\|advertised` / `ListReceivedRoutes`, `ListBestRoutes`, `ListAdvertisedRoutes` | RIB | `QueryRoutesPage` (1,000 rows per page, version-fenced) | unbounded (client 30 s) | Adj-RIB-In, Loc-RIB, Adj-RIB-Out | snapshot-able |
| `rbgp rib best PFX --explain`, `rbgp rib lookup` / `ExplainBestPath`, `LookupBestPath` | RIB | `ExplainBestPath`, `LookupBestPath` | unbounded | Loc-RIB best and candidates | snapshot-able |
| `rbgp rib advertised … --explain`, `rbgp policy explain --direction export` / `ExplainAdvertisedRoute` | RIB | `ExplainAdvertisedRoute` | unbounded | Loc-RIB best, the installed export chain, Adj-RIB-Out for one peer; a dry run of the live staging body | snapshot-able only if the generation carries the installed chain the dry run evaluates; otherwise live |
| `rbgp evpn …`, `rbgp flowspec list`, `rbgp rib bgpls\|vpn\|labeled\|rtc`, `rbgp topology`, `rbgp orr` (eleven RPCs) | RIB | `QueryEvpnRoutes`, `QueryEvpnRoutesPage`, `ExplainEvpnRoute`, `QueryFlowSpecRoutes`, `QueryBgpLsRoutes`, `QueryVpnRoutes`, `QueryLabeledRoutes`, `QueryRtcRoutes`, `QueryOrrTopology`, `QueryOrrStatus` | unbounded | family tables, BGP-LS Adj-RIB-In union, cached ORR state | snapshot-able |
| `rbgp events` route and EVPN history / `ListRouteEvents`, `ListEvpnEvents` | RIB | `QueryRouteEventHistory`, `QueryEvpnRouteEventHistory` | unbounded | actor-owned event rings | snapshot-able |
| `rbgp watch` / `WatchEvents` | both | `Subscribe*Events` | 2 s admission only | returns broadcast receivers | neither (admission only) |
| Periodic BMP stats tick (60 s) | both, from inside the peer manager | `query_state` fan-out; `QueryBmpPeerStats`, `QueryBmpLocRibStats` | 100 ms each | per-session counts; RIB per-peer and per-family counts | mixed |
| BMP Loc-RIB dump, MRT dump, shutdown warm checkpoint | both | `QueryBmpLocRibDump`, `QueryMrtSnapshot`, `QueryWarmMrtSnapshot`, `QueryWarmCheckpointCapture` | chunked or explicit budgets | full tables; per-session generations | snapshot-able for the tables (they *are* snapshots), live for the session generations |

Counts over the rows above, taking `GetPolicyStats` as its three stages and
each joined surface once: **12 snapshot-able, 4 live, 5 mixed**, one
admission-only row, and one row left unclassified. The
`ExplainAdvertisedRoute` row is the one the drafter could not classify with
confidence: the export dry run is pure given its
inputs ([ADR-0103](0103-rpol-execution-model.md)), so it is snapshot-able
if the generation carries the installed chain, and live if it does not.
`PlanConfigTransaction` is listed as snapshot-able but does real resolution
work; it is already budgeted in the owner class, so it is not part of the
inversion either way. The daemon-internal consumers of RIB queries (FIB
reconciler, blackhole limiter, EVPN dataplane) are deliberately out of
scope: they are not operator reads and carry their own generation tokens.

**`policy stats`, end to end.** `GetPolicyStats` in
`crates/api/src/policy_service.rs` runs up to four sequential stages under
one absolute 2 s deadline: peer validation (operator `HasPeerAddress`),
export (`rib_manager_read` of `RibUpdate::QueryExportPolicyTermHits`),
import (operator `QueryImportPolicyTermHits`, whose `deadline` field is the
same instant, so the session fan-out inherits whatever remains rather than a
fresh 2 s), and datasets (operator `QueryPolicyDatasets`). The **export half
is RIB-owned and snapshot-able**: the counters are incremented in the RIB
actor's own export evaluation. The **import half is live**: each session
task evaluates its own import chain and owns its own `ImportPolicyTermHits`;
the peer manager only collects. A generation published by either actor
cannot contain the import counters. If the import half is ever to be
snapshot-able, sessions must publish their own rows — a different design
from "the actor publishes."

### The semantics question

Today a read admitted during prestage or during the cohort transition
observes a **mixed per-session generation**: each session's row reports the
chain that session runs at that instant, so a fleet listing can show both
generations in one response. This is documented operator-visible behavior
(`docs/reference/operations.md`, configuration reload section) and it is
true, row by row.

Each option implies a direction:

- **A and B** keep mixed. Every row is individually current; the fleet is
  not consistent until commit.
- **C** defines the mixture away toward the **last committed generation**:
  a read during the transition reports the pre-commit state for every
  session, including sessions already running the new chain, until the
  actor publishes the post-commit generation. The alternative — publishing
  at transition start — would report the new generation before it is true
  for anyone, which is worse. C therefore means "consistent and up to one
  transition stale"; the live surfaces (import counters) would still show
  the mixture, so `policy stats --direction both` under C reports a
  consistent export half and a mixed import half. That is a documented
  difference, not a hidden one.
- **D** inherits C's direction.
- **E** reports whatever the RIB engine has, mixed, from another process.

Which direction is correct is a product decision this record asks the
maintainer to make explicitly rather than inherit from an implementation.

## The cost of C

Not measured for this draft — no build was run. Stated from the types, at
the flagship shape of 1,000 route-server clients × 400 routes each (400,000
unique prefixes), the shape of the retained
[1,000-peer route-server receipt](../perf/route-server-1000-2026-07.md) and
of the flagship soak.

**Peer generation.** `PeerInfo` (`crates/api/src/peer_types.rs`) is about
seventy-five fields: fixed-width counters and flags, six `String`s
(description, action, last error, authentication, and two optionals), five
`Vec`s (families, required families, inbound limits, paths limits, Add-Path
limits), an `Arc<[u8]>`, an optional negotiated-session block, and an
optional TCP-AO snapshot. Order of one kilobyte per peer including heap;
**about 1 MiB per generation** at 1,000 peers. The size is not the issue.
The cadence is: the counters in those rows change on every UPDATE, so a
generation published only at commit points reports counters as of the last
commit. A generation published periodically (the BMP stats tick already
walks the fleet every 60 s) reports counters up to one period stale. Either
is a defined staleness; today's is "whatever the fan-out returned within 100
ms, or `stale = true`."

**Loc-RIB generation.** `Route` (`crates/rib/src/route.rs`) carries the
prefix, next hop, optional link-local next hop, boxed scope, source peer,
an `Arc<Vec<PathAttribute>>`, a receive timestamp, origin, router ID, and
flags — roughly 100–130 bytes inline, attributes shared by `Arc` and not
deep-copied. A flat copy of 400,000 best routes is **about 50 MiB per
generation** before any index; the previous generation stays resident until
its last reader drops it, so the steady-state cost is up to two
generations. That is inside the ±30–50 MiB run-to-run noise floor the
[memory attribution campaign](../perf/memory-attribution-2026-08.md)
established at 100 peers × 1,000 routes, which means a single run cannot
see it and a median-of-five A/B can.

**Adj-RIB-Out.** 1,000 peers × 400,000 advertised prefixes is 4 × 10⁸
entries. It exists today only because update groups
([ADR-0098](0098-update-groups.md), [ADR-0109](0109-update-group-shared-encode.md))
share one staged table per group. A per-generation copy of Adj-RIB-Out is
not a cost to measure; it is a design C cannot have. Advertised-route
listings under C would have to be answered from the published Loc-RIB
generation plus the published group membership and export chain — i.e. the
`ExplainAdvertisedRoute` dry run per row — or stay actor-served with the
existing version-fenced paging.

**What follows.** C is cheap for the summary surfaces (peer rows, policy
term counters, counts, catalog, event rings, ORR state) and expensive or
impossible for the full tables. A C that copies the tables per generation
is the wrong C; a C that publishes summaries at commit and leaves the paged
listings on the actor is the right one, and it is the one every instance
above would have been served by — all four failures were `rbgp neighbor`
and `rbgp policy stats`, not route listings.

**The measurement that would settle it.** An A/B at the 1,000 × 400 shape
under the attribution campaign's protocol — cgroup `memory.peak` median of
at least five runs per arm, with `memory.swap.max=0` — comparing the
summary-only generation against current source, together with reload
completion p50 from the flagship soak's reload cadence and the soak's
management-plane read-latency gate as the effect measure. The receipt
passes if peak memory moves less than the established noise floor, reload
p50 is unchanged, and the read-latency gate records zero deadline failures
across every reload phase, including rollback.

## What would settle this

1. **The wait-site test matrix** (in preparation): one test per wait site
   that parks the owner and sends a read. It settles B's invariant
   immediately — every site either serves the read or names a per-session
   mutation in flight. Any site that can do neither is a defect regardless
   of which option is chosen.
2. **The rollback fix** (in preparation, instance 4): if it is expressible
   as "flip the flag" the invariant in B is the right abstraction; if it
   needs a new helper or a new lane, per-site admission has run out of
   vocabulary and C is due sooner.
3. **The post-commit tail** (in preparation, instance 3): if it can be
   removed inside the actor, B holds a while longer; if it can only be
   hidden by not entering the actor, that is C's first surface.
4. **The A/B above** for C's memory and reload cost at the flagship shape.
5. **The product decision** on the semantics question: mixed rows, or
   consistent-and-stale.

## Decision (proposed)

The drafter's recommendation, pending the maintainer's decision:

**B now; C for the named summary surfaces once the matrix and the two
in-preparation fixes have landed.**

B first, for two reasons. It is the smallest change that converts the
current practice into a rule with a ratchet, and the ratchet is the part
that has been missing: instances 2 and 4 are both sites that had no
per-session mutation in flight and still fenced reads, which a stated
invariant would have caught on the day the site was written, and a checker
mirroring `scripts/check-clippy-reasons.py` keeps it caught. And B does not
prejudge C: every reason recorded on a readiness-only site is also the
inventory of what C would have to publish to make that site irrelevant.

C second and scoped, for the surfaces the classification marks
snapshot-able and the cost section marks cheap: the peer rows
`ListNeighbors`/`GetNeighborState` read from the peer manager, the export
half of `GetPolicyStats`, the RIB per-peer snapshot behind `rbgp neighbor`,
and the readiness `ListPeers`. Those are the four surfaces the four
instances were about. C is **not** recommended for the paged route
listings, the explain surfaces, or anything that reaches a session task,
and it is not recommended before the semantics question is decided,
because C is the option that changes what an operator sees during a
transition. D is deferred until a joined surface measurably needs it. E is
declined.

If the maintainer prefers A, the classification table and the constants
table above are still the reference for the next instance. If the
maintainer prefers C outright, the cost section says which C.

## Consequences

If accepted as proposed:

- **Positive.** The readiness-only wait becomes the exception that
  explains itself; a reviewer can see, at the call, why a read is fenced.
  The next fenced wait fails a checker and a matrix test instead of a
  soak. For the summary surfaces, a later C removes the read's dependency
  on the owner altogether, and the read budgets can be what they look like
  — bounds on the read — rather than a race against a 2-minute owner.
- **Negative.** Seventeen reasons to write and keep true; one more checker
  with companion tests; and for C, a defined staleness on the summary
  surfaces where today's behavior is "current or `stale = true`". Operators
  reading `rbgp neighbor` during a reload would see the last commit rather
  than the live mixture. The documentation that currently describes the
  mixture would change with it.
- **Neutral.** The live surfaces (`policy stats --direction import`,
  `policy explain --direction import`, `rib received --rejected`,
  readiness `Ping`) stay on the actor under every option; their budgets
  remain read-class budgets against an owner-class actor, mitigated by
  admission and by the per-session bounds that already exist. A future
  "sessions publish their own rows" design would move the import counters
  into C's scope; it is not part of this record.
- **Unchanged.** `RIB_BATCH_REPLY_TIMEOUT` and the owner budgets are not
  in question; they bound real work. The atomic commit remains the single
  switch point, and the ordinary command channel remains unpolled during
  every transaction wait, so mutations are never admitted mid-transaction
  by any option here.
