# ADR-0111: Actor-owned authoritative export-policy replacement continuation

**Status:** Proposed
**Date:** 2026-07-20

## Context

ADR-0105's grouped policy-transition path keeps its optimized cohort work
inside a fenced, actor-owned transaction. A retained 1,000-peer heterogeneous
reload receipt showed that path behaving as designed: the 600-peer cohort
committed with bounded RibManager polls. The subsequent 400-peer authoritative
remainder, however, held the RibManager in a single synchronous
`ReplacePeerExportPolicy` command long enough for the 200 ms readiness probe to
time out. The authoritative replacement did eventually finish.

This is evidence of a readiness-liveness gap in the ordinary per-peer fallback,
not evidence that the RibManager must be sharded. ADR-0100 remains gated on a
measured single-actor ceiling. The smaller design question is whether one
authoritative replacement can retain its current semantics while becoming
resumable within that same actor.

The current command is deceptively broad. It changes installed policy and
update-group membership, reconstructs the conservative prior-emission state
needed by regroup, and runs a full empty-distribution pass that may repair
unrelated dirty or forced peers.
It also preserves exact-export precommit, send/Adj-RIB-Out ordering, residue,
End-of-RIB duties, and last-group cleanup. Splitting only the obvious route loop
would create false readiness without preserving these safety properties.

Tokio does not make an inline synchronous branch preemptible. Its
[`select!` documentation](https://docs.rs/tokio/latest/tokio/macro.select.html#runtime-characteristics)
states that branches run concurrently on the current task, not in parallel, so
one blocking branch prevents the others from progressing. The existing
readiness-lane pattern instead requires the actor to return control between
bounded continuation polls. A type-narrow drain may use
[`Receiver::try_recv`](https://docs.rs/tokio/latest/tokio/sync/mpsc/struct.Receiver.html#method.try_recv),
which immediately distinguishes an empty channel from a disconnected one and
does not report spurious `Empty`. A cooperation point may use
[`yield_now`](https://docs.rs/tokio/latest/tokio/task/fn.yield_now.html#non-guarantees),
but Tokio explicitly permits the same task to be polled again immediately and
may prevent a yield inside `select!` from reaching the executor. These are
scheduling mechanics, not a hard wall-clock guarantee.

## Decision

This ADR proposes an actor-owned continuation for
`RibUpdate::ReplacePeerExportPolicy` only. It does not authorize an
implementation. The existing six-phase `ReplacePeerExportPolicies` clean-cohort
transaction, PeerManager ordering, the existing RIB reply and aggregate
rollback deadlines, and the cohort/remainder partition remain unchanged.

### Ownership and isolation

RibManager remains the sole owner of canonical RIB, update-group, policy, and
Adj-RIB-Out state. It may own at most one clean or authoritative policy
transition at a time; the two continuation types are mutually exclusive.
Acceptance transfers the authoritative command, its reply sender, and all
staged work into RibManager-owned state. Dropping the reply receiver does not
cancel accepted work. In particular, PeerManager's existing five-second RIB
reply timeout may drop that receiver while the accepted forward owner is still
running. The owner must finish normally; any rollback replacement registered
after the timeout remains ordered behind it in the RIB channel and runs only
after the forward owner reaches a terminal state. The continuation must not
turn receiver closure into cancellation or let rollback overtake the accepted
forward command.

While an authoritative continuation is pending, RibManager services only its
read-only `RibReadinessQuery` lane between polls. General queries, route
mutations and batches, resync, refresh, GR/LLGR work, timers, and session
lifecycle updates remain queued. Readiness reports Loc-RIB state through the
existing lane and reuses the existing 30-second owned-transition age check,
metrics, and stalled verdict. It must not expose partially staged policy state.

The continuation owns, rather than borrows across polls:

- the target peer and policy, prior membership identity, reply sender, start
  time, and slow-warning state;
- baseline and residue builders plus peer, workset, group, route-key, family,
  overlay, residue, candidate, and cleanup cursors;
- the unowned destination-group build and pass-local `ExportMemo` and exact
  probe caches;
- the staged outbound envelope, exact-export snapshot/batch continuation, any
  reserved permit, and the post-send Adj-RIB-Out commit cursor; and
- bounded retired-group, overlay, residue, and metrics cleanup state.

Creating the peer workset is itself resumable. The implementation must not hide
an O(peers) `collect`, or a data-dependent `retain`, clone, drop, or destructor
tail, at a phase boundary.

The cooperative destruction bound applies to every normal terminal path,
including primary-channel closure: an accepted owner finishes and incrementally
retires its state before the run loop observes shutdown. External actor-task
abort and process/runtime teardown cannot receive further continuation polls
and are outside the actor-readiness latency contract. They must not be modeled
as command cancellation or a transactional rollback; all normal exits still
need bounded retirement rather than relying on a final large `Drop`.

An in-progress destination prestage remains behind the same fence. A matching
partial destination must be detached for bounded discard rather than adopted;
an unrelated prestage stays paused until the authoritative owner releases.

### Irreversible boundary

`CommitMembership` is the explicit irreversible boundary.

Before that phase, all destination and baseline work is detached or unowned.
Installed policy, update-group membership, emitted wire state, and Adj-RIB-Out
remain unchanged. Any failure may discard the staged work and return an error.

At `CommitMembership`, the target policy and group membership become canonical.
After that point the continuation must not invent transactional rollback.
Failures follow the current authoritative path's fail-closed repair contract:
dirty state and residue remain available for retry, and cleanup runs to a safe
bounded stopping point before the command completes or reports failure.
Ordinary post-commit output failure currently retains dirty, residue, or sparse
rejection-overlay repair state and completes the RIB command with `Ok`; it is not
promoted into a command error. The continuation preserves that result contract.

Transport currently validates an outbound snapshot's concrete profile type and
owner, but does not compare its generation with the encoder's current
generation. A continuation that parks a snapshot across polls must therefore
revalidate the current encoder owner and generation in the RIB immediately
before the irreversible send. This is a new continuation stale-plan fence, not
an existing transport check. Owner or generation drift after
`CommitMembership` is not a transaction abort: emit nothing, do not advance
Adj-RIB-Out, retain the peer's dirty/residue state for a later repair pass, and
do not roll membership back.

### Seven continuation phases

1. **Validate.** Resolve the peer and policy, return `NotFound` or the current
   content-equal no-op where applicable, and capture the canonical prior
   identity. This phase is table-independent; policy comparison may still be
   proportional to the bounded configured chain.

2. **CaptureBaseline.** Incrementally reconstruct the prior unicast and VPN
   regroup state, including route-server control, RTC, rejected overlays,
   tombstones/extras, and the Adj-RIB-Out seed. A clean move may retain its
   equality-suppression baseline. A dirty group leaver's snapshot is intended
   group state, not proven wire state: convert its keys, any retained baseline,
   and tombstones into conservative extra-withdraw residue, then take the
   suppression-free resync path. Cursors cover every group, residue, overlay,
   route-key, family, and candidate scan; no container is flattened merely to
   make it resumable.

3. **PrepareDestination.** Incrementally build an unowned destination group
   with the pass-local memo. Skip construction when the destination already
   exists. No installed policy or membership changes in this phase.

4. **CommitMembership.** In one bounded actor poll, install the canonical
   target policy, using the destination group's shared `PolicyChain` instance
   when grouped, perform the existing leave/join and baseline carry, and mark
   the target dirty. VPN member counts and other table-derived values are
   prepared earlier; an old per-peer table or last-member source group is
   detached into retirement state rather than cleared or dropped here. This is
   the first canonical mutation and the irreversible boundary.

5. **InitDistribution.** Initialize the exact current
   `distribute_changes(empty, empty)` pass. Preserve its complete outbound-peer
   traversal and order, including clean peers and any non-resync side effects;
   the target plus every unrelated dirty or forced peer still receive their
   current resync treatment. Build and traverse that workset incrementally
   without O(peers) collection, invalidate advertised paging exactly once, and
   retain pass-local memo and exact-probe caches for the entire distribution
   pass.

6. **ResyncPeers.** Resume at peer, family, route-key, and candidate granularity
   while preserving all existing grouped and ungrouped behavior, Add-Path,
   ORR/per-client best, every supported family, OTC and policy filtering,
   rejected-route overlays, residue, and End-of-RIB duties. Preserve exact
   probe order, cardinality, and cache lifetime. Reserve and send each staged
   envelope once; commit Adj-RIB-Out only after that send succeeds. The current
   synchronous path instead holds a borrowed `Permit<'_>`, commits Adj-RIB-Out,
   and consumes the already-reserved permit in one non-yielding frame; the
   reservation makes that final enqueue infallible. A continuation cannot park
   that borrow or split that proof implicitly. It needs an explicit owned
   permit/send/commit protocol that names the irrevocable send point, preserves
   repair state across every later commit poll, and cannot duplicate or skip an
   envelope on retry. Channel failure keeps the peer dirty and retains residue.
   Per-candidate exact-export rejection suppresses that announcement, persists
   the sparse rejection overlay, and stages an owed withdrawal when the
   identity was previously advertised. Whole-envelope owner/generation drift
   emits nothing and does not advance Adj-RIB-Out.

7. **RetireAndFinish.** Incrementally retire an empty prior group and its
   route-bearing storage, prune overlay/residue maps, and update counters and
   gauges. Early-empty paths and destructor tails are bounded. Reply only after
   the complete global empty-distribution pass, including unrelated dirty or
   forced peers, reaches its existing terminal state.

### Cooperative poll target

Each poll has a soft cooperative target of at most 64 complete identities or
candidates, or about 25 ms of elapsed work, whichever comes first. The check
occurs only after a complete atomic operation, and every phase and peer boundary
is a cooperation point. Candidate-level checks are required because one
Add-Path or ORR prefix can contain a data-dependent number of candidates.

This is deliberately not a hard latency or performance claim. An individual
atomic work unit may exceed the target, and `yield_now` does not guarantee that
another task runs. No poll may contain an O(table), O(paths-in-prefix), or
O(peers) collect, drop, retain, batch, or commit merely because a timer is also
checked around it.

### Preserved invariants

An implementation must preserve all of the following:

- one canonical actor owner and non-cancellation after an accepted reply is
  dropped;
- per-key FIFO emission and at most one mixed-family envelope for the same
  staged operation;
- membership commit before resync, with no send before the destination and
  conservative prior-emission state are fully staged;
- exact owner, generation, negotiated message ceiling, probe cardinality,
  per-candidate rejection/owed-withdraw reconciliation, and probe-cache
  lifetime;
- one reserve/send attempt for each envelope and Adj-RIB-Out commit only after
  successful send;
- fail-closed dirty/residue retention, withdrawals, and End-of-RIB duties on
  rejected or failed output;
- selection-deferral gates, session-generation fencing, and stale-session
  rejection;
- content-equal policy identity/counter behavior and lossless last-group
  baseline handling;
- the complete outbound-peer distribution pass and its current ordering before
  replying, including unrelated dirty/forced resync work;
- the general-observer fence, with only the read-only readiness lane admitted;
  and
- queued `PeerDown` and all other general work remaining ordered behind the
  owned continuation.

This proposal changes no address family, wire encoding, cohort eligibility,
PeerManager rollback, policy semantics, or sharding boundary.

### Feasibility gates

Implementation remains **NO-GO** until both gates have concrete, reviewed
prototypes:

1. **True resumable container ownership.** Demonstrate owned cursors across
   every route-bearing container and every peer/workset/group/residue/overlay/
   candidate scan, plus bounded cleanup, retirement, and destruction, without
   O(peers) or O(table) collection. Existing unicast pieces are not sufficient:
   the Loc-RIB ordered index may rebuild lazily in O(table), while other-family
   maps remain raw `FxHashMap`s. The strategy must neither regress maintained
   hot-path indexes nor duplicate route bodies.

2. **Object-safe exact-export continuation.** Demonstrate an owned batch
   continuation through the exact-export interface. Prepared
   `SessionExportProfile` attribute and encoded-length caches must survive
   polls while preserving ordered scalar/cardinality fail-closed semantics,
   without unsafe code or self-referential borrowing. The same prototype must
   demonstrate the owned permit/send/commit protocol; changing the permit type
   without proving the one-send and post-send repair boundaries does not pass
   this gate.

Passing these gates permits an implementation proposal and review; it is not
approval to merge production code. Stop and revisit the design if a prototype
requires a worker task/thread or lock around canonical RIB state, changes wire
or rollback semantics, services general work through the fence, leaves an
unbounded table-, peer-, or paths-per-prefix aggregation, retain, clone,
commit, cleanup, or destructor in one poll, or expands into a scheduler or
sharding rewrite.

### Load-bearing validation plan

A future implementation must dispatch a real `ReplacePeerExportPolicy` command
and prove readiness at exact production cursor sentinels. Coverage must include
Add-Path/ORR candidate-level continuation; mixed families; last-member and
cleanup tails; unrelated dirty/forced peers; the general-work fence; a dropped
reply and the five-second forward-timeout/FIFO-rollback ordering; send failure
and exact-export rejection; a real
`SessionExportProfile` cache surviving polls; scalar/cardinality probe fallback;
per-candidate rejection-overlay and owed-withdraw reconciliation; and the
30-second stalled verdict under virtual time. Primary-channel closure must prove
the accepted owner reaches terminal bounded retirement before actor shutdown.
Independent sentinel values must identify the production subwalk so that a
shared phase bitmask cannot make the suite vacuously green.

For each test, the implementation PR must state the production break that makes
it red: removing the relevant cursor check, fence, ownership transfer,
commit-after-send rule, failure residue, cache continuation, or stalled-age
check. A test that remains green with its guarded logic reverted must be
rewritten.

Load-bearing test mutation proof for this docs-only change: N/A. No test or gate
is added or modified.

## Consequences

This ADR supplies a reviewable map for fixing the observed readiness gap
without broadening the grouped transaction or treating sharding as the default
answer. It makes the irreversible boundary and the existing post-commit repair
semantics explicit before any code moves.

If both feasibility gates pass, ordinary authoritative replacement can be
structured so readiness gets cooperation opportunities while general actor
traffic remains intentionally fenced. The design is nevertheless invasive:
it must externalize several nested walks, cache lifetimes, and cleanup tails.
Implementation may remain blocked if that cannot be done without weakening
correctness or complicating the normal hot path.

No runtime behavior changes with this ADR. It makes no performance claim and
does not authorize implementation.
