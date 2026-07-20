# ADR-0105: Grouped export-policy transition transaction

**Status:** Accepted
**Date:** 2026-07-14

## Context

A live policy reload can move hundreds of route-reflector or route-server
sessions from one export policy to another while all of them share an update
group. Rebuilding the destination table and probing every outbound route once
per peer made that common case scale as routes times peers. The optimized path
now shares the work, but spans two single-owner actors, a narrow fast path, a
mixed-fleet partition, compensating rollback, and a readiness bypass. This ADR
records that design as built. It does not broaden the fast path or change its
behavior.

The separately proposed continuation for the ordinary authoritative per-peer
fallback is described in
[ADR-0111](0111-authoritative-policy-replacement-continuation.md); it does not
alter this cohort transaction unless accepted and implemented.

"Atomic" has two different scopes here. The RIB's clean cohort commit is
observationally atomic inside the RIB actor: ordinary RIB work cannot observe
staged state, and no member changes group or receives the new payload before
the final commit. The complete PeerManager transaction is rollback-capable,
not fleet-wide observationally atomic. Session commands and an authoritative
remainder run one peer at a time, and a failed compensating rollback can leave
state that must be retried.

## Decision

### 1. Ownership and fences

PeerManager is the sole owner of the live-policy transaction. It resolves and
captures prior session policies, selects an optional fast-path cohort, applies
session policy commands, submits RIB work, applies the remainder, and owns
commit or compensating rollback even if the original caller disappears. While
it awaits a session or RIB reply, it services only its dedicated, read-only
`ListPeers` readiness lane. Its ordinary command receiver remains behind the
transaction.

RibManager accepts at most one `ReplacePeerExportPolicies` transition at a
time. Once accepted, `pending_clean_policy_transition` is the actor's sole
transition owner. The run loop advances one state-machine poll, services only
the dedicated `LocRibCount` readiness lane, yields, and repeats. General
queries, route mutations and batches, resync, refresh, GR/LLGR work, and timers
remain queued until commit or a cleaned-up fallback handoff. Dropping the
reply receiver does not cancel the actor-owned work.

This fence is what makes the RIB-local commit observable as one transaction.
It also means every additional synchronous poll directly delays all ordinary
RIB work, so the fast path stays deliberately narrow.

### 2. Policy cohort, wire cohorts, and remainder

PeerManager chooses at most one policy cohort. A local O(targets squared) pass
selects the largest structurally equal pair of installed and target export
chains; equal-size pairs tie-break by their lowest canonical `PeerKey`. Only
locally eligible targets for that winning pair are queried, in caller order,
and only Established peers enter the cohort. Import changes are tolerated:
cohort setup hot-applies them per member and defers Route Refresh until after
the batched RIB commit. Fewer than two Established winners disables the cohort
without trying a runner-up. Everything not selected remains in its original
order in the authoritative remainder; the algorithm does not recursively find
a second cohort. State queries run sequentially and each is bounded by the
100 ms peer-query timeout, so wedged winning sessions cost up to one timeout
each while the PeerManager actor services only its readiness lane.

The policy cohort is not a wire-equivalence cohort. RibManager independently
revalidates update-group source and destination, clean state, live session and
encoder identity, and groups exact-export probes by compatible wire snapshot.
Successful probes may be shared within a wire cohort because the staged
payload is identical; each compatible member still checks the largest encoded
message against its own negotiated ceiling. The pass-local cache retains at
most eight wire cohorts per update group. A profile beyond that bound takes
the ordinary exact-probe path rather than growing retained state.

The fast RIB path accepts only clean, grouped-to-grouped, plain single-best
unicast members moving across one source/destination group pair. Clean
requires zero policy-filtered routes in both the source and destination
groups, so the fast path covers only permit-set-preserving (attribute-only)
policy changes; a policy that filters even one route always falls back. Dirty
or forced members, Add-Path, per-client-best, ORF, RTC, VPN or other private
family state, selection gates, stale generations, closed or saturated writer
channels, and exact-export rejection cause a fail-closed handoff before the
first optimized emission. PeerManager then performs ordinary authoritative
RIB replacements for the entire selected policy cohort, one peer at a time,
without hot-applying the session chain a second time.

### 3. The six RIB phases

The actor-owned transition has exactly six phases:

1. **Classify** examines at most eight members per poll, rejects duplicates or
   non-clean members, and proves that the complete cohort has one update-group
   source/destination pair.
2. **StageDestination** creates the unowned destination group when needed,
   takes one complete Loc-RIB prefix-identity snapshot, and builds the
   destination table in chunks of at most 1,024 identities per production
   poll. An already-maintained destination skips the build.
3. **BuildInventory** takes one complete destination-table route-key snapshot,
   then builds the immutable announce, next-hop, and policy-counter inventory
   in chunks of at most 1,024 keys per production poll.
4. **ProbeAndPrepare** exact-probes at most 1,024 announcements per poll for a
   new wire profile, reuses a successful profile's largest encoded length when
   compatible, and reserves each member's outbound writer permit. It emits
   nothing.
5. **Validate** revalidates every session, sender, encoder owner/generation,
   clean-state predicate, group pair, and reserved permit in one actor poll.
   It is the last phase that can fall back; it emits nothing.
6. **CommitMembers** changes memberships, replays counters, and sends the
   shared `Arc` payload through each member's reserved permit in bounded
   batches of at most eight members per poll, draining committed members so
   parked state shrinks monotonically. Once the first batch has emitted,
   later polls only continue or terminate committed — per-batch revalidation
   is deliberately absent because the actor fence admits only the read-only
   readiness lane between batches, and a receiver dropped mid-flush is
   benign (permits are pre-reserved, sending on a closed channel is a no-op,
   and the queued `PeerDown` cleans up after the fence lifts). The terminal
   batch then runs the global `distribute_changes(empty, empty)` retry
   opportunity before replying, so unrelated dirty or forced peers can drain
   promptly rather than waiting for the retry timer.

No phase before `CommitMembers` changes committed membership, policy,
counters, or wire state. On fallback, reserved permits are released and a
destination created by this transition is removed only if it is still
unowned. Failure to prove safe cleanup is an error rather than a per-peer
handoff.

The 1,024-route budget does not bound the two snapshot polls. The initial
Loc-RIB prefix snapshot is O(Loc-RIB entries) in one actor poll; the later
destination-key snapshot is O(destination entries) in one actor poll. They
provide stable identity vectors for the chunked bodies, at the cost of two
full-table allocations and two scheduler-visible, data-dependent polls.
`CommitMembers` bounds the commit/flush body to eight members per poll, but
the terminal batch's global retry tail still enumerates outbound peers and
can perform full Loc-RIB/Adj-RIB-Out work for unrelated dirty or forced
peers. The terminal poll's work shape can therefore reach
O(outbound peers + table entries times dirty/forced peers). These are
explicit bounds of the current model, not claims of constant-time actor
latency.

### 4. Cross-partition apply and rollback order

PeerManager hot-applies the selected cohort's session export chains in caller
order, then asks RibManager to commit the cohort or return a cleaned-up
handoff. After the cohort succeeds, it applies the remainder authoritatively
in original caller order. Import-policy changes and other non-cohort shapes
always use this authoritative path.

Each authoritative failure first compensates the peers changed by that helper,
newest first. If the remainder fails, PeerManager next restores the already
committed cohort, also newest first. Restore attempts continue after an
individual error so the reply contains the composed failures. A successful
rollback restores the captured priors; a failed rollback returns an error and
leaves retry intent where the existing per-peer path can preserve it. A later
persistence failure replays the successful transaction's returned prior token
through the same transaction owner.

Rollback session and bookkeeping restoration remains newest first and may do
O(peers) bounded session work. RIB compensation has one lazy absolute
five-second deadline per top-level policy transaction, shared by authoritative
self-heal and any later cohort unwind. Each partition first-polls every pinned
RIB restore future newest first, without Tokio's cooperative budget, before it
issues any rollback Route Refresh. This registers every bounded-channel waiter
in FIFO order; refresh-generated route work and later peer lifecycle mutations
cannot overtake a restore merely because the channel is full.

PeerManager then awaits the registered aggregate while continuing to service
readiness. Deadline expiry or caller cancellation detaches that same aggregate
rather than reconstructing commands: already-registered repairs may finish in
order after the caller returns, while conservative per-peer pending flags keep
explicit retry intent. The five-second claim bounds cumulative rollback RIB
send/reply waiting across all partitions. It does not bound sequential session
commands, Route Refresh acknowledgements, or the RIB actor's late repair work.

### 5. Readiness and observability

The read-only readiness lanes exist so a legitimate large transition does not
depool a healthy daemon merely because normal actor work is fenced. Each RIB
seam drains at most eight readiness queries, and PeerManager services live
peer snapshots while awaiting owned session or RIB work. Readiness can
overtake queued ordinary commands but cannot preempt a RIB poll that is already
running.

Production exposes transition-in-progress and last-total-duration gauges,
emits one slow warning after five seconds, and records every real actor poll in
`bgp_rib_policy_transition_actor_poll_duration_seconds{poll_kind}`. The four
bounded label values separate chunked work (`bounded`), the two complete table
snapshots (`prefix_snapshot`), the pre-commit validation poll (`finalize`),
and the bounded member commit/flush batches (`commit`, whose terminal batch
includes the global dirty/forced retry tail) so an operator can distinguish a
long transaction from one long single-threaded poll.

Readiness remains successful during legitimate bounded progress, but the
dedicated RIB lane returns a typed stalled verdict once the transition's one
monotonic ownership clock reaches 30 seconds. HTTP `/readyz` and gRPC health
then fail closed with `RIB export-policy transition stalled`. Terminal commit
or cleaned-up fallback removes that verdict at the same actor seam. The
ordinary `QueryLocRibCount` contract remains unchanged; no general query is
admitted through the readiness lane.

## Evidence and earns-its-keep review

The integrated receipt compared base
`a170ab0f38fd97cc294d56ba5f283c7221c2c166` with candidate
`fa2759e9b19ecbc00f245c6d07e520e8f28e0882`. The same frozen candidate harness
drove serial, non-overlapping real daemon runs with 700 real BGP sessions, the
production exact-export encoder path, and 400,400 IPv4-unicast routes. Of those
sessions, 600 changed policy through one cohort and 100 content-stable sessions
formed the remainder. Every measured cycle finished with 700/700 sessions up,
fresh stable-peer markers, and zero parser errors. Relative to that control,
median completion p50 improved from 220.148412 seconds to 1.894807 seconds
(116.185x), and median completion maximum improved from 436.698156 seconds to
2.925734 seconds (149.261x). Structured production logs prove that each
candidate cycle performed one committed 600-member RIB batch and zero
authoritative per-peer RIB commands; the base performed 600 authoritative RIB
commands and zero batches per cycle. The exact provenance, raw rows,
production-event summary, checksums, and reproduction steps are in the
[integrated receipt](../perf/artifacts/policy-reload-cohort-partition-2026-07/README.md).

That speedup has a real availability cost. Median full-fleet delivery-gap p50
grew from 976.8845 milliseconds to 2022.590 milliseconds (2.070x), and median
maximum grew from 1002.756 milliseconds to 2906.551 milliseconds (2.899x).
The fast path therefore earns its current narrow role by removing hundreds of
repeated O(table) rebuilds, not by improving every latency dimension.

The scheduler receipt used the production state-machine seam and real session
encoders. Before each multi-peer iteration reaches `black_box`, the in-code
`assert_shared_transition_receipt` guard in
`crates/transport/benches/fanout.rs` asserts one shared plan, exactly one full
probe and route-shell materialization per route, and zero authoritative
per-peer applies. Its 65,536-route/64-peer workload recorded a 4.927 ms maximum
actor poll, which was also the slower of the two full-snapshot polls. A
separate 4,096-route/700-member clean fixture recorded a 2.001 ms finalization
poll; it had no unrelated dirty/forced residue to exercise the global retry
tail. These are measured cells, not extrapolated upper bounds for a
400,400-route table, a residue-bearing finalization, or another host. The two
O(table) snapshots and the data-dependent finalization retain no hard
wall-clock guarantee. See the
[actor-poll receipt](../perf/policy-regroup-shared-plan-2026-07.md#actor-poll-receipts).

- **Outer config and persistence rollback:** keep. Returning captured priors
  lets the config transaction restore runtime policy after a later persistence
  failure. The cost is a second compensating transaction whose failure must be
  surfaced rather than described as atomic.
- **Session hot-apply:** keep. It changes live import/export chains without
  rebuilding TCP sessions or the BGP FSM. The cost is sequential peer commands,
  transient cross-peer skew, and another state surface that rollback must
  restore.
- **Single policy cohort plus remainder:** keep. It captures the measured
  dominant shape without forcing content-stable or otherwise ineligible peers
  through the RIB batch. Multiple simultaneous policy cohorts would multiply
  state and rollback edges without current demand evidence.
- **Actor fence, single RIB owner, and six phases:** keep. Together they buy
  an auditable, observationally atomic RIB commit while bounded bodies provide
  scheduler opportunities. The cost is queued normal work; the two snapshot
  polls and the terminal global retry are not bounded by the route chunk
  size, though the member commit/flush loop now is (eight members per poll).
- **Immutable inventory and wire-cohort probe sharing:** keep. They change
  staging and exact probing from routes-times-peers toward
  routes-times-compatible-profiles while retaining per-session generation and
  message-ceiling checks. The eight-entry retention bound prevents adversarial
  profile growth.
- **Authoritative remainder and compensating rollback:** keep as the complete
  fallback and mixed-fleet correctness path. It handles every shape the fast
  path rejects. Its session work remains sequential, but cumulative rollback
  RIB send/reply waiting is bounded by one transaction-wide deadline; retaining
  pinned late repairs and conservative retry flags is the cancellation cost.
- **Final global retry opportunity:** keep until production poll data says
  otherwise. It promptly drains unrelated dirty/forced residue before the
  successful transaction reply, matching the authoritative replacement seam.
  Its cost is an unchunked global retry opportunity inside the terminal
  `CommitMembers` batch; use the production poll histogram before optimizing
  or relocating it.
- **Read-only readiness isolation:** keep. It avoids false depools during
  normal transactions, then fails closed at 30 seconds so a true soft wedge is
  automatically depooled. Its cost is a second narrow channel and one
  ownership-age check at each readiness seam.

This review found no existing layer that can be removed without discarding a
measured benefit or a correctness boundary. The complexity that is not paying
for itself is prospective generalization beyond the measured shape; the
following choices keep that complexity out rather than adding it speculatively.
The one plausible measured-path simplification is the second inventory pass
for a newly created destination: its staging deltas might eventually feed the
inventory directly. Do not make that change without first measuring the
snapshot poll in production and proving identical inventory and fallback
semantics for both newly created and already-maintained destinations.

## Rejected scope and simplifications

- Do not generalize the partition into a multi-cohort planner. Revisit only if
  a measured fleet regularly leaves another large compatible cohort in the
  remainder.
- Do not broaden the fast path to Add-Path, per-client-best, VPN, RTC, ORF, or
  other private-family state. The authoritative path is the safe fallback.
- Do not rebuild the transaction around a general RIB scheduler or a parallel
  RibManager. First measure a production single-actor ceiling.
- Do not replace the two snapshots with a new cursor protocol solely because
  they are O(table). Use the production poll histogram to observe a real
  breach, then choose the smallest scheduler repair.
- Do not redesign or chunk member resync in this consolidation phase. The
  delivery-gap receipt makes that a legitimate future target, but changing its
  emission model belongs in a separately measured and reviewed transaction.
- Do not introduce a fleet-wide two-phase commit protocol for session tasks
  and the RIB. The current single-owner plus compensating rollback is adequate
  for the measured route-reflector/route-server workload with the rollback's
  aggregate RIB wait bounded.

## Consequences

- Contributors have one map of the transaction boundaries and can distinguish
  the PeerManager policy cohort from RIB wire-equivalence cohorts.
- The optimized RIB cohort remains all-or-nothing and hidden from ordinary RIB
  observers until finalization; the complete cross-actor transaction remains
  explicitly rollback-capable rather than strictly atomic.
- Normal RIB work may wait behind the transaction. Dedicated read-only
  readiness lanes remain responsive at actor seams, but an owned transition
  reports stalled from 30 seconds until terminal commit or cleaned-up fallback.
- The current implementation deliberately retains two O(table) snapshot polls,
  a terminal commit batch whose global dirty/force retry tail is data-
  dependent, a single-cohort partition, and a sequential authoritative
  remainder. The member commit/flush loop itself is bounded to eight members
  per poll (LAN-447).
- The measured completion win is retained together with its measured delivery-
  gap regression. Neither the ADR nor the microbenchmark receipts turn that
  regression into a success claim.
