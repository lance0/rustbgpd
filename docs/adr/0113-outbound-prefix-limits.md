# ADR-0113: Per-peer outbound unicast prefix limits

**Status:** Proposed
**Date:** 2026-07-21

## Context

An IX route server or route reflector can have a syntactically valid policy
change that makes a much larger outbound table eligible for one client. The
existing import-side `max_prefixes`, `max_prefixes_ipv4`, and
`max_prefixes_ipv6` controls protect rustbgpd from a peer's input; they do not
bound the routes rustbgpd exports. A bad export policy can therefore grow one
client's Adj-RIB-Out to the full table before an operator notices.

No RFC defines outbound maximum-prefix behavior. [RFC 7454 section
8](https://www.rfc-editor.org/rfc/rfc7454.html#section-8) recommends limits on
routes *accepted from* a peer, not routes advertised to it. [RFC
7911](https://www.rfc-editor.org/rfc/rfc7911.html) identifies an advertised
route by `(prefix, Path Identifier)`. Counting distinct prefixes instead is an
intentional product decision here; the RFC prescribes neither that count nor a
limit response.
The behavior below is therefore a product contract, not a protocol compliance
claim.

### Current outbound ownership

The RIB manager owns export policy, RFC 9234 OTC filtering, exact-export
precommit, and Adj-RIB-Out truth. The transport consumes an already-admitted
route envelope and is not the right owner for a local capacity policy.

[ADR-0098](0098-update-groups.md) complicates the storage boundary. An
ungrouped peer has a private `AdjRibOut`. A grouped unicast member does not:
one `GroupRibOut` holds post-policy staged intent and the member's advertised
projection is the group table minus split horizon and its sparse exact-export
rejections. `GroupKey` intentionally contains only shared staging inputs.
Putting a per-client limit in that key would fragment the dominant route-server
fanout case.

The final per-member commit path already orders selection-deferral, policy and
OTC results, exact wire-form rejection, private Adj-RIB-Out mutation, and
enqueue. The limit belongs at that seam: after every reason a candidate is
ineligible for this peer, but before a private table or the limited grouped
member's admitted overlay advances. The shared group table remains staged
intent and can advance before an individual member send, as ADR-0098 specifies.

## Decision

This ADR proposes an implementation contract. It does not authorize feature
code in this tranche.

### Scope and configuration

Add optional non-zero `max_prefixes_out_ipv4` and
`max_prefixes_out_ipv6` fields to `[[neighbors]]` and peer groups. A neighbor
value overrides its group; an absent neighbor value inherits; an absent
effective value means unlimited. Accepted dynamic children inherit the
effective values of their configured peer group. There is no aggregate
outbound limit.

Only IPv4-unicast and IPv6-unicast are in scope. VPN, labeled unicast,
FlowSpec, EVPN, BGP-LS, and RT-Constrain do not count and are not gated. There
is one action: block excess new prefixes while keeping the BGP session
Established. There is no warning-only/restart/disable mode, Cease or other
NOTIFICATION, transport dependency, or update-group split.

With both limits absent, the distribution path and state shape remain the
current unlimited path. In particular, an unlimited grouped member gains no
per-route state and no per-route limit check.

### Admission and counting

Enforcement consumes the final per-peer unicast announcement and withdrawal
vectors after export policy, split horizon, OTC, and exact-export precommit.
It runs before private Adj-RIB-Out or a limited grouped member's admitted
overlay is mutated and before the envelope is enqueued. The grouped intent
table can already reflect the staged route. Routes rejected by any earlier
gate consume no capacity.

Each family counts unique network prefixes, not route identities. For
Add-Path, every path ID for one NLRI consumes one slot in total. A new path ID
for an admitted prefix is an update, not a new prefix. A prefix stops consuming
a slot only when its last advertised path is withdrawn.

For each family and batch, the gate computes the post-withdraw projection
first. Withdrawals always pass, including when usage is already at the limit,
and a withdrawal of the last path frees its slot before announcements are
considered. It then applies these rules:

1. announcements for a prefix still admitted after the withdrawals always
   pass, including attribute changes and new Add-Path path IDs;
2. a net-new prefix passes and becomes admitted while usage is below the
   limit; and
3. a net-new prefix at the limit is removed from the outgoing vector and never
   enters Adj-RIB-Out.

All paths for a newly admitted prefix in the same batch share its single slot.
The implementation may use the manager's existing batch order to choose among
several simultaneous net-new prefixes; this ADR does not create a route
preference or best-path rule at the capacity boundary.

An exact-export rejection of a previously admitted route can synthesize a
withdrawal. That withdrawal frees capacity before any remaining exact-exportable
announcement in the batch is considered. The limiter must not mask an owed
exact-export withdrawal. For grouped peers, advertised-route queries retain
ADR-0098's intended-state semantics: the shared group table may advance before
member send, and dirty resync heals a failed or skipped delivery. This ADR does
not add per-member route bodies or promise wire-acknowledged grouped query state;
only the bounded admitted-prefix overlay changes at the reserved member
commit/enqueue seam.

### State without update-group fragmentation

For an ungrouped limited peer, its private `AdjRibOut` prefix index is the
authoritative admitted set and supplies unique-prefix counts, including
Add-Path refcounts. No duplicate rejected-route inventory is added.

A limited grouped member is the explicit exception to ADR-0098's O(1)
per-member unicast state: the RIB manager keeps a prefix-only admitted set for
each limited family. It is bounded by that family's configured limit.
Grouped advertised iteration and counts become:

`group intent - own source - exact-export rejection, intersect admitted prefixes`.

The set is per member, never part of `GroupKey`, and the shared group table
continues to stage once. A grouped batch that fits is still eligible for the
shared announce payload. If this member blocks a prefix, only its final vector
is materialized; siblings keep the shared payload and remain in the same
group.

Do not remember blocked prefixes. A rejected-prefix overlay grows toward
O(table) in exactly the failure this feature contains. When capacity becomes
available, a coalesced family-scoped resync re-evaluates current Loc-RIB/group
intent instead. The scan is transient O(table), produces at most one admitted
set bounded by the limit, and does not create persistent state proportional to
the rejected table.

Entering a group transfers the prior private advertised-prefix ownership into
the bounded member set before the private unicast table is cleared. Leaving a
group carries that set until the private Adj-RIB-Out resync commits. Existing
regroup baselines and tombstones still own withdrawals; the limiter neither
forgets an old advertisement nor treats a regroup as fresh capacity. A limit
edit alone never changes group membership.

### Reload and transaction semantics

Limit edits are live, local RIB-manager changes. They do not reset the session.
This holds on the inheritance path too: a maximum is reload-matrix `live`, so a
peer-group edit that changes only maxima is applied in place to every
inheriting member, static and dynamic. Only a change set that also moves a
session-reset field falls back to the ADR-0081 reshape.
Before mutating running configuration, resolve inheritance and preflight every
affected live static or dynamic peer as one transaction.

Adding or lowering a limit is valid only when current unique-prefix usage is
less than or equal to the candidate limit. For a formerly unlimited grouped
member, preflight walks its current advertised projection, stops after
`limit + 1`, and materializes the bounded admitted set only after all affected
peers pass. If any family on any affected peer is above its candidate, reject
the whole edit with peer, family, usage, and requested limit. Preserve the
running config, admission state, Adj-RIB-Out, and wire state; lowering is not
an implicit pruning policy.

A valid raise or removal installs the new limit and schedules one coalesced,
target-peer, target-family resync. The same resync is scheduled when a
withdrawal opens capacity during a blocking episode. It uses the existing
export and exact-export path, does not reannounce unrelated families or
siblings, and does not recursively re-arm merely because the table is still
larger than the cap. This is a bounded recovery operation, not a persistent
blocked-prefix queue.

For the v1 persisted config transaction path, limits use a prepared, inactive
transaction. While the old limits remain active, the executor resolves every
affected peer, preflights the candidate, and captures the prior effective
limits and admitted sets in a prepared token bound to the complete live target
set, each peer generation, and the RIB admission epoch. It then persists the
candidate and waits for the acknowledgement. After that acknowledgement, one
RIB-manager commit atomically rechecks the target set, generations, epochs, and
lowering preconditions before it activates any prepared limit and schedules
recovery. Drift rejects the entire activation without a partial limit change.
Preparation or a provably clean persistence failure is discarded without wire
or admission-state changes.

This ordering is a deliberate exception to ADR-0076's established
apply-live-before-persist pattern. Applying a raise or removal first could admit
routes above the old limit; a later persistence failure could not safely roll
that state back as an ordinary lowering. A lost persistence acknowledgement or
post-persist activation failure, including commit-time drift, has an ambiguous
outcome: retain the prior snapshot or commit-confirm journal, keep the
config-mutation fence closed, and require the existing restart boot-repair path.
Do not attempt a best-effort live rollback whose lowering precondition may no
longer hold. The activation command is idempotent by transaction identity so
retry or boot repair cannot apply two recovery transitions.

Commit-confirmed transactions may tighten a limit at or above current usage;
undo only loosens that limit. They reject a raise/removal whose automatic undo
could later become an invalid lowering after new routes are admitted. An
operator can make that loosening change through an ordinary committed
transaction. SIGHUP performs the same all-peer limit preflight. If that step
fails, all limit fields and admission state remain at their prior values even
though the rejected candidate remains in the operator-managed file; unrelated
reload buckets that succeeded earlier retain the existing honest partial
working-snapshot semantics.

Peer-group edits are evaluated by effective values, not merely changed TOML
fields. One over-limit member rejects a group-wide lowering before any sibling
changes. Every live static or dynamic member must acknowledge the same
preflight/apply transaction; an unavailable member rejects it instead of
creating mixed effective limits. Down children inherit the committed value on
reconnect, and the receipt names every affected live peer.

### Blocking episodes, lifecycle, and observability

The first blocked net-new prefix starts a family-specific blocking episode and
emits one warning. Further blocks in that episode increment a counter but do
not log per-prefix warnings or create durable route events. A complete
capacity-recovery resync that blocks nothing, a limit removal, or teardown ends
the episode and emits one recovery notice. A resync that still finds excess
intent keeps the same episode open. These bounded start/recovery log records are
the operator-facing limit events; the feature deliberately does not create an
unbounded durable per-route event stream.

Neighbor API state and human/JSON CLI output expose one row per unicast family:
family, usage, optional limit, optional saturating headroom, blocking boolean,
and the stable reason `outbound_prefix_limit_reached` while blocked. Unlimited
families are reported as unlimited without inventing a numeric limit. Usage is
the post-policy, post-OTC, post-exact-export, admitted unique-prefix count and
must agree with advertised-route queries.

Prometheus exposes bounded peer/family series for limit, usage, headroom, and
blocking state, plus a blocked-prefix attempt counter. No prefix label is
allowed. Limit changes refresh gauges immediately; final batch commit refreshes
usage/headroom from the same admitted truth used by the API. When a family
becomes unlimited, remove its numeric limit and headroom series rather than
leaving stale finite values; usage and blocking retain their documented
unlimited-family behavior.

PeerDown, deletion, or replacement of a session generation clears private
admission state, grouped admitted sets, blocking latches, pending recovery
resync, and gauges. A reconnect starts empty, reapplies desired effective
limits, and admits its initial feed up to the cap. Stale state from an old
generation can neither consume capacity nor clear a new generation's episode.

## Implementation outline

Keep the implementation to at most two independently reviewable PRs:

1. Add the RIB-owned pure per-family batch admission helper, private/grouped
   state, lifecycle cleanup, and family-scoped recovery intent behind an
   internal always-unlimited input. Do not add public config fields or an
   operator-visible limit in this PR, and do not put limit state in transport or
   `GroupKey`.
2. Add resolved/inherited config, the prepared persisted-transaction executor,
   rolling-compatible API fields, CLI/JSON, metrics and bounded log episode
   plumbing, operator configuration/reload docs, and a real-session integration
   receipt. This PR enables the public knob and its observability together.

The feature is incomplete until both land. The first PR has no public partial
surface; the second must not expose a knob until its neighbor state, bounded log
events, and metrics are observable in the same change.

## Load-bearing validation plan

This ADR-only tranche adds no executable test or gate, so red-proof is N/A.
Implementation tests must state the production break that makes each red:

- At limit N, advertise N+1 real prefixes and prove only N are on the wire and
  in Adj-RIB-Out. Removing the admission call must expose N+1.
- At cap, change attributes on an admitted prefix and withdraw another; prove
  both pass. Applying the gate to all announcements or withdrawals must fail.
- Withdraw the last path and add a different prefix in one batch; prove the
  new prefix takes the freed slot. Evaluating announcements first must fail.
- Advertise multiple Add-Path IDs for one NLRI and prove usage is one until the
  last path withdraws. Counting route identities must fail.
- Put limited and unlimited siblings in one update group, overflow only the
  limited member, and prove the sibling and group membership are unchanged.
  Adding the limit to `GroupKey` or filtering the shared payload must fail.
- Move a limited peer group-to-private and private-to-group with prior routes
  and tombstones. Resetting admission during either handoff must leak or lose a
  route and fail the exact final-state assertion.
- Attempt one direct and one inherited lowering below usage. Prove the entire
  config transaction, wire state, and admitted set are unchanged. Mutating any
  peer before all-peer preflight must fail.
- Raise and remove a cap with eligible blocked intent. Prove one family-scoped
  resync fills the new capacity without sibling or other-family churn.
  Omitting recovery or using a peer-wide resync must fail.
- Tear down and reconnect across a blocking episode. Prove old state and
  gauges are reaped and the new generation starts at zero. Keying only by peer
  address without generation cleanup must fail.
- Compare API, human/JSON CLI, and metric family rows against exact advertised
  state through block, recovery, and unlimited transitions. Reading the shared
  group-table count instead of the admitted projection must fail.

The integration receipt must use a real encoder and real BGP sessions, disclose
peer count, family mix, Add-Path mode, and configured limits, and assert that
the grouped path was actually exercised. No performance claim follows from a
mock-only test.

## Earns-its-keep and costs

- **Two unicast family limits** contain the most likely IX/RR export accident
  without inventing semantics for unrelated families. Cost: two inherited
  config/API fields and independent lifecycle state.
- **Block while Established** preserves admitted reachability, withdrawals,
  and remediation visibility. Cost: the peer's view intentionally diverges
  from group intent until capacity recovery.
- **A bounded admitted set for limited grouped members** preserves shared
  staging and caps worst-case memory. Cost: O(limit) per limited peer and a
  member-local vector only when its cap changes a shared batch.
- **No blocked-prefix inventory** prevents the protection mechanism from
  becoming another full-table allocation. Cost: raises, removals, and freed
  capacity require a transient O(table) resync scan.
- **Atomic rejection of an overfull lowering** keeps configuration truthful
  and avoids arbitrary withdrawals. Cost: operators must first reduce export
  policy or withdraw routes instead of using the knob to prune an existing
  view.
- **One fixed action and episode-level telemetry** make failure behavior
  predictable and bounded. Cost: deployments wanting warn/restart/disable
  modes must continue to use external alerting or policy.

## Rejected alternatives

- **FRR's separate update group for each outbound limit.** FRR documents that
  `maximum-prefix-out` creates a separate update group because its sent count
  is group-owned. rustbgpd's post-staging per-member commit seam can preserve
  the existing group and pay only for configured members.
- **Copy BIRD export-limit and reload behavior.** BIRD 3.1 documents its export
  limit as experimental, including temporary reload overshoot, counters that
  ignore blocking, and block mode preventing updates to already accepted
  routes. Those are the exact ambiguities this contract avoids.
- **Disconnect on violation.** A local export mistake should not discard
  already admitted reachability or hide the condition behind session churn.
  No standard requires a NOTIFICATION for this local limit.
- **Store rejected prefixes.** This makes retry cheap but permits O(table)
  state per constrained member when the limit is doing its most important
  work. A bounded admitted set plus transient resync is the safer inverse.
- **Put limits in `GroupKey`.** That avoids member-local filtering at the cost
  of fragmenting route-server fanout by customer-specific capacity. The limit
  does not change shared policy staging and is not group identity.
- **Prune immediately on lowering.** Choosing which currently advertised
  prefixes survive would create a second selection policy at config-apply
  time. Rejecting the edit is atomic and understandable.

## Consequences and re-judge triggers

rustbgpd gains per-client outbound blast-radius containment while retaining
Established sessions and update-group sharing. Unlimited peers keep their
current state and fast path. Limited grouped peers pay a deliberate O(limit)
memory exception; recovery pays bounded, transient table scans rather than
persistent rejected state.

Stop and re-judge before implementation exceeds roughly 1,800-2,000 added
lines or more than two implementation PRs, or if correctness appears to
require a transport dependency, `GroupKey` split, non-unicast/action modes, a
new durable event type, or state not bounded by the admitted cap. Those are
design changes, not implementation details of this ADR.

## Re-judge outcome: line budget exceeded, implementation accepted

The line trigger above fired and was re-judged rather than treated as a
prohibition. Implementation landed in the planned two PRs at 2,662 added
lines total — 760 for the inert RIB-side accounting, 1,902 for the
configured knob and its observability — against the estimated 1,800-2,000.

The overrun is in surface completeness, not in feature scope. Every item is
one this ADR already required: resolved and inherited configuration, the
prepared-inactive transaction executor with its activation recheck, the
all-peer lowering preflight, the family-scoped recovery resync, the neighbor
API/CLI/JSON rows, the bounded metric series, and the operator
documentation. Nothing outside the ADR was added, and no other re-judge
trigger was approached: no transport dependency in the enforcement path, no
`GroupKey` split, no non-unicast or alternative action modes, no new durable
event type, and no state unbounded by the admitted cap.

Trimming to the estimate was considered and rejected. The only remaining
compressible surface was observability, and shipping an enforcing knob whose
usage, headroom, and blocking state an operator cannot see would violate the
stronger requirement stated above — that a limit doing its most important
work must be visible while it does it. A rough line estimate does not
outrank that.

One ordering correction was extracted and landed separately rather than
carried here: the session staged its peer-group policy context after
`PeerUp`, so group-inherited limits could never resolve before the initial
Adj-RIB-Out was built. That defect predates this ADR and independently
affected group-scoped export policy on every initial dump, so it belongs to
its own change with its own regression coverage.
