# ADR-0105: Grouped export-policy transition transaction

**Status:** Accepted
**Date:** 2026-07-14
**Amended:** 2026-08-04 — pre-commit phases carry a 60-second
aggregate ownership budget (twice the 30-second readiness stall bound): a
transition still short of `CommitMembers` at that age hands the cohort to
the authoritative per-peer path fail-closed, because every other pre-commit
fallback trigger is an invalidation event and a slow-but-healthy transition
otherwise fences the actor indefinitely. The stalled readiness verdict is
the early warning; this handoff is the remedy. `CommitMembers` remains
exempt (first emission bars fallback). The same incident removed the per-member policy
fingerprint rendering from runtime classification: group identity is the
interned chain content, and the rendering — O(chain size) per member, tens
of megabytes at IRR scale — was consumed only by the observational
snapshot/planning surfaces, which now use a cached streaming digest.

**Amended:** 2026-08-26 — settlement-owned policy applies preserve typed
session-state outcomes at their clean-state fences. A first 100 ms timeout may
retry once under one shared absolute two-second window; a positive
non-Established reply, session-task loss, or retry exhaustion compensates
rather than committing.
RIB compensation is one rollback-only exact batch with ordered receipts and
the normal two-minute batch-reply bound.

**Amended:** 2026-09-11 — operator reads are served during the cohort RIB
transition instead of waiting for its commit. The forward reload owner
admits its bounded operator-read lane (session snapshots, import-statistics
collections, dataset status) while it awaits the batched RIB reply, on the
same terms as the destination prestage: every cohort session already runs
its new chains, so a read observes the same mixed per-session generation
prestage admits, and the ordinary command receiver stays unpolled. The RIB
run loop serves one bounded general-query budget between pre-commit
transition polls from the primary state, which no pre-commit phase changes,
so such a read returns exactly the pre-commit generation; the query lane
carries only reads, mutations stay queued on the primary channel, and the
`CommitMembers` batches keep the full fence. The terminal commit advances
the advertised page generation so a route listing started before the commit
cannot resume across it. Section 1's "only the readiness lane" wording and
Section 5's "no general query is admitted" describe the design before this
amendment. Rollback and standalone policy transactions are unchanged.

**Amended:** 2026-09-12 — the rollback of a rejected cohort transition admits
the same operator-read lane while the peer manager awaits enqueue or completion
of its exact RIB compensation batch. Session restoration has been attempted,
but an unsuccessful restore can leave a session on a different policy. Reads
report live session state without a common generation pin. The RIB still
executes the authoritative restore synchronously and fences general queries,
so this admission alone does not guarantee completion of neighbor RPCs or
export-policy statistics within their deadlines. The ordinary command receiver
stays unpolled and the two-minute batch-reply bound is unchanged. Standalone
policy transactions and a reload's later compensating replay keep the full fence.

**Amended:** 2026-09-12 — forward API live-impact transactions and catalog
refreshes use the same peer-manager operator-read admission as forward SIGHUP
applies. API publication-failure compensation also admits these reads: policy
chains restore before the staged configuration, and reads report each source's
current values. This supersedes the API fence described in the earlier
amendments. It does not choose admission for SIGHUP's separate generation-unwind
path. Admitted reads remain live observations without a common generation across
sessions or the RIB; caller budgets, mutation ordering, and individual session
ACK/bookkeeping fences are unchanged.

**Amended:** 2026-09-12 — forward policy transactions admit bounded live operator
reads during read-only preflight, cohort selection, clean-state probes and retries, retained-route
proofs, and authoritative per-peer RIB waits. Session policy acknowledgement
remains fenced until the manager records the acknowledged chain. A bounded drain
between completed policy steps prevents a serial fleet walk from accumulating
one uninterrupted read fence.

Generation unwind decides policy and dataset admission separately at their entry
points. If every earlier restoration succeeded, compensation admits the same
live reads, superseding the earlier full-fence claim for generation unwind.
Any earlier restoration failure keeps those reads fenced. For example,
a session can acknowledge its prior runtime settings before the restoring outbound
RIB refresh fails; its manager metadata then still describes the candidate settings.
A fresh session query combined with that metadata would misreport the installed
settings without marking the row stale. This concrete inconsistency requires the
conditional fence even though clean compensation does not require a generation pin.
Reads use each peer's current managed handle, including a replacement created during
compensation.

Dataset generation reevaluation carries its owner's admission through both channel
capacity and reply waits. Legacy dataset refresh uses that same bounded dispatch
with the existing five-second capacity allowance, while retaining its five-second
wall-clock reply deadline. Generation reply accounting still excludes admitted
read servicing. The existing operator deadlines, transaction ownership, and
individual session acknowledgement limits are unchanged; an admitted read settles
before an expired owner resumes, and an expired capacity wait cannot dispatch late.

**Amended:** 2026-09-12 — the SIGHUP `honor_graceful_shutdown` and `honor_blackhole`
fan-outs admit the same live operator reads at completed policy steps and state
probes. These edits change implicit import tails without changing the transport
metadata reported alongside session state or the RFC 8212 explicit-policy verdict.
Desired honor flags are read through the ordinary command lane, which remains
queued until publication. Their ownership alone therefore does not require a
fleet-wide operator-read fence. Each session ACK and its matching manager
bookkeeping remain fenced; inline runtime-setting restoration keeps its separate
fence against inconsistent session and manager metadata.

**Amended:** 2026-10-04 — `BuildInventory` no longer walks the destination table
under the fence when the destination prestage completed for the same group pair.
The prestage builds the inventory in its own unfenced slices after staging, and
from that walk's first slice both groups log every key their table writers touch.
`BuildInventory` drops the walk results for logged keys and re-checks only those
keys against the frozen tables, using the same per-key table-drift, source-flip
and rs-control checks as the fenced walk; the clean-pair predicate is re-run in
full. A prestaged walk that is missing, unfinished, for another pair, outlived by
a recreated group, or checked against a smaller RS-ASN set falls back to the
fenced walk described in Section 3, so the commit-or-degrade outcome is that of a
fenced walk of the same tables.

**Amended:** 2026-10-06 — the unfenced inventory walk clones owned route rows and
aligned next-hop actions in bounded slices, retaining its existing vectors. The
rows are exact-probed in unfenced slices against the preparing member's immutable
encoder snapshot. Mutation logs remain active throughout the walk and probe.

Under the fence, the inventory vectors and successful encoded lengths use the
same in-place compaction for logged keys. Changed rows are appended and re-probed
before computing the current maximum; withdrawn maxima cannot survive in the
proof. The unfenced route, next-hop, and encoded-length allocations reserve one
route slice of headroom for that retained proof's dirty suffix. One final seal
wraps the reconciled vectors in `Arc<Vec<_>>`, preserving their buffers without
copying the route shells or next-hop actions. Capacity is retained; retiring the
last owner still drops all rows, and the over-budget fallback can still grow its
vectors before discarding the proof.
The `rustbgpd_rib::clean_export_probe` debug target captures seal duration with
`phase=fenced`, reconciliation path and row counts, proof validation, and the
full-probe count at entry to `Validate`, without enabling per-prefix events.

An incomplete proof, more than one route slice of changed rows, probe rejection,
or encoder owner/generation drift discards the proof and runs the fenced probe.
Wire-profile compatibility and each member's ceiling are still checked during
`ProbeAndPrepare`; `Validate` keeps its exact current owner/generation checks
before any emission.

**Amended:** 2026-11-11 — the authoritative fallback batch paces members whose
sessions send EVPN. Each such move can resync the member's whole EVPN table,
so a batch of N of them was one RIB poll growing with N × rows. The batch now
applies shared cohorts and every other residual member as before, but leaves
residual EVPN senders unapplied. The negotiated family decides, not current
rows, because an old chain that denied every EVPN route leaves no rows while
the new one may announce the whole table; EVPN group ownership requires the
family too. Their installed chain instance is put back and the reply names
them in caller order. PeerManager sends them in paced commands. Each command
runs the batch's per-member body for a caller-order prefix of the members it
was sent, then one shared distribution pass, and returns the rest. It starts
another member only while the predicted turn stays within 250 ms (the
qualification bars the regroup window's actor poll at 300 ms): the time so
far, plus the pass shares the applied members still owe, plus one member's
recompute and pass share. The estimate is the largest single-member recompute
and the largest single member's own time in a pass measured so far in the
walk; it never shrinks, so a light member does not lower it. The converse is
accepted: one outlier member (its time includes any readiness drain, forced
checkpoint or host preemption) pins the rest of the walk at one member per
command, the convergence of the earlier one-member-per-command walk. A member
whose writer was full still counts: a resynced member is often left marked
dirty for replay, so the dirty mark cannot tell the two apart, and a low first
estimate is bounded by the window below. The first member always runs;
without an estimate only it runs. A member heavier than any
measured yet can still overshoot, so PeerManager sends each command at most
twice the previous command's applied members (one for the first), which bounds
one command's overshoot and keeps the walk's setup linear in the list. The
command's clock starts before its summary capture, so the capture counts. Not
in the prediction: the pass's shared work (the speculative capture and
update-group staging before its member loop; retirement, EoR settlement and
the stale-exempt flush after it), the pass's visits to other dirty or forced
peers, including earlier members still replaying, which is not constant, and
the summary retirement and policy reclamation after the pass. Within a paced
command no member takes the shared cohort transition, which is not budgeted.
Grouping members this way keeps their recomputes warm and their resyncs back
to back, which one
member per command did not: measured per member, the recompute ran cold on
every turn and the resync overlapped the previous member's session encode.
The batch and every command of its walk share one two-minute budget of their
own, anchored when the batch is sent and never renewed per command. The
authoritative remainder walk that follows has an independent two-minute
budget, anchored at its own first RIB command, so the two forward phases are
each bounded separately, not by one two-minute bound across both. Each
command is its own commit point: between
commands an `rbgp` read or a route chunk sees applied members on the new chain
and the rest on the old one, as in the serial remainder walk. The reload
replies, and its configuration is published, only after the last command is
committed and enqueued. A command that fails, a reply that does not account
for every sent member (applied first, then the rest in caller order, or
skipped), or a budget that expires mid-walk restores every captured prior
through the existing rollback batch, which stays one synchronous turn. The
deadline is checked before a command waits for channel capacity and again once
capacity is reserved, and the RIB skips a command whose caller has already
dropped the reply, so an expired walk sends no further command. A command the
RIB is already applying when its reply times out still applies; the rollback
queued behind it in FIFO order restores the end state. A command naming a peer twice is rejected before any mutation. A
member that left the RIB comes back as skipped; its reconnect registers the
session's chain, which cohort setup already hot-applied. Two limits remain.
Rollback carries every captured member, applied or not, through the
non-deferring batch, so the failure path is one turn over the whole list.
Residual members of other private families (VPN, labeled unicast, FlowSpec,
BGP-LS), per-client-best groups, ungrouped peers and sources with mixed
destinations still run inside the batch.

**Amended:** 2026-11-12 — the forward batch paces every residual member, not
only EVPN senders. A residual move resyncs the member's whole table in every
family its session sends, so VPN-, labeled-, FlowSpec- and BGP-LS-only
members, ungrouped and per-client-best members, mixed-family members and the
movers of a source group with mixed destinations each grew the batch's one
turn by a table. The batch now applies only its shared unicast cohorts and
hands back every residual member whose session sends any family, in caller
order, for the paced walk above; a member that sends no family has nothing to
resync and is still applied inline. As before, the negotiated families
decide, not current rows. The walk's turn budget, window, deadlines, commit
points and rollback are unchanged, and the walk now carries more members
under the cohort's own two-minute budget. That one deadline covers the batch,
the walk's per-command overhead and every other RIB unit that runs between
its commands (queued UPDATEs, route chunks, timers), which the former single
turn kept waiting instead. A cohort fallback that fitted the budget as one
long turn can therefore run out of it under load and roll back, and that
rollback pays the one-turn restore below. A destination the batch built for
a shared cohort it then refused is adopted by the walk's first mover. If no
member joined it, it is retired, inside the command's readiness scope, by the
paced command that applies or skips its last mover, by the rollback restore,
or by the next forward batch, whichever comes first. The first limit above (rollback is one turn over the whole list) remains, and
so does the remainder's one-member-per-command walk under its own budget.

**Amended:** 2026-11-13 — the authoritative remainder batches each export
pair that two or more of its peers share. PeerManager still selects one
cohort for the clean transition. In the remainder it now groups the peers
that pass the cohort's local eligibility check by `(installed, target)`
export pair, in first-occurrence order. A peer whose pair is its own, a peer
with retry intent, an RFC 8212 presence transition (ADR-0112: its Route
Refresh follows its RIB step immediately) and every peer of a snapshot that
names a peer twice keep the per-peer path in section 4 unchanged. The walk
applies units in the caller's order of each unit's first target: a peer on
the per-peer path is a unit of its own, and the members of a shared pair run
together, in caller order, where the pair's first member stands, in groups
of at most 100. A group is one unit with three steps. First the session legs
of each member (both hot-applies, the state probe, the bail rules), which
defer the RIB step of every member observed Established. Then one
`ReplacePeerExportPoliciesAuthoritatively` batch followed by its paced walk,
the entry point the cohort handoff uses, so the RIB shares the destination
build and the old-to-new delta across the group. Then the group's deferred
Route Refreshes in walk order, through the step the cohort uses: the session
is probed again, a positively known-down peer owes no refresh, and a failed
refresh is fatal. Legs precede the batch inside a group because the session's
acknowledgment is what makes a registration during the walk install the
right chain, and a failed leg must abort before that group's RIB commit. The
groups are not run legs-first across the walk: a session would then hold the
candidate chains, with its Route Refresh pending, for the whole walk, and a
failed reload would have touched every session instead of the ones reached.
One RIB turn therefore carries the shared cohorts of one group, which is
more than one cohort when its members sit in several source groups, or the
members the paced budget admits. A later group of a pair joins the
destination group the first built, so one batch turn does not grow with the
pair. The exception is a pair with a chain that reads a dataset: the batched
transition does not share an occupied destination across a dataset
reference, so the RIB hands the groups after the first back and each of
those members takes the paced walk's own resync, the cost of the per-peer
path. Refreshing after each group rather than after the pair is safe for the
reason refreshing between pairs is: a route the refresh re-admits reaches a
member still awaiting its batch under the old export chain, and that batch
then moves the member on the delta against the destination. Every RIB
command of the remainder, per-peer or batched, shares the transaction's one
forward budget, anchored at its first RIB command; the session legs of later
units run inside it, as the per-peer walk's always have. Between its session
leg and its batch a member's session holds the new chain while the RIB holds
the old one, the window cohort members already have, and until its refresh
its `AdjRibIn` holds routes accepted under the old import chain; both last
one group, not the walk. Any failure (a session leg, a batch or paced
command, budget expiry, a deferred refresh) restores every captured prior,
remainder then cohort. Those are the members of the units reached; a member
of a later unit was never touched. A captured member whose batch was never
sent is restored too: a member can register with the RIB during the walk,
and that registration installs the candidate chain its session already
holds. The limit that remains: peers with pairwise distinct export changes
still cost one full-table RIB command each under the two-minute budget.

**Amended:** 2026-11-13 — the rollback restore is paced, and its wait
detects a stall instead of bounding the total. This replaces the one
synchronous rollback turn named as a limit in the two amendments above and
changes section 4's rollback paragraphs as follows. Measured before this
change, a rollback of about 80 peers with distinct export chains at a full
table was one RIB turn of 66 to 68 seconds. The detached rollback task still
owns the whole RIB side of a rollback partition. It now sends one
`RestorePeerExportPoliciesAuthoritatively` batch per prior chain, newest
first. That batch restores shared cohorts in its turn, exactly as the
forward batch moves them, and acknowledges each residual member whose
session sends any family with a `Deferred` receipt, leaving its installed
chain in place. A member whose installed chain already equals the prior one
is `Restored` at once, in the batch and in a paced command alike, with no
regroup and no resync: a rollback names every member the failed walk
captured, and the RIB never moved most of them. The test is the chain the
RIB has installed when the command runs, not what the peer manager sent, so
a member that registered under the candidate chain during the walk is not
equal and is restored like any other. The forward batch and its paced walk
share that body and the same shortcut; there it applies only to a member
that registered under the candidate chain before its batch, whose
registration already exported under it. The task restores the `Deferred`
members with
`RestorePacedExportPolicies` commands before it sends the next batch: the
paced command's body, turn budget, window and reply, except that the RIB
applies it even when its caller has dropped the reply. Every command is sent
only after the previous reply, so UPDATEs, queries and timers run between
them, and the longest rollback turn is one prior chain's shared cohorts, the
members the paced budget admits, or one member. The task returns one
`Restored` or `NotFound` receipt per member, newest first; a member that
left the RIB before its command ran is `NotFound`, which closes its debt
under the unchanged rule (a positive session-state observation), and its
next registration carries the session's already-restored chain.

Three properties change with it. First, only the first rollback command is
enqueued before the rollback Route Refreshes. Refresh-generated route work
and peer lifecycle events can now run between restore commands; a member
not yet restored exports them under the candidate chain it already had,
until its own command resyncs its whole table under the prior chain. The
end state is the same. The refreshes are deliberately not held until the
restore ends: restoring what the Loc-RIB accepts matters more than sparing
unrestored members a second round of UPDATEs. Second, the wait for the task expires
`RIB_BATCH_REPLY_TIMEOUT` after the task last completed a RIB command, and
never before the transaction's lazy rollback deadline. A paced restore of N
members takes about as long as the forward walk that applied them, so one
total two-minute rollback deadline would turn a slow, succeeding rollback
into a `known_divergence` fence, which drops every session. The restore's
work list is fixed when it starts, so a restore that keeps completing
commands terminates; one that completes none for two minutes is a stalled
RIB and is fenced as before, with retry intent armed and the task still
owning the late repair. A partition whose restore succeeded renews the
shared rollback deadline for the next partition on the same rule. The outer
bound is the owner's fixed 30-minute settlement budget, which this does not
change. Third, the peer manager holds the transaction for the whole restore,
which can now be minutes; it serves readiness and, where the owner admits
them, operator reads throughout, and logs the restore's start, its progress
every ten seconds and its end. No metric reports restore progress: the only
related series is the clean transition's
`bgp_rib_policy_transition_in_progress`, which does not cover it.

Two limits remain. A restore batch still runs one shared cohort transition
per source group in its one turn, so members returning from many source
groups to one prior chain are restored in a turn that grows with them
(measured in checkpoints at 256 rows: 19,144 for 8 members from two groups,
53,416 for 32). The restore task caps that turn the way the forward walk
caps a pair's batch: a prior chain goes back in batches of at most
`PAIR_BATCH_MEMBERS` (100) members, newest first, each followed by the paced
restores of its deferred members. And one member's restore is one RIB turn. A member that
is alone in its update group rebuilds a group table and resyncs its own
table in that turn; bounding it below one member needs a resumable
replacement, which ADR-0111 examined and rejected.

**Amended:** 2026-11-13 — the forward walks stop rolling back on elapsed
time. Section 4 and the amendments above describe one two-minute budget for
the authoritative remainder and one for a cohort fallback's batch and paced
walk, each an absolute deadline for the whole walk. Measured at a full
table, that deadline rolled back a reload of roughly 80 or more peers with
distinct export chains although every RIB command was completing, and the
rollback then repeated the same work in reverse. Both forward budgets are
now stall detectors, on the rule the rollback wait uses: after each
completed step (a target's session legs or its whole per-peer apply, a
batch, a paced command, a group's Route Refreshes) the budget expires
`RIB_BATCH_REPLY_TIMEOUT` later. The refreshes are session round trips, not
RIB work; renewing after them keeps a group whose refreshes are slow from
spending the stall timeout of the RIB command that follows, as the per-peer
command already excludes its own refresh from the budget. A walk that keeps completing
units commits however long it takes; a walk whose RIB completes no unit for
two minutes rolls back, as does one where a peer refuses or fails its step.
Expiry still admits no further command, and an admitted command stays ahead
of its rollback. The RFC 8212 presence proofs that precede a walk and the
honor-knob fan-outs keep an absolute shared budget. The peer manager holds
the transaction for the whole walk, so mutations and lifecycle commands wait
longer behind a large reload than they did; readiness and admitted operator
reads are served throughout. The outer bound is the owner's fixed 30-minute
settlement budget: at about 1.5 seconds per distinct-chain peer at a full
table, a forward walk alone reaches it near 1,200 such peers, and a walk
that fails late and must be restored reaches it near 600. Reaching it fences
the daemon, so that budget, not this change, is the limit to revisit before
a route server carries that many per-neighbor export policies.

The same change sends a remainder peer whose export pair is its own through
the batch entry point, as a batch of one. The remainder amendment above kept
the per-peer command for it. A unicast member alone in its update group
moves in that batch as a shared cohort of one: the RIB builds the
destination table and emits the old-to-new delta, where the per-peer command
regroups the member and resyncs its whole table. In checkpoints at 256 rows
with 16 such members registered, the batch of one passes about 5,600 and the
per-peer command about 16,000; both put the same 256 announcements on the
wire. Each command also does work in proportion to the registered peers
(about 12 checkpoints per peer for the batch, about 28 for the per-peer
command), so the batch adds no per-command table or fleet pass the per-peer
command did not have. At a full table the 2026-11-12 rollback measurement
restored such members as shared cohorts of one in about 0.83 s each, against
about 1.47 s for the per-peer forward command; the forward figure on this
path is the campaign's to measure. A member the batch cannot move on the
shared transition (an ungrouped or peer-context export chain, a
per-client-best member, a sender of any family other than IPv4 or IPv6
unicast, mixed destinations under one source group) is handed back and
applied by the paced walk, whose body is the per-peer command's own regroup
and resync, so its end state is unchanged at the cost of one short extra RIB
command. A member with no RIB registration is skipped inside the batch, as
the per-peer command's typed absence was accepted. The walk's order is the
remainder amendment's rule, now with every eligible Established peer
planned: units run in the caller's order of each unit's first target. A pair
of any size, one member included, runs where its first member stands in
groups of at most 100; each group runs its session legs, its batch with any
paced commands and its Route Refreshes before the next unit starts. A target
on the per-peer command is a unit of its own in its caller position, whole,
as before. With every peer planned, running the legs ahead of the walk would
have put all N sessions on the candidate import chain, each with its Route
Refresh pending and the RIB still exporting to it under the old chain, for
the whole walk, which is minutes at 150 distinct chains and a full table,
and a failed reload would have exposed all N sessions instead of the ones
reached. Interleaved, that state lasts one unit, and the rollback restores
the units reached. The per-peer command remains for a target that carries retry intent or an
unconfirmed install, an RFC 8212 presence transition, every target of a
snapshot that names a peer twice, the honor-knob fan-outs and a single-peer
hot update.

**Amended:** 2026-11-13 — the walk serves session events between its units.
Section 1 says the peer manager services only its readiness lane while it
awaits a session or RIB reply, and later amendments added admitted operator
reads. With the forward walks and the rollback wait bounded by a stall
timeout instead of two minutes in total, a walk can hold the actor for many
minutes, and everything else the run loop does waited for it: a BFD Down
did not stop its BGP session, a crashed session task was not restarted and
no session event was published until the walk ended. The owner now serves a
fixed set of events at seams between its steps, most of them where it
already drained operator reads: after each target's session step (inside a
group, between two members' steps: a planned member keeps only its key and
chains there, no session handle), after each group's batch and each paced
command, at the end of each unit, between the members of a cohort's session
setup and of its deferred refreshes, between a rollback's session steps and
refreshes, and, while it waits for the detached restore, each time that task
has completed a RIB command when the owner is next polled.
Served there: BFD state changes and due BFD command retries, link changes
and link-check retries, session lifecycle events, one round of session
notifications, and NOTIFICATION events, in the run loop's order (lifecycle
events before a notification, queued BFD changes before a BFD retry). What
a seam takes from the BFD, session notification and NOTIFICATION event
queues is bounded at eight of each per seam; a unit has at least two seams.
The bound is on what the seam takes, not on what a served handler drains:
lifecycle events are drained whole, as in the run loop, and a notification
round that retires, replaces or promotes a session handles every session
notification queued at that moment, as does a served BFD Down that retires
a pending inbound session. A flood therefore costs a seam a fixed amount of
work only while no event in it ends a session. Serving is not
progress: the stall budget is never renewed at a seam, and the time spent
serving is taken out of it. Nothing is served inside a unit, which holds a
session handle across its awaits, except link changes, which only ask
sessions to check and are served in every wait of the walk, including the
cohort's clean transition, the one long wait with no seam.

Ownership is unchanged. The command receiver, internal commands, max-prefix
restart timers, discovery, reconciles and retention stay behind the
transaction, so no mutation, inbound connection or shutdown runs inside it.
A served handler may replace a static peer's session or latch the peer
disabled; it never removes a peer the walk captured. The one notification
that would, a dynamic peer's session going idle or its task ending, is held
and put back on the notification channel when the transaction returns, so
the run loop retires the peer after the owning command, as before. A
replaced session is spawned from the manager's bookkeeping, which the walk
advances only when a session acknowledges a chain: a peer whose step has run
restarts on the candidate chain, one still to walk on the prior chain and is
then walked, and one replaced during a rollback on the restored chain. Its
RIB identity is the peer's slot, which a replacement keeps. The exception is
a dynamic peer whose task exit the walk holds: no session is left to
acknowledge, so the peer adopts the chains of each step, forward or
rollback, without a session step or Route Refresh, and owes nothing,
because it is retired when the walk ends.

A SIGHUP generation suspends BFD coupling for its whole length, and the
ordinary handler ignores every change while it does. Inside a generation a
seam therefore takes only a genuine Down of an accepted member from the
queue, stops the BGP session and records the hold as a prior one, so a
generation that aborts keeps it and the BFD Up that follows still sends the
`Start` the stopped session is owed. An Up, a release and every level
report stay queued until the generation ends, as does a `Start` retry; a
`BfdDown` retry runs. A peer latched disabled inside a generation has its
BFD session drained when the generation ends either way: an abort now
recomputes the disabled set from the peer table as a commit does. Outside a
generation the ordinary handler runs at the seam.

The phase line reports the result: `owned_wait_service_gap_max_us` (the
longest interval between two seams, or from the walk's start or to its
end), `events_served` and `event_service_us`. Later work, not in this
amendment: inbound connections for static peers, which need a lane of their
own off the command channel; max-prefix restart timers and BFD Up inside a
generation; and a seam inside the cohort's clean transition.

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
O(peers) bounded session work. PeerManager supplies the captured RIB priors in
original forward order as one rollback-only exact batch. The RIB rejects
duplicate peer identities before mutation, reverses the batch, and returns one
ordered `Restored` or `NotFound` receipt for every member. A `NotFound` receipt
closes retry debt only when the session state was positively known to be
non-Established; every ambiguous absence remains convergence debt.

The batch send and reply share one lazy absolute `RIB_BATCH_REPLY_TIMEOUT`
(two minutes) across the top-level policy transaction. A detached task owns the
send and receiver, so deadline expiry or caller cancellation cannot cancel a
queued repair. PeerManager waits for the batch to be enqueued before issuing
any rollback Route Refresh; FIFO therefore keeps refresh-generated route work
and later peer lifecycle mutations behind the exact restore. It clears pending
flags only after validating the receipt count, identity order, and positive
outcome. A timeout, lost reply, mismatch, or rejected batch retains conservative
pending flags and makes exact compensation unprovable. The bound does not cover
sequential session commands, Route Refresh acknowledgements, or the RIB actor's
detached late repair work.

The authoritative forward walk follows the same discipline. Its per-peer RIB
commands and the RFC 8212 presence proofs that precede them share one lazy
absolute `RIB_BATCH_REPLY_TIMEOUT` for the whole transaction, so a transition
that falls back to the serial walk is bounded by the same total RIB time the
batched cohort promises rather than by a fresh deadline per peer, which would
scale with the fleet and therefore bound nothing. A per-peer command is not a
cheap inline operation: it performs its own full distribution pass, so a single
reply can legitimately take seconds under load. The forward and rollback
deadlines anchor independently, so a slow walk cannot consume the budget its
own compensation needs. The forward deadline starts at the first actual RIB
command, after any session-only preflight, and covers both channel admission
and the reply. Expiry cancels an unadmitted forward send; an admitted command
remains ahead of its exact rollback in FIFO order. This bounds RIB waits, not
all session and Route Refresh work in the transaction.

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
  RIB send/reply waiting is bounded by one transaction-wide batch deadline;
  retaining the detached late repair and conservative retry flags is the
  cancellation cost.
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
  per poll.
- The measured completion win is retained together with its measured delivery-
  gap regression. Neither the ADR nor the microbenchmark receipts turn that
  regression into a success claim.
