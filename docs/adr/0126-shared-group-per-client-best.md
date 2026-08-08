# ADR-0126: Shared-group per-client best-path — path-hiding mitigation inside update groups

**Status:** Proposed
**Date:** 2026-08-05

## Context

Both documented RFC 7947 §2.3 path-hiding mitigations — `per_client_best`
(ADR-0101) and Add-Path send (ADR-0099 Decision 5) — are update-group
disqualifiers, so no configuration is simultaneously mitigated and grouped.
`rs-config-render` defaults `path_hiding = true`, so every rendered
route-server member sets `per_client_best = true` and rendered fleets run
fully ungrouped. The sealed
[realistic-mix receipt](../perf/irr-reload-realistic-mix-2026-08.md) prices
that at the canonical 320-member × 183,040-prefix shape: steady-state reload
completion p50 87–143 s and sampler RSS peak 10.4–11.3 GiB for per-client
best, versus 4.5 s and 2.0–2.1 GiB for the (mitigation-less) grouped control
— while the mitigation delivers exactly the 18,304 (F = 0.1) / 91,520
(F = 0.5) runner-up pairs the shared-RIB export hides, verified
byte-for-byte on the wire by the received-view-delta verifier.

The semantic opening: per-client best-path for member `m` is "best
export-permitted candidate not sourced by `m`". Under a group-shareable
export chain — content-equal, no peer-context matchers (`GroupKey` already
guarantees both) — the permit verdict on any candidate is identical for
every member. The per-member selections therefore collapse to one shared
computation plus exactly two divergences from today's grouped output:

1. **The member sourcing the staged winner receives the runner-up** — the
   best permitted candidate from any other source — instead of nothing.
   One exception per prefix, not per member.
2. **When the chain denies the Loc-RIB best, all members receive the best
   permitted candidate.** Today's grouped staging stages nothing
   (policy-filtered); per-client best walks on. This divergence is
   group-wide, since verdicts are chain-content-uniform.

This is precisely the optimization RFC 7947 §2.3.2.2 blesses: a global
Loc-RIB with per-client views "stored as deltas" instead of materialized
per-client Loc-RIBs (which ADR-0101 Decision 2 rejected permanently).

What the incumbents do, verified against their documentation:

- **BIRD** implements `secondary` on a `sorted` table: export tries each
  route in preference order until one passes the client's filter. It shares
  table *memory* (no explicit per-client tables) but still runs each
  client's export filter per prefix per client; `sorted` is required and is
  incompatible with `deterministic med`. BIRD 3's threading parallelizes
  those per-client filter runs across cores without deduplicating them.
- **OpenBGPD** implements `rde evaluate all`: the RDE evaluates all paths
  per neighbor. Its early releases shipped the documented bug family of
  openbgpd-portable issue #21 — a suboptimal path not advertised on
  startup/reload when the best was filtered, and a stale second-best
  persisting in `show rib out` after the best was withdrawn until a manual
  session clear — fixed in OpenBGPD 7.0; arouteserver historically kept the
  option off for OpenBGPD for this reason while defaulting `path_hiding:
  True` for BIRD.

Neither shares the export computation or the staged result across clients
with identical policy: both pay O(clients × candidates) filter evaluation
for the mitigation. Staging once per group and deriving per-member views —
mitigation semantics at shared-export cost, with no sorted-table or
comparator restrictions — is a position neither occupies.

## Decision

### 1. `per_client_best` joins the group key instead of disqualifying

When a `per_client_best` peer's chain is shareable (no
`requires_peer_context`) and its key is unicast-only
(`GroupKey::is_unicast_only`), the classifier returns `Groupable` with a
new `per_client_best: bool` key bit. Mitigated and unmitigated groups must
never share a table: divergence (2) means a per-client-best group stages
the first *permitted* candidate where a plain group stages
Loc-RIB-best-or-nothing. Classifier precedence is unchanged above this arm:
peer-context chains, Add-Path send (a negotiated capability outranks the
fallback per family, ADR-0101 Decision 1), and ORF still disqualify with
their existing reasons; ORR remains mutually exclusive by validation.
Non-shareable or non-unicast-only combinations keep today's per-peer
fallback with an operator-visible reason; when `per_client_best` is
configured but the key is not unicast-only (VPN/RTC families negotiated),
that reason is the existing `per_client_best` disqualification string,
reused unchanged — no new reason surface, the fallback behavior is
documented instead.

### 2. Group winner = first permitted candidate in best-path order

The per-client-best group staging pass replaces "evaluate the Loc-RIB best,
stage or filter" with the candidate walk `distribute_multipath_prefix`
already performs for ungrouped per-client-best peers, shared once per
group: collect candidates via the shared `multipath_candidates` collector
(minus the per-target split-horizon exclusion, which stays at member emit
per ADR-0098 Decision 4), sort by `best_path_cmp`, walk in order:

- **winner `w`** = first export-permitted candidate → staged in the group
  table at `path_id 0` (subsumes divergence 2);
- **runner-up `r`** = first permitted candidate whose source differs from
  `w`'s source → staged in the exception lane;
- early exit once both are found.

At zero overlap the walk terminates after one permit — cost identical to
today's grouped pass. Each overlapped prefix adds one candidate evaluation.
No term anywhere scales with member count: the receipt's steady-state
plateau (per-client-best-only, F-scaling, upstream of the commit fan-out)
belongs to the per-member candidate-multiplicity class this design removes
structurally, and no phase of this design reintroduces it. The bound
extends to the emit seam's per-member derived-view queries (the OTC and
denial views): each probes the pass's staged set against the lane and
denial residues rather than scanning a residue per member, keeping the
per-pass cost O(members × staged prefixes).

**Staging trigger:** the pass hands per-client-best groups the same
widened changed-prefix set the ungrouped per-client-best path enumerates
— every prefix with any candidate change, not only Loc-RIB best flips —
because the walk's input is the candidate list, not the Loc-RIB best. A
candidate withdrawal or re-rank can flip the winner or retire the
runner-up while the Loc-RIB best stands (the chain may deny that best
outright); staging only best-flip prefixes would leave the lane stale —
the issue-#21 class Decision 6 rules out. Plain groups keep the exact
best-changed set: their staging input is Loc-RIB-best-or-nothing, so the
narrow set is complete for them, and the widened set is not built at all
when no per-client-best group exists. Winner-equality and lane
suppression make the widened pass a no-op wherever neither slot moved,
which is what keeps the per-candidate-change pricing above intact.

**Counter recording:** every evaluation the walk performs enters the
group's eval accumulator — the winner's permit, the runner-up's permit,
and every candidate denied ahead of either. This is not a two-eval
special case: the walk visits candidates in best-path order and the
winner is the first permitted one, so each candidate it steps over was a
real chain evaluation, and the ungrouped per-client-best path records
those denials too — `distribute_multipath_prefix` records the evaluation
before it branches on the verdict.

No new machinery is needed. `GroupEvalAccumulator::record` is already
per-evaluation — one call bumps `totals` and the candidate's `per_source`
row — so the winner walk calls it for the runner-up exactly as it does
for every other candidate it evaluates: no new accumulator shape and no
new replay path, and `apply_group_policy_counters` replays
`totals − own-sourced` unchanged.

That replay makes this a judgment call between over-replay and
undercount, not a parity result. `per_source` is keyed by the
candidate's **source** peer, so subtracting `per_source[member]` can
withhold an evaluation only from the member that sourced that candidate;
no term can withhold it from anyone else, and adding one means per-member
walk bookkeeping — the O(members × candidates) cost this design exists
to delete. The two reachable options are:

- **Winner only** — exact for the N−1 members that did not source `w`;
  undercounts `source(w)` by one permit. Split horizon removed `w` from
  its own candidate list, so its ungrouped walk ran past `w` and
  recorded `r`'s permit, while the group would hand it the winner
  evaluation minus its own-sourced rows, which is nothing.
- **Every evaluation** (this decision) — exact for `source(w)`;
  over-replays the entire `w`-to-`r` segment, the intervening denials
  and the runner-up permit alike, to every member that sourced none of
  them and whose ungrouped walk stopped at `w`.

Over is the observability-safe direction: an undercount hides an
evaluation a member genuinely performed, while an over-replay shows
evaluations other members did not perform — the same posture as the
dirty-resync over-emit ADR-0098 records as an as-built deviation. The
divergence is bounded by the lane's O(overlapped prefixes) population,
lands as aggregate integer adds rather than records per (prefix × peer),
and does not touch the equivalence verdict: the differential oracle
compares per-member streams and folded state, never counters.

### 3. The exception lane: a per-prefix runner-up sidecar

The runner-up lives in a per-group sidecar map keyed by prefix — one
staged post-policy `Route` shell plus next-hop-override residue and
captured source attributes, exactly the group table's per-entry payload —
**not** inside the group table and **not** per member:

- Not `path_id 1` entries in the table: every existing query, counter,
  resync, and replay seam assumes grouped unicast state lives at
  `path_id 0`; a second in-table rank would leak into all of them and
  re-open the Add-Path rank problems of ADR-0099 Decision 5.
- Not a per-member map: O(members × prefixes) is the shape grouping
  exists to delete.
- Not a candidate reference re-derived at emit: replay — refresh, join,
  resync, channel-full drain — must deliver `adv(m)` with zero policy
  re-evaluation, which requires the post-policy form; the cost is
  bounded by the lane's O(overlapped prefixes) population.

State is O(overlapped prefixes) — populated only where a distinct-source
permitted runner-up exists (18,304 / 91,520 entries at the receipt's two
overlap points, against 183,040 table entries). ADR-0099 Decision 6
already blessed this shape for ORR: stage top-2, single-best keeps
`path_id 0` constant.

### 4. Derived views: the advertised-map invariant

No per-member advertised record is added. A member's advertised set is a
pure function of shared state and member identity:

> **adv(m)** = for each prefix: `w` if `source(w) ≠ m`; else `r` if the
> lane holds one; else nothing — always at `path_id 0`.

This is the ADR-0099 Decision 2 pattern (a per-member emit-time exception
that is a function of entry content/source and member identity, never
per-member history), so it composes with the group-level equality baseline.
Every cold path derives the same function: join, RFC 2918 refresh, and
GShut force-refresh replay `adv(m)` family-filtered with zero policy
re-evaluation (the lane entry carries its post-policy form); dirty resync
announces `adv(m)` and withdraws `tombstones ∖ adv(m)` (over-withdraw
remains the safe direction); advertised queries, BMP stat 17, and adj-out
gauges synthesize from per-source counts with the one-substitution
adjustment.

The query and count synthesis reports `adv(m)` **minus OTC-blocked
slots** — the outcome of the Decision 5 backstop, which strips a
blocked route from every emission while the winner stays in the table
and a blocked runner-up stays in the lane. The ungrouped path's
Adj-RIB-Out is post-backstop by construction (a stripped route is never
committed), so the derived views subtract the same slots to report the
same truth: the blocked winner toward every non-source member, a
blocked lane substitution toward `source(w)`. The OTC residue and the
lane supply the subtraction's inputs; an exact-export rejection at a
slot the backstop already suppressed subtracts nothing further. A plain
group's in-walk gate keeps blocked routes out of its table, so its
views carry no subtraction at all.

### 5. Emit: one new source-flip matrix arm plus a lane delta

`GroupDelta` gains the lane transition (old runner-up, new runner-up)
alongside the existing `(new, old_source)` pair. The source-flip matrix
extends:

- `member == source(w_new)`: announce `r` (implicit replace at
  `path_id 0`) when the lane holds one; withdraw otherwise (today's arm).
- Lane-only change (runner-up flips or retires, winner unchanged): one
  member-scoped delta toward `source(w)` only — announce `r'` or withdraw.
  Equality suppression applies within the lane.
- All-candidates-gone: the shared withdraw is correct for every member
  including `source(w)` (its wire held `r` at the same path-id-free slot).
- Source flip `A → B`: members ≠ A,B ride the shared payload; A gets `w'`;
  B gets `r'`-or-withdraw. Decidable from the delta alone, as today.

The shared `Arc` payload path (ADR-0098 Decision 6) is unchanged; the
exceptions set gains at most the winner/runner-up sources per delta.
Member-scoped emissions lost to a full outbound channel record into
`pending_extra_withdraws` via the existing
`member_scoped_withdraws` seam, extended with the lane arms — the
ADR-0099 channel-full mechanism, not a new one. rs-control communities
divergence (ADR-0101 Decision 3) applies per member at the same emit
seams; lane entries carry source attributes so tag transitions extend to
them.

RFC 9234 OTC egress for per-client-best groups is enforced at the
central pre-commit backstop, matching the ungrouped per-client-best
path's semantics: the winner walk stages the first permitted candidate
regardless of OTC, and every member emission — steady-state, refresh,
join, and resync alike — passes through the backstop, which strips a
blocked route and converts it to a withdraw where a delivered
advertisement may be replaced (over-withdraw remains the safe
direction). The in-walk gate serves single-best staging only. A blocked
winner therefore stays in the group table and a blocked runner-up stays
in the lane; the group's OTC residue derivation covers both — the
recorded winner for non-source members, the lane entry toward
`source(w)` — so per-member diagnostics and the replay reconciliations
see exactly the backstop's outcome. The differential-oracle comparison
is post-backstop on both sides, so byte-identity holds with OTC-blocked
routes invisible to both.

### 6. The OpenBGPD bug family, as non-goals-to-avoid with mechanisms

- **Stale second-best after best withdrawal** (issue #21): impossible by
  construction — there is no per-member rib-out record to go stale;
  `adv(m)` derives from live shared state, every table delta recomputes
  the lane in the same pass, and resync over-withdraws (RFC 4271 no-op).
- **Missing suboptimal advertisement on startup/reload** (issue #21):
  replay and steady-state emission use the single `adv(m)` derivation —
  there is no second bookkeeping path to diverge.
- **Churn on content-equal reload**: interned chain-content keying
  (ADR-0098 Decision 1) makes a content-equal reinstall key-stable;
  nothing restages, nothing emits. A candidate flip that does not change
  `w` or `r` emits nothing (equality suppression at both slots).

### 7. Why this does not hit the Add-Path walls

ADR-0099 Decision 5's disqualifiers are per-member *rank sequences* and
per-member *id history*. Here every member receives at most one route per
prefix at constant `path_id 0`: no rank assignment, no id holes, no
renumbering; withdraws are derivable, not recorded. The substitution is a
pure function of shared state and member identity — the same property that
admitted the RT filter (Decision 2) and control communities (ADR-0101
Decision 3). Add-Path send itself stays disqualified; nothing here narrows
that verdict.

### 8. Generation flips, regroup, and ADR-0105 fencing

A policy reload that changes chain content regroups per-client-best members
like any grouped member: the destination group's table *and lane* are built
once per group (one candidate walk per prefix), members diff against
regroup baselines. Per-client-best groups are **excluded from the ADR-0105
narrow fast path**: its clean predicate (zero policy-filtered routes on
both sides) contradicts the mitigation's reason to exist, and ADR-0105's
"do not broaden" rule stands. They take the ordinary authoritative/regroup
machinery behind the same fences; the 60-second pre-commit ownership budget
and fail-closed handoff apply unchanged, and the handoff target — the
per-peer path — remains a complete correctness fallback (Decision 9's
oracle guarantees equivalence).

The exclusion is demand-gated rather than permanent, and the Non-goals
entry controls until the trigger fires. A per-client-best group with no
policy-filtered routes is one that does not need the mitigation, so
admitting the fast path today would make its correctness assumption hold
only where the mitigation is a no-op — speed bought exactly where there
is nothing to speed up. Re-inclusion is reconsidered only when all three
of the following hold, with a receipt: (a) a deployed fleet runs
per-client-best grouped at the canonical receipt shape; (b) that fleet
reloads regularly at a measured filter-churn rate that pushes reload
completion out of the grouped-control class (~4.5 s ceiling); and (c)
that reload-time cost is attributable to the policy-transition path the
fast path skips. Absent all three the exclusion stands — the same
earn-it-with-a-receipt discipline as the acceptance gate below and the
Decision 9 rendered-default fallback.

### 9. Migration and observability

Classifier flip lands last (Phase 3): existing per-client-best fleets
regroup through the ordinary baseline diff, which must be byte-empty on a
converged fleet (test-pinned) — no session resets. The per-peer path
remains the correctness oracle: the grouped-vs-forced-ungrouped
differential suite (`update_groups_oracle.rs`) extends to per-client-best
fleets with overlapping announcements, asserting identical per-member
streams across staging, refresh, join, resync, channel-full, and regroup.
Observability: membership label `group:N` replaces the `per_client_best`
fallback reason for shareable chains (the reason string remains for
residual disqualifying combinations); `rbgp neighbor show` still names the
per-client-best distribution mode; a lane-size gauge
(`bgp_update_group_runner_up_entries`) exposes the O(overlapped prefixes)
claim; the received-view-delta verifier is the campaign-level equivalence
instrument.

Rendered-default timing: `rs-config-render` fleets group immediately at
ship, conditional on the acceptance gate below — both prongs, not the
flip alone. The default flips in the release that lands Phase 3 only if
the received-view-delta verifier proves byte-identical per-member views
**and** the receipt meets the committed ≥4× sampler RSS-peak reduction.
If the receipt misses that target, the rendered default holds one
release behind an opt-out and flips only on a passing receipt.

## Open decisions

None. The five questions this ADR opened — fallback reason, counter
replay for the walk's evaluations, rendered-default timing, lane storage
form, and ADR-0105 fast-path re-inclusion — are decided and folded into
the design above, as Decisions 1, 2, 9, 3, and 8 respectively. What
remains before this ADR can move to Accepted is not a decision but the
acceptance receipt below.

## Acceptance gate

From the sealed realistic-mix receipt, at the canonical 320 × 183,040
shape, F ∈ {0.1, 0.5}:

- **Equivalence:** byte-identical per-member received views versus today's
  ungrouped per-client-best path — every runner-up pair (18,304 / 91,520)
  delivered, nothing else — proven by the received-view-delta verifier and
  the extended differential oracle.
- **Cost:** ≥4× sampler RSS-peak reduction versus the sealed per-client
  rows (10.4–11.3 GiB), and steady-state reload completion p50 in the
  grouped-control class (~4.5 s ceiling); the one-extra-evaluation overlap
  term must not move completion out of that class at F = 0.5.

## Implementation phases

1. **Staging dark:** first-permitted winner walk + runner-up lane in the
   group pass behind an unchanged classifier; exhaustive lane/source-flip
   unit matrix.
2. **Emit seams:** matrix arm, lane deltas, channel-full recording, dirty
   resync, refresh/join replay, queries/counters, rs-control transitions.
3. **Classifier flip:** key bit, regroup migration, observability,
   differential-oracle extension to overlapping per-client-best fleets.
4. **Receipt:** rerun the realistic-mix campaign, gate as above; amend this
   ADR to Accepted with the measured rows; confirm `rs-config-render`
   keeps `path_hiding = true` with grouped output.

Risk concentrates in Phase 2, not Phase 3. The runner-up lane is new
group-shared mutable state, correctly excluded from the ADR-0105 fast
path — that path's clean predicate (zero policy-filtered routes on both
sides) contradicts the mitigation's reason to exist. The dirty-resync
over-withdraw path and the channel-full `pending_extra_withdraws` seam
must both handle the lane arms before the classifier flips; defects in
this design will concentrate at the emit seams, not the classifier
flip.

## Non-goals

- **Add-Path send grouping** — stays disqualified per ADR-0099 Decision 5
  ("per-member path-id maps or nothing").
- **Per-client Loc-RIBs** — rejected permanently (ADR-0101 Decision 2);
  this design is the RFC 7947 §2.3.2.2 delta formulation instead.
- **VPN/RTC per-client-best staging** and ORR combinations — out of scope;
  existing validation and fallbacks stand.
- **ADR-0105 fast-path broadening** — per-client-best groups stay
  excluded; demand-gated re-inclusion trigger in Decision 8.
- **Sorted tables or comparator restrictions** — the BIRD `secondary`
  constraint set is exactly what the derived-view shape avoids.

## Consequences

If accepted and gated, the rendered route-server default becomes
simultaneously RFC-7947-mitigated and grouped: grouped-class memory and
reload completion at the flagship shape without giving up the mitigation,
with the per-peer path retained wholesale as the correctness oracle and the
fallback for non-shareable chains. The costs: one more group-key bit, a
sidecar lane on per-client-best groups, one more matrix arm to keep proven
by the exhaustive unit matrix and the differential oracle, and a second
export-policy evaluation per overlapped changed prefix.

## References

- RFC 7947 §2.3 (path hiding; §2.3.2.2 per-client views as deltas over a
  global Loc-RIB; §2.3.3 Add-Path send-only) —
  <https://www.rfc-editor.org/rfc/rfc7947>
- BIRD User's Guide: `secondary` (first filter-accepted route from a
  `sorted` table; `sorted` incompatible with `deterministic med`) —
  <https://bird.nic.cz/doc/bird-3.1.2.html>
- OpenBGPD `rde evaluate all` bug family (fixed in 7.0) —
  <https://github.com/openbgpd-portable/openbgpd-portable/issues/21>
- arouteserver path-hiding defaults and per-daemon implementation —
  <https://arouteserver.readthedocs.io/en/latest/GENERAL.html>
- CZ.NIC, "BIRD Journey to Threads. Chapter 3½: Route server performance" —
  <https://en.blog.nic.cz/2022/02/21/bird-journey-to-threads-chapter-3%C2%BD-route-server-performance/>
- Richter et al., "Peering at Peerings: On the Role of IXP Route Servers",
  IMC 2014 (the path-hiding mechanism); Alhamwy et al., SIGCOMM 2025
  Posters (route-diversity point estimate behind the receipt's F values)
- In-repo: ADR-0098, ADR-0099, ADR-0101, ADR-0105,
  [realistic-mix receipt](../perf/irr-reload-realistic-mix-2026-08.md)
