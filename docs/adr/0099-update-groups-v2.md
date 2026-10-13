# ADR-0099: Update groups v2 — per-family keying and RT-aware VPN emit

**Status:** Accepted — shipped across #685 (VPN group staging for non-RTC
groups, family-extended key) and #686 (per-member RT filter at emit +
the membership-delta path), closed by the source-flip channel-full fix
and the VPN scale receipt in this slice.
**Date:** 2026-07-03

A [proposed EVPN amendment](#amendment-2026-10-13-evpn-update-groups) follows
the original record. It is not implemented; the accepted record below describes
the shipped unicast/VPN design.

## Context

ADR-0098 shipped update groups for the unicast RR fanout and left the
other families on the per-peer path. The measured VPN shape at 256
clients repeated the unicast indictment: per-peer `stage_vpn_routes`
was 27.3% of flood CPU plus 40.2% in the per-peer commit (rrharness
vpnflood profile), 18.7 s single-shot convergence, and 8.2 GiB RSS —
a full VPN Adj-RIB-Out per (peer × identity). The v2 design report
(2026-07-03) resolved the four v1 deferrals: per-family keying,
RT-Constrain-filtered VPN, Add-Path send, per-vantage ORR.

## Decisions

1. **One group per peer; the single `GroupKey` gains the groupable
   family dimension.** `sendable_vpnv4`, `sendable_vpnv6`, and
   `rtc_negotiated` (sendable ∋ `(Ipv4, RtConstrain)`) join the key —
   there is NO per-(peer-set × family) membership. Dirty is per-peer
   (a `try_send` failure dirties every family at once), so split
   memberships would still need one coordinated resync spanning both
   groups; the single key reuses every v1 lifecycle seam (regroup
   baselines, tombstones, extra withdraws, gauges) unchanged. Group
   count scales with distinct family-mix configs, never with peer
   count. Sendable families are fixed at OPEN, so the new key
   components add no regroup triggers. VPN staged entries live in the
   VPN maps of the `AdjRibOut` substrate the group table already owns
   (`path_id` 0 only). Labeled-unicast, EVPN, FlowSpec, BGP-LS, and
   RTC's own SAFI-132 table stay per-peer verbatim (RTC's table is
   tiny; no receipt would justify grouping it).

2. **The RT filter is a per-member emit-time filter — not in the key,
   not a disqualifier.** In the key (option a), a PE fleet with
   distinct RT sets would shatter to one group per peer — exactly the
   pre-arc shape. As a disqualifier (option c), the flagship workload
   would be exempted. Option (b) is sound because `pass_m(route)` =
   no filter ∨ `Φ_m.matches_any(route.extended_communities())` is a
   **pure function of route content and the member's current
   membership** — never per-member history — so it composes with the
   group-level equality baseline. Filter *presence* is group-uniform
   (`rtc_negotiated` is in the key); Φ itself never enters the key.
   `RtcMembership::matches_any` (the 96-bit covering-prefix core) is
   REUSED at every seam — there is no second implementation of RTC
   matching semantics to drift.

3. **The Φ emit matrix and its invariant.** The VPN delta carries the
   full displaced route (`old`), not just its source — the RT decision
   on the displaced entry needs its extended communities. Per member:
   `had` = old exists ∧ old.peer ≠ m ∧ pass_m(old); `gets` = new
   exists ∧ new.peer ≠ m ∧ pass_m(new); emit `gets` → announce,
   `had ∧ ¬gets` → withdraw, else skip. The load-bearing invariant:
   **adv(m) = { e ∈ group VPN table : e.peer ≠ m ∧ pass_m(e) } under
   m's CURRENT Φ.** Staging emit preserves it when the table changes
   with Φ fixed; the membership-delta path restores it when Φ changes
   with the table fixed; the single-task manager never interleaves the
   two mid-pass. An oracle invariant checker recomputes adv(m) from
   manager state after every scenario step.

4. **Φ changes take a membership-delta path, not a restage.** Every
   `peer_rt_membership` mutation routes through ONE function
   (`set_rt_membership` — design risk 1). A changed Φ on a live
   VPN-grouped member triggers one walk of the group VPN table —
   old-Φ vs new-Φ per entry — emitting the member-scoped minimal
   RFC 4684 wire delta with ZERO policy evaluations and the table
   untouched (the table is a pure function of (Loc-RIB, group key); Φ
   is member state and cannot touch it by construction). This is
   wire-equivalent to the per-peer dirty restage and strictly cheaper.
   Ungrouped and non-VPN-grouped peers keep the per-peer restage.

## Verdicts on the remaining v1 deferrals

5. **Add-Path send: stays disqualified — per-member correction is
   unsound without per-member state.** The "skip own + stage N+1"
   emit was analyzed hard; where it breaks (design §3, recorded here
   so a v3 knows the bar):

   1. *Path-id assignment is a per-member rank sequence, not a shared
      one.* Per-peer assigns outbound `path_id = 1..=N` over its own
      filtered candidate list. A member whose own candidate holds
      shared rank k either (a) emits ids `{1..N+1}∖{k}` — a hole that
      diverges from the per-peer stream and renumbers *unchanged*
      routes whenever k moves between passes (wire churn the per-peer
      path never produces), or (b) renumbers per member —
      reintroducing the per-member O(deltas) clone cost AND breaking
      the group-table equality baseline (`(key, path_id)`-keyed
      equality at group level no longer corresponds to any member's
      advertised state, so group-level suppression emits wrong member
      deltas). Fixing (b) requires per-member advertised maps —
      deleting the memory win that is the point of grouping.
   2. *Exact withdraws are per-member history.* The "withdraw ids ≥
      next_rank ∪ stale 0" step reads the per-peer rib-out record;
      the group has no per-member id history and id sets differ per
      member. The fallback is over-withdrawing every pass on the hot
      path — a standing wire-parity violation, not the rare
      dirty-resync carve-out.
   3. *Ties are NOT the blocker*: the sort is stable and the
      comparator target-independent (ORR disqualifies), so
      filter-then-sort ≡ sort-then-filter within a pass; tie-order
      drift across passes exists per-peer today and only amplifies
      (1)/(2).
   4. *VPN Add-Path + RTC is categorically unsound for a shared
      list*: the RT gate runs per candidate inside the ranked loop,
      so member ranks depend on Φ_m — no shared ranking exists.
   5. *Benefit is small*: Add-Path send is the RR-mesh case — a
      handful of peers, not the 256/1000-client fanout the receipts
      indict.

   The honest v3 answer is "per-member path-id maps or nothing".

6. **Per-vantage ORR grouping: cut.** Mechanically it rides the
   existing machinery (vantage joins the key; the one member-exception
   — the vantage winner's own source takes second-best, ADR-0095
   Decision 5 — is soundly handled by staging top-2, since single-best
   keeps `path_id = 0` constant). It is cut because the win is bounded
   by peers-per-vantage (small in practice) while adding a second
   staged-table dimension whose memory scales with vantage count.
   **Un-defer trigger:** an operator running many peers per vantage.

## As-built deviations from the design report

- **Targeted heal instead of the blanket failing-Φ withdraw.** The
  design's §2.4 dirty-resync withdraw term ("every table key failing
  ¬pass_m") would put spurious withdraws on clean regroup one-shot
  diffs, which are held to exact-stream parity. Instead the Φ-write
  seam records exactly the keys leaving Φ into the member's
  `pending_extra_withdraws`; the Φ-aware resync retention drops any
  key that re-enters Φ before the resync runs. Same self-healing
  guarantee, exact where the design was blanket.
- **Counter semantics (extends the ADR-0098 carve-out).** The
  membership-delta path bumps permit counters only for newly-passing
  entries (replayed from staged labels); the per-peer restage would
  re-record evals for every still-passing key. Group VPN staging also
  records one eval per key regardless of Φ, where the per-peer path's
  RT gate precedes its policy eval. Totals are aggregates; the oracle
  compares streams and folded state, never counters, for these
  scenarios. Per-member `(vpnv4, vpnv6)` advertised counters — which Φ
  makes non-derivable from group source counts — are maintained
  incrementally at the emit seams, recomputed exact at
  join/resync-complete, and cross-checked by a debug-assert table
  recompute in tests.
- **Channel-full member-scoped withdraws (the slice-1 gap, fixed
  here).** A member-scoped withdraw whose delta still holds a table
  entry — the source-flip arm (member == new source, displaced old
  entry; unicast and VPN) and the VPN RT-mutation-out-of-Φ arm — is
  invisible to group tombstones, which only track table withdrawals.
  Lost to a full outbound channel, it previously stranded a stale
  route on that member until the next covering event. Fixed with the
  existing mechanism: the send-failure seams record the emission's
  member-scoped withdraw keys into that member's
  `pending_extra_withdraws` (`GroupStageOutput::member_scoped_withdraws`,
  `VpnGroupStageOutput::member_scoped_withdraws`); the resync
  retention guard drops any key the member should retain. Two oracle
  scenarios pin it (channel-full forced on exactly a source-flip
  delta, folded-state + invariant assertions; both failed before the
  fix).

## Consequences

Receipts (rrharness, same host, real transport sessions over loopback;
256-client numbers are 3-run medians from the slice PRs, 1000-client
numbers are 3-run medians from the close slice —
`docs/perf/scale-receipt-2026-07.md` has the full tables):

- **Uniform VPN flood (100k VPNv4, no RTC):** 256 clients 18.66 s /
  8227 MiB per-peer → 3.75 s / 492 MiB grouped (~5×, ~17×); 1000
  clients 12.60 s / 625 MiB measured vs ~73 s / ~31 GiB extrapolated
  per-peer (linear model, never measured).
- **Heterogeneous RTC (~10% Φ):** 256 clients 3.21 s / 1481 MiB →
  1.10 s / 482 MiB; 1000 clients 3.92 s / 636 MiB measured vs
  ~12.5 s / ~5.7 GiB extrapolated. Per-peer `stage_vpn_routes` falls
  50% → 3% of samples; the `matches_any` emit walk did not eat the
  win (option-(c) fallback never triggered).
- **Membership flip at scale (1000 clients, 100k staged):** one member
  widening/narrowing its Φ by one RT (1600 routes) emits the
  member-scoped delta fully decoded on that member's wire in ~15 ms /
  ~12 ms — zero policy evaluations, group table untouched.
- The per-member `matches_any` walk is the standing scale risk
  (O(RTs × entries) per member per pass); the upgrade path is a
  sorted-prefix/interval structure over the 96-bit space or
  membership-bucketed payloads, and the option-(c) key change stays
  one line away.
- Metrics are unchanged (membership is still one group per peer);
  `bgp_rib_adj_out_prefixes{afi_safi="vpn"}` for grouped members is
  synthesized from the group table under the member's Φ.

## Amendment (2026-10-13): EVPN update groups

**Status:** Proposed — review and merge this amendment before implementation.
The amendment would replace the EVPN exclusion in decision 1 and clarify the
shared parity contract. Other family exclusions and the original dated results
remain unchanged. This changes storage and distribution of existing EVPN routes,
not their support classification: Types 1–5 reflection, Type 6, VTEP, IRB,
multi-homing and Linux dataplane retain their respective contract boundaries.

### Reason to reopen

The [September fanout baseline](../perf/evpn-fanout-2026-09-05.md) measured
hundreds of receivers but did not attribute the cost. A subsequent exploratory
allocation study of revision `8e54da81e`, using release/jemalloc, a daemon-only
cgroup and two receiver counts at fixed route totals, attributed 96% of live
heap to the per-peer EVPN outbound maps. Each occupied hash bucket contains a
64-byte key, a 152-byte route and one control byte. Capacity rounding explained
the different measured slopes, approximately 286 and 383 bytes per delivery.
This is component attribution, not a qualified soak receipt, a production
envelope or a measured encode speedup.

One shared table removes the repeated route bodies and keys for equivalent
receivers. Replacing only the value with an `Arc` would shrink each slot but
retain one table per receiver and repeated policy/encoding work. Choose grouping;
do not first ship that intermediate storage design. Group count, dirty-member
history and encoding subsets determine the remaining cost, so neither a fixed
28 MB result nor a CPU improvement is promised by this amendment.

### A. One registry and one key

Extend the existing `UpdateGroupRegistry`, `GroupKey` and `GroupRibOut`; keep one
group membership per peer spanning its groupable families. Add `sendable_evpn`
for negotiated `(L2Vpn, Evpn)`. Retain all existing key dimensions: effective
export-chain **content**, eBGP target, RR-client status, local role, RFC 1997
interpretation, sendable unicast/VPN families, RTC negotiation, per-client-best
mode and the exact LLGR family set. The global cluster ID remains a shared
reflection input; a change must invalidate affected staging/encoding through
the existing reload and regroup seams.

The member's address and RT membership do not enter the storage key; they select
its view of the table. Router IDs remain metadata for existing reflection
attribute preparation. RD, MAC, ESI and VNI are route data, not group
dimensions. Transport encoding profiles form separate sharing cohorts; unequal
wire forms must never split or corrupt the RIB's desired table.

Keep existing fallback reasons: peer-context-dependent policy, negotiated
Add-Path send, ORR, ORF, conditional advertisements and slow-peer isolation.
Keep mixed EVPN per-client-best peers on the private path: both unicast-only
classifiers and the clean-policy-transition classifier must exclude EVPN until
their respective algorithms explicitly support it. Do not accidentally activate
a unicast runner-up or transition lane by adding just the new key bit.

Group the currently supported EVPN family, including preservation of existing
Type 6 values; do not introduce separate ownership by route type. Add-Path stays
disqualified under decision 5. This amendment adds no EVPN Add-Path capability,
new route type, origination behavior or stable surface.

### B. Export once, preserve the input to RTC

Stage each affected EVPN key once per group using the existing family-specific
gates and export evaluator. Equal chain names are insufficient: the interned
chain content and its effective fallback must agree. A chain matching destination
address, ASN or peer group remains ungrouped even if its content is identical.
Keep current gate order, Type 5 prefix matching, community rules, GR/LLGR behavior
and explicit next-hop policy actions. Group membership changes when these inputs
change; queued envelopes retain their captured profile and generation.

The group entry owns one post-policy route plus shared **pre-policy** RT match
input and source/reflection identity. The current EVPN RTC gate reads the received
route before export policy can add or remove RTs. Filtering the post-policy route
would therefore change behavior. Reuse the existing `RtcMembership::matches_any`
matcher, including Type 4 ES-Import handling; retain the old match input in a
displaced-entry delta, not a lookup into the already changed Loc-RIB.

Equality includes that match input, not just the post-policy bytes. For example,
an RT100-to-RT200 change under a policy that removes both RTs still withdraws the
key from an RT100-only member and announces it to an RT200-only member. Conversely,
an input-only change that leaves a member's eligibility and exported bytes equal
uses the existing private-path equality rule to avoid an extra event. Policy
denial and counter residue belongs once to the group; replay applies member
eligibility without a second policy evaluator or a full denial map per receiver.

### C. RTC stays a per-member filter

RTC negotiation stays in the key; the actual membership Φ stays outside it, as
permitted by [RFC 7432 §7.10](https://www.rfc-editor.org/rfc/rfc7432.html#section-7.10)
using [RFC 4684](https://www.rfc-editor.org/rfc/rfc4684.html). For a
staged entry `e`, define `eligible(m,e)` as the current source exclusion and RR
rules together with `Φ_m.matches_any(e.received_rts)`; without RTC, that last term
is true. The entry has already passed the group-uniform gates and policy.

| Choice | Stored route tables | Update and membership-change cost |
| --- | --- | --- |
| Split by exact Φ | Up to one table per member; identical memberships can share | Stage/policy/encode per distinct membership; membership changes regroup and rebuild a baseline |
| Per-member filter, chosen | One table per existing staging profile, independent of distinct Φ sets | Match affected entries per member; a Φ change scans the group table once for that member |

Per-member filtering does not guarantee a memory win for every RTC fleet. Compare
the sum of group-table capacities with the sum of private member-selected
capacities, including source-RT metadata and recovery residue. For example, 100
members each interested in one of 100,000 routes can have only 100 private rows,
while an unfiltered group table retains 100,000. Distinct export profiles multiply
that union cost. Keep RTC-negotiated EVPN on the existing private-family path
unless its no-regression qualification passes; qualified unicast/VPN grouping
remains enabled for the same peers. This family-ownership choice is fixed for the
activated/session profile, not switched by live table size. Non-RTC EVPN grouping
can ship first. Do not add an automatic cost heuristic or union-of-interest
staging in this amendment.

The chosen filter also does not remove O(members × affected keys) matching or all
per-member encoding. Matching cost depends on membership size. Reuse bounded
walks and readiness checkpoints; do not add an RT index or claim a latency
improvement without qualification.

At a table change with Φ fixed, use both displaced old and new entries:
`had = eligible(m,old)`, `gets = eligible(m,new)`. Announce a newly eligible or
changed exported value using the private path's suppression predicate; withdraw
only `had && !gets`; otherwise emit nothing.
At a Φ change with the table fixed, apply the same matrix with old/new Φ and no
policy evaluations. A source flip, input-RT change or membership change can require
a member withdrawal while the key remains in the group table. Record that exact
withdrawal duty in the existing member-scoped extra-withdraw machinery extended
to EVPN. Do not substitute blanket withdrawals of all nonmatching keys.

### D. Reflection and shared encoding

Keep today's EVPN eligibility: direct-source exclusion at member emit, the
existing client/non-client RR matrix, and receive-side originator/own-cluster
loop rejection. `ORIGINATOR_ID` is preserved when present; otherwise
`apply_reflector_attributes` supplies the source router ID and prepends
the local cluster ID once. There is no negotiated destination cluster ID to add
to the key or to substitute into `CLUSTER_LIST`. These are the existing
[RFC 4456 §§6, 8 and 10](https://www.rfc-editor.org/rfc/rfc4456.html#section-6)
semantics. A route supplied by RR-A with originator C can still be sent toward
client C, which rejects it on receive. Grouping adds no sender-side originator
exclusion; parity is against the current private path. Any additional sender-side
rule needs a separate all-family decision.

Prepare attributes through each receiver's `SessionExportProfile` before proving
byte equivalence. For equivalent receivers the resulting RR attributes for a
given route are identical; they are not stamped with the receiver's own ID.
Preserve the current emitted EVPN MP next-hop form; `prepare_evpn_candidate`
currently emits no IPv6 link-local companion, and grouping adds none. Reflection
does not replace the VTEP next-hop with the RR address; explicit export-policy
actions retain their existing semantics.

The current shared transport encoder is **unicast-only**, even though VPN already
shares RIB storage. Extend its existing envelope, encode-election cell, producer
guard, progressive publication and session cursor for EVPN; do not fork a second
registry or producer lifecycle. Share bytes only for proven-equal prepared
attributes, next-hop form and a common eligible NLRI subset. One usable cohort
includes a single source, identical received-RT match input and identical original
originator ID, preserving equal prepared reflection attributes; source and RTC
exclusion cannot select half a chunk.
Different subsets or wire forms use separate cohorts or ordinary encoding.
Capture the member filter at queue admission; an
encoder must not consult a later live Φ and reorder a membership transition.

Keep negotiated AS encoding, eBGP/route-server transforms, graceful-shutdown and
LLGR form, message ceiling and MP next-hop form in the byte-equivalence proof.
Standard-size chunks can serve extended-message peers, but packing is not a proof
of attribute identity. Withdrawals, refresh markers and EoR remain member-specific
cursor phases. Every member, including the producer, consumes shared chunks only
at its EVPN announce phase, after its withdrawal/BoRR phases. Advance only that
family's phase on success; failure restarts that family's announcements without
repeating completed withdrawals or markers. EoR/EoRR uses the same ordered bulk
queue after the member cursor, or its full ordinary fallback, finishes the covered
routes; a producer's `Complete` flag alone is insufficient. If preparation fails
or the elected producer is canceled, its existing terminal guard wakes followers;
ordinary encoding retains validation and teardown behavior. Never leave an
initialized sharing cell without a live
producer or a terminal result.

### E. Membership, admission and targeted recovery

A clean member's derived table view equals its admitted outbound state. Join
replays only that view; a clean regroup snapshots the old member view and diffs
it against the new one. Preserve old source/RTC inputs across that boundary.
The admitted projection includes the existing `peer_unexportable` exact-export
rejection overlay as well as source/RR/RTC eligibility. A desired entry
that fails this member's export probe is neither advertised nor retained for its
resync; counts and pending-withdraw retention use this same admissible projection.
When the last member leaves, retire the group and its shared metadata using the
existing bounded retirement path. Other SAFIs retain their private storage.

A shared table is desired state, not proof that every member accepted a delta.
Reserve the member's queue capacity before recording admission. A full channel
retains the pending duties and marks that member dirty; a closed channel stops
retry for that generation. Membership removal belongs to the generation-matched
PeerDown/GR/collision lifecycle owner, not an arbitrary closed-channel observation.
One stalled or departed member must not prevent healthy members from advancing,
and a failed reservation must not clear a withdrawal duty or mark the member
resynchronized. Reuse the existing dirty timer, shared tombstones,
member extras and regroup baseline lifecycle.

Tombstones alone are **not** permission to withdraw a key from every dirty member.
On the first missed admission, retain a bounded, transient set of that member's
actually admitted keys, captured from the prior clean view, old Φ and exact-export
rejection overlay before the missed batch's projection changes. Alternatively,
reconstruct that entire prior view using every displaced delta; current desired
state is insufficient. Extend the existing baseline/residue ownership rather
than creating a standing advertised route map. Successful admissions update
this key provenance until recovery
finishes, using only the actually admitted, member-filtered batches. Intersect
tombstones and extra duties with it, then retain a duty only when the current
member view does not contain the key. This targets the heal and also prevents
a stale failed withdrawal from removing a newly eligible route.

Do not discard this provenance during a dirty RTC change, repeated regroup or
source flip. The initial EVPN recovery key-provenance limits are **16 MiB per
peer** and **256 MiB daemon-wide**, enforced together as internal admission caps.
Charge reserved container capacity and metadata, including snapshot, regroup,
retired and temporary resize copies; retain the charge until memory is freed.
Reserve credits before allocation and recheck before growth, rather than limiting
only the number of live keys. These are proposed resource ceilings, not measured
safe route counts; qualify them on the quiet host before production activation.

If capturing or growing provenance would exceed either cap, or allocation fails,
request a generation-matched session reset through the existing recovery owner
with reason `recovery_provenance_exhausted`; never continue with guessed
withdrawals. Count each accepted reset request in a dedicated recovery-exhaustion
counter, with a fixed cause vocabulary (`peer_limit`, `daemon_limit`,
`allocation_failure`), and log one structured warning for that peer/generation
with the cause, attempted byte charge and both caps. A stale-generation request
must not reset its replacement. This is a session reset under resource pressure,
not transparent recovery. Key sets are not route-body copies, but many dirty peers
can still cost O(dirty members × routes); report retained/peak charges and reset
counts alongside the transient envelope during qualification.

Keep per-member admitted counts and key provenance; failed sends do not advance
them. Existing page versions still invalidate conservatively on projection,
policy, Φ and lifecycle changes, including failed admission; do not add a second
version ledger. A dirty group projection must not be presented as the current
advertised RIB. For grouped advertised reads, choose the family-query pattern of a
same-actor `FAILED_PRECONDITION` guard until resync settles, rather than recreating
private route bodies. This availability tradeoff is accepted: report temporary
unavailability rather than label desired state as admitted output. The
implementation still needs surface/fixture review. Clean views, filters, paging,
explain and BMP stat-17 use the same member projection and admitted counts. MRT
Adj-RIB-In snapshots and BMP's successfully written UPDATE feed remain unchanged.

### F. One parity contract and a closed recovery list

Use one definition for unicast, VPN and EVPN: outside the recovery paths below,
for every receiver and route key the **ordered sequence** of announces and
withdraws equals the per-peer path, with exact NLRI and prepared attribute bytes.
No additional event, withdraw/reannounce transient or same-key reorder is allowed.
Compare the final receiver state as well. EoR remains after the routes it covers.
UPDATE packing, batch boundaries and the relative order of different keys are
unconstrained. This replaces a literal message-stream interpretation of
"exact-stream parity"; it does not relax per-key temporal behavior.

Only these paths permit extra idempotent announcements and require end-state
parity instead of identical per-key event sequences:

| Recovery path | Why replay may differ |
| --- | --- |
| Dirty-peer resync after outbound queue deferral | The shared desired table advanced while that member missed admission; rebuild its current view and heal its recorded withdrawal duties |
| Peer reset or rejoin | A new session requires a fresh advertised baseline; GR/LLGR retained state is settled by the correctly ordered family EoR |
| Regroup interrupted by an already dirty member or failed admission | The retained old baseline and exact pending duties must converge to the new group view despite incomplete earlier delivery |
| Ordinary announce fallback after partial shared-encoder failure/cancellation | Previously sent identical announcements may repeat when the announce inventory restarts; completed withdrawals/markers must not restart |

Even these paths forbid spurious withdrawals: withdraw only a key known to have
been admitted to that receiver and no longer retained, preserving its exact
family identity. A clean join/regroup, normal RTC change, source promotion, GR
stale replacement, route refresh or forced GShut replay is not an additional
exception; compare its events against the corresponding per-peer operation.
Exceptions do not excuse missing announcements, missing withdrawals, changed
attributes or premature EoR.

The existing `update_groups_oracle.rs` compares sorted unicast/VPN RIB-level
batches for most scenarios; several dirty, source-flip, interrupted-regroup and
failed-force scenarios compare only folded state. It also has a folded-only
steady-state per-client-best source-promotion exception. Its folds accept unknown
withdrawals, its comments permit tombstone over-withdraw, and its normalized
records contain neither EVPN events nor final encoded attribute bytes. These
are gaps against this clarified contract, not evidence that it already passes.
Tighten the shared oracle to flatten events by session/receiver/family/key and
compare the ordered per-key sequences **and** folded receiver state. Assert that
each withdrawal removes a currently present key, even in recovery scenarios.
Pin EoR barriers and final-byte transport checks, and remove the steady-state
promotion exemption. Preserve the original ADR's dated
as-built history while correcting affected shared recovery behavior before the
EVPN classifier is enabled. An exception must be named here, not inferred from
a failing test.

### G. Implementation and qualification gates

After this amendment is reviewed and merged, implement in bounded slices with
regressions that fail with the relevant change removed:

The shared-oracle tightening in section F is a **separate v1 correctness slice**,
tracked and reviewed independently of EVPN storage and encoding. It owns unknown
withdrawals, tombstone over-withdraw, the folded-only promotion exemption and any
shipped unicast/VPN defects that the stronger oracle exposes. Its own PRs and
validation must settle those findings before EVPN production activation; do not
bury them in an EVPN rollout commit or alter the parity contract to obtain green
tests.

1. Extend the reviewed recovery machinery for EVPN with the bounded key
   provenance, counted/logged reset fallback and admitted views in section E;
   pin dirty RTC changes, repeated regroup and limit/allocation-failure behavior.
2. Add EVPN staging/storage/member views behind the existing grouping classifier,
   with Type 1–6 identities, source flips, pre-policy RT changes under modifying
   policy, GR/LLGR, eligibility and no-op suppression coverage.
3. Extend shared encoding with final per-key byte/event comparisons, differing
   profiles/subsets, producer cancellation/failure, deferral and ordered EoR.
4. Qualify the candidate with relevant EVPN reflection and RR cluster-list legs,
   including
   M14/M100 and M123, pass on the exact head. Cover advertised API/CLI, paging
   invalidation, metrics and BMP surfaces; review any dirty-read status change
   against the maintained contract without changing the stable inventory here.
   Keep unqualified RTC EVPN on its private-family fallback.

Before activating grouping in main, repeat the fixed-route-total,
two-receiver-count memory cells with release,
jemalloc and a daemon-only cgroup with no swap. Record allocated/live and peak/
steady cgroup memory, group count, member metadata and dirty/regroup/encoding
residues. The one-group per-receiver route-storage slope must collapse; distinct
export profiles and heterogeneous RTC must not regress against the private path.
Run convergence/readiness and soak-shape qualification on a quiet host. Correctness
and quiet-host resource gates must pass before production activation. Publish
the resulting operational envelope with its receipt, not an extrapolated or
loaded-host speedup. No runtime code, measurement, inventory or promotion change
is part of this proposed amendment.
