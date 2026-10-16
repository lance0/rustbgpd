# ADR-0099: Update groups v2 — per-family keying and RT-aware VPN emit

**Status:** Accepted — shipped across #685 (VPN group staging for non-RTC
groups, family-extended key) and #686 (per-member RT filter at emit +
the membership-delta path), closed by the source-flip channel-full fix
and the VPN scale receipt in this slice.
**Date:** 2026-07-03

An [accepted EVPN amendment](#amendment-2026-10-13-evpn-update-groups) follows
the original record. It is not implemented; the original record below describes
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

**Status:** Accepted — design only; implementation and qualification are pending.
The amendment replaces the EVPN exclusion in decision 1 and clarifies the
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
denial records and counter residue belong once to the group; replay applies member
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

> Amended 2026-10-14: the shipped unicast/VPN conservative no-proof fallback is
> the sole named unknown-withdrawal exception. See the
> [bounded-proof amendment](#amendment-2026-10-14-bounded-unicastvpn-recovery-proofs)
> for its causes and limits; complete proofs and EVPN keep targeted withdrawals.

Unicast/VPN proofs may reuse a still-live older key universe after group contents
change. Each capture reconstructs actual OLD admission through member mask bits
and bounded sparse additions; desired membership or a cache hint alone proves
no admission. New keys still consume sparse storage per member. Private/regroup
captures can instead reserve bounded flat proofs. Group cache hints reset on
recreation; sharing across recreated groups remains unqualified.
Sharing an empty proof reserves its immediate sparse requirement before
attachment; refusal retries a fitting flat proof before the counted no-proof
fallback. The [snapshot-churn receipt](../perf/update-group-recovery-snapshot-churn-2026-10-14.md)
qualifies its recorded shapes, not arbitrary churn or general regroup scale.

Reuse also has a capture-cost gate. The
[capture-scan amendment](#amendment-2026-10-15-recovery-capture-scan-cost)
requires ordering costs in the measured phase, separate sorted/shuffled receipts
and a matched whole-system comparison; logical byte savings alone do not accept
the live unicast/VPN CPU trade.

The [slot-indexed capture receipt](../perf/update-group-recovery-slot-capture-scans-2026-10-15.md)
passes the approximately 1.5 times warm component target at its recorded source:
actual pure-unicast sharing takes 0.151–0.752 times flat, including 0.671–0.752
for shuffled OLD. VPN-negotiated groups select exact flat full-OLD proofs at
0.991–1.008 times the flat control; this is not a VPN sharing win. Six dormant
EVPN cells miss the cost target and EVPN ownership remains disabled.

The [slot-indexed selection amendment](#amendment-2026-10-15-slot-indexed-full-old-selection)
and [current component result](#amendment-2026-10-15-slot-indexed-component-cost-result)
keep cold pool cost, the unchanged flat-memory trade and matched whole-system
mass-dirty readiness/convergence plus an actual-release-candidate soak as open
qualification requirements. The earlier failed capture-cost amendments remain
historical evidence; the component pass does not waive those release gates.

The [wire-driven mass-dirty receipt](../perf/update-group-recovery-wire-mass-dirty-2026-10-15.md)
records the fixed protocol and four hosted attempts separately from those
component results. Its
[qualification amendment](#amendment-2026-10-15-wire-driven-mass-dirty-qualification)
preserves the scoped historical `a1854eee` UC no-refusal pass. All four later
`72549e20` cells are INVALID; full-matrix qualification and the actual
release-candidate soak remain open.

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

The shared oracle (`update_groups_oracle.rs`, also run by the fault corpus)
flattens unicast, VPN and EVPN RIB events by session, receiver, family and key.
It compares the ordered per-key sequences, the EoR, BoRR and EoRR barriers with
the per-key progress they cover, and folded receiver state. Every withdrawal
must remove a currently admitted key, including inside a recovery interval.
Inside a recovery interval, each announce must repeat the value it replaces or
equal the key's value when the interval ends. An intermediate value, or a
return to a replaced value, fails even when the end states match. The
steady-state per-client-best promotion exemption has been removed.

The oracle compares normalized routes and next-hop actions, not encoded bytes.
The transport shared-encoding tests give every member the same envelope. They
compare the elected encoder's and the shared follower's per-key NLRI and
attribute bytes with the private encoder's output, which shows encoder parity
only. The transport test `update_group_wire_parity` runs one scenario through
the real RIB manager twice, grouped and on the per-peer path, and encodes each
receiver's output in a real session. It compares ordered per-key NLRI and
attribute bytes and EoR coverage for IPv4 and IPv6 unicast and VPNv4, including
withdrawals and a pass that promotes routes from two sources with mixed
next-hop overrides. It covers that scenario, not the recovery paths above.
Preserve the original ADR's dated as-built history while correcting affected
shared recovery behavior before the EVPN classifier is enabled. An exception
must be named here, not inferred from a failing test.

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
   pin non-RTC dirty changes, repeated regroup and limit/allocation-failure
   behavior. Negotiated RTC EVPN stays private until OLD-membership capture and
   separate RTC qualification are complete.
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

Qualify recovery capture scans separately with same-revision shared and explicit
flat controls. Exercise live older universes, sparse OLD additions/removals and
owner-record scaling; count key visits and search comparisons in passes separate
from measured count/capture phases. Preserve refusals without reporting a ratio.
Materialize OLD inputs before timing and measure count and complete capture in
independent invocations. Credit rows describe logical daemon ledger reservation,
excluding input fixtures, allocator overhead and RSS.
These component receipts do not qualify complete-feed settlement, fleet regroup,
readiness, daemon memory or wire behavior.

Before activating grouping in main, repeat the fixed-route-total,
two-receiver-count memory cells with release,
jemalloc and a daemon-only cgroup with no swap. Record allocated/live and peak/
steady cgroup memory, group count, member metadata and dirty/regroup/encoding
residues. The one-group per-receiver route-storage slope must collapse; distinct
export profiles and heterogeneous RTC must not regress against the private path.

Add a **mass-dirty cell at the soak shape**: force most or all group members
dirty simultaneously, for example with a churn burst against throttled receivers.
Prove the overlap with the observed simultaneous dirty-member count, then remove
the throttle and verify every receiver converges under section F's recovery
contract. Require **zero `recovery_provenance_exhausted` resets**. Report retained
and peak recovery-provenance charge per peer and daemon-wide, including the
temporary capacity charged in section E. Size or revise the provisional
16 MiB / 256 MiB caps from this result with documented headroom before activation;
ordinary backpressure must not introduce fleet-wide session resets absent from
the matching per-peer control. A run that exceeds a cap and resets peers fails
qualification rather than establishing an acceptable recovery envelope.

Count execution-confirmed resets for every fixed cause: `peer_limit`,
`daemon_limit`, `allocation_failure`, `capture_unavailable` and
`admission_invariant`. A run with a capture or admission-invariant reset fails
qualification just as a cap-induced reset does; queue admission alone does not
prove that a reset executed.

Add a **whole-fleet policy-regroup cell at the same shape**. Prove that the
members actually move between groups and every receiver converges under section
F, preserving the per-key event contract for clean regroup. Require zero resets
for all five causes, report retained/peak charge and headroom, and verify that
settled members release their recovery duties and charge. An ordinary policy
edit must not retain a fleet of recovery proofs indefinitely.

Run convergence/readiness and soak-shape qualification on a quiet host. Correctness
and quiet-host resource gates must pass before production activation. Publish
the resulting operational envelope with its receipt, not an extrapolated or
loaded-host speedup. No runtime code, measurement, inventory or promotion change
is part of this design amendment.

## Amendment (2026-10-14): bounded unicast/VPN recovery proofs

The shipped unicast/VPN path has one named exception to section F's prohibition
on unknown withdrawals: **conservative recovery without a complete admitted-key
proof**. A peer enters this counted fallback when proof capture or growth fails
with `peer_limit`, `daemon_limit` or `allocation_failure`, or when a dirty resync
finds `missing_proof`. The exception prevents a failed export from silently
losing an owed withdrawal. It permits unknown withdrawals from retained
baselines, tombstones and member withdrawal duties, restricted to keys no longer
retained in the current member view. It does not permit withdrawing that entire
view, omitting owed withdrawals or announcements, changing attributes, or sending
EoR before the routes it covers. Fallback is sticky through recovery and is
cleared with the completed proof when that session becomes clean.

This is the legacy unicast/VPN fail-safe, not an additional steady-state
exception or permission for EVPN to guess withdrawals. Complete proofs retain
section F's targeted withdrawal rule. EVPN retains section E's counted,
generation-matched reset fallback and its independent activation gates. The
shared oracle must distinguish this explicitly forced legacy exception from
proof-backed recovery; ordinary recovery still rejects unknown withdrawals.

Unicast/VPN proofs share an immutable sorted key universe for a group generation.
Each member retains its own admission bits and bounded sparse additions; a key
in the universe alone proves nothing about that receiver. Capture populates only
the authoritative old member projection, and successful queue admissions update
that member's proof. Key-set changes invalidate the group's cache hint. A hint
owns no memory and cannot revive a released snapshot; the last referencing
member frees the snapshot. Regroup/private captures can instead reserve their
known cardinality directly in a flat proof.

Keep the internal **64 MiB per-peer / 512 MiB daemon** limits. The daemon charge
counts shared key storage once plus all reserved member masks, sparse additions,
pool and record capacities and temporary old/new allocation overlap. Each
referencing peer is conservatively charged the complete shared snapshot plus its
own storage and metadata. Retained entries remain a logical per-member count;
shared physical storage does not reduce that gauge. These charges exclude
allocator overhead, route bodies and other existing recovery residues, which
remain part of the separately measured cgroup envelope. Sharing targets dense
cohorts: a sparsely filtered member can reference a larger key universe than its
own flat proof, and new keys retain per-member sparse storage. A dense-cohort
receipt does not establish a memory improvement for every RTC/filter shape.

The prior sequential flat representation refused a fresh capture at 1,048,576
keys under the production peer limit because the next geometric allocation
charged both old and new capacities. Exact-cardinality reservation and shared
keys remove that particular full-table boundary; neither establishes a universal
safe route count. Mixed-family full-table proofs, later admitted additions,
allocation refusals and final-reference release require regression controls.
Qualify mass reevaluation and peer-down with matched off-box cgroup receipts
against the original parent and the bounded-flat implementation before accepting
the release memory envelope. Do not replace the earlier receipt or extrapolate a
modelled component charge into a whole-daemon memory claim.

## Amendment (2026-10-15): recovery capture scan cost

The shared unicast/VPN capture path is live; only EVPN group ownership remains
disabled. The [initial capture-scan receipt](../perf/update-group-recovery-capture-scans-2026-10-15.md)
found shared capture substantially slower than explicit flat capture. Its OLD
fixtures were sorted before timing. Live unicast slab iteration and VPN/EVPN
hash-map iteration do not promise sorted OLD keys, so a linear merge cannot
assume that ordering.

Order borrowed route references in a fallibly allocated temporary buffer before
shared capture. Charge its actual capacity and header throughout ordering,
universe attachment and proof population; free it before refunding credit or
retrying flat capture. Keep the existing peer and daemon limits. Allocation or
budget refusal for this optional buffer must leave flat capture available.
Sorted shape classification and population walk the universe monotonically;
generic unordered callers retain a safe bounded-search fallback. Sorting itself
remains O(n log n), and sparse OLD subsets may use binary lookup rather than
walking a much larger universe.

Requalify on fresh hosted runners with sorted and deterministically shuffled OLD
fixtures reported separately for every capture-scan profile. Complete capture
includes the production count traversal, temporary allocation, collection,
ordering, classification, reservation, population, sealing and buffer release.
Classification counters exclude sorting comparisons and do not establish an
O(n) bound for the complete operation. Preserve the initial receipt; a new
method needs its own source-pinned receipt.

The acceptance target is shared complete capture within approximately 1.5 times
flat, with no proof loss or refusal hidden from ratios. A component result alone
does not qualify release: compare whole-system mass-dirty readiness and
convergence with sharing enabled and disabled, and run the soak on the actual
release candidate. If the capture target is missed, review a size/churn sharing
gate or a return to flat unicast/VPN capture before release. The earlier
component and memory receipts do not waive this cost gate.

## Amendment (2026-10-15): capture-cost candidate not accepted

The [merge-capture receipt](../perf/update-group-recovery-merge-capture-scans-2026-10-15.md)
records unmerged candidate `7e9fbd30f36c826a64943781b1ced1001f98f183` in
hosted run 38670839102. Its six fresh profile/order campaigns completed all
36 cells and 144 legs with exact proofs, zero refusals and clean settlement.
That is evidence completeness, not acceptance of runtime cost.

Live OLD iteration is not guaranteed to be sorted. The candidate accounts for
borrowed-reference collection and sorting before linear classification and
population. Shared/flat complete-capture ratios reach 2.989 for shuffled
unicast and 6.691 for shuffled VPN; all 24 unicast/VPN cells miss the agreed
approximate 1.5 target. Sorting remains O(n log n). The earlier key-only,
presorted receipt is preserved and cannot establish an attributable absolute
speedup across these methods.

This candidate does not settle the live unicast/VPN capture cost. Review a
bounded sharing gate or exact-reserved flat full-OLD capture as a separate
CPU/memory decision. Keep the existing 64 MiB / 512 MiB limits and conservative
no-proof contract; do not hide fallback or raise caps to pass a comparison.
Matched whole-system mass-dirty readiness, receiver convergence and memory
evidence must exercise the selected path, followed by a soak on the actual
release candidate. EVPN ownership remains disabled under its existing gates.

## Amendment (2026-10-15): slot-indexed full-OLD selection

Pure-unicast groups retain the immutable sorted key universe and add one
immutable `u32` slab-slot-to-key-position index, built and charged with that
universe before publication. Both full capture and empty/incremental admission
supply the actual slab when creating a pure-unicast pool. Every slot hit checks
the exact current prefix and path ID; slot reuse, clearing and moved keys cannot
transfer admission. Old-version hints remain reusable across key-set churn.

Warm full capture makes two authoritative projection walks: sizing and
population. It allocates no per-member ordering buffer and performs no
per-member sort. Each walk permits at most 4,096 exact binary fallback lookups
for mismatched slots. On the next mismatch, sizing stops membership lookups,
finishes the actual count and selects exact flat storage for the second walk.
A successful indexed capture can therefore perform up to 8,192 fallback lookups
across its two walks. Missing-index hints select flat capture explicitly.

The pool index charges the historical slab span, including vacant slots, under
the unchanged 64 MiB per-peer and 512 MiB daemon budgets. All index/key/header
capacities and allocation overlap are admitted before allocation and released
only after storage is freed. Cold pool creation still sorts the shared keys and
builds the index once; report its complete cost separately from warm capture.
Sharing selection compares the actual reused-universe mask and sparse additions
with flat storage. Optional index/share refusal leaves authoritative flat capture
available; true flat refusal keeps the counted conservative withdrawal fallback.

Any group that negotiates VPN uses exact flat storage for its **whole** full
common OLD proof, including unicast rows, even when it currently has no VPN
routes. Private/regroup capture stays flat. This does not disable the separately
pinned incremental or empty-proof sharing operations. Concurrent flat captures
retain more per-peer memory and can reach the existing budgets earlier; growth
still charges replacement overlap and may enter conservative fallback.

This selects a candidate method, not a measured improvement or release verdict.
Preserve the dated failed-cost receipts. Qualify the new method with fresh,
source-pinned sorted/shuffled campaigns, the approximately 1.5-times flat cost
bar, matched whole-system readiness/convergence and memory evidence, and a soak
on the actual release candidate. EVPN ownership remains disabled.

## Amendment (2026-10-15): slot-indexed component cost result

The [slot-indexed capture receipt](../perf/update-group-recovery-slot-capture-scans-2026-10-15.md)
measures source `03ee2ad6d905df3c32e1537ccf3d1646de0d856c` in hosted run
38680284008. Six fresh sorted/shuffled profile campaigns completed 36 cells and
144 ABBA legs with exact OLD proofs, zero refusals and clean settlement. Actual
unicast slab sharing passes the approximately 1.5-times warm component bar at
0.151–0.752 times flat; shuffled unicast is 0.671–0.752. Negotiated VPN selects
exact flat at 0.991–1.008 times its flat control, not a sharing or memory gain.
Six dormant EVPN cells exceed 1.5 and do not qualify ownership or activation.

This closes the selected common-family component cost bar, not whole-system
qualification. Each leg has one anchor and one full capturing member; other
records are empty. Shuffled unicast cold anchor creation costs 739.603–818.664 ms.
Both warm arms use the same profile-selected cold-anchor policy: unicast shared,
VPN flat. The receipt supplies no attributable cold sharing-on/off ratio.
First-pool cost can still affect whole-system readiness. Logical credit is
separate from allocator, RSS and cgroup measurements; finite two-sample pairs
and 10 ms CPU ticks do not describe latency distributions.

Keep 64 MiB per-peer / 512 MiB daemon limits and the conservative no-proof
contract unchanged. VPN-negotiated and private/regroup full OLD captures retain
their flat-memory trade. Matched whole-system mass-dirty readiness, remote
receiver convergence and memory qualification, followed by the actual release
candidate's soak, remain pending. The previous key-only and sorted-merge
receipts remain unchanged and are not attributable absolute comparators or
pooled samples for this different method. EVPN ownership remains disabled.

## Amendment (2026-10-15): wire-driven mass-dirty qualification

**`a1854eee`: UC no-refusal PASS; other three INVALID. Full matrix UNQUALIFIED.** The
[method draft](../perf/update-group-recovery-wire-mass-dirty-2026-10-15.md)
records failed source `23fe8425b3b3b7783a44b180b37ec3af91974275`.
It includes the common-capture dedicated-readiness repair, exact operation-log
byte-range binding and complete top-level raw-file digest roster. Remote
publication verification and same-source local correctness/causal prerequisites
are complete. The full-unicast/full-VPN × 12-member no-refusal/24-member
cap-pressure campaign finished in failure as hosted run 38717584948. All four
original INVALID finalizers were reproduced by the frozen consumer. Each cell
stopped in flat leg 0/B: unicast on ordinary held-state snapshot deadlines, VPN
on actual readiness HTTP 503 after held proof/resume. No operation or leg
completed, and no candidate arm started. Partial samples provide no qualified
median, worst, cost, RSS or cgroup-memory comparison. The later `baf70825`
attempt is recorded separately below; old results cannot be relabeled as
new-source measurements.
Candidate and explicit-flat builds require
identical locked/default-feature commands in isolated targets and different
actual executable hashes. Measured cells fix three alternating-arm repetitions,
six legs per cell, with B then A in each. These are planned requirements, not
completed work in the invalid attempt. The derived local control evidence
records six healthy legs / twelve B/A folds around a genuine timestamp-only missing-age RED, exact
restoration and distinct actual daemon hashes. All local cost/RSS/clocks are
null; those controls do not qualify the 12/24-member matrix.

Keep configuration, policy and the preloaded dataset unchanged while wire
attributes alternate at the full 1,000,000 IPv4 / 230,000 IPv6 shape. Prove
actual all-member dirty overlap using two complete paused sweeps whose
conservative current-episode intervals have a common intersection across both
sweeps, bounded after writer drain and before resume. A source writer-drain
acknowledgement is not a RIB acknowledgement or remote convergence. Require each
member's post-resume dirty=true/force=false resync receipt and exact final wire
fold, validated online and retained as compact receipts rather than raw streams.
Readiness requires bracketed one-second probes, HTTP 200 within 250 ms
and no start gap above 1.25 s. Only measured no-refusal cells apply the median
and worst trigger-to-fleet-fold bar: candidate ≤ explicit-flat × 1.10 + 30 ms.
Pressure cells assess correctness/resources with the same absolute readiness
bar within a fixed 1,800-second leg deadline. No-refusal forbids all fallback,
including startup. Operational daemon_limit fallback is required in explicit-flat
and already-flat VPN pressure arms; indexed unicast pressure requires zero operation fallback deltas. Retain
all four fallback causes across all six monotonic sampling edges and compute
each operation delta from its own pre-operation baseline.

Preserve invalid A/B attempts and the failed small saturation trial as invalid
evidence. Retain the earlier valid full-shape unicast correctness-only controls
separately, with null published measurement clocks. The old bookkeeping-mutant
and restored normal-candidate HTTP 503 failures qualify neither the intended
causal control nor a normal run; logs do not prove the exact blocked frame.
The source-level cold-capture regression supports the dedicated-readiness repair,
not a new whole-system result. Keep the independent dataset acknowledgement
failure separate. The recorded `23fe8425` correctness-only controls completed;
the old hosted qualification and replay are INVALID. Next-source controls,
all four fresh cells and their replay are addressed separately below. Preserve
the external naive-bind EADDRINUSE caveat without inferring TIME_WAIT or counting it as RED.
No prior component sample, correctness-only control or invalid attempt supplies
a whole-system ratio. The existing admitted-key recovery proof caps, bounded
flat-memory trade and conservative no-proof contract remain unchanged. Actual release-candidate soak and EVPN
activation are not established; EVPN group ownership remains disabled.

### Recorded `baf70825` follow-up: qualification failed

Published source `baf7082560d2b8318cbe99e9fed8c1104b06f1bb` integrates the
[peer-budget repair](https://github.com/lance0/rustbgpd/pull/3169): check the
existing work budget after each complete dirty-peer distribution transaction,
withholding dirty-force flags with the same selected-peer boundary. Unrelated
force-only scheduling remains unchanged. A single peer replay and any enclosing
transition retain the existing stalled-operation detector.

The consumer retries only the exact exit-1, empty-stdout ordinary RIB snapshot
timeout. It retains a mandatory per-leg failure journal with closed vocabulary,
phase/peer/sequence/attempt counts, and validates row identity/group/state/dirty
age before later queries. The original query, leg and absolute readiness bars
remain unchanged; HTTP 503 and semantic failures cannot be retried into success.

New full-shape two-receiver controls complete six healthy legs / twelve B/A
folds around the timestamp-only causal RED and exact restored UC/VPN controls.
All four local review receipts are CLEAR, all fourteen owned processes reaped,
and all seven attempted-leg snapshot journals are empty. Zero local failures
do not exercise retry at the larger workload. All local timing/RSS/CPU-cost
fields are null; the separate v3 compact cannot replay raw packets or ownership.
Preserve the older control and invalid-attempt JSON bytes as history.

[Run 38728500056](https://github.com/lance0/rustbgpd/actions/runs/38728500056)
was dispatched at 2026-10-15T11:36:09Z with that exact head. All four jobs failed;
independent frozen replay reproduces all four INVALID finalizers. Only two of
24 required legs and four of 48 operations complete, all in UC flat arms.
Both UC candidate arms start but neither completes B; neither VPN leg completes.
There is no eligible median, worst, cost or memory comparison.

UC no-refusal fails on actual HTTP 503 with a logged 200 ms RIB probe timeout.
UC pressure and both VPN cells first fail on the native 250 ms readiness
checkpoint deadline. All ten ordinary snapshot errors match the closed retry
whitelist; later native failures still stop the run. VPN no-refusal's sampler
exit 1 and retained fixture are secondary cleanup evidence. Failed-leg final
resource/reaping/reset boundaries remain unavailable, not zero. The two completed
flat legs pass full frozen validation; UC pressure's cumulative withdrawals are
192 at B and 192 at A, meaning 192 new B and zero new A.

The [failure summary](../perf/artifacts/update-group-recovery-wire-mass-dirty-2026-10-15/invalid-hosted-baf-attempt.json)
retains four archive/source/binary pins and all 317 file digests. The earlier
controls and failed attempt stay byte-preserved and unpooled. The later
`a1854eee` repair and controls are recorded below without reassigning the failed
result. Whole-system release qualification remains held. Actual
release-candidate soak remains pending, the dataset acknowledgement defect is
separate, and EVPN ownership remains disabled.


### `a1854eee` local controls and recorded hosted source

Published source `a1854eee2f5b67d4a6198999f7e497e9ff9924fe` includes the
[primary-peer replay readiness repair](https://github.com/lance0/rustbgpd/pull/3171).
Its separate v4 controls complete six healthy two-receiver legs / twelve exact
B/A folds around a genuine timestamp-only causal RED and byte-identical restored
UC/VPN success. All fourteen local processes are reaped; all seven snapshot
journals are empty. The new [compact control summary](../perf/artifacts/update-group-recovery-wire-mass-dirty-2026-10-15/local-correctness-controls-v4.json)
binds default builds, distinct binaries and the 9,016-entry tracked input roster.
That roster is not an exhaustive list of compiler-opened/generated inputs.
The independent closure is CLEAR_LOCAL_CORRECTNESS_ONLY; local timing/RSS/cost
remain null. Earlier compact evidence stays immutable and unpooled.

At recorded main `594b0ceb30896c7a864b1a0d730df4051ef080d7`, the production,
protobuf, Cargo and inventory path scopes match `a1854eee`; harness/workflow
inputs differ. This is source evidence, not whole-tree or exact-main measurement.
The equality check refers only to that historical `594b` reference, not later
main such as `ed1d70d3a7363058ca73f300feff1af88d920dd8`.
[Run 38744510988](https://github.com/lance0/rustbgpd/actions/runs/38744510988)
completed at `a1854eee` with one valid cell and three INVALID cells, recorded below.

The later cleanup-only `987ed07828df2227f6ffd48ef9f4230cd689b2b3` changes only
the late wrapper EXIT handler and its tests. All other tracked files and wrapper
commands outside that handler match `a1854eee`; runtime, controller, native
stimulus and fixed bars are unchanged. Any accepted data keeps its actual
`a1854eee` source pin. The valid UC cell independently clears actual outer
invocation, frozen finalizer, job and cleanup/ownership checks; an early
`driver.exit=0` marker alone is never accepted. Other failed/incomplete boundaries
remain unavailable. The whole-system decision stays open, with actual
release-candidate soak pending and EVPN ownership disabled.


### Third hosted attempt: scoped UC pass, full matrix unqualified

The `a1854eee` run attempts ten of 24 required legs. Seven legs / fourteen
operations qualify; sixteen native folds are observed, with two belonging to
an ineligible UC-pressure candidate leg. Only UC no-refusal supplies its complete
six-leg / twelve-operation candidate/flat comparison at twelve receivers, each
with 1,000,000 IPv4 plus 230,000 IPv6 keys.

| UC no-refusal trigger-to-fleet-fold | Flat (s) | Candidate (s) | Ratio | Original limit (s) |
| --- | ---: | ---: | ---: | ---: |
| Median | 45.504123 | 43.305023 | 0.951673 | 50.084535 |
| Worst | 46.836414 | 44.428562 | 0.948590 | 51.550056 |

Both satisfy `candidate ≤ flat × 1.10 + 0.030 seconds`. Daemon-cgroup peaks
(maximum of three complete legs per arm) are 2,345,836,544 flat versus
1,972,015,104 candidate bytes. Held logical proof charge is 472,322,272 versus
46,127,368 bytes at the same 14,760,000 entries; logical credit is not allocated
bytes or attribution of the total cgroup peak. All 542 UC probes return 200,
maximum 45.264656 ms and gap 1.001071167 s, with complete operation brackets.
All four fallback causes remain zero including startup; validated complete-leg
caps/OOM/swap/cleanup pass. Five ordinary snapshot retries (four flat, one
candidate) are part of this observed protocol, not attributed CPU improvement.
Only the explicitly captured reset-disposition/inactive-EVPN metrics are zero;
no general all-family reset total is inferred.

UC pressure reaches candidate B/A native folds and readiness PASS, but its
sampler then raises `KeyError: VmRSS` and leaves exit/footer/fixture/raw-roster
requirements incomplete. The leg and cell remain INVALID; only its flat leg
qualifies. Both VPN cells fail initial flat/B on the native 250 ms readiness
deadline before the first fold. VPN no-refusal also has a secondary sampler
cleanup failure; pressure records no secondary cleanup error. No blocked stack
or proven runtime cause follows from those deadlines. Other three cell cost
and memory comparisons are unavailable.

The [third-attempt compact evidence](../perf/artifacts/update-group-recovery-wire-mass-dirty-2026-10-15/hosted-a185-attempt.json)
retains four API-linked archives, source/binary pins and all 497 raw-file hashes,
including valid per-leg data and failed/incomplete evidence. Earlier JSONs and
runs remain immutable and unpooled. Sampler/readiness follow-ups and fresh full
qualification remain open; no later fix is claimed here. Neither latest main,
actual release-candidate soak, dataset acknowledgement recovery nor EVPN
activation is qualified by the single-cell pass. Release qualification remains held.


### `72549e20`: four INVALID cells after reviewed fixes

The separate [recorded attempt](../perf/update-group-recovery-wire-mass-dirty-2026-10-15.md#recorded-72549e20-four-invalid-cells)
at `72549e20deb639cb75cd10cf28b46010dbd8bed8` leaves all four frozen cells INVALID.
Five legs were attempted; only one UC-pressure flat leg / two operations is
eligible. Six native folds exist, four in incomplete legs; no paired convergence,
cost or memory ratio qualifies. The compact preserves 296 raw-file hashes,
source/binary pins and actual failed completion statuses. The overall workflow
is CANCELLED while all four receipt jobs are FAILURE; logs do not establish a
cancellation initiator, delivered signal or exact instant.

UC post-fold sampler ownership guards lack mismatch operands; VPN no-refusal
has a native deadline followed by secondary sampler failure; VPN pressure's
compound source guard lacks the failing row. No underlying runtime cause or
precise failed source predicate is inferred. Nine strict ordinary snapshot
retries do not waive those failures or supply missing final boundaries.

The same-source V5 local controls separately clear six healthy two-receiver
legs / twelve folds, genuine timestamp-only causal rejection and restoration,
seven empty journals and fourteen reaped processes. Their timing/RSS/cost remain
null. Main `a04497026215ff6ee79543f2ba84e285bd92bb25` includes the reviewed
retirement/reservation and sampler fixes, but differs through later BGP-LS/ORR
production changes and qualification wiring. Its ordinary CI and bounded M122
witnesses are separate validation, not literal-tree, performance or RC equivalence.

All earlier data remain source-pinned and unpooled, including the historical
`a1854eee` single-cell pass. Full-matrix qualification and an actual identified
release-candidate soak remain required; the separate dataset acknowledgement
path and EVPN ownership-off boundary are not qualified here.


### `4dac2d09`: two unicast passes, VPN qualification still open

The separate [wire-driven receipt at `4dac2d09`](../perf/update-group-recovery-wire-mass-dirty-4dac2d09-2026-10-15.md)
records two complete UC cells and two INVALID VPN cells. UC no-refusal passes
its original `flat × 1.10 + 0.030 s` median/maximum bars at 0.950252/0.938036 times
flat. UC pressure passes correctness, availability and resource bars, but costs
**1.430931 times flat by median / 1.406350 by maximum**; those descriptive pressure
costs are not governed by the no-refusal relative bar. Candidate pressure holds
47,974,568 logical proof bytes versus flat's 511,684,448, with different bounded
proof coverage. Logical charge is not RSS or attribution of total cgroup memory.

Retain indexed shared pure-unicast proofs, supported by the component result and
this no-refusal comparison. VPN-negotiated groups retain exact flat full-OLD
proofs; both VPN cells fail initial flat/B on the unchanged 250 ms readiness
deadline before any fold. No underlying daemon cause or VPN cost/resource result
is established. Full qualification remains **UNQUALIFIED**, release remains held,
and an actual identified release-candidate soak is still required. EVPN ownership
stays disabled; the separate dataset acknowledgement path is not qualified.

The measured source remains `4dac2d09f661501ef476196c7b68d5ec3df2e1be`. All tracked
modes, types and Git blobs outside the ten qualification harness/workflow paths
match historical main `f95dd04df0eca75b1ccaefae060e68c557771d56`, not literal tree
or RC measurement equivalence. Local controls remain at their actual `123847d7` source.
All earlier dated amendments and evidence, including the four-attempt failed
receipt and `a1854eee` single-cell pass, remain unchanged and unpooled.
