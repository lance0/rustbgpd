# ADR-0099: Update groups v2 — per-family keying and RT-aware VPN emit

**Status:** Accepted — shipped across #685 (VPN group staging for non-RTC
groups, family-extended key) and #686 (per-member RT filter at emit +
the membership-delta path), closed by the source-flip channel-full fix
and the VPN scale receipt in this slice.
**Date:** 2026-07-03

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
