# ADR-0083: EVPN single-active backup-path pre-install

**Status:** Accepted
**Date:** 2026-06-11

## Context

When the active PE for a single-active Ethernet Segment fails, every
remote VTEP keeps forwarding the segment's MACs at the dead (or
CE-disconnected) PE until BGP reconverges. Today our receive side is
*correct* but reconvergence-speed-bound: `src/evpn_dataplane.rs`
projects single-active remote MACs as plain single-dst FDB rows at the
MAC route's next-hop (the `project_ead_per_evi` projection deliberately
suppresses aliasing for any `(next-hop, ESI)` whose EAD-per-ES carries
the single-active flag), and the RFC 7432 §8.2 mass-withdraw gate in
`project_one` *removes* those MAC rows the moment the origin VTEP's
EAD-per-ES disappears. After the sweep, traffic to those MACs degrades
to unknown-unicast flooding until the new active PE learns and
re-advertises every MAC — an O(MACs-on-segment) re-advertisement wave
multiplied across every remote VTEP.

RFC 7432 §8.4 ("Aliasing and Backup-Path") defines the receive-side fix
this ADR adopts: a non-DF PE on a single-active ES advertises
reachability via the same EAD-per-ES (Single-Active bit set in the ESI
Label extended community) + EAD-per-EVI pair used for aliasing, and "a
remote PE that receives a MAC/IP Advertisement route with a
non-reserved ESI ... SHOULD install a backup path for that MAC
address." The mass-withdraw trigger (§8.2) then becomes a *local
repair*: retarget every affected MAC to the pre-derived backup PE in
one operation instead of flushing them.

### Verified kernel reality (June 2026, `net/ipv4/nexthop.c`, master)

The receive-side mechanism is constrained by what the Linux nexthop API
can express:

1. **No protection/active-backup group type exists.** Nexthop groups
   are `MPATH` (hash ECMP) or `RES` (resilient hash) only. There are no
   standby-member semantics.
2. **FDB nexthop selection is pure hash** — no NUD/liveness coupling,
   no underlay route check, no reselection when the underlay lookup
   fails. Kernel-native failover is not expressible; the daemon must
   drive the switchover.
3. **The usable primitive is the atomic single-netlink NHG membership
   replace** (committed via `rcu_assign_pointer`): one
   `RTM_NEWNEXTHOP` with `NLM_F_REPLACE` retargets every dependent FDB
   row at once, O(1) in the number of MACs.
4. **Footgun:** removing a group's last member deletes the group and
   flushes all dependent FDB entries. A membership replace must never
   pass through empty. (Our `NexthopSocket::add_fdb_group` already
   rejects empty member lists client-side; the discipline must extend
   to teardown ordering.)

These converge on a **hybrid**: pre-installed per-ES NHG indirection
(single-active FDB rows point at a one-member FDB nexthop group whose
member is the active PE; the backup PE's per-VTEP fdb nexthop object is
pre-created so the swap allocates nothing) plus an **event-driven
daemon swap** of the group membership when the active PE's EAD-per-ES
withdrawal arrives.

### What the standards let a remote PE know

- **A remote PE cannot compute the DF or the RFC 8584 BDF.** Type-4 ES
  routes — the DF-election candidate list, the DF Election extended
  community carrying the algorithm/capability agreement (HRW, AC-DF) —
  are filtered by the ES-Import route target and reach only PEs
  attached to the segment (RFC 7432 §8.1, confirmed by RFC 8584). The
  HRW "Backup DF" exists, but only the segment's own PEs can derive it
  reliably.
- **What a remote PE does see** is the eligible-PE set: every PE
  advertising the EAD-per-ES (single-active) + EAD-per-EVI combination
  for the `(ESI, Ethernet Tag)`. RFC 7432 §8.4 says the MAC is
  reachable "via any PE" in that set and leaves backup selection to the
  implementation.
- **Wrong picks are safe in single-active.** At most one egress PE
  forwards toward the CE (the non-DF holds the AC blocked), so a remote
  PE that retargets to a PE which does not become the new DF gets drops
  at that egress until the segment's own DF re-election settles — never
  loops, never duplicates. Backup choice affects only the transient,
  not correctness, and remote VTEPs need not agree with each other.

### Prior art: FRR (source-verified June 2026, master)

FRR's EVPN multihoming is **all-active only** ("FRR supports All-Active
Layer-2 Multihoming ... via LACP Ethernet Segments" — official docs);
there is no receive-side single-active backup path to copy. But FRR's
all-active receive side validates the mechanism class this ADR uses:
`zebra/zebra_evpn_mh.c` keys remote MACs for a remote ES to a per-ES
L2 nexthop group (`zebra_evpn_nhg_update` →
`kernel_upd_mac_nhg(es->nhg_id, ...)`); when bgpd propagates an
EAD-per-ES withdrawal, zebra removes the VTEP from `es->es_vtep_list`
and re-programs the NHG **once**, retargeting all dependent MACs in a
single kernel update rather than per-MAC rewrites. When the VTEP list
empties, zebra deletes the NHG and explicitly uninstalls the dependent
MACs — the same never-through-empty discipline finding 4 demands. The
"ES backup NHG" that appears in `zebra_evpn_mh.c`
(`dplane_br_port_update(... backup_nhg_id)`) is the *local-PE*
access-port fast-failover path (protodown-adjacent), not a receive-side
mechanism; it is out of scope here.

### Existing machinery this composes with

- **ADR-0059 FDB-NHG stack**: `crates/evpn-linux/src/nh_id_alloc.rs`
  (tagged id spaces, `0x3000_0000` per-VTEP NHs / `0x4000_0000`
  groups, offset from FRR's ranges), `nexthop_raw` (raw `RTM_*NEXTHOP`
  socket; `add_fdb_group` is `NLM_F_CREATE|NLM_F_REPLACE` idempotent
  and rejects empty membership), `group_state.rs` (`GroupOwnedMap`
  ref-counting: per-VTEP NHs shared across groups, groups torn down on
  last MAC unref), the periodic `RTM_GETNEXTHOP` drift sweep, and the
  startup `dump_owned` adoption that re-reserves `is_ours` ids so a
  restarted daemon never `NLM_F_REPLACE`-tramples kernel state still
  referenced by surviving FDB rows.
- **All-active aliasing** (`crates/evpn/src/aliasing.rs`): group key is
  `(ESI, EthernetTag)`; `RemoteMacEntry.alias_group_key` +
  `group_members` already define the portable NHG intent; the Linux
  reconcile actor programs it. Single-active is currently the one
  multi-homed shape that bypasses this entire stack.
- **Mass-withdraw** (`crates/evpn/src/mass_withdraw.rs` + the
  `project_one` gate): EAD-per-ES withdrawal currently means "drop the
  MACs". This ADR changes its meaning for single-active segments that
  still have an eligible backup.
- **ADR-0079 adoption sweeps**: NHG-tagged FDB rows are explicitly
  excluded from the single-dst FDB adoption sweep (the ADR-0059 drift
  sweep owns them), and ADR-0079 records the NHG reap-cascade hazard.
  New per-ES groups must stay inside that ownership split.
- **ADR-0082**: all FDB installs (single-dst and NHG rows) carry the
  `NDA_PROTOCOL = RTPROT_BGP` forward-compatible stamp; new rows do
  too, for free, via the shared encoders.

## Decision

**Route single-active remote MACs through a pre-installed one-member
FDB nexthop group per `(ESI, Ethernet Tag)`, pre-create the backup
PE's nexthop object, and convert the EAD-per-ES mass-withdraw from
"flush the MACs" into "atomically replace the group membership with
the backup PE" — with desired state defined as a pure function of the
EVPN RIB so crash-restart and the event path converge on the same
answer.**

### Numbered decisions

1. **Indirection for single-active MACs (pre-install).** A remote MAC
   whose `(next-hop, ESI)` is single-active and whose ES has at least
   one *other* eligible PE is programmed as an `NDA_NH_ID` FDB row
   pointing at a per-`(ESI, EthernetTag)` FDB nexthop group with
   exactly **one member: the primary PE** (the MAC route's advertising
   next-hop). The backup PE's per-VTEP fdb nexthop object is created
   at the same time but is *not* a group member — the kernel hashes
   over all members, and single-active means exactly one egress
   forwards. This needs a small extension to `GroupOwnedMap`'s
   ref-counting: today a `VtepNh` is kept alive only by the groups
   whose membership references it (`ref_groups`; zero refs ⇒ orphan
   reap), so the pre-created backup NH must hold a distinct *standby*
   ref class tied to the group key, or the existing orphan sweep
   deletes the very object the swap depends on. Single-active MACs on an ES with **no** other eligible PE
   (a de-facto single-homed segment) keep today's single-dst rows; the
   NHG indirection buys nothing there.
2. **Backup derivation rule: lowest VTEP IP among the non-primary
   eligible PEs.** The *eligible set* for `(ESI, EthernetTag)` = PEs
   advertising *both* an EAD-per-ES with the Single-Active bit set
   *and* an EAD-per-EVI for that `(ESI, EthernetTag)` — primary
   included. Backup = the numerically lowest VTEP IP in the eligible
   set excluding the primary (the existing `BTreeSet<IpAddr>` total
   order; IPv4 sorts before IPv6, which is fine — it is a tie-break,
   not a preference signal). Deterministic, derivable from routes every
   remote PE already has, and safe when wrong (Context: "wrong picks
   are safe"). We explicitly do **not** try to mimic the segment's DF
   election or the RFC 8584 HRW BDF: the algorithm/capability agreement
   travels in the DF Election extended community on Type-4 routes we
   never receive, so any remote mimicry is a guess that *looks*
   authoritative. Lowest-IP is honest about being arbitrary.
3. **Switchover trigger: EAD-per-ES withdrawal, reinterpreted.** For a
   single-active `(origin VTEP, ESI)` with a non-empty remaining
   eligible set, the `MassWithdrawTrigger` no longer sweeps the MAC
   rows; it drives one `add_fdb_group` (`NLM_F_REPLACE`) per affected
   `(ESI, EthernetTag)` group — groups are keyed per Ethernet Tag, so
   an ES spanning several tags takes one replace each — swapping that
   group's membership to the backup PE's nexthop id. Each netlink
   message retargets every MAC behind its group (finding 3). The MAC
   rows themselves are untouched — no per-MAC churn, no flood-relearn
   wave. When the new active PE later re-advertises the MACs with
   itself as next-hop, normal projection takes over (the primary
   changes, the group follows, see decision 5). If the remaining
   eligible set is **empty**, today's mass-withdraw semantics apply:
   remove the dependent FDB rows *first*, then delete the group —
   never shrink membership through empty (finding 4; FRR orders its
   teardown the same way).
4. **Honest latency budget.** "Sub-second" refers to the *remote
   repair* term this ADR eliminates, and it must be qualified:
   - *AC/link failure at the active PE* (the common case): the active
     PE is alive and withdraws its EAD-per-ES immediately; propagation
     through the RR is tens-to-hundreds of ms; our repair on receipt is
     one netlink message (µs–ms). Sub-second end-to-end is realistic —
     but it is still bounded below by the *egress* side: the backup PE
     must win DF re-election and unblock its AC (RFC 7432 peering/DF
     timers apply on the segment side; that is the segment owner's
     problem, not the receiver's). Before this ADR the remote term was
     the dominant one: flush + flood + O(MACs) re-advertisement.
   - *PE node failure*: nobody withdraws anything until the failed
     PE's BGP sessions die (hold timer — up to 90 s with defaults — or
     BFD between PE and RR). Pre-install makes the repair instant
     *once the withdrawal arrives*; it does nothing for detection.
     Cutting detection needs liveness toward the VTEP itself (BFD to
     remote VTEPs, or underlay route-to-VTEP tracking) — explicitly a
     later, separate ADR; this ADR's state model is what such a
     detector would plug into (it would synthesize the same
     "primary ineligible" transition).
5. **Idempotent state model: desired membership is a pure function of
   the RIB.** Desired group member for `(ESI, EthernetTag)` =
   the MAC routes' advertising next-hop if it is still in the eligible
   set, else the backup per decision 2, else (empty eligible set) the
   group is undesired. (When the eligible set is exactly the primary —
   no backup exists — decision 1's single-dst fallback applies and no
   group is desired either; a group that *currently* points at the
   backup with the primary gone stays desired with one member.) The
   EAD-withdrawal event path (decision 3) is
   only a *prompt* recompute of this function — not a special state.
   Consequences:
   - **Crash-restart converges for free.** The restart converger
     recomputes the same function from the reloaded RIB; the ADR-0059
     `dump_owned` adoption re-reserves surviving group ids; the drift
     sweep corrects any membership mismatch on its existing cadence.
     No new persisted state (ADR-0079: no new owned-state files).
   - **The post-swap window is representable.** "Group points at
     backup while the dead PE's MAC routes still sit in the RIB" is
     exactly what the function yields (primary ineligible → backup),
     so a restart inside the failover window re-derives it instead of
     flapping back to the dead PE.
   - **The `project_one` mass-withdraw gate changes shape for
     single-active:** a Type-2 with non-zero ESI whose origin VTEP
     lost its EAD-per-ES stays projected iff the ES's eligible set is
     non-empty (entry retargeted at the group), and is dropped
     otherwise (today's behavior). All-active semantics are untouched.
6. **Scope.** Receive-side only; single-active only; L2 known-unicast
   FDB only. All-active aliasing groups (ADR-0059) are unchanged —
   single-active groups reuse the same `AliasGroupKey` shape, id
   allocator, per-VTEP NH ref-counting, drift sweep, and CVE-2025-39851
   learning-disabled guard, differing only in the membership function
   (one member vs. the full eligible set). Local-PE-side single-active
   (our own ES going standby, protodown analogs) is out of scope. L3
   (symmetric IRB host routes toward a single-active ES) is out of
   scope for the first slices and recorded as a hazard below.

## Options considered

1. **Kernel-native standby member — rejected (impossible).** There is
   no protection group type in the nexthop API and FDB selection has
   no liveness coupling (findings 1–2). A two-member group containing
   active + backup is *worse* than today: it hash-splits live traffic
   onto the blocked non-DF egress, blackholing ~half the flows during
   steady state.
2. **Reactive-only without pre-install — rejected.** On EAD withdrawal,
   rewrite every affected single-dst FDB row to the backup VTEP. No new
   steady-state structure, but the repair is O(MACs × netlink
   round-trips) per remote VTEP at the worst possible moment, it
   races the concurrent mass-withdraw sweep, and it rebuilds per-MAC
   state the kernel would have retargeted for free behind an NHG. This
   is precisely the per-MAC churn FRR's per-ES NHG exists to avoid.
3. **Hybrid: pre-installed one-member NHG + daemon swap — chosen.**
   Steady-state cost is one group + one pre-created nexthop object per
   single-active `(ESI, EthernetTag)`; failover cost is one netlink
   message regardless of MAC count; every piece (id allocation,
   ref-counting, drift sweep, adoption, empty-group discipline) already
   exists for aliasing. The research pass confirmed rather than
   contradicted this candidate, and FRR's all-active receive side is
   structurally the same mechanism.
4. **Mimic the segment's DF election remotely (HRW BDF) for backup
   choice — rejected.** Needs the Type-4 candidate list and the DF
   Election extended community agreement, both ES-Import-filtered away
   from remote PEs. A guess that happens to match FRR-or-whoever's
   election today silently diverges when the segment changes algorithm
   — and since wrong picks are already safe, the complexity buys
   nothing. Lowest-IP (decision 2) keeps the arbitrariness explicit.

## Operational hazards recorded (not solved here)

- **Never-through-empty discipline.** The kernel deletes a group whose
  last member is removed and flushes every dependent FDB row (finding
  4). `add_fdb_group` already rejects empty membership client-side;
  the new teardown path (eligible set → ∅) must remove dependent FDB
  rows before deleting the group, and the swap path must be a single
  replace, never a remove-then-add. A future reviewer touching
  `group_state.rs` teardown ordering must preserve this.
- **Row-shape migration on upgrade.** Existing deployments carry
  single-dst (`NDA_DST`) rows for single-active MACs; this feature
  programs `NDA_NH_ID` rows, and the kernel rejects both attributes
  combined (`vxlan_fdb_parse`, see `fdb_nhg.rs` header). The kernel
  also rejects converting the row shape in place:
  `vxlan_fdb_update_existing` returns `-EOPNOTSUPP` ("Cannot replace
  an existing non nexthop fdb with a nexthop",
  `drivers/net/vxlan/vxlan_core.c`, master, verified June 2026), so an
  `NLM_F_REPLACE` cannot turn a dst-row into an nhid-row in one
  message. Upgrade conversion is therefore an explicit
  delete-then-add per MAC row — a known, bounded transient gap — or a
  staged migration that converts a segment's rows behind the
  pre-installed group before cutting over. The converger's first pass
  after upgrade performs this fleet-wide; the implementation must
  order it delete→add per row (never batch-delete-then-batch-add) to
  keep the gap per-MAC rather than per-segment.
- **ADR-0079 adoption-sweep interaction.** Single-active NHG rows move
  from the single-dst sweep's jurisdiction to the ADR-0059 drift
  sweep's (nexthop-id-tagged rows are excluded from the FDB adoption
  sweep). A crash *during* the upgrade conversion leaves a mix of both
  shapes for the same MACs; both sweeps must agree on which shape is
  desired so one adopts and the other reaps, not both adopting. The
  reap-cascade hazard from ADR-0079 ("deleting one group can
  invalidate dependents") now applies to per-ES single-active groups
  too, as does the systemd `ManageForeignNextHops=no` deployment
  requirement.
- **Backup egress drops are expected and must not look like a bug.**
  Until the segment's own DF re-election unblocks the backup's AC,
  retargeted traffic drops at the backup PE. Observability should make
  the window legible (a `single_active_backup_active` gauge / event
  with the swap timestamp) so operators can distinguish "expected
  egress DF wait" from "repair failed".
- **Stale-MAC window after failover.** Post-swap, MACs the dead PE
  advertised remain pointed at the backup until the new active PE
  re-advertises (or the routes age out via the origin VTEP's session
  death). MACs that *moved* or *disappeared* during the failure ride
  that window too; mobility-sequence handling on the new active's
  re-advertisements is the corrector. Worth an explicit interop assert.
- **L3/IRB is not covered.** Symmetric-IRB host routes (Type-2 with IP,
  Type-5) toward a single-active ES still converge via the L3 path;
  a single-active ES behind an L3VNI keeps its L3 reconvergence-speed
  behavior until a follow-up extends the same eligible-set function to
  the L3 next-hop choice.
- **Eligible-set flap hygiene.** A flapping EAD-per-ES (e.g. the
  AS_PATH-change heuristic in `mass_withdraw.rs`) now drives NHG
  membership replaces instead of MAC flushes — cheaper, but still
  worth damping observation if a segment flaps fast; the drift sweep's
  cadence is the backstop, not the rate limiter.

## Consequences

- Failover for single-active segments becomes a local repair at every
  remote VTEP: one netlink message per `(ESI, EthernetTag)` group, no
  per-MAC churn, no flood-and-relearn wave. The remote reconvergence
  term drops from O(MACs × VTEPs) re-advertisement to effectively the
  withdrawal propagation delay.
- Steady-state kernel state grows by one nexthop group + at most one
  extra per-VTEP nexthop object per single-active `(ESI, EthernetTag)`
  — the same order as aliasing already costs all-active segments.
- Ship slices (smallest correct slice first):
  1. **Pure logic** (`crates/evpn`): eligible-set fold + backup
     derivation as a pure function of projected EAD state; keep the
     empty-eligible-set → today's-behavior fallback. Unit tests incl.
     the OR-fold duplicate-RD cases `fold_ead_per_es_modes` already
     covers.
  2. **Dataplane pre-install** (`crates/evpn-linux`): extend the
     projection so single-active MAC entries carry
     `alias_group_key` + a one-member desired membership instead of
     bypassing the group machinery (moved here from slice 1 — the
     wiring ships with its first consumer); program single-active
     groups through the existing reconcile actor; pre-create the
     backup per-VTEP NH (ref-counted, not a member); row-shape
     migration verification (hazard above).
  3. **Swap path**: prompt recompute on `MassWithdrawTrigger` for
     single-active segments; single-message membership replace;
     ordered teardown when the eligible set empties; the
     `single_active_backup_active` observability surface.
  4. **Measurement M-job**: containerlab topology with a 2-PE
     single-active ES + ≥1 remote VTEP running rustbgpd; kill the
     active PE's CE link (AC failure) and separately the PE itself
     (node failure); measure the dataplane blackout window at the
     remote CE (continuous traffic probe) before/after this feature,
     and assert the NHG membership swap landed (one `RTM_GETNEXTHOP`
     dump). The before/after numbers go in the ADR's evidence doc, not
     marketing copy — node-failure numbers will honestly show the
     hold-timer floor.
- A future remote-VTEP liveness detector (BFD-to-VTEP or underlay
  route tracking) plugs into decision 5's eligibility function rather
  than inventing a new failover path.

## References

- RFC 7432 §8.2 (mass withdraw), §8.4 (Aliasing and Backup-Path), §14
  (load balancing): <https://www.rfc-editor.org/rfc/rfc7432.html>
- RFC 8584 (HRW DF election, BDF, DF Election extended community;
  Type-4 ES-Import scoping): <https://www.rfc-editor.org/rfc/rfc8584.html>
- Linux nexthop API — group types `MPATH`/`RES` only, hash-only FDB
  selection, atomic group replace via `rcu_assign_pointer`, group
  removal flushing dependent FDB entries (verified June 2026, master):
  <https://github.com/torvalds/linux/blob/master/net/ipv4/nexthop.c>
- FRR receive-side per-ES L2-NHG (`zebra_evpn_nhg_update`,
  `kernel_upd_mac_nhg`, `zebra_evpn_es_vtep_del`; teardown order on
  empty VTEP list; the local-side `backup_nhg_id` br-port path):
  <https://github.com/FRRouting/frr/blob/master/zebra/zebra_evpn_mh.c>
- FRR EVPN docs — All-Active multihoming only:
  <https://docs.frrouting.org/en/latest/evpn.html>
- Our machinery: `crates/evpn/src/aliasing.rs`,
  `crates/evpn/src/mass_withdraw.rs`, `src/evpn_dataplane.rs`
  (`fold_ead_per_es_modes`, `project_ead_per_evi`, `project_one`),
  `crates/evpn-linux/src/group_state.rs`,
  `crates/evpn-linux/src/nh_id_alloc.rs`,
  `crates/evpn-linux/src/linux/nexthop_raw/`,
  `crates/evpn-linux/src/linux/fdb_nhg.rs`

See also ADR-0059 (FDB nexthop groups for aliasing — the machinery this
extends), ADR-0079 (adoption sweeps + NHG reap-cascade hazard),
ADR-0082 (`NDA_PROTOCOL` stamping carried by the shared FDB encoders).
