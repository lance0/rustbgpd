# ADR-0082: NDA_PROTOCOL ownership stamping for EVPN FDB/neighbor state

**Status:** Accepted
**Date:** 2026-06-10

## Context

ADR-0079's crash-restart adoption sweeps key EVPN ownership on
kernel-preserved markers: `extern_learn` (+ permanent state) on managed
VXLAN/L3VXLAN devices for FDB rows and L3 neighbors. `extern_learn` is the
*right family* of marker — the kernel exempts such entries from GC because
a control plane owns them — but it is not *ours*: any EVPN controller
(FRR zebra, a previous rustbgpd, an operator's
`bridge fdb add ... extern_learn`) writes the same flag. A co-resident or
successor controller's rows are indistinguishable from ours at adoption
time, so the sweep can adopt — and later reap — state it never owned. The
hardening follow-up is a second, value-bearing discriminator:
`NDA_PROTOCOL`, the FDB/neigh analog of `rtm_protocol`, stamped at install
and required at adoption.

This is FRR's current model. zebra stamps `NDA_PROTOCOL` on every
neighbor/FDB install through its unified encoder
(`netlink_neigh_update_msg_encode`, default `RTPROT_ZEBRA` = 11), and its
kernel-read ownership test for IP neighbors is

```c
is_own = !!(ndm->ndm_flags & NTF_EXT_LEARNED) && rtprot == RTPROT_ZEBRA;
```

(`zebra/rt_netlink.c`, master). FRR's January 2026 EVPN graceful-restart
work (PR #19778, merged 2026-01-06) builds its restore-across-restart on
exactly these markers: kernel-read *neighbor* entries are re-adopted only
when `is_own` (flag **and** protocol), while kernel-read *MAC/FDB* entries
are re-adopted on `NTF_EXT_LEARNED` alone.

That asymmetry in FRR is not sloppiness — it is the kernel reality, and it
reshapes this ADR (research findings, source-verified June 2026):

1. **IP neighbors: supported since Linux 5.0.** Commit `df9b0e30d44c`
   ("neighbor: Add protocol attribute", David Ahern) landed in v5.0 (not
   5.1 as we previously believed) for both `struct neighbour` and proxy
   entries: a u8 in the `rtm_protocol` value space, stored and echoed in
   dumps, semantically ignored by the kernel — a pure userspace ownership
   tag. iproute2 exposes it as `ip neigh add ... protocol PROTO` (commit
   `6b83edc06`, 2018-12-27) and prints it on `ip neigh show`.
2. **AF_BRIDGE FDB: NOT supported in mainline.** As of June 2026, neither
   `net/bridge/br_fdb.c` nor `drivers/net/vxlan/vxlan_core.c` reads or
   stores `NDA_PROTOCOL`; `rtnl_fdb_add` parses attributes with a NULL
   policy, so a stamped FDB install is **silently accepted and the
   attribute dropped** — it never errors and never round-trips in dumps.
   A patch series adding it ("net: bridge: vxlan: Protocol field in
   bridge fdb", August 2025, motivated by EVPN-MH control-plane vs
   data-plane MAC disambiguation, with matching iproute2
   `bridge fdb ... protocol PROTO` support) is on the mailing lists but
   unmerged. Current iproute2 `bridge fdb` has no `protocol` keyword.
   FRR stamps its FDB installs anyway (a forward-compatible no-op) and,
   consistently, does not require the stamp when reading FDB back.
3. **Value space.** `NDA_PROTOCOL` shares the `rtm_protocol` number space
   (`RTPROT_*`): zebra uses `RTPROT_ZEBRA` (11); `RTPROT_BGP` is 186.
   For neighbor entries the kernel stores and echoes the value but does
   not interpret routing-daemon values; in practice the protocol number is
   a userspace ownership tag (same convention ADR-0079 already documents
   for routes).
4. **Our crate stack already carries the attribute.** We pin
   `netlink-packet-route 0.30.0`, which exposes
   `NeighbourAttribute::Protocol(RouteProtocol)` (emits/parses
   `NDA_PROTOCOL`). The `rtnetlink 0.21.0` neighbour builders have no
   `protocol()` setter, but `message_mut()` lets us push the attribute on
   the request — no dependency change needed.

Our write sites and adoption classifiers (all current code):

| Object | Install site | Adoption/ownership classifier |
|---|---|---|
| L2 single-dst FDB (bridge+VXLAN) | `crates/evpn-linux/src/linux/fdb.rs` `apply_op` (`add_bridge`, flags `Own|Controller|ExtLearned`) | `snapshot.rs` `KernelFdbEntry::is_extern_learned` (FDB snapshot feeding the ADR-0079 sweep + drift logic) |
| ADR-0059 NHG FDB rows | `crates/evpn-linux/src/linux/fdb_nhg.rs` (same flag shape) | NHG drift sweep (nexthop-id-tagged) |
| L3 neighbor (ARP/ND on L3VXLAN) | `crates/evpn-linux/src/linux/l3.rs` `apply_add_l3_neighbor` (`Permanent` + `ExtLearned`) | `linux/l3_adoption.rs` `classify_adoption_neighbor` |
| L3VXLAN router-MAC FDB | `linux/l3.rs` `apply_add_l3vxlan_fdb` (`Own|ExtLearned`, AF_BRIDGE) | `linux/l3_adoption.rs` `classify_adoption_l3vxlan_fdb` |

Only the **L3 neighbor** rows live in a table where the kernel will store
the stamp today; the other three are AF_BRIDGE FDB.

## Decision

**Stamp `NDA_PROTOCOL = RTPROT_BGP` (186) on every EVPN FDB/neighbor
install, and require it at adoption only where the kernel can return it —
IP neighbors now, FDB when kernel support lands — with a one-release
stamp-or-legacy migration window.**

### Numbered decisions

1. **Stamp value: `RTPROT_BGP` (186), i.e. `RouteProtocol::Bgp`.** It is
   the daemon's existing kernel identity — every route we install already
   carries `rtm_protocol = 186` and the ADR-0079 sweeps already key on it.
   One protocol value across routes, neighbors, and FDB keeps `ip neigh`
   / `bridge fdb` output and our classifiers coherent. We do not mint a
   private value: the ADR-0079 hazard ("`RTPROT_BGP` is contested",
   co-residency with another proto-186 daemon unsupported) carries over
   unchanged, and a private value would buy nothing against the actual
   threat (zebra requires `RTPROT_ZEBRA`, so mutual exclusion with FRR
   works with 186; a second rustbgpd is unsupported either way).
2. **Stamp all four install sites now.** `apply_add_l3_neighbor`,
   `apply_add_l3vxlan_fdb`, the L2 `apply_op` add/update arm, and the NHG
   FDB encoder all emit `NeighbourAttribute::Protocol(RouteProtocol::Bgp)`
   (via `message_mut()` where the builder lacks a setter). For the three
   AF_BRIDGE sites this is a forward-compatible no-op on current kernels
   — exactly FRR's posture — and becomes effective automatically when the
   bridge/vxlan support merges. Stamping is uniform so we never have to
   reason about which writer version stamped which object class.
3. **Adoption rule, per object class:**
   - *L3 neighbors* (`classify_adoption_neighbor`): require
     `extern_learn` + permanent (unchanged) **and**
     `Protocol == RouteProtocol::Bgp` *or* protocol-absent (legacy)
     during the migration window; after the window, require the stamp.
     The dump parser gains a `NeighbourAttribute::Protocol` arm.
   - *FDB rows* (L2 snapshot classifier, `classify_adoption_l3vxlan_fdb`):
     rule **unchanged** — `extern_learn` on a managed device. The kernel
     cannot return a stamp it does not store; requiring it would make FDB
     adoption permanently empty. The classifiers grow the protocol check
     in *prefer* mode only: if a dumped FDB row ever carries
     `NDA_PROTOCOL` (a future kernel), a value ≠ `RTPROT_BGP` disqualifies
     the row (it is provably another controller's); absence keeps today's
     flag-based rule. This is forward-hardening with zero behavior change
     on current kernels.
4. **Migration window: one full release, stamp-or-legacy.** Rows installed
   by pre-stamp rustbgpd versions have no `NDA_PROTOCOL`; the first
   post-upgrade adoption sweep would refuse them under a strict rule and
   they would strand as foreign forever (the exact ADR-0079 failure mode
   this work exists to close). Therefore: release N ships stamping +
   accepts stamp-or-legacy at adoption; release N+1 may flip neighbors to
   strict-stamp. The window must be a *release*, not "until first
   converge": although every re-claim rewrites the row with the stamp
   (netlink replace semantics), a crash *before* the post-upgrade
   converge completes leaves unstamped-but-ours rows that the next
   restart must still adopt. Flipping to strict is itself gated on the
   operator having run release N once; document this in the upgrade
   notes, and keep an escape hatch
   (`RUSTBGPD_EVPN_ADOPTION_ACCEPT_LEGACY=1`) for skip-version upgrades.
5. **Kernel-too-old fallback: detect by read-back, not by error.** The
   common failure mode is *not* an install error we can catch once:
   AF_BRIDGE ignores the attribute silently, and kernels before the IP
   neighbor protocol attribute are outside the EVPN kernel baseline we test.
   Defensive shape: if a stamped neighbor install does fail with `EINVAL`
   where the unstamped shape succeeds (strict-validation kernel without the
   attr), retry once unstamped, log once per process, and latch
   stamping-unavailable: adoption then stays on the legacy markers
   permanently for that run. The authoritative signal for "stamp is live"
   is the dump side — our own freshly-installed row echoing `Protocol`
   back — which the adoption sweep sees for free.
6. **Non-goals.** No `NDA_FDB_EXT_ATTRS`/activity-notify usage, no
   persisted stamp state (ADR-0079: no new owned-state files), no change
   to the unicast FIB path (already value-match adoption), and no attempt
   to disambiguate two rustbgpd instances on one host (unsupported).

## Operational hazards recorded (not solved here)

- **The FDB discriminator stays flag-only until the kernel patch lands.**
  An operator's `bridge fdb add ... extern_learn` on a managed VXLAN
  device is still adoptable/reapable by us on current kernels. The ADR
  narrows this for neighbors only; the FDB half lands for free later.
  (The parallel ADR-0079 scoping fix owns the managed-VNI boundary.)
- **A stamp can be silently shed.** `ip neigh replace` by an operator
  without `protocol` rewrites the row stampless; under a future strict
  rule that row strands after the next unclean restart. Same class as
  ADR-0079's "operator's `ip route add proto bgp` is indistinguishable"
  hazard — document, don't solve.
- **A stamp can be silently swapped.** Netlink replace semantics let
  another controller rewrite a row we own with *its* stamp between our
  install and our delete; delete paths trust the owned/adopted sets and
  do not recheck the live row, so the delete would take out the foreign
  row (netlink has no compare-and-delete, so a delete-time recheck only
  narrows the race). Moot for FDB on current kernels (the stamp is not
  stored) and an active-conflict scenario co-residency already excludes.
  Intended fix when FDB stamping goes live: snapshot-driven ownership
  *relinquishment* — a reconcile dump showing a foreign stamp at an
  owned key drops the key from owned state instead of deleting the row,
  the same kernel-reality-wins shape the adoption reap retain uses.
- **FRR co-residency is now *detectably* excluded for neighbors**: zebra
  rows carry `RTPROT_ZEBRA` and ours `RTPROT_BGP`, so the sweeps no
  longer cross-adopt neighbor state. FDB cross-adoption remains possible
  on current kernels (both stamp-as-no-op, both `extern_learn`);
  co-residency stays unsupported.
- Carrier-down still flushes ext-learned neighbors regardless of stamp;
  the level-triggered re-install path (ADR-0079 decision 5) is the
  mitigation, unchanged.

## Consequences

- The scariest residual ADR-0079 false-adoption case — adopting and later
  reaping another controller's L3 neighbor state — closes on kernels
  ≥ 5.0 with zero new dependencies (`netlink-packet-route 0.30.0` already
  models the attribute; `rtnetlink 0.21.0` reaches it via
  `message_mut()`).
- Three of four write sites stamp into the void today. That is accepted
  and deliberate (FRR parity): when bridge/vxlan `NDA_PROTOCOL` merges,
  already-deployed rustbgpd versions begin writing effective stamps with
  no upgrade, and the prefer-mode classifier starts honoring them with no
  flag day.
- `ip neigh show` / JSON output on managed L3VXLAN devices gains
  `protocol bgp`, improving operator attribution alongside the existing
  `extern_learn` flag.
- The M60 adoption-sweep interop job should grow two asserts: a
  still-desired L3 neighbor re-adopted with the stamp present, and a
  planted `extern_learn` + `protocol zebra` neighbor row left untouched
  (foreign by stamp). FDB asserts stay flag-based until a CI kernel
  stores the attribute.
- Upgrade docs gain the release-N-before-strict note (decision 4); the
  strict flip is a separate, observable change in a later release, not
  part of this ADR's first slice.

## References

- Kernel commit `df9b0e30d44c` "neighbor: Add protocol attribute"
  (David Ahern, merged v5.0):
  <https://github.com/torvalds/linux/commit/df9b0e30d44c901ac27c0f38cd54511b3f130c6d>;
  changelog entry: <https://kernelnewbies.org/Linux_5.0>
- `nda_policy` / `rtnl_fdb_add` (NULL-policy parse; FDB handlers ignore
  the attribute), `net/core/neighbour.c` + `net/core/rtnetlink.c`,
  torvalds/linux master (verified 2026-06: no `NDA_PROTOCOL` in
  `net/bridge/br_fdb.c` or `drivers/net/vxlan/vxlan_core.c`)
- Proposed bridge/vxlan FDB protocol support (unmerged, Aug 2025):
  <https://www.mail-archive.com/bridge@lists.linux-foundation.org/msg11200.html>,
  <https://lkml.org/lkml/2025/8/18/1486>
- FRR zebra `is_own` check and NDA_PROTOCOL stamping:
  <https://github.com/FRRouting/frr/blob/master/zebra/rt_netlink.c>
- FRR EVPN graceful restart (PR #19778, merged 2026-01-06; neigh restore
  keyed on `is_own`, MAC/FDB restore on `NTF_EXT_LEARNED`):
  <https://github.com/FRRouting/frr/pull/19778>
- iproute2 `ip neigh` protocol support (commit `6b83edc06`, 2018-12-27);
  iproute2 main `bridge/fdb.c` has no protocol keyword (verified 2026-06):
  <https://github.com/iproute2/iproute2>
- `netlink-packet-route` 0.30.0 `NeighbourAttribute::Protocol`:
  <https://docs.rs/netlink-packet-route/0.30.0/netlink_packet_route/neighbour/enum.NeighbourAttribute.html>

See also ADR-0079 (adoption sweeps; the marker table and `RTPROT_BGP`
contested-marker hazard this ADR extends), ADR-0059 (NHG drift sweep),
ADR-0061 (unicast FIB ownership discipline).
