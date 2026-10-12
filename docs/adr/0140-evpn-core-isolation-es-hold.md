# ADR-0140: EVPN core isolation and startup hold for bound Ethernet Segments

**Status:** Accepted (design; no runtime behavior shipped. The four open
decisions were taken on 2026-10-12; see [Decisions](#decisions))
**Date:** 2026-10-12

## Context

An all-active multihomed PE that loses every L2VPN/EVPN session, or every
underlay uplink, can no longer reach the overlay. The remote PEs see its
routes withdraw and stop sending to it. The CE does not see any change. Its
LACP member toward the isolated PE stays up, so the CE keeps hashing a share
of its flows into that PE, which drops them. Nothing ends this while the
isolation lasts. The same happens at boot: the ES bond comes up before EVPN
has converged, and the PE attracts traffic it has no routes for.

A premise run reproduced the loss on the current tree. The topology had a
stock-Linux FRR 10.7.1 PE and rustbgpd sharing one all-active ES, a Linux
802.3ad CE, and a remote FRR PE, on a Linux 7.0 kernel. Only rustbgpd's
underlay was cut. Its EVPN sessions went Idle and the remote Type 2 route
disappeared, but its ES bond and the CE member stayed `UP,LOWER_UP`. The CE
kept both ports in its active aggregator, with actor and partner LACP state
63 on both. Of 20 packet identities the CE hashed toward rustbgpd, all 20
reached rustbgpd's ES port and none reached the remote host. All 20 control
identities hashed toward FRR were delivered. After the underlay was restored,
all 40 were delivered again. The run makes no timing claim.

rustbgpd has no defence today:

- [ADR-0085](0085-evpn-es-interface-binding.md) drains an ES from the
  attachment circuit's own carrier. It explicitly deferred a global startup
  delay. The segment actor reads EVPN session state only for the RFC 9785
  §4.3 boot DF-recovery wait (`settle_boot_wait`, bounded at 30 s).
- The single-active AC gate sets `IFLA_BRPORT_STATE disabled` on the bound
  bridge port. That stops forwarding but leaves the link and LACP up, so the
  CE does not move its traffic. It does not apply to all-active segments.
- No RFC covers this. It is vendor practice: FRR documents uplink tracking
  and an ES startup delay, both implemented with protodown.

The fix must make the CE take the isolated PE's member out of its
aggregator, from the PE side. It must not leave a CE link down after the
condition clears. When the daemon exits, the links it took down must have a
defined release path:

- in-process on clean shutdown;
- out-of-process from the supervisor's stop hook after any exit;
- at the next start when neither of those ran.

Decision 6 states exactly which guarantee holds in each case.

### Primary sources: Linux protodown

The original proposal used `IFLA_PROTO_DOWN` with a rustbgpd bit in
`IFLA_PROTO_DOWN_REASON`. That action does not work on the devices an ES
binds to.

- **Only devices that opt in accept protodown.** `do_set_proto_down`
  returns `-EOPNOTSUPP` with "Protodown not supported by device" unless
  `dev->change_proto_down` is set
  ([net/core/rtnetlink.c#L3001-L3053](https://github.com/torvalds/linux/blob/v7.0/net/core/rtnetlink.c#L3001-L3053)).
  The same check guards the sysfs `proto_down` write
  ([net/core/dev.c#L10170-L10182](https://github.com/torvalds/linux/blob/v7.0/net/core/dev.c#L10170-L10182)).
  In v7.0 exactly two drivers set the flag:
  [macvlan](https://github.com/torvalds/linux/blob/v7.0/drivers/net/macvlan.c#L1225)
  and [vxlan](https://github.com/torvalds/linux/blob/v7.0/drivers/net/vxlan/vxlan_core.c#L3374).
  Bonding, team, veth and every physical NIC driver leave it unset. A search
  of v7.3-rc7 finds no further users.
- **History and kernel floor.** The generic handler and the macvlan and vxlan
  implementations arrived in v5.1 (commits `b58996795dc4`, `2e8b4ba64676`,
  `8f1af75df3a7`). `IFLA_PROTO_DOWN_REASON` arrived in v5.9 (`829eb208e80d`).
  v5.17 replaced `ndo_change_proto_down` with the `change_proto_down` flag
  (`2106efda785b`) and did not change which drivers support it. Before v7.2,
  a macvlan's protodown could be undone by toggling its lower device's
  carrier. v7.2 makes `netif_carrier_on()` a no-op while protodown is on
  (`99f8efac7f99`).
- **Reason semantics.** A reason update with a mask changes only the masked
  bits. A zero or absent mask replaces the whole word, which clears other
  owners' reasons
  ([net/core/dev.c#L10191-L10209](https://github.com/torvalds/linux/blob/v7.0/net/core/dev.c#L10191-L10209)).
  Setting a reason does not set protodown. Clearing protodown fails with
  `-EBUSY` ("Cannot clear protodown, active reasons") while any reason bit
  remains set.
- **What protodown does.** `netif_change_proto_down` only turns the local
  device's carrier off or on. On a device that supports it, it is a
  carrier-off with an owner field, not a signal to the far end.

### Primary sources: FRR 10.7.1

The pinned tree is
[f8c0b08d](https://github.com/FRRouting/frr/tree/f8c0b08dcb0c78f9e42b9b86ae70b049e4e617c1).

- **Uplink tracking.** An interface configured with `evpn mh uplink` counts
  as up only while it is operative (up, running and lower-up). The PE is
  isolated when uplinks are configured and none is up
  ([zebra_evpn_mh.c#L3900-L3903](https://github.com/FRRouting/frr/blob/f8c0b08dcb0c78f9e42b9b86ae70b049e4e617c1/zebra/zebra_evpn_mh.c#L3900-L3903)).
  FRR does not use BGP session state for this.
- **What FRR protodowns.** FRR records the reason on the ES bond in software
  only. It writes protodown to the kernel on each **bond member**
  ([zebra_evpn_mh.c#L3766-L3813](https://github.com/FRRouting/frr/blob/f8c0b08dcb0c78f9e42b9b86ae70b049e4e617c1/zebra/zebra_evpn_mh.c#L3766-L3813)).
  Protodown is reported as not applicable to a bond master
  ([interface.c#L2774-L2780](https://github.com/FRRouting/frr/blob/f8c0b08dcb0c78f9e42b9b86ae70b049e4e617c1/zebra/interface.c#L2774-L2780)).
  The netlink write masks FRR's own reason bit, which defaults to bit 7
  ([if_netlink.c#L1610-L1623](https://github.com/FRRouting/frr/blob/f8c0b08dcb0c78f9e42b9b86ae70b049e4e617c1/zebra/if_netlink.c#L1610-L1623)).
- **Startup delay.** The default is 180 s and the range 0–3600
  ([zebra_evpn_mh.h#L284](https://github.com/FRRouting/frr/blob/f8c0b08dcb0c78f9e42b9b86ae70b049e4e617c1/zebra/zebra_evpn_mh.h#L284),
  [zebra_vty.c#L2808](https://github.com/FRRouting/frr/blob/f8c0b08dcb0c78f9e42b9b86ae70b049e4e617c1/zebra/zebra_vty.c#L2808)).
  The timer starts at zebra init and again when the first uplink recovers
  ([zebra_evpn_mh.c#L3970-L3983](https://github.com/FRRouting/frr/blob/f8c0b08dcb0c78f9e42b9b86ae70b049e4e617c1/zebra/zebra_evpn_mh.c#L3970-L3983)).
  It is a plain timer, not gated on BGP convergence.
- **No peer check.** Every local ES is protodowned, including one with no
  remote ES peer
  ([zebra_evpn_mh.c#L3870-L3877](https://github.com/FRRouting/frr/blob/f8c0b08dcb0c78f9e42b9b86ae70b049e4e617c1/zebra/zebra_evpn_mh.c#L3870-L3877)).
- **No fallback.** A rejected protodown write is logged only at debug level.
  zebra does not retry and does not fall back to another action
  ([interface.c#L1437-L1458](https://github.com/FRRouting/frr/blob/f8c0b08dcb0c78f9e42b9b86ae70b049e4e617c1/zebra/interface.c#L1437-L1458)).
  On stock Linux, where bond members are physical NICs or veths, FRR's
  uplink tracking and startup delay therefore have no kernel effect. FRR's
  shipped behaviour depends on a platform whose member ports accept
  protodown. Which Cumulus Linux component provides that was not verified
  from a primary source.
- **Crash safety.** At startup zebra clears its own reason bits and leaves
  foreign ones in place
  ([interface.c#L1825-L1844](https://github.com/FRRouting/frr/blob/f8c0b08dcb0c78f9e42b9b86ae70b049e4e617c1/zebra/interface.c#L1825-L1844)).

### Probe: what the kernel accepts and what the CE sees

The probe ran in an owned privileged container (`NET_ADMIN`, `SYS_ADMIN`)
with iproute2 6.15 on the Linux 7.0 kernel. It used three network
namespaces. `pe1` and `pe2` each had an 802.3ad bond `es0` with
`lacp_rate fast` and the same `ad_actor_system`, as two all-active PEs.
Each bond had one veth member. The CE bond had `ad_select stable` and one
member toward each PE. Both CE members joined aggregator 1 with LACP state
63 before every step. All namespaces were deleted after the run.

| PE-side action on `pe1` | Kernel result | CE observation |
|---|---|---|
| `protodown on` / `protodown_reason N on`, bond master | `EOPNOTSUPP`: "Protodown not supported by device" | — |
| The same on the enslaved veth, or a sysfs `proto_down` write | Rejected the same way; sysfs returns `EIO` | — |
| `carrier off`, bond master or enslaved veth | `EOPNOTSUPP` | — |
| `protodown_reason` on a macvlan, as a reference | Accepted; reasons `<0,7>` coexist; `protodown off` with bit 0 still set returns `EBUSY` | — |
| Admin-down the bond member | Accepted; member stays enslaved; bond carrier drops within 0.2 s | CE member `NO-CARRIER` within 10 ms, out of the transmit set; rejoins within 10 ms of admin-up |
| Admin-down the bond master | Accepted; member stays up with carrier | CE member in `BACKUP` after 2.4 s (LACP fast timeout); rejoins 0.3 s after admin-up |
| Change `ad_actor_system` on the running bond | Accepted | CE moves the member to a separate aggregator 2 (`BACKUP`) within 4 s; restored by writing the original value back |
| `lacp_active off` or `coupled_control off` on a running bond | Rejected: "unable to set option because the bond is up" | — |
| Per-member bond options | Writable: `queue_id`, `prio`, `actor_port_prio` only ([bond_netlink.c#L135-L139](https://github.com/torvalds/linux/blob/v7.0/drivers/net/bonding/bond_netlink.c#L135-L139)) | None of them affects LACP sync |

The veth result for member admin-down comes from `veth_close` turning off
its peer's carrier
([veth.c#L1410-L1417](https://github.com/torvalds/linux/blob/v7.0/drivers/net/veth.c#L1410-L1417)).
Whether a physical NIC drops PHY link on admin-down depends on the driver;
i40e and ice, for example, expose a `link-down-on-close` private flag. When
the PHY stays up, the closed member stops sending LACPDUs, so the CE removes
it after its LACP timeout: about 3 s at the fast rate, 90 s at the slow rate.
That path was not probed on hardware.

### Constraints from this codebase

- The RIB already holds what the signal needs. `QueryEvpnSessionsSynced`
  reads the newest live-session record per peer and reports `true` only when
  at least one L2VPN/EVPN session is established, every such session has
  sent End-of-RIB, and GR selection deferral does not hold the family.
- The `link_carrier` monitor (ADR-0085 decision 4) already projects carrier
  for named links over `RTNLGRP_LINK`, with a poll backstop.
- ADR-0085 turns carrier loss on a bound link into the `Link` drain reason,
  and re-arms `recovery_delay_seconds` on every up edge. Any PE-side action
  that removes carrier from the bound bond therefore also withdraws the ES's
  routes. Releasing the action returns origination through the existing
  hold-off.
- `esi = "auto-lacp"` segments are NotReady while their bond is admin down,
  has no carrier, or has no LACP partner. A held auto-lacp segment loses its
  runtime ESI and its routes. It regains them on the first probe after
  release, up to 2 s later.
- [ADR-0079](0079-kernel-state-crash-restart-reconciliation.md) sets the
  ownership rule for kernel state that survives a crash: use a kernel marker
  where one exists. Where none exists, use an exact-value receipt in
  `runtime_state_dir`, as the FIB and BLACKHOLE paths do.

## Decision

### 1. Scope: bound segments, opt-in

The feature applies only to segments with an ADR-0085 `interface` binding,
in either redundancy mode. A single-active DF that loses its core is the
same case: it still elects itself DF and forwards, so its CE never fails
over. An unbound segment has no handle to act on and is unaffected.

The feature is **opt-in** and global, through a new top-level table.
rustbgpd takes control of link admin state only when the operator enables it
explicitly. Enabling it is consent to the ownership contract in decision 3.

```toml
[evpn_core_isolation]
enabled = true                 # default false
uplinks = ["eth1", "eth2"]     # optional; see decision 2
hold_after_sync_seconds = 10   # default 10, 0..=3600
backstop_seconds = 180         # default 180, 1..=3600
```

The table is accepted only when `[[ethernet_segments]]` has at least one
bound segment and the EVPN dataplane runs on Linux. Validation rejects a
`backstop_seconds` below `hold_after_sync_seconds`.

While the feature is enabled, each `interface` may be bound by only one
segment. Today two explicit-ESI segments may bind the same interface; with
the feature on, validation rejects that and names both segments. With two
segments on one link, isolating one ES would also disconnect the other,
which might be `suppressed_no_peer`, and a per-interface state could not
represent both. This record does not define per-interface aggregation.

Validation also rejects any `uplinks` entry that names a bound
`interface`, and the error names both the uplink and the segment. Without
this check, isolation would latch: rustbgpd's own admin-down would remove
that uplink's carrier, and the ORed signal would never clear. Config
validation does not read the kernel, so the runtime check in decision 2
covers an uplink that is enslaved under a bound bond.

Runtime reload may toggle `enabled`, edit the lists and change the timers.
Disabling the feature releases every held link at once (decision 6).

### 2. Signal: core isolation

The PE is **core-isolated** when either condition holds.

- **Sessions.** The RIB has no Established L2VPN/EVPN session **and** no
  L2VPN/EVPN peer whose routes it is retaining as stale under GR or LLGR.
  The answer comes from the RIB's live-session records through an extension
  of the existing `QueryEvpnSessionsSynced` reply (established count, stale
  count, synced). The segment actor already polls that query. Stale
  retention is excluded because a planned route-reflector restart drops the
  sessions while the overlay data plane keeps forwarding on retained routes.
  Isolating during that window would cause the outage it is meant to
  prevent.
- **Uplinks, optional.** `uplinks` is set and **all** of the named links
  lack carrier in the `link_carrier` projection. A missing link counts as
  down, as in ADR-0085. Losing one redundant uplink while another still has
  carrier does not isolate the PE.
- **Our own actions never feed the uplink signal.** An uplink is excluded
  from the signal whenever it is a managed member, the bound link itself,
  or a link whose master is a bound bond. "Managed member" covers anything
  in the receipt or found by member discovery. Discovery and the
  `link_carrier` projection see the same kernel state, so this applies at
  runtime.
  - The daemon logs an error that names both the uplink and the binding.
  - The binding's state becomes `uplink_overlap`, and `rbgp doctor`
    reports it as `fail`.
  - If every configured uplink is excluded, the uplink signal is false.
  - Carrier loss caused by rustbgpd's own admin-down therefore cannot hold
    the PE isolated.

The two are **ORed**. The session signal is topology-independent but only
as fast as the hold timer or BFD. The uplink signal is immediate but sees
only local link failure. Requiring both would add no protection, because the
sessions must fail anyway, and would lose the fast path. A wrong `uplinks`
entry can isolate a healthy PE. The CE still has the other ES member, so
the cost is redundancy, not reachability. The doctor check in decision 7 names
an uplink set with no carrier.

Isolation is entered immediately. Session hold timers, BFD and GR already
provide debounce, and a flapping uplink is damped by the recovery hold in
decision 5.

### 3. Action: admin-down the bound link's members

The action takes the CE-facing link administratively down by clearing
`IFF_UP` with `RTM_SETLINK`:

- If the bound interface is a bond, every **member** is taken down. The bond
  master stays up and the members stay enslaved.
- Otherwise the bound link itself is taken down.

Member admin-down is chosen over the alternatives for these reasons:

- **Protodown.** No CE-facing device in the probe accepts it, and no
  upstream bond, team, veth or physical-NIC driver supports it through
  v7.3-rc7. FRR's stock-Linux behaviour shows the failure mode: the write
  fails at debug level and the CE is never moved. The first implementation
  has no protodown provider (see [Decisions](#decisions), item 2).
- **Bond master admin-down.** It depends on the CE's LACP timeout: 2.4 s in
  the probe at the fast rate, up to 90 s at the slow rate. With a static
  LAG it never takes effect, because the members keep carrier.
- **`carrier off`.** Neither bonds nor veths support it. Of the drivers that
  implement `ndo_change_carrier` (dummy, tun, team and a few NIC drivers),
  most change only the local carrier, which the CE does not see.
- **Leaving or stopping LACP on a member.** Linux bonding has no per-member
  control for this. `lacp_active` and `coupled_control` can only be set on a
  bond that is down, and passive LACP still answers an active partner.
  Changing `ad_actor_system` on a running bond does move the member to a
  separate CE aggregator. But it applies to the whole bond, leaves the
  member with carrier, and works only if the CE's aggregator selection keeps
  the other PE's aggregator active. With `ad_select bandwidth` or `count`,
  two one-port aggregators tie, and the CE may pick the isolated PE's.
  A crash would also leave the bond with the wrong LACP identity. It is
  rejected.
- **nftables or tc drop.** This is not a fix. LACP and carrier stay up, so
  the CE keeps hashing the same flows into the PE. They are dropped at a
  different point.

**Device and provider contract.**

- The bound link is a bond, a physical NIC or a veth.
- The kernel floor is that of the existing EVPN dataplane, because admin
  state is ordinary `RTM_SETLINK`.
- CE removal is immediate when the member's far end loses carrier on
  admin-down, as with a veth or a NIC that drops PHY on close. Otherwise it
  is bounded by the CE's LACP timeout. A deployment needs either a NIC that
  drops link on close or a CE that requests fast LACPDUs (Linux
  `lacp_rate fast`, the LACP short timeout elsewhere). The operator guide must state this.

**Blast radius.** Each action touches one ES's attachment links only. Local
switching between this CE and other local ACs on the same PE stops while the
hold is in place. LLDP and any other protocol on those members stop too.
The bound bond loses carrier, so the ADR-0085 `Link` drain withdraws the
ES's Type 1/4 and local Type 2 routes. That is correct while isolated, and
on release origination returns through the existing recovery hold-off,
after the CE link is back (the M67 path). Single-active AC-gate state is
unaffected. The gate reconciles against observed port state when the link
returns.

**Exclusive admin-ownership contract.** Admin state is a single bit with
no owner field, and the kernel offers no compare-and-set on it. rustbgpd
therefore does not claim to tell its own writes apart from anyone else's.
The contract:

- While the feature is enabled and a segment is bound, rustbgpd owns the
  admin state of that binding's CE-facing members: each member of the bound
  bond, or the bound link itself. The operator must not manage that state by
  any other means, including `ip link`, systemd-networkd, NetworkManager or
  ifupdown. To work on a member, disable the feature or remove the binding
  first. Either releases the hold through decision 6.
- systemd-networkd with `ActivationPolicy=always-up` re-raises any link set
  down, and `BindCarrier=` also drives admin state. Members of a bound ES
  need `ActivationPolicy=manual`. NetworkManager's behaviour toward an
  externally downed bond port was not verified, so members should be
  unmanaged. The operator guide must state both.

**Fresh state checks before acting.** Immediately before each admin-down or
admin-up, rustbgpd re-reads the link. It writes only if the link still
matches the identity in decision 6 and its admin state differs from the
target.

**Level-triggered member discovery while a hold is in place.** A bond can
gain a member during the hold. That includes a held member that left the
bond and was enslaved again. A newly enslaved member starts admin-up and
rejoins LACP, so the CE would hash into the isolated PE again.

- While a hold is in place, rustbgpd recomputes the bound bond's member set
  from current kernel state. It does so on every `RTNLGRP_LINK` event that
  adds a link, changes a link's master or changes admin state, and on every
  poll-backstop pass.
- Each current member is classified:
  - **In the receipt, identity matches, admin-down:** held.
  - **In the receipt, admin-up:** `overridden` (below).
  - **Not in the receipt, admin-up, not previously overridden:** new. The
    receipt entry is durably published first, and the member is then taken
    down.
  - **Not in the receipt, admin-down:** left alone and not recorded.
- A member already admin-down when a hold begins is therefore left out of
  the receipt and is not raised on release. This is best effort within the
  contract, not a guarantee against other writers.
- A held member seen admin-up during the hold breaks the contract. rustbgpd
  does not take it down again, which would fight another manager. It reports
  `overridden` and removes the member from the receipt. It also remembers
  the override in memory until the hold ends, so the discovery pass does not
  treat the member as new.

**Residual race.** Re-reading the link and writing `RTM_SETLINK` are two
separate operations, so a foreign write between them goes undetected. The
next link event or poll then shows the result. Under the contract, nothing
legitimate writes in that window. Outside it, rustbgpd cannot tell an
operator's admin-down of an owned member from its own, and release raises
that member. Discovery has the same window: a member enslaved between two
passes carries traffic until the next event or poll. Decision 6 covers the
crash windows.

### 4. Safety rule: never isolate a CE that has no other ES member

Isolation takes an ES's links down only if the ES had at least one **remote
ES peer**: a Type 4 route for that ESI from another originator, carrying
the matching ES-Import route target, present in the Loc-RIB while the core
was up. The segment actor already gathers these candidates for DF election.

- The peer set is the one held while the last L2VPN/EVPN session was still
  Established. Type 4 routes that vanish because this PE's own sessions
  dropped do not count as peer departures. The implementation must take the
  session count and the per-ESI peer set from one RIB reply, or otherwise
  order the two, so the last-session-down flush cannot clear the peer set
  first.
- An ES whose peer withdrew its Type 4 while the core was still up has no
  other member left. It is not isolated: the CE keeps local switching, and
  traffic to the overlay would be lost either way.
- The peer set lives in memory only. After a restart during isolation, the
  set is empty, and decision 5's backstop releases the links.
- If both ES members are isolated together, both take their CE links down.
  The CE then has no path to the overlay through either PE, which is
  already the case. Only local switching on the isolated PEs is lost. This
  matches FRR, which isolates every ES unconditionally.

A suppressed isolation is reported, never silent (decision 7).

### 5. Startup hold and recovery hold

A hold **arms** at daemon start (the startup hold) or at the isolation edge.
An isolation hold stays in place while the PE is core-isolated. Once the PE
is no longer isolated, the hold releases under one of two separate rules:

- **Normal release.** `QueryEvpnSessionsSynced` has reported `true`
  continuously for `hold_after_sync_seconds` (default **10**, 0–3600).
  `true` means at least one L2VPN/EVPN session is Established, every
  Established session has sent End-of-RIB, and GR selection deferral does
  not hold the family.
- **Backstop release.** No normal release has happened when
  `backstop_seconds` (default **180**, 1–3600) have passed. The clock starts
  at daemon start for the startup hold, and at the core-up edge for an
  isolation hold.

**Availability trade-off.** The backstop can release before End-of-RIB, and
it does so deliberately: an EVPN session that never syncs must not keep the
CE out of the PE indefinitely. A backstop release is always reported:

- a `warn` log with the reason `backstop_unsynced`;
- the per-interface state `backstop_released`, held until a later sync is
  observed;
- a doctor warning (decision 7).

The 180 s default matches FRR's `startup-delay` default. Wherever this
record says release follows End-of-RIB, it means the normal release only.

**The settle period is a hold, not a confirmation.**
`hold_after_sync_seconds` gives the dataplane supervisor time to program the
remote MACs learned from the synced routes. Its expiry does not show that
the programming finished or succeeded, and release does not wait for any
dataplane acknowledgement.

A fresh start has no peer set, so the startup hold applies to every bound
ES without the decision 4 check. When the backstop fires:

- If the core is still unreachable and no peer was ever recorded,
  decision 4 applies and the links come up.
- If the core came up during the startup hold, a peer was recorded, and the
  core was then lost before release, the startup hold has already become an
  isolation hold.

Once a link is back up, ADR-0085's `recovery_delay_seconds` still governs
when the ES originates its own routes again. CE traffic reaches this PE
before the PE attracts remote traffic, never after.

A startup hold takes down links that are up at boot. On a planned graceful
restart, this moves all of the CE's traffic to the other ES member until
release. This decision does not include a GR-aware exemption.

**Planned-restart gap.** Clean shutdown releases held links (decision 6),
and links that were not held are already up. The CE may therefore hash
into this PE during two windows:

- after the old daemon has shut down, until the new daemon arms its startup
  hold;
- during a supervisor restart delay, such as systemd's `RestartSec`.

In those windows the PE forwards only on whatever kernel state remains. The
guarantee is therefore narrower: from the moment the startup hold arms, and
while EVPN syncs within the backstop, the CE does not use this PE before
End-of-RIB.

A handoff in which a clean shutdown followed by a restart leaves links held
was rejected. It needs a durable "restart follows" marker, and a stale
marker would leave links down after a stop that was not followed by a
start, which is the failure decision 6 exists to prevent.

### 6. Crash and reconcile safety

**Receipt.** Before each admin-down, rustbgpd durably publishes
`<runtime_state_dir>/evpn-core-isolation-owned.json`. The receipt records
**intent**, not proof that the write completed. If it cannot be published,
rustbgpd does not act and reports `action_failed`. Entries are removed
after a successful admin-up. This follows ADR-0079: admin state has no
kernel marker, so ownership needs an exact-value receipt.

**Atomic publication and a stable lock.**

- Every receipt update is published atomically, as the BLACKHOLE and FIB
  ownership receipts already are: write a temporary file, fsync it, rename
  it over the receipt, then fsync the directory.
- A rename replaces the receipt's inode, so a lock held on the receipt
  itself would not survive an update. Mutual exclusion therefore uses a
  separate lock file, `<runtime_state_dir>/evpn-core-isolation-owned.json.lock`.
  That file is created once and never renamed or removed.
- The daemon takes an exclusive advisory lock on the lock file at startup
  and holds it until exit. The kernel drops the lock when the process dies.
- The release helper takes the same lock before it reads or rewrites the
  receipt. Both of them update the receipt only while holding the lock.

**Incarnation identity.** `name` and `ifindex` are not durable: the kernel
reuses ifindex values, and a link can be renamed. ADR-0085 already resolves
bindings by name for this reason. Each receipt entry records everything
netlink exposes that distinguishes one link incarnation from another:

- the kernel boot ID (`/proc/sys/kernel/random/boot_id`);
- the identity of the daemon's network namespace (namespace inode and
  device);
- the binding identity: the segment's configured `esi` text and the bound
  interface name;
- the member's ifindex and name;
- the member's permanent MAC: `IFLA_BOND_SLAVE_PERM_HWADDR` for a bond
  member, and `IFLA_PERM_ADDRESS` when the kernel reports one (it omits an
  all-zero address, as on a veth). An absent attribute is recorded as
  absent;
- the member's assigned MAC (`IFLA_ADDRESS`);
- the master bond's ifindex and name.

**Safe rule.**

- A receipt entry is raised only if every recorded field matches the link's
  current state exactly, exactly one link matches, and the link is still
  admin-down.
- A different boot ID means the host rebooted and the kernel state is new.
  The entry is discarded and nothing is touched.
- On any other mismatch or ambiguity, rustbgpd **never raises the link**.
  That covers a changed name, ifindex, MAC or master, a missing link, more
  than one candidate, or a link that cannot be read.
  - The entry is kept.
  - The binding's state becomes `ownership_ambiguous` in the metric, and
    `rbgp doctor` reports it as `fail`.
  - The operator resolves it by raising the link by hand and clearing the
    entry.
- A renamed owned link is ambiguous under this rule. It is left down and
  reported, not raised under its new name. A member that left the bond
  while held is handled the same way.

**Crash between publication and the kernel write.** The receipt names a member
that was never taken down. At reconcile that member is admin-up. The entry
is discarded, because there is nothing to raise. If the startup hold applies,
the member is taken down again after a fresh receipt publication. A crash
during publication leaves either the old receipt or the new one, never a
partial file.

**Release paths, and what each one guarantees.**

- **Clean shutdown.** The daemon closes the EVPN sessions, releases every
  held link through the fresh checks, and then removes the receipt.
- **Out-of-process release after any exit.**
  - `rustbgpd --release-core-isolation --runtime-state-dir <dir>` is a
    one-shot mode beside `--check` and `--diff`.
  - It does not parse the configuration. The config is mutable and may be
    the reason the daemon failed. The receipt's location therefore never
    depends on it.
  - The daemon accepts the same `--runtime-state-dir` flag. When the flag is
    given and differs from the config's `runtime_state_dir`, the daemon
    refuses to start. The flag and the daemon's actual directory therefore
    cannot diverge silently.
  - The helper takes the lock without blocking. It exits non-zero without
    acting if a live daemon holds the lock.
  - Otherwise it applies the incarnation guards and safe rule above, raises
    only the members whose guards all match, and atomically republishes the
    receipt with whatever remains. It exits 0 only when nothing owned is
    left down. It exits non-zero while `ownership_ambiguous` entries
    remain.
  - **Failing loudly.** The helper fails with a non-zero exit and a message
    on stderr, which the journal records, when any of these holds:
    - the directory is missing or unreadable;
    - the lock file cannot be opened;
    - the receipt exists but cannot be read or parsed.
  - **Proving there is nothing to release.** A missing receipt counts as
    success only when the directory exists and is readable, and the helper
    holds the lock. Every admin-down is preceded by a durable receipt
    publication in that directory. A missing receipt there therefore proves
    that no owned link is down.
  - The shipped systemd unit passes the directory to both commands:
    `ExecStart=/usr/local/bin/rustbgpd --runtime-state-dir /var/lib/rustbgpd /etc/rustbgpd/config.toml`
    and
    `ExecStopPost=/usr/local/bin/rustbgpd --release-core-isolation --runtime-state-dir /var/lib/rustbgpd`.
    systemd runs `ExecStopPost=` after the service stops, after an
    unexpected exit, and after a failed start. It therefore also runs when
    `StartLimitBurst` stops further restarts.
  - The helper needs `CAP_NET_ADMIN`. The unit's capability set applies to
    it, and EVPN deployments already grant that capability.
  - Supervisors without a stop hook, such as plain containers, runit or
    OpenRC without a `stop_post`, must run the same command after the
    daemon exits. The operator guide documents this.
- **Next start.** The receipt is read before the startup hold arms.
  - Entries that pass every guard and are still admin-down are adopted into
    the startup hold, and decision 5 releases them.
  - Such an entry is raised at once if its segment is no longer bound or the
    feature is disabled.
  - Other entries follow the safe rule.
- **What remains.** Sometimes neither the stop hook nor a restart runs. The
  supervisor may have no hook configured, the helper may fail, or systemd
  itself may be killed. The CE links then stay down until the next start
  reconciles them, or an operator runs the release command or raises them
  by hand. A host crash is not in this set, because the reboot discards the
  entries by boot ID.

The guarantee is therefore exactly this. A daemon exit leaves no CE link
down that rustbgpd took down when one of these runs: a clean shutdown, the
stop-hook release, or a later start. The exception is links that the safe
rule leaves down as `ownership_ambiguous`, and those are reported.

**Runtime changes.** Removing a binding, rebinding to another link,
removing the ES, or disabling the feature releases the affected links
through the same guarded path. The ADR-0084 operator drain does not change
the hold.

### 7. Observability

- `evpn_es_core_isolation_state{interface, state}`: a state set per bound
  interface, in the pattern of `evpn_es_auto_esi_state`. It is keyed by
  interface because an auto-lacp ES can lose its ESI while held. States:
  - `released`
  - `startup_hold`
  - `isolated`
  - `recovering` (core up, waiting for sync or settle)
  - `backstop_released` (released by the backstop before sync; becomes
    `released` once sync is observed)
  - `suppressed_no_peer` (decision 4 stopped an isolation)
  - `overridden`
  - `ownership_ambiguous` (decision 6: a receipt entry that the safe rule
    will not raise)
  - `uplink_overlap` (decision 2: an uplink is, or is enslaved under, this
    binding and is excluded from the signal)
  - `action_failed`
  - `disabled`
- `evpn_core_isolated{signal}`: 0 or 1, with `signal` ∈ {`sessions`,
  `uplinks`}.
- Every transition is logged once with a stable reason code. Entering
  `isolated` and `suppressed_no_peer` log at `warn`.
- `rbgp doctor` adds one `evpn.es.<interface>.core_isolation` check per
  bound ES while the feature is enabled, built like the auto-lacp check.
  - `warn` for `isolated`, `backstop_released`, `suppressed_no_peer` or
    `overridden`.
  - `fail` for `action_failed`, `ownership_ambiguous` and
    `uplink_overlap`.
  - It also warns when every configured uplink lacks carrier while
    sessions are Established, which points to a wrong `uplinks` list.

### 8. Required evidence

Each regression must fail when the action is removed:

- Paused-clock unit tests of the planner:
  - isolate → hold;
  - recover → sync → settle → release;
  - backstop release before sync, with its warning state;
  - GR-stale non-isolation;
  - the peer latch across the last-session-down flush;
  - override handling, including no re-down by the discovery pass;
  - validation rejecting two segments that bind one interface while the
    feature is enabled, and an uplink that names a bound interface;
  - an uplink found at runtime under a bound bond is excluded, so isolation
    still releases once the core is back.
- Netns tests (privileged runner):
  - member admin-down and admin-up on a bond and on a veth;
  - receipt write-ahead;
  - adoption after a simulated crash;
  - an entry discarded for a foreign boot ID;
  - `ownership_ambiguous`, with the link left down, for:
    - a recreated link (new ifindex or permanent MAC);
    - a renamed owned link;
    - a member removed from the bond;
  - release of a receipt-only link once its binding is removed;
  - a member enslaved while isolated: its receipt entry is written before
    it is taken down, and it is raised on release;
  - `--release-core-isolation`:
    - refuses while the daemon holds the lock, including across a receipt
      update, which replaces the receipt's inode;
    - exits non-zero for a missing directory or an unreadable receipt, and
      exits 0 for a readable directory with no receipt;
    - after a simulated crash, raises exactly the guarded members and leaves
      ambiguous ones down.
- Interop in the existing FRR all-active topology:
  - Cut rustbgpd's underlay. The CE drops its member from the aggregator,
    and remote↔CE traffic continues through FRR with bounded loss.
  - Restore the underlay. The link returns only after EVPN sync and the
    settle hold.
  - Restart rustbgpd. When EVPN syncs within the backstop, the CE does not
    use rustbgpd's link before End-of-RIB.
  - Record the pre-fix loss in the receipt.

Timing bounds need a quiet host. Results from a busy development host count
as correctness evidence only.

## Decisions

The four questions this record left open were decided on 2026-10-12.

1. **Opt-in.** rustbgpd takes control of link admin state only with
   explicit operator consent: `[evpn_core_isolation] enabled = true`.
2. **Admin-down of the bound bond's members only** for the first
   implementation. While EVPN multi-homing is alpha there is no protodown
   provider. Adding one would need a CE-facing device that accepts a masked
   reason write.
3. **Holds.** `hold_after_sync_seconds` defaults to 10 s. A separate
   backstop, `backstop_seconds`, defaults to 180 s. A backstop release that
   happens without sync produces a warning in the log, the metric and the
   doctor check (decision 5).
4. **Signal.** The PE is isolated when it loses its EVPN sessions **or all**
   configured uplinks are down. Losing one redundant uplink while another
   still carries traffic does not isolate the PE.

## Consequences

- An isolated all-active PE stops attracting CE traffic. At recovery and
  at boot, release normally waits for EVPN to sync. The backstop can release
  earlier, with a warning. This closes the loss the premise run measured,
  within the limits of the CE's LACP settings.
- rustbgpd starts owning link admin state on CE-facing links, a new
  kernel-ownership surface. Its safety rests on the exclusive-ownership
  contract, fresh checks and an identity-guarded receipt, not on a kernel
  marker. The residual race in decision 3 remains.
- Reusing ADR-0085's link drain means isolation and release need no new
  drain reason. Origination order follows the tested link-recovery path.
- A planned restart moves CE traffic to the other ES member for the
  startup hold. Between the old daemon's shutdown and the new daemon's
  startup hold, the CE may still hash into this PE (decision 5).
- The `ExecStopPost=` release adds a step to the shipped unit. Deployments
  under other supervisors need the equivalent hook, or they rely on the next
  start to release the links.
- Stock-Linux FRR peers do not provide the reverse protection. If the FRR
  member is isolated, its protodown write fails and the CE keeps hashing
  into it. Operators of mixed deployments should know this.

## References

- [ADR-0079](0079-kernel-state-crash-restart-reconciliation.md),
  [ADR-0084](0084-evpn-ethernet-segment-drain.md),
  [ADR-0085](0085-evpn-es-interface-binding.md),
  [ADR-0102](0102-evpn-origination-acknowledgement.md).
- RFC 7432 §8 and §14.1.2, RFC 8584 §3, RFC 9785 §4.3.
- Linux v7.0: `net/core/rtnetlink.c`, `net/core/dev.c`,
  `drivers/net/bonding/{bond_options.c,bond_netlink.c}`,
  `drivers/net/veth.c`, and `Documentation/networking/bonding.rst`
  (`lacp_active`, `coupled_control`, `ad_actor_system`).
- FRR 10.7.1: `zebra/zebra_evpn_mh.c`, `zebra/interface.c`,
  `zebra/if_netlink.c`, and `doc/user/bgp.rst` (EVPN-MH uplink tracking
  and startup delay).
- systemd `systemd.network(5)` (`ActivationPolicy=`) and `systemd.service(5)`
  (`ExecStopPost=`).
