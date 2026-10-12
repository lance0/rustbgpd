# ADR-0140: EVPN core isolation and startup hold for bound Ethernet Segments

**Status:** Proposed (design only; no runtime behavior shipped. Four
decisions remain open; see [Open decisions](#open-decisions))
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
aggregator, from the PE side, without leaving a CE link down after the
condition clears or the daemon dies.

### Primary sources: Linux protodown

The ticket proposed `IFLA_PROTO_DOWN` with a rustbgpd bit in
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

The feature is **opt-in** and global, through a new top-level table:

```toml
[evpn_core_isolation]
enabled = true                 # default false
uplinks = ["eth1", "eth2"]     # optional; see decision 2
hold_after_sync_seconds = 10   # default 10, 0..=3600
max_hold_seconds = 180         # default 180, 0..=3600
```

The table is accepted only when `[[ethernet_segments]]` has at least one
bound segment and the EVPN dataplane runs on Linux. Validation rejects
`max_hold_seconds < hold_after_sync_seconds` unless `max_hold_seconds` is 0.
Runtime reload may toggle `enabled`, edit the lists and change the timers.
Disabling the feature releases every held link at once (decision 6).
Whether this should be default-on is open decision 1.

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
- **Uplinks, optional.** `uplinks` is set and none of the named links has
  carrier in the `link_carrier` projection. A missing link counts as down,
  as in ADR-0085.

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
  fails at debug level and the CE is never moved. A protodown provider is
  open decision 2. It is not part of the v1 contract.
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

**Other link owners.** Admin state has no owner field, so the contract is
explicit:

- rustbgpd takes only links that are admin-up when it acts. A link already
  down is not recorded and is never brought up by rustbgpd.
- rustbgpd brings up only links it recorded in its receipt (decision 6),
  matched by name and ifindex.
- If a held link is observed admin-up while rustbgpd holds it, rustbgpd
  treats this as an operator or network-manager override. It does not take
  the link down again, it reports `overridden`, and it drops the link from
  its receipt.
- systemd-networkd with `ActivationPolicy=always-up` re-raises any link set
  down. With `BindCarrier=` it also drives admin state. Members of a held
  ES need `ActivationPolicy=manual` (or `up`, which acts only on
  reconfiguration), and the operator guide must say so. NetworkManager's
  behaviour toward an externally downed bond port was not verified.
  Members should be unmanaged or the setup tested before enabling.
- An operator who downs a held member for maintenance cannot be told apart
  from rustbgpd's own down, which uses the same bit. Release will bring that
  member up. Maintenance on a held ES should use the ADR-0084 drain or
  disable this feature first. Protodown reasons would avoid this, which is
  the main argument for open decision 2.

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
  set is empty, and decision 5's ceiling releases the links.
- If both ES members are isolated together, both take their CE links down.
  The CE then has no path to the overlay through either PE, which is
  already the case. Only local switching on the isolated PEs is lost. This
  matches FRR, which isolates every ES unconditionally.

A suppressed isolation is reported, never silent (decision 7).

### 5. Startup hold and recovery hold

The two holds follow one sequence. A hold **arms** at daemon start (the
startup hold) or at the isolation edge. An isolation hold stays in place
while the PE is core-isolated. Once it is not, the hold **releases** when
either of these happens first:

- `QueryEvpnSessionsSynced` has reported `true` continuously for
  `hold_after_sync_seconds` (default **10**, 0–3600); or
- `max_hold_seconds` (default **180**, 0–3600) have passed since the
  core-up edge, or since daemon start for the startup hold. With 0, the
  startup hold is disabled, and an isolation hold releases as soon as the
  core is up.

The startup hold is the one case where the ceiling can release a
core-isolated PE. A fresh start has no peer set, so the startup hold applies
to every bound ES without the decision 4 check. When it expires, decision 4
applies: if the core is still unreachable and no peer was ever recorded, the
links come up. The 180 s default matches FRR's `startup-delay` default, so
an unreachable core cannot hold CE links down indefinitely. If the core
comes up during the startup hold and a peer is recorded, and the core is
then lost before release, the startup hold becomes an isolation hold.

Gating on sync rather than a plain timer releases a healthy PE in seconds
rather than minutes, and it never releases before every established EVPN
session has sent End-of-RIB. The settle period covers dataplane programming
of the remote MACs learned from those routes. Once a link is back up,
ADR-0085's `recovery_delay_seconds` still governs when the ES's own routes
are originated again. CE traffic enters before this PE attracts remote
traffic, never after.

A startup hold takes down links that are up at boot. On a planned
graceful restart this moves all of the CE's traffic to the other ES member
until EVPN syncs. That is the intended outcome of "the CE does not use this
PE before End-of-RIB". A GR-aware exemption is not part of this decision.

### 6. Crash and reconcile safety

- **Receipt.** Before the first admin-down, rustbgpd writes and fsyncs
  `<runtime_state_dir>/evpn-core-isolation-owned.json`. The receipt lists
  `(ES binding, link name, ifindex)` for each link about to be taken down.
  Entries are removed after a successful admin-up. If the receipt cannot be
  written, rustbgpd does not act and reports `action_failed`. This follows
  ADR-0079: there is no kernel marker for admin state, so ownership needs an
  exact-value receipt.
- **Clean shutdown** releases every held link after the EVPN sessions are
  closed, then removes the receipt. A stopped daemon leaves no CE link down.
- **Unclean exit, then restart.** The receipt is read before the
  startup hold arms. Recorded links that still match by name and ifindex and
  are still down are adopted into the startup hold, and decision 5 releases
  them. Any recorded link whose ES is no longer bound, or whose
  binding changed, or that exists while the feature is disabled, is brought
  up at once. Entries that no longer match, because the link is gone or was
  recreated with a new ifindex, are dropped without action.
- **Unclean exit with no restart.** The links stay down until an operator
  raises them. The receipt is plain JSON and names them, and the operator
  guide gives the `ip link set <member> up` recovery. The shipped systemd
  unit restarts on failure. An `ExecStopPost=` helper that releases from
  the receipt is a possible follow-up. It is not part of this decision.
- **Runtime changes.** Removing a binding, rebinding to another link,
  removing the ES, or disabling the feature releases the affected links
  through the same path. The ADR-0084 operator drain does not change the
  hold.

### 7. Observability

- `evpn_es_core_isolation_state{interface, state}`: a state set per bound
  interface, in the pattern of `evpn_es_auto_esi_state`. It is keyed by
  interface because an auto-lacp ES can lose its ESI while held. States:
  - `released`
  - `startup_hold`
  - `isolated`
  - `recovering` (core up, waiting for sync or settle)
  - `suppressed_no_peer` (decision 4 stopped an isolation)
  - `overridden`
  - `action_failed`
  - `disabled`
- `evpn_core_isolated{signal}`: 0 or 1, with `signal` ∈ {`sessions`,
  `uplinks`}.
- Every transition is logged once with a stable reason code. Entering
  `isolated` and `suppressed_no_peer` log at `warn`.
- `rbgp doctor` adds one `evpn.es.<interface>.core_isolation` check per
  bound ES while the feature is enabled, built like the auto-lacp check.
  - `warn` for `isolated`, `startup_hold` past `max_hold_seconds`,
    `suppressed_no_peer` or `overridden`.
  - `fail` for `action_failed`.
  - It also warns when every configured uplink lacks carrier while
    sessions are Established, which points to a wrong `uplinks` list.

### 8. Required evidence

Each regression must fail when the action is removed:

- Paused-clock unit tests of the planner:
  - isolate → hold;
  - recover → sync → settle → release;
  - the ceiling;
  - GR-stale non-isolation;
  - the peer latch across the last-session-down flush;
  - override handling.
- Netns tests (privileged runner): member admin-down and up on bond and
  veth. Also receipt write-ahead, adoption after a simulated crash, and
  release of a receipt-only link once its binding is removed.
- Interop in the existing FRR all-active topology:
  - Cut rustbgpd's underlay. The CE drops its member from the aggregator,
    and remote↔CE traffic continues through FRR with bounded loss.
  - Restore the underlay. The link returns only after EVPN sync and the
    settle period.
  - Restart rustbgpd. The CE does not use rustbgpd's link before
    End-of-RIB.
  - Record the pre-fix loss in the receipt.

Timing bounds need a quiet host. Results from a busy development host count
as correctness evidence only.

## Open decisions

1. **Opt-in or default-on.** Recommendation: **opt-in**. The action changes
   admin state on links that other managers may own, and its effect on the
   CE depends on CE LACP settings outside rustbgpd's control. Revisit after
   the interop receipt and one operator deployment.
2. **Admin-down only, or protodown where supported.** Recommendation:
   **admin-down only** for v1. A protodown provider has better ownership
   semantics: a reason bit, foreign reasons preserved, and kernel-side
   EBUSY protection. But no device in the supported topology accepts it, so
   it cannot be qualified or tested. Add it as a second provider, selected
   by probing with a masked reason write, only when a CE-facing device that
   accepts it is in scope.
3. **Startup-hold defaults.** Recommendation: `hold_after_sync_seconds = 10`
   and `max_hold_seconds = 180`, which is FRR's startup-delay default. The
   alternative is a 30 s ceiling to match ADR-0085's `recovery_delay_seconds`
   and the RFC 9785 boot wait. That gives less protection when the core is
   slow to establish.
4. **Uplink combination.** Recommendation: **OR**, as in decision 2. The
   alternative, sessions only with no `uplinks` key, is simpler but detects
   isolation only at hold-timer or BFD speed.

## Consequences

- An isolated all-active PE stops attracting CE traffic. Recovery and boot
  release only after EVPN has synced. This closes the loss the premise run
  measured, within the limits of the CE's LACP settings.
- rustbgpd starts owning link admin state on CE-facing links. That is a new
  kernel-ownership surface. Its safety comes from the receipt and the
  don't-fight rule, not from a kernel marker.
- Reusing ADR-0085's link drain means isolation and release need no new
  drain reason. Origination order follows the tested link-recovery path.
- A planned restart now moves CE traffic to the other ES member for the
  startup hold.
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
- systemd `systemd.network(5)`, `ActivationPolicy=`.
