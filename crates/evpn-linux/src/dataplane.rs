//! [`Dataplane`] trait — the abstract interface the reconcile actor
//! drives.
//!
//! Two implementations exist:
//!
//! - [`crate::InMemoryDataplane`] (Phase 2) — the test fake. All
//!   platforms.
//! - `LinuxDataplane` (Phase 4, behind `cfg(target_os = "linux")`) —
//!   the real netlink impl.
//!
//! The actor is generic over `D: Dataplane`, so the same `tokio::select!`
//! loop drives both impls. Diff-loop unit tests live in `src/diff.rs`
//! and don't touch this trait at all (they're pure functions over
//! [`KernelSnapshot`] + [`rustbgpd_evpn::RemoteMacTable`]).
//!
//! ## Native `async fn` in trait
//!
//! Workspace MSRV is Rust 1.95, so `async fn` in trait is stable. The
//! actor is generic over `D: Dataplane`, so we don't need
//! `dyn Dataplane` and don't need the `async-trait` macro. Trait
//! methods return RPITIT (`-> impl Future + Send`) implicitly via the
//! `async fn` syntax.
//!
//! ## Reference
//!
//! - ADR-0054 §3 (kernel observation surface)
//! - ADR-0054 §6 (reconcile-on-event plus periodic full resync)

use std::collections::HashMap;
use std::net::IpAddr;

use rustbgpd_evpn::ip_vrf::{IpVrfRouteDump, IpVrfStatus, IpVrfTable};
use rustbgpd_evpn::{EvpnInstanceId, EvpnInstanceTable, IpVrfId, LocalMacObservation, MacAddress};
#[cfg_attr(not(test), allow(unused_imports))]
use tokio::sync::mpsc;

use crate::error::DataplaneError;
use crate::snapshot::{InstanceProbes, KernelSnapshot};

/// Single dataplane operation the actor asks the implementation to
/// apply.
///
/// One-to-one with [`rustbgpd_evpn::DataplaneOpKind`] but carries the
/// `(VNI, MAC)` key inline so the trait method signature is uniform.
/// The reconcile actor translates between the two when emitting
/// reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataplaneOp {
    /// Program a fresh remote-MAC FDB entry for `(vni, mac)` pointing
    /// at `dst`. Implementations should set `NTF_EXT_LEARNED` and
    /// route through the bridge/master path per ADR-0054 §5.
    AddRemoteFdb {
        /// EVPN instance identifying the bridge / VXLAN port.
        vni: EvpnInstanceId,
        /// MAC the entry programs.
        mac: MacAddress,
        /// Local Linux bridge VLAN attribution for ADR-0089
        /// VLAN-aware instances. `None` preserves the legacy
        /// non-VLAN-aware FDB wire shape.
        vlan: Option<u16>,
        /// Remote VTEP destination IP.
        dst: IpAddr,
    },
    /// Update an existing remote-MAC entry to a new VTEP destination
    /// (mobility — same MAC, different remote VTEP).
    UpdateRemoteFdb {
        /// EVPN instance identifying the bridge / VXLAN port.
        vni: EvpnInstanceId,
        /// MAC the entry programs.
        mac: MacAddress,
        /// Local Linux bridge VLAN attribution for ADR-0089
        /// VLAN-aware instances. `None` preserves the legacy
        /// non-VLAN-aware FDB wire shape.
        vlan: Option<u16>,
        /// New remote VTEP destination IP.
        dst: IpAddr,
    },
    /// Withdraw a previously-programmed remote-MAC entry. The
    /// implementation must only act on entries it owns
    /// (`NTF_EXT_LEARNED`); the actor's [`crate::OwnedSet`] makes that
    /// a structural property by iterating only owned keys at the diff
    /// level.
    RemoveRemoteFdb {
        /// EVPN instance the withdrawal targets.
        vni: EvpnInstanceId,
        /// MAC the entry programmed.
        mac: MacAddress,
        /// Local Linux bridge VLAN attribution for the row to remove.
        /// Keeps VLAN-aware deletes scoped to the configured bridge
        /// VLAN instead of matching another VLAN's row.
        vlan: Option<u16>,
    },
    /// Apply the per-port flood-flag triplet to a CE-facing bridge
    /// port (Gate 8b BUM-suppression primitive). Realized in
    /// [`crate::LinuxDataplane`] via a single `RTM_NEWLINK`
    /// (sent through `rtnetlink::LinkHandle::set_port`) carrying
    /// `IFLA_LINKINFO` with `IFLA_INFO_PORT_KIND = "bridge"` and
    /// `IFLA_INFO_PORT_DATA` holding the
    /// `IFLA_BRPORT_UNICAST_FLOOD` / `IFLA_BRPORT_MCAST_FLOOD` /
    /// `IFLA_BRPORT_BCAST_FLOOD` triplet. Implementations failing
    /// to apply the triplet surface
    /// [`DataplaneError::KernelTooOld`] (`EOPNOTSUPP`),
    /// [`DataplaneError::PermissionDenied`] (`EPERM` / `EACCES`),
    /// [`DataplaneError::LinkNotFound`] (`ENODEV` — stale
    /// ifindex), [`DataplaneError::InvalidArgument`]
    /// (caller-side guard, e.g. ifindex 0), or
    /// [`DataplaneError::Other`] (catch-all that the actor's
    /// backoff retries). The reconcile actor records the failure
    /// and the operator sees it via
    /// [`rustbgpd_evpn::DataplaneReport::failed`].
    SetBumPortFlags {
        /// CE-facing bridge port ifindex.
        ifindex: u32,
        /// Desired flag triplet for this port.
        flags: crate::bum_filter::BumPortFlags,
    },
    /// Apply the single-active AC gate: set the bound AC bridge
    /// port's `IFLA_BRPORT_STATE` to `BR_STATE_DISABLED` (`blocked`)
    /// or `BR_STATE_FORWARDING`. Realized in `crate::LinuxDataplane`
    /// via `RTM_SETLINK`/`AF_BRIDGE` + nested `IFLA_PROTINFO` — the
    /// `bridge link set ... state` wire shape, deliberately NOT the
    /// [`Self::SetBumPortFlags`] `set_port` shape, whose
    /// `NETDEV_CHANGE` side effect makes the bridge's carrier check
    /// instantly re-enable a just-disabled oper-up port (see
    /// `linux::ac_gate` module docs). The message carries **only**
    /// the state attribute so the flood-flag triplet on the same
    /// port is never clobbered (the kernel's `br_setport` applies
    /// only the attributes present). Failure classification:
    /// [`DataplaneError::PermissionDenied`] (`EPERM` / `EACCES`),
    /// [`DataplaneError::LinkNotFound`] (`ENODEV` — stale ifindex),
    /// [`DataplaneError::InvalidArgument`] (`EOPNOTSUPP` / `EINVAL` —
    /// the ifindex is not a bridge port, e.g. the bound link was
    /// unenslaved between snapshot and apply), or
    /// [`DataplaneError::Other`] for the actor's backoff.
    SetAcPortState {
        /// Bound AC bridge-port ifindex.
        ifindex: u32,
        /// `true` → `BR_STATE_DISABLED`; `false` →
        /// `BR_STATE_FORWARDING`.
        blocked: bool,
    },
    /// Create a configured ADR-0091 managed bridge and stamp it with
    /// its durable `IFLA_ALT_IFNAME` ownership marker. Implementations
    /// must treat an already-present exact stamp as idempotent success
    /// after a fresh link dump confirms the link is the expected bridge.
    CreateManagedBridge {
        /// Linux bridge name.
        name: String,
        /// Desired protected `vlan_filtering` value.
        vlan_filtering: bool,
        /// Durable rustbgpd ownership stamp for this bridge.
        ownership_stamp: String,
    },
    /// Delete a rustbgpd-stamped bridge that is no longer configured.
    /// Implementations must first confirm the live link still carries
    /// the exact expected ownership stamp and is a bridge.
    RemoveManagedBridge {
        /// Linux bridge name.
        name: String,
        /// Durable rustbgpd ownership stamp expected on the bridge.
        ownership_stamp: String,
    },
    /// Create a configured ADR-0091 managed fixed-VNI VXLAN and stamp
    /// it with its durable `IFLA_ALT_IFNAME` ownership marker.
    /// Implementations must treat an already-present exact stamp as
    /// idempotent success only after a fresh link dump confirms the link
    /// is the expected fixed-VNI VXLAN with matching protected
    /// attributes.
    CreateManagedVxlan {
        /// Linux VXLAN link name.
        name: String,
        /// Desired protected VXLAN attributes.
        spec: rustbgpd_evpn::ManagedVxlanNetdevSpec,
        /// Durable rustbgpd ownership stamp for this VXLAN.
        ownership_stamp: String,
    },
    /// Delete a rustbgpd-stamped fixed-VNI VXLAN that is no longer
    /// configured. Implementations must first confirm the live link
    /// still carries the exact expected ownership stamp and is a VXLAN.
    RemoveManagedVxlan {
        /// Linux VXLAN link name.
        name: String,
        /// Durable rustbgpd ownership stamp expected on the VXLAN.
        ownership_stamp: String,
    },
    /// Create a configured ADR-0091 managed collect-metadata / SVD VXLAN and
    /// stamp it with its durable `IFLA_ALT_IFNAME` ownership marker.
    /// Implementations must treat an already-present exact stamp as idempotent
    /// success only after a fresh link dump confirms the link is the expected
    /// SVD VXLAN with matching protected attributes and derived VNI mappings.
    CreateManagedSvdVxlan {
        /// Linux VXLAN link name.
        name: String,
        /// Desired protected SVD VXLAN attributes and derived VLAN/VNI bindings.
        spec: rustbgpd_evpn::ManagedSvdVxlanNetdevSpec,
        /// Durable rustbgpd ownership stamp for this SVD VXLAN.
        ownership_stamp: String,
    },
    /// Delete a rustbgpd-stamped collect-metadata / SVD VXLAN that is no longer
    /// configured. Implementations must first confirm the live link still
    /// carries the exact expected ownership stamp and is an SVD VXLAN.
    RemoveManagedSvdVxlan {
        /// Linux VXLAN link name.
        name: String,
        /// Durable rustbgpd ownership stamp expected on the SVD VXLAN.
        ownership_stamp: String,
    },
    /// Create a configured ADR-0091 managed VRF and stamp it with
    /// its durable `IFLA_ALT_IFNAME` ownership marker.
    /// Implementations must treat an already-present exact stamp as
    /// idempotent success only after a fresh link dump confirms the link
    /// is the expected VRF with matching protected attributes.
    CreateManagedVrf {
        /// Linux VRF link name.
        name: String,
        /// Desired protected VRF attributes.
        spec: rustbgpd_evpn::ManagedVrfNetdevSpec,
        /// Durable rustbgpd ownership stamp for this VRF.
        ownership_stamp: String,
    },
    /// Delete a rustbgpd-stamped VRF that is no longer configured.
    /// Implementations must first confirm the live link still carries
    /// the exact expected ownership stamp and is a VRF.
    RemoveManagedVrf {
        /// Linux VRF link name.
        name: String,
        /// Durable rustbgpd ownership stamp expected on the VRF.
        ownership_stamp: String,
    },
    /// Create a configured ADR-0091 managed L3 VXLAN and stamp it with
    /// its durable `IFLA_ALT_IFNAME` ownership marker.
    /// Implementations must treat an already-present exact stamp as
    /// idempotent success only after a fresh link dump confirms the link
    /// is the expected fixed-VNI L3 VXLAN with matching protected
    /// attributes.
    CreateManagedL3Vxlan {
        /// Linux L3 VXLAN link name.
        name: String,
        /// Desired protected L3 VXLAN attributes.
        spec: rustbgpd_evpn::ManagedL3VxlanNetdevSpec,
        /// Durable rustbgpd ownership stamp for this L3 VXLAN.
        ownership_stamp: String,
    },
    /// Delete a rustbgpd-stamped L3 VXLAN that is no longer configured.
    /// Implementations must first confirm the live link still carries
    /// the exact expected ownership stamp and is a VXLAN.
    RemoveManagedL3Vxlan {
        /// Linux L3 VXLAN link name.
        name: String,
        /// Durable rustbgpd ownership stamp expected on the L3 VXLAN.
        ownership_stamp: String,
    },
    /// Create a configured ADR-0091 managed VLAN upper and stamp it
    /// with its durable `IFLA_ALT_IFNAME` ownership marker.
    /// Implementations must treat an already-present exact stamp as
    /// idempotent success only after a fresh link dump confirms the link
    /// is the expected VLAN upper with matching lower bridge and VLAN id.
    CreateManagedVlanUpper {
        /// Linux VLAN upper link name.
        name: String,
        /// Desired protected VLAN upper attributes.
        spec: rustbgpd_evpn::ManagedVlanUpperNetdevSpec,
        /// Durable rustbgpd ownership stamp for this VLAN upper.
        ownership_stamp: String,
    },
    /// Delete a rustbgpd-stamped VLAN upper that is no longer configured.
    /// Implementations must first confirm the live link still carries the
    /// exact expected ownership stamp and is a VLAN upper.
    RemoveManagedVlanUpper {
        /// Linux VLAN upper link name.
        name: String,
        /// Durable rustbgpd ownership stamp expected on the VLAN upper.
        ownership_stamp: String,
    },
    /// Install a remote IP-prefix route into the IP-VRF's
    /// `table_id`. Gate 9 symmetric IRB / slice 6c. The Linux
    /// implementation in `crate::linux::l3` sets `RTPROT_BGP` and
    /// `RTNH_F_ONLINK` on the kernel route.
    AddRemoteIpRoute {
        /// IP-VRF the prefix belongs to (for accounting).
        vrf_id: IpVrfId,
        /// Prefix to install.
        prefix: rustbgpd_evpn::EvpnIpPrefixValue,
        /// Kernel VRF route table id.
        table_id: u32,
        /// L3 VXLAN ifindex the route uses as output device.
        l3vxlan_ifindex: u32,
        /// Remote VTEP next-hop (must match `prefix`'s family;
        /// slice 6c does not implement cross-family `RTA_VIA`).
        next_hop: IpAddr,
        /// Remote PE's router MAC. Not consumed by the kernel
        /// route-add itself (the kernel resolves the inner DMAC via
        /// the L3 neighbor table), but carried on the op so the
        /// reconcile actor's apply loop can correlate this route
        /// with the `(l3vxlan_ifindex, router_mac)` FDB prerequisite
        /// for fail-stop gating: a route install must not proceed
        /// when its prerequisite resolution-add failed in the same
        /// pass, or the kernel would forward to an unresolved path.
        router_mac: MacAddress,
    },
    /// Remove a remote IP-prefix route previously installed by
    /// [`Self::AddRemoteIpRoute`].
    RemoveRemoteIpRoute {
        /// IP-VRF the prefix belongs to.
        vrf_id: IpVrfId,
        /// Prefix to remove.
        prefix: rustbgpd_evpn::EvpnIpPrefixValue,
        /// Kernel VRF route table id (needed because the kernel
        /// matches on table for delete).
        table_id: u32,
        /// L3 VXLAN ifindex (matched as part of the delete key).
        l3vxlan_ifindex: u32,
        /// Remote VTEP next-hop.
        next_hop: IpAddr,
    },
    /// Add (or replace) a permanent ARP/ND entry on the L3 VXLAN
    /// device mapping `next_hop` → `router_mac`. The kernel
    /// consults this when building the inner Ethernet header
    /// during symmetric-IRB encapsulation. Refcounted by the
    /// reconcile actor across all owned prefixes sharing the
    /// `(l3vxlan_ifindex, next_hop)` pair.
    AddL3Neighbor {
        /// IP-VRF the entry serves (for accounting / observability).
        vrf_id: IpVrfId,
        /// L3 VXLAN ifindex (the dev the entry lives on).
        l3vxlan_ifindex: u32,
        /// Remote VTEP IP (the neighbor's address).
        next_hop: IpAddr,
        /// Remote PE's router MAC (the link-layer address).
        router_mac: MacAddress,
    },
    /// Remove an L3 neighbor entry. Only emitted when no remaining
    /// owned route still references the `(l3vxlan_ifindex, next_hop)`
    /// pair.
    RemoveL3Neighbor {
        /// IP-VRF the entry served (for accounting).
        vrf_id: IpVrfId,
        /// L3 VXLAN ifindex.
        l3vxlan_ifindex: u32,
        /// Remote VTEP IP whose neighbor row is being removed.
        next_hop: IpAddr,
    },
    /// Add (or replace) the FDB row on the L3 VXLAN device that
    /// maps `router_mac` → `next_hop`. Sets only `NTF_SELF`
    /// (L3VXLANs aren't bridge ports). Refcounted by the reconcile
    /// actor across all owned prefixes sharing the
    /// `(l3vxlan_ifindex, router_mac)` pair.
    AddL3VxlanFdb {
        /// IP-VRF the entry serves.
        vrf_id: IpVrfId,
        /// L3 VXLAN ifindex.
        l3vxlan_ifindex: u32,
        /// Remote PE's router MAC.
        router_mac: MacAddress,
        /// Remote VTEP IP (the VXLAN tunnel endpoint).
        next_hop: IpAddr,
    },
    /// Remove an L3VXLAN FDB row.
    RemoveL3VxlanFdb {
        /// IP-VRF the entry served.
        vrf_id: IpVrfId,
        /// L3 VXLAN ifindex.
        l3vxlan_ifindex: u32,
        /// Remote PE's router MAC.
        router_mac: MacAddress,
    },
    /// Install an all-active ESI overlay-index Type 5 route into the
    /// IP-VRF's `table_id` as route-level ECMP over the L3 VXLAN
    /// device. The reconcile actor only emits this after the
    /// companion L3 neighbor rows and L3VXLAN FDB-NHG row are in
    /// place, so forwarding has a complete recursive path.
    AddRemoteIpRouteEcmp {
        /// IP-VRF the prefix belongs to.
        vrf_id: IpVrfId,
        /// Prefix to install.
        prefix: rustbgpd_evpn::EvpnIpPrefixValue,
        /// Kernel VRF route table id.
        table_id: u32,
        /// L3 VXLAN ifindex every ECMP next-hop uses as output
        /// device.
        l3vxlan_ifindex: u32,
        /// Canonical sorted+deduped remote VTEP next-hops.
        next_hops: Vec<IpAddr>,
        /// Remote PE Router MAC used by the prerequisite L3VXLAN
        /// FDB-NHG row.
        router_mac: MacAddress,
    },
    /// Remove an all-active ECMP route previously installed by
    /// [`Self::AddRemoteIpRouteEcmp`].
    RemoveRemoteIpRouteEcmp {
        /// IP-VRF the prefix belongs to.
        vrf_id: IpVrfId,
        /// Prefix to remove.
        prefix: rustbgpd_evpn::EvpnIpPrefixValue,
        /// Kernel VRF route table id.
        table_id: u32,
        /// L3 VXLAN ifindex every ECMP next-hop uses as output
        /// device.
        l3vxlan_ifindex: u32,
        /// Canonical sorted+deduped remote VTEP next-hops.
        next_hops: Vec<IpAddr>,
    },
    /// Install or replace the L3VXLAN Router-MAC FDB-NHG path for an
    /// all-active ESI overlay-index Type 5 target set. The reconcile
    /// actor's coordinator decomposes this into per-VTEP L3 FDB
    /// nexthops, an L3 FDB nexthop group, and a direct L3VXLAN FDB
    /// row with `NDA_NH_ID`.
    InstallL3FdbNhg {
        /// IP-VRF the group serves.
        vrf_id: IpVrfId,
        /// Route whose all-active target set references this group.
        prefix: rustbgpd_evpn::EvpnIpPrefixValue,
        /// Dataplane-owned group identity.
        group_key: crate::group_state::L3NhgKey,
        /// Remote PE Router MAC programmed in the L3VXLAN FDB row.
        router_mac: MacAddress,
        /// L3 VXLAN ifindex where the Router-MAC FDB row lives.
        l3vxlan_ifindex: u32,
        /// Canonical sorted+deduped remote VTEP members.
        members: Vec<IpAddr>,
    },
    /// Remove one all-active route's reference to an L3 FDB-NHG
    /// group and garbage-collect the group/member objects if it was
    /// the last route using them.
    RemoveL3FdbNhg {
        /// IP-VRF the group served.
        vrf_id: IpVrfId,
        /// Route whose all-active target set referenced this group.
        prefix: rustbgpd_evpn::EvpnIpPrefixValue,
        /// Dataplane-owned group identity.
        group_key: crate::group_state::L3NhgKey,
        /// Remote PE Router MAC programmed in the L3VXLAN FDB row.
        router_mac: MacAddress,
        /// L3 VXLAN ifindex where the Router-MAC FDB row lives.
        l3vxlan_ifindex: u32,
    },
    /// Install an FDB-NHG row for `(vni, mac)` pointing at the kernel
    /// nexthop group keyed by `group_key`. The reconcile actor's
    /// coordinator decomposes this into the actual netlink sequence:
    /// per-VTEP member adds (for any members not yet installed), the
    /// group add (or `NLM_F_REPLACE` if the group already exists with
    /// a different member set), and the FDB-row install with
    /// `NDA_NH_ID`. ADR-0059 §5 invariants 1+3 dictate the order:
    /// members → group → FDB row.
    InstallFdbNhg {
        /// EVPN instance the FDB row belongs to.
        vni: EvpnInstanceId,
        /// MAC the entry programs.
        mac: MacAddress,
        /// Local Linux bridge VLAN attribution for ADR-0089
        /// VLAN-aware instances. `None` preserves the legacy
        /// non-VLAN-aware FDB-NHG wire shape.
        vlan: Option<u16>,
        /// Dataplane-owned group identity `(VNI, ESI, EthernetTag)`.
        /// ADR-0059 §7's `share_l2_nhg` knob defaults off, so the
        /// key includes VNI in slice 3 — two L2VNIs sharing the same
        /// `(ESI, EthernetTag)` get separate kernel groups.
        group_key: crate::group_state::AliasGroupKey,
        /// Canonical sorted+deduped member VTEP IPs. Produced by
        /// [`rustbgpd_evpn::group_members`] on the slice 1
        /// `RemoteMacEntry`. Exactly one member (the active PE) for
        /// ADR-0083 single-active groups.
        members: Vec<IpAddr>,
        /// ADR-0083 single-active backup PE. The coordinator
        /// pre-creates this per-VTEP fdb nexthop and pins it with the
        /// `GroupOwnedMap` standby ref class — it is **not** a group
        /// member (the kernel hashes over all members; single-active
        /// means exactly one egress forwards). `None` for all-active
        /// aliasing groups.
        standby: Option<IpAddr>,
        /// ADR-0083 row-shape conversion: `true` when the kernel
        /// currently holds a single-dst (`NDA_DST`) row at this
        /// `(vni, mac)` that must be deleted before the `NDA_NH_ID`
        /// install — the kernel rejects the in-place conversion with
        /// `-EOPNOTSUPP` ("Cannot replace an existing non nexthop
        /// fdb with a nexthop", `vxlan_fdb_update_existing`). The
        /// coordinator performs the delete→add **per row** inside
        /// this one op so the forwarding gap stays per-MAC, never
        /// batch-delete-then-batch-add.
        convert_from_dst: bool,
    },
    /// Update an existing FDB nexthop group's member set in place.
    /// The reconcile actor emits this when the same `group_key` has
    /// different members than `last_applied`. Applies as a single
    /// `RTM_NEWNEXTHOP` with `NLM_F_CREATE | NLM_F_REPLACE` on the
    /// same `nh_id`; FDB rows referencing the group keep pointing at
    /// the same ID, no forwarding gap. ADR-0059 §5 invariant 3.
    UpdateFdbNhgMembers {
        /// Dataplane-owned group identity.
        group_key: crate::group_state::AliasGroupKey,
        /// New canonical member set.
        members: Vec<IpAddr>,
        /// ADR-0083 single-active backup PE (see
        /// [`Self::InstallFdbNhg::standby`]). The diff emits this op
        /// when the member set *or* the standby drifted; the
        /// coordinator re-pins / GCs the standby NH accordingly.
        standby: Option<IpAddr>,
    },
    /// Remove an FDB-NHG row for `(vni, mac)`. The reconcile actor's
    /// coordinator consults its `GroupOwnedMap` refcount: if this MAC
    /// is the last referrer to the group, the coordinator follows up
    /// by removing the group and unref'ing per-VTEP members. ADR-0059
    /// §5 invariant 2 dictates the order: FDB row → group → members.
    RemoveFdbNhg {
        /// EVPN instance the FDB row belonged to.
        vni: EvpnInstanceId,
        /// MAC the entry programmed.
        mac: MacAddress,
        /// Local Linux bridge VLAN attribution for the row to remove.
        /// Keeps VLAN-aware deletes scoped to the configured bridge
        /// VLAN instead of matching another VLAN's row.
        vlan: Option<u16>,
        /// Dataplane-owned group identity (needed so the coordinator
        /// knows which group to unref without re-deriving it from
        /// owned state).
        group_key: crate::group_state::AliasGroupKey,
    },
}

/// Kernel-side notifications the actor consumes through
/// [`Dataplane::next_event`]. Phase 2 only emits a small subset; Phase 4
/// extends with the full `RTNLGRP_LINK` / `RTNLGRP_NEIGH` event set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelEvent {
    /// Some FDB or link state changed — wake the reconcile loop. The
    /// next dump will surface what changed; we don't carry deltas
    /// because the reconcile is level-triggered (ADR-0054 §6).
    KernelStateChanged,
    /// Local MAC observation flowing upward to the domain layer.
    /// Phase 2 doesn't act on these; the reconcile actor forwards
    /// them through [`crate::Dataplane::next_event`] verbatim and the
    /// daemon will route them in Phase 5.
    LocalMacObservation(rustbgpd_evpn::LocalMacObservation),
}

/// Trait the reconcile actor drives.
///
/// Implementations own the kernel-state side of the boundary —
/// netlink sockets, internal state, retry queues. The actor never
/// touches netlink directly; everything goes through this trait.
pub trait Dataplane: Send {
    /// Probe each instance against the kernel-observed topology and
    /// produce per-instance `Ready` / `NotReady` / `Unbound` results.
    /// The actor calls this on every reconcile pass so probe outcomes
    /// reflect current kernel state.
    fn probe(
        &mut self,
        instances: &EvpnInstanceTable,
    ) -> impl Future<Output = InstanceProbes> + Send;

    /// Probe each configured IP-VRF against the kernel-observed
    /// topology and produce per-VRF [`IpVrfStatus`] verdicts (Gate 9,
    /// ADR-0058 §3). Intended to be called on every reconcile pass so
    /// readiness reflects current kernel state; the call site itself
    /// lives with the rest of the reconcile-actor wiring (intent
    /// plumbing slice).
    ///
    /// Default returns an empty map — implementations that don't
    /// support Gate 9 (`InMemoryDataplane`, future non-Linux impls)
    /// silently no-op for IP-VRFs. The trait extension stays
    /// non-breaking because of this default.
    fn probe_ip_vrfs(
        &mut self,
        _ip_vrfs: &IpVrfTable,
    ) -> impl Future<Output = HashMap<IpVrfId, IpVrfStatus>> + Send {
        async { HashMap::new() }
    }

    /// Dump every kernel route in each configured IP-VRF's
    /// `table_id`, classify it, and produce per-VRF observations the
    /// daemon's L3 originator (slice 6b) can subscribe to. Counters
    /// for filtered routes ride alongside on
    /// [`IpVrfRouteDump::filter_counts`].
    ///
    /// Returns `None` on transient kernel-dump failure. The
    /// reconciler forwards `None` to the daemon, which preserves the
    /// last successful observation snapshot in its watch channel
    /// rather than synthesizing an empty dump — a swallowed dump
    /// failure would otherwise look identical to "the kernel has no
    /// routes" and the L3 originator would withdraw every
    /// currently-originated Type 5 (ADR-0054 §6 level-triggered
    /// model requires "don't advance state on failure", not "publish
    /// empty"). Implementations log the underlying error before
    /// returning `None`.
    ///
    /// Default returns `Some(IpVrfRouteDump::default())` —
    /// implementations that don't support Gate 9
    /// (`InMemoryDataplane`, future non-Linux impls) silently no-op
    /// for IP-VRF routes (zero VRFs configured → no observations,
    /// no failure either). The trait extension stays non-breaking
    /// via this default.
    fn dump_ip_vrf_routes(
        &mut self,
        _ip_vrfs: &IpVrfTable,
    ) -> impl Future<Output = Option<IpVrfRouteDump>> + Send {
        async { Some(IpVrfRouteDump::default()) }
    }

    /// Dump crash-leftover L3 kernel state that carries our ADR-0079
    /// ownership markers: `proto bgp` + onlink routes in configured
    /// IP-VRF tables, `NUD_PERMANENT` + `extern_learn` neighbors on
    /// managed L3VXLAN devices, and `extern_learn` L3VXLAN FDB rows.
    /// The reconcile actor's one-shot L3 adoption sweep consumes this
    /// to adopt rows whose in-memory ownership record died with a
    /// previous process; re-claim happens implicitly through the
    /// replace-semantics L3 apply path, and the deferred reap re-dumps
    /// through the same method to confirm a row is still ours before
    /// removing it.
    ///
    /// Returns `None` on any sub-dump failure — the caller must retry
    /// on a later pass rather than latch onto a partial kernel view (a
    /// partial view could mis-classify a still-marked row as vanished
    /// and silently drop it from the reap set).
    ///
    /// Default returns `Some(L3AdoptionDump::default())` —
    /// implementations without Gate 9 L3 support observe zero marker
    /// rows, so the sweep adopts nothing and the trait extension stays
    /// non-breaking.
    fn dump_l3_adoption_candidates(
        &mut self,
        _ip_vrfs: &IpVrfTable,
    ) -> impl Future<Output = Option<crate::l3_adoption::L3AdoptionDump>> + Send {
        async { Some(crate::l3_adoption::L3AdoptionDump::default()) }
    }

    /// Dump the current kernel FDB + link inventory.
    fn dump_snapshot(
        &mut self,
    ) -> impl Future<Output = Result<KernelSnapshot, DataplaneError>> + Send;

    /// Apply one [`DataplaneOp`]. Errors are returned per-op so the
    /// actor can record `applied` vs `failed` granularly.
    fn apply(
        &mut self,
        op: &DataplaneOp,
    ) -> impl Future<Output = Result<(), DataplaneError>> + Send;

    /// Wait for the next kernel event, or shutdown signal. Returning
    /// `None` is the implementation's request that the actor should
    /// no longer call this method (e.g., the netlink subscription
    /// closed). The actor falls back to its periodic dump cadence in
    /// that case.
    fn next_event(&mut self) -> impl Future<Output = Option<KernelEvent>> + Send;

    /// Take ownership of the upward `LocalMacObservation` channel
    /// receiver, if the implementation surfaces one.
    ///
    /// Called **once** at construction time by the daemon; subsequent
    /// calls return `None`. The originator (`src/evpn_originator.rs`)
    /// owns the receiver for its lifetime, running its own
    /// `tokio::select!` loop on it independently of the reconcile
    /// actor's `next_event()` loop.
    ///
    /// A dedicated channel is intentionally **not** routed through
    /// [`KernelEvent::LocalMacObservation`] + the reconcile actor —
    /// that path would couple the originator's channel layout to the
    /// reconcile actor and force the actor to outlive the originator.
    /// Splitting the upward observation flow at the trait boundary
    /// keeps the two consumers independent (ADR-0054 §1's "narrow
    /// interface" rule).
    ///
    /// Implementations that do not surface local MAC observations
    /// (e.g., `LinuxDataplane` until `RTNLGRP_NEIGH` subscription
    /// lands in Phase D-real) return `None`. The originator treats
    /// `None` as "no live observation feed available" and stays
    /// quiescent.
    fn take_local_mac_rx(&mut self) -> Option<mpsc::Receiver<LocalMacObservation>> {
        // Default impl returns None — implementations override only
        // when they actually surface observations. This keeps the
        // trait extension non-breaking for downstream impls.
        None
    }
}

/// Sibling trait providing the ADR-0059 FDB nexthop group surface.
///
/// Separate from [`Dataplane`] because:
///
/// 1. The high-level `DataplaneOp::InstallFdbNhg` / `UpdateFdbNhgMembers`
///    / `RemoveFdbNhg` ops require allocator + refcount state owned by
///    the reconcile actor — they don't route through `apply()` because
///    the actor needs to allocate IDs, consult its `GroupOwnedMap`,
///    and decide per-VTEP-NH lifecycle before any netlink call.
/// 2. The reconcile actor's coordinator calls these low-level methods
///    directly, in the ADR-0059 §5 invariant 1+2 order (members →
///    group → FDB row on install; FDB row → group → members on
///    teardown).
/// 3. `LinuxDataplane` implements via the slice-2 `NexthopSocket` plus
///    `linux::fdb_nhg`. `InMemoryDataplane` implements via recording
///    so the actor's coordinator is unit-testable without netlink.
pub trait NexthopOps: Send {
    /// Install one per-VTEP FDB nexthop. `id` is pre-allocated by the
    /// caller (the reconcile actor's `NhIdAllocator`).
    fn add_nexthop_member(
        &mut self,
        id: u32,
        gateway: IpAddr,
    ) -> impl Future<Output = Result<(), DataplaneError>> + Send;

    /// Install an FDB nexthop group naming the per-VTEP `member_ids`.
    /// Uses `NLM_F_CREATE | NLM_F_REPLACE` so the same call serves
    /// both create and replace (atomic alias-set update — ADR-0059 §5
    /// invariant 3).
    fn add_nexthop_group(
        &mut self,
        id: u32,
        member_ids: &[u32],
    ) -> impl Future<Output = Result<(), DataplaneError>> + Send;

    /// Remove a nexthop by ID. Idempotent: ENOENT is treated as ACK
    /// (the slice-2 `NexthopSocket::del` handles this).
    fn del_nexthop(&mut self, id: u32) -> impl Future<Output = Result<(), DataplaneError>> + Send;

    /// Install a bridge FDB row for `(vni, mac)` pointing at the
    /// kernel nexthop group via `NDA_NH_ID`. CVE-2025-39851 guard at
    /// the impl: refuse install if the target L2VXLAN does not have
    /// learning disabled.
    fn install_fdb_nhg_row(
        &mut self,
        vni: EvpnInstanceId,
        mac: MacAddress,
        vlan: Option<u16>,
        nh_id: u32,
    ) -> impl Future<Output = Result<(), DataplaneError>> + Send;

    /// Remove the bridge FDB row for `(vni, mac)`. Idempotent.
    fn remove_fdb_nhg_row(
        &mut self,
        vni: EvpnInstanceId,
        mac: MacAddress,
        vlan: Option<u16>,
    ) -> impl Future<Output = Result<(), DataplaneError>> + Send;

    /// Install an L3VXLAN FDB row for `router_mac` that points at an
    /// L3 FDB nexthop group via `NDA_NH_ID`. Unlike the L2 helper,
    /// this is keyed directly by the L3VXLAN ifindex and carries only
    /// the `self`/extern-learn FDB shape.
    fn install_l3_fdb_nhg_row(
        &mut self,
        l3vxlan_ifindex: u32,
        router_mac: MacAddress,
        nh_id: u32,
    ) -> impl Future<Output = Result<(), DataplaneError>> + Send;

    /// Remove the L3VXLAN FDB-NHG row for `router_mac`.
    fn remove_l3_fdb_nhg_row(
        &mut self,
        l3vxlan_ifindex: u32,
        router_mac: MacAddress,
    ) -> impl Future<Output = Result<(), DataplaneError>> + Send;

    /// Dump rustbgpd-owned L2 FDB-NHG kernel nexthops (filtered by
    /// the `0x3000_0000` / `0x4000_0000` tag bits). Used at startup
    /// for allocator collision avoidance (ADR-0059 review callout
    /// #3 / slice 3 startup adoption).
    fn dump_owned_nexthops(
        &mut self,
    ) -> impl Future<Output = Result<Vec<KernelNexthop>, DataplaneError>> + Send;

    /// Dump rustbgpd-owned L3VXLAN FDB-NHG kernel nexthops (filtered
    /// by the `0x5000_0000` / `0x6000_0000` tag bits). This is the
    /// all-active ESI Type-5 substrate surface; it is intentionally
    /// separate from [`Self::dump_owned_nexthops`] so the existing
    /// L2 startup adoption path cannot adopt or reap L3 IDs.
    fn dump_owned_l3_nexthops(
        &mut self,
    ) -> impl Future<Output = Result<Vec<KernelNexthop>, DataplaneError>> + Send {
        async { Ok(Vec::new()) }
    }
}

/// One nexthop entry surfaced by [`NexthopOps::dump_owned_nexthops`]
/// or [`NexthopOps::dump_owned_l3_nexthops`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelNexthop {
    /// Tagged kernel nexthop ID (one of rustbgpd's L2 or L3 NHID
    /// ownership ranges).
    pub id: u32,
    /// Kind: per-VTEP (single gateway) or group (list of member IDs).
    pub kind: KernelNexthopKind,
}

/// Discriminator for [`KernelNexthop`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelNexthopKind {
    /// Per-VTEP FDB nexthop with a gateway IP.
    Member { gateway: IpAddr },
    /// FDB nexthop group naming a set of per-VTEP member IDs.
    Group { member_ids: Vec<u32> },
}
