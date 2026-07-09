//! ADR-0079 L3 adoption-sweep types.
//!
//! The EVPN symmetric-IRB install pipeline (Gate 9 slice 6c) tracks
//! ownership of three kernel objects — per-prefix VRF routes, shared
//! L3 neighbors, shared L3VXLAN FDB rows — purely in memory
//! ([`crate::l3_diff::L3OwnedState`]). After an unclean restart that
//! record is gone, but every row we wrote carries a kernel-preserved
//! ownership marker (the ADR-0079 marker table):
//!
//! - **VRF routes**: `RTPROT_BGP` + `RTNH_F_ONLINK` in a configured
//!   `[[evpn_ip_vrfs]]` `table_id` (write side:
//!   `linux::l3::build_ip_route_message`).
//! - **L3 neighbors**: `NUD_PERMANENT` + `NTF_EXT_LEARNED` on a
//!   managed L3VXLAN device (write side:
//!   `linux::l3::apply_add_l3_neighbor`).
//! - **L3VXLAN FDB rows**: `NUD_NOARP | NUD_PERMANENT` state with
//!   `NTF_SELF | NTF_EXT_LEARNED` flags on a managed L3VXLAN device
//!   (write side: `linux::l3::apply_add_l3vxlan_fdb`).
//!
//! [`crate::Dataplane::dump_l3_adoption_candidates`] walks the kernel
//! for marker-matching rows; the reconcile actor adopts them so they
//! keep forwarding, lets a still-desired prefix re-claim them
//! implicitly (every L3 add applies with netlink replace semantics, so
//! the re-install *is* the claim), and reaps whatever stays unclaimed
//! after the deferral.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rustbgpd_evpn::{EvpnIpPrefixValue, IpVrfId, MacAddress};

/// One adopted crash-leftover VRF route — everything the eventual
/// `RemoveRemoteIpRoute` op needs, captured at dump time because the
/// kernel row (not the intent, which may no longer carry the prefix)
/// is the only authority on its identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdoptedL3Route {
    /// Kernel route table the row lives in (the configured IP-VRF
    /// `table_id` that matched at dump time).
    pub table_id: u32,
    /// Output device — the IP-VRF's L3VXLAN ifindex.
    pub l3vxlan_ifindex: u32,
    /// Representative gateway — the remote VTEP next-hop. For ECMP
    /// rows this is the first deterministic member.
    pub next_hop: IpAddr,
    /// Full gateway set. Scalar rows carry exactly one element;
    /// ECMP rows carry every onlink next-hop.
    pub next_hops: Vec<IpAddr>,
}

/// One adopted crash-leftover L3VXLAN FDB row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdoptedL3VxlanFdb {
    /// Owning IP-VRF, inferred from the managed L3VXLAN ifindex.
    pub vrf_id: IpVrfId,
    /// Kernel target shape for the row.
    pub target: AdoptedL3VxlanFdbTarget,
}

/// Kernel target shape for an adopted L3VXLAN FDB row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdoptedL3VxlanFdbTarget {
    /// Legacy scalar row (`NDA_DST`) pointing at one remote VTEP.
    SingleDst,
    /// All-active row (`NDA_NH_ID`) pointing at an L3 FDB nexthop
    /// group.
    NexthopGroup {
        /// Kernel nexthop group ID carried in `NDA_NH_ID`.
        nh_id: u32,
    },
}

/// Marker-matching kernel L3 state surfaced by one
/// [`crate::Dataplane::dump_l3_adoption_candidates`] call.
///
/// Keys mirror the [`crate::l3_diff::L3OwnedState`] shape so the
/// reconcile actor can subtract already-owned rows with plain map
/// lookups. Values carry whichever identity the matching remove op
/// needs (for neighbors / FDB rows that is just the owning `vrf_id`
/// accounting tag — the kernel delete keys on the map key itself).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct L3AdoptionDump {
    /// `(vrf_id, prefix)` → everything `RemoveRemoteIpRoute` needs.
    pub routes: BTreeMap<(IpVrfId, EvpnIpPrefixValue), AdoptedL3Route>,
    /// `(l3vxlan_ifindex, next_hop)` → owning `vrf_id`.
    pub neighbors: BTreeMap<(u32, IpAddr), IpVrfId>,
    /// `(l3vxlan_ifindex, router_mac)` → adopted FDB row identity.
    pub l3vxlan_fdb: BTreeMap<(u32, MacAddress), AdoptedL3VxlanFdb>,
    /// LAN-283 foreign-state visibility: `(vrf_id, prefix)` keys in a
    /// configured IP-VRF table whose route row does NOT carry our
    /// marker pair — another writer's state. The reconcile actor
    /// blocks replaces over these keys and never deletes them.
    pub foreign_routes: BTreeSet<(IpVrfId, EvpnIpPrefixValue)>,
    /// Foreign `(l3vxlan_ifindex, next_hop)` neighbor keys on managed
    /// L3VXLAN devices: rows programmed by another agent (permanent /
    /// noarp state without our markers, or a non-BGP `NDA_PROTOCOL`
    /// stamp). Transient kernel-dynamic ARP/ND cache entries are NOT
    /// classified foreign — our control-plane replace of a volatile
    /// cache entry is normal operation.
    pub foreign_neighbors: BTreeSet<(u32, IpAddr)>,
    /// Foreign `(l3vxlan_ifindex, router_mac)` FDB keys on managed
    /// L3VXLAN devices — any row that is not marker-matching (managed
    /// L3VXLANs run `nolearning`, so every row was programmed by
    /// someone).
    pub foreign_fdb: BTreeSet<(u32, MacAddress)>,
}

impl L3AdoptionDump {
    /// True when no marker rows were observed in any of the three
    /// kernel surfaces (foreign rows do not count — they are never
    /// adoption candidates).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty() && self.neighbors.is_empty() && self.l3vxlan_fdb.is_empty()
    }
}
