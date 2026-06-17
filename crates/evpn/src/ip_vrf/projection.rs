//! Pure-logic Type 5 projection — inbound RT-5 NLRI + path attrs →
//! [`RemoteIpPrefixTable`] keyed by `(IpVrfId, prefix)`.
//!
//! Sibling of `crates/evpn/src/projection.rs` (Type 2 → `RemoteMacTable`)
//! but for the IRB case (Type 5). ADR-0058 §2 pins the contract: a
//! received Type 5 maps to a remote prefix in the IP-VRF whose
//! configured `route_targets` intersect the route's RT extcomms; the
//! daemon's downstream reconciler turns each `RemoteIpPrefixEntry`
//! into a kernel FIB install (`RTM_NEWROUTE` in the VRF's
//! `table_id`, recursive next-hop via the L3VXLAN device + Router
//! MAC FDB entry).
//!
//! Pure: no I/O, no tokio, no kernel state. The daemon's projection
//! pass calls this once per RIB recompute pass and hands the table
//! to the dataplane.
//!
//! ## RT match semantics
//!
//! A Type 5 route is imported into IP-VRF `V` when any RT in the
//! route's `ExtendedCommunities` matches any RT in
//! `V.route_targets`. A route with no RT extcomms (or whose RTs
//! intersect *no* configured IP-VRF) is recorded in
//! [`RemoteIpPrefixTable::drops`] with [`DropReason::NoMatchingIpVrf`]
//! — observable, not silent. Those routes are either malformed or
//! intended for L2 EVIs and have no place in an IP-VRF FIB.
//!
//! A route whose RTs intersect *multiple* IP-VRFs is considered for
//! import into every match — but each candidate VRF still has to
//! pass the L3VNI check (§Wire L3VNI vs configured L3VNI below). In
//! practice the wire route carries a single L3VNI, so a route that
//! matches multiple IP-VRFs by RT can only land in the one whose
//! configured L3VNI agrees; the others are recorded with
//! [`DropReason::L3VniMismatch`]. RFC 9136 §4.4.2 allows the same
//! prefix in two tenant FIBs when both tenants legitimately claim
//! the same RT (and same VNI); shared RTs across distinct-VNI
//! tenants is operator misconfig and the projection surfaces it
//! rather than silently programming the wrong encap.
//!
//! ## Wire L3VNI vs configured L3VNI
//!
//! Each candidate IP-VRF must additionally satisfy
//! `route.l3vni == vrf.id.as_u32()`. A mismatch means the
//! originator's VNI for that RT disagrees with our local config —
//! installing the route anyway would program a kernel FIB entry
//! whose VXLAN encap uses the wrong VNI. Drop with
//! [`DropReason::L3VniMismatch`] so the misconfig is observable.
//! When the check passes, the [`RemoteIpPrefixEntry::l3vni`] is
//! sourced from the *VRF's* configured VNI (not echoed from the
//! wire) so any future drift in the wire decoder can't propagate
//! into kernel programming.
//!
//! ## Router MAC
//!
//! Interface-less Type 5 routes (Gateway Address zero, ESI zero) must
//! carry a Router MAC extcomm — the inner destination MAC for symmetric
//! IRB recursive lookup. GW-IP overlay-index Type 5 routes (non-zero
//! Gateway Address, ESI zero) resolve that inner MAC recursively from a
//! matching Type 2 MAC/IP route in an L2VNI linked to the target
//! IP-VRF. ESI overlay-index Type 5 routes (non-zero ESI) resolve
//! through scoped EAD-per-EVI protected-recursion input only when that
//! input identifies exactly one single-active remote VTEP; all-active,
//! ambiguous, and unresolved shapes stay fail-closed.
//!
//! ## Self-origination filter
//!
//! Routes whose `next_hop` matches any local IP-VRF's `local_vtep_ip`
//! are dropped — they came from us, the RIB just reflected them via
//! a route reflector. Filtering here keeps the daemon from
//! programming kernel routes pointing at its own VTEP.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rustbgpd_wire::{
    EthernetSegmentIdentifier, EthernetTagId, EvpnIpPrefixValue, ExtendedCommunity, MacAddress,
    RouteDistinguisher,
};

use crate::instance::EvpnInstanceId;
use crate::ip_vrf::IpVrfId;
use crate::route_target::RouteTarget;

/// VRF metric label for Type 5 projection drops that happen before
/// the route can be scoped to a configured IP-VRF.
pub const UNSCOPED_DROP_VRF_LABEL: &str = "_unscoped";

/// Trimmed best-path EVPN Type 5 record for projection input.
///
/// The daemon translates `EvpnRibRoute` (`crates/rib`) into this
/// portable struct at the call site. Carrying the wire-shaped types
/// lets the projection log meaningful messages without a custom DTO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectedIpPrefixRoute {
    /// Route Distinguisher of the originating IP-VRF.
    pub rd: RouteDistinguisher,
    /// Advertised prefix (IPv4 or IPv6).
    pub prefix: EvpnIpPrefixValue,
    /// Resolved next hop from `MP_REACH_NLRI` — the remote VTEP IP
    /// the dataplane will program as the FIB nexthop.
    pub next_hop: IpAddr,
    /// Type 5 Gateway Address. Zero selects the Interface-less model;
    /// non-zero values use RFC 9135 §9.2 overlay-index recursion
    /// through Type 2 MAC/IP state.
    pub gateway: IpAddr,
    /// Type 5 Ethernet Segment Identifier. Non-zero values are RFC
    /// 9136 §4.3 ESI overlay-index routes; projection resolves the
    /// bounded single-active receive shape only when callers provide
    /// scoped EAD-per-EVI protected-recursion input.
    pub esi: EthernetSegmentIdentifier,
    /// Type 5 Ethernet Tag. The VLAN-based service-interface model
    /// usually carries zero, but RFC 9136 §4.3 ESI overlay-index
    /// recursion is scoped by the Type 5's Ethernet Tag and matching
    /// EAD-per-EVI state, so the receive-side DTO must preserve it
    /// for single-active ESI overlay-index protected recursion.
    pub ethernet_tag: EthernetTagId,
    /// L3VNI from the route's MPLS label slot (RFC 8365: VXLAN VNI
    /// carried in the MPLS label field).
    pub l3vni: u32,
    /// Route Targets from the route's `ExtendedCommunities` — used
    /// to match the route to a configured IP-VRF.
    pub route_targets: Vec<RouteTarget>,
    /// Router MAC from the RFC 9135 §4.2 Router MAC extcomm — the
    /// inner destination MAC for the recursive lookup. `None` when
    /// the route doesn't carry one; the projection drops the route
    /// in that case.
    pub router_mac: Option<MacAddress>,
}

/// Trimmed best-path EVPN Type 2 MAC/IP route usable for resolving
/// an RFC 9135 §9.2 Type 5 overlay-index Gateway Address.
///
/// The daemon builds this from the same RIB snapshot as Type 5 input
/// and only passes rows that survived the normal Type 2 projection
/// gates: remote, non-quarantined, mass-withdraw-reachable MAC/IP
/// routes with a host IP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectedOverlayIndexRoute {
    /// L2VNI carried by the Type 2 route's primary label.
    pub vni: EvpnInstanceId,
    /// Host IP carried by the Type 2 MAC/IP NLRI.
    pub host_ip: IpAddr,
    /// MAC carried by the Type 2 MAC/IP NLRI.
    pub mac: MacAddress,
    /// Remote VTEP next hop for the Type 2 route.
    pub next_hop: IpAddr,
    /// MAC mobility sequence (RFC 7432 §15) of the originating Type 2
    /// route, when it carried a `MAC Mobility` extended community. Used
    /// to resolve overlay-index contenders the same way the Type 2
    /// projection does — the highest sequence reflects the most recent
    /// host location.
    pub mobility_sequence: Option<u32>,
}

/// Redundancy mode resolved for one ESI overlay-index Type 5 EAD candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EsiOverlayRedundancyMode {
    /// Every signal for the candidate says single-active.
    SingleActive,
    /// Every signal for the candidate says all-active.
    AllActive,
    /// Duplicate or cross-scope signals disagree; fail closed.
    Conflicting,
}

impl EsiOverlayRedundancyMode {
    const fn from_single_active(single_active: bool) -> Self {
        if single_active {
            Self::SingleActive
        } else {
            Self::AllActive
        }
    }

    const fn fold(self, other: Self) -> Self {
        match (self, other) {
            (Self::Conflicting, _) | (_, Self::Conflicting) => Self::Conflicting,
            (Self::SingleActive, Self::SingleActive) => Self::SingleActive,
            (Self::AllActive, Self::AllActive) => Self::AllActive,
            (Self::SingleActive, Self::AllActive) | (Self::AllActive, Self::SingleActive) => {
                Self::Conflicting
            }
        }
    }
}

/// Trimmed EAD-per-EVI row usable as the future RFC 9136 §4.3
/// receive-side resolver input for ESI overlay-index Type 5 routes.
///
/// This is intentionally scoped to the *local* L2VNI / MAC-VRF. The
/// existing Type 2 alias index is keyed only by `(ESI, Ethernet Tag)`,
/// which is sufficient for L2 aliasing but too broad for Type 5
/// protected recursion: the Type 5 importer must resolve through an
/// EAD-per-EVI row in an L2VNI linked to the matched IP-VRF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectedEsiOverlayEadPerEvi {
    /// Local L2VNI / MAC-VRF that scoped the received EAD-per-EVI row.
    pub l2vni: EvpnInstanceId,
    /// Ethernet Segment Identifier from the EAD-per-EVI route.
    pub esi: EthernetSegmentIdentifier,
    /// Ethernet Tag from the EAD-per-EVI route.
    pub ethernet_tag: EthernetTagId,
    /// Remote VTEP next hop for the EAD-per-EVI route.
    pub next_hop: IpAddr,
    /// Whether the EAD route belongs to a single-active Ethernet
    /// Segment. The resolver folds this wire-facing boolean into
    /// [`EsiOverlayRedundancyMode`] so all-active and conflicting
    /// duplicate signals stay distinguishable.
    pub single_active: bool,
}

/// Candidate remote VTEP for one scoped ESI overlay-index lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EsiOverlayEadCandidate {
    /// Remote VTEP next hop from the matching EAD-per-EVI route.
    pub next_hop: IpAddr,
    /// Redundancy mode resolved from the candidate's EAD state.
    pub mode: EsiOverlayRedundancyMode,
}

/// Deterministic remote-VTEP target set for all-active ESI Type 5 receive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EsiOverlayAllActiveTargetSet {
    next_hops: Vec<IpAddr>,
}

impl EsiOverlayAllActiveTargetSet {
    /// Build a deterministic non-empty target set.
    ///
    /// Returns `None` when the input is empty after collection.
    #[must_use]
    pub fn from_next_hops<I>(next_hops: I) -> Option<Self>
    where
        I: IntoIterator<Item = IpAddr>,
    {
        let mut next_hops: Vec<IpAddr> = next_hops.into_iter().collect();
        next_hops.sort();
        next_hops.dedup();
        if next_hops.is_empty() {
            None
        } else {
            Some(Self { next_hops })
        }
    }

    /// Remote VTEPs in deterministic order.
    #[must_use]
    pub fn next_hops(&self) -> &[IpAddr] {
        &self.next_hops
    }

    /// Number of remote VTEPs in the target set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.next_hops.len()
    }

    /// Always false for resolver-built target sets; provided with
    /// [`Self::len`] for collection-like API symmetry.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.next_hops.is_empty()
    }
}

/// Resolved dataplane next-hop shape for one remote IP prefix.
///
/// The long-shipped Type 5 path is single-target. ADR-0090's
/// all-active ESI overlay-index receive path needs a deterministic
/// target set for the same `(IP-VRF, prefix)` route. Keeping the shape
/// explicit here lets the L3 diff model reason about all-active routes
/// without overloading the legacy scalar `next_hop` convenience field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteIpPrefixTargets {
    /// Single remote VTEP target.
    Single { next_hop: IpAddr },
    /// All-active ESI overlay-index target set. Non-empty and
    /// deterministic by construction.
    AllActive(EsiOverlayAllActiveTargetSet),
}

impl RemoteIpPrefixTargets {
    /// Build the single-target shape.
    #[must_use]
    pub const fn single(next_hop: IpAddr) -> Self {
        Self::Single { next_hop }
    }

    /// Build an all-active target set.
    ///
    /// Returns `None` when the supplied target set is empty.
    #[must_use]
    pub fn all_active<I>(next_hops: I) -> Option<Self>
    where
        I: IntoIterator<Item = IpAddr>,
    {
        EsiOverlayAllActiveTargetSet::from_next_hops(next_hops).map(Self::AllActive)
    }

    /// Representative next-hop for legacy display/status surfaces.
    ///
    /// For all-active target sets this is the first deterministic
    /// member, not a forwarding tie-break.
    #[must_use]
    pub fn representative_next_hop(&self) -> IpAddr {
        match self {
            Self::Single { next_hop } => *next_hop,
            Self::AllActive(targets) => targets.next_hops()[0],
        }
    }

    /// Deterministic next-hop members.
    #[must_use]
    pub fn next_hops(&self) -> &[IpAddr] {
        match self {
            Self::Single { next_hop } => std::slice::from_ref(next_hop),
            Self::AllActive(targets) => targets.next_hops(),
        }
    }

    /// True for the all-active target-set shape.
    #[must_use]
    pub const fn is_all_active(&self) -> bool {
        matches!(self, Self::AllActive(_))
    }
}

/// Model result for ESI overlay-index Type 5 protected recursion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EsiOverlayResolvedTargets {
    /// Existing single-active receive path: one remote VTEP.
    SingleActive { next_hop: IpAddr },
    /// Future all-active receive path: one or more remote VTEPs.
    AllActive(EsiOverlayAllActiveTargetSet),
}

/// Scoped resolver index for ESI overlay-index Type 5 receive.
///
/// It preserves the load-bearing lookup key `(local L2VNI, ESI,
/// Ethernet Tag)` and a deterministic set of candidate VTEP next hops.
/// The production table still imports only an exactly-one single-active
/// candidate, but ADR-0090's projection model can now distinguish
/// all-active target sets from conflicting redundancy signals before the
/// L3 dataplane writer is upgraded.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EsiOverlayEadIndex {
    by_key: BTreeMap<
        (EvpnInstanceId, EthernetSegmentIdentifier, EthernetTagId),
        Vec<EsiOverlayEadCandidate>,
    >,
}

impl EsiOverlayEadIndex {
    /// Build an empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a scoped EAD-per-EVI resolver index.
    ///
    /// Zero ESI rows are ignored because they cannot satisfy an ESI
    /// overlay-index Type 5 lookup. Duplicate next hops for the same
    /// key are de-duplicated and returned in deterministic order.
    #[must_use]
    pub fn build<I>(routes: I) -> Self
    where
        I: IntoIterator<Item = ProjectedEsiOverlayEadPerEvi>,
    {
        let mut tmp: BTreeMap<
            (EvpnInstanceId, EthernetSegmentIdentifier, EthernetTagId),
            BTreeMap<IpAddr, EsiOverlayRedundancyMode>,
        > = BTreeMap::new();
        for route in routes {
            if route.esi == EthernetSegmentIdentifier::ZERO {
                continue;
            }
            let mode = EsiOverlayRedundancyMode::from_single_active(route.single_active);
            tmp.entry((route.l2vni, route.esi, route.ethernet_tag))
                .or_default()
                .entry(route.next_hop)
                .and_modify(|existing| *existing = existing.fold(mode))
                .or_insert(mode);
        }
        Self {
            by_key: tmp
                .into_iter()
                .map(|(key, next_hops)| {
                    (
                        key,
                        next_hops
                            .into_iter()
                            .map(|(next_hop, mode)| EsiOverlayEadCandidate { next_hop, mode })
                            .collect(),
                    )
                })
                .collect(),
        }
    }

    /// Candidate VTEPs for a scoped `(L2VNI, ESI, Ethernet Tag)` lookup.
    #[must_use]
    pub fn candidates_for(
        &self,
        l2vni: EvpnInstanceId,
        esi: EthernetSegmentIdentifier,
        ethernet_tag: EthernetTagId,
    ) -> Option<&[EsiOverlayEadCandidate]> {
        self.by_key
            .get(&(l2vni, esi, ethernet_tag))
            .map(Vec::as_slice)
    }

    /// Number of scoped resolver keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    /// True when no non-zero-ESI EAD-per-EVI rows were indexed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }
}

impl ProjectedIpPrefixRoute {
    /// Convenience helper for callers that already have an
    /// `ExtendedCommunities` attribute on the route — pulls the RT
    /// list and Router MAC out in one pass.
    #[must_use]
    pub fn extcomms_to_fields(
        ext_comms: &[ExtendedCommunity],
    ) -> (Vec<RouteTarget>, Option<MacAddress>) {
        let mut rts: Vec<RouteTarget> = Vec::new();
        let mut router_mac: Option<MacAddress> = None;
        for c in ext_comms {
            if let Some(rt) = RouteTarget::from_extended_community(*c) {
                rts.push(rt);
            } else if let Some(bytes) = c.as_router_mac() {
                router_mac = Some(MacAddress::new(bytes));
            }
        }
        (rts, router_mac)
    }
}

/// One imported remote-prefix entry — the daemon-facing shape that
/// the dataplane reconciler turns into `RTM_NEWROUTE` + bridge FDB
/// for the inner-MAC resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteIpPrefixEntry {
    /// Prefix to install in the IP-VRF's route table.
    pub prefix: EvpnIpPrefixValue,
    /// The FIB nexthop — what the recursive lookup terminates on
    /// after VXLAN encap. For interface-less Type 5 this is the Type 5
    /// originator VTEP; for overlay-index Type 5 it is the resolved
    /// Type 2 MAC/IP route's VTEP. For all-active target sets this is
    /// the deterministic representative member retained for legacy
    /// display/status callers; dataplane code must inspect
    /// [`Self::targets`] before treating it as a single egress.
    pub next_hop: IpAddr,
    /// Resolved dataplane target shape.
    pub targets: RemoteIpPrefixTargets,
    /// L3VNI to wrap encapsulated frames with.
    pub l3vni: u32,
    /// Inner destination MAC the kernel needs for the recursive
    /// lookup. For interface-less Type 5 this is the RFC 9135 Router
    /// MAC extcomm; for overlay-index Type 5 it is the MAC of the
    /// resolved Type 2 MAC/IP route.
    pub router_mac: MacAddress,
}

impl RemoteIpPrefixEntry {
    /// Build a legacy single-target entry.
    #[must_use]
    pub const fn single(
        prefix: EvpnIpPrefixValue,
        next_hop: IpAddr,
        l3vni: u32,
        router_mac: MacAddress,
    ) -> Self {
        Self {
            prefix,
            next_hop,
            targets: RemoteIpPrefixTargets::single(next_hop),
            l3vni,
            router_mac,
        }
    }

    /// Build an all-active target-set entry.
    ///
    /// Returns `None` when the supplied target set is empty.
    #[must_use]
    pub fn all_active<I>(
        prefix: EvpnIpPrefixValue,
        next_hops: I,
        l3vni: u32,
        router_mac: MacAddress,
    ) -> Option<Self>
    where
        I: IntoIterator<Item = IpAddr>,
    {
        let targets = RemoteIpPrefixTargets::all_active(next_hops)?;
        let next_hop = targets.representative_next_hop();
        Some(Self {
            prefix,
            next_hop,
            targets,
            l3vni,
            router_mac,
        })
    }
}

/// Per-IP-VRF imported prefix table. Keyed by `(IpVrfId, prefix)` so
/// the same prefix can legitimately appear in multiple IP-VRFs (RFC
/// 9136 §4.4.2 allows the same RT under different tenants).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RemoteIpPrefixTable {
    entries: BTreeMap<(IpVrfId, EvpnIpPrefixValue), RemoteIpPrefixEntry>,
    drops: Vec<DropReason>,
}

impl RemoteIpPrefixTable {
    /// New empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Iterate entries in deterministic order.
    pub fn iter(
        &self,
    ) -> impl Iterator<Item = (&(IpVrfId, EvpnIpPrefixValue), &RemoteIpPrefixEntry)> {
        self.entries.iter()
    }

    /// Insert an already-resolved entry for one IP-VRF.
    ///
    /// Projection helpers are the normal production entry point. This
    /// method exists for future staged projection paths and for
    /// dataplane-model tests that need to exercise target-set shapes
    /// before the production projector imports them.
    pub fn insert_resolved(
        &mut self,
        vrf_id: IpVrfId,
        entry: RemoteIpPrefixEntry,
    ) -> Option<RemoteIpPrefixEntry> {
        self.entries.insert((vrf_id, entry.prefix), entry)
    }

    /// Entries scoped to one IP-VRF.
    pub fn for_vrf(
        &self,
        vrf: IpVrfId,
    ) -> impl Iterator<Item = (&EvpnIpPrefixValue, &RemoteIpPrefixEntry)> {
        self.entries
            .iter()
            .filter(move |((id, _), _)| *id == vrf)
            .map(|((_, p), e)| (p, e))
    }

    /// Number of imported prefixes across all IP-VRFs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no prefix was imported.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Routes that *were* in the input stream but got dropped, with
    /// the reason. Useful for diagnostic / CLI surfaces.
    #[must_use]
    pub fn drops(&self) -> &[DropReason] {
        &self.drops
    }

    /// Count dropped Type 5 routes by bounded `(vrf, reason)` labels
    /// for Prometheus / status surfaces. Prefix, gateway, next-hop,
    /// RD, RT, and MAC values deliberately stay out of the key.
    #[must_use]
    pub fn drop_counts_by_vrf_reason(&self) -> BTreeMap<(String, &'static str), u64> {
        let mut counts = BTreeMap::new();
        for drop in &self.drops {
            *counts
                .entry((drop.vrf_label().to_string(), drop.reason_label()))
                .or_insert(0) += 1;
        }
        counts
    }
}

/// Why a single route was excluded from the projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropReason {
    /// The route's RT extcomms didn't intersect any IP-VRF in the
    /// table — silently importing it would land it in an arbitrary
    /// tenant or none.
    NoMatchingIpVrf {
        prefix: EvpnIpPrefixValue,
        next_hop: IpAddr,
    },
    /// The route carried no Router MAC extcomm.
    MissingRouterMac {
        prefix: EvpnIpPrefixValue,
        next_hop: IpAddr,
    },
    /// The route uses RFC 9135 overlay-index semantics, but the
    /// matched IP-VRF has no local L2VNI linked through
    /// `[[evpn_instances]].ip_vrf`. Without that binding the daemon
    /// cannot safely scope the recursive Type 2 lookup to a tenant.
    OverlayIndexNoLinkedL2Vni {
        prefix: EvpnIpPrefixValue,
        gateway: IpAddr,
        next_hop: IpAddr,
        vrf: String,
    },
    /// The route uses RFC 9135 overlay-index semantics, but no
    /// eligible Type 2 MAC/IP route resolved the Gateway Address in
    /// the matched IP-VRF's linked L2VNIs.
    UnresolvedOverlayIndexGateway {
        prefix: EvpnIpPrefixValue,
        gateway: IpAddr,
        next_hop: IpAddr,
        vrf: String,
    },
    /// The route uses RFC 9135 overlay-index semantics, but the Gateway
    /// Address resolved to more than one distinct MAC at the highest MAC
    /// mobility sequence. A single MAC reachable through several VTEPs
    /// (multi-homing) resolves; conflicting MACs would leak traffic
    /// across an ambiguous recursive lookup, so they stay fail-closed.
    /// `candidates` counts the distinct MACs.
    AmbiguousOverlayIndexGateway {
        prefix: EvpnIpPrefixValue,
        gateway: IpAddr,
        next_hop: IpAddr,
        vrf: String,
        candidates: usize,
    },
    /// The route tried to use both RFC 9135 GW-IP overlay index and
    /// RFC 9136 §4.3 ESI overlay index. Those are distinct recursive
    /// resolution modes; accepting both would make the FIB nexthop and
    /// inner MAC source ambiguous.
    DualOverlayIndexes {
        prefix: EvpnIpPrefixValue,
        gateway: IpAddr,
        next_hop: IpAddr,
        vrf: String,
    },
    /// The route uses ESI overlay-index semantics, but the matched
    /// IP-VRF has no linked local L2VNI to scope the protected
    /// EAD-per-EVI lookup.
    EsiOverlayNoLinkedL2Vni {
        prefix: EvpnIpPrefixValue,
        next_hop: IpAddr,
        vrf: String,
    },
    /// The route uses ESI overlay-index semantics, but it carried no
    /// Router MAC extended community. RFC 9136 §4.3 uses the Router
    /// MAC as the inner destination MAC after protected recursion.
    MissingEsiOverlayRouterMac {
        prefix: EvpnIpPrefixValue,
        next_hop: IpAddr,
        vrf: String,
    },
    /// The route uses ESI overlay-index semantics, but no resolvable
    /// EAD candidate in a linked L2VNI satisfied the `(ESI, Ethernet
    /// Tag)` protected-recursion key. This covers both "no matching
    /// EAD-per-EVI row" and the daemon-side case where an EAD-per-EVI
    /// row existed but its companion EAD-per-ES mode was missing or
    /// unknown (so the candidate was filtered out before resolution).
    UnresolvedEsiOverlayIndex {
        prefix: EvpnIpPrefixValue,
        next_hop: IpAddr,
        vrf: String,
    },
    /// The route resolved at least one all-active EAD candidate, or a
    /// mixed/conflicting redundancy set. Production import deliberately
    /// keeps these fail-closed until L3 multipath/NHG programming exists.
    UnsupportedAllActiveEsiOverlayIndex {
        prefix: EvpnIpPrefixValue,
        next_hop: IpAddr,
        vrf: String,
        candidates: usize,
    },
    /// The route resolved more than one single-active EAD candidate.
    /// There is no safe deterministic tie-break for a single-nexthop
    /// L3 FIB entry, so the prefix remains unimported.
    AmbiguousEsiOverlayIndex {
        prefix: EvpnIpPrefixValue,
        next_hop: IpAddr,
        vrf: String,
        candidates: usize,
    },
    /// The route uses RFC 9136 §4.3 ESI overlay-index semantics, but
    /// the caller used a projection entry point without EAD
    /// protected-recursion input. Importing it as Interface-less would
    /// program the wrong recursive path.
    UnsupportedEsiOverlayIndex {
        prefix: EvpnIpPrefixValue,
        next_hop: IpAddr,
        vrf: String,
    },
    /// The route's `NEXT_HOP` matched one of our own IP-VRFs' VTEP IPs
    /// — reflected from a route reflector. The daemon would otherwise
    /// program a kernel route pointing at itself.
    SelfOriginated {
        prefix: EvpnIpPrefixValue,
        next_hop: IpAddr,
        vrf: String,
    },
    /// The route's RTs matched an IP-VRF, but the route's wire
    /// `l3vni` (label slot) disagreed with that IP-VRF's configured
    /// L3VNI. This means the originator and the local config
    /// disagree on the L3VNI for the same RT — either misconfig on
    /// the originator, or the operator's RT list overlaps two
    /// distinct tenants on this PE. Importing the route would
    /// produce a kernel FIB entry whose VXLAN encap uses the wrong
    /// VNI; drop instead so the misconfig is observable.
    L3VniMismatch {
        prefix: EvpnIpPrefixValue,
        next_hop: IpAddr,
        vrf: String,
        observed_vni: u32,
        configured_vni: u32,
    },
}

impl DropReason {
    /// Stable, bounded label for Prometheus and operator summaries.
    #[must_use]
    pub const fn reason_label(&self) -> &'static str {
        match self {
            Self::NoMatchingIpVrf { .. } => "no_matching_ip_vrf",
            Self::MissingRouterMac { .. } => "missing_router_mac",
            Self::OverlayIndexNoLinkedL2Vni { .. } => "overlay_index_no_linked_l2vni",
            Self::UnresolvedOverlayIndexGateway { .. } => "unresolved_overlay_index_gateway",
            Self::AmbiguousOverlayIndexGateway { .. } => "ambiguous_overlay_index_gateway",
            Self::DualOverlayIndexes { .. } => "dual_overlay_indexes",
            Self::EsiOverlayNoLinkedL2Vni { .. } => "esi_overlay_no_linked_l2vni",
            Self::MissingEsiOverlayRouterMac { .. } => "missing_esi_overlay_router_mac",
            Self::UnresolvedEsiOverlayIndex { .. } => "unresolved_esi_overlay_index",
            Self::UnsupportedAllActiveEsiOverlayIndex { .. } => {
                "unsupported_all_active_esi_overlay_index"
            }
            Self::AmbiguousEsiOverlayIndex { .. } => "ambiguous_esi_overlay_index",
            Self::UnsupportedEsiOverlayIndex { .. } => "unsupported_esi_overlay_index",
            Self::SelfOriginated { .. } => "self_originated",
            Self::L3VniMismatch { .. } => "l3vni_mismatch",
        }
    }

    /// Operator-facing IP-VRF label, or a fixed unscoped sentinel for
    /// drops that happen before RT / VRF resolution can run.
    #[must_use]
    pub fn vrf_label(&self) -> &str {
        match self {
            Self::OverlayIndexNoLinkedL2Vni { vrf, .. }
            | Self::UnresolvedOverlayIndexGateway { vrf, .. }
            | Self::AmbiguousOverlayIndexGateway { vrf, .. }
            | Self::DualOverlayIndexes { vrf, .. }
            | Self::EsiOverlayNoLinkedL2Vni { vrf, .. }
            | Self::MissingEsiOverlayRouterMac { vrf, .. }
            | Self::UnresolvedEsiOverlayIndex { vrf, .. }
            | Self::UnsupportedAllActiveEsiOverlayIndex { vrf, .. }
            | Self::AmbiguousEsiOverlayIndex { vrf, .. }
            | Self::UnsupportedEsiOverlayIndex { vrf, .. }
            | Self::SelfOriginated { vrf, .. }
            | Self::L3VniMismatch { vrf, .. } => vrf,
            Self::NoMatchingIpVrf { .. } | Self::MissingRouterMac { .. } => UNSCOPED_DROP_VRF_LABEL,
        }
    }
}

/// Build a [`RemoteIpPrefixTable`] from the IP-VRF table and a stream
/// of inbound Type 5 records.
///
/// Pure: no I/O, no tokio.
///
/// ## Multi-tenant fan-out
///
/// When a route's RTs intersect multiple IP-VRFs, the route is
/// imported into every match (one entry per `(IpVrfId, prefix)`).
/// This mirrors the receiving PE's behavior in RFC 9136 §4.4.2 —
/// the wire route doesn't know which tenant it's "really" for, so
/// every matching FIB gets the install.
pub fn project_ip_prefix_routes<I>(
    vrfs: &crate::ip_vrf::IpVrfTable,
    routes: I,
) -> RemoteIpPrefixTable
where
    I: IntoIterator<Item = ProjectedIpPrefixRoute>,
{
    project_ip_prefix_routes_with_overlay_index(vrfs, routes, std::iter::empty())
}

/// Build a [`RemoteIpPrefixTable`] from Type 5 records plus Type 2
/// MAC/IP records that can resolve RFC 9135 §9.2 overlay-index
/// gateways.
///
/// Interface-less Type 5 routes (Gateway Address zero) keep the
/// existing Router-MAC-extcomm projection path. Non-zero Gateway
/// Address routes are recursively resolved through exactly one Type 2
/// MAC/IP route in an L2VNI linked to the matched IP-VRF; unresolved
/// or ambiguous gateways are recorded as drops.
#[must_use]
pub fn project_ip_prefix_routes_with_overlay_index<I, O>(
    vrfs: &crate::ip_vrf::IpVrfTable,
    routes: I,
    overlay_index_routes: O,
) -> RemoteIpPrefixTable
where
    I: IntoIterator<Item = ProjectedIpPrefixRoute>,
    O: IntoIterator<Item = ProjectedOverlayIndexRoute>,
{
    project_ip_prefix_routes_inner(
        vrfs,
        routes,
        overlay_index_routes,
        EsiOverlayIndexMode::Unsupported,
    )
}

/// Build a [`RemoteIpPrefixTable`] from Type 5 records, Type 2
/// GW-IP overlay-index input, and EAD-per-EVI protected-recursion
/// input for RFC 9136 §4.3 ESI overlay-index receive.
///
/// ESI overlay-index v1 imports only the shape that the current L3
/// dataplane can represent: exactly one single-active EAD candidate in
/// an L2VNI linked to the matched IP-VRF. All-active and ambiguous
/// candidates are recorded as drops instead of picking a lossy
/// single-nexthop tie-break.
#[must_use]
pub fn project_ip_prefix_routes_with_overlay_and_esi_index<I, O, E>(
    vrfs: &crate::ip_vrf::IpVrfTable,
    routes: I,
    overlay_index_routes: O,
    esi_overlay_ead_routes: E,
) -> RemoteIpPrefixTable
where
    I: IntoIterator<Item = ProjectedIpPrefixRoute>,
    O: IntoIterator<Item = ProjectedOverlayIndexRoute>,
    E: IntoIterator<Item = ProjectedEsiOverlayEadPerEvi>,
{
    let esi_index = EsiOverlayEadIndex::build(esi_overlay_ead_routes);
    project_ip_prefix_routes_inner(
        vrfs,
        routes,
        overlay_index_routes,
        EsiOverlayIndexMode::Enabled(&esi_index),
    )
}

#[derive(Debug, Clone, Copy)]
enum EsiOverlayIndexMode<'a> {
    Unsupported,
    Enabled(&'a EsiOverlayEadIndex),
}

#[derive(Debug, Clone, Copy)]
enum PrefixResolution {
    OverlayIndex,
    EsiOverlayIndex,
    UnsupportedEsiOverlayIndex,
    InterfaceLess(MacAddress),
}

fn project_ip_prefix_routes_inner<I, O>(
    vrfs: &crate::ip_vrf::IpVrfTable,
    routes: I,
    overlay_index_routes: O,
    esi_overlay_mode: EsiOverlayIndexMode<'_>,
) -> RemoteIpPrefixTable
where
    I: IntoIterator<Item = ProjectedIpPrefixRoute>,
    O: IntoIterator<Item = ProjectedOverlayIndexRoute>,
{
    // Pre-collect local VTEP IPs from every IP-VRF for the
    // self-origination filter.
    let local_vteps: Vec<(String, IpAddr)> = vrfs
        .iter()
        .map(|v| (v.name.clone(), v.local_vtep_ip))
        .collect();
    let overlay_index = build_overlay_index(overlay_index_routes);

    let mut table = RemoteIpPrefixTable::new();

    for route in routes {
        // Self-origination filter: NEXT_HOP matches a local VTEP.
        if let Some((vrf_name, _)) = local_vteps.iter().find(|(_, ip)| *ip == route.next_hop) {
            table.drops.push(DropReason::SelfOriginated {
                prefix: route.prefix,
                next_hop: route.next_hop,
                vrf: vrf_name.clone(),
            });
            continue;
        }

        let overlay_gateway = !route.gateway.is_unspecified();

        let resolution = match classify_prefix_resolution(&route, esi_overlay_mode) {
            Ok(resolution) => resolution,
            Err(reason) => {
                table.drops.push(reason);
                continue;
            }
        };

        // RT match: for every IP-VRF whose RT set intersects the
        // route's RT list, additionally verify the route's wire
        // L3VNI matches the IP-VRF's configured L3VNI before
        // installing. A mismatch means the originator's VNI
        // disagrees with our config for the same RT, which would
        // program a kernel FIB entry whose VXLAN encap uses the
        // wrong VNI — drop with `L3VniMismatch` so the misconfig
        // is observable rather than silently wrong.
        let mut matched_any_rt = false;
        for vrf in vrfs.iter() {
            if !rt_match(&vrf.route_targets, &route.route_targets) {
                continue;
            }
            matched_any_rt = true;
            if route.l3vni != vrf.id.as_u32() {
                table.drops.push(DropReason::L3VniMismatch {
                    prefix: route.prefix,
                    next_hop: route.next_hop,
                    vrf: vrf.name.clone(),
                    observed_vni: route.l3vni,
                    configured_vni: vrf.id.as_u32(),
                });
                continue;
            }
            let (next_hop, router_mac) = match resolve_prefix_for_vrf(
                vrfs,
                vrf,
                &route,
                resolution,
                overlay_gateway,
                &overlay_index,
                esi_overlay_mode,
            ) {
                Ok(resolved) => resolved,
                Err(reason) => {
                    table.drops.push(reason);
                    continue;
                }
            };
            let entry = RemoteIpPrefixEntry {
                prefix: route.prefix,
                next_hop,
                targets: RemoteIpPrefixTargets::single(next_hop),
                l3vni: vrf.id.as_u32(),
                router_mac,
            };
            // Last-write-wins on (IpVrfId, prefix) collisions.
            // Equal-best routes only land here after the RIB has
            // picked one, so this branch is operationally
            // unreachable, but the projection stays deterministic
            // by inserting last.
            table.entries.insert((vrf.id, route.prefix), entry);
        }
        if !matched_any_rt {
            table.drops.push(DropReason::NoMatchingIpVrf {
                prefix: route.prefix,
                next_hop: route.next_hop,
            });
        }
    }

    table
}

fn classify_prefix_resolution(
    route: &ProjectedIpPrefixRoute,
    esi_overlay_mode: EsiOverlayIndexMode<'_>,
) -> Result<PrefixResolution, DropReason> {
    let overlay_gateway = !route.gateway.is_unspecified();
    if route.esi != EthernetSegmentIdentifier::ZERO {
        return Ok(match esi_overlay_mode {
            EsiOverlayIndexMode::Unsupported => PrefixResolution::UnsupportedEsiOverlayIndex,
            EsiOverlayIndexMode::Enabled(_) => PrefixResolution::EsiOverlayIndex,
        });
    }
    if overlay_gateway {
        return Ok(PrefixResolution::OverlayIndex);
    }
    route
        .router_mac
        .map(PrefixResolution::InterfaceLess)
        .ok_or(DropReason::MissingRouterMac {
            prefix: route.prefix,
            next_hop: route.next_hop,
        })
}

fn resolve_prefix_for_vrf(
    vrfs: &crate::ip_vrf::IpVrfTable,
    vrf: &crate::ip_vrf::IpVrf,
    route: &ProjectedIpPrefixRoute,
    resolution: PrefixResolution,
    overlay_gateway: bool,
    overlay_index: &OverlayIndexMap,
    esi_overlay_mode: EsiOverlayIndexMode<'_>,
) -> Result<(IpAddr, MacAddress), DropReason> {
    match resolution {
        PrefixResolution::UnsupportedEsiOverlayIndex => {
            Err(DropReason::UnsupportedEsiOverlayIndex {
                prefix: route.prefix,
                next_hop: route.next_hop,
                vrf: vrf.name.clone(),
            })
        }
        PrefixResolution::OverlayIndex => {
            resolve_overlay_index_gateway(vrfs, vrf, route, overlay_index)
                .map(|resolved| (resolved.next_hop, resolved.mac))
        }
        PrefixResolution::EsiOverlayIndex => {
            if overlay_gateway {
                return Err(DropReason::DualOverlayIndexes {
                    prefix: route.prefix,
                    gateway: route.gateway,
                    next_hop: route.next_hop,
                    vrf: vrf.name.clone(),
                });
            }
            let Some(router_mac) = route.router_mac else {
                return Err(DropReason::MissingEsiOverlayRouterMac {
                    prefix: route.prefix,
                    next_hop: route.next_hop,
                    vrf: vrf.name.clone(),
                });
            };
            let EsiOverlayIndexMode::Enabled(esi_overlay_index) = esi_overlay_mode else {
                unreachable!("ESI overlay resolution only selected in enabled mode");
            };
            resolve_esi_overlay_index(vrfs, vrf, route, esi_overlay_index)
                .map(|resolved| (resolved, router_mac))
        }
        PrefixResolution::InterfaceLess(router_mac) => Ok((route.next_hop, router_mac)),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OverlayIndexTarget {
    mac: MacAddress,
    next_hop: IpAddr,
    mobility_sequence: Option<u32>,
}

type OverlayIndexMap = BTreeMap<(EvpnInstanceId, IpAddr), Vec<OverlayIndexTarget>>;

fn build_overlay_index<O>(routes: O) -> OverlayIndexMap
where
    O: IntoIterator<Item = ProjectedOverlayIndexRoute>,
{
    let mut index: OverlayIndexMap = BTreeMap::new();
    for route in routes {
        index
            .entry((route.vni, route.host_ip))
            .or_default()
            .push(OverlayIndexTarget {
                mac: route.mac,
                next_hop: route.next_hop,
                mobility_sequence: route.mobility_sequence,
            });
    }
    index
}

fn resolve_overlay_index_gateway(
    vrfs: &crate::ip_vrf::IpVrfTable,
    vrf: &crate::ip_vrf::IpVrf,
    route: &ProjectedIpPrefixRoute,
    overlay_index: &OverlayIndexMap,
) -> Result<OverlayIndexTarget, DropReason> {
    let Some(linked_l2vnis) = vrfs
        .referenced_l2vnis(&vrf.name)
        .filter(|vnis| !vnis.is_empty())
    else {
        return Err(DropReason::OverlayIndexNoLinkedL2Vni {
            prefix: route.prefix,
            gateway: route.gateway,
            next_hop: route.next_hop,
            vrf: vrf.name.clone(),
        });
    };
    let matches = overlay_index_matches(linked_l2vnis, route.gateway, overlay_index);
    if matches.is_empty() {
        return Err(DropReason::UnresolvedOverlayIndexGateway {
            prefix: route.prefix,
            gateway: route.gateway,
            next_hop: route.next_hop,
            vrf: vrf.name.clone(),
        });
    }
    // Mobility tie-break, mirroring the Type 2 projection: the highest
    // MAC mobility sequence reflects the most recent host location, so
    // it wins (a route with no sequence loses to one that carries one).
    // Among the top-sequence contenders, a single MAC — possibly
    // multi-homed across several VTEPs — is unambiguous; resolve it to
    // the lowest next_hop for determinism. Distinct MACs tied at the
    // top sequence are a genuine conflict and stay fail-closed.
    let top_seq = matches
        .iter()
        .map(|t| t.mobility_sequence)
        .max()
        .expect("matches is non-empty");
    let winners: Vec<OverlayIndexTarget> = matches
        .into_iter()
        .filter(|t| t.mobility_sequence == top_seq)
        .collect();
    let mut distinct_macs: Vec<MacAddress> = Vec::new();
    for w in &winners {
        if !distinct_macs.contains(&w.mac) {
            distinct_macs.push(w.mac);
        }
    }
    if distinct_macs.len() == 1 {
        Ok(winners
            .into_iter()
            .min_by_key(|t| t.next_hop)
            .expect("winners is non-empty"))
    } else {
        Err(DropReason::AmbiguousOverlayIndexGateway {
            prefix: route.prefix,
            gateway: route.gateway,
            next_hop: route.next_hop,
            vrf: vrf.name.clone(),
            candidates: distinct_macs.len(),
        })
    }
}

fn overlay_index_matches(
    linked_l2vnis: &BTreeSet<EvpnInstanceId>,
    gateway: IpAddr,
    overlay_index: &OverlayIndexMap,
) -> Vec<OverlayIndexTarget> {
    let mut matches = Vec::new();
    for vni in linked_l2vnis {
        if let Some(targets) = overlay_index.get(&(*vni, gateway)) {
            matches.extend(targets.iter().copied());
        }
    }
    matches
}

fn resolve_esi_overlay_index(
    vrfs: &crate::ip_vrf::IpVrfTable,
    vrf: &crate::ip_vrf::IpVrf,
    route: &ProjectedIpPrefixRoute,
    esi_overlay_index: &EsiOverlayEadIndex,
) -> Result<IpAddr, DropReason> {
    match resolve_esi_overlay_index_targets(vrfs, vrf, route, esi_overlay_index)? {
        EsiOverlayResolvedTargets::SingleActive { next_hop } => Ok(next_hop),
        EsiOverlayResolvedTargets::AllActive(targets) => {
            Err(DropReason::UnsupportedAllActiveEsiOverlayIndex {
                prefix: route.prefix,
                next_hop: route.next_hop,
                vrf: vrf.name.clone(),
                candidates: targets.len(),
            })
        }
    }
}

fn resolve_esi_overlay_index_targets(
    vrfs: &crate::ip_vrf::IpVrfTable,
    vrf: &crate::ip_vrf::IpVrf,
    route: &ProjectedIpPrefixRoute,
    esi_overlay_index: &EsiOverlayEadIndex,
) -> Result<EsiOverlayResolvedTargets, DropReason> {
    let Some(linked_l2vnis) = vrfs
        .referenced_l2vnis(&vrf.name)
        .filter(|vnis| !vnis.is_empty())
    else {
        return Err(DropReason::EsiOverlayNoLinkedL2Vni {
            prefix: route.prefix,
            next_hop: route.next_hop,
            vrf: vrf.name.clone(),
        });
    };
    let candidates = esi_overlay_matches(linked_l2vnis, route, esi_overlay_index);
    if candidates.is_empty() {
        return Err(DropReason::UnresolvedEsiOverlayIndex {
            prefix: route.prefix,
            next_hop: route.next_hop,
            vrf: vrf.name.clone(),
        });
    }
    if candidates
        .iter()
        .any(|candidate| candidate.mode == EsiOverlayRedundancyMode::Conflicting)
    {
        return Err(DropReason::UnsupportedAllActiveEsiOverlayIndex {
            prefix: route.prefix,
            next_hop: route.next_hop,
            vrf: vrf.name.clone(),
            candidates: candidates.len(),
        });
    }
    let has_single_active = candidates
        .iter()
        .any(|candidate| candidate.mode == EsiOverlayRedundancyMode::SingleActive);
    let has_all_active = candidates
        .iter()
        .any(|candidate| candidate.mode == EsiOverlayRedundancyMode::AllActive);
    match (has_single_active, has_all_active) {
        (true, true) => Err(DropReason::UnsupportedAllActiveEsiOverlayIndex {
            prefix: route.prefix,
            next_hop: route.next_hop,
            vrf: vrf.name.clone(),
            candidates: candidates.len(),
        }),
        (true, false) => match candidates.as_slice() {
            [candidate] => Ok(EsiOverlayResolvedTargets::SingleActive {
                next_hop: candidate.next_hop,
            }),
            _ => Err(DropReason::AmbiguousEsiOverlayIndex {
                prefix: route.prefix,
                next_hop: route.next_hop,
                vrf: vrf.name.clone(),
                candidates: candidates.len(),
            }),
        },
        (false, true) => EsiOverlayAllActiveTargetSet::from_next_hops(
            candidates.iter().map(|candidate| candidate.next_hop),
        )
        .map(EsiOverlayResolvedTargets::AllActive)
        .ok_or(DropReason::UnresolvedEsiOverlayIndex {
            prefix: route.prefix,
            next_hop: route.next_hop,
            vrf: vrf.name.clone(),
        }),
        (false, false) => Err(DropReason::UnresolvedEsiOverlayIndex {
            prefix: route.prefix,
            next_hop: route.next_hop,
            vrf: vrf.name.clone(),
        }),
    }
}

fn esi_overlay_matches(
    linked_l2vnis: &BTreeSet<EvpnInstanceId>,
    route: &ProjectedIpPrefixRoute,
    esi_overlay_index: &EsiOverlayEadIndex,
) -> Vec<EsiOverlayEadCandidate> {
    let mut by_next_hop: BTreeMap<IpAddr, EsiOverlayRedundancyMode> = BTreeMap::new();
    for vni in linked_l2vnis {
        if let Some(candidates) =
            esi_overlay_index.candidates_for(*vni, route.esi, route.ethernet_tag)
        {
            for candidate in candidates {
                by_next_hop
                    .entry(candidate.next_hop)
                    .and_modify(|mode| *mode = mode.fold(candidate.mode))
                    .or_insert(candidate.mode);
            }
        }
    }
    by_next_hop
        .into_iter()
        .map(|(next_hop, mode)| EsiOverlayEadCandidate { next_hop, mode })
        .collect()
}

/// Intersection test: at least one RT in common.
fn rt_match(vrf_rts: &[RouteTarget], route_rts: &[RouteTarget]) -> bool {
    vrf_rts.iter().any(|a| route_rts.iter().any(|b| a == b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip_vrf::{IpVrf, IpVrfId, IpVrfTable};
    use rustbgpd_wire::{Ipv4Prefix, Ipv6Prefix};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn rt(s: &str) -> RouteTarget {
        s.parse().unwrap()
    }

    fn mac() -> MacAddress {
        MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
    }

    fn mac_with_tail(tail: u8) -> MacAddress {
        MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, tail])
    }

    fn l2vni(n: u32) -> EvpnInstanceId {
        EvpnInstanceId::new(n).unwrap()
    }

    fn vrf_with(name: &str, vni: u32, local: &str, rts: &[&str]) -> IpVrf {
        IpVrf::new(
            name.to_string(),
            IpVrfId::new(vni).unwrap(),
            "65000:5000".parse::<RouteDistinguisher>().unwrap(),
            rts.iter().map(|s| rt(s)).collect(),
            local.parse().unwrap(),
            mac(),
            format!("vrf-{name}"),
            format!("vni{vni}"),
            vni,
        )
        .unwrap()
    }

    fn v4(addr: [u8; 4], len: u8) -> EvpnIpPrefixValue {
        EvpnIpPrefixValue::V4(Ipv4Prefix::new(Ipv4Addr::from(addr), len))
    }

    fn v6(addr: [u8; 16], len: u8) -> EvpnIpPrefixValue {
        EvpnIpPrefixValue::V6(Ipv6Prefix::new(Ipv6Addr::from(addr), len))
    }

    fn route(prefix: EvpnIpPrefixValue, nh: &str, rts: &[&str]) -> ProjectedIpPrefixRoute {
        let gateway = match prefix {
            EvpnIpPrefixValue::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            EvpnIpPrefixValue::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        ProjectedIpPrefixRoute {
            rd: "65000:5000".parse().unwrap(),
            prefix,
            next_hop: nh.parse().unwrap(),
            gateway,
            esi: EthernetSegmentIdentifier::ZERO,
            ethernet_tag: EthernetTagId(0),
            l3vni: 5000,
            route_targets: rts.iter().map(|s| rt(s)).collect(),
            router_mac: Some(mac()),
        }
    }

    fn overlay(
        vni: u32,
        host_ip: &str,
        mac_tail: u8,
        next_hop: &str,
    ) -> ProjectedOverlayIndexRoute {
        overlay_seq(vni, host_ip, mac_tail, next_hop, None)
    }

    fn overlay_seq(
        vni: u32,
        host_ip: &str,
        mac_tail: u8,
        next_hop: &str,
        mobility_sequence: Option<u32>,
    ) -> ProjectedOverlayIndexRoute {
        ProjectedOverlayIndexRoute {
            vni: l2vni(vni),
            host_ip: host_ip.parse().unwrap(),
            mac: mac_with_tail(mac_tail),
            next_hop: next_hop.parse().unwrap(),
            mobility_sequence,
        }
    }

    fn esi(bytes: [u8; 10]) -> EthernetSegmentIdentifier {
        EthernetSegmentIdentifier::new(bytes)
    }

    fn esi_ead(
        l2vni_raw: u32,
        esi: EthernetSegmentIdentifier,
        ethernet_tag: u32,
        next_hop: &str,
        single_active: bool,
    ) -> ProjectedEsiOverlayEadPerEvi {
        ProjectedEsiOverlayEadPerEvi {
            l2vni: l2vni(l2vni_raw),
            esi,
            ethernet_tag: EthernetTagId(ethernet_tag),
            next_hop: next_hop.parse().unwrap(),
            single_active,
        }
    }

    fn one_vrf(name: &str, vni: u32, local: &str, rts: &[&str]) -> IpVrfTable {
        let mut t = IpVrfTable::new();
        t.insert(vrf_with(name, vni, local, rts)).unwrap();
        t
    }

    #[test]
    fn esi_overlay_ead_index_scopes_by_l2vni_and_ethernet_tag() {
        let esi = esi([0, 0, 0, 0, 0, 0, 0, 0, 0, 7]);
        let index = EsiOverlayEadIndex::build(vec![
            ProjectedEsiOverlayEadPerEvi {
                l2vni: l2vni(100),
                esi,
                ethernet_tag: EthernetTagId(0),
                next_hop: "10.0.0.2".parse().unwrap(),
                single_active: true,
            },
            ProjectedEsiOverlayEadPerEvi {
                l2vni: l2vni(100),
                esi,
                ethernet_tag: EthernetTagId(0),
                next_hop: "10.0.0.2".parse().unwrap(),
                single_active: true,
            },
            ProjectedEsiOverlayEadPerEvi {
                l2vni: l2vni(200),
                esi,
                ethernet_tag: EthernetTagId(0),
                next_hop: "10.0.0.3".parse().unwrap(),
                single_active: true,
            },
            ProjectedEsiOverlayEadPerEvi {
                l2vni: l2vni(100),
                esi,
                ethernet_tag: EthernetTagId(42),
                next_hop: "10.0.0.4".parse().unwrap(),
                single_active: true,
            },
            ProjectedEsiOverlayEadPerEvi {
                l2vni: l2vni(100),
                esi: EthernetSegmentIdentifier::ZERO,
                ethernet_tag: EthernetTagId(0),
                next_hop: "10.0.0.5".parse().unwrap(),
                single_active: true,
            },
        ]);

        assert_eq!(index.len(), 3);
        assert_eq!(
            index.candidates_for(l2vni(100), esi, EthernetTagId(0)),
            Some(
                &[EsiOverlayEadCandidate {
                    next_hop: "10.0.0.2".parse().unwrap(),
                    mode: EsiOverlayRedundancyMode::SingleActive,
                }][..]
            )
        );
        assert_eq!(
            index.candidates_for(l2vni(200), esi, EthernetTagId(0)),
            Some(
                &[EsiOverlayEadCandidate {
                    next_hop: "10.0.0.3".parse().unwrap(),
                    mode: EsiOverlayRedundancyMode::SingleActive,
                }][..]
            )
        );
        assert_eq!(
            index.candidates_for(l2vni(100), esi, EthernetTagId(42)),
            Some(
                &[EsiOverlayEadCandidate {
                    next_hop: "10.0.0.4".parse().unwrap(),
                    mode: EsiOverlayRedundancyMode::SingleActive,
                }][..]
            )
        );
        assert_eq!(
            index.candidates_for(
                l2vni(100),
                EthernetSegmentIdentifier::ZERO,
                EthernetTagId(0)
            ),
            None
        );
    }

    #[test]
    fn esi_overlay_ead_index_preserves_conflicting_duplicate_mode() {
        let esi = esi([0, 0, 0, 0, 0, 0, 0, 0, 0, 8]);
        let index = EsiOverlayEadIndex::build(vec![
            esi_ead(100, esi, 0, "10.0.0.2", true),
            esi_ead(100, esi, 0, "10.0.0.2", false),
        ]);

        assert_eq!(
            index.candidates_for(l2vni(100), esi, EthernetTagId(0)),
            Some(
                &[EsiOverlayEadCandidate {
                    next_hop: "10.0.0.2".parse().unwrap(),
                    mode: EsiOverlayRedundancyMode::Conflicting,
                }][..]
            )
        );
    }

    #[test]
    fn esi_overlay_index_type5_models_all_active_target_set_deterministically() {
        let mut vrfs = one_vrf("blue", 5000, "10.0.0.1", &["65000:5000"]);
        vrfs.mark_referenced_by_l2vni("blue".to_string(), l2vni(100));
        let vrf = vrfs.iter().next().unwrap();
        let esi = esi([0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
        let mut r = route(v4([10, 1, 0, 0], 24), "10.0.0.9", &["65000:5000"]);
        r.esi = esi;
        r.ethernet_tag = EthernetTagId(42);
        let index = EsiOverlayEadIndex::build(vec![
            esi_ead(100, esi, 42, "10.0.0.3", false),
            esi_ead(100, esi, 42, "10.0.0.2", false),
            esi_ead(100, esi, 42, "10.0.0.3", false),
        ]);

        let resolved = resolve_esi_overlay_index_targets(&vrfs, vrf, &r, &index).unwrap();

        match resolved {
            EsiOverlayResolvedTargets::AllActive(targets) => assert_eq!(
                targets.next_hops(),
                &[
                    "10.0.0.2".parse::<IpAddr>().unwrap(),
                    "10.0.0.3".parse::<IpAddr>().unwrap()
                ]
            ),
            EsiOverlayResolvedTargets::SingleActive { next_hop } => {
                panic!("expected all-active target set, got single-active {next_hop}")
            }
        }
    }

    #[test]
    fn esi_overlay_index_type5_models_single_survivor_all_active_target_set() {
        let mut vrfs = one_vrf("blue", 5000, "10.0.0.1", &["65000:5000"]);
        vrfs.mark_referenced_by_l2vni("blue".to_string(), l2vni(100));
        let vrf = vrfs.iter().next().unwrap();
        let esi = esi([0, 0, 0, 0, 0, 0, 0, 0, 0, 10]);
        let mut r = route(v4([10, 2, 0, 0], 24), "10.0.0.9", &["65000:5000"]);
        r.esi = esi;
        let index = EsiOverlayEadIndex::build(vec![esi_ead(100, esi, 0, "10.0.0.2", false)]);

        let resolved = resolve_esi_overlay_index_targets(&vrfs, vrf, &r, &index).unwrap();

        match resolved {
            EsiOverlayResolvedTargets::AllActive(targets) => assert_eq!(
                targets.next_hops(),
                &["10.0.0.2".parse::<IpAddr>().unwrap()]
            ),
            EsiOverlayResolvedTargets::SingleActive { next_hop } => {
                panic!("expected all-active target set, got single-active {next_hop}")
            }
        }
    }

    #[test]
    fn esi_overlay_index_type5_model_fails_closed_on_mixed_modes() {
        let mut vrfs = one_vrf("blue", 5000, "10.0.0.1", &["65000:5000"]);
        vrfs.mark_referenced_by_l2vni("blue".to_string(), l2vni(100));
        let vrf = vrfs.iter().next().unwrap();
        let esi = esi([0, 0, 0, 0, 0, 0, 0, 0, 0, 11]);
        let mut r = route(v4([10, 3, 0, 0], 24), "10.0.0.9", &["65000:5000"]);
        r.esi = esi;
        let index = EsiOverlayEadIndex::build(vec![
            esi_ead(100, esi, 0, "10.0.0.2", true),
            esi_ead(100, esi, 0, "10.0.0.3", false),
        ]);

        let err = resolve_esi_overlay_index_targets(&vrfs, vrf, &r, &index).unwrap_err();

        assert!(matches!(
            err,
            DropReason::UnsupportedAllActiveEsiOverlayIndex { ref vrf, candidates: 2, .. }
                if vrf == "blue"
        ));
    }

    #[test]
    fn esi_overlay_index_type5_model_fails_closed_on_duplicate_mode_conflict() {
        let mut vrfs = one_vrf("blue", 5000, "10.0.0.1", &["65000:5000"]);
        vrfs.mark_referenced_by_l2vni("blue".to_string(), l2vni(100));
        let vrf = vrfs.iter().next().unwrap();
        let esi = esi([0, 0, 0, 0, 0, 0, 0, 0, 0, 12]);
        let mut r = route(v4([10, 4, 0, 0], 24), "10.0.0.9", &["65000:5000"]);
        r.esi = esi;
        let index = EsiOverlayEadIndex::build(vec![
            esi_ead(100, esi, 0, "10.0.0.2", true),
            esi_ead(100, esi, 0, "10.0.0.2", false),
        ]);

        let err = resolve_esi_overlay_index_targets(&vrfs, vrf, &r, &index).unwrap_err();

        assert!(matches!(
            err,
            DropReason::UnsupportedAllActiveEsiOverlayIndex { ref vrf, candidates: 1, .. }
                if vrf == "blue"
        ));
    }

    #[test]
    fn empty_input_yields_empty_table() {
        let vrfs = one_vrf("blue", 5000, "10.0.0.1", &["65000:5000"]);
        let table = project_ip_prefix_routes(&vrfs, std::iter::empty());
        assert!(table.is_empty());
        assert!(table.drops().is_empty());
    }

    #[test]
    fn happy_path_imports_into_matching_vrf() {
        let vrfs = one_vrf("blue", 5000, "10.0.0.1", &["65000:5000"]);
        let table = project_ip_prefix_routes(
            &vrfs,
            vec![route(v4([10, 1, 0, 0], 24), "10.0.0.2", &["65000:5000"])],
        );
        assert_eq!(table.len(), 1);
        let v = IpVrfId::new(5000).unwrap();
        let entries: Vec<_> = table.for_vrf(v).collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].1.next_hop,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
        assert_eq!(entries[0].1.l3vni, 5000);
        assert_eq!(entries[0].1.router_mac, mac());
    }

    #[test]
    fn no_rt_match_drops_with_reason() {
        let vrfs = one_vrf("blue", 5000, "10.0.0.1", &["65000:5000"]);
        let table = project_ip_prefix_routes(
            &vrfs,
            vec![route(v4([10, 1, 0, 0], 24), "10.0.0.2", &["65000:9999"])],
        );
        assert!(table.is_empty());
        assert_eq!(table.drops().len(), 1);
        assert!(matches!(
            table.drops()[0],
            DropReason::NoMatchingIpVrf { .. }
        ));
    }

    #[test]
    fn missing_router_mac_drops_with_reason() {
        let vrfs = one_vrf("blue", 5000, "10.0.0.1", &["65000:5000"]);
        let mut r = route(v4([10, 1, 0, 0], 24), "10.0.0.2", &["65000:5000"]);
        r.router_mac = None;
        let table = project_ip_prefix_routes(&vrfs, vec![r]);
        assert!(table.is_empty());
        assert!(matches!(
            table.drops()[0],
            DropReason::MissingRouterMac { .. }
        ));
    }

    #[test]
    fn non_zero_esi_type5_drops_without_ead_recursion_input() {
        let vrfs = one_vrf("blue", 5000, "10.0.0.1", &["65000:5000"]);
        let mut r = route(v4([10, 1, 0, 0], 24), "10.0.0.2", &["65000:5000"]);
        r.esi = EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        r.ethernet_tag = EthernetTagId(101);
        let table = project_ip_prefix_routes(&vrfs, vec![r]);
        assert!(
            table.is_empty(),
            "ESI overlay-index Type 5 must not fall through as interface-less"
        );
        assert!(matches!(
            table.drops()[0],
            DropReason::UnsupportedEsiOverlayIndex { .. }
        ));
        assert_eq!(
            table.drops()[0].reason_label(),
            "unsupported_esi_overlay_index"
        );
    }

    #[test]
    fn non_zero_esi_with_non_zero_gateway_still_drops_as_esi_overlay() {
        let mut vrfs = one_vrf("blue", 5000, "10.0.0.1", &["65000:5000"]);
        vrfs.mark_referenced_by_l2vni("blue".to_string(), l2vni(100));
        let mut r = route(v4([10, 1, 0, 0], 24), "10.0.0.2", &["65000:5000"]);
        r.esi = EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        r.gateway = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));

        let table = project_ip_prefix_routes_with_overlay_index(
            &vrfs,
            vec![r],
            vec![overlay(100, "192.0.2.10", 0xaa, "10.0.0.3")],
        );

        assert!(table.is_empty());
        assert!(matches!(
            table.drops()[0],
            DropReason::UnsupportedEsiOverlayIndex { .. }
        ));
    }

    #[test]
    fn esi_overlay_index_type5_resolves_through_single_active_ead_per_evi() {
        let mut vrfs = one_vrf("blue", 5000, "10.0.0.1", &["65000:5000"]);
        vrfs.mark_referenced_by_l2vni("blue".to_string(), l2vni(100));
        let esi = esi([0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
        let mut r = route(v4([10, 1, 0, 0], 24), "10.0.0.9", &["65000:5000"]);
        r.esi = esi;
        r.ethernet_tag = EthernetTagId(42);
        r.router_mac = Some(mac_with_tail(0xee));

        let table = project_ip_prefix_routes_with_overlay_and_esi_index(
            &vrfs,
            vec![r],
            Vec::new(),
            vec![esi_ead(100, esi, 42, "10.0.0.2", true)],
        );

        assert!(table.drops().is_empty());
        let entries: Vec<_> = table.for_vrf(IpVrfId::new(5000).unwrap()).collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1.next_hop, "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(entries[0].1.router_mac, mac_with_tail(0xee));
    }

    #[test]
    fn esi_overlay_index_type5_ignores_ead_outside_linked_l2vni_or_tag() {
        let mut vrfs = one_vrf("blue", 5000, "10.0.0.1", &["65000:5000"]);
        vrfs.mark_referenced_by_l2vni("blue".to_string(), l2vni(100));
        let esi = esi([0, 0, 0, 0, 0, 0, 0, 0, 0, 10]);
        let mut r = route(v4([10, 2, 0, 0], 24), "10.0.0.9", &["65000:5000"]);
        r.esi = esi;
        r.ethernet_tag = EthernetTagId(42);

        let table = project_ip_prefix_routes_with_overlay_and_esi_index(
            &vrfs,
            vec![r],
            Vec::new(),
            vec![
                esi_ead(200, esi, 42, "10.0.0.2", true),
                esi_ead(100, esi, 43, "10.0.0.3", true),
            ],
        );

        assert!(table.is_empty());
        assert!(matches!(
            table.drops()[0],
            DropReason::UnresolvedEsiOverlayIndex { ref vrf, .. } if vrf == "blue"
        ));
    }

    #[test]
    fn esi_overlay_index_type5_drops_all_active_until_l3_multipath_exists() {
        let mut vrfs = one_vrf("blue", 5000, "10.0.0.1", &["65000:5000"]);
        vrfs.mark_referenced_by_l2vni("blue".to_string(), l2vni(100));
        let esi = esi([0, 0, 0, 0, 0, 0, 0, 0, 0, 11]);
        let mut r = route(v4([10, 3, 0, 0], 24), "10.0.0.9", &["65000:5000"]);
        r.esi = esi;

        let table = project_ip_prefix_routes_with_overlay_and_esi_index(
            &vrfs,
            vec![r],
            Vec::new(),
            vec![esi_ead(100, esi, 0, "10.0.0.2", false)],
        );

        assert!(table.is_empty());
        assert!(matches!(
            table.drops()[0],
            DropReason::UnsupportedAllActiveEsiOverlayIndex { ref vrf, candidates: 1, .. }
                if vrf == "blue"
        ));
        assert_eq!(
            table.drops()[0].reason_label(),
            "unsupported_all_active_esi_overlay_index"
        );
    }

    #[test]
    fn esi_overlay_index_type5_drops_ambiguous_single_active_candidates() {
        let mut vrfs = one_vrf("blue", 5000, "10.0.0.1", &["65000:5000"]);
        vrfs.mark_referenced_by_l2vni("blue".to_string(), l2vni(100));
        let esi = esi([0, 0, 0, 0, 0, 0, 0, 0, 0, 12]);
        let mut r = route(v4([10, 4, 0, 0], 24), "10.0.0.9", &["65000:5000"]);
        r.esi = esi;

        let table = project_ip_prefix_routes_with_overlay_and_esi_index(
            &vrfs,
            vec![r],
            Vec::new(),
            vec![
                esi_ead(100, esi, 0, "10.0.0.2", true),
                esi_ead(100, esi, 0, "10.0.0.3", true),
            ],
        );

        assert!(table.is_empty());
        assert!(matches!(
            table.drops()[0],
            DropReason::AmbiguousEsiOverlayIndex { ref vrf, candidates: 2, .. }
                if vrf == "blue"
        ));
    }

    #[test]
    fn esi_overlay_index_type5_requires_router_mac() {
        let mut vrfs = one_vrf("blue", 5000, "10.0.0.1", &["65000:5000"]);
        vrfs.mark_referenced_by_l2vni("blue".to_string(), l2vni(100));
        let esi = esi([0, 0, 0, 0, 0, 0, 0, 0, 0, 13]);
        let mut r = route(v4([10, 5, 0, 0], 24), "10.0.0.9", &["65000:5000"]);
        r.esi = esi;
        r.router_mac = None;

        let table = project_ip_prefix_routes_with_overlay_and_esi_index(
            &vrfs,
            vec![r],
            Vec::new(),
            vec![esi_ead(100, esi, 0, "10.0.0.2", true)],
        );

        assert!(table.is_empty());
        assert!(matches!(
            table.drops()[0],
            DropReason::MissingEsiOverlayRouterMac { ref vrf, .. } if vrf == "blue"
        ));
    }

    #[test]
    fn esi_overlay_index_type5_rejects_dual_overlay_indexes() {
        let mut vrfs = one_vrf("blue", 5000, "10.0.0.1", &["65000:5000"]);
        vrfs.mark_referenced_by_l2vni("blue".to_string(), l2vni(100));
        let esi = esi([0, 0, 0, 0, 0, 0, 0, 0, 0, 14]);
        let mut r = route(v4([10, 6, 0, 0], 24), "10.0.0.9", &["65000:5000"]);
        r.esi = esi;
        r.gateway = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

        let table = project_ip_prefix_routes_with_overlay_and_esi_index(
            &vrfs,
            vec![r],
            Vec::new(),
            vec![esi_ead(100, esi, 0, "10.0.0.2", true)],
        );

        assert!(table.is_empty());
        assert!(matches!(
            table.drops()[0],
            DropReason::DualOverlayIndexes { ref vrf, .. } if vrf == "blue"
        ));
    }

    #[test]
    fn drop_counts_use_bounded_vrf_and_reason_labels() {
        let vrfs = one_vrf("blue", 5000, "10.0.0.1", &["65000:5000"]);
        let no_rt = route(v4([10, 1, 0, 0], 24), "10.0.0.2", &["65000:9999"]);
        let mut missing_router_mac = route(v4([10, 2, 0, 0], 24), "10.0.0.2", &["65000:5000"]);
        missing_router_mac.router_mac = None;
        let mut unresolved_overlay_1 = route(v4([10, 3, 0, 0], 24), "10.0.0.2", &["65000:5000"]);
        unresolved_overlay_1.gateway = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let mut unresolved_overlay_2 = route(v4([10, 4, 0, 0], 24), "10.0.0.2", &["65000:5000"]);
        unresolved_overlay_2.gateway = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));

        let table = project_ip_prefix_routes(
            &vrfs,
            vec![
                no_rt,
                missing_router_mac,
                unresolved_overlay_1,
                unresolved_overlay_2,
            ],
        );
        let counts = table.drop_counts_by_vrf_reason();

        assert_eq!(
            counts.get(&(UNSCOPED_DROP_VRF_LABEL.to_string(), "no_matching_ip_vrf")),
            Some(&1)
        );
        assert_eq!(
            counts.get(&(UNSCOPED_DROP_VRF_LABEL.to_string(), "missing_router_mac")),
            Some(&1)
        );
        assert_eq!(
            counts.get(&("blue".to_string(), "overlay_index_no_linked_l2vni")),
            Some(&2)
        );
        assert_eq!(counts.len(), 3);
    }

    #[test]
    fn nonzero_v4_gateway_without_linked_l2vni_drops() {
        let vrfs = one_vrf("blue", 5000, "10.0.0.1", &["65000:5000"]);
        let mut r = route(v4([10, 1, 0, 0], 24), "10.0.0.2", &["65000:5000"]);
        r.gateway = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10));
        let table = project_ip_prefix_routes(&vrfs, vec![r]);
        assert!(table.is_empty());
        assert!(matches!(
            table.drops()[0],
            DropReason::OverlayIndexNoLinkedL2Vni {
                gateway: IpAddr::V4(gateway),
                ref vrf,
                ..
            } if gateway == Ipv4Addr::new(10, 0, 0, 10) && vrf == "blue"
        ));
    }

    #[test]
    fn nonzero_v6_gateway_without_linked_l2vni_drops() {
        let vrfs = one_vrf("blue", 5000, "2001:db8::1", &["65000:5000"]);
        let mut r = route(
            v6(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                32,
            ),
            "2001:db8::2",
            &["65000:5000"],
        );
        r.gateway = IpAddr::V6("2001:db8::10".parse().unwrap());
        let table = project_ip_prefix_routes(&vrfs, vec![r]);
        assert!(table.is_empty());
        assert!(matches!(
            table.drops()[0],
            DropReason::OverlayIndexNoLinkedL2Vni {
                gateway: IpAddr::V6(gateway),
                ref vrf,
                ..
            } if gateway == "2001:db8::10".parse::<Ipv6Addr>().unwrap() && vrf == "blue"
        ));
    }

    #[test]
    fn overlay_index_gateway_resolves_through_linked_type2_mac_ip() {
        let mut vrfs = one_vrf("blue", 5000, "10.0.0.1", &["65000:5000"]);
        vrfs.mark_referenced_by_l2vni("blue".to_string(), l2vni(100));
        let mut r = route(v4([10, 1, 0, 0], 24), "10.0.0.9", &["65000:5000"]);
        r.gateway = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        // Overlay-index resolution uses the Type 2 MAC, not the
        // Type 5 Router-MAC extcomm.
        r.router_mac = None;

        let table = project_ip_prefix_routes_with_overlay_index(
            &vrfs,
            vec![r],
            vec![overlay(100, "192.0.2.10", 0xaa, "10.0.0.2")],
        );

        assert!(table.drops().is_empty());
        let blue = IpVrfId::new(5000).unwrap();
        let entries: Vec<_> = table.for_vrf(blue).collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1.next_hop, "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(entries[0].1.router_mac, mac_with_tail(0xaa));
    }

    #[test]
    fn overlay_index_gateway_ignores_type2_outside_linked_l2vnis() {
        let mut vrfs = one_vrf("blue", 5000, "10.0.0.1", &["65000:5000"]);
        vrfs.mark_referenced_by_l2vni("blue".to_string(), l2vni(100));
        let mut r = route(v4([10, 1, 0, 0], 24), "10.0.0.9", &["65000:5000"]);
        r.gateway = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));

        let table = project_ip_prefix_routes_with_overlay_index(
            &vrfs,
            vec![r],
            vec![overlay(200, "192.0.2.10", 0xaa, "10.0.0.2")],
        );

        assert!(table.is_empty());
        assert!(matches!(
            table.drops()[0],
            DropReason::UnresolvedOverlayIndexGateway { ref vrf, .. } if vrf == "blue"
        ));
    }

    #[test]
    fn overlay_index_gateway_drops_when_type2_resolution_is_ambiguous() {
        let mut vrfs = one_vrf("blue", 5000, "10.0.0.1", &["65000:5000"]);
        vrfs.mark_referenced_by_l2vni("blue".to_string(), l2vni(100));
        vrfs.mark_referenced_by_l2vni("blue".to_string(), l2vni(101));
        let mut r = route(v4([10, 1, 0, 0], 24), "10.0.0.9", &["65000:5000"]);
        r.gateway = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));

        let table = project_ip_prefix_routes_with_overlay_index(
            &vrfs,
            vec![r],
            vec![
                overlay(100, "192.0.2.10", 0xaa, "10.0.0.2"),
                overlay(101, "192.0.2.10", 0xbb, "10.0.0.3"),
            ],
        );

        assert!(table.is_empty());
        assert!(matches!(
            table.drops()[0],
            DropReason::AmbiguousOverlayIndexGateway { candidates: 2, .. }
        ));
    }

    #[test]
    fn overlay_index_gateway_resolves_multihomed_same_mac() {
        // A multi-homed gateway: the same MAC for the gateway IP is
        // reachable through two ES-peer VTEPs. That is unambiguous —
        // resolve to a deterministic (lowest) next_hop, not a drop.
        let mut vrfs = one_vrf("blue", 5000, "10.0.0.1", &["65000:5000"]);
        vrfs.mark_referenced_by_l2vni("blue".to_string(), l2vni(100));
        let mut r = route(v4([10, 1, 0, 0], 24), "10.0.0.9", &["65000:5000"]);
        r.gateway = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        r.router_mac = None;

        let table = project_ip_prefix_routes_with_overlay_index(
            &vrfs,
            vec![r],
            vec![
                overlay(100, "192.0.2.10", 0xaa, "10.0.0.3"),
                overlay(100, "192.0.2.10", 0xaa, "10.0.0.2"),
            ],
        );

        assert!(table.drops().is_empty());
        let blue = IpVrfId::new(5000).unwrap();
        let entries: Vec<_> = table.for_vrf(blue).collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1.next_hop, "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(entries[0].1.router_mac, mac_with_tail(0xaa));
    }

    #[test]
    fn overlay_index_gateway_higher_mobility_sequence_wins() {
        // The gateway IP moved from MAC 0xaa to MAC 0xbb. The newer
        // advertisement carries the higher mobility sequence, so it wins
        // the recursive lookup rather than dropping as ambiguous.
        let mut vrfs = one_vrf("blue", 5000, "10.0.0.1", &["65000:5000"]);
        vrfs.mark_referenced_by_l2vni("blue".to_string(), l2vni(100));
        let mut r = route(v4([10, 1, 0, 0], 24), "10.0.0.9", &["65000:5000"]);
        r.gateway = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        r.router_mac = None;

        let table = project_ip_prefix_routes_with_overlay_index(
            &vrfs,
            vec![r],
            vec![
                overlay_seq(100, "192.0.2.10", 0xaa, "10.0.0.2", Some(5)),
                overlay_seq(100, "192.0.2.10", 0xbb, "10.0.0.3", Some(6)),
            ],
        );

        assert!(table.drops().is_empty());
        let blue = IpVrfId::new(5000).unwrap();
        let entries: Vec<_> = table.for_vrf(blue).collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1.next_hop, "10.0.0.3".parse::<IpAddr>().unwrap());
        assert_eq!(entries[0].1.router_mac, mac_with_tail(0xbb));
    }

    #[test]
    fn self_originated_route_dropped() {
        let vrfs = one_vrf("blue", 5000, "10.0.0.1", &["65000:5000"]);
        let table = project_ip_prefix_routes(
            &vrfs,
            vec![route(v4([10, 1, 0, 0], 24), "10.0.0.1", &["65000:5000"])],
        );
        assert!(table.is_empty());
        assert!(matches!(
            table.drops()[0],
            DropReason::SelfOriginated { ref vrf, .. } if vrf == "blue"
        ));
    }

    #[test]
    fn route_with_multiple_matching_vrfs_imports_into_each_with_matching_vni() {
        // Two VRFs share an RT but have distinct L3VNIs (the table
        // enforces VNI uniqueness). The wire route carries a single
        // L3VNI — so it can match the L3VNI of at most one VRF.
        // Under the post-fix semantics, the route imports into the
        // VRF whose VNI matches and is dropped (L3VniMismatch) for
        // the other.
        let mut vrfs = IpVrfTable::new();
        vrfs.insert(vrf_with("blue", 5000, "10.0.0.1", &["65000:5000"]))
            .unwrap();
        vrfs.insert(vrf_with("red", 5001, "10.0.0.1", &["65000:5000"]))
            .unwrap();
        let table = project_ip_prefix_routes(
            &vrfs,
            vec![route(v4([10, 1, 0, 0], 24), "10.0.0.2", &["65000:5000"])],
        );
        let blue = IpVrfId::new(5000).unwrap();
        let red = IpVrfId::new(5001).unwrap();
        assert_eq!(table.for_vrf(blue).count(), 1);
        assert_eq!(table.for_vrf(red).count(), 0);
        // The mismatch with the red VRF is recorded so an operator
        // can spot the misconfig (RT shared across tenants with
        // different VNIs).
        assert!(table.drops().iter().any(|d| matches!(
            d,
            DropReason::L3VniMismatch { vrf, observed_vni: 5000, configured_vni: 5001, .. }
                if vrf == "red"
        )));
    }

    #[test]
    fn l3vni_mismatch_drops_route_and_records_drop_reason() {
        // Single VRF with VNI=5000, but the route advertises VNI=9999.
        // RT matches → would have imported under the old semantics;
        // under the post-fix semantics it's dropped.
        let vrfs = one_vrf("blue", 5000, "10.0.0.1", &["65000:5000"]);
        let mut r = route(v4([10, 1, 0, 0], 24), "10.0.0.2", &["65000:5000"]);
        r.l3vni = 9999;
        let table = project_ip_prefix_routes(&vrfs, vec![r]);
        assert!(table.is_empty(), "L3VNI-mismatched route must not import");
        assert!(
            table.drops().iter().any(|d| matches!(
                d,
                DropReason::L3VniMismatch {
                    observed_vni: 9999,
                    configured_vni: 5000,
                    ..
                }
            )),
            "must record L3VniMismatch drop reason: {:?}",
            table.drops()
        );
    }

    #[test]
    fn entry_l3vni_uses_vrf_configured_vni_not_route_label() {
        // Defense-in-depth: even when the route's wire VNI matches
        // the VRF's configured VNI on the happy path, the entry
        // should carry the *VRF's* VNI (not echo back the route's
        // label). This pins the contract that downstream FIB
        // programming uses the local-config VNI, immunizing the
        // dataplane from any drift if the wire decoder ever loses
        // precision.
        let vrfs = one_vrf("blue", 5000, "10.0.0.1", &["65000:5000"]);
        let table = project_ip_prefix_routes(
            &vrfs,
            vec![route(v4([10, 1, 0, 0], 24), "10.0.0.2", &["65000:5000"])],
        );
        let blue = IpVrfId::new(5000).unwrap();
        let entries: Vec<_> = table.for_vrf(blue).collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1.l3vni, 5000);
    }

    #[test]
    fn route_matching_one_vrf_skips_others() {
        let mut vrfs = IpVrfTable::new();
        vrfs.insert(vrf_with("blue", 5000, "10.0.0.1", &["65000:5000"]))
            .unwrap();
        vrfs.insert(vrf_with("red", 5001, "10.0.0.1", &["65000:5001"]))
            .unwrap();
        let table = project_ip_prefix_routes(
            &vrfs,
            vec![route(v4([10, 1, 0, 0], 24), "10.0.0.2", &["65000:5000"])],
        );
        assert_eq!(table.len(), 1);
        let blue = IpVrfId::new(5000).unwrap();
        let red = IpVrfId::new(5001).unwrap();
        assert_eq!(table.for_vrf(blue).count(), 1);
        assert_eq!(table.for_vrf(red).count(), 0);
    }

    #[test]
    fn v6_prefix_imports_cleanly() {
        let vrfs = one_vrf("blue", 5000, "2001:db8::1", &["65000:5000"]);
        let table = project_ip_prefix_routes(
            &vrfs,
            vec![route(
                v6(
                    [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    32,
                ),
                "2001:db8::2",
                &["65000:5000"],
            )],
        );
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn extcomms_to_fields_round_trips() {
        let rt_c = rt("65000:5000").to_extended_community();
        let mac_c = ExtendedCommunity::router_mac([0x02, 0, 0, 0, 0, 0x42]);
        let (rts, mac) = ProjectedIpPrefixRoute::extcomms_to_fields(&[rt_c, mac_c]);
        assert_eq!(rts.len(), 1);
        assert_eq!(mac.unwrap().octets(), [0x02, 0, 0, 0, 0, 0x42]);
    }

    #[test]
    fn extcomms_to_fields_handles_missing_router_mac() {
        let rt_c = rt("65000:5000").to_extended_community();
        let (rts, mac) = ProjectedIpPrefixRoute::extcomms_to_fields(&[rt_c]);
        assert_eq!(rts.len(), 1);
        assert!(mac.is_none());
    }

    #[test]
    fn empty_route_targets_drops_with_no_match_reason() {
        let vrfs = one_vrf("blue", 5000, "10.0.0.1", &["65000:5000"]);
        let r = route(v4([10, 1, 0, 0], 24), "10.0.0.2", &[]);
        let table = project_ip_prefix_routes(&vrfs, vec![r]);
        assert!(table.is_empty());
        assert!(matches!(
            table.drops()[0],
            DropReason::NoMatchingIpVrf { .. }
        ));
    }
}
