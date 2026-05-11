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
//! Every imported Type 5 must carry a Router MAC extcomm — the inner
//! destination MAC for symmetric IRB recursive lookup. Routes without
//! one are dropped (logged at the call site, not here).
//!
//! ## Self-origination filter
//!
//! Routes whose `next_hop` matches any local IP-VRF's `local_vtep_ip`
//! are dropped — they came from us, the RIB just reflected them via
//! a route reflector. Filtering here keeps the daemon from
//! programming kernel routes pointing at its own VTEP.

use std::collections::BTreeMap;
use std::net::IpAddr;

use rustbgpd_wire::{EvpnIpPrefixValue, ExtendedCommunity, MacAddress, RouteDistinguisher};

use crate::ip_vrf::IpVrfId;
use crate::route_target::RouteTarget;

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
    /// Originator VTEP — the FIB nexthop, what the recursive lookup
    /// terminates on after VXLAN encap.
    pub next_hop: IpAddr,
    /// L3VNI to wrap encapsulated frames with.
    pub l3vni: u32,
    /// Inner destination MAC the kernel needs for the recursive
    /// lookup. Pulled from the RFC 9135 Router MAC extcomm.
    pub router_mac: MacAddress,
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
    // Pre-collect local VTEP IPs from every IP-VRF for the
    // self-origination filter.
    let local_vteps: Vec<(String, IpAddr)> = vrfs
        .iter()
        .map(|v| (v.name.clone(), v.local_vtep_ip))
        .collect();

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

        // Router MAC must be present.
        let Some(router_mac) = route.router_mac else {
            table.drops.push(DropReason::MissingRouterMac {
                prefix: route.prefix,
                next_hop: route.next_hop,
            });
            continue;
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
            let entry = RemoteIpPrefixEntry {
                prefix: route.prefix,
                next_hop: route.next_hop,
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
        ProjectedIpPrefixRoute {
            rd: "65000:5000".parse().unwrap(),
            prefix,
            next_hop: nh.parse().unwrap(),
            l3vni: 5000,
            route_targets: rts.iter().map(|s| rt(s)).collect(),
            router_mac: Some(mac()),
        }
    }

    fn one_vrf(name: &str, vni: u32, local: &str, rts: &[&str]) -> IpVrfTable {
        let mut t = IpVrfTable::new();
        t.insert(vrf_with(name, vni, local, rts)).unwrap();
        t
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
