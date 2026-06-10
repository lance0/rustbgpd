//! Per-IP-VRF kernel-route observation (Gate 9 slice 6a).
//!
//! Walks every `RTM_GETROUTE` reply, filters by `IpVrf.table_id`, and
//! runs each surviving message through the [`classify`] pure function.
//! The dump output is a `HashMap<IpVrfId, Vec<LocalIpRouteObservation>>`
//! the daemon (slice 6b) feeds into the L3 originator.
//!
//! ADR-0054 §1 splits the boundary at "Linux observes, daemon decides"
//! — the classifier is the *observation* policy (kernel-route shape is
//! eligible / ineligible), not the *origination* policy (RT match,
//! readiness gate). The originator slice owns the latter.
//!
//! ## Filtering policy
//!
//! Conservative on the first pass — connected / static / manual only,
//! plus three negative filters:
//!
//! - **Installed by another routing daemon** — `RTPROT_BGP`,
//!   `RTPROT_ZEBRA`, `RTPROT_OSPF`, `RTPROT_BIRD`, `RTPROT_RIP`,
//!   `RTPROT_ISIS`, `RTPROT_BABEL`, etc. Re-originating routes another
//!   daemon installed would create an origination loop on the host.
//! - **Output device is the IP-VRF's own L3 VXLAN** — these were
//!   installed via our own remote-Type 5 path (slice 6c will install
//!   them once that lands); originating them back out as local Type 5
//!   would echo every remote route back to its origin.
//! - **Non-forwardable route types** — `RTN_LOCAL`, `RTN_BROADCAST`,
//!   `RTN_MULTICAST`, `RTN_UNREACHABLE`, `RTN_PROHIBIT`,
//!   `RTN_BLACKHOLE`, `RTN_THROW`. Only `RTN_UNICAST` is a candidate.
//! - **Link-local or multicast prefix** — `169.254.0.0/16`,
//!   `fe80::/10`, `224.0.0.0/4`, `ff00::/8`. Operators almost never
//!   advertise these via Type 5; the filter catches the common
//!   misconfig.
//!
//! Family-cross with `IpVrf.local_vtep_ip` is *not* filtered here —
//! the originator (slice 6b) catches it via
//! `OriginationError::FamilyMismatch` so the counter shows up per VRF
//! rather than getting folded into a generic "filtered" total.
//!
//! ## Kernel `table_id` placement
//!
//! Linux encodes the table ID in two places:
//!
//! 1. `RouteHeader.table: u8` for legacy tables 0..=255.
//! 2. `RouteAttribute::Table(u32)` for tables `0..=u32::MAX` (the
//!    kernel sets `header.table = RT_TABLE_COMPAT` (252) when the
//!    real id is `>= 256`).
//!
//! [`extract_table_id`] prefers the attribute, falls back to the
//! header. The IP-VRF schema permits `table_id` up to `u32::MAX`, so
//! both paths must work.

use std::collections::HashMap;

use futures::stream::TryStreamExt;
use netlink_packet_route::AddressFamily;
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteMessage, RouteProtocol, RouteType,
};
use rtnetlink::{Handle, IpVersion, RouteMessageBuilder};

use rustbgpd_evpn::ip_vrf::{
    IpVrfId, IpVrfRouteDump, IpVrfTable, LocalIpRouteObservation, RouteFilterReason, RouteSource,
};
use rustbgpd_evpn::{EvpnIpPrefixValue, Ipv4Prefix, Ipv6Prefix};

use crate::error::DataplaneError;

/// What the classifier returns for one route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    /// Keep this route as a Type 5 candidate.
    Keep(RouteSource),
    /// Drop with the given reason.
    Drop(RouteFilterReason),
}

/// Normalized input the classifier needs. The dump path translates
/// each `RouteMessage` into this shape so the classifier itself is a
/// pure function and can be exhaustively unit-tested without
/// touching netlink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassifiedRoute {
    /// `RouteHeader.protocol` — how the kernel says this route was
    /// learned.
    pub protocol: RouteProtocol,
    /// `RouteHeader.kind` — the route type (unicast, local, …).
    pub route_type: RouteType,
    /// Destination prefix in wire-friendly form.
    pub prefix: EvpnIpPrefixValue,
    /// `RouteAttribute::Oif(_)` for single-output routes. `None`
    /// means "no output interface attribute"; in that case the
    /// L3VXLAN-output filter is conservatively suppressed (we keep
    /// the route).
    pub output_ifindex: Option<u32>,
    /// IP-VRF's L3VXLAN ifindex resolved from the link cache. `None`
    /// when the operator-named L3VXLAN device is not currently
    /// present; the classifier suppresses the L3VXLAN-output filter
    /// in that case so a transient device dropout does not stall
    /// origination.
    pub l3vxlan_ifindex: Option<u32>,
}

/// Pure classifier. The dump / watch loop translates `RouteMessage`
/// to [`ClassifiedRoute`] and feeds it here.
#[must_use]
pub fn classify(route: ClassifiedRoute) -> Classification {
    if let (Some(out), Some(l3v)) = (route.output_ifindex, route.l3vxlan_ifindex)
        && out == l3v
    {
        return Classification::Drop(RouteFilterReason::OutputDeviceIsL3Vxlan);
    }

    if route.route_type != RouteType::Unicast {
        return Classification::Drop(RouteFilterReason::NonForwardableType);
    }

    if is_link_local_or_multicast(route.prefix) {
        return Classification::Drop(RouteFilterReason::LinkLocalOrMulticast);
    }

    // The active-routing-daemon arms and the default-deny arm both
    // return `Drop(InstalledByRoutingDaemon)` — listing the known
    // protocols documents *why* they're dropped and is easier to
    // extend than spelling the negative case out in the wildcard.
    #[allow(clippy::match_same_arms)]
    match route.protocol {
        RouteProtocol::Kernel => Classification::Keep(RouteSource::Connected),
        RouteProtocol::Static => Classification::Keep(RouteSource::Static),
        RouteProtocol::Boot => Classification::Keep(RouteSource::Manual),
        // Active routing daemons — re-originating their routes would
        // create an origination loop.
        RouteProtocol::Bgp
        | RouteProtocol::Zebra
        | RouteProtocol::Bird
        | RouteProtocol::Ospf
        | RouteProtocol::Isis
        | RouteProtocol::Rip
        | RouteProtocol::Babel
        | RouteProtocol::Eigrp => Classification::Drop(RouteFilterReason::InstalledByRoutingDaemon),
        // Default-deny on protocols we don't explicitly recognize.
        // Better to surface the unknown via a counter than to silently
        // re-originate a route from an unexpected source.
        _ => Classification::Drop(RouteFilterReason::InstalledByRoutingDaemon),
    }
}

fn is_link_local_or_multicast(prefix: EvpnIpPrefixValue) -> bool {
    match prefix {
        EvpnIpPrefixValue::V4(p) => p.addr.is_link_local() || p.addr.is_multicast(),
        EvpnIpPrefixValue::V6(p) => {
            let octets = p.addr.octets();
            // fe80::/10 — link-local. `is_unicast_link_local` is
            // unstable, so spell it out via the segment pattern.
            let link_local = octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80;
            link_local || p.addr.is_multicast()
        }
    }
}

/// Per-IP-VRF resolution snapshot the dump needs to do its filter
/// pass. Built by the caller from the existing
/// [`crate::linux::ip_vrf`] inventory pass, so this module never
/// re-walks the link table.
#[derive(Debug, Clone, Default)]
pub(crate) struct IpVrfRoutingResolution {
    /// IP-VRF `table_id` keyed by `IpVrfId`. Routes whose table
    /// doesn't match any entry here are silently ignored (they're not
    /// "ours").
    pub tables: HashMap<u32, IpVrfId>,
    /// L3VXLAN ifindex per `IpVrfId` when the operator-named device
    /// has been observed. Absent when the device is not currently
    /// present.
    pub l3vxlan_ifindexes: HashMap<IpVrfId, u32>,
}

impl IpVrfRoutingResolution {
    /// Build from a configured [`IpVrfTable`] plus a name→ifindex map
    /// (built upstream from the link inventory). VRFs in the table
    /// always contribute their `table_id`; the L3VXLAN ifindex is
    /// populated only when the name resolves.
    pub(crate) fn from_table(
        ip_vrfs: &IpVrfTable,
        l3vxlan_name_to_ifindex: &HashMap<String, u32>,
    ) -> Self {
        let mut out = Self::default();
        for vrf in ip_vrfs.iter() {
            out.tables.insert(vrf.table_id, vrf.id);
            if let Some(idx) = l3vxlan_name_to_ifindex.get(&vrf.l3vxlan_device) {
                out.l3vxlan_ifindexes.insert(vrf.id, *idx);
            }
        }
        out
    }
}

fn note_observation(dump: &mut IpVrfRouteDump, obs: LocalIpRouteObservation) {
    dump.observations.entry(obs.vrf_id).or_default().push(obs);
}

fn note_filter(dump: &mut IpVrfRouteDump, vrf_id: IpVrfId, reason: RouteFilterReason) {
    *dump.filter_counts.entry((vrf_id, reason)).or_default() += 1;
}

/// Walk every kernel route (IPv4 + IPv6), filter by IP-VRF
/// `table_id`, classify each, and produce the per-VRF observation
/// table.
///
/// # Errors
///
/// Returns [`DataplaneError::Other`] if the underlying rtnetlink
/// route dump stream yields an error. The reconciler treats this as
/// "do not advance observations this pass" and retries on the next
/// dump.
pub(crate) async fn dump_routes(
    handle: &Handle,
    resolution: &IpVrfRoutingResolution,
) -> Result<IpVrfRouteDump, DataplaneError> {
    let mut out = IpVrfRouteDump::default();
    if resolution.tables.is_empty() {
        return Ok(out);
    }
    // Seed every configured VRF with an empty entry so the daemon can
    // emit a zero-valued gauge even when nothing was observed for it.
    for vrf_id in resolution.tables.values() {
        out.observations.entry(*vrf_id).or_default();
    }

    dump_one_family(handle, IpVersion::V4, resolution, &mut out).await?;
    dump_one_family(handle, IpVersion::V6, resolution, &mut out).await?;
    Ok(out)
}

async fn dump_one_family(
    handle: &Handle,
    version: IpVersion,
    resolution: &IpVrfRoutingResolution,
    out: &mut IpVrfRouteDump,
) -> Result<(), DataplaneError> {
    let msg = match version {
        IpVersion::V4 => RouteMessageBuilder::<std::net::Ipv4Addr>::new().build(),
        IpVersion::V6 => RouteMessageBuilder::<std::net::Ipv6Addr>::new().build(),
    };
    let mut stream = handle.route().get(msg).execute();
    while let Some(route) = stream
        .try_next()
        .await
        .map_err(|e| DataplaneError::Other(format!("route dump ({version:?}): {e}")))?
    {
        ingest_route_message(&route, resolution, out);
    }
    Ok(())
}

/// Classify one `RouteMessage` and record it. Public-in-crate so
/// the test module can drive it against synthesized messages without
/// the kernel.
pub(crate) fn ingest_route_message(
    msg: &RouteMessage,
    resolution: &IpVrfRoutingResolution,
    out: &mut IpVrfRouteDump,
) {
    let table_id = extract_table_id(msg);
    let Some(vrf_id) = resolution.tables.get(&table_id).copied() else {
        return; // not one of ours
    };
    // Seed the observations entry so the daemon can emit a zero-valued
    // gauge for a VRF that has only filtered routes this pass.
    out.observations.entry(vrf_id).or_default();

    let Some(prefix) = extract_prefix(msg) else {
        note_filter(out, vrf_id, RouteFilterReason::Malformed);
        return;
    };

    let classified = ClassifiedRoute {
        protocol: msg.header.protocol,
        route_type: msg.header.kind,
        prefix,
        output_ifindex: extract_output_ifindex(msg),
        l3vxlan_ifindex: resolution.l3vxlan_ifindexes.get(&vrf_id).copied(),
    };

    match classify(classified) {
        Classification::Keep(source) => {
            note_observation(
                out,
                LocalIpRouteObservation {
                    vrf_id,
                    prefix,
                    source,
                },
            );
        }
        Classification::Drop(reason) => note_filter(out, vrf_id, reason),
    }
}

/// Effective routing table id for one `RouteMessage`. Prefers the
/// `RouteAttribute::Table(u32)` attribute (used for tables `>= 256`),
/// falls back to the 8-bit header field. `pub(super)` so the
/// ADR-0079 adoption walk (`super::l3_adoption`) shares the same
/// table-id decoding as the observation classifier.
pub(super) fn extract_table_id(msg: &RouteMessage) -> u32 {
    for attr in &msg.attributes {
        if let RouteAttribute::Table(t) = attr {
            return *t;
        }
    }
    u32::from(msg.header.table)
}

/// Build an [`EvpnIpPrefixValue`] from the message's destination
/// attribute + header `destination_prefix_length` + header
/// `address_family`. Returns `None` on family / attribute mismatch
/// (the classifier counts those as `Malformed`). `pub(super)` for
/// the same `super::l3_adoption` reuse as [`extract_table_id`].
pub(super) fn extract_prefix(msg: &RouteMessage) -> Option<EvpnIpPrefixValue> {
    let mut dest: Option<&RouteAddress> = None;
    for attr in &msg.attributes {
        if let RouteAttribute::Destination(addr) = attr {
            dest = Some(addr);
            break;
        }
    }
    let len = msg.header.destination_prefix_length;
    match (msg.header.address_family, dest) {
        (AddressFamily::Inet, Some(RouteAddress::Inet(v4))) => {
            if len > 32 {
                return None;
            }
            Some(EvpnIpPrefixValue::V4(Ipv4Prefix::new(*v4, len)))
        }
        (AddressFamily::Inet6, Some(RouteAddress::Inet6(v6))) => {
            if len > 128 {
                return None;
            }
            Some(EvpnIpPrefixValue::V6(Ipv6Prefix::new(*v6, len)))
        }
        // Default routes: no Destination attribute and length 0. Both
        // families are legitimate here, even though slice 6b will
        // typically suppress them via family / policy.
        (AddressFamily::Inet, None) if len == 0 => Some(EvpnIpPrefixValue::V4(Ipv4Prefix::new(
            std::net::Ipv4Addr::UNSPECIFIED,
            0,
        ))),
        (AddressFamily::Inet6, None) if len == 0 => Some(EvpnIpPrefixValue::V6(Ipv6Prefix::new(
            std::net::Ipv6Addr::UNSPECIFIED,
            0,
        ))),
        _ => None,
    }
}

/// Output ifindex from the first `RouteAttribute::Oif`, or `None`
/// when the route has multipath / no output attribute. `pub(super)`
/// for the same `super::l3_adoption` reuse as [`extract_table_id`].
pub(super) fn extract_output_ifindex(msg: &RouteMessage) -> Option<u32> {
    for attr in &msg.attributes {
        if let RouteAttribute::Oif(idx) = attr {
            return Some(*idx);
        }
    }
    None
}

/// Re-export the [`RouteHeader`] type for the tests module's
/// builder convenience without polluting the parent module's public
/// surface.
#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_route::route::{RouteFlags, RouteHeader};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(addr: [u8; 4], len: u8) -> EvpnIpPrefixValue {
        EvpnIpPrefixValue::V4(Ipv4Prefix::new(Ipv4Addr::from(addr), len))
    }

    fn v6(addr: [u16; 8], len: u8) -> EvpnIpPrefixValue {
        let a = Ipv6Addr::new(
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
        );
        EvpnIpPrefixValue::V6(Ipv6Prefix::new(a, len))
    }

    fn keep_static(prefix: EvpnIpPrefixValue) -> ClassifiedRoute {
        ClassifiedRoute {
            protocol: RouteProtocol::Static,
            route_type: RouteType::Unicast,
            prefix,
            output_ifindex: Some(10),
            l3vxlan_ifindex: Some(20),
        }
    }

    #[test]
    fn keeps_kernel_connected_route() {
        let r = ClassifiedRoute {
            protocol: RouteProtocol::Kernel,
            ..keep_static(v4([198, 51, 100, 0], 24))
        };
        assert_eq!(classify(r), Classification::Keep(RouteSource::Connected));
    }

    #[test]
    fn keeps_static_route() {
        assert_eq!(
            classify(keep_static(v4([198, 51, 100, 0], 24))),
            Classification::Keep(RouteSource::Static),
        );
    }

    #[test]
    fn keeps_boot_route_as_manual() {
        let r = ClassifiedRoute {
            protocol: RouteProtocol::Boot,
            ..keep_static(v4([198, 51, 100, 0], 24))
        };
        assert_eq!(classify(r), Classification::Keep(RouteSource::Manual));
    }

    #[test]
    fn drops_bgp_protocol() {
        let r = ClassifiedRoute {
            protocol: RouteProtocol::Bgp,
            ..keep_static(v4([198, 51, 100, 0], 24))
        };
        assert_eq!(
            classify(r),
            Classification::Drop(RouteFilterReason::InstalledByRoutingDaemon),
        );
    }

    #[test]
    fn drops_zebra_ospf_isis_rip_bird_babel_as_routing_daemon() {
        for proto in [
            RouteProtocol::Zebra,
            RouteProtocol::Ospf,
            RouteProtocol::Isis,
            RouteProtocol::Rip,
            RouteProtocol::Bird,
            RouteProtocol::Babel,
        ] {
            let r = ClassifiedRoute {
                protocol: proto,
                ..keep_static(v4([198, 51, 100, 0], 24))
            };
            assert_eq!(
                classify(r),
                Classification::Drop(RouteFilterReason::InstalledByRoutingDaemon),
                "protocol {proto:?} should be dropped",
            );
        }
    }

    #[test]
    fn drops_unknown_protocol_default_deny() {
        let r = ClassifiedRoute {
            protocol: RouteProtocol::Other(99),
            ..keep_static(v4([198, 51, 100, 0], 24))
        };
        assert_eq!(
            classify(r),
            Classification::Drop(RouteFilterReason::InstalledByRoutingDaemon),
        );
    }

    #[test]
    fn drops_route_with_output_on_l3vxlan() {
        let r = ClassifiedRoute {
            output_ifindex: Some(20),
            l3vxlan_ifindex: Some(20),
            ..keep_static(v4([198, 51, 100, 0], 24))
        };
        assert_eq!(
            classify(r),
            Classification::Drop(RouteFilterReason::OutputDeviceIsL3Vxlan),
        );
    }

    #[test]
    fn keeps_route_when_l3vxlan_unknown_but_output_set() {
        let r = ClassifiedRoute {
            output_ifindex: Some(20),
            l3vxlan_ifindex: None,
            ..keep_static(v4([198, 51, 100, 0], 24))
        };
        assert_eq!(classify(r), Classification::Keep(RouteSource::Static));
    }

    #[test]
    fn drops_non_unicast_route_types() {
        for rt in [
            RouteType::Local,
            RouteType::Broadcast,
            RouteType::Multicast,
            RouteType::BlackHole,
            RouteType::Unreachable,
            RouteType::Prohibit,
            RouteType::Throw,
        ] {
            let r = ClassifiedRoute {
                route_type: rt,
                ..keep_static(v4([198, 51, 100, 0], 24))
            };
            assert_eq!(
                classify(r),
                Classification::Drop(RouteFilterReason::NonForwardableType),
                "route type {rt:?} should be dropped",
            );
        }
    }

    #[test]
    fn drops_link_local_v4() {
        let r = keep_static(v4([169, 254, 1, 0], 24));
        assert_eq!(
            classify(r),
            Classification::Drop(RouteFilterReason::LinkLocalOrMulticast),
        );
    }

    #[test]
    fn drops_multicast_v4() {
        let r = keep_static(v4([224, 0, 0, 0], 24));
        assert_eq!(
            classify(r),
            Classification::Drop(RouteFilterReason::LinkLocalOrMulticast),
        );
    }

    #[test]
    fn drops_link_local_v6() {
        let r = keep_static(v6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 64));
        assert_eq!(
            classify(r),
            Classification::Drop(RouteFilterReason::LinkLocalOrMulticast),
        );
    }

    #[test]
    fn drops_multicast_v6() {
        let r = keep_static(v6([0xff00, 0, 0, 0, 0, 0, 0, 0], 8));
        assert_eq!(
            classify(r),
            Classification::Drop(RouteFilterReason::LinkLocalOrMulticast),
        );
    }

    #[test]
    fn label_strings_stable() {
        // Stable Prometheus labels — bumping any of these is a metric
        // break. Pin them so a refactor catches the change.
        assert_eq!(
            RouteFilterReason::InstalledByRoutingDaemon.label(),
            "installed_by_routing_daemon",
        );
        assert_eq!(
            RouteFilterReason::OutputDeviceIsL3Vxlan.label(),
            "output_device_is_l3vxlan",
        );
        assert_eq!(
            RouteFilterReason::NonForwardableType.label(),
            "non_forwardable_type",
        );
        assert_eq!(
            RouteFilterReason::LinkLocalOrMulticast.label(),
            "link_local_or_multicast",
        );
        assert_eq!(RouteFilterReason::Malformed.label(), "malformed");
    }

    fn vrf(id: u32, table_id: u32) -> rustbgpd_evpn::IpVrf {
        use rustbgpd_evpn::{IpVrf, MacAddress, RouteDistinguisher};
        IpVrf::new(
            format!("vrf{id}"),
            IpVrfId::new(id).unwrap(),
            format!("65000:{table_id}")
                .parse::<RouteDistinguisher>()
                .unwrap(),
            vec![format!("65000:{table_id}").parse().unwrap()],
            std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]),
            format!("vrf{id}"),
            format!("l3vxlan{id}"),
            table_id,
        )
        .expect("test vrf builds")
    }

    fn resolution(vrfs: &IpVrfTable, l3vxlan_idx: &[(IpVrfId, u32)]) -> IpVrfRoutingResolution {
        let mut name_to_ifindex = HashMap::new();
        for vrf in vrfs.iter() {
            if let Some((_, idx)) = l3vxlan_idx.iter().find(|(id, _)| *id == vrf.id) {
                name_to_ifindex.insert(vrf.l3vxlan_device.clone(), *idx);
            }
        }
        IpVrfRoutingResolution::from_table(vrfs, &name_to_ifindex)
    }

    fn route_msg(
        family: AddressFamily,
        prefix_len: u8,
        dest_attr: Option<RouteAddress>,
        proto: RouteProtocol,
        kind: RouteType,
        table: u32,
        oif: Option<u32>,
    ) -> RouteMessage {
        let mut msg = RouteMessage::default();
        msg.header = RouteHeader {
            address_family: family,
            destination_prefix_length: prefix_len,
            source_prefix_length: 0,
            tos: 0,
            // For table > 255 the header carries RT_TABLE_COMPAT and
            // the real id rides in the attribute. We always emit the
            // attribute on the test side so extract_table_id has a
            // single happy path.
            table: u8::try_from(table.min(252)).unwrap_or(252),
            protocol: proto,
            scope: netlink_packet_route::route::RouteScope::default(),
            kind,
            flags: RouteFlags::empty(),
        };
        msg.attributes.push(RouteAttribute::Table(table));
        if let Some(d) = dest_attr {
            msg.attributes.push(RouteAttribute::Destination(d));
        }
        if let Some(idx) = oif {
            msg.attributes.push(RouteAttribute::Oif(idx));
        }
        msg
    }

    #[test]
    fn ingest_records_observation_for_static_route_in_known_vrf() {
        let mut table = IpVrfTable::new();
        table.insert(vrf(100, 100)).unwrap();
        let res = resolution(&table, &[(IpVrfId::new(100).unwrap(), 20)]);

        let msg = route_msg(
            AddressFamily::Inet,
            24,
            Some(RouteAddress::Inet(Ipv4Addr::new(198, 51, 100, 0))),
            RouteProtocol::Static,
            RouteType::Unicast,
            100,
            Some(10),
        );

        let mut out = IpVrfRouteDump::default();
        ingest_route_message(&msg, &res, &mut out);
        let vrf_id = IpVrfId::new(100).unwrap();
        assert_eq!(out.observations.get(&vrf_id).unwrap().len(), 1);
        assert_eq!(
            out.observations.get(&vrf_id).unwrap()[0].source,
            RouteSource::Static,
        );
        assert!(out.filter_counts.is_empty());
    }

    #[test]
    fn ingest_drops_route_with_output_on_l3vxlan() {
        let mut table = IpVrfTable::new();
        table.insert(vrf(100, 100)).unwrap();
        let l3v_ifindex = 20;
        let res = resolution(&table, &[(IpVrfId::new(100).unwrap(), l3v_ifindex)]);

        let msg = route_msg(
            AddressFamily::Inet,
            24,
            Some(RouteAddress::Inet(Ipv4Addr::new(198, 51, 100, 0))),
            RouteProtocol::Static,
            RouteType::Unicast,
            100,
            Some(l3v_ifindex),
        );

        let mut out = IpVrfRouteDump::default();
        ingest_route_message(&msg, &res, &mut out);
        let vrf_id = IpVrfId::new(100).unwrap();
        assert!(out.observations.get(&vrf_id).unwrap().is_empty());
        assert_eq!(
            out.filter_counts
                .get(&(vrf_id, RouteFilterReason::OutputDeviceIsL3Vxlan))
                .copied(),
            Some(1),
        );
    }

    #[test]
    fn ingest_ignores_route_for_unknown_table() {
        let mut table = IpVrfTable::new();
        table.insert(vrf(100, 100)).unwrap();
        let res = resolution(&table, &[]);

        let msg = route_msg(
            AddressFamily::Inet,
            24,
            Some(RouteAddress::Inet(Ipv4Addr::new(198, 51, 100, 0))),
            RouteProtocol::Static,
            RouteType::Unicast,
            999, // not our VRF
            None,
        );

        let mut out = IpVrfRouteDump::default();
        ingest_route_message(&msg, &res, &mut out);
        assert!(out.observations.values().all(Vec::is_empty));
        assert!(out.filter_counts.is_empty());
    }

    #[test]
    fn ingest_counts_malformed_when_prefix_attr_missing_but_length_nonzero() {
        let mut table = IpVrfTable::new();
        table.insert(vrf(100, 100)).unwrap();
        let res = resolution(&table, &[]);

        // Header says /24 but no Destination attribute → the kernel
        // never emits this shape (a real /24 always carries the
        // attribute), so the dump treats it as parser-vs-kernel drift.
        let msg = route_msg(
            AddressFamily::Inet,
            24,
            None,
            RouteProtocol::Static,
            RouteType::Unicast,
            100,
            None,
        );

        let mut out = IpVrfRouteDump::default();
        ingest_route_message(&msg, &res, &mut out);
        let vrf_id = IpVrfId::new(100).unwrap();
        assert_eq!(
            out.filter_counts
                .get(&(vrf_id, RouteFilterReason::Malformed))
                .copied(),
            Some(1),
        );
    }

    #[test]
    fn ingest_accepts_default_route_with_no_destination_attr() {
        let mut table = IpVrfTable::new();
        table.insert(vrf(100, 100)).unwrap();
        let res = resolution(&table, &[]);

        let msg = route_msg(
            AddressFamily::Inet,
            0,
            None,
            RouteProtocol::Static,
            RouteType::Unicast,
            100,
            None,
        );

        let mut out = IpVrfRouteDump::default();
        ingest_route_message(&msg, &res, &mut out);
        let vrf_id = IpVrfId::new(100).unwrap();
        assert_eq!(out.observations.get(&vrf_id).unwrap().len(), 1);
        assert_eq!(
            out.observations.get(&vrf_id).unwrap()[0].prefix,
            v4([0, 0, 0, 0], 0),
        );
    }
}
