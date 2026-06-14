//! Self-consistency proof for ADR-0087 overlay-index Type 5
//! origination.
//!
//! The strongest test that origination and projection agree on the
//! GW-IP encoding is to feed a natively-originated GW-IP Type 5 route
//! straight back through the *own* receive-side projection
//! (`project_ip_prefix_routes_with_overlay_index`) with a matching
//! Type 2 MAC/IP route present, and assert it resolves end-to-end.
//! By construction this pins the two halves to one wire shape — if
//! origination ever drifts (label, ESI, gateway field, missing-RMAC),
//! the route stops resolving here.
//!
//! ESI overlay-index origination is outbound-only in this slice: the
//! receive-side projection carries the Type 5 ESI only to drop it
//! fail-closed until protected EAD recursion is implemented. The ESI
//! case below therefore pins the standards wire shape directly instead
//! of pretending it can exercise protected recursion locally.

use std::net::IpAddr;

use rustbgpd_evpn::ip_vrf::{
    IpVrf, IpVrfId, IpVrfTable, LocalIpRoute, OverlayIndexMode, ProjectedIpPrefixRoute,
    ProjectedOverlayIndexRoute, originate_ip_prefix_route,
    project_ip_prefix_routes_with_overlay_index,
};
use rustbgpd_evpn::{EvpnInstanceId, RouteTarget};
use rustbgpd_wire::{
    EthernetSegmentIdentifier, EvpnRoute, Ipv4Prefix, MacAddress, PathAttribute, RouteDistinguisher,
};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// Build a GW-IP-mode IP-VRF linked to one L2VNI (the projection
/// requires the link to scope the recursive Type 2 lookup).
fn gw_vrf_table(l2vni: u32) -> IpVrfTable {
    let vrf = IpVrf::new(
        "tenant-blue".to_string(),
        IpVrfId::new(5000).unwrap(),
        "65000:5000".parse::<RouteDistinguisher>().unwrap(),
        vec!["65000:5000".parse::<RouteTarget>().unwrap()],
        ip("10.0.0.1"),
        MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
        "vrf-blue".to_string(),
        "vni5000".to_string(),
        5000,
    )
    .unwrap()
    .with_overlay_index_mode(OverlayIndexMode::GatewayIp);

    let mut table = IpVrfTable::new();
    table.insert(vrf).unwrap();
    table.mark_referenced_by_l2vni(
        "tenant-blue".to_string(),
        EvpnInstanceId::new(l2vni).unwrap(),
    );
    table
}

fn esi() -> EthernetSegmentIdentifier {
    EthernetSegmentIdentifier::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
}

fn overlay_mac() -> MacAddress {
    MacAddress::new([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee])
}

/// Build an ESI-mode IP-VRF linked to one local EVI. Config
/// validation proves the EVI belongs to the selected ES; this pure
/// crate-level test only needs the resolved domain object.
fn esi_vrf_table(l2vni: u32) -> IpVrfTable {
    let vrf = IpVrf::new(
        "tenant-blue".to_string(),
        IpVrfId::new(5000).unwrap(),
        "65000:5000".parse::<RouteDistinguisher>().unwrap(),
        vec!["65000:5000".parse::<RouteTarget>().unwrap()],
        ip("10.0.0.1"),
        MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
        "vrf-blue".to_string(),
        "vni5000".to_string(),
        5000,
    )
    .unwrap()
    .with_esi_overlay_index(
        esi(),
        overlay_mac(),
        Some(EvpnInstanceId::new(l2vni).unwrap()),
    );

    let mut table = IpVrfTable::new();
    table.insert(vrf).unwrap();
    table.mark_referenced_by_l2vni(
        "tenant-blue".to_string(),
        EvpnInstanceId::new(l2vni).unwrap(),
    );
    table
}

/// Translate an originated Type 5 (the daemon's outbound shape) into
/// the projection's inbound `ProjectedIpPrefixRoute`, exactly as the
/// daemon's RIB → projection bridge would after a reflect.
fn originated_to_projected(
    route: &EvpnRoute,
    attributes: &[PathAttribute],
    next_hop: IpAddr,
) -> ProjectedIpPrefixRoute {
    let EvpnRoute::IpPrefix(p) = route else {
        panic!("expected a Type 5 IpPrefix route");
    };
    let ext_comms: Vec<_> = attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::ExtendedCommunities(c) => Some(c.clone()),
            _ => None,
        })
        .unwrap_or_default();
    let (route_targets, router_mac) = ProjectedIpPrefixRoute::extcomms_to_fields(&ext_comms);
    ProjectedIpPrefixRoute {
        rd: p.rd,
        prefix: p.prefix,
        next_hop,
        gateway: p.gateway,
        esi: p.esi,
        l3vni: p.label.as_vni(),
        route_targets,
        router_mac,
    }
}

#[test]
fn natively_originated_gateway_ip_type5_resolves_through_own_projection() {
    const L2VNI: u32 = 100;
    let vrfs = gw_vrf_table(L2VNI);
    let vrf = vrfs.get("tenant-blue").unwrap();

    // The gateway host lives on the linked L2VNI (its Type 2 MAC/IP
    // route). The originator selects this via after the connected-
    // subnet check; here we hand it directly to the pure builder.
    let gateway = ip("10.1.1.5");
    let local = LocalIpRoute::v4(Ipv4Prefix::new("192.168.50.0".parse().unwrap(), 24))
        .with_gateway(Some(gateway));
    let originated = originate_ip_prefix_route(vrf, &local).unwrap();

    // Sanity: the originated route really is the GW-IP shape.
    if let EvpnRoute::IpPrefix(p) = &originated.route {
        assert_eq!(p.gateway, gateway, "gateway carried in the Gateway field");
        assert_eq!(p.label.as_vni(), 5000, "L3VNI carried in the label");
    } else {
        panic!("expected Type 5");
    }
    let has_rmac = originated.attributes.iter().any(|a| {
        matches!(a, PathAttribute::ExtendedCommunities(c)
            if c.iter().any(|x| x.as_router_mac().is_some()))
    });
    assert!(!has_rmac, "GW-IP route must omit the Router MAC extcomm");

    // The companion Type 2 MAC/IP route for the gateway host, on the
    // linked L2VNI, learned from a *remote* VTEP (not ours).
    let gw_mac = MacAddress::new([0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]);
    let overlay = ProjectedOverlayIndexRoute {
        vni: EvpnInstanceId::new(L2VNI).unwrap(),
        host_ip: gateway,
        mac: gw_mac,
        next_hop: ip("10.0.0.9"),
        mobility_sequence: None,
    };

    // Project the originated Type 5 (as if reflected back to us by a
    // peer that does *not* share our local VTEP — use a non-local
    // next hop so the self-origination filter doesn't drop it).
    let projected =
        originated_to_projected(&originated.route, &originated.attributes, ip("10.0.0.9"));
    let table = project_ip_prefix_routes_with_overlay_index(&vrfs, vec![projected], vec![overlay]);

    assert!(
        table.drops().is_empty(),
        "the natively-originated GW-IP route must resolve, got drops: {:?}",
        table.drops(),
    );
    let entries: Vec<_> = table.for_vrf(IpVrfId::new(5000).unwrap()).collect();
    assert_eq!(entries.len(), 1, "exactly one resolved prefix");
    let entry = entries[0].1;
    assert_eq!(
        entry.next_hop,
        ip("10.0.0.9"),
        "resolved next hop is the gateway host's Type 2 VTEP, not the Type 5 originator",
    );
    assert_eq!(
        entry.router_mac, gw_mac,
        "resolved inner MAC is the gateway host's Type 2 MAC",
    );
    assert_eq!(entry.l3vni, 5000);
}

#[test]
fn natively_originated_esi_type5_has_rfc9136_overlay_index_shape() {
    let vrfs = esi_vrf_table(100);
    let vrf = vrfs.get("tenant-blue").unwrap();
    let local = LocalIpRoute::v4(Ipv4Prefix::new("192.168.50.0".parse().unwrap(), 24))
        .with_gateway(Some(ip("10.1.1.5")));
    let originated = originate_ip_prefix_route(vrf, &local).unwrap();

    let EvpnRoute::IpPrefix(prefix) = &originated.route else {
        panic!("expected Type 5");
    };
    assert_eq!(prefix.esi, esi(), "ESI is the overlay index");
    assert_eq!(
        prefix.gateway,
        ip("0.0.0.0"),
        "Gateway Address stays zero so the route does not carry two overlay indexes"
    );
    assert_eq!(
        prefix.label.as_vni(),
        5000,
        "L3VNI remains in the label slot, matching the GW-IP shape"
    );

    let ext_comms: Vec<_> = originated
        .attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::ExtendedCommunities(c) => Some(c.clone()),
            _ => None,
        })
        .unwrap_or_default();
    assert_eq!(
        ext_comms
            .iter()
            .filter_map(|c| c.as_router_mac())
            .collect::<Vec<_>>(),
        vec![overlay_mac().octets()],
        "ESI overlay-index routes carry the configured virtual/transit Router MAC"
    );
}

#[test]
fn gateway_ip_type5_holds_unresolved_when_companion_type2_absent() {
    // ADR-0087 decision 2: origination is not gated on the Type 2 —
    // the route is held unresolved (an observable drop), not silently
    // dropped at origination. The receive side surfaces it.
    let vrfs = gw_vrf_table(100);
    let vrf = vrfs.get("tenant-blue").unwrap();
    let local = LocalIpRoute::v4(Ipv4Prefix::new("192.168.50.0".parse().unwrap(), 24))
        .with_gateway(Some(ip("10.1.1.5")));
    let originated = originate_ip_prefix_route(vrf, &local).unwrap();

    let projected =
        originated_to_projected(&originated.route, &originated.attributes, ip("10.0.0.9"));
    let table = project_ip_prefix_routes_with_overlay_index(&vrfs, vec![projected], vec![]);

    assert!(table.is_empty(), "no resolved prefix without the Type 2");
    assert_eq!(table.drops().len(), 1);
    assert_eq!(
        table.drops()[0].reason_label(),
        "unresolved_overlay_index_gateway",
    );
}

#[test]
fn gateway_ip_mode_fallback_type5_resolves_through_interface_less_projection() {
    // ADR-0087 decision 1: a route in gateway_ip mode whose via was
    // not eligible falls back to the interface-less wire shape. This
    // pins the fallback to the receive-side projection too: Gateway
    // Address zero + Router MAC extcomm must still import exactly like
    // the pre-ADR-0087 Type 5 shape.
    let vrfs = gw_vrf_table(100);
    let vrf = vrfs.get("tenant-blue").unwrap();
    let local = LocalIpRoute::v4(Ipv4Prefix::new("192.168.50.0".parse().unwrap(), 24));
    let originated = originate_ip_prefix_route(vrf, &local).unwrap();

    if let EvpnRoute::IpPrefix(p) = &originated.route {
        assert_eq!(
            p.gateway,
            ip("0.0.0.0"),
            "fallback route uses the interface-less Gateway Address",
        );
    } else {
        panic!("expected Type 5");
    }
    let has_rmac = originated.attributes.iter().any(|a| {
        matches!(a, PathAttribute::ExtendedCommunities(c)
            if c.iter().any(|x| x.as_router_mac().is_some()))
    });
    assert!(
        has_rmac,
        "fallback route must keep the Router MAC extcomm for interface-less projection",
    );

    let projected =
        originated_to_projected(&originated.route, &originated.attributes, ip("10.0.0.9"));
    let table = project_ip_prefix_routes_with_overlay_index(&vrfs, vec![projected], Vec::new());

    assert!(
        table.drops().is_empty(),
        "fallback interface-less route must resolve, got drops: {:?}",
        table.drops(),
    );
    let entries: Vec<_> = table.for_vrf(IpVrfId::new(5000).unwrap()).collect();
    assert_eq!(entries.len(), 1, "exactly one resolved fallback prefix");
    let entry = entries[0].1;
    assert_eq!(entry.next_hop, ip("10.0.0.9"));
    assert_eq!(
        entry.router_mac,
        MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
    );
    assert_eq!(entry.l3vni, 5000);
}
