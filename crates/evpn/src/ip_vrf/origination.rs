//! Pure-logic Type 5 origination — local VRF route → outbound RT-5
//! NLRI + path attributes.
//!
//! Mirrors `crates/evpn/src/origination.rs` (Type 2) and
//! `crates/evpn/src/origination_es.rs` (Type 1 / Type 4) for the
//! Gate 9 IRB case. ADR-0058 pins the symmetric Interface-less
//! RT-5 shape (RFC 9136 §4.4.2); ADR-0087 adds the opt-in GW-IP
//! overlay-index shape (RFC 9136 §4.1/§4.2). The on-wire fields are:
//!
//! - `prefix`: the kernel route key (IPv4 or IPv6).
//! - `gateway`: zero (`0.0.0.0` / `::`) in the Interface-less model
//!   (inner-MAC resolution via the Router MAC extcomm); the vetted
//!   kernel-route via in GW-IP mode (receivers resolve recursively
//!   through the gateway host's Type 2 MAC/IP route).
//! - `label`: the IP-VRF's L3VNI in the 24-bit MPLS label slot —
//!   in *both* modes. ADR-0087 decision 4 deliberately deviates from
//!   the RFC 9136 §3.1 SHOULD-zero for overlay-index routes: our own
//!   receive side enforces `label == L3VNI` before overlay
//!   resolution, and FRR's gateway-ip RT-5s keep the VNI too.
//! - `esi`: all-zero (multihomed-IP-VRF is out of scope for Gate 9;
//!   validated at config load, asserted by the builder). Also a hard
//!   RFC 9136 §3.2 requirement in GW-IP mode — ESI and GW IP must
//!   not both be non-zero.
//! - `ethernet_tag`: zero (Type 5 doesn't use the EVI tag concept).
//!
//! And the non-MP path attribute list (the only thing this layer
//! emits — the next-hop is carried separately on
//! [`OriginatedIpPrefixRoute::next_hop`] for the encoder to fold
//! into `MP_REACH_NLRI` at send time, NOT as a standalone
//! `PathAttribute::NextHop`):
//!
//! - `ORIGIN = IGP` — these are routes from the local kernel.
//! - `AS_PATH = empty` — iBGP origination puts no ASN; eBGP wrapping
//!   is the transport's job.
//! - `ExtendedCommunities`: { Route Target ×N from
//!   `IpVrf::route_targets`, BGP Encapsulation = 8 (VXLAN), and —
//!   only when the gateway is zero — Router MAC extcomm =
//!   `IpVrf::router_mac`. GW-IP routes omit the Router MAC: RFC 9136
//!   §3.2 makes it ignored-if-present when the GW IP is the overlay
//!   index, and the inner MAC comes from the resolved Type 2. }
//!
//! Pure: no I/O, no tokio. The daemon-side supervisor calls this once
//! per local kernel route change and hands the result to the RIB
//! injection channel.

use std::net::IpAddr;

use rustbgpd_wire::{
    AsPath, EthernetSegmentIdentifier, EthernetTagId, EvpnIpPrefixRoute, EvpnIpPrefixValue,
    EvpnRoute, ExtendedCommunity, Ipv4Prefix, Ipv6Prefix, MplsLabel, Origin, PathAttribute,
};

#[cfg(test)]
use rustbgpd_wire::MacAddress;

use crate::ip_vrf::{IpVrf, OverlayIndexMode};

/// Subset of an `[[evpn_ip_vrfs]]` entry plus a local kernel-route
/// prefix, enough to build one outbound Type 5 advertisement. The
/// daemon constructs this at the call site from `IpVrf` + the
/// netlink-observed `RTM_NEWROUTE` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalIpRoute {
    /// Prefix to advertise (IPv4 or IPv6).
    pub prefix: EvpnIpPrefixValue,
    /// Vetted GW-IP overlay-index gateway (ADR-0087). `None`
    /// originates the Interface-less shape. Callers run the kernel
    /// via through [`select_overlay_gateway`] first — this field is
    /// the *output* of that selection, not the raw `RTA_GATEWAY`.
    pub gateway: Option<IpAddr>,
}

impl LocalIpRoute {
    /// Build from an IPv4 prefix (Interface-less — no gateway).
    #[must_use]
    pub fn v4(prefix: Ipv4Prefix) -> Self {
        Self {
            prefix: EvpnIpPrefixValue::V4(prefix),
            gateway: None,
        }
    }

    /// Build from an IPv6 prefix (Interface-less — no gateway).
    #[must_use]
    pub fn v6(prefix: Ipv6Prefix) -> Self {
        Self {
            prefix: EvpnIpPrefixValue::V6(prefix),
            gateway: None,
        }
    }

    /// Attach a vetted GW-IP overlay-index gateway (ADR-0087).
    #[must_use]
    pub fn with_gateway(mut self, gateway: Option<IpAddr>) -> Self {
        self.gateway = gateway;
        self
    }
}

/// Decide whether a kernel route's via becomes the RT-5 Gateway
/// Address (ADR-0087 decision 1). Returns `Some(via)` only when all
/// of the following hold; everything else originates Interface-less:
///
/// 1. The IP-VRF opted in (`overlay_index_mode = "gateway_ip"`).
/// 2. The route has a via and it is a specified (non-zero) address.
/// 3. The via's family matches the prefix's family — the RT-5
///    Gateway field shares the prefix's wire family, so a
///    cross-family via is unrepresentable.
/// 4. The via is contained in one of `connected_subnets` — the
///    `RouteSource::Connected` prefixes observed in the same IP-VRF
///    this reconcile pass, excluding /0. A via outside every
///    connected subnet is not a directly attached overlay host, so
///    no Type 2 will ever resolve it; advertising it as a GW IP
///    would strand the route at receivers
///    (`unresolved_overlay_index_gateway`), while the Interface-less
///    fallback always forwards correctly through this VTEP's FIB.
///
/// Pure; the daemon-side originator feeds the result into
/// [`LocalIpRoute::with_gateway`].
#[must_use]
pub fn select_overlay_gateway(
    vrf: &IpVrf,
    prefix: EvpnIpPrefixValue,
    via: Option<IpAddr>,
    connected_subnets: &[EvpnIpPrefixValue],
) -> Option<IpAddr> {
    if vrf.overlay_index_mode != OverlayIndexMode::GatewayIp {
        return None;
    }
    let via = via?;
    if via.is_unspecified() {
        return None;
    }
    let family_ok = matches!(
        (prefix, via),
        (EvpnIpPrefixValue::V4(_), IpAddr::V4(_)) | (EvpnIpPrefixValue::V6(_), IpAddr::V6(_))
    );
    if !family_ok {
        return None;
    }
    connected_subnets
        .iter()
        .any(|subnet| prefix_contains(*subnet, via))
        .then_some(via)
}

/// Whether `ip` falls inside `subnet`. `/0` never matches — a
/// (pathological) connected default route must not whitelist every
/// via (ADR-0087 decision 1).
fn prefix_contains(subnet: EvpnIpPrefixValue, ip: IpAddr) -> bool {
    match (subnet, ip) {
        (EvpnIpPrefixValue::V4(p), IpAddr::V4(v4)) => {
            if p.len == 0 || p.len > 32 {
                return false;
            }
            let mask = u32::MAX << (32 - u32::from(p.len));
            (u32::from(v4) & mask) == (u32::from(p.addr) & mask)
        }
        (EvpnIpPrefixValue::V6(p), IpAddr::V6(v6)) => {
            if p.len == 0 || p.len > 128 {
                return false;
            }
            let mask = u128::MAX << (128 - u32::from(p.len));
            (u128::from(v6) & mask) == (u128::from(p.addr) & mask)
        }
        _ => false,
    }
}

/// One outbound Type 5 advertisement, ready to hand to the RIB
/// injection channel. Holds the `EvpnRoute` (which becomes the NLRI
/// the wire encoder serializes via `MP_REACH_NLRI`) and the
/// non-MP-REACH path attributes that ride alongside.
///
/// `MP_REACH_NLRI` itself is added at encode time, not here — the
/// transport already owns that wrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginatedIpPrefixRoute {
    /// The EVPN Type 5 NLRI to advertise.
    pub route: EvpnRoute,
    /// Non-MP path attributes (`Origin`, empty `AsPath`,
    /// `ExtendedCommunities`). The next-hop is *not* in this list —
    /// see [`Self::next_hop`].
    pub attributes: Vec<PathAttribute>,
    /// Local VTEP IP this advertisement names as `NEXT_HOP`. Carried
    /// separately from `attributes` so the wire encoder folds it into
    /// `MP_REACH_NLRI` at send time (the right place for an MP-BGP
    /// next-hop) instead of also emitting a standalone
    /// `PathAttribute::NextHop`.
    pub next_hop: IpAddr,
}

/// Build a single outbound Type 5 advertisement for a kernel route
/// inside the named IP-VRF.
///
/// Pure. Panics never; returns a structural error when the prefix's
/// IP family is incompatible with the IP-VRF's `local_vtep_ip`
/// (RFC 9136 §3 forbids family-cross IRB in the Interface-less
/// model — the next-hop, gateway, and prefix must agree on family
/// for the receiving PE's recursive lookup).
///
/// # Errors
/// Returns [`OriginationError::FamilyMismatch`] when the prefix is
/// IPv4 but the VRF's `local_vtep_ip` is IPv6 (or vice versa), and
/// [`OriginationError::GatewayFamilyMismatch`] when a supplied
/// gateway's family disagrees with the prefix (the RT-5 Gateway
/// field shares the prefix's wire family). The daemon must filter
/// both upstream ([`select_overlay_gateway`] never emits a
/// cross-family gateway) — these are the structural safety nets.
pub fn originate_ip_prefix_route(
    vrf: &IpVrf,
    route: &LocalIpRoute,
) -> Result<OriginatedIpPrefixRoute, OriginationError> {
    let family_ok = matches!(
        (route.prefix, vrf.local_vtep_ip),
        (EvpnIpPrefixValue::V4(_), IpAddr::V4(_)) | (EvpnIpPrefixValue::V6(_), IpAddr::V6(_))
    );
    if !family_ok {
        return Err(OriginationError::FamilyMismatch {
            vrf: vrf.name.clone(),
            prefix_family: family_of(route.prefix),
            local_vtep_ip: vrf.local_vtep_ip,
        });
    }
    if let Some(gw) = route.gateway {
        let gw_family_ok = matches!(
            (route.prefix, gw),
            (EvpnIpPrefixValue::V4(_), IpAddr::V4(_)) | (EvpnIpPrefixValue::V6(_), IpAddr::V6(_))
        );
        if !gw_family_ok {
            return Err(OriginationError::GatewayFamilyMismatch {
                vrf: vrf.name.clone(),
                prefix_family: family_of(route.prefix),
                gateway: gw,
            });
        }
    }

    // Build the Type 5 NLRI. esi = 0, ethernet_tag = 0; label = the
    // L3VNI in the 24-bit label slot (RFC 8365 maps VXLAN VNI through
    // the MPLS label field on the wire — kept in GW-IP mode too, see
    // ADR-0087 decision 4). Gateway: zero in the Interface-less
    // model; the vetted via in GW-IP mode.
    let gateway = route.gateway.unwrap_or(match route.prefix {
        EvpnIpPrefixValue::V4(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        EvpnIpPrefixValue::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
    });
    let nlri = EvpnRoute::IpPrefix(EvpnIpPrefixRoute {
        rd: vrf.rd,
        esi: EthernetSegmentIdentifier::ZERO,
        ethernet_tag: EthernetTagId(0),
        prefix: route.prefix,
        gateway,
        label: MplsLabel::new(vrf.id.as_u32()),
    });

    // Path attributes. The wire encoder adds MP_REACH_NLRI at send
    // time using `next_hop` from the OriginatedIpPrefixRoute return,
    // so the attribute list does not contain MP_REACH here.
    let mut ext_comms: Vec<ExtendedCommunity> = Vec::with_capacity(vrf.route_targets.len() + 2);
    for rt in &vrf.route_targets {
        ext_comms.push(rt.to_extended_community());
    }
    // BGP Encapsulation = VXLAN (8) — RFC 8365 §6.
    ext_comms.push(ExtendedCommunity::bgp_encapsulation(VXLAN_ENCAP));
    if route.gateway.is_none() {
        // Router MAC (RFC 9135 §4.2 / RFC 9136). Subtype 0x03 of
        // opaque type 0x06; the wire helper handles the byte layout.
        // Interface-less only: with a GW-IP overlay index the inner
        // MAC comes from the resolved Type 2 and RFC 9136 §3.2 makes
        // a Router MAC extcomm ignored-if-present, so we omit it
        // (ADR-0087 decision 4).
        ext_comms.push(ExtendedCommunity::router_mac(vrf.router_mac.octets()));
    }

    let attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: Vec::new(),
        }),
        PathAttribute::ExtendedCommunities(ext_comms),
    ];

    Ok(OriginatedIpPrefixRoute {
        route: nlri,
        attributes,
        next_hop: vrf.local_vtep_ip,
    })
}

/// RFC 8365 §6 — VXLAN tunnel type in the BGP Encapsulation extcomm.
const VXLAN_ENCAP: u16 = 8;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OriginationError {
    #[error(
        "evpn_ip_vrfs[{vrf}]: prefix family ({prefix_family}) does not match local_vtep_ip ({local_vtep_ip}); \
         RFC 9136 Interface-less IRB requires the family of prefix, gateway, and next-hop to agree"
    )]
    FamilyMismatch {
        vrf: String,
        prefix_family: &'static str,
        local_vtep_ip: IpAddr,
    },
    #[error(
        "evpn_ip_vrfs[{vrf}]: gateway {gateway} family does not match prefix family ({prefix_family}); \
         the RT-5 Gateway Address shares the prefix's wire family (RFC 9136 §3.1)"
    )]
    GatewayFamilyMismatch {
        vrf: String,
        prefix_family: &'static str,
        gateway: IpAddr,
    },
}

fn family_of(p: EvpnIpPrefixValue) -> &'static str {
    match p {
        EvpnIpPrefixValue::V4(_) => "ipv4",
        EvpnIpPrefixValue::V6(_) => "ipv6",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip_vrf::IpVrfId;
    use rustbgpd_wire::RouteDistinguisher;

    fn vrf(local: &str) -> IpVrf {
        IpVrf::new(
            "tenant-blue".to_string(),
            IpVrfId::new(5000).unwrap(),
            "65000:5000".parse::<RouteDistinguisher>().unwrap(),
            vec!["65000:5000".parse().unwrap()],
            local.parse().unwrap(),
            MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            "vrf-blue".to_string(),
            "vni5000".to_string(),
            5000,
        )
        .unwrap()
    }

    fn route_v4(addr: [u8; 4], len: u8) -> LocalIpRoute {
        LocalIpRoute::v4(Ipv4Prefix::new(std::net::Ipv4Addr::from(addr), len))
    }

    fn route_v6(addr: [u8; 16], len: u8) -> LocalIpRoute {
        LocalIpRoute::v6(Ipv6Prefix::new(std::net::Ipv6Addr::from(addr), len))
    }

    #[test]
    fn happy_path_v4_origination() {
        let v = vrf("10.0.0.1");
        let r = route_v4([10, 1, 0, 0], 24);
        let out = originate_ip_prefix_route(&v, &r).unwrap();
        assert_eq!(out.next_hop, "10.0.0.1".parse::<IpAddr>().unwrap());
        match &out.route {
            EvpnRoute::IpPrefix(p) => {
                assert_eq!(p.label.as_vni(), 5000);
                assert_eq!(p.esi, EthernetSegmentIdentifier::ZERO);
                assert_eq!(p.ethernet_tag.0, 0);
                assert_eq!(p.gateway, IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                assert!(matches!(p.prefix, EvpnIpPrefixValue::V4(_)));
            }
            other => panic!("expected IpPrefix, got {other:?}"),
        }
    }

    #[test]
    fn attribute_list_carries_origin_igp_empty_as_path_and_extcomms() {
        let v = vrf("10.0.0.1");
        let r = route_v4([10, 1, 0, 0], 24);
        let out = originate_ip_prefix_route(&v, &r).unwrap();

        // ORIGIN = IGP
        assert!(
            out.attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::Origin(Origin::Igp)))
        );
        // AS_PATH is empty (iBGP origination)
        let has_empty_aspath = out
            .attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::AsPath(ap) if ap.is_empty()));
        assert!(has_empty_aspath, "AS_PATH must be present and empty");
    }

    #[test]
    fn ext_comms_include_rt_encap_and_router_mac() {
        let v = vrf("10.0.0.1");
        let r = route_v4([10, 1, 0, 0], 24);
        let out = originate_ip_prefix_route(&v, &r).unwrap();

        let ext_comms = out
            .attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::ExtendedCommunities(c) => Some(c.clone()),
                _ => None,
            })
            .expect("ExtendedCommunities attribute present");

        // Exactly one VXLAN encap extcomm.
        let encap: Vec<_> = ext_comms
            .iter()
            .filter_map(|c| c.as_bgp_encapsulation())
            .collect();
        assert_eq!(encap, vec![VXLAN_ENCAP]);

        // Exactly one Router MAC extcomm matching the configured MAC.
        let macs: Vec<_> = ext_comms.iter().filter_map(|c| c.as_router_mac()).collect();
        assert_eq!(macs, vec![[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]]);

        // At least one Route Target — exact decode happens in the wire
        // crate's tests; here we just confirm one is present.
        let any_rt = ext_comms.iter().any(|c| c.route_target().is_some());
        assert!(any_rt, "at least one route-target extcomm must be present");
    }

    #[test]
    fn family_mismatch_v4_prefix_v6_vtep_is_rejected() {
        let v = vrf("2001:db8::1");
        let r = route_v4([10, 1, 0, 0], 24);
        let err = originate_ip_prefix_route(&v, &r).unwrap_err();
        assert!(matches!(err, OriginationError::FamilyMismatch { .. }));
    }

    #[test]
    fn family_mismatch_v6_prefix_v4_vtep_is_rejected() {
        let v = vrf("10.0.0.1");
        let r = route_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            32,
        );
        let err = originate_ip_prefix_route(&v, &r).unwrap_err();
        assert!(matches!(err, OriginationError::FamilyMismatch { .. }));
    }

    #[test]
    fn v6_prefix_with_v6_vtep_yields_v6_gateway_zero() {
        let v = vrf("2001:db8::1");
        let r = route_v6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            32,
        );
        let out = originate_ip_prefix_route(&v, &r).unwrap();
        match &out.route {
            EvpnRoute::IpPrefix(p) => {
                assert!(matches!(p.prefix, EvpnIpPrefixValue::V6(_)));
                assert_eq!(p.gateway, IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED));
            }
            other => panic!("expected IpPrefix, got {other:?}"),
        }
    }

    #[test]
    fn label_carries_l3vni() {
        let v = vrf("10.0.0.1");
        let r = route_v4([10, 1, 0, 0], 24);
        let out = originate_ip_prefix_route(&v, &r).unwrap();
        if let EvpnRoute::IpPrefix(p) = &out.route {
            assert_eq!(p.label.as_vni(), 5000);
        }
    }

    // --- ADR-0087 GW-IP overlay-index mode ---

    fn gw_vrf(local: &str) -> IpVrf {
        vrf(local).with_overlay_index_mode(OverlayIndexMode::GatewayIp)
    }

    fn v4_prefix(addr: [u8; 4], len: u8) -> EvpnIpPrefixValue {
        EvpnIpPrefixValue::V4(Ipv4Prefix::new(std::net::Ipv4Addr::from(addr), len))
    }

    #[test]
    fn select_gateway_via_on_connected_subnet_is_chosen() {
        let v = gw_vrf("10.0.0.1");
        let connected = [v4_prefix([10, 1, 1, 0], 24)];
        let got = select_overlay_gateway(
            &v,
            v4_prefix([192, 168, 50, 0], 24),
            Some("10.1.1.5".parse().unwrap()),
            &connected,
        );
        assert_eq!(got, Some("10.1.1.5".parse().unwrap()));
    }

    #[test]
    fn select_gateway_via_off_connected_subnet_falls_back() {
        let v = gw_vrf("10.0.0.1");
        let connected = [v4_prefix([10, 1, 1, 0], 24)];
        let got = select_overlay_gateway(
            &v,
            v4_prefix([192, 168, 50, 0], 24),
            Some("10.9.9.1".parse().unwrap()),
            &connected,
        );
        assert_eq!(got, None);
    }

    #[test]
    fn select_gateway_no_via_falls_back() {
        let v = gw_vrf("10.0.0.1");
        let connected = [v4_prefix([10, 1, 1, 0], 24)];
        let got = select_overlay_gateway(&v, v4_prefix([192, 168, 50, 0], 24), None, &connected);
        assert_eq!(got, None);
    }

    #[test]
    fn select_gateway_mode_off_ignores_via_even_on_subnet() {
        let v = vrf("10.0.0.1"); // default interface_less
        let connected = [v4_prefix([10, 1, 1, 0], 24)];
        let got = select_overlay_gateway(
            &v,
            v4_prefix([192, 168, 50, 0], 24),
            Some("10.1.1.5".parse().unwrap()),
            &connected,
        );
        assert_eq!(got, None);
    }

    #[test]
    fn select_gateway_cross_family_via_falls_back() {
        let v = gw_vrf("10.0.0.1");
        let connected = [v4_prefix([10, 1, 1, 0], 24)];
        let got = select_overlay_gateway(
            &v,
            v4_prefix([192, 168, 50, 0], 24),
            Some("2001:db8::5".parse().unwrap()),
            &connected,
        );
        assert_eq!(got, None);
    }

    #[test]
    fn select_gateway_connected_default_route_does_not_whitelist() {
        let v = gw_vrf("10.0.0.1");
        let connected = [v4_prefix([0, 0, 0, 0], 0)];
        let got = select_overlay_gateway(
            &v,
            v4_prefix([192, 168, 50, 0], 24),
            Some("10.1.1.5".parse().unwrap()),
            &connected,
        );
        assert_eq!(got, None, "/0 must not whitelist every via");
    }

    #[test]
    fn select_gateway_v6_via_on_connected_subnet_is_chosen() {
        let v = gw_vrf("2001:db8::1");
        let connected = [EvpnIpPrefixValue::V6(Ipv6Prefix::new(
            "2001:db8:1::".parse().unwrap(),
            64,
        ))];
        let prefix = EvpnIpPrefixValue::V6(Ipv6Prefix::new("2001:db8:50::".parse().unwrap(), 48));
        let got = select_overlay_gateway(
            &v,
            prefix,
            Some("2001:db8:1::5".parse().unwrap()),
            &connected,
        );
        assert_eq!(got, Some("2001:db8:1::5".parse().unwrap()));
    }

    #[test]
    fn gateway_route_carries_gateway_zero_esi_l3vni_and_no_router_mac() {
        let v = gw_vrf("10.0.0.1");
        let r = route_v4([192, 168, 50, 0], 24).with_gateway(Some("10.1.1.5".parse().unwrap()));
        let out = originate_ip_prefix_route(&v, &r).unwrap();
        match &out.route {
            EvpnRoute::IpPrefix(p) => {
                assert_eq!(p.gateway, "10.1.1.5".parse::<IpAddr>().unwrap());
                assert_eq!(p.esi, EthernetSegmentIdentifier::ZERO);
                assert_eq!(p.ethernet_tag.0, 0);
                assert_eq!(p.label.as_vni(), 5000, "L3VNI stays in the label slot");
            }
            other => panic!("expected IpPrefix, got {other:?}"),
        }
        let ext_comms = out
            .attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::ExtendedCommunities(c) => Some(c.clone()),
                _ => None,
            })
            .expect("ExtendedCommunities attribute present");
        assert!(
            ext_comms.iter().all(|c| c.as_router_mac().is_none()),
            "GW-IP routes must not carry a Router MAC extcomm (RFC 9136 §3.2)",
        );
        // RTs + VXLAN encap stay.
        assert!(ext_comms.iter().any(|c| c.route_target().is_some()));
        assert_eq!(
            ext_comms
                .iter()
                .filter_map(|c| c.as_bgp_encapsulation())
                .collect::<Vec<_>>(),
            vec![VXLAN_ENCAP],
        );
        assert_eq!(out.next_hop, "10.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn no_gateway_route_keeps_interface_less_shape_even_in_gateway_mode() {
        let v = gw_vrf("10.0.0.1");
        let r = route_v4([10, 1, 0, 0], 24); // fallback: no vetted gateway
        let out = originate_ip_prefix_route(&v, &r).unwrap();
        match &out.route {
            EvpnRoute::IpPrefix(p) => {
                assert_eq!(p.gateway, IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            }
            other => panic!("expected IpPrefix, got {other:?}"),
        }
        let ext_comms = out
            .attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::ExtendedCommunities(c) => Some(c.clone()),
                _ => None,
            })
            .expect("ExtendedCommunities attribute present");
        assert_eq!(
            ext_comms
                .iter()
                .filter_map(|c| c.as_router_mac())
                .collect::<Vec<_>>(),
            vec![[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]],
            "fallback routes keep the Router MAC extcomm",
        );
    }

    #[test]
    fn gateway_family_mismatch_is_rejected_structurally() {
        let v = gw_vrf("10.0.0.1");
        let r = route_v4([192, 168, 50, 0], 24).with_gateway(Some("2001:db8::5".parse().unwrap()));
        let err = originate_ip_prefix_route(&v, &r).unwrap_err();
        assert!(matches!(
            err,
            OriginationError::GatewayFamilyMismatch { .. }
        ));
    }
}
