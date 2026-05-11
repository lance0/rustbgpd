//! Pure-logic Type 5 origination — local VRF route → outbound RT-5
//! NLRI + path attributes.
//!
//! Mirrors `crates/evpn/src/origination.rs` (Type 2) and
//! `crates/evpn/src/origination_es.rs` (Type 1 / Type 4) for the
//! Gate 9 IRB case. ADR-0058 pins the symmetric Interface-less
//! RT-5 shape (RFC 9136 §4.4.2) — the on-wire fields are:
//!
//! - `prefix`: the kernel route key (IPv4 or IPv6).
//! - `gateway`: zero (`0.0.0.0` / `::`) — Interface-less model uses
//!   the Router MAC extcomm for inner-MAC resolution, not the
//!   gateway field.
//! - `label`: the IP-VRF's L3VNI in the 24-bit MPLS label slot.
//! - `esi`: all-zero (multihomed-IP-VRF is out of scope for Gate 9;
//!   validated at config load, asserted by the builder).
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
//!   `IpVrf::route_targets`, BGP Encapsulation = 8 (VXLAN), Router
//!   MAC extcomm = `IpVrf::router_mac` }.
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

use crate::ip_vrf::IpVrf;

/// Subset of an `[[evpn_ip_vrfs]]` entry plus a local kernel-route
/// prefix, enough to build one outbound Type 5 advertisement. The
/// daemon constructs this at the call site from `IpVrf` + the
/// netlink-observed `RTM_NEWROUTE` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalIpRoute {
    /// Prefix to advertise (IPv4 or IPv6).
    pub prefix: EvpnIpPrefixValue,
}

impl LocalIpRoute {
    /// Build from an IPv4 prefix.
    #[must_use]
    pub fn v4(prefix: Ipv4Prefix) -> Self {
        Self {
            prefix: EvpnIpPrefixValue::V4(prefix),
        }
    }

    /// Build from an IPv6 prefix.
    #[must_use]
    pub fn v6(prefix: Ipv6Prefix) -> Self {
        Self {
            prefix: EvpnIpPrefixValue::V6(prefix),
        }
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
/// IPv4 but the VRF's `local_vtep_ip` is IPv6 (or vice versa). The
/// daemon must filter such routes upstream — this is the structural
/// safety net.
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

    // Build the Type 5 NLRI. Interface-less model: gateway = 0,
    // esi = 0, ethernet_tag = 0; label = the L3VNI in the 24-bit
    // label slot (RFC 8365 maps VXLAN VNI through the MPLS label
    // field on the wire).
    let gateway = match route.prefix {
        EvpnIpPrefixValue::V4(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        EvpnIpPrefixValue::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
    };
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
    // Router MAC (RFC 9135 §4.2 / RFC 9136). Subtype 0x03 of opaque
    // type 0x06; the wire helper handles the byte layout.
    ext_comms.push(ExtendedCommunity::router_mac(vrf.router_mac.octets()));

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
}
