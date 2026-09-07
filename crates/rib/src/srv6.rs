//! RFC 9252 service SID eligibility, separate from UPDATE framing/disposition.

use rustbgpd_wire::{
    Afi, EvpnRoute, PathAttribute, PmsiTunnelType, Safi, Srv6SidInformation, Srv6SidStructure,
    decode_prefix_sid_services,
};

use crate::route::{EvpnRibRoute, Route, VpnRibRoute};

pub(crate) const INVALID_DETAIL: &str =
    "no semantically valid applicable SRv6 service SID; received attributes remain retained";

pub(crate) fn unicast_eligible(route: &Route) -> bool {
    let afi = match route.prefix {
        rustbgpd_wire::Prefix::V4(_) => Afi::Ipv4,
        rustbgpd_wire::Prefix::V6(_) => Afi::Ipv6,
    };
    service_eligible(&route.attributes, (afi, Safi::Unicast), None)
}

pub(crate) fn vpn_eligible(route: &VpnRibRoute) -> bool {
    service_eligible(&route.attributes, route.afi_safi(), None)
}

pub(crate) fn evpn_eligible(route: &EvpnRibRoute) -> bool {
    service_eligible(
        &route.attributes,
        (Afi::L2Vpn, Safi::Evpn),
        Some(&route.route),
    )
}

#[derive(Clone, Copy)]
enum Transposition {
    None,
    Function(u8),
    Argument(u8),
}

/// Interpret only the service encodings specified by RFC 9252 sections 5/6.
/// The inspection model preserves first-service and unknown-type behavior.
/// Ordinary routes do not allocate; SRv6-bearing checks use its decoded vectors.
fn service_eligible(
    attributes: &[PathAttribute],
    family: (Afi, Safi),
    evpn: Option<&EvpnRoute>,
) -> bool {
    if !matches!(
        family,
        (Afi::Ipv4 | Afi::Ipv6, Safi::Unicast | Safi::MplsVpn) | (Afi::L2Vpn, Safi::Evpn)
    ) {
        return true;
    }
    let Some(value) = attributes.iter().find_map(|attribute| match attribute {
        PathAttribute::Unknown(raw) if raw.type_code == 40 => Some(raw.data.as_ref()),
        _ => None,
    }) else {
        return true;
    };
    let l3 = service_transposition(attributes, family, evpn, 5);
    let l2 = service_transposition(attributes, family, evpn, 6);
    if l3.is_none() && l2.is_none() {
        return true;
    }
    let Ok(services) = decode_prefix_sid_services(value) else {
        // Structural failures belong to UPDATE/MRT admission, not this
        // semantic predicate. Preserve their existing disposition contract.
        return true;
    };
    let mut applicable = false;
    for service in services {
        let Some(transposition) = (match service.tlv_type {
            5 => l3,
            6 => l2,
            _ => None,
        }) else {
            continue;
        };
        applicable = true;
        if service
            .sids
            .iter()
            .any(|sid| sid_eligible(sid, transposition))
        {
            return true;
        }
    }
    // Generic Prefix-SID and services outside this route's encoding retain
    // their existing behavior; an unrelated service cannot rescue a bad SID.
    !applicable
}

fn service_transposition(
    attributes: &[PathAttribute],
    family: (Afi, Safi),
    evpn: Option<&EvpnRoute>,
    service: u8,
) -> Option<Transposition> {
    match (family, service) {
        ((Afi::Ipv4 | Afi::Ipv6, Safi::Unicast), 5) => Some(Transposition::None),
        ((Afi::Ipv4 | Afi::Ipv6, Safi::MplsVpn), 5) => Some(Transposition::Function(20)),
        ((Afi::L2Vpn, Safi::Evpn), _) => match (evpn?, service) {
            (EvpnRoute::EadPerEs(_), 6) => {
                let has_label = attributes.iter().any(|attribute| {
                    matches!(attribute, PathAttribute::ExtendedCommunities(values)
                        if values.iter().any(|value| value.as_esi_label().is_some()))
                });
                Some(Transposition::Argument(if has_label { 24 } else { 0 }))
            }
            (EvpnRoute::EadPerEvi(_) | EvpnRoute::MacIp(_), 6) | (EvpnRoute::IpPrefix(_), 5) => {
                Some(Transposition::Function(24))
            }
            (EvpnRoute::MacIp(route), 5) if route.ip.is_some() => {
                Some(Transposition::Function(if route.label2.is_some() {
                    24
                } else {
                    0
                }))
            }
            (EvpnRoute::Imet(_), 6) => {
                let ingress_replication = attributes
                    .iter()
                    .find_map(PathAttribute::pmsi_tunnel)
                    .is_some_and(|pmsi| pmsi.tunnel_type == PmsiTunnelType::IngressReplication);
                Some(Transposition::Function(if ingress_replication {
                    24
                } else {
                    0
                }))
            }
            _ => None,
        },
        _ => None,
    }
}

fn sid_eligible(sid: &Srv6SidInformation, transposition: Transposition) -> bool {
    // RFC 9819 requires Structure for argument-capable End.DT2M (24), even
    // when no argument is used. An unrecognized behavior alone is not invalid.
    if sid.endpoint_behavior == 24 && sid.structures.is_empty() {
        return false;
    }
    sid.structures
        .iter()
        .all(|structure| structure_eligible(sid, *structure, transposition))
}

fn structure_eligible(
    sid: &Srv6SidInformation,
    structure: Srv6SidStructure,
    transposition: Transposition,
) -> bool {
    // End.DT2M is the argument-capable behavior understood here. RFC 9252
    // section 3.2.1 requires ignoring unknown behaviors with arguments; the
    // known non-argument behaviors likewise require AL=0.
    if structure.argument_length != 0 && sid.endpoint_behavior != 24 {
        return false;
    }
    let total = u16::from(structure.locator_block_length)
        + u16::from(structure.locator_node_length)
        + u16::from(structure.function_length)
        + u16::from(structure.argument_length);
    let offset = u16::from(structure.transposition_offset);
    let length = u16::from(structure.transposition_length);
    // Verified erratum 7817 permits equality, including a fully transposed
    // trailing Function. Never implement the original strict-greater typo.
    if total > 128 || offset + length > total {
        return false;
    }
    if length == 0 {
        return offset == 0;
    }
    let locator =
        u16::from(structure.locator_block_length) + u16::from(structure.locator_node_length);
    let (width, component, start) = match transposition {
        Transposition::None => return false,
        Transposition::Function(width) => (width, structure.function_length, locator),
        Transposition::Argument(width) => (
            width,
            structure.argument_length,
            locator + u16::from(structure.function_length),
        ),
    };
    // RFC 9252 section 4 and the family label definitions identify which
    // component is transposed; a same-size slice of the Locator is not it.
    if length > u16::from(width) || offset < start || offset + length > start + u16::from(component)
    {
        return false;
    }
    let transposed_bits = (u128::MAX >> (128 - length)) << (128 - offset - length);
    u128::from(sid.sid_value) & transposed_bits == 0
}

#[cfg(test)]
pub(crate) mod tests {
    use std::net::Ipv6Addr;

    use rustbgpd_wire::{
        EthernetSegmentIdentifier, EthernetTagId, EvpnEadPerEs, EvpnEadPerEvi, EvpnEs, EvpnImet,
        EvpnIpPrefixRoute, EvpnIpPrefixValue, EvpnMacIp, ExtendedCommunity, MacAddress, MplsLabel,
        PmsiTunnel, PmsiTunnelIdentifier, RawAttribute, RouteDistinguisher,
    };

    use super::*;

    pub(crate) fn service_attribute(
        kind: u8,
        sid: Ipv6Addr,
        behavior: u16,
        structure: Option<[u8; 6]>,
    ) -> PathAttribute {
        let mut information = vec![0];
        information.extend(sid.octets());
        information.push(0);
        information.extend(behavior.to_be_bytes());
        information.push(0);
        if let Some(structure) = structure {
            information.extend([1, 0, 6]);
            information.extend(structure);
        }
        let mut service = vec![0, 1];
        service.extend(u16::try_from(information.len()).unwrap().to_be_bytes());
        service.extend(information);
        let mut data = vec![kind];
        data.extend(u16::try_from(service.len()).unwrap().to_be_bytes());
        data.extend(service);
        PathAttribute::Unknown(RawAttribute {
            flags: 0xe0,
            type_code: 40,
            data: data.into(),
        })
    }

    fn append_service(attribute: &mut PathAttribute, extra: PathAttribute) {
        let PathAttribute::Unknown(attribute) = attribute else {
            panic!("raw service fixture");
        };
        let PathAttribute::Unknown(extra) = extra else {
            panic!("raw service fixture");
        };
        let mut value = attribute.data.to_vec();
        value.extend(extra.data);
        attribute.data = value.into();
    }

    #[test]
    fn structure_limits_distinguish_unlabeled_vpn_and_evpn() {
        let sid = "2001:db8:111:1::".parse().unwrap();
        let mac = EvpnRoute::MacIp(EvpnMacIp {
            rd: RouteDistinguisher([0; 8]),
            esi: EthernetSegmentIdentifier::ZERO,
            ethernet_tag: EthernetTagId(0),
            mac: MacAddress([0, 1, 2, 3, 4, 5]),
            ip: None,
            label1: MplsLabel::new(0x30),
            label2: None,
        });
        for (structure, unicast, vpn, evpn) in [
            ([40, 24, 16, 0, 0, 0], true, true, true),
            ([40, 24, 16, 0, 16, 64], false, true, true), // Erratum equality.
            ([40, 24, 32, 0, 20, 64], false, true, true),
            ([40, 24, 32, 0, 21, 64], false, false, true),
            ([40, 24, 32, 0, 24, 64], false, false, true),
            ([40, 24, 32, 0, 25, 64], false, false, false),
            ([40, 24, 16, 0, 17, 63], false, false, false), // Exceeds FL.
            ([40, 24, 16, 0, 1, 63], false, false, false),  // Locator, not Function.
            ([100, 24, 16, 0, 0, 0], false, false, false),
            ([40, 24, 16, 0, 16, 65], false, false, false),
            ([40, 24, 16, 0, 0, 1], false, false, false),
            ([255; 6], false, false, false),
        ] {
            let l3 = [service_attribute(5, sid, 19, Some(structure))];
            assert_eq!(
                service_eligible(&l3, (Afi::Ipv6, Safi::Unicast), None),
                unicast,
                "unicast {structure:?}"
            );
            assert_eq!(
                service_eligible(&l3, (Afi::Ipv4, Safi::MplsVpn), None),
                vpn,
                "VPN {structure:?}"
            );
            let l2 = [service_attribute(6, sid, 23, Some(structure))];
            assert_eq!(
                service_eligible(&l2, (Afi::L2Vpn, Safi::Evpn), Some(&mac)),
                evpn,
                "EVPN {structure:?}"
            );
        }
        let nonzero_transposed = [service_attribute(
            5,
            "2001:db8:111:1:1::".parse().unwrap(),
            19,
            Some([40, 24, 16, 0, 16, 64]),
        )];
        assert!(!service_eligible(
            &nonzero_transposed,
            (Afi::Ipv6, Safi::MplsVpn),
            None
        ));
    }

    #[test]
    fn unknown_behaviors_and_argument_capable_zero_sid() {
        let sid = Ipv6Addr::UNSPECIFIED;
        let ead = EvpnRoute::EadPerEs(EvpnEadPerEs {
            rd: RouteDistinguisher([0; 8]),
            esi: EthernetSegmentIdentifier::new([1; 10]),
            ethernet_tag: EthernetTagId::MAX_ET,
            label: MplsLabel::new(0x30),
        });
        for (behavior, structure, expected) in [
            (0xffff, None, true),
            (0xffff, Some([40, 24, 16, 0, 0, 0]), true),
            (0xffff, Some([40, 24, 16, 16, 0, 0]), false),
            (23, Some([40, 24, 16, 16, 0, 0]), false),
            (24, None, false),
            (24, Some([40, 24, 16, 0, 0, 0]), true), // RFC 9819 EAD without ARG.
            (24, Some([40, 24, 16, 16, 0, 0]), true),
        ] {
            assert_eq!(
                service_eligible(
                    &[service_attribute(6, sid, behavior, structure)],
                    (Afi::L2Vpn, Safi::Evpn),
                    Some(&ead)
                ),
                expected,
                "behavior {behavior} structure {structure:?}"
            );
        }
        let transposed = service_attribute(6, sid, 24, Some([40, 24, 16, 16, 16, 80]));
        assert!(!service_eligible(
            std::slice::from_ref(&transposed),
            (Afi::L2Vpn, Safi::Evpn),
            Some(&ead)
        ));
        assert!(service_eligible(
            &[
                transposed,
                PathAttribute::ExtendedCommunities(vec![ExtendedCommunity::esi_label(false, 7)]),
            ],
            (Afi::L2Vpn, Safi::Evpn),
            Some(&ead)
        ));
        assert!(
            !service_eligible(
                &[
                    service_attribute(6, sid, 24, Some([40, 24, 16, 16, 16, 64])),
                    PathAttribute::ExtendedCommunities(vec![ExtendedCommunity::esi_label(
                        false, 7
                    )]),
                ],
                (Afi::L2Vpn, Safi::Evpn),
                Some(&ead)
            ),
            "Function bits cannot be transposed through the ESI Argument label"
        );
    }

    #[test]
    fn only_first_applicable_service_can_supply_a_valid_sid() {
        let sid = "2001:db8:111:1::".parse().unwrap();
        let invalid = service_attribute(5, sid, 19, Some([100, 24, 16, 0, 0, 0]));
        let valid = service_attribute(5, sid, 19, Some([40, 24, 16, 0, 0, 0]));
        let mut duplicate = invalid.clone();
        append_service(&mut duplicate, valid.clone());
        assert!(!service_eligible(
            &[duplicate],
            (Afi::Ipv4, Safi::MplsVpn),
            None
        ));
        let mut mixed = invalid;
        append_service(
            &mut mixed,
            service_attribute(6, sid, 23, Some([40, 24, 16, 0, 0, 0])),
        );
        assert!(!service_eligible(
            std::slice::from_ref(&mixed),
            (Afi::Ipv4, Safi::MplsVpn),
            None
        ));
        // A later valid SID Information entry within the first service is
        // eligible; this differs from a later duplicate service instance.
        let PathAttribute::Unknown(mut raw) = mixed else {
            panic!("raw fixture");
        };
        let PathAttribute::Unknown(valid) = valid else {
            panic!("raw fixture");
        };
        let first_service_length = usize::from(u16::from_be_bytes([raw.data[1], raw.data[2]]));
        let mut data = raw.data[..3 + first_service_length].to_vec();
        data.extend_from_slice(&valid.data[4..]);
        let length = u16::try_from(data.len() - 3).unwrap().to_be_bytes();
        data[1..3].copy_from_slice(&length);
        raw.data = data.into();
        assert!(service_eligible(
            &[PathAttribute::Unknown(raw)],
            (Afi::Ipv4, Safi::MplsVpn),
            None
        ));
    }

    #[test]
    fn mac_ip_services_and_unsupported_encodings_keep_their_scope() {
        let sid = "2001:db8:111:1::".parse().unwrap();
        let invalid_l2 = service_attribute(6, sid, 23, Some([100, 24, 16, 0, 0, 0]));
        let valid_l3 = service_attribute(5, sid, 19, Some([40, 24, 16, 0, 16, 64]));
        let mut both = invalid_l2;
        append_service(&mut both, valid_l3.clone());
        let mut route = EvpnMacIp {
            rd: RouteDistinguisher::ZERO,
            esi: EthernetSegmentIdentifier::ZERO,
            ethernet_tag: EthernetTagId(0),
            mac: MacAddress([0, 1, 2, 3, 4, 5]),
            ip: Some("192.0.2.1".parse().unwrap()),
            label1: MplsLabel::new(0),
            label2: Some(MplsLabel::new(0)),
        };
        assert!(service_eligible(
            std::slice::from_ref(&both),
            (Afi::L2Vpn, Safi::Evpn),
            Some(&EvpnRoute::MacIp(route.clone()))
        ));
        route.label2 = None;
        assert!(!service_eligible(
            std::slice::from_ref(&both),
            (Afi::L2Vpn, Safi::Evpn),
            Some(&EvpnRoute::MacIp(route.clone()))
        ));
        route.ip = None;
        assert!(!service_eligible(
            std::slice::from_ref(&both),
            (Afi::L2Vpn, Safi::Evpn),
            Some(&EvpnRoute::MacIp(route))
        ));
        let prefix = EvpnRoute::IpPrefix(EvpnIpPrefixRoute {
            rd: RouteDistinguisher::ZERO,
            esi: EthernetSegmentIdentifier::ZERO,
            ethernet_tag: EthernetTagId(0),
            prefix: EvpnIpPrefixValue::V4(rustbgpd_wire::Ipv4Prefix::new(
                "192.0.2.0".parse().unwrap(),
                24,
            )),
            gateway: "0.0.0.0".parse().unwrap(),
            label: MplsLabel::new(0),
        });
        assert!(service_eligible(
            &[valid_l3],
            (Afi::L2Vpn, Safi::Evpn),
            Some(&prefix)
        ));
        let invalid = [service_attribute(5, sid, 19, Some([255; 6]))];
        for family in [
            (Afi::Ipv4, Safi::LabeledUnicast),
            (Afi::Ipv4, Safi::FlowSpec),
            (Afi::L2Vpn, Safi::Evpn),
        ] {
            let es = EvpnRoute::Es(EvpnEs {
                rd: RouteDistinguisher::ZERO,
                esi: EthernetSegmentIdentifier::new([1; 10]),
                originator_ip: sid.into(),
            });
            assert!(service_eligible(&invalid, family, Some(&es)));
        }
        assert!(service_eligible(&[], (Afi::Ipv4, Safi::MplsVpn), None));
    }

    #[test]
    fn evpn_transposition_uses_the_actual_label_field() {
        let sid = "2001:db8:111:1::".parse().unwrap();
        let l2 = service_attribute(6, sid, 23, Some([40, 24, 16, 0, 16, 64]));
        let evi = EvpnRoute::EadPerEvi(EvpnEadPerEvi {
            rd: RouteDistinguisher([0; 8]),
            esi: EthernetSegmentIdentifier::new([1; 10]),
            ethernet_tag: EthernetTagId(0),
            label: MplsLabel::new(0x30),
        });
        assert!(service_eligible(
            std::slice::from_ref(&l2),
            (Afi::L2Vpn, Safi::Evpn),
            Some(&evi)
        ));
        let imet = EvpnRoute::Imet(EvpnImet {
            rd: RouteDistinguisher([0; 8]),
            ethernet_tag: EthernetTagId(0),
            originator_ip: sid.into(),
        });
        assert!(!service_eligible(
            std::slice::from_ref(&l2),
            (Afi::L2Vpn, Safi::Evpn),
            Some(&imet)
        ));
        assert!(service_eligible(
            &[
                l2,
                PathAttribute::PmsiTunnel(PmsiTunnel {
                    flags: 0,
                    tunnel_type: PmsiTunnelType::IngressReplication,
                    mpls_label: 0x30,
                    tunnel_identifier: PmsiTunnelIdentifier::Ipv6(sid),
                }),
            ],
            (Afi::L2Vpn, Safi::Evpn),
            Some(&imet)
        ));
    }
}
