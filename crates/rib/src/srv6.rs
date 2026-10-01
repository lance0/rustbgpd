//! `SRv6` service SID eligibility, separate from UPDATE framing/disposition.

use rustbgpd_wire::{
    Afi, EvpnRoute, PathAttribute, Safi, Srv6SidInformation, Srv6SidStructure,
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

/// Interpret the supported RFC 9252 and RFC 10018 service encodings.
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
                let width = attributes
                    .iter()
                    .find_map(PathAttribute::pmsi_tunnel)
                    .and_then(|pmsi| pmsi.tunnel_type.evpn_srv6_function_bits())
                    .unwrap_or(0);
                Some(Transposition::Function(width))
            }
            _ => None,
        },
        _ => None,
    }
}

/// End.DT2M and its SID-list-compression flavors (RFC 9800): uDT2M with
/// NEXT-CSID (68) and End.DT2M with REPLACE-CSID (124). RFC 9819 section 3
/// applies the same ESI-filtering argument rules to all three.
fn argument_capable(behavior: u16) -> bool {
    matches!(behavior, 24 | 68 | 124)
}

fn sid_eligible(sid: &Srv6SidInformation, transposition: Transposition) -> bool {
    // RFC 9819 requires Structure for the argument-capable End.DT2M family,
    // even when no argument is used. An unrecognized behavior alone is not
    // invalid.
    if argument_capable(sid.endpoint_behavior) && sid.structures.is_empty() {
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
    // The End.DT2M family is the argument-capable behavior understood here.
    // RFC 9252 section 3.2.1 requires ignoring unknown behaviors with
    // arguments; the known non-argument behaviors likewise require AL=0.
    if structure.argument_length != 0 && !argument_capable(sid.endpoint_behavior) {
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

/// Pure RFC 9819 section 3.3 result. Route lookup and egress association are
/// established by the caller; no route selection or forwarding state changes.
pub(crate) struct ArgumentComposition {
    pub status: crate::update::Srv6ArgumentStatus,
    pub sid: Option<std::net::Ipv6Addr>,
    pub detail: &'static str,
}

impl ArgumentComposition {
    pub(crate) const fn absent(
        status: crate::update::Srv6ArgumentStatus,
        detail: &'static str,
    ) -> Self {
        Self {
            status,
            sid: None,
            detail,
        }
    }
}

/// Inspect the caller-selected pair. The caller, not equal RD, received peer,
/// next-hop or `ORIGINATOR_ID`, establishes applicability to the egress PE/ES.
/// This result is arithmetic over retained signaling, not forwarding eligibility.
pub(crate) fn inspect_argument_pair(
    imet: Option<&EvpnRibRoute>,
    ead: Option<&EvpnRibRoute>,
) -> ArgumentComposition {
    use crate::update::Srv6ArgumentStatus as Status;
    let absent = ArgumentComposition::absent;
    let Some(imet) = imet else {
        return absent(
            Status::Unavailable,
            "IMET route is absent from the requested table snapshot",
        );
    };
    if !matches!(imet.route, EvpnRoute::Imet(_)) {
        return absent(Status::Unavailable, "primary route is not IMET");
    }
    let imet_sid = match inspection_l2_sid(&imet.attributes) {
        Ok(Some(sid)) => sid,
        Ok(None) => return absent(Status::Unavailable, "IMET has no End.DT2M service SID"),
        Err(error) => return error,
    };
    let pmsi_label = match inspection_label(&imet.attributes, &imet_sid, false) {
        Ok(label) => label,
        Err(error) => return error,
    };
    let without_argument = compose_argument(&imet_sid, pmsi_label, None);
    // Validate the destination first. AL=0 MUST ignore even malformed or
    // ambiguous companion attributes (RFC 9819 section 3.3 step 1).
    if without_argument.status != Status::LocFuncOnly || imet_sid.structures[0].argument_length == 0
    {
        return without_argument;
    }
    let Some(ead) = ead else {
        return without_argument;
    };
    if !matches!(ead.route, EvpnRoute::EadPerEs(route) if route.ethernet_tag == rustbgpd_wire::EthernetTagId::MAX_ET)
    {
        return absent(
            Status::Unavailable,
            "companion route is not Ethernet A-D per ES",
        );
    }
    let ead_sid = match inspection_l2_sid(&ead.attributes) {
        Ok(Some(sid)) => sid,
        Ok(None) => return without_argument,
        Err(error) => return error,
    };
    // Resolve zero/unequal AL and nontransposed cases before reading an
    // irrelevant ESI label. An AL conflict must not become "missing label".
    let without_label = compose_argument(&imet_sid, pmsi_label, Some((&ead_sid, None)));
    if without_label.status != Status::Unavailable {
        return without_label;
    }
    let esi_label = match inspection_label(&ead.attributes, &ead_sid, true) {
        Ok(label) => label,
        Err(error) => return error,
    };
    compose_argument(
        &imet_sid,
        pmsi_label,
        Some((&ead_sid, esi_label.map(|(label, _)| label))),
    )
}

fn inspection_l2_sid(
    attributes: &[PathAttribute],
) -> Result<Option<Srv6SidInformation>, ArgumentComposition> {
    use crate::update::Srv6ArgumentStatus as Status;
    let Some(value) = attributes.iter().find_map(|attribute| match attribute {
        PathAttribute::Unknown(raw) if raw.type_code == 40 => Some(raw.data.as_ref()),
        _ => None,
    }) else {
        return Ok(None);
    };
    let services = decode_prefix_sid_services(value).map_err(|_| {
        ArgumentComposition::absent(
            Status::Unavailable,
            "Prefix-SID attribute cannot be decoded",
        )
    })?;
    let Some(service) = services.into_iter().find(|service| service.tlv_type == 6) else {
        return Ok(None);
    };
    if !service
        .sids
        .iter()
        .any(|sid| argument_capable(sid.endpoint_behavior))
    {
        return Ok(None);
    }
    if service.sids.len() != 1 {
        return Err(ArgumentComposition::absent(
            Status::Ambiguous,
            "L2 service has multiple SID Information entries",
        ));
    }
    Ok(service.sids.into_iter().next())
}

fn inspection_label(
    attributes: &[PathAttribute],
    sid: &Srv6SidInformation,
    argument: bool,
) -> Result<Option<(u32, u8)>, ArgumentComposition> {
    use crate::update::Srv6ArgumentStatus as Status;
    if !sid
        .structures
        .iter()
        .any(|structure| structure.transposition_length != 0)
    {
        return Ok(None);
    }
    if argument {
        let mut labels = attributes
            .iter()
            .filter_map(PathAttribute::extended_communities)
            .flatten()
            .filter_map(|community| community.as_esi_label().map(|(_, label)| label));
        let label = labels.next();
        if labels.next().is_some() {
            return Err(ArgumentComposition::absent(
                Status::Ambiguous,
                "multiple ESI Label extended communities",
            ));
        }
        Ok(label.map(|label| (label, 24)))
    } else {
        let mut tunnels = attributes.iter().filter_map(PathAttribute::pmsi_tunnel);
        let tunnel = tunnels.next();
        if tunnels.next().is_some() {
            return Err(ArgumentComposition::absent(
                Status::Ambiguous,
                "multiple PMSI Tunnel attributes",
            ));
        }
        Ok(tunnel.and_then(|tunnel| {
            tunnel
                .tunnel_type
                .evpn_srv6_function_bits()
                .map(|width| (tunnel.mpls_label, width))
        }))
    }
}

/// Compose one caller-selected pair. PMSI carries its raw 24-bit field and
/// EVPN Function capacity; the ESI Label Argument is a raw 24-bit field.
/// The Ethernet A-D NLRI label is never an Argument input.
pub(crate) fn compose_argument(
    imet: &Srv6SidInformation,
    pmsi_label: Option<(u32, u8)>,
    ead: Option<(&Srv6SidInformation, Option<u32>)>,
) -> ArgumentComposition {
    use crate::update::Srv6ArgumentStatus as Status;
    let absent = ArgumentComposition::absent;
    if !argument_capable(imet.endpoint_behavior) {
        return absent(
            Status::Unavailable,
            "IMET SID is not a supported End.DT2M behavior",
        );
    }
    let imet_structure = match imet.structures.as_slice() {
        [structure] => *structure,
        [] => return absent(Status::Unavailable, "IMET SID Structure is missing"),
        _ => return absent(Status::Ambiguous, "IMET has multiple SID Structures"),
    };
    let Some(imet_sid) = restore_component(
        imet,
        imet_structure,
        pmsi_label.map(|(label, _)| label),
        Transposition::Function(pmsi_label.map_or(0, |(_, width)| width)),
    ) else {
        return absent(
            Status::Unavailable,
            "IMET SID Structure or Function transposition is invalid or unavailable",
        );
    };
    let destination_offset = argument_offset(imet_structure);
    let loc_func = imet_sid & prefix_mask(destination_offset);
    let loc_func_only = |detail| ArgumentComposition {
        status: Status::LocFuncOnly,
        sid: Some(loc_func.into()),
        detail,
    };
    if imet_structure.argument_length == 0 {
        // The companion SID and Structure MUST be ignored in this case.
        return loc_func_only("IMET advertises zero Argument length; companion SID is ignored");
    }
    let Some((ead, esi_label)) = ead else {
        return loc_func_only(
            "selected companion has no usable End.DT2M Argument in the requested snapshot",
        );
    };
    if !argument_capable(ead.endpoint_behavior) {
        return loc_func_only("Ethernet A-D per ES has no supported End.DT2M SID");
    }
    let ead_structure = match ead.structures.as_slice() {
        [structure] => *structure,
        [] => {
            return absent(
                Status::Unavailable,
                "Ethernet A-D per ES SID Structure is missing",
            );
        }
        _ => {
            return absent(
                Status::Ambiguous,
                "Ethernet A-D per ES has multiple SID Structures",
            );
        }
    };
    if argument_offset(ead_structure) + u16::from(ead_structure.argument_length) > 128 {
        return absent(
            Status::Unavailable,
            "Ethernet A-D per ES SID Structure exceeds 128 bits",
        );
    }
    if ead_structure.argument_length == 0 {
        return loc_func_only("Ethernet A-D per ES advertises zero Argument length");
    }
    if imet_structure.argument_length != ead_structure.argument_length {
        return absent(
            Status::Conflict,
            "nonzero IMET and Ethernet A-D per ES Argument lengths differ",
        );
    }
    let Some(ead_sid) =
        restore_component(ead, ead_structure, esi_label, Transposition::Argument(24))
    else {
        return absent(
            Status::Unavailable,
            "Ethernet A-D per ES SID Structure or Argument transposition is invalid or unavailable",
        );
    };
    let length = u16::from(imet_structure.argument_length);
    let source_offset = argument_offset(ead_structure);
    let argument = (ead_sid >> (128 - source_offset - length)) & !prefix_mask(128 - length);
    ArgumentComposition {
        status: Status::Composed,
        sid: Some((loc_func | (argument << (128 - destination_offset - length))).into()),
        detail: "Argument extracted at the companion offset and inserted at the IMET offset",
    }
}

fn argument_offset(structure: Srv6SidStructure) -> u16 {
    u16::from(structure.locator_block_length)
        + u16::from(structure.locator_node_length)
        + u16::from(structure.function_length)
}

fn prefix_mask(length: u16) -> u128 {
    u128::MAX.checked_shl(u32::from(128 - length)).unwrap_or(0)
}

fn restore_component(
    sid: &Srv6SidInformation,
    structure: Srv6SidStructure,
    label: Option<u32>,
    transposition: Transposition,
) -> Option<u128> {
    if !structure_eligible(sid, structure, transposition) {
        return None;
    }
    let length = u16::from(structure.transposition_length);
    let mut value = u128::from(sid.sid_value);
    if length != 0 {
        let label = label.filter(|label| *label < (1 << 24))?;
        value |= u128::from(label >> (24 - length))
            << (128 - u16::from(structure.transposition_offset) - length);
    }
    Some(value)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::net::Ipv6Addr;

    use rustbgpd_wire::{
        EthernetSegmentIdentifier, EthernetTagId, EvpnEadPerEs, EvpnEadPerEvi, EvpnEs, EvpnImet,
        EvpnIpPrefixRoute, EvpnIpPrefixValue, EvpnMacIp, ExtendedCommunity, MacAddress, MplsLabel,
        PmsiTunnel, PmsiTunnelIdentifier, PmsiTunnelType, RawAttribute, RouteDistinguisher,
    };

    use super::*;
    use crate::attr_set::AttrSet;

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

    fn inspection_sid(value: &str, behavior: u16, structure: [u8; 6]) -> Srv6SidInformation {
        let PathAttribute::Unknown(raw) =
            service_attribute(6, value.parse().unwrap(), behavior, Some(structure))
        else {
            unreachable!()
        };
        decode_prefix_sid_services(&raw.data)
            .unwrap()
            .remove(0)
            .sids
            .remove(0)
    }

    #[test]
    fn argument_composition_rfc9819_outcomes_and_distinct_offsets() {
        use crate::update::Srv6ArgumentStatus as Status;
        // RFC 9819 Figures 1–6, including the four section 3.3 outcomes.
        for behavior in [24, 68, 124] {
            let mut imet = inspection_sid("2001:db8:1:fbd1::", behavior, [32, 16, 16, 16, 0, 0]);
            let mut ead = inspection_sid("::aaaa:0:0:0", 24, [32, 16, 16, 16, 0, 0]);
            let result = compose_argument(&imet, None, Some((&ead, None)));
            assert_eq!(result.status, Status::Composed);
            assert_eq!(
                result.sid.unwrap(),
                "2001:db8:1:fbd1:aaaa::".parse::<Ipv6Addr>().unwrap()
            );

            let absent = compose_argument(&imet, None, None);
            assert_eq!(absent.status, Status::LocFuncOnly);
            assert_eq!(absent.sid, Some(imet.sid_value));
            ead.structures[0].argument_length = 0;
            assert_eq!(
                compose_argument(&imet, None, Some((&ead, None))).status,
                Status::LocFuncOnly
            );
            ead.structures[0].argument_length = 8;
            let conflict = compose_argument(&imet, None, Some((&ead, None)));
            assert_eq!(conflict.status, Status::Conflict);
            assert!(conflict.sid.is_none());

            // AL=0 ignores even an ambiguous or invalid companion Structure.
            imet.structures[0].argument_length = 0;
            ead.structures.push(ead.structures[0]);
            let ignored = compose_argument(&imet, None, Some((&ead, None)));
            assert_eq!(ignored.status, Status::LocFuncOnly);
            assert_eq!(ignored.sid, Some(imet.sid_value));
        }
        // Figure 7: copying/OR-ing the source SID at its original offset is wrong.
        let imet = inspection_sid("2001:db8:1:fbd1:fbd1::", 124, [32, 16, 32, 16, 0, 0]);
        let ead = inspection_sid("::aaaa:0:0:0", 68, [32, 16, 16, 16, 0, 0]);
        assert_eq!(
            compose_argument(&imet, None, Some((&ead, None)))
                .sid
                .unwrap(),
            "2001:db8:1:fbd1:fbd1:aaaa::".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn argument_composition_restores_each_24_bit_component_and_clears_tail() {
        use crate::update::Srv6ArgumentStatus as Status;
        let imet = inspection_sid("2001:db8:1::ffff", 24, [32, 16, 16, 16, 16, 48]);
        let ead = inspection_sid("::ffff", 124, [32, 16, 32, 16, 16, 80]);
        let result = compose_argument(
            &imet,
            Some((0x00fb_d100, 24)),
            Some((&ead, Some(0x00aa_aa00))),
        );
        assert_eq!(result.status, Status::Composed);
        assert_eq!(
            result.sid.unwrap(),
            "2001:db8:1:fbd1:aaaa::".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            compose_argument(&imet, None, Some((&ead, Some(0x00aa_aa00)))).status,
            Status::Unavailable
        );
        assert_eq!(
            compose_argument(&imet, Some((0x00fb_d100, 24)), Some((&ead, None))).status,
            Status::Unavailable
        );
        assert_eq!(
            compose_argument(&imet, Some((1 << 24, 24)), Some((&ead, Some(0x00aa_aa00)))).status,
            Status::Unavailable
        );
        let mut invalid = ead.clone();
        invalid.sid_value = "::1:0:0".parse().unwrap(); // nonzero vacated Argument bit.
        assert_eq!(
            compose_argument(
                &imet,
                Some((0x00fb_d100, 24)),
                Some((&invalid, Some(0x00aa_aa00)))
            )
            .status,
            Status::Unavailable
        );
    }

    #[test]
    fn argument_composition_resolves_lengths_before_requiring_argument_label() {
        use crate::update::Srv6ArgumentStatus as Status;
        let imet = inspection_sid("2001:db8:1:fbd1::", 24, [32, 16, 16, 16, 0, 0]);
        let mut ead = inspection_sid("::", 24, [32, 16, 16, 8, 8, 64]);
        // A missing ESI Label cannot conceal the explicit unequal-AL conflict.
        assert_eq!(
            compose_argument(&imet, None, Some((&ead, None))).status,
            Status::Conflict
        );
        ead.structures[0].argument_length = 0;
        // No Argument is used, so its transposition fields are irrelevant.
        assert_eq!(
            compose_argument(&imet, None, Some((&ead, None))).status,
            Status::LocFuncOnly
        );
        ead.structures[0].argument_length = 16;
        assert_eq!(
            compose_argument(&imet, None, Some((&ead, None))).status,
            Status::Unavailable
        );
    }

    #[test]
    fn argument_composition_rejects_ambiguous_missing_and_invalid_structures() {
        use crate::update::Srv6ArgumentStatus as Status;
        let imet = inspection_sid("2001:db8:1:fbd1::", 24, [32, 16, 16, 16, 0, 0]);
        let ead = inspection_sid("::aaaa:0:0:0", 24, [32, 16, 16, 16, 0, 0]);
        for structure in [
            [255; 6],
            [32, 16, 16, 65, 0, 0],
            [32, 16, 16, 16, 17, 48],
            [32, 16, 16, 16, 0, 1],
        ] {
            let invalid = inspection_sid("::", 24, structure);
            assert_eq!(
                compose_argument(&invalid, Some((0, 24)), Some((&ead, None))).status,
                Status::Unavailable
            );
        }
        let mut missing = imet.clone();
        missing.structures.clear();
        assert_eq!(
            compose_argument(&missing, None, Some((&ead, None))).status,
            Status::Unavailable
        );
        let mut multiple = imet.clone();
        multiple.structures.push(multiple.structures[0]);
        assert_eq!(
            compose_argument(&multiple, None, Some((&ead, None))).status,
            Status::Ambiguous
        );
        let mut unknown = imet.clone();
        unknown.endpoint_behavior = 0xffff;
        assert_eq!(
            compose_argument(&unknown, None, Some((&ead, None))).status,
            Status::Unavailable
        );
        assert_eq!(
            compose_argument(&imet, None, Some((&unknown, None))).status,
            Status::LocFuncOnly
        );
        // Legal endpoints at bit 0 and bit 128 never shift by 128.
        let imet = inspection_sid("ffff::", 24, [0, 0, 0, 128, 0, 0]);
        let ead = inspection_sid("::aaaa", 24, [0, 0, 0, 128, 0, 0]);
        assert_eq!(
            compose_argument(&imet, None, Some((&ead, None))).sid,
            Some(ead.sid_value)
        );
        let imet = inspection_sid("2001:db8::1", 24, [64, 48, 16, 0, 0, 0]);
        assert_eq!(
            compose_argument(&imet, None, None).sid,
            Some(imet.sid_value)
        );
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
            // Compressed End.DT2M flavors follow the same RFC 9819 rules.
            (68, Some([40, 24, 16, 16, 0, 0]), true),
            (124, Some([40, 24, 16, 16, 0, 0]), true),
            (68, None, false),
            (124, None, false),
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

    pub(crate) fn p2mp_imet() -> EvpnRibRoute {
        use std::{net::Ipv4Addr, time::Instant};

        use crate::route::RouteOrigin;

        let sid: Ipv6Addr = "2001:db8:1::".parse().unwrap();
        let peer = Ipv4Addr::new(10, 0, 0, 1);
        EvpnRibRoute {
            route: EvpnRoute::Imet(EvpnImet {
                rd: RouteDistinguisher([0; 8]),
                ethernet_tag: EthernetTagId(0),
                originator_ip: sid.into(),
            }),
            next_hop: sid.into(),
            link_local_next_hop: None,
            peer: peer.into(),
            attributes: AttrSet::new(vec![
                service_attribute(6, sid, 24, Some([32, 16, 16, 0, 16, 48])),
                PathAttribute::PmsiTunnel(PmsiTunnel {
                    flags: 0,
                    tunnel_type: PmsiTunnelType::Other(0x0d),
                    mpls_label: 0x00fb_d100,
                    tunnel_identifier: PmsiTunnelIdentifier::Raw(vec![0, 0, 0, 1, 192, 0, 2, 1]),
                }),
            ]),
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ibgp,
            peer_router_id: peer,
            is_stale: false,
            is_llgr_stale: false,
        }
    }

    #[test]
    fn srv6_p2mp_transposed_imet_is_selected() {
        use crate::loc_rib::LocRib;
        let route = p2mp_imet();
        let mut loc = LocRib::new();
        assert!(loc.recompute_evpn(route.key(), std::iter::once(&route)));
        assert!(
            loc.get_evpn(&route.key()).is_some(),
            "SRv6 P2MP IMET with a transposed Function must stay selected"
        );
    }

    #[test]
    fn p2mp_function_width_is_enforced_in_selection_and_argument_inspection() {
        use crate::update::Srv6ArgumentStatus as Status;
        let mut route = p2mp_imet();
        let raw = route.attributes.clone();
        assert_eq!(
            inspect_argument_pair(Some(&route), None).sid,
            Some("2001:db8:1:fbd1::".parse().unwrap())
        );
        assert_eq!(route.attributes, raw);
        for (tunnel, length, sid, eligible) in [
            (Some(PmsiTunnelType::Other(0x0d)), 20, "2001:db8:1::", true),
            (Some(PmsiTunnelType::Other(0x0d)), 21, "2001:db8:1::", false),
            (
                Some(PmsiTunnelType::IngressReplication),
                24,
                "2001:db8:1::",
                true,
            ),
            (Some(PmsiTunnelType::Other(0x0c)), 16, "2001:db8:1::", false),
            (Some(PmsiTunnelType::Other(0x8d)), 16, "2001:db8:1::", false),
            (None, 16, "2001:db8:1::", false),
            (
                Some(PmsiTunnelType::Other(0x0d)),
                16,
                "2001:db8:1:1::",
                false,
            ),
        ] {
            let mut attributes = vec![service_attribute(
                6,
                sid.parse().unwrap(),
                24,
                Some([32, 16, 24, 0, length, 48]),
            )];
            if let Some(tunnel_type) = tunnel {
                let mut pmsi = raw
                    .iter()
                    .find_map(PathAttribute::pmsi_tunnel)
                    .unwrap()
                    .clone();
                pmsi.tunnel_type = tunnel_type;
                // Low bits remain opaque; only the high TL bits are restored.
                pmsi.mpls_label |= 0xf;
                attributes.push(PathAttribute::PmsiTunnel(pmsi));
            }
            route.attributes = AttrSet::new(attributes);
            assert_eq!(
                evpn_eligible(&route),
                eligible,
                "{tunnel:?}, TL={length}, {sid}"
            );
            let result = inspect_argument_pair(Some(&route), None);
            assert_eq!(
                result.status,
                if eligible {
                    Status::LocFuncOnly
                } else {
                    Status::Unavailable
                }
            );
            if eligible {
                let label = if length == 24 {
                    0x00fb_d10f
                } else {
                    0x00fb_d100
                };
                assert_eq!(
                    result.sid,
                    Some(
                        (u128::from("2001:db8:1::".parse::<Ipv6Addr>().unwrap()) | (label << 56))
                            .into()
                    )
                );
            }
        }
    }

    #[test]
    fn p2mp_inspection_preserves_ambiguity_and_first_service_rules() {
        use crate::update::Srv6ArgumentStatus as Status;
        let mut route = p2mp_imet();
        let raw = route.attributes.clone();
        AttrSet::edit(&mut route.attributes, |attrs| attrs.push(attrs[1].clone()));
        assert_eq!(
            inspect_argument_pair(Some(&route), None).status,
            Status::Ambiguous
        );
        route.attributes = raw;
        AttrSet::edit(&mut route.attributes, |attrs| {
            let mut first = service_attribute(
                6,
                "2001:db8:1::".parse().unwrap(),
                24,
                Some([32, 16, 24, 0, 21, 48]),
            );
            append_service(&mut first, attrs[0].clone());
            attrs[0] = first;
        });
        assert!(
            !evpn_eligible(&route),
            "a later duplicate service cannot rescue the first"
        );
        assert_eq!(
            inspect_argument_pair(Some(&route), None).status,
            Status::Unavailable
        );
    }

    #[test]
    fn compressed_dt2m_imet_with_argument_is_selected() {
        use std::{net::Ipv4Addr, time::Instant};

        use crate::{loc_rib::LocRib, route::RouteOrigin};

        let sid: Ipv6Addr = "2001:db8:111:1::".parse().unwrap();
        let peer = Ipv4Addr::new(10, 0, 0, 1);
        let route = EvpnRibRoute {
            route: EvpnRoute::Imet(EvpnImet {
                rd: RouteDistinguisher([0; 8]),
                ethernet_tag: EthernetTagId(0),
                originator_ip: sid.into(),
            }),
            next_hop: sid.into(),
            link_local_next_hop: None,
            peer: peer.into(),
            attributes: AttrSet::new(vec![
                service_attribute(6, sid, 124, Some([40, 24, 16, 16, 0, 0])),
                PathAttribute::PmsiTunnel(PmsiTunnel {
                    flags: 0,
                    tunnel_type: PmsiTunnelType::IngressReplication,
                    mpls_label: 0,
                    tunnel_identifier: PmsiTunnelIdentifier::Ipv6(sid),
                }),
            ]),
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ibgp,
            peer_router_id: peer,
            is_stale: false,
            is_llgr_stale: false,
        };
        let mut loc = LocRib::new();
        assert!(loc.recompute_evpn(route.key(), std::iter::once(&route)));
        assert!(
            loc.get_evpn(&route.key()).is_some(),
            "REPLACE-CSID End.DT2M IMET with AL=16 must stay selected"
        );
    }
}
