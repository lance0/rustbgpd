//! RFC 9069 Loc-RIB BMP synthesis: rebuild BGP UPDATE PDUs from RIB
//! entries for Route Monitoring of the emulated Loc-RIB instance peer.
//!
//! Loc-RIB routes were stripped of their next-hop / `MP_REACH_NLRI`
//! at decode (per MP-BGP architecture), so announcement PDUs
//! reconstruct the appropriate reachability attribute — the same
//! pattern as the MRT exporter's attribute synthesis, except the NLRI
//! rides *inside* the UPDATE here rather than in a table-dump record
//! header. All PDUs use 4-octet-ASN encoding and no Add-Path, matching
//! the fabricated OPEN advertised in the Loc-RIB Peer Up (§5.2.1).
//!
//! V1 synthesis scope: IPv4/IPv6 unicast and VPNv4/VPNv6 (SAFI 128) —
//! the families declared in `LOC_RIB_FAMILIES`. Other Loc-RIB
//! families (EVPN, BGP-LS, labeled-unicast, FlowSpec, RTC) land
//! additively later; they are deliberately absent from the fabricated
//! OPEN so collectors are not promised streams that never arrive.

use std::net::{IpAddr, Ipv4Addr};

use bytes::{Bytes, BytesMut};
use rustbgpd_bmp::{BmpPathStatus, tlv as bmp_tlv};
use rustbgpd_wire::{
    Afi, Capability, EXTENDED_MAX_MESSAGE_LEN, Ipv4NlriEntry, Ipv4Prefix, Ipv4UnicastMode,
    MpReachNlri, MpUnreachNlri, NlriEntry, OpenMessage, PathAttribute, Prefix, Safi, UpdateMessage,
    VpnNlri, VpnNlriEntry,
};
use tracing::warn;

use crate::best_path::BestPathReason;
use crate::route::{Route, VpnRibRoute};

/// `AS_TRANS` (RFC 6793): 2-byte OPEN AS field stand-in for ASNs > 65535.
const AS_TRANS: u16 = 23456;

/// The AFI/SAFI pairs streamed on the Loc-RIB view, and therefore the
/// MP capabilities carried in the fabricated OPEN and the families that
/// receive an End-of-RIB after a table dump.
pub const LOC_RIB_FAMILIES: [(Afi, Safi); 4] = [
    (Afi::Ipv4, Safi::Unicast),
    (Afi::Ipv6, Safi::Unicast),
    (Afi::Ipv4, Safi::MplsVpn),
    (Afi::Ipv6, Safi::MplsVpn),
];

/// Map a decisive best-path step to the draft's Reason Code
/// (draft-ietf-grow-bmp-path-marking-tlv-05 §3.2, Table 2). Steps with
/// no registered code (stale/RPKI/ASPA preference, cluster-list
/// length, EVPN MAC mobility) map to `None` — the Reason Code is
/// optional and omitting it beats mislabeling the step.
#[must_use]
pub fn path_marking_reason_code(reason: BestPathReason) -> Option<u16> {
    match reason {
        BestPathReason::HigherLocalPref => Some(bmp_tlv::REASON_LOCAL_PREF),
        BestPathReason::ShorterAsPath => Some(bmp_tlv::REASON_AS_PATH_LEN),
        BestPathReason::LowerOrigin => Some(bmp_tlv::REASON_ORIGIN),
        BestPathReason::LowerMed => Some(bmp_tlv::REASON_MED),
        BestPathReason::EbgpOverIbgp => Some(bmp_tlv::REASON_PEER_TYPE),
        BestPathReason::OrrInteriorCost => Some(bmp_tlv::REASON_IGP_COST),
        // RFC 4456 substitutes ORIGINATOR_ID for the BGP identifier on
        // reflected routes — the same RFC 4271 §9.1.2.2 step the
        // draft's "router ID" code names.
        BestPathReason::LowerOriginatorId => Some(bmp_tlv::REASON_ROUTER_ID),
        BestPathReason::LowerPeerAddress => Some(bmp_tlv::REASON_PEER_ADDRESS),
        BestPathReason::StalePreference
        | BestPathReason::RpkiPreference
        | BestPathReason::AspaPreference
        | BestPathReason::ShorterClusterList
        | BestPathReason::EvpnMacMobility => None,
    }
}

/// Path Marking payload (path-marking-05 §3.1) for a Loc-RIB best
/// route: always Best (a Loc-RIB route is the decision-process winner
/// by definition), plus Stale when the GR/LLGR machinery says so.
/// `reason` is the decisive step versus the runner-up, when one was
/// compared. Primary/Backup/Non-installed/Filtered/Suppressed bits are
/// FIB, policy-drop, and damping concepts a route reflector without a
/// forwarding plane cannot attest to — deliberately never set.
#[must_use]
pub fn loc_rib_path_status(is_stale: bool, reason: Option<BestPathReason>) -> BmpPathStatus {
    let mut status = bmp_tlv::PATH_STATUS_BEST;
    if is_stale {
        status |= bmp_tlv::PATH_STATUS_STALE;
    }
    BmpPathStatus {
        status,
        reason: reason.and_then(path_marking_reason_code),
    }
}

fn empty_mp_reach(afi: Afi, safi: Safi, next_hop: IpAddr) -> MpReachNlri {
    MpReachNlri {
        afi,
        safi,
        next_hop,
        link_local_next_hop: None,
        announced: vec![],
        flowspec_announced: vec![],
        evpn_announced: vec![],
        bgpls_announced: vec![],
        labeled_announced: vec![],
        vpn_announced: vec![],
        rtc_announced: vec![],
    }
}

fn empty_mp_unreach(afi: Afi, safi: Safi) -> MpUnreachNlri {
    MpUnreachNlri {
        afi,
        safi,
        withdrawn: vec![],
        flowspec_withdrawn: vec![],
        evpn_withdrawn: vec![],
        bgpls_withdrawn: vec![],
        vpn_withdrawn: vec![],
        labeled_withdrawn: vec![],
        rtc_withdrawn: vec![],
    }
}

/// Encode a built `UpdateMessage` into a complete PDU (with header),
/// or `None` with a warning if it cannot be represented on the wire.
fn encode_update(update: &UpdateMessage, what: &str) -> Option<Bytes> {
    let mut buf = BytesMut::with_capacity(update.encoded_len());
    match update.encode_with_limit(&mut buf, EXTENDED_MAX_MESSAGE_LEN) {
        Ok(()) => Some(buf.freeze()),
        Err(e) => {
            warn!(error = %e, what, "failed to synthesize Loc-RIB BMP UPDATE, skipping");
            None
        }
    }
}

fn build_update(
    announced: &[Ipv4NlriEntry],
    withdrawn: &[Ipv4NlriEntry],
    attributes: &[PathAttribute],
    what: &str,
) -> Option<Bytes> {
    match UpdateMessage::try_build(
        announced,
        withdrawn,
        attributes,
        true, // 4-octet ASN encoding (RFC 9069 §5.4)
        false,
        Ipv4UnicastMode::Body,
    ) {
        Ok(update) => encode_update(&update, what),
        Err(e) => {
            warn!(error = %e, what, "failed to synthesize Loc-RIB BMP UPDATE, skipping");
            None
        }
    }
}

/// Build an announcement UPDATE from the route's borrowed attribute
/// slice with one synthesized `extra` attribute injected at
/// `insert_pos`, without materializing a modified attribute Vec (the
/// hot path: one PDU per Loc-RIB best change, so a full deep clone of
/// the attributes per emission dominated BMP-on allocation).
///
/// [`rustbgpd_wire::attribute::encode_path_attributes`] emits
/// attributes strictly in slice order with no cross-attribute state,
/// so encoding `attrs[..pos]`, `extra`, `attrs[pos..]` piecewise is
/// byte-identical to clone-and-insert followed by
/// [`UpdateMessage::try_build`] (pinned by the `borrowed_encode_*`
/// tests below against the clone-based oracle).
fn build_announce_with_extra(
    announced_v4: &[Ipv4Prefix],
    attrs: &[PathAttribute],
    insert_pos: usize,
    extra: &PathAttribute,
    what: &str,
) -> Option<Bytes> {
    let mut attrs_buf = Vec::new();
    // 4-octet ASN encoding, no Add-Path (RFC 9069 §5.4) — must match
    // `build_update`'s flags.
    let result = rustbgpd_wire::attribute::encode_path_attributes(
        &attrs[..insert_pos],
        &mut attrs_buf,
        true,
        false,
    )
    .and_then(|()| {
        rustbgpd_wire::attribute::encode_path_attributes(
            std::slice::from_ref(extra),
            &mut attrs_buf,
            true,
            false,
        )
    })
    .and_then(|()| {
        rustbgpd_wire::attribute::encode_path_attributes(
            &attrs[insert_pos..],
            &mut attrs_buf,
            true,
            false,
        )
    });
    if let Err(e) = result {
        warn!(error = %e, what, "failed to synthesize Loc-RIB BMP UPDATE, skipping");
        return None;
    }
    let mut nlri_buf = Vec::new();
    rustbgpd_wire::nlri::encode_nlri(announced_v4, &mut nlri_buf);
    let update = UpdateMessage {
        withdrawn_routes: Bytes::new(),
        path_attributes: Bytes::from(attrs_buf),
        nlri: Bytes::from(nlri_buf),
    };
    encode_update(&update, what)
}

/// Synthesize an announcement UPDATE for a unicast Loc-RIB best route.
///
/// IPv4 with an IPv4 next-hop uses the classic body NLRI + `NEXT_HOP`
/// attribute; IPv6 (and RFC 8950 IPv4-over-IPv6-next-hop) uses
/// `MP_REACH_NLRI` with the prefix inside the attribute.
#[must_use]
pub fn synthesize_unicast_announce(route: &Route) -> Option<Bytes> {
    let attrs = route.attributes.as_slice();
    match (route.prefix, route.next_hop) {
        (Prefix::V4(v4_prefix), IpAddr::V4(nh)) => {
            // Inject NEXT_HOP after ORIGIN and AS_PATH (canonical order).
            let insert_pos = attrs
                .iter()
                .position(|a| !matches!(a, PathAttribute::Origin(_) | PathAttribute::AsPath(_)))
                .unwrap_or(attrs.len());
            build_announce_with_extra(
                &[v4_prefix],
                attrs,
                insert_pos,
                &PathAttribute::NextHop(nh),
                "unicast v4 announce",
            )
        }
        (prefix, next_hop) => {
            let afi = match prefix {
                Prefix::V4(_) => Afi::Ipv4, // RFC 8950: IPv4 NLRI, IPv6 next-hop
                Prefix::V6(_) => Afi::Ipv6,
            };
            let mut mp_reach = empty_mp_reach(afi, Safi::Unicast, next_hop);
            mp_reach.link_local_next_hop = route.link_local_next_hop;
            mp_reach.announced = vec![NlriEntry { path_id: 0, prefix }];
            build_announce_with_extra(
                &[],
                attrs,
                attrs.len(),
                &PathAttribute::MpReachNlri(mp_reach),
                "unicast mp announce",
            )
        }
    }
}

/// Synthesize a withdrawal UPDATE for a unicast prefix that lost its
/// Loc-RIB best (v4: body withdrawn field; v6: `MP_UNREACH_NLRI`).
#[must_use]
pub fn synthesize_unicast_withdraw(prefix: Prefix) -> Option<Bytes> {
    match prefix {
        Prefix::V4(v4_prefix) => build_update(
            &[],
            &[Ipv4NlriEntry {
                path_id: 0,
                prefix: v4_prefix,
            }],
            &[],
            "unicast v4 withdraw",
        ),
        Prefix::V6(_) => {
            let mut mp_unreach = empty_mp_unreach(Afi::Ipv6, Safi::Unicast);
            mp_unreach.withdrawn = vec![NlriEntry { path_id: 0, prefix }];
            build_update(
                &[],
                &[],
                &[PathAttribute::MpUnreachNlri(mp_unreach)],
                "unicast v6 withdraw",
            )
        }
    }
}

/// The wire AFI for a VPN NLRI (SAFI is always `MplsVpn`).
fn vpn_afi(nlri: &VpnNlri) -> Afi {
    match nlri.prefix.family() {
        rustbgpd_wire::VpnAddressFamily::V4 => Afi::Ipv4,
        rustbgpd_wire::VpnAddressFamily::V6 => Afi::Ipv6,
    }
}

/// Synthesize an announcement UPDATE for a VPNv4/VPNv6 Loc-RIB best
/// route: `MP_REACH_NLRI` carrying the full NLRI (RD + label stack +
/// prefix, preserved verbatim) with the route's VPN next-hop.
#[must_use]
pub fn synthesize_vpn_announce(route: &VpnRibRoute) -> Option<Bytes> {
    let attrs = route.attributes.as_slice();
    let mut mp_reach = empty_mp_reach(vpn_afi(&route.nlri), Safi::MplsVpn, route.next_hop);
    mp_reach.vpn_announced = vec![VpnNlriEntry {
        path_id: 0,
        nlri: route.nlri.clone(),
    }];
    build_announce_with_extra(
        &[],
        attrs,
        attrs.len(),
        &PathAttribute::MpReachNlri(mp_reach),
        "vpn announce",
    )
}

/// Synthesize a withdrawal UPDATE for a VPN RD+prefix identity that
/// lost its Loc-RIB best: `MP_UNREACH_NLRI` (the encoder emits the
/// RFC 8277 §2.4 3-octet compatibility field in place of the label
/// stack).
#[must_use]
pub fn synthesize_vpn_withdraw(nlri: &VpnNlri) -> Option<Bytes> {
    let mut mp_unreach = empty_mp_unreach(vpn_afi(nlri), Safi::MplsVpn);
    mp_unreach.vpn_withdrawn = vec![VpnNlriEntry {
        path_id: 0,
        nlri: nlri.clone(),
    }];
    build_update(
        &[],
        &[],
        &[PathAttribute::MpUnreachNlri(mp_unreach)],
        "vpn withdraw",
    )
}

/// Synthesize the RFC 4724 End-of-RIB marker for a family: the empty
/// UPDATE for IPv4 unicast, an empty `MP_UNREACH_NLRI` otherwise.
#[must_use]
pub fn synthesize_end_of_rib(afi: Afi, safi: Safi) -> Option<Bytes> {
    if (afi, safi) == (Afi::Ipv4, Safi::Unicast) {
        build_update(&[], &[], &[], "eor v4 unicast")
    } else {
        build_update(
            &[],
            &[],
            &[PathAttribute::MpUnreachNlri(empty_mp_unreach(afi, safi))],
            "eor mp",
        )
    }
}

/// Fabricate the RFC 9069 §5.2.1 OPEN PDU for the emulated Loc-RIB
/// instance peer: 4-octet-ASN capability plus one MP capability per
/// [`LOC_RIB_FAMILIES`] entry. Used verbatim as both the sent and the
/// received OPEN of the Loc-RIB Peer Up.
///
/// # Panics
///
/// Panics if the fabricated OPEN cannot be encoded — impossible by
/// construction (fixed capability set, bounded size).
#[must_use]
pub fn loc_rib_open_pdu(local_asn: u32, router_id: Ipv4Addr) -> Bytes {
    let mut capabilities: Vec<Capability> = LOC_RIB_FAMILIES
        .iter()
        .map(|&(afi, safi)| Capability::MultiProtocol { afi, safi })
        .collect();
    capabilities.push(Capability::FourOctetAs { asn: local_asn });
    let open = OpenMessage {
        version: 4,
        my_as: u16::try_from(local_asn).unwrap_or(AS_TRANS),
        hold_time: 0,
        bgp_identifier: router_id,
        capabilities,
    };
    let mut buf = BytesMut::with_capacity(open.encoded_len());
    open.encode(&mut buf)
        .expect("fabricated Loc-RIB OPEN is bounded and always encodable");
    buf.freeze()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
    use std::sync::Arc;
    use std::time::Instant;

    use rustbgpd_wire::{
        AsPath, AsPathSegment, BgpHeader, Ipv4Prefix, Ipv6Prefix, MplsLabelEntry, Origin,
        RouteDistinguisher, VpnPrefix,
    };

    use super::*;
    use crate::route::RouteOrigin;

    fn base_attrs() -> Vec<PathAttribute> {
        vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65001, 4_200_000_001])],
            }),
        ]
    }

    fn unicast_route(prefix: Prefix, next_hop: IpAddr) -> Route {
        Route {
            prefix,
            next_hop,
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: next_hop,
            attributes: Arc::new(base_attrs()),
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            aspa_context: rustbgpd_wire::AspaValidationContext::default(),
        }
    }

    fn vpn_nlri() -> VpnNlri {
        VpnNlri {
            labels: vec![MplsLabelEntry {
                label: 1042,
                traffic_class: 0,
                bottom_of_stack: true,
            }],
            route_distinguisher: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 7]),
            prefix: VpnPrefix::V4 {
                addr: Ipv4Addr::new(10, 40, 0, 0),
                len: 24,
            },
        }
    }

    fn vpn_route() -> VpnRibRoute {
        VpnRibRoute {
            nlri: vpn_nlri(),
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
            link_local_next_hop: None,
            peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            attributes: Arc::new(base_attrs()),
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ibgp,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
        }
    }

    /// Decode a synthesized PDU back into a parsed UPDATE (4-octet ASN,
    /// no Add-Path — the fabricated OPEN's session parameters).
    fn decode_pdu(pdu: &Bytes) -> rustbgpd_wire::ParsedUpdate {
        let mut buf = pdu.clone();
        let header = BgpHeader::decode(&mut buf, EXTENDED_MAX_MESSAGE_LEN).unwrap();
        let body_len = usize::from(header.length) - 19;
        let update = UpdateMessage::decode(&mut buf, body_len).unwrap();
        update.parse(true, false, &[]).unwrap()
    }

    #[test]
    fn unicast_v4_announce_round_trips() {
        let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 16));
        let route = unicast_route(prefix, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        let pdu = synthesize_unicast_announce(&route).unwrap();
        let parsed = decode_pdu(&pdu);
        assert_eq!(parsed.announced.len(), 1);
        assert_eq!(Prefix::V4(parsed.announced[0].prefix), prefix);
        assert!(parsed.withdrawn.is_empty());
        assert!(parsed.attributes.iter().any(
            |a| matches!(a, PathAttribute::NextHop(nh) if *nh == Ipv4Addr::new(192, 0, 2, 1))
        ));
        // 4-octet ASN encoding: the >65535 ASN survives the round-trip.
        assert!(parsed.attributes.iter().any(|a| matches!(
            a,
            PathAttribute::AsPath(p) if matches!(
                &p.segments[0],
                AsPathSegment::AsSequence(asns) if asns.contains(&4_200_000_001)
            )
        )));
    }

    #[test]
    fn unicast_v6_announce_round_trips_via_mp_reach() {
        let prefix = Prefix::V6(Ipv6Prefix::new(
            "2001:db8:40::".parse::<Ipv6Addr>().unwrap(),
            48,
        ));
        let nh = IpAddr::V6("2001:db8::1".parse().unwrap());
        let route = unicast_route(prefix, nh);
        let pdu = synthesize_unicast_announce(&route).unwrap();
        let parsed = decode_pdu(&pdu);
        assert!(
            parsed.announced.is_empty(),
            "v6 NLRI must not be in the body"
        );
        let mp = parsed
            .attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::MpReachNlri(mp) => Some(mp),
                _ => None,
            })
            .expect("MP_REACH present");
        assert_eq!((mp.afi, mp.safi), (Afi::Ipv6, Safi::Unicast));
        assert_eq!(mp.next_hop, nh);
        assert_eq!(mp.announced, vec![NlriEntry { path_id: 0, prefix }]);
    }

    #[test]
    fn unicast_withdraws_round_trip() {
        let v4 = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 2, 0, 0), 16));
        let parsed = decode_pdu(&synthesize_unicast_withdraw(v4).unwrap());
        assert_eq!(parsed.withdrawn.len(), 1);
        assert_eq!(Prefix::V4(parsed.withdrawn[0].prefix), v4);

        let v6 = Prefix::V6(Ipv6Prefix::new(
            "2001:db8:41::".parse::<Ipv6Addr>().unwrap(),
            48,
        ));
        let parsed = decode_pdu(&synthesize_unicast_withdraw(v6).unwrap());
        let mp = parsed
            .attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::MpUnreachNlri(mp) => Some(mp),
                _ => None,
            })
            .expect("MP_UNREACH present");
        assert_eq!(
            mp.withdrawn,
            vec![NlriEntry {
                path_id: 0,
                prefix: v6
            }]
        );
    }

    #[test]
    fn vpn_announce_and_withdraw_round_trip() {
        let route = vpn_route();
        let parsed = decode_pdu(&synthesize_vpn_announce(&route).unwrap());
        let mp = parsed
            .attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::MpReachNlri(mp) => Some(mp),
                _ => None,
            })
            .expect("MP_REACH present");
        assert_eq!((mp.afi, mp.safi), (Afi::Ipv4, Safi::MplsVpn));
        assert_eq!(mp.next_hop, route.next_hop);
        assert_eq!(mp.vpn_announced.len(), 1);
        assert_eq!(mp.vpn_announced[0].nlri, route.nlri);

        // Withdraw: RD + prefix identity survives; the label field is
        // the RFC 8277 §2.4 compatibility value, not the stack.
        let parsed = decode_pdu(&synthesize_vpn_withdraw(&route.nlri).unwrap());
        let mp = parsed
            .attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::MpUnreachNlri(mp) => Some(mp),
                _ => None,
            })
            .expect("MP_UNREACH present");
        assert_eq!(mp.vpn_withdrawn.len(), 1);
        assert_eq!(mp.vpn_withdrawn[0].nlri.key(), route.nlri.key());
    }

    /// Rich attribute set exercising multi-segment `AS_PATH`, MED,
    /// `LOCAL_PREF`, communities of every flavor, RR attributes, and an
    /// extended-length (>255 B value) attribute.
    fn rich_attrs() -> Vec<PathAttribute> {
        use rustbgpd_wire::{ExtendedCommunity, LargeCommunity};
        vec![
            PathAttribute::Origin(Origin::Egp),
            PathAttribute::AsPath(AsPath {
                segments: vec![
                    AsPathSegment::AsSequence(vec![65001, 4_200_000_001]),
                    AsPathSegment::AsSet(vec![65010, 65011]),
                ],
            }),
            PathAttribute::Med(50),
            PathAttribute::LocalPref(200),
            // 128 communities = 512-byte value → extended-length flag.
            PathAttribute::Communities((0..128).map(|i| 0x0001_0000 + i).collect()),
            PathAttribute::ExtendedCommunities(vec![ExtendedCommunity::new(0x0002_FDE8_0000_0007)]),
            PathAttribute::LargeCommunities(vec![LargeCommunity {
                global_admin: 65001,
                local_data1: 7,
                local_data2: 9,
            }]),
            PathAttribute::OriginatorId(Ipv4Addr::new(10, 0, 0, 9)),
            PathAttribute::ClusterList(vec![Ipv4Addr::new(10, 0, 0, 1)]),
        ]
    }

    /// The pre-borrowed-encode construction: clone the attribute Vec,
    /// insert the extra attribute, `try_build` + encode. The M81
    /// receipt pinned these bytes; the piecewise borrowed encode must
    /// reproduce them exactly.
    fn clone_based_oracle(
        announced: &[Ipv4NlriEntry],
        attrs: &[PathAttribute],
        insert_pos: usize,
        extra: PathAttribute,
    ) -> Bytes {
        let mut cloned = attrs.to_vec();
        cloned.insert(insert_pos, extra);
        let update =
            UpdateMessage::try_build(announced, &[], &cloned, true, false, Ipv4UnicastMode::Body)
                .unwrap();
        let mut buf = BytesMut::with_capacity(update.encoded_len());
        update
            .encode_with_limit(&mut buf, EXTENDED_MAX_MESSAGE_LEN)
            .unwrap();
        buf.freeze()
    }

    #[test]
    fn borrowed_encode_unicast_v4_matches_clone_based_oracle() {
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 16);
        let nh = Ipv4Addr::new(192, 0, 2, 1);
        let mut route = unicast_route(Prefix::V4(prefix), IpAddr::V4(nh));
        route.attributes = Arc::new(rich_attrs());
        let insert_pos = 2; // after ORIGIN + AS_PATH
        let expected = clone_based_oracle(
            &[Ipv4NlriEntry { path_id: 0, prefix }],
            &rich_attrs(),
            insert_pos,
            PathAttribute::NextHop(nh),
        );
        assert_eq!(synthesize_unicast_announce(&route).unwrap(), expected);
    }

    #[test]
    fn borrowed_encode_unicast_mp_matches_clone_based_oracle() {
        // IPv6 unicast with a link-local next hop, and the RFC 8950
        // IPv4-prefix-over-IPv6-next-hop shape.
        for prefix in [
            Prefix::V6(Ipv6Prefix::new(
                "2001:db8:40::".parse::<Ipv6Addr>().unwrap(),
                48,
            )),
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 3, 0, 0), 16)),
        ] {
            let nh: IpAddr = "2001:db8::1".parse().unwrap();
            let mut route = unicast_route(prefix, nh);
            route.attributes = Arc::new(rich_attrs());
            route.link_local_next_hop = Some("fe80::1".parse().unwrap());
            let afi = match prefix {
                Prefix::V4(_) => Afi::Ipv4,
                Prefix::V6(_) => Afi::Ipv6,
            };
            let mut mp_reach = empty_mp_reach(afi, Safi::Unicast, nh);
            mp_reach.link_local_next_hop = route.link_local_next_hop;
            mp_reach.announced = vec![NlriEntry { path_id: 0, prefix }];
            let expected = clone_based_oracle(
                &[],
                &rich_attrs(),
                rich_attrs().len(),
                PathAttribute::MpReachNlri(mp_reach),
            );
            assert_eq!(synthesize_unicast_announce(&route).unwrap(), expected);
        }
    }

    #[test]
    fn borrowed_encode_vpn_matches_clone_based_oracle() {
        let mut route = vpn_route();
        route.attributes = Arc::new(rich_attrs());
        let mut mp_reach = empty_mp_reach(Afi::Ipv4, Safi::MplsVpn, route.next_hop);
        mp_reach.vpn_announced = vec![VpnNlriEntry {
            path_id: 0,
            nlri: route.nlri.clone(),
        }];
        let expected = clone_based_oracle(
            &[],
            &rich_attrs(),
            rich_attrs().len(),
            PathAttribute::MpReachNlri(mp_reach),
        );
        assert_eq!(synthesize_vpn_announce(&route).unwrap(), expected);
    }

    /// Attribute-less edge: a route whose attrs are empty still emits
    /// the injected attribute alone, identically to clone-and-insert.
    #[test]
    fn borrowed_encode_empty_attrs_matches_clone_based_oracle() {
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 9, 0, 0), 16);
        let nh = Ipv4Addr::new(192, 0, 2, 7);
        let mut route = unicast_route(Prefix::V4(prefix), IpAddr::V4(nh));
        route.attributes = Arc::new(vec![]);
        let expected = clone_based_oracle(
            &[Ipv4NlriEntry { path_id: 0, prefix }],
            &[],
            0,
            PathAttribute::NextHop(nh),
        );
        assert_eq!(synthesize_unicast_announce(&route).unwrap(), expected);
    }

    #[test]
    fn end_of_rib_markers() {
        // IPv4 unicast EoR is the canonical 23-byte empty UPDATE.
        let eor = synthesize_end_of_rib(Afi::Ipv4, Safi::Unicast).unwrap();
        assert_eq!(eor.len(), 23);
        // MP EoR: only an empty MP_UNREACH for the family.
        let parsed = decode_pdu(&synthesize_end_of_rib(Afi::Ipv6, Safi::MplsVpn).unwrap());
        let mp = parsed
            .attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::MpUnreachNlri(mp) => Some(mp),
                _ => None,
            })
            .expect("MP_UNREACH present");
        assert_eq!((mp.afi, mp.safi), (Afi::Ipv6, Safi::MplsVpn));
        assert!(mp.withdrawn.is_empty() && mp.vpn_withdrawn.is_empty());
    }

    /// path-marking-05 §3.2 mapping: every decisive step with a
    /// registered Reason Code maps to it; steps the draft has no code
    /// for map to `None` (the field is optional — omit, don't lie).
    #[test]
    fn reason_code_mapping_covers_every_variant() {
        use rustbgpd_bmp::tlv;

        use crate::best_path::BestPathReason as R;
        let cases = [
            (R::HigherLocalPref, Some(tlv::REASON_LOCAL_PREF)),
            (R::ShorterAsPath, Some(tlv::REASON_AS_PATH_LEN)),
            (R::LowerOrigin, Some(tlv::REASON_ORIGIN)),
            (R::LowerMed, Some(tlv::REASON_MED)),
            (R::EbgpOverIbgp, Some(tlv::REASON_PEER_TYPE)),
            (R::OrrInteriorCost, Some(tlv::REASON_IGP_COST)),
            (R::LowerOriginatorId, Some(tlv::REASON_ROUTER_ID)),
            (R::LowerPeerAddress, Some(tlv::REASON_PEER_ADDRESS)),
            (R::StalePreference, None),
            (R::RpkiPreference, None),
            (R::AspaPreference, None),
            (R::ShorterClusterList, None),
            (R::EvpnMacMobility, None),
        ];
        for (reason, expected) in cases {
            assert_eq!(
                path_marking_reason_code(reason),
                expected,
                "mapping for {reason:?}"
            );
        }
        // Numeric pins straight from Table 2 so a constant edit in the
        // bmp crate cannot silently shift the wire values.
        assert_eq!(path_marking_reason_code(R::HigherLocalPref), Some(0x0003));
        assert_eq!(path_marking_reason_code(R::LowerPeerAddress), Some(0x000A));
    }

    /// path-marking-05 §3.1: Loc-RIB payloads always carry Best
    /// (0x00000002); the GR/LLGR stale flag adds Stale (0x00000400).
    #[test]
    fn loc_rib_path_status_bits() {
        let fresh = loc_rib_path_status(false, None);
        assert_eq!(fresh.status, 0x0000_0002);
        assert_eq!(fresh.reason, None);

        let stale = loc_rib_path_status(true, Some(BestPathReason::HigherLocalPref));
        assert_eq!(stale.status, 0x0000_0402);
        assert_eq!(stale.reason, Some(0x0003));

        // A decisive step without a registered code yields no reason.
        let unmapped = loc_rib_path_status(false, Some(BestPathReason::RpkiPreference));
        assert_eq!(unmapped.reason, None);
    }

    /// The fabricated OPEN (RFC 9069 §5.2.1) carries the 4-octet-ASN
    /// capability and one MP capability per streamed family, with
    /// `AS_TRANS` in the 2-byte field for a >65535 local ASN.
    #[test]
    fn fabricated_open_carries_required_capabilities() {
        let router_id = Ipv4Addr::new(10, 0, 0, 1);
        let pdu = loc_rib_open_pdu(4_200_000_777, router_id);
        let mut buf = pdu.clone();
        let header = BgpHeader::decode(&mut buf, EXTENDED_MAX_MESSAGE_LEN).unwrap();
        let open = OpenMessage::decode(&mut buf, usize::from(header.length) - 19).unwrap();
        assert_eq!(open.my_as, AS_TRANS);
        assert_eq!(open.bgp_identifier, router_id);
        assert_eq!(open.four_byte_as(), 4_200_000_777);
        for (afi, safi) in LOC_RIB_FAMILIES {
            assert!(
                open.capabilities
                    .iter()
                    .any(|c| *c == Capability::MultiProtocol { afi, safi }),
                "missing MP capability for {afi:?}/{safi:?}"
            );
        }
    }
}
