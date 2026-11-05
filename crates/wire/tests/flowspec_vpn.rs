//! RFC 8955 §8 VPN `FlowSpec` (AFI 1 / SAFI 134) wire vectors.

use std::net::Ipv4Addr;

use proptest::prelude::*;
use rustbgpd_wire::attribute::{decode_path_attributes, encode_path_attributes};
use rustbgpd_wire::flowspec::{
    decode_flowspec_nlri, decode_vpn_flowspec_nlri, try_encode_flowspec_nlri,
    try_encode_vpn_flowspec_nlri,
};
use rustbgpd_wire::{
    Afi, BitmaskMatch, DecodeError, EncodeError, FlowSpecComponent, FlowSpecPrefix, FlowSpecRule,
    Ipv4Prefix, MpReachNlri, MpUnreachNlri, NumericMatch, PathAttribute, RouteDistinguisher, Safi,
    VpnFlowSpecRule, family_label, parse_family,
};

/// `01 20 cb00710a 03 81 11`: destination 203.0.113.10/32, protocol = 17.
const RULE: [u8; 9] = [0x01, 0x20, 0xcb, 0x00, 0x71, 0x0a, 0x03, 0x81, 0x11];

fn rule() -> FlowSpecRule {
    FlowSpecRule {
        components: vec![
            FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V4(Ipv4Prefix::new(
                Ipv4Addr::new(203, 0, 113, 10),
                32,
            ))),
            FlowSpecComponent::IpProtocol(vec![eq(17, true)]),
        ],
    }
}

fn eq(value: u64, end_of_list: bool) -> NumericMatch {
    NumericMatch {
        end_of_list,
        and_bit: false,
        lt: false,
        gt: false,
        eq: true,
        value,
    }
}

/// A port rule whose components are exactly `len` octets (odd, at least 3).
fn port_rule(len: usize) -> FlowSpecRule {
    assert!(len >= 3 && len % 2 == 1);
    let terms = (len - 1) / 2;
    FlowSpecRule {
        components: vec![FlowSpecComponent::Port(
            (0..terms).map(|i| eq(80, i + 1 == terms)).collect(),
        )],
    }
}

fn nlri(rd: [u8; 8]) -> Vec<u8> {
    let mut out = vec![u8::try_from(8 + RULE.len()).unwrap()];
    out.extend_from_slice(&rd);
    out.extend_from_slice(&RULE);
    out
}

fn mp_reach(rules: Vec<VpnFlowSpecRule>) -> MpReachNlri {
    MpReachNlri {
        afi: Afi::Ipv4,
        safi: Safi::FlowSpecVpn,
        next_hop: Ipv4Addr::UNSPECIFIED.into(),
        link_local_next_hop: None,
        announced: vec![],
        flowspec_announced: vec![],
        evpn_announced: vec![],
        bgpls_announced: vec![],
        vpn_announced: vec![],
        labeled_announced: vec![],
        rtc_announced: vec![],
        vpn_flowspec_announced: rules,
    }
}

fn mp_unreach(rules: Vec<VpnFlowSpecRule>) -> MpUnreachNlri {
    MpUnreachNlri {
        afi: Afi::Ipv4,
        safi: Safi::FlowSpecVpn,
        withdrawn: vec![],
        flowspec_withdrawn: vec![],
        evpn_withdrawn: vec![],
        bgpls_withdrawn: vec![],
        vpn_withdrawn: vec![],
        labeled_withdrawn: vec![],
        rtc_withdrawn: vec![],
        vpn_flowspec_withdrawn: rules,
    }
}

/// One optional attribute with a one-octet length.
fn attr(type_code: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![0x80, type_code, u8::try_from(value.len()).unwrap()];
    out.extend_from_slice(value);
    out
}

fn decode(bytes: &[u8]) -> Result<Vec<PathAttribute>, DecodeError> {
    decode_path_attributes(bytes, true, &[])
}

fn encode(attribute: PathAttribute) -> Vec<u8> {
    let mut out = Vec::new();
    encode_path_attributes(&[attribute], &mut out, true, false).unwrap();
    out
}

/// The detail of a malformed NLRI, either from the NLRI codec or wrapped by
/// the path-attribute decoder as an RFC 7606 Optional Attribute Error.
fn malformed_detail(error: DecodeError) -> String {
    match error {
        DecodeError::MalformedField { detail, .. } => detail,
        DecodeError::UpdateAttributeError {
            subcode: 9, detail, ..
        } => detail,
        other => panic!("expected a malformed-NLRI error, got {other:?}"),
    }
}

#[test]
fn golden_vectors_for_each_rd_type_round_trip() {
    for (rd, text) in [
        // Type 0: 44407:40.
        ([0, 0, 0xad, 0x77, 0, 0, 0, 0x28], "44407:40"),
        // Type 1: 192.0.2.1:100.
        ([0, 1, 192, 0, 2, 1, 0, 100], "192.0.2.1:100"),
        // Type 2: 65536:10.
        ([0, 2, 0, 1, 0, 0, 0, 10], "65536:10"),
        // Unknown type 3 stays raw on decode and re-encodes unchanged.
        ([0, 3, 1, 2, 3, 4, 5, 6], "0x0003010203040506"),
    ] {
        let expected = VpnFlowSpecRule {
            rd: RouteDistinguisher(rd),
            rule: rule(),
        };
        assert_eq!(expected.rd.to_string(), text);

        let mut reach = vec![0x00, 0x01, 0x86, 0x00, 0x00];
        reach.extend(nlri(rd));
        let wire = attr(14, &reach);
        let decoded = decode(&wire).unwrap();
        assert_eq!(
            decoded,
            [PathAttribute::MpReachNlri(Box::new(mp_reach(vec![
                expected.clone()
            ])))]
        );
        assert_eq!(encode(decoded[0].clone()), wire, "{text}");

        let mut unreach = vec![0x00, 0x01, 0x86];
        unreach.extend(nlri(rd));
        let wire = attr(15, &unreach);
        let decoded = decode(&wire).unwrap();
        assert_eq!(
            decoded,
            [PathAttribute::MpUnreachNlri(Box::new(mp_unreach(vec![
                expected
            ])))]
        );
        assert_eq!(encode(decoded[0].clone()), wire, "{text}");
    }
}

#[test]
fn end_of_rib_is_an_empty_mp_unreach() {
    let wire = attr(15, &[0x00, 0x01, 0x86]);
    let decoded = decode(&wire).unwrap();
    assert_eq!(
        decoded,
        [PathAttribute::MpUnreachNlri(Box::new(mp_unreach(vec![])))]
    );
    assert_eq!(encode(decoded[0].clone()), wire);
}

#[test]
fn route_distinguisher_alone_moves_the_length_past_240() {
    // 235 octets of components: one octet for SAFI 133, two for SAFI 134.
    let rule = port_rule(235);
    let mut global = Vec::new();
    try_encode_flowspec_nlri(std::slice::from_ref(&rule), &mut global, Afi::Ipv4).unwrap();
    assert_eq!(global[0], 235);
    assert_eq!(global.len(), 1 + 235);

    let vpn = VpnFlowSpecRule {
        rd: RouteDistinguisher([0, 0, 0xad, 0x77, 0, 0, 0, 0x28]),
        rule,
    };
    let mut wire = Vec::new();
    try_encode_vpn_flowspec_nlri(std::slice::from_ref(&vpn), &mut wire).unwrap();
    assert_eq!(&wire[..2], &[0xf0, 243]);
    assert_eq!(&wire[2..10], &vpn.rd.0);
    assert_eq!(&wire[10..], &global[1..]);
    assert_eq!(decode_vpn_flowspec_nlri(&wire).unwrap(), [vpn]);
}

/// Port terms (`=80`) written out by hand, independent of the encoder.
fn port_bytes(terms: usize) -> Vec<u8> {
    let mut out = vec![0x04];
    for i in 0..terms {
        out.extend([if i + 1 == terms { 0x81 } else { 0x01 }, 80]);
    }
    out
}

#[test]
fn rd_inclusive_payloads_of_239_and_240_octets() {
    let rd = [0, 0, 0xad, 0x77, 0, 0, 0, 0x28];
    // 239 = RD 8 + port 231: the largest one-octet length.
    let mut payload_239 = rd.to_vec();
    payload_239.extend(port_bytes(115));
    assert_eq!(payload_239.len(), 239);
    let rule_239 = VpnFlowSpecRule {
        rd: RouteDistinguisher(rd),
        rule: port_rule(231),
    };
    // 240 = RD 8 + destination 203.0.113.0/24 (5) + port 227: the smallest
    // two-octet length, which GoBGP v4.11.0 writes as 0xf0f0.
    let mut payload_240 = rd.to_vec();
    payload_240.extend([0x01, 0x18, 0xcb, 0x00, 0x71]);
    payload_240.extend(port_bytes(113));
    assert_eq!(payload_240.len(), 240);
    let mut rule = port_rule(227);
    rule.components.insert(
        0,
        FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V4(Ipv4Prefix::new(
            Ipv4Addr::new(203, 0, 113, 0),
            24,
        ))),
    );
    let rule_240 = VpnFlowSpecRule {
        rd: RouteDistinguisher(rd),
        rule,
    };

    for (rule, header, payload) in [
        (&rule_239, &[0xef][..], &payload_239),
        (&rule_240, &[0xf0, 0xf0][..], &payload_240),
    ] {
        let golden = [header, payload.as_slice()].concat();
        let mut wire = Vec::new();
        try_encode_vpn_flowspec_nlri(std::slice::from_ref(rule), &mut wire).unwrap();
        assert_eq!(wire, golden, "encode {}", payload.len());
        assert_eq!(
            decode_vpn_flowspec_nlri(&golden).unwrap(),
            std::slice::from_ref(rule),
            "decode {}",
            payload.len()
        );
    }
    // GoBGP keeps a received two-octet form when it re-encodes, so 239 can
    // also arrive as 0xf0ef. It decodes to the same rule and re-encodes
    // canonically.
    let two_octet = [&[0xf0, 0xef][..], &payload_239].concat();
    assert_eq!(decode_vpn_flowspec_nlri(&two_octet).unwrap(), [rule_239]);
}

#[test]
fn the_4095_octet_bound_includes_the_route_distinguisher() {
    let rd = RouteDistinguisher([0, 1, 192, 0, 2, 1, 0, 100]);
    let fits = VpnFlowSpecRule {
        rd,
        rule: port_rule(4087),
    };
    let mut wire = Vec::new();
    try_encode_vpn_flowspec_nlri(std::slice::from_ref(&fits), &mut wire).unwrap();
    assert_eq!(&wire[..2], &[0xff, 0xff]);
    assert_eq!(wire.len(), 2 + 4095);
    assert_eq!(decode_vpn_flowspec_nlri(&wire).unwrap(), [fits]);

    // 4089 octets fit SAFI 133 but not SAFI 134, and a refusal leaves the
    // buffer as it was.
    let rule = port_rule(4089);
    try_encode_flowspec_nlri(std::slice::from_ref(&rule), &mut Vec::new(), Afi::Ipv4).unwrap();
    let mut wire = vec![0xaa];
    let error =
        try_encode_vpn_flowspec_nlri(&[VpnFlowSpecRule { rd, rule }], &mut wire).unwrap_err();
    assert_eq!(
        error,
        EncodeError::ValueOutOfRange {
            field: "FlowSpec NLRI rule length",
            value: "4097".to_string(),
        }
    );
    assert_eq!(wire, [0xaa]);
}

#[test]
fn malformed_nlri_is_refused() {
    let rd = [0, 0, 0xad, 0x77, 0, 0, 0, 0x28];
    // A length below the 8-octet RD.
    let detail = malformed_detail(decode_vpn_flowspec_nlri(&[5, 0, 0, 0xad, 0x77, 0]).unwrap_err());
    assert!(
        detail.contains("shorter than its 8-octet Route Distinguisher"),
        "{detail}"
    );
    // An RD with no components.
    let mut wire = vec![8];
    wire.extend_from_slice(&rd);
    let detail = malformed_detail(decode_vpn_flowspec_nlri(&wire).unwrap_err());
    assert!(detail.contains("no components"), "{detail}");
    // Truncated input: the length promises more than the buffer holds.
    let whole = nlri(rd);
    for cut in 1..whole.len() {
        assert!(decode_vpn_flowspec_nlri(&whole[..cut]).is_err(), "{cut}");
    }
    // An extended length that overruns the buffer.
    let mut wire = vec![0xf1, 0x00];
    wire.extend(&whole[1..]);
    let detail = malformed_detail(decode_vpn_flowspec_nlri(&wire).unwrap_err());
    assert!(detail.contains("truncated: need 256"), "{detail}");
}

#[test]
fn malformed_second_nlri_does_not_misframe_the_first() {
    let first = nlri([0, 0, 0xad, 0x77, 0, 0, 0, 0x28]);
    let second = nlri([0, 2, 0, 1, 0, 0, 0, 10]);
    let both = [first.clone(), second].concat();
    let decoded = decode_vpn_flowspec_nlri(&both).unwrap();
    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded[0].rd.to_string(), "44407:40");
    assert_eq!(decoded[1].rd.to_string(), "65536:10");

    // A second NLRI too short for its RD fails the whole attribute, with the
    // error naming the second NLRI's length, not a shifted reading of the first.
    let mut bad = first.clone();
    bad.extend([3, 0, 0, 1]);
    let detail = malformed_detail(decode_vpn_flowspec_nlri(&bad).unwrap_err());
    assert!(detail.contains("NLRI length 3"), "{detail}");
    // Reading the same bytes as SAFI 133 frames them differently: the RD
    // octets are not a rule, so the families cannot be decoded as each other.
    assert!(decode_flowspec_nlri(&first, Afi::Ipv4).is_err());
}

#[test]
fn non_zero_next_hop_length_is_refused() {
    let mut reach = vec![0x00, 0x01, 0x86, 0x04, 192, 0, 2, 1, 0x00];
    reach.extend(nlri([0, 0, 0xad, 0x77, 0, 0, 0, 0x28]));
    let detail = malformed_detail(decode(&attr(14, &reach)).unwrap_err());
    assert!(
        detail.contains("next-hop length 4 (expected 0)"),
        "{detail}"
    );
}

#[test]
fn ipv6_vpn_flowspec_stays_unsupported() {
    let mut reach = vec![0x00, 0x02, 0x86, 0x00, 0x00];
    reach.extend(nlri([0, 0, 0xad, 0x77, 0, 0, 0, 0x28]));
    let detail = malformed_detail(decode(&attr(14, &reach)).unwrap_err());
    assert!(detail.contains("unsupported AFI/SAFI 2/134"), "{detail}");
    let detail = malformed_detail(decode(&attr(15, &[0x00, 0x02, 0x86])).unwrap_err());
    assert!(detail.contains("unsupported AFI/SAFI 2/134"), "{detail}");

    assert_eq!(
        parse_family("l3vpn_ipv4_flowspec"),
        Some((Afi::Ipv4, Safi::FlowSpecVpn))
    );
    assert_eq!(family_label(Afi::Ipv6, Safi::FlowSpecVpn), None);
    assert_eq!(Safi::from_u8(134), Some(Safi::FlowSpecVpn));
}

#[test]
fn ipv6_flow_label_is_malformed_in_ipv4_vpn_flowspec() {
    // RD 44407:40, then type 13 (Flow Label, IPv6-only per RFC 8956) = 1.
    let mut nlri = vec![11, 0, 0, 0xad, 0x77, 0, 0, 0, 0x28];
    nlri.extend([0x0d, 0x81, 0x01]);
    let mut reach = vec![0x00, 0x01, 0x86, 0x00, 0x00];
    reach.extend(&nlri);
    let mut unreach = vec![0x00, 0x01, 0x86];
    unreach.extend(&nlri);
    for wire in [attr(14, &reach), attr(15, &unreach)] {
        let detail = malformed_detail(decode(&wire).unwrap_err());
        assert!(detail.contains("component type 13"), "{detail}");
    }
}

#[test]
fn vpn_flowspec_is_never_encoded_outside_afi_1() {
    let rule = VpnFlowSpecRule {
        rd: RouteDistinguisher([0, 0, 0xad, 0x77, 0, 0, 0, 0x28]),
        rule: rule(),
    };
    for afi in [Afi::Ipv6, Afi::L2Vpn, Afi::BgpLs] {
        let mut reach = mp_reach(vec![rule.clone()]);
        reach.afi = afi;
        let mut unreach = mp_unreach(vec![rule.clone()]);
        unreach.afi = afi;
        for attribute in [
            PathAttribute::MpReachNlri(Box::new(reach)),
            PathAttribute::MpUnreachNlri(Box::new(unreach)),
        ] {
            let mut wire = vec![0xaa, 0xbb];
            let error = encode_path_attributes(&[attribute], &mut wire, true, false).unwrap_err();
            assert_eq!(
                error,
                EncodeError::ValueOutOfRange {
                    field: "VPN FlowSpec AFI",
                    value: (afi as u16).to_string(),
                }
            );
            assert_eq!(wire, [0xaa, 0xbb], "a refused encode leaves the buffer");
        }
    }
}

fn arb_numeric() -> impl Strategy<Value = Vec<NumericMatch>> {
    prop::collection::vec(
        (
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            any::<u64>(),
        ),
        1..4,
    )
    .prop_map(|terms| {
        let last = terms.len() - 1;
        terms
            .into_iter()
            .enumerate()
            .map(|(i, (and_bit, lt, gt, eq, value))| NumericMatch {
                end_of_list: i == last,
                and_bit,
                lt,
                gt,
                eq,
                value,
            })
            .collect()
    })
}

fn arb_bitmask() -> impl Strategy<Value = Vec<BitmaskMatch>> {
    prop::collection::vec(
        (any::<bool>(), any::<bool>(), any::<bool>(), any::<u16>()),
        1..4,
    )
    .prop_map(|terms| {
        let last = terms.len() - 1;
        terms
            .into_iter()
            .enumerate()
            .map(|(i, (and_bit, not_bit, match_bit, value))| BitmaskMatch {
                end_of_list: i == last,
                and_bit,
                not_bit,
                match_bit,
                value,
            })
            .collect()
    })
}

fn arb_rule() -> impl Strategy<Value = FlowSpecRule> {
    (
        prop::option::of((any::<u32>(), 0..=32_u8)),
        prop::option::of(arb_numeric()),
        prop::option::of(arb_numeric()),
        prop::option::of(arb_bitmask()),
        prop::option::of(arb_numeric()),
    )
        .prop_filter_map(
            "a rule needs a component",
            |(dst, proto, port, flags, dscp)| {
                let components: Vec<_> = [
                    dst.map(|(addr, len)| {
                        FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V4(Ipv4Prefix::new(
                            addr.into(),
                            len,
                        )))
                    }),
                    proto.map(FlowSpecComponent::IpProtocol),
                    port.map(FlowSpecComponent::DestinationPort),
                    flags.map(FlowSpecComponent::TcpFlags),
                    dscp.map(FlowSpecComponent::Dscp),
                ]
                .into_iter()
                .flatten()
                .collect();
                (!components.is_empty()).then_some(FlowSpecRule { components })
            },
        )
}

proptest! {
    #[test]
    fn vpn_flowspec_nlri_round_trips(
        rules in prop::collection::vec((any::<[u8; 8]>(), arb_rule()), 1..4),
    ) {
        let rules: Vec<_> = rules
            .into_iter()
            .map(|(rd, rule)| VpnFlowSpecRule { rd: RouteDistinguisher(rd), rule })
            .collect();
        let wire = encode(PathAttribute::MpReachNlri(Box::new(mp_reach(rules.clone()))));
        let decoded = decode(&wire).unwrap();
        prop_assert_eq!(
            &decoded,
            &[PathAttribute::MpReachNlri(Box::new(mp_reach(rules.clone())))]
        );
        prop_assert_eq!(encode(decoded[0].clone()), wire);

        let wire = encode(PathAttribute::MpUnreachNlri(Box::new(mp_unreach(rules.clone()))));
        prop_assert_eq!(
            decode(&wire).unwrap(),
            [PathAttribute::MpUnreachNlri(Box::new(mp_unreach(rules)))]
        );
    }
}
