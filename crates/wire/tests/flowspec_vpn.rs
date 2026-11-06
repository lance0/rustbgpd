//! RFC 8955 §8 / RFC 8956 VPN `FlowSpec` (AFI 1/2 / SAFI 134) wire vectors.

use std::net::{Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;
use rustbgpd_wire::attribute::{decode_path_attributes, encode_path_attributes};
use rustbgpd_wire::flowspec::{
    decode_flowspec_nlri, decode_vpn_flowspec_nlri, decode_vpn_flowspec_nlri_for_afi,
    try_encode_flowspec_nlri, try_encode_vpn_flowspec_nlri, try_encode_vpn_flowspec_nlri_for_afi,
};
use rustbgpd_wire::{
    Afi, BitmaskMatch, DecodeError, EncodeError, FlowSpecComponent, FlowSpecPrefix, FlowSpecRule,
    Ipv4Prefix, Ipv6Prefix, Ipv6PrefixOffset, MpReachNlri, MpUnreachNlri, NumericMatch,
    PathAttribute, RouteDistinguisher, Safi, VpnFlowSpecRule, family_label, parse_family,
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
fn vpn_flowspec_family_registry_covers_both_ip_families() {
    for (name, afi) in [
        ("l3vpn_ipv4_flowspec", Afi::Ipv4),
        ("l3vpn_ipv6_flowspec", Afi::Ipv6),
    ] {
        assert_eq!(parse_family(name), Some((afi, Safi::FlowSpecVpn)));
        assert_eq!(family_label(afi, Safi::FlowSpecVpn), Some(name));
    }
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
fn vpn_flowspec_is_never_encoded_outside_ip_afis() {
    let rule = VpnFlowSpecRule {
        rd: RouteDistinguisher([0, 0, 0xad, 0x77, 0, 0, 0, 0x28]),
        rule: rule(),
    };
    for afi in [Afi::L2Vpn, Afi::BgpLs] {
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

fn ipv6_prefix(address: &str, len: u8, offset: u8) -> FlowSpecPrefix {
    FlowSpecPrefix::V6(Ipv6PrefixOffset {
        prefix: Ipv6Prefix::new(address.parse().unwrap(), len),
        offset,
    })
}

// Destination 2001:db8::/32, source ::1234:5678:9a00:0/64-104,
// upper-layer TCP, fragment bits LF/FF/IsF, Flow Label = 0xabcde.
const IPV6_RULE: [u8; 27] = [
    1, 32, 0, 0x20, 1, 0x0d, 0xb8, 2, 104, 64, 0x12, 0x34, 0x56, 0x78, 0x9a, 3, 0x81, 6, 12, 0x81,
    0x0e, 13, 0xa1, 0, 0x0a, 0xbc, 0xde,
];

fn ipv6_rule() -> FlowSpecRule {
    FlowSpecRule {
        components: vec![
            FlowSpecComponent::DestinationPrefix(ipv6_prefix("2001:db8::", 32, 0)),
            FlowSpecComponent::SourcePrefix(ipv6_prefix("::1234:5678:9a00:0", 104, 64)),
            FlowSpecComponent::IpProtocol(vec![eq(6, true)]),
            FlowSpecComponent::Fragment(vec![BitmaskMatch {
                end_of_list: true,
                and_bit: false,
                not_bit: false,
                match_bit: true,
                value: 0x0e,
            }]),
            FlowSpecComponent::FlowLabel(vec![eq(0x000a_bcde, true)]),
        ],
    }
}

fn ipv6_nlri(rd: [u8; 8], components: &[u8]) -> Vec<u8> {
    let mut wire = vec![u8::try_from(8 + components.len()).unwrap()];
    wire.extend(rd);
    wire.extend(components);
    wire
}

#[test]
fn ipv6_vpn_golden_vectors_cover_offsets_flow_label_and_each_rd_type() {
    for rd in [
        [0, 0, 0xad, 0x77, 0, 0, 0, 40],
        [0, 1, 192, 0, 2, 1, 0, 100],
        [0, 2, 0, 1, 0, 0, 0, 10],
        [0, 3, 1, 2, 3, 4, 5, 6],
    ] {
        let expected = VpnFlowSpecRule {
            rd: RouteDistinguisher(rd),
            rule: ipv6_rule(),
        };
        let nlri = ipv6_nlri(rd, &IPV6_RULE);
        assert_eq!(
            decode_vpn_flowspec_nlri_for_afi(&nlri, Afi::Ipv6).unwrap(),
            std::slice::from_ref(&expected)
        );
        let mut encoded = Vec::new();
        try_encode_vpn_flowspec_nlri_for_afi(
            std::slice::from_ref(&expected),
            &mut encoded,
            Afi::Ipv6,
        )
        .unwrap();
        assert_eq!(encoded, nlri);
        for (code, header) in [(14, vec![0, 2, 134, 0, 0]), (15, vec![0, 2, 134])] {
            let wire = attr(code, &[header, nlri.clone()].concat());
            let mut reach = mp_reach(vec![expected.clone()]);
            reach.afi = Afi::Ipv6;
            let mut unreach = mp_unreach(vec![expected.clone()]);
            unreach.afi = Afi::Ipv6;
            let expected_attr = if code == 14 {
                PathAttribute::MpReachNlri(Box::new(reach))
            } else {
                PathAttribute::MpUnreachNlri(Box::new(unreach))
            };
            assert_eq!(decode(&wire).unwrap(), std::slice::from_ref(&expected_attr));
            assert_eq!(encode(expected_attr), wire);
        }
    }
    let wire = attr(15, &[0, 2, 134]);
    let mut expected = mp_unreach(vec![]);
    expected.afi = Afi::Ipv6;
    assert_eq!(
        decode(&wire).unwrap(),
        [PathAttribute::MpUnreachNlri(Box::new(expected))]
    );
}

#[test]
fn ipv6_prefix_offsets_use_only_matching_bits_and_clear_padding() {
    for (len, offset, pattern, address, canonical) in [
        (0, 0, vec![], "::", vec![]),
        (71, 65, vec![0xff], "::7e00:0:0:0", vec![0xfc]),
        (128, 127, vec![0xff], "::1", vec![0x80]),
        (
            128,
            0,
            vec![0xff; 16],
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            vec![0xff; 16],
        ),
    ] {
        for kind in [1, 2] {
            let components = [vec![kind, len, offset], pattern.clone()].concat();
            let canonical = [vec![kind, len, offset], canonical.clone()].concat();
            let prefix = ipv6_prefix(address, len, offset);
            let rule = FlowSpecRule {
                components: vec![if kind == 1 {
                    FlowSpecComponent::DestinationPrefix(prefix)
                } else {
                    FlowSpecComponent::SourcePrefix(prefix)
                }],
            };
            let vpn = VpnFlowSpecRule {
                rd: RouteDistinguisher([0; 8]),
                rule: rule.clone(),
            };
            assert_eq!(
                decode_vpn_flowspec_nlri_for_afi(&ipv6_nlri([0; 8], &components), Afi::Ipv6)
                    .unwrap(),
                std::slice::from_ref(&vpn)
            );
            let mut wire = Vec::new();
            try_encode_vpn_flowspec_nlri_for_afi(&[vpn], &mut wire, Afi::Ipv6).unwrap();
            assert_eq!(wire, ipv6_nlri([0; 8], &canonical));
            let global = [vec![u8::try_from(components.len()).unwrap()], components].concat();
            assert_eq!(
                decode_flowspec_nlri(&global, Afi::Ipv6).unwrap(),
                std::slice::from_ref(&rule)
            );
            let mut wire = Vec::new();
            try_encode_flowspec_nlri(&[rule], &mut wire, Afi::Ipv6).unwrap();
            assert_eq!(&wire[1..], canonical);
        }
    }
}

#[test]
fn ipv6_malformed_prefixes_and_fragments_fail_the_whole_nlri_list() {
    let good = ipv6_nlri([0; 8], &IPV6_RULE);
    for components in [
        vec![1, 0, 1],
        vec![1, 128, 128],
        vec![2, 32, 32],
        vec![1, 129, 0],
        vec![2, 64, 65],
        vec![1, 32],
        vec![1, 64, 32, 1, 2, 3],
        vec![12, 0x91, 0, 2],
        vec![12, 0xa1, 0, 0, 0, 2],
        vec![12, 0x01, 2, 0x91, 0, 4],
    ] {
        let bad = ipv6_nlri([0; 8], &components);
        for wire in [bad.clone(), [good.clone(), bad].concat()] {
            assert!(
                decode_vpn_flowspec_nlri_for_afi(&wire, Afi::Ipv6).is_err(),
                "{wire:02x?}"
            );
        }
        let global = [vec![u8::try_from(components.len()).unwrap()], components].concat();
        assert!(decode_flowspec_nlri(&global, Afi::Ipv6).is_err());
    }
    for cut in 1..good.len() {
        assert!(
            decode_vpn_flowspec_nlri_for_afi(&good[..cut], Afi::Ipv6).is_err(),
            "{cut}"
        );
    }
    for bad in [
        vec![3, 0, 0, 1],
        vec![8, 0, 0, 0, 0, 0, 0, 0, 0],
        vec![0xf1, 0, 0],
    ] {
        assert!(decode_vpn_flowspec_nlri_for_afi(&bad, Afi::Ipv6).is_err());
    }
    let reach = [vec![0, 2, 134, 4, 192, 0, 2, 1, 0], good].concat();
    assert!(malformed_detail(decode(&attr(14, &reach)).unwrap_err()).contains("expected 0"));
}

#[test]
fn ipv6_fragment_reserved_bits_and_flow_label_widths_are_canonical() {
    for value in [0, 1, 0x000f_ffff, u64::MAX] {
        let rule = FlowSpecRule {
            components: vec![
                FlowSpecComponent::Fragment(vec![BitmaskMatch {
                    end_of_list: true,
                    and_bit: false,
                    not_bit: false,
                    match_bit: true,
                    value: 0x0e,
                }]),
                FlowSpecComponent::FlowLabel(vec![eq(value, true)]),
            ],
        };
        let mut global = Vec::new();
        try_encode_flowspec_nlri(std::slice::from_ref(&rule), &mut global, Afi::Ipv6).unwrap();
        assert_eq!(
            decode_flowspec_nlri(&global, Afi::Ipv6).unwrap(),
            std::slice::from_ref(&rule)
        );
        if value == 0x000f_ffff {
            assert_eq!(&global[4..], &[13, 0xa1, 0, 0x0f, 0xff, 0xff]);
        }
        global[3] = 0xff; // Received reserved fragment bits MUST be ignored.
        assert_eq!(
            decode_flowspec_nlri(&global, Afi::Ipv6).unwrap(),
            std::slice::from_ref(&rule)
        );
        let vpn = VpnFlowSpecRule {
            rd: RouteDistinguisher([0; 8]),
            rule,
        };
        let mut wire = Vec::new();
        try_encode_vpn_flowspec_nlri_for_afi(std::slice::from_ref(&vpn), &mut wire, Afi::Ipv6)
            .unwrap();
        wire[11] = 0xff;
        assert_eq!(
            decode_vpn_flowspec_nlri_for_afi(&wire, Afi::Ipv6).unwrap(),
            [vpn]
        );
    }
    let mut rule = FlowSpecRule {
        components: vec![FlowSpecComponent::Fragment(vec![BitmaskMatch {
            end_of_list: true,
            and_bit: false,
            not_bit: false,
            match_bit: true,
            value: u16::MAX,
        }])],
    };
    let mut wire = Vec::new();
    try_encode_flowspec_nlri(std::slice::from_ref(&rule), &mut wire, Afi::Ipv6).unwrap();
    assert_eq!(wire, [3, 12, 0x81, 0x0e]);
    rule.components = vec![FlowSpecComponent::FlowLabel(vec![eq(1, true); 2047])];
    let mut wire = Vec::new();
    try_encode_flowspec_nlri(&[rule], &mut wire, Afi::Ipv6).unwrap();
    assert_eq!(
        wire.len(),
        4097,
        "minimal numeric widths preserve the 4095-octet bound"
    );
    let decoded = decode_flowspec_nlri(&wire, Afi::Ipv6).unwrap();
    let mut roundtrip = Vec::new();
    try_encode_flowspec_nlri(&decoded, &mut roundtrip, Afi::Ipv6).unwrap();
    assert_eq!(roundtrip, wire);
}

#[test]
fn ipv6_vpn_rd_inclusive_length_boundaries() {
    let rd = RouteDistinguisher([0; 8]);
    let mut rule_240 = port_rule(229);
    rule_240.components.insert(
        0,
        FlowSpecComponent::DestinationPrefix(ipv6_prefix("::", 0, 0)),
    );
    let mut too_large = port_rule(4085);
    too_large.components.insert(
        0,
        FlowSpecComponent::DestinationPrefix(ipv6_prefix("::", 0, 0)),
    );
    for (rule, header, payload) in [
        (
            port_rule(231),
            vec![0xef],
            [vec![0; 8], port_bytes(115)].concat(),
        ),
        (
            rule_240,
            vec![0xf0, 0xf0],
            [vec![0; 8], vec![1, 0, 0], port_bytes(114)].concat(),
        ),
        (
            port_rule(4087),
            vec![0xff, 0xff],
            [vec![0; 8], port_bytes(2043)].concat(),
        ),
    ] {
        let vpn = VpnFlowSpecRule { rd, rule };
        let golden = [header, payload].concat();
        let mut encoded = Vec::new();
        try_encode_vpn_flowspec_nlri_for_afi(std::slice::from_ref(&vpn), &mut encoded, Afi::Ipv6)
            .unwrap();
        assert_eq!(encoded, golden);
        assert_eq!(
            decode_vpn_flowspec_nlri_for_afi(&golden, Afi::Ipv6).unwrap(),
            [vpn]
        );
    }
    let mut buf = vec![0xaa];
    let error = try_encode_vpn_flowspec_nlri_for_afi(
        &[
            VpnFlowSpecRule {
                rd,
                rule: ipv6_rule(),
            },
            VpnFlowSpecRule {
                rd,
                rule: too_large,
            },
        ],
        &mut buf,
        Afi::Ipv6,
    )
    .unwrap_err();
    assert_eq!(
        error,
        EncodeError::ValueOutOfRange {
            field: "FlowSpec NLRI rule length",
            value: "4096".into()
        }
    );
    assert_eq!(buf, [0xaa]);
    try_encode_flowspec_nlri(&[port_rule(4095)], &mut buf, Afi::Ipv6).unwrap();
}

#[test]
fn invalid_typed_prefixes_refuse_encoding_without_partial_output() {
    for (afi, prefix) in [
        (Afi::Ipv4, ipv6_prefix("2001:db8::", 32, 0)),
        (
            Afi::Ipv6,
            FlowSpecPrefix::V4(Ipv4Prefix::new(Ipv4Addr::LOCALHOST, 32)),
        ),
        (Afi::Ipv6, ipv6_prefix("::", 64, 64)),
        (Afi::Ipv6, ipv6_prefix("::", 0, 1)),
    ] {
        let invalid = FlowSpecRule {
            components: vec![FlowSpecComponent::DestinationPrefix(prefix)],
        };
        let mut buf = vec![0xaa];
        assert!(try_encode_flowspec_nlri(std::slice::from_ref(&invalid), &mut buf, afi).is_err());
        assert_eq!(buf, [0xaa]);
        assert!(
            try_encode_vpn_flowspec_nlri_for_afi(
                &[VpnFlowSpecRule {
                    rd: RouteDistinguisher([0; 8]),
                    rule: invalid,
                }],
                &mut buf,
                afi
            )
            .is_err()
        );
        assert_eq!(buf, [0xaa]);
    }
}

proptest! {
    #[test]
    fn ipv6_vpn_prefix_offsets_round_trip(length in 1_u8..=128, offset in any::<u8>(), address in any::<u128>()) {
        let offset = offset % length;
        let prefix = Ipv6PrefixOffset { prefix: Ipv6Prefix::new(Ipv6Addr::from(address & (u128::MAX >> offset)), length), offset };
        let vpn = VpnFlowSpecRule { rd: RouteDistinguisher([0; 8]), rule: FlowSpecRule {
            components: vec![FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V6(prefix))],
        } };
        let mut wire = Vec::new();
        try_encode_vpn_flowspec_nlri_for_afi(std::slice::from_ref(&vpn), &mut wire, Afi::Ipv6).unwrap();
        prop_assert_eq!(decode_vpn_flowspec_nlri_for_afi(&wire, Afi::Ipv6).unwrap(), [vpn]);
    }
}
