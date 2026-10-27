use rustbgpd_wire::attribute::{decode_path_attributes, encode_path_attributes};
use rustbgpd_wire::{ExtendedCommunity, FlowSpecAction, Ipv6ExtendedCommunity, PathAttribute};

const V4: u64 = 0x010c_c000_020a_0000;
const V6: [u8; 20] = [
    0x00, 0x0c, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0, 0,
];

#[test]
fn direct_targets_use_the_current_draft_vectors() {
    for copy in [false, true] {
        let action = FlowSpecAction::RedirectToIp {
            addr: "192.0.2.10".parse().unwrap(),
            copy,
        };
        let community = ExtendedCommunity::from_flowspec_action(&action);
        assert_eq!(community.as_u64(), V4 | u64::from(copy));
        assert_eq!(community.as_flowspec_action(), Some(action));

        let community = Ipv6ExtendedCommunity::from_flowspec_redirect_to_ip(
            "2001:db8::10".parse().unwrap(),
            copy,
        );
        let mut expected = V6;
        expected[19] = u8::from(copy);
        assert_eq!(community.as_bytes(), &expected);
        assert_eq!(
            community.as_flowspec_redirect_to_ip(),
            Some(("2001:db8::10".parse().unwrap(), copy))
        );
    }
}

#[test]
fn direct_target_interpretation_does_not_conflate_other_actions() {
    for raw in [
        0x0800_c000_020a_0000,
        0x8108_c000_020a_0000,
        0x800c_0000_0000_0000,
    ] {
        assert!(!matches!(
            ExtendedCommunity::new(raw).as_flowspec_action(),
            Some(FlowSpecAction::RedirectToIp { .. })
        ));
    }
    let mut vrf = V6;
    vrf[1] = 0x0d;
    assert_eq!(
        Ipv6ExtendedCommunity::new(vrf).as_flowspec_redirect_to_ip(),
        None
    );
}

#[test]
fn received_reserved_bits_are_ignored_but_raw_values_survive() {
    for copy in [false, true] {
        let raw = V4 | 0xfffe | u64::from(copy);
        let community = ExtendedCommunity::new(raw);
        let action = community.as_flowspec_action().unwrap();
        assert_eq!(community.as_u64(), raw);
        assert_eq!(
            ExtendedCommunity::from_flowspec_action(&action).as_u64(),
            V4 | u64::from(copy)
        );

        let mut raw = V6;
        raw[18] = 0xff;
        raw[19] = 0xfe | u8::from(copy);
        let community = Ipv6ExtendedCommunity::new(raw);
        let (address, observed_copy) = community.as_flowspec_redirect_to_ip().unwrap();
        assert_eq!(observed_copy, copy);
        assert_eq!(community.as_bytes(), &raw);
        let mut canonical = V6;
        canonical[19] = u8::from(copy);
        assert_eq!(
            Ipv6ExtendedCommunity::from_flowspec_redirect_to_ip(address, observed_copy).as_bytes(),
            &canonical
        );
    }
}

#[test]
fn ipv6_targets_travel_in_attribute_25_without_truncation_or_invented_partial() {
    for partial in [false, true] {
        for count in [1, 14] {
            let values = vec![Ipv6ExtendedCommunity::new(V6); count];
            let attribute = if partial {
                PathAttribute::Ipv6ExtendedCommunitiesPartial(values)
            } else {
                PathAttribute::Ipv6ExtendedCommunities(values)
            };
            let mut encoded = Vec::new();
            encode_path_attributes(std::slice::from_ref(&attribute), &mut encoded, true, false)
                .unwrap();
            let flags = 0xc0 | if partial { 0x20 } else { 0 };
            if count == 1 {
                assert_eq!(&encoded[..3], &[flags, 25, 20]);
                assert_eq!(&encoded[3..], &V6);
            } else {
                assert_eq!(&encoded[..4], &[flags | 0x10, 25, 0x01, 0x18]);
                assert_eq!(&encoded[4..], V6.repeat(count));
            }
            assert_eq!(
                decode_path_attributes(&encoded, true, &[]).unwrap(),
                vec![attribute]
            );
        }
    }
}

#[test]
fn empty_ipv6_extended_communities_cannot_be_encoded() {
    for attribute in [
        PathAttribute::Ipv6ExtendedCommunities(Vec::new()),
        PathAttribute::Ipv6ExtendedCommunitiesPartial(Vec::new()),
    ] {
        let mut encoded = Vec::new();
        assert!(matches!(
            encode_path_attributes(&[attribute], &mut encoded, true, false),
            Err(rustbgpd_wire::EncodeError::ValueOutOfRange { .. })
        ));
    }
}
