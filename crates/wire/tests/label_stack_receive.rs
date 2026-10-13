//! Pin the RFC 3107 receive interpretation: NLRI bytes alone cannot distinguish
//! an S-clear single label from a valid longer stack (RFC 8277 §2.2).

use bytes::Bytes;
use rustbgpd_wire::{Afi, DecodeError, NotificationCode, PathAttribute, Safi, UpdateMessage};

const FAMILIES: [(Afi, Safi); 4] = [
    (Afi::Ipv4, Safi::LabeledUnicast),
    (Afi::Ipv6, Safi::LabeledUnicast),
    (Afi::Ipv4, Safi::MplsVpn),
    (Afi::Ipv6, Safi::MplsVpn),
];

fn nlri(afi: Afi, safi: Safi, labels: &[u8], prefix: bool) -> Vec<u8> {
    let mut value = labels.to_vec();
    if safi == Safi::MplsVpn {
        // RD 257:7; its first three bytes also form a BOS-terminated label.
        value.extend_from_slice(&[0, 0, 1, 1, 0, 0, 0, 7]);
    }
    if prefix {
        value.extend_from_slice(if afi == Afi::Ipv4 {
            &[203, 0, 113][..]
        } else {
            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0][..]
        });
    }
    let bits = u8::try_from(value.len() * 8).unwrap();
    let mut encoded = vec![bits];
    encoded.extend_from_slice(&value);
    encoded
}

fn update(afi: Afi, safi: Safi, nlri: &[u8], withdraw: bool, add_path: bool) -> UpdateMessage {
    let mut value = Vec::from((afi as u16).to_be_bytes());
    value.push(safi as u8);
    if !withdraw {
        let next_hop = if afi == Afi::Ipv4 {
            vec![192, 0, 2, 1]
        } else {
            vec![0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        };
        // VPN next hops prepend a zero RD.
        value.push(
            u8::try_from(next_hop.len() + if safi == Safi::MplsVpn { 8 } else { 0 }).unwrap(),
        );
        if safi == Safi::MplsVpn {
            value.extend_from_slice(&[0; 8]);
        }
        value.extend_from_slice(&next_hop);
        value.push(0);
    }
    if add_path {
        value.extend_from_slice(&7_u32.to_be_bytes());
    }
    value.extend_from_slice(nlri);
    let mut attributes = vec![0x80, if withdraw { 15 } else { 14 }];
    attributes.push(u8::try_from(value.len()).unwrap());
    attributes.extend_from_slice(&value);
    UpdateMessage {
        withdrawn_routes: Bytes::new(),
        path_attributes: Bytes::from(attributes),
        nlri: Bytes::new(),
    }
}

fn route(
    afi: Afi,
    safi: Safi,
    bytes: &[u8],
    add_path: bool,
) -> (Vec<u32>, String, Option<[u8; 8]>) {
    let families = if add_path { vec![(afi, safi)] } else { vec![] };
    let decoded = update(afi, safi, bytes, false, add_path)
        .parse_revised(true, true, false, &families)
        .unwrap();
    assert!(decoded.malformed.is_empty());
    let PathAttribute::MpReachNlri(mp) = &decoded.update.attributes[0] else {
        panic!("expected MP_REACH_NLRI");
    };
    if safi == Safi::MplsVpn {
        let [entry] = mp.vpn_announced.as_slice() else {
            panic!("expected one VPN route");
        };
        assert_eq!(entry.path_id, if add_path { 7 } else { 0 });
        (
            entry.nlri.labels.iter().map(|label| label.label).collect(),
            entry.nlri.prefix.to_string(),
            Some(entry.nlri.route_distinguisher.0),
        )
    } else {
        let [entry] = mp.labeled_announced.as_slice() else {
            panic!("expected one labeled route");
        };
        assert_eq!(entry.path_id, if add_path { 7 } else { 0 });
        (
            entry.nlri.labels.iter().map(|label| label.label).collect(),
            entry.nlri.prefix.to_string(),
            None,
        )
    }
}

#[test]
fn single_label_with_bos_and_real_two_label_stack_preserve_the_route_key() {
    for (afi, safi) in FAMILIES {
        for add_path in [false, true] {
            let one = route(afi, safi, &nlri(afi, safi, &[0, 6, 0x41], true), add_path);
            let two = route(
                afi,
                safi,
                &nlri(afi, safi, &[0, 6, 0x40, 0, 12, 0x81], true),
                add_path,
            );
            assert_eq!(one.0, [100]);
            assert_eq!(two.0, [100, 200]);
            assert_eq!(
                one.2,
                (safi == Safi::MplsVpn).then_some([0, 0, 1, 1, 0, 0, 0, 7])
            );
            assert_eq!(
                one.1,
                if afi == Afi::Ipv4 {
                    "203.0.113.0/24"
                } else {
                    "2001:db8::/64"
                }
            );
            assert_eq!((&one.1, one.2), (&two.1, two.2));
        }
    }
}

#[test]
fn s_clear_bytes_are_ambiguous_and_keep_the_bos_terminated_route_identity() {
    assert_eq!(
        nlri(Afi::Ipv4, Safi::LabeledUnicast, &[0, 6, 0x40], true),
        [48, 0, 6, 0x40, 203, 0, 113]
    );
    for (afi, safi) in FAMILIES {
        for add_path in [false, true] {
            let compliant = route(afi, safi, &nlri(afi, safi, &[0, 6, 0x41], true), add_path);
            let ambiguous = route(afi, safi, &nlri(afi, safi, &[0, 6, 0x40], true), add_path);
            assert_eq!(ambiguous.0.len(), 2);
            assert_eq!(ambiguous.0[0], 100);
            assert_ne!((&compliant.1, compliant.2), (&ambiguous.1, ambiguous.2));
            if afi == Afi::Ipv4 {
                assert_eq!(ambiguous.1, "0.0.0.0/0");
            } else {
                assert_eq!(ambiguous.1, "b800::/40");
            }
            if safi == Safi::MplsVpn {
                assert_eq!(ambiguous.0, [100, 0]);
                assert_eq!(
                    ambiguous.2,
                    Some(if afi == Afi::Ipv4 {
                        [1, 0, 0, 0, 7, 203, 0, 113]
                    } else {
                        [1, 0, 0, 0, 7, 0x20, 1, 0x0d]
                    })
                );
            } else if afi == Afi::Ipv4 {
                assert_eq!(ambiguous.0, [100, 0xcb007]);
            }
        }
    }
}

#[test]
fn unlocatable_label_boundary_remains_fatal_for_revised_mp_announces_and_withdrawals() {
    for (afi, safi) in FAMILIES {
        for withdraw in [false, true] {
            for add_path in [false, true] {
                // No BOS and no prefix: the label or RD cannot be located.
                let mut bytes = nlri(afi, safi, &[0, 6, 0x40], false);
                if safi == Safi::MplsVpn {
                    bytes[4..].fill(0);
                }
                let families = if add_path { vec![(afi, safi)] } else { vec![] };
                let err = update(afi, safi, &bytes, withdraw, add_path)
                    .parse_revised(true, true, false, &families)
                    .unwrap_err();
                assert!(
                    matches!(err, DecodeError::UpdateAttributeError { subcode: 9, .. }),
                    "{afi:?}/{safi:?} withdraw={withdraw} Add-Path={add_path}: {err:?}"
                );
                let (code, subcode, data) = err.to_notification();
                assert_eq!(code, NotificationCode::UpdateMessage);
                assert_eq!(subcode, 9);
                assert_eq!(&data[..2], &[0x80, if withdraw { 15 } else { 14 }]);
            }
        }
    }
}
