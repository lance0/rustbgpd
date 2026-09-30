//! One-off, opt-in differential for uncompressed BGP4MP UPDATE dumps.
//! Compares IPv4/IPv6 unicast NLRI, including Add-Path IDs; other MP families fail closed.
//! Pinned 2026-09-30 00:00 UTC files (download outside Git, verify with sha256sum, decompress):
//! RIS rrc03: https://data.ris.ripe.net/rrc03/2026.09/updates.20260930.0000.gz
//!   50a97ec55a6f6cbe8eb46cf9555a10c39d5729b0af87f7569136167fecce3ca4
//! RouteViews route-views2:
//!   https://archive.routeviews.org/route-views2/bgpdata/2026.09/UPDATES/updates.20260930.0000.bz2
//!   1d0eb3ed48cdaef7a40ebbdaabe1bb8e830f6fe60391c5b60e57196e0551f469
//! Run once per decompressed file:
//! MRT_DIFFERENTIAL_PATH=/path/to/updates.mrt MRT_DIFFERENTIAL_OUT=/path/to/output \
//!   cargo test --test mrt_real_differential real_updates -- --ignored --nocapture
//! RFC 7606 differences require an individual verdict; only RFC 9774 AS_SET is pre-exempted.
use bgpkit_parser::models::{
    Afi as KitAfi, AsPathSegment as KitSegment, AsnLength, AttributeValue, Bgp4MpEnum, BgpMessage,
    BgpUpdateMessage, Community, MetaCommunity, MrtMessage, NetworkPrefix, Nlri, Safi as KitSafi,
};
use bgpkit_parser::parser::bgp::parse_bgp_message;
use bgpkit_parser::parser::mrt::chunk_mrt_record;
use bytes::{Bytes, BytesMut};
use rustbgpd_wire::constants::HEADER_LEN;
use rustbgpd_wire::{
    Afi, AsPathSegment, DecodeError, ErrorDisposition, Ipv4UnicastMode, Ipv6Prefix,
    MalformedAttribute, MpReachNlri, NlriEntry, PathAttribute, Prefix, RawAttribute,
    RevisedParsedUpdate, Safi, UpdateMessage,
};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Write};
use std::net::{IpAddr, Ipv6Addr};

#[derive(Debug, PartialEq, Eq)]
struct Shape {
    announced: Vec<(String, u32)>,
    withdrawn: Vec<(String, u32)>,
    path: Vec<String>,
    communities: Vec<String>,
    known: BTreeSet<u8>,
}

fn kit_prefix(n: &NetworkPrefix) -> (String, u32) {
    (n.prefix.to_string(), n.path_id.unwrap_or(0))
}

fn known_identity(kit: &BTreeSet<u8>, typed: &BTreeSet<u8>) -> BTreeSet<u8> {
    kit.difference(typed).copied().collect()
}

#[test]
#[should_panic(expected = "known attribute decoded as Unknown")]
fn known_attribute_negative_control() {
    let clean = std::fs::read("tests/fixtures/bgpkit/clean_ipv4_update.bin").unwrap();
    let mut body = Bytes::copy_from_slice(&clean[HEADER_LEN..]);
    let clean = UpdateMessage::decode(&mut body, clean.len() - HEADER_LEN)
        .unwrap()
        .parse_revised(true, false, false, &[])
        .unwrap()
        .update;
    let mut attributes = clean.attributes;
    attributes.push(PathAttribute::AtomicAggregate);
    let update = UpdateMessage::build(
        &clean.announced,
        &clean.withdrawn,
        &attributes,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    let mut bytes = BytesMut::new();
    update.encode(&mut bytes).unwrap();
    let mut kit_bytes = bytes.clone().freeze();
    let BgpMessage::Update(kit) =
        parse_bgp_message(&mut kit_bytes, false, &AsnLength::Bits32).unwrap()
    else {
        panic!("expected UPDATE")
    };
    let mut rust_bytes = bytes.freeze().slice(HEADER_LEN..);
    let body_len = rust_bytes.len();
    let mut rust = UpdateMessage::decode(&mut rust_bytes, body_len)
        .unwrap()
        .parse_revised(true, false, false, &[])
        .unwrap();
    assert!(
        verdict(&kit, &rust).is_none(),
        "valid ATOMIC_AGGREGATE must match"
    );
    *rust
        .update
        .attributes
        .iter_mut()
        .find(|a| matches!(a, PathAttribute::AtomicAggregate))
        .unwrap() = PathAttribute::Unknown(RawAttribute {
        flags: 0x40,
        type_code: 6,
        data: Bytes::new(),
    });
    let (category, reason) = verdict(&kit, &rust).expect("altered known attribute must differ");
    assert_eq!(category, "other");
    assert!(reason.contains("known_to_kit_but_unknown_to_rust={6}"));
    assert!(
        verdict(&kit, &rust).is_none(),
        "known attribute decoded as Unknown"
    );
}

#[test]
fn add_path_identity_negative_control() {
    let clean = std::fs::read("tests/fixtures/bgpkit/clean_ipv4_update.bin").unwrap();
    let mut body = Bytes::copy_from_slice(&clean[HEADER_LEN..]);
    let clean = UpdateMessage::decode(&mut body, clean.len() - HEADER_LEN)
        .unwrap()
        .parse_revised(true, false, false, &[])
        .unwrap()
        .update;
    let mut announced = clean.announced;
    assert!(!announced.is_empty());
    announced[0].path_id = 7;
    let update = UpdateMessage::build(
        &announced,
        &clean.withdrawn,
        &clean.attributes,
        true,
        true,
        Ipv4UnicastMode::Body,
    );
    let mut bytes = BytesMut::new();
    update.encode(&mut bytes).unwrap();
    let mut kit_bytes = bytes.clone().freeze();
    let BgpMessage::Update(kit) =
        parse_bgp_message(&mut kit_bytes, true, &AsnLength::Bits32).unwrap()
    else {
        panic!("expected UPDATE")
    };
    assert_eq!(kit.announced_prefixes[0].path_id, Some(7));
    let mut rust_bytes = bytes.freeze().slice(HEADER_LEN..);
    let body_len = rust_bytes.len();
    let mut rust = UpdateMessage::decode(&mut rust_bytes, body_len)
        .unwrap()
        .parse_revised(true, false, true, &[])
        .unwrap();
    assert_eq!(rust.update.announced[0].path_id, 7);
    assert!(
        verdict(&kit, &rust).is_none(),
        "valid Add-Path UPDATE must match"
    );
    rust.update.announced[0].path_id = 8;
    let (category, reason) = verdict(&kit, &rust).expect("changed path ID must differ");
    assert_eq!(category, "other");
    assert!(reason.contains("(\"203.0.113.0/24\", 7)"));
    assert!(reason.contains("(\"203.0.113.0/24\", 8)"));
}

#[test]
fn mp_add_path_unicast_control() {
    let clean = std::fs::read("tests/fixtures/bgpkit/clean_ipv4_update.bin").unwrap();
    let mut body = Bytes::copy_from_slice(&clean[HEADER_LEN..]);
    let clean = UpdateMessage::decode(&mut body, clean.len() - HEADER_LEN)
        .unwrap()
        .parse_revised(true, false, false, &[])
        .unwrap()
        .update;
    let mut attributes = clean.attributes;
    attributes.push(PathAttribute::MpReachNlri(Box::new(MpReachNlri {
        afi: Afi::Ipv6,
        safi: Safi::Unicast,
        next_hop: IpAddr::V6(Ipv6Addr::LOCALHOST),
        link_local_next_hop: None,
        announced: vec![NlriEntry {
            path_id: 7,
            prefix: Prefix::V6(Ipv6Prefix::new(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                32,
            )),
        }],
        flowspec_announced: Vec::new(),
        evpn_announced: Vec::new(),
        bgpls_announced: Vec::new(),
        vpn_announced: Vec::new(),
        labeled_announced: Vec::new(),
        rtc_announced: Vec::new(),
    })));
    let update = UpdateMessage::build(&[], &[], &attributes, true, true, Ipv4UnicastMode::Body);
    let mut bytes = BytesMut::new();
    update.encode(&mut bytes).unwrap();
    let mut kit_bytes = bytes.clone().freeze();
    let BgpMessage::Update(kit) =
        parse_bgp_message(&mut kit_bytes, true, &AsnLength::Bits32).unwrap()
    else {
        panic!("expected UPDATE")
    };
    let kit_id = kit.attributes.iter().find_map(|a| match a {
        AttributeValue::MpReachNlri(n) => n.prefixes.first().and_then(|p| p.path_id),
        _ => None,
    });
    assert_eq!(kit_id, Some(7));

    let mut rust_bytes = bytes.freeze().slice(HEADER_LEN..);
    let body_len = rust_bytes.len();
    let raw = UpdateMessage::decode(&mut rust_bytes, body_len).unwrap();
    let rust = raw
        .parse_revised(true, false, true, mp_add_path_families(true))
        .unwrap();
    assert!(
        verdict(&kit, &rust).is_none(),
        "MP Add-Path UPDATE must match"
    );
    let without_mp_add_path = raw.parse_revised(true, false, true, &[]);
    assert!(
        match without_mp_add_path {
            Ok(ref rust) => verdict(&kit, rust).is_some(),
            Err(_) => true,
        },
        "omitting MP Add-Path negotiation must not appear to agree"
    );
}

#[test]
fn typed_mp_scope_negative_control() {
    let clean = std::fs::read("tests/fixtures/bgpkit/clean_ipv4_update.bin").unwrap();
    let mut kit_bytes = Bytes::copy_from_slice(&clean);
    let BgpMessage::Update(mut kit) =
        parse_bgp_message(&mut kit_bytes, false, &AsnLength::Bits32).unwrap()
    else {
        panic!("expected UPDATE")
    };
    let mut rust_bytes = Bytes::copy_from_slice(&clean[HEADER_LEN..]);
    let body_len = rust_bytes.len();
    let rust = UpdateMessage::decode(&mut rust_bytes, body_len)
        .unwrap()
        .parse_revised(true, false, false, &[])
        .unwrap();
    assert!(
        verdict(&kit, &rust).is_none(),
        "valid unicast UPDATE must match"
    );

    kit.attributes.add_attr(
        AttributeValue::MpUnreachNlri(Nlri::new_link_state_unreachable(
            KitSafi::LinkState,
            Vec::new(),
        ))
        .into(),
    );
    let (category, reason) = verdict(&kit, &rust).expect("typed MP must not be ignored");
    assert_eq!(category, "other");
    assert_eq!(reason, "unsupported MP NLRI family in unicast differential");
}

#[test]
fn as_set_exemption_requires_exclusive_cause() {
    let mut bytes = std::fs::read("tests/fixtures/bgpkit/clean_ipv4_update.bin").unwrap();
    // The fixture's AS_PATH starts with a two-ASN AS_SEQUENCE. Change only
    // its segment type byte on the wire; the encoder rejects AS_SET by design.
    let path_header = bytes
        .windows(4)
        .position(|w| w == [0x40, 2, 10, 2])
        .unwrap();
    bytes[path_header + 3] = 1;
    let mut kit_bytes = Bytes::copy_from_slice(&bytes);
    let BgpMessage::Update(kit) =
        parse_bgp_message(&mut kit_bytes, false, &AsnLength::Bits32).unwrap()
    else {
        panic!("expected UPDATE")
    };
    let mut rust_bytes = Bytes::copy_from_slice(&bytes[HEADER_LEN..]);
    let body_len = rust_bytes.len();
    let mut rust = UpdateMessage::decode(&mut rust_bytes, body_len)
        .unwrap()
        .parse_revised(true, false, false, &[])
        .unwrap();
    assert!(matches!(verdict(&kit, &rust), Some(("expected-as-set", _))));

    // Isolate the classifier condition: another type-2 cause must override the
    // AS_SET exemption even if both parsers retained identical attributes.
    rust.malformed.push(MalformedAttribute {
        type_code: 2,
        disposition: ErrorDisposition::AttributeDiscard,
        error: DecodeError::UpdateAttributeError {
            subcode: 1,
            data: Vec::new(),
            detail: "duplicate AS_PATH".into(),
        },
    });
    assert!(matches!(verdict(&kit, &rust), Some(("other", _))));
}

fn kit_shape(u: &bgpkit_parser::models::BgpUpdateMessage) -> Shape {
    let mut announced: Vec<_> = u.announced_prefixes.iter().map(kit_prefix).collect();
    let mut withdrawn: Vec<_> = u.withdrawn_prefixes.iter().map(kit_prefix).collect();
    let mut path = Vec::new();
    let mut communities = Vec::new();
    let mut known = BTreeSet::new();
    for a in &u.attributes {
        if !matches!(
            a,
            AttributeValue::Unknown(_)
                | AttributeValue::Deprecated(_)
                // IANA reserves type 255 for development; a typed representation
                // here is not a production known-attribute contract.
                | AttributeValue::Development(_)
        ) {
            known.insert(u8::from(a.attr_type()));
        }
    }
    for a in &u.attributes {
        match a {
            AttributeValue::AsPath(p) => {
                for s in &p.segments {
                    let (kind, asns) = match s {
                        KitSegment::AsSequence(v) => ("seq", v),
                        KitSegment::AsSet(v) => ("set", v),
                        KitSegment::ConfedSequence(v) => ("confed-seq", v),
                        KitSegment::ConfedSet(v) => ("confed-set", v),
                    };
                    path.push(format!(
                        "{kind}:{:?}",
                        asns.iter().map(|a| u32::from(*a)).collect::<Vec<_>>()
                    ));
                }
            }
            AttributeValue::MpReachNlri(n) => announced.extend(n.prefixes.iter().map(kit_prefix)),
            AttributeValue::MpUnreachNlri(n) => withdrawn.extend(n.prefixes.iter().map(kit_prefix)),
            _ => {}
        }
    }
    for c in u.attributes.iter_communities() {
        match c {
            MetaCommunity::Plain(v) => {
                let value = match v {
                    Community::NoExport => "65535:65281".to_owned(),
                    Community::NoAdvertise => "65535:65282".to_owned(),
                    Community::NoExportSubConfed => "65535:65283".to_owned(),
                    Community::Custom(asn, local) => format!("{}:{local}", u32::from(asn)),
                };
                communities.push(format!("standard:{value}"));
            }
            MetaCommunity::Large(v) => communities.push(format!("large:{v}")),
            _ => {}
        }
    }
    for a in u.attributes.clone().into_attributes_iter() {
        if matches!(a.value, AttributeValue::ExtendedCommunities(_)) {
            let bytes = a.encode(AsnLength::Bits32).unwrap();
            let header = if bytes[0] & 0x10 != 0 { 4 } else { 3 };
            communities.extend(
                bytes[header..]
                    .as_chunks::<8>()
                    .0
                    .iter()
                    .map(|v| format!("extended:{:016x}", u64::from_be_bytes(*v))),
            );
        }
    }
    announced.sort();
    withdrawn.sort();
    communities.sort();
    Shape {
        announced,
        withdrawn,
        path,
        communities,
        known,
    }
}

fn rust_shape(u: &rustbgpd_wire::ParsedUpdate) -> (Shape, BTreeSet<u8>) {
    let mut announced: Vec<_> = u
        .announced
        .iter()
        .map(|n| (n.prefix.to_string(), n.path_id))
        .collect();
    let mut withdrawn: Vec<_> = u
        .withdrawn
        .iter()
        .map(|n| (n.prefix.to_string(), n.path_id))
        .collect();
    let mut path = Vec::new();
    let mut communities = Vec::new();
    let mut known = BTreeSet::new();
    let mut typed = BTreeSet::new();
    for a in &u.attributes {
        if !matches!(a, PathAttribute::Unknown(_)) {
            known.insert(a.type_code());
            typed.insert(a.type_code());
        }
        match a {
            PathAttribute::AsPath(p) => {
                for s in &p.segments {
                    let (kind, asns) = match s {
                        AsPathSegment::AsSequence(v) => ("seq", v),
                        AsPathSegment::AsSet(v) => ("set", v),
                    };
                    path.push(format!("{kind}:{asns:?}"));
                }
            }
            PathAttribute::MpReachNlri(n) => announced.extend(
                n.announced
                    .iter()
                    .map(|n| (n.prefix.to_string(), n.path_id)),
            ),
            PathAttribute::MpUnreachNlri(n) => withdrawn.extend(
                n.withdrawn
                    .iter()
                    .map(|n| (n.prefix.to_string(), n.path_id)),
            ),
            _ => {}
        }
        if let Some(v) = a.communities() {
            communities.extend(
                v.iter()
                    .map(|v| format!("standard:{}:{}", v >> 16, v & 0xffff)),
            );
        }
        if let Some(v) = a.extended_communities() {
            communities.extend(v.iter().map(|v| format!("extended:{:016x}", v.as_u64())));
        }
        if let Some(v) = a.large_communities() {
            communities.extend(v.iter().map(|v| format!("large:{v}")));
        }
    }
    announced.sort();
    withdrawn.sort();
    communities.sort();
    (
        Shape {
            announced,
            withdrawn,
            path,
            communities,
            known,
        },
        typed,
    )
}

fn unsupported_kit_mp(kit: &BgpUpdateMessage) -> bool {
    kit.attributes.iter().any(|a| {
        let n = match a {
            AttributeValue::MpReachNlri(n) | AttributeValue::MpUnreachNlri(n) => n,
            _ => return false,
        };
        !matches!(
            (n.afi, n.safi),
            (KitAfi::Ipv4 | KitAfi::Ipv6, KitSafi::Unicast)
        ) || n.labeled_prefixes.is_some()
            || n.link_state_nlris.is_some()
            || n.flowspec_nlris.is_some()
    })
}

fn unsupported_rust_mp(rust: &RevisedParsedUpdate) -> bool {
    rust.update.attributes.iter().any(|a| match a {
        PathAttribute::MpReachNlri(n) => {
            !matches!((n.afi, n.safi), (Afi::Ipv4 | Afi::Ipv6, Safi::Unicast))
                || !n.flowspec_announced.is_empty()
                || !n.evpn_announced.is_empty()
                || !n.bgpls_announced.is_empty()
                || !n.vpn_announced.is_empty()
                || !n.labeled_announced.is_empty()
                || !n.rtc_announced.is_empty()
        }
        PathAttribute::MpUnreachNlri(n) => {
            !matches!((n.afi, n.safi), (Afi::Ipv4 | Afi::Ipv6, Safi::Unicast))
                || !n.flowspec_withdrawn.is_empty()
                || !n.evpn_withdrawn.is_empty()
                || !n.bgpls_withdrawn.is_empty()
                || !n.vpn_withdrawn.is_empty()
                || !n.labeled_withdrawn.is_empty()
                || !n.rtc_withdrawn.is_empty()
        }
        _ => false,
    })
}

fn verdict(kit: &BgpUpdateMessage, rust: &RevisedParsedUpdate) -> Option<(&'static str, String)> {
    if unsupported_kit_mp(kit) || unsupported_rust_mp(rust) {
        return Some((
            "other",
            "unsupported MP NLRI family in unicast differential".into(),
        ));
    }
    let (ours, typed) = rust_shape(&rust.update);
    let theirs = kit_shape(kit);
    let missing = known_identity(&theirs.known, &typed);
    let disposition = rust.malformed.iter().map(|m| m.disposition).max();
    let as_set = rust.update.attributes.iter().any(|a| matches!(a, PathAttribute::AsPath(p) if p.segments.iter().any(|s| matches!(s, AsPathSegment::AsSet(_)))));
    if disposition == Some(ErrorDisposition::TreatAsWithdraw)
        && as_set
        && rust
            .malformed
            .iter()
            .all(|m| m.type_code == 2 && matches!(m.error, DecodeError::ProhibitedAsSet { .. }))
        && kit.attributes.validation_warnings().is_empty()
        && ours == theirs
        && missing.is_empty()
    {
        return Some((
            "expected-as-set",
            "RFC 9774 AS_SET treat-as-withdraw vs bgpkit accept".into(),
        ));
    }
    if disposition.is_some()
        || !kit.attributes.validation_warnings().is_empty()
        || ours != theirs
        || !missing.is_empty()
    {
        return Some((
            "other",
            format!(
                "rust_disposition={disposition:?} rust_malformed={:?} kit_warnings={:?} rust={ours:?} kit={theirs:?} known_to_kit_but_unknown_to_rust={missing:?}",
                rust.malformed,
                kit.attributes.validation_warnings()
            ),
        ));
    }
    None
}

fn bgp_bytes(body: &[u8], subtype: u16) -> Option<(&[u8], bool, bool, bool)> {
    let four_as = matches!(subtype, 4 | 7 | 9 | 11);
    let add_path = matches!(subtype, 8..=11);
    let asn_len = if four_as { 4 } else { 2 };
    let is_ibgp = body.get(..asn_len)? == body.get(asn_len..2 * asn_len)?;
    let afi_at = if four_as { 10 } else { 6 };
    let afi = body.get(afi_at..afi_at + 2)?;
    let ipv6 = u16::from_be_bytes([afi[0], afi[1]]) == 2;
    let offset = if four_as { 12 } else { 8 } + if ipv6 { 32 } else { 8 };
    let bytes = body.get(offset..)?;
    (bytes.get(18) == Some(&2)).then_some((bytes, four_as, add_path, is_ibgp))
}

#[test]
fn et_header_is_already_split_from_message_bytes() {
    let bgp = std::fs::read("tests/fixtures/bgpkit/clean_ipv4_update.bin").unwrap();
    let mut message = Vec::new();
    message.extend_from_slice(&64512u32.to_be_bytes());
    message.extend_from_slice(&64513u32.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]);
    message.extend_from_slice(&bgp);
    let mut wire = Vec::new();
    wire.extend_from_slice(&1_700_000_000u32.to_be_bytes());
    wire.extend_from_slice(&17u16.to_be_bytes());
    wire.extend_from_slice(&4u16.to_be_bytes());
    wire.extend_from_slice(&((message.len() + 4) as u32).to_be_bytes());
    wire.extend_from_slice(&123_456u32.to_be_bytes());
    wire.extend_from_slice(&message);

    let raw = chunk_mrt_record(&mut Cursor::new(&wire)).unwrap();
    assert_eq!(raw.header_bytes.len(), 16);
    assert_eq!(raw.message_bytes.as_ref(), message.as_slice());
    assert_eq!(raw.raw_bytes().as_ref(), wire.as_slice());
    let (extracted, four_as, add_path, is_ibgp) = bgp_bytes(&raw.message_bytes, 4).unwrap();
    assert_eq!(extracted, bgp.as_slice());
    assert!(four_as);
    assert!(!add_path);
    assert!(!is_ibgp);
    let record = raw.parse().unwrap();
    assert!(matches!(
        record.message,
        MrtMessage::Bgp4Mp(Bgp4MpEnum::Message(ref m))
            if matches!(&m.bgp_message, BgpMessage::Update(_))
    ));
}

fn mp_add_path_families(add_path: bool) -> &'static [(Afi, Safi)] {
    const UNICAST: [(Afi, Safi); 2] = [(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
    if add_path { &UNICAST } else { &[] }
}

#[test]
#[ignore]
fn real_updates() {
    let path = std::env::var("MRT_DIFFERENTIAL_PATH")
        .expect("set MRT_DIFFERENTIAL_PATH to uncompressed MRT");
    let out =
        std::env::var("MRT_DIFFERENTIAL_OUT").expect("set MRT_DIFFERENTIAL_OUT to a directory");
    std::fs::create_dir_all(&out).unwrap();
    let mut reader = BufReader::new(File::open(&path).unwrap());
    let mut records = 0u64;
    let mut updates = 0u64;
    let mut accepted = 0u64;
    let mut expected_as_set = 0u64;
    let mut other = 0u64;
    let mut log = File::create(format!("{out}/discrepancies.txt")).unwrap();
    while !reader.fill_buf().unwrap().is_empty() {
        records += 1;
        let raw =
            chunk_mrt_record(&mut reader).unwrap_or_else(|e| panic!("record {records}: {e:?}"));
        let ty = u16::from_be_bytes(raw.header_bytes[4..6].try_into().unwrap());
        if !matches!(ty, 16 | 17) {
            continue;
        }
        let subtype = u16::from_be_bytes(raw.header_bytes[6..8].try_into().unwrap());
        if !matches!(subtype, 1 | 4 | 6..=11) {
            continue;
        }
        let kit = raw.clone().parse();
        let kit_update = match &kit {
            Ok(r) => match &r.message {
                MrtMessage::Bgp4Mp(Bgp4MpEnum::Message(m)) => match &m.bgp_message {
                    BgpMessage::Update(u) => Some(u),
                    _ => None,
                },
                _ => None,
            },
            Err(_) => None,
        };
        let Some((bgp, four_as, add_path, is_ibgp)) = bgp_bytes(&raw.message_bytes, subtype) else {
            assert!(
                kit_update.is_none(),
                "record {records}: skipped bgpkit UPDATE"
            );
            continue;
        };
        updates += 1;
        let rust = if bgp.len() >= HEADER_LEN {
            let mut body = Bytes::copy_from_slice(&bgp[HEADER_LEN..]);
            UpdateMessage::decode(&mut body, bgp.len() - HEADER_LEN).and_then(|u| {
                u.parse_revised(four_as, is_ibgp, add_path, mp_add_path_families(add_path))
            })
        } else {
            panic!("record {records}: short UPDATE");
        };
        let result = match (&kit_update, &rust) {
            (Some(k), Ok(r)) => verdict(k, r),
            _ => Some(("other", format!("parse rust={rust:?} kit={kit:?}"))),
        };
        if let Some((category, reason)) = result {
            if category == "expected-as-set" {
                expected_as_set += 1;
            }
            if category == "other" {
                other += 1;
            }
            writeln!(log, "record={records} update={updates} subtype={subtype} category={category} reason={reason}").unwrap();
            std::fs::write(format!("{out}/record-{records}.mrt"), raw.raw_bytes()).unwrap();
        } else {
            accepted += 1;
        }
    }
    println!(
        "records={records} updates={updates} accepted={accepted} expected_as_set={expected_as_set} other={other}"
    );
    assert!(updates > 0);
    assert_eq!(
        other, 0,
        "unclassified discrepancies in {out}/discrepancies.txt"
    );
}
