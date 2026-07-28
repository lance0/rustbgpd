use bgpkit_parser::error::BgpValidationWarning;
use bgpkit_parser::models::{
    AsPathSegment as KitSegment, AsnLength, BgpMessage as KitMessage, BgpUpdateMessage,
    MetaCommunity, MrtMessage, TableDumpV2Message,
};
use bgpkit_parser::parser::bgp::parse_bgp_message;
use bgpkit_parser::parser::bmp::{
    messages::{BmpMessage as KitBmpMessage, BmpMessageBody},
    parse_bmp_msg,
};
use bgpkit_parser::parser::mrt::chunk_mrt_record;
use bytes::{Bytes, BytesMut};
use rustbgpd_bmp::{BmpPeerInfo, BmpPeerType, BmpVersion, codec::encode_route_monitoring};
use rustbgpd_mrt::codec::{RibEntry, encode_peer_index_table, encode_rib_entries};
use rustbgpd_rib::update::MrtPeerEntry;
use rustbgpd_wire::constants::HEADER_LEN;
use rustbgpd_wire::{
    AsPath, AsPathSegment, ErrorDisposition, Ipv4NlriEntry, Ipv4Prefix, Ipv4UnicastMode,
    LargeCommunity, Origin, PathAttribute, Prefix, UpdateMessage,
};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, UNIX_EPOCH};

const FIXTURE_DIR: &str = "tests/fixtures/bgpkit";
const STANDARD: [u32; 3] = [(64512 << 16) | 10, (64512 << 16) | 20, (64512 << 16) | 10];

fn prefix() -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24)
}

fn large_communities() -> Vec<LargeCommunity> {
    vec![
        LargeCommunity::new(64512, 100, 1),
        LargeCommunity::new(64512, 200, 2),
    ]
}

#[derive(Debug, PartialEq, Eq)]
struct Canonical {
    prefix: String,
    segments: Vec<(String, Vec<u32>)>,
    standard: Vec<String>,
    large: Vec<String>,
}

fn attributes() -> Vec<PathAttribute> {
    let segments = vec![AsPathSegment::AsSequence(vec![64512, 64513])];
    vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments }),
        PathAttribute::NextHop(Ipv4Addr::new(192, 0, 2, 1)),
        PathAttribute::Communities(STANDARD.to_vec()),
        PathAttribute::LargeCommunities(large_communities()),
    ]
}

fn clean_update() -> Vec<u8> {
    let message = UpdateMessage::build(
        &[Ipv4NlriEntry {
            path_id: 0,
            prefix: prefix(),
        }],
        &[],
        &attributes(),
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    let mut bytes = BytesMut::new();
    message.encode(&mut bytes).unwrap();
    bytes.to_vec()
}

fn generated_fixtures() -> [(&'static str, Vec<u8>); 3] {
    let clean = clean_update();
    let mut mrt = Vec::new();
    let peer = MrtPeerEntry {
        peer_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
        peer_bgp_id: Ipv4Addr::new(192, 0, 2, 2),
        peer_asn: 64512,
    };
    encode_peer_index_table(
        &mut mrt,
        1_700_000_000,
        Ipv4Addr::new(192, 0, 2, 254),
        "bgpkit-oracle",
        &[peer],
    )
    .unwrap();
    encode_rib_entries(
        &mut mrt,
        1_700_000_000,
        7,
        &Prefix::V4(prefix()),
        &[RibEntry {
            peer_index: 0,
            originated_time: 1_699_999_900,
            path_id: 0,
            attributes: attributes(),
        }],
    )
    .unwrap();
    let bmp = encode_route_monitoring(
        &BmpPeerInfo {
            peer_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            peer_asn: 64512,
            peer_bgp_id: Ipv4Addr::new(192, 0, 2, 2),
            peer_type: BmpPeerType::Global,
            is_ipv6: false,
            is_post_policy: false,
            is_rib_out: false,
            is_as4: true,
            timestamp: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        },
        &clean,
        None,
        BmpVersion::V3,
    )
    .to_vec();
    [
        ("clean_ipv4_update.bin", clean),
        ("table_dump_v2.bin", mrt),
        ("bmp_v3_route_monitoring.bin", bmp),
    ]
}

fn checked_in(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURE_DIR}/{name}")).unwrap()
}

fn kit_update(bytes: &[u8]) -> BgpUpdateMessage {
    let mut input = Bytes::copy_from_slice(bytes);
    match parse_bgp_message(&mut input, false, &AsnLength::Bits32).unwrap() {
        KitMessage::Update(update) => update,
        other => panic!("expected UPDATE, got {other:?}"),
    }
}

fn kit_canonical(update: &BgpUpdateMessage) -> Canonical {
    assert_eq!(
        update.announced_prefixes.len(),
        1,
        "expected exactly one BGPKIT announced prefix"
    );
    let segments = update
        .attributes
        .as_path()
        .unwrap()
        .segments
        .iter()
        .map(|segment| match segment {
            KitSegment::AsSequence(asns) => (
                "sequence".into(),
                asns.iter().map(|asn| u32::from(*asn)).collect(),
            ),
            KitSegment::AsSet(asns) => (
                "set".into(),
                asns.iter().map(|asn| u32::from(*asn)).collect(),
            ),
            other => panic!("excluded AS-path segment {other:?}"),
        })
        .collect();
    let mut standard = Vec::new();
    let mut large = Vec::new();
    for community in update.attributes.iter_communities() {
        match community {
            MetaCommunity::Plain(value) => standard.push(value.to_string()),
            MetaCommunity::Large(value) => large.push(value.to_string()),
            _ => {}
        }
    }
    standard.sort();
    large.sort();
    Canonical {
        prefix: update.announced_prefixes[0].to_string(),
        segments,
        standard,
        large,
    }
}

fn rust_canonical(bytes: &[u8]) -> Canonical {
    let mut body = Bytes::copy_from_slice(&bytes[HEADER_LEN..]);
    let parsed = UpdateMessage::decode(&mut body, bytes.len() - HEADER_LEN)
        .unwrap()
        .parse(true, false, &[])
        .unwrap();
    assert_eq!(
        parsed.announced.len(),
        1,
        "expected exactly one rustbgpd announced prefix"
    );
    canonical_from_rust(parsed.announced[0].prefix.to_string(), &parsed.attributes)
}

fn canonical_from_rust(prefix: String, attributes: &[PathAttribute]) -> Canonical {
    let mut segments = Vec::new();
    let mut standard = Vec::new();
    let mut large = Vec::new();
    for attribute in attributes {
        match attribute {
            PathAttribute::AsPath(path) => {
                segments = path
                    .segments
                    .iter()
                    .map(|segment| match segment {
                        AsPathSegment::AsSequence(asns) => ("sequence".into(), asns.clone()),
                        AsPathSegment::AsSet(asns) => ("set".into(), asns.clone()),
                    })
                    .collect();
            }
            PathAttribute::Communities(values) => {
                standard.extend(
                    values
                        .iter()
                        .map(|value| format!("{}:{}", value >> 16, value & 0xffff)),
                );
            }
            PathAttribute::LargeCommunities(values) => {
                large.extend(values.iter().map(ToString::to_string));
            }
            _ => {}
        }
    }
    standard.sort();
    large.sort();
    Canonical {
        prefix,
        segments,
        standard,
        large,
    }
}

fn expected() -> Canonical {
    Canonical {
        prefix: "203.0.113.0/24".into(),
        segments: vec![("sequence".into(), vec![64512, 64513])],
        standard: vec!["64512:10".into(), "64512:10".into(), "64512:20".into()],
        large: vec!["64512:100:1".into(), "64512:200:2".into()],
    }
}

#[test]
fn fixtures_are_production_codec_reproducible() {
    for (name, generated) in generated_fixtures() {
        if std::env::var_os("REGENERATE_BGPKIT_FIXTURES").is_some() {
            std::fs::create_dir_all(FIXTURE_DIR).unwrap();
            std::fs::write(format!("{FIXTURE_DIR}/{name}"), &generated).unwrap();
        }
        assert_eq!(generated, checked_in(name), "{name} is not reproducible");
    }
}

#[test]
fn clean_raw_update_agrees_with_both_parsers() {
    let bytes = checked_in("clean_ipv4_update.bin");
    assert_eq!(
        rust_canonical(&bytes),
        expected(),
        "rustbgpd parser bypassed"
    );
    let update = kit_update(&bytes);
    assert_eq!(kit_canonical(&update), expected(), "BGPKIT parser bypassed");
}

#[test]
fn clean_mrt_and_bmp_match_the_canonical_update() {
    let mut cursor = std::io::Cursor::new(checked_in("table_dump_v2.bin"));
    let peer_index = chunk_mrt_record(&mut cursor).unwrap().parse().unwrap();
    assert!(matches!(
        peer_index.message,
        MrtMessage::TableDumpV2Message(TableDumpV2Message::PeerIndexTable(_))
    ));
    let rib = chunk_mrt_record(&mut cursor).unwrap().parse().unwrap();
    let MrtMessage::TableDumpV2Message(TableDumpV2Message::RibAfi(rib)) = rib.message else {
        panic!("expected RIB_IPV4_UNICAST");
    };
    assert_eq!(
        rib.rib_entries.len(),
        1,
        "expected exactly one MRT RIB entry"
    );
    assert_eq!(
        kit_canonical(&BgpUpdateMessage {
            withdrawn_prefixes: vec![],
            attributes: rib.rib_entries[0].attributes.clone(),
            announced_prefixes: vec![rib.prefix],
        }),
        expected()
    );

    let mut bmp_bytes = Bytes::from(checked_in("bmp_v3_route_monitoring.bin"));
    let bmp: KitBmpMessage = parse_bmp_msg(&mut bmp_bytes).unwrap();
    let BmpMessageBody::RouteMonitoring(route) = bmp.message_body else {
        panic!("expected BMP Route Monitoring");
    };
    let KitMessage::Update(update) = route.bgp_message else {
        panic!("expected embedded UPDATE");
    };
    assert_eq!(kit_canonical(&update), expected());
}

#[test]
fn as_set_observations_are_independent() {
    let bytes = checked_in("as_set_ipv4_update.bin");
    assert_eq!(bytes.len(), 57);
    assert_eq!(
        Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        "0f6c88c61dfb3bf02fea98f0a7cc8782821511dfe27ed842b930f8ed9463b7a9"
    );
    let mut body = Bytes::copy_from_slice(&bytes[HEADER_LEN..]);
    let revised = UpdateMessage::decode(&mut body, bytes.len() - HEADER_LEN)
        .unwrap()
        .parse_revised(true, false, false, &[])
        .unwrap();
    assert!(
        revised
            .update
            .attributes
            .contains(&PathAttribute::AsPath(AsPath {
                segments: vec![
                    AsPathSegment::AsSequence(vec![65001]),
                    AsPathSegment::AsSet(vec![65002, 65003]),
                ],
            }))
    );
    assert_eq!(
        revised
            .malformed
            .iter()
            .map(|malformed| malformed.disposition)
            .max(),
        Some(ErrorDisposition::TreatAsWithdraw),
        "rustbgpd AS_SET disposition contract"
    );

    let update = kit_update(&bytes);
    assert!(matches!(
        update.attributes.as_path().unwrap().segments.as_slice(),
        [KitSegment::AsSequence(sequence), KitSegment::AsSet(set)]
            if sequence.iter().map(|asn| u32::from(*asn)).collect::<Vec<_>>() == [65001]
                && set.iter().map(|asn| u32::from(*asn)).collect::<Vec<_>>() == [65002, 65003]
    ));
    let warning_categories: Vec<&str> = update
        .attributes
        .validation_warnings()
        .iter()
        .map(normalize_warning)
        .collect();
    assert_eq!(warning_categories, Vec::<&str>::new(), "BGPKIT warnings");
}

fn normalize_warning(warning: &BgpValidationWarning) -> &'static str {
    match warning {
        BgpValidationWarning::MalformedAsPath { .. } => "malformed-as-path",
        BgpValidationWarning::AttributeFlagsError { .. } => "attribute-flags",
        BgpValidationWarning::AttributeLengthError { .. } => "attribute-length",
        _ => "other",
    }
}
