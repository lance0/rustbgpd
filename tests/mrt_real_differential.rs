//! One-off, opt-in differential for uncompressed BGP4MP UPDATE dumps.
//! Pinned 2026-09-30 00:00 UTC files (download outside Git, verify with sha256sum, decompress):
//! RIS rrc03: https://data.ris.ripe.net/rrc03/2026.09/updates.20260930.0000.gz
//!   50a97ec55a6f6cbe8eb46cf9555a10c39d5729b0af87f7569136167fecce3ca4
//! RouteViews route-views2:
//!   https://archive.routeviews.org/route-views2/bgpdata/2026.09/UPDATES/updates.20260930.0000.bz2
//!   1d0eb3ed48cdaef7a40ebbdaabe1bb8e830f6fe60391c5b60e57196e0551f469
//! Run once per decompressed file:
//! MRT_DIFFERENTIAL_PATH=/path/to/updates.mrt MRT_DIFFERENTIAL_OUT=/path/to/output \
//!   cargo test --test mrt_real_differential real_updates -- --ignored --nocapture
use bgpkit_parser::models::{
    AsPathSegment as KitSegment, AsnLength, AttributeValue, Bgp4MpEnum, BgpMessage, Community,
    MetaCommunity, MrtMessage,
};
use bgpkit_parser::parser::mrt::chunk_mrt_record;
use bytes::Bytes;
use rustbgpd_wire::constants::HEADER_LEN;
use rustbgpd_wire::{AsPathSegment, ErrorDisposition, PathAttribute, UpdateMessage};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};

#[derive(Debug, PartialEq, Eq)]
struct Shape {
    announced: Vec<String>,
    withdrawn: Vec<String>,
    path: Vec<String>,
    communities: Vec<String>,
    known: BTreeSet<u8>,
}

fn known_identity(kit: &BTreeSet<u8>, typed: &BTreeSet<u8>) -> BTreeSet<u8> {
    kit.difference(typed).copied().collect()
}

#[test]
#[should_panic(expected = "known attribute decoded as Unknown")]
fn known_attribute_negative_control() {
    let kit = BTreeSet::from([1, 2, 3, 6]);
    let altered = BTreeSet::from([1, 2, 3]); // plausible ATOMIC_AGGREGATE -> Unknown regression
    assert!(
        known_identity(&kit, &altered).is_empty(),
        "known attribute decoded as Unknown"
    );
}

fn kit_shape(u: &bgpkit_parser::models::BgpUpdateMessage) -> Shape {
    let mut announced: Vec<_> = u
        .announced_prefixes
        .iter()
        .map(ToString::to_string)
        .collect();
    let mut withdrawn: Vec<_> = u
        .withdrawn_prefixes
        .iter()
        .map(ToString::to_string)
        .collect();
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
            AttributeValue::MpReachNlri(n) => {
                announced.extend(n.prefixes.iter().map(ToString::to_string))
            }
            AttributeValue::MpUnreachNlri(n) => {
                withdrawn.extend(n.prefixes.iter().map(ToString::to_string))
            }
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
    let mut announced: Vec<_> = u.announced.iter().map(|n| n.prefix.to_string()).collect();
    let mut withdrawn: Vec<_> = u.withdrawn.iter().map(|n| n.prefix.to_string()).collect();
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
            PathAttribute::MpReachNlri(n) => {
                announced.extend(n.announced.iter().map(|n| n.prefix.to_string()))
            }
            PathAttribute::MpUnreachNlri(n) => {
                withdrawn.extend(n.withdrawn.iter().map(|n| n.prefix.to_string()))
            }
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
    let mut expected_7606 = 0u64;
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
            UpdateMessage::decode(&mut body, bgp.len() - HEADER_LEN)
                .and_then(|u| u.parse_revised(four_as, is_ibgp, add_path, &[]))
        } else {
            panic!("record {records}: short UPDATE");
        };
        let mut reason = String::new();
        let mut category = "other";
        match (&kit_update, &rust) {
            (Some(k), Ok(r)) => {
                let disposition = r.malformed.iter().map(|m| m.disposition).max();
                let (ours, typed) = rust_shape(&r.update);
                let theirs = kit_shape(k);
                let missing = known_identity(&theirs.known, &typed);
                let as_set = r.update.attributes.iter().any(|a| matches!(a, PathAttribute::AsPath(p) if p.segments.iter().any(|s| matches!(s, AsPathSegment::AsSet(_)))));
                if disposition == Some(ErrorDisposition::TreatAsWithdraw)
                    && as_set
                    && r.malformed.iter().all(|m| m.type_code == 2)
                    && k.attributes.validation_warnings().is_empty()
                    && ours == theirs
                    && missing.is_empty()
                {
                    expected_as_set += 1;
                    category = "expected-as-set";
                    reason = "RFC 9774 AS_SET treat-as-withdraw vs bgpkit accept".into();
                } else if (disposition.is_some() || !k.attributes.validation_warnings().is_empty())
                    && ours == theirs
                    && missing.is_empty()
                {
                    expected_7606 += 1;
                    category = "expected-rfc7606";
                    reason = format!(
                        "rfc7606 rust={disposition:?} malformed={:?} kit_warnings={:?}",
                        r.malformed,
                        k.attributes.validation_warnings()
                    );
                } else if ours != theirs || !missing.is_empty() {
                    reason = format!(
                        "shape rust={ours:?} kit={theirs:?} known_to_kit_but_unknown_to_rust={missing:?}"
                    );
                } else {
                    accepted += 1;
                }
            }
            _ => reason = format!("parse rust={rust:?} kit={kit:?}"),
        }
        if !reason.is_empty() {
            if category == "other" {
                other += 1;
            }
            writeln!(log, "record={records} update={updates} subtype={subtype} category={category} reason={reason}").unwrap();
            std::fs::write(format!("{out}/record-{records}.mrt"), raw.raw_bytes()).unwrap();
        }
    }
    println!(
        "records={records} updates={updates} accepted={accepted} expected_as_set={expected_as_set} expected_7606={expected_7606} other={other}"
    );
    assert!(updates > 0);
    assert_eq!(
        other, 0,
        "unclassified discrepancies in {out}/discrepancies.txt"
    );
}
