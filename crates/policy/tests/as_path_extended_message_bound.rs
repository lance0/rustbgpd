//! `AS_PATH` matching is length-bounded under RFC 8654 Extended Messages.
//!
//! A maximum-size (65,533-byte) UPDATE whose `AS_PATH` fills the extended
//! message budget decodes, renders, and regex/length-matches without
//! truncation or a fixed-capacity ceiling. Pins existing behavior: the
//! policy engine matches the rendered path string, so no fixed-size
//! per-ASN buffer exists anywhere in the match path.

use rustbgpd_policy::AsPathRegex;
use rustbgpd_wire::constants::HEADER_LEN;
use rustbgpd_wire::{EXTENDED_MAX_MESSAGE_LEN, MAX_MESSAGE_LEN, PathAttribute, UpdateMessage};

const ASN_FILLER: u32 = 65000;
const ORIGIN_ASN: u32 = 65001;

#[test]
fn as_path_matching_bounded_at_max_extended_message() {
    // Fill the extended-message budget: header (19) + withdrawn_len (2) +
    // attrs_len (2) + attribute header (4) leaves 65,508 bytes of AS_PATH
    // data. Each full AS_SEQUENCE segment is 2 + 255 * 4 bytes.
    let budget = usize::from(EXTENDED_MAX_MESSAGE_LEN) - HEADER_LEN - 2 - 2 - 4;
    let mut attr_data: Vec<u8> = Vec::new();
    let mut asn_count = 0usize;
    loop {
        let remaining = budget - attr_data.len();
        if remaining < 2 + 4 {
            break;
        }
        let seg_len = ((remaining - 2) / 4).min(255);
        attr_data.push(2); // AS_SEQUENCE
        attr_data.push(u8::try_from(seg_len).unwrap());
        for _ in 0..seg_len {
            attr_data.extend_from_slice(&ASN_FILLER.to_be_bytes());
            asn_count += 1;
        }
    }
    // Make the final (origin) ASN distinctive.
    let tail = attr_data.len() - 4;
    attr_data[tail..].copy_from_slice(&ORIGIN_ASN.to_be_bytes());

    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&0u16.to_be_bytes()); // withdrawn routes length
    let attrs_len = u16::try_from(attr_data.len() + 4).unwrap();
    body.extend_from_slice(&attrs_len.to_be_bytes());
    body.push(0x50); // TRANSITIVE | EXTENDED_LENGTH
    body.push(2); // AS_PATH
    body.extend_from_slice(&u16::try_from(attr_data.len()).unwrap().to_be_bytes());
    body.extend_from_slice(&attr_data);

    let total = HEADER_LEN + body.len();
    assert!(
        total > usize::from(MAX_MESSAGE_LEN),
        "must exceed the classic 4096-byte limit"
    );
    assert!(total <= usize::from(EXTENDED_MAX_MESSAGE_LEN));
    assert!(
        asn_count > 16_000,
        "budget math regressed: only {asn_count} ASNs"
    );

    let update = UpdateMessage::decode(&mut &body[..], body.len()).unwrap();
    let parsed = update.parse(true, false, &[]).unwrap();
    let as_path = parsed
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::AsPath(p) => Some(p),
            _ => None,
        })
        .expect("AS_PATH decodes from a maximum-size extended message");

    // Length matching sees every ASN, not a capped prefix.
    assert_eq!(as_path.len(), asn_count);
    assert_eq!(as_path.origin_asn(), Some(ORIGIN_ASN));

    // Regex matching operates on the full rendered path.
    let rendered = as_path.to_aspath_string();
    assert!(AsPathRegex::new("_65001$").unwrap().is_match(&rendered));
    assert!(!AsPathRegex::new("_64999_").unwrap().is_match(&rendered));
}
