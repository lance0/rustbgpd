#![no_main]
//! Fuzz the ROUTE-REFRESH body decoder, including the RFC 5291 ORF
//! section (Address-Prefix entry parsing, raw/malformed group
//! preservation) and RFC 7313 subtypes. Input is a ROUTE-REFRESH
//! *body*. A successful decode must round-trip losslessly: unknown
//! AFI/SAFI, unknown subtypes, and unparsed/malformed ORF groups are
//! all preserved verbatim by design.

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use rustbgpd_wire::{Message, RouteRefreshMessage, decode_message};

fuzz_target!(|data: &[u8]| {
    // In the real session path the body length comes from a header already
    // bounded by the negotiated maximum message size; mirror that bound so
    // the re-encoded message stays decodable (RFC 8654 extended limit).
    if data.len() > usize::from(rustbgpd_wire::EXTENDED_MAX_MESSAGE_LEN) - 19 {
        return;
    }
    let mut buf = Bytes::copy_from_slice(data);
    let Ok(rr) = RouteRefreshMessage::decode(&mut buf, data.len()) else {
        return;
    };
    let mut encoded = bytes::BytesMut::new();
    // Re-encode under the same RFC 8654 extended regime the decode above
    // accepts — `encode()` pins the 4096 base limit, so an ORF-heavy
    // refresh between 4097 and 65535 octets round-trips only with the
    // extended limit.
    rr.encode_with_limit(&mut encoded, rustbgpd_wire::EXTENDED_MAX_MESSAGE_LEN)
        .expect("decoded ROUTE-REFRESH must re-encode");
    let mut wire = encoded.freeze();
    let msg = decode_message(&mut wire, rustbgpd_wire::EXTENDED_MAX_MESSAGE_LEN)
        .expect("re-encoded ROUTE-REFRESH must decode");
    let Message::RouteRefresh(redecoded) = msg else {
        panic!("re-encoded ROUTE-REFRESH decoded as a different message type");
    };
    assert_eq!(rr, redecoded, "ROUTE-REFRESH round-trip mismatch");
});
