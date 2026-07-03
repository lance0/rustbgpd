#![no_main]
//! Fuzz the OPEN body decoder, including the full optional-parameter /
//! capability codec (MP-BGP, Add-Path, ORF, unknown capabilities kept
//! verbatim). Input is an OPEN *body* (header already consumed, as in
//! the real session path). A successful decode must round-trip: encode
//! the message and decode it again via the top-level message decoder.

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use rustbgpd_wire::{Message, OpenMessage, decode_message};

fuzz_target!(|data: &[u8]| {
    let mut buf = Bytes::copy_from_slice(data);
    let Ok(open) = OpenMessage::decode(&mut buf, data.len()) else {
        return;
    };
    // The capability codec promises lossless round-trips (unknown and
    // malformed-but-framed capabilities are preserved as raw bytes).
    let mut encoded = bytes::BytesMut::new();
    open.encode(&mut encoded)
        .expect("decoded OPEN must re-encode");
    let mut wire = encoded.freeze();
    let msg = decode_message(&mut wire, rustbgpd_wire::constants::MAX_MESSAGE_LEN)
        .expect("re-encoded OPEN must decode");
    let Message::Open(redecoded) = msg else {
        panic!("re-encoded OPEN decoded as a different message type");
    };
    assert_eq!(open, redecoded, "OPEN round-trip mismatch");
});
