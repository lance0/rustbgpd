#![no_main]
use libfuzzer_sys::fuzz_target;
use rustbgpd_wire::vpn::{
    decode_vpnv4_nlri, decode_vpnv6_nlri, encode_vpnv4_nlri, encode_vpnv6_nlri,
};

fuzz_target!(|data: &[u8]| {
    // Decode must never panic on arbitrary input, for either family. A
    // successful decode must round-trip: re-encoding and re-decoding yields the
    // same NLRI set (idempotent, tolerant of non-canonical padding the decoder
    // ignores).
    if let Ok(entries) = decode_vpnv4_nlri(data) {
        let mut buf = Vec::new();
        encode_vpnv4_nlri(&entries, &mut buf).expect("round-trip encode (v4)");
        let redecoded = decode_vpnv4_nlri(&buf).expect("round-trip decode (v4)");
        assert_eq!(entries, redecoded, "vpnv4 round-trip mismatch");
    }
    if let Ok(entries) = decode_vpnv6_nlri(data) {
        let mut buf = Vec::new();
        encode_vpnv6_nlri(&entries, &mut buf).expect("round-trip encode (v6)");
        let redecoded = decode_vpnv6_nlri(&buf).expect("round-trip decode (v6)");
        assert_eq!(entries, redecoded, "vpnv6 round-trip mismatch");
    }
});
