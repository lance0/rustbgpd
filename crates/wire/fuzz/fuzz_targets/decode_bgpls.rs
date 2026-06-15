#![no_main]
use libfuzzer_sys::fuzz_target;
use rustbgpd_wire::bgpls::{
    decode_bgpls_nlri, decode_bgpls_tlvs, decode_bgpls_vpn_nlri, encode_bgpls_nlri,
    encode_bgpls_tlvs,
};

fuzz_target!(|data: &[u8]| {
    // Decoders must never panic on arbitrary input. A successful decode must
    // round-trip: re-encoding and re-decoding yields the same value.
    if let Ok(routes) = decode_bgpls_nlri(data) {
        let mut buf = Vec::new();
        encode_bgpls_nlri(&routes, &mut buf).expect("round-trip encode (nlri)");
        let redecoded = decode_bgpls_nlri(&buf).expect("round-trip decode (nlri)");
        assert_eq!(routes, redecoded, "bgp-ls nlri round-trip mismatch");
    }
    // VPN-scoped NLRI carries an 8-byte RD prefix and has no paired encoder;
    // just assert the decoder never panics.
    let _ = decode_bgpls_vpn_nlri(data);
    if let Ok(tlvs) = decode_bgpls_tlvs(data) {
        let mut buf = Vec::new();
        encode_bgpls_tlvs(&tlvs, &mut buf).expect("round-trip encode (tlvs)");
        let redecoded = decode_bgpls_tlvs(&buf).expect("round-trip decode (tlvs)");
        assert_eq!(tlvs, redecoded, "bgp-ls tlv round-trip mismatch");
    }
});
