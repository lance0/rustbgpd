#![no_main]
use libfuzzer_sys::fuzz_target;
use rustbgpd_wire::evpn::{decode_evpn_nlri, encode_evpn_nlri};

fuzz_target!(|data: &[u8]| {
    // Never panic on arbitrary input.
    if let Ok(routes) = decode_evpn_nlri(data) {
        // Successful decode must round-trip through encode back into valid bytes
        // that decode identically.
        let mut buf = Vec::new();
        encode_evpn_nlri(&routes, &mut buf);
        let redecoded = decode_evpn_nlri(&buf).expect("round-trip decode");
        assert_eq!(routes, redecoded, "evpn round-trip mismatch");
    }
});
