#![no_main]
//! Fuzz the RFC 4684 RT-Constrain NLRI codec (AFI 1 / SAFI 132).
//! Decode must never panic; a successful decode must round-trip
//! losslessly through encode and back.

use libfuzzer_sys::fuzz_target;
use rustbgpd_wire::{decode_rtc_nlri, encode_rtc_nlri};

fuzz_target!(|data: &[u8]| {
    if let Ok(entries) = decode_rtc_nlri(data) {
        let mut buf = Vec::new();
        encode_rtc_nlri(&entries, &mut buf).expect("decoded RTC NLRI must re-encode");
        let redecoded = decode_rtc_nlri(&buf).expect("round-trip decode");
        assert_eq!(entries, redecoded, "rtc round-trip mismatch");
    }
});
