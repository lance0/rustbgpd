#![no_main]
//! Fuzz RFC 8277 labeled-unicast NLRI codecs (SAFI 4), announce and
//! withdraw modes, legacy and Add-Path framing, both families.
//!
//! Announce mode is lossless: a successful decode must re-encode and
//! re-decode to the same value. Withdraw mode is deliberately NOT
//! one-generation lossless — the decoder preserves whatever label
//! stack the peer sent (RFC 8277 §2.4 compatibility parsing) while the
//! encoder always writes the 0x800000 compatibility field — so it is
//! checked for second-generation idempotence instead: once a value has
//! passed through encode, further decode/encode cycles are stable.

use libfuzzer_sys::fuzz_target;
use rustbgpd_wire::{
    LabeledAddressFamily, decode_labeled_nlri, decode_labeled_nlri_addpath,
    decode_labeled_withdraw_nlri, decode_labeled_withdraw_nlri_addpath, encode_labeled_nlri,
    encode_labeled_nlri_addpath,
};

fuzz_target!(|data: &[u8]| {
    for family in [LabeledAddressFamily::V4, LabeledAddressFamily::V6] {
        // Announce mode: lossless round-trip.
        if let Ok(entries) = decode_labeled_nlri(data, family) {
            let mut buf = Vec::new();
            encode_labeled_nlri(&entries, family, &mut buf)
                .expect("decoded announce NLRI must re-encode");
            let redecoded =
                decode_labeled_nlri(&buf, family).expect("round-trip decode (announce)");
            assert_eq!(entries, redecoded, "labeled announce round-trip mismatch");
        }
        if let Ok(entries) = decode_labeled_nlri_addpath(data, family) {
            let mut buf = Vec::new();
            encode_labeled_nlri_addpath(&entries, family, &mut buf)
                .expect("decoded Add-Path announce NLRI must re-encode");
            let redecoded = decode_labeled_nlri_addpath(&buf, family)
                .expect("round-trip decode (announce, add-path)");
            assert_eq!(
                entries, redecoded,
                "labeled add-path announce round-trip mismatch"
            );
        }
        // Withdraw mode: never panic; second generation must be stable.
        if let Ok(gen1) = decode_labeled_withdraw_nlri(data, family) {
            let mut buf = Vec::new();
            rustbgpd_wire::encode_labeled_withdraw_nlri(&gen1, family, &mut buf)
                .expect("decoded withdraw NLRI must re-encode");
            let gen2 =
                decode_labeled_withdraw_nlri(&buf, family).expect("round-trip decode (withdraw)");
            let mut buf2 = Vec::new();
            rustbgpd_wire::encode_labeled_withdraw_nlri(&gen2, family, &mut buf2)
                .expect("second-generation withdraw NLRI must re-encode");
            assert_eq!(buf, buf2, "labeled withdraw encode not idempotent");
            // Withdraw identity is the prefix; that must survive verbatim.
            assert_eq!(
                gen1.iter().map(|e| e.prefix).collect::<Vec<_>>(),
                gen2.iter().map(|e| e.prefix).collect::<Vec<_>>(),
                "labeled withdraw prefixes changed across round-trip"
            );
        }
        // Add-Path withdraw: decode must never panic.
        let _ = decode_labeled_withdraw_nlri_addpath(data, family);
    }
});
