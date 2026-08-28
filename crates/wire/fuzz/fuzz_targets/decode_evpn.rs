#![no_main]
use libfuzzer_sys::fuzz_target;
use rustbgpd_wire::evpn::{decode_evpn_nlri, decode_evpn_nlri_counted, encode_evpn_nlri};

fuzz_target!(|data: &[u8]| {
    // Never panic on arbitrary input.
    if let Ok(routes) = decode_evpn_nlri(data) {
        let (observed_routes, observations) =
            decode_evpn_nlri_counted(data).expect("legacy-success input must decode counted");
        assert_eq!(routes, observed_routes, "counted decode changed routes");
        assert!(
            observations.windows(2).all(|pair| pair[0].0 < pair[1].0),
            "discard observations must be unique and sorted"
        );
        assert!(
            observations.iter().all(|(_, count)| *count > 0),
            "discard observations must not contain zero counts"
        );
        // Successful decode must round-trip through encode back into valid bytes
        // that decode identically.
        let mut buf = Vec::new();
        encode_evpn_nlri(&routes, &mut buf).expect("decoded routes must re-encode");
        let redecoded = decode_evpn_nlri(&buf).expect("round-trip decode");
        assert_eq!(routes, redecoded, "evpn round-trip mismatch");
    }
});
