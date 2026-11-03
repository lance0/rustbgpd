#![no_main]
use libfuzzer_sys::fuzz_target;
use rustbgpd_wire::capability::Afi;
use rustbgpd_wire::flowspec::{
    decode_flowspec_nlri, decode_vpn_flowspec_nlri, try_encode_vpn_flowspec_nlri,
};

fuzz_target!(|data: &[u8]| {
    let _ = decode_flowspec_nlri(data, Afi::Ipv4);
    let _ = decode_flowspec_nlri(data, Afi::Ipv6);
    // VPN FlowSpec (SAFI 134): a decoded NLRI list re-encodes canonically
    // and decodes back to the same rules.
    if let Ok(rules) = decode_vpn_flowspec_nlri(data, Afi::Ipv4) {
        let mut wire = Vec::new();
        try_encode_vpn_flowspec_nlri(&rules, &mut wire, Afi::Ipv4)
            .expect("a decoded VPN FlowSpec NLRI fits the length field");
        assert_eq!(
            decode_vpn_flowspec_nlri(&wire, Afi::Ipv4).as_ref(),
            Ok(&rules)
        );
    }
});
