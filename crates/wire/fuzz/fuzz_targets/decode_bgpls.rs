#![no_main]
use libfuzzer_sys::fuzz_target;
use rustbgpd_wire::bgpls::{
    BgpLsNlri, decode_bgpls_nlri, decode_bgpls_tlvs, decode_bgpls_vpn_nlri, encode_bgpls_nlri,
    encode_bgpls_tlvs,
};
use rustbgpd_wire::bgpls_topo::{
    bgp_ls_attribute_tlvs, igp_metric, prefix_metric, te_default_metric,
};

/// Run every topology accessor the ORR topology build consumes on a
/// decoded NLRI. Accessors return `None` on malformed descriptors and must
/// never panic.
fn topology_accessors(routes: &[BgpLsNlri]) {
    for route in routes {
        for key in [route.local_node_key(), route.remote_node_key()]
            .into_iter()
            .flatten()
        {
            std::hint::black_box(key.as_bytes());
        }
        let _ = route.link_ipv4_interface_address();
        let _ = route.link_ipv4_neighbor_address();
        let _ = route.link_ipv6_interface_address();
        let _ = route.link_ipv6_neighbor_address();
        let _ = route.link_local_remote_ids();
        let _ = route.ip_reachability();
    }
}

fuzz_target!(|data: &[u8]| {
    // Decoders must never panic on arbitrary input. A successful decode must
    // round-trip: re-encoding and re-decoding yields the same value.
    if let Ok(routes) = decode_bgpls_nlri(data) {
        topology_accessors(&routes);
        let mut buf = Vec::new();
        encode_bgpls_nlri(&routes, &mut buf).expect("round-trip encode (nlri)");
        let redecoded = decode_bgpls_nlri(&buf).expect("round-trip decode (nlri)");
        assert_eq!(routes, redecoded, "bgp-ls nlri round-trip mismatch");
    }
    if let Ok(routes) = decode_bgpls_vpn_nlri(data) {
        topology_accessors(&routes);
        let mut buf = Vec::new();
        encode_bgpls_nlri(&routes, &mut buf).expect("round-trip encode (vpn nlri)");
        let redecoded = decode_bgpls_vpn_nlri(&buf).expect("round-trip decode (vpn nlri)");
        assert_eq!(routes, redecoded, "bgp-ls vpn nlri round-trip mismatch");
    }
    if let Ok(tlvs) = bgp_ls_attribute_tlvs(data) {
        let _ = igp_metric(&tlvs);
        let _ = prefix_metric(&tlvs);
        let _ = te_default_metric(&tlvs);
        let mut buf = Vec::new();
        encode_bgpls_tlvs(&tlvs, &mut buf).expect("round-trip encode (tlvs)");
        let redecoded = decode_bgpls_tlvs(&buf).expect("round-trip decode (tlvs)");
        assert_eq!(tlvs, redecoded, "bgp-ls tlv round-trip mismatch");
    }
});
