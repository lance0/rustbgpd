#![no_main]
use libfuzzer_sys::fuzz_target;
use rustbgpd_wire::capability::Afi;
use rustbgpd_wire::flowspec::decode_flowspec_nlri;

fuzz_target!(|data: &[u8]| {
    let _ = decode_flowspec_nlri(data, Afi::Ipv4);
    let _ = decode_flowspec_nlri(data, Afi::Ipv6);
});
