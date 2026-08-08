#![no_main]

use libfuzzer_sys::fuzz_target;
use rustbgpd_bfd::ControlPacket;

fuzz_target!(|data: &[u8]| {
    // Keep one datagram from turning into unbounded campaign work; production
    // BFD control packets carry a one-octet Length field.
    if data.len() > 256 {
        return;
    }
    let _ = ControlPacket::decode(data);
});
