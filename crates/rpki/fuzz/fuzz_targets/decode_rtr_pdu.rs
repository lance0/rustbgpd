#![no_main]

use libfuzzer_sys::fuzz_target;
use rustbgpd_rpki::rtr_codec::RtrPdu;

fuzz_target!(|data: &[u8]| {
    // Keep malformed advertised lengths from turning one input into
    // unbounded campaign work; the live RTR reader uses the same frame cap.
    if data.len() > 65_535 {
        return;
    }
    let _ = RtrPdu::decode(data);
});
