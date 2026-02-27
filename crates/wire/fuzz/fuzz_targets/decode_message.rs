#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use rustbgpd_wire::message::decode_message;

fuzz_target!(|data: &[u8]| {
    let mut buf = Bytes::copy_from_slice(data);
    // Must never panic regardless of input
    let _ = decode_message(&mut buf);
});
