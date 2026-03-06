#![no_main]
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Need at least 4 bytes for the minimal UPDATE body
    if data.len() < 4 {
        return;
    }

    let mut buf = Bytes::copy_from_slice(data);
    if let Ok(update) = rustbgpd_wire::UpdateMessage::decode(&mut buf, data.len()) {
        // Try parsing with both 2-byte and 4-byte AS modes
        let _ = update.parse(true, false, &[]);
        let _ = update.parse(false, false, &[]);
    }
});
