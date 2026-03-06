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
        // Exercise both legacy and Add-Path decode branches for body NLRI and
        // MP_REACH/MP_UNREACH parsing.
        let _ = update.parse(true, false, &[]);
        let _ = update.parse(false, false, &[]);
        let _ = update.parse(true, true, &[]);
        let _ = update.parse(
            true,
            false,
            &[(rustbgpd_wire::Afi::Ipv4, rustbgpd_wire::Safi::Unicast)],
        );
        let _ = update.parse(
            true,
            false,
            &[(rustbgpd_wire::Afi::Ipv6, rustbgpd_wire::Safi::Unicast)],
        );
    }
});
