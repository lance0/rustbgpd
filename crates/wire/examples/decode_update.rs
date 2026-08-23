use bytes::Bytes;
use rustbgpd_wire::{MAX_MESSAGE_LEN, Message, decode_message};

const CAPTURED_UPDATE: [u8; 47] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x2f, 0x02, // marker, length, UPDATE
    0x00, 0x00, // withdrawn routes length
    0x00, 0x14, // path attributes length
    0x40, 0x01, 0x01, 0x00, // ORIGIN: IGP
    0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfc, 0x00, // AS_PATH: 64512
    0x40, 0x03, 0x04, 0xc0, 0x00, 0x02, 0x01, // NEXT_HOP: 192.0.2.1
    0x18, 0xcb, 0x00, 0x71, // NLRI: 203.0.113.0/24
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Bytes::from_static(&CAPTURED_UPDATE);
    let Message::Update(update) = decode_message(&mut bytes, MAX_MESSAGE_LEN)? else {
        return Err("capture is not a BGP UPDATE".into());
    };
    assert!(bytes.is_empty(), "capture contains trailing bytes");
    let parsed = update.parse(true, false, &[])?;

    assert_eq!(parsed.announced.len(), 1);
    let prefix = parsed.announced[0].prefix;
    assert_eq!(prefix.to_string(), "203.0.113.0/24");
    println!("announced: {prefix}");
    Ok(())
}
