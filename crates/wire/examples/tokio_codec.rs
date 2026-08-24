use bytes::BytesMut;
use rustbgpd_wire::{BgpCodec, EXTENDED_MAX_MESSAGE_LEN, MAX_MESSAGE_LEN, Message};
use tokio_util::codec::{Decoder, Encoder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Extended Messages is directional: our advertised capability lets this
    // side receive extended frames, while a peer that did not advertise it
    // still limits this side to standard-size outbound frames.
    let mut codec = BgpCodec::with_max_message_lengths(EXTENDED_MAX_MESSAGE_LEN, MAX_MESSAGE_LEN);

    let mut wire = BytesMut::new();
    codec.encode(Message::Keepalive, &mut wire)?;
    let decoded = codec.decode(&mut wire)?.expect("complete KEEPALIVE");

    assert_eq!(decoded, Message::Keepalive);
    assert!(wire.is_empty());
    println!("decoded {decoded}");
    Ok(())
}
