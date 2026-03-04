use std::net::Ipv4Addr;

use bytes::Bytes;
use proptest::prelude::*;
use rustbgpd_wire::capability::{Afi, Capability, GracefulRestartFamily, Safi};
use rustbgpd_wire::constants::{BGP_VERSION, MAX_MESSAGE_LEN};
use rustbgpd_wire::message::{Message, decode_message, encode_message};
use rustbgpd_wire::notification::NotificationCode;
use rustbgpd_wire::notification_msg::NotificationMessage;
use rustbgpd_wire::open::OpenMessage;
use rustbgpd_wire::update::UpdateMessage;

fn arb_notification_code() -> impl Strategy<Value = NotificationCode> {
    prop_oneof![
        Just(NotificationCode::MessageHeader),
        Just(NotificationCode::OpenMessage),
        Just(NotificationCode::UpdateMessage),
        Just(NotificationCode::HoldTimerExpired),
        Just(NotificationCode::FsmError),
        Just(NotificationCode::Cease),
        // Unknown codes: 0 and 7–255 (outside the RFC 4271 range)
        prop_oneof![Just(0u8), 7..=255u8].prop_map(NotificationCode::Unknown),
    ]
}

fn arb_afi() -> impl Strategy<Value = Afi> {
    prop_oneof![Just(Afi::Ipv4), Just(Afi::Ipv6),]
}

fn arb_safi() -> impl Strategy<Value = Safi> {
    prop_oneof![Just(Safi::Unicast), Just(Safi::Multicast),]
}

fn arb_gr_family() -> impl Strategy<Value = GracefulRestartFamily> {
    (arb_afi(), arb_safi(), any::<bool>()).prop_map(|(afi, safi, fp)| GracefulRestartFamily {
        afi,
        safi,
        forwarding_preserved: fp,
    })
}

fn arb_extended_nexthop_family() -> impl Strategy<Value = rustbgpd_wire::ExtendedNextHopFamily> {
    (arb_afi(), arb_safi(), arb_afi()).prop_map(|(nlri_afi, nlri_safi, next_hop_afi)| {
        rustbgpd_wire::ExtendedNextHopFamily {
            nlri_afi,
            nlri_safi,
            next_hop_afi,
        }
    })
}

fn arb_capability() -> impl Strategy<Value = Capability> {
    prop_oneof![
        (arb_afi(), arb_safi()).prop_map(|(afi, safi)| Capability::MultiProtocol { afi, safi }),
        proptest::collection::vec(arb_extended_nexthop_family(), 0..=4)
            .prop_map(Capability::ExtendedNextHop),
        (
            any::<bool>(),
            (0..=4095u16),
            proptest::collection::vec(arb_gr_family(), 0..=4),
        )
            .prop_map(|(restart_state, restart_time, families)| {
                Capability::GracefulRestart {
                    restart_state,
                    restart_time,
                    families,
                }
            }),
        any::<u32>().prop_map(|asn| Capability::FourOctetAs { asn }),
        // Unknown capabilities: code must not collide with known codes
        // (1 = MultiProtocol, 2 = RouteRefresh, 5 = ExtendedNextHop,
        // 6 = ExtendedMessage, 64 = GracefulRestart, 65 = FourOctetAs,
        // 69 = AddPath).
        (
            prop_oneof![3..5u8, 7..64u8, 66..69u8, 70..=255u8],
            proptest::collection::vec(any::<u8>(), 0..32)
        )
            .prop_map(|(code, data)| Capability::Unknown {
                code,
                data: Bytes::from(data),
            }),
    ]
}

/// Generate an OPEN message that fits within wire limits.
/// Optional parameters are capped at 255 bytes, and we limit capabilities
/// to keep the total well under that.
fn arb_open() -> impl Strategy<Value = OpenMessage> {
    (
        any::<u16>(),                                       // my_as
        prop_oneof![Just(0u16), 3..=300u16],                // hold_time (0 or >=3)
        any::<[u8; 4]>(),                                   // bgp_identifier
        proptest::collection::vec(arb_capability(), 0..=8), // capabilities
    )
        .prop_map(|(my_as, hold_time, id_bytes, capabilities)| OpenMessage {
            version: BGP_VERSION,
            my_as,
            hold_time,
            bgp_identifier: Ipv4Addr::from(id_bytes),
            capabilities,
        })
}

/// Generate an UPDATE message that fits within the 4096-byte max.
/// Total body = 2 + withdrawn + 2 + attrs + nlri, plus 19-byte header.
/// Keep each section small to stay well under 4096.
fn arb_update() -> impl Strategy<Value = UpdateMessage> {
    (
        proptest::collection::vec(any::<u8>(), 0..500),
        proptest::collection::vec(any::<u8>(), 0..500),
        proptest::collection::vec(any::<u8>(), 0..500),
    )
        .prop_map(|(withdrawn, attrs, nlri)| UpdateMessage {
            withdrawn_routes: Bytes::from(withdrawn),
            path_attributes: Bytes::from(attrs),
            nlri: Bytes::from(nlri),
        })
}

/// Generate a NOTIFICATION message with variable data.
/// Max data = 4096 - 19 (header) - 2 (code+subcode) = 4075.
/// Keep it reasonable for test speed.
fn arb_notification() -> impl Strategy<Value = NotificationMessage> {
    (
        arb_notification_code(),
        any::<u8>(),
        proptest::collection::vec(any::<u8>(), 0..200),
    )
        .prop_map(|(code, subcode, data)| {
            NotificationMessage::new(code, subcode, Bytes::from(data))
        })
}

fn arb_message() -> impl Strategy<Value = Message> {
    prop_oneof![
        Just(Message::Keepalive),
        arb_open().prop_map(Message::Open),
        arb_update().prop_map(Message::Update),
        arb_notification().prop_map(Message::Notification),
    ]
}

/// Corruption strategies for negative testing.
mod corrupt {
    use bytes::{BufMut, BytesMut};

    /// Flip a single random bit in the buffer.
    pub fn bit_flip(data: &[u8], byte_idx: usize, bit_idx: usize) -> Vec<u8> {
        let mut out = data.to_vec();
        if !out.is_empty() {
            let i = byte_idx % out.len();
            out[i] ^= 1 << (bit_idx % 8);
        }
        out
    }

    /// Truncate the buffer to a shorter length.
    pub fn truncate(data: &[u8], new_len: usize) -> Vec<u8> {
        let len = if data.is_empty() {
            0
        } else {
            new_len % data.len()
        };
        data[..len].to_vec()
    }

    /// Insert a random byte at a random position.
    pub fn insert_byte(data: &[u8], pos: usize, byte: u8) -> Vec<u8> {
        let mut out = data.to_vec();
        let i = if out.is_empty() {
            0
        } else {
            pos % (out.len() + 1)
        };
        out.insert(i, byte);
        out
    }

    /// Overwrite a range of bytes with a given value.
    pub fn overwrite(data: &[u8], start: usize, val: u8, count: usize) -> Vec<u8> {
        let mut out = data.to_vec();
        if !out.is_empty() {
            let s = start % out.len();
            let n = count % 8 + 1;
            for i in s..(s + n).min(out.len()) {
                out[i] = val;
            }
        }
        out
    }

    /// Extend the buffer with extra garbage bytes.
    pub fn extend(data: &[u8], extra: &[u8]) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(data.len() + extra.len());
        buf.put_slice(data);
        buf.put_slice(extra);
        buf.to_vec()
    }
}

proptest! {
    #[test]
    fn roundtrip_any_message(msg in arb_message()) {
        let encoded = encode_message(&msg).expect("encode should succeed");
        let mut bytes = encoded.freeze();
        let decoded = decode_message(&mut bytes, MAX_MESSAGE_LEN).expect("decode should succeed");
        prop_assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_open(open in arb_open()) {
        let msg = Message::Open(open);
        let encoded = encode_message(&msg).expect("encode should succeed");
        let mut bytes = encoded.freeze();
        let decoded = decode_message(&mut bytes, MAX_MESSAGE_LEN).expect("decode should succeed");
        prop_assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_update(update in arb_update()) {
        let msg = Message::Update(update);
        let encoded = encode_message(&msg).expect("encode should succeed");
        let mut bytes = encoded.freeze();
        let decoded = decode_message(&mut bytes, MAX_MESSAGE_LEN).expect("decode should succeed");
        prop_assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_notification(notif in arb_notification()) {
        let msg = Message::Notification(notif);
        let encoded = encode_message(&msg).expect("encode should succeed");
        let mut bytes = encoded.freeze();
        let decoded = decode_message(&mut bytes, MAX_MESSAGE_LEN).expect("decode should succeed");
        prop_assert_eq!(msg, decoded);
    }

    #[test]
    fn decode_never_panics(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let mut buf = Bytes::from(data);
        // We don't care about the result, just that it doesn't panic
        let _ = decode_message(&mut buf, MAX_MESSAGE_LEN);
    }

    /// Encode a valid message, flip one bit, decode — must not panic.
    #[test]
    fn corrupt_bit_flip_never_panics(
        msg in arb_message(),
        byte_idx in any::<usize>(),
        bit_idx in any::<usize>(),
    ) {
        let encoded = encode_message(&msg).expect("encode should succeed");
        let corrupted = corrupt::bit_flip(&encoded, byte_idx, bit_idx);
        let mut buf = Bytes::from(corrupted);
        let _ = decode_message(&mut buf, MAX_MESSAGE_LEN); // Ok or Err, never panic
    }

    /// Encode a valid message, truncate it, decode — must not panic.
    #[test]
    fn corrupt_truncation_never_panics(
        msg in arb_message(),
        new_len in any::<usize>(),
    ) {
        let encoded = encode_message(&msg).expect("encode should succeed");
        let corrupted = corrupt::truncate(&encoded, new_len);
        let mut buf = Bytes::from(corrupted);
        let _ = decode_message(&mut buf, MAX_MESSAGE_LEN);
    }

    /// Encode a valid message, insert a random byte, decode — must not panic.
    #[test]
    fn corrupt_insertion_never_panics(
        msg in arb_message(),
        pos in any::<usize>(),
        byte in any::<u8>(),
    ) {
        let encoded = encode_message(&msg).expect("encode should succeed");
        let corrupted = corrupt::insert_byte(&encoded, pos, byte);
        let mut buf = Bytes::from(corrupted);
        let _ = decode_message(&mut buf, MAX_MESSAGE_LEN);
    }

    /// Encode a valid message, overwrite a section, decode — must not panic.
    #[test]
    fn corrupt_overwrite_never_panics(
        msg in arb_message(),
        start in any::<usize>(),
        val in any::<u8>(),
        count in any::<usize>(),
    ) {
        let encoded = encode_message(&msg).expect("encode should succeed");
        let corrupted = corrupt::overwrite(&encoded, start, val, count);
        let mut buf = Bytes::from(corrupted);
        let _ = decode_message(&mut buf, MAX_MESSAGE_LEN);
    }

    /// Encode a valid message, append garbage, decode — must not panic.
    #[test]
    fn corrupt_trailing_garbage_never_panics(
        msg in arb_message(),
        garbage in proptest::collection::vec(any::<u8>(), 1..256),
    ) {
        let encoded = encode_message(&msg).expect("encode should succeed");
        let corrupted = corrupt::extend(&encoded, &garbage);
        let mut buf = Bytes::from(corrupted);
        let _ = decode_message(&mut buf, MAX_MESSAGE_LEN);
    }
}
