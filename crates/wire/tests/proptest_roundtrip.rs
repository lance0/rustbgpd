use std::net::Ipv4Addr;

use bytes::Bytes;
use proptest::prelude::*;
use rustbgpd_wire::capability::{Afi, Capability, Safi};
use rustbgpd_wire::constants::BGP_VERSION;
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
    ]
}

fn arb_afi() -> impl Strategy<Value = Afi> {
    prop_oneof![Just(Afi::Ipv4), Just(Afi::Ipv6),]
}

fn arb_safi() -> impl Strategy<Value = Safi> {
    prop_oneof![Just(Safi::Unicast), Just(Safi::Multicast),]
}

fn arb_capability() -> impl Strategy<Value = Capability> {
    prop_oneof![
        (arb_afi(), arb_safi()).prop_map(|(afi, safi)| Capability::MultiProtocol { afi, safi }),
        any::<u32>().prop_map(|asn| Capability::FourOctetAs { asn }),
        // Unknown capabilities: code must not collide with known codes (1, 65)
        // and data length fits in u8
        (
            prop_oneof![2..65u8, 66..=255u8],
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

proptest! {
    #[test]
    fn roundtrip_any_message(msg in arb_message()) {
        let encoded = encode_message(&msg).expect("encode should succeed");
        let mut bytes = encoded.freeze();
        let decoded = decode_message(&mut bytes).expect("decode should succeed");
        prop_assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_open(open in arb_open()) {
        let msg = Message::Open(open);
        let encoded = encode_message(&msg).expect("encode should succeed");
        let mut bytes = encoded.freeze();
        let decoded = decode_message(&mut bytes).expect("decode should succeed");
        prop_assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_update(update in arb_update()) {
        let msg = Message::Update(update);
        let encoded = encode_message(&msg).expect("encode should succeed");
        let mut bytes = encoded.freeze();
        let decoded = decode_message(&mut bytes).expect("decode should succeed");
        prop_assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_notification(notif in arb_notification()) {
        let msg = Message::Notification(notif);
        let encoded = encode_message(&msg).expect("encode should succeed");
        let mut bytes = encoded.freeze();
        let decoded = decode_message(&mut bytes).expect("decode should succeed");
        prop_assert_eq!(msg, decoded);
    }

    #[test]
    fn decode_never_panics(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let mut buf = Bytes::from(data);
        // We don't care about the result, just that it doesn't panic
        let _ = decode_message(&mut buf);
    }
}
