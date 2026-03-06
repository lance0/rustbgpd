use bytes::{Bytes, BytesMut};

use crate::constants::HEADER_LEN;
use crate::error::{DecodeError, EncodeError};
use crate::header::{BgpHeader, MessageType};
use crate::keepalive;
use crate::notification_msg::NotificationMessage;
use crate::open::OpenMessage;
use crate::route_refresh::RouteRefreshMessage;
use crate::update::UpdateMessage;

/// A decoded BGP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// BGP OPEN message.
    Open(OpenMessage),
    /// BGP UPDATE message.
    Update(UpdateMessage),
    /// BGP NOTIFICATION message.
    Notification(NotificationMessage),
    /// BGP KEEPALIVE message (no body).
    Keepalive,
    /// BGP ROUTE-REFRESH message.
    RouteRefresh(RouteRefreshMessage),
}

impl Message {
    /// Returns the message type.
    #[must_use]
    pub fn message_type(&self) -> MessageType {
        match self {
            Self::Open(_) => MessageType::Open,
            Self::Update(_) => MessageType::Update,
            Self::Notification(_) => MessageType::Notification,
            Self::Keepalive => MessageType::Keepalive,
            Self::RouteRefresh(_) => MessageType::RouteRefresh,
        }
    }
}

impl std::fmt::Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open(o) => write!(f, "OPEN AS={} hold={}", o.my_as, o.hold_time),
            Self::Update(_) => write!(f, "UPDATE"),
            Self::Notification(n) => write!(f, "NOTIFICATION {}/{}", n.code, n.subcode),
            Self::Keepalive => write!(f, "KEEPALIVE"),
            Self::RouteRefresh(rr) => write!(f, "{rr}"),
        }
    }
}

/// Decode a complete BGP message from a buffer.
///
/// The buffer must contain exactly one complete message (header + body).
/// The caller (transport framing layer) is responsible for length-delimited
/// framing — use [`peek_message_length`](crate::header::peek_message_length)
/// to determine when a complete message is available.
///
/// `max_message_len` is the negotiated maximum: 4096 normally, or 65535
/// when Extended Messages (RFC 8654) has been negotiated.
///
/// Advances the buffer past the consumed bytes on success.
///
/// # Errors
///
/// Returns a [`DecodeError`] if the header is malformed or the message body
/// fails validation for its type.
pub fn decode_message(buf: &mut Bytes, max_message_len: u16) -> Result<Message, DecodeError> {
    let header = BgpHeader::decode(buf, max_message_len)?;
    let body_len = usize::from(header.length) - HEADER_LEN;

    match header.message_type {
        MessageType::Keepalive => {
            keepalive::validate_keepalive(&header)?;
            Ok(Message::Keepalive)
        }
        MessageType::Notification => {
            let msg = NotificationMessage::decode(buf, body_len)?;
            Ok(Message::Notification(msg))
        }
        MessageType::Open => {
            let msg = OpenMessage::decode(buf, body_len)?;
            Ok(Message::Open(msg))
        }
        MessageType::Update => {
            let msg = UpdateMessage::decode(buf, body_len)?;
            Ok(Message::Update(msg))
        }
        MessageType::RouteRefresh => {
            let msg = RouteRefreshMessage::decode(buf, body_len)?;
            Ok(Message::RouteRefresh(msg))
        }
    }
}

/// Encode a BGP message into a newly allocated `BytesMut`.
///
/// Returns the complete wire-format message including the 19-byte header.
///
/// # Errors
///
/// Returns an [`EncodeError`] if the message exceeds the maximum BGP message
/// size or a field value is out of range.
pub fn encode_message(msg: &Message) -> Result<BytesMut, EncodeError> {
    let mut buf = BytesMut::with_capacity(match msg {
        Message::Keepalive => keepalive::KEEPALIVE_LEN,
        Message::Notification(n) => n.encoded_len(),
        Message::Open(o) => o.encoded_len(),
        Message::Update(u) => u.encoded_len(),
        Message::RouteRefresh(rr) => rr.encoded_len(),
    });

    match msg {
        Message::Keepalive => {
            keepalive::encode_keepalive(&mut buf);
        }
        Message::Notification(n) => {
            n.encode(&mut buf)?;
        }
        Message::Open(o) => {
            o.encode(&mut buf)?;
        }
        Message::Update(u) => {
            u.encode(&mut buf)?;
        }
        Message::RouteRefresh(rr) => {
            rr.encode(&mut buf)?;
        }
    }

    Ok(buf)
}

/// Encode a BGP message with a custom maximum message length.
///
/// Same as [`encode_message`] but uses `max_message_len` for UPDATE
/// size validation (RFC 8654 Extended Messages).
///
/// # Errors
///
/// Returns an [`EncodeError`] if the message exceeds the negotiated maximum
/// or a field value is out of range.
pub fn encode_message_with_limit(
    msg: &Message,
    max_message_len: u16,
) -> Result<BytesMut, EncodeError> {
    let mut buf = BytesMut::with_capacity(match msg {
        Message::Keepalive => keepalive::KEEPALIVE_LEN,
        Message::Notification(n) => n.encoded_len(),
        Message::Open(o) => o.encoded_len(),
        Message::Update(u) => u.encoded_len(),
        Message::RouteRefresh(rr) => rr.encoded_len(),
    });

    match msg {
        Message::Keepalive => {
            keepalive::encode_keepalive(&mut buf);
        }
        Message::Notification(n) => {
            n.encode(&mut buf)?;
        }
        Message::Open(o) => {
            o.encode(&mut buf)?;
        }
        Message::Update(u) => {
            u.encode_with_limit(&mut buf, max_message_len)?;
        }
        Message::RouteRefresh(rr) => {
            rr.encode(&mut buf)?;
        }
    }

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::capability::{Afi, Capability, Safi};
    use crate::constants::{BGP_VERSION, MAX_MESSAGE_LEN};
    use crate::notification::NotificationCode;

    #[test]
    fn roundtrip_keepalive() {
        let encoded = encode_message(&Message::Keepalive).unwrap();
        let mut bytes = encoded.freeze();
        let decoded = decode_message(&mut bytes, MAX_MESSAGE_LEN).unwrap();
        assert_eq!(decoded, Message::Keepalive);
    }

    #[test]
    fn roundtrip_notification() {
        let msg = Message::Notification(NotificationMessage::new(
            NotificationCode::Cease,
            2,
            Bytes::from_static(&[0x01, 0x02]),
        ));
        let encoded = encode_message(&msg).unwrap();
        let mut bytes = encoded.freeze();
        let decoded = decode_message(&mut bytes, MAX_MESSAGE_LEN).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_open_minimal() {
        let msg = Message::Open(OpenMessage {
            version: BGP_VERSION,
            my_as: 65001,
            hold_time: 90,
            bgp_identifier: Ipv4Addr::new(10, 0, 0, 1),
            capabilities: vec![],
        });
        let encoded = encode_message(&msg).unwrap();
        let mut bytes = encoded.freeze();
        let decoded = decode_message(&mut bytes, MAX_MESSAGE_LEN).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_open_with_caps() {
        let msg = Message::Open(OpenMessage {
            version: BGP_VERSION,
            my_as: 23456,
            hold_time: 180,
            bgp_identifier: Ipv4Addr::new(192, 168, 1, 1),
            capabilities: vec![
                Capability::MultiProtocol {
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                },
                Capability::FourOctetAs { asn: 4_200_000_001 },
                Capability::Unknown {
                    code: 128,
                    data: Bytes::from_static(&[0xAA]),
                },
            ],
        });
        let encoded = encode_message(&msg).unwrap();
        let mut bytes = encoded.freeze();
        let decoded = decode_message(&mut bytes, MAX_MESSAGE_LEN).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_update_minimal() {
        let msg = Message::Update(UpdateMessage {
            withdrawn_routes: Bytes::new(),
            path_attributes: Bytes::new(),
            nlri: Bytes::new(),
        });
        let encoded = encode_message(&msg).unwrap();
        let mut bytes = encoded.freeze();
        let decoded = decode_message(&mut bytes, MAX_MESSAGE_LEN).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_update_with_data() {
        let msg = Message::Update(UpdateMessage {
            withdrawn_routes: Bytes::from_static(&[0x18, 0x0A, 0x00]),
            path_attributes: Bytes::from_static(&[0x40, 0x01, 0x00]),
            nlri: Bytes::from_static(&[0x18, 0xC0, 0xA8]),
        });
        let encoded = encode_message(&msg).unwrap();
        let mut bytes = encoded.freeze();
        let decoded = decode_message(&mut bytes, MAX_MESSAGE_LEN).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn message_type_accessor() {
        assert_eq!(Message::Keepalive.message_type(), MessageType::Keepalive);
        assert_eq!(
            Message::Notification(NotificationMessage::new(
                NotificationCode::Cease,
                0,
                Bytes::new()
            ))
            .message_type(),
            MessageType::Notification
        );
    }

    #[test]
    fn decode_rejects_garbage() {
        let mut buf = Bytes::from_static(&[0x00; 19]);
        assert!(decode_message(&mut buf, MAX_MESSAGE_LEN).is_err());
    }

    #[test]
    fn decode_rejects_truncated() {
        let mut buf = Bytes::from_static(&[0xFF; 10]);
        assert!(matches!(
            decode_message(&mut buf, MAX_MESSAGE_LEN),
            Err(DecodeError::Incomplete { .. })
        ));
    }
}
