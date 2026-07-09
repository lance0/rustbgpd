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
/// Same as [`encode_message`] but uses `max_message_len` for UPDATE,
/// NOTIFICATION, and ROUTE-REFRESH size validation (RFC 8654 §3: Extended
/// Messages apply to every message type except OPEN and KEEPALIVE, which
/// always use the standard 4096-byte limit).
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
            n.encode_with_limit(&mut buf, max_message_len)?;
        }
        Message::Open(o) => {
            // RFC 8654 §3: OPEN is never extended — always 4096.
            o.encode(&mut buf)?;
        }
        Message::Update(u) => {
            u.encode_with_limit(&mut buf, max_message_len)?;
        }
        Message::RouteRefresh(rr) => {
            rr.encode_with_limit(&mut buf, max_message_len)?;
        }
    }

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::capability::{Afi, Capability, Safi};
    use crate::constants::{BGP_VERSION, EXTENDED_MAX_MESSAGE_LEN, MAX_MESSAGE_LEN};
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

    // RFC 8654 §3: the extended limit applies to NOTIFICATION and
    // ROUTE-REFRESH, not just UPDATE — and the standard 4096-byte limit
    // must still bound them when Extended Messages was not negotiated.

    fn big_notification(data_len: usize) -> Message {
        Message::Notification(NotificationMessage::new(
            NotificationCode::Cease,
            2,
            Bytes::from(vec![0_u8; data_len]),
        ))
    }

    fn big_route_refresh(raw_orf_len: usize) -> Message {
        use crate::orf::{OrfEntries, OrfEntryGroup, OrfPayload, OrfType, WhenToRefresh};
        Message::RouteRefresh(RouteRefreshMessage::new_with_orf(
            Afi::Ipv4,
            Safi::Unicast,
            OrfPayload {
                when_to_refresh: WhenToRefresh::Immediate,
                groups: vec![OrfEntryGroup {
                    orf_type: OrfType::AddressPrefix,
                    entries: OrfEntries::Raw(Bytes::from(vec![0_u8; raw_orf_len])),
                }],
            },
        ))
    }

    #[test]
    fn notification_respects_extended_limit_both_directions() {
        let msg = big_notification(5000); // total 5021 bytes
        assert!(matches!(
            encode_message_with_limit(&msg, MAX_MESSAGE_LEN),
            Err(EncodeError::MessageTooLong { size: 5021 })
        ));
        let encoded = encode_message_with_limit(&msg, EXTENDED_MAX_MESSAGE_LEN).unwrap();
        assert_eq!(encoded.len(), 5021);
        // Inbound: accepted at the extended limit, rejected at the standard one.
        let decoded = decode_message(&mut encoded.clone().freeze(), EXTENDED_MAX_MESSAGE_LEN);
        assert_eq!(decoded.unwrap(), msg);
        assert!(decode_message(&mut encoded.freeze(), MAX_MESSAGE_LEN).is_err());
    }

    #[test]
    fn route_refresh_respects_extended_limit_both_directions() {
        let msg = big_route_refresh(5000); // header + body + ORF section > 4096
        assert!(matches!(
            encode_message_with_limit(&msg, MAX_MESSAGE_LEN),
            Err(EncodeError::MessageTooLong { .. })
        ));
        let encoded = encode_message_with_limit(&msg, EXTENDED_MAX_MESSAGE_LEN).unwrap();
        assert!(encoded.len() > usize::from(MAX_MESSAGE_LEN));
        // Inbound: accepted at the extended limit (the raw ORF bytes
        // re-decode as parsed entries, so compare the type, not the value),
        // rejected at the standard one.
        let decoded = decode_message(&mut encoded.clone().freeze(), EXTENDED_MAX_MESSAGE_LEN);
        assert!(matches!(decoded.unwrap(), Message::RouteRefresh(_)));
        assert!(decode_message(&mut encoded.freeze(), MAX_MESSAGE_LEN).is_err());
    }

    #[test]
    fn notification_boundary_at_4096_and_65535() {
        // Exactly 4096 total fits the standard limit; one more byte does not.
        let at_limit = big_notification(usize::from(MAX_MESSAGE_LEN) - HEADER_LEN - 2);
        let encoded = encode_message_with_limit(&at_limit, MAX_MESSAGE_LEN).unwrap();
        assert_eq!(encoded.len(), usize::from(MAX_MESSAGE_LEN));
        let over = big_notification(usize::from(MAX_MESSAGE_LEN) - HEADER_LEN - 1);
        assert!(encode_message_with_limit(&over, MAX_MESSAGE_LEN).is_err());
        assert!(encode_message_with_limit(&over, EXTENDED_MAX_MESSAGE_LEN).is_ok());
        // Exactly 65535 total fits the extended limit; one more byte does not.
        let at_ext = big_notification(usize::from(EXTENDED_MAX_MESSAGE_LEN) - HEADER_LEN - 2);
        let encoded = encode_message_with_limit(&at_ext, EXTENDED_MAX_MESSAGE_LEN).unwrap();
        assert_eq!(encoded.len(), usize::from(EXTENDED_MAX_MESSAGE_LEN));
        let over_ext = big_notification(usize::from(EXTENDED_MAX_MESSAGE_LEN) - HEADER_LEN - 1);
        assert!(encode_message_with_limit(&over_ext, EXTENDED_MAX_MESSAGE_LEN).is_err());
    }

    #[test]
    fn open_never_uses_extended_limit() {
        // RFC 8654 §3: OPEN is excluded from Extended Messages — an
        // oversized OPEN must fail even with the extended limit.
        let msg = Message::Open(OpenMessage {
            version: BGP_VERSION,
            my_as: 65001,
            hold_time: 90,
            bgp_identifier: Ipv4Addr::new(10, 0, 0, 1),
            capabilities: vec![Capability::Unknown {
                code: 128,
                data: Bytes::from(vec![0_u8; 5000]),
            }],
        });
        assert!(encode_message_with_limit(&msg, EXTENDED_MAX_MESSAGE_LEN).is_err());
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
    fn roundtrip_orf_route_refresh() {
        use crate::nlri::{Ipv4Prefix, Prefix};
        use crate::orf::{
            AddressPrefixOrf, OrfAction, OrfEntries, OrfEntryGroup, OrfMatch, OrfPayload, OrfType,
            WhenToRefresh,
        };
        use crate::route_refresh::RouteRefreshMessage;

        let payload = OrfPayload {
            when_to_refresh: WhenToRefresh::Immediate,
            groups: vec![OrfEntryGroup {
                orf_type: OrfType::AddressPrefix,
                entries: OrfEntries::AddressPrefix(vec![AddressPrefixOrf {
                    action: OrfAction::Add,
                    match_: OrfMatch::Deny,
                    sequence: 5,
                    min_len: 0,
                    max_len: 0,
                    prefix: Some(Prefix::V4(Ipv4Prefix::new(
                        Ipv4Addr::new(192, 168, 0, 0),
                        16,
                    ))),
                }]),
            }],
        };
        let msg = Message::RouteRefresh(RouteRefreshMessage::new_with_orf(
            Afi::Ipv4,
            Safi::Unicast,
            payload,
        ));
        let encoded = encode_message(&msg).unwrap();
        let mut bytes = encoded.freeze();
        let decoded = decode_message(&mut bytes, MAX_MESSAGE_LEN).unwrap();
        assert_eq!(decoded, msg);
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
