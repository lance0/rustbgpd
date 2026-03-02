use bytes::{Buf, BufMut};

use crate::constants::{self, HEADER_LEN, MARKER, MARKER_LEN, MAX_MESSAGE_LEN, MIN_MESSAGE_LEN};
use crate::error::DecodeError;

/// BGP message type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MessageType {
    Open = 1,
    Update = 2,
    Notification = 3,
    Keepalive = 4,
    RouteRefresh = 5,
}

impl MessageType {
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            constants::message_type::OPEN => Some(Self::Open),
            constants::message_type::UPDATE => Some(Self::Update),
            constants::message_type::NOTIFICATION => Some(Self::Notification),
            constants::message_type::KEEPALIVE => Some(Self::Keepalive),
            constants::message_type::ROUTE_REFRESH => Some(Self::RouteRefresh),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => write!(f, "OPEN"),
            Self::Update => write!(f, "UPDATE"),
            Self::Notification => write!(f, "NOTIFICATION"),
            Self::Keepalive => write!(f, "KEEPALIVE"),
            Self::RouteRefresh => write!(f, "ROUTE-REFRESH"),
        }
    }
}

/// Decoded BGP message header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BgpHeader {
    pub length: u16,
    pub message_type: MessageType,
}

impl BgpHeader {
    /// Decode a BGP header from a buffer. Validates marker, length, and type.
    /// Advances the buffer by 19 bytes on success.
    ///
    /// # Errors
    ///
    /// Returns a [`DecodeError`] if the buffer is too short, the marker is
    /// invalid, the length is out of range, or the message type is unknown.
    pub fn decode(buf: &mut impl Buf) -> Result<Self, DecodeError> {
        if buf.remaining() < HEADER_LEN {
            return Err(DecodeError::Incomplete {
                needed: HEADER_LEN,
                available: buf.remaining(),
            });
        }

        // Validate marker (16 bytes of 0xFF)
        let mut marker = [0u8; MARKER_LEN];
        buf.copy_to_slice(&mut marker);
        if marker != MARKER {
            return Err(DecodeError::InvalidMarker);
        }

        let length = buf.get_u16();
        if !(MIN_MESSAGE_LEN..=MAX_MESSAGE_LEN).contains(&length) {
            return Err(DecodeError::InvalidLength { length });
        }

        let type_byte = buf.get_u8();
        let message_type =
            MessageType::from_u8(type_byte).ok_or(DecodeError::UnknownMessageType(type_byte))?;

        Ok(Self {
            length,
            message_type,
        })
    }

    /// Encode a BGP header into a buffer.
    pub fn encode(&self, buf: &mut impl BufMut) {
        buf.put_slice(&MARKER);
        buf.put_u16(self.length);
        buf.put_u8(self.message_type.as_u8());
    }
}

/// Peek at a buffer to check if a complete BGP message is available.
///
/// Returns `Ok(Some(length))` if the header is valid and the full message
/// needs `length` bytes. Returns `Ok(None)` if fewer than 19 bytes are
/// available. Returns `Err` if the header is malformed.
///
/// Does NOT advance the buffer.
///
/// # Errors
///
/// Returns a [`DecodeError`] if the marker is invalid, the length is out
/// of range, or the message type is unknown.
pub fn peek_message_length(buf: &[u8]) -> Result<Option<u16>, DecodeError> {
    if buf.len() < HEADER_LEN {
        return Ok(None);
    }

    // Check marker
    if buf[..MARKER_LEN] != MARKER {
        return Err(DecodeError::InvalidMarker);
    }

    let length = u16::from_be_bytes([buf[16], buf[17]]);
    if !(MIN_MESSAGE_LEN..=MAX_MESSAGE_LEN).contains(&length) {
        return Err(DecodeError::InvalidLength { length });
    }

    let type_byte = buf[18];
    if MessageType::from_u8(type_byte).is_none() {
        return Err(DecodeError::UnknownMessageType(type_byte));
    }

    Ok(Some(length))
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::*;

    fn make_header(length: u16, msg_type: u8) -> BytesMut {
        let mut buf = BytesMut::with_capacity(HEADER_LEN);
        buf.put_slice(&MARKER);
        buf.put_u16(length);
        buf.put_u8(msg_type);
        buf
    }

    #[test]
    fn decode_valid_keepalive_header() {
        let mut buf = make_header(19, 4).freeze();
        let hdr = BgpHeader::decode(&mut buf).unwrap();
        assert_eq!(hdr.length, 19);
        assert_eq!(hdr.message_type, MessageType::Keepalive);
        assert_eq!(buf.remaining(), 0);
    }

    #[test]
    fn decode_valid_open_header() {
        let mut buf = make_header(29, 1).freeze();
        let hdr = BgpHeader::decode(&mut buf).unwrap();
        assert_eq!(hdr.message_type, MessageType::Open);
    }

    #[test]
    fn reject_invalid_marker() {
        let mut data = make_header(19, 4);
        data[0] = 0x00; // corrupt marker
        let mut buf = data.freeze();
        assert!(matches!(
            BgpHeader::decode(&mut buf),
            Err(DecodeError::InvalidMarker)
        ));
    }

    #[test]
    fn reject_length_too_small() {
        let mut buf = make_header(18, 4).freeze();
        assert!(matches!(
            BgpHeader::decode(&mut buf),
            Err(DecodeError::InvalidLength { length: 18 })
        ));
    }

    #[test]
    fn reject_length_too_large() {
        let mut buf = make_header(4097, 4).freeze();
        assert!(matches!(
            BgpHeader::decode(&mut buf),
            Err(DecodeError::InvalidLength { length: 4097 })
        ));
    }

    #[test]
    fn reject_unknown_type() {
        let mut buf = make_header(19, 99).freeze();
        assert!(matches!(
            BgpHeader::decode(&mut buf),
            Err(DecodeError::UnknownMessageType(99))
        ));
    }

    #[test]
    fn reject_incomplete_buffer() {
        let mut buf = bytes::Bytes::from_static(&[0xFF; 10]);
        assert!(matches!(
            BgpHeader::decode(&mut buf),
            Err(DecodeError::Incomplete { .. })
        ));
    }

    #[test]
    fn roundtrip_header() {
        let original = BgpHeader {
            length: 100,
            message_type: MessageType::Update,
        };
        let mut encoded = BytesMut::with_capacity(HEADER_LEN);
        original.encode(&mut encoded);
        let mut buf = encoded.freeze();
        let decoded = BgpHeader::decode(&mut buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn peek_returns_none_for_short_buffer() {
        assert_eq!(peek_message_length(&[0xFF; 10]).unwrap(), None);
    }

    #[test]
    fn peek_returns_length_for_valid_header() {
        let buf = make_header(42, 1);
        assert_eq!(peek_message_length(&buf).unwrap(), Some(42));
    }

    #[test]
    fn peek_rejects_bad_marker() {
        let mut data = make_header(19, 4);
        data[15] = 0x00;
        assert!(matches!(
            peek_message_length(&data),
            Err(DecodeError::InvalidMarker)
        ));
    }
}
