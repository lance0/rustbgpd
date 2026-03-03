use bytes::{Buf, BufMut, Bytes};

use crate::constants::HEADER_LEN;
use crate::error::{DecodeError, EncodeError};
use crate::header::{BgpHeader, MessageType};
use crate::notification::NotificationCode;

/// A decoded BGP NOTIFICATION message (RFC 4271 §4.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationMessage {
    pub code: NotificationCode,
    pub subcode: u8,
    pub data: Bytes,
}

impl NotificationMessage {
    /// Decode a NOTIFICATION message body from a buffer.
    /// The header must already be consumed; `body_len` is
    /// `header.length - HEADER_LEN`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::MalformedField`] if the body is too short, or
    /// [`DecodeError::Incomplete`] if the buffer has fewer bytes than `body_len`.
    pub fn decode(buf: &mut impl Buf, body_len: usize) -> Result<Self, DecodeError> {
        if body_len < 2 {
            return Err(DecodeError::MalformedField {
                message_type: "NOTIFICATION",
                detail: format!("body too short: {body_len} bytes (need at least 2)"),
            });
        }

        if buf.remaining() < body_len {
            return Err(DecodeError::Incomplete {
                needed: body_len,
                available: buf.remaining(),
            });
        }

        let code_byte = buf.get_u8();
        let code = NotificationCode::from_u8(code_byte);

        let subcode = buf.get_u8();

        let data_len = body_len - 2;
        let data = buf.copy_to_bytes(data_len);

        Ok(Self {
            code,
            subcode,
            data,
        })
    }

    /// Encode a NOTIFICATION message body into a buffer.
    /// Does NOT write the header — call this after encoding the header.
    pub fn encode_body(&self, buf: &mut impl BufMut) {
        buf.put_u8(self.code.as_u8());
        buf.put_u8(self.subcode);
        buf.put_slice(&self.data);
    }

    /// Encode a complete NOTIFICATION message (header + body).
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::MessageTooLong`] if the encoded message exceeds
    /// the maximum BGP message size.
    pub fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
        let total_len = HEADER_LEN + 2 + self.data.len();
        if total_len > usize::from(crate::constants::MAX_MESSAGE_LEN) {
            return Err(EncodeError::MessageTooLong { size: total_len });
        }

        let header = BgpHeader {
            #[expect(clippy::cast_possible_truncation)]
            length: total_len as u16,
            message_type: MessageType::Notification,
        };
        header.encode(buf);
        self.encode_body(buf);
        Ok(())
    }

    /// Total encoded size in bytes.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        HEADER_LEN + 2 + self.data.len()
    }

    /// Convenience: build a NOTIFICATION from code, subcode, and data.
    #[must_use]
    pub fn new(code: NotificationCode, subcode: u8, data: Bytes) -> Self {
        Self {
            code,
            subcode,
            data,
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::*;
    use crate::constants::MAX_MESSAGE_LEN;

    #[test]
    fn decode_notification_no_data() {
        // code=6 (Cease), subcode=2 (Administrative Shutdown), no data
        let body: &[u8] = &[6, 2];
        let mut buf = Bytes::copy_from_slice(body);
        let msg = NotificationMessage::decode(&mut buf, 2).unwrap();
        assert_eq!(msg.code, NotificationCode::Cease);
        assert_eq!(msg.subcode, 2);
        assert!(msg.data.is_empty());
    }

    #[test]
    fn decode_notification_with_data() {
        let body: &[u8] = &[1, 2, 0x00, 0x0F]; // Header Error, Bad Length, data=[0,15]
        let mut buf = Bytes::copy_from_slice(body);
        let msg = NotificationMessage::decode(&mut buf, 4).unwrap();
        assert_eq!(msg.code, NotificationCode::MessageHeader);
        assert_eq!(msg.subcode, 2);
        assert_eq!(msg.data.as_ref(), &[0x00, 0x0F]);
    }

    #[test]
    fn reject_body_too_short() {
        let body: &[u8] = &[1];
        let mut buf = Bytes::copy_from_slice(body);
        assert!(NotificationMessage::decode(&mut buf, 1).is_err());
    }

    #[test]
    fn encode_decode_roundtrip() {
        let original = NotificationMessage::new(
            NotificationCode::OpenMessage,
            6, // Unacceptable Hold Time
            Bytes::from_static(&[0x00, 0x02]),
        );

        let mut encoded = BytesMut::with_capacity(original.encoded_len());
        original.encode(&mut encoded).unwrap();

        // Decode: skip header, then decode body
        let mut bytes = encoded.freeze();
        let header = BgpHeader::decode(&mut bytes, MAX_MESSAGE_LEN).unwrap();
        assert_eq!(header.message_type, MessageType::Notification);

        let decoded =
            NotificationMessage::decode(&mut bytes, usize::from(header.length) - HEADER_LEN)
                .unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn reject_message_too_long() {
        let msg = NotificationMessage::new(
            NotificationCode::Cease,
            0,
            Bytes::from(vec![0u8; 4096]), // way too big
        );
        let mut buf = BytesMut::with_capacity(5000);
        assert!(matches!(
            msg.encode(&mut buf),
            Err(EncodeError::MessageTooLong { .. })
        ));
    }
}
