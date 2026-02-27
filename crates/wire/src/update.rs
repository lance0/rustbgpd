use bytes::{Buf, BufMut, Bytes};

use crate::constants::{HEADER_LEN, MAX_MESSAGE_LEN};
use crate::error::{DecodeError, EncodeError};
use crate::header::{BgpHeader, MessageType};

/// A decoded BGP UPDATE message (RFC 4271 §4.3).
///
/// In M0, the three variable-length sections are stored as raw `Bytes`.
/// Full attribute and NLRI parsing is M1 scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateMessage {
    /// Raw withdrawn routes (NLRI encoding).
    pub withdrawn_routes: Bytes,
    /// Raw path attributes.
    pub path_attributes: Bytes,
    /// Raw Network Layer Reachability Information.
    pub nlri: Bytes,
}

impl UpdateMessage {
    /// Decode an UPDATE message body from a buffer.
    /// The header must already be consumed; `body_len` is
    /// `header.length - HEADER_LEN`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UpdateLengthMismatch`] if the body is too short
    /// or length fields are inconsistent, or [`DecodeError::Incomplete`] if
    /// the buffer has fewer bytes than `body_len`.
    pub fn decode(buf: &mut impl Buf, body_len: usize) -> Result<Self, DecodeError> {
        // Minimum body: withdrawn_len(2) + attrs_len(2) = 4
        if body_len < 4 {
            return Err(DecodeError::UpdateLengthMismatch {
                detail: format!("body too short: {body_len} bytes (need at least 4)"),
            });
        }

        if buf.remaining() < body_len {
            return Err(DecodeError::Incomplete {
                needed: body_len,
                available: buf.remaining(),
            });
        }

        let withdrawn_routes_len = buf.get_u16();

        // Validate withdrawn routes fit in remaining body
        // body_len = 2 (withdrawn_len) + withdrawn_routes + 2 (attrs_len) + attrs + nlri
        let after_withdrawn = body_len
            .checked_sub(2)
            .and_then(|v| v.checked_sub(usize::from(withdrawn_routes_len)))
            .ok_or_else(|| DecodeError::UpdateLengthMismatch {
                detail: format!(
                    "withdrawn routes length {withdrawn_routes_len} exceeds body"
                ),
            })?;

        if after_withdrawn < 2 {
            return Err(DecodeError::UpdateLengthMismatch {
                detail: format!(
                    "no room for path attributes length after {withdrawn_routes_len} \
                     bytes of withdrawn routes"
                ),
            });
        }

        let withdrawn_routes = buf.copy_to_bytes(usize::from(withdrawn_routes_len));

        let path_attributes_len = buf.get_u16();

        let nlri_len = after_withdrawn
            .checked_sub(2)
            .and_then(|v| v.checked_sub(usize::from(path_attributes_len)))
            .ok_or_else(|| DecodeError::UpdateLengthMismatch {
                detail: format!(
                    "path attributes length {path_attributes_len} exceeds remaining body"
                ),
            })?;

        let path_attributes = buf.copy_to_bytes(usize::from(path_attributes_len));
        let nlri = buf.copy_to_bytes(nlri_len);

        Ok(Self {
            withdrawn_routes,
            path_attributes,
            nlri,
        })
    }

    /// Encode a complete UPDATE message (header + body) into a buffer.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::MessageTooLong`] if the encoded message exceeds
    /// the maximum BGP message size.
    pub fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
        let body_len =
            2 + self.withdrawn_routes.len() + 2 + self.path_attributes.len() + self.nlri.len();
        let total_len = HEADER_LEN + body_len;

        if total_len > usize::from(MAX_MESSAGE_LEN) {
            return Err(EncodeError::MessageTooLong { size: total_len });
        }

        let header = BgpHeader {
            #[expect(clippy::cast_possible_truncation)]
            length: total_len as u16,
            message_type: MessageType::Update,
        };
        header.encode(buf);

        #[expect(clippy::cast_possible_truncation)]
        buf.put_u16(self.withdrawn_routes.len() as u16);
        buf.put_slice(&self.withdrawn_routes);

        #[expect(clippy::cast_possible_truncation)]
        buf.put_u16(self.path_attributes.len() as u16);
        buf.put_slice(&self.path_attributes);

        buf.put_slice(&self.nlri);

        Ok(())
    }

    /// Total encoded size in bytes.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        HEADER_LEN + 2 + self.withdrawn_routes.len() + 2 + self.path_attributes.len()
            + self.nlri.len()
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::*;

    #[test]
    fn decode_minimal_update() {
        // withdrawn_len=0, attrs_len=0, no NLRI
        let body: &[u8] = &[0, 0, 0, 0];
        let mut buf = Bytes::copy_from_slice(body);
        let msg = UpdateMessage::decode(&mut buf, 4).unwrap();
        assert!(msg.withdrawn_routes.is_empty());
        assert!(msg.path_attributes.is_empty());
        assert!(msg.nlri.is_empty());
    }

    #[test]
    fn decode_with_withdrawn_routes() {
        // withdrawn_len=3, withdrawn=[0x18, 0x0A, 0x00] (10.0.0.0/24), attrs_len=0
        let body: &[u8] = &[0, 3, 0x18, 0x0A, 0x00, 0, 0];
        let mut buf = Bytes::copy_from_slice(body);
        let msg = UpdateMessage::decode(&mut buf, 7).unwrap();
        assert_eq!(msg.withdrawn_routes.as_ref(), &[0x18, 0x0A, 0x00]);
        assert!(msg.path_attributes.is_empty());
        assert!(msg.nlri.is_empty());
    }

    #[test]
    fn decode_with_all_sections() {
        let mut body = BytesMut::new();
        body.put_u16(2); // withdrawn_len
        body.put_slice(&[0x10, 0x0A]); // withdrawn
        body.put_u16(3); // attrs_len
        body.put_slice(&[0x40, 0x01, 0x00]); // attrs (fake)
        body.put_slice(&[0x18, 0xC0, 0xA8]); // NLRI (fake)

        let total = body.len();
        let mut buf = body.freeze();
        let msg = UpdateMessage::decode(&mut buf, total).unwrap();
        assert_eq!(msg.withdrawn_routes.len(), 2);
        assert_eq!(msg.path_attributes.len(), 3);
        assert_eq!(msg.nlri.len(), 3);
    }

    #[test]
    fn reject_withdrawn_overflow() {
        // withdrawn_len=100, but body is only 6 bytes
        let body: &[u8] = &[0, 100, 0, 0, 0, 0];
        let mut buf = Bytes::copy_from_slice(body);
        assert!(matches!(
            UpdateMessage::decode(&mut buf, 6),
            Err(DecodeError::UpdateLengthMismatch { .. })
        ));
    }

    #[test]
    fn reject_attrs_overflow() {
        // withdrawn_len=0, attrs_len=100, but body is only 4 bytes
        let body: &[u8] = &[0, 0, 0, 100];
        let mut buf = Bytes::copy_from_slice(body);
        assert!(matches!(
            UpdateMessage::decode(&mut buf, 4),
            Err(DecodeError::UpdateLengthMismatch { .. })
        ));
    }

    #[test]
    fn encode_decode_roundtrip() {
        let original = UpdateMessage {
            withdrawn_routes: Bytes::from_static(&[0x18, 0x0A, 0x00]),
            path_attributes: Bytes::from_static(&[0x40, 0x01, 0x00]),
            nlri: Bytes::from_static(&[0x18, 0xC0, 0xA8]),
        };

        let mut encoded = BytesMut::with_capacity(original.encoded_len());
        original.encode(&mut encoded).unwrap();

        let mut bytes = encoded.freeze();
        let header = BgpHeader::decode(&mut bytes).unwrap();
        assert_eq!(header.message_type, MessageType::Update);

        let body_len = usize::from(header.length) - HEADER_LEN;
        let decoded = UpdateMessage::decode(&mut bytes, body_len).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn reject_message_too_long() {
        let msg = UpdateMessage {
            withdrawn_routes: Bytes::new(),
            path_attributes: Bytes::from(vec![0u8; 4096]),
            nlri: Bytes::new(),
        };
        let mut buf = BytesMut::with_capacity(5000);
        assert!(matches!(
            msg.encode(&mut buf),
            Err(EncodeError::MessageTooLong { .. })
        ));
    }
}
