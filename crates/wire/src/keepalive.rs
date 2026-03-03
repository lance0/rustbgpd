use bytes::BufMut;

use crate::constants::{HEADER_LEN, MIN_MESSAGE_LEN};
use crate::error::DecodeError;
use crate::header::{BgpHeader, MessageType};

/// Validate that a KEEPALIVE message has the correct length.
/// KEEPALIVE is header-only — exactly 19 bytes, no body.
///
/// # Errors
///
/// Returns [`DecodeError::InvalidKeepaliveLength`] if the header length is
/// not exactly 19 bytes.
pub fn validate_keepalive(header: &BgpHeader) -> Result<(), DecodeError> {
    if header.length != MIN_MESSAGE_LEN {
        return Err(DecodeError::InvalidKeepaliveLength {
            length: header.length,
        });
    }
    Ok(())
}

/// Encode a KEEPALIVE message (19 bytes: header only).
pub fn encode_keepalive(buf: &mut impl BufMut) {
    let header = BgpHeader {
        length: MIN_MESSAGE_LEN,
        message_type: MessageType::Keepalive,
    };
    header.encode(buf);
}

/// Size of an encoded KEEPALIVE message.
pub const KEEPALIVE_LEN: usize = HEADER_LEN;

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::*;
    use crate::constants::MAX_MESSAGE_LEN;
    use crate::header::BgpHeader;

    #[test]
    fn encode_produces_19_bytes() {
        let mut buf = BytesMut::with_capacity(KEEPALIVE_LEN);
        encode_keepalive(&mut buf);
        assert_eq!(buf.len(), 19);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let mut buf = BytesMut::with_capacity(KEEPALIVE_LEN);
        encode_keepalive(&mut buf);
        let mut bytes = buf.freeze();
        let header = BgpHeader::decode(&mut bytes, MAX_MESSAGE_LEN).unwrap();
        assert_eq!(header.message_type, MessageType::Keepalive);
        assert_eq!(header.length, 19);
        validate_keepalive(&header).unwrap();
    }

    #[test]
    fn reject_wrong_length() {
        let header = BgpHeader {
            length: 20,
            message_type: MessageType::Keepalive,
        };
        assert!(matches!(
            validate_keepalive(&header),
            Err(DecodeError::InvalidKeepaliveLength { length: 20 })
        ));
    }
}
