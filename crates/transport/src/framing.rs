//! Length-delimited BGP message framing over TCP byte streams.

use bytes::{Bytes, BytesMut};
use rustbgpd_wire::constants::MAX_MESSAGE_LEN;
use rustbgpd_wire::{DecodeError, Message, decode_message, peek_message_length};

/// Length-delimited read buffer for BGP messages.
///
/// Accumulates bytes from TCP reads and extracts complete BGP messages
/// using [`peek_message_length`] for framing and [`decode_message`] for
/// parsing.
pub struct ReadBuffer {
    pub(crate) buf: BytesMut,
    max_message_len: u16,
}

impl ReadBuffer {
    /// Create a new read buffer with capacity for one standard-size BGP message.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: BytesMut::with_capacity(MAX_MESSAGE_LEN.into()),
            max_message_len: MAX_MESSAGE_LEN,
        }
    }

    /// Update the maximum message length (e.g., after Extended Messages negotiation).
    /// Reserves additional capacity if the new limit exceeds current capacity.
    pub fn set_max_message_len(&mut self, len: u16) {
        self.max_message_len = len;
        let needed = usize::from(len);
        if self.buf.capacity() < needed {
            self.buf.reserve(needed - self.buf.capacity());
        }
    }

    /// Try to extract and decode one complete BGP message from the buffer.
    ///
    /// Returns `Ok(None)` if the buffer doesn't yet contain a complete
    /// message. On success, the consumed bytes are removed from the buffer.
    /// The returned tuple contains the decoded message and the raw PDU bytes
    /// (including the 19-byte BGP header), needed for BMP Route Monitoring.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] if the header is malformed or the message
    /// body fails validation.
    pub fn try_decode(&mut self) -> Result<Option<(Message, Bytes)>, DecodeError> {
        let len = match peek_message_length(&self.buf, self.max_message_len)? {
            Some(len) => usize::from(len),
            None => return Ok(None),
        };

        if self.buf.len() < len {
            return Ok(None);
        }

        let frame = self.buf.split_to(len).freeze();
        let raw = frame.clone(); // Bytes::clone is refcount-only, no data copy
        let mut bytes = frame;
        let msg = decode_message(&mut bytes, self.max_message_len)?;
        Ok(Some((msg, raw)))
    }

    /// Clear all buffered data (e.g., after TCP disconnect).
    pub fn clear(&mut self) {
        self.buf.clear();
    }
}

impl Default for ReadBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use bytes::BufMut;
    use rustbgpd_wire::{Message, encode_message};

    use super::*;

    #[test]
    fn empty_buffer_returns_none() {
        let mut rb = ReadBuffer::new();
        assert!(rb.try_decode().unwrap().is_none());
    }

    #[test]
    fn partial_header_returns_none() {
        let mut rb = ReadBuffer::new();
        rb.buf.put_slice(&[0xFF; 10]); // less than 19-byte header
        assert!(rb.try_decode().unwrap().is_none());
    }

    #[test]
    fn complete_keepalive_decodes() {
        let mut rb = ReadBuffer::new();
        let encoded = encode_message(&Message::Keepalive).unwrap();
        rb.buf.put_slice(&encoded);

        let (msg, raw) = rb.try_decode().unwrap().unwrap();
        assert_eq!(msg, Message::Keepalive);
        assert_eq!(&raw[..], &encoded[..]);
        assert!(rb.buf.is_empty());
    }

    #[test]
    fn two_messages_back_to_back() {
        let mut rb = ReadBuffer::new();
        let ka1 = encode_message(&Message::Keepalive).unwrap();
        let ka2 = encode_message(&Message::Keepalive).unwrap();
        rb.buf.put_slice(&ka1);
        rb.buf.put_slice(&ka2);

        assert_eq!(rb.try_decode().unwrap().unwrap().0, Message::Keepalive);
        assert_eq!(rb.try_decode().unwrap().unwrap().0, Message::Keepalive);
        assert!(rb.try_decode().unwrap().is_none());
    }

    #[test]
    fn partial_message_body_returns_none() {
        let mut rb = ReadBuffer::new();
        let encoded = encode_message(&Message::Keepalive).unwrap();
        // Put only part of the message (header says 19 bytes, give 18)
        rb.buf.put_slice(&encoded[..18]);

        assert!(rb.try_decode().unwrap().is_none());
    }

    #[test]
    fn invalid_marker_returns_error() {
        let mut rb = ReadBuffer::new();
        rb.buf.put_slice(&[0x00; 19]); // invalid marker
        assert!(rb.try_decode().is_err());
    }

    #[test]
    fn message_split_across_extends() {
        let mut rb = ReadBuffer::new();
        let encoded = encode_message(&Message::Keepalive).unwrap();

        // First chunk: partial
        rb.buf.put_slice(&encoded[..10]);
        assert!(rb.try_decode().unwrap().is_none());

        // Second chunk: rest of message
        rb.buf.put_slice(&encoded[10..]);
        assert_eq!(rb.try_decode().unwrap().unwrap().0, Message::Keepalive);
    }

    #[test]
    fn clear_empties_buffer() {
        let mut rb = ReadBuffer::new();
        rb.buf.put_slice(&[0xFF; 100]);
        rb.clear();
        assert!(rb.buf.is_empty());
    }
}
