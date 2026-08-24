//! Tokio framing adapter for BGP message streams.
//!
//! BGP Extended Messages negotiation is directional: the capability we
//! advertise controls the frames accepted inbound, while the peer's
//! capability controls the frames sent outbound. [`BgpCodec`] therefore
//! keeps separate limits for the two directions.
//!
//! ```rust
//! use bytes::BytesMut;
//! use rustbgpd_wire::{
//!     BgpCodec, EXTENDED_MAX_MESSAGE_LEN, MAX_MESSAGE_LEN, Message,
//! };
//! use tokio_util::codec::{Decoder, Encoder};
//!
//! let mut codec = BgpCodec::with_max_message_lengths(
//!     EXTENDED_MAX_MESSAGE_LEN,
//!     MAX_MESSAGE_LEN,
//! );
//! let mut wire = BytesMut::new();
//! codec.encode(Message::Keepalive, &mut wire)?;
//! assert_eq!(codec.decode(&mut wire)?, Some(Message::Keepalive));
//! # Ok::<(), rustbgpd_wire::BgpCodecError>(())
//! ```

use std::io;

use bytes::BytesMut;
use thiserror::Error;
use tokio_util::codec::{Decoder, Encoder};

use crate::constants::HEADER_LEN;
use crate::{
    DecodeError, EncodeError, MAX_MESSAGE_LEN, Message, decode_message, encode_message_with_limit,
    peek_message_length,
};

/// Errors produced by [`BgpCodec`].
///
/// Tokio requires decoder and encoder errors to accept [`io::Error`]. The
/// protocol variants remain typed so a caller can, for example, map a
/// [`DecodeError`] to its BGP NOTIFICATION.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BgpCodecError {
    /// The framed transport reported an I/O error.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// A complete inbound frame failed BGP validation.
    #[error(transparent)]
    Decode(#[from] DecodeError),
    /// An outbound message could not be encoded within its configured limit.
    #[error(transparent)]
    Encode(#[from] EncodeError),
}

/// A `tokio_util::codec` adapter for complete BGP messages.
///
/// The default limits both directions to the RFC 4271 maximum of 4096 bytes.
/// After OPEN negotiation, update the inbound and outbound limits separately:
/// our advertised Extended Message capability controls inbound acceptance,
/// while the peer's advertised capability controls outbound encoding.
///
/// The decoded item is [`Message`]. Applications that also require the exact
/// original PDU bytes should continue to frame with [`peek_message_length`]
/// and retain the split frame before calling [`decode_message`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BgpCodec {
    inbound_max_message_len: u16,
    outbound_max_message_len: u16,
}

impl BgpCodec {
    /// Create a codec with the standard 4096-byte limit in both directions.
    #[must_use]
    pub const fn new() -> Self {
        Self::with_max_message_lengths(MAX_MESSAGE_LEN, MAX_MESSAGE_LEN)
    }

    /// Create a codec with explicit inbound and outbound message limits.
    ///
    /// RFC 8654 deployments normally use [`MAX_MESSAGE_LEN`] or
    /// [`crate::EXTENDED_MAX_MESSAGE_LEN`]. Intermediate values are also
    /// accepted as an application-level defensive ceiling.
    #[must_use]
    pub const fn with_max_message_lengths(
        inbound_max_message_len: u16,
        outbound_max_message_len: u16,
    ) -> Self {
        Self {
            inbound_max_message_len,
            outbound_max_message_len,
        }
    }

    /// Return the maximum accepted inbound message length.
    #[must_use]
    pub const fn inbound_max_message_len(&self) -> u16 {
        self.inbound_max_message_len
    }

    /// Set the maximum accepted inbound message length.
    pub const fn set_inbound_max_message_len(&mut self, max_message_len: u16) {
        self.inbound_max_message_len = max_message_len;
    }

    /// Return the maximum encoded outbound message length.
    #[must_use]
    pub const fn outbound_max_message_len(&self) -> u16 {
        self.outbound_max_message_len
    }

    /// Set the maximum encoded outbound message length.
    pub const fn set_outbound_max_message_len(&mut self, max_message_len: u16) {
        self.outbound_max_message_len = max_message_len;
    }
}

impl Default for BgpCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for BgpCodec {
    type Item = Message;
    type Error = BgpCodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let Some(frame_len) = peek_message_length(src, self.inbound_max_message_len)? else {
            src.reserve(HEADER_LEN.saturating_sub(src.len()));
            return Ok(None);
        };
        let frame_len = usize::from(frame_len);

        if src.len() < frame_len {
            src.reserve(frame_len - src.len());
            return Ok(None);
        }

        // Split the declared frame before body decoding. A malformed body can
        // then consume only its own PDU, never bytes from a following frame.
        let mut frame = src.split_to(frame_len).freeze();
        let message = decode_message(&mut frame, self.inbound_max_message_len)?;
        debug_assert!(
            frame.is_empty(),
            "complete message decoder left frame bytes"
        );
        Ok(Some(message))
    }
}

impl Encoder<Message> for BgpCodec {
    type Error = BgpCodecError;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        // Encode transactionally into a temporary buffer so a validation
        // error cannot leave a partial frame in Tokio's write buffer.
        let encoded = encode_message_with_limit(&item, self.outbound_max_message_len)?;
        dst.reserve(encoded.len());
        dst.extend_from_slice(&encoded);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use bytes::{BufMut, Bytes};
    use tokio_util::codec::{Decoder, Encoder};

    use super::*;
    use crate::constants::{BGP_VERSION, EXTENDED_MAX_MESSAGE_LEN, MARKER, message_type};
    use crate::{
        Afi, NotificationCode, NotificationMessage, OpenMessage, RouteRefreshMessage, Safi,
        UpdateMessage, encode_message, encode_message_with_limit,
    };

    fn representative_messages() -> Vec<Message> {
        vec![
            Message::Open(OpenMessage {
                version: BGP_VERSION,
                my_as: 64_512,
                hold_time: 90,
                bgp_identifier: Ipv4Addr::new(192, 0, 2, 1),
                capabilities: vec![],
            }),
            Message::Update(UpdateMessage {
                withdrawn_routes: Bytes::new(),
                path_attributes: Bytes::new(),
                nlri: Bytes::new(),
            }),
            Message::Notification(NotificationMessage::new(
                NotificationCode::Cease,
                0,
                Bytes::new(),
            )),
            Message::Keepalive,
            Message::RouteRefresh(RouteRefreshMessage::new(Afi::Ipv4, Safi::Unicast)),
        ]
    }

    fn extended_notification() -> Message {
        Message::Notification(NotificationMessage::new(
            NotificationCode::Cease,
            0,
            Bytes::from(vec![0xab; 5000]),
        ))
    }

    #[test]
    fn defaults_to_standard_directional_limits() {
        let codec = BgpCodec::new();
        assert_eq!(codec.inbound_max_message_len(), MAX_MESSAGE_LEN);
        assert_eq!(codec.outbound_max_message_len(), MAX_MESSAGE_LEN);
        assert_eq!(codec, BgpCodec::default());
    }

    #[test]
    fn partial_header_and_body_do_not_advance() {
        let mut codec = BgpCodec::new();
        let mut partial_header = BytesMut::from(&MARKER[..10]);
        let original_header = partial_header.clone();
        assert!(codec.decode(&mut partial_header).unwrap().is_none());
        assert_eq!(partial_header, original_header);
        assert!(partial_header.capacity() >= HEADER_LEN);

        let encoded = encode_message(&Message::Keepalive).unwrap();
        let mut partial_body = BytesMut::from(&encoded[..encoded.len() - 1]);
        let original_body = partial_body.clone();
        assert!(codec.decode(&mut partial_body).unwrap().is_none());
        assert_eq!(partial_body, original_body);
        assert!(partial_body.capacity() >= encoded.len());
    }

    #[test]
    fn consecutive_frames_advance_exactly_one_at_a_time() {
        let encoded = encode_message(&Message::Keepalive).unwrap();
        let mut src = BytesMut::new();
        src.extend_from_slice(&encoded);
        src.extend_from_slice(&encoded);
        let mut codec = BgpCodec::new();

        assert_eq!(codec.decode(&mut src).unwrap(), Some(Message::Keepalive));
        assert_eq!(src.as_ref(), encoded.as_ref());
        assert_eq!(codec.decode(&mut src).unwrap(), Some(Message::Keepalive));
        assert!(src.is_empty());
    }

    #[test]
    fn malformed_header_does_not_advance() {
        let mut src = BytesMut::from(&[0_u8; HEADER_LEN][..]);
        let original = src.clone();
        let mut codec = BgpCodec::new();

        assert!(matches!(
            codec.decode(&mut src),
            Err(BgpCodecError::Decode(DecodeError::InvalidMarker))
        ));
        assert_eq!(src, original);
    }

    #[test]
    fn malformed_complete_body_preserves_following_frame() {
        let mut src = BytesMut::new();
        src.put_slice(&MARKER);
        src.put_u16(20);
        src.put_u8(message_type::NOTIFICATION);
        src.put_u8(NotificationCode::Cease.as_u8());
        let keepalive = encode_message(&Message::Keepalive).unwrap();
        src.extend_from_slice(&keepalive);
        let mut codec = BgpCodec::new();

        assert!(matches!(
            codec.decode(&mut src),
            Err(BgpCodecError::Decode(DecodeError::MalformedField {
                message_type: "NOTIFICATION",
                ..
            }))
        ));
        assert_eq!(src.as_ref(), keepalive.as_ref());
    }

    #[test]
    fn inbound_and_outbound_extended_limits_are_independent() {
        let message = extended_notification();
        let encoded = encode_message_with_limit(&message, EXTENDED_MAX_MESSAGE_LEN).unwrap();
        let mut src = encoded.clone();
        let mut codec =
            BgpCodec::with_max_message_lengths(EXTENDED_MAX_MESSAGE_LEN, MAX_MESSAGE_LEN);

        assert_eq!(codec.decode(&mut src).unwrap(), Some(message.clone()));
        let mut dst = BytesMut::new();
        assert!(matches!(
            codec.encode(message.clone(), &mut dst),
            Err(BgpCodecError::Encode(EncodeError::MessageTooLong { .. }))
        ));
        assert!(dst.is_empty());

        codec.set_outbound_max_message_len(EXTENDED_MAX_MESSAGE_LEN);
        codec.encode(message, &mut dst).unwrap();
        assert_eq!(dst, encoded);
    }

    #[test]
    fn extended_limit_never_applies_to_open_or_keepalive() {
        let mut src = BytesMut::new();
        src.put_slice(&MARKER);
        src.put_u16(MAX_MESSAGE_LEN + 1);
        src.put_u8(message_type::OPEN);
        src.resize(usize::from(MAX_MESSAGE_LEN) + 1, 0);
        let original = src.clone();
        let mut codec =
            BgpCodec::with_max_message_lengths(EXTENDED_MAX_MESSAGE_LEN, EXTENDED_MAX_MESSAGE_LEN);

        assert!(matches!(
            codec.decode(&mut src),
            Err(BgpCodecError::Decode(DecodeError::InvalidLength {
                length
            })) if length == MAX_MESSAGE_LEN + 1
        ));
        assert_eq!(src, original);
    }

    #[test]
    fn every_message_variant_round_trips_through_traits() {
        let mut codec = BgpCodec::new();
        for message in representative_messages() {
            let mut wire = BytesMut::new();
            codec.encode(message.clone(), &mut wire).unwrap();
            assert_eq!(codec.decode(&mut wire).unwrap(), Some(message));
            assert!(wire.is_empty());
        }
    }

    #[test]
    fn encode_error_leaves_existing_destination_unchanged() {
        let mut codec = BgpCodec::new();
        let mut dst = BytesMut::from(&b"existing"[..]);
        let original = dst.clone();

        assert!(codec.encode(extended_notification(), &mut dst).is_err());
        assert_eq!(dst, original);
    }

    #[test]
    fn partial_eof_uses_tokio_io_error_contract() {
        let mut codec = BgpCodec::new();
        let mut src = BytesMut::from(&MARKER[..10]);

        assert!(matches!(
            codec.decode_eof(&mut src),
            Err(BgpCodecError::Io(_))
        ));
    }

    #[test]
    fn setters_update_only_the_selected_direction() {
        let mut codec = BgpCodec::new();
        codec.set_inbound_max_message_len(EXTENDED_MAX_MESSAGE_LEN);
        assert_eq!(codec.inbound_max_message_len(), EXTENDED_MAX_MESSAGE_LEN);
        assert_eq!(codec.outbound_max_message_len(), MAX_MESSAGE_LEN);

        codec.set_outbound_max_message_len(8192);
        assert_eq!(codec.inbound_max_message_len(), EXTENDED_MAX_MESSAGE_LEN);
        assert_eq!(codec.outbound_max_message_len(), 8192);
    }
}
