//! rustbgpd-wire — BGP message codec
//!
//! Pure codec library for BGP message encoding and decoding.
//! Zero internal dependencies. This crate is independently publishable.
//!
//! # Message Types
//!
//! - [`OpenMessage`] — BGP OPEN with capability negotiation
//! - [`NotificationMessage`] — BGP NOTIFICATION with error codes
//! - [`UpdateMessage`] — BGP UPDATE (wire-level framing, raw bytes in M0)
//! - `Keepalive` — represented as [`Message::Keepalive`] unit variant
//!
//! # Entry Points
//!
//! - [`decode_message`] — decode a complete BGP message from bytes
//! - [`encode_message`] — encode a BGP message to bytes
//! - [`peek_message_length`](header::peek_message_length) — check if a
//!   complete message is available (for transport framing)
//!
//! # Invariants
//!
//! - Maximum message size: 4096 bytes (RFC 4271 §4.1)
//! - No panics on malformed input — all paths return `Result`
//! - No `unsafe` code

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

pub mod attribute;
pub mod capability;
pub mod constants;
pub mod error;
pub mod header;
pub mod keepalive;
pub mod message;
pub mod nlri;
pub mod notification;
pub mod notification_msg;
pub mod open;
pub mod update;
pub mod validate;

// Re-export primary public API
pub use capability::{Afi, Capability, Safi};
pub use error::{DecodeError, EncodeError};
pub use header::{BgpHeader, MessageType, peek_message_length};
pub use message::{Message, decode_message, encode_message};
pub use notification::NotificationCode;
pub use notification_msg::NotificationMessage;
pub use open::OpenMessage;
pub use update::UpdateMessage;

// Re-export attribute types
pub use attribute::{AsPath, AsPathSegment, Origin, PathAttribute, RawAttribute};
pub use nlri::Ipv4Prefix;
pub use update::ParsedUpdate;
pub use validate::UpdateError;
