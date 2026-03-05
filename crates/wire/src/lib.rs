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
pub mod flowspec;
pub mod header;
pub mod keepalive;
pub mod message;
pub mod nlri;
pub mod notification;
pub mod notification_msg;
pub mod open;
pub mod route_refresh;
pub mod update;
pub mod validate;

// Re-export primary public API
pub use capability::{
    AddPathFamily, AddPathMode, Afi, Capability, ExtendedNextHopFamily, GracefulRestartFamily,
    LlgrFamily, Safi,
};
pub use constants::{EXTENDED_MAX_MESSAGE_LEN, MAX_MESSAGE_LEN};
pub use error::{DecodeError, EncodeError};
pub use header::{BgpHeader, MessageType, peek_message_length};
pub use message::{Message, decode_message, encode_message, encode_message_with_limit};
pub use notification::NotificationCode;
pub use notification_msg::NotificationMessage;
pub use open::OpenMessage;
pub use route_refresh::{RouteRefreshMessage, RouteRefreshSubtype};
pub use update::{Ipv4UnicastMode, UpdateMessage};

/// RPKI origin validation state per RFC 6811.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum RpkiValidation {
    /// A VRP covers the prefix and the origin AS matches.
    Valid,
    /// A VRP covers the prefix but the origin AS does not match.
    Invalid,
    /// No VRP covers the prefix.
    #[default]
    NotFound,
}

impl std::fmt::Display for RpkiValidation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Valid => write!(f, "valid"),
            Self::Invalid => write!(f, "invalid"),
            Self::NotFound => write!(f, "not_found"),
        }
    }
}

impl std::str::FromStr for RpkiValidation {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "valid" => Ok(Self::Valid),
            "invalid" => Ok(Self::Invalid),
            "not_found" => Ok(Self::NotFound),
            other => Err(format!(
                "unknown RPKI validation state {other:?}, expected \"valid\", \"invalid\", or \"not_found\""
            )),
        }
    }
}

// Re-export attribute types
pub use attribute::{
    AsPath, AsPathSegment, ExtendedCommunity, LargeCommunity, MpReachNlri, MpUnreachNlri, Origin,
    PathAttribute, RawAttribute, is_private_asn,
};
pub use nlri::{Ipv4NlriEntry, Ipv4Prefix, Ipv6Prefix, NlriEntry, Prefix};
pub use update::ParsedUpdate;
pub use validate::{UpdateError, is_valid_ipv6_nexthop};

// Re-export FlowSpec types
pub use flowspec::{
    BitmaskMatch, FlowSpecAction, FlowSpecComponent, FlowSpecPrefix, FlowSpecRule,
    Ipv6PrefixOffset, NumericMatch,
};

// Well-known communities (RFC 1997 + RFC 9494)
/// `LLGR_STALE` community (RFC 9494 §4.6): marks a route as long-lived stale.
pub const COMMUNITY_LLGR_STALE: u32 = 0xFFFF_0006;
/// `NO_LLGR` community (RFC 9494 §4.7): this route must not enter LLGR stale phase.
pub const COMMUNITY_NO_LLGR: u32 = 0xFFFF_0007;

// Re-export RPKI types
// (RpkiValidation is defined above in this file)
