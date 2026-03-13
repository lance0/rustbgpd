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
//! - [`peek_message_length`] — check if a
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

/// Path attribute types and codec (`ORIGIN`, `AS_PATH`, `NEXT_HOP`, etc.).
pub mod attribute;
/// BGP capability negotiation types and codec (RFC 5492).
pub mod capability;
/// Wire-format constants: markers, lengths, type codes.
pub mod constants;
/// Decode and encode error types.
pub mod error;
/// FlowSpec NLRI types and codec (RFC 8955 / RFC 8956).
pub mod flowspec;
/// BGP message header codec (RFC 4271 §4.1).
pub mod header;
/// KEEPALIVE message encoding and validation.
pub mod keepalive;
/// Top-level BGP message enum and codec dispatch.
pub mod message;
/// NLRI prefix types and codec (IPv4, IPv6, Add-Path).
pub mod nlri;
/// NOTIFICATION error codes, subcodes, and shutdown communication.
pub mod notification;
/// NOTIFICATION message struct and codec.
pub mod notification_msg;
/// OPEN message struct and codec.
pub mod open;
/// ROUTE-REFRESH message struct and codec (RFC 2918 / RFC 7313).
pub mod route_refresh;
/// UPDATE message struct, codec, and builder.
pub mod update;
/// UPDATE attribute semantic validation (RFC 4271 §6.3).
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

/// ASPA path verification state per draft-ietf-sidrops-aspa-verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum AspaValidation {
    /// All hops in the `AS_PATH` have authorized provider relationships.
    Valid,
    /// At least one hop has a proven unauthorized provider relationship.
    Invalid,
    /// Verification could not complete due to missing ASPA records.
    #[default]
    Unknown,
}

impl std::fmt::Display for AspaValidation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Valid => write!(f, "valid"),
            Self::Invalid => write!(f, "invalid"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl std::str::FromStr for AspaValidation {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "valid" => Ok(Self::Valid),
            "invalid" => Ok(Self::Invalid),
            "unknown" => Ok(Self::Unknown),
            other => Err(format!(
                "unknown ASPA validation state {other:?}, expected \"valid\", \"invalid\", or \"unknown\""
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
