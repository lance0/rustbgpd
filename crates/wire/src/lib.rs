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
/// EVPN NLRI types and codec (RFC 7432 + RFC 9136).
pub mod evpn;
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
/// PMSI Tunnel path attribute (RFC 6514 §5) — used by EVPN Type 3 IMET
/// for ingress-replication BUM.
pub mod pmsi;
/// ROUTE-REFRESH message struct and codec (RFC 2918 / RFC 7313).
pub mod route_refresh;
/// UPDATE message struct, codec, and builder.
pub mod update;
/// UPDATE attribute semantic validation (RFC 4271 §6.3).
pub mod validate;

// Re-export primary public API
pub use capability::{
    AddPathFamily, AddPathMode, Afi, BgpRole, Capability, ExtendedNextHopFamily,
    GracefulRestartFamily, LlgrFamily, Safi,
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

// ── Routing-domain result enums ──────────────────────────────────────
//
// `RpkiValidation` and `AspaValidation` are routing-domain concepts, not
// wire-format types. They live here because the wire crate is the current
// lowest common dependency shared by rib, policy, and transport — avoiding
// a rib → rpki dependency edge. If more shared non-wire types accumulate,
// extract them into a dedicated domain-types crate.

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
pub use pmsi::{PmsiTunnel, PmsiTunnelIdentifier, PmsiTunnelType};
pub use update::ParsedUpdate;
pub use validate::{UpdateError, UpdateValidationOptions, is_valid_ipv6_nexthop};

// Re-export FlowSpec types
pub use flowspec::{
    BitmaskMatch, FlowSpecAction, FlowSpecComponent, FlowSpecPrefix, FlowSpecRule,
    Ipv6PrefixOffset, NumericMatch,
};

// Re-export EVPN types
pub use evpn::{
    EthernetSegmentIdentifier, EthernetTagId, EvpnEadPerEs, EvpnEadPerEvi, EvpnEs, EvpnImet,
    EvpnIpPrefixRoute, EvpnIpPrefixValue, EvpnMacIp, EvpnRoute, EvpnRouteKey, MacAddress,
    MplsLabel, RouteDistinguisher, RouteDistinguisherParseError, decode_evpn_nlri,
    encode_evpn_nlri,
};

// Well-known communities (RFC 1997 + RFC 7999 + RFC 8326 + RFC 9494)
/// `NO_EXPORT` community (RFC 1997): routes carrying this community must not
/// be advertised outside a BGP confederation boundary.
pub const COMMUNITY_NO_EXPORT: u32 = 0xFFFF_FF01;
/// `NO_ADVERTISE` community (RFC 1997): routes carrying this community must
/// not be advertised to any other BGP peer.
pub const COMMUNITY_NO_ADVERTISE: u32 = 0xFFFF_FF02;
/// `NO_EXPORT_SUBCONFED` community (RFC 1997): routes carrying this community
/// must not be advertised to external BGP peers, including confederation
/// external peers.
pub const COMMUNITY_NO_EXPORT_SUBCONFED: u32 = 0xFFFF_FF03;
/// `BLACKHOLE` community (RFC 7999 §5): advisory signal that traffic destined
/// toward the tagged prefix should be discarded by receivers that explicitly
/// opted in to honoring the request.
pub const COMMUNITY_BLACKHOLE: u32 = 0xFFFF_029A;
/// `GRACEFUL_SHUTDOWN` community (RFC 8326 §3): tags routes on a session
/// being brought down for maintenance so receivers de-prefer them by
/// setting `LOCAL_PREF` to a low value (canonical: 0).
pub const COMMUNITY_GRACEFUL_SHUTDOWN: u32 = 0xFFFF_0000;
/// `LLGR_STALE` community (RFC 9494 §4.6): marks a route as long-lived stale.
pub const COMMUNITY_LLGR_STALE: u32 = 0xFFFF_0006;
/// `NO_LLGR` community (RFC 9494 §4.7): this route must not enter LLGR stale phase.
pub const COMMUNITY_NO_LLGR: u32 = 0xFFFF_0007;

// Re-export RPKI types
// (RpkiValidation is defined above in this file)

#[cfg(test)]
mod well_known_community_tests {
    use super::*;

    /// Pins the spec-mandated well-known community values. A refactor that
    /// accidentally renames or repurposes these constants is silently
    /// behavior-preserving at the type level — this test makes the value
    /// drift loud.
    #[test]
    fn well_known_community_values_match_specs() {
        assert_eq!(COMMUNITY_NO_EXPORT, 0xFFFF_FF01, "RFC 1997");
        assert_eq!(COMMUNITY_NO_ADVERTISE, 0xFFFF_FF02, "RFC 1997");
        assert_eq!(COMMUNITY_NO_EXPORT_SUBCONFED, 0xFFFF_FF03, "RFC 1997");
        assert_eq!(COMMUNITY_BLACKHOLE, 0xFFFF_029A, "RFC 7999 §5");
        assert_eq!(COMMUNITY_GRACEFUL_SHUTDOWN, 0xFFFF_0000, "RFC 8326 §3");
        assert_eq!(COMMUNITY_LLGR_STALE, 0xFFFF_0006, "RFC 9494 §4.6");
        assert_eq!(COMMUNITY_NO_LLGR, 0xFFFF_0007, "RFC 9494 §4.7");
    }
}
