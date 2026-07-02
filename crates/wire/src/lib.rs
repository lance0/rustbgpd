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
/// BGP-LS NLRI codec substrate (RFC 9552).
pub mod bgpls;
/// Typed BGP-LS topology accessors over the opaque codec (RFC 9552).
pub mod bgpls_topo;
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
/// IPv4/IPv6 labeled-unicast NLRI codec substrate (RFC 8277, SAFI 4).
pub mod labeled;
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
/// Outbound Route Filtering (ORF) types and codec (RFC 5291 + RFC 5292).
pub mod orf;
/// PMSI Tunnel path attribute (RFC 6514 §5) — used by EVPN Type 3 IMET
/// for ingress-replication BUM.
pub mod pmsi;
/// ROUTE-REFRESH message struct and codec (RFC 2918 / RFC 7313).
pub mod route_refresh;
/// RT-Constrain NLRI codec substrate (RFC 4684).
pub mod rtc;
/// UPDATE message struct, codec, and builder.
pub mod update;
/// UPDATE attribute semantic validation (RFC 4271 §6.3).
pub mod validate;
/// VPNv4/VPNv6 labeled NLRI codec substrate (RFC 4364 / RFC 4659 / RFC 8277).
pub mod vpn;

// Re-export primary public API
pub use capability::{
    AddPathFamily, AddPathMode, Afi, BgpRole, Capability, ExtendedNextHopFamily,
    GracefulRestartFamily, LlgrFamily, Safi,
};
pub use constants::{EXTENDED_MAX_MESSAGE_LEN, MAX_MESSAGE_LEN};
pub use error::{DecodeError, EncodeError};
pub use header::{BgpHeader, MessageType, peek_message_length};
pub use labeled::{
    LabeledAddressFamily, LabeledNlri, LabeledNlriEntry, decode_labeled_nlri,
    decode_labeled_nlri_addpath, decode_labeled_withdraw_nlri,
    decode_labeled_withdraw_nlri_addpath, encode_labeled_nlri, encode_labeled_nlri_addpath,
    encode_labeled_withdraw_nlri, encode_labeled_withdraw_nlri_addpath,
};
pub use message::{Message, decode_message, encode_message, encode_message_with_limit};
pub use notification::NotificationCode;
pub use notification_msg::NotificationMessage;
pub use open::OpenMessage;
pub use route_refresh::{RouteRefreshMessage, RouteRefreshSubtype};
pub use rtc::{
    RTC_MAX_PREFIX_BITS, RTC_MIN_NON_DEFAULT_PREFIX_BITS, RTC_SAFI, RtcNlri, decode_rtc_nlri,
    encode_rtc_nlri,
};
pub use update::{Ipv4UnicastMode, UpdateMessage};
pub use vpn::{
    LABELED_UNICAST_SAFI, MPLS_VPN_SAFI, MplsLabelEntry, VPNV4_AFI, VPNV6_AFI, VpnAddressFamily,
    VpnNlri, VpnNlriEntry, VpnPrefix, VpnRouteKey, decode_vpn_nlri, decode_vpn_nlri_addpath,
    decode_vpn_withdraw_nlri, decode_vpn_withdraw_nlri_addpath, decode_vpnv4_nlri,
    decode_vpnv6_nlri, encode_vpn_nlri, encode_vpn_nlri_addpath, encode_vpn_withdraw_nlri,
    encode_vpn_withdraw_nlri_addpath, encode_vpnv4_nlri, encode_vpnv6_nlri,
};

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

/// Session context needed to choose and replay ASPA path verification.
///
/// ASPA verification is role-aware in
/// `draft-ietf-sidrops-aspa-verification-25`: routes received from a
/// provider use downstream verification, while customer/peer/route-server
/// shapes use upstream verification. Stored routes keep this compact context
/// so RTR cache updates can revalidate them with the same relationship
/// semantics used at import time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct AspaValidationContext {
    /// Neighbor ASN used for the draft v25 leftmost-AS precondition.
    pub neighbor_asn: Option<u32>,
    /// Locally configured BGP Role for this eBGP session.
    pub local_role: Option<BgpRole>,
    /// True when the local speaker is an RS-client receiving through a
    /// transparent route server / IX, where the draft exempts the leftmost-AS
    /// precondition.
    pub first_as_check_exempt: bool,
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
pub use bgpls::{
    BGP_LS_AFI, BGP_LS_ROUTE_DISTINGUISHER_LEN, BGP_LS_SAFI, BGP_LS_VPN_SAFI, BgpLsNlri,
    BgpLsNlriKey, BgpLsNlriType, BgpLsTlv, decode_bgpls_nlri, decode_bgpls_tlvs,
    decode_bgpls_vpn_nlri, encode_bgpls_nlri, encode_bgpls_tlvs,
};
pub use bgpls_topo::{
    BGP_LS_TLV_AUTONOMOUS_SYSTEM, BGP_LS_TLV_BGP_LS_IDENTIFIER, BGP_LS_TLV_IGP_METRIC,
    BGP_LS_TLV_IGP_ROUTER_ID, BGP_LS_TLV_IP_REACHABILITY, BGP_LS_TLV_IPV4_INTERFACE_ADDRESS,
    BGP_LS_TLV_IPV4_NEIGHBOR_ADDRESS, BGP_LS_TLV_IPV6_INTERFACE_ADDRESS,
    BGP_LS_TLV_IPV6_NEIGHBOR_ADDRESS, BGP_LS_TLV_LINK_LOCAL_REMOTE_IDENTIFIERS,
    BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS, BGP_LS_TLV_MULTI_TOPOLOGY_ID, BGP_LS_TLV_OSPF_AREA_ID,
    BGP_LS_TLV_OSPF_ROUTE_TYPE, BGP_LS_TLV_PREFIX_METRIC, BGP_LS_TLV_REMOTE_NODE_DESCRIPTORS,
    BGP_LS_TLV_TE_DEFAULT_METRIC, BgpLsNodeKey, bgp_ls_attribute_tlvs, igp_metric, prefix_metric,
    te_default_metric,
};
pub use nlri::{Ipv4NlriEntry, Ipv4Prefix, Ipv6Prefix, NlriEntry, Prefix};
pub use orf::{
    AddressPrefixOrf, OrfAction, OrfCapEntry, OrfCapType, OrfEntries, OrfEntryGroup, OrfMatch,
    OrfPayload, OrfSendReceive, OrfType, WhenToRefresh,
};
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
