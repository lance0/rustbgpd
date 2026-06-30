//! Output actions and negotiated session parameters produced by the FSM.

use std::collections::HashMap;

use rustbgpd_wire::{
    AddPathMode, Afi, BgpRole, Capability, GracefulRestartFamily, LlgrFamily, NotificationMessage,
    OpenMessage, Safi,
};

use crate::state::SessionState;

/// Which timer to start or stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimerType {
    /// TCP connect-retry timer (exponential backoff).
    ConnectRetry,
    /// Hold timer — peer must send KEEPALIVE/UPDATE before expiry.
    Hold,
    /// Keepalive timer — send KEEPALIVE at this interval.
    Keepalive,
}

/// Result of a successful OPEN exchange — the negotiated session parameters.
///
/// `#[non_exhaustive]`: new negotiated capabilities add fields here, so
/// external crates build it from [`NegotiatedSession::default`] and assign
/// the `pub` fields they need rather than using a struct literal.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[expect(
    clippy::struct_excessive_bools,
    reason = "negotiated OPEN state is clearer as explicit capability flags"
)]
pub struct NegotiatedSession {
    /// Peer's 4-byte ASN (from capability, or 2-byte fallback).
    pub peer_asn: u32,
    /// Peer's BGP Identifier (router ID).
    pub peer_router_id: std::net::Ipv4Addr,
    /// Negotiated hold time in seconds.
    pub hold_time: u16,
    /// Keepalive interval = `hold_time` / 3 (0 if `hold_time` is 0).
    pub keepalive_interval: u16,
    /// Capabilities the peer advertised.
    pub peer_capabilities: Vec<Capability>,
    /// Locally configured BGP Role advertised for this eBGP session.
    pub local_role: Option<BgpRole>,
    /// Peer-advertised BGP Role, if present and valid.
    pub remote_role: Option<BgpRole>,
    /// True when both sides advertised compatible BGP Roles.
    pub role_negotiated: bool,
    /// Whether both sides support 4-octet AS numbers.
    pub four_octet_as: bool,
    /// Address families negotiated between both sides.
    pub negotiated_families: Vec<(Afi, Safi)>,
    /// Whether the peer advertised Graceful Restart capability.
    pub peer_gr_capable: bool,
    /// Whether the peer set the R-bit (currently in restart state).
    pub peer_restart_state: bool,
    /// Peer's advertised restart time (seconds).
    pub peer_restart_time: u16,
    /// Per-family forwarding state from the peer's GR capability.
    pub peer_gr_families: Vec<GracefulRestartFamily>,
    /// Whether the peer advertised Route Refresh capability (RFC 2918).
    pub peer_route_refresh: bool,
    /// Whether the peer advertised Enhanced Route Refresh (RFC 7313).
    pub peer_enhanced_route_refresh: bool,
    /// Whether both sides support Extended Messages (RFC 8654).
    pub peer_extended_message: bool,
    /// Per-AFI/SAFI negotiated Extended Next Hop encoding (RFC 8950).
    ///
    /// The key is the NLRI family, and the value is the negotiated next-hop
    /// AFI for that family. For this implementation the meaningful negotiated
    /// mapping is IPv4 unicast -> IPv6.
    pub extended_nexthop_families: HashMap<(Afi, Safi), Afi>,
    /// Whether both sides support Notification GR (RFC 8538 N-bit).
    pub peer_notification_gr: bool,
    /// Whether the peer advertised Long-Lived Graceful Restart (RFC 9494).
    pub peer_llgr_capable: bool,
    /// Per-family LLGR stale times from the peer's capability.
    pub peer_llgr_families: Vec<LlgrFamily>,
    /// Per-AFI/SAFI Add-Path negotiated mode (RFC 7911).
    ///
    /// Only families where both sides agree are included. The mode
    /// indicates what *we* can do: `Receive` means we accept Add-Path
    /// from the peer, `Send` means we can send Add-Path, `Both` means both.
    pub add_path_families: HashMap<(Afi, Safi), AddPathMode>,
    /// Families for which we negotiated receiving Address-Prefix ORF entries
    /// from the peer (RFC 5291/5292): we advertised Receive and the peer
    /// advertised Send. Outbound advertisement for these families is gated
    /// until the peer sends a Route Refresh (RFC 5291 §6).
    pub negotiated_orf_recv: Vec<(Afi, Safi)>,
}

impl Default for NegotiatedSession {
    /// A zeroed/empty negotiation: no peer ASN, an unspecified router ID,
    /// no hold time, no advertised capabilities, and every optional feature
    /// flag clear. `Ipv4Addr` and the per-feature collections have no derived
    /// `Default` shape we want, so this is written by hand.
    fn default() -> Self {
        Self {
            peer_asn: 0,
            peer_router_id: std::net::Ipv4Addr::UNSPECIFIED,
            hold_time: 0,
            keepalive_interval: 0,
            peer_capabilities: Vec::new(),
            local_role: None,
            remote_role: None,
            role_negotiated: false,
            four_octet_as: false,
            negotiated_families: Vec::new(),
            peer_gr_capable: false,
            peer_restart_state: false,
            peer_restart_time: 0,
            peer_gr_families: Vec::new(),
            peer_route_refresh: false,
            peer_enhanced_route_refresh: false,
            peer_extended_message: false,
            extended_nexthop_families: HashMap::new(),
            peer_notification_gr: false,
            peer_llgr_capable: false,
            peer_llgr_families: Vec::new(),
            add_path_families: HashMap::new(),
            negotiated_orf_recv: Vec::new(),
        }
    }
}

/// Output actions produced by the FSM on each transition.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Action {
    /// Send an OPEN message to the peer.
    SendOpen(OpenMessage),
    /// Send a KEEPALIVE message to the peer.
    SendKeepalive,
    /// Send a NOTIFICATION message to the peer, then close.
    SendNotification(NotificationMessage),
    /// Start (or restart) a timer with the given duration in seconds.
    StartTimer(TimerType, u32),
    /// Cancel a running timer.
    StopTimer(TimerType),
    /// Initiate an outbound TCP connection to the peer.
    InitiateTcpConnection,
    /// Tear down the TCP connection.
    CloseTcpConnection,
    /// The FSM transitioned to a new state (for telemetry).
    StateChanged {
        /// Previous FSM state.
        old: SessionState,
        /// New FSM state.
        new: SessionState,
    },
    /// The session is fully established — negotiated parameters enclosed.
    /// Boxed: `NegotiatedSession` is by far the largest `Action` variant, so
    /// inlining it would bloat every `Action` (clippy `large_enum_variant`).
    SessionEstablished(Box<NegotiatedSession>),
    /// The session left the Established state.
    SessionDown,
    /// A timer-expired event arrived for a timer that should not be
    /// running in the current state. The FSM ignores it instead of
    /// tearing the session down (RFC 4271 §8.1 leaves stale-timer
    /// behavior implementation-defined; tearing down a healthy session
    /// because of a daemon-side timer-management bug is operationally
    /// hostile). Daemon-side telemetry hooks this for visibility.
    StaleTimerIgnored {
        /// FSM state when the stale timer arrived.
        state: SessionState,
        /// Which timer the daemon delivered.
        timer: TimerType,
    },
    /// RFC 9234 Role-Mismatch observed at OPEN time — emitted alongside
    /// `SendNotification(OpenMessage / ROLE_MISMATCH)` so transport can
    /// label `bgp_role_mismatch_total{peer, local_role, remote_role}`
    /// with the configured local role and (where available) the peer's
    /// advertised role. The notification + close + transition to Idle are
    /// still driven by the surrounding `SendNotification`,
    /// `CloseTcpConnection`, and `StateChanged` actions; this variant is
    /// strictly observability.
    RoleMismatchObserved {
        /// Locally configured role (`None` if we didn't advertise Role).
        local_role: Option<BgpRole>,
        /// Peer's advertised role (`None` if absent; for duplicate-Role
        /// OPENs the FIRST received Role value is reported).
        remote_role: Option<BgpRole>,
    },
}
