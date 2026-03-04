use std::collections::HashMap;

use rustbgpd_wire::{
    AddPathMode, Afi, Capability, GracefulRestartFamily, NotificationMessage, OpenMessage, Safi,
};

use crate::state::SessionState;

/// Which timer to start or stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimerType {
    ConnectRetry,
    Hold,
    Keepalive,
}

/// Result of a successful OPEN exchange — the negotiated session parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
#[expect(clippy::struct_excessive_bools)]
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
    /// Whether both sides support Extended Messages (RFC 8654).
    pub peer_extended_message: bool,
    /// Per-AFI/SAFI negotiated Extended Next Hop encoding (RFC 8950).
    ///
    /// The key is the NLRI family, and the value is the negotiated next-hop
    /// AFI for that family. For this implementation the meaningful negotiated
    /// mapping is IPv4 unicast -> IPv6.
    pub extended_nexthop_families: HashMap<(Afi, Safi), Afi>,
    /// Per-AFI/SAFI Add-Path negotiated mode (RFC 7911).
    ///
    /// Only families where both sides agree are included. The mode
    /// indicates what *we* can do: `Receive` means we accept Add-Path
    /// from the peer, `Send` means we can send Add-Path, `Both` means both.
    pub add_path_families: HashMap<(Afi, Safi), AddPathMode>,
}

/// Output actions produced by the FSM on each transition.
#[derive(Debug, Clone, PartialEq, Eq)]
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
        old: SessionState,
        new: SessionState,
    },
    /// The session is fully established — negotiated parameters enclosed.
    SessionEstablished(NegotiatedSession),
    /// The session left the Established state.
    SessionDown,
}
