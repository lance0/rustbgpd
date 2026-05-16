use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use rustbgpd_wire::{EvpnRouteKey, Prefix};

use crate::route::EvpnRibRoute;

/// Type of route change event emitted by the RIB manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteEventType {
    /// A new best route was installed.
    Added,
    /// The best route was withdrawn with no replacement.
    Withdrawn,
    /// The best route changed to a different path.
    BestChanged,
}

/// A route change event published via broadcast channel.
#[derive(Debug, Clone)]
pub struct RouteEvent {
    /// Monotonic process-local route event identifier.
    pub event_id: u64,
    /// The kind of route change.
    pub event_type: RouteEventType,
    /// The affected prefix.
    pub prefix: Prefix,
    /// The peer advertising the current best route, if any.
    pub peer: Option<IpAddr>,
    /// The peer that previously held the best route, if any.
    pub previous_peer: Option<IpAddr>,
    /// Unix epoch timestamp as a string.
    pub timestamp: String,
    /// Add-Path path identifier (RFC 7911). 0 = no Add-Path.
    pub path_id: u32,
}

/// EVPN best-path change event published on the EVPN broadcast.
///
/// Distinct from [`RouteEvent`] because EVPN routes are keyed by
/// [`EvpnRouteKey`] (not [`Prefix`]) and consumers — most notably the
/// daemon's local-MAC originator — need the full new best to build a
/// `RemoteMacView` without a follow-up RIB query. Carrying the full
/// [`EvpnRibRoute`] on the event side keeps the consumer's hot path
/// allocation-free: path attributes are already `Arc`-shared, so the
/// per-subscriber broadcast clone copies a `~120` B struct plus a
/// pointer increment.
///
/// Both `best` and `previous_best` are carried so consumers can derive
/// per-VNI context (the RFC 8365 §5 raw-24-bit VNI lives in
/// `EvpnMacIp.label1`, not in the route key) on **every** event,
/// including `Withdrawn`. Mapping the key's RD back to a configured
/// instance is unreliable: remote PEs advertise Type 2 routes under
/// **their** RD per RFC 7432 §7.9.5, not the local importer's, so an
/// RD-keyed scan over `EvpnInstanceTable` will usually miss for
/// withdrawn remote routes.
#[derive(Debug, Clone)]
pub struct EvpnRouteEvent {
    /// The kind of route change.
    pub event_type: RouteEventType,
    /// The affected EVPN route key.
    pub key: EvpnRouteKey,
    /// Current best path. `Some` for `Added` / `BestChanged`; `None`
    /// for `Withdrawn`. Originator builds `RemoteMacView` directly
    /// from this — no follow-up RIB query needed.
    pub best: Option<EvpnRibRoute>,
    /// Best path immediately before this change. `Some` for
    /// `Withdrawn` / `BestChanged`; `None` for `Added`. Carrying it
    /// lets consumers recover per-VNI context (`EvpnMacIp.label1`)
    /// for `Withdrawn` events without an unreliable RD-to-instance
    /// scan, and lets BMP-style observers report the prior next-hop
    /// without a back-channel query.
    pub previous_best: Option<EvpnRibRoute>,
    /// Peer that holds the new best (`None` for `Withdrawn`).
    pub peer: Option<IpAddr>,
    /// Peer that previously held best (`None` for `Added`).
    pub previous_peer: Option<IpAddr>,
    /// Unix epoch timestamp as a string.
    pub timestamp: String,
}

/// Returns the current Unix epoch time as a string.
#[must_use]
pub fn unix_timestamp_now() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string()
}
