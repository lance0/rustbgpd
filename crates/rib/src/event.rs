use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use rustbgpd_wire::Prefix;

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

/// Returns the current Unix epoch time as a string.
#[must_use]
pub fn unix_timestamp_now() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string()
}
