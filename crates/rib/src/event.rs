use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use rustbgpd_wire::Ipv4Prefix;

/// Type of route change event emitted by the RIB manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteEventType {
    Added,
    Withdrawn,
    BestChanged,
}

/// A route change event published via broadcast channel.
#[derive(Debug, Clone)]
pub struct RouteEvent {
    pub event_type: RouteEventType,
    pub prefix: Ipv4Prefix,
    pub peer: Option<IpAddr>,
    pub previous_peer: Option<IpAddr>,
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
