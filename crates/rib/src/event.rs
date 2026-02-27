use std::net::IpAddr;

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
}
