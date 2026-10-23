//! Route change events published by the RIB manager. A [`RouteEvent`]
//! identifies the changed prefix and the peers involved but carries no route;
//! an [`EvpnRouteEvent`] carries the full new and previous best route.
//!
//! Events name peers by the address each had when the event was built, not
//! by [`PeerId`](crate::PeerId): a handle can move to a new endpoint or, once
//! released, to nothing, and history must keep the endpoint it recorded.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rustbgpd_wire::{EvpnRouteKey, Prefix};

use crate::route::{AspaContextId, EvpnRibRoute};

/// Type of route change event emitted by the RIB manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RouteEventType {
    /// A new best route was installed.
    Added,
    /// The best route was withdrawn with no replacement.
    Withdrawn,
    /// The best route changed to a different path.
    BestChanged,
    /// A route was present but denied by export policy for a target peer.
    PolicyFiltered,
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
    /// Address of the peer advertising the current best route, if any,
    /// when the event was built.
    pub peer: Option<IpAddr>,
    /// Address of the peer that previously held the best route, if any.
    pub previous_peer: Option<IpAddr>,
    /// Address of the outbound peer whose export policy filtered the route,
    /// if any.
    pub target_peer: Option<IpAddr>,
    /// Interned source context of `peer`, which records its interface when
    /// it is a scoped (IPv6 link-local) neighbor. Captured when the event
    /// is built, so history keeps the interface the route was learned on
    /// after the neighbor changes or is deleted. Two bytes: the event keeps
    /// its pre-scope size. Read it with [`Self::peer_interface`].
    pub peer_scope: AspaContextId,
    /// Interned source context of `previous_peer`, like `peer_scope`.
    pub previous_peer_scope: AspaContextId,
    /// Interned source context of `target_peer`, like `peer_scope`.
    pub target_peer_scope: AspaContextId,
    /// Event time in Unix epoch milliseconds, captured when the event is
    /// built (see [`unix_time_ms_now`]).
    pub timestamp_unix_ms: i64,
    /// Add-Path path identifier (RFC 7911). 0 = no Add-Path.
    pub path_id: u32,
    /// Stable operator-facing reason, e.g. "`policy_denied`".
    pub reason: String,
}

impl RouteEvent {
    /// Interface `peer` had when the event was recorded; `None` for a
    /// numbered or absent peer.
    #[must_use]
    pub fn peer_interface(&self) -> Option<Arc<str>> {
        self.peer_scope.peer_interface()
    }

    /// Interface `previous_peer` had when the event was recorded.
    #[must_use]
    pub fn previous_peer_interface(&self) -> Option<Arc<str>> {
        self.previous_peer_scope.peer_interface()
    }

    /// Interface `target_peer` had when the event was recorded.
    #[must_use]
    pub fn target_peer_interface(&self) -> Option<Arc<str>> {
        self.target_peer_scope.peer_interface()
    }

    /// Whether this event names the neighbor (`address`, `interface`) as
    /// its current, previous or target peer. A scoped neighbor matches only
    /// on the interface the event recorded; a numbered one has none. By
    /// address, so history keeps matching a neighbor deleted or re-added
    /// since the event.
    #[must_use]
    pub fn involves(&self, address: IpAddr, interface: Option<&str>) -> bool {
        let named = |peer: Option<IpAddr>, scope: AspaContextId| {
            peer == Some(address) && scope.peer_interface().as_deref() == interface
        };
        named(self.peer, self.peer_scope)
            || named(self.previous_peer, self.previous_peer_scope)
            || named(self.target_peer, self.target_peer_scope)
    }
}

/// EVPN best-path change event published on the EVPN broadcast.
///
/// Distinct from [`RouteEvent`] because EVPN routes are keyed by
/// [`EvpnRouteKey`] (not [`Prefix`]) and consumers — most notably the
/// daemon's local-MAC originator — need the full new best to build a
/// `RemoteMacView` without a follow-up RIB query. Carrying the full
/// [`EvpnRibRoute`] on the event side keeps the consumer's hot path
/// allocation-free: the 400 B event is allocated once, then the
/// history and live broadcast share that allocation through `Arc`.
/// Each subscriber clone copies one `Arc`; nested path attributes
/// remain shared, and the hot path still avoids a follow-up query.
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
    /// Address of the peer that holds the new best when the event was
    /// built (`None` for `Withdrawn`). Render `best` with this address, not
    /// by resolving its handle.
    pub peer: Option<IpAddr>,
    /// Address of the peer that previously held best (`None` for `Added`);
    /// `previous_best`'s address, like `peer`.
    pub previous_peer: Option<IpAddr>,
    /// Event time in Unix epoch milliseconds, captured when the event is
    /// built (see [`unix_time_ms_now`]).
    pub timestamp_unix_ms: i64,
}

/// Return the RD embedded in an EVPN route key.
///
/// `None` for a route type this build does not model (`EvpnRouteKey` is
/// non-exhaustive); callers must treat such keys as filter non-matches
/// and render an absent RD.
#[must_use]
pub const fn evpn_key_rd(key: &EvpnRouteKey) -> Option<rustbgpd_wire::RouteDistinguisher> {
    match key {
        EvpnRouteKey::EadPerEs { rd, .. }
        | EvpnRouteKey::EadPerEvi { rd, .. }
        | EvpnRouteKey::MacIp { rd, .. }
        | EvpnRouteKey::Imet { rd, .. }
        | EvpnRouteKey::Es { rd, .. }
        | EvpnRouteKey::IpPrefix { rd, .. }
        | EvpnRouteKey::Smet { rd, .. } => Some(*rd),
        _ => None,
    }
}

/// Returns the current wall-clock time in Unix epoch milliseconds, for
/// stamping an event where it originates.
#[must_use]
pub fn unix_time_ms_now() -> i64 {
    unix_time_ms(SystemTime::now())
}

/// Converts a wall-clock time to Unix epoch milliseconds. Times before the
/// epoch map to 0; times past the `i64` range saturate.
#[must_use]
pub fn unix_time_ms(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |elapsed| {
        i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
    })
}

/// Renders an event time for the deprecated decimal-string `timestamp`
/// fields: whole Unix epoch seconds, truncated.
#[must_use]
pub fn unix_seconds_string(timestamp_unix_ms: i64) -> String {
    timestamp_unix_ms.div_euclid(1000).to_string()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn events_in_one_second_get_distinct_ordered_ms_and_the_same_seconds_string() {
        let second = UNIX_EPOCH + Duration::from_secs(1_783_915_201);
        let first = unix_time_ms(second + Duration::from_millis(120));
        let next = unix_time_ms(second + Duration::from_millis(870));
        assert_eq!(first, 1_783_915_201_120);
        assert_eq!(next, 1_783_915_201_870);
        assert!(first < next);
        // The deprecated string keeps whole, truncated seconds.
        assert_eq!(unix_seconds_string(first), "1783915201");
        assert_eq!(unix_seconds_string(next), "1783915201");
        assert_eq!(unix_seconds_string(1_783_915_200_999), "1783915200");
        assert_eq!(unix_seconds_string(1_783_915_201_000), "1783915201");
    }

    #[test]
    fn unix_time_ms_clamps_out_of_range_times() {
        assert_eq!(unix_time_ms(UNIX_EPOCH), 0);
        assert_eq!(unix_time_ms(UNIX_EPOCH - Duration::from_secs(1)), 0);
        assert_eq!(unix_seconds_string(0), "0");
        assert!(unix_time_ms_now() > 1_700_000_000_000);
    }
}
