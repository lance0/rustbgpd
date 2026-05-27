//! Sink boundary for handing route + EVPN events to an out-of-crate
//! consumer (ADR-0072 PR5).
//!
//! `crates/rib` cannot depend on `crates/api` (would cycle through
//! the proto types), and it also cannot depend on
//! `rustbgpd-event-history` directly because the encode step needs
//! `crates/api`'s proto conversion helpers. The compromise: define a
//! tiny trait here in `rib`, let the binary plug in an EHM-backed
//! implementation that owns both the EHM handle and the proto
//! encoders. The RIB calls into the trait; the trait impl resolves
//! the cycle on the binary side.
//!
//! See `docs/adr/0072-durable-event-history.md` "Producer wiring"
//! for the contract: the sink fires **after** the existing
//! `route_event_history` ring + `route_events_tx` broadcast so the
//! legacy live surfaces (`WatchRoutes`, `WatchEvents`,
//! `ListRouteEvents`) are unchanged. The durable cursor
//! (`SubscribeFromEvent`) is the consumer of the sink path.

use crate::event::{EvpnRouteEvent, RouteEvent};

/// Object-safe sink that hands a snapshot of each emitted RIB event
/// to an out-of-crate consumer.
///
/// Implementations must be non-blocking. The binary-side EHM-backed
/// implementation uses `EventHistorySender::try_send` (drop on full
/// queue + metric + degraded flag). Implementations MUST NOT panic
/// in the publish hot path; a panic here would unwind through the
/// RIB actor.
///
/// Trait methods take `&RouteEvent` / `&EvpnRouteEvent` rather than
/// owned values so the existing `publish_*_event` paths can clone
/// only when needed (EVPN events carry `Arc<EvpnRibRoute>` payloads
/// that are cheap to clone, but the legacy ring already takes one
/// clone for its `push_back` so passing by reference here saves
/// another).
pub trait RibEventSink: Send + Sync + 'static {
    /// Hand a route event to the sink. Called from
    /// `RibManager::publish_route_event` **after** the event has been
    /// stamped with its process-local `event_id`, appended to the
    /// bounded ring, and broadcast on `route_events_tx`. Legacy
    /// `event_id` value is preserved as-is on the snapshot the sink
    /// sees; the durable cursor overwrites it from the EHM commit on
    /// the wire path.
    fn publish_route_event(&self, event: &RouteEvent);

    /// Hand an EVPN best-path event to the sink. Called from
    /// `RibManager::publish_evpn_route_event` after the existing
    /// ring + broadcast work. EVPN events do not currently carry a
    /// process-local `event_id`; the durable envelope id is the only
    /// id surfaced on the EHM-backed wire path.
    fn publish_evpn_event(&self, event: &EvpnRouteEvent);
}

/// No-op sink used when `[event_history]` is disabled or EHM failed
/// to start with `required = false`. Keeps `RibManager`'s sink slot
/// non-`Option<T>` so the publish hot path is one virtual call
/// regardless of EHM state — the JIT can devirtualize the noop case
/// to a no-op return.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopRibEventSink;

impl RibEventSink for NoopRibEventSink {
    fn publish_route_event(&self, _event: &RouteEvent) {}
    fn publish_evpn_event(&self, _event: &EvpnRouteEvent) {}
}
