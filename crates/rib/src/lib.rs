//! rustbgpd-rib — RIB data structures
//!
//! Adj-RIB-In per neighbor, managed by a single tokio task.
//! Peer sessions send updates via bounded `mpsc` channel.
//! Queries use embedded `oneshot` for response.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

/// Per-peer inbound RIB storage.
pub mod adj_rib_in;
/// Per-peer outbound RIB storage.
pub mod adj_rib_out;
/// Best-path selection algorithm (RFC 4271 §9.1.2).
pub mod best_path;
/// Route change event types for broadcast subscribers.
pub mod event;
/// Sink boundary for handing route + EVPN events to an out-of-crate
/// consumer (ADR-0072 durable event outbox).
pub mod event_sink;
/// Loc-RIB: best route per prefix.
pub mod loc_rib;
/// RIB manager task and submodules.
pub mod manager;
/// Per-peer Outbound Route Filtering (ORF) state (RFC 5291 + RFC 5292).
mod orf;
/// Family-split prefix-trie map backing the compact prefix-keyed RIB indexes.
mod prefix_map;
/// Route and `FlowSpec` route data types.
pub mod route;
/// Shared unit-test fixtures (canonical test route builders).
#[cfg(test)]
mod test_support;
/// RIB update messages and outbound route structures.
pub mod update;

pub use best_path::{BestPathReason, best_path_cmp, multipath_equal};
pub use event::{EvpnRouteEvent, RouteEvent, RouteEventType};
pub use event_sink::{NoopRibEventSink, RibEventSink};
pub use loc_rib::LocRib;
pub use manager::RibManager;
pub use route::{
    EvpnRibRoute, FibInstallCandidate, FibInstallNextHop, FlowSpecRoute, NextHopScope, Route,
    RouteOrigin,
};
pub use update::{
    BestPathCandidate, ExplainAdvertisedRoute, ExplainBestPath, ExplainDecision, ExplainReason,
    MrtPeerEntry, MrtSnapshotData, NeighborPolicyStats, OutboundRouteUpdate, RibCommandError,
    RibUpdate,
};
