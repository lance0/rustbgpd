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
/// Loc-RIB: best route per prefix.
pub mod loc_rib;
/// RIB manager task and submodules.
pub mod manager;
/// Route and `FlowSpec` route data types.
pub mod route;
/// RIB update messages and outbound route structures.
pub mod update;

pub use best_path::best_path_cmp;
pub use event::{RouteEvent, RouteEventType};
pub use loc_rib::LocRib;
pub use manager::RibManager;
pub use route::{FlowSpecRoute, Route, RouteOrigin};
pub use update::{MrtPeerEntry, MrtSnapshotData, OutboundRouteUpdate, RibUpdate};
