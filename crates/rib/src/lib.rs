//! rustbgpd-rib — RIB data structures
//!
//! Adj-RIB-In per neighbor, managed by a single tokio task.
//! Peer sessions send updates via bounded `mpsc` channel.
//! Queries use embedded `oneshot` for response.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

pub mod adj_rib_in;
pub mod adj_rib_out;
pub mod best_path;
pub mod event;
pub mod loc_rib;
pub mod manager;
pub mod route;
pub mod update;

pub use best_path::best_path_cmp;
pub use event::{RouteEvent, RouteEventType};
pub use loc_rib::LocRib;
pub use manager::RibManager;
pub use route::{FlowSpecRoute, Route, RouteOrigin};
pub use update::{MrtPeerEntry, MrtSnapshotData, OutboundRouteUpdate, RibUpdate};
