//! rustbgpd-api — gRPC API server
//!
//! Tonic bindings for all five rustbgpd services:
//! `GlobalService`, `NeighborService`, `RibService`, `InjectionService`, `ControlService`.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

mod control_service;
mod global_service;
mod injection_service;
mod neighbor_service;
pub mod peer_types;
mod policy_service;
mod rib_service;
pub mod server;

/// Generated protobuf/gRPC types.
#[allow(clippy::all, clippy::pedantic, missing_docs)]
pub mod proto {
    tonic::include_proto!("rustbgpd.v1");
}
