//! rustbgpd-api — gRPC API server
//!
//! Tonic bindings for all five rustbgpd services:
//! `GlobalService`, `NeighborService`, `RibService`, `InjectionService`, `ControlService`.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

mod rib_service;
pub mod server;

/// Generated protobuf/gRPC types.
#[allow(clippy::all, clippy::pedantic)]
pub mod proto {
    tonic::include_proto!("rustbgpd.v1");
}
