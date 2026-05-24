//! rustbgpd-api — gRPC API server
//!
//! Tonic bindings for the rustbgpd services:
//! `GlobalService`, `NeighborService`, `PolicyService`, `PeerGroupService`,
//! `RibService`, `EventService`, `InjectionService`, `ControlService`,
//! `EvpnService`.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

mod audit;
pub mod authz;
pub mod authz_principal;
pub mod authz_runtime;
pub mod bfd_service;
mod config_service;
mod connect_info;
mod control_service;
mod event_service;
pub mod evpn_service;
mod global_service;
mod injection_service;
mod neighbor_service;
mod peer_group_service;
pub mod peer_types;
mod policy_helpers;
mod policy_service;
mod rib_service;
pub mod server;

pub use evpn_service::EvpnService;

/// Generated protobuf/gRPC types.
#[allow(clippy::all, clippy::pedantic, missing_docs)]
pub mod proto {
    tonic::include_proto!("rustbgpd.v1");
}
