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
pub mod event_history_sinks;
mod event_service;
pub mod evpn_service;
mod global_service;
mod gnmi_service;
mod injection_service;
pub mod json_format;
mod neighbor_service;
mod peer_group_service;
pub mod peer_types;
mod policy_helpers;
mod policy_service;
pub mod rib_service;
pub mod server;
#[cfg(test)]
mod test_support;

pub use evpn_service::EvpnService;

/// Public-facing alias for the proto-encoding helpers used by the
/// binary's peer-manager + BFD bridge to construct
/// [`crate::proto::BgpEvent`] envelopes for the durable outbox
/// (ADR-0072 PR5).
///
/// Re-exported through a dedicated `event_converters` module rather
/// than via the private `event_service` so the binary doesn't need
/// to know which submodule owns the encoders. The encoders' wire
/// shape is part of the public API surface as of PR5; renaming
/// requires bumping the api crate's version.
pub mod event_converters {
    pub use crate::event_service::convert::{
        evpn_event_to_bgp_event, otc_route_blocked_event_to_bgp_event, policy_event_to_bgp_event,
        route_event_to_bgp_event, session_event_to_bgp_event,
    };
}

/// Generated protobuf/gRPC types.
#[allow(clippy::all, clippy::pedantic, missing_docs)]
pub mod proto {
    tonic::include_proto!("rustbgpd.v1");
}

/// Generated OpenConfig gNMI protobuf/gRPC types.
#[allow(clippy::all, clippy::pedantic, missing_docs)]
pub mod gnmi_ext {
    tonic::include_proto!("gnmi_ext");
}

/// Generated OpenConfig gNMI service and message types.
#[allow(clippy::all, clippy::pedantic, missing_docs)]
pub mod gnmi {
    tonic::include_proto!("gnmi");
}
