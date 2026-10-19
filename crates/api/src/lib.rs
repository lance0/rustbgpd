//! rustbgpd-api — gRPC API server
//!
//! Tonic bindings for the rustbgpd services: `GlobalService`,
//! `ConfigService`, `NeighborService`, `PolicyService`, `PeerGroupService`,
//! `RibService`, `BfdService`, `RpkiService`, `EventService`,
//! `InjectionService`, `ControlService`, `EvpnService`, and the `OpenConfig`
//! `gnmi.gNMI` service.
//! The authoritative roster is the set of `add_service` registrations in
//! [`server`].

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

pub mod accept_backoff;
mod actor_read;
mod audit;
pub mod authz;
pub mod authz_principal;
pub mod authz_runtime;
pub mod bfd_service;
mod config_service;
mod connect_info;
mod control_service;
pub mod credentials;
pub mod dampening_control;
mod event_service;
pub mod evpn_service;
mod global_service;
pub mod gnmi_dialout;
mod gnmi_service;
pub mod health_probe;
pub mod import_roster;
mod injection_service;
pub mod json_format;
pub mod metrics_render;
mod neighbor_service;
pub mod owner_publication;
mod peer_group_service;
pub mod peer_types;
mod policy_helpers;
mod policy_service;
#[cfg(test)]
mod replacement_summary_tests;
pub mod rib_service;
mod route_distinguisher;
pub mod rpki_service;
pub mod runtime_config_settlement;
pub mod server;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod watch_handoff_tests;

pub use config_service::{
    ConfigService, MAX_CONFIRM_ID_CHARS, MAX_CONFIRM_TIMEOUT_SECONDS, update_group_impact_to_proto,
};
pub use evpn_service::EvpnService;
pub use neighbor_service::NeighborService;
pub use policy_service::PolicyService;

/// The `BgpEvent` conversion `ListSessionEvents` applies to each row.
pub mod event_converters {
    pub use crate::event_service::convert::session_event_to_bgp_event;
}

/// Generated protobuf/gRPC types.
#[allow(
    clippy::all,
    clippy::pedantic,
    missing_docs,
    reason = "tonic-generated protobuf modules control their own lint shape"
)]
pub mod proto {
    tonic::include_proto!("rustbgpd.v1");
}

/// Generated OpenConfig gNMI protobuf/gRPC types.
#[allow(
    clippy::all,
    clippy::pedantic,
    missing_docs,
    reason = "tonic-generated protobuf modules control their own lint shape"
)]
pub mod gnmi_ext {
    tonic::include_proto!("gnmi_ext");
}

/// Generated OpenConfig gNMI service and message types.
#[allow(
    clippy::all,
    clippy::pedantic,
    missing_docs,
    reason = "tonic-generated protobuf modules control their own lint shape"
)]
pub mod gnmi {
    tonic::include_proto!("gnmi");
}

/// Generated gNMI dial-out (device-initiated push) service types.
#[allow(
    clippy::all,
    clippy::pedantic,
    missing_docs,
    reason = "tonic-generated protobuf modules control their own lint shape"
)]
pub mod gnmi_dialout_proto {
    include!(concat!(
        env!("OUT_DIR"),
        "/dialout/rustbgpd.gnmi_dialout.v1.rs"
    ));
}
