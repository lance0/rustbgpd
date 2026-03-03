//! rustbgpd-rpki — RPKI origin validation
//!
//! VRP table management, RTR protocol (RFC 8210) client, and multi-cache
//! aggregation for RPKI origin validation (RFC 6811).
//!
//! # Components
//!
//! - [`VrpTable`] — immutable, sorted VRP table with origin validation
//! - [`VrpEntry`] — a single Validated ROA Payload
//! - [`rtr_codec`] — encode/decode RTR protocol PDUs
//! - [`rtr_client`] — async per-cache-server connection manager
//! - [`vrp_manager`] — multi-cache merge and snapshot distribution

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

pub mod rtr_client;
pub mod rtr_codec;
pub mod vrp;
pub mod vrp_manager;

pub use rtr_client::{RtrClient, RtrClientConfig, VrpUpdate};
pub use vrp::{VrpEntry, VrpTable};
pub use vrp_manager::{RpkiTableUpdate, VrpManager};
