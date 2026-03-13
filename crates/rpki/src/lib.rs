//! rustbgpd-rpki — RPKI origin validation and ASPA path verification
//!
//! VRP table management, ASPA table management, RTR protocol (RFC 8210)
//! client, and multi-cache aggregation for RPKI origin validation (RFC 6811)
//! and ASPA upstream path verification (draft-ietf-sidrops-aspa-verification).
//!
//! # Components
//!
//! - [`VrpTable`] — immutable, sorted VRP table with origin validation
//! - [`VrpEntry`] — a single Validated ROA Payload
//! - [`AspaTable`] — immutable ASPA lookup table
//! - [`AspaRecord`] — a single ASPA record (customer → providers)
//! - [`aspa_verify`] — ASPA upstream path verification algorithm
//! - [`rtr_codec`] — encode/decode RTR protocol PDUs
//! - [`rtr_client`] — async per-cache-server connection manager
//! - [`vrp_manager`] — multi-cache merge and snapshot distribution

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

pub mod aspa;
pub mod aspa_verify;
pub mod rtr_client;
pub mod rtr_codec;
pub mod vrp;
pub mod vrp_manager;

pub use aspa::{AspaRecord, AspaTable};
pub use rtr_client::{RtrClient, RtrClientConfig, VrpUpdate};
pub use vrp::{VrpEntry, VrpTable};
pub use vrp_manager::{AspaTableUpdate, RpkiTableUpdate, VrpManager};
