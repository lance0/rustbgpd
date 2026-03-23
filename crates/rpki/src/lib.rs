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

use std::sync::Arc;

pub use aspa::{AspaRecord, AspaTable};
pub use rtr_client::{RtrClient, RtrClientConfig, VrpUpdate};
pub use vrp::{VrpEntry, VrpTable};
pub use vrp_manager::{AspaTableUpdate, RpkiTableUpdate, VrpManager};

/// Snapshot of RPKI validation tables, broadcast to transport sessions
/// via `tokio::sync::watch` for import-time route validation.
///
/// Each session holds a `watch::Receiver<ValidationSnapshot>` and borrows
/// the current snapshot when evaluating import policy.  The RIB manager
/// keeps its own copy as the authoritative backstop.
#[derive(Debug, Clone, Default)]
pub struct ValidationSnapshot {
    /// Current VRP table for origin validation (RFC 6811).
    pub vrp_table: Option<Arc<VrpTable>>,
    /// Current ASPA table for upstream path verification.
    pub aspa_table: Option<Arc<AspaTable>>,
}

impl ValidationSnapshot {
    /// Validate a route's origin against the VRP table (RFC 6811).
    ///
    /// Returns `NotFound` if no VRP table is loaded or no origin ASN present.
    #[must_use]
    pub fn validate_rpki(
        &self,
        prefix: &rustbgpd_wire::Prefix,
        origin_asn: Option<u32>,
    ) -> rustbgpd_wire::RpkiValidation {
        match (&self.vrp_table, origin_asn) {
            (Some(table), Some(asn)) => table.validate(prefix, asn),
            _ => rustbgpd_wire::RpkiValidation::NotFound,
        }
    }

    /// Validate a route's `AS_PATH` against the ASPA table.
    ///
    /// Returns `Unknown` if no ASPA table is loaded or no `AS_PATH` present.
    #[must_use]
    pub fn validate_aspa(
        &self,
        as_path: Option<&rustbgpd_wire::AsPath>,
    ) -> rustbgpd_wire::AspaValidation {
        match (&self.aspa_table, as_path) {
            (Some(table), Some(path)) => aspa_verify::verify_upstream(path, table),
            _ => rustbgpd_wire::AspaValidation::Unknown,
        }
    }
}
