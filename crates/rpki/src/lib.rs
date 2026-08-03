//! rustbgpd-rpki — RPKI origin validation and ASPA path verification
//!
//! VRP table management, ASPA table management, RTR protocol (RFC 8210)
//! client, and multi-cache aggregation for RPKI origin validation (RFC 6811)
//! and ASPA path verification (draft-ietf-sidrops-aspa-verification).
//!
//! # Components
//!
//! - [`VrpTable`] — immutable, prefix-length-indexed VRP table with origin validation
//! - [`VrpEntry`] — a single Validated ROA Payload
//! - [`AspaTable`] — immutable ASPA lookup table
//! - [`AspaRecord`] — a single ASPA record (customer → providers)
//! - [`aspa_verify`] — ASPA path verification algorithms
//! - [`rtr_codec`] — encode/decode RTR protocol PDUs
//! - [`rtr_client`] — async per-cache-server connection manager
//! - [`vrp_manager`] — multi-cache merge and snapshot distribution
//!
//! # RTR protocol support
//!
//! The RTR client implements a deliberately scoped subset of RFC 8210 and
//! draft-ietf-sidrops-8210bis:
//!
//! - **Versions** — v2 (8210bis) is preferred for ASPA support, with
//!   automatic fallback to v1 (RFC 8210) on explicit rejection (error
//!   code 4) or pre-session disconnect. Every PDU in a session must carry
//!   the negotiated version; a mismatch ends the session.
//! - **Epoch model** — `(protocol version, session ID, serial)` is
//!   tracked as ONE per-cache epoch, advanced only as a unit at a
//!   validated End of Data. Incremental data is applied only when the
//!   response identity (Cache Response and End of Data session IDs, RFC
//!   1982 serial progression) matches the held epoch; any mismatch forces
//!   a full resynchronization via Reset Query — never a splice.
//! - **Data retention** — validated VRPs and ASPAs are retained through
//!   disconnect, reconnect, version fallback, and Cache Reset. They are
//!   dropped only when a full replacement completes or the expire
//!   interval passes without a fresh End of Data.
//! - **ASPA (v2)** — 8210bis replacement semantics: an announce replaces
//!   the customer ASN's entire provider set; a withdraw (empty provider
//!   set on the wire) removes the customer ASN.
//! - **Transaction bounds** — each transaction is bounded by a wall-clock
//!   deadline and record/byte budgets, so a broken or malicious cache
//!   cannot wedge the client or exhaust memory.
//! - **Not implemented** — Router Key PDUs (`BGPsec`, type 9) are rejected
//!   as unknown and end the session; transport security (RTR over
//!   TLS/SSH) — connections are plain TCP.

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
    /// Current ASPA table for path verification.
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
    /// Per `draft-ietf-sidrops-aspa-verification-27` §6.2, ASPA
    /// verification is applied only to `{AFI 1 (IPv4), SAFI 1 (Unicast)}`
    /// and `{AFI 2 (IPv6), SAFI 1 (Unicast)}`. For any other family this
    /// returns `Unknown` immediately without consulting the table — the
    /// §6.2 gate prevents EVPN, `FlowSpec`, multicast, MPLS-VPN, and other
    /// non-unicast families from silently inheriting an ASPA verdict
    /// computed from an unrelated AS path.
    ///
    /// Returns `Unknown` if no ASPA table is loaded or no `AS_PATH` is
    /// present.
    #[must_use]
    pub fn validate_aspa(
        &self,
        as_path: Option<&rustbgpd_wire::AsPath>,
        family: (rustbgpd_wire::Afi, rustbgpd_wire::Safi),
        context: rustbgpd_wire::AspaValidationContext,
    ) -> rustbgpd_wire::AspaValidation {
        use rustbgpd_wire::{Afi, AspaValidation, Safi};
        // §6.2 family gate.
        if !matches!(family, (Afi::Ipv4 | Afi::Ipv6, Safi::Unicast)) {
            return AspaValidation::Unknown;
        }
        match (&self.aspa_table, as_path) {
            (Some(table), Some(path)) => aspa_verify::verify(path, table, context),
            _ => AspaValidation::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustbgpd_wire::{Afi, AsPath, AsPathSegment, AspaValidation, AspaValidationContext, Safi};

    fn snap_with_table() -> ValidationSnapshot {
        ValidationSnapshot {
            vrp_table: None,
            aspa_table: Some(Arc::new(AspaTable::new(vec![AspaRecord {
                customer_asn: 1,
                provider_asns: vec![2],
            }]))),
        }
    }

    fn ipv4_unicast_path() -> AsPath {
        // Compresses to [2, 1]: neighbor=2, origin=1; 1 attests 2 as provider.
        AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![2, 1])],
        }
    }

    #[test]
    fn validate_aspa_runs_for_ipv4_unicast() {
        let snap = snap_with_table();
        let path = ipv4_unicast_path();
        assert_eq!(
            snap.validate_aspa(
                Some(&path),
                (Afi::Ipv4, Safi::Unicast),
                AspaValidationContext::default(),
            ),
            AspaValidation::Valid,
        );
    }

    #[test]
    fn validate_aspa_runs_for_ipv6_unicast() {
        let snap = snap_with_table();
        let path = ipv4_unicast_path();
        assert_eq!(
            snap.validate_aspa(
                Some(&path),
                (Afi::Ipv6, Safi::Unicast),
                AspaValidationContext::default(),
            ),
            AspaValidation::Valid,
        );
    }

    #[test]
    fn validate_aspa_returns_unknown_for_evpn() {
        // §6.2: AFI L2VPN / SAFI EVPN is out of scope; gate returns Unknown
        // regardless of how the AS_PATH would otherwise validate.
        let snap = snap_with_table();
        let path = ipv4_unicast_path();
        assert_eq!(
            snap.validate_aspa(
                Some(&path),
                (Afi::L2Vpn, Safi::Evpn),
                AspaValidationContext::default(),
            ),
            AspaValidation::Unknown,
        );
    }

    #[test]
    fn validate_aspa_returns_unknown_for_flowspec() {
        let snap = snap_with_table();
        let path = ipv4_unicast_path();
        assert_eq!(
            snap.validate_aspa(
                Some(&path),
                (Afi::Ipv4, Safi::FlowSpec),
                AspaValidationContext::default(),
            ),
            AspaValidation::Unknown,
        );
    }

    #[test]
    fn validate_aspa_returns_unknown_for_ipv6_flowspec() {
        let snap = snap_with_table();
        let path = ipv4_unicast_path();
        assert_eq!(
            snap.validate_aspa(
                Some(&path),
                (Afi::Ipv6, Safi::FlowSpec),
                AspaValidationContext::default(),
            ),
            AspaValidation::Unknown,
        );
    }

    #[test]
    fn validate_aspa_returns_unknown_for_multicast_safi() {
        let snap = snap_with_table();
        let path = ipv4_unicast_path();
        assert_eq!(
            snap.validate_aspa(
                Some(&path),
                (Afi::Ipv4, Safi::Multicast),
                AspaValidationContext::default(),
            ),
            AspaValidation::Unknown,
        );
    }

    #[test]
    fn validate_aspa_returns_unknown_when_no_table() {
        let snap = ValidationSnapshot {
            vrp_table: None,
            aspa_table: None,
        };
        let path = ipv4_unicast_path();
        assert_eq!(
            snap.validate_aspa(
                Some(&path),
                (Afi::Ipv4, Safi::Unicast),
                AspaValidationContext::default(),
            ),
            AspaValidation::Unknown,
        );
    }

    #[test]
    fn validate_aspa_returns_unknown_when_no_path() {
        let snap = snap_with_table();
        assert_eq!(
            snap.validate_aspa(
                None,
                (Afi::Ipv4, Safi::Unicast),
                AspaValidationContext::default(),
            ),
            AspaValidation::Unknown,
        );
    }
}
