//! Canonical reason-label vocabulary for UPDATE-path route rejection.
//!
//! Single source of truth for the `reason` strings that ingress (and
//! the OTC egress sibling) route-rejection mechanisms report across
//! every surface: Prometheus label values, log-line tokens, and
//! structured event payloads. Producers must source the string from
//! the types here rather than repeating a literal, so the surfaces
//! can never drift apart.
//!
//! Contract rules:
//!
//! - Labels are `snake_case`, stable across releases, and
//!   low-cardinality — never a peer address or prefix.
//! - One reason string per mechanism, shared by every surface that
//!   reports that mechanism. The metric label value IS the documented
//!   string; log lines may add detail but carry the canonical token.
//! - Reasons are named for what was observed on the wire, not for the
//!   consumer that reacts to it.
//!
//! Renaming any string here is a breaking observability change
//! (operators key alerts on these values) and must be called out in
//! the changelog with old → new pairs.
//!
//! Mechanisms with no reason label: `bgp_as_path_loop_detected_total`
//! and `bgp_max_prefix_exceeded_total` encode the mechanism in the
//! metric name itself and carry only a `peer` label — there is no
//! reason string to pin. `bgp_rr_loop_detected_total` likewise has no
//! `reason` label, but the log line emitted alongside it
//! distinguishes the two RFC 4456 §8 loop signals via
//! [`RrLoopReason`].

/// RFC 9234 Only-to-Customer route-leak block reasons.
///
/// Surfaces sharing this vocabulary:
///
/// - `bgp_otc_routes_blocked_total{peer, reason}` label values
///   ([`crate::BgpMetrics::record_otc_routes_blocked`]);
/// - the `reason` field of the transport `OtcRouteBlockedEvent`
///   structured payload (and through it the gRPC
///   `OTC_ROUTE_BLOCKED` event surface);
/// - the `reason` token on the transport warn/debug log lines;
/// - the documented values in `docs/OPERATIONS.md` and ADR-0071.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OtcBlockReason {
    /// Ingress: a route carrying OTC arrived while we act as
    /// Provider or Route Server — the route was only ever meant to
    /// travel toward customers (RFC 9234 §5 I1).
    IngressFromCustomerRsclient,
    /// Ingress: a route carrying OTC arrived on a lateral Peer
    /// session with an OTC value that is not the peer's ASN
    /// (RFC 9234 §5 I2).
    IngressPeerMismatch,
    /// Ingress: the OTC attribute had a malformed length, so the
    /// announcements were dropped treat-as-withdraw style
    /// (RFC 9234 §5 + RFC 7606).
    MalformedLength,
    /// Egress: a unicast route carrying OTC was about to be
    /// advertised up to a Provider / lateral Peer / Route Server,
    /// which RFC 9234 §5 prohibits.
    EgressToUpstreamViaOtc,
}

impl OtcBlockReason {
    /// Every canonical OTC block reason, for vocabulary walks in
    /// tests and docs.
    pub const ALL: [Self; 4] = [
        Self::IngressFromCustomerRsclient,
        Self::IngressPeerMismatch,
        Self::MalformedLength,
        Self::EgressToUpstreamViaOtc,
    ];

    /// The canonical reason string shared by every surface.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IngressFromCustomerRsclient => "ingress_from_customer_rsclient",
            Self::IngressPeerMismatch => "ingress_peer_mismatch",
            Self::MalformedLength => "malformed_length",
            Self::EgressToUpstreamViaOtc => "egress_to_upstream_via_otc",
        }
    }
}

impl std::fmt::Display for OtcBlockReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// ADR-0107 route-server strict-peer `NEXT_HOP` ownership rejection
/// reasons (RFC 7948 §4.8).
///
/// Surfaces sharing this vocabulary today:
///
/// - the `reason` token on the transport warn log line emitted when the
///   pre-policy ownership gate rejects an UPDATE's unicast
///   announcements.
///
/// A `bgp_next_hop_ownership_blocked_total{peer, reason}` counter and a
/// structured event are planned follow-ups; they must consume these
/// exact strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NextHopOwnershipBlockReason {
    /// An address component of the wire next-hop identity is not the
    /// advertising session's own address.
    ForeignNextHop,
    /// The wire identity carried a global + link-local next-hop pair;
    /// the session maps to exactly one address, so the companion is
    /// unverifiable under the strict-peer pilot (never silently
    /// ignored — ADR-0107 §2).
    UnverifiedLinkLocalCompanion,
    /// A link-local next-hop arrived on a session without a scoped
    /// link-local identity, so `fe80::/10` + interface scope cannot be
    /// mapped to the advertising session.
    UnscopedLinkLocal,
}

impl NextHopOwnershipBlockReason {
    /// Every canonical ownership block reason, for vocabulary walks in
    /// tests and docs.
    pub const ALL: [Self; 3] = [
        Self::ForeignNextHop,
        Self::UnverifiedLinkLocalCompanion,
        Self::UnscopedLinkLocal,
    ];

    /// The canonical reason string shared by every surface.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ForeignNextHop => "foreign_next_hop",
            Self::UnverifiedLinkLocalCompanion => "unverified_link_local_companion",
            Self::UnscopedLinkLocal => "unscoped_link_local",
        }
    }
}

impl std::fmt::Display for NextHopOwnershipBlockReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// RFC 4456 §8 route-reflection loop signals.
///
/// `bgp_rr_loop_detected_total{peer}` counts both signals together
/// (the mechanism lives in the metric name; the label set is
/// unchanged since the metric shipped). The log line emitted with
/// each increment carries this token as its `reason` field so
/// operators can tell which attribute evidenced the loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RrLoopReason {
    /// The received `ORIGINATOR_ID` equals our own router-id.
    OriginatorId,
    /// Our cluster-id is already present in the received
    /// `CLUSTER_LIST`.
    ClusterList,
}

impl RrLoopReason {
    /// Every canonical RR loop reason, for vocabulary walks in tests
    /// and docs.
    pub const ALL: [Self; 2] = [Self::OriginatorId, Self::ClusterList];

    /// The canonical reason token used on the log surface.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OriginatorId => "originator_id",
            Self::ClusterList => "cluster_list",
        }
    }
}

impl std::fmt::Display for RrLoopReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Exact outbound encoder rejection reasons shared by metrics and RIB logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExactExportReason {
    Encoding,
    MissingIpv6NextHop,
    Ipv4RequiresExtendedNextHop,
    MessageTooLong,
}

impl ExactExportReason {
    pub const ALL: [Self; 4] = [
        Self::Encoding,
        Self::MissingIpv6NextHop,
        Self::Ipv4RequiresExtendedNextHop,
        Self::MessageTooLong,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Encoding => "encoding",
            Self::MissingIpv6NextHop => "missing_ipv6_next_hop",
            Self::Ipv4RequiresExtendedNextHop => "ipv4_requires_extended_next_hop",
            Self::MessageTooLong => "message_too_long",
        }
    }
}

impl std::fmt::Display for ExactExportReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::{ExactExportReason, NextHopOwnershipBlockReason, OtcBlockReason, RrLoopReason};

    fn assert_snake_case(label: &str) {
        assert!(!label.is_empty(), "reason label must not be empty");
        assert!(
            label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
            "reason label {label:?} must be snake_case ([a-z0-9_])"
        );
        assert!(
            !label.starts_with('_') && !label.ends_with('_'),
            "reason label {label:?} must not start or end with '_'"
        );
    }

    #[test]
    fn otc_block_reasons_are_snake_case_and_distinct() {
        let mut seen = std::collections::HashSet::new();
        for reason in OtcBlockReason::ALL {
            assert_snake_case(reason.as_str());
            assert!(seen.insert(reason.as_str()), "duplicate label");
        }
    }

    #[test]
    fn next_hop_ownership_block_reasons_are_snake_case_and_distinct() {
        let mut seen = std::collections::HashSet::new();
        for reason in NextHopOwnershipBlockReason::ALL {
            assert_snake_case(reason.as_str());
            assert!(seen.insert(reason.as_str()), "duplicate label");
        }
    }

    #[test]
    fn rr_loop_reasons_are_snake_case_and_distinct() {
        let mut seen = std::collections::HashSet::new();
        for reason in RrLoopReason::ALL {
            assert_snake_case(reason.as_str());
            assert!(seen.insert(reason.as_str()), "duplicate label");
        }
    }

    #[test]
    fn exact_export_reasons_are_snake_case_and_distinct() {
        let mut seen = std::collections::HashSet::new();
        for reason in ExactExportReason::ALL {
            assert_snake_case(reason.as_str());
            assert!(seen.insert(reason.as_str()), "duplicate label");
        }
    }

    /// Pins the exact strings: these are operator-facing stable
    /// identifiers (alert expressions key on them). Renaming one is a
    /// breaking observability change — if this test fails, the rename
    /// must be deliberate and called out in the changelog with the
    /// old → new pair.
    #[test]
    fn canonical_reason_strings_are_pinned() {
        let otc: Vec<&str> = OtcBlockReason::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(
            otc,
            [
                "ingress_from_customer_rsclient",
                "ingress_peer_mismatch",
                "malformed_length",
                "egress_to_upstream_via_otc",
            ]
        );
        let ownership: Vec<&str> = NextHopOwnershipBlockReason::ALL
            .iter()
            .map(|r| r.as_str())
            .collect();
        assert_eq!(
            ownership,
            [
                "foreign_next_hop",
                "unverified_link_local_companion",
                "unscoped_link_local",
            ]
        );
        let rr: Vec<&str> = RrLoopReason::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(rr, ["originator_id", "cluster_list"]);
        let exact: Vec<&str> = ExactExportReason::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(
            exact,
            [
                "encoding",
                "missing_ipv6_next_hop",
                "ipv4_requires_extended_next_hop",
                "message_too_long",
            ]
        );
    }
}
