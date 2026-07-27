use std::any::Any;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use rustbgpd_policy::PolicyChain;
use rustbgpd_rpki::{AspaTable, VrpTable};
use rustbgpd_wire::{
    AddressPrefixOrf, Afi, BgpRole, EvpnRouteKey, Prefix, RouteRefreshSubtype, Safi, WhenToRefresh,
};
use tokio::sync::{broadcast, mpsc, oneshot};

/// Failure returned by the dedicated, type-narrow RIB readiness lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RibReadinessError {
    /// An actor-owned export-policy transition exceeded its maximum healthy
    /// ownership age, so ordinary RIB work may be wedged behind its fence.
    PolicyTransitionStalled,
}

/// Type-narrow readiness queries serviced independently of the general RIB
/// query lane.
///
/// Keeping this channel separate lets the actor prove liveness while an
/// atomic policy transition deliberately fences every ordinary query and
/// mutation behind its terminal commit or fail-closed fallback handoff.
#[derive(Debug)]
pub enum RibReadinessQuery {
    /// Return the current Loc-RIB best-path count.
    LocRibCount {
        /// Response channel.
        reply: oneshot::Sender<Result<usize, RibReadinessError>>,
    },
}

/// Canonical, side-effect-free input to update-group eligibility.
#[expect(
    clippy::struct_excessive_bools,
    reason = "mirrors the independent runtime update-group predicates"
)]
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct UpdateGroupClassifierInput {
    pub policy_fingerprint: Option<String>,
    pub policy_provenance: Option<String>,
    pub policy_requires_peer_context: bool,
    pub target_is_ebgp: bool,
    pub target_is_rr_client: bool,
    /// Local RFC 9234 role. OTC egress eligibility is a RIB-staging
    /// decision, so groups with different roles must never share a table.
    pub target_local_role: Option<u8>,
    /// RFC 1997 `NO_EXPORT` egress enforcement. A staging gate whose
    /// outcome differs per peer (honor vs transparent), so peers that
    /// differ must never share a staged winner.
    pub interpret_rfc1997: bool,
    pub sendable_families: Vec<(u16, u8)>,
    pub llgr_families: Vec<(u16, u8)>,
    pub add_path_send: bool,
    pub per_client_best: bool,
    pub orr_vantage: Option<IpAddr>,
    pub orf_installed: bool,
}

/// Exact runtime grouping key, excluding diagnostics and non-staging families.
#[expect(
    clippy::struct_excessive_bools,
    reason = "mirrors the independent fields of the runtime GroupKey"
)]
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct UpdateGroupFingerprint {
    pub policy_fingerprint: Option<String>,
    pub target_is_ebgp: bool,
    pub target_is_rr_client: bool,
    pub target_local_role: Option<u8>,
    pub interpret_rfc1997: bool,
    pub sendable_ipv4_unicast: bool,
    pub sendable_ipv6_unicast: bool,
    pub sendable_vpnv4: bool,
    pub sendable_vpnv6: bool,
    pub rtc_negotiated: bool,
    pub llgr_families: Vec<(u16, u8)>,
}

/// Stable classifier result shared by live registration and config planning.
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum UpdateGroupClassification {
    Groupable(UpdateGroupFingerprint),
    PolicyPeerContext,
    AddPathSend,
    PerClientBest,
    OrrVantage,
    OrfInstalled,
}

impl UpdateGroupClassification {
    #[must_use]
    pub const fn reason(&self) -> Option<&'static str> {
        match self {
            Self::Groupable(_) => None,
            Self::PolicyPeerContext => Some("policy_peer_context"),
            Self::AddPathSend => Some("add_path_send"),
            Self::PerClientBest => Some("per_client_best"),
            Self::OrrVantage => Some("orr_vantage"),
            Self::OrfInstalled => Some("orf_installed"),
        }
    }
}

/// Apply the runtime eligibility precedence without reading or mutating RIB state.
#[must_use]
pub fn classify_update_group(mut input: UpdateGroupClassifierInput) -> UpdateGroupClassification {
    input.sendable_families.sort_unstable();
    input.sendable_families.dedup();
    input.llgr_families.sort_unstable();
    input.llgr_families.dedup();
    if input.policy_requires_peer_context {
        UpdateGroupClassification::PolicyPeerContext
    } else if input.add_path_send {
        UpdateGroupClassification::AddPathSend
    } else if input.per_client_best {
        UpdateGroupClassification::PerClientBest
    } else if input.orr_vantage.is_some() {
        UpdateGroupClassification::OrrVantage
    } else if input.orf_installed {
        UpdateGroupClassification::OrfInstalled
    } else {
        let contains = |family| input.sendable_families.contains(&family);
        UpdateGroupClassification::Groupable(UpdateGroupFingerprint {
            policy_fingerprint: input.policy_fingerprint,
            target_is_ebgp: input.target_is_ebgp,
            target_is_rr_client: input.target_is_rr_client,
            target_local_role: input.target_local_role,
            interpret_rfc1997: input.interpret_rfc1997,
            sendable_ipv4_unicast: contains((1, 1)),
            sendable_ipv6_unicast: contains((2, 1)),
            sendable_vpnv4: contains((1, 128)),
            sendable_vpnv6: contains((2, 128)),
            rtc_negotiated: contains((1, 132)),
            llgr_families: input.llgr_families,
        })
    }
}

/// One established peer in the side-effect-free planner snapshot.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct UpdateGroupPeerSnapshot {
    pub peer: IpAddr,
    pub input: UpdateGroupClassifierInput,
    pub classification: UpdateGroupClassification,
    pub runtime_membership: String,
}

#[derive(Clone, Debug, Default, Hash, PartialEq, Eq)]
pub struct UpdateGroupSnapshot {
    pub peers: Vec<UpdateGroupPeerSnapshot>,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
/// Stable relationship between two live update-group memberships.
pub enum UpdateGroupComparisonVerdict {
    Unknown,
    Private,
    Shared,
    Separate,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
/// Stable membership state without internal group identifiers.
pub enum UpdateGroupComparisonMembership {
    Unknown,
    Grouped,
    PolicyPeerContext,
    AddPathSend,
    PerClientBest,
    OrrVantage,
    OrfInstalled,
    SlowPeer,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
/// Semantic staging input that separates two groupable peers.
pub enum UpdateGroupComparisonDifference {
    ExportPolicy,
    SessionKind,
    RouteReflectorClient,
    LocalRole,
    Rfc1997Mode,
    NegotiatedFamilies,
    LlgrFamilies,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
/// One actor-owned comparison of two configured peers.
pub struct UpdateGroupPeerComparison {
    pub primary_update_group: String,
    pub verdict: UpdateGroupComparisonVerdict,
    pub primary_membership: UpdateGroupComparisonMembership,
    pub comparison_membership: UpdateGroupComparisonMembership,
    pub differences: Vec<UpdateGroupComparisonDifference>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlannedGroupability {
    Group { id: String },
    Private { reason: String, fingerprint: String },
    Indeterminate { reason: String },
    Absent,
}

impl PlannedGroupability {
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Group { id } => id.clone(),
            Self::Private { reason, .. } | Self::Indeterminate { reason } => reason.clone(),
            Self::Absent => "absent".to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateGroupFamilyImpact {
    pub peer: IpAddr,
    pub afi: u16,
    pub safi: u8,
    pub current: PlannedGroupability,
    pub candidate: PlannedGroupability,
    pub transition: String,
    pub reason: String,
    pub provenance: String,
    pub local_resync: bool,
    pub remote_route_refresh: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpdateGroupImpactRollup {
    pub affected_peers: u32,
    pub affected_families: u32,
    pub no_op: u32,
    pub regroup: u32,
    pub shared_migration: u32,
    pub private_resync: u32,
    pub indeterminate: u32,
    pub projected_shared_groups: u32,
    pub projected_private_views: u32,
    pub local_resyncs: u32,
    pub remote_route_refreshes: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpdateGroupImpactPlan {
    pub schema_version: u32,
    pub entries: Vec<UpdateGroupFamilyImpact>,
    pub rollup: UpdateGroupImpactRollup,
    pub capacity_class: String,
    pub capacity_basis: String,
}

#[cfg(test)]
mod update_group_classifier_tests {
    use super::*;

    fn input() -> UpdateGroupClassifierInput {
        UpdateGroupClassifierInput {
            policy_fingerprint: Some("permit-all".to_string()),
            policy_provenance: Some("toml_compiled_ir".to_string()),
            policy_requires_peer_context: false,
            target_is_ebgp: false,
            target_is_rr_client: true,
            target_local_role: None,
            interpret_rfc1997: true,
            sendable_families: vec![(2, 1), (1, 1), (1, 1)],
            llgr_families: vec![],
            add_path_send: false,
            per_client_best: false,
            orr_vantage: None,
            orf_installed: false,
        }
    }

    #[test]
    fn classifier_canonicalizes_families() {
        let UpdateGroupClassification::Groupable(result) = classify_update_group(input()) else {
            panic!("uniform input must group");
        };
        assert!(result.sendable_ipv4_unicast);
        assert!(result.sendable_ipv6_unicast);
    }

    #[test]
    fn classifier_uses_runtime_fallback_precedence() {
        let mut value = input();
        value.policy_requires_peer_context = true;
        value.add_path_send = true;
        value.orf_installed = true;
        assert_eq!(
            classify_update_group(value),
            UpdateGroupClassification::PolicyPeerContext
        );
    }

    #[test]
    fn classifier_golden_groupability_scenarios() {
        let cases: Vec<(&str, UpdateGroupClassifierInput, Option<&str>)> = vec![
            ("uniform", input(), None),
            (
                "rtc_membership",
                UpdateGroupClassifierInput {
                    sendable_families: vec![(1, 132), (1, 128)],
                    ..input()
                },
                None,
            ),
            (
                "per_client_best",
                UpdateGroupClassifierInput {
                    per_client_best: true,
                    ..input()
                },
                Some("per_client_best"),
            ),
            (
                "orf",
                UpdateGroupClassifierInput {
                    orf_installed: true,
                    ..input()
                },
                Some("orf_installed"),
            ),
            (
                "orr",
                UpdateGroupClassifierInput {
                    orr_vantage: Some("192.0.2.9".parse().unwrap()),
                    ..input()
                },
                Some("orr_vantage"),
            ),
            (
                "toml_peer_context",
                UpdateGroupClassifierInput {
                    policy_requires_peer_context: true,
                    policy_provenance: Some("toml_compiled_ir".to_string()),
                    ..input()
                },
                Some("policy_peer_context"),
            ),
            (
                "rpol_peer_context",
                UpdateGroupClassifierInput {
                    policy_requires_peer_context: true,
                    policy_provenance: Some("rpol_compiled_ir".to_string()),
                    ..input()
                },
                Some("policy_peer_context"),
            ),
        ];
        for (name, value, expected_reason) in cases {
            let result = classify_update_group(value);
            assert_eq!(result.reason(), expected_reason, "scenario {name}");
        }
    }

    #[test]
    fn canonical_fingerprint_ignores_non_key_family_and_provenance() {
        let left = input();
        let mut right = left.clone();
        right.sendable_families.push((25, 70));
        right.policy_provenance = Some("rpol_compiled_ir".to_string());
        assert_eq!(classify_update_group(left), classify_update_group(right));
    }

    #[test]
    fn canonical_fingerprint_separates_rfc9234_local_roles() {
        let mut customer = input();
        customer.target_local_role = Some(BgpRole::Customer.to_u8());
        let mut provider = customer.clone();
        provider.target_local_role = Some(BgpRole::Provider.to_u8());

        assert_ne!(
            classify_update_group(customer),
            classify_update_group(provider),
            "peers with different OTC egress semantics must not share a table"
        );
    }
}

use crate::best_path::BestPathReason;
use crate::event::{EvpnRouteEvent, RouteEvent};
use crate::route::{
    BgpLsRibRoute, BgpLsRouteKey, EvpnRibRoute, FibInstallCandidate, FlowSpecRoute,
    LabeledRibRoute, LabeledRibRouteKey, Route, RtcRibRoute, RtcRibRouteKey, VpnRibRoute,
    VpnRibRouteKey,
};

/// Stable identity of one route tested by the exact outbound encoder.
///
/// The key deliberately contains no attributes or next-hop data: it is used
/// to maintain a per-peer rejected overlay alongside the ordinary
/// Adj-RIB-Out identity maps.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ExactExportKey {
    /// IPv4/IPv6 unicast prefix plus Add-Path identifier.
    Unicast(Prefix, u32),
    /// RFC 8955/8956 `FlowSpec` identity.
    FlowSpec(crate::route::FlowSpecKey),
    /// RFC 7432 EVPN identity.
    Evpn(EvpnRouteKey),
    /// RFC 9552 BGP-LS identity.
    BgpLs(BgpLsRouteKey),
    /// VPNv4/VPNv6 identity.
    Vpn(VpnRibRouteKey),
    /// Labeled-unicast identity.
    Labeled(LabeledRibRouteKey),
    /// RT-Constrain identity.
    Rtc(RtcRibRouteKey),
}

impl ExactExportKey {
    /// Compact diagnostic identity that never formats peer-controlled NLRI
    /// payloads. The hash is for local correlation only, not a stable API.
    #[must_use]
    pub fn bounded_log_identity(&self) -> String {
        use std::hash::{Hash, Hasher};

        if let Self::Unicast(prefix, path_id) = self {
            return format!("prefix={prefix} path_id={path_id}");
        }
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.hash(&mut hasher);
        let path_id = match self {
            Self::BgpLs(key) => key.path_id,
            Self::Vpn(key) => key.path_id,
            Self::Labeled(key) => key.path_id,
            Self::Rtc(key) => key.path_id,
            Self::Unicast(_, path_id) => *path_id,
            Self::FlowSpec(_) | Self::Evpn(_) => 0,
        };
        format!(
            "family={} path_id={path_id} key_hash={:016x}",
            self.family_label(),
            hasher.finish()
        )
    }

    /// Family NLRI identity without a session-local outbound Add-Path rank.
    ///
    /// Invariant: `RibManager::live_exact_export_nlri`
    /// (crates/rib/src/manager/mod.rs) builds its unicast live set keyed at
    /// `path_id` 0 to match this normalization. Changing the Add-Path keying
    /// here requires changing that builder too.
    #[must_use]
    pub fn nlri_identity(&self) -> Self {
        match self {
            Self::Unicast(prefix, _) => Self::Unicast(*prefix, 0),
            Self::FlowSpec(key) => Self::FlowSpec(key.clone()),
            Self::Evpn(key) => Self::Evpn(*key),
            Self::BgpLs(key) => Self::BgpLs(crate::route::BgpLsRouteKey {
                family: key.family,
                nlri: key.nlri.clone(),
                path_id: 0,
            }),
            Self::Vpn(key) => Self::Vpn(crate::route::VpnRibRouteKey {
                nlri_key: key.nlri_key,
                path_id: 0,
            }),
            Self::Labeled(key) => Self::Labeled(crate::route::LabeledRibRouteKey {
                prefix: key.prefix,
                path_id: 0,
            }),
            Self::Rtc(key) => Self::Rtc(crate::route::RtcRibRouteKey {
                nlri: key.nlri,
                path_id: 0,
            }),
        }
    }

    /// Stable low-cardinality family label used by exact-export rejection
    /// metrics. The values are deliberately constrained to the telemetry
    /// allow-list; no NLRI or peer-controlled text enters a label.
    #[must_use]
    pub fn family_label(&self) -> &'static str {
        match self {
            Self::Unicast(Prefix::V4(_), _) => "ipv4_unicast",
            Self::Unicast(Prefix::V6(_), _) => "ipv6_unicast",
            Self::FlowSpec(key) if key.afi == Afi::Ipv4 => "ipv4_flowspec",
            Self::FlowSpec(_) => "ipv6_flowspec",
            Self::Evpn(_) => "l2vpn_evpn",
            Self::BgpLs(key) if key.family == crate::route::BgpLsFamily::LinkState => "bgpls",
            Self::BgpLs(_) => "bgpls_vpn",
            Self::Vpn(key) if key.afi_safi().0 == Afi::Ipv4 => "l3vpn_ipv4_unicast",
            Self::Vpn(_) => "l3vpn_ipv6_unicast",
            Self::Labeled(key) if key.afi_safi().0 == Afi::Ipv4 => "ipv4_labeled_unicast",
            Self::Labeled(_) => "ipv6_labeled_unicast",
            Self::Rtc(_) => "rtc",
        }
    }
}

/// Borrowed, family-complete input to a session's exact export probe.
///
/// Candidates are already post-policy. The unicast next-hop override is kept
/// beside the route because it is part of the final wire representation.
#[derive(Clone, Copy)]
pub enum ExactExportCandidate<'a> {
    /// IPv4/IPv6 unicast.
    Unicast {
        /// Post-policy route.
        route: &'a Route,
        /// Post-policy next-hop action for this route.
        next_hop_override: Option<&'a rustbgpd_policy::NextHopAction>,
    },
    /// RFC 8955/8956 `FlowSpec`.
    FlowSpec(&'a FlowSpecRoute),
    /// RFC 7432 EVPN.
    Evpn(&'a EvpnRibRoute),
    /// RFC 9552 BGP-LS.
    BgpLs(&'a BgpLsRibRoute),
    /// VPNv4/VPNv6.
    Vpn(&'a VpnRibRoute),
    /// Labeled-unicast.
    Labeled(&'a LabeledRibRoute),
    /// RT-Constrain.
    Rtc(&'a RtcRibRoute),
}

impl ExactExportCandidate<'_> {
    /// Return the canonical Adj-RIB-Out identity for this candidate.
    #[must_use]
    pub fn key(&self) -> ExactExportKey {
        match self {
            Self::Unicast { route, .. } => ExactExportKey::Unicast(route.prefix, route.path_id),
            Self::FlowSpec(route) => ExactExportKey::FlowSpec(route.selection_key()),
            Self::Evpn(route) => ExactExportKey::Evpn(route.key()),
            Self::BgpLs(route) => ExactExportKey::BgpLs(route.key()),
            Self::Vpn(route) => ExactExportKey::Vpn(route.key()),
            Self::Labeled(route) => ExactExportKey::Labeled(route.key()),
            Self::Rtc(route) => ExactExportKey::Rtc(route.key()),
        }
    }
}

/// Bounded machine-readable reason for rejecting an exact export candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExactExportErrorCode {
    /// A structured wire encoder rejected the candidate.
    Encoding,
    /// No usable IPv6 next-hop exists for this session and route.
    MissingIpv6NextHop,
    /// A scoped link-local session cannot send IPv4 without RFC 8950.
    Ipv4RequiresExtendedNextHop,
    /// The one-route UPDATE exceeds the negotiated message ceiling.
    MessageTooLong,
}

impl ExactExportErrorCode {
    /// Canonical typed observability reason for this failure class.
    #[must_use]
    pub const fn reason(self) -> rustbgpd_telemetry::reason_labels::ExactExportReason {
        use rustbgpd_telemetry::reason_labels::ExactExportReason;
        match self {
            Self::Encoding => ExactExportReason::Encoding,
            Self::MissingIpv6NextHop => ExactExportReason::MissingIpv6NextHop,
            Self::Ipv4RequiresExtendedNextHop => ExactExportReason::Ipv4RequiresExtendedNextHop,
            Self::MessageTooLong => ExactExportReason::MessageTooLong,
        }
    }

    /// Stable low-cardinality label suitable for metrics and API projection.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.reason().as_str()
    }
}

/// Exact export rejection with a low-cardinality code and bounded detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactExportError {
    code: ExactExportErrorCode,
    detail: String,
}

impl ExactExportError {
    const MAX_DETAIL_CHARS: usize = 256;

    /// Construct an error while enforcing the diagnostic cardinality bound.
    #[must_use]
    pub fn new(code: ExactExportErrorCode, detail: impl std::fmt::Display) -> Self {
        let detail = detail
            .to_string()
            .chars()
            .take(Self::MAX_DETAIL_CHARS)
            .collect();
        Self { code, detail }
    }

    /// Stable rejection category.
    #[must_use]
    pub const fn code(&self) -> ExactExportErrorCode {
        self.code
    }

    /// Human-readable detail, bounded to 256 Unicode scalar values.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl std::fmt::Display for ExactExportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.detail)
    }
}

impl std::error::Error for ExactExportError {}

/// Successful exact one-route export probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExactExportResult {
    /// Encoded BGP message length including the fixed header.
    pub encoded_len: usize,
    /// Negotiated message ceiling used by the same immutable snapshot.
    pub max_len: usize,
    /// Immutable session export-profile generation used by the probe.
    pub generation: u64,
}

/// Immutable exact-export view captured once for a whole outbound envelope.
///
/// `as_any` is intentionally part of the contract: the transport must verify
/// that a RIB envelope was probed with its own concrete session profile before
/// using that same profile for live encoding.
pub trait ExactExportSnapshot: Any + Send + Sync {
    /// Stable identity of the encoder/session that produced this snapshot.
    fn owner_id(&self) -> u64;

    /// Monotonic generation of the immutable session export profile.
    fn generation(&self) -> u64;

    /// Probe one post-policy route using the exact live message builder.
    ///
    /// # Errors
    ///
    /// Returns a bounded typed error when preparation or encoding fails, or
    /// when the exact single-route message exceeds the snapshot's negotiated
    /// ceiling.
    fn probe_announcement(
        &self,
        candidate: ExactExportCandidate<'_>,
    ) -> Result<ExactExportResult, ExactExportError>;

    /// Probe an ordered batch of post-policy routes. The default preserves
    /// scalar semantics exactly; implementations may override it to share
    /// preparation work within this call. Results must have the same length
    /// and order as `candidates`.
    fn probe_announcements(
        &self,
        candidates: &[ExactExportCandidate<'_>],
    ) -> Vec<Result<ExactExportResult, ExactExportError>> {
        candidates
            .iter()
            .copied()
            .map(|candidate| self.probe_announcement(candidate))
            .collect()
    }

    /// Reapply this target snapshot's ceiling and generation to successful
    /// exact probes produced by `source`.
    ///
    /// Implementations must return `None` unless they can prove that both
    /// snapshots produce identical wire bytes for the same candidate after
    /// excluding only the target-owned message ceiling and identity fields.
    /// Probe failures are deliberately not representable here: callers may
    /// reuse only encoded lengths from successful source probes. For a
    /// wire-equivalent source/target pair, acceptance must be monotone in the
    /// encoded length: every value at or below the target's negotiated ceiling
    /// succeeds, and every longer value fails. The returned vector must
    /// preserve the input lengths' cardinality and order.
    fn reuse_successful_probes(
        &self,
        source: &dyn ExactExportSnapshot,
        encoded_lengths: &[usize],
    ) -> Option<Vec<Result<ExactExportResult, ExactExportError>>> {
        let _ = (source, encoded_lengths);
        None
    }

    /// Concrete type hook used by the owning transport at the trust boundary.
    fn as_any(&self) -> &dyn Any;
}

/// Replaceable owner of immutable exact-export snapshots.
pub trait ExactExportEncoder: Send + Sync {
    /// Stable identity used by transport to reject another session's snapshot.
    fn owner_id(&self) -> u64;

    /// Capture the profile that both RIB precommit and live envelope encoding
    /// must use without observing a mid-envelope runtime change.
    fn snapshot(&self) -> Arc<dyn ExactExportSnapshot>;
}

/// Per-peer post-policy Adj-RIB-Out route counts per AFI/SAFI —
/// the RFC 8671 BMP stat type 15/17 source.
pub type AdjRibOutCounts = HashMap<IpAddr, Vec<((Afi, Safi), u64)>>;

/// One peer's export-policy replacement inside a grouped RIB batch.
///
/// A compatible clean cohort commits atomically inside the RIB actor. An
/// ineligible or stale batch instead returns a cleaned-up handoff; the caller's
/// subsequent ordinary per-peer applies are rollback-capable, but are not
/// fleet-wide observationally atomic.
#[derive(Clone)]
pub struct PeerExportPolicyReplacement {
    /// The target peer.
    pub peer: IpAddr,
    /// New effective export policy (`None` = permit-all/global fallback resolved already).
    pub export_policy: Option<PolicyChain>,
}

/// Result of attempting an optimized export-policy cohort transition.
///
/// A handoff is fail-closed: the RIB has removed every uncommitted destination
/// and has not changed any peer policy, group membership, counter, or wire
/// state. The caller must then apply the replacements through ordinary
/// [`RibUpdate::ReplacePeerExportPolicy`] commands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportPolicyCohortOutcome {
    /// The cohort transition committed atomically.
    Committed,
    /// The optimized transition was ineligible or became stale before commit.
    RequiresAuthoritativePerPeerApply,
}

/// Once-per-update-group cell through which the first consuming session task
/// (the elected encoder) publishes its progressively encoded wire chunks so
/// every other member of the group can stream the bytes instead of
/// re-encoding the same shared announce inventory.
///
/// The payload is transport-owned and deliberately opaque here (the same
/// trust-boundary pattern as [`ExactExportSnapshot::as_any`]): the RIB only
/// guarantees that every member envelope of one grouped fanout carries the
/// same cell. Transport downcasts, proves wire-equivalence between its own
/// export profile and the encoder's, and falls back to its ordinary
/// per-session encode when the proof fails.
///
/// The lock is synchronous on purpose: initialization only *constructs* the
/// (empty) progressive stream state, so encoder election commits with no
/// await point between winning the election and starting to encode — a
/// cancelled task can never leave an initialized cell with no live encoder.
#[derive(Default)]
pub struct SharedGroupEncode {
    /// First-consumer-initializes cell; losers stream instead of re-encoding.
    pub cell: std::sync::OnceLock<Arc<dyn Any + Send + Sync>>,
}

/// Routes to be sent outbound to a peer.
#[derive(Default)]
pub struct OutboundRouteUpdate {
    /// Exact session export snapshot used to preflight every announcement in
    /// this envelope. Transport rejects an envelope whose snapshot is absent
    /// or belongs to another encoder implementation.
    pub exact_export_snapshot: Option<Arc<dyn ExactExportSnapshot>>,
    /// Optional source peer omitted from the shared unicast announce view.
    /// Set only by a preflighted clean group-transition envelope; ordinary
    /// updates materialize their already-filtered member view and leave this
    /// `None`.
    pub announce_source_exclusion: Option<IpAddr>,
    /// Routes to announce to this peer. `Arc`-shared so an update-group
    /// fanout enqueues ONE staged announce vector to every in-sync
    /// member instead of cloning the `Route` shells per member
    /// (transport only ever reads it).
    pub announce: Arc<[Route]>,
    /// Withdrawn routes with their path IDs. For non-Add-Path peers,
    /// `path_id` is always 0.
    pub withdraw: Vec<(Prefix, u32)>,
    /// End-of-RIB markers to send for these families after the route updates.
    pub end_of_rib: Vec<(Afi, Safi)>,
    /// RFC 7313 route-refresh demarcation markers to emit around the update.
    /// `BoRR` markers are sent before route payloads; `EoRR` markers after.
    pub refresh_markers: Vec<(Afi, Safi, RouteRefreshSubtype)>,
    /// Per-route next-hop override from export policy. Parallel to `announce` —
    /// `next_hop_override[i]` applies to `announce[i]`. Shared alongside it.
    pub next_hop_override: Arc<[Option<rustbgpd_policy::NextHopAction>]>,
    /// `FlowSpec` routes to announce (RFC 8955).
    pub flowspec_announce: Vec<FlowSpecRoute>,
    /// `FlowSpec` rules to withdraw.
    pub flowspec_withdraw: Vec<crate::route::FlowSpecKey>,
    /// EVPN routes to announce (RFC 7432).
    pub evpn_announce: Vec<EvpnRibRoute>,
    /// EVPN route keys to withdraw.
    pub evpn_withdraw: Vec<EvpnRouteKey>,
    /// BGP-LS routes to announce (RFC 9552).
    pub bgpls_announce: Vec<BgpLsRibRoute>,
    /// BGP-LS route keys to withdraw.
    pub bgpls_withdraw: Vec<BgpLsRouteKey>,
    /// VPNv4/VPNv6 routes to announce (RFC 4364 / RFC 4659).
    pub vpn_announce: Vec<VpnRibRoute>,
    /// VPNv4/VPNv6 route keys to withdraw.
    pub vpn_withdraw: Vec<VpnRibRouteKey>,
    /// IPv4/IPv6 labeled-unicast routes to announce (RFC 8277).
    pub labeled_announce: Vec<LabeledRibRoute>,
    /// IPv4/IPv6 labeled-unicast route keys to withdraw.
    pub labeled_withdraw: Vec<LabeledRibRouteKey>,
    /// RT-Constrain routes to announce (RFC 4684).
    pub rtc_announce: Vec<RtcRibRoute>,
    /// RT-Constrain route keys to withdraw.
    pub rtc_withdraw: Vec<RtcRibRouteKey>,
    /// Unicast routes rejected by the pre-commit RFC 9234 OTC egress gate.
    /// Transport publishes the existing per-route metric/event diagnostics
    /// but never attempts to encode these routes.
    pub otc_blocked: Vec<Route>,
    /// Ask the session task to send a ROUTE-REFRESH *request* toward the
    /// peer (RFC 2918) for **every negotiated family**, so the peer
    /// re-advertises its routes. Used by the RIB manager's
    /// outbound-registration failover: the survivor's Adj-RIB-In was
    /// cleared by the superseded session's replacement reset (the
    /// Adj-RIB-In is keyed by peer address, and while superseded the
    /// survivor's stamped `RoutesReceived` are discarded by the
    /// session-identity gate) and must be re-learned from the peer.
    ///
    /// Family selection is deliberately delegated to the session task:
    /// the manager cannot know the receive-side family set, because
    /// `PeerUp` carries only the *sendable* subset (families with a
    /// usable local next-hop), while the refresh repopulates inbound
    /// state — a family negotiated for receive but pruned from the
    /// sendable set must still be refreshed. The session task iterates
    /// its authoritative negotiated set and enforces the Route Refresh
    /// capability; for a peer without the capability the request is
    /// skipped with a warning and inbound state recovers only on the
    /// peer's natural re-advertisement.
    pub request_refresh_all_negotiated: bool,
    /// Encode-once cell shared by every member envelope of one grouped
    /// fanout (set only by the clean group-transition seam alongside
    /// `announce_source_exclusion`). `None` = ordinary per-session encode.
    pub shared_group_encode: Option<Arc<SharedGroupEncode>>,
}

/// Aggregate route-policy evaluation counters for one neighbor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NeighborPolicyStats {
    /// Import policy evaluations that permitted a route.
    pub import_policy_routes_permitted: u64,
    /// Import policy evaluations that denied a route.
    pub import_policy_routes_denied: u64,
    /// Export policy evaluations that permitted a route.
    pub export_policy_routes_permitted: u64,
    /// Export policy evaluations that denied a route.
    pub export_policy_routes_denied: u64,
}

/// Per-term hit-counter snapshot for one installed export chain
/// (`RibUpdate::QueryExportPolicyTermHits`).
#[derive(Debug, Clone)]
pub struct ExportPolicyTermHits {
    /// Peer the chain is installed for; `None` = the shared global
    /// fallback chain instance (peers evaluated against the fallback
    /// before any per-peer install).
    pub peer: Option<IpAddr>,
    /// Routes evaluated through the chain since install.
    pub evals: u64,
    /// Routes denied by an evaluation error since install (ADR-0103
    /// Decision 4 fail-closed rail).
    pub eval_errors: u64,
    /// Most recent evaluation error, rendered (`None` = no evaluation
    /// has errored since install).
    pub last_error: Option<String>,
    /// Per-term labeled hit counts, in chain walk order.
    pub terms: Vec<rustbgpd_policy::TermHitRow>,
}

/// Typed error for API-visible RIB command replies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RibCommandError {
    /// Requested RIB object does not exist.
    NotFound(String),
    /// Unexpected RIB command failure.
    Internal(String),
}

impl RibCommandError {
    #[must_use]
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::NotFound(message.into())
    }

    #[must_use]
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }
}

impl std::fmt::Display for RibCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(message) | Self::Internal(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for RibCommandError {}

/// Failure returned by an export-explain query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExplainAdvertisedRouteError {
    /// Target peer or selected source path does not exist.
    NotFound(String),
    /// The selected explain mode was not negotiated for the target peer.
    FailedPrecondition(String),
}

impl std::fmt::Display for ExplainAdvertisedRouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(message) | Self::FailedPrecondition(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for ExplainAdvertisedRouteError {}

/// Stable identity of one unicast path in an Adj-RIB-In.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RouteSourceIdentity {
    /// Peer that advertised the path.
    pub peer: IpAddr,
    /// RFC 7911 inbound path identifier. Zero is a valid identity.
    pub path_id: u32,
}

/// Structured explanation for whether a route would be advertised to a peer.
#[derive(Debug, Clone)]
pub struct ExplainAdvertisedRoute {
    /// Final decision for this peer/prefix.
    pub decision: ExplainDecision,
    /// Target peer address.
    pub peer: IpAddr,
    /// Prefix being explained.
    pub prefix: Prefix,
    /// Resolved next-hop if the route would be advertised.
    pub next_hop: Option<IpAddr>,
    /// Add-Path identifier for the advertised route.
    pub path_id: u32,
    /// Peer that originated the selected best route.
    pub route_peer: Option<IpAddr>,
    /// Selected best route type.
    pub route_type: Option<rustbgpd_policy::RouteType>,
    /// Explanation reasons, in order. Most entries are decisive; stable
    /// aggregate diagnostics may be non-decisive and say so explicitly.
    pub reasons: Vec<ExplainReason>,
    /// Export modifications that would be applied.
    pub modifications: rustbgpd_policy::RouteModifications,
    /// RFC 9107 ORR vantage the target peer is bound to. `None` when
    /// the peer has no *resolved* vantage — non-ORR explains are
    /// byte-for-byte the pre-ORR shape.
    pub orr_vantage: Option<IpAddr>,
    /// Per-vantage candidate ranking behind an ORR explain, best
    /// first — the same candidate set and order distribution would
    /// use. Empty for non-ORR explains.
    pub orr_candidates: Vec<OrrExplainCandidate>,
    /// The full export gate ladder in the exact order the live export
    /// path evaluates it, one step per gate with a pass/stop verdict.
    /// The single-best unicast and VPN ladders come from a dry-run of
    /// the *same* staging body live distribution uses.
    pub gates: Vec<ExportGateStep>,
    /// Update group the target peer's unicast export is staged under,
    /// when grouped (shared staging + per-member source-flip emit).
    /// `None` = per-peer export path.
    pub update_group_id: Option<u64>,
    /// `true` when the decision is `Advertise` but an identical route
    /// already sits in the advertised state (Adj-RIB-Out / group
    /// table), so the live path suppresses re-announcement. `false` on
    /// `Advertise` means the staged route differs and would be sent.
    /// Local send-side state only — remote acceptance is not observable.
    pub already_advertised: bool,
    /// Route Distinguisher for a VPN explain; `None` for unicast.
    pub rd: Option<rustbgpd_wire::RouteDistinguisher>,
    /// Requested Adj-RIB-In identity. `None` preserves the legacy
    /// winner-oriented explanation.
    pub source: Option<RouteSourceIdentity>,
}

/// Verdict of one export gate for one (route, peer) explain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportGateVerdict {
    /// The route cleared this gate.
    Pass,
    /// This gate stopped the route — nothing past it was evaluated.
    Stop,
    /// The gate does not apply to this peer (e.g. no export policy
    /// configured, no ORF filter installed).
    NotApplicable,
}

impl ExportGateVerdict {
    /// Stable lowercase label used by the API/CLI surfaces.
    ///
    /// The CLI's `gate_verdict_label` maps the proto enum (which adds an
    /// `Unspecified` variant) rather than reusing this across the
    /// client/server boundary — keep the two label sets in sync.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Stop => "stop",
            Self::NotApplicable => "not_applicable",
        }
    }
}

/// One rung of the export decision ladder a route traverses toward a
/// peer, in live evaluation order.
#[derive(Debug, Clone)]
pub struct ExportGateStep {
    /// Stable gate name (ladder rung), e.g. `split_horizon`,
    /// `export_policy`, `adj_rib_out`.
    pub gate: &'static str,
    /// Reason code for this step — matches the legacy
    /// `ExplainReason::code` vocabulary where one existed (e.g.
    /// `rr_non_client_to_non_client`, `policy_denied`).
    pub code: &'static str,
    /// Verdict for this gate.
    pub verdict: ExportGateVerdict,
    /// Human-readable detail (which ORF entry semantics, which policy
    /// term decided, the compared advertised state, ...).
    pub detail: String,
}

/// One candidate in an ORR (RFC 9107) advertised-route explanation.
#[derive(Debug, Clone)]
pub struct OrrExplainCandidate {
    /// Adj-RIB-In source peer of this candidate path.
    pub peer: IpAddr,
    /// Add-Path identifier of the candidate in its Adj-RIB-In.
    pub path_id: u32,
    /// Candidate's `NEXT_HOP` — the input to the vantage cost lookup.
    pub next_hop: IpAddr,
    /// Vantage interior (SPF) cost to `next_hop`. `None` = unknown /
    /// unreachable, ranked least preferred (RFC 9107 §3.1).
    pub cost: Option<u64>,
    /// True for the per-vantage winner (first in ORR best-path order).
    pub selected: bool,
}

/// Final decision for an advertised-route explanation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExplainDecision {
    Advertise,
    Deny,
    NoBestRoute,
    UnsupportedFamily,
}

/// One reason in an advertised-route explanation. A reason may be an
/// explicitly labeled aggregate/non-decisive diagnostic.
#[derive(Debug, Clone)]
pub struct ExplainReason {
    pub code: &'static str,
    pub message: String,
}

/// Structured explanation of why a particular route was or was not selected as best.
#[derive(Debug, Clone)]
pub struct ExplainBestPath {
    /// Prefix being explained.
    pub prefix: Prefix,
    /// The best route for this prefix, if one exists.
    pub best: Option<Route>,
    /// All candidates with their comparison against the best route.
    pub candidates: Vec<BestPathCandidate>,
    /// Peer this explanation was scoped to, when the request named one.
    /// `None` = global Loc-RIB view (the pre-Add-Path explain shape).
    pub peer: Option<IpAddr>,
    /// Peer's Add-Path `send_max` when scoped to a peer (`0` =
    /// single-best send, or global view). When non-zero, the top
    /// `add_path_send_max` candidates by best-path preference get a
    /// non-zero `BestPathCandidate::advertised_path_id`.
    pub add_path_send_max: u32,
    /// The decision step that selected the winner over the runner-up —
    /// the last surviving competitor by best-path order. `None` when
    /// the prefix has no competing path (single-path trivial winner) or
    /// no best route at all.
    pub best_reason: Option<BestPathReason>,
    /// Compared values behind `best_reason`, winner's value first
    /// (e.g. `"local_pref 200 > 100"`). Empty when `best_reason` is
    /// `None`.
    pub best_reason_detail: String,
}

/// A candidate route with its comparison result against the best route.
#[derive(Debug, Clone)]
pub struct BestPathCandidate {
    /// The candidate route.
    pub route: Route,
    /// Which decision step determined the ordering vs. the best route.
    pub vs_best_reason: BestPathReason,
    /// How this candidate compares to the best route.
    pub vs_best_ordering: std::cmp::Ordering,
    /// When the explain was scoped to a peer with Add-Path send mode
    /// (`add_path_send_max > 0`), non-zero = this candidate would be
    /// advertised at this rank (1-based, capped at
    /// `add_path_send_max`); zero = filtered out by the peer's
    /// export policy / family check / split-horizon / iBGP or
    /// RFC 4456 route-reflector suppression, or beyond `send_max`.
    /// Always zero in single-best send mode
    /// (`add_path_send_max == 0`) and on a global-view explain —
    /// see `ExplainBestPath::add_path_send_max` for why single-best
    /// can't be expressed through this field.
    pub advertised_path_id: u32,
    /// Compared values behind `vs_best_reason`, candidate's value
    /// first (e.g. `"local_pref 100 < 200"`).
    pub vs_best_detail: String,
    /// Whether this candidate survives the equal-cost multipath cut
    /// vs the best route (strict / relax-only / not at all).
    pub multipath: crate::best_path::MultipathEligibility,
}

/// Which table a paged route query ([`RibUpdate::QueryRoutesPage`]) reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteQueryScope {
    /// Adj-RIB-In routes, optionally narrowed to one peer.
    Received {
        /// Optional peer filter; `None` reads all peers.
        peer: Option<IpAddr>,
    },
    /// Loc-RIB best routes.
    Best,
    /// Routes advertised to a specific peer (Adj-RIB-Out, or the
    /// synthesized view for an update-grouped member).
    Advertised {
        /// The target peer.
        peer: IpAddr,
    },
}

/// Resume cursor for a paged route query: the identity key of the last
/// route on the previous page. The tuple's derived total order carries
/// no routing meaning; it exists so stable cursors can be cut through
/// the unordered route tables (see the `Ord` note on [`Prefix`]).
pub type RouteQueryKey = (Prefix, IpAddr, u32);

/// Identity key of a route within a paged-query scope.
#[must_use]
pub fn route_query_key(route: &Route) -> RouteQueryKey {
    (route.prefix, route.peer, route.path_id)
}

/// Row filter evaluated inside the RIB task during a paged route query.
pub type RouteQueryFilter = Box<dyn Fn(&Route) -> bool + Send + Sync>;

/// Process-local scope-class mutation version bound into an opaque route-page
/// token. The manager owns one conservative version each for Received, Best,
/// and Advertised views, so a peer-specific walk may also be invalidated by an
/// unrelated mutation in the same class. `epoch` advances when the generation
/// counter rolls over; exhausting both words disables continuation rather than
/// silently reusing a version.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RoutePageVersion {
    pub epoch: u64,
    pub generation: u64,
}

/// A route-page continuation could not be served safely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutePageError {
    /// The requested scope class changed after the preceding page. Callers
    /// must restart from an empty token rather than risk skipped or duplicate
    /// rows.
    Invalidated,
    /// The process-local version space was exhausted. This fail-closed state
    /// is reachable only through fault injection in practice.
    GenerationExhausted,
}

/// One page of a resumable route query.
#[derive(Debug, Clone, Default)]
pub struct RoutePage {
    /// Routes on this page, ascending by identity key.
    pub routes: Vec<Route>,
    /// Total filter-matching routes in scope (cursor-independent).
    pub total: u64,
    /// Whether matching routes remain beyond this page.
    pub has_more: bool,
    /// Mutation version that must accompany the next continuation request.
    pub version: RoutePageVersion,
}

/// Effective live unicast distribution mode for a registered peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveDistributionMode {
    /// The peer has no active outbound registration.
    Unknown,
    /// Ordinary Loc-RIB single-best distribution.
    SingleBest,
    /// Negotiated Add-Path send is active for at least one family.
    AddPath,
    /// RFC 9107 ORR is active with a resolved vantage.
    Orr,
    /// RFC 7947 per-client-best export is active.
    PerClientBest,
}

/// Atomic neighbor-facing snapshot of live outbound RIB state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerOutboundState {
    /// Update-group membership label, or empty when unregistered.
    pub update_group: String,
    /// Effective live distribution mode.
    pub effective_distribution_mode: EffectiveDistributionMode,
    /// Process-start RFC 4724 selection-deferral state, one row per family.
    pub selection_deferral: Vec<SelectionDeferralPeerFamilyState>,
    /// ADR-0113 outbound unicast capacity, one row per limited family.
    pub outbound_prefix_limits: Vec<OutboundPrefixLimitFamilyState>,
}

/// One neighbor's RIB-owned fields returned by the aggregate operator
/// snapshot query.  These fields must be read in one RIB actor turn so an
/// API response never joins advertised, policy, and outbound state from
/// different generations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborRibSnapshot {
    /// Peer whose outbound state was read.
    pub peer: IpAddr,
    /// Prefixes currently advertised to this peer.
    pub advertised_count: usize,
    /// Route-policy evaluation counters for this peer.
    pub policy_stats: NeighborPolicyStats,
    /// Live outbound registration and capacity state.
    pub outbound: PeerOutboundState,
}

/// One actor-turn response for `NeighborService`'s RIB-owned state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborRibSnapshotResponse {
    /// Snapshot rows in request order.
    pub snapshots: Vec<NeighborRibSnapshot>,
    /// Optional update-group comparison requested with the primary snapshot.
    pub comparison: Option<UpdateGroupPeerComparison>,
}

/// Neighbor-facing ADR-0113 outbound capacity for one unicast family.
///
/// `usage` is the post-policy, post-OTC, post-exact-export admitted
/// unique-prefix count — the same truth advertised-route queries report,
/// never the shared update-group table's count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundPrefixLimitFamilyState {
    /// `ipv4_unicast` or `ipv6_unicast`.
    pub family: String,
    /// Distinct prefixes currently admitted for this family.
    pub usage: u64,
    /// Configured maximum; `None` is unlimited, never a synthesized zero.
    pub limit: Option<u32>,
    /// Saturating `limit - usage`; `None` while unlimited.
    pub headroom: Option<u32>,
    /// Whether a blocking episode is open for this family.
    pub blocking: bool,
}

/// Stable reason reported while a family's outbound limit is blocking.
pub const OUTBOUND_PREFIX_LIMIT_REACHED: &str = "outbound_prefix_limit_reached";

/// One configuration level's outbound unicast maxima (ADR-0113).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OutboundPrefixLimitPair {
    /// IPv4-unicast maximum (`None` = unlimited).
    pub ipv4: Option<NonZeroU32>,
    /// IPv6-unicast maximum (`None` = unlimited).
    pub ipv6: Option<NonZeroU32>,
}

impl OutboundPrefixLimitPair {
    /// This level's value for one family, or `None` outside unicast.
    #[must_use]
    pub fn family(self, afi: Afi) -> Option<NonZeroU32> {
        match afi {
            Afi::Ipv4 => self.ipv4,
            Afi::Ipv6 => self.ipv6,
            _ => None,
        }
    }
}

/// The resolver tables an outbound prefix-limit edit installs.
///
/// The RIB manager resolves each live peer itself — a neighbor entry
/// overrides its peer group, an absent neighbor entry inherits, and an
/// absent effective value is unlimited — so an accepted dynamic child
/// inherits the same effective values as a static member of its group
/// without the caller enumerating live sessions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutboundPrefixLimitConfig {
    /// Per-neighbor overrides, keyed by neighbor address.
    pub neighbors: HashMap<IpAddr, OutboundPrefixLimitPair>,
    /// Peer-group defaults, keyed by group name.
    pub groups: HashMap<String, OutboundPrefixLimitPair>,
}

/// One family that cannot accept its candidate limit because the peer
/// already advertises more than it (ADR-0113: lowering is not an implicit
/// pruning policy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundPrefixLimitViolation {
    /// The peer whose advertised state blocks the edit.
    pub peer: IpAddr,
    /// `ipv4_unicast` or `ipv6_unicast`.
    pub family: String,
    /// Distinct prefixes currently advertised.
    pub usage: u64,
    /// The candidate the operator asked for.
    pub requested: u32,
}

impl std::fmt::Display for OutboundPrefixLimitViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} advertises {} prefixes, above the requested maximum {}",
            self.peer, self.family, self.usage, self.requested
        )
    }
}

/// Neighbor-facing RFC 4724 selection-deferral state for one family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionDeferralPeerFamilyState {
    pub afi: Afi,
    pub safi: Safi,
    pub active: bool,
    pub waiter_state: String,
    pub waiter_session_id: Option<u64>,
    pub blocking_waiters: u64,
    pub remaining_millis: u64,
    pub release_reason: String,
}

/// Messages sent from peer sessions to the RIB manager.
pub enum RibUpdate {
    /// Peer session sent us routes.
    RoutesReceived {
        /// Source peer address.
        peer: IpAddr,
        /// Transport session identity (peer-manager scoped generation) of
        /// the session that received these routes. The RIB manager
        /// discards a batch whose id doesn't match the peer's registered
        /// session, so routes from a superseded session (RFC 4271 §6.8
        /// collision loser) queued behind the winner's `PeerUp` cannot
        /// land in the replacement session's Adj-RIB-In. `0` = legacy
        /// emitters without identity tracking (degrades to the
        /// pre-stamping accept behavior; see `PeerDown::session_id`).
        session_id: u64,
        /// Newly announced routes.
        announced: Vec<Route>,
        /// Withdrawn prefixes with Add-Path path identifiers.
        /// `(prefix, path_id)` — `path_id = 0` for non-Add-Path peers.
        withdrawn: Vec<(Prefix, u32)>,
        /// `FlowSpec` routes announced (RFC 8955).
        flowspec_announced: Vec<FlowSpecRoute>,
        /// `FlowSpec` rules withdrawn.
        flowspec_withdrawn: Vec<crate::route::FlowSpecKey>,
        /// EVPN routes announced (RFC 7432).
        evpn_announced: Vec<EvpnRibRoute>,
        /// EVPN route keys withdrawn.
        evpn_withdrawn: Vec<EvpnRouteKey>,
    },
    /// Peer session sent us BGP-LS routes (RFC 9552).
    BgpLsRoutesReceived {
        /// Source peer address.
        peer: IpAddr,
        /// Transport session identity of the session that received these routes.
        session_id: u64,
        /// Newly announced BGP-LS routes.
        announced: Vec<BgpLsRibRoute>,
        /// Withdrawn BGP-LS route keys.
        withdrawn: Vec<BgpLsRouteKey>,
    },
    /// Peer session sent us VPNv4/VPNv6 routes (RFC 4364 / RFC 4659).
    VpnRoutesReceived {
        /// Source peer address.
        peer: IpAddr,
        /// Transport session identity of the session that received these routes.
        session_id: u64,
        /// Newly announced VPN routes.
        announced: Vec<VpnRibRoute>,
        /// Withdrawn VPN route keys.
        withdrawn: Vec<VpnRibRouteKey>,
    },
    /// Peer session sent us IPv4/IPv6 labeled-unicast routes (RFC 8277).
    LabeledRoutesReceived {
        /// Source peer address.
        peer: IpAddr,
        /// Transport session identity of the session that received these routes.
        session_id: u64,
        /// Newly announced labeled routes.
        announced: Vec<LabeledRibRoute>,
        /// Withdrawn labeled route keys.
        withdrawn: Vec<LabeledRibRouteKey>,
    },
    /// Peer session sent us RT-Constrain routes (RFC 4684).
    RtcRoutesReceived {
        /// Source peer address.
        peer: IpAddr,
        /// Transport session identity of the session that received these routes.
        session_id: u64,
        /// Newly announced RT-Constrain routes.
        announced: Vec<RtcRibRoute>,
        /// Withdrawn RT-Constrain route keys.
        withdrawn: Vec<RtcRibRouteKey>,
    },
    /// Peer session went down — clear all routes from this peer.
    PeerDown {
        /// The peer whose session went down.
        peer: IpAddr,
        /// Transport session identity (peer-manager scoped generation) of
        /// the session that went down. The RIB manager discards a
        /// `PeerDown` whose id doesn't match the currently registered
        /// session, so a stale collision-loser teardown (RFC 4271 §6.8)
        /// processed after the winner's `PeerUp` cannot destroy the
        /// surviving session's state. `0` = legacy emitters without
        /// identity tracking (every session of such an emitter shares
        /// id 0, which degrades to the pre-stamping behavior).
        session_id: u64,
    },
    /// Peer was *deleted* from the configuration (not a session flap):
    /// after clearing any remaining per-peer state, remove the peer's
    /// metric label sets so the exposition stops advertising a peer
    /// that no longer exists. The delete path queues this behind the
    /// session's own `PeerDown`, so it is processed after the teardown
    /// emissions it cleans up.
    PeerDeleted {
        /// The peer that was deleted.
        peer: IpAddr,
    },
    /// Peer session established — register for outbound updates.
    PeerUp {
        /// The peer whose session came up.
        peer: IpAddr,
        /// Transport session identity (peer-manager scoped generation).
        /// Recorded by the RIB manager at registration so that later
        /// `PeerDown`/`PeerGracefulRestart` events can be matched to the
        /// session that emitted them (see `PeerDown::session_id`).
        session_id: u64,
        /// Peer's remote ASN (for MRT `PEER_INDEX_TABLE`).
        peer_asn: u32,
        /// Peer's BGP router ID.
        peer_router_id: Ipv4Addr,
        /// Channel to send outbound route updates to this peer's transport.
        outbound_tx: mpsc::Sender<OutboundRouteUpdate>,
        /// Export policy chain applied before sending routes to this peer.
        export_policy: Option<PolicyChain>,
        /// Address families that the transport can actually serialize for this
        /// peer. Routes whose AFI is not in this list are filtered out of
        /// Adj-RIB-Out, preventing divergence between RIB state and wire.
        sendable_families: Vec<(Afi, Safi)>,
        /// Whether this peer is eBGP (true) or iBGP (false).
        is_ebgp: bool,
        /// Whether this peer is a route reflector client (RFC 4456).
        route_reflector_client: bool,
        /// Optimal Route Reflection vantage point (RFC 9107) configured
        /// for this route-reflector-client, if any: an IP identifying the
        /// client's IGP location as a BGP-LS topology node.
        orr_vantage: Option<IpAddr>,
        /// RFC 7947 §2.3.2 per-client best-path for a route-server
        /// client: unicast export stages the first export-policy-
        /// permitted candidate (path-hiding mitigation) instead of the
        /// Loc-RIB best. Families with negotiated Add-Path send take the
        /// multipath path instead (a negotiated capability outranks the
        /// fallback).
        per_client_best: bool,
        /// RFC 1997 `NO_EXPORT`/`NO_EXPORT_SUBCONFED` egress enforcement
        /// for this peer: when `true` and the peer is eBGP, source routes
        /// carrying either community are suppressed at staging. Resolved
        /// in config (default `!route_server_client`).
        interpret_rfc1997: bool,
        /// Families for which this peer negotiated Add-Path Send/Both.
        /// Multi-path export is only enabled for these families.
        add_path_send_families: Vec<(Afi, Safi)>,
        /// Maximum paths per prefix to send via Add-Path (0 = single-best only).
        add_path_send_max: u32,
        /// Families for which the peer negotiated sending us Address-Prefix ORF
        /// entries (RFC 5291/5292). Initial advertisement for these families is
        /// gated until the peer sends a ROUTE-REFRESH (RFC 5291 §6).
        negotiated_orf_recv: Vec<(Afi, Safi)>,
        /// Families for which the peer advertised the Long-Lived Graceful
        /// Restart capability (RFC 9494). LLGR-stale routes must not be
        /// advertised to an eBGP peer whose family is absent from this
        /// list (RFC 9494 §4.4 export restriction); iBGP peers take the
        /// §4.6 `NO_EXPORT` + `LOCAL_PREF`-0 form instead, applied in
        /// transport.
        negotiated_llgr_families: Vec<(Afi, Safi)>,
    },
    /// Family-local effective Add-Path caps after applying peer Paths-Limit.
    PeerAddPathLimits {
        /// Peer address.
        peer: IpAddr,
        /// Transport session identity; stale sessions are ignored.
        session_id: u64,
        /// Effective limit per negotiated Add-Path send family.
        limits: Vec<((Afi, Safi), u32)>,
    },
    /// Peer pushed Address-Prefix ORF entries via ROUTE-REFRESH (RFC 5291).
    /// Install/update the per-peer outbound prefix filter for `(afi, safi)` and
    /// re-evaluate this peer's Adj-RIB-Out.
    PeerOrfUpdate {
        /// The peer that sent the ORF entries.
        peer: IpAddr,
        /// Transport session identity of the emitting session. ORF state
        /// is per-session (RFC 5291), so a stale ORF push from a
        /// superseded session is discarded rather than installed as the
        /// replacement session's outbound filter (see
        /// `RoutesReceived::session_id`).
        session_id: u64,
        /// Address family of the ORF section.
        afi: Afi,
        /// Sub-address family of the ORF section.
        safi: Safi,
        /// When-to-refresh directive: IMMEDIATE sweeps now, DEFER installs only.
        when: WhenToRefresh,
        /// The ORF entries, in wire order (mix of ADD/REMOVE/REMOVE-ALL).
        entries: Vec<AddressPrefixOrf>,
        /// Completion reply.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Peer session's slow-peer flag changed (LAN-470). Sent only when
    /// `slow_peer_isolation` is configured for the peer: `slow = true`
    /// moves the peer onto the per-peer (ungrouped) update path so it
    /// stops holding back its update-group's shared encode; `false`
    /// regroups it through the ordinary regroup baseline-diff seam.
    PeerSlowState {
        /// The peer whose slow flag changed.
        peer: IpAddr,
        /// Transport session identity of the emitting session — a stale
        /// signal from a superseded session must not (de)isolate the
        /// replacement session (see `RoutesReceived::session_id`).
        session_id: u64,
        /// The new slow-flag value.
        slow: bool,
    },
    /// Update per-peer policy identity metadata used during export policy evaluation.
    SetPeerPolicyContext {
        /// Peer whose policy identity is being updated.
        peer: IpAddr,
        /// Transport session identity that emitted the update.
        session_id: u64,
        /// Optional peer-group membership.
        peer_group: Option<String>,
    },
    /// Session-bound export context needed before the initial Adj-RIB-Out
    /// build. Sent immediately before `PeerUp`; the session id prevents a
    /// collision loser from overwriting the winner's role.
    SetPeerExportContext {
        /// Peer whose export context is being staged.
        peer: IpAddr,
        /// Transport session identity that will accompany `PeerUp`.
        session_id: u64,
        /// Local RFC 9234 BGP Role, if configured.
        local_role: Option<BgpRole>,
    },
    /// Stage the session's RFC 7947 §2.3.2 route-server control-community
    /// context immediately before [`RibUpdate::PeerUp`] builds the initial
    /// Adj-RIB-Out. The session id prevents a collision loser from
    /// overwriting the winner's context. Absent (never sent, or sent as
    /// `None`) means the session does not interpret control communities.
    SetPeerRsControl {
        /// Peer whose control-community context is being staged.
        peer: IpAddr,
        /// Transport session identity that will accompany `PeerUp`.
        session_id: u64,
        /// The route server's local ASN for this session when
        /// `rs_control_communities` is enabled; `None` disables
        /// interpretation (full transparency).
        rs_control_asn: Option<u32>,
    },
    /// Stage the session's exact outbound encoder immediately before
    /// [`RibUpdate::PeerUp`] builds the initial Adj-RIB-Out. The session id
    /// prevents a queued collision loser from replacing the winner's encoder.
    SetPeerExportEncoder {
        /// Peer whose exact encoder is being staged.
        peer: IpAddr,
        /// Transport session identity that will accompany `PeerUp`.
        session_id: u64,
        /// Session-owned replaceable encoder.
        encoder: Arc<dyn ExactExportEncoder>,
    },
    /// Stage the peer's negotiated GR context before `PeerUp` builds any
    /// outbound state. The startup selection-deferral roster uses this to
    /// exclude Restart-State/non-GR peers and stamp the remaining `EoR` waiter.
    SetPeerGracefulRestartContext {
        /// Peer whose OPEN was negotiated.
        peer: IpAddr,
        /// Transport generation that owns this immutable OPEN context.
        session_id: u64,
        /// Peer's RFC 4724 Restart State bit.
        peer_restart_state: bool,
        /// Negotiated families present in the peer's GR capability.
        peer_gr_families: Vec<(Afi, Safi)>,
        /// Peer negotiated enhanced route refresh (RFC 7313), so a
        /// collision-failback convergence wait on `BoRR`/`EoRR` is
        /// fulfillable.
        peer_enhanced_refresh: bool,
    },
    /// Inject a locally-originated route.
    InjectRoute {
        /// The route to inject.
        route: Route,
        /// Completion reply.
        reply: oneshot::Sender<Result<(), RibCommandError>>,
    },
    /// Withdraw a locally-injected route.
    WithdrawInjected {
        /// Prefix to withdraw.
        prefix: Prefix,
        /// Add-Path path identifier (0 = default path).
        path_id: u32,
        /// Completion reply.
        reply: oneshot::Sender<Result<(), RibCommandError>>,
    },
    /// Query: return all received routes, optionally filtered by peer.
    QueryReceivedRoutes {
        /// Optional peer filter; `None` returns all peers.
        peer: Option<IpAddr>,
        /// Response channel.
        reply: oneshot::Sender<Vec<Route>>,
    },
    /// Query: one bounded page of a resumable route listing. Filtering
    /// and pagination run inside the RIB task with per-page bounded
    /// allocation. Continuations are mutation-fenced: a change in the
    /// manager's conservative Received, Best, or Advertised scope class
    /// returns [`RoutePageError::Invalidated`] instead of serving a torn walk.
    /// The reply channel doubles as the cancellation token: an
    /// abandoned caller (dropped receiver) skips the scan entirely.
    QueryRoutesPage {
        /// Which table to read.
        scope: RouteQueryScope,
        /// Optional row filter evaluated inside the RIB task; `None`
        /// keeps every route in scope.
        filter: Option<RouteQueryFilter>,
        /// Resume strictly after this key; `None` starts from the
        /// beginning.
        after: Option<RouteQueryKey>,
        /// Mutation version decoded from the continuation token. `None`
        /// starts a new walk at the scope's current version.
        expected_version: Option<RoutePageVersion>,
        /// Maximum routes on the page (clamped to a server-side cap).
        page_size: usize,
        /// Response channel; a dropped receiver cancels the query.
        reply: oneshot::Sender<Result<RoutePage, RoutePageError>>,
    },
    /// Query: return best routes from the Loc-RIB.
    QueryBestRoutes {
        /// Response channel.
        reply: oneshot::Sender<Vec<Route>>,
    },
    /// Query: return per-prefix FIB install candidates — the best route plus
    /// its equal-cost (ECMP) next-hop set, bounded by `max_paths`. The
    /// deliberate install-candidate view ADR-0066 builds multipath on.
    QueryFibInstallCandidates {
        /// Max equal-cost next-hops per prefix (per-table `maximum_paths`).
        max_paths: u32,
        /// ADR-0066 multipath-relax: group equal-cost candidates by `AS_PATH`
        /// *length* rather than an exact `AS_PATH` match (global best-path knob).
        relax: bool,
        /// ADR-0068 weighted multipath: when the whole equal-cost group carries a
        /// Link Bandwidth Extended Community, weight next-hops in proportion to
        /// it; otherwise every next-hop stays weight 1 (equal cost).
        weighted: bool,
        /// Response channel.
        reply: oneshot::Sender<Vec<FibInstallCandidate>>,
    },
    /// Query: return the current per-peer peer-group map.
    QueryPeerGroups {
        /// Response channel.
        reply: oneshot::Sender<HashMap<IpAddr, String>>,
    },
    /// Query: return routes advertised to a specific peer.
    QueryAdvertisedRoutes {
        /// The target peer.
        peer: IpAddr,
        /// Response channel.
        reply: oneshot::Sender<Vec<Route>>,
    },
    /// Query: explain why a particular route was selected as best for a prefix.
    ExplainBestPath {
        /// Prefix to explain.
        prefix: Prefix,
        /// Optional peer scope (Add-Path send view). When `Some`, the
        /// response shape is unchanged from the global form: the
        /// Loc-RIB best stays in `best`, and `candidates` lists
        /// every *non-best* route the RIB knows about (the winner is
        /// never repeated in `candidates`). The peer scope adds
        /// per-candidate advertisement tagging:
        /// `advertised_path_id != 0` is set only on candidates that
        /// the named peer would actually receive — i.e. those that
        /// pass the peer's export policy + sendable-family check +
        /// split-horizon / RR suppression and that fall within the
        /// peer's effective `add_path_send_max`. Candidates beyond
        /// the cap or rejected by the filters stay at
        /// `advertised_path_id = 0` so the operator can see *why*
        /// each isn't advertised. Note that ranks in `candidates`
        /// may start at 2 when the Loc-RIB winner (in `best`) is
        /// itself advertised at rank 1 to the peer; rank 1 is
        /// therefore not always present in the candidates list.
        /// When `None`, returns the global Loc-RIB view (every
        /// candidate carries `advertised_path_id = 0`).
        peer: Option<IpAddr>,
        /// Response channel. `None` = unknown peer (peer was set but
        /// not registered with this RIB).
        reply: oneshot::Sender<Option<ExplainBestPath>>,
    },
    /// Query: explain whether the current best route for a prefix would be advertised to a peer.
    ExplainAdvertisedRoute {
        /// The target peer.
        peer: IpAddr,
        /// Prefix to explain. For a VPN explain (`rd` set) this is the
        /// RD-scoped inner prefix.
        prefix: Prefix,
        /// `Some` = explain the VPNv4/VPNv6 (SAFI 128) route identified
        /// by `(rd, prefix)` instead of the plain unicast prefix.
        rd: Option<rustbgpd_wire::RouteDistinguisher>,
        /// `true` = explain the labeled-unicast (SAFI 4, RFC 8277) route
        /// for `prefix` instead of the plain unicast prefix. Mutually
        /// exclusive with `rd` (callers validate; `rd` wins here).
        labeled: bool,
        /// Optional exact Adj-RIB-In path to explain. Supported only for
        /// negotiated unicast Add-Path send.
        source: Option<RouteSourceIdentity>,
        /// Response channel.
        reply: oneshot::Sender<Result<ExplainAdvertisedRoute, ExplainAdvertisedRouteError>>,
    },
    /// Subscribe to route change events via broadcast channel.
    SubscribeRouteEvents {
        /// Response channel carrying the broadcast receiver.
        reply: oneshot::Sender<broadcast::Receiver<RouteEvent>>,
    },
    /// Query recent route change events from the bounded in-memory history.
    QueryRouteEventHistory {
        /// Optional peer filter. Matches both the current and previous
        /// best-path peer so peer-scoped queries include withdraws and
        /// best-path moves away from the peer.
        peer: Option<IpAddr>,
        /// Optional address-family filter. `None` = all unicast families.
        afi: Option<Afi>,
        /// Optional exact prefix filter. `None` = all unicast prefixes.
        prefix: Option<Prefix>,
        /// Maximum events to return from the recent window. 0 = manager default.
        limit: usize,
        /// Response channel carrying events ordered oldest-to-newest within
        /// the selected recent window.
        reply: oneshot::Sender<Vec<RouteEvent>>,
    },
    /// Subscribe to EVPN best-path change events. Distinct from
    /// `SubscribeRouteEvents` because EVPN routes are keyed by
    /// `EvpnRouteKey`, not `Prefix`, and the event payload carries
    /// the full new best path so subscribers (e.g., the daemon's
    /// local-MAC originator) don't need a follow-up RIB query to
    /// build a `RemoteMacView`.
    SubscribeEvpnRouteEvents {
        /// Response channel carrying the broadcast receiver.
        reply: oneshot::Sender<broadcast::Receiver<EvpnRouteEvent>>,
    },
    /// Query recent EVPN best-path change events from the bounded in-memory history.
    QueryEvpnRouteEventHistory {
        /// Optional peer filter. Matches both the current and previous best-path peer.
        peer: Option<IpAddr>,
        /// Optional EVPN route type filter. `None` = all route types.
        route_type: Option<u8>,
        /// Optional Route Distinguisher filter. `None` = all RDs.
        rd: Option<rustbgpd_wire::RouteDistinguisher>,
        /// Optional event type filter. Empty = all EVPN event types.
        event_types: std::collections::BTreeSet<crate::event::RouteEventType>,
        /// Maximum events to return from the recent window. 0 = manager default.
        limit: usize,
        /// Response channel carrying events ordered oldest-to-newest within
        /// the selected recent window.
        reply: oneshot::Sender<Vec<EvpnRouteEvent>>,
    },
    /// End-of-RIB marker received from a peer for a given address family.
    EndOfRib {
        /// The peer that sent the `EoR`.
        peer: IpAddr,
        /// Transport session identity of the emitting session. A stale
        /// `EoR` from a superseded session must not complete the
        /// registered session's GR/LLGR stale sweep for the family (see
        /// `RoutesReceived::session_id`).
        session_id: u64,
        /// Address family identifier.
        afi: Afi,
        /// Subsequent address family identifier.
        safi: Safi,
    },
    /// Peer entered graceful restart — preserve routes but mark stale.
    PeerGracefulRestart {
        /// The restarting peer.
        peer: IpAddr,
        /// Transport session identity (peer-manager scoped generation) of
        /// the session that went down with GR. Subject to the same
        /// stale-teardown discard rule as `PeerDown::session_id` — a GR
        /// flap from a superseded session must not mark the surviving
        /// session's routes stale. When the id matches, GR stale-path
        /// retention behaves exactly as before stamping.
        session_id: u64,
        /// Peer's advertised restart time (seconds).
        restart_time: u16,
        /// Our configured stale routes time (seconds).
        stale_routes_time: u64,
        /// All families from the peer's Graceful Restart capability.
        gr_families: Vec<(Afi, Safi)>,
        /// Whether the peer supports Long-Lived Graceful Restart (RFC 9494).
        peer_llgr_capable: bool,
        /// Per-family LLGR stale times from the peer's capability.
        peer_llgr_families: Vec<rustbgpd_wire::LlgrFamily>,
        /// Our configured LLGR stale time (seconds). 0 = disabled.
        llgr_stale_time: u32,
    },
    /// Query: return the number of prefixes in the Loc-RIB.
    QueryLocRibCount {
        /// Response channel.
        reply: oneshot::Sender<usize>,
    },
    /// Query: return every peer's post-policy Adj-RIB-Out route counts
    /// per AFI/SAFI — the source for RFC 8671 BMP stat types 15/17.
    QueryAdjRibOutCounts {
        /// Response channel: peer -> `((afi, safi), count)` entries.
        reply: oneshot::Sender<AdjRibOutCounts>,
    },
    /// Query: return the number of prefixes advertised to a specific peer.
    QueryAdvertisedCount {
        /// The target peer.
        peer: IpAddr,
        /// Response channel.
        reply: oneshot::Sender<usize>,
    },
    /// Query: how many of a peer's Adj-RIB-In routes are still retained as
    /// Graceful Restart or Long-Lived Graceful Restart stale.
    ///
    /// ADR-0112 needs this before it lets a live RFC 8212 import-presence edit
    /// touch a peer that is not Established. Session-local route bookkeeping
    /// cannot answer it: the session actor can have cleared its own route set
    /// while the RIB still serves the routes it learned under the prior policy,
    /// and re-evaluating those against a new verdict is exactly the pairing the
    /// ADR forbids.
    QueryPeerRetainedStale {
        /// The target peer.
        peer: IpAddr,
        /// Response channel.
        reply: oneshot::Sender<usize>,
    },
    /// Query: return aggregate route-policy counters for a specific peer.
    QueryNeighborPolicyStats {
        /// The target peer.
        peer: IpAddr,
        /// Response channel.
        reply: oneshot::Sender<NeighborPolicyStats>,
    },
    /// Query a peer's live shared-group label, private-path reason
    /// (`policy_peer_context`, `add_path_send`, `per_client_best`,
    /// `orr_vantage`, `orf_installed`, or recoverable `slow_peer`), or empty
    /// when no outbound registration exists.
    QueryPeerUpdateGroup {
        /// The target peer.
        peer: IpAddr,
        /// Response channel.
        reply: oneshot::Sender<String>,
    },
    /// Query: atomically return neighbor-facing live outbound state.
    QueryPeerOutboundState {
        /// The target peer.
        peer: IpAddr,
        /// Response channel.
        reply: oneshot::Sender<PeerOutboundState>,
    },
    /// Query: atomically return every RIB-owned field `NeighborService` exposes
    /// for a set of peers, plus an optional update-group comparison.  One
    /// actor turn avoids per-peer request amplification and mixed-generation
    /// rows in `ListNeighbors` and `GetNeighborState`.
    QueryNeighborRibSnapshots {
        /// Peers to snapshot, in the desired response order.
        peers: Vec<IpAddr>,
        /// Optional `(primary, comparison)` update-group comparison.
        comparison: Option<(IpAddr, IpAddr)>,
        /// Response channel.
        reply: oneshot::Sender<NeighborRibSnapshotResponse>,
    },
    /// Side-effect-free snapshot used by config impact planning.
    QueryUpdateGroupSnapshot {
        reply: oneshot::Sender<UpdateGroupSnapshot>,
    },
    /// Query: compare two live update-group registrations in one actor turn.
    QueryUpdateGroupComparison {
        primary: IpAddr,
        comparison: IpAddr,
        reply: oneshot::Sender<UpdateGroupPeerComparison>,
    },
    /// TEST ONLY: a peer's advertised VPN view recomputed from manager
    /// state — the Φ-filtered group table for a VPN-grouped member, the
    /// per-peer Adj-RIB-Out otherwise. The update-groups oracle's
    /// invariant checker (design §5) compares this against the folded
    /// emitted stream after every scenario step.
    #[cfg(test)]
    TestQueryVpnAdvertised {
        /// The target peer.
        peer: IpAddr,
        /// Response channel: `(Debug-formatted VpnRouteKey, source peer)`.
        reply: oneshot::Sender<Vec<(String, IpAddr)>>,
    },
    /// TEST ONLY: transient outbound-distribution state that must be
    /// empty after a differential-oracle scenario reaches quiescence.
    #[cfg(test)]
    TestQueryOutboundHealth {
        /// Response channel: dirty peers, forced peers, group-dirty members,
        /// group tombstones, regroup baselines, and carried extra-withdraw
        /// residue, respectively.
        reply: oneshot::Sender<(usize, usize, usize, usize, usize, usize)>,
    },
    /// TEST ONLY: evidence that the clean policy transition scales with plans
    /// and compatible wire cohorts rather than members.
    #[cfg(test)]
    TestQueryPolicyTransitionStats {
        /// Plan builds, full probes, route-shell materializations, max actor
        /// poll in nanoseconds, and actual state-machine poll count.
        reply: oneshot::Sender<(usize, usize, usize, u128, usize)>,
    },
    /// TEST ONLY: prospective destination groups that have no committed member.
    #[cfg(test)]
    TestQueryUncommittedPolicyTransitionGroups {
        /// Response channel for the number of still-unowned group RIBs.
        reply: oneshot::Sender<usize>,
    },
    /// Query: snapshot the live per-term guard-hit counters of the
    /// installed export chains (ADR-0096 Decision 3.3). Counters
    /// accumulate since a chain instance was installed and reset when
    /// it is replaced.
    QueryExportPolicyTermHits {
        /// Optional peer filter; `None` = every installed chain.
        peer: Option<IpAddr>,
        /// Response channel.
        reply: oneshot::Sender<Vec<ExportPolicyTermHits>>,
    },
    /// Preflight an outbound prefix-limit edit across every affected live
    /// peer and hold it as an inactive prepared transaction (ADR-0113).
    ///
    /// Nothing observable changes: the running limits, admission state,
    /// Adj-RIB-Out, and wire state stay as they are until
    /// [`RibUpdate::ApplyOutboundPrefixLimits`] activates the same
    /// transaction identity.
    PrepareOutboundPrefixLimits {
        /// Caller transaction identity; activation is idempotent by it.
        txn: u64,
        /// Candidate resolver tables for the whole running configuration.
        config: OutboundPrefixLimitConfig,
        /// Every family that is already above its candidate, or `Ok`.
        reply: oneshot::Sender<Result<(), Vec<OutboundPrefixLimitViolation>>>,
    },
    /// Activate or discard a prepared outbound prefix-limit transaction.
    ///
    /// Activation atomically rechecks the prepared target set, each peer's
    /// session generation, the admission epoch, and the lowering
    /// preconditions; drift rejects the whole activation rather than
    /// applying part of it.
    ApplyOutboundPrefixLimits {
        /// Transaction identity from the matching prepare.
        txn: u64,
        /// `true` activates, `false` discards the preparation.
        activate: bool,
        /// Response channel; `Err` describes the drift that rejected it.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Replace the effective export policy for a peer and resync outbound state.
    ReplacePeerExportPolicy {
        /// The target peer.
        peer: IpAddr,
        /// New effective export policy (`None` = permit-all/global fallback resolved already).
        export_policy: Option<PolicyChain>,
        /// Response channel for success/failure.
        reply: oneshot::Sender<Result<(), RibCommandError>>,
    },
    /// Replace a cohort of peer export policies as one optimized RIB transaction.
    ///
    /// Clean, equivalent grouped-to-grouped unicast members may share one
    /// transition inventory and exact-probe plan. Every unsupported or
    /// ambiguous batch returns a wholesale per-peer handoff before its first
    /// emission.
    ReplacePeerExportPolicies {
        /// Replacements in caller transaction order.
        replacements: Vec<PeerExportPolicyReplacement>,
        /// Response channel for failure or the committed/per-peer-handoff outcome.
        reply: oneshot::Sender<Result<ExportPolicyCohortOutcome, String>>,
    },
    /// Create and stage the prospective destination update-group of an
    /// upcoming [`RibUpdate::ReplacePeerExportPolicies`] cohort — without
    /// the transition fence.
    ///
    /// Staging proceeds in budgeted actor slices interleaved with ordinary
    /// mutation traffic, and the created group is kept current by the
    /// ordinary all-groups staging pass exactly like any owned group, so
    /// its table is live (not a stale snapshot) whenever the cohort
    /// transition arrives. The transition's `StageDestination` phase then
    /// finds the destination `Maintained` and skips its fenced full-table
    /// staging walk — the dominant share of the fenced reload wall at
    /// route-server scale, during which every queued churn delta stalls.
    ///
    /// Best-effort: an `Err` reply (or a dropped reply) only means the
    /// transition will stage the destination itself under the fence, as
    /// before. The caller owns sending
    /// [`RibUpdate::DiscardPreparedExportPolicyDestination`] if its cohort
    /// transaction fails before the transition command is sent.
    PrepareExportPolicyDestination {
        /// Exemplar cohort member; its peer flags seed the group profile.
        peer: IpAddr,
        /// The destination export chain (`None` = permit-all resolved).
        export_policy: Option<PolicyChain>,
        /// Resolves once the destination is fully staged, or with the
        /// reason the preparation was skipped.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Discard a previously prepared, still-unowned destination group after
    /// the cohort transaction failed before its transition was sent, so an
    /// orphaned staged table does not keep consuming per-churn staging
    /// work. A destination that gained members (the transition committed)
    /// is never removed.
    DiscardPreparedExportPolicyDestination {
        /// The exemplar peer passed to the matching prepare.
        peer: IpAddr,
        /// The destination export chain passed to the matching prepare.
        export_policy: Option<PolicyChain>,
    },
    /// Force re-emission of all currently-advertised routes to a peer
    /// without changing policy. Used when an outbound *attribute*
    /// surface changes (e.g. RFC 8326 `GRACEFUL_SHUTDOWN` community
    /// attach toggle) so the peer sees the updated wire form.
    RefreshPeerOutbound {
        /// The target peer.
        peer: IpAddr,
        /// Response channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Peer sent us a ROUTE-REFRESH — re-advertise our Loc-RIB for this family.
    RouteRefreshRequest {
        /// The requesting peer.
        peer: IpAddr,
        /// Transport session identity of the emitting session. A stale
        /// request from a superseded session would only trigger a
        /// spurious re-advertisement, but it is discarded by the same
        /// rule for consistency (see `RoutesReceived::session_id`).
        session_id: u64,
        /// Address family identifier.
        afi: Afi,
        /// Subsequent address family identifier.
        safi: Safi,
    },
    /// Peer sent Beginning-of-RIB-Refresh (RFC 7313) for this family.
    BeginRouteRefresh {
        /// The peer that sent `BoRR`.
        peer: IpAddr,
        /// Transport session identity of the emitting session. A stale
        /// `BoRR` from a superseded session must not open an enhanced-
        /// refresh window over the registered session's Adj-RIB-In (see
        /// `RoutesReceived::session_id`).
        session_id: u64,
        /// Address family identifier.
        afi: Afi,
        /// Subsequent address family identifier.
        safi: Safi,
    },
    /// Peer sent End-of-RIB-Refresh (RFC 7313) for this family.
    EndRouteRefresh {
        /// The peer that sent `EoRR`.
        peer: IpAddr,
        /// Transport session identity of the emitting session. A stale
        /// `EoRR` from a superseded session must not close the registered
        /// session's enhanced-refresh window early and sweep its
        /// refresh-stale routes (see `RoutesReceived::session_id`).
        session_id: u64,
        /// Address family identifier.
        afi: Afi,
        /// Subsequent address family identifier.
        safi: Safi,
    },
    /// Local enhanced-route-refresh accounting expired for this family.
    /// This synthetic event sweeps the RIB refresh window but cannot stand in
    /// for an RFC 7313 `EoRR` received from the peer.
    RouteRefreshTimeout {
        /// Peer whose refresh accounting window expired.
        peer: IpAddr,
        /// Transport session identity owning the accounting window.
        session_id: u64,
        /// Address family identifier.
        afi: Afi,
        /// Subsequent address family identifier.
        safi: Safi,
    },
    /// RPKI cache update — new VRP table for origin validation.
    RpkiCacheUpdate {
        /// The new VRP table snapshot.
        table: Arc<VrpTable>,
    },
    /// ASPA cache update — new ASPA table for path verification.
    AspaTableUpdate {
        /// The new ASPA table snapshot.
        table: Arc<AspaTable>,
    },
    /// Inject a locally-originated `FlowSpec` route.
    InjectFlowSpec {
        /// The `FlowSpec` route to inject.
        route: FlowSpecRoute,
        /// Completion reply.
        reply: oneshot::Sender<Result<(), RibCommandError>>,
    },
    /// Withdraw a locally-injected `FlowSpec` route.
    WithdrawFlowSpec {
        /// Family-complete `FlowSpec` identity to withdraw.
        key: crate::route::FlowSpecKey,
        /// Completion reply.
        reply: oneshot::Sender<Result<(), RibCommandError>>,
    },
    /// Inject a locally-originated EVPN route (RFC 7432).
    ///
    /// Entry point for controller-driven injection — an SDN controller
    /// calls `InjectionService::AddEvpnRoute` which synthesizes an
    /// `EvpnRibRoute` with `origin_type = RouteOrigin::Local` and pushes
    /// it here. The RR then reflects the route to all iBGP peers
    /// negotiating L2VPN/EVPN.
    InjectEvpn {
        /// The EVPN route to inject.
        route: EvpnRibRoute,
        /// Completion reply.
        reply: oneshot::Sender<Result<(), RibCommandError>>,
    },
    /// Withdraw a locally-injected EVPN route.
    WithdrawEvpn {
        /// The EVPN route key to withdraw.
        key: EvpnRouteKey,
        /// Completion reply.
        reply: oneshot::Sender<Result<(), RibCommandError>>,
    },
    /// Query `FlowSpec` routes from the Loc-RIB.
    QueryFlowSpecRoutes {
        /// Response channel.
        reply: oneshot::Sender<Vec<FlowSpecRoute>>,
    },
    /// Query EVPN routes from the Loc-RIB (RFC 7432).
    QueryEvpnRoutes {
        /// Response channel.
        reply: oneshot::Sender<Vec<EvpnRibRoute>>,
    },
    /// Query BGP-LS routes from the Loc-RIB (RFC 9552).
    QueryBgpLsRoutes {
        /// Response channel.
        reply: oneshot::Sender<Vec<BgpLsRibRoute>>,
    },
    /// Query VPNv4/VPNv6 routes from the Loc-RIB (RFC 4364 / RFC 4659).
    QueryVpnRoutes {
        /// Response channel.
        reply: oneshot::Sender<Vec<VpnRibRoute>>,
    },
    /// Query IPv4/IPv6 labeled-unicast routes from the Loc-RIB (RFC 8277).
    QueryLabeledRoutes {
        /// Response channel.
        reply: oneshot::Sender<Vec<LabeledRibRoute>>,
    },
    /// Query RT-Constrain routes from the Loc-RIB (RFC 4684).
    QueryRtcRoutes {
        /// Response channel.
        reply: oneshot::Sender<Vec<RtcRibRoute>>,
    },
    /// Query a snapshot of the RFC 9107 ORR topology graph, built on
    /// demand from every peer's BGP-LS Adj-RIB-In (NOT the Loc-RIB —
    /// the SPF wants the union view across peers).
    QueryOrrTopology {
        /// Response channel.
        reply: oneshot::Sender<crate::orr::OrrTopologySnapshot>,
    },
    /// Query per-vantage RFC 9107 ORR status: resolution state, SPF
    /// reach, bound peers, and topology totals — served from the cached
    /// `OrrState` when vantages are configured.
    QueryOrrStatus {
        /// Response channel.
        reply: oneshot::Sender<crate::orr::OrrStatusSnapshot>,
    },
    /// Query a full RIB snapshot for MRT `TABLE_DUMP_V2` export.
    QueryMrtSnapshot {
        /// Response channel.
        reply: oneshot::Sender<MrtSnapshotData>,
    },
    /// Query one actor-consistent, session-fenced post-import-policy
    /// Adj-RIB-In snapshot for a shutdown warm checkpoint. The caller supplies
    /// the exact PM/session inventory; any mismatch rejects the complete
    /// snapshot.
    QueryWarmMrtSnapshot {
        /// Strictly sorted, duplicate-free eligible view inventory.
        views: Vec<WarmMrtSnapshotView>,
        /// Cooperative cancellation/deadline and pre-materialization limit.
        /// The RIB actor checks this while counting and cloning routes so a
        /// timed-out shutdown query cannot wedge the actor behind a full-table
        /// synchronous snapshot.
        budget: WarmMrtSnapshotBudget,
        /// Response channel. `Err` is a fail-closed checkpoint result.
        reply: oneshot::Sender<Result<MrtSnapshotData, String>>,
    },
    /// One bounded chunk of an RFC 9069 Loc-RIB table dump for a
    /// (re)connected BMP collector: synthesize at most one chunk of
    /// UPDATE PDUs (unicast + VPN bests, resumed from `cursor`) with
    /// their install times, ending with an End-of-RIB PDU per dumped
    /// family on the final chunk. The BMP dump forwarder drives the
    /// chunk loop, so the full table is never materialized at once and
    /// live route processing interleaves between chunks.
    QueryBmpLocRibDump {
        /// Resume position from the previous chunk's reply; `None`
        /// starts a fresh dump.
        cursor: Option<rustbgpd_bmp::BmpDumpCursor>,
        /// Reply channel for this chunk (from the BMP manager's
        /// `BmpDumpRequest`).
        reply: oneshot::Sender<rustbgpd_bmp::BmpDumpChunk>,
    },
    /// Query per-AFI/SAFI Loc-RIB route counts for the RFC 9069 BMP
    /// statistics report (stat type 10 entries; type 8 is their sum).
    /// Scope matches the streamed Loc-RIB families (unicast + VPN).
    QueryBmpLocRibStats {
        /// Response channel: `(afi, safi, count)` per family.
        reply: oneshot::Sender<Vec<(u16, u8, u64)>>,
    },
}

/// Peer metadata for MRT `PEER_INDEX_TABLE`.
#[derive(Debug, Clone)]
pub struct MrtPeerEntry {
    /// Peer's transport address.
    pub peer_addr: IpAddr,
    /// Peer's BGP router ID.
    pub peer_bgp_id: Ipv4Addr,
    /// Peer's autonomous system number.
    pub peer_asn: u32,
}

/// Complete RIB snapshot for MRT dump.
#[derive(Debug)]
pub struct MrtSnapshotData {
    /// All known peers for the `PEER_INDEX_TABLE`.
    pub peers: Vec<MrtPeerEntry>,
    /// All post-import-policy Adj-RIB-In unicast routes across all peers.
    pub routes: Vec<Route>,
    /// All post-import-policy Adj-RIB-In EVPN routes across all peers. Encoded
    /// as RFC 6396 `RIB_GENERIC` records (AFI 25 / SAFI 70). Empty for
    /// non-EVPN deployments.
    pub evpn_routes: Vec<crate::route::EvpnRibRoute>,
}

/// Bounded work contract for a shutdown warm snapshot.
///
/// `deadline` is checked inside the synchronous RIB actor loop. `cancelled`
/// additionally lets a caller whose async wait was dropped stop an in-flight
/// actor query from another runtime worker. `max_materialized_bytes` bounds the
/// exact owned route-vector storage reserved before any route clone occurs.
#[derive(Debug, Clone)]
pub struct WarmMrtSnapshotBudget {
    /// Monotonic terminal deadline shared with the shutdown coordinator.
    pub deadline: Instant,
    /// Set when the waiting coordinator is cancelled or times out.
    pub cancelled: Arc<AtomicBool>,
    /// Hard cap for owned snapshot vector storage.
    pub max_materialized_bytes: usize,
}

impl WarmMrtSnapshotBudget {
    /// Fail closed before or during synchronous actor work.
    ///
    /// # Errors
    ///
    /// Returns a bounded diagnostic when the caller cancelled the query or
    /// the shared terminal deadline has elapsed.
    pub fn check(&self) -> Result<(), String> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err("warm checkpoint snapshot was cancelled".to_string());
        }
        if Instant::now() >= self.deadline {
            return Err("warm checkpoint snapshot exceeded its terminal deadline".to_string());
        }
        Ok(())
    }
}

/// One exact peer/family/session view requested for a warm MRT snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarmMrtSnapshotView {
    /// Configured numbered peer address.
    pub peer: IpAddr,
    /// Peer-manager generation of the active session.
    pub session_id: u64,
    /// Remote ASN negotiated by that session.
    pub peer_asn: u32,
    /// Remote BGP identifier negotiated by that session.
    pub peer_router_id: Ipv4Addr,
    /// Exact supported family.
    pub afi: Afi,
    /// Exact supported SAFI.
    pub safi: Safi,
    /// Whether Add-Path receive/both was negotiated for this view.
    pub add_path_receive: bool,
}

impl WarmMrtSnapshotView {
    /// Stable ordering key independent of enum declaration order.
    #[must_use]
    pub fn sort_key(&self) -> (IpAddr, u16, u8, u64, u32, Ipv4Addr, bool) {
        (
            self.peer,
            self.afi as u16,
            self.safi as u8,
            self.session_id,
            self.peer_asn,
            self.peer_router_id,
            self.add_path_receive,
        )
    }
}
