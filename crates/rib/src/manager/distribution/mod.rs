use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use rustbgpd_policy::{
    PolicyAction, PolicyChain, PolicyEvaluation, RouteContext, RouteFamily, RouteType,
    evaluate_chain_with_attribution,
};
use rustbgpd_rpki::VrpTable;
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{
    AddressPrefixOrf, Afi, BgpRole, OrfAction, OrfMatch, Prefix, RouteRefreshSubtype, Safi,
    WhenToRefresh,
};
use tracing::{debug, info, warn};

use super::helpers::{
    LOCAL_PEER, bgpls_route_family, bgpls_routes_equal, evpn_routes_equal, flowspec_route_family,
    gauge_val, labeled_route_family, labeled_routes_equal, prefix_family, routes_equal,
    rtc_routes_equal, should_suppress_ibgp_inner, unicast_route_family, validate_route_aspa,
    validate_route_rpki, vpn_route_family, vpn_routes_equal,
};
use super::{
    PendingRouteChunk, PendingRoutesReceived, PolicyFilteredRouteKey, RibManager,
    UnicastPrefixPeers,
};
use crate::adj_rib_in::AdjRibIn;
use crate::adj_rib_out::AdjRibOut;
use crate::event::{RouteEvent, RouteEventType};
use crate::loc_rib::LocRib;
use crate::update::{
    ExactExportKey, ExplainAdvertisedRoute, ExplainDecision, ExplainReason, ExportGateStep,
    ExportGateVerdict, NeighborPolicyStats, OutboundRouteUpdate, RibCommandError,
};

mod bgpls;
mod evpn;
mod export_memo;
mod flowspec;
mod labeled;
mod rtc;
mod unicast;
mod vpn;

pub(in crate::manager) use export_memo::ExportMemo;

/// RFC 9494 §4.4 export restriction: an LLGR-stale route "SHOULD NOT be
/// advertised to any neighbor from which the Long-Lived Graceful Restart
/// Capability has not been received". For an eBGP target that means
/// suppression (withdraw-if-present, the standard ineligibility shape at
/// staging). iBGP targets are NOT suppressed here — the §4.6 intra-AS
/// exception permits advertising to them with `NO_EXPORT` attached and
/// `LOCAL_PREF` zero, a per-peer attribute form applied in transport's
/// `prepare_outbound_attributes_*` beside the other per-peer rewrites
/// (`ORIGINATOR_ID`/`CLUSTER_LIST`, `GShut`).
///
/// Staleness is the locally-promoted `is_llgr_stale` flag OR a carried
/// `LLGR_STALE` community: promotion sets both, but a route *received*
/// already tagged by an upstream helper only carries the community
/// (which "MUST NOT be removed when the route is further advertised").
fn llgr_stale_export_suppressed(
    is_llgr_stale: bool,
    communities: &[u32],
    family: (Afi, Safi),
    target_is_ebgp: bool,
    llgr: Option<&Vec<(Afi, Safi)>>,
) -> bool {
    target_is_ebgp
        && !llgr.is_some_and(|families| families.contains(&family))
        && (is_llgr_stale || communities.contains(&rustbgpd_wire::COMMUNITY_LLGR_STALE))
}

/// RFC 9234 §5 egress rule for IPv4/IPv6 unicast: a route that already
/// carries OTC must not be propagated toward a Provider, Peer, or Route
/// Server. The local role names our side of those relationships.
fn otc_egress_blocked(route: &crate::route::Route, local_role: Option<BgpRole>) -> bool {
    matches!(
        local_role,
        Some(BgpRole::Customer | BgpRole::Peer | BgpRole::RouteServerClient)
    ) && route.attributes.iter().any(|attribute| match attribute {
        rustbgpd_wire::PathAttribute::OnlyToCustomer(_) => true,
        rustbgpd_wire::PathAttribute::Unknown(raw) => {
            raw.type_code == rustbgpd_wire::constants::attr_type::ONLY_TO_CUSTOMER
        }
        _ => false,
    })
}

fn route_type(origin: crate::route::RouteOrigin) -> RouteType {
    match origin {
        crate::route::RouteOrigin::Local => RouteType::Local,
        crate::route::RouteOrigin::Ibgp => RouteType::Internal,
        crate::route::RouteOrigin::Ebgp => RouteType::External,
    }
}

fn route_type_label(route_type: RouteType) -> &'static str {
    match route_type {
        RouteType::Local => "local_route",
        RouteType::Internal => "ibgp_route",
        RouteType::External => "ebgp_route",
    }
}

fn route_type_message(route_type: RouteType) -> &'static str {
    match route_type {
        RouteType::Local => "best route is locally originated",
        RouteType::Internal => "best route was learned from an iBGP peer",
        RouteType::External => "best route was learned from an eBGP peer",
    }
}

/// Human-readable `(AFI, SAFI)` label for explain output.
fn family_label(family: (Afi, Safi)) -> String {
    let afi = match family.0 {
        Afi::Ipv4 => "ipv4",
        Afi::Ipv6 => "ipv6",
        Afi::L2Vpn => "l2vpn",
        Afi::BgpLs => "bgpls",
    };
    let safi = match family.1 {
        Safi::Unicast => "unicast",
        Safi::FlowSpec => "flowspec",
        Safi::Multicast => "multicast",
        Safi::LabeledUnicast => "labeled_unicast",
        Safi::Evpn => "evpn",
        Safi::BgpLs => "bgpls",
        Safi::BgpLsVpn => "bgpls_vpn",
        Safi::MplsVpn => "mpls_vpn",
        Safi::RtConstrain => "rtc",
    };
    format!("{afi} {safi}")
}

/// Reason code + message for a route stopped by
/// [`should_suppress_ibgp_inner`] — distinguishes the RFC 4456
/// non-client-to-non-client reflection case from plain iBGP split
/// horizon. Explain-only; inputs mirror the suppression check exactly.
fn rr_suppression_reason(
    best: &crate::route::Route,
    target_is_ebgp: bool,
    target_is_rr_client: bool,
    cluster_id: Option<Ipv4Addr>,
    peer_is_rr_client: &HashMap<IpAddr, bool>,
) -> (&'static str, &'static str) {
    if !target_is_ebgp
        && !best.is_ebgp()
        && cluster_id.is_some()
        && !peer_is_rr_client.get(&best.peer).copied().unwrap_or(false)
        && !target_is_rr_client
    {
        (
            "rr_non_client_to_non_client",
            "route reflector will not reflect a non-client iBGP route to another non-client",
        )
    } else {
        (
            "ibgp_split_horizon",
            "iBGP split horizon suppresses advertisement of this route",
        )
    }
}

/// `"<policy>"` or `"<policy>:<term>"` label of the deciding export
/// chain member, enriched with the rpol term name via the statement
/// trace (explain-only re-walk, pinned to agree with the counted
/// evaluation by the policy crate's agreement tests). TOML members
/// carry no term name and render unchanged.
fn policy_label_with_term(
    chain: Option<&PolicyChain>,
    ctx: &RouteContext<'_>,
    matched_policy: Option<&str>,
) -> String {
    let term_suffix = rustbgpd_policy::explain_chain_statements(chain, ctx)
        .steps
        .last()
        .filter(|step| step.policy_name.as_deref() == matched_policy)
        .and_then(|step| step.term_name.as_deref())
        .map(|term| format!(":{term}"))
        .unwrap_or_default();
    format!("{}{term_suffix}", matched_policy.unwrap_or("inline"))
}

/// The consumer identity for the shared single-best export tail
/// ([`RibManager::distribute_single_best_prefix`]): a concrete peer
/// (today's per-peer path — split horizon against the peer,
/// peer-context policy fields, direct per-peer counter recording) or a
/// whole update group (shared staging — split horizon deferred to
/// member emit via the source-flip matrix, peer-context-free chain by
/// group eligibility, evaluations accumulated once and replayed per
/// member as integer adds). ONE body serves both paths: the per-peer
/// path stays the correctness oracle for the group path forever
/// (design risk 1 — parameterized, never copied).
pub(in crate::manager) enum ExportTarget<'a> {
    Peer {
        peer: IpAddr,
        peer_asn: Option<u32>,
        peer_group: Option<&'a str>,
        metrics: &'a BgpMetrics,
        policy_stats: &'a mut NeighborPolicyStats,
        peer_label: &'a str,
    },
    Group {
        evals: &'a mut super::update_groups::GroupEvalAccumulator,
        local_role: Option<BgpRole>,
        otc_blocked: &'a mut Vec<crate::route::Route>,
    },
    /// Explain-only dry run of the shared staging body: behaves like
    /// `Peer` for every decision input (split horizon, policy peer
    /// context) but records NOTHING into metrics/counters — a one-shot
    /// operator query must not skew `bgp_policy_routes_total` or the
    /// per-term hit counters — and captures the gate ladder into
    /// `trace` instead. The explain handler passes scratch output
    /// vectors and never commits, so the run is fully side-effect-free.
    Explain {
        peer: IpAddr,
        peer_asn: Option<u32>,
        peer_group: Option<&'a str>,
        local_role: Option<BgpRole>,
        trace: &'a mut ExportGateTrace,
    },
}

/// Explain-only capture of one dry-run pass through the shared export
/// staging body (`distribute_single_best_prefix` / `stage_vpn_routes`).
/// Filled through [`ExportTarget::Explain`]; every field is written by
/// the same code that stages live exports, so the explanation cannot
/// drift from the real decision.
#[derive(Debug, Default)]
pub(in crate::manager) struct ExportGateTrace {
    /// Gate ladder in live evaluation order.
    pub gates: Vec<ExportGateStep>,
    /// Source peer of the selected best route (once the ladder reached it).
    pub best_peer: Option<IpAddr>,
    /// Route type of the selected best route.
    pub best_route_type: Option<RouteType>,
    /// Export-policy modifications of the permitting chain verdict.
    pub modifications: rustbgpd_policy::RouteModifications,
    /// `"<policy>"` or `"<policy>:<term>"` label of the deciding chain
    /// member (rpol term via the statement trace), `None` = no chain.
    pub policy_label: Option<String>,
    /// Post-modification next hop the route would be staged with.
    pub staged_next_hop: Option<IpAddr>,
    /// Post-modification Add-Path identifier (always 0 on single-best).
    pub staged_path_id: u32,
    /// `true` when the staged route equals the advertised state and the
    /// live path would suppress re-announcement.
    pub suppressed_identical: bool,
}

impl ExportGateTrace {
    fn push(
        &mut self,
        gate: &'static str,
        code: &'static str,
        verdict: ExportGateVerdict,
        detail: String,
    ) {
        self.gates.push(ExportGateStep {
            gate,
            code,
            verdict,
            detail,
        });
    }

    /// Stop code of the gate that halted the ladder, if any.
    pub(in crate::manager) fn stopped(&self) -> Option<&ExportGateStep> {
        self.gates
            .iter()
            .find(|step| step.verdict == ExportGateVerdict::Stop)
    }

    /// Assemble the operator-facing explanation from a completed dry
    /// run. The legacy `reasons` list keeps its pre-ladder shape (one
    /// decisive stop reason, or route-type + policy-permit on
    /// advertise) so existing consumers see unchanged output.
    pub(in crate::manager) fn into_explain(
        self,
        peer: IpAddr,
        prefix: Prefix,
        rd: Option<rustbgpd_wire::RouteDistinguisher>,
        update_group_id: Option<u64>,
    ) -> ExplainAdvertisedRoute {
        let (decision, reasons) = if let Some(step) = self.stopped() {
            let decision = match step.code {
                "no_best_route" | "no_orr_candidate" => ExplainDecision::NoBestRoute,
                "family_not_sendable" => ExplainDecision::UnsupportedFamily,
                _ => ExplainDecision::Deny,
            };
            (
                decision,
                vec![ExplainReason {
                    code: step.code,
                    message: step.detail.clone(),
                }],
            )
        } else {
            let mut reasons = Vec::new();
            if let Some(route_type) = self.best_route_type {
                reasons.push(ExplainReason {
                    code: route_type_label(route_type),
                    message: route_type_message(route_type).to_string(),
                });
            }
            if let Some(label) = &self.policy_label {
                reasons.push(ExplainReason {
                    code: "policy_permitted",
                    message: format!("export policy {label:?} permitted this route"),
                });
            }
            (ExplainDecision::Advertise, reasons)
        };
        ExplainAdvertisedRoute {
            decision,
            peer,
            prefix,
            next_hop: self.staged_next_hop,
            path_id: self.staged_path_id,
            route_peer: self.best_peer,
            route_type: self.best_route_type,
            reasons,
            modifications: self.modifications,
            orr_vantage: None,
            orr_candidates: Vec::new(),
            gates: self.gates,
            update_group_id,
            already_advertised: self.suppressed_identical,
            rd,
        }
    }
}

impl<'a> ExportTarget<'a> {
    /// The peer to apply split horizon against; `None` for group
    /// staging (lifted out — applied per member at emit time; the
    /// explain dry run applies it against the member directly, which is
    /// exactly what the source-flip matrix does per member at emit).
    fn split_horizon_peer(&self) -> Option<IpAddr> {
        match self {
            Self::Peer { peer, .. } | Self::Explain { peer, .. } => Some(*peer),
            Self::Group { .. } => None,
        }
    }

    /// Peer-context fields for the policy `RouteContext`. Group-staged
    /// chains never read them (`requires_peer_context` disqualifies).
    /// Returns `'a`-lived data (not `&self`-lived) so a built
    /// `RouteContext` doesn't pin the target while explain trace hooks
    /// need it mutably.
    fn ctx_peer(&self) -> (Option<IpAddr>, Option<u32>, Option<&'a str>) {
        match self {
            Self::Peer {
                peer,
                peer_asn,
                peer_group,
                ..
            }
            | Self::Explain {
                peer,
                peer_asn,
                peer_group,
                ..
            } => (Some(*peer), *peer_asn, *peer_group),
            Self::Group { .. } => (None, None, None),
        }
    }

    /// Record one export-chain evaluation: directly per peer, or into
    /// the group accumulator for per-member replay. Explain dry runs
    /// record nothing — counting a one-shot operator query would skew
    /// `bgp_policy_routes_total` and the per-term hit counters.
    fn record_eval(&mut self, evaluation: &PolicyEvaluation, source: IpAddr) {
        match self {
            Self::Peer {
                metrics,
                policy_stats,
                peer_label,
                ..
            } => record_export_policy_eval(metrics, policy_stats, peer_label, evaluation),
            Self::Group { evals, .. } => evals.record(evaluation, source),
            Self::Explain { .. } => {}
        }
    }

    /// Target stamped on policy-denial records; group records carry the
    /// `LOCAL_PEER` placeholder and are restamped per member.
    fn policy_filtered_target(&self) -> IpAddr {
        match self {
            Self::Peer { peer, .. } | Self::Explain { peer, .. } => *peer,
            Self::Group { .. } => LOCAL_PEER,
        }
    }

    /// Evaluate the export chain for one route. Live targets take the
    /// counting walker (ADR-0096 per-term hit counters + eval totals);
    /// an explain dry run takes the IR-level non-counting evaluation so
    /// a one-shot operator query cannot skew `rbgp policy stats` — the
    /// two are pinned to agree by the policy crate's parity tests.
    fn evaluate_export_chain(
        &self,
        export_pol: Option<&PolicyChain>,
        ctx: &RouteContext<'_>,
    ) -> (rustbgpd_policy::PolicyResult, PolicyEvaluation) {
        match self {
            Self::Peer { .. } | Self::Group { .. } => {
                evaluate_chain_with_attribution(export_pol, ctx)
            }
            Self::Explain { .. } => match export_pol {
                Some(chain) => chain.compiled().evaluate_with_attribution(ctx),
                None => (
                    rustbgpd_policy::PolicyResult::permit(),
                    PolicyEvaluation {
                        action: PolicyAction::Permit,
                        matched_policy: None,
                        eval_error: None,
                    },
                ),
            },
        }
    }

    /// Explain trace sink; `None` for live targets, making every
    /// `gate(...)` recording call a no-op on the hot path.
    fn trace(&mut self) -> Option<&mut ExportGateTrace> {
        match self {
            Self::Explain { trace, .. } => Some(trace),
            Self::Peer { .. } | Self::Group { .. } => None,
        }
    }

    fn local_role(&self) -> Option<BgpRole> {
        match self {
            Self::Group { local_role, .. } | Self::Explain { local_role, .. } => *local_role,
            Self::Peer { .. } => None,
        }
    }

    fn record_otc_blocked(&mut self, route: crate::route::Route) {
        if let Self::Group { otc_blocked, .. } = self {
            otc_blocked.push(route);
        }
    }

    /// Record one gate-ladder step (explain dry runs only). The detail
    /// closure keeps live staging free of format!/allocation cost.
    fn gate(
        &mut self,
        gate: &'static str,
        code: &'static str,
        verdict: ExportGateVerdict,
        detail: impl FnOnce() -> String,
    ) {
        if let Some(trace) = self.trace() {
            trace.push(gate, code, verdict, detail());
        }
    }
}

fn record_export_policy_eval(
    metrics: &BgpMetrics,
    stats: &mut NeighborPolicyStats,
    peer_label: &str,
    evaluation: &PolicyEvaluation,
) {
    let policy = evaluation.matched_policy.as_deref().unwrap_or("inline");
    let action = match evaluation.action {
        PolicyAction::Permit => {
            stats.export_policy_routes_permitted =
                stats.export_policy_routes_permitted.saturating_add(1);
            "permit"
        }
        PolicyAction::Deny => {
            stats.export_policy_routes_denied = stats.export_policy_routes_denied.saturating_add(1);
            "deny"
        }
    };
    metrics.record_policy_routes(peer_label, policy, "export", action);
    // LAN-301: a fail-closed deny also counts on the eval-error
    // aggregate (direction × closed error kind). Error path only.
    if let Some(error) = &evaluation.eval_error {
        metrics.record_policy_eval_error("export", error.kind.label());
    }
}

fn adj_rib_out_contains_exact_key(
    rib_out: &AdjRibOut,
    key: &crate::update::ExactExportKey,
) -> bool {
    use crate::update::ExactExportKey;
    match key {
        ExactExportKey::Unicast(prefix, path_id) => rib_out.get(prefix, *path_id).is_some(),
        ExactExportKey::FlowSpec(key) => rib_out.get_flowspec(key).is_some(),
        ExactExportKey::Evpn(key) => rib_out.get_evpn(key).is_some(),
        ExactExportKey::BgpLs(key) => rib_out.get_bgpls(key).is_some(),
        ExactExportKey::Vpn(key) => rib_out.get_vpn(key).is_some(),
        ExactExportKey::Labeled(key) => rib_out.get_labeled(key).is_some(),
        ExactExportKey::Rtc(key) => rib_out.get_rtc(key).is_some(),
    }
}

impl RibManager {
    #[expect(
        clippy::too_many_arguments,
        reason = "RIB update messages carry every supported family as one transaction"
    )]
    pub(super) fn try_send_and_commit_outbound_update(
        &mut self,
        peer: IpAddr,
        next_hop_override: Arc<[Option<rustbgpd_policy::NextHopAction>]>,
        announce: Arc<[crate::route::Route]>,
        withdraw: Vec<(Prefix, u32)>,
        end_of_rib: Vec<(Afi, Safi)>,
        refresh_markers: Vec<(Afi, Safi, RouteRefreshSubtype)>,
        flowspec_announce: Vec<crate::route::FlowSpecRoute>,
        flowspec_withdraw: Vec<crate::route::FlowSpecKey>,
        evpn_announce: Vec<crate::route::EvpnRibRoute>,
        evpn_withdraw: Vec<rustbgpd_wire::EvpnRouteKey>,
        bgpls_announce: Vec<crate::route::BgpLsRibRoute>,
        bgpls_withdraw: Vec<crate::route::BgpLsRouteKey>,
        vpn_announce: Vec<crate::route::VpnRibRoute>,
        vpn_withdraw: Vec<crate::route::VpnRibRouteKey>,
        labeled_announce: Vec<crate::route::LabeledRibRoute>,
        labeled_withdraw: Vec<crate::route::LabeledRibRouteKey>,
        rtc_announce: Vec<crate::route::RtcRibRoute>,
        rtc_withdraw: Vec<crate::route::RtcRibRouteKey>,
    ) -> bool {
        self.try_send_and_commit_outbound_update_with_group_prior(
            peer,
            next_hop_override,
            announce,
            withdraw,
            end_of_rib,
            refresh_markers,
            flowspec_announce,
            flowspec_withdraw,
            evpn_announce,
            evpn_withdraw,
            bgpls_announce,
            bgpls_withdraw,
            vpn_announce,
            vpn_withdraw,
            labeled_announce,
            labeled_withdraw,
            rtc_announce,
            rtc_withdraw,
            HashSet::new(),
        )
    }

    #[expect(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "outbound commit needs all family queues for one atomic send"
    )]
    pub(super) fn try_send_and_commit_outbound_update_with_group_prior(
        &mut self,
        peer: IpAddr,
        mut next_hop_override: Arc<[Option<rustbgpd_policy::NextHopAction>]>,
        mut announce: Arc<[crate::route::Route]>,
        mut withdraw: Vec<(Prefix, u32)>,
        end_of_rib: Vec<(Afi, Safi)>,
        refresh_markers: Vec<(Afi, Safi, RouteRefreshSubtype)>,
        mut flowspec_announce: Vec<crate::route::FlowSpecRoute>,
        mut flowspec_withdraw: Vec<crate::route::FlowSpecKey>,
        mut evpn_announce: Vec<crate::route::EvpnRibRoute>,
        mut evpn_withdraw: Vec<rustbgpd_wire::EvpnRouteKey>,
        mut bgpls_announce: Vec<crate::route::BgpLsRibRoute>,
        mut bgpls_withdraw: Vec<crate::route::BgpLsRouteKey>,
        mut vpn_announce: Vec<crate::route::VpnRibRoute>,
        mut vpn_withdraw: Vec<crate::route::VpnRibRouteKey>,
        mut labeled_announce: Vec<crate::route::LabeledRibRoute>,
        mut labeled_withdraw: Vec<crate::route::LabeledRibRouteKey>,
        mut rtc_announce: Vec<crate::route::RtcRibRoute>,
        mut rtc_withdraw: Vec<crate::route::RtcRibRouteKey>,
        group_prior: HashSet<crate::update::ExactExportKey>,
    ) -> bool {
        let Some(tx) = self.outbound_peers.get(&peer).cloned() else {
            return false;
        };
        let Ok(permit) = tx.try_reserve() else {
            return false;
        };

        // Validate the trust boundary before consuming any durable pending
        // state (OTC diagnostics or the rejected-route overlay). A failed
        // precommit must leave those structures intact for the retry.
        let has_candidate_route_payload = !announce.is_empty()
            || !withdraw.is_empty()
            || !flowspec_announce.is_empty()
            || !flowspec_withdraw.is_empty()
            || !evpn_announce.is_empty()
            || !evpn_withdraw.is_empty()
            || !bgpls_announce.is_empty()
            || !bgpls_withdraw.is_empty()
            || !vpn_announce.is_empty()
            || !vpn_withdraw.is_empty()
            || !labeled_announce.is_empty()
            || !labeled_withdraw.is_empty()
            || !rtc_announce.is_empty()
            || !rtc_withdraw.is_empty();
        let exact_export_snapshot = if has_candidate_route_payload {
            let Some(encoder) = self.peer_export_encoders.get(&peer) else {
                warn!(%peer, "route-bearing outbound update has no exact export encoder — refusing Adj-RIB-Out commit");
                return false;
            };
            Some(encoder.snapshot())
        } else {
            None
        };

        // A grouped member's unicast advertised state is group-owned
        // (design §2: NO per-peer unicast storage) — skip the per-peer
        // unicast commit and synthesize its gauge from the group table.
        // Same for VPN when the member's group stages VPN (non-RTC
        // groups, v2 slice 1). Other families always commit per peer.
        let grouped_unicast_count = self.grouped_advertised_count(peer);

        // RFC 9234 egress enforcement for every concrete-peer selection
        // shape. Single-best group staging applies the same gate before its
        // shared table commit; this central pass covers private single-best,
        // ORR, Add-Path, and per-client-best without duplicating their tails.
        let mut otc_blocked: Vec<crate::route::Route> = self
            .pending_otc_blocked
            .remove(&peer)
            .map(|pending| pending.into_values().collect())
            .unwrap_or_default();
        let local_role = self.peer_local_roles.get(&peer).copied().flatten();
        if announce
            .iter()
            .any(|route| otc_egress_blocked(route, local_role))
        {
            debug_assert!(
                grouped_unicast_count.is_none(),
                "group staging must reject OTC before its shared table commit"
            );
            debug_assert_eq!(announce.len(), next_hop_override.len());
            let mut permitted = Vec::with_capacity(announce.len());
            let mut permitted_next_hops = Vec::with_capacity(next_hop_override.len());
            // Preserve the caller's withdrawal order while making duplicate
            // detection constant-time for large policy reload/resync batches.
            let mut withdrawn_keys: HashSet<(Prefix, u32)> = withdraw.iter().copied().collect();
            for (route, next_hop) in announce
                .iter()
                .cloned()
                .zip(next_hop_override.iter().cloned())
            {
                if otc_egress_blocked(&route, local_role) {
                    if self
                        .adj_ribs_out
                        .get(&peer)
                        .and_then(|rib_out| rib_out.get(&route.prefix, route.path_id))
                        .is_some()
                        && withdrawn_keys.insert((route.prefix, route.path_id))
                    {
                        withdraw.push((route.prefix, route.path_id));
                    }
                    otc_blocked.push(route);
                } else {
                    permitted.push(route);
                    permitted_next_hops.push(next_hop);
                }
            }
            announce = permitted.into();
            next_hop_override = permitted_next_hops.into();
        }

        // A route rejected on an earlier pass was never advertised (or its
        // prior advertisement was withdrawn by that transition). Suppress a
        // later ordinary withdrawal for the same identity and retire the
        // sparse rejection entry. This runs before deciding whether the
        // envelope is route-bearing, so a rejected-only withdrawal needs no
        // transport snapshot or empty wire message.
        if let Some(rejected) = self.peer_unexportable.get_mut(&peer) {
            withdraw.retain(|(prefix, path_id)| {
                !rejected.remove(&crate::update::ExactExportKey::Unicast(*prefix, *path_id))
            });
            flowspec_withdraw.retain(|key| {
                !rejected.remove(&crate::update::ExactExportKey::FlowSpec(key.clone()))
            });
            evpn_withdraw
                .retain(|key| !rejected.remove(&crate::update::ExactExportKey::Evpn(*key)));
            bgpls_withdraw
                .retain(|key| !rejected.remove(&crate::update::ExactExportKey::BgpLs(key.clone())));
            vpn_withdraw
                .retain(|key| !rejected.remove(&crate::update::ExactExportKey::Vpn(key.clone())));
            labeled_withdraw
                .retain(|key| !rejected.remove(&crate::update::ExactExportKey::Labeled(*key)));
            rtc_withdraw
                .retain(|key| !rejected.remove(&crate::update::ExactExportKey::Rtc(key.clone())));
        }
        if self
            .peer_unexportable
            .get(&peer)
            .is_some_and(HashSet::is_empty)
        {
            self.peer_unexportable.remove(&peer);
        }

        if let Some(snapshot) = exact_export_snapshot.as_ref() {
            use crate::update::{ExactExportCandidate, ExactExportKey};

            let mut previously_advertised = group_prior;
            let candidate_keys = announce
                .iter()
                .map(|route| ExactExportKey::Unicast(route.prefix, route.path_id))
                .chain(
                    flowspec_announce
                        .iter()
                        .map(|route| ExactExportKey::FlowSpec(route.selection_key())),
                )
                .chain(
                    evpn_announce
                        .iter()
                        .map(|route| ExactExportKey::Evpn(route.key())),
                )
                .chain(
                    bgpls_announce
                        .iter()
                        .map(|route| ExactExportKey::BgpLs(route.key())),
                )
                .chain(
                    vpn_announce
                        .iter()
                        .map(|route| ExactExportKey::Vpn(route.key())),
                )
                .chain(
                    labeled_announce
                        .iter()
                        .map(|route| ExactExportKey::Labeled(route.key())),
                )
                .chain(
                    rtc_announce
                        .iter()
                        .map(|route| ExactExportKey::Rtc(route.key())),
                )
                .collect::<Vec<_>>();
            if let Some(rib_out) = self.adj_ribs_out.get(&peer) {
                previously_advertised.extend(
                    candidate_keys
                        .iter()
                        .filter(|key| adj_rib_out_contains_exact_key(rib_out, key))
                        .cloned(),
                );
            }

            let mut owed_withdrawals = HashSet::new();
            let mut new_rejections = Vec::new();
            {
                let rejected = self.peer_unexportable.entry(peer).or_default();
                let mut accepts = |candidate: ExactExportCandidate<'_>| {
                    let key = candidate.key();
                    match snapshot.probe_announcement(candidate) {
                        Ok(_) => {
                            rejected.remove(&key);
                            true
                        }
                        Err(error) => {
                            let newly_rejected = rejected.insert(key.clone());
                            if newly_rejected && previously_advertised.contains(&key) {
                                owed_withdrawals.insert(key.clone());
                            }
                            if newly_rejected {
                                new_rejections.push((key, error));
                            }
                            false
                        }
                    }
                };

                debug_assert_eq!(announce.len(), next_hop_override.len());
                let unicast_keep = announce
                    .iter()
                    .zip(next_hop_override.iter())
                    .map(|(route, next_hop)| {
                        accepts(ExactExportCandidate::Unicast {
                            route,
                            next_hop_override: next_hop.as_ref(),
                        })
                    })
                    .collect::<Vec<_>>();
                if unicast_keep.iter().any(|keep| !keep) {
                    let permitted_routes = announce
                        .iter()
                        .cloned()
                        .zip(unicast_keep.iter().copied())
                        .filter_map(|(route, keep)| keep.then_some(route))
                        .collect::<Vec<_>>();
                    let permitted_next_hops = next_hop_override
                        .iter()
                        .cloned()
                        .zip(unicast_keep.iter().copied())
                        .filter_map(|(next_hop, keep)| keep.then_some(next_hop))
                        .collect::<Vec<_>>();
                    announce = permitted_routes.into();
                    next_hop_override = permitted_next_hops.into();
                }
                flowspec_announce.retain(|route| accepts(ExactExportCandidate::FlowSpec(route)));
                evpn_announce.retain(|route| accepts(ExactExportCandidate::Evpn(route)));
                bgpls_announce.retain(|route| accepts(ExactExportCandidate::BgpLs(route)));
                vpn_announce.retain(|route| accepts(ExactExportCandidate::Vpn(route)));
                labeled_announce.retain(|route| accepts(ExactExportCandidate::Labeled(route)));
                rtc_announce.retain(|route| accepts(ExactExportCandidate::Rtc(route)));
            }

            for key in owed_withdrawals {
                match key {
                    ExactExportKey::Unicast(prefix, path_id) => {
                        if !withdraw.contains(&(prefix, path_id)) {
                            withdraw.push((prefix, path_id));
                        }
                    }
                    ExactExportKey::FlowSpec(key) => {
                        if !flowspec_withdraw.contains(&key) {
                            flowspec_withdraw.push(key);
                        }
                    }
                    ExactExportKey::Evpn(key) => {
                        if !evpn_withdraw.contains(&key) {
                            evpn_withdraw.push(key);
                        }
                    }
                    ExactExportKey::BgpLs(key) => {
                        if !bgpls_withdraw.contains(&key) {
                            bgpls_withdraw.push(key);
                        }
                    }
                    ExactExportKey::Vpn(key) => {
                        if !vpn_withdraw.contains(&key) {
                            vpn_withdraw.push(key);
                        }
                    }
                    ExactExportKey::Labeled(key) => {
                        if !labeled_withdraw.contains(&key) {
                            labeled_withdraw.push(key);
                        }
                    }
                    ExactExportKey::Rtc(key) => {
                        if !rtc_withdraw.contains(&key) {
                            rtc_withdraw.push(key);
                        }
                    }
                }
            }
            for (key, error) in new_rejections {
                self.metrics.record_exact_export_rejection(
                    &peer.to_string(),
                    key.family_label(),
                    error.code().reason(),
                );
                warn!(
                    %peer,
                    identity = %key.bounded_log_identity(),
                    reason = error.code().as_str(),
                    detail = error.detail(),
                    profile_generation = snapshot.generation(),
                    "route rejected before Adj-RIB-Out commit because its exact wire form is unexportable"
                );
            }
        }

        if self
            .peer_unexportable
            .get(&peer)
            .is_some_and(HashSet::is_empty)
        {
            self.peer_unexportable.remove(&peer);
        }

        // Recompute grouped projections after the sparse overlay mutation;
        // these counts drive both metrics and query/BMP truth.
        let grouped_unicast_count = self.grouped_advertised_count(peer);
        let grouped_vpn_count = self.grouped_vpn_advertised_count(peer);

        if !announce.is_empty()
            || !withdraw.is_empty()
            || !flowspec_announce.is_empty()
            || !flowspec_withdraw.is_empty()
            || !evpn_announce.is_empty()
            || !evpn_withdraw.is_empty()
            || !bgpls_announce.is_empty()
            || !bgpls_withdraw.is_empty()
            || !vpn_announce.is_empty()
            || !vpn_withdraw.is_empty()
            || !labeled_announce.is_empty()
            || !labeled_withdraw.is_empty()
            || !rtc_announce.is_empty()
            || !rtc_withdraw.is_empty()
        {
            let loc_rib_len = self.loc_rib.len();
            let rib_out = self
                .adj_ribs_out
                .entry(peer)
                .or_insert_with(|| AdjRibOut::with_capacity(peer, loc_rib_len));
            if grouped_unicast_count.is_none() {
                for route in announce.iter() {
                    rib_out.insert(route.clone());
                }
                for (prefix, path_id) in &withdraw {
                    rib_out.withdraw(prefix, *path_id);
                }
            }
            for route in &flowspec_announce {
                rib_out.insert_flowspec(route.clone());
            }
            for key in &flowspec_withdraw {
                rib_out.remove_flowspec(key);
            }
            for route in &evpn_announce {
                rib_out.insert_evpn(route.clone());
            }
            for key in &evpn_withdraw {
                rib_out.remove_evpn(key);
            }
            for route in &bgpls_announce {
                rib_out.insert_bgpls(route.clone());
            }
            for key in &bgpls_withdraw {
                rib_out.remove_bgpls(key);
            }
            if grouped_vpn_count.is_none() {
                for route in &vpn_announce {
                    rib_out.insert_vpn(route.clone());
                }
                for key in &vpn_withdraw {
                    rib_out.remove_vpn(key);
                }
            }
            for route in &labeled_announce {
                rib_out.insert_labeled(route.clone());
            }
            for key in &labeled_withdraw {
                rib_out.remove_labeled(key);
            }
            for route in &rtc_announce {
                rib_out.insert_rtc(route.clone());
            }
            for key in &rtc_withdraw {
                rib_out.remove_rtc(key);
            }
            self.metrics.set_adj_rib_out_prefixes(
                &peer.to_string(),
                "all",
                gauge_val(grouped_unicast_count.unwrap_or_else(|| rib_out.len())),
            );
            self.metrics.set_adj_rib_out_prefixes(
                &peer.to_string(),
                "flowspec",
                gauge_val(rib_out.flowspec_len()),
            );
            self.metrics.set_adj_rib_out_prefixes(
                &peer.to_string(),
                "evpn",
                gauge_val(rib_out.evpn_len()),
            );
            self.metrics.set_adj_rib_out_prefixes(
                &peer.to_string(),
                "bgpls",
                gauge_val(rib_out.bgpls_len()),
            );
            self.metrics.set_adj_rib_out_prefixes(
                &peer.to_string(),
                "vpn",
                gauge_val(grouped_vpn_count.unwrap_or_else(|| rib_out.vpn_len())),
            );
            self.metrics.set_adj_rib_out_prefixes(
                &peer.to_string(),
                "labeled",
                gauge_val(rib_out.labeled_len()),
            );
            self.metrics.set_adj_rib_out_prefixes(
                &peer.to_string(),
                "rtc",
                gauge_val(rib_out.rtc_len()),
            );
        }

        permit.send(OutboundRouteUpdate {
            exact_export_snapshot,
            announce,
            withdraw,
            end_of_rib,
            refresh_markers,
            next_hop_override,
            flowspec_announce,
            flowspec_withdraw,
            evpn_announce,
            evpn_withdraw,
            bgpls_announce,
            bgpls_withdraw,
            vpn_announce,
            vpn_withdraw,
            labeled_announce,
            labeled_withdraw,
            rtc_announce,
            rtc_withdraw,
            otc_blocked,
            request_refresh_all_negotiated: false,
        });
        true
    }

    pub(super) fn handle_replace_peer_export_policy(
        &mut self,
        peer: IpAddr,
        export_policy: Option<PolicyChain>,
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    ) {
        if !self.outbound_peers.contains_key(&peer) {
            let _ = reply.send(Err(format!(
                "peer {peer} not registered for outbound updates"
            )));
            return;
        }

        // A content-equal replacement keeps the installed chain
        // INSTANCE, not just the group key: an update group's staging
        // handle shares the installed instance's ADR-0096 term-hit
        // counters (`PolicyChain::share`), so swapping in a fresh
        // (zeroed) content-equal instance would freeze what the
        // term-hits query reports while evaluations keep landing on
        // the group's old instance. The peer manager already skips
        // content-equal reinstalls at the fan-out; this guards the
        // seam itself for any other sender.
        if self.peer_export_policies.get(&peer) != Some(&export_policy) {
            self.peer_export_policies.insert(peer, export_policy);
        }
        // Update-group membership recompute on the policy replacement
        // seam (per-peer gRPC edits, ADR-0076 live-impact txns, and
        // SIGHUP rpol overlays all funnel through this handler).
        // Content-equality keying makes a reinstall of an identical
        // chain key-stable — no regroup, and (key-stable fast path) NO
        // resync either: a grouped member's staged output is a pure
        // function of the key, so re-emitting would be a no-op flood.
        // Everything else — regrouped members (one-shot baseline diff)
        // and ungrouped peers (per-peer equality-suppressed diff) —
        // takes the dirty resync exactly as before.
        let before = self.grouped_member_of(peer);
        self.recompute_update_group(peer);
        let key_stable = before.is_some() && before == self.grouped_member_of(peer);
        if !key_stable {
            self.mark_outbound_dirty(peer);
        }
        self.distribute_changes(&HashSet::new(), &HashSet::new());
        let _ = reply.send(Ok(()));
    }

    /// Force re-emission of all currently-advertised routes to a peer
    /// without changing policy. The export-policy path already does
    /// the same thing as a side-effect of policy replacement; this
    /// variant exists for outbound *attribute* surface changes that
    /// don't go through policy (e.g. RFC 8326 `GShut` community attach
    /// toggle, where the toggle lives as a per-session bool but
    /// changing it must trigger a fresh outbound emission so peers
    /// see the updated wire form on routes already in `AdjRibOut`).
    pub(super) fn handle_refresh_peer_outbound(
        &mut self,
        peer: IpAddr,
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    ) {
        if !self.outbound_peers.contains_key(&peer) {
            let _ = reply.send(Err(format!(
                "peer {peer} not registered for outbound updates"
            )));
            return;
        }
        // `force_outbound_peers` (not `dirty_peers`) — a force-only
        // resync bypasses AdjRibOut equality suppression for currently-
        // advertised exportable routes, which is exactly what GShut and
        // similar outbound-attribute toggles need (the wire change is
        // applied later in transport, invisible to this RIB diff). The
        // distribution loop clears the entry on successful emission so
        // the force is one-shot.
        self.force_outbound_peers.insert(peer);
        self.distribute_changes(&HashSet::new(), &HashSet::new());
        let _ = reply.send(Ok(()));
    }

    /// Apply Address-Prefix ORF entries pushed by a peer (RFC 5291/5292).
    ///
    /// Installs/updates the per-`(peer, AFI, SAFI)` filter and lifts the
    /// initial-advertisement gate. The re-advertisement sweep runs for
    /// `IMMEDIATE` (or after a malformed-field reset, RFC 5291 §5.2); `DEFER`
    /// installs the filter only — it stays live for subsequent outbound churn
    /// and is swept on a later IMMEDIATE/plain ROUTE-REFRESH.
    pub(super) fn handle_peer_orf_update(
        &mut self,
        peer: IpAddr,
        afi: Afi,
        safi: Safi,
        when: rustbgpd_wire::WhenToRefresh,
        entries: &[rustbgpd_wire::AddressPrefixOrf],
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    ) {
        if !self.outbound_peers.contains_key(&peer) {
            let _ = reply.send(Err(format!(
                "peer {peer} not registered for outbound updates"
            )));
            return;
        }
        // ORF is arbitrary per-peer outbound state and therefore a grouping
        // disqualifier. Assert before installing the filter: inserting it
        // first would make a later membership recompute hide an invalid
        // pre-existing grouped registration.
        debug_assert!(
            self.grouped_member_of(peer).is_none(),
            "an ORF-receive peer must never be registered in an update group"
        );
        let family = (afi, safi);
        // The ORF message is itself a ROUTE-REFRESH (RFC 5291 §6) — lift the gate.
        if let Some(pending) = self.peer_orf_pending.get_mut(&peer) {
            pending.remove(&family);
        }
        let filter = self
            .peer_orf_filters
            .entry(peer)
            .or_default()
            .entry(family)
            .or_default();
        let unknown_when = matches!(when, WhenToRefresh::Unknown(_));
        let reset = match when {
            WhenToRefresh::Unknown(value) => {
                // RFC 5291 only defines IMMEDIATE and DEFER. Treat an unknown
                // value like a malformed negotiated ORF control field: clear the
                // installed list and force a safe resync instead of silently
                // installing peer state with defer-like behavior.
                let remove_all = AddressPrefixOrf {
                    action: OrfAction::RemoveAll,
                    match_: OrfMatch::Permit,
                    sequence: 0,
                    min_len: 0,
                    max_len: 0,
                    prefix: None,
                };
                let _ = filter.apply(&[remove_all]);
                warn!(
                    %peer,
                    ?family,
                    when_to_refresh = value,
                    "unknown ORF When-to-refresh — installed ORF list for this type reset"
                );
                true
            }
            _ => filter.apply(entries).is_err(),
        };
        let now_empty = filter.is_empty();
        if reset && !unknown_when {
            warn!(%peer, ?family, "malformed ORF entry — installed ORF list for this type reset");
        }
        // An emptied filter (REMOVE-ALL or a reset) means permit-all again —
        // drop the entry so the absent-filter fast path applies.
        if now_empty && let Some(by_family) = self.peer_orf_filters.get_mut(&peer) {
            by_family.remove(&family);
        }
        if reset || when == WhenToRefresh::Immediate {
            // If this peer's EoR for the family was withheld at `PeerUp`
            // (GR restarter + §6 gate, see `send_initial_table`), the forced
            // resync below is the gated flood: move the family into
            // `pending_eor` and mark the peer dirty so the resync piggybacks
            // the EoR behind the flooded routes (or flushes it standalone
            // when the filter yields no routes). A DEFER update lifts the
            // gate without flooding, so the deferral stays put and rides the
            // later plain ROUTE-REFRESH or IMMEDIATE update that actually
            // advertises the family.
            if let Some(families) = self.gr_deferred_eor.get_mut(&peer)
                && families.remove(&family)
            {
                if families.is_empty() {
                    self.gr_deferred_eor.remove(&peer);
                }
                self.pending_eor.entry(peer).or_default().insert(family);
                self.mark_outbound_dirty(peer);
            }
            self.force_outbound_peers.insert(peer);
            self.distribute_changes(&HashSet::new(), &HashSet::new());
        }
        let _ = reply.send(Ok(()));
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "RIB update messages carry every supported family as one transaction"
    )]
    pub(super) fn enqueue_routes_received(
        &mut self,
        peer: IpAddr,
        announced: Vec<crate::route::Route>,
        withdrawn: Vec<(Prefix, u32)>,
        flowspec_announced: Vec<crate::route::FlowSpecRoute>,
        flowspec_withdrawn: Vec<crate::route::FlowSpecKey>,
        evpn_announced: Vec<crate::route::EvpnRibRoute>,
        evpn_withdrawn: Vec<rustbgpd_wire::EvpnRouteKey>,
    ) {
        if let std::collections::hash_map::Entry::Vacant(entry) = self.ribs.entry(peer) {
            let pending = PendingRoutesReceived::new(
                peer,
                announced,
                withdrawn,
                flowspec_announced,
                flowspec_withdrawn,
                evpn_announced,
                evpn_withdrawn,
            );
            entry.insert(AdjRibIn::with_capacity(
                peer,
                pending.route_capacity_hint(),
                pending.flowspec_capacity_hint(),
            ));
            self.pending_route_batches.push_back(pending);
            return;
        }

        self.pending_route_batches
            .push_back(PendingRoutesReceived::new(
                peer,
                announced,
                withdrawn,
                flowspec_announced,
                flowspec_withdrawn,
                evpn_announced,
                evpn_withdrawn,
            ));
    }

    pub(super) fn process_next_route_chunk(&mut self) -> bool {
        let Some(mut pending) = self.pending_route_batches.pop_front() else {
            return false;
        };

        let peer = pending.peer();
        let Some(chunk) = pending.next_chunk() else {
            // Empty/exhausted batch — flush anything still accumulated
            // (defensive; normally the has_more() branch below flushes).
            self.flush_pending_distribute();
            return false;
        };

        match chunk {
            PendingRouteChunk::Withdrawn(withdrawn) => {
                self.pending_exact_export_withdrawals.extend(
                    withdrawn
                        .iter()
                        .map(|&(prefix, path_id)| ExactExportKey::Unicast(prefix, path_id)),
                );
                self.process_withdraw_chunk(peer, withdrawn);
            }
            PendingRouteChunk::Announced(announced) => {
                self.process_announce_chunk(peer, announced);
            }
            PendingRouteChunk::FlowSpecWithdrawn(flowspec_withdrawn) => {
                self.pending_exact_export_withdrawals.extend(
                    flowspec_withdrawn
                        .iter()
                        .cloned()
                        .map(ExactExportKey::FlowSpec),
                );
                self.process_flowspec_withdraw_chunk(peer, flowspec_withdrawn);
            }
            PendingRouteChunk::FlowSpecAnnounced(flowspec_announced) => {
                self.process_flowspec_announce_chunk(peer, flowspec_announced);
            }
            PendingRouteChunk::EvpnWithdrawn(evpn_withdrawn) => {
                self.pending_exact_export_withdrawals
                    .extend(evpn_withdrawn.iter().copied().map(ExactExportKey::Evpn));
                self.process_evpn_withdraw_chunk(peer, evpn_withdrawn);
            }
            PendingRouteChunk::EvpnAnnounced(evpn_announced) => {
                self.process_evpn_announce_chunk(peer, evpn_announced);
            }
        }

        if pending.has_more() {
            self.pending_route_batches.push_front(pending);
        } else {
            // Batch fully drained — distribute the changes accumulated
            // across all its chunks in one coalesced outbound pass.
            self.flush_pending_distribute();
            let withdrawn = std::mem::take(&mut self.pending_exact_export_withdrawals);
            self.retire_exact_export_rejections(withdrawn);
        }
        true
    }

    /// Distribute the best-path changes accumulated across the chunks of a
    /// route batch in a single pass, then clear the accumulator. Called when
    /// a batch drains (see [`Self::process_next_route_chunk`]); a no-op when
    /// nothing accumulated. Deferring distribution this way coalesces a
    /// multi-chunk initial-load flood into one outbound batch per peer
    /// instead of one per 1024-route chunk, while `recompute_best` still runs
    /// per chunk so Loc-RIB and route events stay live mid-batch.
    fn flush_pending_distribute(&mut self) {
        if self.pending_distribute_changed.is_empty() && self.pending_distribute_affected.is_empty()
        {
            return;
        }
        let changed = std::mem::take(&mut self.pending_distribute_changed);
        let affected = std::mem::take(&mut self.pending_distribute_affected);
        self.distribute_changes(&changed, &affected);
    }

    /// Register `peer` as a unicast announcer for `prefix` in the reverse
    /// index. MUST be called by every seam that inserts a unicast route
    /// into an Adj-RIB-In — see the [`UnicastPrefixPeers`] contract.
    pub(in crate::manager) fn register_unicast_announcer(&mut self, peer: IpAddr, prefix: Prefix) {
        let peers = self.unicast_prefix_peers.entry(prefix).or_default();
        if !peers.contains(&peer) {
            peers.push(peer);
        }
    }

    /// All Adj-RIB-In candidates for `prefix`, collected via the announcing-
    /// peers reverse index: only peers indexed for the prefix are probed,
    /// instead of every peer's Adj-RIB-In (mostly misses at RR scale). A
    /// stale index entry (peer withdrew / went down and was not yet pruned)
    /// yields no candidates and is skipped — over-counting is benign.
    pub(in crate::manager) fn unicast_candidates<'a>(
        ribs: &'a HashMap<IpAddr, AdjRibIn>,
        prefix_peers: &'a UnicastPrefixPeers,
        prefix: &'a Prefix,
    ) -> impl Iterator<Item = &'a crate::route::Route> {
        prefix_peers
            .get(prefix)
            .into_iter()
            .flatten()
            .filter_map(move |peer| ribs.get(peer))
            .flat_map(move |rib| rib.iter_prefix(prefix))
    }

    /// Announce fast path: full per-prefix rescans only where the
    /// announce could actually have changed the Loc-RIB best.
    ///
    /// All changes in an announce chunk are inserts/replacements in ONE
    /// peer's Adj-RIB-In (already applied when this runs). Per prefix the
    /// challenger is the announcing peer's own best candidate (its
    /// `iter_prefix` minimum under `best_path_cmp`), compared against the
    /// RIB-RESIDENT current best — not the Loc-RIB clone — so the decision
    /// is grounded in the same objects a full rescan would compare.
    /// Enumerated cases, with anything doubtful falling back to the full
    /// (indexed) rescan:
    ///
    /// 1. No current best exists → full rescan (the announce almost
    ///    certainly installs one; also re-establishes the "a best exists
    ///    iff any candidate exists" invariant cheaply — few candidates).
    /// 2. The announcing peer OWNS the current best → full rescan: the
    ///    best itself may have been replaced (payload change, possibly now
    ///    losing to another candidate), and same-peer Add-Path candidates
    ///    are the only ones that can TIE it (`best_path_cmp` is a total
    ///    order whose final step compares peer addresses), which only the
    ///    full enumeration + `LocRib::recompute` payload arbitration
    ///    resolves.
    /// 3. The current best's own Adj-RIB-In entry is missing → full rescan
    ///    (defensive; unreachable while every mutation seam recomputes its
    ///    affected set).
    /// 4. The challenger strictly LOSES to the rib-resident best → skip
    ///    entirely. Sound: every candidate of the announcing peer loses
    ///    (the challenger is their minimum), all other candidates are
    ///    untouched and still lose to the best, and no payload changed —
    ///    a full rescan would compute `did_change == false` (no Loc-RIB
    ///    write, no route event, no BMP emission).
    /// 5. The challenger strictly BEATS the rib-resident best → install it
    ///    directly, no rescan: it beats the old minimum, hence every
    ///    untouched candidate, and its own peer's other candidates by
    ///    construction (within-peer ties resolve to the same first-in-
    ///    `iter_prefix`-order object a full scan would pick, cross-peer
    ///    ties are impossible) — so it IS the full scan's winner.
    ///    `LocRib::recompute` over the singleton keeps the change
    ///    detection identical. Only taken with the BMP Loc-RIB tap off:
    ///    BMP path-marking needs the runner-up, which requires the full
    ///    candidate enumeration anyway.
    /// 6. Challenger ties the best → unreachable cross-peer (case 2 covers
    ///    same-peer) → conservative full rescan.
    pub(super) fn recompute_best_after_announce(
        &mut self,
        peer: IpAddr,
        affected: &HashSet<Prefix>,
    ) -> HashSet<Prefix> {
        use std::cmp::Ordering;

        // Some(true): install the challenger directly (case 5).
        // Some(false): provably unchanged, skip (case 4).
        // None: full rescan (cases 1-3, 6).
        let mut changed = HashSet::new();
        let mut needs_full = HashSet::new();
        for prefix in affected {
            let verdict = 'fast: {
                let Some(best) = self.loc_rib.get(prefix) else {
                    break 'fast None; // case 1
                };
                if best.peer == peer {
                    break 'fast None; // case 2
                }
                let Some(best_in_rib) = self
                    .ribs
                    .get(&best.peer)
                    .and_then(|rib| rib.get(prefix, best.path_id))
                else {
                    break 'fast None; // case 3
                };
                let challenger = self.ribs.get(&peer).and_then(|rib| {
                    rib.iter_prefix(prefix)
                        .min_by(|a, b| crate::best_path::best_path_cmp(a, b))
                });
                let Some(challenger) = challenger else {
                    break 'fast None; // announce raced a removal: rescan
                };
                match crate::best_path::best_path_cmp(challenger, best_in_rib) {
                    Ordering::Greater => Some(false),                      // case 4
                    Ordering::Less if self.bmp_tx.is_none() => Some(true), // case 5
                    _ => None, // case 5 with BMP on, or case 6
                }
            };
            match verdict {
                Some(false) => {}
                None => {
                    needs_full.insert(*prefix);
                }
                Some(true) => {
                    let previous_best = self.loc_rib.get(prefix).map(|r| (r.peer, r.path_id));
                    // Re-resolve the winner (the classification borrows
                    // ended above): the announcing peer's best candidate.
                    let Some(winner) = self.ribs.get(&peer).and_then(|rib| {
                        rib.iter_prefix(prefix)
                            .min_by(|a, b| crate::best_path::best_path_cmp(a, b))
                    }) else {
                        needs_full.insert(*prefix);
                        continue;
                    };
                    // Singleton recompute: the winner is provably the full
                    // scan's minimum, and `LocRib::recompute` keeps the
                    // payload-change detection identical to the full path.
                    if self.loc_rib.recompute(*prefix, std::iter::once(winner)) {
                        changed.insert(*prefix);
                        self.publish_best_change_events(*prefix, previous_best);
                    }
                }
            }
        }
        changed.extend(self.recompute_best(&needs_full));
        changed
    }

    /// Withdraw fast path: the withdrawals (already applied to ONE peer's
    /// Adj-RIB-In) only *removed* candidates — no payloads changed. If the
    /// current best's own Adj-RIB-In entry still exists, the minimum of a
    /// shrunken set that still contains the old minimum is unchanged →
    /// skip. If the best was withdrawn (or no best exists), full rescan.
    pub(super) fn recompute_best_after_withdraw(
        &mut self,
        affected: &HashSet<Prefix>,
    ) -> HashSet<Prefix> {
        let needs_full: HashSet<Prefix> = affected
            .iter()
            .filter(|prefix| {
                let Some(best) = self.loc_rib.get(prefix) else {
                    return true; // no best: rescan (cheap; re-checks invariant)
                };
                self.ribs
                    .get(&best.peer)
                    .and_then(|rib| rib.get(prefix, best.path_id))
                    .is_none() // best itself withdrawn → full rescan
            })
            .copied()
            .collect();
        self.recompute_best(&needs_full)
    }

    /// Recompute Loc-RIB best path for a set of affected prefixes.
    /// Returns the set of prefixes that actually changed.
    /// Also emits route events to the broadcast channel.
    pub(super) fn recompute_best(&mut self, affected: &HashSet<Prefix>) -> HashSet<Prefix> {
        let mut changed = HashSet::new();
        for prefix in affected {
            let previous_best = self.loc_rib.get(prefix).map(|r| (r.peer, r.path_id));
            // Inner scope: `candidates` borrows the Adj-RIB-Ins and must be
            // dropped before the `&mut self` event publication below.
            let did_change = {
                // One probe pass over the announcing-peers reverse index does
                // double duty: collect the candidates AND lazily prune peers
                // whose Adj-RIB-In no longer holds this prefix (withdraw,
                // session down, GR/LLGR sweep, ... — removal seams have no
                // eager hook by design, see the `UnicastPrefixPeers` contract).
                let mut candidates: smallvec::SmallVec<[&crate::route::Route; 8]> =
                    smallvec::SmallVec::new();
                if let Some(peers) = self.unicast_prefix_peers.get_mut(prefix) {
                    let ribs = &self.ribs;
                    peers.retain(|peer| {
                        let before = candidates.len();
                        if let Some(rib) = ribs.get(peer) {
                            candidates.extend(rib.iter_prefix(prefix));
                        }
                        candidates.len() > before
                    });
                    if peers.is_empty() {
                        self.unicast_prefix_peers.remove(prefix);
                    }
                }
                let did_change = self.loc_rib.recompute(*prefix, candidates.iter().copied());
                if did_change {
                    // RFC 9069 Loc-RIB tap: any change to the best is a
                    // Route Monitoring announce of the new best (BGP
                    // implicit withdraw covers replacement); a best that
                    // disappeared is an explicit withdraw. Timestamp = the
                    // Loc-RIB install time as stored by the recompute.
                    // Best-unchanged prefixes never reach this branch.
                    if self.bmp_tx.is_some() {
                        let (pdu, path_status) = match self.loc_rib.get(prefix) {
                            Some(best) => {
                                // Path Marking reason = the decisive step
                                // versus the runner-up (the closest
                                // competitor), re-derived here from the
                                // explain ladder — the hot-path comparator
                                // records nothing, and a sole candidate
                                // carries no reason (nothing was compared).
                                let runner_up = candidates
                                    .iter()
                                    .copied()
                                    .filter(|c| !(c.peer == best.peer && c.path_id == best.path_id))
                                    .min_by(|a, b| crate::best_path::best_path_cmp(a, b));
                                let reason = runner_up.map(|r| {
                                    crate::best_path::best_path_cmp_with_reason(best, r).1
                                });
                                let status = crate::bmp_sync::loc_rib_path_status(
                                    best.is_stale || best.is_llgr_stale,
                                    reason,
                                );
                                (
                                    crate::bmp_sync::synthesize_unicast_announce(best),
                                    Some(status),
                                )
                            }
                            None => (crate::bmp_sync::synthesize_unicast_withdraw(*prefix), None),
                        };
                        // Announce timestamp = the stored Loc-RIB
                        // install time, so a later BMP table dump
                        // reports the exact same stamp for this route
                        // (LAN-193). Withdraws have no stored entry —
                        // event time is the honest stamp.
                        let timestamp = self
                            .loc_rib
                            .install_time(prefix)
                            .unwrap_or_else(std::time::SystemTime::now);
                        self.emit_bmp_loc_rib(pdu, path_status, timestamp);
                    }
                }
                did_change
            };
            if did_change {
                changed.insert(*prefix);
                self.publish_best_change_events(*prefix, previous_best);
            }
        }
        self.metrics
            .set_loc_rib_prefixes("all", gauge_val(self.loc_rib.len()));
        changed
    }

    /// Emit the route event for a Loc-RIB best change already applied
    /// (added / withdrawn / replaced), diffing `previous_best` against the
    /// freshly installed state. Shared by the full rescan and the announce
    /// fast path's direct install.
    fn publish_best_change_events(&mut self, prefix: Prefix, previous_best: Option<(IpAddr, u32)>) {
        let current_best = self.loc_rib.get(&prefix).map(|r| (r.peer, r.path_id));
        match (previous_best, current_best) {
            (None, Some((peer, path_id))) => {
                debug!(%prefix, %peer, "best path added");
                self.publish_route_event(RouteEvent {
                    event_id: 0,
                    event_type: RouteEventType::Added,
                    prefix,
                    peer: Some(peer),
                    previous_peer: None,
                    target_peer: None,
                    timestamp: crate::event::unix_timestamp_now(),
                    path_id,
                    reason: String::new(),
                });
            }
            (Some((old_peer, old_path_id)), None) => {
                debug!(%prefix, "best path removed");
                self.publish_route_event(RouteEvent {
                    event_id: 0,
                    event_type: RouteEventType::Withdrawn,
                    prefix,
                    peer: None,
                    previous_peer: Some(old_peer),
                    target_peer: None,
                    timestamp: crate::event::unix_timestamp_now(),
                    path_id: old_path_id,
                    reason: String::new(),
                });
            }
            (Some((old_peer, _old_path_id)), Some((peer, path_id))) => {
                debug!(%prefix, %peer, "best path changed");
                self.publish_route_event(RouteEvent {
                    event_id: 0,
                    event_type: RouteEventType::BestChanged,
                    prefix,
                    peer: Some(peer),
                    previous_peer: Some(old_peer),
                    target_peer: None,
                    timestamp: crate::event::unix_timestamp_now(),
                    path_id,
                    reason: String::new(),
                });
            }
            (None, None) => {}
        }
    }

    /// Distribute Loc-RIB changes to all registered outbound peers.
    ///
    /// For clean peers, only `changed_prefixes` are evaluated. Dirty peers
    /// (those that failed a previous `try_send()`) get a full export resync:
    /// all Loc-RIB and `AdjRibOut` prefixes are diffed to bring the peer's
    /// view back in sync. `AdjRibOut` is only committed after a successful
    /// channel send; on failure the peer stays dirty for retry via the
    /// resync timer.
    ///
    /// Routes are filtered by `sendable_families` (set at `PeerUp` time)
    /// so that Adj-RIB-Out only contains routes the transport can actually
    /// serialize for this peer. The transport retains `is_family_negotiated`
    /// as a safety net.
    #[expect(
        clippy::too_many_lines,
        reason = "distribution loop coordinates dirty peers, forced resync, and all families"
    )]
    pub(super) fn distribute_changes(
        &mut self,
        best_changed: &HashSet<Prefix>,
        all_affected: &HashSet<Prefix>,
    ) {
        if best_changed.is_empty()
            && all_affected.is_empty()
            && self.dirty_peers.is_empty()
            && self.force_outbound_peers.is_empty()
        {
            return;
        }

        let peers: Vec<IpAddr> = self.outbound_peers.keys().copied().collect();
        // Pass-scoped export memo: shares post-modification attribute
        // sets and AS_PATH match strings across the whole peer fanout —
        // this outlives the per-peer iteration deliberately, since the
        // win is identical modified attrs across peers sharing a chain.
        let mut export_memo = ExportMemo::default();
        // Update-group shared staging: ONE export-tail pass per (group,
        // changed prefix), committed to the group tables. The per-peer
        // loop below emits the deltas per member via the source-flip
        // matrix; disqualified peers take the per-peer staging path
        // exactly as before.
        let group_stage = self.stage_update_groups(best_changed, &mut export_memo);
        for peer in peers {
            let member_of = self.grouped_member_of(peer);
            // For dirty peers, compute full prefix set from Loc-RIB + AdjRibOut
            let is_dirty = self.dirty_peers.contains(&peer);
            // `is_force` peers are dirty-equivalent for prefix enumeration AND
            // bypass the AdjRibOut equality suppression in the per-prefix
            // helpers — see `RibUpdate::RefreshPeerOutbound` rationale on
            // `force_outbound_peers`.
            let is_force = self.force_outbound_peers.contains(&peer);
            // A grouped force-only resync intentionally re-announces the
            // current group table and ignores pass tombstones/deltas. Its
            // setters synchronously run an empty distribution pass, so it
            // cannot meet a genuine best-change pass. A failed force send is
            // also dirty and is valid here: dirty assembly includes the
            // tombstones needed to heal subsequent churn.
            debug_assert!(
                member_of.is_none() || !is_force || is_dirty || best_changed.is_empty(),
                "a grouped force-only resync cannot share a nonempty best-change pass"
            );
            let resync = is_dirty || is_force;
            let effective_prefixes: Cow<'_, HashSet<Prefix>> = if resync {
                let mut all: HashSet<Prefix> = self.loc_rib.iter().map(|r| r.prefix).collect();
                if let Some(gid) = member_of {
                    // A grouped member's advertised state is the group
                    // table (plus any pending withdraw residue); the
                    // per-peer Adj-RIB-Out holds no unicast for it.
                    if let Some(group) = self.group_ribs.get(&gid) {
                        all.extend(group.table.iter().map(|r| r.prefix));
                        all.extend(group.tombstones.iter().map(|(p, _)| *p));
                    }
                    if let Some(base) = self.pending_regroup_baseline.get(&peer) {
                        all.extend(base.unicast.keys().map(|(p, _)| *p));
                    }
                } else {
                    // For multi-path (and per-client-best — same
                    // Adj-RIB-In candidate source) dirty resync, also
                    // include all Adj-RIB-In prefixes
                    if self.peer_has_any_add_path_send(peer)
                        || self.peer_per_client_best.contains(&peer)
                    {
                        for rib in self.ribs.values() {
                            all.extend(rib.iter().map(|r| r.prefix));
                        }
                    }
                    if let Some(rib_out) = self.adj_ribs_out.get(&peer) {
                        all.extend(rib_out.iter().map(|r| r.prefix));
                    }
                }
                // Extra (over-)withdraw residue keys can be in NONE of
                // the sources above (withdrawn while the peer was
                // dirty, then carried across a regroup): without them
                // a resync can enumerate empty — or skip the keys
                // entirely — and the owed withdraws are never emitted.
                if let Some(extras) = self.pending_extra_withdraws.get(&peer) {
                    all.extend(extras.unicast.iter().map(|(prefix, _)| *prefix));
                }
                Cow::Owned(all)
            } else if member_of.is_some() {
                // Grouped peers have no ORR / Add-Path extras (both are
                // grouping disqualifiers): the group deltas cover
                // exactly the best-changed set.
                Cow::Borrowed(best_changed)
            } else {
                // An RFC 9107 ORR peer selects from the per-target
                // candidate set, not the Loc-RIB best — a candidate
                // change that leaves the Loc-RIB best untouched can
                // still flip the vantage best, so ORR peers stage every
                // affected prefix (same reasoning as Add-Path send).
                // Per-client-best (RFC 7947 §2.3.2) selects from the
                // same per-target candidate set — a candidate change
                // can flip the filtered best without moving the Loc-RIB
                // best, so those peers stage every affected prefix too.
                let peer_has_resolved_orr = self
                    .peer_orr_vantage
                    .get(&peer)
                    .is_some_and(|vantage| self.orr.spf.contains_key(vantage));
                let peer_per_client_best = self.peer_per_client_best.contains(&peer);
                let extras: Vec<Prefix> = all_affected
                    .iter()
                    .filter(|prefix| {
                        (peer_has_resolved_orr
                            || peer_per_client_best
                            || self.add_path_send_max_for_prefix(peer, prefix) > 0)
                            && !best_changed.contains(*prefix)
                    })
                    .copied()
                    .collect();
                // Common case (no ORR vantage, no Add-Path extras):
                // borrow the shared changed set instead of re-hashing a
                // per-peer clone of it — this loop runs once per
                // outbound peer per distribution pass.
                if extras.is_empty() {
                    Cow::Borrowed(best_changed)
                } else {
                    let mut prefixes = best_changed.clone();
                    prefixes.extend(extras);
                    Cow::Owned(prefixes)
                }
            };
            let effective_flowspec_rules: HashSet<crate::route::FlowSpecKey> = if resync {
                let mut all: HashSet<crate::route::FlowSpecKey> = self
                    .loc_rib
                    .iter_flowspec()
                    .map(crate::route::FlowSpecRoute::selection_key)
                    .collect();
                if let Some(rib_out) = self.adj_ribs_out.get(&peer) {
                    all.extend(
                        rib_out
                            .iter_flowspec()
                            .map(crate::route::FlowSpecRoute::selection_key),
                    );
                }
                all
            } else {
                HashSet::new()
            };

            let effective_evpn_keys: HashSet<rustbgpd_wire::EvpnRouteKey> = if resync {
                let mut all: HashSet<rustbgpd_wire::EvpnRouteKey> = self
                    .loc_rib
                    .iter_evpn()
                    .map(crate::route::EvpnRibRoute::key)
                    .collect();
                if let Some(rib_out) = self.adj_ribs_out.get(&peer) {
                    all.extend(rib_out.iter_evpn().map(crate::route::EvpnRibRoute::key));
                }
                all
            } else {
                HashSet::new()
            };

            let effective_bgpls_keys: HashSet<crate::route::BgpLsRouteKey> = if resync {
                let mut all: HashSet<crate::route::BgpLsRouteKey> = self
                    .loc_rib
                    .iter_bgpls()
                    .map(crate::route::BgpLsRibRoute::key)
                    .collect();
                if let Some(rib_out) = self.adj_ribs_out.get(&peer) {
                    all.extend(rib_out.iter_bgpls().map(crate::route::BgpLsRibRoute::key));
                }
                all
            } else {
                HashSet::new()
            };

            // A member of a VPN-staging group holds no per-peer VPN
            // Adj-RIB-Out: its advertised VPN state is the group table
            // (plus pending withdraw residue), so the resync enumeration
            // synthesizes from those — mirroring the unicast synthesis
            // above. (RTC members' Φ is applied by the resync assembly,
            // not the enumeration — over-enumeration is harmless.)
            let vpn_grouped = self.vpn_grouped_member_of(peer);
            let effective_l3vpn_keys: HashSet<rustbgpd_wire::VpnRouteKey> = if resync {
                let mut all: HashSet<rustbgpd_wire::VpnRouteKey> = self
                    .loc_rib
                    .iter_vpn()
                    .map(|route| route.nlri.key())
                    .collect();
                if let Some(gid) = vpn_grouped {
                    if let Some(group) = self.group_ribs.get(&gid) {
                        all.extend(group.table.iter_vpn().map(|route| route.nlri.key()));
                        all.extend(group.vpn_tombstones.iter().copied());
                    }
                    if let Some(base) = self.pending_regroup_baseline.get(&peer) {
                        all.extend(base.vpn.keys().copied());
                    }
                } else {
                    // For a VPN Add-Path-send resync, the staged top-N draws from
                    // every Adj-RIB-In identity, not just the Loc-RIB bests.
                    if self.peer_vpn_add_path_send(peer) {
                        for rib in self.ribs.values() {
                            all.extend(rib.iter_vpn().map(|route| route.nlri.key()));
                        }
                    }
                    if let Some(rib_out) = self.adj_ribs_out.get(&peer) {
                        all.extend(rib_out.iter_vpn().map(|route| route.nlri.key()));
                    }
                }
                // Same residue rule as the unicast enumeration above.
                if let Some(extras) = self.pending_extra_withdraws.get(&peer) {
                    all.extend(extras.vpn.iter().copied());
                }
                all
            } else {
                HashSet::new()
            };

            let effective_labeled_keys: HashSet<Prefix> = if resync {
                let mut all: HashSet<Prefix> = self
                    .loc_rib
                    .iter_labeled()
                    .map(|route| route.nlri.key())
                    .collect();
                // For a labeled Add-Path-send resync, the staged top-N draws
                // from every Adj-RIB-In identity, not just the Loc-RIB bests.
                if self.peer_labeled_add_path_send(peer) {
                    for rib in self.ribs.values() {
                        all.extend(rib.iter_labeled().map(|route| route.nlri.key()));
                    }
                }
                if let Some(rib_out) = self.adj_ribs_out.get(&peer) {
                    all.extend(rib_out.iter_labeled().map(|route| route.nlri.key()));
                }
                all
            } else {
                HashSet::new()
            };

            let effective_rtc_keys: HashSet<crate::route::RtcRibRouteKey> = if resync {
                let mut all: HashSet<crate::route::RtcRibRouteKey> = self
                    .loc_rib
                    .iter_rtc()
                    .map(crate::route::RtcRibRoute::key)
                    .collect();
                if let Some(rib_out) = self.adj_ribs_out.get(&peer) {
                    all.extend(rib_out.iter_rtc().map(crate::route::RtcRibRoute::key));
                }
                all
            } else {
                HashSet::new()
            };

            if effective_prefixes.is_empty()
                && effective_flowspec_rules.is_empty()
                && effective_evpn_keys.is_empty()
                && effective_bgpls_keys.is_empty()
                && effective_l3vpn_keys.is_empty()
                && effective_labeled_keys.is_empty()
                && effective_rtc_keys.is_empty()
            {
                self.clear_policy_filtered_routes_for_peer(peer);
                // Resync flags must clear here too — otherwise a
                // force-only refresh on a peer with no exportable
                // routes would leave `force_outbound_peers` populated,
                // and the next unrelated dirty resync (or another
                // RefreshPeerOutbound for a different reason) would
                // accidentally inherit the bypass-equality-suppression
                // semantics. Same shape for `dirty_peers` for symmetry.
                // The residue drop is safe here: pending extra
                // withdraws feed the enumerations above, so an empty
                // enumeration proves there is no residue to emit.
                if is_dirty {
                    self.dirty_peers.remove(&peer);
                    self.clear_grouped_member_synced(peer);
                }
                if is_force {
                    self.force_outbound_peers.remove(&peer);
                }
                continue;
            }

            let mut announce = Vec::new();
            let mut withdraw = Vec::new();
            let mut nh_override_flags: Vec<Option<rustbgpd_policy::NextHopAction>> = Vec::new();
            // Set for an in-sync grouped member covered by the group's
            // pre-built shared emission: the announce payload is an Arc
            // clone shared across members, not a per-member Vec build.
            let mut shared_unicast: Option<super::update_groups::SharedUnicastPayload> = None;
            let mut fs_announce = Vec::new();
            let mut fs_withdraw = Vec::new();
            let mut evpn_announce = Vec::new();
            let mut evpn_withdraw = Vec::new();
            let mut bgpls_announce = Vec::new();
            let mut bgpls_withdraw = Vec::new();
            let mut vpn_announce = Vec::new();
            let mut vpn_withdraw = Vec::new();
            let mut labeled_announce = Vec::new();
            let mut labeled_withdraw = Vec::new();
            let mut rtc_announce = Vec::new();
            let mut rtc_withdraw = Vec::new();
            let mut group_otc_blocked = Vec::new();
            let mut current_policy_filtered_routes: HashSet<PolicyFilteredRouteKey> =
                HashSet::new();

            // Grouped member: the unicast portion comes from the group —
            // source-flip matrix over this pass's deltas for a clean
            // member, full-table replay (tombstone withdraws / regroup
            // one-shot diff) for a resyncing one. No per-prefix staging,
            // no policy eval: the shared group pass already ran once.
            // Non-unicast families ride the per-peer path below
            // unchanged, in the same OutboundRouteUpdate.
            if let Some(gid) = member_of {
                // The member's Φ: the VPN resync assembles under the
                // CURRENT filter — the member may have gone dirty across
                // a Φ change, which is why the membership-delta path
                // defers to this (design §2.4).
                let member_filter = self.member_rt_filter(peer);
                if let Some(group) = self.group_ribs.get(&gid) {
                    if resync {
                        Self::assemble_group_resync(
                            group,
                            peer,
                            is_dirty,
                            is_force,
                            self.pending_regroup_baseline
                                .get(&peer)
                                .map(|base| &base.unicast),
                            self.pending_extra_withdraws
                                .get(&peer)
                                .map(|extras| &extras.unicast),
                            &mut announce,
                            &mut withdraw,
                            &mut nh_override_flags,
                        );
                        // VPN portion of the resync, from the group's VPN
                        // maps under the member's Φ; the per-peer VPN
                        // staging below is skipped for these members
                        // (`vpn_grouped` gate).
                        if group.stages_vpn() {
                            Self::assemble_group_vpn_resync(
                                group,
                                peer,
                                member_filter.as_ref(),
                                is_dirty,
                                is_force,
                                self.pending_regroup_baseline
                                    .get(&peer)
                                    .map(|base| &base.vpn),
                                self.pending_extra_withdraws
                                    .get(&peer)
                                    .map(|extras| &extras.vpn),
                                &mut vpn_announce,
                                &mut vpn_withdraw,
                            );
                        }
                    } else if let Some(stage) = group_stage.get(&gid) {
                        if stage.shared_applies_to(peer) {
                            // Common case: this member's matrix output IS
                            // the shared emission — enqueue Arc clones.
                            shared_unicast =
                                Some((stage.shared_announce.clone(), stage.shared_nh.clone()));
                            withdraw.extend_from_slice(&stage.shared_withdraw);
                        } else {
                            super::update_groups::emit_group_deltas_for_member(
                                &stage.deltas,
                                peer,
                                &mut announce,
                                &mut withdraw,
                                &mut nh_override_flags,
                            );
                        }
                    }
                    current_policy_filtered_routes
                        .extend(group.policy_filtered_for_member(peer, &effective_prefixes));
                    group_otc_blocked = group
                        .otc_blocked_for_member(peer, (!resync).then_some(&effective_prefixes));
                }
                // Per-member export-policy counters — integer adds, no
                // per-(prefix × peer) work. A clean pass takes the group
                // verdict delta; a resync (dirty or force) replays
                // join-style full-table counters, matching the ungrouped
                // per-prefix staging path which re-records every Loc-RIB
                // entry on resync (LAN-210).
                if resync {
                    self.apply_group_join_counters(peer, gid, None);
                } else if let Some(stage) = group_stage.get(&gid) {
                    self.apply_group_policy_counters(peer, &stage.evals);
                }
            }
            if member_of.is_some() {
                let pending = self.pending_otc_blocked.entry(peer).or_default();
                if resync {
                    pending.clear();
                } else {
                    pending.retain(|(prefix, _), _| !effective_prefixes.contains(prefix));
                }
                pending.extend(
                    group_otc_blocked
                        .into_iter()
                        .map(|route| ((route.prefix, route.path_id), route)),
                );
                if pending.is_empty() {
                    self.pending_otc_blocked.remove(&peer);
                }
            }

            // Resolve export policy, sendable families, and RR state before
            // borrowing rib_out (which holds a &mut to self.adj_ribs_out).
            let export_pol = self
                .export_policy_for(peer)
                .map(rustbgpd_policy::PolicyChain::share);
            let sendable = self.peer_sendable_families.get(&peer).cloned();
            let llgr = self.peer_advertised_llgr_families.get(&peer).cloned();
            let target_is_ebgp = self.peer_is_ebgp.get(&peer).copied().unwrap_or(true);
            let target_is_rr_client = self.peer_is_rr_client.get(&peer).copied().unwrap_or(false);
            let target_peer_asn = self.peer_asn.get(&peer).copied();
            let target_peer_group = self.peer_group.get(&peer).map(String::as_str);
            let cluster_id = self.cluster_id;
            let peer_add_path_send_max =
                self.peer_add_path_send_max.get(&peer).copied().unwrap_or(0);
            let peer_add_path_send_limits = self
                .peer_add_path_send_limits
                .get(&peer)
                .cloned()
                .unwrap_or_default();
            let peer_add_path_send_families = self
                .peer_add_path_send_families
                .get(&peer)
                .cloned()
                .unwrap_or_default();
            // ORF state, resolved before the &mut rib_out borrow below. Cloning
            // is cheap: ORF filters are small and present only for peers that
            // negotiated ORF (None for everyone else).
            let orf_filters = self.peer_orf_filters.get(&peer).cloned();
            // RFC 9107 ORR: a peer bound to a vantage that resolved this
            // pass takes the per-vantage best below; an unresolved
            // vantage silently falls back to the standard single-best
            // (the status is surfaced by `rbgp orr`).
            let orr_ctx = self
                .peer_orr_vantage
                .get(&peer)
                .and_then(|vantage| self.orr.spf.get(vantage))
                .map(|spf| (&self.orr.topology, spf));
            let per_client_best = self.peer_per_client_best.contains(&peer);
            let rtc_filter = self.rtc_vpn_filter(peer, sendable.as_ref());
            let orf_gated = self
                .peer_orf_pending
                .get(&peer)
                .cloned()
                .unwrap_or_default();
            let loc_rib = &self.loc_rib;
            let loc_rib_len = loc_rib.len();
            let target_peer_label = peer.to_string();
            let metrics = self.metrics.clone();
            let policy_stats = self.export_policy_stats.entry(peer).or_default();

            let rib_out = self
                .adj_ribs_out
                .entry(peer)
                .or_insert_with(|| AdjRibOut::with_capacity(peer, loc_rib_len));

            // Stage: compute delta without mutating AdjRibOut. Grouped
            // members skip the per-prefix staging wholesale — their
            // unicast update was assembled from the group table above.
            let empty_prefixes: HashSet<Prefix> = HashSet::new();
            let staging_prefixes: &HashSet<Prefix> = if member_of.is_none() {
                &effective_prefixes
            } else {
                &empty_prefixes
            };
            for prefix in staging_prefixes {
                let family = prefix_family(prefix);
                // RFC 5291 §6 gate: suppress this family's advertisement (incl.
                // ongoing churn) until the peer's first ROUTE-REFRESH lifts it.
                if orf_gated.contains(&family) {
                    continue;
                }
                let orf = orf_filters.as_ref().and_then(|m| m.get(&family));
                let prefix_send_max = if peer_add_path_send_families.contains(&family) {
                    peer_add_path_send_limits
                        .get(&family)
                        .copied()
                        .unwrap_or(peer_add_path_send_max)
                } else {
                    0
                };
                if prefix_send_max > 0 {
                    // Multi-path: collect all candidates, filter, sort, diff
                    let mut policy_filtered = Vec::new();
                    Self::distribute_multipath_prefix(
                        &self.ribs,
                        &self.unicast_prefix_peers,
                        rib_out,
                        &self.peer_is_rr_client,
                        prefix,
                        peer,
                        target_peer_asn,
                        target_peer_group,
                        prefix_send_max,
                        false,
                        target_is_ebgp,
                        target_is_rr_client,
                        cluster_id,
                        sendable.as_ref(),
                        llgr.as_ref(),
                        export_pol.as_ref(),
                        orf,
                        orr_ctx,
                        &mut export_memo,
                        &metrics,
                        policy_stats,
                        &target_peer_label,
                        &mut announce,
                        &mut withdraw,
                        &mut nh_override_flags,
                        &mut policy_filtered,
                        is_force,
                    );
                    current_policy_filtered_routes.extend(policy_filtered);
                } else if per_client_best {
                    // RFC 7947 §2.3.2 per-client best-path: the first
                    // export-policy-permitted candidate from the
                    // per-target candidate set, staged at path_id 0
                    // (single-best shape). Add-Path families took the
                    // multipath arm above — a negotiated capability
                    // outranks the fallback. ORR cannot coexist: the
                    // vantage requires an iBGP route-reflector-client
                    // while per_client_best requires an eBGP
                    // route-server client (validation-enforced).
                    debug_assert!(orr_ctx.is_none(), "ORR vantage on a per-client-best peer");
                    let mut policy_filtered = Vec::new();
                    Self::distribute_multipath_prefix(
                        &self.ribs,
                        &self.unicast_prefix_peers,
                        rib_out,
                        &self.peer_is_rr_client,
                        prefix,
                        peer,
                        target_peer_asn,
                        target_peer_group,
                        1,
                        true,
                        target_is_ebgp,
                        target_is_rr_client,
                        cluster_id,
                        sendable.as_ref(),
                        llgr.as_ref(),
                        export_pol.as_ref(),
                        orf,
                        None,
                        &mut export_memo,
                        &metrics,
                        policy_stats,
                        &target_peer_label,
                        &mut announce,
                        &mut withdraw,
                        &mut nh_override_flags,
                        &mut policy_filtered,
                        is_force,
                    );
                    current_policy_filtered_routes.extend(policy_filtered);
                } else if let Some((orr_topology, orr_spf)) = orr_ctx {
                    // ORR peer with a resolved vantage: per-vantage best.
                    let mut policy_filtered = Vec::new();
                    Self::distribute_orr_best_prefix(
                        &self.ribs,
                        &self.unicast_prefix_peers,
                        rib_out,
                        &self.peer_is_rr_client,
                        orr_topology,
                        orr_spf,
                        prefix,
                        peer,
                        target_peer_asn,
                        target_peer_group,
                        target_is_ebgp,
                        target_is_rr_client,
                        cluster_id,
                        sendable.as_ref(),
                        llgr.as_ref(),
                        export_pol.as_ref(),
                        orf,
                        &mut export_memo,
                        &metrics,
                        policy_stats,
                        &target_peer_label,
                        &mut announce,
                        &mut withdraw,
                        &mut nh_override_flags,
                        &mut policy_filtered,
                        is_force,
                    );
                    current_policy_filtered_routes.extend(policy_filtered);
                } else {
                    let mut policy_filtered = Vec::new();
                    let mut target = ExportTarget::Peer {
                        peer,
                        peer_asn: target_peer_asn,
                        peer_group: target_peer_group,
                        metrics: &metrics,
                        policy_stats: &mut *policy_stats,
                        peer_label: &target_peer_label,
                    };
                    Self::distribute_single_best_prefix(
                        loc_rib,
                        rib_out,
                        &self.peer_is_rr_client,
                        prefix,
                        &mut target,
                        target_is_ebgp,
                        target_is_rr_client,
                        cluster_id,
                        sendable.as_ref(),
                        llgr.as_ref(),
                        export_pol.as_ref(),
                        orf,
                        &mut export_memo,
                        &mut announce,
                        &mut withdraw,
                        &mut nh_override_flags,
                        &mut policy_filtered,
                        is_force,
                    );
                    current_policy_filtered_routes.extend(policy_filtered);
                }
            }

            if resync && !effective_flowspec_rules.is_empty() {
                Self::stage_flowspec_rules(
                    loc_rib,
                    rib_out,
                    &self.peer_is_rr_client,
                    &effective_flowspec_rules,
                    peer,
                    target_peer_asn,
                    target_peer_group,
                    target_is_ebgp,
                    target_is_rr_client,
                    cluster_id,
                    sendable.as_ref(),
                    llgr.as_ref(),
                    export_pol.as_ref(),
                    &metrics,
                    policy_stats,
                    &target_peer_label,
                    &mut fs_announce,
                    &mut fs_withdraw,
                );
            }

            if resync && !effective_evpn_keys.is_empty() {
                Self::stage_evpn_routes(
                    loc_rib,
                    rib_out,
                    &self.peer_is_rr_client,
                    &effective_evpn_keys,
                    peer,
                    target_peer_asn,
                    target_peer_group,
                    target_is_ebgp,
                    target_is_rr_client,
                    cluster_id,
                    sendable.as_ref(),
                    llgr.as_ref(),
                    export_pol.as_ref(),
                    &metrics,
                    policy_stats,
                    &target_peer_label,
                    &mut evpn_announce,
                    &mut evpn_withdraw,
                    is_force,
                );
            }

            if resync && !effective_bgpls_keys.is_empty() {
                Self::stage_bgpls_routes(
                    loc_rib,
                    rib_out,
                    &self.peer_is_rr_client,
                    &effective_bgpls_keys,
                    peer,
                    target_peer_asn,
                    target_peer_group,
                    target_is_ebgp,
                    target_is_rr_client,
                    cluster_id,
                    sendable.as_ref(),
                    llgr.as_ref(),
                    export_pol.as_ref(),
                    &metrics,
                    policy_stats,
                    &target_peer_label,
                    &mut bgpls_announce,
                    &mut bgpls_withdraw,
                    is_force,
                );
            }

            // A VPN-staging group member's VPN resync was assembled from
            // the group table above — no per-peer staging, no policy
            // re-evaluation.
            if resync && vpn_grouped.is_none() && !effective_l3vpn_keys.is_empty() {
                let mut target = ExportTarget::Peer {
                    peer,
                    peer_asn: target_peer_asn,
                    peer_group: target_peer_group,
                    metrics: &metrics,
                    policy_stats: &mut *policy_stats,
                    peer_label: &target_peer_label,
                };
                Self::stage_vpn_routes(
                    loc_rib,
                    &self.ribs,
                    rib_out,
                    &self.peer_is_rr_client,
                    &effective_l3vpn_keys,
                    &mut target,
                    target_is_ebgp,
                    target_is_rr_client,
                    cluster_id,
                    sendable.as_ref(),
                    llgr.as_ref(),
                    rtc_filter.as_ref(),
                    orr_ctx,
                    peer_add_path_send_max,
                    self.peer_add_path_send_limits.get(&peer),
                    &peer_add_path_send_families,
                    export_pol.as_ref(),
                    &mut vpn_announce,
                    &mut vpn_withdraw,
                    is_force,
                );
            }

            if resync && !effective_labeled_keys.is_empty() {
                Self::stage_labeled_routes(
                    loc_rib,
                    &self.ribs,
                    rib_out,
                    &self.peer_is_rr_client,
                    &effective_labeled_keys,
                    peer,
                    target_peer_asn,
                    target_peer_group,
                    target_is_ebgp,
                    target_is_rr_client,
                    cluster_id,
                    sendable.as_ref(),
                    llgr.as_ref(),
                    orr_ctx,
                    peer_add_path_send_max,
                    self.peer_add_path_send_limits.get(&peer),
                    &peer_add_path_send_families,
                    export_pol.as_ref(),
                    &metrics,
                    policy_stats,
                    &target_peer_label,
                    &mut labeled_announce,
                    &mut labeled_withdraw,
                    is_force,
                );
            }

            if resync && !effective_rtc_keys.is_empty() {
                Self::stage_rtc_routes(
                    loc_rib,
                    rib_out,
                    &self.peer_is_rr_client,
                    &effective_rtc_keys,
                    peer,
                    target_peer_asn,
                    target_peer_group,
                    target_is_ebgp,
                    target_is_rr_client,
                    cluster_id,
                    sendable.as_ref(),
                    llgr.as_ref(),
                    export_pol.as_ref(),
                    &metrics,
                    policy_stats,
                    &target_peer_label,
                    &mut rtc_announce,
                    &mut rtc_withdraw,
                    is_force,
                );
            }

            // A dirty peer on the per-peer path may carry extra
            // (over-)withdraw residue: group tombstones that rode a
            // grouped→per-peer move while the peer was dirty. Those
            // keys are in neither the Loc-RIB nor the Adj-RIB-Out
            // seeded from the regroup baseline, so the equality diff
            // above cannot emit them — append them here (the per-peer
            // twin of the grouped resync assembly's extras term). A key
            // staged for announce this pass or still present in
            // Adj-RIB-Out (genuinely advertised — commit-after-send)
            // is not stale and must not be withdrawn; one already
            // staged for withdraw needs no duplicate. The residue is
            // dropped only after a successful send (the unconditional
            // `clear_grouped_member_synced` below).
            if is_dirty
                && member_of.is_none()
                && let Some(extras) = self.pending_extra_withdraws.get(&peer)
            {
                let announced: HashSet<(Prefix, u32)> =
                    announce.iter().map(|r| (r.prefix, r.path_id)).collect();
                let staged: HashSet<(Prefix, u32)> = withdraw.iter().copied().collect();
                withdraw.extend(extras.unicast.iter().copied().filter(|key| {
                    !announced.contains(key)
                        && !staged.contains(key)
                        && rib_out.get(&key.0, key.1).is_none()
                }));
                let vpn_announced: HashSet<rustbgpd_wire::VpnRouteKey> =
                    vpn_announce.iter().map(|r| r.nlri.key()).collect();
                let vpn_staged: HashSet<rustbgpd_wire::VpnRouteKey> =
                    vpn_withdraw.iter().map(|key| key.nlri_key).collect();
                vpn_withdraw.extend(
                    extras
                        .vpn
                        .iter()
                        .copied()
                        .filter(|key| {
                            !vpn_announced.contains(key)
                                && !vpn_staged.contains(key)
                                && rib_out
                                    .get_vpn(&crate::route::VpnRibRouteKey {
                                        nlri_key: *key,
                                        path_id: 0,
                                    })
                                    .is_none()
                        })
                        .map(|nlri_key| crate::route::VpnRibRouteKey {
                            nlri_key,
                            path_id: 0,
                        }),
                );
            }

            // The outbound payload: the group-shared Arc for a covered
            // member, otherwise this peer's own staged vectors. A shared
            // member never stages per-peer unicast (grouped + in-sync),
            // so the locals are empty by construction when it is taken.
            debug_assert!(
                shared_unicast.is_none() || (announce.is_empty() && nh_override_flags.is_empty()),
                "shared group payload must not coexist with per-peer staged unicast"
            );
            let (announce, nh_override_flags): super::update_groups::SharedUnicastPayload =
                match shared_unicast {
                    Some(shared) => shared,
                    None => (announce.into(), nh_override_flags.into()),
                };
            if !announce.is_empty()
                || !withdraw.is_empty()
                || !fs_announce.is_empty()
                || !fs_withdraw.is_empty()
                || !evpn_announce.is_empty()
                || !evpn_withdraw.is_empty()
                || !bgpls_announce.is_empty()
                || !bgpls_withdraw.is_empty()
                || !vpn_announce.is_empty()
                || !vpn_withdraw.is_empty()
                || !labeled_announce.is_empty()
                || !labeled_withdraw.is_empty()
                || !rtc_announce.is_empty()
                || !rtc_withdraw.is_empty()
                || self.pending_otc_blocked.contains_key(&peer)
            {
                // If a prior initial dump / route-refresh EoR was deferred,
                // piggyback it on the successful dirty resync update so it
                // can't be starved behind the resync message on a small queue.
                // EoR piggyback only attaches to *dirty* resyncs (the
                // dump-deferral pattern). A force-only resync is a
                // GShut-style outbound-attribute refresh and never
                // carries pending EoR by definition.
                let pending_eor = if is_dirty {
                    self.pending_eor
                        .get(&peer)
                        .map(|families| families.iter().copied().collect())
                        .unwrap_or_default()
                } else {
                    vec![]
                };
                let announced_count = announce.len();
                let withdrawn_count = withdraw.len();
                let group_prior = if let Some(gid) = member_of {
                    let mut prior = HashSet::new();
                    if is_dirty {
                        // The member's wire is the last successfully sent
                        // view, while the shared table may have advanced
                        // through failed passes. Treat every resync announce
                        // as possibly replacing an advertised key so an exact
                        // rejection over-withdraws instead of leaking stale
                        // attributes on the peer.
                        prior.extend(announce.iter().map(|route| {
                            crate::update::ExactExportKey::Unicast(route.prefix, route.path_id)
                        }));
                        prior.extend(
                            vpn_announce
                                .iter()
                                .map(|route| crate::update::ExactExportKey::Vpn(route.key())),
                        );
                    } else if is_force {
                        if let Some(group) = self.group_ribs.get(&gid) {
                            let rejected = self.peer_unexportable.get(&peer);
                            prior.extend(group.table.iter().filter_map(|route| {
                                let key = crate::update::ExactExportKey::Unicast(
                                    route.prefix,
                                    route.path_id,
                                );
                                (route.peer != peer
                                    && !rejected.is_some_and(|keys| keys.contains(&key)))
                                .then_some(key)
                            }));
                        }
                    } else if let Some(stage) = group_stage.get(&gid) {
                        let rejected = self.peer_unexportable.get(&peer);
                        prior.extend(stage.deltas.iter().filter_map(|delta| {
                            let key =
                                crate::update::ExactExportKey::Unicast(delta.prefix, delta.path_id);
                            (delta.old_source.is_some_and(|source| source != peer)
                                && !rejected.is_some_and(|keys| keys.contains(&key)))
                            .then_some(crate::update::ExactExportKey::Unicast(
                                delta.prefix,
                                delta.path_id,
                            ))
                        }));
                    }
                    if let Some(base) = self.pending_regroup_baseline.get(&peer) {
                        prior.extend(base.unicast.keys().map(|(prefix, path_id)| {
                            crate::update::ExactExportKey::Unicast(*prefix, *path_id)
                        }));
                        prior.extend(base.vpn.keys().map(|key| {
                            crate::update::ExactExportKey::Vpn(crate::route::VpnRibRouteKey {
                                nlri_key: *key,
                                path_id: 0,
                            })
                        }));
                    }
                    prior
                } else {
                    HashSet::new()
                };
                if self.try_send_and_commit_outbound_update_with_group_prior(
                    peer,
                    nh_override_flags,
                    announce,
                    withdraw,
                    pending_eor.clone(),
                    vec![],
                    fs_announce,
                    fs_withdraw,
                    evpn_announce,
                    evpn_withdraw,
                    bgpls_announce,
                    bgpls_withdraw,
                    vpn_announce,
                    vpn_withdraw,
                    labeled_announce,
                    labeled_withdraw,
                    rtc_announce,
                    rtc_withdraw,
                    group_prior,
                ) {
                    self.update_policy_filtered_routes_for_prefixes(
                        peer,
                        &effective_prefixes,
                        &current_policy_filtered_routes,
                    );
                    if resync {
                        info!(
                            %peer,
                            announced = announced_count,
                            withdrawn = withdrawn_count,
                            dirty = is_dirty,
                            force = is_force,
                            "outbound routes resynced"
                        );
                        if is_dirty {
                            self.dirty_peers.remove(&peer);
                            self.clear_grouped_member_synced(peer);
                            if pending_eor.is_empty() {
                                self.flush_pending_eor(peer);
                            } else {
                                self.pending_eor.remove(&peer);
                            }
                            self.retry_pending_refresh(peer);
                        }
                        // Force is one-shot: clear after a successful
                        // emission so a subsequent unrelated dirty
                        // resync doesn't re-bypass equality checks.
                        if is_force {
                            self.force_outbound_peers.remove(&peer);
                        }
                    }
                } else {
                    warn!(%peer, "outbound channel full or closed — marking dirty for resync");
                    self.metrics.record_outbound_route_drop(&peer.to_string());
                    self.mark_outbound_dirty(peer);
                    // A grouped member that just went dirty missed this
                    // pass's withdrawals: record them as tombstones so
                    // its resync can (over-)withdraw them.
                    if let Some(gid) = member_of
                        && let Some(stage) = group_stage.get(&gid)
                    {
                        if let Some(group) = self.group_ribs.get_mut(&gid) {
                            let withdrawn: Vec<(Prefix, u32)> = stage.withdrawn_keys().collect();
                            group.tombstones.extend(withdrawn);
                        }
                        // A source-flip member-scoped withdraw (this
                        // member is the delta's new source) keeps the
                        // key IN the table — invisible to tombstones.
                        // Ride the member's extra-withdraw residue.
                        let lost: Vec<(Prefix, u32)> =
                            stage.member_scoped_withdraws(peer).collect();
                        if !lost.is_empty() {
                            self.pending_extra_withdraws
                                .entry(peer)
                                .or_default()
                                .unicast
                                .extend(lost);
                        }
                        self.refresh_group_residue_gauge();
                    }
                }
            } else {
                self.update_policy_filtered_routes_for_prefixes(
                    peer,
                    &effective_prefixes,
                    &current_policy_filtered_routes,
                );
                if resync {
                    // Resync triggered but no diff — already in sync.
                    debug!(%peer, "outbound routes unchanged after resync");
                    if is_dirty {
                        self.dirty_peers.remove(&peer);
                        self.clear_grouped_member_synced(peer);
                        self.flush_pending_eor(peer);
                        self.retry_pending_refresh(peer);
                    }
                    if is_force {
                        self.force_outbound_peers.remove(&peer);
                    }
                }
            }
        }
    }
}
