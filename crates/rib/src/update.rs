use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use rustbgpd_policy::PolicyChain;
use rustbgpd_rpki::{AspaTable, VrpTable};
use rustbgpd_wire::{
    AddressPrefixOrf, Afi, EvpnRouteKey, FlowSpecRule, Prefix, RouteRefreshSubtype, Safi,
    WhenToRefresh,
};
use tokio::sync::{broadcast, mpsc, oneshot};

use crate::best_path::BestPathReason;
use crate::event::{EvpnRouteEvent, RouteEvent};
use crate::route::{
    BgpLsRibRoute, BgpLsRouteKey, EvpnRibRoute, FibInstallCandidate, FlowSpecRoute,
    LabeledRibRoute, LabeledRibRouteKey, Route, RtcRibRoute, RtcRibRouteKey, VpnRibRoute,
    VpnRibRouteKey,
};

/// Per-peer post-policy Adj-RIB-Out route counts per AFI/SAFI —
/// the RFC 8671 BMP stat type 15/17 source.
pub type AdjRibOutCounts = HashMap<IpAddr, Vec<((Afi, Safi), u64)>>;

/// Routes to be sent outbound to a peer.
#[derive(Default)]
pub struct OutboundRouteUpdate {
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
    pub flowspec_withdraw: Vec<FlowSpecRule>,
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
    /// Decisive explanation reasons, in order.
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
    pub already_advertised: bool,
    /// Route Distinguisher for a VPN explain; `None` for unicast.
    pub rd: Option<rustbgpd_wire::RouteDistinguisher>,
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

/// One decisive reason in an advertised-route explanation.
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

/// One page of a resumable route query.
#[derive(Debug, Clone, Default)]
pub struct RoutePage {
    /// Routes on this page, ascending by identity key.
    pub routes: Vec<Route>,
    /// Total filter-matching routes in scope (cursor-independent).
    pub total: u64,
    /// Whether matching routes remain beyond this page.
    pub has_more: bool,
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
        flowspec_withdrawn: Vec<FlowSpecRule>,
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
    /// Update per-peer policy identity metadata used during export policy evaluation.
    SetPeerPolicyContext {
        /// Peer whose policy identity is being updated.
        peer: IpAddr,
        /// Transport session identity that emitted the update.
        session_id: u64,
        /// Optional peer-group membership.
        peer_group: Option<String>,
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
    /// allocation (same mutation-robust cursor step as the BMP Loc-RIB
    /// dump), and the reply channel doubles as the cancellation token:
    /// an abandoned caller (dropped receiver) skips the scan entirely.
    QueryRoutesPage {
        /// Which table to read.
        scope: RouteQueryScope,
        /// Optional row filter evaluated inside the RIB task; `None`
        /// keeps every route in scope.
        filter: Option<RouteQueryFilter>,
        /// Resume strictly after this key; `None` starts from the
        /// beginning.
        after: Option<RouteQueryKey>,
        /// Maximum routes on the page (clamped to a server-side cap).
        page_size: usize,
        /// Response channel; a dropped receiver cancels the query.
        reply: oneshot::Sender<RoutePage>,
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
        /// Response channel.
        reply: oneshot::Sender<Option<ExplainAdvertisedRoute>>,
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
    /// Query: return aggregate route-policy counters for a specific peer.
    QueryNeighborPolicyStats {
        /// The target peer.
        peer: IpAddr,
        /// Response channel.
        reply: oneshot::Sender<NeighborPolicyStats>,
    },
    /// Query: return a peer's update-group membership label — `group:N`
    /// when the fingerprint grouped it, an ungrouped reason
    /// (`policy_peer_context` / `add_path_send` / `orr_vantage` /
    /// `orf_installed`) when a v1 disqualifier applies, or empty for a
    /// peer with no outbound registration. Shadow mode: observational
    /// only; distribution still runs per peer.
    QueryPeerUpdateGroup {
        /// The target peer.
        peer: IpAddr,
        /// Response channel.
        reply: oneshot::Sender<String>,
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
    /// Replace the effective export policy for a peer and resync outbound state.
    ReplacePeerExportPolicy {
        /// The target peer.
        peer: IpAddr,
        /// New effective export policy (`None` = permit-all/global fallback resolved already).
        export_policy: Option<PolicyChain>,
        /// Response channel for success/failure.
        reply: oneshot::Sender<Result<(), String>>,
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
        /// The `FlowSpec` rule to withdraw.
        rule: FlowSpecRule,
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
    /// All Adj-RIB-In unicast routes across all peers.
    pub routes: Vec<Route>,
    /// All Adj-RIB-In EVPN routes across all peers. Encoded as RFC 6396
    /// `RIB_GENERIC` records (AFI 25 / SAFI 70). Empty for non-EVPN
    /// deployments.
    pub evpn_routes: Vec<crate::route::EvpnRibRoute>,
}
