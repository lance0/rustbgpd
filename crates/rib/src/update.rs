use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use rustbgpd_policy::PolicyChain;
use rustbgpd_rpki::VrpTable;
use rustbgpd_wire::{Afi, FlowSpecRule, Prefix, RouteRefreshSubtype, Safi};
use tokio::sync::{broadcast, mpsc, oneshot};

use crate::event::RouteEvent;
use crate::route::{FlowSpecRoute, Route};

/// Routes to be sent outbound to a peer.
pub struct OutboundRouteUpdate {
    /// Routes to announce to this peer.
    pub announce: Vec<Route>,
    /// Withdrawn routes with their path IDs. For non-Add-Path peers,
    /// `path_id` is always 0.
    pub withdraw: Vec<(Prefix, u32)>,
    /// End-of-RIB markers to send for these families after the route updates.
    pub end_of_rib: Vec<(Afi, Safi)>,
    /// RFC 7313 route-refresh demarcation markers to emit around the update.
    /// `BoRR` markers are sent before route payloads; `EoRR` markers after.
    pub refresh_markers: Vec<(Afi, Safi, RouteRefreshSubtype)>,
    /// Per-route next-hop override from export policy. Parallel to `announce` —
    /// `next_hop_override[i]` applies to `announce[i]`.
    pub next_hop_override: Vec<Option<rustbgpd_policy::NextHopAction>>,
    /// `FlowSpec` routes to announce (RFC 8955).
    pub flowspec_announce: Vec<FlowSpecRoute>,
    /// `FlowSpec` rules to withdraw.
    pub flowspec_withdraw: Vec<FlowSpecRule>,
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
    /// Decisive explanation reasons, in order.
    pub reasons: Vec<ExplainReason>,
    /// Export modifications that would be applied.
    pub modifications: rustbgpd_policy::RouteModifications,
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

/// Messages sent from peer sessions to the RIB manager.
pub enum RibUpdate {
    /// Peer session sent us routes.
    RoutesReceived {
        /// Source peer address.
        peer: IpAddr,
        /// Newly announced routes.
        announced: Vec<Route>,
        /// Withdrawn prefixes with Add-Path path identifiers.
        /// `(prefix, path_id)` — `path_id = 0` for non-Add-Path peers.
        withdrawn: Vec<(Prefix, u32)>,
        /// `FlowSpec` routes announced (RFC 8955).
        flowspec_announced: Vec<FlowSpecRoute>,
        /// `FlowSpec` rules withdrawn.
        flowspec_withdrawn: Vec<FlowSpecRule>,
    },
    /// Peer session went down — clear all routes from this peer.
    PeerDown {
        /// The peer whose session went down.
        peer: IpAddr,
    },
    /// Peer session established — register for outbound updates.
    PeerUp {
        /// The peer whose session came up.
        peer: IpAddr,
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
        /// Families for which this peer negotiated Add-Path Send/Both.
        /// Multi-path export is only enabled for these families.
        add_path_send_families: Vec<(Afi, Safi)>,
        /// Maximum paths per prefix to send via Add-Path (0 = single-best only).
        add_path_send_max: u32,
    },
    /// Update per-peer policy identity metadata used during export policy evaluation.
    SetPeerPolicyContext {
        /// Peer whose policy identity is being updated.
        peer: IpAddr,
        /// Optional peer-group membership.
        peer_group: Option<String>,
    },
    /// Inject a locally-originated route.
    InjectRoute {
        /// The route to inject.
        route: Route,
        /// Completion reply.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Withdraw a locally-injected route.
    WithdrawInjected {
        /// Prefix to withdraw.
        prefix: Prefix,
        /// Add-Path path identifier (0 = default path).
        path_id: u32,
        /// Completion reply.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Query: return all received routes, optionally filtered by peer.
    QueryReceivedRoutes {
        /// Optional peer filter; `None` returns all peers.
        peer: Option<IpAddr>,
        /// Response channel.
        reply: oneshot::Sender<Vec<Route>>,
    },
    /// Query: return best routes from the Loc-RIB.
    QueryBestRoutes {
        /// Response channel.
        reply: oneshot::Sender<Vec<Route>>,
    },
    /// Query: return routes advertised to a specific peer.
    QueryAdvertisedRoutes {
        /// The target peer.
        peer: IpAddr,
        /// Response channel.
        reply: oneshot::Sender<Vec<Route>>,
    },
    /// Query: explain whether the current best route for a prefix would be advertised to a peer.
    ExplainAdvertisedRoute {
        /// The target peer.
        peer: IpAddr,
        /// Prefix to explain.
        prefix: Prefix,
        /// Response channel.
        reply: oneshot::Sender<Option<ExplainAdvertisedRoute>>,
    },
    /// Subscribe to route change events via broadcast channel.
    SubscribeRouteEvents {
        /// Response channel carrying the broadcast receiver.
        reply: oneshot::Sender<broadcast::Receiver<RouteEvent>>,
    },
    /// End-of-RIB marker received from a peer for a given address family.
    EndOfRib {
        /// The peer that sent the `EoR`.
        peer: IpAddr,
        /// Address family identifier.
        afi: Afi,
        /// Subsequent address family identifier.
        safi: Safi,
    },
    /// Peer entered graceful restart — preserve routes but mark stale.
    PeerGracefulRestart {
        /// The restarting peer.
        peer: IpAddr,
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
    /// Query: return the number of prefixes advertised to a specific peer.
    QueryAdvertisedCount {
        /// The target peer.
        peer: IpAddr,
        /// Response channel.
        reply: oneshot::Sender<usize>,
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
    /// Peer sent us a ROUTE-REFRESH — re-advertise our Loc-RIB for this family.
    RouteRefreshRequest {
        /// The requesting peer.
        peer: IpAddr,
        /// Address family identifier.
        afi: Afi,
        /// Subsequent address family identifier.
        safi: Safi,
    },
    /// Peer sent Beginning-of-RIB-Refresh (RFC 7313) for this family.
    BeginRouteRefresh {
        /// The peer that sent `BoRR`.
        peer: IpAddr,
        /// Address family identifier.
        afi: Afi,
        /// Subsequent address family identifier.
        safi: Safi,
    },
    /// Peer sent End-of-RIB-Refresh (RFC 7313) for this family.
    EndRouteRefresh {
        /// The peer that sent `EoRR`.
        peer: IpAddr,
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
    /// Inject a locally-originated `FlowSpec` route.
    InjectFlowSpec {
        /// The `FlowSpec` route to inject.
        route: FlowSpecRoute,
        /// Completion reply.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Withdraw a locally-injected `FlowSpec` route.
    WithdrawFlowSpec {
        /// The `FlowSpec` rule to withdraw.
        rule: FlowSpecRule,
        /// Completion reply.
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Query `FlowSpec` routes from the Loc-RIB.
    QueryFlowSpecRoutes {
        /// Response channel.
        reply: oneshot::Sender<Vec<FlowSpecRoute>>,
    },
    /// Query a full RIB snapshot for MRT `TABLE_DUMP_V2` export.
    QueryMrtSnapshot {
        /// Response channel.
        reply: oneshot::Sender<MrtSnapshotData>,
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
    /// All Adj-RIB-In routes across all peers.
    pub routes: Vec<Route>,
}
