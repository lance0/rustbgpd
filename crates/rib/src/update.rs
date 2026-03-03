use std::net::IpAddr;
use std::sync::Arc;

use rustbgpd_policy::Policy;
use rustbgpd_rpki::VrpTable;
use rustbgpd_wire::{Afi, FlowSpecRule, Prefix, Safi};
use tokio::sync::{broadcast, mpsc, oneshot};

use crate::event::RouteEvent;
use crate::route::{FlowSpecRoute, Route};

/// Routes to be sent outbound to a peer.
pub struct OutboundRouteUpdate {
    pub announce: Vec<Route>,
    /// Withdrawn routes with their path IDs. For non-Add-Path peers,
    /// `path_id` is always 0.
    pub withdraw: Vec<(Prefix, u32)>,
    /// End-of-RIB markers to send for these families after the route updates.
    pub end_of_rib: Vec<(Afi, Safi)>,
    /// Per-route next-hop override from export policy. Parallel to `announce` —
    /// `next_hop_override[i]` applies to `announce[i]`.
    pub next_hop_override: Vec<Option<rustbgpd_policy::NextHopAction>>,
    /// `FlowSpec` routes to announce (RFC 8955).
    pub flowspec_announce: Vec<FlowSpecRoute>,
    /// `FlowSpec` rules to withdraw.
    pub flowspec_withdraw: Vec<FlowSpecRule>,
}

/// Messages sent from peer sessions to the RIB manager.
pub enum RibUpdate {
    /// Peer session sent us routes.
    RoutesReceived {
        peer: IpAddr,
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
    PeerDown { peer: IpAddr },
    /// Peer session established — register for outbound updates.
    PeerUp {
        peer: IpAddr,
        outbound_tx: mpsc::Sender<OutboundRouteUpdate>,
        export_policy: Option<Policy>,
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
    /// Inject a locally-originated route.
    InjectRoute {
        route: Route,
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Withdraw a locally-injected route.
    WithdrawInjected {
        prefix: Prefix,
        /// Add-Path path identifier (0 = default path).
        path_id: u32,
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Query: return all received routes, optionally filtered by peer.
    QueryReceivedRoutes {
        peer: Option<IpAddr>,
        reply: oneshot::Sender<Vec<Route>>,
    },
    /// Query: return best routes from the Loc-RIB.
    QueryBestRoutes { reply: oneshot::Sender<Vec<Route>> },
    /// Query: return routes advertised to a specific peer.
    QueryAdvertisedRoutes {
        peer: IpAddr,
        reply: oneshot::Sender<Vec<Route>>,
    },
    /// Subscribe to route change events via broadcast channel.
    SubscribeRouteEvents {
        reply: oneshot::Sender<broadcast::Receiver<RouteEvent>>,
    },
    /// End-of-RIB marker received from a peer for a given address family.
    EndOfRib { peer: IpAddr, afi: Afi, safi: Safi },
    /// Peer entered graceful restart — preserve routes but mark stale.
    PeerGracefulRestart {
        peer: IpAddr,
        /// Peer's advertised restart time (seconds).
        restart_time: u16,
        /// Our configured stale routes time (seconds).
        stale_routes_time: u64,
        /// All families from the peer's Graceful Restart capability.
        gr_families: Vec<(Afi, Safi)>,
    },
    /// Query: return the number of prefixes in the Loc-RIB.
    QueryLocRibCount { reply: oneshot::Sender<usize> },
    /// Query: return the number of prefixes advertised to a specific peer.
    QueryAdvertisedCount {
        peer: IpAddr,
        reply: oneshot::Sender<usize>,
    },
    /// Peer sent us a ROUTE-REFRESH — re-advertise our Loc-RIB for this family.
    RouteRefreshRequest { peer: IpAddr, afi: Afi, safi: Safi },
    /// RPKI cache update — new VRP table for origin validation.
    RpkiCacheUpdate { table: Arc<VrpTable> },
    /// Inject a locally-originated `FlowSpec` route.
    InjectFlowSpec {
        route: FlowSpecRoute,
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Withdraw a locally-injected `FlowSpec` route.
    WithdrawFlowSpec {
        rule: FlowSpecRule,
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Query `FlowSpec` routes from the Loc-RIB.
    QueryFlowSpecRoutes {
        reply: oneshot::Sender<Vec<FlowSpecRoute>>,
    },
}
