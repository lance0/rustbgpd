use std::net::IpAddr;

use rustbgpd_policy::Policy;
use rustbgpd_wire::{Afi, Prefix, Safi};
use tokio::sync::{broadcast, mpsc, oneshot};

use crate::event::RouteEvent;
use crate::route::Route;

/// Routes to be sent outbound to a peer.
pub struct OutboundRouteUpdate {
    pub announce: Vec<Route>,
    pub withdraw: Vec<Prefix>,
    /// End-of-RIB markers to send for these families after the route updates.
    pub end_of_rib: Vec<(Afi, Safi)>,
    /// Per-route next-hop override from export policy. Parallel to `announce` —
    /// `next_hop_override[i]` applies to `announce[i]`.
    pub next_hop_override: Vec<Option<rustbgpd_policy::NextHopAction>>,
}

/// Messages sent from peer sessions to the RIB manager.
pub enum RibUpdate {
    /// Peer session sent us routes.
    RoutesReceived {
        peer: IpAddr,
        announced: Vec<Route>,
        withdrawn: Vec<Prefix>,
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
    },
    /// Inject a locally-originated route.
    InjectRoute {
        route: Route,
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Withdraw a locally-injected route.
    WithdrawInjected {
        prefix: Prefix,
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
}
