use std::net::IpAddr;

use rustbgpd_policy::PrefixList;
use tokio::sync::{broadcast, mpsc, oneshot};

use crate::event::RouteEvent;
use crate::route::Route;

/// Routes to be sent outbound to a peer.
pub struct OutboundRouteUpdate {
    pub announce: Vec<Route>,
    pub withdraw: Vec<rustbgpd_wire::Ipv4Prefix>,
}

/// Messages sent from peer sessions to the RIB manager.
pub enum RibUpdate {
    /// Peer session sent us routes.
    RoutesReceived {
        peer: IpAddr,
        announced: Vec<Route>,
        withdrawn: Vec<rustbgpd_wire::Ipv4Prefix>,
    },
    /// Peer session went down — clear all routes from this peer.
    PeerDown { peer: IpAddr },
    /// Peer session established — register for outbound updates.
    PeerUp {
        peer: IpAddr,
        outbound_tx: mpsc::Sender<OutboundRouteUpdate>,
        export_policy: Option<PrefixList>,
    },
    /// Inject a locally-originated route.
    InjectRoute {
        route: Route,
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Withdraw a locally-injected route.
    WithdrawInjected {
        prefix: rustbgpd_wire::Ipv4Prefix,
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
}
