use std::net::IpAddr;

use tokio::sync::oneshot;

use crate::route::Route;

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
    /// Query: return all received routes, optionally filtered by peer.
    QueryReceivedRoutes {
        peer: Option<IpAddr>,
        reply: oneshot::Sender<Vec<Route>>,
    },
    /// Query: return best routes from the Loc-RIB.
    QueryBestRoutes { reply: oneshot::Sender<Vec<Route>> },
}
