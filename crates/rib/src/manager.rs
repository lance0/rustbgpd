use std::collections::HashMap;
use std::net::IpAddr;

use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::adj_rib_in::AdjRibIn;
use crate::update::RibUpdate;

/// Central RIB manager that owns all Adj-RIB-In state.
///
/// Runs as a single tokio task, receiving updates via an mpsc channel.
/// No `Arc<RwLock>` — all state is owned by this task.
pub struct RibManager {
    ribs: HashMap<IpAddr, AdjRibIn>,
    rx: mpsc::Receiver<RibUpdate>,
}

impl RibManager {
    #[must_use]
    pub fn new(rx: mpsc::Receiver<RibUpdate>) -> Self {
        Self {
            ribs: HashMap::new(),
            rx,
        }
    }

    /// Run the RIB manager event loop until the channel is closed.
    pub async fn run(mut self) {
        while let Some(update) = self.rx.recv().await {
            match update {
                RibUpdate::RoutesReceived {
                    peer,
                    announced,
                    withdrawn,
                } => {
                    let rib = self.ribs.entry(peer).or_insert_with(|| AdjRibIn::new(peer));

                    for prefix in &withdrawn {
                        if rib.withdraw(prefix) {
                            debug!(%peer, %prefix, "withdrawn");
                        }
                    }

                    for route in announced {
                        debug!(%peer, prefix = %route.prefix, "announced");
                        rib.insert(route);
                    }

                    debug!(%peer, routes = rib.len(), "rib updated");
                }

                RibUpdate::PeerDown { peer } => {
                    if let Some(rib) = self.ribs.get_mut(&peer) {
                        let count = rib.len();
                        rib.clear();
                        debug!(%peer, cleared = count, "peer down — rib cleared");
                    }
                }

                RibUpdate::QueryReceivedRoutes { peer, reply } => {
                    let routes: Vec<_> = match peer {
                        Some(peer_addr) => self
                            .ribs
                            .get(&peer_addr)
                            .map(|rib| rib.iter().cloned().collect())
                            .unwrap_or_default(),
                        None => self
                            .ribs
                            .values()
                            .flat_map(|rib| rib.iter().cloned())
                            .collect(),
                    };

                    if reply.send(routes).is_err() {
                        warn!("query caller dropped before receiving response");
                    }
                }
            }
        }

        debug!("rib manager shutting down");
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Instant;

    use rustbgpd_wire::Ipv4Prefix;
    use tokio::sync::oneshot;

    use super::*;
    use crate::route::Route;

    fn make_route(prefix: Ipv4Prefix, next_hop: Ipv4Addr) -> Route {
        Route {
            prefix,
            next_hop,
            attributes: vec![],
            received_at: Instant::now(),
        }
    }

    #[tokio::test]
    async fn routes_received_and_queried() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx);
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));

        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![route],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryReceivedRoutes {
            peer: Some(peer),
            reply: reply_tx,
        })
        .await
        .unwrap();

        let routes = reply_rx.await.unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, prefix);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn peer_down_clears_routes() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx);
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));

        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![route],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        tx.send(RibUpdate::PeerDown { peer }).await.unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryReceivedRoutes {
            peer: Some(peer),
            reply: reply_tx,
        })
        .await
        .unwrap();

        let routes = reply_rx.await.unwrap();
        assert!(routes.is_empty());

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn withdrawal_removes_route() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx);
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24);

        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![
                make_route(prefix1, Ipv4Addr::new(10, 0, 0, 1)),
                make_route(prefix2, Ipv4Addr::new(10, 0, 0, 1)),
            ],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![],
            withdrawn: vec![prefix1],
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryReceivedRoutes {
            peer: Some(peer),
            reply: reply_tx,
        })
        .await
        .unwrap();

        let routes = reply_rx.await.unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, prefix2);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn query_all_peers() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx);
        let handle = tokio::spawn(manager.run());

        let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![make_route(
                Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24),
                Ipv4Addr::new(10, 0, 0, 1),
            )],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![make_route(
                Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24),
                Ipv4Addr::new(10, 0, 0, 2),
            )],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryReceivedRoutes {
            peer: None,
            reply: reply_tx,
        })
        .await
        .unwrap();

        let routes = reply_rx.await.unwrap();
        assert_eq!(routes.len(), 2);

        drop(tx);
        handle.await.unwrap();
    }
}
