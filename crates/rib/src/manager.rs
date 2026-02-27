use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use rustbgpd_wire::Ipv4Prefix;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::adj_rib_in::AdjRibIn;
use crate::loc_rib::LocRib;
use crate::update::RibUpdate;

/// Central RIB manager that owns all Adj-RIB-In and Loc-RIB state.
///
/// Runs as a single tokio task, receiving updates via an mpsc channel.
/// No `Arc<RwLock>` — all state is owned by this task.
pub struct RibManager {
    ribs: HashMap<IpAddr, AdjRibIn>,
    loc_rib: LocRib,
    rx: mpsc::Receiver<RibUpdate>,
}

impl RibManager {
    #[must_use]
    pub fn new(rx: mpsc::Receiver<RibUpdate>) -> Self {
        Self {
            ribs: HashMap::new(),
            loc_rib: LocRib::new(),
            rx,
        }
    }

    /// Recompute Loc-RIB best path for a set of affected prefixes.
    fn recompute_best(&mut self, affected: &HashSet<Ipv4Prefix>) {
        for prefix in affected {
            let candidates: Vec<_> = self
                .ribs
                .values()
                .filter_map(|rib| rib.get(prefix))
                .collect();
            let changed = self.loc_rib.recompute(*prefix, candidates.into_iter());
            if changed {
                if let Some(best) = self.loc_rib.get(prefix) {
                    debug!(
                        %prefix,
                        peer = %best.peer,
                        "best path changed"
                    );
                } else {
                    debug!(%prefix, "best path removed");
                }
            }
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
                    let mut affected = HashSet::new();

                    for prefix in &withdrawn {
                        if rib.withdraw(prefix) {
                            debug!(%peer, %prefix, "withdrawn");
                            affected.insert(*prefix);
                        }
                    }

                    for route in announced {
                        debug!(%peer, prefix = %route.prefix, "announced");
                        affected.insert(route.prefix);
                        rib.insert(route);
                    }

                    debug!(%peer, routes = rib.len(), "rib updated");
                    self.recompute_best(&affected);
                }

                RibUpdate::PeerDown { peer } => {
                    if let Some(rib) = self.ribs.get_mut(&peer) {
                        let affected: HashSet<Ipv4Prefix> = rib.iter().map(|r| r.prefix).collect();
                        let count = rib.len();
                        rib.clear();
                        debug!(%peer, cleared = count, "peer down — rib cleared");
                        self.recompute_best(&affected);
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

                RibUpdate::QueryBestRoutes { reply } => {
                    let routes: Vec<_> = self.loc_rib.iter().cloned().collect();
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
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Instant;

    use rustbgpd_wire::{AsPath, AsPathSegment, Ipv4Prefix, Origin, PathAttribute};
    use tokio::sync::oneshot;

    use super::*;
    use crate::route::Route;

    fn make_route(prefix: Ipv4Prefix, next_hop: Ipv4Addr) -> Route {
        Route {
            prefix,
            next_hop,
            peer: IpAddr::V4(next_hop),
            attributes: vec![],
            received_at: Instant::now(),
        }
    }

    fn make_route_with_lp(prefix: Ipv4Prefix, peer: Ipv4Addr, local_pref: u32) -> Route {
        Route {
            prefix,
            next_hop: peer,
            peer: IpAddr::V4(peer),
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65001])],
                }),
                PathAttribute::LocalPref(local_pref),
            ],
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

    // --- Loc-RIB integration tests ---

    #[tokio::test]
    async fn best_routes_returns_winner() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx);
        let handle = tokio::spawn(manager.run());

        let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
        let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

        // Peer1: local_pref 100
        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 1), 100)],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Peer2: local_pref 200 — should win
        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 2), 200)],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();

        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 1);
        assert_eq!(best[0].peer, peer2);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn peer_down_promotes_second_best() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx);
        let handle = tokio::spawn(manager.run());

        let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
        let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 1), 100)],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 2), 200)],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Peer2 goes down — peer1 should be promoted
        tx.send(RibUpdate::PeerDown { peer: peer2 }).await.unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();

        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 1);
        assert_eq!(best[0].peer, peer1);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn withdrawal_updates_best() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx);
        let handle = tokio::spawn(manager.run());

        let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
        let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 1), 100)],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 2), 200)],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Peer2 withdraws the prefix
        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![],
            withdrawn: vec![prefix],
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();

        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 1);
        assert_eq!(best[0].peer, peer1);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn different_best_per_prefix() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx);
        let handle = tokio::spawn(manager.run());

        let prefix_a = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
        let prefix_b = Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 16);
        let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

        // Peer1 wins prefix_a (higher LP), peer2 wins prefix_b (higher LP)
        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![
                make_route_with_lp(prefix_a, Ipv4Addr::new(1, 0, 0, 1), 200),
                make_route_with_lp(prefix_b, Ipv4Addr::new(1, 0, 0, 1), 100),
            ],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![
                make_route_with_lp(prefix_a, Ipv4Addr::new(1, 0, 0, 2), 100),
                make_route_with_lp(prefix_b, Ipv4Addr::new(1, 0, 0, 2), 200),
            ],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();

        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 2);

        let best_a = best.iter().find(|r| r.prefix == prefix_a).unwrap();
        let best_b = best.iter().find(|r| r.prefix == prefix_b).unwrap();
        assert_eq!(best_a.peer, peer1);
        assert_eq!(best_b.peer, peer2);

        drop(tx);
        handle.await.unwrap();
    }
}
