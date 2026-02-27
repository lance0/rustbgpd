use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};

use rustbgpd_policy::{PrefixList, check_prefix_list};
use rustbgpd_wire::Ipv4Prefix;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::adj_rib_in::AdjRibIn;
use crate::adj_rib_out::AdjRibOut;
use crate::loc_rib::LocRib;
use crate::update::{OutboundRouteUpdate, RibUpdate};

/// Sentinel peer address for locally-injected routes.
const LOCAL_PEER: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// Central RIB manager that owns all Adj-RIB-In, Loc-RIB, and Adj-RIB-Out state.
///
/// Runs as a single tokio task, receiving updates via an mpsc channel.
/// No `Arc<RwLock>` — all state is owned by this task.
pub struct RibManager {
    ribs: HashMap<IpAddr, AdjRibIn>,
    loc_rib: LocRib,
    adj_ribs_out: HashMap<IpAddr, AdjRibOut>,
    outbound_peers: HashMap<IpAddr, mpsc::Sender<OutboundRouteUpdate>>,
    export_policy: Option<PrefixList>,
    rx: mpsc::Receiver<RibUpdate>,
}

impl RibManager {
    #[must_use]
    pub fn new(rx: mpsc::Receiver<RibUpdate>, export_policy: Option<PrefixList>) -> Self {
        Self {
            ribs: HashMap::new(),
            loc_rib: LocRib::new(),
            adj_ribs_out: HashMap::new(),
            outbound_peers: HashMap::new(),
            export_policy,
            rx,
        }
    }

    /// Recompute Loc-RIB best path for a set of affected prefixes.
    /// Returns the set of prefixes that actually changed.
    fn recompute_best(&mut self, affected: &HashSet<Ipv4Prefix>) -> HashSet<Ipv4Prefix> {
        let mut changed = HashSet::new();
        for prefix in affected {
            let candidates: Vec<_> = self
                .ribs
                .values()
                .filter_map(|rib| rib.get(prefix))
                .collect();
            let did_change = self.loc_rib.recompute(*prefix, candidates.into_iter());
            if did_change {
                changed.insert(*prefix);
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
        changed
    }

    /// Distribute Loc-RIB changes to all registered outbound peers.
    fn distribute_changes(&mut self, changed_prefixes: &HashSet<Ipv4Prefix>) {
        if changed_prefixes.is_empty() {
            return;
        }

        let peers: Vec<IpAddr> = self.outbound_peers.keys().copied().collect();
        for peer in peers {
            let mut announce = Vec::new();
            let mut withdraw = Vec::new();

            let rib_out = self
                .adj_ribs_out
                .entry(peer)
                .or_insert_with(|| AdjRibOut::new(peer));

            for prefix in changed_prefixes {
                if let Some(best) = self.loc_rib.get(prefix) {
                    // Split horizon: don't send route back to its source
                    if best.peer == peer {
                        // If we previously advertised this, withdraw it
                        if rib_out.withdraw(prefix) {
                            withdraw.push(*prefix);
                        }
                        continue;
                    }

                    // Export policy check
                    if check_prefix_list(self.export_policy.as_ref(), *prefix)
                        != rustbgpd_policy::PolicyAction::Permit
                    {
                        if rib_out.withdraw(prefix) {
                            withdraw.push(*prefix);
                        }
                        continue;
                    }

                    // Advertise (or re-advertise if already in Adj-RIB-Out)
                    rib_out.insert(best.clone());
                    announce.push(best.clone());
                } else {
                    // Best path removed — withdraw if previously advertised
                    if rib_out.withdraw(prefix) {
                        withdraw.push(*prefix);
                    }
                }
            }

            if (!announce.is_empty() || !withdraw.is_empty())
                && let Some(tx) = self.outbound_peers.get(&peer)
            {
                let update = OutboundRouteUpdate { announce, withdraw };
                if tx.try_send(update).is_err() {
                    warn!(%peer, "outbound channel full or closed");
                }
            }
        }
    }

    /// Send the full Loc-RIB to a newly established peer (initial table dump).
    fn send_initial_table(&mut self, peer: IpAddr) {
        let mut announce = Vec::new();
        let rib_out = self
            .adj_ribs_out
            .entry(peer)
            .or_insert_with(|| AdjRibOut::new(peer));

        for route in self.loc_rib.iter() {
            // Split horizon
            if route.peer == peer {
                continue;
            }
            // Export policy
            if check_prefix_list(self.export_policy.as_ref(), route.prefix)
                != rustbgpd_policy::PolicyAction::Permit
            {
                continue;
            }
            rib_out.insert(route.clone());
            announce.push(route.clone());
        }

        if !announce.is_empty()
            && let Some(tx) = self.outbound_peers.get(&peer)
        {
            let update = OutboundRouteUpdate {
                announce,
                withdraw: vec![],
            };
            if tx.try_send(update).is_err() {
                warn!(%peer, "outbound channel full or closed during initial dump");
            }
        }
    }

    /// Run the RIB manager event loop until the channel is closed.
    #[expect(clippy::too_many_lines)]
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
                    let changed = self.recompute_best(&affected);
                    self.distribute_changes(&changed);
                }

                RibUpdate::PeerDown { peer } => {
                    if let Some(rib) = self.ribs.get_mut(&peer) {
                        let affected: HashSet<Ipv4Prefix> = rib.iter().map(|r| r.prefix).collect();
                        let count = rib.len();
                        rib.clear();
                        debug!(%peer, cleared = count, "peer down — rib cleared");
                        let changed = self.recompute_best(&affected);
                        self.distribute_changes(&changed);
                    }
                    // Clean up outbound state
                    self.adj_ribs_out.remove(&peer);
                    self.outbound_peers.remove(&peer);
                }

                RibUpdate::PeerUp { peer, outbound_tx } => {
                    debug!(%peer, "peer up — registering for outbound updates");
                    self.outbound_peers.insert(peer, outbound_tx);
                    self.send_initial_table(peer);
                }

                RibUpdate::InjectRoute { route, reply } => {
                    let prefix = route.prefix;
                    let rib = self
                        .ribs
                        .entry(LOCAL_PEER)
                        .or_insert_with(|| AdjRibIn::new(LOCAL_PEER));
                    rib.insert(route);
                    debug!(%prefix, "injected local route");

                    let mut affected = HashSet::new();
                    affected.insert(prefix);
                    let changed = self.recompute_best(&affected);
                    self.distribute_changes(&changed);

                    let _ = reply.send(Ok(()));
                }

                RibUpdate::WithdrawInjected { prefix, reply } => {
                    let rib = self
                        .ribs
                        .entry(LOCAL_PEER)
                        .or_insert_with(|| AdjRibIn::new(LOCAL_PEER));
                    if rib.withdraw(&prefix) {
                        debug!(%prefix, "withdrawn injected route");
                        let mut affected = HashSet::new();
                        affected.insert(prefix);
                        let changed = self.recompute_best(&affected);
                        self.distribute_changes(&changed);
                        let _ = reply.send(Ok(()));
                    } else {
                        let _ = reply.send(Err(format!("prefix {prefix} not found")));
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

                RibUpdate::QueryAdvertisedRoutes { peer, reply } => {
                    let routes: Vec<_> = self
                        .adj_ribs_out
                        .get(&peer)
                        .map(|rib| rib.iter().cloned().collect())
                        .unwrap_or_default();

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
        let manager = RibManager::new(rx, None);
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
        let manager = RibManager::new(rx, None);
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
        let manager = RibManager::new(rx, None);
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
        let manager = RibManager::new(rx, None);
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
        let manager = RibManager::new(rx, None);
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
        let manager = RibManager::new(rx, None);
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
        let manager = RibManager::new(rx, None);
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
        let manager = RibManager::new(rx, None);
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

    // --- M3 outbound distribution tests ---

    #[tokio::test]
    async fn peer_up_triggers_initial_table_dump() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None);
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        // Inject a route from source
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Register target for outbound
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
        })
        .await
        .unwrap();

        // Should receive initial table dump
        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);
        assert_eq!(update.announce[0].prefix, prefix);
        assert!(update.withdraw.is_empty());

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn route_change_distributes_to_peer() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None);
        let handle = tokio::spawn(manager.run());

        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
        })
        .await
        .unwrap();

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);
        assert_eq!(update.announce[0].prefix, prefix);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn split_horizon_prevents_echo() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None);
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer,
            outbound_tx: out_tx,
        })
        .await
        .unwrap();

        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        // The route is FROM this peer — should not be sent back
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Force a query to serialize the event loop
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let _ = reply_rx.await;

        // Channel should be empty (no outbound update sent)
        assert!(out_rx.try_recv().is_err());

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn peer_down_cleans_up_outbound() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None);
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let (out_tx, _out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer,
            outbound_tx: out_tx,
        })
        .await
        .unwrap();

        tx.send(RibUpdate::PeerDown { peer }).await.unwrap();

        // Query advertised routes — should be empty after PeerDown
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedRoutes {
            peer,
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
    async fn inject_route_enters_loc_rib_and_distributes() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None);
        let handle = tokio::spawn(manager.run());

        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
        })
        .await
        .unwrap();

        let prefix = Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 16);
        let route = Route {
            prefix,
            next_hop: Ipv4Addr::UNSPECIFIED,
            peer: LOCAL_PEER,
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
            ],
            received_at: Instant::now(),
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::InjectRoute {
            route,
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_ok());

        // Should be in Loc-RIB
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 1);
        assert_eq!(best[0].prefix, prefix);

        // Should have been distributed
        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn withdraw_injected_removes_and_distributes() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None);
        let handle = tokio::spawn(manager.run());

        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
        })
        .await
        .unwrap();

        let prefix = Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 16);
        let route = Route {
            prefix,
            next_hop: Ipv4Addr::UNSPECIFIED,
            peer: LOCAL_PEER,
            attributes: vec![PathAttribute::Origin(Origin::Igp)],
            received_at: Instant::now(),
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::InjectRoute {
            route,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let _ = reply_rx.await;

        // Consume the inject announcement
        let _ = out_rx.recv().await;

        // Now withdraw
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::WithdrawInjected {
            prefix,
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_ok());

        // Should receive withdrawal
        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.withdraw.len(), 1);
        assert_eq!(update.withdraw[0], prefix);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn export_policy_blocks_denied() {
        use rustbgpd_policy::{PolicyAction, PrefixList, PrefixListEntry};

        let denied_prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8);
        let export_policy = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: denied_prefix,
                ge: None,
                le: None,
                action: PolicyAction::Deny,
            }],
            default_action: PolicyAction::Permit,
        };

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, Some(export_policy));
        let handle = tokio::spawn(manager.run());

        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
        })
        .await
        .unwrap();

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        // This route matches the deny entry
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(denied_prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Force serialization
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let _ = reply_rx.await;

        // Should NOT have received the denied route
        assert!(out_rx.try_recv().is_err());

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn query_advertised_routes() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None);
        let handle = tokio::spawn(manager.run());

        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (out_tx, mut _out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
        })
        .await
        .unwrap();

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
        })
        .await
        .unwrap();

        // Wait for distribution
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedRoutes {
            peer: target,
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
}
