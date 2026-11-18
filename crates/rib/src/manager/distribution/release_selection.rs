//! Resumable unicast best selection during startup release. A prefix is
//! published only after every announcing session and path has been examined.

use std::task::Poll;

use rustbgpd_wire::{Afi, Prefix};

use super::{BestSource, RibManager};
use crate::best_path::{best_path_cmp_ranked, best_path_cmp_with_reason, stale_rank};
use crate::manager::helpers::{UNICAST_FAMILIES, gauge_val, set_loc_rib_prefixes};
use crate::manager::{PrefixAnnouncers, UnicastPrefixPeers};
use crate::route::Route;

#[derive(Debug)]
pub(in crate::manager) struct ReleaseSelection {
    prefix: Prefix,
    announcer: usize,
    live_announcers: usize,
    after_path: Option<u32>,
    best: Option<(Route, u8)>,
    runner_up: Option<(Route, u8)>,
}

impl ReleaseSelection {
    pub(in crate::manager) fn new(prefix: Prefix) -> Self {
        Self {
            prefix,
            announcer: 0,
            live_announcers: 0,
            after_path: None,
            best: None,
            runner_up: None,
        }
    }

    fn consider(&mut self, route: &Route, bmp: bool) {
        if !crate::srv6::unicast_eligible(route) {
            return;
        }
        let rank = stale_rank(route);
        let wins = |(other, other_rank): &(Route, u8)| {
            best_path_cmp_ranked(route, rank, other, *other_rank).is_lt()
        };
        if self.best.as_ref().is_none_or(wins) {
            if bmp {
                self.runner_up = self.best.take();
            }
            self.best = Some((route.clone(), rank));
        } else if bmp && self.runner_up.as_ref().is_none_or(wins) {
            self.runner_up = Some((route.clone(), rank));
        }
    }
}

impl UnicastPrefixPeers {
    /// Compact without changing live source order (the first minimum wins a tie).
    /// Swapping with a visited empty source preserves every epoch if a mutation
    /// cancels the fold before its stale tail is truncated.
    fn keep_release_announcer(&mut self, prefix: Prefix, read: usize, write: usize) {
        if read != write
            && let PrefixAnnouncers::Spill(handle) = self.prefixes[&prefix]
        {
            self.spills[(handle.get() - 1) as usize].swap(read, write);
        }
    }

    fn finish_release_announcers(&mut self, prefix: Prefix, live: usize) {
        match self.prefixes.get(&prefix).copied() {
            Some(PrefixAnnouncers::Spill(handle)) => {
                let peers = &mut self.spills[(handle.get() - 1) as usize];
                peers.truncate(live);
                match peers.as_slice() {
                    [] => {
                        self.prefixes.remove(&prefix);
                        self.release_spill(handle);
                    }
                    [last] => {
                        self.prefixes
                            .insert(prefix, PrefixAnnouncers::Inline(*last));
                        self.release_spill(handle);
                    }
                    _ => {}
                }
            }
            Some(PrefixAnnouncers::Inline(_)) if live == 0 => {
                self.prefixes.remove(&prefix);
            }
            _ => {}
        }
    }
}

impl RibManager {
    /// Charge every candidate visit, including a failed source seek and the
    /// final commit. A ready result reports whether selection removed the
    /// prior Loc-RIB row. Ordinary affected-prefix mutations invalidate this fold.
    pub(in crate::manager) fn poll_release_selection(
        &mut self,
        selection: &mut ReleaseSelection,
        budget: &mut usize,
    ) -> Poll<bool> {
        let prefix = selection.prefix;
        while *budget > 0 {
            let epoch = self
                .unicast_prefix_peers
                .epochs(&prefix)
                .nth(selection.announcer);
            let Some(epoch) = epoch else {
                *budget -= 1;
                if selection.live_announcers != selection.announcer {
                    self.unicast_prefix_peers
                        .finish_release_announcers(prefix, selection.live_announcers);
                }
                let previous_best = self.loc_rib.get(&prefix).map(BestSource::of);
                let best = selection.best.as_ref().map(|(route, _)| route);
                let changed = self.loc_rib.recompute(prefix, best.into_iter());
                if changed {
                    if self.bmp_tx.is_some() {
                        let reason = best
                            .zip(selection.runner_up.as_ref())
                            .map(|(best, (other, _))| best_path_cmp_with_reason(best, other).1);
                        self.emit_unicast_best_bmp(prefix, reason);
                    }
                    self.publish_best_change_events(prefix, previous_best);
                }
                return Poll::Ready(changed && best.is_none());
            };
            let mut paths = self
                .unicast_prefix_peers
                .epoch_peers
                .get(&epoch)
                .and_then(|peer| self.ribs.get(peer))
                .map(|rib| rib.iter_prefix_after(&prefix, selection.after_path))
                .into_iter()
                .flatten();
            while *budget > 0 {
                *budget -= 1;
                if let Some(route) = paths.next() {
                    selection.after_path = Some(route.path_id);
                    selection.consider(route, self.bmp_tx.is_some());
                } else {
                    if selection.after_path.take().is_some() {
                        self.unicast_prefix_peers.keep_release_announcer(
                            prefix,
                            selection.announcer,
                            selection.live_announcers,
                        );
                        selection.live_announcers += 1;
                    }
                    selection.announcer += 1;
                    break;
                }
            }
        }
        Poll::Pending
    }

    pub(in crate::manager) fn publish_unicast_selection_counts(&self) {
        let counts = self.loc_rib.family_lens().unicast;
        match [Afi::Ipv4, Afi::Ipv6].map(|afi| self.unicast_release_in_progress(afi)) {
            [false, false] => set_loc_rib_prefixes(&self.metrics, UNICAST_FAMILIES, counts),
            [false, true] => self
                .metrics
                .set_loc_rib_prefixes(UNICAST_FAMILIES[0], gauge_val(counts[0])),
            [true, false] => self
                .metrics
                .set_loc_rib_prefixes(UNICAST_FAMILIES[1], gauge_val(counts[1])),
            [true, true] => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adj_rib_in::AdjRibIn;
    use crate::test_support::{make_route_with_lp, peer_v4};
    use rustbgpd_telemetry::BgpMetrics;
    use rustbgpd_wire::Ipv4Prefix;
    use std::collections::HashSet;
    use std::net::Ipv4Addr;
    use tokio::sync::mpsc;

    #[test]
    fn interleaved_update_recomputes_an_unswept_frozen_winner() {
        use rustbgpd_wire::Safi;

        let mut manager = RibManager::new(
            mpsc::channel(1).1,
            mpsc::channel(1).1,
            None,
            None,
            BgpMetrics::new(),
        );
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
        let key = Prefix::V4(prefix);
        let keys = HashSet::from([key]);
        let routes = [(1, 100), (2, 300), (3, 200)]
            .map(|(octet, lp)| make_route_with_lp(prefix, Ipv4Addr::new(198, 51, 100, octet), lp));
        for route in &routes {
            let mut rib = AdjRibIn::new(route.peer);
            rib.insert(route.clone());
            manager.ribs.insert(route.peer, rib);
            manager.register_unicast_announcer(route.peer, key);
        }
        // Only the first route had been selected when the hold began. The
        // second arrived during the hold; now the third announces or withdraws.
        manager.release_readiness_count = Some(1);
        manager.set_owed_release_open((Afi::Ipv4, Safi::Unicast), true);
        assert!(manager.loc_rib.recompute(key, std::iter::once(&routes[0])));
        assert_eq!(
            manager.recompute_best_after_announce(routes[2].peer, &keys),
            keys
        );
        assert_eq!(manager.loc_rib.get(&key).unwrap().peer, routes[1].peer);

        assert!(manager.loc_rib.recompute(key, std::iter::once(&routes[0])));
        assert!(
            manager
                .ribs
                .get_mut(&routes[2].peer)
                .unwrap()
                .withdraw(&key, routes[2].path_id)
        );
        assert_eq!(manager.recompute_best_after_withdraw(&keys), keys);
        assert_eq!(manager.loc_rib.get(&key).unwrap().peer, routes[1].peer);
    }

    #[test]
    fn release_selection_charges_each_path_and_empty_source_before_committing() {
        let (bmp_tx, mut bmp_rx) = mpsc::channel(4);
        let mut manager = RibManager::new(
            mpsc::channel(1).1,
            mpsc::channel(1).1,
            None,
            None,
            BgpMetrics::new(),
        )
        .with_bmp_tx(bmp_tx);
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
        let key = Prefix::V4(prefix);
        let addr = Ipv4Addr::new(198, 51, 100, 1);
        let peer = peer_v4(addr);
        let mut rib = AdjRibIn::new(peer);
        for id in 0..100 {
            let mut route = make_route_with_lp(prefix, addr, 200 - id);
            route.path_id = id;
            rib.insert(route);
        }
        manager.ribs.insert(peer, rib);
        // Six stale source probes must fit inside the same work budget as paths.
        for i in 2..8 {
            manager.register_unicast_announcer(peer_v4(Ipv4Addr::new(198, 51, 100, i)), key);
        }
        manager.register_unicast_announcer(peer, key);
        let mut selection = ReleaseSelection::new(key);
        let mut budget = 12;
        AdjRibIn::take_path_visits();
        assert!(
            manager
                .poll_release_selection(&mut selection, &mut budget)
                .is_pending()
        );
        assert_eq!(budget, 0);
        assert_eq!(AdjRibIn::take_path_visits(), 6);
        assert!(manager.loc_rib.get(&key).is_none());
        assert!(bmp_rx.try_recv().is_err());

        // Withdraw the provisional winner behind the cursor. The next fold
        // must restart; the committed winner and BMP reason come from live input.
        manager.ribs.get_mut(&peer).unwrap().withdraw(&key, 0);
        selection = ReleaseSelection::new(key);
        let mut work = 0;
        let mut reads = 0;
        loop {
            let mut remaining = 7;
            let complete = manager.poll_release_selection(&mut selection, &mut remaining);
            let visited = AdjRibIn::take_path_visits();
            assert!(visited <= 7 - remaining);
            work += 7 - remaining;
            reads += visited;
            if complete.is_ready() {
                break;
            }
            assert!(manager.loc_rib.get(&key).is_none());
            assert!(manager.route_event_history.is_empty());
        }
        assert_eq!(reads, 99);
        assert_eq!(work, 99 + 6 + 1 + 1); // paths, stale sources, live source end, commit
        assert_eq!(manager.unicast_prefix_peers.peers(&key).count(), 1);
        let installed = manager.loc_rib.get(&key).unwrap();
        assert_eq!(installed.path_id, 1);
        assert_eq!(manager.route_event_history.len(), 1);
        let rustbgpd_bmp::BmpEvent::LocRibRouteMonitoring { path_status, .. } =
            bmp_rx.try_recv().unwrap()
        else {
            panic!("missing unicast best announcement");
        };
        assert_eq!(
            path_status.unwrap().reason,
            crate::bmp_sync::unicast_path_status(
                installed,
                Some(crate::best_path::BestPathReason::HigherLocalPref)
            )
            .reason
        );
        let mut replay = ReleaseSelection::new(key);
        assert_eq!(
            manager.poll_release_selection(&mut replay, &mut 128),
            Poll::Ready(false)
        );
        assert_eq!(manager.route_event_history.len(), 1);
        assert!(bmp_rx.try_recv().is_err());
    }
}
