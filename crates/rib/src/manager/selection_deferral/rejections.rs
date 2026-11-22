//! A frozen Loc-RIB row keeps its exact outbound rejections after its last
//! input withdraws. Release retires them after delivering the withdrawal.
//! Outbound Add-Path IDs need not be contiguous or equal the input path ID.

use std::collections::{BTreeSet, HashMap, HashSet};

use rustbgpd_wire::{Afi, Prefix, Safi};

use super::{RibManager, SelectionDeferral};
use crate::PeerId;
use crate::update::ExactExportKey;

#[derive(Default)]
pub(in crate::manager) struct ReleaseRejections {
    tracked: [bool; 2],
    // One compact tuple per actual rejected unicast path in a startup AFI.
    // The prefix-major order seeks every receiver and rank of a vanished NLRI.
    keys: [BTreeSet<(Prefix, u32, PeerId)>; 2],
}

impl ReleaseRejections {
    pub(super) fn initialize(
        &mut self,
        deferral: Option<&SelectionDeferral>,
        existing: &HashMap<PeerId, HashSet<ExactExportKey>>,
    ) {
        self.update_tracking(deferral);
        self.keys = Default::default();
        if self.tracked.contains(&true) {
            for (&peer, keys) in existing {
                for key in keys {
                    self.record(peer, key, true);
                }
            }
        }
    }

    pub(super) fn update_tracking(&mut self, deferral: Option<&SelectionDeferral>) {
        self.tracked = [Afi::Ipv4, Afi::Ipv6]
            .map(|afi| deferral.is_some_and(|gate| gate.may_hold_family((afi, Safi::Unicast))));
    }

    pub(in crate::manager) fn len(&self) -> usize {
        self.keys.iter().map(BTreeSet::len).sum()
    }

    pub(in crate::manager) fn record(
        &mut self,
        peer: PeerId,
        key: &ExactExportKey,
        rejected: bool,
    ) {
        let ExactExportKey::Unicast(prefix, path) = *key else {
            return;
        };
        let family = usize::from(matches!(prefix, Prefix::V6(_)));
        if self.tracked[family] {
            let key = (prefix, path, peer);
            if rejected {
                self.keys[family].insert(key);
            } else {
                self.keys[family].remove(&key);
            }
        }
    }

    fn last(&self, prefix: Prefix) -> Option<(Prefix, u32, PeerId)> {
        // UNASSIGNED has the highest slot and generation in PeerId's map order.
        self.keys[usize::from(matches!(prefix, Prefix::V6(_)))]
            .range(..=(prefix, u32::MAX, PeerId::UNASSIGNED))
            .next_back()
            .filter(|entry| entry.0 == prefix)
            .copied()
    }

    pub(super) fn retirement_pending(&self) -> bool {
        (0..2).any(|family| !self.tracked[family] && !self.keys[family].is_empty())
    }

    pub(super) fn retire_index(&mut self, mut budget: usize) {
        for (keys, tracked) in self.keys.iter_mut().zip(self.tracked) {
            if !tracked {
                let n = budget.min(keys.len());
                for _ in 0..n {
                    keys.pop_first();
                }
                budget -= n;
            }
        }
    }
}

pub(super) struct RetireReleaseRejections {
    prefixes: Vec<Prefix>,
    announcer: usize,
    source_absent: bool,
}

impl RibManager {
    pub(super) fn release_rejections_for_batch(
        &self,
        covered: &HashSet<Prefix>,
    ) -> Option<RetireReleaseRejections> {
        let index = &self.unicast_release.rejections;
        if index.len() == 0 {
            return None;
        }
        let prefixes: Vec<_> = covered
            .iter()
            .copied()
            .filter(|prefix| self.loc_rib.get(prefix).is_none() && index.last(*prefix).is_some())
            .collect();
        (!prefixes.is_empty()).then_some(RetireReleaseRejections {
            prefixes,
            announcer: 0,
            source_absent: false,
        })
    }

    /// Distribution holds its mutation fence until these prefixes have been
    /// checked. Every step visits one input source, removes one matching
    /// outbound rank, or advances between prefixes.
    pub(super) fn retire_release_rejections(
        &mut self,
        retirement: &mut RetireReleaseRejections,
        budget: usize,
    ) -> bool {
        for _ in 0..budget {
            let Some(&prefix) = retirement.prefixes.last() else {
                return true;
            };
            if !retirement.source_absent {
                if let Some(epoch) = self
                    .unicast_prefix_peers
                    .epochs(&prefix)
                    .nth(retirement.announcer)
                {
                    let live = self
                        .unicast_prefix_peers
                        .epoch_peers
                        .get(&epoch)
                        .and_then(|peer| self.ribs.get(peer))
                        .is_some_and(|rib| rib.iter_prefix(&prefix).next().is_some());
                    if live {
                        retirement.prefixes.pop();
                        retirement.announcer = 0;
                    } else {
                        retirement.announcer += 1;
                    }
                } else {
                    retirement.source_absent = true;
                }
                continue;
            }
            let index = &mut self.unicast_release.rejections;
            if let Some(key @ (_, path, peer)) = index.last(prefix) {
                index.keys[usize::from(matches!(prefix, Prefix::V6(_)))].remove(&key);
                self.set_exact_export_rejection(peer, ExactExportKey::Unicast(prefix, path), false);
            } else {
                retirement.prefixes.pop();
                retirement.announcer = 0;
                retirement.source_absent = false;
            }
        }
        retirement.prefixes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adj_rib_in::AdjRibIn;
    use crate::manager::selection_deferral::{
        SelectionDeferralConfig, SelectionDeferralWaiterConfig,
    };
    use crate::test_support::make_route;
    use rustbgpd_telemetry::BgpMetrics;
    use rustbgpd_wire::Ipv4Prefix;
    use std::net::Ipv4Addr;
    use std::time::Duration;
    use tokio::sync::mpsc;

    #[test]
    fn release_retires_only_dead_nlri_ranks_with_bounded_work() {
        let mut manager = RibManager::new(
            mpsc::channel(1).1,
            mpsc::channel(1).1,
            None,
            None,
            BgpMetrics::new(),
        );
        let peer = PeerId::from_ipv4(Ipv4Addr::new(192, 0, 2, 1));
        let second = PeerId::from_ipv4(Ipv4Addr::new(192, 0, 2, 2));
        let dead = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
        let live_prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 24);
        let live = Prefix::V4(live_prefix);
        manager.peer_unexportable.insert(
            peer,
            HashSet::from([
                ExactExportKey::Unicast(dead, 0),
                ExactExportKey::Unicast(dead, u32::MAX),
                ExactExportKey::Unicast(live, 17),
            ]),
        );
        manager.peer_unexportable.insert(
            second,
            HashSet::from([ExactExportKey::Unicast(dead, 150_000)]),
        );
        let unrelated = (0..1000u32)
            .map(|i| {
                ExactExportKey::Unicast(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(i + 1), 32)), i)
            })
            .collect::<HashSet<_>>();
        manager
            .peer_unexportable
            .get_mut(&peer)
            .unwrap()
            .extend(unrelated.iter().cloned());
        manager = manager.with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: peer.into(),
                families: vec![(Afi::Ipv4, Safi::Unicast)],
            }],
        });
        // A surviving input can exist without an installed winner.
        let source = Ipv4Addr::new(198, 51, 100, 1);
        let mut rib = AdjRibIn::new(PeerId::from_ipv4(source));
        rib.insert(make_route(live_prefix, source));
        manager.ribs.insert(PeerId::from_ipv4(source), rib);
        manager.register_unicast_announcer(PeerId::from_ipv4(source), live);

        let mut retirement = manager
            .release_rejections_for_batch(&HashSet::from([dead, live]))
            .unwrap();
        for turn in 1..=6 {
            let before = manager.unicast_release.rejections.len();
            let done = manager.retire_release_rejections(&mut retirement, 1);
            assert!(before - manager.unicast_release.rejections.len() <= 1);
            assert_eq!(
                done,
                turn == 6,
                "only covered prefixes and their actual sources/ranks cost work"
            );
        }
        assert!(!manager.peer_unexportable.contains_key(&second));
        let mut kept = unrelated;
        kept.insert(ExactExportKey::Unicast(live, 17));
        assert_eq!(manager.peer_unexportable[&peer], kept);
        let index = &mut manager.unicast_release.rejections;
        let before = index.len();
        index.update_tracking(None);
        index.retire_index(3);
        assert_eq!(index.len(), before - 3);
        assert_eq!(manager.peer_unexportable[&peer], kept);
    }
}
