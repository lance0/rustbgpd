//! A non-GR source is detached and its keys selected at teardown. The actor
//! distributes those changes over bounded key/member pages. A shared stage
//! owns the actor until its last member has consumed the previous group state.

use super::distribution::ReleaseDistribution;
use super::helpers::{LOCAL_PEER, prefix_family, unicast_deferral_exempt};
use super::{Afi, HashSet, PeerId, Prefix, RibManager, RibUpdate, Safi};
use crate::route::{FlowSpecKey, Route};
use std::collections::hash_set;

const KEYS_PER_PAGE: usize = 16;
pub(super) const MEMBERS_PER_PAGE: usize = 8;
pub(super) const RECEIVER_ROWS_PER_POLL: usize = 256;

#[derive(Clone, Copy)]
enum PrimaryTurn {
    AfterBatch,
    CheckFrom(usize),
    Fenced,
}

enum PrimaryHead {
    Independent,
    CheckFrom(usize),
    Fenced,
}

enum Page {
    Unicast(Box<ReleaseDistribution>),
    FlowSpec {
        keys: HashSet<FlowSpecKey>,
        next: usize,
    },
}

pub(super) struct SourceDeparture {
    source: PeerId,
    peers: Vec<PeerId>,
    // Retain the identities independently of the consuming iterator. FIFO
    // lookahead can prove a new unicast message independent in O(message rows).
    affected: HashSet<Prefix>,
    best: HashSet<Prefix>,
    held: HashSet<Prefix>,
    unicast: [Vec<Prefix>; 2],
    plain_groups_only: [bool; 2],
    flowspec: hash_set::IntoIter<FlowSpecKey>,
    families: HashSet<(Afi, Safi)>,
    page: Option<Page>,
    primary: PrimaryTurn,
}

impl SourceDeparture {
    pub(super) fn holds_family(&self, family: (Afi, Safi)) -> bool {
        self.families.contains(&family)
    }

    pub(super) fn peer_batch(&self, after: Option<PeerId>, limit: usize) -> Vec<PeerId> {
        let at = after.map_or(0, |after| self.peers.partition_point(|&peer| peer <= after));
        self.peers[at..].iter().take(limit).copied().collect()
    }

    fn next_page(&mut self) -> Option<Page> {
        for (index, keys) in self.unicast.iter_mut().enumerate() {
            if !keys.is_empty() {
                let shared = self.plain_groups_only[index];
                let key_limit = if shared {
                    RECEIVER_ROWS_PER_POLL
                } else {
                    KEYS_PER_PAGE
                };
                let mut page: HashSet<_> =
                    keys.drain(keys.len().saturating_sub(key_limit)..).collect();
                let held = page
                    .extract_if(|prefix| self.held.contains(prefix))
                    .collect();
                let best = page.intersection(&self.best).copied().collect();
                let afi = [Afi::Ipv4, Afi::Ipv6][index];
                return Some(Page::Unicast(Box::new(ReleaseDistribution::for_departure(
                    afi, page, best, held, shared,
                ))));
            }
        }
        let keys: HashSet<_> = self.flowspec.by_ref().take(KEYS_PER_PAGE).collect();
        (!keys.is_empty()).then_some(Page::FlowSpec { keys, next: 0 })
    }

    fn independent_routes(
        &self,
        offset: usize,
        peer: PeerId,
        announced: &[Route],
        withdrawn: &[(Prefix, u32)],
    ) -> PrimaryHead {
        if peer == self.source {
            return PrimaryHead::Fenced;
        }
        let rows = announced.len() + withdrawn.len();
        let end = (offset + KEYS_PER_PAGE).min(rows);
        for index in offset..end {
            let prefix = if index < announced.len() {
                &announced[index].prefix
            } else {
                &withdrawn[index - announced.len()].0
            };
            if self.affected.contains(prefix) {
                return PrimaryHead::Fenced;
            }
        }
        if end == rows {
            PrimaryHead::Independent
        } else {
            PrimaryHead::CheckFrom(end)
        }
    }

    fn classify(&self, update: &RibUpdate, offset: usize) -> PrimaryHead {
        match update {
            RibUpdate::SessionRoutes { routes, .. } => self.classify(routes, offset),
            RibUpdate::RoutesReceived {
                peer,
                announced,
                withdrawn,
                flowspec_announced,
                flowspec_withdrawn,
                evpn_announced,
                evpn_withdrawn,
                ..
            } if flowspec_announced.is_empty()
                && flowspec_withdrawn.is_empty()
                && evpn_announced.is_empty()
                && evpn_withdrawn.is_empty() =>
            {
                self.independent_routes(offset, *peer, announced, withdrawn)
            }
            RibUpdate::WireRoutesReceived(batch)
                if batch.flowspec_announced.is_empty()
                    && batch.flowspec_withdrawn.is_empty()
                    && batch.evpn_announced.is_empty()
                    && batch.evpn_withdrawn.is_empty() =>
            {
                self.independent_routes(offset, batch.peer, &batch.announced, &batch.withdrawn)
            }
            _ => PrimaryHead::Fenced,
        }
    }
}

impl RibManager {
    pub(super) fn large_source_departure(&self, keys: usize) -> bool {
        keys.saturating_mul(self.outbound_peers.len()) > RECEIVER_ROWS_PER_POLL
    }

    pub(super) fn start_source_departure(
        &mut self,
        source: PeerId,
        affected: HashSet<Prefix>,
        best: HashSet<Prefix>,
        fs_affected: &HashSet<FlowSpecKey>,
    ) {
        debug_assert!(self.source_departure.is_none());
        self.invalidate_flowspec_dependencies(&affected);
        let _ = self.observe_conditional_advertisement_prefixes(affected.iter());
        let local = self.ribs.get(&LOCAL_PEER);
        let readiness = self.replacement_readiness.clone();
        let checkpoint = || super::replacement_readiness_checkpoint(&readiness, false);
        let mut held = HashSet::new();
        let mut unicast = [Vec::new(), Vec::new()];
        for &key in &affected {
            checkpoint();
            if self.selection_deferred(prefix_family(&key))
                && !best.contains(&key)
                && !local.is_some_and(|rib| rib.iter_prefix(&key).any(unicast_deferral_exempt))
            {
                if self.helper_stale_exempt.is_empty() {
                    continue;
                }
                // A frozen winner stays off the group stage. A helper may
                // nevertheless have lost a stale path for this identity.
                held.insert(key);
            }
            unicast[usize::from(matches!(key, Prefix::V6(_)))].push(key);
        }
        let unicast_keys = unicast.iter().map(Vec::len).sum::<usize>();
        if unicast_keys > held.len() {
            self.fib_candidate_changes_tx
                .send_modify(|generation| *generation = generation.wrapping_add(1));
        }
        let flowspec = if fs_affected.is_empty() {
            HashSet::new()
        } else {
            self.select_flowspec_departure_keys(fs_affected)
        };
        let mut families: HashSet<_> = flowspec
            .iter()
            .inspect(|_| checkpoint())
            .map(FlowSpecKey::family)
            .collect();
        for keys in &unicast {
            if let Some(key) = keys.first() {
                families.insert(prefix_family(key));
            }
        }
        if families.is_empty() {
            return;
        }
        let mut peers: Vec<_> = self
            .outbound_peers
            .keys()
            .copied()
            .filter(|&peer| peer != source)
            .collect();
        peers.sort_unstable();
        // A group stages these keys once and shares the result. Amortize its
        // fixed cost across a wider key batch, then narrow each member visit
        // to the same receiver-row budget. Private and per-client-best
        // exporters keep narrow pages for their per-member and lane walks.
        // Receive-only peers do not export.
        let plain_groups_only = [Afi::Ipv4, Afi::Ipv6].map(|afi| {
            let mut eligible = peers
                .iter()
                .copied()
                .filter(|peer| {
                    self.peer_sendable_families
                        .get(peer)
                        .is_some_and(|families| families.contains(&(afi, Safi::Unicast)))
                })
                .peekable();
            eligible.peek().is_some()
                && eligible.all(|peer| {
                    self.grouped_member_of(peer)
                        .and_then(|gid| self.group_ribs.get(&gid))
                        .is_some_and(|group| !group.per_client_best)
                })
        });
        let pages = unicast
            .iter()
            .zip(plain_groups_only)
            .map(|(keys, shared)| {
                keys.len().div_ceil(if shared {
                    RECEIVER_ROWS_PER_POLL
                } else {
                    KEYS_PER_PAGE
                })
            })
            .sum::<usize>()
            + flowspec.len().div_ceil(KEYS_PER_PAGE);
        // With a single key batch, the first safe seam is also the last
        // chance to admit an independent message before all its rows are sent.
        let primary = if pages == 1 {
            PrimaryTurn::CheckFrom(0)
        } else {
            PrimaryTurn::AfterBatch
        };
        self.source_departure = Some(Box::new(SourceDeparture {
            source,
            peers,
            affected,
            best,
            held,
            unicast,
            plain_groups_only,
            flowspec: flowspec.into_iter(),
            families,
            page: None,
            primary,
        }));
    }

    pub(super) fn advance_source_departure(&mut self) {
        let work = self
            .source_departure
            .as_mut()
            .expect("departure owns the actor");
        let Some(mut page) = work.page.take().or_else(|| work.next_page()) else {
            self.source_departure = None;
            // The last admitted export can release the final strong reference
            // to a departed route's attributes. Use the same retirement owner
            // as synchronous teardown once the rejection proofs are consumed.
            super::with_executor_handoff(|| {
                self.with_replacement_readiness(|manager| {
                    manager.prune_exact_export_rejections();
                    manager.finish_peer_attribute_gc();
                });
            });
            self.finish_source_departure_markers();
            return;
        };
        let done = match &mut page {
            Page::Unicast(pass) => self.poll_unicast_release_distribution(pass),
            Page::FlowSpec { keys, next } => {
                let end = (*next + MEMBERS_PER_PAGE).min(work.peers.len());
                let peers = work.peers[*next..end].to_vec();
                let done = end == work.peers.len();
                *next = end;
                self.distribute_flowspec_departure_page(keys, &peers);
                done
            }
        };
        let work = self
            .source_departure
            .as_mut()
            .expect("departure remains live through publication");
        if !done {
            work.page = Some(page);
        } else if matches!(work.primary, PrimaryTurn::AfterBatch) {
            work.primary = PrimaryTurn::CheckFrom(0);
        }
    }

    pub(super) fn poll_source_departure_turn(&mut self) {
        // An admitted UPDATE must apply through its final route chunk before
        // another batch can stage. A noncommuting FIFO head stays in place.
        if !self.pending_route_batches.is_empty() {
            debug_assert!(
                self.source_departure
                    .as_ref()
                    .is_some_and(|work| work.page.is_none())
            );
            self.traced_route_chunk();
            return;
        }
        let work = self
            .source_departure
            .as_mut()
            .expect("departure owns the actor");
        if let PrimaryTurn::CheckFrom(offset) = work.primary {
            work.primary = PrimaryTurn::AfterBatch;
            debug_assert!(work.page.is_none());
            if self.primary_lookahead.is_none() {
                self.primary_lookahead = self.rx.try_recv().ok();
            }
            if let Some(update) = &self.primary_lookahead {
                match work.classify(update, offset) {
                    PrimaryHead::CheckFrom(offset) => {
                        work.primary = PrimaryTurn::CheckFrom(offset);
                        return;
                    }
                    PrimaryHead::Fenced => work.primary = PrimaryTurn::Fenced,
                    PrimaryHead::Independent => {
                        if let Some(update) = self.try_recv_primary() {
                            self.handle_update(update);
                            return;
                        }
                    }
                }
            }
        }
        self.advance_source_departure();
    }
}

#[cfg(test)]
thread_local! {
    static RECEIVER_ROWS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn inspect_receiver_row() {
    RECEIVER_ROWS.set(RECEIVER_ROWS.get() + 1);
}

#[cfg(test)]
pub(super) fn take_receiver_rows() -> usize {
    RECEIVER_ROWS.replace(0)
}
