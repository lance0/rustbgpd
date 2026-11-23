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
const QUIET_PAGE_RECEIVER_KEYS: usize = 65_536;
/// Receiver-keys one quiet delivery unit may visit; at about 0.4 µs per
/// private receiver-key this keeps a single unit near 3 ms.
pub(super) const QUIET_UNIT_RECEIVER_KEYS: usize = 8_192;
/// Wall-clock budget for consecutive quiet units in one actor turn. It sits
/// well below the waiting-UPDATE delay bar, leaving room for the last unit.
pub(super) const QUIET_LOOP_BUDGET: std::time::Duration = std::time::Duration::from_millis(10);

/// Members one quiet delivery unit covers for a page of `keys` receiver-keys.
pub(super) fn quiet_delivery_members(keys: usize) -> usize {
    (QUIET_UNIT_RECEIVER_KEYS / keys.max(1)).max(1)
}

#[derive(Clone, Copy)]
enum PrimaryTurn {
    AfterBatch,
    CheckFrom(usize),
    Fenced,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Exporters {
    Private,
    PlainGroups,
    Mixed,
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
    exporters: [Exporters; 2],
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

    fn next_page(&mut self, quiet: bool) -> Option<Page> {
        // An arrival must wait for the pinned page to reach its entire roster.
        // A one-key page still has to reach every member of a larger roster.
        let quiet_width =
            (QUIET_PAGE_RECEIVER_KEYS / self.peers.len().max(1)).clamp(1, RECEIVER_ROWS_PER_POLL);
        let page_width = |remaining: usize, queued_width, can_widen| {
            if quiet {
                // Leave a seam for an arrival just after the empty observation,
                // even when the wider page could consume the entire remainder.
                let limit = if can_widen {
                    quiet_width
                } else {
                    quiet_width.min(queued_width)
                };
                limit.min(remaining.saturating_sub(1).max(1))
            } else {
                queued_width
            }
        };
        for (index, keys) in self.unicast.iter_mut().enumerate() {
            if !keys.is_empty() {
                let shared = self.exporters[index] == Exporters::PlainGroups;
                let key_limit = page_width(
                    keys.len(),
                    if shared {
                        RECEIVER_ROWS_PER_POLL
                    } else {
                        KEYS_PER_PAGE
                    },
                    self.exporters[index] != Exporters::Mixed,
                );
                let mut page: HashSet<_> =
                    keys.drain(keys.len().saturating_sub(key_limit)..).collect();
                let held = page
                    .extract_if(|prefix| self.held.contains(prefix))
                    .collect();
                let best = page.intersection(&self.best).copied().collect();
                let afi = [Afi::Ipv4, Afi::Ipv6][index];
                let wide = self.exporters[index] != Exporters::Mixed;
                return Some(Page::Unicast(Box::new(ReleaseDistribution::for_departure(
                    afi, page, best, held, shared, wide,
                ))));
            }
        }
        let width = page_width(self.flowspec.len(), KEYS_PER_PAGE, true);
        let keys: HashSet<_> = self.flowspec.by_ref().take(width).collect();
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
        // One departure owns the actor at a time. A teardown reached while
        // one is live keeps the synchronous path instead of replacing it.
        self.source_departure.is_none()
            && keys.saturating_mul(self.outbound_peers.len()) > RECEIVER_ROWS_PER_POLL
    }

    /// A private receiver that selects its own winner among all candidates,
    /// as the private export walk decides it.
    pub(in crate::manager) fn private_per_client_best(&self, peer: PeerId) -> bool {
        self.peer_per_client_best.contains(&peer)
    }

    /// The private export walk ranks this receiver's candidates by its ORR
    /// vantage when that vantage resolved in the current SPF results.
    pub(in crate::manager) fn orr_vantage_resolved(&self, peer: PeerId) -> bool {
        self.peer_orr_vantage
            .get(&peer)
            .is_some_and(|vantage| self.orr.spf.contains_key(vantage))
    }

    // Membership and capabilities are fenced for the departure. Mixed,
    // multipath, per-client-best and ORR exporters retain narrow pages for
    // their per-receiver candidate walks.
    fn departure_exporters(&self, peers: &[PeerId], afi: Afi) -> Exporters {
        let family = (afi, Safi::Unicast);
        let mut kind = None;
        for &peer in peers {
            if !self
                .peer_sendable_families
                .get(&peer)
                .is_some_and(|families| families.contains(&family))
            {
                continue;
            }
            let member = match self.grouped_member_of(peer) {
                Some(gid)
                    if self
                        .group_ribs
                        .get(&gid)
                        .is_some_and(|group| !group.per_client_best) =>
                {
                    Exporters::PlainGroups
                }
                None if !self
                    .peer_add_path_send_families
                    .get(&peer)
                    .is_some_and(|families| families.contains(&family))
                    && !self.private_per_client_best(peer)
                    && !self.orr_vantage_resolved(peer) =>
                {
                    Exporters::Private
                }
                _ => return Exporters::Mixed,
            };
            if kind.replace(member).is_some_and(|prior| prior != member) {
                return Exporters::Mixed;
            }
        }
        kind.unwrap_or(Exporters::Mixed)
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
        let exporters = [Afi::Ipv4, Afi::Ipv6].map(|afi| self.departure_exporters(&peers, afi));
        let pages = unicast
            .iter()
            .zip(exporters)
            .map(|(keys, kind)| {
                keys.len().div_ceil(if kind == Exporters::PlainGroups {
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
            exporters,
            flowspec: flowspec.into_iter(),
            families,
            page: None,
            primary,
        }));
    }

    /// Nothing admissible waits behind the departure. A fenced FIFO head
    /// cannot run before the departure ends, so wider pages only bring it
    /// forward. A lagging receiver keeps the narrow path.
    pub(super) fn source_departure_quiet(&self) -> bool {
        let fenced = self
            .source_departure
            .as_ref()
            .is_some_and(|work| matches!(work.primary, PrimaryTurn::Fenced));
        (fenced || self.primary_backlog() == 0)
            && self.dirty_peers.is_empty()
            && self.force_outbound_peers.is_empty()
            && self.owing_peers.is_empty()
            && self.helper_stale_exempt.is_empty()
    }

    pub(super) fn advance_source_departure(&mut self) {
        // Check again at every unit, including inside a pinned page.
        let quiet = self.source_departure_quiet();
        #[cfg(test)]
        if quiet {
            super::tests::source_departure::after_empty_fifo();
        }
        let work = self
            .source_departure
            .as_mut()
            .expect("departure owns the actor");
        let Some(mut page) = work.page.take().or_else(|| work.next_page(quiet)) else {
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
            Page::Unicast(pass) => self.poll_unicast_release_distribution(pass, quiet),
            Page::FlowSpec { keys, next } => {
                let members = if quiet {
                    quiet_delivery_members(keys.len()).max(MEMBERS_PER_PAGE)
                } else {
                    MEMBERS_PER_PAGE.min(RECEIVER_ROWS_PER_POLL / keys.len())
                };
                let end = (*next + members).min(work.peers.len());
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

    /// Run one departure unit or one primary dispatch. Returns `false` when
    /// the turn applied primary work, which ends a quiet run of units.
    pub(super) fn poll_source_departure_turn(&mut self) -> bool {
        // An admitted UPDATE must apply through its final route chunk before
        // another batch can stage. A noncommuting FIFO head stays in place.
        if !self.pending_route_batches.is_empty() {
            debug_assert!(
                self.source_departure
                    .as_ref()
                    .is_some_and(|work| work.page.is_none())
            );
            self.traced_route_chunk();
            return false;
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
                        return false;
                    }
                    PrimaryHead::Fenced => work.primary = PrimaryTurn::Fenced,
                    PrimaryHead::Independent => {
                        if let Some(update) = self.try_recv_primary() {
                            self.handle_update(update);
                            return false;
                        }
                    }
                }
            }
        }
        self.advance_source_departure();
        true
    }
}

#[cfg(test)]
impl RibManager {
    /// Whether the live departure has a page in progress.
    pub(super) fn departure_page_open(&self) -> bool {
        self.source_departure
            .as_ref()
            .is_some_and(|work| work.page.is_some())
    }

    /// Whether the open page restored RS counts for a member page that has
    /// not yet received its emission.
    pub(super) fn departure_rs_restore_pinned(&self) -> bool {
        self.source_departure
            .as_ref()
            .and_then(|work| work.page.as_ref())
            .is_some_and(|page| matches!(page, Page::Unicast(pass) if pass.rs_restore_pinned()))
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
