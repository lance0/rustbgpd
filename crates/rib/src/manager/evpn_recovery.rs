//! EVPN admitted-key recovery and complete-feed lifecycle fences.
//!
//! Full producers borrow actual OLD/NEW values before retirement and pass
//! their sparse payload through the existing mixed-family admission. Fixed
//! session receipts retain only completion coverage and ordered marker debt.

use rustbgpd_wire::EvpnRouteKey;

use super::update_groups::recovery_provenance::{
    EvpnProofView, Exhaustion, PeerSession, ProvenanceHandle,
};
use super::{IpAddr, RibManager};
use crate::adj_rib_out::AdjRibOut;
use crate::route::EvpnRibRoute;
use crate::update::{EvpnRecoveryReset, EvpnRecoveryResetOutcome, OutboundRouteUpdate};
use tokio::sync::{mpsc, oneshot};

/// Registration failed before a charged primary record existed. This bounded
/// inline session control state retains reset handoff, not recovery keys. Its
/// fixed size is excluded from the ledger's provenance-allocation charge.
#[derive(Clone, Copy)]
pub(super) struct PendingReset {
    error: Exhaustion,
    admitted: bool,
}

/// One receipt on the existing actor record, separate from charged route-key
/// provenance. Its channel and handle fence every completion after a replay.
pub(super) struct ResetReceipt {
    pub(super) handle: Option<ProvenanceHandle>,
    pub(super) outbound: mpsc::Sender<OutboundRouteUpdate>,
    pub(super) receiver: oneshot::Receiver<EvpnRecoveryResetOutcome>,
}

/// A full producer's operation-local admission fence. Payload vectors remain
/// in the existing mixed-family transaction, never in session control state.
pub(in crate::manager) struct EvpnFeedSeal {
    session_id: u64,
    outbound: mpsc::Sender<OutboundRouteUpdate>,
    provenance: ProvenanceHandle,
    target: EvpnFeedTarget,
    revision: u64,
    pub(in crate::manager) required_markers: u8,
}

/// A sparse clean diff, consumed once in the operation that moved membership.
pub(in crate::manager) struct EvpnCompleteFeed {
    pub(in crate::manager) seal: EvpnFeedSeal,
    pub(in crate::manager) announce: Vec<EvpnRibRoute>,
    pub(in crate::manager) withdraw: Vec<EvpnRouteKey>,
}

/// Fixed lifecycle metadata; the enclosing record owns the session/channel.
/// Invalid coverage requires a full producer again. Marker debt survives that
/// invalidation but cannot authorize settlement or another route admission.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EvpnFeedTarget {
    Grouped { group_id: usize, table_stamp: u64 },
    PrivateHandoff,
}

pub(super) struct EvpnFeedCompletion {
    provenance: ProvenanceHandle,
    target: EvpnFeedTarget,
    revision: u64,
    complete: bool,
    owed_markers: u8,
}

const EVPN_EOR: u8 = 1;
const EVPN_EORR: u8 = 2;
const EVPN_FAMILY: (rustbgpd_wire::Afi, rustbgpd_wire::Safi) =
    (rustbgpd_wire::Afi::L2Vpn, rustbgpd_wire::Safi::Evpn);

impl RibManager {
    /// Zero is permanently invalid, including after stamp-space exhaustion.
    /// A group recreated under an interned gid receives a different stamp.
    pub(in crate::manager) fn next_evpn_table_stamp(&mut self) -> Option<u64> {
        let next = self.evpn_table_stamp.checked_add(1)?;
        self.evpn_table_stamp = next;
        Some(next)
    }

    fn evpn_completion_record(&self, peer: IpAddr) -> Option<&super::LiveSessionRecord> {
        let session_id = self.outbound_session_ids.get(&peer)?;
        let outbound = self.outbound_peers.get(&peer)?;
        self.live_sessions.get(&peer)?.iter().find(|record| {
            record.session_id == *session_id && record.outbound_tx.same_channel(outbound)
        })
    }

    fn evpn_completion_record_mut(
        &mut self,
        peer: IpAddr,
    ) -> Option<&mut super::LiveSessionRecord> {
        let session_id = *self.outbound_session_ids.get(&peer)?;
        let outbound = self.outbound_peers.get(&peer)?;
        self.live_sessions
            .get_mut(&peer)?
            .iter_mut()
            .find(|record| {
                record.session_id == session_id && record.outbound_tx.same_channel(outbound)
            })
    }

    fn replace_evpn_feed_completion(
        &mut self,
        peer: IpAddr,
        completion: Option<EvpnFeedCompletion>,
    ) -> bool {
        let Some(record) = self.evpn_completion_record_mut(peer) else {
            return false;
        };
        let had = record.evpn_feed_completion.is_some();
        let has = completion.is_some();
        record.evpn_feed_completion = completion;
        match (had, has) {
            (false, true) => self.evpn_feed_receipt_count += 1,
            (true, false) => self.evpn_feed_receipt_count -= 1,
            _ => {}
        }
        true
    }

    /// Physical record removal owns this adjustment, before later ledger cleanup.
    pub(in crate::manager) fn drop_evpn_feed_receipts(
        &mut self,
        peer: IpAddr,
        session_id: Option<u64>,
    ) {
        let removed = self.live_sessions.get_mut(&peer).map_or(0, |records| {
            records
                .iter_mut()
                .filter(|record| session_id.is_none_or(|id| record.session_id == id))
                .map(|record| usize::from(record.evpn_feed_completion.take().is_some()))
                .sum::<usize>()
        });
        self.evpn_feed_receipt_count -= removed;
    }

    fn ensure_evpn_feed_receipt(&mut self, peer: IpAddr, target: EvpnFeedTarget) -> Option<u64> {
        let provenance = self.evpn_recovery_handle(peer)?;
        if let Some(completion) = self
            .evpn_completion_record(peer)
            .and_then(|record| record.evpn_feed_completion.as_ref())
            .filter(|completion| completion.provenance == provenance)
        {
            return Some(completion.revision);
        }
        let revision = self.next_evpn_table_stamp()?;
        self.replace_evpn_feed_completion(
            peer,
            Some(EvpnFeedCompletion {
                provenance,
                target,
                revision,
                complete: false,
                owed_markers: 0,
            }),
        )
        .then_some(revision)
    }

    pub(in crate::manager) fn invalidate_evpn_feed_completion(&mut self, peer: IpAddr) {
        if self
            .evpn_completion_record(peer)
            .is_none_or(|record| record.evpn_feed_completion.is_none())
        {
            return;
        }
        let revision = self.next_evpn_table_stamp().unwrap_or(0);
        if let Some(completion) = self
            .evpn_completion_record_mut(peer)
            .and_then(|record| record.evpn_feed_completion.as_mut())
        {
            completion.complete = false;
            completion.revision = revision;
        }
    }

    pub(in crate::manager) fn begin_private_evpn_handoff(&mut self, peer: IpAddr) -> bool {
        let Some(provenance) = self.evpn_recovery_handle(peer) else {
            return false;
        };
        let owed_markers = self
            .evpn_completion_record(peer)
            .and_then(|record| record.evpn_feed_completion.as_ref())
            .filter(|completion| completion.provenance == provenance)
            .map_or(0, |completion| completion.owed_markers);
        let Some(revision) = self.next_evpn_table_stamp() else {
            return false;
        };
        self.replace_evpn_feed_completion(
            peer,
            Some(EvpnFeedCompletion {
                provenance,
                target: EvpnFeedTarget::PrivateHandoff,
                revision,
                complete: false,
                owed_markers,
            }),
        )
    }

    /// This caller's dirty bookkeeping does not change its already-built
    /// complete plan. Preserve only that operation's otherwise-current seal.
    pub(in crate::manager) fn mark_outbound_dirty_with_evpn_feed(
        &mut self,
        peer: IpAddr,
        feed: &mut Option<EvpnCompleteFeed>,
    ) -> bool {
        let current = feed
            .as_ref()
            .is_some_and(|feed| self.evpn_feed_seal_is_current(peer, &feed.seal));
        let marked = self.mark_outbound_dirty(peer);
        if current
            && marked
            && let Some(feed) = feed
            && let Some(revision) = self
                .evpn_completion_record(peer)
                .and_then(|record| record.evpn_feed_completion.as_ref())
                .map(|completion| completion.revision)
        {
            let previous = feed.seal.revision;
            feed.seal.revision = revision;
            if !self.evpn_feed_seal_is_current(peer, &feed.seal) {
                feed.seal.revision = previous;
            }
        }
        marked
    }

    pub(in crate::manager) fn has_evpn_feed_completion(&self, peer: IpAddr) -> bool {
        self.evpn_completion_record(peer)
            .and_then(|record| record.evpn_feed_completion.as_ref())
            .is_some_and(|completion| {
                self.evpn_recovery_handle(peer) == Some(completion.provenance)
            })
    }

    pub(in crate::manager) fn has_private_evpn_handoff(&self, peer: IpAddr) -> bool {
        self.evpn_completion_record(peer)
            .and_then(|record| record.evpn_feed_completion.as_ref())
            .is_some_and(|completion| {
                completion.target == EvpnFeedTarget::PrivateHandoff
                    && self.evpn_recovery_handle(peer) == Some(completion.provenance)
            })
    }

    pub(in crate::manager) fn evpn_admitted_count(&self, peer: IpAddr) -> usize {
        self.evpn_completion_record(peer)
            .map_or(0, |record| record.evpn_admitted_count)
    }

    pub(in crate::manager) fn set_evpn_admitted_count(&mut self, peer: IpAddr, count: usize) {
        if let Some(record) = self.evpn_completion_record_mut(peer) {
            record.evpn_admitted_count = count;
        }
    }

    /// Borrow actual OLD only while this staging operation still owns it.
    /// A retained proof supersedes the clean projection after a missed send.
    pub(in crate::manager) fn evpn_prior_admitted(
        &self,
        peer: IpAddr,
        key: &EvpnRouteKey,
        stage: Option<&super::update_groups::EvpnGroupStageOutput>,
    ) -> Option<bool> {
        if let Some(proof) = self
            .evpn_recovery_handle(peer)
            .and_then(|handle| self.evpn_recovery.proof(handle).ok().flatten())
        {
            return Some(proof.contains(key));
        }
        let stage = stage?;
        let gid = self.evpn_grouped_member_of(peer)?;
        let group = self.group_ribs.get(&gid)?;
        let prior = stage
            .deltas
            .binary_search_by_key(key, |delta| delta.key)
            .ok()
            .and_then(|index| stage.deltas[index].old.as_ref());
        let filter = self.member_rt_filter(peer);
        Some(prior.is_some_and(|prior| {
            prior.input.eligible(
                &prior.route,
                peer,
                group,
                self.cluster_id,
                filter.as_ref(),
                self.peer_unexportable.get(&peer),
            )
        }))
    }

    /// Stage one scalar from unique final ANN/WD identities, with ANN winning.
    /// No receiver state changes until the existing mixed commit succeeds.
    pub(in crate::manager) fn planned_evpn_admitted_count(
        &self,
        peer: IpAddr,
        announce: &[EvpnRibRoute],
        withdraw: &[EvpnRouteKey],
        stage: Option<&super::update_groups::EvpnGroupStageOutput>,
    ) -> Option<usize> {
        let mut count = self
            .evpn_recovery_handle(peer)
            .and_then(|handle| self.evpn_recovery.proof(handle).ok().flatten())
            .map_or_else(|| self.evpn_admitted_count(peer), EvpnProofView::len);
        let mut previous = None;
        for route in announce {
            self.replacement_checkpoint(false);
            let key = route.key();
            if previous != Some(key) && !self.evpn_prior_admitted(peer, &key, stage)? {
                count = count.checked_add(1)?;
            }
            previous = Some(key);
        }
        for key in withdraw {
            self.replacement_checkpoint(false);
            if announce
                .binary_search_by_key(key, EvpnRibRoute::key)
                .is_err()
                && self.evpn_prior_admitted(peer, key, stage)?
            {
                count = count.checked_sub(1)?;
            }
        }
        Some(count)
    }

    /// Only an exact connection replay may move the fixed marker debt. Its
    /// prior coverage and all operation-local seals expire on that replay.
    pub(in crate::manager) fn take_evpn_feed_completion(
        &mut self,
        peer: IpAddr,
        session_id: u64,
        outbound: &mpsc::Sender<OutboundRouteUpdate>,
    ) -> Option<EvpnFeedCompletion> {
        let mut completion = self
            .live_sessions
            .get_mut(&peer)?
            .iter_mut()
            .find(|record| {
                record.session_id == session_id && record.outbound_tx.same_channel(outbound)
            })?
            .evpn_feed_completion
            .take()?;
        self.evpn_feed_receipt_count -= 1;
        completion.complete = false;
        completion.revision = self.next_evpn_table_stamp().unwrap_or(0);
        Some(completion)
    }

    pub(in crate::manager) fn evpn_feed_is_current(&self, peer: IpAddr) -> bool {
        let Some(record) = self.evpn_completion_record(peer) else {
            return false;
        };
        let Some(completion) = record.evpn_feed_completion.as_ref() else {
            return false;
        };
        completion.complete
            && completion.revision != 0
            && !record.outbound_tx.is_closed()
            && !self.evpn_recovery_reset_pending(peer)
            && self.evpn_recovery_handle(peer) == Some(completion.provenance)
            && match completion.target {
                EvpnFeedTarget::Grouped {
                    group_id,
                    table_stamp,
                } => {
                    table_stamp != 0
                        && self.evpn_grouped_member_of(peer) == Some(group_id)
                        && self.group_ribs.get(&group_id).is_some_and(|group| {
                            group.evpn_table_stamp == table_stamp && group.members.contains(&peer)
                        })
                }
                EvpnFeedTarget::PrivateHandoff => self.evpn_grouped_member_of(peer).is_none(),
            }
    }

    pub(in crate::manager) fn evpn_feed_seal_is_current(
        &self,
        peer: IpAddr,
        seal: &EvpnFeedSeal,
    ) -> bool {
        seal.revision != 0
            && self.outbound_session_ids.get(&peer) == Some(&seal.session_id)
            && self
                .outbound_peers
                .get(&peer)
                .is_some_and(|tx| !tx.is_closed() && tx.same_channel(&seal.outbound))
            && self.evpn_recovery_handle(peer) == Some(seal.provenance)
            && self
                .evpn_completion_record(peer)
                .and_then(|record| record.evpn_feed_completion.as_ref())
                .is_some_and(|completion| {
                    completion.provenance == seal.provenance && completion.revision == seal.revision
                })
            && match seal.target {
                EvpnFeedTarget::Grouped {
                    group_id,
                    table_stamp,
                } => {
                    table_stamp != 0
                        && self.evpn_grouped_member_of(peer) == Some(group_id)
                        && self.group_ribs.get(&group_id).is_some_and(|group| {
                            group.evpn_table_stamp == table_stamp && group.members.contains(&peer)
                        })
                }
                EvpnFeedTarget::PrivateHandoff => {
                    self.evpn_grouped_member_of(peer).is_none()
                        && self.has_private_evpn_handoff(peer)
                }
            }
            && !self.evpn_recovery_reset_pending(peer)
    }

    fn evpn_projection_matches_proof(&self, peer: IpAddr, seal: &EvpnFeedSeal) -> bool {
        let Ok(Some(proof)) = self.evpn_recovery.proof(seal.provenance) else {
            return false;
        };
        let readiness = self.replacement_readiness.clone();
        match seal.target {
            EvpnFeedTarget::Grouped { group_id, .. } => {
                let Some(group) = self.group_ribs.get(&group_id) else {
                    return false;
                };
                let filter = self.member_rt_filter(peer);
                let mut count = 0;
                for route in group.evpn_member_projection_with_checkpoint(
                    peer,
                    self.cluster_id,
                    filter.as_ref(),
                    self.peer_unexportable.get(&peer),
                    || super::replacement_readiness_checkpoint(&readiness, false),
                ) {
                    if !proof.contains(&route.key()) {
                        return false;
                    }
                    count += 1;
                }
                count == proof.len()
            }
            EvpnFeedTarget::PrivateHandoff => {
                self.adj_ribs_out
                    .get(&peer)
                    .map_or(proof.is_empty(), |private| {
                        private.evpn_len() == proof.len()
                            && private.iter_evpn().all(|route| {
                                super::replacement_readiness_checkpoint(&readiness, false);
                                proof.contains(&route.key())
                            })
                    })
            }
        }
    }

    /// This seal is minted only after the existing private full-resync walk
    /// has staged Loc-RIB, actual private rows and every retained proof key.
    pub(in crate::manager) fn private_evpn_feed_seal(&self, peer: IpAddr) -> Option<EvpnFeedSeal> {
        let record = self.evpn_completion_record(peer)?;
        let completion = record.evpn_feed_completion.as_ref()?;
        if completion.target != EvpnFeedTarget::PrivateHandoff
            || completion.revision == 0
            || self.evpn_recovery_handle(peer) != Some(completion.provenance)
            || !self
                .evpn_recovery
                .proof(completion.provenance)
                .is_ok_and(|proof| proof.is_some())
            || record.outbound_tx.is_closed()
            || self.evpn_grouped_member_of(peer).is_some()
            || self.selection_deferred(EVPN_FAMILY)
            || self.evpn_recovery_reset_pending(peer)
        {
            return None;
        }
        Some(EvpnFeedSeal {
            session_id: record.session_id,
            outbound: record.outbound_tx.clone(),
            provenance: completion.provenance,
            target: EvpnFeedTarget::PrivateHandoff,
            revision: completion.revision,
            required_markers: 0,
        })
    }

    /// Called only by a complete producer after its final mixed-family
    /// transaction or proved no-op. Key equality corroborates that admission.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "consuming the seal prevents reusing one complete feed across admissions"
    )]
    pub(in crate::manager) fn complete_evpn_feed_admitted(
        &mut self,
        peer: IpAddr,
        seal: EvpnFeedSeal,
        admitted_markers: u8,
    ) -> bool {
        if !self.evpn_feed_seal_is_current(peer, &seal) {
            return false;
        }
        let matches = self.evpn_projection_matches_proof(peer, &seal);
        #[cfg(test)]
        let matches = matches
            && !std::mem::take(&mut self.adj_rib_out_commit_stats.fail_evpn_feed_completion);
        if !matches {
            self.invalidate_evpn_feed_completion(peer);
            self.evpn_recovery.fail_admission(seal.provenance);
            self.mark_outbound_dirty_inner(peer, false);
            self.retry_evpn_recovery_reset(peer);
            return false;
        }
        let count = self
            .evpn_recovery
            .proof(seal.provenance)
            .ok()
            .flatten()
            .map(EvpnProofView::len);
        if let Some(count) = count {
            self.set_evpn_admitted_count(peer, count);
        }
        if matches!(seal.target, EvpnFeedTarget::Grouped { .. })
            && let Some(private) = self.adj_ribs_out.get_mut(&peer)
        {
            // The complete mixed admission now owns this family's actual
            // state. A refused enqueue never reaches this storage transfer.
            let readiness = &self.replacement_readiness;
            private.release_evpn_with(&mut || {
                super::replacement_readiness_checkpoint(readiness, false);
            });
        }
        let inherited = self
            .evpn_completion_record(peer)
            .and_then(|record| record.evpn_feed_completion.as_ref())
            .map_or(0, |completion| completion.owed_markers);
        let pending_eor = self
            .pending_eor
            .get(&peer)
            .is_some_and(|families| families.contains(&EVPN_FAMILY))
            || self
                .gr_deferred_eor
                .get(&peer)
                .is_some_and(|families| families.contains(&EVPN_FAMILY));
        let completion = EvpnFeedCompletion {
            provenance: seal.provenance,
            target: seal.target,
            revision: seal.revision,
            complete: true,
            owed_markers: (inherited
                | seal.required_markers
                | if pending_eor { EVPN_EOR } else { 0 })
                & !admitted_markers,
        };
        if !self.replace_evpn_feed_completion(peer, Some(completion)) {
            return false;
        }
        self.try_settle_evpn_feed(peer);
        true
    }

    /// Extend an existing full private inventory with proof-owned withdrawals
    /// for which neither current eligible ANN nor an actual private body exists.
    pub(in crate::manager) fn append_private_evpn_proof_withdrawals(
        proof: EvpnProofView<'_>,
        private: &AdjRibOut,
        announce: &mut [EvpnRibRoute],
        withdraw: &mut Vec<EvpnRouteKey>,
        checkpoint: &mut impl FnMut(bool),
    ) {
        announce.sort_unstable_by(|left, right| {
            checkpoint(false);
            left.key().cmp(&right.key())
        });
        for key in proof.iter_with_checkpoint(&mut *checkpoint) {
            if private.get_evpn(&key).is_none()
                && announce
                    .binary_search_by_key(&key, EvpnRibRoute::key)
                    .is_err()
            {
                withdraw.push(key);
            }
        }
    }

    pub(in crate::manager) fn evpn_admitted_marker_bits(
        end_of_rib: &[(rustbgpd_wire::Afi, rustbgpd_wire::Safi)],
        refresh: &[(
            rustbgpd_wire::Afi,
            rustbgpd_wire::Safi,
            rustbgpd_wire::RouteRefreshSubtype,
        )],
    ) -> u8 {
        let mut bits = 0;
        if end_of_rib.contains(&EVPN_FAMILY) {
            bits |= EVPN_EOR;
        }
        if refresh.iter().any(|&(afi, safi, subtype)| {
            (afi, safi) == EVPN_FAMILY && subtype == rustbgpd_wire::RouteRefreshSubtype::EoRR
        }) {
            bits |= EVPN_EORR;
        }
        bits
    }

    pub(in crate::manager) fn evpn_feed_markers_admitted(
        &mut self,
        peer: IpAddr,
        sender: &mpsc::Sender<OutboundRouteUpdate>,
        bits: u8,
    ) {
        if !self.evpn_feed_is_current(peer)
            || !self
                .outbound_peers
                .get(&peer)
                .is_some_and(|tx| tx.same_channel(sender))
        {
            return;
        }
        if let Some(completion) = self
            .evpn_completion_record_mut(peer)
            .and_then(|record| record.evpn_feed_completion.as_mut())
        {
            completion.owed_markers &= !bits;
        }
        if bits & EVPN_EOR != 0
            && let Some(pending) = self.pending_eor.get_mut(&peer)
        {
            pending.remove(&EVPN_FAMILY);
            if pending.is_empty() {
                self.pending_eor.remove(&peer);
            }
        }
        self.try_settle_evpn_feed(peer);
    }

    fn try_settle_evpn_feed(&mut self, peer: IpAddr) -> bool {
        if !self.evpn_feed_is_current(peer) {
            return false;
        }
        let Some(completion) = self
            .evpn_completion_record(peer)
            .and_then(|record| record.evpn_feed_completion.as_ref())
        else {
            return false;
        };
        if completion.owed_markers != 0 {
            return false;
        }
        let handle = completion.provenance;
        if self.evpn_recovery.finish_recovery(handle) != Ok(true) {
            return false;
        }
        self.replace_evpn_feed_completion(peer, None);
        true
    }

    pub(in crate::manager) fn evpn_resync_data_is_covered(
        &mut self,
        peer: IpAddr,
        complete_producer: bool,
    ) -> bool {
        if complete_producer
            && (self.evpn_feed_is_current(peer)
                || self
                    .evpn_recovery_handle(peer)
                    .is_some_and(|handle| self.evpn_recovery.is_dormant(handle)))
        {
            return true;
        }
        // An admitted common envelope cannot complete a missing or rejected
        // EVPN feed. Keep its duty without undoing that envelope's enqueue.
        self.mark_outbound_dirty_inner(peer, false);
        if !self.selection_deferred(EVPN_FAMILY) {
            if let Some(handle) = self.evpn_recovery_handle(peer) {
                self.evpn_recovery.fail_admission(handle);
            }
            self.retry_evpn_recovery_reset(peer);
        }
        false
    }

    fn pending_marker_family_ready(
        &self,
        peer: IpAddr,
        family: (rustbgpd_wire::Afi, rustbgpd_wire::Safi),
    ) -> bool {
        !self.eor_held(peer, family)
            && !self
                .peer_orf_pending
                .get(&peer)
                .is_some_and(|families| families.contains(&family))
            && !self
                .gr_deferred_eor
                .get(&peer)
                .is_some_and(|families| families.contains(&family))
            && (family != EVPN_FAMILY
                || (self.evpn_grouped_member_of(peer).is_none()
                    && !self.has_private_evpn_handoff(peer))
                || self.evpn_feed_is_current(peer))
    }

    pub(in crate::manager) fn evpn_marker_retry_runnable(&self, peer: IpAddr) -> bool {
        #[cfg(test)]
        if let Some(observer) = &self.replacement_readiness_test_hook {
            observer("evpn_marker_candidate");
        }
        !self.dirty_peers.contains(&peer)
            && !self.evpn_recovery_reset_pending(peer)
            && !self.outbound_channel_gone(peer)
            && (self.pending_eor.get(&peer).is_some_and(|families| {
                families
                    .iter()
                    .any(|&family| self.pending_marker_family_ready(peer, family))
            }) || (self.evpn_feed_is_current(peer)
                && self.pending_marker_family_ready(peer, EVPN_FAMILY)
                && self
                    .evpn_completion_record(peer)
                    .and_then(|record| record.evpn_feed_completion.as_ref())
                    .is_some_and(|completion| completion.owed_markers != 0)))
    }

    pub(in crate::manager) fn retry_evpn_feed_markers_bounded(&mut self) {
        if self.evpn_feed_receipt_count == 0 && self.pending_eor.is_empty() {
            return;
        }
        let mut peers = Vec::with_capacity(super::RESYNC_PEERS_PER_TICK);
        let completion_peers = (self.evpn_feed_receipt_count != 0)
            .then_some(&self.live_sessions)
            .into_iter()
            .flat_map(|sessions| sessions.keys().copied());
        for peer in completion_peers.chain(self.pending_eor.keys().copied()) {
            self.replacement_checkpoint(false);
            if peers.contains(&peer) || !self.evpn_marker_retry_runnable(peer) {
                continue;
            }
            let order = |peer: IpAddr| {
                (
                    self.evpn_marker_cursor.is_some_and(|cursor| peer <= cursor),
                    peer,
                )
            };
            let position = peers.partition_point(|&existing| order(existing) < order(peer));
            if position < super::RESYNC_PEERS_PER_TICK {
                if peers.len() == super::RESYNC_PEERS_PER_TICK {
                    peers.pop();
                }
                peers.insert(position, peer);
            }
        }
        for peer in peers {
            self.evpn_marker_cursor = Some(peer);
            let Some(sender) = self.outbound_peers.get(&peer).cloned() else {
                continue;
            };
            let session_id = self.outbound_session_ids.get(&peer).copied();
            let owed = if self.evpn_feed_is_current(peer) {
                self.evpn_completion_record(peer)
                    .and_then(|record| record.evpn_feed_completion.as_ref())
                    .map_or(0, |completion| completion.owed_markers)
            } else {
                0
            };
            let mut end_of_rib = self
                .pending_eor
                .get(&peer)
                .into_iter()
                .flat_map(|families| families.iter().copied())
                .filter(|&family| self.pending_marker_family_ready(peer, family))
                .collect::<Vec<_>>();
            let evpn_ready = self.pending_marker_family_ready(peer, EVPN_FAMILY);
            if owed & EVPN_EOR != 0 && evpn_ready && !end_of_rib.contains(&EVPN_FAMILY) {
                end_of_rib.push(EVPN_FAMILY);
            }
            let refresh_markers = if owed & EVPN_EORR != 0 && evpn_ready {
                vec![(
                    EVPN_FAMILY.0,
                    EVPN_FAMILY.1,
                    rustbgpd_wire::RouteRefreshSubtype::EoRR,
                )]
            } else {
                vec![]
            };
            let bits = Self::evpn_admitted_marker_bits(&end_of_rib, &refresh_markers);
            let update = OutboundRouteUpdate {
                end_of_rib: end_of_rib.clone(),
                refresh_markers,
                ..OutboundRouteUpdate::default()
            };
            if sender.try_send(update).is_ok()
                && self.outbound_session_ids.get(&peer).copied() == session_id
                && self
                    .outbound_peers
                    .get(&peer)
                    .is_some_and(|current| current.same_channel(&sender))
            {
                if let Some(pending) = self.pending_eor.get_mut(&peer) {
                    pending.retain(|family| !end_of_rib.contains(family));
                    if pending.is_empty() {
                        self.pending_eor.remove(&peer);
                    }
                }
                self.evpn_feed_markers_admitted(peer, &sender, bits);
            }
        }
    }

    /// Walk both complete projections while OLD is still alive. Only the
    /// sparse wire payload escapes this function; unchanged route bodies are
    /// borrowed. Dirty recovery uses the charged admitted keys instead of
    /// labelling desired OLD values as actually admitted.
    pub(in crate::manager) fn prepare_complete_evpn_feed(
        &mut self,
        peer: IpAddr,
        destination: usize,
        old_group: Option<usize>,
        old_is_clean: bool,
    ) -> Option<EvpnCompleteFeed> {
        self.prepare_complete_evpn_feed_before_deltas(
            peer,
            destination,
            old_group,
            old_is_clean,
            &[],
        )
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one complete producer keeps old-value eligibility, the sparse diff and its admission fence together"
    )]
    pub(in crate::manager) fn prepare_complete_evpn_feed_before_deltas(
        &mut self,
        peer: IpAddr,
        destination: usize,
        old_group: Option<usize>,
        old_is_clean: bool,
        old_deltas: &[super::update_groups::EvpnGroupDelta],
    ) -> Option<EvpnCompleteFeed> {
        let table_stamp = self
            .group_ribs
            .get(&destination)
            .filter(|group| group.owns_evpn_routes())?
            .evpn_table_stamp;
        if table_stamp == 0 {
            return None;
        }
        let target = EvpnFeedTarget::Grouped {
            group_id: destination,
            table_stamp,
        };
        let revision = self.ensure_evpn_feed_receipt(peer, target)?;
        let group = self.group_ribs.get(&destination)?;
        let provenance = self.evpn_recovery_handle(peer)?;
        let session_id = *self.outbound_session_ids.get(&peer)?;
        let outbound = self.outbound_peers.get(&peer)?.clone();
        if outbound.is_closed()
            || self.evpn_recovery_reset_pending(peer)
            || self.selection_deferred(EVPN_FAMILY)
            || group.evpn_table_stamp == 0
        {
            return None;
        }
        let readiness = self.replacement_readiness.clone();
        let mut checkpoint = || super::replacement_readiness_checkpoint(&readiness, false);
        if !group.evpn_projection_complete_with_checkpoint(&mut checkpoint) {
            return None;
        }
        let filter = self.member_rt_filter(peer);
        let rejected = self.peer_unexportable.get(&peer);
        let prior_group = old_group.and_then(|gid| self.group_ribs.get(&gid));
        if old_is_clean
            && prior_group
                .is_some_and(|old| !old.evpn_projection_complete_with_checkpoint(&mut checkpoint))
        {
            return None;
        }
        let private = self.adj_ribs_out.get(&peer);
        let prior = |key: &EvpnRouteKey| {
            if !old_is_clean {
                return None;
            }
            if let Some(old) = prior_group {
                let (route, input) = old.evpn_value_before_deltas(key, old_deltas)?;
                input
                    .eligible(route, peer, old, self.cluster_id, filter.as_ref(), rejected)
                    .then_some(route)
            } else {
                private?.get_evpn(key)
            }
        };
        let current = |key: &EvpnRouteKey| {
            let route = group.table.get_evpn(key)?;
            // The previous exact rejection does not reject a replacement:
            // every changed/reintroduced candidate receives a fresh probe.
            group
                .evpn_inputs
                .get(key)?
                .eligible(route, peer, group, self.cluster_id, filter.as_ref(), None)
                .then_some(route)
        };
        let mut announce = Vec::new();
        let mut withdraw = Vec::new();
        for route in group.table.iter_evpn() {
            checkpoint();
            let key = route.key();
            if current(&key).is_some()
                && prior(&key).is_none_or(|old| !super::helpers::evpn_routes_equal(old, route))
            {
                announce.push(route.clone());
            }
        }
        if !old_is_clean {
            let proof = self.evpn_recovery.proof(provenance).ok().flatten()?;
            for key in proof.iter_with_checkpoint(|force| {
                super::replacement_readiness_checkpoint(&readiness, force);
            }) {
                if current(&key).is_none() {
                    withdraw.push(key);
                }
            }
        } else if let Some(old) = prior_group {
            for route in old.evpn_member_projection_before_deltas(
                old_deltas,
                peer,
                self.cluster_id,
                filter.as_ref(),
                rejected,
                &checkpoint,
            ) {
                let key = route.key();
                if current(&key).is_none() {
                    withdraw.push(key);
                }
            }
        } else if let Some(private) = private {
            for route in private.iter_evpn() {
                checkpoint();
                let key = route.key();
                if current(&key).is_none() {
                    withdraw.push(key);
                }
            }
        }
        Some(EvpnCompleteFeed {
            seal: EvpnFeedSeal {
                session_id,
                outbound,
                provenance,
                target,
                revision,
                required_markers: 0,
            },
            announce,
            withdraw,
        })
    }
    pub(in crate::manager) fn take_evpn_recovery_reset_receipt(
        &mut self,
        peer: IpAddr,
        session_id: u64,
        outbound: &mpsc::Sender<OutboundRouteUpdate>,
    ) -> (Option<ResetReceipt>, bool) {
        self.live_sessions
            .get_mut(&peer)
            .and_then(|sessions| {
                sessions
                    .iter_mut()
                    .find(|record| record.session_id == session_id)
            })
            .filter(|record| record.outbound_tx.same_channel(outbound))
            .map_or((None, false), |record| {
                (
                    record.evpn_recovery_reset_receipt.take(),
                    record.evpn_recovery_reset_retry_reported,
                )
            })
    }

    pub(in crate::manager) fn evpn_grouped_member_of(&self, peer: IpAddr) -> Option<usize> {
        let gid = self.grouped_member_of(peer)?;
        self.group_ribs.get(&gid)?.owns_evpn_routes().then_some(gid)
    }

    fn evpn_recovery_owner(&self, peer: IpAddr) -> Option<PeerSession> {
        Some(PeerSession {
            peer,
            session_id: *self.outbound_session_ids.get(&peer)?,
        })
    }

    pub(in crate::manager) fn evpn_recovery_handle(
        &self,
        peer: IpAddr,
    ) -> Option<ProvenanceHandle> {
        self.evpn_recovery
            .primary_handle(self.evpn_recovery_owner(peer)?)
    }

    fn evpn_registration_reset(&self, peer: IpAddr) -> Option<PendingReset> {
        let owner = self.evpn_recovery_owner(peer)?;
        let sender = self.outbound_peers.get(&peer)?;
        self.live_sessions
            .get(&peer)?
            .last()
            .filter(|record| {
                record.session_id == owner.session_id && record.outbound_tx.same_channel(sender)
            })?
            .evpn_recovery_reset
    }

    pub(in crate::manager) fn register_evpn_recovery(&mut self, peer: IpAddr, fresh: bool) -> bool {
        let Some(gid) = self.evpn_grouped_member_of(peer) else {
            return true;
        };
        self.register_evpn_recovery_for_group(peer, gid, fresh)
    }

    fn register_evpn_recovery_for_group(&mut self, peer: IpAddr, gid: usize, fresh: bool) -> bool {
        if !self
            .group_ribs
            .get(&gid)
            .is_some_and(super::update_groups::GroupRibOut::owns_evpn_routes)
        {
            return false;
        }
        if self.evpn_registration_reset(peer).is_some() {
            self.retry_evpn_recovery_reset(peer);
            return false;
        }
        let Some(owner) = self.evpn_recovery_owner(peer) else {
            return false;
        };
        if self.evpn_recovery.primary_handle(owner).is_some() {
            return true;
        }
        match self.evpn_recovery.register(owner) {
            Ok(handle) => {
                if !fresh {
                    // An existing session needs G2's filtered prior capture;
                    // a new record's sealed empty proof is for fresh sessions.
                    let _ = self.evpn_recovery.finish_recovery(handle);
                }
                true
            }
            Err(error) => {
                if let Some(record) = self.newest_live_session_mut(peer, owner.session_id) {
                    record.evpn_recovery_reset = Some(PendingReset {
                        error,
                        admitted: false,
                    });
                }
                self.retry_evpn_recovery_reset(peer);
                self.mark_outbound_dirty(peer);
                false
            }
        }
    }

    pub(in crate::manager) fn prepare_evpn_registration_replay(&mut self, peer: IpAddr) {
        let Some(handle) = self.evpn_recovery_handle(peer) else {
            return;
        };
        if self.evpn_recovery.is_dormant(handle) {
            if self.evpn_grouped_member_of(peer).is_some() {
                self.capture_shared_evpn_admitted(peer);
            } else {
                // A settled former owner still has actual private OLD.
                // Same-channel cleanup must capture it before dropping it.
                self.capture_private_evpn_admitted(peer);
            }
        }
    }

    /// Capture actual private admitted rows through an existing owner claim.
    pub(in crate::manager) fn capture_private_evpn_admitted(&mut self, peer: IpAddr) -> bool {
        self.capture_evpn_admitted(peer, true, &[], None)
    }

    /// Claim an explicit owned destination before changing private membership.
    /// Ordinary private registrations still do not allocate recovery state.
    pub(in crate::manager) fn capture_private_evpn_before_join(
        &mut self,
        peer: IpAddr,
        destination: usize,
    ) -> bool {
        self.capture_evpn_admitted(peer, true, &[], Some(destination))
    }

    /// Only a settled clean owner proves the installed table is actual OLD.
    /// Capturing/exhausted or missing owners cannot recurse into this capture.
    pub(in crate::manager) fn capture_clean_evpn_before_dirty(&mut self, peer: IpAddr) {
        if !self.dirty_peers.contains(&peer)
            && self
                .evpn_completion_record(peer)
                .is_some_and(|record| record.evpn_feed_completion.is_none())
            && self.evpn_grouped_member_of(peer).is_some()
            && self
                .evpn_recovery_handle(peer)
                .is_some_and(|handle| self.evpn_recovery.is_dormant(handle))
        {
            self.capture_shared_evpn_admitted(peer);
        }
    }

    pub(in crate::manager) fn capture_shared_evpn_admitted(&mut self, peer: IpAddr) -> bool {
        self.capture_evpn_admitted(peer, false, &[], None)
    }

    pub(in crate::manager) fn capture_shared_evpn_before_deltas(
        &mut self,
        peer: IpAddr,
        old_deltas: &[super::update_groups::EvpnGroupDelta],
    ) -> bool {
        self.capture_evpn_admitted(peer, false, old_deltas, None)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "old projection validation, optional sharing and authoritative flat fallback form one capture transaction"
    )]
    fn capture_evpn_admitted(
        &mut self,
        peer: IpAddr,
        private: bool,
        old_deltas: &[super::update_groups::EvpnGroupDelta],
        destination: Option<usize>,
    ) -> bool {
        let gid = destination.or_else(|| self.evpn_grouped_member_of(peer));
        if let Some(gid) = gid {
            if !self.register_evpn_recovery_for_group(peer, gid, false) {
                return false;
            }
        } else if !private || self.evpn_recovery_handle(peer).is_none() {
            return false;
        }
        let handle = self
            .evpn_recovery_handle(peer)
            .expect("registered EVPN owner");
        match self.evpn_recovery.begin_capture(handle) {
            Ok(false) => {
                if self
                    .evpn_recovery
                    .proof(handle)
                    .is_ok_and(|proof| proof.is_some())
                {
                    return true;
                }
                self.refuse_evpn_capture(peer, handle);
                return false;
            }
            Err(_) => {
                self.retry_evpn_recovery_reset(peer);
                return false;
            }
            Ok(true) => {}
        }
        let readiness = self.replacement_readiness.clone();
        let checkpoint = std::cell::RefCell::new(|| {
            super::replacement_readiness_checkpoint_at(&readiness, "capture_evpn", false);
        });
        let captured = if private {
            let rib = self.adj_ribs_out.get(&peer);
            self.evpn_recovery
                .reserve_capture(handle, rib.map_or(0, AdjRibOut::evpn_len), &mut |force| {
                    super::replacement_readiness_checkpoint(&readiness, force);
                })
                .is_ok_and(|reserved| reserved)
                && capture_admitted_keys(
                    &mut self.evpn_recovery,
                    handle,
                    rib.into_iter()
                        .flat_map(AdjRibOut::iter_evpn)
                        .map(EvpnRibRoute::key),
                    &mut || checkpoint.borrow_mut()(),
                )
        } else {
            let gid = gid.expect("shared capture has an owned group");
            let filter = self.member_rt_filter(peer);
            let group = self
                .group_ribs
                .get_mut(&gid)
                .expect("owned group remains installed");
            // Desired state is usable only before mutation and after a complete transfer.
            if !group.evpn_projection_complete_with_checkpoint(&mut || checkpoint.borrow_mut()())
                || self
                    .adj_ribs_out
                    .get(&peer)
                    .is_some_and(|rib| rib.evpn_len() != 0)
            {
                false
            } else {
                let projected: &super::update_groups::GroupRibOut = group;
                let cluster_id = self.cluster_id;
                let rejected = self.peer_unexportable.get(&peer);
                let actual = || {
                    projected
                        .evpn_member_projection_before_deltas(
                            old_deltas,
                            peer,
                            cluster_id,
                            filter.as_ref(),
                            rejected,
                            || checkpoint.borrow_mut()(),
                        )
                        .map(EvpnRibRoute::key)
                };
                let mut allocation_checkpoint =
                    |force| super::replacement_readiness_checkpoint(&readiness, force);
                let ledger = &mut self.evpn_recovery;
                let captured = (|| {
                    let (count, additions) = ledger.capture_shape(
                        group.evpn_recovery_universe,
                        actual(),
                        &mut allocation_checkpoint,
                    )?;
                    let shared = ledger
                        .share_capture(
                            handle,
                            group.evpn_recovery_universe,
                            group.table.evpn_len(),
                            group.table.iter_evpn().map(EvpnRibRoute::key),
                            (count, additions),
                            &mut allocation_checkpoint,
                        )
                        .ok()
                        .flatten();
                    ledger.reserve_capture(
                        handle,
                        if shared.is_some() { additions } else { count },
                        &mut allocation_checkpoint,
                    )?;
                    let populated = capture_admitted_keys(ledger, handle, actual(), &mut || {
                        checkpoint.borrow_mut()();
                    });
                    Ok::<_, super::update_groups::recovery_provenance::Exhaustion>((
                        populated, shared,
                    ))
                })();
                match captured {
                    Ok((true, shared)) => {
                        if let Some(shared) = shared {
                            group.evpn_recovery_universe = Some(shared);
                        }
                        true
                    }
                    Ok((false, _)) | Err(_) => false,
                }
            }
        };
        if !captured
            || self
                .evpn_recovery
                .seal_capture_with_checkpoint(handle, &mut |force| {
                    super::replacement_readiness_checkpoint(&self.replacement_readiness, force);
                })
                != Ok(true)
        {
            self.refuse_evpn_capture(peer, handle);
            return false;
        }
        true
    }

    /// G2's pre-mutation capture seam. The iterator is already filtered for
    /// source/RR/OLD-RTC eligibility and actual exact-export admission; its
    /// producer must not walk current desired state after a missed send.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "G2 supplies the authoritative EVPN member projection before activation"
        )
    )]
    pub(in crate::manager) fn capture_evpn_recovery_before_projection(
        &mut self,
        peer: IpAddr,
        keys: impl Iterator<Item = EvpnRouteKey>,
    ) -> bool {
        if self.evpn_grouped_member_of(peer).is_none() {
            return false;
        }
        if !self.register_evpn_recovery(peer, false) {
            return false;
        }
        let handle = self
            .evpn_recovery_handle(peer)
            .expect("registered EVPN owner");
        match self.evpn_recovery.begin_capture(handle) {
            Ok(false) => {
                if self
                    .evpn_recovery
                    .proof(handle)
                    .is_ok_and(|proof| proof.is_some())
                {
                    return true;
                }
                self.refuse_evpn_capture(peer, handle);
                return false;
            }
            Err(_) => {
                self.retry_evpn_recovery_reset(peer);
                return false;
            }
            Ok(true) => {}
        }
        for key in keys {
            self.replacement_checkpoint(false);
            if self
                .evpn_recovery
                .capture_key_with_checkpoint(handle, key, &mut |force| {
                    super::replacement_readiness_checkpoint(&self.replacement_readiness, force);
                })
                .is_err()
            {
                self.mark_outbound_dirty(peer);
                self.retry_evpn_recovery_reset(peer);
                return false;
            }
        }
        if self
            .evpn_recovery
            .seal_capture_with_checkpoint(handle, &mut |force| {
                super::replacement_readiness_checkpoint(&self.replacement_readiness, force);
            })
            != Ok(true)
        {
            self.refuse_evpn_capture(peer, handle);
            return false;
        }
        true
    }

    fn refuse_evpn_capture(&mut self, peer: IpAddr, handle: ProvenanceHandle) {
        // Preserve any allocation/capacity refusal already recorded. A lost
        // producer must never remain Capturing with no reset duty.
        self.evpn_recovery.abort_capture(handle);
        self.mark_outbound_dirty(peer);
        self.retry_evpn_recovery_reset(peer);
    }

    pub(in crate::manager) fn evpn_recovery_reset_pending(&self, peer: IpAddr) -> bool {
        self.evpn_registration_reset(peer).is_some()
            || self
                .evpn_recovery_handle(peer)
                .is_some_and(|handle| self.evpn_recovery.exhaustion(handle).is_some())
    }

    /// Queue admission retains one receipt; only actual guarded execution
    /// suppresses retries. Polling never waits on the lifecycle/session actor.
    pub(in crate::manager) fn retry_evpn_recovery_reset(&mut self, peer: IpAddr) {
        let handle = self.evpn_recovery_handle(peer);
        let (Some(owner), Some(outbound)) = (
            self.evpn_recovery_owner(peer),
            self.outbound_peers.get(&peer).cloned(),
        ) else {
            return;
        };
        let mut failed = None;
        let mut executed = false;
        if let Some(record) = self.newest_live_session_mut(peer, owner.session_id)
            && let Some(receipt) = record.evpn_recovery_reset_receipt.as_mut()
        {
            if receipt.handle != handle || !receipt.outbound.same_channel(&outbound) {
                record.evpn_recovery_reset_receipt = None;
            } else {
                match receipt.receiver.try_recv() {
                    Ok(EvpnRecoveryResetOutcome::Executed) => executed = true,
                    Ok(EvpnRecoveryResetOutcome::Rejected) => failed = Some("execution_rejected"),
                    Err(oneshot::error::TryRecvError::Closed) => failed = Some("execution_dropped"),
                    Err(oneshot::error::TryRecvError::Empty) => return,
                }
                record.evpn_recovery_reset_receipt = None;
            }
        }
        if executed {
            if let Some(handle) = handle {
                self.evpn_recovery.mark_reset_admitted(handle);
            } else if let Some(record) = self.newest_live_session_mut(peer, owner.session_id)
                && let Some(pending) = record.evpn_recovery_reset.as_mut()
            {
                pending.admitted = true;
            }
            return;
        }
        let error = if let Some(handle) = handle {
            if self.evpn_recovery.reset_admitted(handle) {
                return;
            }
            self.evpn_recovery.exhaustion(handle)
        } else {
            self.evpn_registration_reset(peer)
                .filter(|pending| !pending.admitted)
                .map(|pending| pending.error)
        };
        let (Some(error), Some(handler)) = (error, self.evpn_recovery_reset.clone()) else {
            return;
        };
        if let Some(failure) = failed {
            self.report_evpn_reset_retry(peer, owner.session_id, error, failure);
        }
        let (peer_limit_bytes, daemon_limit_bytes) = self.evpn_recovery.limits();
        let (reply, receiver) = oneshot::channel();
        if handler(
            EvpnRecoveryReset {
                peer,
                session_id: owner.session_id,
                outbound: outbound.clone(),
                cause: error.cause,
                limiting_peer: error.limiting_peer,
                attempted_peer_bytes: error.attempted_peer_bytes,
                attempted_daemon_bytes: error.attempted_daemon_bytes,
                peer_limit_bytes,
                daemon_limit_bytes,
            },
            reply,
        ) {
            if let Some(record) = self.newest_live_session_mut(peer, owner.session_id) {
                record.evpn_recovery_reset_receipt = Some(ResetReceipt {
                    handle,
                    outbound,
                    receiver,
                });
            }
        } else {
            self.report_evpn_reset_retry(peer, owner.session_id, error, "owner_queue_refused");
        }
    }

    fn report_evpn_reset_retry(
        &mut self,
        peer: IpAddr,
        session_id: u64,
        error: Exhaustion,
        failure: &'static str,
    ) {
        let Some(record) = self.newest_live_session_mut(peer, session_id) else {
            return;
        };
        if record.evpn_recovery_reset_retry_reported {
            return;
        }
        record.evpn_recovery_reset_retry_reported = true;
        tracing::warn!(%peer, session_id, cause = error.cause.as_str(), failure,
            "EVPN recovery reset lacks an execution receipt; retaining bounded retry");
    }

    pub(in crate::manager) fn evpn_advertised_resync_in_progress(&self, peer: IpAddr) -> bool {
        // A retained primary/reset handoff remains authoritative through an
        // exact connection replay or a move to the private projection. A
        // negotiated EVPN family in an ordinary unicast group does not.
        self.evpn_recovery_reset_pending(peer)
            || self
                .evpn_recovery_handle(peer)
                .is_some_and(|handle| !self.evpn_recovery.is_dormant(handle))
            || self.evpn_grouped_member_of(peer).is_some_and(|gid| {
                self.dirty_peers.contains(&peer)
                    || self.group_ribs[&gid].dirty_members.contains(&peer)
            })
    }

    /// Called with an outbound queue permit, before any admission-side
    /// mutation. Sorting uses the existing owned batch, without key scratch.
    pub(in crate::manager) fn reserve_evpn_recovery_admission(
        &mut self,
        peer: IpAddr,
        announce: &mut [EvpnRibRoute],
        withdraw: &mut Vec<EvpnRouteKey>,
    ) -> bool {
        if self.evpn_recovery_reset_pending(peer) {
            self.retry_evpn_recovery_reset(peer);
            return false;
        }
        let Some(handle) = self.evpn_recovery_handle(peer) else {
            return self.evpn_grouped_member_of(peer).is_none();
        };
        if self.evpn_recovery.is_dormant(handle) {
            // Ordinary clean deltas need no recovery key allocation. G2's
            // capture seam must run before a missed projection can advance.
            return self.evpn_grouped_member_of(peer).is_none()
                || !self.dirty_peers.contains(&peer);
        }
        if self
            .evpn_recovery
            .proof(handle)
            .is_ok_and(|proof| proof.is_some_and(EvpnProofView::is_empty))
        {
            self.prepare_empty_evpn_admission(peer, handle, announce);
        }
        let Ok(Some(proof)) = self.evpn_recovery.proof(handle) else {
            self.evpn_recovery.fail_admission(handle);
            self.mark_outbound_dirty_inner(peer, false);
            self.retry_evpn_recovery_reset(peer);
            return false;
        };
        withdraw.retain(|key| proof.contains(key));
        withdraw.sort_unstable();
        withdraw.dedup();
        announce.sort_unstable_by_key(EvpnRibRoute::key);
        if self.evpn_recovery.reserve_admission_with_checkpoint(
            handle,
            announce.iter().map(EvpnRibRoute::key),
            withdraw,
            &mut |force| {
                super::replacement_readiness_checkpoint(&self.replacement_readiness, force);
            },
        ) == Ok(true)
        {
            return true;
        }
        self.evpn_recovery.fail_admission(handle);
        self.mark_outbound_dirty_inner(peer, false);
        self.retry_evpn_recovery_reset(peer);
        false
    }

    fn prepare_empty_evpn_admission(
        &mut self,
        peer: IpAddr,
        handle: ProvenanceHandle,
        candidates: &[EvpnRibRoute],
    ) {
        let Some(gid) = self.evpn_grouped_member_of(peer) else {
            return;
        };
        let group = self.group_ribs.get_mut(&gid).expect("owned group exists");
        let readiness = self.replacement_readiness.clone();
        let mut checkpoint = |force| super::replacement_readiness_checkpoint(&readiness, force);
        let sparse = candidates
            .iter()
            .filter(|route| {
                checkpoint(false);
                let key = route.key();
                !self
                    .evpn_recovery
                    .candidate_universe_contains(
                        handle,
                        group.evpn_recovery_universe,
                        &key,
                        &mut checkpoint,
                    )
                    .unwrap_or_else(|| group.table.get_evpn(&key).is_some())
            })
            .count();
        if let Ok(Some(universe)) = self.evpn_recovery.share_capture(
            handle,
            group.evpn_recovery_universe,
            group.table.evpn_len(),
            group.table.iter_evpn().map(EvpnRibRoute::key),
            (candidates.len(), sparse),
            &mut checkpoint,
        ) {
            group.evpn_recovery_universe = Some(universe);
        }
    }

    pub(in crate::manager) fn admit_evpn_recovery_batch(
        &mut self,
        peer: IpAddr,
        announce: &[EvpnRibRoute],
        withdraw: &[EvpnRouteKey],
    ) -> bool {
        let Some(handle) = self.evpn_recovery_handle(peer) else {
            return true;
        };
        if self.evpn_recovery.is_dormant(handle) {
            return true;
        }
        // Candidate capacity was reserved before any commit-side mutation;
        // final gates only remove announces or add admitted withdrawals.
        let admitted = self.evpn_recovery.apply_admitted_with_checkpoint(
            handle,
            announce.iter().map(EvpnRibRoute::key),
            withdraw,
            &mut |force| {
                super::replacement_readiness_checkpoint(&self.replacement_readiness, force);
            },
        );
        if admitted == Ok(true) {
            return true;
        }
        self.evpn_recovery.fail_admission(handle);
        self.retry_evpn_recovery_reset(peer);
        // The refused envelope admitted no common-family mutation. The
        // generation-fenced reset owns recovery; do not allocate a new common
        // proof merely to mark this failed EVPN precommit dirty.
        self.mark_outbound_dirty_inner(peer, false);
        false
    }

    pub(in crate::manager) fn preflight_final_evpn_recovery(
        &mut self,
        peer: IpAddr,
        announce: &mut [EvpnRibRoute],
        withdraw: &mut Vec<EvpnRouteKey>,
    ) -> bool {
        let Some(handle) = self.evpn_recovery_handle(peer) else {
            return true;
        };
        if self.evpn_recovery.is_dormant(handle) {
            return true;
        }
        announce.sort_unstable_by_key(EvpnRibRoute::key);
        withdraw.sort_unstable();
        withdraw.dedup();
        if self.evpn_recovery.preflight_admitted_with_checkpoint(
            handle,
            announce.iter().map(EvpnRibRoute::key),
            withdraw,
            &mut |force| {
                super::replacement_readiness_checkpoint(&self.replacement_readiness, force);
            },
        ) == Ok(true)
        {
            return true;
        }
        self.retry_evpn_recovery_reset(peer);
        // The refused envelope admitted no common-family mutation. The
        // generation-fenced reset owns recovery; do not allocate a new common
        // proof merely to mark this failed EVPN precommit dirty.
        self.mark_outbound_dirty_inner(peer, false);
        false
    }

    pub(in crate::manager) fn retain_evpn_recovery_withdrawals(
        &self,
        peer: IpAddr,
        withdrawals: &mut Vec<EvpnRouteKey>,
    ) {
        let Some(handle) = self.evpn_recovery_handle(peer) else {
            return;
        };
        if self.evpn_recovery.is_dormant(handle) {
            return;
        }
        let proof = self.evpn_recovery.proof(handle).ok().flatten();
        withdrawals.retain(|key| proof.is_some_and(|keys| keys.contains(key)));
        withdrawals.sort_unstable();
        withdrawals.dedup();
    }

    pub(in crate::manager) fn finish_evpn_recovery(&mut self, peer: IpAddr) -> bool {
        if self.evpn_recovery_reset_pending(peer) {
            self.mark_outbound_dirty(peer);
            self.retry_evpn_recovery_reset(peer);
            return false;
        }
        let Some(handle) = self.evpn_recovery_handle(peer) else {
            return true;
        };
        if self.evpn_recovery.is_dormant(handle) {
            return true;
        }
        // The legacy resync has no shared EVPN projection or completeness
        // barrier. G2 must settle explicitly after its complete admitted heal.
        if self.evpn_grouped_member_of(peer).is_some() {
            if self.evpn_feed_is_current(peer) {
                // Route duties have completed, even while an ordered marker
                // retains the EVPN proof. Do not turn that debt into data dirty.
                self.try_settle_evpn_feed(peer);
                return true;
            }
            self.mark_outbound_dirty(peer);
            return false;
        }
        if self.has_private_evpn_handoff(peer) {
            if self.evpn_feed_is_current(peer) {
                self.try_settle_evpn_feed(peer);
                return true;
            }
            self.mark_outbound_dirty_inner(peer, false);
            return false;
        }
        let actual = self.adj_ribs_out.get(&peer);
        let matches = self.evpn_recovery.proof(handle).is_ok_and(|proof| {
            proof.is_some_and(|keys| {
                actual.map_or(0, AdjRibOut::evpn_len) == keys.len()
                    && actual
                        .is_none_or(|rib| rib.iter_evpn().all(|route| keys.contains(&route.key())))
            })
        });
        if !matches {
            self.mark_outbound_dirty(peer);
            return false;
        }
        if self.evpn_recovery.finish_recovery(handle) != Ok(true) {
            self.mark_outbound_dirty(peer);
            return false;
        }
        true
    }

    /// Proof primitive for tests. Live settlement requires the complete-feed
    /// receipt and actual ordered marker admission in `try_settle_evpn_feed`.
    #[cfg(test)]
    pub(in crate::manager) fn settle_evpn_recovery(
        &mut self,
        peer: IpAddr,
        current: impl Iterator<Item = EvpnRouteKey>,
    ) -> bool {
        let Some(handle) = self.evpn_recovery_handle(peer) else {
            return false;
        };
        let matches = self.evpn_recovery.proof(handle).is_ok_and(|proof| {
            proof.is_some_and(|keys| {
                keys.iter_with_checkpoint(|force| {
                    super::replacement_readiness_checkpoint(&self.replacement_readiness, force);
                })
                .eq(current)
            })
        });
        matches && self.evpn_recovery.finish_recovery(handle) == Ok(true)
    }

    pub(in crate::manager) fn retire_evpn_recovery(&mut self, peer: IpAddr) {
        if let Some(handle) = self.evpn_recovery_handle(peer) {
            self.evpn_recovery.retire_member(handle);
        }
        if let Some(owner) = self.evpn_recovery_owner(peer)
            && let Some(outbound) = self.outbound_peers.get(&peer)
            && let Some(record) = self.live_sessions.get_mut(&peer).and_then(|sessions| {
                sessions.iter_mut().find(|record| {
                    record.session_id == owner.session_id
                        && record.outbound_tx.same_channel(outbound)
                })
            })
        {
            record.evpn_recovery_reset = None;
            record.evpn_recovery_reset_receipt = None;
            record.evpn_recovery_reset_retry_reported = false;
            self.evpn_feed_receipt_count -=
                usize::from(record.evpn_feed_completion.take().is_some());
        }
    }
}

fn capture_admitted_keys(
    ledger: &mut super::update_groups::recovery_provenance::EvpnRecoveryProvenance,
    handle: ProvenanceHandle,
    keys: impl Iterator<Item = EvpnRouteKey>,
    checkpoint: &mut impl FnMut(),
) -> bool {
    for key in keys {
        checkpoint();
        if ledger
            .capture_key_with_checkpoint(handle, key, &mut |_| checkpoint())
            .is_err()
        {
            return false;
        }
    }
    true
}
