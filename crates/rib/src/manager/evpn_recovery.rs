//! Dormant G1 recovery boundaries; EVPN group staging is a later slice.
//!
//! G2 must supply the authoritative admissible member-key iterator before
//! moving a clean projection, including its OLD pre-policy RTC input. Neither
//! negotiated EVPN nor the current Loc-RIB/post-policy RTs prove ownership or
//! reconstruct that prior. This module deliberately has no projection builder.

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

impl RibManager {
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
        if self.evpn_grouped_member_of(peer).is_none() {
            return true;
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
        if self.evpn_grouped_member_of(peer).is_none() {
            return;
        }
        let Some(handle) = self.evpn_recovery_handle(peer) else {
            return;
        };
        if self.evpn_recovery.is_dormant(handle) {
            self.capture_shared_evpn_admitted(peer);
        }
    }

    /// Future private-to-shared commit supplies a real ownership claim first;
    /// this reads the actual private admitted map, never a desired group view.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "live EVPN ownership transfer is deferred until complete G2 admission and view integration"
        )
    )]
    pub(in crate::manager) fn capture_private_evpn_admitted(&mut self, peer: IpAddr) -> bool {
        self.capture_evpn_admitted(peer, true)
    }

    pub(in crate::manager) fn capture_shared_evpn_admitted(&mut self, peer: IpAddr) -> bool {
        self.capture_evpn_admitted(peer, false)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "old projection validation, optional sharing and authoritative flat fallback form one capture transaction"
    )]
    fn capture_evpn_admitted(&mut self, peer: IpAddr, private: bool) -> bool {
        let Some(gid) = self.evpn_grouped_member_of(peer) else {
            return false;
        };
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
                        .evpn_member_projection_with_checkpoint(
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
            return !self.dirty_peers.contains(&peer);
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
            self.mark_outbound_dirty(peer);
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

    /// G2 calls this only after its entire recovery batch was admitted, with
    /// the current authoritative admissible member keys in identity order.
    /// Key equality supplements that delivery barrier; it cannot replace it.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "G2 owns the complete EVPN recovery delivery barrier"
        )
    )]
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
