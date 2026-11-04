//! Admission of RIB-to-session envelopes against per-peer row credit and the
//! one-live-operation latch (`crate::outbound_credit`).

use std::sync::{Arc, Weak};

use rustbgpd_telemetry::reason_labels::OutboundCommitRefusal;

use super::RibManager;
use super::distribution::OutboundCommitFailure;
use crate::PeerId;
use crate::outbound_credit::{
    OperationLatch, OutboundCredit, OutboundOperation, PrivateFamilies, row_credit_for,
};

/// One peer's outbound credit and its live whole-table operation, kept
/// across session generations.
#[derive(Default)]
pub(super) struct PeerCredit {
    credit: Arc<OutboundCredit>,
    latch: Weak<OperationLatch>,
}

impl PeerCredit {
    fn busy(&self) -> bool {
        self.credit.rows() != 0 || self.latch.strong_count() != 0
    }
}

/// The refusal for a peer without credit or with a live operation.
pub(super) const CREDIT_REFUSAL: OutboundCommitFailure =
    OutboundCommitFailure::Refused(OutboundCommitRefusal::OutboundCredit);

impl RibManager {
    /// Fix every peer's ordinary row credit at `rows` instead of sizing it
    /// from the number of registered peers. For tests and bench builds.
    #[cfg(any(test, feature = "bench-internals"))]
    #[must_use]
    pub fn with_outbound_row_credit(mut self, rows: usize) -> Self {
        self.outbound_row_credit_override = Some(rows);
        self
    }

    /// Ensure `peer` has a credit entry.
    pub(super) fn register_outbound_credit(&mut self, peer: PeerId) {
        self.outbound_credit.entry(peer).or_default();
    }

    /// The per-peer row credit at the current number of registered outbound
    /// peers, read at each admission. Every registered peer counts, private
    /// family or not (a grouped peer's OTC diagnostics are charged too), so
    /// the count needs no membership tracking and the credits of the live
    /// peers sum to at most `DAEMON_ROW_CREDIT` (or `P` times the floor).
    /// Envelopes admitted while fewer peers were registered stay charged
    /// until they drop; such a peer is refused until it is back under the
    /// current credit, so that excess only drains.
    pub(super) fn outbound_row_credit(&self) -> usize {
        self.outbound_row_credit_override
            .unwrap_or_else(|| row_credit_for(self.outbound_peers.len()))
    }

    /// Which of `peer`'s families it holds in its own Adj-RIB-Out.
    pub(super) fn private_families(&self, peer: PeerId) -> PrivateFamilies {
        PrivateFamilies {
            unicast: self.grouped_member_of(peer).is_none(),
            vpn: self.vpn_grouped_member_of(peer).is_none(),
            evpn: self.evpn_grouped_member_of(peer).is_none(),
        }
    }

    /// Preflight for a private-family producer, before it stages anything:
    /// whether `peer` already holds its whole credit, so an envelope built
    /// now would be refused. False while closing, when a withdrawal may
    /// still be admitted against capacity alone.
    pub(super) fn outbound_credit_exhausted(&self, peer: PeerId) -> bool {
        !self.outbound_closing
            && self
                .outbound_credit
                .get(&peer)
                .is_some_and(|entry| entry.credit.rows() >= self.outbound_row_credit())
    }

    /// Count a preflight refusal like a refused send.
    pub(super) fn refuse_outbound_for_credit(&self, peer: PeerId) {
        let _ = self.outbound_commit_failed(peer, CREDIT_REFUSAL);
    }

    /// Preflight for a per-peer private-family producer: when `peer`'s
    /// credit is exhausted, count the refusal, mark the peer dirty as a
    /// refused send would, and return true so the caller stages nothing.
    ///
    /// Not for a clean peer whose whole-table operation is live: it covers
    /// the peer's table, so the producer stages and the send is refused only
    /// for rows it actually holds, and an empty diff costs no second resync.
    /// A dirty peer owes a resync anyway, so it stages nothing.
    pub(super) fn outbound_preflight_refused(&mut self, peer: PeerId) -> bool {
        if !self.outbound_credit_exhausted(peer)
            || (self.outbound_operation_live(peer) && !self.dirty_peers.contains(&peer))
        {
            return false;
        }
        self.refuse_outbound_for_credit(peer);
        self.mark_dirty_after_family_send_failure(peer, CREDIT_REFUSAL);
        true
    }

    /// Record entry into a private-family staging producer for `peer`
    /// (test hook; a no-op outside tests).
    #[cfg(test)]
    pub(super) fn note_outbound_staging(&mut self, peer: PeerId) {
        *self.outbound_stagings.entry(peer).or_default() += 1;
    }

    #[cfg(not(test))]
    #[expect(clippy::unused_self, reason = "the staging hook records only in tests")]
    pub(super) fn note_outbound_staging(&mut self, _peer: PeerId) {}

    /// Staging-producer entries recorded for `peer`.
    #[cfg(test)]
    pub(super) fn outbound_stagings(&self, peer: PeerId) -> usize {
        self.outbound_stagings.get(&peer).copied().unwrap_or(0)
    }

    /// Admit an ordinary envelope with private rows: while the peer's live
    /// rows are below its credit, or, during shutdown, when the envelope's
    /// private rows withdraw, or announce only keys they also withdraw
    /// (`closing_admissible`). Returns the credit to charge; a peer that
    /// never registered is not tracked.
    pub(super) fn admit_ordinary_credit(
        &self,
        peer: PeerId,
        closing_admissible: impl FnOnce() -> bool,
    ) -> Result<Option<Arc<OutboundCredit>>, OutboundCommitFailure> {
        let Some(entry) = self.outbound_credit.get(&peer) else {
            return Ok(None);
        };
        if entry.credit.rows() < self.outbound_row_credit()
            || (self.outbound_closing && closing_admissible())
        {
            Ok(Some(Arc::clone(&entry.credit)))
        } else {
            Err(CREDIT_REFUSAL)
        }
    }

    /// Admit a whole-table operation of up to `envelopes` envelopes, nested
    /// markers included: refused while another operation of `peer` is live,
    /// or when the channel has no room at all. With less room than
    /// `envelopes`, it reserves what there is ([`OutboundOperation::reserve`]);
    /// a caller that must be accepted whole checks
    /// [`OutboundOperation::reserved`]. Nothing is sent.
    pub(super) fn begin_outbound_operation(
        &mut self,
        peer: PeerId,
        envelopes: usize,
    ) -> Result<OutboundOperation, OutboundCommitFailure> {
        let Some(sender) = self.outbound_peers.get(&peer) else {
            return Err(OutboundCommitFailure::WriterUnavailable);
        };
        let entry = self.outbound_credit.entry(peer).or_default();
        if entry.latch.strong_count() != 0 {
            return Err(CREDIT_REFUSAL);
        }
        let operation =
            OutboundOperation::reserve(sender, envelopes, &self.outbound_latch_released)
                .ok_or(OutboundCommitFailure::WriterUnavailable)?;
        entry.latch = Arc::downgrade(operation.latch());
        Ok(operation)
    }

    /// Preflight before building a complete EVPN feed outside an admitted
    /// operation: while the peer's previous whole-table operation is live a
    /// second feed would be refused, so build none and leave the peer dirty;
    /// its resync builds the feed once the operation drains.
    pub(super) fn complete_feed_deferred(&mut self, peer: PeerId) -> bool {
        if !self.outbound_operation_live(peer) {
            return false;
        }
        self.refuse_outbound_for_credit(peer);
        self.mark_outbound_dirty_inner(peer, false);
        true
    }

    /// Whether a whole-table operation of `peer` is still live.
    pub(super) fn outbound_operation_live(&self, peer: PeerId) -> bool {
        self.outbound_credit
            .get(&peer)
            .is_some_and(|entry| entry.latch.strong_count() != 0)
    }

    /// Daemon shutdown began: from here on an ordinary envelope that only
    /// withdraws needs channel capacity alone, so the withdrawals staged by
    /// the shutdown drains reach the sessions before their Cease.
    pub(super) fn begin_outbound_close(&mut self) {
        self.outbound_closing = true;
    }

    /// Forget idle credit of peers no longer registered (a deleted
    /// neighbor). A peer whose envelopes are still live keeps its entry, so
    /// a re-added neighbor counts them; a later deletion sweeps it.
    pub(super) fn forget_idle_outbound_credit(&mut self) {
        let registered = &self.outbound_peers;
        self.outbound_credit
            .retain(|peer, entry| registered.contains_key(peer) || entry.busy());
    }

    /// Live private rows held by `peer`'s envelopes.
    #[cfg(test)]
    pub(super) fn outbound_credit_rows(&self, peer: PeerId) -> usize {
        self.outbound_credit
            .get(&peer)
            .map_or(0, |entry| entry.credit.rows())
    }

    /// `peer`'s credit, to charge it directly.
    #[cfg(test)]
    pub(super) fn outbound_credit_handle(&mut self, peer: PeerId) -> Arc<OutboundCredit> {
        Arc::clone(&self.outbound_credit.entry(peer).or_default().credit)
    }
}
