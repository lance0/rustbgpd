//! End-of-RIB obligations: one per (peer, family) whose marker the current
//! session still owes, and the reasons the marker may not leave yet.
//!
//! RFC 4724 §4.1 has the End-of-RIB marker follow the initial update of its
//! family. Several conditions can withhold it or order it behind data still
//! owed to the peer. Each is an [`EorHold`]; `eor_hold_applies` is the one
//! place that decides whether a reason applies, and the functions in this
//! module are the only ones that send a pending marker. A marker
//! leaves from the call that finds its hold set empty: a release of a hold
//! ([`RibManager::release_eor_hold`], [`RibManager::release_eor_orf_table`])
//! or the admission of the table it follows ([`RibManager::settle_eor`]).
//!
//! The obligation stores the reasons nothing else owns: the ORF table hold,
//! the RT-Constrain membership hold and a refused send. The other reasons
//! are read from their owners (the selection gate, the grace window, the
//! EVPN feed, the resync flags and the owed keys) each time, so no copy of
//! them can go stale. Their owners call `release_eor_hold` when they clear;
//! a test build checks after every actor turn that no marker was left ready
//! but unsent (`assert_eor_settled`).

use std::collections::{HashMap, HashSet};
use std::fmt;

use rustbgpd_wire::{Afi, Safi};
use tracing::{debug, warn};

use super::RibManager;
use super::graceful_restart::DeadlineMap;
use crate::PeerId;
use crate::outbound_credit::{OutboundOperation, send_marker};
use crate::update::OutboundRouteUpdate;

const EVPN: (Afi, Safi) = (Afi::L2Vpn, Safi::Evpn);

/// One reason an owed End-of-RIB marker may not be sent yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EorHold {
    /// The family's RFC 4724 convergence gate is armed.
    Selection,
    /// RFC 4684 §6: the peer's RT-Constrain End-of-RIB is outstanding, so
    /// its VPN and EVPN markers wait for the membership it completes.
    RtMembership,
    /// The planned-restart grace window covers the family toward a helper.
    Grace,
    /// RFC 5291 §6: the marker follows the table the peer's first
    /// ROUTE-REFRESH unlocks.
    OrfTable,
    /// The peer's complete EVPN feed is not current.
    EvpnFeed,
    /// A dirty or forced resync of the peer's table has not been admitted.
    Resync,
    /// The family owes keys that must be absorbed ahead of the marker.
    OwedKeys,
    /// The writer refused the marker; the next offer is a resync or a tick.
    Writer,
}

impl EorHold {
    pub(super) const ALL: [Self; 8] = [
        Self::Selection,
        Self::RtMembership,
        Self::Grace,
        Self::OrfTable,
        Self::EvpnFeed,
        Self::Resync,
        Self::OwedKeys,
        Self::Writer,
    ];

    const fn bit(self) -> u8 {
        1 << self as u8
    }
}

/// A set of [`EorHold`] reasons.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct HoldSet(u8);

impl HoldSet {
    pub(super) const EMPTY: Self = Self(0);
    const ALL: Self = Self(u8::MAX);
    /// The holds that withhold a marker until something outside this
    /// peer's own outbound data happens. A helper's stale carry and the
    /// initial dump ask for these only.
    pub(super) const WITHHELD: Self =
        Self(EorHold::Selection.bit() | EorHold::RtMembership.bit() | EorHold::Grace.bit());
    /// The reasons an admitted resync envelope satisfies for the markers it
    /// carries: it is the resync, it covers the owed keys, it has a writer
    /// slot, and its own seal settles the EVPN feed.
    const RESYNC_SATISFIES: Self = Self(
        EorHold::Resync.bit()
            | EorHold::OwedKeys.bit()
            | EorHold::Writer.bit()
            | EorHold::EvpnFeed.bit(),
    );

    pub(super) const fn contains(self, hold: EorHold) -> bool {
        self.0 & hold.bit() != 0
    }

    #[cfg(test)]
    pub(super) const fn is_empty(self) -> bool {
        self.0 == 0
    }

    const fn with(self, hold: EorHold) -> Self {
        Self(self.0 | hold.bit())
    }

    const fn without(self, hold: EorHold) -> Self {
        Self(self.0 & !hold.bit())
    }

    const fn minus(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

impl fmt::Debug for HoldSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set()
            .entries(EorHold::ALL.iter().filter(|hold| self.contains(**hold)))
            .finish()
    }
}

/// What prompted an attempt to send a peer's owed markers.
pub(super) enum EorTrigger<'a> {
    /// A hold reason was released; no table of the peer was admitted in
    /// this call, so a pending resync still comes first.
    Release,
    /// A whole-table envelope of the peer (a resync or a refresh answer)
    /// was admitted in `operation`: the markers follow it on its slots.
    Table(&'a mut OutboundOperation),
    /// The initial table was admitted. `evpn_covered` is false when it did
    /// not establish the EVPN coverage the peer needs.
    InitialTable {
        operation: Option<&'a mut OutboundOperation>,
        evpn_covered: bool,
    },
}

impl<'a> EorTrigger<'a> {
    /// [`Self::Table`] inside `operation`, or [`Self::Release`] without one.
    pub(super) fn behind(operation: Option<&'a mut OutboundOperation>) -> Self {
        operation.map_or(Self::Release, Self::Table)
    }
}

/// How the trigger changes which reasons count.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Offer {
    Release,
    Table,
    InitialTable {
        evpn_covered: bool,
    },
    /// A polling lane: the resync tick or the owed-key drain.
    Retry,
}

/// One session's owed markers with the reasons stored for each.
type OwedMarkers = Vec<((Afi, Safi), HoldSet)>;

/// The markers each registered session still owes.
#[derive(Debug, Default)]
pub(super) struct EorObligations {
    /// Owed markers in the order they were first owed, with the reasons
    /// stored here: only [`EorHold::OrfTable`] and [`EorHold::Writer`].
    /// A session owes a handful of families, so a list keeps the order an
    /// initial dump sends them in. Entries are never left empty.
    owed: HashMap<PeerId, OwedMarkers>,
    /// Peers under the [`EorHold::RtMembership`] hold, with its cap. Armed
    /// at `PeerUp` when the session starts with an empty membership; a peer
    /// with the Restart State bit set is never held.
    rt_membership: DeadlineMap<PeerId>,
    /// Held peers whose RT-Constrain End-of-RIB arrived while RT-Constrain
    /// selection was deferred: membership is rebuilt when that deferral is
    /// staged or released, and the hold ends there.
    rt_membership_complete: HashSet<PeerId>,
    /// Markers the tick's fallback sent ([`RibManager::eor_unsettled_ready`]).
    #[cfg(test)]
    pub(super) unsettled_tick_sends: usize,
}

impl EorObligations {
    /// Whether any marker is owed to anyone.
    pub(super) fn is_empty(&self) -> bool {
        self.owed.is_empty()
    }

    /// Peers that are owed a marker.
    pub(super) fn peers(&self) -> impl Iterator<Item = PeerId> + '_ {
        self.owed.keys().copied()
    }

    /// Whether `peer` is owed any marker.
    pub(super) fn owes_peer(&self, peer: PeerId) -> bool {
        self.owed.contains_key(&peer)
    }

    /// Whether `peer` is owed `family`'s marker.
    pub(super) fn owes(&self, peer: PeerId, family: (Afi, Safi)) -> bool {
        self.owed
            .get(&peer)
            .is_some_and(|owed| owed.iter().any(|(owed, _)| *owed == family))
    }

    /// The families whose marker `peer` is owed.
    pub(super) fn families(&self, peer: PeerId) -> impl Iterator<Item = (Afi, Safi)> + '_ {
        self.owed
            .get(&peer)
            .into_iter()
            .flat_map(|owed| owed.iter().map(|(family, _)| *family))
    }

    /// Whether `family`'s marker toward `peer` waits for the table its
    /// first ROUTE-REFRESH unlocks.
    pub(super) fn behind_orf_table(&self, peer: PeerId, family: (Afi, Safi)) -> bool {
        self.stored(peer, family).contains(EorHold::OrfTable)
    }

    /// Whether `peer` is under the RT-Constrain membership hold.
    pub(super) fn rt_membership_held(&self, peer: PeerId) -> bool {
        self.rt_membership.contains_key(&peer)
    }

    /// The nearest RT-Constrain membership cap.
    pub(super) fn next_rt_membership_cap(&mut self) -> Option<tokio::time::Instant> {
        self.rt_membership.min()
    }

    /// Held peers whose RT-Constrain membership cap is at or before `due`.
    pub(super) fn rt_membership_caps_due(&self, due: tokio::time::Instant) -> Vec<PeerId> {
        self.rt_membership
            .iter()
            .filter(|&(_, &deadline)| deadline <= due)
            .map(|(&peer, _)| peer)
            .collect()
    }

    fn stored(&self, peer: PeerId, family: (Afi, Safi)) -> HoldSet {
        self.owed
            .get(&peer)
            .and_then(|owed| owed.iter().find(|(owed, _)| *owed == family))
            .map_or(HoldSet::EMPTY, |(_, stored)| *stored)
    }

    fn stored_mut(&mut self, peer: PeerId, family: (Afi, Safi)) -> Option<&mut HoldSet> {
        self.owed
            .get_mut(&peer)?
            .iter_mut()
            .find(|(owed, _)| *owed == family)
            .map(|(_, stored)| stored)
    }

    fn owe(&mut self, peer: PeerId, family: (Afi, Safi)) {
        let owed = self.owed.entry(peer).or_default();
        if !owed.iter().any(|(owed, _)| *owed == family) {
            owed.push((family, HoldSet::EMPTY));
        }
    }

    fn store(&mut self, peer: PeerId, family: (Afi, Safi), hold: EorHold) {
        if let Some(stored) = self.stored_mut(peer, family) {
            *stored = stored.with(hold);
        }
    }

    fn unstore(&mut self, peer: PeerId, family: (Afi, Safi), hold: EorHold) {
        if let Some(stored) = self.stored_mut(peer, family) {
            *stored = stored.without(hold);
        }
    }

    fn discharge(&mut self, peer: PeerId, family: (Afi, Safi)) {
        if let Some(owed) = self.owed.get_mut(&peer) {
            owed.retain(|(owed, _)| *owed != family);
            if owed.is_empty() {
                self.owed.remove(&peer);
            }
        }
    }
}

impl RibManager {
    /// Whether `hold` applies to `family`'s End-of-RIB toward `peer` now.
    /// Every reason is decided here and nowhere else.
    fn eor_hold_applies(&self, peer: PeerId, family: (Afi, Safi), hold: EorHold) -> bool {
        match hold {
            EorHold::Selection => self.selection_convergence_held(family),
            EorHold::RtMembership => {
                self.eor.rt_membership_held(peer) && Self::rtc_gated_family(family)
            }
            EorHold::Grace => self.eor_grace_held(peer, family),
            EorHold::OrfTable | EorHold::Writer => self.eor.stored(peer, family).contains(hold),
            EorHold::EvpnFeed => {
                family == EVPN
                    && (self.evpn_grouped_member_of(peer).is_some()
                        || self.has_private_evpn_handoff(peer))
                    && !self.evpn_feed_is_current(peer)
            }
            EorHold::Resync => {
                self.dirty_peers.contains(&peer) || self.force_outbound_peers.contains(&peer)
            }
            EorHold::OwedKeys => self.owes(peer, family),
        }
    }

    /// The reasons `family`'s End-of-RIB toward `peer` may not be sent now.
    /// Production asks only whether any reason of a set applies
    /// ([`Self::eor_held_by`]); the whole set serves the end-of-turn check.
    #[cfg(test)]
    pub(super) fn eor_holds(&self, peer: PeerId, family: (Afi, Safi)) -> HoldSet {
        EorHold::ALL
            .into_iter()
            .filter(|&hold| self.eor_hold_applies(peer, family, hold))
            .fold(HoldSet::EMPTY, HoldSet::with)
    }

    /// Whether any reason in `among` applies; stops at the first that does.
    fn eor_held_by(&self, peer: PeerId, family: (Afi, Safi), among: HoldSet) -> bool {
        EorHold::ALL
            .into_iter()
            .any(|hold| among.contains(hold) && self.eor_hold_applies(peer, family, hold))
    }

    /// Whether a hold that withholds the marker ([`HoldSet::WITHHELD`])
    /// applies to `family` toward `peer`.
    pub(super) fn eor_withheld(&self, peer: PeerId, family: (Afi, Safi)) -> bool {
        self.eor_held_by(peer, family, HoldSet::WITHHELD)
    }

    /// Whether no reason keeps `family`'s marker from this `offer`, not
    /// counting the reasons in `beyond`. Offering the marker again is what
    /// ends a refusal, so [`EorHold::Writer`] never counts.
    fn eor_free_for(
        &self,
        peer: PeerId,
        family: (Afi, Safi),
        offer: Offer,
        beyond: HoldSet,
    ) -> bool {
        let mut counted = HoldSet::ALL.without(EorHold::Writer).minus(beyond);
        match offer {
            Offer::Release => {}
            // The admitted table is the resync the marker waited for.
            Offer::Table => counted = counted.without(EorHold::Resync),
            // An initial table that left the peer's EVPN coverage open
            // keeps the EVPN marker, whatever the feed's state says.
            Offer::InitialTable { evpn_covered } => {
                if !evpn_covered && family == EVPN {
                    return false;
                }
                counted = counted.without(EorHold::Resync);
            }
            // The polling lanes also wait for an RFC 5291 §6 gate that is
            // still up, where a release sends the marker of a family whose
            // table the peer never asked for.
            Offer::Retry => {
                if self
                    .peer_orf_pending
                    .get(&peer)
                    .is_some_and(|gated| gated.contains(&family))
                {
                    return false;
                }
            }
        }
        !self.eor_held_by(peer, family, counted)
    }

    /// Record that the current session of `peer` owes `family`'s marker.
    pub(super) fn owe_eor(&mut self, peer: PeerId, family: (Afi, Safi)) {
        self.eor.owe(peer, family);
    }

    /// Owe `family`'s marker behind the table the peer's first
    /// ROUTE-REFRESH unlocks.
    pub(super) fn owe_eor_behind_orf_table(&mut self, peer: PeerId, family: (Afi, Safi)) {
        self.owe_eor(peer, family);
        self.eor.store(peer, family, EorHold::OrfTable);
    }

    /// Arm the RT-Constrain membership hold of a new session until `cap`.
    pub(super) fn hold_eor_for_rt_membership(&mut self, peer: PeerId, cap: tokio::time::Instant) {
        self.eor.rt_membership_complete.remove(&peer);
        self.eor.rt_membership.insert(peer, cap);
    }

    /// `peer`'s RT membership is complete on the wire, but RT-Constrain
    /// selection is still deferred: the hold ends when that deferral is
    /// staged or released ([`Self::release_completed_rt_membership_holds`]).
    pub(super) fn rt_membership_completed_while_deferred(&mut self, peer: PeerId) {
        if self.eor.rt_membership_held(peer) {
            self.eor.rt_membership_complete.insert(peer);
        }
    }

    /// RT-Constrain selection was just staged or released and every
    /// membership rebuilt: end the holds whose End-of-RIB already arrived.
    pub(super) fn release_completed_rt_membership_holds(&mut self) {
        let complete: Vec<PeerId> = self.eor.rt_membership_complete.drain().collect();
        for peer in complete {
            self.release_eor_hold(peer, EorHold::RtMembership, EorTrigger::Release);
        }
    }

    /// The session of `peer` ended: its markers and holds go with it.
    pub(super) fn forget_eor(&mut self, peer: PeerId) {
        self.eor.owed.remove(&peer);
        self.eor.rt_membership.remove(&peer);
        self.eor.rt_membership_complete.remove(&peer);
    }

    /// `hold` no longer applies to `peer`: send every marker of the peer
    /// that nothing holds any more. The RT-Constrain membership hold is
    /// stored here and is dropped first; the holds read from their owners
    /// were cleared by the caller.
    pub(super) fn release_eor_hold(
        &mut self,
        peer: PeerId,
        hold: EorHold,
        trigger: EorTrigger<'_>,
    ) {
        match hold {
            EorHold::RtMembership => {
                self.eor.rt_membership_complete.remove(&peer);
                if self.eor.rt_membership.remove(&peer).is_none() {
                    return;
                }
            }
            EorHold::OrfTable | EorHold::Writer => {
                debug_assert!(
                    false,
                    "{hold:?} is released per family or by the next offer"
                );
            }
            EorHold::Selection
            | EorHold::Grace
            | EorHold::EvpnFeed
            | EorHold::Resync
            | EorHold::OwedKeys => {}
        }
        self.settle_eor(peer, trigger);
    }

    /// A dirty resync of `peer` was admitted (in `operation`, when it ran
    /// as one): the markers it was holding follow it.
    pub(super) fn resync_settles_eor(
        &mut self,
        peer: PeerId,
        operation: Option<&mut OutboundOperation>,
    ) {
        self.release_eor_hold(peer, EorHold::Resync, EorTrigger::behind(operation));
    }

    /// The ORF table hold of `families` toward `peer` ended (the gated
    /// table was admitted, or the cap passed): send what nothing else holds.
    pub(super) fn release_eor_orf_table(
        &mut self,
        peer: PeerId,
        families: impl IntoIterator<Item = (Afi, Safi)>,
        trigger: EorTrigger<'_>,
    ) {
        for family in families {
            self.eor.unstore(peer, family, EorHold::OrfTable);
        }
        self.settle_eor(peer, trigger);
    }

    /// `families`' markers toward `peer` were admitted inside an envelope
    /// built from [`Self::eor_resync_ready`], or the EVPN feed saw its
    /// End-of-RIB admitted.
    pub(super) fn eor_discharged(&mut self, peer: PeerId, families: &[(Afi, Safi)]) {
        for &family in families {
            self.eor.discharge(peer, family);
        }
    }

    /// The owed markers a dirty resync envelope of `peer` may carry behind
    /// its routes: those only the resync itself was holding.
    pub(super) fn eor_resync_ready(&self, peer: PeerId) -> Vec<(Afi, Safi)> {
        self.eor
            .families(peer)
            .inspect(|_| self.replacement_checkpoint(false))
            .filter(|&family| {
                !self.eor_held_by(peer, family, HoldSet::ALL.minus(HoldSet::RESYNC_SATISFIES))
            })
            .collect()
    }

    /// Whether an owed marker of `peer` waits only for its family's owed
    /// keys to be absorbed, as the owed-key drain sees it.
    pub(super) fn eor_waits_on_owed_keys(&self, peer: PeerId) -> bool {
        let owed_keys = HoldSet::EMPTY.with(EorHold::OwedKeys);
        self.eor.families(peer).any(|family| {
            self.owes(peer, family) && self.eor_free_for(peer, family, Offer::Retry, owed_keys)
        })
    }

    /// Whether the polling lanes may send `family`'s marker to `peer` as a
    /// plain marker: nothing holds it, the RFC 5291 §6 gate included.
    pub(super) fn eor_retry_ready(&self, peer: PeerId, family: (Afi, Safi)) -> bool {
        self.eor_free_for(peer, family, Offer::Retry, HoldSet::EMPTY)
    }

    /// Send the owed markers of `peer` that nothing holds for this
    /// `trigger`. A family that owes keys sends its marker only behind
    /// them: a release opens one operation that absorbs them and then
    /// sends the marker; inside another operation, or refused, the marker
    /// stays owed and the owed-key drain retries it.
    pub(super) fn settle_eor(&mut self, peer: PeerId, trigger: EorTrigger<'_>) {
        let (offer, operation) = match trigger {
            EorTrigger::Release => (Offer::Release, None),
            EorTrigger::Table(operation) => (Offer::Table, Some(operation)),
            EorTrigger::InitialTable {
                operation,
                evpn_covered,
            } => (Offer::InitialTable { evpn_covered }, operation),
        };
        // Owed keys do not keep a marker out: this call absorbs them.
        let owed_keys = HoldSet::EMPTY.with(EorHold::OwedKeys);
        let mut ready: Vec<(Afi, Safi)> = self
            .eor
            .families(peer)
            .filter(|&family| self.eor_free_for(peer, family, offer, owed_keys))
            .collect();
        if ready.is_empty() {
            return;
        }
        let Some(tx) = self.outbound_peers.get(&peer).cloned() else {
            return;
        };
        let owed: Vec<(Afi, Safi)> = ready
            .iter()
            .copied()
            .filter(|&family| self.owes(peer, family))
            .collect();
        let mut own_operation = None;
        let operation = if owed.is_empty() {
            operation
        } else if operation.is_some() {
            ready.retain(|family| !owed.contains(family));
            operation
        } else {
            let envelopes = owed.len() + 1;
            if let Some(mut absorbing) = self
                .begin_outbound_operation(peer, envelopes)
                .ok()
                .filter(|operation| operation.reserved() == envelopes)
            {
                for &family in &owed {
                    if self
                        .absorb_owed_family(peer, family, &mut absorbing)
                        .is_err()
                    {
                        ready.retain(|kept| *kept != family);
                    }
                }
                // One failed absorption escalates every family to the
                // resync; no later marker may overtake that fallback.
                if self.dirty_peers.contains(&peer) || self.force_outbound_peers.contains(&peer) {
                    return;
                }
                Some(own_operation.insert(absorbing))
            } else {
                debug!(%peer, ?owed, "End-of-RIB waits to absorb owed keys: a whole-table update is still live or the channel is full");
                ready.retain(|family| !owed.contains(family));
                None
            }
        };
        if ready.is_empty() {
            return;
        }
        let families = ready;
        let marker_only = self.evpn_feed_is_current(peer);
        let sent = self.send_eor_markers(
            peer,
            &tx,
            &families,
            Vec::new(),
            operation.and_then(OutboundOperation::slot),
        );
        let initial = matches!(offer, Offer::InitialTable { .. });
        if sent {
            let bits = Self::evpn_admitted_marker_bits(&families, &[]);
            if bits != 0 || initial {
                self.evpn_feed_markers_admitted(peer, &tx, bits);
            }
            if !initial {
                self.complete_initial_selection_replay(peer);
                self.retire_completed_initial_group_admitted(peer);
            }
        } else {
            if initial {
                warn!(%peer, "outbound channel full — `EoR` deferred");
            } else {
                warn!(%peer, "outbound channel full — `EoR` still deferred");
            }
            self.metrics.record_outbound_eor_deferral(&peer.label());
            if !marker_only {
                self.mark_outbound_dirty(peer);
            }
        }
    }

    /// One standalone attempt, from a polling lane, at the markers a
    /// refused send left owed to `peer` (with `obligations`), together with
    /// the EVPN End-of-RIB and `EoRR` its current complete feed owes.
    /// A refused send leaves them for the next tick.
    pub(super) fn retry_eor_markers(&mut self, peer: PeerId, obligations: bool) {
        let Some(tx) = self.outbound_peers.get(&peer).cloned() else {
            return;
        };
        let session_id = self.outbound_session_ids.get(&peer).copied();
        let unsettled = if obligations {
            self.eor_unsettled_ready(peer)
        } else {
            Vec::new()
        };
        let mut families: Vec<(Afi, Safi)> = if obligations {
            self.eor
                .families(peer)
                .filter(|family| {
                    unsettled.contains(family) || self.eor_refused_retry_ready(peer, *family)
                })
                .collect()
        } else {
            Vec::new()
        };
        let mut refresh_markers = Vec::new();
        let (feed_owes_eor, feed_owes_eorr) = self.evpn_feed_owed_markers(peer);
        if (feed_owes_eor || feed_owes_eorr) && self.eor_retry_ready(peer, EVPN) {
            if feed_owes_eor && !families.contains(&EVPN) {
                families.push(EVPN);
            }
            if feed_owes_eorr {
                refresh_markers.push((EVPN.0, EVPN.1, rustbgpd_wire::RouteRefreshSubtype::EoRR));
            }
        }
        if families.is_empty() && refresh_markers.is_empty() {
            return;
        }
        let evpn_bits = Self::evpn_admitted_marker_bits(&families, &refresh_markers);
        if !self.send_eor_markers(peer, &tx, &families, refresh_markers, None) {
            return;
        }
        if !unsettled.is_empty() {
            warn!(
                %peer,
                families = ?unsettled,
                "End-of-RIB sent by the resync tick: the release of its last hold did not send it"
            );
            #[cfg(test)]
            {
                self.eor.unsettled_tick_sends += unsettled.len();
            }
        }
        if self.outbound_session_ids.get(&peer).copied() == session_id
            && self
                .outbound_peers
                .get(&peer)
                .is_some_and(|current| current.same_channel(&tx))
        {
            self.evpn_feed_markers_admitted(peer, &tx, evpn_bits);
        }
    }

    /// Production fallback of the tick's marker lane: the owed markers of
    /// `peer` that nothing holds and that no refused send explains. Every
    /// release sends the markers it frees, so this is empty unless one
    /// missed a marker. The tick then sends it within one interval, where
    /// it would otherwise stay owed until the session ended, and logs it.
    /// A test build fails earlier, at the end of the turn that left the
    /// marker (`assert_eor_settled`). The EVPN marker a current
    /// complete feed still owes is that feed's own tick retry, not this.
    fn eor_unsettled_ready(&self, peer: PeerId) -> Vec<(Afi, Safi)> {
        self.eor
            .families(peer)
            .filter(|&family| {
                !self.eor.stored(peer, family).contains(EorHold::Writer)
                    && self.eor_retry_ready(peer, family)
                    && !(family == EVPN && self.evpn_feed_owed_markers(peer).0)
            })
            .collect()
    }

    /// Whether a polling lane may retry `family`'s owed marker: a send of
    /// it was refused and nothing else holds it.
    fn eor_refused_retry_ready(&self, peer: PeerId, family: (Afi, Safi)) -> bool {
        self.eor.stored(peer, family).contains(EorHold::Writer)
            && self.eor_retry_ready(peer, family)
    }

    /// Whether the resync tick has a refused marker of `peer` to retry.
    pub(super) fn eor_retry_pending(&self, peer: PeerId) -> bool {
        self.eor
            .families(peer)
            .any(|family| self.eor_refused_retry_ready(peer, family))
            || !self.eor_unsettled_ready(peer).is_empty()
    }

    /// Whether a polling lane has a marker of `peer` to send now: a refused
    /// one, or one its current complete EVPN feed owes. A peer whose EVPN
    /// recovery reset is pending gets none of either until the reset runs.
    pub(super) fn eor_retry_runnable(&self, peer: PeerId) -> bool {
        #[cfg(test)]
        if let Some(observer) = &self.replacement_readiness_test_hook {
            observer("evpn_marker_candidate");
        }
        !self.evpn_recovery_reset_pending(peer)
            && !self.outbound_channel_gone(peer)
            && (self.eor_retry_pending(peer) || {
                let (end_of_rib, end_of_refresh) = self.evpn_feed_owed_markers(peer);
                (end_of_rib || end_of_refresh) && self.eor_retry_ready(peer, EVPN)
            })
    }

    /// Put `families`' markers (and `refresh_markers`) on `peer`'s channel.
    /// The owed markers among them are discharged when the writer takes the
    /// envelope and marked refused when it does not. The only sender of a
    /// pending marker: its callers pass families whose hold set is empty.
    fn send_eor_markers(
        &mut self,
        peer: PeerId,
        tx: &tokio::sync::mpsc::Sender<OutboundRouteUpdate>,
        families: &[(Afi, Safi)],
        refresh_markers: Vec<(Afi, Safi, rustbgpd_wire::RouteRefreshSubtype)>,
        slot: Option<crate::outbound_credit::OutboundSlot>,
    ) -> bool {
        let update = OutboundRouteUpdate {
            end_of_rib: families.to_vec(),
            refresh_markers,
            ..OutboundRouteUpdate::default()
        };
        let sent = match slot {
            Some(slot) => {
                slot.send(update);
                true
            }
            None => send_marker(tx, update).is_ok(),
        };
        for &family in families {
            if sent {
                self.eor.discharge(peer, family);
            } else {
                self.eor.store(peer, family, EorHold::Writer);
            }
        }
        sent
    }

    /// Test builds: after every actor turn, no owed marker may be left
    /// with an empty hold set and a live writer. Such a marker would leave
    /// only on a later, unrelated event: the release that emptied its set
    /// did not send it.
    #[cfg(test)]
    pub(super) fn assert_eor_settled(&self) {
        for peer in self.eor.peers() {
            if self
                .outbound_peers
                .get(&peer)
                .is_none_or(tokio::sync::mpsc::Sender::is_closed)
            {
                continue;
            }
            for family in self.eor.families(peer) {
                let holds = self.eor_holds(peer, family);
                assert!(
                    !holds.is_empty(),
                    "End-of-RIB for {family:?} toward {peer} is owed with no hold and was not sent: \
                     the release that emptied its hold set did not settle it"
                );
            }
        }
    }

    /// Test driver: offer `peer`'s owed markers as a release would.
    #[cfg(test)]
    pub(super) fn settle_eor_now(&mut self, peer: PeerId) {
        self.settle_eor(peer, EorTrigger::Release);
    }

    /// Test driver: end `peer`'s RT-Constrain membership hold.
    #[cfg(test)]
    pub(super) fn end_rt_membership_hold(&mut self, peer: PeerId) {
        self.release_eor_hold(peer, EorHold::RtMembership, EorTrigger::Release);
    }

    /// Test access: the families whose marker `peer` is owed.
    #[cfg(test)]
    pub(super) fn eor_pending(&self, peer: PeerId) -> HashSet<(Afi, Safi)> {
        self.eor.families(peer).collect()
    }

    /// Test access: the families whose marker `peer` is owed behind its
    /// ORF table.
    #[cfg(test)]
    pub(super) fn eor_behind_orf_table(&self, peer: PeerId) -> HashSet<(Afi, Safi)> {
        self.eor
            .families(peer)
            .filter(|&family| self.eor.behind_orf_table(peer, family))
            .collect()
    }
}
