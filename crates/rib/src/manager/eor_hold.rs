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
//! A release stages no routes: a marker whose family still owes keys stays
//! behind [`EorHold::OwedKeys`] for the owed-key drain, which reads the
//! peer's credit. A unicast marker leaves when its family's charged steps
//! have caught up; any other family is absorbed whole, one per step
//! ([`RibManager::absorb_owed_eor`]).
//!
//! The obligation stores the reasons nothing else owns: the ORF table hold,
//! the RT-Constrain membership hold and a refused send. The other reasons
//! are read from their owners (the selection gate, the grace window, the
//! EVPN feed, the resync flags and the owed keys) each time, so no copy of
//! them can go stale. Their owners call `release_eor_hold` when they clear;
//! a test build checks after every actor turn that no marker was left ready
//! but unsent (`assert_eor_settled`).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;
use std::ops::Bound::{Excluded, Unbounded};

use rustbgpd_wire::{Afi, Safi};
use tracing::{debug, warn};

use super::{RESYNC_PEERS_PER_TICK, RibManager};
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
    /// Initial unicast replay still has pages to admit for this member.
    InitialReplay,
    /// The peer's complete EVPN feed is not current.
    EvpnFeed,
    /// A dirty resync of the peer's table has not been admitted, or a
    /// forced one is still to run.
    Resync,
    /// The family owes keys that must be absorbed ahead of the marker.
    OwedKeys,
    /// A source departure still owns changes in this family, or this marker
    /// is queued for its bounded release after the departure.
    SourceDeparture,
    /// The writer refused the marker; the next offer is a resync or a tick.
    Writer,
}

impl EorHold {
    pub(super) const ALL: [Self; 10] = [
        Self::Selection,
        Self::RtMembership,
        Self::Grace,
        Self::OrfTable,
        Self::InitialReplay,
        Self::EvpnFeed,
        Self::Resync,
        Self::OwedKeys,
        Self::SourceDeparture,
        Self::Writer,
    ];

    const fn bit(self) -> u16 {
        1 << self as u16
    }
}

/// A set of [`EorHold`] reasons.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct HoldSet(u16);

impl HoldSet {
    pub(super) const EMPTY: Self = Self(0);
    const ALL: Self = Self(u16::MAX);
    /// The holds that withhold a marker until something outside this
    /// peer's own outbound data happens. A helper's stale carry and the
    /// initial dump ask for these only.
    pub(super) const WITHHELD: Self = Self(
        EorHold::Selection.bit()
            | EorHold::RtMembership.bit()
            | EorHold::Grace.bit()
            | EorHold::SourceDeparture.bit(),
    );
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

    fn offer(self) -> (Offer, Option<&'a mut OutboundOperation>) {
        match self {
            Self::Release => (Offer::Release, None),
            Self::Table(operation) => (Offer::Table, Some(operation)),
            Self::InitialTable {
                operation,
                evpn_covered,
            } => (Offer::InitialTable { evpn_covered }, operation),
        }
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

#[derive(Debug)]
struct RtMembershipHold {
    cap: tokio::time::Instant,
    /// The membership rebuild this connection's completion is waiting for.
    completion_epoch: Option<u64>,
}

#[derive(Debug)]
struct SelectionMarkerRelease {
    family: (Afi, Safi),
    peers: BTreeSet<PeerId>,
    resynced: HashSet<PeerId>,
}

/// The markers each registered session still owes.
#[derive(Debug, Default)]
pub(super) struct EorObligations {
    /// Owed markers in the order they were first owed, with the reasons
    /// stored here: only [`EorHold::OrfTable`] and [`EorHold::Writer`].
    /// A session owes a handful of families, so a list keeps the order an
    /// initial dump sends them in. Entries are never left empty.
    owed: HashMap<PeerId, OwedMarkers>,
    /// Peers whose ordinary marker debt is runnable.
    /// Debt and hold ownership stay in their original records.
    retry: BTreeSet<PeerId>,
    /// Markers whose peer was visited while departure owned its family.
    /// The terminal and subsequent marker ticks release a bounded page each.
    departure_waiters: BTreeMap<PeerId, smallvec::SmallVec<[(Afi, Safi); 2]>>,
    /// Complete receipts eligible for a retry, or parked behind EVPN selection.
    /// Arming the gate hides this entire ring; its one release takes the set.
    evpn_receipts: BTreeSet<PeerId>,
    /// Complete EVPN receipts to wake when the global selection hold opens.
    evpn_selection_waiters: BTreeSet<PeerId>,
    /// Ordinary debt covered by a startup non-unicast gate. The gate hands
    /// the whole set to its release without enumerating its receivers.
    selection_peers: HashMap<(Afi, Safi), BTreeSet<PeerId>>,
    /// Membership at release survives discharge until the peer's deferred
    /// refresh is handled. Session teardown removes the peer before reuse.
    releasing: VecDeque<SelectionMarkerRelease>,
    /// Peers whose markers a member body freed; offered when the pass ends.
    /// Empty between turns.
    settle_after_pass: Vec<PeerId>,
    /// Peers under the [`EorHold::RtMembership`] hold, with its cap. Armed
    /// at `PeerUp` when the session starts with an empty membership; a peer
    /// with the Restart State bit set is never held.
    rt_membership: BTreeMap<PeerId, RtMembershipHold>,
    /// Removing a completed peer must not rescan the other peers for the next cap.
    rt_membership_caps: BTreeSet<(tokio::time::Instant, PeerId)>,
    /// Held peers whose RT-Constrain End-of-RIB arrived while RT-Constrain
    /// selection was deferred: membership is rebuilt when that deferral is
    /// staged or released, and the hold ends there.
    rt_membership_complete: BTreeSet<(u64, PeerId)>,
    /// A rebuild releases all earlier epochs, including older work still draining.
    rt_membership_epoch: u64,
    /// Length of the released prefix of `rt_membership_complete`.
    rt_membership_released: usize,
    /// Markers the tick's fallback found ([`RibManager::eor_unsettled`]).
    #[cfg(test)]
    pub(super) unsettled_tick_finds: usize,
    /// A test of the fallback itself: let it run, and let a marker stay
    /// unsettled past a checked point.
    #[cfg(test)]
    pub(super) allow_unsettled: bool,
}

impl EorObligations {
    /// Whether any marker is owed to anyone.
    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.owed.is_empty()
    }

    /// Ordinary debt of an unreleased non-unicast startup family.
    pub(super) fn peers_for_family(
        &self,
        family: (Afi, Safi),
    ) -> impl Iterator<Item = PeerId> + '_ {
        self.selection_peers
            .get(&family)
            .into_iter()
            .flatten()
            .copied()
    }

    pub(super) fn begin_family_release(
        &mut self,
        family: (Afi, Safi),
        resynced: HashSet<PeerId>,
        has_refresh: bool,
    ) {
        if family == EVPN {
            // Startup selection releases each family once. No peer walk on arm or release.
            debug_assert!(self.evpn_selection_waiters.is_empty());
            self.evpn_selection_waiters = std::mem::take(&mut self.evpn_receipts);
        }
        let peers = self.selection_peers.remove(&family).unwrap_or_default();
        if !peers.is_empty() || has_refresh {
            self.releasing.push_back(SelectionMarkerRelease {
                family,
                peers,
                resynced,
            });
        }
    }

    pub(super) fn release_pending(&self, peer: PeerId, family: (Afi, Safi)) -> bool {
        self.releasing
            .iter()
            .find(|release| release.family == family)
            .is_some_and(|release| release.peers.contains(&peer))
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
    pub(super) fn next_rt_membership_cap(&self) -> Option<tokio::time::Instant> {
        self.rt_membership_caps.first().map(|&(cap, _)| cap)
    }

    /// Held peers whose RT-Constrain membership cap is at or before `due`.
    pub(super) fn rt_membership_caps_due(&self, due: tokio::time::Instant) -> Vec<PeerId> {
        self.rt_membership_caps
            .iter()
            .take_while(|&&(cap, _)| cap <= due)
            .map(|&(_, peer)| peer)
            .collect()
    }

    fn remove_rt_membership_hold(&mut self, peer: PeerId) -> bool {
        let Some(hold) = self.rt_membership.remove(&peer) else {
            return false;
        };
        self.rt_membership_caps.remove(&(hold.cap, peer));
        if let Some(epoch) = hold.completion_epoch {
            self.rt_membership_complete.remove(&(epoch, peer));
            if epoch != self.rt_membership_epoch {
                self.rt_membership_released -= 1;
            }
        }
        true
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
        if let Some(waiters) = self.departure_waiters.get_mut(&peer) {
            waiters.retain(|queued| *queued != family);
            if waiters.is_empty() {
                self.departure_waiters.remove(&peer);
            }
        }
        if let Some(peers) = self.selection_peers.get_mut(&family) {
            peers.remove(&peer);
            if peers.is_empty() {
                self.selection_peers.remove(&family);
            }
        }
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
            EorHold::Selection => self.selection_peer_convergence_held(peer, family),
            EorHold::SourceDeparture => {
                self.source_departure
                    .as_ref()
                    .is_some_and(|work| work.holds_family(family))
                    || self
                        .eor
                        .departure_waiters
                        .get(&peer)
                        .is_some_and(|queued| queued.contains(&family))
            }
            EorHold::RtMembership => {
                self.eor.rt_membership_held(peer) && Self::rtc_gated_family(family)
            }
            EorHold::Grace => self.eor_grace_held(peer, family),
            EorHold::OrfTable | EorHold::Writer => self.eor.stored(peer, family).contains(hold),
            EorHold::InitialReplay => self.is_initial_member_replay(peer),
            EorHold::EvpnFeed => {
                family == EVPN
                    && (self.evpn_grouped_member_of(peer).is_some()
                        || self.has_private_evpn_handoff(peer))
                    && !self.evpn_feed_is_current(peer)
            }
            // A force bit kept only for a family a selection gate still
            // defers is not a pending resync: the forced pass already ran
            // for everything else (`selection_partial_caught_up`), and the
            // gate's release runs the rest.
            EorHold::Resync => {
                self.dirty_peers.contains(&peer)
                    || (self.force_outbound_peers.contains(&peer)
                        && !self.selection_partial_caught_up(peer))
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

    /// The roster is normally installed before the first registration.
    pub(super) fn initialize_selection_marker_peers(&mut self) {
        self.eor.selection_peers.clear();
        let Some(gate) = &self.selection_deferral else {
            return;
        };
        for (&peer, markers) in &self.eor.owed {
            for &(family, _) in markers {
                if family.1 != Safi::Unicast && gate.may_hold_family(family) {
                    self.eor
                        .selection_peers
                        .entry(family)
                        .or_default()
                        .insert(peer);
                }
            }
        }
    }

    fn record_eor_debt(&mut self, peer: PeerId, family: (Afi, Safi)) {
        self.eor.owe(peer, family);
        if family.1 != Safi::Unicast
            && self
                .selection_deferral
                .as_ref()
                .is_some_and(|gate| gate.may_hold_family(family))
        {
            self.eor
                .selection_peers
                .entry(family)
                .or_default()
                .insert(peer);
        }
    }

    /// Record that the current session of `peer` owes `family`'s marker.
    pub(super) fn owe_eor(&mut self, peer: PeerId, family: (Afi, Safi)) {
        self.record_eor_debt(peer, family);
        self.refresh_eor_retry(peer);
    }

    /// Owe `family`'s marker behind the table the peer's first
    /// ROUTE-REFRESH unlocks.
    pub(super) fn owe_eor_behind_orf_table(&mut self, peer: PeerId, family: (Afi, Safi)) {
        self.record_eor_debt(peer, family);
        self.eor.store(peer, family, EorHold::OrfTable);
        self.refresh_eor_retry(peer);
    }

    /// Arm the RT-Constrain membership hold of a new session until `cap`.
    pub(super) fn hold_eor_for_rt_membership(&mut self, peer: PeerId, cap: tokio::time::Instant) {
        self.eor.remove_rt_membership_hold(peer);
        self.eor.rt_membership.insert(
            peer,
            RtMembershipHold {
                cap,
                completion_epoch: None,
            },
        );
        self.eor.rt_membership_caps.insert((cap, peer));
        self.refresh_eor_retry(peer);
    }

    /// `peer`'s RT membership is complete on the wire, but RT-Constrain
    /// selection is still deferred: the hold ends when that deferral is
    /// staged or released ([`Self::publish_rebuilt_rt_memberships`]).
    pub(super) fn rt_membership_completed_while_deferred(&mut self, peer: PeerId) {
        if let Some(hold) = self.eor.rt_membership.get_mut(&peer)
            && hold.completion_epoch.is_none()
        {
            let epoch = self.eor.rt_membership_epoch;
            hold.completion_epoch = Some(epoch);
            self.eor.rt_membership_complete.insert((epoch, peer));
        }
    }

    /// RT-Constrain selection was just staged or released and every
    /// membership rebuilt. Release only completions that preceded this rebuild.
    pub(super) fn publish_rebuilt_rt_memberships(&mut self) {
        if self.eor.rt_membership_complete.is_empty() {
            self.eor.rt_membership_epoch = 0;
        } else if self.eor.rt_membership_complete.len() != self.eor.rt_membership_released {
            self.eor.rt_membership_epoch += 1;
            self.eor.rt_membership_released = self.eor.rt_membership_complete.len();
        }
    }

    pub(super) fn released_rt_membership_pending(&self) -> bool {
        self.eor.rt_membership_released != 0
    }

    pub(super) fn service_released_rt_membership(&mut self, budget: usize) -> usize {
        let mut examined = 0;
        while examined < budget && self.released_rt_membership_pending() {
            let &(epoch, peer) = self
                .eor
                .rt_membership_complete
                .first()
                .expect("released RT membership");
            debug_assert_ne!(epoch, self.eor.rt_membership_epoch);
            examined += 1;
            #[cfg(test)]
            self.observe_marker_candidate();
            self.release_eor_hold(peer, EorHold::RtMembership, EorTrigger::Release);
        }
        examined
    }

    /// The session of `peer` ended: its markers and holds go with it.
    pub(super) fn forget_eor(&mut self, peer: PeerId) {
        self.eor.owed.remove(&peer);
        self.eor.departure_waiters.remove(&peer);
        self.eor.selection_peers.retain(|_, peers| {
            peers.remove(&peer);
            !peers.is_empty()
        });
        self.eor.releasing.retain_mut(|release| {
            release.peers.remove(&peer);
            release.resynced.remove(&peer);
            !release.peers.is_empty()
                || self
                    .selection_deferred_refresh
                    .contains_key(&release.family)
        });
        // The EVPN receipt indexes follow the feed receipt, which this
        // teardown invalidated first (`clear_outbound_peer_state`).
        self.eor.retry.remove(&peer);
        self.eor.remove_rt_membership_hold(peer);
        self.eor
            .settle_after_pass
            .retain(|deferred| *deferred != peer);
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
                if !self.eor.remove_rt_membership_hold(peer) {
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
            | EorHold::SourceDeparture
            | EorHold::Grace
            | EorHold::InitialReplay
            | EorHold::EvpnFeed
            | EorHold::Resync
            | EorHold::OwedKeys => {}
        }
        self.settle_eor(peer, trigger);
    }

    /// A resync of `peer` held by a selection gate for one family finished
    /// for the rest. For a forced resync that is where the kept force bit
    /// stops being a pending resync, so the markers it held follow now; a
    /// dirty resync settled its markers at its own exit.
    pub(super) fn forced_resync_caught_up(
        &mut self,
        peer: PeerId,
        dirty: bool,
        operation: Option<&mut OutboundOperation>,
    ) {
        self.set_selection_partial_caught_up(peer, true);
        if !dirty {
            self.resync_settles_eor(peer, operation);
        }
    }

    /// A release that happened inside a member body (a pass cancelled the
    /// last owed key of a family): the marker is offered once the pass is
    /// over, so it cannot overtake rows the same pass still stages and the
    /// completion hooks never run under an open body.
    pub(super) fn defer_eor_settle(&mut self, peer: PeerId) {
        self.eor.settle_after_pass.push(peer);
    }

    /// Offer the markers of every peer a pass deferred
    /// ([`Self::defer_eor_settle`]). Runs at the end of a distribution pass
    /// and at the end of every actor turn and resync tick.
    pub(super) fn settle_eor_after_pass(&mut self) {
        // Keep first occurrences so the existing reverse insertion order stays unchanged.
        let mut seen = HashSet::new();
        self.eor.settle_after_pass.retain(|peer| seen.insert(*peer));
        while let Some(peer) = self.eor.settle_after_pass.pop() {
            self.release_eor_hold(peer, EorHold::OwedKeys, EorTrigger::Release);
        }
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
        self.refresh_eor_retry(peer);
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

    /// The first owed marker of `peer` that waits only for its family's
    /// owed keys to be absorbed, as the owed-key drain sees it. A cursor
    /// family's marker (unicast, EVPN) is never absorbed: it leaves when
    /// the family's charged drain steps have caught up.
    fn eor_waiting_on_owed_keys(&self, peer: PeerId) -> Option<(Afi, Safi)> {
        let owed_keys = HoldSet::EMPTY.with(EorHold::OwedKeys);
        self.eor.families(peer).find(|&family| {
            !super::outbound_owing::OwedFamily::of(family)
                .is_some_and(super::outbound_owing::OwedFamily::has_cursor)
                && self.owes(peer, family)
                && self.eor_free_for(peer, family, Offer::Retry, owed_keys)
        })
    }

    /// One step of the owed-key drain for a marker that waits only for its
    /// family's owed keys: absorb that one family into an operation of its
    /// own and send the marker behind it. The caller read `peer`'s credit;
    /// no hold release stages an owed family. Returns whether the marker
    /// left. A refusal for capacity leaves the family and its marker owed
    /// for a later step; any other refusal escalates the peer to a resync,
    /// which carries the marker.
    pub(super) fn absorb_owed_eor(&mut self, peer: PeerId) -> bool {
        let Some(family) = self.eor_waiting_on_owed_keys(peer) else {
            return false;
        };
        let Some(mut operation) = self
            .begin_outbound_operation(peer, 2)
            .ok()
            .filter(|operation| operation.reserved() == 2)
        else {
            debug!(%peer, ?family, "End-of-RIB waits to absorb owed keys: a whole-table update is still live or the channel is full");
            return false;
        };
        if self
            .absorb_owed_family(peer, family, &mut operation)
            .is_err()
        {
            return false;
        }
        self.settle_free_family_eor(peer, family, Some(&mut operation));
        !self.eor.owes(peer, family)
    }

    /// Whether `family`'s marker toward `peer` waits for a complete EVPN
    /// feed that is not current. Only a build of the peer's table (a resync
    /// or a refresh answer) makes the feed current; no release or tick does.
    pub(super) fn eor_waits_for_evpn_feed(&self, peer: PeerId, family: (Afi, Safi)) -> bool {
        self.eor_hold_applies(peer, family, EorHold::EvpnFeed)
    }

    /// Whether the polling lanes may send `family`'s marker to `peer` as a
    /// plain marker: nothing holds it, the RFC 5291 §6 gate included.
    pub(super) fn eor_retry_ready(&self, peer: PeerId, family: (Afi, Safi)) -> bool {
        self.eor_free_for(peer, family, Offer::Retry, HoldSet::EMPTY)
    }

    /// Send the owed markers of `peer` that nothing holds for this
    /// `trigger`. A family that owes keys sends its marker only behind
    /// them, and this call stages no routes: that marker stays owed until
    /// the owed-key drain has sent the family (unicast) or absorbs it
    /// ([`Self::absorb_owed_eor`]).
    /// A refused marker marks the peer dirty, so its resync carries it.
    pub(super) fn settle_eor(&mut self, peer: PeerId, trigger: EorTrigger<'_>) {
        let (offer, operation) = trigger.offer();
        self.settle_eor_as(peer, None, offer, operation, false);
    }

    /// [`Self::settle_eor`] for the markers of `families` only: the table
    /// the trigger admitted covers no other family.
    pub(super) fn settle_eor_of(
        &mut self,
        peer: PeerId,
        families: &[(Afi, Safi)],
        trigger: EorTrigger<'_>,
    ) {
        let (offer, operation) = trigger.offer();
        self.settle_eor_as(peer, Some(families), offer, operation, false);
    }

    /// This peer's release visit found its table admitted or owned by a
    /// subsequent drain. A full writer only needs a marker retry.
    pub(super) fn settle_unicast_release_eor(
        &mut self,
        peer: PeerId,
        family: (Afi, Safi),
        missing_group_rows_admitted: bool,
    ) {
        let caught_up = self.selection_partial_caught_up(peer);
        let offer = if caught_up {
            Offer::Table
        } else {
            Offer::Release
        };
        // A refused terminal behind a held member's newly admitted rows
        // captures its exact group baseline for the corrective resync.
        let retry_marker_only = caught_up || !missing_group_rows_admitted;
        self.settle_eor_as(peer, Some(&[family]), offer, None, retry_marker_only);
    }

    /// A resync of `peer` was admitted while a
    /// selection gate still held a family's marker, and that gate is now
    /// released: the marker follows the table, even while the peer stays
    /// dirty for another deferred family. A refused marker waits for the
    /// tick's marker retry; the table is not sent again.
    pub(super) fn settle_eor_behind_resync(&mut self, peer: PeerId) {
        self.settle_eor_as(peer, None, Offer::Table, None, true);
    }

    /// A release from inside a refresh answer that absorbed a family's owed
    /// keys and was then deferred, or from the shutdown flush: send the
    /// markers nothing holds. A refused marker waits for the tick's marker
    /// retry, with no resync.
    pub(super) fn settle_free_eor(&mut self, peer: PeerId) {
        self.settle_eor_as(peer, None, Offer::Release, None, true);
    }

    /// [`Self::settle_free_eor`] for one family. When a refresh absorbed
    /// its table, the marker follows on a slot of the same operation.
    pub(super) fn settle_free_family_eor(
        &mut self,
        peer: PeerId,
        family: (Afi, Safi),
        operation: Option<&mut OutboundOperation>,
    ) {
        self.settle_eor_as(peer, Some(&[family]), Offer::Release, operation, true);
    }

    /// Send the markers of `peer` (of `only`, when given) that no hold
    /// keeps from this `offer`, owed keys included, on a slot of
    /// `operation` or as a marker of their own. `retry_refused` leaves a
    /// refused marker to the tick's marker retry; otherwise the refusal
    /// marks the peer dirty.
    fn settle_eor_as(
        &mut self,
        peer: PeerId,
        only: Option<&[(Afi, Safi)]>,
        offer: Offer,
        operation: Option<&mut OutboundOperation>,
        retry_refused: bool,
    ) {
        let families: Vec<(Afi, Safi)> = self
            .eor
            .families(peer)
            .filter(|family| only.is_none_or(|only| only.contains(family)))
            .filter(|&family| self.eor_free_for(peer, family, offer, HoldSet::EMPTY))
            .collect();
        if families.is_empty() {
            self.refresh_eor_retry(peer);
            return;
        }
        let Some(tx) = self.outbound_peers.get(&peer).cloned() else {
            self.eor.retry.remove(&peer);
            return;
        };
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
            if families.contains(&EVPN) {
                // This refused offer was the release wake. The debt moves to
                // the retry ring instead of a second offer from the receipt lane.
                self.eor.evpn_selection_waiters.remove(&peer);
            }
            if !retry_refused && !marker_only {
                self.mark_outbound_dirty(peer);
            }
        }
        self.refresh_eor_retry(peer);
    }

    /// One standalone attempt, from a polling lane, at the markers a
    /// refused send left owed to `peer` (with `obligations`), together with
    /// the EVPN End-of-RIB and `EoRR` its current complete feed owes.
    /// A refused send leaves them for the next tick.
    pub(super) fn retry_eor_markers(&mut self, peer: PeerId, obligations: bool) {
        let Some(tx) = self.outbound_peers.get(&peer).cloned() else {
            return;
        };
        // A stale scheduling hint can outlive a closed writer or a pending reset.
        if tx.is_closed() || self.evpn_recovery_reset_pending(peer) {
            return;
        }
        let session_id = self.outbound_session_ids.get(&peer).copied();
        let unsettled = if obligations {
            self.eor_unsettled_ready(peer, Offer::Retry)
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
        if evpn_bits != 0 {
            // This offer consumes the wake even when the writer refuses it.
            self.eor.evpn_selection_waiters.remove(&peer);
        }
        if !unsettled.is_empty() {
            // Logged whether or not the writer takes it: a refused send
            // becomes an ordinary retry, which is not reported again.
            warn!(
                %peer,
                families = ?unsettled,
                "End-of-RIB left to the resync tick: the release of its last hold did not send it"
            );
            #[cfg(test)]
            {
                assert!(
                    self.eor.allow_unsettled,
                    "End-of-RIB for {unsettled:?} toward {peer} was left to the resync tick:                      the release that emptied its hold set did not settle it"
                );
                self.eor.unsettled_tick_finds += unsettled.len();
            }
        }
        if !self.send_eor_markers(peer, &tx, &families, refresh_markers, None) {
            // The consumed wake leaves the refused receipt in no index until
            // this puts it on the retry ring, whichever lane made the offer.
            self.refresh_eor_retry(peer);
            return;
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

    /// Whether `family`'s marker toward `peer` was left behind by a release:
    /// owed, not refused by the writer, and held by nothing a polling lane
    /// respects. The EVPN marker a current complete feed still owes is that
    /// feed's own tick retry, not a missed release. The tick's fallback and
    /// the test-build check both ask here, so they cannot disagree.
    ///
    /// `offer` is the one difference: the fallback is a polling lane and
    /// waits for an RFC 5291 §6 gate ([`Offer::Retry`]), as the tick always
    /// has; the check asks as a release would ([`Offer::Release`]), because
    /// a release sends such a marker at once and nothing else will until
    /// the peer refreshes.
    fn eor_unsettled(&self, peer: PeerId, family: (Afi, Safi), offer: Offer) -> bool {
        !self.eor.stored(peer, family).contains(EorHold::Writer)
            && self.eor_free_for(peer, family, offer, HoldSet::EMPTY)
            && !(family == EVPN && self.evpn_feed_owed_markers(peer).0)
    }

    /// Production fallback of the tick's marker lane: the markers of `peer`
    /// a release left behind ([`Self::eor_unsettled`]), unless the peer's
    /// writer is gone or its EVPN recovery reset is pending. Every release
    /// sends the markers it frees, so this is empty unless one missed a
    /// marker. The tick then sends it within one interval, where it would
    /// otherwise stay owed until the session ended, and logs it. A test
    /// build fails instead, here and at every checked point
    /// (`assert_eor_settled`).
    fn eor_unsettled_ready(&self, peer: PeerId, offer: Offer) -> Vec<(Afi, Safi)> {
        if self.outbound_channel_gone(peer) || self.evpn_recovery_reset_pending(peer) {
            return Vec::new();
        }
        self.eor
            .families(peer)
            .filter(|&family| self.eor_unsettled(peer, family, offer))
            .collect()
    }

    /// Whether a polling lane may retry `family`'s owed marker: a send of
    /// it was refused and nothing else holds it.
    fn eor_refused_retry_ready(&self, peer: PeerId, family: (Afi, Safi)) -> bool {
        if !self.eor.stored(peer, family).contains(EorHold::Writer) {
            return false;
        }
        if matches!(family, (Afi::Ipv4 | Afi::Ipv6, Safi::Unicast)) {
            // The ORF cap already authorized an empty completion. Refusal by
            // the writer must not reinstate an indefinite wait for a refresh.
            let offer = if self.orf_eor_cap_passed.contains(&peer) {
                Offer::Release
            } else {
                Offer::Retry
            };
            // A sibling gate can keep a dirty peer parked after its table
            // was admitted. Any new missed delta invalidates that receipt.
            let covered = if self.selection_partial_caught_up(peer) {
                HoldSet::EMPTY.with(EorHold::Resync)
            } else {
                HoldSet::EMPTY
            };
            return self.eor_free_for(peer, family, offer, covered);
        }
        self.eor_retry_ready(peer, family)
    }

    /// Whether the resync tick has a refused marker of `peer` to retry.
    pub(super) fn eor_retry_pending(&self, peer: PeerId) -> bool {
        self.eor
            .families(peer)
            .any(|family| self.eor_refused_retry_ready(peer, family))
            || !self.eor_unsettled_ready(peer, Offer::Retry).is_empty()
    }

    /// Update the scheduling hint after an owner changes. A later offer rechecks
    /// the live session, holds and feed receipt before sending anything.
    pub(super) fn refresh_eor_retry(&mut self, peer: PeerId) {
        if let Some(work) = &self.source_departure
            && let Some(owed) = self.eor.owed.get(&peer)
        {
            for &(family, _) in owed {
                if work.holds_family(family) {
                    let waiters = self.eor.departure_waiters.entry(peer).or_default();
                    if !waiters.contains(&family) {
                        waiters.push(family);
                    }
                }
            }
        }
        let owes_receipt = self.evpn_feed_receipt_count != 0
            && self.evpn_feed_owed_markers(peer) != (false, false);
        if !owes_receipt {
            self.eor.evpn_selection_waiters.remove(&peer);
        }
        if owes_receipt
            && !self.eor.evpn_selection_waiters.contains(&peer)
            && (self.selection_convergence_held(EVPN) || self.eor_retry_ready(peer, EVPN))
        {
            self.eor.evpn_receipts.insert(peer);
        } else {
            self.eor.evpn_receipts.remove(&peer);
        }
        if self.eor_retry_runnable(peer) {
            self.eor.retry.insert(peer);
        } else {
            self.eor.retry.remove(&peer);
        }
    }

    /// Read by the event loop even when the resync timer is disarmed.
    pub(super) fn marker_retry_pending(&self) -> bool {
        !self.eor.retry.is_empty()
            || (!self.eor.evpn_receipts.is_empty() && !self.selection_convergence_held(EVPN))
    }

    pub(super) fn marker_release_pending(&self) -> bool {
        !self.eor.releasing.is_empty()
            || self.released_rt_membership_pending()
            || self.released_evpn_markers_pending()
            || (self.source_departure.is_none() && !self.eor.departure_waiters.is_empty())
    }

    /// The cursor has published its final data page. Reoffer a bounded page
    /// now, leaving the rest under their hold for the existing release timer.
    pub(super) fn finish_source_departure_markers(&mut self) {
        debug_assert!(self.source_departure.is_none());
        self.service_departure_markers(RESYNC_PEERS_PER_TICK);
    }

    fn service_departure_markers(&mut self, budget: usize) -> usize {
        if self.source_departure.is_some() {
            return 0;
        }
        let mut spent = 0;
        while spent < budget {
            let Some((peer, families)) = self.eor.departure_waiters.pop_first() else {
                break;
            };
            spent += 1;
            #[cfg(test)]
            self.observe_marker_candidate();
            self.settle_eor_as(peer, Some(&families), Offer::Release, None, true);
        }
        spent
    }

    fn released_evpn_markers_pending(&self) -> bool {
        !self.eor.evpn_selection_waiters.is_empty() && !self.selection_convergence_held(EVPN)
    }

    pub(super) fn service_selection_marker_releases(&mut self, budget: usize) {
        let rtc_budget = if self.eor.releasing.is_empty() {
            budget
        } else {
            budget / 2
        };
        let spent = self.service_released_rt_membership(rtc_budget);
        self.service_family_release_markers(budget - spent);
    }

    fn service_family_release_markers(&mut self, budget: usize) -> usize {
        let mut spent = 0;
        while spent < budget {
            let Some(release) = self.eor.releasing.front_mut() else {
                break;
            };
            let family = release.family;
            let marker = release.peers.pop_first();
            let next = marker.or_else(|| {
                self.selection_deferred_refresh
                    .get(&family)?
                    .first()
                    .copied()
            });
            let Some(peer) = next else {
                self.eor.releasing.pop_front();
                continue;
            };
            let was_resynced = release.resynced.remove(&peer);
            spent += 1;
            #[cfg(test)]
            self.observe_marker_candidate();
            self.finish_selection_marker_peer(family, peer, was_resynced, marker.is_some());
            if self
                .eor
                .releasing
                .front()
                .is_some_and(|release| release.peers.is_empty())
                && !self.selection_deferred_refresh.contains_key(&family)
            {
                self.eor.releasing.pop_front();
            }
        }
        spent
    }

    /// Offer released receipts once. A refusal remains on the ordinary ring.
    pub(super) fn service_marker_release_backlog(&mut self, budget: usize) {
        // One membership completion can settle several families for the peer and
        // run their replay completion hooks. Keep this cap even on an RTC-only tick.
        let rtc = self.service_released_rt_membership(budget.min(RESYNC_PEERS_PER_TICK / 4));
        // Share the receiver budget with earlier releases while departures drain.
        let departure = self.service_departure_markers((budget - rtc).div_ceil(2));
        let remaining = budget - rtc - departure;
        // Known cost: while any released receipt waits, an earlier family's
        // release runs at half rate. That includes one visit for each waiter
        // still queued behind its own EVPN release, which sends nothing here.
        let family_budget = if self.released_evpn_markers_pending() {
            remaining / 2
        } else {
            remaining
        };
        let spent = self.service_family_release_markers(family_budget);
        if self.released_evpn_markers_pending() {
            // Every visit takes its peer out of the set, so the front of the
            // set is the next unvisited waiter. A receiver whose own EVPN
            // release visit is still queued is held by it: this offer sends
            // nothing, and that visit sends the marker behind its table.
            let visits: smallvec::SmallVec<[PeerId; RESYNC_PEERS_PER_TICK]> = self
                .eor
                .evpn_selection_waiters
                .iter()
                .take(remaining - spent)
                .copied()
                .collect();
            for peer in visits {
                #[cfg(test)]
                self.observe_marker_candidate();
                self.eor.evpn_selection_waiters.remove(&peer);
                self.retry_eor_markers(peer, false);
                self.refresh_eor_retry(peer);
            }
        }
    }

    /// One slice of a pass over the retry ring, in peer order from the
    /// cursor. A pass offers each refused marker once and never wraps, so a
    /// writer that stays full costs one offer per pass. Returns whether the
    /// pass has peers left: the caller runs the next slice at the backlog
    /// cadence, and waits the ordinary retry interval before the next pass.
    ///
    /// When both timers are due this tick shares its visits with released
    /// receivers. Take existing retries first so a newly refused release
    /// cannot be attempted a second time in this same tick.
    pub(super) fn retry_eor_markers_bounded(&mut self) -> bool {
        let retry_budget = if self.marker_release_pending() {
            RESYNC_PEERS_PER_TICK / 2
        } else {
            RESYNC_PEERS_PER_TICK
        };
        let after = (
            self.evpn_marker_cursor.map_or(Unbounded, Excluded),
            Unbounded,
        );
        let visible_receipts =
            !self.eor.evpn_receipts.is_empty() && !self.selection_convergence_held(EVPN);
        // Ordered union past the cursor. A peer can own both an ordinary
        // marker and an EVPN receipt and gets only one offer per pass.
        let mut ordinary = self.eor.retry.range(after).peekable();
        let mut receipts = visible_receipts
            .then(|| self.eor.evpn_receipts.range(after))
            .into_iter()
            .flatten()
            .peekable();
        let ring = std::iter::from_fn(|| match (ordinary.peek(), receipts.peek()) {
            (Some(a), Some(b)) if a == b => {
                receipts.next();
                ordinary.next()
            }
            (Some(a), Some(b)) if b < a => receipts.next(),
            (None, _) => receipts.next(),
            _ => ordinary.next(),
        });
        #[cfg(test)]
        let ring = ring.inspect(|_| self.observe_marker_candidate());
        let slice: smallvec::SmallVec<[PeerId; RESYNC_PEERS_PER_TICK]> =
            ring.take(retry_budget).copied().collect();
        let release_budget = RESYNC_PEERS_PER_TICK - slice.len();
        for peer in slice {
            self.evpn_marker_cursor = Some(peer);
            self.replacement_checkpoint(false);
            self.retry_eor_markers(peer, true);
            self.refresh_eor_retry(peer);
        }
        // Read after the offers: a delivered marker has left the ring.
        let rest = (
            self.evpn_marker_cursor.map_or(Unbounded, Excluded),
            Unbounded,
        );
        let more = self.eor.retry.range(rest).next().is_some()
            || (visible_receipts && self.eor.evpn_receipts.range(rest).next().is_some());
        if !more {
            self.evpn_marker_cursor = None;
        }
        self.service_marker_release_backlog(release_budget);
        more
    }

    #[cfg(test)]
    pub(super) fn observe_marker_candidate(&self) {
        if let Some(observer) = &self.marker_retry_test_hook {
            observer("evpn_marker_candidate");
        }
    }

    /// Whether the ordinary debt ledger has a runnable marker for this peer.
    /// A pending EVPN recovery reset blocks every family on this sender.
    fn eor_retry_runnable(&self, peer: PeerId) -> bool {
        #[cfg(test)]
        if let Some(observer) = &self.marker_retry_test_hook {
            observer("evpn_marker_eligibility");
        }
        self.eor.owes_peer(peer)
            && !self.evpn_recovery_reset_pending(peer)
            && !self.outbound_channel_gone(peer)
            && self.eor_retry_pending(peer)
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

    /// Test builds: after every actor turn and every resync tick, no
    /// marker may be left behind ([`Self::eor_unsettled_ready`]). Such a
    /// marker would leave only on a later tick: the release that emptied its
    /// hold set did not send it.
    #[cfg(test)]
    pub(super) fn assert_eor_settled(&self) {
        if self.eor.allow_unsettled {
            return;
        }
        for &peer in self.eor.owed.keys() {
            let unsettled = self.eor_unsettled_ready(peer, Offer::Release);
            assert!(
                unsettled.is_empty(),
                "End-of-RIB for {unsettled:?} toward {peer} is owed with no hold and was not sent: \
                 the release that emptied its hold set did not settle it"
            );
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
