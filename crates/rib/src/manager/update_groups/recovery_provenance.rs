//! Actor-owned EVPN recovery keys and their capacity credits.
//!
//! Credits cover container headers and requested reserved capacity, including
//! overlapping reallocations. Allocator bookkeeping and RSS are separate
//! qualification surfaces. Register ownership before changing a projection;
//! failed capture stays exhausted until that owned record is retired.

use std::mem::size_of;
use std::net::IpAddr;

pub(in crate::manager) use crate::update::EvpnRecoveryExhaustionCause as ExhaustionCause;
use rustbgpd_wire::EvpnRouteKey;
use smallvec::SmallVec;

pub(in crate::manager) const PEER_LIMIT_BYTES: usize = 16 * 1024 * 1024;
pub(in crate::manager) const DAEMON_LIMIT_BYTES: usize = 256 * 1024 * 1024;

type Keys = SmallVec<[EvpnRouteKey; 0]>;
type Records = SmallVec<[Record; 0]>;
type Words = SmallVec<[u64; 0]>;
type Universes = SmallVec<[Universe; 0]>;

/// Weak identity: the pool frees storage after its final record releases it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::manager) struct UniverseHandle(u64);

#[derive(Debug)]
struct Universe {
    handle: UniverseHandle,
    references: usize,
    keys: Keys,
}

impl Universe {
    fn charge(&self) -> usize {
        size_of::<Self>() + self.keys.capacity() * size_of::<EvpnRouteKey>()
    }
}

/// Raw universe membership is not admission: only set bits and sparse keys are.
#[derive(Clone, Copy, Debug)]
pub(in crate::manager) struct EvpnProofView<'a> {
    universe: &'a [EvpnRouteKey],
    words: &'a [u64],
    sparse: &'a [EvpnRouteKey],
    masked: usize,
}

impl<'a> EvpnProofView<'a> {
    pub(in crate::manager) fn len(self) -> usize {
        self.masked + self.sparse.len()
    }

    pub(in crate::manager) fn is_empty(self) -> bool {
        self.len() == 0
    }

    pub(in crate::manager) fn contains(self, key: &EvpnRouteKey) -> bool {
        self.universe
            .binary_search(key)
            .is_ok_and(|position| self.words[position / 64] & (1_u64 << (position % 64)) != 0)
            || self.sparse.binary_search(key).is_ok()
    }

    /// Checkpoint excluded and trailing universe rows as well as returned keys.
    pub(in crate::manager) fn iter_with_checkpoint<'c>(
        self,
        mut checkpoint: impl FnMut(bool) + 'c,
    ) -> impl Iterator<Item = EvpnRouteKey> + 'c
    where
        'a: 'c,
    {
        let mut base = 0;
        let mut sparse = 0;
        let mut pending = None;
        std::iter::from_fn(move || {
            while pending.is_none() && base < self.universe.len() {
                checkpoint(false);
                let position = base;
                base += 1;
                if self.words[position / 64] & (1_u64 << (position % 64)) != 0 {
                    pending = Some(self.universe[position]);
                }
            }
            match (pending, self.sparse.get(sparse).copied()) {
                (Some(left), Some(right)) if left <= right => pending.take(),
                (_, Some(right)) => {
                    checkpoint(false);
                    sparse += 1;
                    Some(right)
                }
                (Some(_), None) => pending.take(),
                (None, None) => None,
            }
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(in crate::manager) struct PeerSession {
    pub(in crate::manager) peer: IpAddr,
    pub(in crate::manager) session_id: u64,
}

/// Fences even a retired and re-registered identical peer/session tuple.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(in crate::manager) struct ProvenanceHandle {
    owner: PeerSession,
    id: u64,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::manager) struct Exhaustion {
    pub(in crate::manager) cause: ExhaustionCause,
    pub(in crate::manager) limiting_peer: Option<IpAddr>,
    pub(in crate::manager) attempted_peer_bytes: usize,
    pub(in crate::manager) attempted_daemon_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::manager) struct Usage {
    pub(in crate::manager) retained: usize,
    pub(in crate::manager) peak: usize,
}

#[derive(Clone, Copy, Debug)]
enum State {
    Dormant,
    Capturing,
    Ready,
    Exhausted(Exhaustion),
}

#[derive(Debug)]
struct Record {
    handle: ProvenanceHandle,
    primary: bool,
    reset_admitted: bool,
    state: State,
    keys: Keys,
    universe: Option<UniverseHandle>,
    universe_charge: usize,
    words: Words,
    masked: usize,
    peer_peak: usize,
    // Duplicated within the charged peer range; mutations maintain one total.
    peer_retained: usize,
}

impl Record {
    fn charge(&self) -> usize {
        size_of::<Self>()
            + self.keys.capacity() * size_of::<EvpnRouteKey>()
            + self.words.capacity() * size_of::<u64>()
            + self.universe_charge
    }
}

#[derive(Debug)]
pub(in crate::manager) struct EvpnRecoveryProvenance {
    records: Records,
    universes: Universes,
    next_universe: Option<u64>,
    daemon_used: usize,
    daemon_peak: usize,
    peer_limit: usize,
    daemon_limit: usize,
    next_id: u64,
    #[cfg(test)]
    fail_next_allocation: bool,
    #[cfg(test)]
    allocation_countdown: Option<usize>,
}

impl EvpnRecoveryProvenance {
    pub(in crate::manager) fn new() -> Self {
        Self::with_limits(PEER_LIMIT_BYTES, DAEMON_LIMIT_BYTES)
    }

    fn with_limits(peer_limit: usize, daemon_limit: usize) -> Self {
        assert!(
            daemon_limit >= size_of::<Self>(),
            "ledger header needs credit"
        );
        Self {
            records: Records::new(),
            universes: Universes::new(),
            next_universe: Some(1),
            daemon_used: size_of::<Self>(),
            daemon_peak: size_of::<Self>(),
            peer_limit,
            daemon_limit,
            next_id: 1,
            #[cfg(test)]
            fail_next_allocation: false,
            #[cfg(test)]
            allocation_countdown: None,
        }
    }

    #[cfg(test)]
    pub(in crate::manager) fn with_test_limits(peer: usize, daemon: usize) -> Self {
        Self::with_limits(peer, daemon)
    }

    #[cfg(test)]
    pub(in crate::manager) fn fail_next_allocation_for_test(&mut self) {
        self.fail_next_allocation = true;
    }

    #[cfg(test)]
    pub(in crate::manager) fn fail_allocation_after_for_test(&mut self, allowed: Option<usize>) {
        self.allocation_countdown = allowed;
    }

    pub(in crate::manager) fn limits(&self) -> (usize, usize) {
        (self.peer_limit, self.daemon_limit)
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "G4 mass-dirty qualification will consume retained and peak daemon credits"
        )
    )]
    pub(in crate::manager) fn daemon_usage(&self) -> Usage {
        Usage {
            retained: self.daemon_used,
            peak: self.daemon_peak,
        }
    }

    /// Charges aggregate all retained generations and snapshots at an address.
    pub(in crate::manager) fn peer_usage(&self, peer: IpAddr) -> Usage {
        self.records
            .get(self.peer_range(peer).start)
            .filter(|r| r.handle.owner.peer == peer)
            .map_or(
                Usage {
                    retained: 0,
                    peak: 0,
                },
                |record| Usage {
                    retained: record.peer_retained,
                    peak: record.peer_peak,
                },
            )
    }

    fn peer_range(&self, peer: IpAddr) -> std::ops::Range<usize> {
        let start = self.records.partition_point(|r| r.handle.owner.peer < peer);
        let end = self
            .records
            .partition_point(|r| r.handle.owner.peer <= peer);
        start..end
    }

    fn owner_range(&self, owner: PeerSession) -> std::ops::Range<usize> {
        let start = self.records.partition_point(|r| r.handle.owner < owner);
        let end = self.records.partition_point(|r| r.handle.owner <= owner);
        start..end
    }

    fn index(&self, handle: ProvenanceHandle) -> Option<usize> {
        self.records
            .binary_search_by_key(&handle, |record| record.handle)
            .ok()
    }

    /// Snapshot-only ownership does not make a peer an active member. The
    /// sorted owner range excludes every unrelated peer and session.
    pub(in crate::manager) fn primary_handle(
        &self,
        owner: PeerSession,
    ) -> Option<ProvenanceHandle> {
        self.records[self.owner_range(owner)]
            .iter()
            .find_map(|record| record.primary.then_some(record.handle))
    }

    pub(in crate::manager) fn exhaustion(&self, handle: ProvenanceHandle) -> Option<Exhaustion> {
        let index = self.index(handle)?;
        let record = &self.records[index];
        let primary = if record.primary {
            record
        } else {
            let owner = self.primary_handle(handle.owner)?;
            if owner.generation != handle.generation {
                return None;
            }
            &self.records[self.index(owner)?]
        };
        if let State::Exhausted(error) = primary.state {
            Some(error)
        } else {
            None
        }
    }

    pub(in crate::manager) fn is_dormant(&self, handle: ProvenanceHandle) -> bool {
        self.index(handle).is_some_and(|i| {
            self.records[i].primary && matches!(self.records[i].state, State::Dormant)
        })
    }

    pub(in crate::manager) fn reset_admitted(&self, handle: ProvenanceHandle) -> bool {
        self.index(handle)
            .is_some_and(|i| self.records[i].primary && self.records[i].reset_admitted)
    }

    pub(in crate::manager) fn mark_reset_admitted(&mut self, handle: ProvenanceHandle) -> bool {
        let Some(index) = self.index(handle) else {
            return false;
        };
        let record = &mut self.records[index];
        if !record.primary || !matches!(record.state, State::Exhausted(_)) || record.reset_admitted
        {
            return false;
        }
        record.reset_admitted = true;
        true
    }

    fn checked_handle_index(&self, handle: ProvenanceHandle) -> Result<Option<usize>, Exhaustion> {
        let Some(index) = self.index(handle) else {
            return Ok(None);
        };
        // Capturing primary keys use only this exact logarithmic lookup.
        // Snapshots also inherit refusal from their matching primary episode.
        if self.records[index].primary {
            if let State::Exhausted(error) = self.records[index].state {
                return Err(error);
            }
        } else if let Some(error) = self.exhaustion(handle) {
            return Err(error);
        }
        Ok(Some(index))
    }

    fn mark_exhausted(&mut self, handle: ProvenanceHandle, mut error: Exhaustion) -> Exhaustion {
        if error.cause == ExhaustionCause::AdmissionInvariant {
            error.attempted_peer_bytes = self.peer_usage(handle.owner.peer).retained;
            error.attempted_daemon_bytes = self.daemon_used;
        }
        if let Some(primary) = self.primary_handle(handle.owner)
            && primary.generation == handle.generation
            && let Some(index) = self.index(primary)
        {
            self.records[index].state = State::Exhausted(error);
        }
        error
    }

    fn overflow() -> Exhaustion {
        Exhaustion {
            cause: ExhaustionCause::AllocationFailure,
            limiting_peer: None,
            attempted_peer_bytes: usize::MAX,
            attempted_daemon_bytes: usize::MAX,
        }
    }

    fn admission_invariant() -> Exhaustion {
        Exhaustion {
            cause: ExhaustionCause::AdmissionInvariant,
            limiting_peer: None,
            attempted_peer_bytes: 0,
            attempted_daemon_bytes: 0,
        }
    }

    pub(in crate::manager) fn fail_admission(&mut self, handle: ProvenanceHandle) -> bool {
        self.fail_control(handle, ExhaustionCause::AdmissionInvariant, false)
    }

    pub(in crate::manager) fn abort_capture(&mut self, handle: ProvenanceHandle) -> bool {
        self.fail_control(handle, ExhaustionCause::CaptureUnavailable, true)
    }

    fn fail_control(
        &mut self,
        handle: ProvenanceHandle,
        cause: ExhaustionCause,
        capturing_only: bool,
    ) -> bool {
        let Some(index) = self.index(handle) else {
            return false;
        };
        if !self.records[index].primary
            || matches!(self.records[index].state, State::Exhausted(_))
            || (capturing_only && !matches!(self.records[index].state, State::Capturing))
        {
            return false;
        }
        let error = Exhaustion {
            cause,
            limiting_peer: None,
            attempted_peer_bytes: self.peer_usage(handle.owner.peer).retained,
            attempted_daemon_bytes: self.daemon_used,
        };
        self.mark_exhausted(handle, error);
        true
    }

    fn check(&self, address: IpAddr, peer: usize, daemon: usize) -> Result<(), Exhaustion> {
        let cause = if peer > self.peer_limit {
            Some(ExhaustionCause::PeerLimit)
        } else if daemon > self.daemon_limit {
            Some(ExhaustionCause::DaemonLimit)
        } else {
            None
        };
        match cause {
            Some(cause) => Err(Exhaustion {
                cause,
                limiting_peer: (cause == ExhaustionCause::PeerLimit).then_some(address),
                attempted_peer_bytes: peer,
                attempted_daemon_bytes: daemon,
            }),
            None => Ok(()),
        }
    }

    #[cfg_attr(
        not(test),
        expect(
            clippy::unused_self,
            reason = "Only test builds read the ledger-owned allocation fault hook"
        )
    )]
    fn allocation_permitted(&mut self) -> bool {
        #[cfg(test)]
        if let Some(remaining) = self.allocation_countdown {
            self.allocation_countdown = remaining.checked_sub(1);
            if remaining == 0 {
                return false;
            }
        }
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_allocation) {
            return false;
        }
        true
    }

    fn note_peer_peak(&mut self, peer: IpAddr, attempted: usize) {
        let range = self.peer_range(peer);
        for record in &mut self.records[range] {
            record.peer_peak = record.peer_peak.max(attempted);
        }
    }

    fn set_peer_retained(&mut self, peer: IpAddr, retained: usize) {
        let range = self.peer_range(peer);
        for record in &mut self.records[range] {
            record.peer_retained = retained;
        }
    }

    fn metadata_peer_peak(
        records: &[Record],
        resizing: bool,
        additional: usize,
    ) -> Result<usize, Exhaustion> {
        let retained = records.first().map_or(0, |record| record.peer_retained);
        let copies = if resizing {
            records
                .len()
                .checked_mul(size_of::<Record>())
                .ok_or_else(Self::overflow)?
        } else {
            0
        };
        retained
            .checked_add(copies)
            .and_then(|n| n.checked_add(additional))
            .ok_or_else(Self::overflow)
    }

    /// The constructor record and, during resize, both metadata arrays overlap.
    #[allow(
        clippy::too_many_lines,
        reason = "Metadata preflight and ownership transfer form one atomic admission."
    )]
    fn insert_record(
        &mut self,
        owner: PeerSession,
        generation: Option<u64>,
    ) -> Result<ProvenanceHandle, Exhaustion> {
        let next_id = self.next_id.checked_add(1).ok_or_else(Self::overflow)?;
        let prior_usage = self.peer_usage(owner.peer);
        let prior_peak = prior_usage.peak;
        let old_cap = self.records.capacity();
        let new_cap = if self.records.len() == old_cap {
            old_cap.checked_mul(2).ok_or_else(Self::overflow)?.max(1)
        } else {
            old_cap
        };
        let resizing = new_cap != old_cap;
        let new_bytes = new_cap
            .checked_mul(size_of::<Record>())
            .ok_or_else(Self::overflow)?;
        let resize_bytes = if resizing {
            new_bytes
                .checked_add(size_of::<Records>())
                .ok_or_else(Self::overflow)?
        } else {
            0
        };
        let extra = resize_bytes
            .checked_add(size_of::<Record>())
            .ok_or_else(Self::overflow)?;
        let daemon = self
            .daemon_used
            .checked_add(extra)
            .ok_or_else(Self::overflow)?;
        let target_extra = size_of::<Record>()
            .checked_mul(2)
            .ok_or_else(Self::overflow)?;
        let mut target_peak = target_extra;
        let credited_range = if resizing {
            0..self.records.len()
        } else {
            self.peer_range(owner.peer)
        };
        for records in self.records[credited_range.clone()]
            .chunk_by(|a, b| a.handle.owner.peer == b.handle.owner.peer)
        {
            let peer = records[0].handle.owner.peer;
            let additional = if peer == owner.peer { target_extra } else { 0 };
            let attempted = Self::metadata_peer_peak(records, resizing, additional)?;
            if peer == owner.peer {
                target_peak = attempted;
            }
            self.check(peer, attempted, daemon)?;
        }
        self.check(owner.peer, target_peak, daemon)?;
        self.daemon_used = daemon;
        self.daemon_peak = self.daemon_peak.max(daemon);
        // Peaks include the old metadata copies, before ownership moves.
        let mut start = credited_range.start;
        while start < credited_range.end {
            let peer = self.records[start].handle.owner.peer;
            let mut end = start + 1;
            while end < credited_range.end && self.records[end].handle.owner.peer == peer {
                end += 1;
            }
            let additional = if peer == owner.peer { target_extra } else { 0 };
            let peak = Self::metadata_peer_peak(&self.records[start..end], resizing, additional)
                .expect("metadata peer peak was checked before reserving");
            for record in &mut self.records[start..end] {
                record.peer_peak = record.peer_peak.max(peak);
            }
            start = end;
        }
        if resizing {
            if !self.allocation_permitted() || self.records.try_grow(new_cap).is_err() {
                self.daemon_used -= extra;
                return Err(Exhaustion {
                    cause: ExhaustionCause::AllocationFailure,
                    limiting_peer: None,
                    attempted_peer_bytes: target_peak,
                    attempted_daemon_bytes: daemon,
                });
            }
            self.daemon_used -= old_cap * size_of::<Record>() + size_of::<Records>();
        }
        let handle = ProvenanceHandle {
            owner,
            id: self.next_id,
            generation: generation.unwrap_or(self.next_id),
        };
        let index = self
            .records
            .binary_search_by_key(&handle, |record| record.handle)
            .unwrap_err();
        self.records.insert(
            index,
            Record {
                handle,
                primary: generation.is_none(),
                reset_admitted: false,
                state: State::Ready,
                keys: Keys::new(),
                universe: None,
                universe_charge: 0,
                words: Words::new(),
                masked: 0,
                peer_peak: target_peak.max(prior_peak),
                peer_retained: prior_usage.retained + size_of::<Record>(),
            },
        );
        self.set_peer_retained(owner.peer, prior_usage.retained + size_of::<Record>());
        self.next_id = next_id;
        self.daemon_used -= size_of::<Record>();
        Ok(handle)
    }

    /// Fresh registration starts with a sealed empty proof, never desired keys.
    pub(in crate::manager) fn register(
        &mut self,
        owner: PeerSession,
    ) -> Result<ProvenanceHandle, Exhaustion> {
        if let Some(handle) = self.primary_handle(owner) {
            return Ok(handle);
        }
        self.insert_record(owner, None)
    }

    fn universe_index(&self, handle: UniverseHandle) -> Option<usize> {
        self.universes
            .binary_search_by_key(&handle.0, |universe| universe.handle.0)
            .ok()
    }

    fn view(&self, index: usize) -> EvpnProofView<'_> {
        let record = &self.records[index];
        let universe = record
            .universe
            .and_then(|handle| self.universe_index(handle))
            .map_or(&[][..], |index| self.universes[index].keys.as_slice());
        EvpnProofView {
            universe,
            words: &record.words,
            sparse: &record.keys,
            masked: record.masked,
        }
    }

    fn sort_keys(keys: &mut Keys, checkpoint: &mut impl FnMut(bool)) {
        checkpoint(true);
        keys.sort_unstable_by(|left, right| {
            checkpoint(false);
            left.cmp(right)
        });
        keys.dedup_by(|left, right| {
            checkpoint(false);
            left == right
        });
        checkpoint(true);
    }

    /// Count actual OLD keys outside a live older universe, without scratch keys.
    pub(in crate::manager) fn capture_shape<A: Iterator<Item = EvpnRouteKey>>(
        &self,
        hint: Option<UniverseHandle>,
        mut keys: A,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<(usize, usize), Exhaustion> {
        let universe = hint
            .and_then(|handle| self.universe_index(handle))
            .map(|index| self.universes[index].keys.as_slice());
        keys.try_fold((0_usize, 0_usize), |(count, additions), key| {
            checkpoint(false);
            let missing = universe.is_some_and(|keys| {
                keys.binary_search_by(|prior| {
                    checkpoint(false);
                    prior.cmp(&key)
                })
                .is_err()
            });
            Ok((
                count.checked_add(1).ok_or_else(Self::overflow)?,
                additions
                    .checked_add(usize::from(missing))
                    .ok_or_else(Self::overflow)?,
            ))
        })
    }

    /// Optional sharing refuses without exhausting the authoritative flat fallback.
    #[expect(
        clippy::too_many_lines,
        reason = "mask allocation and optional universe construction roll back before exposing one captured owner"
    )]
    pub(in crate::manager) fn share_capture<A: Iterator<Item = EvpnRouteKey>>(
        &mut self,
        handle: ProvenanceHandle,
        hint: Option<UniverseHandle>,
        count: usize,
        keys: A,
        filtered: usize,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<Option<UniverseHandle>, Exhaustion> {
        let Some(index) = self.checked_handle_index(handle)? else {
            return Ok(None);
        };
        let record = &self.records[index];
        if let Some(universe) = record.universe {
            return Ok(Some(universe));
        }
        if !record.primary
            || !record.keys.is_empty()
            || count == 0
            || !matches!(record.state, State::Capturing | State::Ready)
        {
            return Ok(None);
        }
        let reused = hint.filter(|hint| self.universe_index(*hint).is_some());
        let (length, universe_charge) = if let Some(hint) = reused {
            let universe = &self.universes[self.universe_index(hint).expect("live hint")];
            universe
                .references
                .checked_add(1)
                .ok_or_else(Self::overflow)?;
            (universe.keys.len(), universe.charge())
        } else {
            (
                count,
                count
                    .checked_mul(size_of::<EvpnRouteKey>())
                    .and_then(|n| n.checked_add(size_of::<Universe>()))
                    .ok_or_else(Self::overflow)?,
            )
        };
        let words = length.div_ceil(64);
        let bytes = words
            .checked_mul(size_of::<u64>())
            .ok_or_else(Self::overflow)?;
        if filtered
            .checked_mul(size_of::<EvpnRouteKey>())
            .ok_or_else(Self::overflow)?
            < bytes
        {
            return Ok(None);
        }
        let extra = bytes
            .checked_add(size_of::<Words>())
            .ok_or_else(Self::overflow)?;
        let retained = self.peer_usage(handle.owner.peer).retained;
        let peer = retained
            .checked_add(universe_charge)
            .and_then(|n| n.checked_add(extra))
            .ok_or_else(Self::overflow)?;
        let daemon = self
            .daemon_used
            .checked_add(extra)
            .ok_or_else(Self::overflow)?;
        self.check(handle.owner.peer, peer, daemon)?;
        self.daemon_used = daemon;
        self.daemon_peak = self.daemon_peak.max(daemon);
        self.note_peer_peak(handle.owner.peer, peer);
        checkpoint(true);
        let failed =
            !self.allocation_permitted() || self.records[index].words.try_grow(words).is_err();
        checkpoint(true);
        if failed {
            self.daemon_used -= extra;
            return Err(Exhaustion {
                cause: ExhaustionCause::AllocationFailure,
                limiting_peer: None,
                attempted_peer_bytes: peer,
                attempted_daemon_bytes: daemon,
            });
        }
        for _ in 0..words {
            checkpoint(false);
            self.records[index].words.push(0);
        }
        self.daemon_used -= size_of::<Words>();
        self.set_peer_retained(handle.owner.peer, retained + bytes);
        let created = match reused {
            Some(hint) => Ok(hint),
            None => self.create_universe(handle, count, keys, checkpoint),
        };
        let universe = match created {
            Ok(universe) => universe,
            Err(error) => {
                checkpoint(true);
                self.records[index].words.clear();
                self.records[index]
                    .words
                    .try_grow(0)
                    .expect("empty pinned SmallVec deallocation cannot fail");
                checkpoint(true);
                self.daemon_used -= bytes;
                self.set_peer_retained(handle.owner.peer, retained);
                return Err(error);
            }
        };
        let position = self
            .universe_index(universe)
            .expect("owned universe exists");
        self.universes[position].references += 1;
        self.records[index].universe = Some(universe);
        self.records[index].universe_charge = self.universes[position].charge();
        self.set_peer_retained(
            handle.owner.peer,
            retained + bytes + self.records[index].universe_charge,
        );
        Ok(Some(universe))
    }

    #[expect(
        clippy::too_many_lines,
        reason = "construction credits and fallible pool growth share one rollback boundary"
    )]
    fn create_universe<A: Iterator<Item = EvpnRouteKey>>(
        &mut self,
        handle: ProvenanceHandle,
        count: usize,
        keys: A,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<UniverseHandle, Exhaustion> {
        let id = self.next_universe.ok_or_else(Self::overflow)?;
        let bytes = count
            .checked_mul(size_of::<EvpnRouteKey>())
            .ok_or_else(Self::overflow)?;
        let temporary = bytes
            .checked_add(size_of::<Universe>())
            .and_then(|n| n.checked_add(size_of::<Keys>()))
            .ok_or_else(Self::overflow)?;
        let peer = self
            .peer_usage(handle.owner.peer)
            .retained
            .checked_add(temporary)
            .and_then(|n| n.checked_add(size_of::<Universe>()))
            .ok_or_else(Self::overflow)?;
        let daemon = self
            .daemon_used
            .checked_add(temporary)
            .ok_or_else(Self::overflow)?;
        self.check(handle.owner.peer, peer, daemon)?;
        self.daemon_used = daemon;
        self.daemon_peak = self.daemon_peak.max(daemon);
        self.note_peer_peak(handle.owner.peer, peer);
        let mut owned = Keys::new();
        let mut attempted_peer = peer;
        let built = (|| {
            checkpoint(true);
            let failed = !self.allocation_permitted() || owned.try_grow(count).is_err();
            checkpoint(true);
            if failed {
                return Err(Exhaustion {
                    cause: ExhaustionCause::AllocationFailure,
                    limiting_peer: None,
                    attempted_peer_bytes: attempted_peer,
                    attempted_daemon_bytes: daemon,
                });
            }
            for key in keys {
                checkpoint(false);
                if owned.len() == count {
                    return Err(Self::admission_invariant());
                }
                owned.push(key);
            }
            Self::sort_keys(&mut owned, checkpoint);
            let old = self.universes.capacity();
            let new = if old == self.universes.len() {
                old.checked_mul(2).ok_or_else(Self::overflow)?.max(1)
            } else {
                old
            };
            let resizing = old != new;
            let extra = if resizing {
                new.checked_mul(size_of::<Universe>())
                    .and_then(|n| n.checked_add(size_of::<Universes>()))
                    .ok_or_else(Self::overflow)?
            } else {
                0
            };
            let daemon = self
                .daemon_used
                .checked_add(extra)
                .ok_or_else(Self::overflow)?;
            if resizing {
                let mut start = 0;
                while start < self.records.len() {
                    checkpoint(false);
                    let address = self.records[start].handle.owner.peer;
                    let range = self.peer_range(address);
                    let copies = self.records[range.clone()].iter().try_fold(
                        0_usize,
                        |copies, record| {
                            checkpoint(false);
                            copies
                                .checked_add(if record.universe.is_some() {
                                    size_of::<Universe>()
                                } else {
                                    0
                                })
                                .ok_or_else(Self::overflow)
                        },
                    )?;
                    let retained = if address == handle.owner.peer {
                        peer
                    } else {
                        self.peer_usage(address).retained
                    };
                    let attempted = retained.checked_add(copies).ok_or_else(Self::overflow)?;
                    if address == handle.owner.peer {
                        attempted_peer = attempted;
                    }
                    self.check(address, attempted, daemon)?;
                    self.note_peer_peak(address, attempted);
                    start = range.end;
                }
            }
            self.check(handle.owner.peer, attempted_peer, daemon)?;
            self.daemon_used = daemon;
            self.daemon_peak = self.daemon_peak.max(daemon);
            if resizing {
                checkpoint(true);
                let failed = !self.allocation_permitted() || self.universes.try_grow(new).is_err();
                checkpoint(true);
                if failed {
                    self.daemon_used -= extra;
                    return Err(Exhaustion {
                        cause: ExhaustionCause::AllocationFailure,
                        limiting_peer: None,
                        attempted_peer_bytes: attempted_peer,
                        attempted_daemon_bytes: daemon,
                    });
                }
                self.daemon_used -= old * size_of::<Universe>() + size_of::<Universes>();
            }
            Ok(())
        })();
        if let Err(error) = built {
            checkpoint(true);
            drop(owned);
            checkpoint(true);
            self.daemon_used -= temporary;
            return Err(error);
        }
        let universe = UniverseHandle(id);
        checkpoint(true);
        self.universes.push(Universe {
            handle: universe,
            references: 0,
            keys: owned,
        });
        checkpoint(true);
        self.next_universe = id.checked_add(1);
        self.daemon_used -= size_of::<Universe>() + size_of::<Keys>();
        Ok(universe)
    }

    fn release_universe(&mut self, handle: UniverseHandle) {
        let Some(index) = self.universe_index(handle) else {
            return;
        };
        if self.universes[index].references != 0 {
            return;
        }
        let bytes = self.universes[index].keys.capacity() * size_of::<EvpnRouteKey>();
        drop(self.universes.remove(index));
        self.daemon_used -= bytes;
        if self.universes.is_empty() {
            let bytes = self.universes.capacity() * size_of::<Universe>();
            self.universes
                .try_grow(0)
                .expect("empty pinned SmallVec deallocation cannot fail");
            self.daemon_used -= bytes;
        }
    }

    pub(in crate::manager) fn reserve_capture(
        &mut self,
        handle: ProvenanceHandle,
        count: usize,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<bool, Exhaustion> {
        let Some(index) = self.checked_handle_index(handle)? else {
            return Ok(false);
        };
        if !self.records[index].primary || !matches!(self.records[index].state, State::Capturing) {
            return Ok(false);
        }
        checkpoint(true);
        let result = self.grow_keys(handle, count);
        checkpoint(true);
        result
            .map(|()| true)
            .map_err(|error| self.mark_exhausted(handle, error))
    }

    fn grow_keys(&mut self, handle: ProvenanceHandle, capacity: usize) -> Result<(), Exhaustion> {
        let index = self.index(handle).expect("owned provenance record");
        let old_cap = self.records[index].keys.capacity();
        if capacity <= old_cap {
            return Ok(());
        }
        let new_bytes = capacity
            .checked_mul(size_of::<EvpnRouteKey>())
            .ok_or_else(Self::overflow)?;
        let extra = new_bytes
            .checked_add(size_of::<Keys>())
            .ok_or_else(Self::overflow)?;
        let peer = self
            .peer_usage(handle.owner.peer)
            .retained
            .checked_add(extra)
            .ok_or_else(Self::overflow)?;
        let daemon = self
            .daemon_used
            .checked_add(extra)
            .ok_or_else(Self::overflow)?;
        self.check(handle.owner.peer, peer, daemon)?;
        self.daemon_used = daemon;
        self.daemon_peak = self.daemon_peak.max(daemon);
        self.note_peer_peak(handle.owner.peer, peer);
        if !self.allocation_permitted() || self.records[index].keys.try_grow(capacity).is_err() {
            self.daemon_used -= extra;
            return Err(Exhaustion {
                cause: ExhaustionCause::AllocationFailure,
                limiting_peer: None,
                attempted_peer_bytes: peer,
                attempted_daemon_bytes: daemon,
            });
        }
        // Pinned SmallVec has freed the old allocation before returning.
        self.daemon_used -= old_cap * size_of::<EvpnRouteKey>() + size_of::<Keys>();
        let retained = self.peer_usage(handle.owner.peer).retained + new_bytes
            - old_cap * size_of::<EvpnRouteKey>();
        self.set_peer_retained(handle.owner.peer, retained);
        Ok(())
    }

    pub(in crate::manager) fn begin_capture(
        &mut self,
        handle: ProvenanceHandle,
    ) -> Result<bool, Exhaustion> {
        let Some(index) = self.checked_handle_index(handle)? else {
            return Ok(false);
        };
        if !self.records[index].primary || !matches!(self.records[index].state, State::Dormant) {
            return Ok(false);
        }
        self.records[index].state = State::Capturing;
        Ok(true)
    }

    /// Append an unordered capture; callers checkpoint their projection walk.
    pub(in crate::manager) fn capture_key_with_checkpoint(
        &mut self,
        handle: ProvenanceHandle,
        key: EvpnRouteKey,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<bool, Exhaustion> {
        checkpoint(false);
        let Some(index) = self.checked_handle_index(handle)? else {
            return Ok(false);
        };
        if !matches!(self.records[index].state, State::Capturing) {
            return Ok(false);
        }
        if let Some(universe) = self.records[index].universe {
            let position = self.universe_index(universe).and_then(|index| {
                self.universes[index]
                    .keys
                    .binary_search_by(|prior| {
                        checkpoint(false);
                        prior.cmp(&key)
                    })
                    .ok()
            });
            if let Some(position) = position {
                let bit = 1_u64 << (position % 64);
                if self.records[index].words[position / 64] & bit == 0 {
                    self.records[index].words[position / 64] |= bit;
                    self.records[index].masked += 1;
                }
                return Ok(true);
            }
        }
        let keys = &self.records[index].keys;
        if keys.len() == keys.capacity() {
            checkpoint(true);
            let capacity = keys
                .capacity()
                .checked_mul(2)
                .map(|n| n.max(1))
                .ok_or_else(Self::overflow)
                .and_then(|cap| self.grow_keys(handle, cap));
            checkpoint(true);
            if let Err(error) = capacity {
                return Err(self.mark_exhausted(handle, error));
            }
        }
        self.records[index].keys.push(key);
        Ok(true)
    }

    /// In-place unstable sorting and deduplication allocate no scratch buffer.
    pub(in crate::manager) fn seal_capture_with_checkpoint(
        &mut self,
        handle: ProvenanceHandle,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<bool, Exhaustion> {
        let Some(index) = self.checked_handle_index(handle)? else {
            return Ok(false);
        };
        if !matches!(self.records[index].state, State::Capturing) {
            return Ok(false);
        }
        Self::sort_keys(&mut self.records[index].keys, checkpoint);
        self.records[index].state = State::Ready;
        Ok(true)
    }

    #[cfg(test)]
    pub(in crate::manager) fn capture_key(
        &mut self,
        handle: ProvenanceHandle,
        key: EvpnRouteKey,
    ) -> Result<bool, Exhaustion> {
        self.capture_key_with_checkpoint(handle, key, &mut |_| {})
    }

    #[cfg(test)]
    pub(in crate::manager) fn seal_capture(
        &mut self,
        handle: ProvenanceHandle,
    ) -> Result<bool, Exhaustion> {
        self.seal_capture_with_checkpoint(handle, &mut |_| {})
    }

    /// None means there is no complete proof; it never permits a withdrawal.
    pub(in crate::manager) fn proof(
        &self,
        handle: ProvenanceHandle,
    ) -> Result<Option<EvpnProofView<'_>>, Exhaustion> {
        Ok(self.checked_handle_index(handle)?.and_then(|index| {
            matches!(self.records[index].state, State::Ready).then(|| self.view(index))
        }))
    }

    #[cfg(test)]
    pub(in crate::manager) fn proof_keys(
        &self,
        handle: ProvenanceHandle,
    ) -> Result<Option<Vec<EvpnRouteKey>>, Exhaustion> {
        self.proof(handle)
            .map(|proof| proof.map(|proof| proof.iter_with_checkpoint(|_| {}).collect()))
    }

    /// Keep a charged immutable copy under the same peer/session ownership.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "G2 EVPN regroup wiring will consume charged key snapshots"
        )
    )]
    pub(in crate::manager) fn snapshot(
        &mut self,
        handle: ProvenanceHandle,
    ) -> Result<Option<ProvenanceHandle>, Exhaustion> {
        let Some(proof) = self.proof(handle)? else {
            return Ok(None);
        };
        let sparse_len = proof.sparse.len();
        let words_len = proof.words.len();
        let source = self.index(handle).expect("owned snapshot source");
        let universe = self.records[source].universe;
        let universe_charge = self.records[source].universe_charge;
        let masked = self.records[source].masked;
        let snapshot = match self.insert_record(handle.owner, Some(handle.generation)) {
            Ok(snapshot) => snapshot,
            Err(error) => return Err(self.mark_exhausted(handle, error)),
        };
        let copied = (|| {
            self.grow_keys(snapshot, sparse_len)?;
            if universe.is_none() {
                let source = self.index(handle).expect("snapshot source remains owned");
                let destination = self.index(snapshot).expect("new snapshot remains owned");
                let (before, after) = self.records.split_at_mut(destination);
                after[0]
                    .keys
                    .extend_from_slice(before[source].keys.as_slice());
                return Ok(());
            }
            let bytes = words_len
                .checked_mul(size_of::<u64>())
                .ok_or_else(Self::overflow)?;
            let extra = bytes
                .checked_add(size_of::<Words>())
                .ok_or_else(Self::overflow)?;
            let retained = self.peer_usage(handle.owner.peer).retained;
            let peer = retained
                .checked_add(universe_charge)
                .and_then(|n| n.checked_add(extra))
                .ok_or_else(Self::overflow)?;
            let daemon = self
                .daemon_used
                .checked_add(extra)
                .ok_or_else(Self::overflow)?;
            self.check(handle.owner.peer, peer, daemon)?;
            let destination = self.index(snapshot).expect("new snapshot remains owned");
            self.daemon_used = daemon;
            self.daemon_peak = self.daemon_peak.max(daemon);
            self.note_peer_peak(handle.owner.peer, peer);
            if words_len != 0
                && (!self.allocation_permitted()
                    || self.records[destination].words.try_grow(words_len).is_err())
            {
                self.daemon_used -= extra;
                return Err(Exhaustion {
                    cause: ExhaustionCause::AllocationFailure,
                    limiting_peer: None,
                    attempted_peer_bytes: peer,
                    attempted_daemon_bytes: daemon,
                });
            }
            self.daemon_used -= size_of::<Words>();
            self.records[destination].universe = universe;
            self.records[destination].universe_charge = universe_charge;
            self.records[destination].masked = masked;
            if let Some(universe) = universe {
                let position = self
                    .universe_index(universe)
                    .expect("snapshot universe remains owned");
                self.universes[position].references += 1;
            }
            self.set_peer_retained(handle.owner.peer, retained + bytes + universe_charge);
            let source = self.index(handle).expect("snapshot source remains owned");
            let (before, after) = self.records.split_at_mut(destination);
            after[0]
                .keys
                .extend_from_slice(before[source].keys.as_slice());
            after[0]
                .words
                .extend_from_slice(before[source].words.as_slice());
            Ok(())
        })();
        if let Err(error) = copied {
            self.retire(snapshot);
            return Err(self.mark_exhausted(handle, error));
        }
        Ok(Some(snapshot))
    }

    // Reservation ignores withdrawal credit: later export gates may remove
    // withdrawals while retaining announcements from the candidate batch.
    fn planned_len<A>(
        keys: &[EvpnRouteKey],
        announcements: A,
        withdrawals: &[EvpnRouteKey],
        credit_withdrawals: bool,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<usize, Exhaustion>
    where
        A: Iterator<Item = EvpnRouteKey> + Clone,
    {
        if !withdrawals.windows(2).all(|w| {
            checkpoint(false);
            w[0] < w[1]
        }) {
            return Err(Self::admission_invariant());
        }
        let mut previous = None;
        for key in announcements.clone() {
            checkpoint(false);
            if previous.is_some_and(|old| old >= key) {
                return Err(Self::admission_invariant());
            }
            previous = Some(key);
        }
        let mut old = 0;
        for key in withdrawals {
            checkpoint(false);
            while let Some(prior) = keys.get(old) {
                checkpoint(false);
                if prior >= key {
                    break;
                }
                old += 1;
            }
            if keys.get(old) != Some(key) {
                return Err(Self::admission_invariant());
            }
        }
        let mut old = 0;
        let mut withdrawn = 0;
        let mut additional = 0_usize;
        for key in announcements {
            checkpoint(false);
            while let Some(prior) = keys.get(old) {
                checkpoint(false);
                if *prior >= key {
                    break;
                }
                old += 1;
            }
            while let Some(prior) = withdrawals.get(withdrawn) {
                checkpoint(false);
                if *prior >= key {
                    break;
                }
                withdrawn += 1;
            }
            if keys.get(old) != Some(&key)
                || (credit_withdrawals && withdrawals.get(withdrawn) == Some(&key))
            {
                additional = additional.checked_add(1).ok_or_else(Self::overflow)?;
            }
        }
        keys.len()
            .checked_sub(if credit_withdrawals {
                withdrawals.len()
            } else {
                0
            })
            .and_then(|n| n.checked_add(additional))
            .ok_or_else(Self::overflow)
    }

    /// Reserve the union of old proof and candidate announcements without
    /// changing keys. Reserve after owning a queue slot and before export-side
    /// mutations; final admission can only remove announcements or add known
    /// withdrawals, so its application then needs no allocation.
    pub(in crate::manager) fn reserve_admission_with_checkpoint<A>(
        &mut self,
        handle: ProvenanceHandle,
        announcements: A,
        withdrawals: &[EvpnRouteKey],
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<bool, Exhaustion>
    where
        A: DoubleEndedIterator<Item = EvpnRouteKey> + ExactSizeIterator + Clone,
    {
        let Some(index) = self.checked_handle_index(handle)? else {
            return Ok(false);
        };
        if !self.records[index].primary || !matches!(self.records[index].state, State::Ready) {
            return Ok(false);
        }
        if self.records[index].universe.is_some() {
            let result = Self::shared_batch_capacity(
                self.view(index),
                announcements,
                withdrawals,
                checkpoint,
            )
            .and_then(|capacity| {
                checkpoint(true);
                let result = self.grow_keys(handle, capacity);
                checkpoint(true);
                result
            });
            return result
                .map(|()| true)
                .map_err(|error| self.mark_exhausted(handle, error));
        }
        let result = Self::planned_len(
            self.records[index].keys.as_slice(),
            announcements,
            withdrawals,
            false,
            checkpoint,
        )
        .and_then(|length| {
            checkpoint(true);
            let result = self.grow_keys(handle, length);
            checkpoint(true);
            result
        });
        if let Err(error) = result {
            return Err(self.mark_exhausted(handle, error));
        }
        Ok(true)
    }

    /// Update only final accepted batches, after queue reservation and before
    /// enqueue. Both inputs are sorted/unique and announcements are a cloneable
    /// borrowed exact-size iterator, so no temporary key vector is needed.
    /// After `reserve_admission`, final filtering must only remove announcements
    /// or add known withdrawals; this makes application allocation-free.
    pub(in crate::manager) fn apply_admitted_with_checkpoint<A>(
        &mut self,
        handle: ProvenanceHandle,
        announcements: A,
        withdrawals: &[EvpnRouteKey],
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<bool, Exhaustion>
    where
        A: DoubleEndedIterator<Item = EvpnRouteKey> + ExactSizeIterator + Clone,
    {
        let Some(index) = self.checked_handle_index(handle)? else {
            return Ok(false);
        };
        if !self.records[index].primary || !matches!(self.records[index].state, State::Ready) {
            return Ok(false);
        }
        if self.records[index].universe.is_some() {
            return self.apply_shared(handle, index, announcements, withdrawals, checkpoint);
        }
        let result = Self::planned_len(
            self.records[index].keys.as_slice(),
            announcements.clone(),
            withdrawals,
            true,
            checkpoint,
        );
        let final_len = match result {
            Ok(length) => length,
            Err(error) => return Err(self.mark_exhausted(handle, error)),
        };
        if final_len > self.records[index].keys.capacity() {
            let error = Self::admission_invariant();
            return Err(self.mark_exhausted(handle, error));
        }
        let keys = &mut self.records[index].keys;
        let mut withdrawn = 0;
        keys.retain(|key| {
            checkpoint(false);
            while withdrawn < withdrawals.len() && withdrawals[withdrawn] < *key {
                checkpoint(false);
                withdrawn += 1;
            }
            withdrawals.get(withdrawn) != Some(key)
        });
        let mut old = keys.len();
        let mut announced = announcements;
        let mut next = announced.next_back();
        while final_len > keys.len() {
            checkpoint(false);
            keys.push(next.expect("growth has an announcement"));
        }
        for target in (0..final_len).rev() {
            checkpoint(false);
            let old_key = old.checked_sub(1).map(|i| keys[i]);
            let key = match (old_key, next) {
                (Some(left), Some(right)) if left > right => {
                    old -= 1;
                    left
                }
                (Some(left), Some(right)) if left == right => {
                    old -= 1;
                    next = announced.next_back();
                    left
                }
                (_, Some(right)) => {
                    next = announced.next_back();
                    right
                }
                (Some(left), None) => {
                    old -= 1;
                    left
                }
                (None, None) => unreachable!("union length was checked"),
            };
            keys[target] = key;
        }
        Ok(true)
    }

    /// Final gates must preserve the reserved capacity contract. Check this
    /// before any other-family advertised/capacity state is committed.
    pub(in crate::manager) fn preflight_admitted_with_checkpoint<A>(
        &mut self,
        handle: ProvenanceHandle,
        announcements: A,
        withdrawals: &[EvpnRouteKey],
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<bool, Exhaustion>
    where
        A: DoubleEndedIterator<Item = EvpnRouteKey> + ExactSizeIterator + Clone,
    {
        let Some(index) = self.checked_handle_index(handle)? else {
            return Ok(false);
        };
        if !self.records[index].primary || !matches!(self.records[index].state, State::Ready) {
            return Ok(false);
        }
        if self.records[index].universe.is_some() {
            return match Self::shared_batch_capacity(
                self.view(index),
                announcements,
                withdrawals,
                checkpoint,
            ) {
                Ok(capacity) if capacity <= self.records[index].keys.capacity() => Ok(true),
                Ok(_) => Err(self.mark_exhausted(handle, Self::admission_invariant())),
                Err(error) => Err(self.mark_exhausted(handle, error)),
            };
        }
        match Self::planned_len(
            self.records[index].keys.as_slice(),
            announcements,
            withdrawals,
            true,
            checkpoint,
        ) {
            Ok(length) if length <= self.records[index].keys.capacity() => Ok(true),
            Ok(_) => Err(self.mark_exhausted(handle, Self::admission_invariant())),
            Err(error) => Err(self.mark_exhausted(handle, error)),
        }
    }

    #[cfg(test)]
    pub(in crate::manager) fn reserve_admission<A>(
        &mut self,
        handle: ProvenanceHandle,
        announcements: A,
        withdrawals: &[EvpnRouteKey],
    ) -> Result<bool, Exhaustion>
    where
        A: DoubleEndedIterator<Item = EvpnRouteKey> + ExactSizeIterator + Clone,
    {
        self.reserve_admission_with_checkpoint(handle, announcements, withdrawals, &mut |_| {})
    }

    #[cfg(test)]
    pub(in crate::manager) fn apply_admitted<A>(
        &mut self,
        handle: ProvenanceHandle,
        announcements: A,
        withdrawals: &[EvpnRouteKey],
    ) -> Result<bool, Exhaustion>
    where
        A: DoubleEndedIterator<Item = EvpnRouteKey> + ExactSizeIterator + Clone,
    {
        self.apply_admitted_with_checkpoint(handle, announcements, withdrawals, &mut |_| {})
    }

    #[cfg(test)]
    pub(in crate::manager) fn preflight_admitted<A>(
        &mut self,
        handle: ProvenanceHandle,
        announcements: A,
        withdrawals: &[EvpnRouteKey],
    ) -> Result<bool, Exhaustion>
    where
        A: DoubleEndedIterator<Item = EvpnRouteKey> + ExactSizeIterator + Clone,
    {
        self.preflight_admitted_with_checkpoint(handle, announcements, withdrawals, &mut |_| {})
    }

    fn sorted_match(
        keys: &[EvpnRouteKey],
        cursor: &mut Option<usize>,
        key: EvpnRouteKey,
        checkpoint: &mut impl FnMut(bool),
    ) -> Option<usize> {
        let position = cursor.get_or_insert_with(|| {
            keys.partition_point(|prior| {
                checkpoint(false);
                *prior < key
            })
        });
        while let Some(prior) = keys.get(*position) {
            checkpoint(false);
            match prior.cmp(&key) {
                std::cmp::Ordering::Less => *position += 1,
                std::cmp::Ordering::Equal => return Some(*position),
                std::cmp::Ordering::Greater => return None,
            }
        }
        None
    }

    fn shared_batch_capacity<A: Iterator<Item = EvpnRouteKey>>(
        proof: EvpnProofView<'_>,
        announcements: A,
        withdrawals: &[EvpnRouteKey],
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<usize, Exhaustion> {
        let mut previous = None;
        let mut base = None;
        let mut sparse = None;
        for &key in withdrawals {
            checkpoint(false);
            if previous.is_some_and(|prior| prior >= key) {
                return Err(Self::admission_invariant());
            }
            let admitted = Self::sorted_match(proof.universe, &mut base, key, checkpoint)
                .map_or_else(
                    || Self::sorted_match(proof.sparse, &mut sparse, key, checkpoint).is_some(),
                    |position| proof.words[position / 64] & (1_u64 << (position % 64)) != 0,
                );
            if !admitted {
                return Err(Self::admission_invariant());
            }
            previous = Some(key);
        }
        previous = None;
        let mut capacity = proof.sparse.len();
        for key in announcements {
            checkpoint(false);
            if previous.is_some_and(|prior| prior >= key) {
                return Err(Self::admission_invariant());
            }
            previous = Some(key);
            let in_base = proof
                .universe
                .binary_search_by(|prior| {
                    checkpoint(false);
                    prior.cmp(&key)
                })
                .is_ok();
            if !in_base
                && proof
                    .sparse
                    .binary_search_by(|prior| {
                        checkpoint(false);
                        prior.cmp(&key)
                    })
                    .is_err()
            {
                capacity = capacity.checked_add(1).ok_or_else(Self::overflow)?;
            }
        }
        Ok(capacity)
    }

    fn apply_shared<A>(
        &mut self,
        handle: ProvenanceHandle,
        index: usize,
        announcements: A,
        withdrawals: &[EvpnRouteKey],
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<bool, Exhaustion>
    where
        A: DoubleEndedIterator<Item = EvpnRouteKey> + ExactSizeIterator + Clone,
    {
        let capacity = match Self::shared_batch_capacity(
            self.view(index),
            announcements.clone(),
            withdrawals,
            checkpoint,
        ) {
            Ok(capacity) => capacity,
            Err(error) => return Err(self.mark_exhausted(handle, error)),
        };
        if capacity > self.records[index].keys.capacity() {
            return Err(self.mark_exhausted(handle, Self::admission_invariant()));
        }
        let universe = self
            .universe_index(self.records[index].universe.expect("shared record"))
            .expect("owned universe");
        let raw = self.universes[universe].keys.as_slice();
        let record = &mut self.records[index];
        let mut cursor = None;
        for &key in withdrawals {
            checkpoint(false);
            if let Some(position) = Self::sorted_match(raw, &mut cursor, key, checkpoint) {
                record.words[position / 64] &= !(1_u64 << (position % 64));
                record.masked -= 1;
            }
        }
        let mut withdrawn = 0;
        record.keys.retain(|key| {
            checkpoint(false);
            while withdrawals
                .get(withdrawn)
                .is_some_and(|withdrawn| withdrawn < key)
            {
                checkpoint(false);
                withdrawn += 1;
            }
            withdrawals.get(withdrawn) != Some(key)
        });
        let old_len = record.keys.len();
        for key in announcements {
            checkpoint(false);
            if let Ok(position) = raw.binary_search_by(|prior| {
                checkpoint(false);
                prior.cmp(&key)
            }) {
                let bit = 1_u64 << (position % 64);
                if record.words[position / 64] & bit == 0 {
                    record.words[position / 64] |= bit;
                    record.masked += 1;
                }
            } else if record.keys[..old_len]
                .binary_search_by(|prior| {
                    checkpoint(false);
                    prior.cmp(&key)
                })
                .is_err()
            {
                record.keys.push(key);
            }
        }
        if record.keys.len() != old_len {
            Self::sort_keys(&mut record.keys, checkpoint);
        }
        Ok(true)
    }

    fn free_keys(&mut self, index: usize) {
        let record = &mut self.records[index];
        let bytes = record.keys.capacity() * size_of::<EvpnRouteKey>()
            + record.words.capacity() * size_of::<u64>();
        let peer = record.handle.owner.peer;
        let charge = bytes + record.universe_charge;
        let universe = record.universe.take();
        record.universe_charge = 0;
        record.masked = 0;
        record.keys.clear();
        record
            .keys
            .try_grow(0)
            .expect("empty pinned SmallVec deallocation cannot fail");
        record.words.clear();
        record
            .words
            .try_grow(0)
            .expect("empty pinned SmallVec deallocation cannot fail");
        self.daemon_used -= bytes;
        self.set_peer_retained(peer, self.peer_usage(peer).retained - charge);
        if let Some(universe) = universe {
            let position = self
                .universe_index(universe)
                .expect("owned universe exists");
            self.universes[position].references -= 1;
            self.release_universe(universe);
        }
    }

    /// Free the allocation before returning its credits. Empty clear alone
    /// would leave capacity charged. Exhaustion cannot become a fresh capture.
    pub(in crate::manager) fn finish_recovery(
        &mut self,
        handle: ProvenanceHandle,
    ) -> Result<bool, Exhaustion> {
        let Some(index) = self.checked_handle_index(handle)? else {
            return Ok(false);
        };
        if !self.records[index].primary || !matches!(self.records[index].state, State::Ready) {
            return Ok(false);
        }
        self.free_keys(index);
        self.records[index].state = State::Dormant;
        Ok(true)
    }

    /// Release this member and all its ledger-owned snapshots. The primary
    /// handle fences a replacement, even if its peer/session tuple is reused.
    pub(in crate::manager) fn retire_member(&mut self, handle: ProvenanceHandle) -> bool {
        let Some(index) = self.index(handle) else {
            return false;
        };
        if !self.records[index].primary {
            return false;
        }
        while let Some(owned) = self.records[self.owner_range(handle.owner)]
            .iter()
            .find_map(|record| {
                (record.handle.generation == handle.generation).then_some(record.handle)
            })
        {
            self.retire(owned);
        }
        true
    }

    /// Retiring a handle cannot free a replacement record, even if ownership
    /// was re-registered with the same peer/session tuple.
    pub(in crate::manager) fn retire(&mut self, handle: ProvenanceHandle) -> bool {
        let Some(index) = self.index(handle) else {
            return false;
        };
        self.free_keys(index);
        let retained = self.peer_usage(handle.owner.peer).retained - self.records[index].charge();
        drop(self.records.remove(index));
        self.set_peer_retained(handle.owner.peer, retained);
        // Vacant outer capacity remains daemon-charged until it is freed.
        if self.records.is_empty() {
            let bytes = self.records.capacity() * size_of::<Record>();
            self.records
                .try_grow(0)
                .expect("empty pinned SmallVec deallocation cannot fail");
            self.daemon_used -= bytes;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use rustbgpd_wire::{EthernetTagId, RouteDistinguisher};

    fn owner(peer: u8, session_id: u64) -> PeerSession {
        PeerSession {
            peer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, peer)),
            session_id,
        }
    }

    fn key(n: u32) -> EvpnRouteKey {
        EvpnRouteKey::Imet {
            rd: RouteDistinguisher::ZERO,
            ethernet_tag: EthernetTagId(n),
            originator_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        }
    }

    fn capture(
        ledger: &mut EvpnRecoveryProvenance,
        handle: ProvenanceHandle,
        keys: &[EvpnRouteKey],
    ) {
        assert!(ledger.finish_recovery(handle).unwrap());
        assert!(ledger.begin_capture(handle).unwrap());
        for &key in keys {
            assert!(ledger.capture_key(handle, key).unwrap());
        }
        assert!(ledger.seal_capture(handle).unwrap());
    }

    fn capacity(ledger: &EvpnRecoveryProvenance, handle: ProvenanceHandle) -> usize {
        ledger.records[ledger.index(handle).unwrap()]
            .keys
            .capacity()
    }

    fn assert_running_charges(ledger: &EvpnRecoveryProvenance) {
        let mut daemon =
            size_of::<EvpnRecoveryProvenance>() + ledger.records.capacity() * size_of::<Record>();
        daemon += ledger.universes.capacity() * size_of::<Universe>();
        daemon += ledger
            .universes
            .iter()
            .map(|universe| universe.keys.capacity() * size_of::<EvpnRouteKey>())
            .sum::<usize>();
        for record in &ledger.records {
            daemon += record.keys.capacity() * size_of::<EvpnRouteKey>()
                + record.words.capacity() * size_of::<u64>();
            let expected: usize = ledger
                .records
                .iter()
                .filter(|other| other.handle.owner.peer == record.handle.owner.peer)
                .map(Record::charge)
                .sum();
            assert_eq!(record.peer_retained, expected);
            assert_eq!(
                ledger.peer_usage(record.handle.owner.peer).retained,
                expected
            );
            assert!(record.peer_peak >= expected);
        }
        assert_eq!(ledger.daemon_usage().retained, daemon);
    }

    #[test]
    fn cached_peer_totals_follow_growth_snapshot_failure_and_retirement() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let first = ledger.register(owner(1, 7)).unwrap();
        let second = ledger.register(owner(1, 8)).unwrap();
        let other = ledger.register(owner(2, 9)).unwrap();
        assert_running_charges(&ledger);
        capture(&mut ledger, first, &[key(1), key(2), key(3)]);
        assert_running_charges(&ledger);
        let snapshot = ledger.snapshot(first).unwrap().unwrap();
        assert_running_charges(&ledger);
        let before = ledger.daemon_usage().retained;
        ledger.fail_next_allocation_for_test();
        let error = ledger.snapshot(first).unwrap_err();
        assert_eq!(error.cause, ExhaustionCause::AllocationFailure);
        assert_eq!(ledger.daemon_usage().retained, before);
        assert_running_charges(&ledger);
        assert_eq!(
            ledger.proof_keys(snapshot),
            Err(error),
            "matching snapshots inherit primary refusal"
        );
        assert!(ledger.retire_member(first));
        assert_running_charges(&ledger);
        capture(&mut ledger, second, &[key(4), key(5)]);
        assert_running_charges(&ledger);
        assert!(ledger.finish_recovery(second).unwrap());
        assert_running_charges(&ledger);
        assert!(ledger.retire_member(second));
        assert_running_charges(&ledger);
        assert!(ledger.retire_member(other));
        assert_running_charges(&ledger);
        assert_eq!(ledger.peer_usage(owner(1, 7).peer).retained, 0);
    }

    #[test]
    fn exact_handle_lookup_keeps_old_snapshot_exhaustion_off_replacement() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let first = ledger.register(owner(1, 7)).unwrap();
        capture(&mut ledger, first, &[key(1)]);
        let snapshot = ledger.snapshot(first).unwrap().unwrap();
        assert!(ledger.fail_admission(first));
        assert!(ledger.proof_keys(snapshot).is_err());
        assert!(ledger.retire(first));
        let replacement = ledger.register(first.owner).unwrap();
        assert_eq!(ledger.primary_handle(first.owner), Some(replacement));
        assert_eq!(ledger.exhaustion(snapshot), None);
        assert_eq!(
            ledger.proof_keys(snapshot).unwrap(),
            Some([key(1)].to_vec())
        );
        assert_eq!(ledger.proof_keys(replacement).unwrap(), Some([].to_vec()));
        assert!(!ledger.abort_capture(snapshot));
        assert!(!ledger.mark_reset_admitted(snapshot));
        assert!(ledger.retire(snapshot));
        assert_running_charges(&ledger);
    }
    #[test]
    fn fresh_proof_capture_and_retained_capacity_have_distinct_lifetimes() {
        let mut ledger = EvpnRecoveryProvenance::new();
        assert_eq!(ledger.limits(), (PEER_LIMIT_BYTES, DAEMON_LIMIT_BYTES));
        let handle = ledger.register(owner(1, 7)).unwrap();
        assert_eq!(ledger.proof_keys(handle).unwrap(), Some([].to_vec()));
        assert!(!ledger.begin_capture(handle).unwrap());
        assert!(ledger.finish_recovery(handle).unwrap());
        assert_eq!(ledger.proof_keys(handle).unwrap(), None);
        assert!(ledger.begin_capture(handle).unwrap());
        for n in [3, 1, 3, 2] {
            assert!(ledger.capture_key(handle, key(n)).unwrap());
        }
        assert_eq!(ledger.proof_keys(handle).unwrap(), None);
        assert!(!ledger.finish_recovery(handle).unwrap());
        let before_seal = ledger.daemon_usage().retained;
        assert!(ledger.seal_capture(handle).unwrap());
        assert_eq!(
            ledger.proof_keys(handle).unwrap(),
            Some([key(1), key(2), key(3)].to_vec())
        );
        assert_eq!(ledger.daemon_usage().retained, before_seal);
        assert_eq!(capacity(&ledger, handle), 4);
        let before_delete = ledger.daemon_usage().retained;
        assert!(
            ledger
                .apply_admitted(handle, [].into_iter(), &[key(1), key(2), key(3)])
                .unwrap()
        );
        assert_eq!(ledger.proof_keys(handle).unwrap(), Some([].to_vec()));
        assert_eq!(ledger.daemon_usage().retained, before_delete);
        assert_eq!(capacity(&ledger, handle), 4);
        assert!(ledger.finish_recovery(handle).unwrap());
        assert_eq!(capacity(&ledger, handle), 0);
        assert_eq!(
            ledger.daemon_usage().retained,
            before_delete - 4 * size_of::<EvpnRouteKey>()
        );
        assert!(ledger.retire_member(handle));
        assert_eq!(
            ledger.daemon_usage().retained,
            size_of::<EvpnRecoveryProvenance>()
        );
    }

    #[test]
    fn accepted_union_is_in_place_and_replay_does_not_allocate() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let handle = ledger.register(owner(1, 7)).unwrap();
        capture(&mut ledger, handle, &[key(1), key(3), key(5)]);
        let before = ledger.daemon_usage();
        ledger.fail_next_allocation = true;
        assert!(
            ledger
                .apply_admitted(
                    handle,
                    [key(2), key(3), key(4)].into_iter(),
                    &[key(1), key(5)]
                )
                .unwrap()
        );
        assert_eq!(
            ledger.proof_keys(handle).unwrap(),
            Some([key(2), key(3), key(4)].to_vec())
        );
        assert!(
            ledger
                .apply_admitted(handle, [key(2), key(3), key(4)].into_iter(), &[])
                .unwrap()
        );
        assert!(
            ledger
                .apply_admitted(handle, [key(3)].into_iter(), &[key(3)])
                .unwrap()
        );
        assert_eq!(ledger.daemon_usage(), before);
        assert!(ledger.fail_next_allocation);
        let error = ledger
            .reserve_admission(handle, [key(5), key(6)].into_iter(), &[])
            .unwrap_err();
        assert_eq!(error.cause, ExhaustionCause::AllocationFailure);
        assert!(!ledger.fail_next_allocation);
        assert_eq!(capacity(&ledger, handle), 4);
        assert_eq!(ledger.daemon_usage().retained, before.retained);
        assert_eq!(
            ledger.records[ledger.index(handle).unwrap()]
                .keys
                .as_slice(),
            &[key(2), key(3), key(4)]
        );
        assert_eq!(ledger.proof_keys(handle), Err(error));
        assert_eq!(ledger.begin_capture(handle), Err(error));
        assert_eq!(ledger.finish_recovery(handle), Err(error));
        assert!(ledger.retire_member(handle));
    }

    #[test]
    fn flat_admission_checkpoints_validation_allocation_and_final_merge() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let handle = ledger.register(owner(1, 7)).unwrap();
        let original: Vec<_> = (1..=128).map(key).collect();
        capture(&mut ledger, handle, &original);
        assert!(
            ledger.records[ledger.index(handle).unwrap()]
                .universe
                .is_none()
        );
        let announcements = [key(129), key(130)];
        let withdrawals = [key(1), key(128)];
        let mut reserved_visits = 0;
        let mut allocation_edges = 0;
        assert!(
            ledger
                .reserve_admission_with_checkpoint(
                    handle,
                    announcements.into_iter(),
                    &withdrawals,
                    &mut |force| {
                        if force {
                            allocation_edges += 1;
                        } else {
                            reserved_visits += 1;
                        }
                    },
                )
                .unwrap()
        );
        assert!(reserved_visits >= original.len());
        assert_eq!(allocation_edges, 2);
        assert_eq!(ledger.proof_keys(handle).unwrap(), Some(original.clone()));
        let mut preflight_visits = 0;
        assert!(
            ledger
                .preflight_admitted_with_checkpoint(
                    handle,
                    announcements.into_iter(),
                    &withdrawals,
                    &mut |_| preflight_visits += 1,
                )
                .unwrap()
        );
        assert!(preflight_visits >= original.len());
        let mut applied_visits = 0;
        ledger.fail_next_allocation_for_test();
        assert!(
            ledger
                .apply_admitted_with_checkpoint(
                    handle,
                    announcements.into_iter(),
                    &withdrawals,
                    &mut |_| applied_visits += 1,
                )
                .unwrap()
        );
        // In addition to final validation, both retained OLD keys and every
        // merged result are visited. A wrapper-only callback cannot meet this.
        assert!(applied_visits >= preflight_visits + 2 * original.len());
        assert_eq!(
            ledger.proof_keys(handle).unwrap(),
            Some((2..128).chain(129..=130).map(key).collect())
        );
        assert!(ledger.fail_next_allocation);
        allocation_edges = 0;
        let error = ledger
            .reserve_admission_with_checkpoint(
                handle,
                [key(131), key(132), key(133)].into_iter(),
                &[],
                &mut |force| allocation_edges += usize::from(force),
            )
            .unwrap_err();
        assert_eq!(error.cause, ExhaustionCause::AllocationFailure);
        assert_eq!(allocation_edges, 2, "failed growth is also bracketed");
        assert_running_charges(&ledger);
    }

    #[test]
    fn candidate_reservation_ignores_withdraw_credit_and_final_apply_does_not_allocate() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let handle = ledger.register(owner(1, 7)).unwrap();
        assert!(
            ledger
                .reserve_admission(handle, [key(1), key(3), key(5)].into_iter(), &[])
                .unwrap()
        );
        assert!(
            ledger
                .apply_admitted(handle, [key(1), key(3), key(5)].into_iter(), &[])
                .unwrap()
        );
        assert!(
            ledger
                .reserve_admission(
                    handle,
                    [key(2), key(3), key(4)].into_iter(),
                    &[key(1), key(5)]
                )
                .unwrap()
        );
        // The true union has five keys; oldlen + anncount would charge six.
        assert_eq!(capacity(&ledger, handle), 5);
        assert_eq!(
            ledger.proof_keys(handle).unwrap(),
            Some([key(1), key(3), key(5)].to_vec())
        );
        let reserved = ledger.daemon_usage();
        ledger.fail_next_allocation_for_test();
        // Final gates dropped one ANN and both candidate withdrawals.
        assert!(
            ledger
                .apply_admitted(handle, [key(2), key(3)].into_iter(), &[])
                .unwrap()
        );
        assert_eq!(
            ledger.proof_keys(handle).unwrap(),
            Some([key(1), key(2), key(3), key(5)].to_vec())
        );
        assert!(
            ledger
                .reserve_admission(handle, [key(1), key(2), key(3), key(5)].into_iter(), &[])
                .unwrap()
        );
        assert_eq!(ledger.daemon_usage(), reserved);
        assert!(ledger.fail_next_allocation);
    }

    #[test]
    fn exhausted_reset_handoff_is_charged_primary_state_and_generation_fenced() {
        let mut ledger =
            EvpnRecoveryProvenance::with_test_limits(PEER_LIMIT_BYTES, DAEMON_LIMIT_BYTES);
        let handle = ledger.register(owner(1, 7)).unwrap();
        assert!(!ledger.is_dormant(handle));
        assert!(!ledger.mark_reset_admitted(handle));
        assert!(
            ledger
                .reserve_admission(handle, [key(1)].into_iter(), &[])
                .unwrap()
        );
        assert!(
            ledger
                .apply_admitted(handle, [key(1)].into_iter(), &[])
                .unwrap()
        );
        let snapshot = ledger.snapshot(handle).unwrap().unwrap();
        let retained = ledger.daemon_usage().retained;
        ledger.fail_next_allocation_for_test();
        let error = ledger
            .reserve_admission(handle, [key(2), key(3)].into_iter(), &[])
            .unwrap_err();
        assert_eq!(error.cause, ExhaustionCause::AllocationFailure);
        assert_eq!(ledger.daemon_usage().retained, retained);
        assert_eq!(
            ledger.records[ledger.index(handle).unwrap()]
                .keys
                .as_slice(),
            &[key(1)]
        );
        assert_eq!(ledger.exhaustion(handle), Some(error));
        assert!(!ledger.reset_admitted(handle));
        assert!(!ledger.mark_reset_admitted(snapshot));
        assert!(!ledger.reset_admitted(snapshot));
        assert!(ledger.mark_reset_admitted(handle));
        assert!(ledger.reset_admitted(handle));
        assert!(!ledger.mark_reset_admitted(handle));
        assert!(!ledger.is_dormant(handle));
        assert!(ledger.retire_member(handle));
        let replacement = ledger.register(handle.owner).unwrap();
        assert!(!ledger.reset_admitted(replacement));
        assert!(!ledger.mark_reset_admitted(handle));
        assert!(!ledger.reset_admitted(handle));
        assert_eq!(ledger.exhaustion(replacement), None);
        assert!(ledger.finish_recovery(replacement).unwrap());
        assert!(ledger.is_dormant(replacement));
        assert!(ledger.begin_capture(replacement).unwrap());
        assert!(!ledger.is_dormant(replacement));
        assert!(!ledger.finish_recovery(replacement).unwrap());
    }

    #[test]
    fn accepted_batches_match_set_semantics_for_all_small_interleavings() {
        use std::collections::BTreeSet;

        for old_mask in 0_u32..16 {
            for withdrawn_mask in 0_u32..16 {
                if withdrawn_mask & !old_mask != 0 {
                    continue;
                }
                for announced_mask in 0_u32..16 {
                    let select = |mask| {
                        (0..4)
                            .filter(|n| mask & (1 << n) != 0)
                            .map(key)
                            .collect::<Vec<_>>()
                    };
                    let old = select(old_mask);
                    let withdrawn = select(withdrawn_mask);
                    let announced = select(announced_mask);
                    let mut expected: BTreeSet<_> = old.iter().copied().collect();
                    for key in &withdrawn {
                        expected.remove(key);
                    }
                    expected.extend(announced.iter().copied());
                    let mut ledger = EvpnRecoveryProvenance::new();
                    let handle = ledger.register(owner(1, 7)).unwrap();
                    assert!(
                        ledger
                            .reserve_admission(handle, old.iter().copied(), &[])
                            .unwrap()
                    );
                    assert!(
                        ledger
                            .apply_admitted(handle, old.iter().copied(), &[])
                            .unwrap()
                    );
                    assert!(
                        ledger
                            .reserve_admission(handle, announced.iter().copied(), &withdrawn)
                            .unwrap()
                    );
                    assert!(
                        ledger
                            .apply_admitted(handle, announced.iter().copied(), &withdrawn)
                            .unwrap()
                    );
                    assert_eq!(
                        ledger.proof_keys(handle).unwrap().unwrap(),
                        expected.into_iter().collect::<Vec<_>>()
                    );
                }
            }
        }
    }

    #[test]
    fn peer_limit_includes_old_and_new_capacity_during_growth() {
        let record = size_of::<Record>();
        let key_size = size_of::<EvpnRouteKey>();
        let limit = record + 24 * key_size + size_of::<Keys>();
        let mut ledger = EvpnRecoveryProvenance::with_limits(limit, DAEMON_LIMIT_BYTES);
        let handle = ledger.register(owner(1, 7)).unwrap();
        assert!(ledger.finish_recovery(handle).unwrap());
        assert!(ledger.begin_capture(handle).unwrap());
        for n in 1..=16 {
            assert!(ledger.capture_key(handle, key(n)).unwrap());
        }
        assert_eq!(capacity(&ledger, handle), 16);
        assert_eq!(ledger.peer_usage(handle.owner.peer).peak, limit);
        let retained = ledger.daemon_usage().retained;
        let error = ledger.capture_key(handle, key(17)).unwrap_err();
        assert_eq!(error.cause, ExhaustionCause::PeerLimit);
        assert_eq!(
            error.attempted_peer_bytes,
            record + 48 * key_size + size_of::<Keys>()
        );
        assert_eq!(capacity(&ledger, handle), 16);
        assert_eq!(ledger.daemon_usage().retained, retained);
        assert_eq!(ledger.seal_capture(handle), Err(error));
        assert_eq!(ledger.register(handle.owner).unwrap(), handle);
        assert!(ledger.retire_member(handle));
    }

    #[test]
    fn metadata_headers_and_retained_generations_share_the_peer_cap() {
        let record = size_of::<Record>();
        let mut ledger = EvpnRecoveryProvenance::with_limits(4 * record, DAEMON_LIMIT_BYTES);
        let first = ledger.register(owner(1, 1)).unwrap();
        let second = ledger.register(owner(1, 2)).unwrap();
        assert_eq!(ledger.peer_usage(first.owner.peer).retained, 2 * record);
        assert_eq!(ledger.peer_usage(first.owner.peer).peak, 4 * record);
        let retained = ledger.daemon_usage().retained;
        let error = ledger.register(owner(1, 3)).unwrap_err();
        assert_eq!(error.cause, ExhaustionCause::PeerLimit);
        assert_eq!(error.attempted_peer_bytes, 6 * record);
        assert_eq!(ledger.records.len(), 2);
        assert_eq!(ledger.daemon_usage().retained, retained);
        assert_eq!(ledger.proof_keys(first).unwrap(), Some([].to_vec()));
        assert_eq!(ledger.proof_keys(second).unwrap(), Some([].to_vec()));
    }

    #[test]
    fn metadata_refusal_names_the_retained_peer_whose_copies_exceed_its_cap() {
        let record = size_of::<Record>();
        let mut ledger = EvpnRecoveryProvenance::with_test_limits(3 * record, DAEMON_LIMIT_BYTES);
        ledger.register(owner(3, 1)).unwrap();
        ledger.register(owner(4, 1)).unwrap();
        let first_b = ledger.register(owner(2, 1)).unwrap();
        let second_b = ledger.register(owner(2, 2)).unwrap();
        assert_eq!(ledger.records.capacity(), 4);
        assert_eq!(ledger.peer_usage(first_b.owner.peer).peak, 3 * record);
        let before = ledger.daemon_usage();
        let initiating_a = owner(1, 1);
        let error = ledger.register(initiating_a).unwrap_err();
        assert_eq!(error.cause, ExhaustionCause::PeerLimit);
        assert_eq!(error.limiting_peer, Some(first_b.owner.peer));
        assert_eq!(error.attempted_peer_bytes, 4 * record);
        assert_eq!(ledger.primary_handle(initiating_a), None);
        assert_eq!(ledger.records.capacity(), 4);
        assert_eq!(ledger.daemon_usage(), before);
        for handle in [first_b, second_b] {
            assert_eq!(ledger.proof_keys(handle).unwrap(), Some([].to_vec()));
            assert_eq!(ledger.exhaustion(handle), None);
            assert_eq!(ledger.primary_handle(handle.owner), Some(handle));
        }
    }

    #[test]
    fn snapshots_remain_owned_and_charged_until_explicit_retirement() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let handle = ledger.register(owner(1, 7)).unwrap();
        capture(&mut ledger, handle, &[key(1), key(2)]);
        let snapshot = ledger.snapshot(handle).unwrap().unwrap();
        let after_snapshot = ledger.daemon_usage().retained;
        assert_eq!(capacity(&ledger, snapshot), 2);
        assert!(
            ledger
                .apply_admitted(handle, [key(3)].into_iter(), &[key(1)])
                .unwrap()
        );
        assert_eq!(
            ledger.proof_keys(handle).unwrap(),
            Some([key(2), key(3)].to_vec())
        );
        assert_eq!(
            ledger.proof_keys(snapshot).unwrap(),
            Some([key(1), key(2)].to_vec())
        );
        assert!(
            !ledger
                .apply_admitted(snapshot, [].into_iter(), &[key(1)])
                .unwrap()
        );
        assert!(!ledger.finish_recovery(snapshot).unwrap());
        assert_eq!(ledger.daemon_usage().retained, after_snapshot);
        assert!(ledger.retire_member(handle));
        assert_eq!(
            ledger.daemon_usage().retained,
            size_of::<EvpnRecoveryProvenance>()
        );
        assert_eq!(ledger.proof_keys(snapshot).unwrap(), None);
        assert!(!ledger.retire(snapshot));
    }

    #[test]
    fn old_snapshot_failure_and_release_cannot_touch_replacement_generation() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let first = ledger.register(owner(1, 7)).unwrap();
        capture(&mut ledger, first, &[key(1)]);
        let old = ledger.snapshot(first).unwrap().unwrap();
        assert!(ledger.retire(first));
        let replacement = ledger.register(first.owner).unwrap();
        assert_ne!(replacement, first);
        assert_ne!(replacement.generation, old.generation);
        ledger.fail_next_allocation = true;
        assert_eq!(
            ledger.snapshot(old).unwrap_err().cause,
            ExhaustionCause::AllocationFailure
        );
        assert_eq!(ledger.proof_keys(replacement).unwrap(), Some([].to_vec()));
        assert!(!ledger.retire_member(first));
        assert!(!ledger.retire(first));
        assert!(ledger.retire(old));
        assert_eq!(ledger.proof_keys(replacement).unwrap(), Some([].to_vec()));
        assert!(ledger.retire_member(replacement));
    }

    #[test]
    fn retained_snapshot_preserves_peer_peak_without_claiming_membership() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let session = owner(1, 7);
        let first = ledger.register(session).unwrap();
        let keys: Vec<_> = (1..=64).map(key).collect();
        assert!(
            ledger
                .reserve_admission(first, keys.iter().copied(), &[])
                .unwrap()
        );
        assert!(
            ledger
                .apply_admitted(first, keys.iter().copied(), &[])
                .unwrap()
        );
        let snapshot = ledger.snapshot(first).unwrap().unwrap();
        let peak = ledger.peer_usage(session.peer).peak;
        assert_eq!(ledger.primary_handle(session), Some(first));
        assert!(ledger.retire(first));
        assert_eq!(ledger.primary_handle(session), None);
        assert_eq!(ledger.peer_usage(session.peer).peak, peak);
        let replacement = ledger.register(session).unwrap();
        assert_eq!(ledger.primary_handle(session), Some(replacement));
        assert!(!ledger.retire_member(first));
        assert!(ledger.retire(snapshot));
        assert_eq!(ledger.peer_usage(session.peer).peak, peak);
        assert_eq!(
            ledger.peer_usage(session.peer).retained,
            size_of::<Record>()
        );
        assert_eq!(ledger.proof_keys(first).unwrap(), None);
        assert_eq!(ledger.proof_keys(replacement).unwrap(), Some([].to_vec()));
        assert!(ledger.finish_recovery(replacement).unwrap());
        assert_eq!(ledger.primary_handle(session), Some(replacement));
        assert!(ledger.retire_member(replacement));
        assert_eq!(ledger.primary_handle(session), None);
        assert_eq!(
            ledger.peer_usage(session.peer),
            Usage {
                retained: 0,
                peak: 0
            }
        );
    }

    #[test]
    fn daemon_limit_covers_snapshot_overlap_and_retained_metadata_slack() {
        let header = size_of::<EvpnRecoveryProvenance>();
        let record = size_of::<Record>();
        let key_size = size_of::<EvpnRouteKey>();
        let limit = header + 7 * record + 128 * key_size + size_of::<Records>();
        let mut ledger = EvpnRecoveryProvenance::with_limits(PEER_LIMIT_BYTES, limit);
        let first = ledger.register(owner(1, 7)).unwrap();
        let second = ledger.register(owner(2, 7)).unwrap();
        let keys: Vec<_> = (1..=64).map(key).collect();
        assert!(
            ledger
                .reserve_admission(first, keys.iter().copied(), &[])
                .unwrap()
        );
        assert!(
            ledger
                .reserve_admission(second, keys.iter().copied(), &[])
                .unwrap()
        );
        assert!(
            ledger
                .apply_admitted(first, keys.iter().copied(), &[])
                .unwrap()
        );
        assert!(
            ledger
                .apply_admitted(second, keys.iter().copied(), &[])
                .unwrap()
        );
        assert_eq!(ledger.records.capacity(), 2);
        let error = ledger.snapshot(first).unwrap_err();
        assert_eq!(error.cause, ExhaustionCause::DaemonLimit);
        assert_eq!(ledger.records.len(), 2);
        assert_eq!(ledger.records.capacity(), 4);
        assert_eq!(
            ledger.daemon_usage().retained,
            header + 4 * record + 128 * key_size
        );
        assert_eq!(ledger.proof_keys(first), Err(error));
        assert_eq!(ledger.proof_keys(second).unwrap(), Some(keys.clone()));
        assert!(ledger.retire_member(first));
        assert!(ledger.retire_member(second));
        assert_eq!(ledger.daemon_usage().retained, header);
    }

    #[test]
    fn allocation_failure_rolls_back_credits_and_keeps_reserved_peak() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let empty = ledger.daemon_usage().retained;
        ledger.fail_next_allocation = true;
        let error = ledger.register(owner(1, 7)).unwrap_err();
        assert_eq!(error.cause, ExhaustionCause::AllocationFailure);
        assert_eq!(ledger.daemon_usage().retained, empty);
        assert!(ledger.records.is_empty());
        let handle = ledger.register(owner(1, 7)).unwrap();
        let before = ledger.daemon_usage().retained;
        ledger.fail_next_allocation = true;
        let error = ledger.snapshot(handle).unwrap_err();
        assert_eq!(error.cause, ExhaustionCause::AllocationFailure);
        assert_eq!(ledger.daemon_usage().retained, before);
        assert_eq!(
            ledger.peer_usage(handle.owner.peer).peak,
            4 * size_of::<Record>()
        );
        assert_eq!(ledger.proof_keys(handle), Err(error));
        assert!(ledger.retire_member(handle));
    }

    #[test]
    fn checked_overflow_fails_closed_without_allocation() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let handle = ledger.register(owner(1, 7)).unwrap();
        let before = ledger.daemon_usage().retained;
        let error = ledger.grow_keys(handle, usize::MAX).unwrap_err();
        assert_eq!(error.cause, ExhaustionCause::AllocationFailure);
        assert_eq!(error.attempted_peer_bytes, usize::MAX);
        assert_eq!(ledger.daemon_usage().retained, before);
        ledger.mark_exhausted(handle, error);
        assert_eq!(ledger.proof_keys(handle), Err(error));
        assert!(ledger.retire_member(handle));
        ledger.next_id = u64::MAX;
        assert_eq!(
            ledger.register(owner(1, 7)).unwrap_err().cause,
            ExhaustionCause::AllocationFailure
        );
        assert!(ledger.records.is_empty());
    }

    #[test]
    fn exhaustion_cause_names_are_bounded() {
        assert_eq!(ExhaustionCause::PeerLimit.as_str(), "peer_limit");
        assert_eq!(ExhaustionCause::DaemonLimit.as_str(), "daemon_limit");
        assert_eq!(
            ExhaustionCause::AllocationFailure.as_str(),
            "allocation_failure"
        );
    }

    #[test]
    fn unknown_withdrawal_is_not_admitted() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let handle = ledger.register(owner(1, 7)).unwrap();
        assert_eq!(
            ledger
                .apply_admitted(handle, [].into_iter(), &[key(1)])
                .unwrap_err()
                .cause,
            ExhaustionCause::AdmissionInvariant
        );
    }

    #[test]
    fn duplicate_withdrawal_is_not_admitted() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let handle = ledger.register(owner(1, 7)).unwrap();
        assert!(
            ledger
                .reserve_admission(handle, [key(1)].into_iter(), &[])
                .unwrap()
        );
        ledger
            .apply_admitted(handle, [key(1)].into_iter(), &[])
            .unwrap();
        assert_eq!(
            ledger
                .apply_admitted(handle, [].into_iter(), &[key(1), key(1)])
                .unwrap_err()
                .cause,
            ExhaustionCause::AdmissionInvariant
        );
    }

    #[test]
    fn unordered_accepted_batch_is_not_admitted() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let handle = ledger.register(owner(1, 7)).unwrap();
        assert_eq!(
            ledger
                .apply_admitted(handle, [key(2), key(1)].into_iter(), &[])
                .unwrap_err()
                .cause,
            ExhaustionCause::AdmissionInvariant
        );
    }
    #[test]
    fn final_preflight_rejects_unreserved_growth_without_growing_storage() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let handle = ledger.register(owner(1, 7)).unwrap();
        ledger
            .reserve_admission(handle, [key(1)].into_iter(), &[])
            .unwrap();
        ledger
            .apply_admitted(handle, [key(1)].into_iter(), &[])
            .unwrap();
        let before = ledger.daemon_usage();
        let too_many: Vec<_> = (1..=128).map(key).collect();
        assert_eq!(
            ledger
                .preflight_admitted(handle, too_many.into_iter(), &[])
                .unwrap_err()
                .cause,
            ExhaustionCause::AdmissionInvariant
        );
        assert_eq!(ledger.daemon_usage(), before);
        assert_eq!(
            ledger.proof_keys(handle).unwrap_err().cause,
            ExhaustionCause::AdmissionInvariant
        );
    }

    #[test]
    fn unavailable_capture_has_a_distinct_sticky_cause_and_cannot_abort_ready_proof() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let ready = ledger.register(owner(1, 7)).unwrap();
        assert!(!ledger.abort_capture(ready));
        let capturing = ledger.register(owner(2, 7)).unwrap();
        assert!(ledger.finish_recovery(capturing).unwrap());
        assert!(ledger.begin_capture(capturing).unwrap());
        assert!(ledger.abort_capture(capturing));
        assert_eq!(
            ledger.proof_keys(capturing).unwrap_err().cause,
            ExhaustionCause::CaptureUnavailable
        );
        assert!(!ledger.abort_capture(capturing));
        assert_eq!(ledger.proof_keys(ready).unwrap().unwrap(), []);
    }
    #[test]
    fn final_apply_unreserved_growth_is_typed_and_preserves_storage_without_allocating() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let handle = ledger.register(owner(1, 7)).unwrap();
        capture(&mut ledger, handle, &[key(1)]);
        assert!(
            ledger
                .reserve_admission(handle, [key(1)].into_iter(), &[])
                .unwrap()
        );
        let before = ledger.daemon_usage();
        ledger.fail_next_allocation_for_test();
        let expanded: Vec<_> = (1..=128).map(key).collect();
        let error = ledger
            .apply_admitted(handle, expanded.into_iter(), &[])
            .unwrap_err();
        assert_eq!(error.cause, ExhaustionCause::AdmissionInvariant);
        assert_eq!(
            error.attempted_peer_bytes,
            ledger.peer_usage(handle.owner.peer).retained
        );
        assert_eq!(error.attempted_daemon_bytes, before.retained);
        assert!(
            ledger.fail_next_allocation,
            "application never tries to allocate"
        );
        assert_eq!(ledger.daemon_usage(), before);
        assert_eq!(
            ledger.records[ledger.index(handle).unwrap()]
                .keys
                .as_slice(),
            &[key(1)]
        );
        assert_running_charges(&ledger);
    }

    fn shared_capture(
        ledger: &mut EvpnRecoveryProvenance,
        handle: ProvenanceHandle,
        hint: Option<UniverseHandle>,
        raw: &[EvpnRouteKey],
        actual: &[EvpnRouteKey],
    ) -> UniverseHandle {
        assert!(ledger.finish_recovery(handle).unwrap());
        assert!(ledger.begin_capture(handle).unwrap());
        let (count, additions) = ledger
            .capture_shape(hint, actual.iter().copied(), &mut |_| {})
            .unwrap();
        let shared = ledger
            .share_capture(
                handle,
                hint,
                raw.len(),
                raw.iter().copied(),
                count,
                &mut |_| {},
            )
            .unwrap()
            .unwrap();
        ledger
            .reserve_capture(
                handle,
                if hint.is_some() { additions } else { 0 },
                &mut |_| {},
            )
            .unwrap();
        for &key in actual {
            ledger.capture_key(handle, key).unwrap();
        }
        ledger.seal_capture(handle).unwrap();
        shared
    }

    #[test]
    fn shared_dense_members_charge_one_universe_and_distinct_admission_masks() {
        const MEMBERS: u8 = 32;
        const ROUTES: usize = 4096;
        let raw = (0..u32::try_from(ROUTES).unwrap())
            .map(key)
            .collect::<Vec<_>>();
        let key_bytes = ROUTES * size_of::<EvpnRouteKey>();
        let budget = key_bytes
            + usize::from(MEMBERS)
                * (4 * size_of::<Record>() + 2 * ROUTES.div_ceil(64) * size_of::<u64>())
            + 8192;
        assert!(
            budget < 2 * key_bytes,
            "two complete universes must not fit"
        );
        let mut ledger = EvpnRecoveryProvenance::with_limits(PEER_LIMIT_BYTES, budget);
        let mut hint = None;
        let mut owners = Vec::new();
        for n in 1..=MEMBERS {
            let handle = ledger.register(owner(n, 7)).unwrap();
            let actual = raw
                .iter()
                .copied()
                .filter(|candidate| *candidate != key(u32::from(n)))
                .collect::<Vec<_>>();
            let shared = shared_capture(&mut ledger, handle, hint, &raw, &actual);
            if let Some(prior) = hint {
                assert_eq!(shared, prior);
            }
            hint = Some(shared);
            let proof = ledger.proof(handle).unwrap().unwrap();
            assert_eq!(proof.len(), ROUTES - 1);
            assert!(!proof.contains(&key(u32::from(n))));
            assert!(proof.contains(&key(0)));
            assert_eq!(
                ledger.records[ledger.index(handle).unwrap()]
                    .keys
                    .capacity(),
                0
            );
            owners.push(handle);
        }
        assert_eq!(ledger.universes.len(), 1);
        assert_eq!(ledger.universes[0].references, usize::from(MEMBERS));
        assert_running_charges(&ledger);
        for handle in owners {
            assert!(ledger.retire_member(handle));
        }
        assert_eq!(
            ledger.daemon_usage().retained,
            size_of::<EvpnRecoveryProvenance>()
        );
        assert!(ledger.universes.is_empty());
    }

    #[test]
    fn older_universe_capture_keeps_removed_bits_clear_and_new_old_keys_sparse() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let raw = [key(1), key(2), key(3), key(4)];
        let first = ledger.register(owner(1, 7)).unwrap();
        let shared = shared_capture(&mut ledger, first, None, &raw, &raw);
        let second = ledger.register(owner(2, 7)).unwrap();
        let actual = [key(9), key(2), key(7)];
        assert_eq!(
            ledger
                .capture_shape(Some(shared), actual.into_iter(), &mut |_| {})
                .unwrap(),
            (3, 2)
        );
        assert!(ledger.finish_recovery(second).unwrap());
        ledger.begin_capture(second).unwrap();
        assert_eq!(
            ledger
                .share_capture(second, Some(shared), 3, actual.into_iter(), 3, &mut |_| {})
                .unwrap(),
            Some(shared)
        );
        ledger.reserve_capture(second, 2, &mut |_| {}).unwrap();
        let reserved = ledger.daemon_usage().retained;
        ledger.fail_next_allocation_for_test();
        for key in actual {
            ledger.capture_key(second, key).unwrap();
        }
        assert!(ledger.proof(second).unwrap().is_none());
        ledger.seal_capture(second).unwrap();
        assert_eq!(
            ledger.proof_keys(second).unwrap(),
            Some(vec![key(2), key(7), key(9)])
        );
        assert_eq!(ledger.proof_keys(first).unwrap(), Some(raw.to_vec()));
        assert!(ledger.fail_next_allocation);
        assert_eq!(ledger.daemon_usage().retained, reserved);
        let view = ledger.proof(second).unwrap().unwrap();
        let mut visited = 0;
        let folded = view
            .iter_with_checkpoint(|force| {
                assert!(!force);
                visited += 1;
            })
            .collect::<Vec<_>>();
        assert_eq!(folded, [key(2), key(7), key(9)]);
        assert_eq!(
            visited,
            raw.len() + 2,
            "excluded and trailing base keys are checkpointed"
        );
        assert_running_charges(&ledger);
    }

    #[test]
    fn shared_final_admission_is_allocation_free_and_rejects_unmarked_or_duplicate_withdrawals() {
        for withdrawals in [vec![key(2)], vec![key(1), key(1)], vec![key(3), key(1)]] {
            let mut ledger = EvpnRecoveryProvenance::new();
            let handle = ledger.register(owner(1, 7)).unwrap();
            shared_capture(
                &mut ledger,
                handle,
                None,
                &[key(1), key(2), key(3)],
                &[key(1), key(3)],
            );
            let before = ledger.proof_keys(handle).unwrap();
            let error = ledger
                .apply_admitted(handle, [].into_iter(), &withdrawals)
                .unwrap_err();
            assert_eq!(error.cause, ExhaustionCause::AdmissionInvariant);
            assert_eq!(ledger.proof_keys(handle), Err(error));
            assert_eq!(
                ledger
                    .view(ledger.index(handle).unwrap())
                    .iter_with_checkpoint(|_| {})
                    .collect::<Vec<_>>(),
                before.unwrap()
            );
            assert_running_charges(&ledger);
        }
        let mut ledger = EvpnRecoveryProvenance::new();
        let handle = ledger.register(owner(1, 7)).unwrap();
        shared_capture(
            &mut ledger,
            handle,
            None,
            &[key(1), key(2), key(3)],
            &[key(1), key(3)],
        );
        ledger
            .reserve_admission(handle, [key(1), key(2), key(4)].into_iter(), &[key(1)])
            .unwrap();
        let before = ledger.daemon_usage().retained;
        ledger.fail_next_allocation_for_test();
        ledger
            .preflight_admitted(
                handle,
                [key(1), key(2), key(4)].into_iter(),
                &[key(1), key(3)],
            )
            .unwrap();
        ledger
            .apply_admitted(
                handle,
                [key(1), key(2), key(4)].into_iter(),
                &[key(1), key(3)],
            )
            .unwrap();
        assert_eq!(
            ledger.proof_keys(handle).unwrap(),
            Some(vec![key(1), key(2), key(4)])
        );
        assert_eq!(ledger.daemon_usage().retained, before);
        assert!(ledger.fail_next_allocation);
        assert_running_charges(&ledger);
    }

    #[test]
    fn optional_shared_allocation_refusals_roll_back_and_leave_flat_capture_available() {
        for failure in 0..3 {
            let mut ledger = EvpnRecoveryProvenance::new();
            let handle = ledger.register(owner(1, 7)).unwrap();
            ledger.finish_recovery(handle).unwrap();
            ledger.begin_capture(handle).unwrap();
            let raw = (0..128).map(key).collect::<Vec<_>>();
            let before = ledger.daemon_usage().retained;
            ledger.allocation_countdown = Some(failure);
            let error = ledger
                .share_capture(
                    handle,
                    None,
                    raw.len(),
                    raw.iter().copied(),
                    raw.len(),
                    &mut |_| {},
                )
                .unwrap_err();
            assert_eq!(error.cause, ExhaustionCause::AllocationFailure);
            assert_eq!(ledger.daemon_usage().retained, before);
            assert!(ledger.universes.is_empty());
            assert_eq!(ledger.exhaustion(handle), None);
            ledger.reserve_capture(handle, 1, &mut |_| {}).unwrap();
            ledger.capture_key(handle, key(7)).unwrap();
            ledger.seal_capture(handle).unwrap();
            assert_eq!(ledger.proof_keys(handle).unwrap(), Some(vec![key(7)]));
            assert_running_charges(&ledger);
        }
    }

    #[test]
    fn shared_snapshot_mask_allocation_failure_keeps_source_and_universe_ownership() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let first = ledger.register(owner(1, 7)).unwrap();
        let raw: Vec<_> = (1..=128).map(key).collect();
        let hint = shared_capture(&mut ledger, first, None, &raw, &[key(1)]);
        let second = ledger.register(owner(2, 7)).unwrap();
        shared_capture(&mut ledger, second, Some(hint), &raw, &[key(2)]);
        // Leave a vacant charged record slot, so the injected refusal reaches
        // the new mask copy rather than an outer metadata resize.
        let spare = ledger.register(owner(3, 7)).unwrap();
        assert!(ledger.retire_member(spare));
        assert!(ledger.records.len() < ledger.records.capacity());
        assert!(ledger.records[ledger.index(first).unwrap()].keys.is_empty());
        assert!(
            !ledger.records[ledger.index(first).unwrap()]
                .words
                .is_empty()
        );
        let before = ledger.daemon_usage().retained;
        let peer_before = ledger.peer_usage(first.owner.peer).retained;
        ledger.fail_next_allocation_for_test();
        let error = ledger.snapshot(first).unwrap_err();
        assert_eq!(error.cause, ExhaustionCause::AllocationFailure);
        assert!(!ledger.fail_next_allocation);
        assert_eq!(ledger.proof_keys(first), Err(error));
        assert_eq!(
            ledger
                .view(ledger.index(first).unwrap())
                .iter_with_checkpoint(|_| {})
                .collect::<Vec<_>>(),
            [key(1)]
        );
        assert_eq!(ledger.proof_keys(second).unwrap(), Some(vec![key(2)]));
        assert_eq!(ledger.universes[0].references, 2);
        assert_eq!(ledger.records.len(), 2);
        assert_eq!(ledger.daemon_usage().retained, before);
        assert_eq!(ledger.peer_usage(first.owner.peer).retained, peer_before);
        assert_running_charges(&ledger);
        assert!(ledger.retire_member(first));
        assert_eq!(ledger.universes[0].references, 1);
        assert_eq!(ledger.proof_keys(second).unwrap(), Some(vec![key(2)]));
        assert_running_charges(&ledger);
        assert!(ledger.retire_member(second));
        assert!(ledger.universe_index(hint).is_none());
        assert_eq!(
            ledger.daemon_usage().retained,
            size_of::<EvpnRecoveryProvenance>()
        );
        assert_running_charges(&ledger);
    }

    #[test]
    fn shared_snapshot_references_survive_primary_retirement_and_weak_hint_cannot_alias() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let handle = ledger.register(owner(1, 7)).unwrap();
        let hint = shared_capture(&mut ledger, handle, None, &[key(1), key(2)], &[key(1)]);
        let snapshot = ledger.snapshot(handle).unwrap().unwrap();
        assert_eq!(ledger.universes[0].references, 2);
        ledger
            .apply_admitted(handle, [key(2)].into_iter(), &[key(1)])
            .unwrap();
        assert_eq!(ledger.proof_keys(snapshot).unwrap(), Some(vec![key(1)]));
        assert_eq!(ledger.proof_keys(handle).unwrap(), Some(vec![key(2)]));
        ledger.retire(handle);
        let replacement = ledger.register(handle.owner).unwrap();
        assert_eq!(ledger.proof_keys(replacement).unwrap(), Some(vec![]));
        assert_eq!(ledger.proof_keys(snapshot).unwrap(), Some(vec![key(1)]));
        assert!(!ledger.retire(handle));
        assert_running_charges(&ledger);
        ledger.retire(snapshot);
        assert!(ledger.universe_index(hint).is_none());
        let next = shared_capture(&mut ledger, replacement, Some(hint), &[key(7)], &[key(7)]);
        assert_ne!(next, hint);
        assert!(
            !ledger
                .proof(replacement)
                .unwrap()
                .unwrap()
                .contains(&key(1))
        );
        assert_running_charges(&ledger);
        ledger.retire_member(replacement);
        assert_eq!(
            ledger.daemon_usage().retained,
            size_of::<EvpnRecoveryProvenance>()
        );
    }

    #[test]
    fn shared_sparse_refusal_is_sticky_and_preserves_other_owner_and_full_overlap_caps() {
        for cause in [
            ExhaustionCause::PeerLimit,
            ExhaustionCause::DaemonLimit,
            ExhaustionCause::AllocationFailure,
        ] {
            let mut ledger = EvpnRecoveryProvenance::new();
            let first = ledger.register(owner(1, 7)).unwrap();
            let raw = [key(1), key(2), key(3)];
            let hint = shared_capture(&mut ledger, first, None, &raw, &raw);
            let second = ledger.register(owner(2, 7)).unwrap();
            shared_capture(&mut ledger, second, Some(hint), &raw, &raw);
            match cause {
                ExhaustionCause::PeerLimit => {
                    ledger.peer_limit = ledger.peer_usage(second.owner.peer).retained;
                }
                ExhaustionCause::DaemonLimit => ledger.daemon_limit = ledger.daemon_used,
                ExhaustionCause::AllocationFailure => ledger.fail_next_allocation_for_test(),
                _ => unreachable!(),
            }
            let error = ledger
                .reserve_admission(second, [key(9)].into_iter(), &[])
                .unwrap_err();
            assert_eq!(error.cause, cause);
            assert_eq!(ledger.proof_keys(second), Err(error));
            assert_eq!(ledger.proof_keys(first).unwrap(), Some(raw.to_vec()));
            assert_running_charges(&ledger);
        }
    }
}
