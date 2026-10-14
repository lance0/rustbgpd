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
    peer_peak: usize,
}

impl Record {
    fn charge(&self) -> usize {
        size_of::<Self>() + self.keys.capacity() * size_of::<EvpnRouteKey>()
    }
}

#[derive(Debug)]
pub(in crate::manager) struct EvpnRecoveryProvenance {
    records: Records,
    daemon_used: usize,
    daemon_peak: usize,
    peer_limit: usize,
    daemon_limit: usize,
    next_id: u64,
    #[cfg(test)]
    fail_next_allocation: bool,
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
            daemon_used: size_of::<Self>(),
            daemon_peak: size_of::<Self>(),
            peer_limit,
            daemon_limit,
            next_id: 1,
            #[cfg(test)]
            fail_next_allocation: false,
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
        let mut usage = Usage {
            retained: 0,
            peak: 0,
        };
        for record in self.records.iter().filter(|r| r.handle.owner.peer == peer) {
            usage.retained += record.charge();
            usage.peak = usage.peak.max(record.peer_peak);
        }
        usage
    }

    fn index(&self, handle: ProvenanceHandle) -> Option<usize> {
        self.records
            .binary_search_by_key(&handle, |record| record.handle)
            .ok()
    }

    /// Snapshot-only ownership does not make a peer an active member.
    pub(in crate::manager) fn primary_handle(
        &self,
        owner: PeerSession,
    ) -> Option<ProvenanceHandle> {
        self.records.iter().find_map(|record| {
            (record.handle.owner == owner && record.primary).then_some(record.handle)
        })
    }

    pub(in crate::manager) fn exhaustion(&self, handle: ProvenanceHandle) -> Option<Exhaustion> {
        self.records.iter().find_map(|record| {
            if record.handle.owner == handle.owner
                && record.handle.generation == handle.generation
                && record.primary
                && let State::Exhausted(error) = record.state
            {
                return Some(error);
            }
            None
        })
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
        if let Some(error) = self.exhaustion(handle) {
            return Err(error);
        }
        Ok(self.index(handle))
    }

    fn mark_exhausted(&mut self, handle: ProvenanceHandle, error: Exhaustion) -> Exhaustion {
        for record in &mut self.records {
            if record.handle.owner == handle.owner
                && record.handle.generation == handle.generation
                && record.primary
            {
                record.state = State::Exhausted(error);
                break;
            }
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
        if std::mem::take(&mut self.fail_next_allocation) {
            return false;
        }
        true
    }

    fn note_peer_peak(&mut self, peer: IpAddr, attempted: usize) {
        for record in self
            .records
            .iter_mut()
            .filter(|r| r.handle.owner.peer == peer)
        {
            record.peer_peak = record.peer_peak.max(attempted);
        }
    }

    fn metadata_peer_peak(
        records: &[Record],
        resizing: bool,
        additional: usize,
    ) -> Result<usize, Exhaustion> {
        let retained = records.iter().try_fold(0_usize, |total, record| {
            total
                .checked_add(record.charge())
                .ok_or_else(Self::overflow)
        })?;
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
    fn insert_record(
        &mut self,
        owner: PeerSession,
        generation: Option<u64>,
    ) -> Result<ProvenanceHandle, Exhaustion> {
        let next_id = self.next_id.checked_add(1).ok_or_else(Self::overflow)?;
        let prior_peak = self.peer_usage(owner.peer).peak;
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
        for records in self
            .records
            .as_slice()
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
        let mut start = 0;
        while start < self.records.len() {
            let peer = self.records[start].handle.owner.peer;
            let mut end = start + 1;
            while end < self.records.len() && self.records[end].handle.owner.peer == peer {
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
                peer_peak: target_peak.max(prior_peak),
            },
        );
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
    pub(in crate::manager) fn capture_key(
        &mut self,
        handle: ProvenanceHandle,
        key: EvpnRouteKey,
    ) -> Result<bool, Exhaustion> {
        let Some(index) = self.checked_handle_index(handle)? else {
            return Ok(false);
        };
        if !matches!(self.records[index].state, State::Capturing) {
            return Ok(false);
        }
        let keys = &self.records[index].keys;
        if keys.len() == keys.capacity() {
            let capacity = keys
                .capacity()
                .checked_mul(2)
                .map(|n| n.max(1))
                .ok_or_else(Self::overflow)
                .and_then(|cap| self.grow_keys(handle, cap));
            if let Err(error) = capacity {
                return Err(self.mark_exhausted(handle, error));
            }
        }
        self.records[index].keys.push(key);
        Ok(true)
    }

    /// In-place unstable sorting and deduplication allocate no scratch buffer.
    pub(in crate::manager) fn seal_capture(
        &mut self,
        handle: ProvenanceHandle,
    ) -> Result<bool, Exhaustion> {
        let Some(index) = self.checked_handle_index(handle)? else {
            return Ok(false);
        };
        if !matches!(self.records[index].state, State::Capturing) {
            return Ok(false);
        }
        self.records[index].keys.sort_unstable();
        self.records[index].keys.dedup();
        self.records[index].state = State::Ready;
        Ok(true)
    }

    /// None means there is no complete proof; it never permits a withdrawal.
    pub(in crate::manager) fn proof(
        &self,
        handle: ProvenanceHandle,
    ) -> Result<Option<&[EvpnRouteKey]>, Exhaustion> {
        Ok(self.checked_handle_index(handle)?.and_then(|i| {
            matches!(self.records[i].state, State::Ready).then_some(self.records[i].keys.as_slice())
        }))
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
        let Some(keys) = self.proof(handle)? else {
            return Ok(None);
        };
        let length = keys.len();
        let snapshot = match self.insert_record(handle.owner, Some(handle.generation)) {
            Ok(snapshot) => snapshot,
            Err(error) => return Err(self.mark_exhausted(handle, error)),
        };
        if let Err(error) = self.grow_keys(snapshot, length) {
            self.retire(snapshot);
            return Err(self.mark_exhausted(handle, error));
        }
        let source = self.index(handle).expect("snapshot source remains owned");
        let destination = self.index(snapshot).expect("new snapshot remains owned");
        let (before, after) = self.records.split_at_mut(destination);
        after[0]
            .keys
            .extend_from_slice(before[source].keys.as_slice());
        Ok(Some(snapshot))
    }

    // Reservation ignores withdrawal credit: later export gates may remove
    // withdrawals while retaining announcements from the candidate batch.
    fn planned_len<A>(
        keys: &[EvpnRouteKey],
        announcements: A,
        withdrawals: &[EvpnRouteKey],
        credit_withdrawals: bool,
    ) -> Result<usize, Exhaustion>
    where
        A: Iterator<Item = EvpnRouteKey> + Clone,
    {
        assert!(
            withdrawals.windows(2).all(|w| w[0] < w[1]),
            "withdrawals must be sorted and unique"
        );
        let mut previous = None;
        for key in announcements.clone() {
            assert!(
                previous.is_none_or(|old| old < key),
                "announcements must be sorted and unique"
            );
            previous = Some(key);
        }
        let mut old = 0;
        for key in withdrawals {
            while old < keys.len() && keys[old] < *key {
                old += 1;
            }
            assert!(
                keys.get(old) == Some(key),
                "withdrawal requires an admitted key"
            );
        }
        let mut old = 0;
        let mut withdrawn = 0;
        let mut additional = 0_usize;
        for key in announcements {
            while old < keys.len() && keys[old] < key {
                old += 1;
            }
            while withdrawn < withdrawals.len() && withdrawals[withdrawn] < key {
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
    pub(in crate::manager) fn reserve_admission<A>(
        &mut self,
        handle: ProvenanceHandle,
        announcements: A,
        withdrawals: &[EvpnRouteKey],
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
        let result = Self::planned_len(
            self.records[index].keys.as_slice(),
            announcements,
            withdrawals,
            false,
        )
        .and_then(|length| self.grow_keys(handle, length));
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
    pub(in crate::manager) fn apply_admitted<A>(
        &mut self,
        handle: ProvenanceHandle,
        announcements: A,
        withdrawals: &[EvpnRouteKey],
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
        let result = Self::planned_len(
            self.records[index].keys.as_slice(),
            announcements.clone(),
            withdrawals,
            true,
        );
        let final_len = match result {
            Ok(length) => length,
            Err(error) => return Err(self.mark_exhausted(handle, error)),
        };
        if let Err(error) = self.grow_keys(handle, final_len) {
            return Err(self.mark_exhausted(handle, error));
        }
        let keys = &mut self.records[index].keys;
        let mut withdrawn = 0;
        keys.retain(|key| {
            while withdrawn < withdrawals.len() && withdrawals[withdrawn] < *key {
                withdrawn += 1;
            }
            withdrawals.get(withdrawn) != Some(key)
        });
        let mut old = keys.len();
        let mut announced = announcements;
        let mut next = announced.next_back();
        if final_len > keys.len() {
            keys.resize(final_len, next.expect("growth has an announcement"));
        }
        for target in (0..final_len).rev() {
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

    fn free_keys(&mut self, index: usize) {
        let bytes = self.records[index].keys.capacity() * size_of::<EvpnRouteKey>();
        self.records[index].keys.clear();
        self.records[index]
            .keys
            .try_grow(0)
            .expect("empty pinned SmallVec deallocation cannot fail");
        self.daemon_used -= bytes;
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
        while let Some(owned) = self.records.iter().find_map(|record| {
            (record.handle.owner == handle.owner && record.handle.generation == handle.generation)
                .then_some(record.handle)
        }) {
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
        drop(self.records.remove(index));
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

    #[test]
    fn fresh_proof_capture_and_retained_capacity_have_distinct_lifetimes() {
        let mut ledger = EvpnRecoveryProvenance::new();
        assert_eq!(ledger.limits(), (PEER_LIMIT_BYTES, DAEMON_LIMIT_BYTES));
        let handle = ledger.register(owner(1, 7)).unwrap();
        assert_eq!(ledger.proof(handle).unwrap(), Some([].as_slice()));
        assert!(!ledger.begin_capture(handle).unwrap());
        assert!(ledger.finish_recovery(handle).unwrap());
        assert_eq!(ledger.proof(handle).unwrap(), None);
        assert!(ledger.begin_capture(handle).unwrap());
        for n in [3, 1, 3, 2] {
            assert!(ledger.capture_key(handle, key(n)).unwrap());
        }
        assert_eq!(ledger.proof(handle).unwrap(), None);
        assert!(!ledger.finish_recovery(handle).unwrap());
        let before_seal = ledger.daemon_usage().retained;
        assert!(ledger.seal_capture(handle).unwrap());
        assert_eq!(
            ledger.proof(handle).unwrap(),
            Some([key(1), key(2), key(3)].as_slice())
        );
        assert_eq!(ledger.daemon_usage().retained, before_seal);
        assert_eq!(capacity(&ledger, handle), 4);
        let before_delete = ledger.daemon_usage().retained;
        assert!(
            ledger
                .apply_admitted(handle, [].into_iter(), &[key(1), key(2), key(3)])
                .unwrap()
        );
        assert_eq!(ledger.proof(handle).unwrap(), Some([].as_slice()));
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
            ledger.proof(handle).unwrap(),
            Some([key(2), key(3), key(4)].as_slice())
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
            .apply_admitted(handle, [key(5), key(6)].into_iter(), &[])
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
        assert_eq!(ledger.proof(handle), Err(error));
        assert_eq!(ledger.begin_capture(handle), Err(error));
        assert_eq!(ledger.finish_recovery(handle), Err(error));
        assert!(ledger.retire_member(handle));
    }

    #[test]
    fn candidate_reservation_ignores_withdraw_credit_and_final_apply_does_not_allocate() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let handle = ledger.register(owner(1, 7)).unwrap();
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
            ledger.proof(handle).unwrap(),
            Some([key(1), key(3), key(5)].as_slice())
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
            ledger.proof(handle).unwrap(),
            Some([key(1), key(2), key(3), key(5)].as_slice())
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
                            .apply_admitted(handle, old.iter().copied(), &[])
                            .unwrap()
                    );
                    assert!(
                        ledger
                            .apply_admitted(handle, announced.iter().copied(), &withdrawn)
                            .unwrap()
                    );
                    assert_eq!(
                        ledger.proof(handle).unwrap().unwrap(),
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
        assert_eq!(ledger.proof(first).unwrap(), Some([].as_slice()));
        assert_eq!(ledger.proof(second).unwrap(), Some([].as_slice()));
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
            assert_eq!(ledger.proof(handle).unwrap(), Some([].as_slice()));
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
            ledger.proof(handle).unwrap(),
            Some([key(2), key(3)].as_slice())
        );
        assert_eq!(
            ledger.proof(snapshot).unwrap(),
            Some([key(1), key(2)].as_slice())
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
        assert_eq!(ledger.proof(snapshot).unwrap(), None);
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
        assert_eq!(ledger.proof(replacement).unwrap(), Some([].as_slice()));
        assert!(!ledger.retire_member(first));
        assert!(!ledger.retire(first));
        assert!(ledger.retire(old));
        assert_eq!(ledger.proof(replacement).unwrap(), Some([].as_slice()));
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
        assert_eq!(ledger.proof(first).unwrap(), None);
        assert_eq!(ledger.proof(replacement).unwrap(), Some([].as_slice()));
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
        assert_eq!(ledger.proof(first), Err(error));
        assert_eq!(ledger.proof(second).unwrap(), Some(keys.as_slice()));
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
        assert_eq!(ledger.proof(handle), Err(error));
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
        assert_eq!(ledger.proof(handle), Err(error));
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
    #[should_panic(expected = "withdrawal requires an admitted key")]
    fn unknown_withdrawal_is_not_admitted() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let handle = ledger.register(owner(1, 7)).unwrap();
        ledger
            .apply_admitted(handle, [].into_iter(), &[key(1)])
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "withdrawals must be sorted and unique")]
    fn duplicate_withdrawal_is_not_admitted() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let handle = ledger.register(owner(1, 7)).unwrap();
        ledger
            .apply_admitted(handle, [key(1)].into_iter(), &[])
            .unwrap();
        ledger
            .apply_admitted(handle, [].into_iter(), &[key(1), key(1)])
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "announcements must be sorted and unique")]
    fn unordered_accepted_batch_is_not_admitted() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let handle = ledger.register(owner(1, 7)).unwrap();
        ledger
            .apply_admitted(handle, [key(2), key(1)].into_iter(), &[])
            .unwrap();
    }
}
