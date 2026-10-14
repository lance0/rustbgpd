//! Bounded, actor-owned unicast/VPN recovery proofs.
//!
//! Credits cover owned headers and exact requested capacities, including the
//! full old/new overlap during growth. Allocator overhead and RSS need their
//! separate qualification receipt; a failed proof uses the actor's fallback.

use std::mem::size_of;
use std::net::IpAddr;

use rustbgpd_wire::{Prefix, VpnRouteKey};
use smallvec::SmallVec;

use crate::route::VpnRibRouteKey;
use crate::update::ExactExportKey;

const PEER_LIMIT_BYTES: usize = 64 * 1024 * 1024;
const DAEMON_LIMIT_BYTES: usize = 512 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::manager) enum Key {
    Unicast(Prefix, u32),
    Vpn(VpnRouteKey, u32),
}

impl TryFrom<&ExactExportKey> for Key {
    type Error = ();

    fn try_from(key: &ExactExportKey) -> Result<Self, Self::Error> {
        match key {
            ExactExportKey::Unicast(prefix, path_id) => Ok(Self::Unicast(*prefix, *path_id)),
            ExactExportKey::Vpn(key) => Ok(Self::Vpn(key.nlri_key, key.path_id)),
            _ => Err(()),
        }
    }
}

impl From<Key> for ExactExportKey {
    fn from(key: Key) -> Self {
        match key {
            Key::Unicast(prefix, path_id) => Self::Unicast(prefix, path_id),
            Key::Vpn(nlri_key, path_id) => Self::Vpn(VpnRibRouteKey { nlri_key, path_id }),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::manager) enum FailureCause {
    PeerLimit,
    DaemonLimit,
    AllocationFailure,
    MissingProof,
}

impl FailureCause {
    pub(in crate::manager) const fn as_str(self) -> &'static str {
        match self {
            Self::PeerLimit => "peer_limit",
            Self::DaemonLimit => "daemon_limit",
            Self::AllocationFailure => "allocation_failure",
            Self::MissingProof => "missing_proof",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::manager) struct Failure {
    pub(in crate::manager) cause: FailureCause,
    pub(in crate::manager) limiting_peer: Option<IpAddr>,
    pub(in crate::manager) attempted_peer_bytes: usize,
    pub(in crate::manager) attempted_daemon_bytes: usize,
}

type Keys = SmallVec<[Key; 0]>;
type Records = SmallVec<[Record; 0]>;

#[derive(Debug)]
#[cfg_attr(test, derive(Clone, PartialEq, Eq))]
pub(in crate::manager) struct AdmittedKeys(Keys);

impl AdmittedKeys {
    pub(in crate::manager) fn len(&self) -> usize {
        self.0.len()
    }

    #[cfg(test)]
    pub(in crate::manager) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(in crate::manager) fn contains(&self, key: &ExactExportKey) -> bool {
        Key::try_from(key).is_ok_and(|key| self.0.binary_search(&key).is_ok())
    }

    pub(in crate::manager) fn iter(&self) -> impl Iterator<Item = ExactExportKey> + '_ {
        self.0.iter().copied().map(ExactExportKey::from)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Capturing,
    Complete,
    Failed(Failure),
}

#[derive(Debug)]
#[cfg_attr(test, derive(Clone, PartialEq, Eq))]
struct Record {
    peer: IpAddr,
    state: State,
    keys: AdmittedKeys,
}

impl Record {
    fn charge(&self) -> usize {
        size_of::<Self>() + self.keys.0.capacity() * size_of::<Key>()
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(Clone, PartialEq, Eq))]
pub(in crate::manager) struct AdmittedRecovery {
    records: Records,
    used: usize,
    peak: usize,
    peer_limit: usize,
    daemon_limit: usize,
    #[cfg(test)]
    fail_next_allocation: bool,
}

impl AdmittedRecovery {
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
            used: size_of::<Self>(),
            peak: size_of::<Self>(),
            peer_limit,
            daemon_limit,
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

    pub(in crate::manager) fn entries_with_checkpoint(
        &self,
        checkpoint: &mut impl FnMut(bool),
    ) -> usize {
        self.records
            .iter()
            .map(|record| {
                checkpoint(false);
                record.keys.len()
            })
            .sum()
    }

    pub(in crate::manager) fn bytes(&self) -> usize {
        self.used
    }

    pub(in crate::manager) fn peak_bytes(&self) -> usize {
        self.peak
    }

    pub(in crate::manager) fn contains_record(&self, peer: IpAddr) -> bool {
        self.index(peer).is_ok()
    }

    pub(in crate::manager) fn contains_key(&self, peer: &IpAddr) -> bool {
        self.get(peer).is_some()
    }

    pub(in crate::manager) fn get(&self, peer: &IpAddr) -> Option<&AdmittedKeys> {
        let record = &self.records[self.index(*peer).ok()?];
        (record.state == State::Complete).then_some(&record.keys)
    }

    #[cfg(test)]
    pub(in crate::manager) fn keys(&self) -> impl Iterator<Item = &IpAddr> {
        self.records
            .iter()
            .filter_map(|record| (record.state == State::Complete).then_some(&record.peer))
    }

    fn index(&self, peer: IpAddr) -> Result<usize, usize> {
        self.records
            .binary_search_by_key(&peer, |record| record.peer)
    }

    fn index_with_checkpoint(
        &self,
        peer: IpAddr,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<usize, usize> {
        self.records.binary_search_by(|record| {
            checkpoint(false);
            record.peer.cmp(&peer)
        })
    }

    fn missing_proof(&self, peer: IpAddr) -> Failure {
        Failure {
            cause: FailureCause::MissingProof,
            limiting_peer: None,
            attempted_peer_bytes: self
                .index(peer)
                .ok()
                .map_or(0, |index| self.records[index].charge()),
            attempted_daemon_bytes: self.used,
        }
    }

    fn overflow() -> Failure {
        Failure {
            cause: FailureCause::AllocationFailure,
            limiting_peer: None,
            attempted_peer_bytes: usize::MAX,
            attempted_daemon_bytes: usize::MAX,
        }
    }

    fn check(&self, address: IpAddr, peer: usize, daemon: usize) -> Result<(), Failure> {
        let cause = if peer > self.peer_limit {
            Some(FailureCause::PeerLimit)
        } else if daemon > self.daemon_limit {
            Some(FailureCause::DaemonLimit)
        } else {
            None
        };
        match cause {
            None => Ok(()),
            Some(cause) => Err(Failure {
                cause,
                limiting_peer: (cause == FailureCause::PeerLimit).then_some(address),
                attempted_peer_bytes: peer,
                attempted_daemon_bytes: daemon,
            }),
        }
    }

    #[cfg_attr(
        not(test),
        expect(
            clippy::unused_self,
            reason = "Test builds use the owned allocation failure hook"
        )
    )]
    fn allocation_permitted(&mut self) -> bool {
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_allocation) {
            return false;
        }
        true
    }

    fn insert_record(
        &mut self,
        peer: IpAddr,
        state: State,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<(), Failure> {
        let Err(index) = self.index_with_checkpoint(peer, checkpoint) else {
            return Err(self.missing_proof(peer));
        };
        let old_cap = self.records.capacity();
        let new_cap = if self.records.len() == old_cap {
            old_cap.checked_mul(2).ok_or_else(Self::overflow)?.max(1)
        } else {
            old_cap
        };
        let resizing = new_cap != old_cap;
        let extra = if resizing {
            new_cap
                .checked_mul(size_of::<Record>())
                .and_then(|bytes| bytes.checked_add(size_of::<Records>()))
                .ok_or_else(Self::overflow)?
        } else {
            0
        }
        .checked_add(size_of::<Record>())
        .ok_or_else(Self::overflow)?;
        let daemon = self.used.checked_add(extra).ok_or_else(Self::overflow)?;
        let target = size_of::<Record>()
            .checked_mul(2)
            .ok_or_else(Self::overflow)?;
        // A metadata resize also copies headers belonging to other peers.
        if resizing {
            for record in &self.records {
                checkpoint(false);
                let attempted = record
                    .charge()
                    .checked_add(size_of::<Record>())
                    .ok_or_else(Self::overflow)?;
                self.check(record.peer, attempted, daemon)?;
            }
        }
        self.check(peer, target, daemon)?;
        self.used = daemon;
        self.peak = self.peak.max(daemon);
        if resizing {
            checkpoint(true);
            let failed = !self.allocation_permitted() || self.records.try_grow(new_cap).is_err();
            checkpoint(true);
            if failed {
                self.used -= extra;
                return Err(Failure {
                    cause: FailureCause::AllocationFailure,
                    limiting_peer: None,
                    attempted_peer_bytes: target,
                    attempted_daemon_bytes: daemon,
                });
            }
            // try_grow has freed the old array before returning.
            self.used -= old_cap * size_of::<Record>() + size_of::<Records>();
        }
        checkpoint(true);
        self.records.insert(
            index,
            Record {
                peer,
                state,
                keys: AdmittedKeys(Keys::new()),
            },
        );
        checkpoint(true);
        self.used -= size_of::<Record>(); // The temporary constructor is gone.
        Ok(())
    }

    pub(in crate::manager) fn begin_capture_with_checkpoint(
        &mut self,
        peer: IpAddr,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<bool, Failure> {
        if let Ok(index) = self.index_with_checkpoint(peer, checkpoint) {
            return match self.records[index].state {
                State::Failed(error) => Err(error),
                State::Capturing | State::Complete => Ok(false),
            };
        }
        self.insert_record(peer, State::Capturing, checkpoint)?;
        Ok(true)
    }

    pub(in crate::manager) fn insert_empty_with_checkpoint(
        &mut self,
        peer: IpAddr,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<(), Failure> {
        if let Ok(index) = self.index_with_checkpoint(peer, checkpoint) {
            return match self.records[index].state {
                State::Failed(error) => Err(error),
                State::Capturing | State::Complete => Ok(()),
            };
        }
        self.insert_record(peer, State::Complete, checkpoint)
    }

    fn grow_keys(
        &mut self,
        index: usize,
        capacity: usize,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<(), Failure> {
        checkpoint(false);
        let record = &self.records[index];
        let old_cap = record.keys.0.capacity();
        if capacity <= old_cap {
            return Ok(());
        }
        let extra = capacity
            .checked_mul(size_of::<Key>())
            .and_then(|bytes| bytes.checked_add(size_of::<Keys>()))
            .ok_or_else(Self::overflow)?;
        let peer = record
            .charge()
            .checked_add(extra)
            .ok_or_else(Self::overflow)?;
        let daemon = self.used.checked_add(extra).ok_or_else(Self::overflow)?;
        self.check(record.peer, peer, daemon)?;
        self.used = daemon;
        self.peak = self.peak.max(daemon);
        checkpoint(true);
        let failed =
            !self.allocation_permitted() || self.records[index].keys.0.try_grow(capacity).is_err();
        checkpoint(true);
        if failed {
            self.used -= extra;
            return Err(Failure {
                cause: FailureCause::AllocationFailure,
                limiting_peer: None,
                attempted_peer_bytes: peer,
                attempted_daemon_bytes: daemon,
            });
        }
        self.used -= old_cap * size_of::<Key>() + size_of::<Keys>();
        Ok(())
    }

    fn free_keys(&mut self, index: usize, checkpoint: &mut impl FnMut(bool)) {
        checkpoint(true);
        let keys = &mut self.records[index].keys.0;
        let bytes = keys.capacity() * size_of::<Key>();
        keys.clear();
        keys.try_grow(0)
            .expect("empty pinned SmallVec deallocation cannot fail");
        self.used -= bytes;
        checkpoint(true);
    }

    fn fail(&mut self, index: usize, error: Failure, checkpoint: &mut impl FnMut(bool)) -> Failure {
        self.free_keys(index, checkpoint);
        self.records[index].state = State::Failed(error);
        error
    }

    pub(in crate::manager) fn push_capture_with_checkpoint(
        &mut self,
        peer: IpAddr,
        key: Key,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<(), Failure> {
        let Ok(index) = self.index_with_checkpoint(peer, checkpoint) else {
            return Err(self.missing_proof(peer));
        };
        checkpoint(false);
        match self.records[index].state {
            State::Failed(error) => return Err(error),
            State::Complete => return Err(self.fail(index, self.missing_proof(peer), checkpoint)),
            State::Capturing => {}
        }
        let keys = &self.records[index].keys.0;
        if keys.len() == keys.capacity() {
            let capacity = match keys.capacity().checked_mul(2) {
                Some(capacity) => capacity.max(1),
                None => return Err(self.fail(index, Self::overflow(), checkpoint)),
            };
            if let Err(error) = self.grow_keys(index, capacity, checkpoint) {
                return Err(self.fail(index, error, checkpoint));
            }
        }
        self.records[index].keys.0.push(key);
        Ok(())
    }

    pub(in crate::manager) fn seal_capture_with_checkpoint(
        &mut self,
        peer: IpAddr,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<(), Failure> {
        let Ok(index) = self.index_with_checkpoint(peer, checkpoint) else {
            return Err(self.missing_proof(peer));
        };
        match self.records[index].state {
            State::Failed(error) => return Err(error),
            State::Complete => return Ok(()),
            State::Capturing => {}
        }
        let keys = &mut self.records[index].keys.0;
        Self::sort_keys(keys, checkpoint);
        self.records[index].state = State::Complete;
        Ok(())
    }

    fn complete_index(
        &mut self,
        peer: IpAddr,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<Option<usize>, Failure> {
        let Ok(index) = self.index_with_checkpoint(peer, checkpoint) else {
            return Ok(None);
        };
        match self.records[index].state {
            State::Failed(error) => Err(error),
            State::Capturing => Err(self.fail(index, self.missing_proof(peer), checkpoint)),
            State::Complete => Ok(Some(index)),
        }
    }

    fn union_len<A>(
        keys: &[Key],
        announcements: A,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<usize, Failure>
    where
        A: Iterator<Item = Key>,
    {
        let mut len = keys.len();
        for key in announcements {
            checkpoint(false);
            if keys
                .binary_search_by(|prior| {
                    checkpoint(false);
                    prior.cmp(&key)
                })
                .is_err()
            {
                len = len.checked_add(1).ok_or_else(Self::overflow)?;
            }
        }
        Ok(len)
    }

    /// Reserve the union with unique, possibly unordered candidates; no withdrawal credit.
    pub(in crate::manager) fn reserve_admitted_with_checkpoint<A>(
        &mut self,
        peer: IpAddr,
        announcements: A,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<bool, Failure>
    where
        A: Iterator<Item = Key>,
    {
        let Some(index) = self.complete_index(peer, checkpoint)? else {
            return Ok(false);
        };
        let result = Self::union_len(&self.records[index].keys.0, announcements, checkpoint)
            .and_then(|capacity| self.grow_keys(index, capacity, checkpoint));
        if let Err(error) = result {
            return Err(self.fail(index, error, checkpoint));
        }
        Ok(true)
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

    /// Unique ANN may be unordered; W is sorted/unique. Reservation makes this allocation-free.
    pub(in crate::manager) fn apply_admitted_with_checkpoint<A, W>(
        &mut self,
        peer: IpAddr,
        announcements: A,
        withdrawals: W,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<bool, Failure>
    where
        A: Clone + Iterator<Item = Key>,
        W: Clone + Iterator<Item = Key>,
    {
        let Some(index) = self.complete_index(peer, checkpoint)? else {
            return Ok(false);
        };
        let mut previous = None;
        let mut prior_cursor = 0;
        for key in withdrawals.clone() {
            checkpoint(false);
            if previous.is_some_and(|prior| prior >= key) {
                return Err(self.fail(index, self.missing_proof(peer), checkpoint));
            }
            previous = Some(key);
            let keys = &self.records[index].keys.0;
            while prior_cursor < keys.len() && keys[prior_cursor] < key {
                checkpoint(false);
                prior_cursor += 1;
            }
            checkpoint(false);
            if keys.get(prior_cursor) != Some(&key) {
                return Err(self.fail(index, self.missing_proof(peer), checkpoint));
            }
        }
        if !self.reserve_admitted_with_checkpoint(peer, announcements.clone(), checkpoint)? {
            return Ok(false);
        }
        let keys = &mut self.records[index].keys.0;
        let mut withdrawals = withdrawals;
        let mut withdrawn = withdrawals.next();
        keys.retain(|key| {
            checkpoint(false);
            while withdrawn.is_some_and(|withdrawal| withdrawal < *key) {
                checkpoint(false);
                withdrawn = withdrawals.next();
            }
            withdrawn != Some(*key)
        });
        let old_len = keys.len();
        for key in announcements {
            checkpoint(false);
            if keys[..old_len]
                .binary_search_by(|prior| {
                    checkpoint(false);
                    prior.cmp(&key)
                })
                .is_err()
            {
                if keys.len() == keys.capacity() {
                    return Err(self.fail(index, self.missing_proof(peer), checkpoint));
                }
                keys.push(key);
            }
        }
        if keys.len() != old_len {
            Self::sort_keys(keys, checkpoint);
        }
        Ok(true)
    }

    pub(in crate::manager) fn remove_with_checkpoint(
        &mut self,
        peer: &IpAddr,
        checkpoint: &mut impl FnMut(bool),
    ) -> bool {
        let Ok(index) = self.index_with_checkpoint(*peer, checkpoint) else {
            return false;
        };
        self.free_keys(index, checkpoint);
        checkpoint(true);
        drop(self.records.remove(index));
        checkpoint(true);
        if self.records.is_empty() {
            let bytes = self.records.capacity() * size_of::<Record>();
            checkpoint(true);
            self.records
                .try_grow(0)
                .expect("empty pinned SmallVec deallocation cannot fail");
            self.used -= bytes;
            checkpoint(true);
        }
        true
    }

    #[cfg(test)]
    pub(in crate::manager) fn clear_with_checkpoint(&mut self, checkpoint: &mut impl FnMut(bool)) {
        while let Some(record) = self.records.last() {
            let peer = record.peer;
            checkpoint(false);
            self.remove_with_checkpoint(&peer, checkpoint);
        }
    }
}

#[cfg(test)]
impl AdmittedRecovery {
    pub(in crate::manager) fn entries(&self) -> usize {
        self.entries_with_checkpoint(&mut |_| {})
    }

    pub(in crate::manager) fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub(in crate::manager) fn begin_capture(&mut self, peer: IpAddr) -> Result<bool, Failure> {
        self.begin_capture_with_checkpoint(peer, &mut |_| {})
    }

    pub(in crate::manager) fn push_capture(
        &mut self,
        peer: IpAddr,
        key: Key,
    ) -> Result<(), Failure> {
        self.push_capture_with_checkpoint(peer, key, &mut |_| {})
    }

    pub(in crate::manager) fn seal_capture(&mut self, peer: IpAddr) -> Result<(), Failure> {
        self.seal_capture_with_checkpoint(peer, &mut |_| {})
    }

    pub(in crate::manager) fn insert_empty(&mut self, peer: IpAddr) -> Result<(), Failure> {
        self.insert_empty_with_checkpoint(peer, &mut |_| {})
    }

    pub(in crate::manager) fn reserve_admitted<A: Iterator<Item = Key>>(
        &mut self,
        peer: IpAddr,
        announcements: A,
    ) -> Result<bool, Failure> {
        self.reserve_admitted_with_checkpoint(peer, announcements, &mut |_| {})
    }

    pub(in crate::manager) fn apply_admitted<A, W>(
        &mut self,
        peer: IpAddr,
        announcements: A,
        withdrawals: W,
    ) -> Result<bool, Failure>
    where
        A: Clone + Iterator<Item = Key>,
        W: Clone + Iterator<Item = Key>,
    {
        self.apply_admitted_with_checkpoint(peer, announcements, withdrawals, &mut |_| {})
    }

    pub(in crate::manager) fn remove(&mut self, peer: &IpAddr) -> bool {
        self.remove_with_checkpoint(peer, &mut |_| {})
    }

    pub(in crate::manager) fn clear(&mut self) {
        self.clear_with_checkpoint(&mut |_| {});
    }
}

#[cfg(test)]
impl std::ops::Index<&IpAddr> for AdmittedRecovery {
    type Output = AdmittedKeys;

    fn index(&self, peer: &IpAddr) -> &Self::Output {
        self.get(peer).expect("a complete admitted proof")
    }
}

#[cfg(test)]
impl FromIterator<ExactExportKey> for AdmittedKeys {
    fn from_iter<T: IntoIterator<Item = ExactExportKey>>(keys: T) -> Self {
        let mut keys: Keys = keys
            .into_iter()
            .filter_map(|key| Key::try_from(&key).ok())
            .collect();
        keys.sort_unstable();
        keys.dedup();
        Self(keys)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rustbgpd_wire::{Ipv4Prefix, RouteDistinguisher, VpnPrefix};

    use super::*;

    fn peer(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, n))
    }

    fn key(n: u8) -> Key {
        Key::Unicast(
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, n), 32)),
            u32::from(n),
        )
    }

    fn capture(ledger: &mut AdmittedRecovery, peer: IpAddr, keys: &[Key]) {
        assert!(ledger.begin_capture(peer).unwrap());
        for &key in keys {
            ledger.push_capture(peer, key).unwrap();
        }
        ledger.seal_capture(peer).unwrap();
    }

    #[test]
    fn capture_is_hidden_until_sealed_and_retains_duplicate_slack() {
        let mut ledger = AdmittedRecovery::new();
        assert!(ledger.begin_capture(peer(1)).unwrap());
        for n in [7, 3, 7, 1, 5] {
            ledger.push_capture(peer(1), key(n)).unwrap();
        }
        let charged = ledger.bytes();
        assert_eq!(ledger.entries(), 5);
        assert!(ledger.contains_record(peer(1)));
        assert!(!ledger.contains_key(&peer(1)));
        assert_eq!(ledger.keys().count(), 0);
        assert!(!ledger.begin_capture(peer(1)).unwrap());
        ledger.seal_capture(peer(1)).unwrap();
        assert_eq!(ledger.entries(), 4);
        assert_eq!(ledger.bytes(), charged);
        assert_eq!(
            ledger[&peer(1)].iter().collect::<Vec<_>>(),
            [1, 3, 5, 7].map(|n| ExactExportKey::from(key(n)))
        );
        assert!(ledger[&peer(1)].contains(&key(3).into()));
        assert!(!ledger[&peer(1)].contains(&key(2).into()));
    }

    #[test]
    fn fresh_empty_proof_does_not_capture_desired_keys() {
        let mut ledger = AdmittedRecovery::new();
        ledger.insert_empty(peer(2)).unwrap();
        assert!(ledger[&peer(2)].is_empty());
        assert!(!ledger.begin_capture(peer(2)).unwrap());
        assert_eq!(ledger.keys().copied().collect::<Vec<_>>(), [peer(2)]);
        assert!(
            !ledger
                .apply_admitted(peer(1), [key(1)].into_iter(), [].into_iter())
                .unwrap()
        );
        assert!(
            ledger
                .apply_admitted(peer(2), [key(1)].into_iter(), [].into_iter())
                .unwrap()
        );
        assert_eq!(ledger[&peer(2)].len(), 1);
    }

    #[test]
    fn compact_keys_round_trip_unicast_and_vpn_path_identity() {
        let vpn = Key::Vpn(
            VpnRouteKey {
                route_distinguisher: RouteDistinguisher::new([0, 0, 0xfd, 0xe8, 0, 0, 0, 7]),
                prefix: VpnPrefix::V4 {
                    addr: Ipv4Addr::new(10, 2, 0, 0),
                    len: 16,
                },
            },
            123,
        );
        for compact in [key(9), vpn] {
            let exact = ExactExportKey::from(compact);
            assert_eq!(Key::try_from(&exact), Ok(compact));
        }
        let unsupported = ExactExportKey::Labeled(crate::route::LabeledRibRouteKey {
            prefix: match key(9) {
                Key::Unicast(prefix, _) => prefix,
                Key::Vpn(_, _) => unreachable!(),
            },
            path_id: 9,
        });
        assert!(Key::try_from(&unsupported).is_err());
        let mut ledger = AdmittedRecovery::new();
        capture(&mut ledger, peer(1), &[vpn, key(9)]);
        assert!(!ledger[&peer(1)].contains(&unsupported));
        assert_eq!(
            ledger[&peer(1)].iter().collect::<Vec<_>>(),
            [key(9), vpn].map(ExactExportKey::from)
        );
    }

    #[test]
    fn exact_union_reservation_uses_no_withdrawal_credit() {
        let r = size_of::<Record>();
        let k = size_of::<Key>();
        let h = size_of::<Keys>();
        let mut ledger =
            AdmittedRecovery::with_test_limits((r + 10 * k + h).max(2 * r), DAEMON_LIMIT_BYTES);
        capture(&mut ledger, peer(1), &[key(1), key(3), key(5), key(7)]);
        assert!(
            ledger
                .reserve_admitted(peer(1), [key(3), key(4), key(6)].into_iter())
                .unwrap()
        );
        assert_eq!(ledger.records[0].keys.0.capacity(), 6);
        assert_eq!(ledger.entries(), 4); // Reservation does not publish candidate keys.
        let charged = ledger.bytes();
        assert!(
            ledger
                .apply_admitted(
                    peer(1),
                    [key(6), key(3)].into_iter(),
                    [key(1), key(5)].into_iter()
                )
                .unwrap()
        );
        assert_eq!(
            ledger[&peer(1)].iter().collect::<Vec<_>>(),
            [3, 6, 7].map(|n| ExactExportKey::from(key(n)))
        );
        assert_eq!(ledger.bytes(), charged);
    }

    #[test]
    fn filtered_commit_replay_and_withdraw_reannounce_do_not_allocate() {
        let mut ledger = AdmittedRecovery::new();
        capture(&mut ledger, peer(1), &[key(1), key(3), key(5)]);
        ledger
            .reserve_admitted(peer(1), [key(2), key(3), key(4)].into_iter())
            .unwrap();
        let charged = ledger.bytes();
        ledger.fail_next_allocation_for_test();
        ledger
            .apply_admitted(
                peer(1),
                [key(2), key(3)].into_iter(),
                [key(1), key(3), key(5)].into_iter(),
            )
            .unwrap();
        assert_eq!(
            ledger[&peer(1)].iter().collect::<Vec<_>>(),
            [2, 3].map(|n| ExactExportKey::from(key(n)))
        );
        ledger
            .apply_admitted(peer(1), [key(3), key(2)].into_iter(), [].into_iter())
            .unwrap();
        assert_eq!(ledger.bytes(), charged);
        assert!(ledger.fail_next_allocation);
        let error = ledger
            .reserve_admitted(peer(1), (1..=8).map(key))
            .unwrap_err();
        assert_eq!(error.cause, FailureCause::AllocationFailure);
        assert!(!ledger.fail_next_allocation);
        assert!(ledger.get(&peer(1)).is_none());
        assert_eq!(ledger.entries(), 0);
    }

    #[test]
    fn failed_key_allocation_releases_partial_keys_and_is_sticky() {
        let mut ledger = AdmittedRecovery::new();
        assert!(ledger.begin_capture(peer(1)).unwrap());
        ledger.push_capture(peer(1), key(1)).unwrap();
        let baseline = size_of::<AdmittedRecovery>() + size_of::<Record>();
        ledger.fail_next_allocation_for_test();
        let error = ledger.push_capture(peer(1), key(2)).unwrap_err();
        assert_eq!(error.cause, FailureCause::AllocationFailure);
        assert_eq!(ledger.bytes(), baseline);
        assert_eq!(ledger.entries(), 0);
        assert!(ledger.contains_record(peer(1)));
        assert!(!ledger.contains_key(&peer(1)));
        assert_eq!(ledger.begin_capture(peer(1)), Err(error));
        assert_eq!(ledger.push_capture(peer(1), key(3)), Err(error));
        assert_eq!(ledger.seal_capture(peer(1)), Err(error));
        assert_eq!(ledger.insert_empty(peer(1)), Err(error));
        assert_eq!(
            ledger.apply_admitted(peer(1), [].into_iter(), [].into_iter()),
            Err(error)
        );
        assert!(ledger.remove(&peer(1)));
        assert_eq!(ledger.bytes(), size_of::<AdmittedRecovery>());
        capture(&mut ledger, peer(1), &[key(3)]);
        assert_eq!(ledger[&peer(1)].len(), 1);
    }

    #[test]
    fn metadata_allocation_failure_rolls_back_without_publishing_a_record() {
        let mut ledger = AdmittedRecovery::new();
        let baseline = ledger.bytes();
        ledger.fail_next_allocation_for_test();
        let error = ledger.begin_capture(peer(1)).unwrap_err();
        assert_eq!(error.cause, FailureCause::AllocationFailure);
        assert!(!ledger.contains_record(peer(1)));
        assert_eq!(ledger.bytes(), baseline);
        assert_eq!(ledger.peak_bytes(), error.attempted_daemon_bytes);
        assert!(ledger.peak_bytes() > baseline);
        assert!(ledger.begin_capture(peer(1)).unwrap());
    }

    #[test]
    fn peer_cap_checks_old_and_entire_new_capacity_before_growth() {
        let r = size_of::<Record>();
        let k = size_of::<Key>();
        let h = size_of::<Keys>();
        let cap = (r + 24 * k + h).max(2 * r);
        let mut ledger = AdmittedRecovery::with_test_limits(cap, DAEMON_LIMIT_BYTES);
        assert!(ledger.begin_capture(peer(1)).unwrap());
        for n in 1..=16 {
            ledger.push_capture(peer(1), key(n)).unwrap();
        }
        let before = ledger.peak_bytes();
        let error = ledger.push_capture(peer(1), key(17)).unwrap_err();
        assert_eq!(error.cause, FailureCause::PeerLimit);
        assert_eq!(error.limiting_peer, Some(peer(1)));
        assert_eq!(error.attempted_peer_bytes, r + 48 * k + h);
        assert_eq!(ledger.peak_bytes(), before); // Refused reservation never got credit.
        assert_eq!(ledger.bytes(), size_of::<AdmittedRecovery>() + r);
        assert!(!ledger.contains_key(&peer(1)));
    }

    #[test]
    fn metadata_overlap_can_name_another_peer_as_the_limit() {
        let r = size_of::<Record>();
        let k = size_of::<Key>();
        let mut ledger = AdmittedRecovery::with_test_limits(4 * r, DAEMON_LIMIT_BYTES);
        capture(&mut ledger, peer(1), &[]);
        capture(&mut ledger, peer(2), &[]);
        // Fill peer 1 almost to its cap using one exact union allocation.
        let count = (3 * r - size_of::<Keys>()) / k;
        assert!(count > 0);
        ledger
            .reserve_admitted(peer(1), (0..u8::try_from(count).unwrap()).map(key))
            .unwrap();
        let before = ledger.bytes();
        ledger.peer_limit = r + count * k; // Retained storage fits; its copied header does not.
        assert!(ledger.peer_limit >= 2 * r);
        let error = ledger.begin_capture(peer(3)).unwrap_err();
        assert_eq!(error.cause, FailureCause::PeerLimit);
        assert_eq!(error.limiting_peer, Some(peer(1)));
        assert!(!ledger.contains_record(peer(3)));
        assert!(ledger.contains_key(&peer(1)));
        assert!(ledger.contains_key(&peer(2)));
        assert_eq!(ledger.bytes(), before);
    }

    #[test]
    fn daemon_cap_counts_full_metadata_overlap_before_insertion() {
        let r = size_of::<Record>();
        let base = size_of::<AdmittedRecovery>();
        let cap = base + 3 * r + size_of::<Records>();
        let mut ledger = AdmittedRecovery::with_test_limits(PEER_LIMIT_BYTES, cap);
        ledger.insert_empty(peer(1)).unwrap();
        let before = ledger.bytes();
        let error = ledger.insert_empty(peer(2)).unwrap_err();
        assert_eq!(error.cause, FailureCause::DaemonLimit);
        assert_eq!(
            error.attempted_daemon_bytes,
            base + 4 * r + size_of::<Records>()
        );
        assert_eq!(ledger.bytes(), before);
        assert!(ledger.contains_key(&peer(1)));
        assert!(!ledger.contains_record(peer(2)));
    }

    #[test]
    fn withdrawals_retain_capacity_and_release_frees_before_credit() {
        let mut ledger = AdmittedRecovery::new();
        capture(&mut ledger, peer(2), &[key(1), key(2), key(3)]);
        ledger.insert_empty(peer(1)).unwrap();
        let charged = ledger.bytes();
        ledger
            .apply_admitted(
                peer(2),
                [].into_iter(),
                [key(1), key(2), key(3)].into_iter(),
            )
            .unwrap();
        assert!(ledger[&peer(2)].is_empty());
        assert_eq!(ledger.bytes(), charged);
        assert!(ledger.remove(&peer(2)));
        assert_eq!(
            ledger.bytes(),
            size_of::<AdmittedRecovery>() + 2 * size_of::<Record>()
        );
        assert_eq!(ledger.keys().copied().collect::<Vec<_>>(), [peer(1)]);
        assert!(!ledger.remove(&peer(2)));
        let peak = ledger.peak_bytes();
        ledger.clear();
        assert_eq!(ledger.bytes(), size_of::<AdmittedRecovery>());
        assert_eq!(ledger.entries(), 0);
        assert_eq!(ledger.keys().count(), 0);
        assert_eq!(ledger.records.capacity(), 0);
        assert_eq!(ledger.peak_bytes(), peak);
    }

    #[test]
    fn overflow_fails_closed_and_cause_names_are_fixed() {
        let mut ledger = AdmittedRecovery::new();
        ledger.insert_empty(peer(1)).unwrap();
        let before = ledger.bytes();
        let error = ledger.grow_keys(0, usize::MAX, &mut |_| {}).unwrap_err();
        assert_eq!(error.cause, FailureCause::AllocationFailure);
        assert_eq!(error.attempted_daemon_bytes, usize::MAX);
        assert_eq!(ledger.bytes(), before);
        assert_eq!(FailureCause::PeerLimit.as_str(), "peer_limit");
        assert_eq!(FailureCause::DaemonLimit.as_str(), "daemon_limit");
        assert_eq!(
            FailureCause::AllocationFailure.as_str(),
            "allocation_failure"
        );
        assert_eq!(FailureCause::MissingProof.as_str(), "missing_proof");
    }

    #[test]
    fn filtered_unordered_announcements_need_no_exact_size_or_scratch() {
        let mut ledger = AdmittedRecovery::new();
        capture(&mut ledger, peer(1), &[key(1), key(3)]);
        let candidates = [key(4), key(2), key(3), key(5)];
        ledger
            .reserve_admitted(peer(1), candidates.iter().copied())
            .unwrap();
        ledger.fail_next_allocation_for_test();
        let ann = candidates
            .iter()
            .copied()
            .filter(|candidate| *candidate != key(5));
        ledger
            .apply_admitted(peer(1), ann, [key(1), key(3)].iter().copied())
            .unwrap();
        assert_eq!(
            ledger[&peer(1)].iter().collect::<Vec<_>>(),
            [2, 3, 4].map(|n| ExactExportKey::from(key(n)))
        );
        assert!(ledger.fail_next_allocation);
        let fixture: AdmittedKeys = [key(4), key(2), key(2), key(3)]
            .map(ExactExportKey::from)
            .into_iter()
            .collect();
        assert_eq!(ledger[&peer(1)], fixture);
    }

    #[test]
    fn malformed_withdrawals_fail_closed_without_panicking() {
        for withdrawals in [[key(2), key(1)], [key(1), key(1)], [key(1), key(3)]] {
            let mut ledger = AdmittedRecovery::new();
            capture(&mut ledger, peer(1), &[key(1), key(2)]);
            let error = ledger
                .apply_admitted(peer(1), [].into_iter(), withdrawals.into_iter())
                .unwrap_err();
            assert_eq!(error.cause, FailureCause::MissingProof);
            assert!(ledger.get(&peer(1)).is_none());
            assert_eq!(ledger.entries(), 0);
            assert_eq!(
                ledger.bytes(),
                size_of::<AdmittedRecovery>() + size_of::<Record>()
            );
            assert_eq!(ledger.begin_capture(peer(1)), Err(error));
        }
    }

    #[test]
    fn insufficient_reservation_fails_without_allocating_or_panicking() {
        let mut ledger = AdmittedRecovery::new();
        capture(&mut ledger, peer(1), &[key(1)]);
        let peak = ledger.peak_bytes();
        ledger.fail_next_allocation_for_test();
        // A duplicated re-announce after W violates the caller's unique ANN contract.
        let error = ledger
            .apply_admitted(peer(1), [key(1), key(1)].into_iter(), [key(1)].into_iter())
            .unwrap_err();
        assert_eq!(error.cause, FailureCause::MissingProof);
        assert!(ledger.fail_next_allocation);
        assert_eq!(ledger.peak_bytes(), peak);
        assert_eq!(ledger.entries(), 0);
        assert!(ledger.get(&peer(1)).is_none());
        assert_eq!(ledger.begin_capture(peer(1)), Err(error));
    }

    #[test]
    fn applying_an_incomplete_capture_releases_it_and_stays_failed() {
        let mut ledger = AdmittedRecovery::new();
        assert!(ledger.is_empty());
        assert!(ledger.begin_capture(peer(1)).unwrap());
        assert!(!ledger.is_empty());
        ledger.push_capture(peer(1), key(1)).unwrap();
        let error = ledger
            .reserve_admitted(peer(1), [].into_iter())
            .unwrap_err();
        assert_eq!(error.cause, FailureCause::MissingProof);
        assert_eq!(ledger.entries(), 0);
        assert!(ledger.get(&peer(1)).is_none());
        assert_eq!(ledger.seal_capture(peer(1)), Err(error));
        assert_eq!(
            ledger.bytes(),
            size_of::<AdmittedRecovery>() + size_of::<Record>()
        );
        assert!(!ledger.is_empty()); // Failed records still need retirement.
        assert!(ledger.remove(&peer(1)));
        assert!(ledger.is_empty());
    }

    #[test]
    fn checkpoint_covers_capture_union_application_growth_sort_and_retirement() {
        let mut ledger = AdmittedRecovery::new();
        let mut events = Vec::new();
        ledger
            .begin_capture_with_checkpoint(peer(1), &mut |force| events.push(force))
            .unwrap();
        for n in [3, 1, 2] {
            ledger
                .push_capture_with_checkpoint(peer(1), key(n), &mut |force| events.push(force))
                .unwrap();
        }
        ledger
            .seal_capture_with_checkpoint(peer(1), &mut |force| events.push(force))
            .unwrap();
        assert!(events.iter().filter(|force| **force).count() >= 10);
        events.clear();
        assert_eq!(
            ledger.entries_with_checkpoint(&mut |force| events.push(force)),
            3
        );
        assert_eq!(events, [false]);
        events.clear();
        ledger
            .reserve_admitted_with_checkpoint(
                peer(1),
                [key(5), key(3), key(4)].iter().copied(),
                &mut |force| events.push(force),
            )
            .unwrap();
        assert_eq!(events.iter().filter(|force| **force).count(), 2); // One exact growth.
        assert!(events.iter().filter(|force| !**force).count() >= 3);
        events.clear();
        ledger
            .apply_admitted_with_checkpoint(
                peer(1),
                [key(4), key(3)].iter().copied(),
                [key(1), key(3)].iter().copied(),
                &mut |force| events.push(force),
            )
            .unwrap();
        assert_eq!(events.iter().filter(|force| **force).count(), 2); // Only the in-place sort.
        assert!(events.iter().filter(|force| !**force).count() >= 6);
        events.clear();
        assert!(ledger.remove_with_checkpoint(&peer(1), &mut |force| events.push(force)));
        assert_eq!(events.iter().filter(|force| **force).count(), 6);
        assert_eq!(ledger.bytes(), size_of::<AdmittedRecovery>());
    }
}
