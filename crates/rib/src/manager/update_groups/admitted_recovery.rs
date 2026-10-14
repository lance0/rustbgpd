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

/// Immutable pool identity; never reused even after its storage is released.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::manager) struct SnapshotHandle(u64);

type Words = SmallVec<[u64; 0]>;
type Snapshots = SmallVec<[Snapshot; 0]>;

#[derive(Debug)]
#[cfg_attr(test, derive(Clone, PartialEq, Eq))]
struct Snapshot {
    handle: SnapshotHandle,
    references: usize,
    keys: Keys,
}

impl Snapshot {
    fn charge(&self) -> usize {
        size_of::<Self>() + self.keys.capacity() * size_of::<Key>()
    }
}

/// A borrowed exact set. Only mask bits and sparse keys prove admission;
/// membership in the raw immutable key universe never does.
#[derive(Clone, Copy, Debug)]
pub(in crate::manager) struct AdmittedKeyView<'a> {
    universe: &'a [Key],
    words: &'a [u64],
    sparse: &'a [Key],
    masked: usize,
}

impl<'a> AdmittedKeyView<'a> {
    pub(in crate::manager) fn len(self) -> usize {
        self.masked + self.sparse.len()
    }

    pub(in crate::manager) fn is_empty(self) -> bool {
        self.len() == 0
    }

    fn contains_key(self, key: Key) -> bool {
        self.universe.binary_search(&key).is_ok_and(|index| {
            self.words
                .get(index / 64)
                .is_some_and(|word| word & (1_u64 << (index % 64)) != 0)
        }) || self.sparse.binary_search(&key).is_ok()
    }

    pub(in crate::manager) fn contains(self, key: &ExactExportKey) -> bool {
        Key::try_from(key).is_ok_and(|key| self.contains_key(key))
    }

    #[cfg(test)]
    pub(in crate::manager) fn iter(self) -> impl Iterator<Item = ExactExportKey> + 'a {
        self.iter_with_checkpoint(|_| {})
    }

    /// Visit every underlying universe key, including masked-out and trailing
    /// entries, before merging the admitted subset with sparse additions.
    pub(in crate::manager) fn iter_with_checkpoint<'c>(
        self,
        mut checkpoint: impl FnMut(bool) + 'c,
    ) -> impl Iterator<Item = ExactExportKey> + 'c
    where
        'a: 'c,
    {
        let mut base_index = 0;
        let mut sparse_index = 0;
        let mut pending_base = None;
        std::iter::from_fn(move || {
            while pending_base.is_none() && base_index < self.universe.len() {
                checkpoint(false);
                let index = base_index;
                base_index += 1;
                if self.words[index / 64] & (1_u64 << (index % 64)) != 0 {
                    pending_base = Some(self.universe[index]);
                }
            }
            let sparse = self.sparse.get(sparse_index).copied();
            let key = match (pending_base, sparse) {
                (Some(a), Some(b)) if a <= b => pending_base.take(),
                (Some(_) | None, Some(_)) => {
                    checkpoint(false);
                    sparse_index += 1;
                    sparse
                }
                (Some(_), None) => pending_base.take(),
                (None, None) => None,
            };
            key.map(ExactExportKey::from)
        })
    }
}

#[cfg(test)]
impl AdmittedKeys {
    pub(in crate::manager) fn view(&self) -> AdmittedKeyView<'_> {
        AdmittedKeyView {
            universe: &[],
            words: &[],
            sparse: &self.0,
            masked: 0,
        }
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
    snapshot: Option<SnapshotHandle>,
    words: Words,
    masked: usize,
}

impl Record {
    fn charge(&self) -> usize {
        size_of::<Self>()
            + self.keys.0.capacity() * size_of::<Key>()
            + self.words.capacity() * size_of::<u64>()
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(Clone, PartialEq, Eq))]
pub(in crate::manager) struct AdmittedRecovery {
    records: Records,
    snapshots: Snapshots,
    next_snapshot: Option<u64>,
    used: usize,
    peak: usize,
    peer_limit: usize,
    daemon_limit: usize,
    #[cfg(test)]
    fail_next_allocation: bool,
    #[cfg(test)]
    allocation_countdown: Option<usize>,
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
            snapshots: Snapshots::new(),
            next_snapshot: Some(1),
            used: size_of::<Self>(),
            peak: size_of::<Self>(),
            peer_limit,
            daemon_limit,
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

    pub(in crate::manager) fn entries_with_checkpoint(
        &self,
        checkpoint: &mut impl FnMut(bool),
    ) -> usize {
        self.records
            .iter()
            .map(|record| {
                checkpoint(false);
                record.masked + record.keys.0.len()
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

    pub(in crate::manager) fn get(&self, peer: &IpAddr) -> Option<AdmittedKeyView<'_>> {
        let record = &self.records[self.index(*peer).ok()?];
        if record.state != State::Complete {
            return None;
        }
        let universe = match record.snapshot {
            Some(handle) => self
                .snapshots
                .get(self.snapshot_index(handle)?)?
                .keys
                .as_slice(),
            None => &[],
        };
        Some(AdmittedKeyView {
            universe,
            words: &record.words,
            sparse: &record.keys.0,
            masked: record.masked,
        })
    }

    #[cfg(test)]
    pub(in crate::manager) fn owned_proof(&self, peer: &IpAddr) -> Option<AdmittedKeys> {
        self.get(peer).map(|proof| proof.iter().collect())
    }

    #[cfg(test)]
    pub(in crate::manager) fn keys(&self) -> impl Iterator<Item = &IpAddr> {
        self.records
            .iter()
            .filter_map(|record| (record.state == State::Complete).then_some(&record.peer))
    }

    fn snapshot_index(&self, handle: SnapshotHandle) -> Option<usize> {
        self.snapshots
            .binary_search_by_key(&handle.0, |snapshot| snapshot.handle.0)
            .ok()
    }

    fn peer_charge(&self, index: usize) -> usize {
        let record = &self.records[index];
        record.charge()
            + record
                .snapshot
                .and_then(|handle| self.snapshot_index(handle))
                .map_or(0, |index| self.snapshots[index].charge())
    }

    fn shared_words(count: usize) -> Result<usize, Failure> {
        count
            .checked_add(63)
            .map(|count| count / 64)
            .ok_or_else(Self::overflow)
    }

    /// Create directly in charged fallible storage. No intermediate full key
    /// collection or infallible shared heap header exists.
    #[expect(
        clippy::too_many_lines,
        reason = "snapshot construction and all temporary header/capacity credits roll back at the same ownership boundary"
    )]
    fn create_snapshot<A: Iterator<Item = Key>>(
        &mut self,
        peer: IpAddr,
        count: usize,
        keys: A,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<SnapshotHandle, Failure> {
        let index = self.index(peer).map_err(|_| self.missing_proof(peer))?;
        let id = self.next_snapshot.ok_or_else(Self::overflow)?;
        let key_bytes = count
            .checked_mul(size_of::<Key>())
            .ok_or_else(Self::overflow)?;
        let temporary = key_bytes
            .checked_add(size_of::<Snapshot>())
            .and_then(|n| n.checked_add(size_of::<Keys>()))
            .ok_or_else(Self::overflow)?;
        let attempted_peer = self
            .peer_charge(index)
            .checked_add(temporary)
            .and_then(|n| n.checked_add(size_of::<Snapshot>()))
            .ok_or_else(Self::overflow)?;
        let daemon = self
            .used
            .checked_add(temporary)
            .ok_or_else(Self::overflow)?;
        self.check(peer, attempted_peer, daemon)?;
        self.used = daemon;
        self.peak = self.peak.max(daemon);
        let mut owned = Keys::new();
        checkpoint(true);
        let failed = !self.allocation_permitted() || owned.try_grow(count).is_err();
        checkpoint(true);
        if failed {
            checkpoint(true);
            drop(owned);
            checkpoint(true);
            self.used -= temporary;
            return Err(Failure {
                cause: FailureCause::AllocationFailure,
                limiting_peer: None,
                attempted_peer_bytes: attempted_peer,
                attempted_daemon_bytes: daemon,
            });
        }
        for key in keys {
            checkpoint(false);
            if owned.len() == count {
                checkpoint(true);
                drop(owned);
                checkpoint(true);
                self.used -= temporary;
                return Err(self.missing_proof(peer));
            }
            owned.push(key);
        }
        Self::sort_keys(&mut owned, checkpoint);
        let old_cap = self.snapshots.capacity();
        let new_cap = if old_cap == self.snapshots.len() {
            if let Some(cap) = old_cap.checked_mul(2) {
                cap.max(1)
            } else {
                checkpoint(true);
                drop(owned);
                checkpoint(true);
                self.used -= temporary;
                return Err(Self::overflow());
            }
        } else {
            old_cap
        };
        let resizing = new_cap != old_cap;
        let extra = if resizing {
            if let Some(n) = new_cap
                .checked_mul(size_of::<Snapshot>())
                .and_then(|n| n.checked_add(size_of::<Snapshots>()))
            {
                n
            } else {
                checkpoint(true);
                drop(owned);
                checkpoint(true);
                self.used -= temporary;
                return Err(Self::overflow());
            }
        } else {
            0
        };
        let Some(daemon) = self.used.checked_add(extra) else {
            checkpoint(true);
            drop(owned);
            checkpoint(true);
            self.used -= temporary;
            return Err(Self::overflow());
        };
        if resizing {
            for record_index in 0..self.records.len() {
                checkpoint(false);
                if self.records[record_index].snapshot.is_some() {
                    let address = self.records[record_index].peer;
                    let charge = self
                        .peer_charge(record_index)
                        .checked_add(size_of::<Snapshot>());
                    let result = charge
                        .ok_or_else(Self::overflow)
                        .and_then(|charge| self.check(address, charge, daemon));
                    if let Err(error) = result {
                        checkpoint(true);
                        drop(owned);
                        checkpoint(true);
                        self.used -= temporary;
                        return Err(error);
                    }
                }
            }
        }
        if let Err(error) = self.check(peer, attempted_peer, daemon) {
            checkpoint(true);
            drop(owned);
            checkpoint(true);
            self.used -= temporary;
            return Err(error);
        }
        self.used = daemon;
        self.peak = self.peak.max(daemon);
        if resizing {
            checkpoint(true);
            let failed = !self.allocation_permitted() || self.snapshots.try_grow(new_cap).is_err();
            checkpoint(true);
            if failed {
                checkpoint(true);
                drop(owned);
                checkpoint(true);
                self.used -= extra + temporary;
                return Err(Failure {
                    cause: FailureCause::AllocationFailure,
                    limiting_peer: None,
                    attempted_peer_bytes: attempted_peer,
                    attempted_daemon_bytes: daemon,
                });
            }
            self.used -= old_cap * size_of::<Snapshot>() + size_of::<Snapshots>();
        }
        checkpoint(true);
        let handle = SnapshotHandle(id);
        self.snapshots.push(Snapshot {
            handle,
            references: 0,
            keys: owned,
        });
        checkpoint(true);
        self.next_snapshot = id.checked_add(1);
        self.used -= size_of::<Snapshot>() + size_of::<Keys>();
        Ok(handle)
    }

    fn release_snapshot(&mut self, handle: SnapshotHandle, checkpoint: &mut impl FnMut(bool)) {
        let Some(index) = self.snapshot_index(handle) else {
            return;
        };
        if self.snapshots[index].references != 0 {
            return;
        }
        let bytes = self.snapshots[index].keys.capacity() * size_of::<Key>();
        checkpoint(true);
        drop(self.snapshots.remove(index));
        self.used -= bytes;
        checkpoint(true);
        if self.snapshots.is_empty() {
            let headers = self.snapshots.capacity() * size_of::<Snapshot>();
            checkpoint(true);
            self.snapshots
                .try_grow(0)
                .expect("empty pinned SmallVec deallocation cannot fail");
            self.used -= headers;
            checkpoint(true);
        }
    }

    /// Reserve immediate sparse additions before optional snapshot publication.
    /// A refused empty representation leaves authoritative flat capture available.
    pub(in crate::manager) fn share_capture_with_checkpoint<A: Iterator<Item = Key>>(
        &mut self,
        peer: IpAddr,
        hint: Option<SnapshotHandle>,
        count: usize,
        keys: A,
        shape: (usize, usize),
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<Option<SnapshotHandle>, Failure> {
        let index = self.index(peer).map_err(|_| self.missing_proof(peer))?;
        if self.records[index].masked != 0 || !self.records[index].keys.0.is_empty() {
            return Ok(self.records[index].snapshot);
        }
        if self.records[index].snapshot.is_none() && count == 0 {
            return Ok(None);
        }
        if matches!(self.records[index].state, State::Failed(_)) {
            return Err(self.missing_proof(peer));
        }
        let shared = self.grow_keys(index, shape.1, checkpoint).and_then(|()| {
            self.attach_snapshot_with_checkpoint(index, hint, count, keys, shape.0, checkpoint)
        });
        if matches!(shared, Ok(Some(_))) {
            return shared;
        }
        self.free_keys(index, checkpoint);
        shared
    }

    fn attach_snapshot_with_checkpoint<A: Iterator<Item = Key>>(
        &mut self,
        index: usize,
        hint: Option<SnapshotHandle>,
        count: usize,
        keys: A,
        filtered: usize,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<Option<SnapshotHandle>, Failure> {
        if let Some(handle) = self.records[index].snapshot {
            return Ok(Some(handle));
        }
        let peer = self.records[index].peer;
        let words = Self::shared_words(count)?;
        let bytes = words
            .checked_mul(size_of::<u64>())
            .ok_or_else(Self::overflow)?;
        let flat = filtered
            .checked_mul(size_of::<Key>())
            .ok_or_else(Self::overflow)?;
        if flat < bytes {
            return Ok(None);
        }
        let reused = hint.filter(|handle| self.snapshot_index(*handle).is_some());
        let (actual_words, snapshot_charge) = if let Some(handle) = reused {
            let snapshot = &self.snapshots[self
                .snapshot_index(handle)
                .ok_or_else(|| self.missing_proof(peer))?];
            (Self::shared_words(snapshot.keys.len())?, snapshot.charge())
        } else {
            (
                words,
                count
                    .checked_mul(size_of::<Key>())
                    .and_then(|n| n.checked_add(size_of::<Snapshot>()))
                    .ok_or_else(Self::overflow)?,
            )
        };
        let bytes = actual_words
            .checked_mul(size_of::<u64>())
            .ok_or_else(Self::overflow)?;
        let attempted_peer = self.records[index]
            .charge()
            .checked_add(snapshot_charge)
            .and_then(|n| n.checked_add(bytes))
            .and_then(|n| n.checked_add(size_of::<Words>()))
            .ok_or_else(Self::overflow)?;
        let extra = bytes
            .checked_add(size_of::<Words>())
            .ok_or_else(Self::overflow)?;
        let daemon = self.used.checked_add(extra).ok_or_else(Self::overflow)?;
        self.check(peer, attempted_peer, daemon)?;
        self.used = daemon;
        self.peak = self.peak.max(daemon);
        checkpoint(true);
        let failed = !self.allocation_permitted()
            || self.records[index].words.try_grow(actual_words).is_err();
        checkpoint(true);
        if failed {
            self.used -= extra;
            return Err(Failure {
                cause: FailureCause::AllocationFailure,
                limiting_peer: None,
                attempted_peer_bytes: attempted_peer,
                attempted_daemon_bytes: daemon,
            });
        }
        for _ in 0..actual_words {
            checkpoint(false);
            self.records[index].words.push(0);
        }
        self.used -= size_of::<Words>();
        // The mask precedes the key/pool allocations. Pool growth is the last
        // fallible step, so a refusal cannot strand an expanded shared pool.
        let handle = match reused {
            Some(handle) => handle,
            None => match self.create_snapshot(peer, count, keys, checkpoint) {
                Ok(handle) => handle,
                Err(error) => {
                    checkpoint(true);
                    self.records[index].words.clear();
                    self.records[index]
                        .words
                        .try_grow(0)
                        .expect("empty pinned SmallVec deallocation cannot fail");
                    self.used -= bytes;
                    checkpoint(true);
                    return Err(error);
                }
            },
        };
        let snapshot_index = self
            .snapshot_index(handle)
            .ok_or_else(|| self.missing_proof(peer))?;
        self.records[index].snapshot = Some(handle);
        self.snapshots[snapshot_index].references += 1;
        Ok(Some(handle))
    }

    /// Count authoritative OLD keys and the sparse capacity needed beside a
    /// live older universe, without collecting an uncharged key inventory.
    pub(in crate::manager) fn capture_shape_with_checkpoint<A: Iterator<Item = Key>>(
        &self,
        hint: Option<SnapshotHandle>,
        keys: A,
        checkpoint: &mut impl FnMut(bool),
    ) -> (usize, usize) {
        let universe = hint
            .and_then(|handle| self.snapshot_index(handle))
            .map(|index| self.snapshots[index].keys.as_slice());
        keys.fold((0, 0), |(count, additions), key| {
            checkpoint(false);
            let missing = universe.is_some_and(|keys| {
                keys.binary_search_by(|prior| {
                    checkpoint(false);
                    prior.cmp(&key)
                })
                .is_err()
            });
            (count + 1, additions + usize::from(missing))
        })
    }

    /// An attached empty proof's universe takes precedence over a group hint.
    pub(in crate::manager) fn candidate_universe_contains(
        &self,
        peer: IpAddr,
        hint: Option<SnapshotHandle>,
        key: &Key,
        checkpoint: &mut impl FnMut(bool),
    ) -> Option<bool> {
        let index = self.index(peer).ok()?;
        let universe = self.records[index].snapshot.or(hint)?;
        let index = self.snapshot_index(universe)?;
        Some(
            self.snapshots[index]
                .keys
                .binary_search_by(|prior| {
                    checkpoint(false);
                    prior.cmp(key)
                })
                .is_ok(),
        )
    }

    /// Reserve flat keys or the exact sparse additions of a shared capture.
    pub(in crate::manager) fn reserve_capture_with_checkpoint(
        &mut self,
        peer: IpAddr,
        count: usize,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<(), Failure> {
        let index = self.index(peer).map_err(|_| self.missing_proof(peer))?;
        if let Err(error) = self.grow_keys(index, count, checkpoint) {
            return Err(self.fail(index, error, checkpoint));
        }
        Ok(())
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
                .map_or(0, |index| self.peer_charge(index)),
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
                    .checked_add(
                        record
                            .snapshot
                            .and_then(|handle| self.snapshot_index(handle))
                            .map_or(0, |index| self.snapshots[index].charge()),
                    )
                    .and_then(|charge| charge.checked_add(size_of::<Record>()))
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
                snapshot: None,
                words: Words::new(),
                masked: 0,
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
        let peer = self
            .peer_charge(index)
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
        let record = &mut self.records[index];
        let bytes = record.keys.0.capacity() * size_of::<Key>()
            + record.words.capacity() * size_of::<u64>();
        record.keys.0.clear();
        record
            .keys
            .0
            .try_grow(0)
            .expect("empty pinned SmallVec deallocation cannot fail");
        record.words.clear();
        record
            .words
            .try_grow(0)
            .expect("empty pinned SmallVec deallocation cannot fail");
        record.masked = 0;
        let snapshot = record.snapshot.take();
        self.used -= bytes;
        checkpoint(true);
        if let Some(handle) = snapshot
            && let Some(snapshot) = self.snapshot_index(handle)
        {
            self.snapshots[snapshot].references -= 1;
            self.release_snapshot(handle, checkpoint);
        }
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
        if let Some(handle) = self.records[index].snapshot {
            let position = self
                .snapshot_index(handle)
                .and_then(|snapshot| self.snapshots[snapshot].keys.binary_search(&key).ok());
            if let Some(position) = position {
                let bit = 1_u64 << (position % 64);
                if self.records[index].words[position / 64] & bit == 0 {
                    self.records[index].words[position / 64] |= bit;
                    self.records[index].masked += 1;
                }
                return Ok(());
            }
            // Only the authoritative OLD producer reaches this seam. A key
            // outside an older universe uses the charged sparse storage.
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
        universe: &[Key],
        announcements: A,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<usize, Failure>
    where
        A: Iterator<Item = Key>,
    {
        let mut len = keys.len();
        for key in announcements {
            checkpoint(false);
            if universe
                .binary_search_by(|prior| {
                    checkpoint(false);
                    prior.cmp(&key)
                })
                .is_ok()
            {
                continue;
            }
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
        let universe = self.records[index]
            .snapshot
            .and_then(|handle| self.snapshot_index(handle))
            .map_or(&[][..], |snapshot| self.snapshots[snapshot].keys.as_slice());
        let result = Self::union_len(
            &self.records[index].keys.0,
            universe,
            announcements,
            checkpoint,
        )
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

    /// A sorted stream keeps its matched position; only its first lookup needs
    /// a lower bound, so a small withdrawal does not walk the whole universe.
    fn sorted_match(
        keys: &[Key],
        cursor: &mut Option<usize>,
        key: Key,
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
        let universe = self.records[index]
            .snapshot
            .and_then(|handle| self.snapshot_index(handle))
            .map_or(&[][..], |snapshot| self.snapshots[snapshot].keys.as_slice());
        let record = &self.records[index];
        let mut previous = None;
        let mut base_cursor = None;
        let mut sparse_cursor = None;
        for key in withdrawals.clone() {
            checkpoint(false);
            if previous.is_some_and(|prior| prior >= key) {
                return Err(self.fail(index, self.missing_proof(peer), checkpoint));
            }
            let admitted = if let Some(position) =
                Self::sorted_match(universe, &mut base_cursor, key, checkpoint)
            {
                record.words[position / 64] & (1_u64 << (position % 64)) != 0
            } else {
                Self::sorted_match(&record.keys.0, &mut sparse_cursor, key, checkpoint).is_some()
            };
            if !admitted {
                return Err(self.fail(index, self.missing_proof(peer), checkpoint));
            }
            previous = Some(key);
        }
        if !self.reserve_admitted_with_checkpoint(peer, announcements.clone(), checkpoint)? {
            return Ok(false);
        }
        let universe = self.records[index]
            .snapshot
            .and_then(|handle| self.snapshot_index(handle))
            .map_or(&[][..], |snapshot| self.snapshots[snapshot].keys.as_slice());
        let record = &mut self.records[index];
        // Replay only after complete validation and reservation. Each direct
        // position is retained for clearing; no matched-position allocation.
        let mut base_cursor = None;
        for key in withdrawals.clone() {
            checkpoint(false);
            if let Some(position) = Self::sorted_match(universe, &mut base_cursor, key, checkpoint)
            {
                record.words[position / 64] &= !(1_u64 << (position % 64));
                record.masked -= 1;
            }
        }
        let keys = &mut record.keys.0;
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
            if let Ok(position) = universe.binary_search(&key) {
                let bit = 1_u64 << (position % 64);
                if record.words[position / 64] & bit == 0 {
                    record.words[position / 64] |= bit;
                    record.masked += 1;
                }
            } else if keys[..old_len]
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
            ledger.get(&peer(1)).unwrap().iter().collect::<Vec<_>>(),
            [1, 3, 5, 7].map(|n| ExactExportKey::from(key(n)))
        );
        assert!(ledger.get(&peer(1)).unwrap().contains(&key(3).into()));
        assert!(!ledger.get(&peer(1)).unwrap().contains(&key(2).into()));
    }

    #[test]
    fn fresh_empty_proof_does_not_capture_desired_keys() {
        let mut ledger = AdmittedRecovery::new();
        ledger.insert_empty(peer(2)).unwrap();
        assert!(ledger.get(&peer(2)).unwrap().is_empty());
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
        assert_eq!(ledger.get(&peer(2)).unwrap().len(), 1);
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
        assert!(!ledger.get(&peer(1)).unwrap().contains(&unsupported));
        assert_eq!(
            ledger.get(&peer(1)).unwrap().iter().collect::<Vec<_>>(),
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
            ledger.get(&peer(1)).unwrap().iter().collect::<Vec<_>>(),
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
            ledger.get(&peer(1)).unwrap().iter().collect::<Vec<_>>(),
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
        assert_eq!(ledger.get(&peer(1)).unwrap().len(), 1);
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
        assert!(ledger.get(&peer(2)).unwrap().is_empty());
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
            ledger.get(&peer(1)).unwrap().iter().collect::<Vec<_>>(),
            [2, 3, 4].map(|n| ExactExportKey::from(key(n)))
        );
        assert!(ledger.fail_next_allocation);
        let fixture: AdmittedKeys = [key(4), key(2), key(2), key(3)]
            .map(ExactExportKey::from)
            .into_iter()
            .collect();
        assert_eq!(ledger.owned_proof(&peer(1)).unwrap(), fixture);
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
    fn shared_capture(
        ledger: &mut AdmittedRecovery,
        address: IpAddr,
        hint: Option<SnapshotHandle>,
        raw: &[Key],
        actual: &[Key],
    ) -> SnapshotHandle {
        ledger.begin_capture(address).unwrap();
        let shape = ledger.capture_shape_with_checkpoint(hint, actual.iter().copied(), &mut |_| {});
        let handle = ledger
            .share_capture_with_checkpoint(
                address,
                hint,
                raw.len(),
                raw.iter().copied(),
                shape,
                &mut |_| {},
            )
            .unwrap()
            .unwrap();
        for key in actual {
            ledger.push_capture(address, *key).unwrap();
        }
        ledger.seal_capture(address).unwrap();
        handle
    }

    #[test]
    fn shared_proof_checkpoints_excluded_trailing_keys_and_idempotent_candidates() {
        let mut ledger = AdmittedRecovery::new();
        let raw: Vec<_> = (1..=100).map(key).collect();
        shared_capture(&mut ledger, peer(1), None, &raw, &raw[..1]);
        let mut visited = 0;
        let actual: Vec<_> = ledger
            .get(&peer(1))
            .unwrap()
            .iter_with_checkpoint(|force| {
                assert!(!force);
                visited += 1;
            })
            .collect();
        assert_eq!(actual, [ExactExportKey::from(key(1))]);
        assert_eq!(visited, raw.len());

        ledger
            .insert_empty_with_checkpoint(peer(2), &mut |_| {})
            .unwrap();
        let handle =
            ledger.records[ledger.index_with_checkpoint(peer(1), &mut |_| {}).unwrap()].snapshot;
        ledger
            .share_capture_with_checkpoint(
                peer(2),
                handle,
                raw.len(),
                raw.iter().copied(),
                (raw.len(), 0),
                &mut |_| {},
            )
            .unwrap()
            .unwrap();
        visited = 0;
        assert_eq!(
            ledger
                .get(&peer(2))
                .unwrap()
                .iter_with_checkpoint(|_| visited += 1)
                .count(),
            0,
        );
        assert_eq!(visited, raw.len());

        let before = ledger.bytes();
        visited = 0;
        ledger
            .reserve_admitted_with_checkpoint(peer(1), raw.iter().copied(), &mut |force| {
                if !force {
                    visited += 1;
                }
            })
            .unwrap();
        assert!(visited >= raw.len());
        assert_eq!(ledger.bytes(), before);
        assert_eq!(ledger.get(&peer(1)).unwrap().len(), 1);
    }

    #[test]
    fn shared_key_storage_is_charged_once_but_each_peer_references_its_full_charge() {
        let mut ledger = AdmittedRecovery::new();
        let raw: Vec<_> = (1..=100).map(key).collect();
        let handle = shared_capture(&mut ledger, peer(1), None, &raw, &raw);
        let first = ledger.bytes();
        let handle2 = shared_capture(&mut ledger, peer(2), Some(handle), &raw, &raw[..50]);
        assert_eq!(handle, handle2);
        assert_eq!(ledger.snapshots.len(), 1);
        assert_eq!(ledger.snapshots[0].references, 2);
        let local = ledger.records.capacity() * size_of::<Record>()
            + ledger
                .records
                .iter()
                .map(|record| record.words.capacity() * size_of::<u64>())
                .sum::<usize>();
        assert_eq!(
            ledger.bytes(),
            size_of::<AdmittedRecovery>()
                + local
                + ledger.snapshots.capacity() * size_of::<Snapshot>()
                + raw.len() * size_of::<Key>()
        );
        assert!(ledger.bytes() < first + raw.len() * size_of::<Key>());
        assert_eq!(
            ledger.peer_charge(0),
            ledger.records[0].charge() + ledger.snapshots[0].charge()
        );
        assert_eq!(
            ledger.peer_charge(1),
            ledger.records[1].charge() + ledger.snapshots[0].charge()
        );
        assert_eq!(ledger.get(&peer(1)).unwrap().len(), 100);
        assert_eq!(ledger.get(&peer(2)).unwrap().len(), 50);
        assert!(ledger.remove(&peer(1)));
        assert_eq!(ledger.snapshots[0].references, 1);
        assert_eq!(ledger.get(&peer(2)).unwrap().len(), 50);
        assert!(ledger.remove(&peer(2)));
        assert!(ledger.snapshots.is_empty());
        assert_eq!(ledger.snapshots.capacity(), 0);
        assert_eq!(ledger.bytes(), size_of::<AdmittedRecovery>());
    }

    #[test]
    fn shared_mask_sparse_additions_and_mixed_family_iteration_preserve_exact_admission() {
        let mut ledger = AdmittedRecovery::new();
        let vpn = Key::Vpn(
            VpnRouteKey {
                route_distinguisher: RouteDistinguisher::new([0, 0, 0, 1, 0, 0, 0, 2]),
                prefix: VpnPrefix::V4 {
                    addr: Ipv4Addr::new(10, 0, 0, 0),
                    len: 24,
                },
            },
            0,
        );
        let raw = [key(1), key(2), key(4), vpn];
        let handle = shared_capture(&mut ledger, peer(1), None, &raw, &[key(1), vpn]);
        let unused = ledger.get(&peer(1)).unwrap();
        assert!(!unused.contains(&key(2).into()));
        assert_eq!(
            unused.iter().collect::<Vec<_>>(),
            [key(1), vpn].map(ExactExportKey::from)
        );
        ledger
            .reserve_admitted(peer(1), [key(2), key(3), vpn].into_iter())
            .unwrap();
        let reserved = ledger.bytes();
        ledger.fail_next_allocation_for_test();
        ledger
            .apply_admitted(
                peer(1),
                [vpn, key(3), key(2)].into_iter(),
                [key(1), vpn].into_iter(),
            )
            .unwrap();
        ledger
            .apply_admitted(peer(1), [key(3), key(2), vpn].into_iter(), [].into_iter())
            .unwrap();
        assert_eq!(ledger.bytes(), reserved);
        assert!(ledger.fail_next_allocation);
        assert_eq!(
            ledger.get(&peer(1)).unwrap().iter().collect::<Vec<_>>(),
            [key(2), key(3), vpn].map(ExactExportKey::from)
        );
        assert_eq!(ledger.records[0].keys.0.as_slice(), &[key(3)]);
        assert_eq!(ledger.records[0].masked, 2);
        assert_eq!(ledger.records[0].snapshot, Some(handle));
        let error = ledger
            .apply_admitted(peer(1), [].into_iter(), [key(4)].into_iter())
            .unwrap_err();
        assert_eq!(error.cause, FailureCause::MissingProof);
        assert!(ledger.get(&peer(1)).is_none());
        assert!(ledger.snapshots.is_empty());
    }

    fn bulk_vpn_key(n: u8) -> Key {
        Key::Vpn(
            VpnRouteKey {
                route_distinguisher: RouteDistinguisher::new([0, 0, 0, 1, 0, 0, 0, 2]),
                prefix: VpnPrefix::V4 {
                    addr: Ipv4Addr::new(10, 0, 0, n),
                    len: 32,
                },
            },
            u32::from(n),
        )
    }

    #[test]
    fn bulk_withdraw_merges_masked_and_sparse_uc_vpn_without_adopting_unset_bits() {
        let mut ledger = AdmittedRecovery::new();
        let raw = [
            key(2),
            key(4),
            key(6),
            bulk_vpn_key(2),
            bulk_vpn_key(4),
            bulk_vpn_key(6),
        ];
        shared_capture(
            &mut ledger,
            peer(1),
            None,
            &raw,
            &[key(2), key(6), bulk_vpn_key(4)],
        );
        ledger
            .apply_admitted(
                peer(1),
                [key(1), key(5), bulk_vpn_key(1), bulk_vpn_key(5)].into_iter(),
                [].into_iter(),
            )
            .unwrap();
        let ann = [bulk_vpn_key(5), key(3), key(2)];
        ledger.reserve_admitted(peer(1), ann.into_iter()).unwrap();
        let before = ledger.bytes();
        ledger.fail_next_allocation_for_test();
        ledger
            .apply_admitted(
                peer(1),
                ann.into_iter(),
                [key(1), key(2), key(5), bulk_vpn_key(4), bulk_vpn_key(5)].into_iter(),
            )
            .unwrap();
        let remaining = [key(2), key(3), key(6), bulk_vpn_key(1), bulk_vpn_key(5)];
        assert_eq!(
            ledger.get(&peer(1)).unwrap().iter().collect::<Vec<_>>(),
            remaining.map(ExactExportKey::from)
        );
        assert_eq!(ledger.records[0].masked, 2);
        assert_eq!(
            ledger.records[0].keys.0.as_slice(),
            &[key(3), bulk_vpn_key(1), bulk_vpn_key(5)]
        );
        ledger
            .apply_admitted(peer(1), [].into_iter(), remaining.into_iter())
            .unwrap();
        assert!(ledger.get(&peer(1)).unwrap().is_empty());
        assert_eq!(ledger.records[0].masked, 0);
        assert!(ledger.records[0].keys.0.is_empty());
        assert_eq!(ledger.bytes(), before);
        assert!(ledger.fail_next_allocation);
    }

    #[test]
    fn bulk_withdraw_invalid_suffix_fails_before_reservation_and_keeps_other_masks() {
        let raw = [key(2), key(4), bulk_vpn_key(2), bulk_vpn_key(4)];
        for withdrawals in [
            vec![key(2), key(2)],
            vec![bulk_vpn_key(2), key(2)],
            vec![key(2), key(3)],
            vec![key(2), key(4)],
            vec![key(2), bulk_vpn_key(3)],
            vec![key(2), bulk_vpn_key(4)],
        ] {
            let mut ledger = AdmittedRecovery::new();
            let handle =
                shared_capture(&mut ledger, peer(1), None, &raw, &[key(2), bulk_vpn_key(2)]);
            shared_capture(&mut ledger, peer(2), Some(handle), &raw, &raw);
            ledger
                .apply_admitted(
                    peer(1),
                    [key(1), bulk_vpn_key(1)].into_iter(),
                    [].into_iter(),
                )
                .unwrap();
            let other = ledger.owned_proof(&peer(2)).unwrap();
            ledger.fail_next_allocation_for_test();
            let error = ledger
                .apply_admitted(peer(1), [key(7)].into_iter(), withdrawals.into_iter())
                .unwrap_err();
            assert_eq!(error.cause, FailureCause::MissingProof);
            assert!(
                ledger.fail_next_allocation,
                "invalid W must fail before ANN reservation"
            );
            assert!(
                ledger.get(&peer(1)).is_none(),
                "a partial proof must never be published"
            );
            assert_eq!(ledger.begin_capture(peer(1)), Err(error));
            assert_eq!(ledger.owned_proof(&peer(2)).unwrap(), other);
            assert_eq!(ledger.snapshots[0].references, 1);
        }
    }

    #[test]
    fn bulk_withdraw_reservation_refusal_keeps_other_masks_and_fails_closed() {
        for cause in [FailureCause::AllocationFailure, FailureCause::PeerLimit] {
            let mut ledger = AdmittedRecovery::new();
            let raw = [key(2), key(4), bulk_vpn_key(2), bulk_vpn_key(4)];
            let handle =
                shared_capture(&mut ledger, peer(1), None, &raw, &[key(2), bulk_vpn_key(2)]);
            shared_capture(&mut ledger, peer(2), Some(handle), &raw, &raw);
            ledger
                .apply_admitted(peer(1), [key(1)].into_iter(), [].into_iter())
                .unwrap();
            let other = ledger.owned_proof(&peer(2)).unwrap();
            if cause == FailureCause::AllocationFailure {
                ledger.fail_next_allocation_for_test();
            } else {
                ledger.peer_limit = ledger.peer_charge(0);
            }
            let visited = std::cell::Cell::new(0);
            let withdrawals = [key(2), bulk_vpn_key(2)];
            let removed = withdrawals.iter().copied().inspect(|_| {
                visited.set(visited.get() + 1);
            });
            let error = ledger
                .apply_admitted_with_checkpoint(
                    peer(1),
                    [key(3)].into_iter(),
                    removed,
                    &mut |force| {
                        if force {
                            assert_eq!(
                                visited.get(),
                                withdrawals.len(),
                                "failed reservation must consume W only for validation"
                            );
                        }
                    },
                )
                .unwrap_err();
            assert_eq!(error.cause, cause);
            assert!(ledger.get(&peer(1)).is_none());
            assert_eq!(ledger.begin_capture(peer(1)), Err(error));
            assert_eq!(ledger.owned_proof(&peer(2)).unwrap(), other);
            assert_eq!(ledger.snapshots[0].references, 1);
        }
    }

    #[test]
    fn bulk_withdraw_match_comparisons_are_linear_and_tiny_ranges_skip_the_prefix() {
        fn full_key(n: u32) -> Key {
            Key::Unicast(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(n), 32)), 0)
        }
        for count in [256, 2048, 16_384] {
            let raw: Vec<_> = (0..count).map(full_key).collect();
            let mut cursor = None;
            let mut comparisons = 0;
            for (position, key) in raw.iter().copied().enumerate() {
                assert_eq!(
                    AdmittedRecovery::sorted_match(&raw, &mut cursor, key, &mut |force| {
                        assert!(!force);
                        comparisons += 1;
                    }),
                    Some(position),
                );
            }
            assert!(comparisons >= raw.len());
            assert!(
                comparisons <= 2 * raw.len() + 64,
                "{comparisons} comparisons for {} keys",
                raw.len()
            );
            cursor = None;
            comparisons = 0;
            for (position, key) in raw.iter().copied().enumerate().skip(raw.len() - 2) {
                assert_eq!(
                    AdmittedRecovery::sorted_match(&raw, &mut cursor, key, &mut |force| {
                        assert!(!force);
                        comparisons += 1;
                    }),
                    Some(position),
                );
            }
            assert!(comparisons <= 64, "tiny suffix walked {comparisons} keys");
        }
    }

    #[test]
    fn bulk_withdraw_full_mixed_proof_has_bounded_visits_without_allocating() {
        fn full_key(n: u32) -> Key {
            Key::Unicast(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(n), 32)), 0)
        }
        for count in [256, 2048, 16_384] {
            let mut ledger = AdmittedRecovery::new();
            let raw: Vec<_> = (0..count).map(|n| full_key(4 * n)).collect();
            let masked: Vec<_> = raw.iter().step_by(2).copied().collect();
            shared_capture(&mut ledger, peer(1), None, &raw, &masked);
            let sparse: Vec<_> = (0..count).map(|n| full_key(4 * n + 1)).collect();
            ledger
                .apply_admitted(peer(1), sparse.iter().copied(), [].into_iter())
                .unwrap();
            let mut withdrawals: Vec<_> = masked.iter().chain(&sparse).copied().collect();
            withdrawals.sort_unstable();
            let before = ledger.bytes();
            ledger.fail_next_allocation_for_test();
            let mut visits = 0;
            ledger
                .apply_admitted_with_checkpoint(
                    peer(1),
                    [].into_iter(),
                    withdrawals.iter().copied(),
                    &mut |force| {
                        if !force {
                            visits += 1;
                        }
                    },
                )
                .unwrap();
            assert!(visits >= withdrawals.len());
            assert!(
                visits <= 4 * (raw.len() + sparse.len() + withdrawals.len()) + 128,
                "{visits} visits for {} universe / {} sparse / {} W",
                raw.len(),
                sparse.len(),
                withdrawals.len()
            );
            assert!(ledger.get(&peer(1)).unwrap().is_empty());
            assert_eq!(ledger.bytes(), before);
            assert!(ledger.fail_next_allocation);
        }
    }

    #[test]
    fn older_universe_capture_reserves_only_actual_sparse_keys_before_population() {
        let mut ledger = AdmittedRecovery::new();
        let raw = [key(1), key(2), bulk_vpn_key(1)];
        let handle = shared_capture(&mut ledger, peer(1), None, &raw, &raw);
        let actual = [bulk_vpn_key(2), key(99), key(2)]; // Deliberately unordered.
        let mut visits = 0;
        let (count, additions) =
            ledger.capture_shape_with_checkpoint(Some(handle), actual.into_iter(), &mut |_| {
                visits += 1;
            });
        assert_eq!((count, additions), (3, 2));
        assert!(visits >= actual.len());
        ledger.begin_capture(peer(2)).unwrap();
        assert_eq!(
            ledger
                .share_capture_with_checkpoint(
                    peer(2),
                    Some(handle),
                    count,
                    actual.into_iter(),
                    (count, additions),
                    &mut |_| {}
                )
                .unwrap(),
            Some(handle)
        );
        ledger
            .reserve_capture_with_checkpoint(peer(2), additions, &mut |_| {})
            .unwrap();
        assert_eq!(ledger.records[1].keys.0.capacity(), additions);
        let reserved = ledger.bytes();
        ledger.fail_next_allocation_for_test();
        for key in actual {
            ledger.push_capture(peer(2), key).unwrap();
        }
        assert!(
            ledger.get(&peer(2)).is_none(),
            "partial capture is never published"
        );
        ledger.seal_capture(peer(2)).unwrap();
        assert!(ledger.fail_next_allocation);
        assert_eq!(ledger.bytes(), reserved);
        assert_eq!(ledger.snapshots.len(), 1);
        assert_eq!(ledger.snapshots[0].references, 2);
        assert_eq!(
            ledger.get(&peer(2)).unwrap().iter().collect::<Vec<_>>(),
            [key(2), key(99), bulk_vpn_key(2)].map(ExactExportKey::from)
        );
        assert!(!ledger.get(&peer(2)).unwrap().contains(&key(1).into()));
        assert_eq!(
            ledger.get(&peer(1)).unwrap().iter().collect::<Vec<_>>(),
            raw.map(ExactExportKey::from)
        );
    }

    #[test]
    fn older_universe_delta_refusal_releases_only_the_capturing_owner() {
        for cause in [
            FailureCause::AllocationFailure,
            FailureCause::PeerLimit,
            FailureCause::DaemonLimit,
        ] {
            let mut ledger = AdmittedRecovery::new();
            let raw = [key(1), key(2), bulk_vpn_key(1)];
            let handle = shared_capture(&mut ledger, peer(1), None, &raw, &raw);
            let actual = [key(2), key(3), bulk_vpn_key(2)];
            ledger.begin_capture(peer(2)).unwrap();
            ledger
                .share_capture_with_checkpoint(
                    peer(2),
                    Some(handle),
                    actual.len(),
                    actual.into_iter(),
                    (actual.len(), 0),
                    &mut |_| {},
                )
                .unwrap()
                .unwrap();
            let (count, additions) =
                ledger.capture_shape_with_checkpoint(Some(handle), actual.into_iter(), &mut |_| {});
            assert_eq!((count, additions), (3, 2));
            match cause {
                FailureCause::AllocationFailure => ledger.fail_next_allocation_for_test(),
                FailureCause::PeerLimit => ledger.peer_limit = ledger.peer_charge(1),
                FailureCause::DaemonLimit => ledger.daemon_limit = ledger.bytes(),
                FailureCause::MissingProof => unreachable!(),
            }
            let error = ledger
                .reserve_capture_with_checkpoint(peer(2), additions, &mut |_| {})
                .unwrap_err();
            assert_eq!(error.cause, cause);
            assert_eq!(ledger.seal_capture(peer(2)), Err(error));
            assert!(ledger.get(&peer(2)).is_none());
            assert_eq!(ledger.records[1].keys.0.capacity(), 0);
            assert_eq!(ledger.records[1].words.capacity(), 0);
            assert_eq!(ledger.snapshots[0].references, 1);
            assert_eq!(
                ledger.get(&peer(1)).unwrap().iter().collect::<Vec<_>>(),
                raw.map(ExactExportKey::from)
            );
        }
    }

    #[test]
    fn optional_sparse_allocations_roll_back_before_attaching_an_older_snapshot() {
        for stage in 0..2 {
            let mut ledger = AdmittedRecovery::new();
            let raw: Vec<_> = (1..=100).map(key).collect();
            let actual: Vec<_> = (101..=200).map(key).collect();
            let handle = shared_capture(&mut ledger, peer(1), None, &raw, &raw);
            ledger.begin_capture(peer(2)).unwrap();
            let before = ledger.bytes();
            ledger.allocation_countdown = Some(stage);
            let error = ledger
                .share_capture_with_checkpoint(
                    peer(2),
                    Some(handle),
                    actual.len(),
                    actual.iter().copied(),
                    (actual.len(), actual.len()),
                    &mut |_| {},
                )
                .unwrap_err();
            assert_eq!(error.cause, FailureCause::AllocationFailure);
            assert_eq!(ledger.bytes(), before);
            assert_eq!(ledger.records[1].state, State::Capturing);
            assert!(ledger.records[1].snapshot.is_none());
            assert_eq!(ledger.records[1].keys.0.capacity(), 0);
            assert_eq!(ledger.records[1].words.capacity(), 0);
            assert_eq!(ledger.snapshots[0].handle, handle);
            assert_eq!(ledger.snapshots[0].references, 1);
            ledger
                .reserve_capture_with_checkpoint(peer(2), actual.len(), &mut |_| {})
                .unwrap();
            for key in &actual {
                ledger.push_capture(peer(2), *key).unwrap();
            }
            ledger.seal_capture(peer(2)).unwrap();
            assert_eq!(
                ledger.get(&peer(2)).unwrap().iter().collect::<Vec<_>>(),
                actual
                    .into_iter()
                    .map(ExactExportKey::from)
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                ledger.get(&peer(1)).unwrap().iter().collect::<Vec<_>>(),
                raw.into_iter()
                    .map(ExactExportKey::from)
                    .collect::<Vec<_>>()
            );
            ledger.remove(&peer(2));
            assert_eq!(ledger.snapshots[0].references, 1);
            ledger.remove(&peer(1));
            assert_eq!(ledger.bytes(), size_of::<AdmittedRecovery>());
        }
    }

    #[test]
    fn released_snapshot_hint_never_aliases_a_later_key_universe() {
        let mut ledger = AdmittedRecovery::new();
        let first = shared_capture(&mut ledger, peer(1), None, &[key(1), key(2)], &[key(1)]);
        ledger.remove(&peer(1));
        let next = shared_capture(
            &mut ledger,
            peer(2),
            Some(first),
            &[key(3), key(4)],
            &[key(4)],
        );
        assert_ne!(first, next);
        assert_eq!(
            ledger.get(&peer(2)).unwrap().iter().collect::<Vec<_>>(),
            [ExactExportKey::from(key(4))]
        );
        assert!(!ledger.get(&peer(2)).unwrap().contains(&key(1).into()));
    }

    #[test]
    fn optional_snapshot_allocations_roll_back_at_each_physical_stage() {
        for stage in 0..3 {
            let mut ledger = AdmittedRecovery::new();
            ledger.begin_capture(peer(1)).unwrap();
            let before = ledger.bytes();
            ledger.allocation_countdown = Some(stage);
            let result = ledger.share_capture_with_checkpoint(
                peer(1),
                None,
                100,
                (1..=100).map(key),
                (100, 0),
                &mut |_| {},
            );
            assert_eq!(result.unwrap_err().cause, FailureCause::AllocationFailure);
            assert_eq!(ledger.bytes(), before);
            assert!(ledger.snapshots.is_empty());
            assert_eq!(ledger.snapshots.capacity(), 0);
            assert!(ledger.records[0].snapshot.is_none());
            assert_eq!(ledger.records[0].words.capacity(), 0);
            // A valid smaller flat alternative remains possible after refusal.
            ledger
                .reserve_capture_with_checkpoint(peer(1), 2, &mut |_| {})
                .unwrap();
            ledger.push_capture(peer(1), key(1)).unwrap();
            ledger.push_capture(peer(1), key(2)).unwrap();
            ledger.seal_capture(peer(1)).unwrap();
            assert_eq!(ledger.get(&peer(1)).unwrap().len(), 2);
        }
    }

    #[test]
    fn refused_new_member_mask_keeps_the_other_members_snapshot_and_charge() {
        let mut ledger = AdmittedRecovery::new();
        let raw: Vec<_> = (1..=100).map(key).collect();
        let handle = shared_capture(&mut ledger, peer(1), None, &raw, &raw);
        ledger.begin_capture(peer(2)).unwrap();
        let before = ledger.bytes();
        ledger.fail_next_allocation_for_test();
        assert_eq!(
            ledger
                .share_capture_with_checkpoint(
                    peer(2),
                    Some(handle),
                    raw.len(),
                    raw.iter().copied(),
                    (raw.len(), 0),
                    &mut |_| {}
                )
                .unwrap_err()
                .cause,
            FailureCause::AllocationFailure
        );
        assert_eq!(ledger.bytes(), before);
        assert_eq!(ledger.snapshots[0].references, 1);
        assert_eq!(ledger.get(&peer(1)).unwrap().len(), 100);
        assert!(ledger.records[1].snapshot.is_none());
    }

    #[test]
    fn oversized_raw_universe_does_not_refuse_a_bounded_filtered_flat_proof() {
        let cap = 4 * size_of::<Record>() + 4 * size_of::<Key>() + size_of::<Keys>();
        let mut ledger = AdmittedRecovery::with_test_limits(cap, DAEMON_LIMIT_BYTES);
        ledger.begin_capture(peer(1)).unwrap();
        assert_eq!(
            ledger
                .share_capture_with_checkpoint(
                    peer(1),
                    None,
                    100,
                    (1..=100).map(key),
                    (2, 0),
                    &mut |_| {}
                )
                .unwrap_err()
                .cause,
            FailureCause::PeerLimit
        );
        ledger
            .reserve_capture_with_checkpoint(peer(1), 2, &mut |_| {})
            .unwrap();
        ledger.push_capture(peer(1), key(1)).unwrap();
        ledger.push_capture(peer(1), key(2)).unwrap();
        ledger.seal_capture(peer(1)).unwrap();
        assert!(ledger.records[0].snapshot.is_none());
        assert_eq!(ledger.get(&peer(1)).unwrap().len(), 2);
    }

    #[test]
    fn production_budgets_admit_full_table_shared_proof_and_one_small_new_key() {
        fn full_key(n: u32) -> Key {
            Key::Unicast(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(n), 32)), 0)
        }
        const COUNT: u32 = 1_230_000;
        assert_eq!(PEER_LIMIT_BYTES, 64 * 1024 * 1024);
        assert_eq!(DAEMON_LIMIT_BYTES, 512 * 1024 * 1024);
        let mut ledger = AdmittedRecovery::new();
        assert_eq!(ledger.peer_limit, PEER_LIMIT_BYTES);
        assert_eq!(ledger.daemon_limit, DAEMON_LIMIT_BYTES);
        ledger.insert_empty(peer(1)).unwrap();
        let handle = ledger
            .share_capture_with_checkpoint(
                peer(1),
                None,
                COUNT as usize,
                (0..COUNT).map(full_key),
                (COUNT as usize, 0),
                &mut |_| {},
            )
            .unwrap()
            .unwrap();
        assert!(
            ledger.get(&peer(1)).unwrap().is_empty(),
            "desired universe is not admission"
        );
        ledger
            .reserve_admitted(peer(1), (0..COUNT).map(full_key))
            .unwrap();
        ledger
            .apply_admitted(peer(1), (0..COUNT).map(full_key), [].into_iter())
            .unwrap();
        assert_eq!(ledger.get(&peer(1)).unwrap().len(), COUNT as usize);
        let before = ledger.bytes();
        ledger
            .reserve_admitted(peer(1), [full_key(COUNT)].into_iter())
            .unwrap();
        assert_eq!(ledger.bytes() - before, size_of::<Key>());
        ledger
            .apply_admitted(peer(1), [full_key(COUNT)].into_iter(), [].into_iter())
            .unwrap();
        assert_eq!(ledger.snapshots[0].handle, handle);
        assert_eq!(ledger.snapshots[0].keys.capacity(), COUNT as usize);
        assert_eq!(ledger.get(&peer(1)).unwrap().len(), COUNT as usize + 1);
        assert!(ledger.peer_charge(0) < PEER_LIMIT_BYTES);
        assert!(ledger.peak_bytes() < DAEMON_LIMIT_BYTES);
        ledger.remove(&peer(1));
        assert_eq!(ledger.bytes(), size_of::<AdmittedRecovery>());
        // The unchanged production peer cap must reject an oversized universe
        // before an allocation or key walk, rather than accepting usize::MAX.
        ledger.insert_empty(peer(1)).unwrap();
        let before = ledger.bytes();
        let error = ledger
            .share_capture_with_checkpoint(
                peer(1),
                None,
                3_000_000,
                std::iter::empty(),
                (3_000_000, 0),
                &mut |_| {},
            )
            .unwrap_err();
        assert_eq!(error.cause, FailureCause::PeerLimit);
        assert_eq!(ledger.bytes(), before);
    }
}
