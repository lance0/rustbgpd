//! Actor-owned EVPN recovery keys and their capacity credits.
//!
//! Each key a record admits occupies one slot in the ledger's slot space.
//! A record holds its slots as sorted IDs while it holds few of them and as a
//! bitset once that is smaller, so its cost tracks its own keys rather than
//! the ledger's highest slot. A slot's holder count covers every record entry
//! and reservation pin that names it, and a slot is reused only after that
//! count reaches zero, so an entry can never come to name a different key.
//! New keys take the lowest free slot and free slots at the top are trimmed,
//! so IDs stay compact as the space drains. Slot IDs never leave this module.
//!
//! Credits cover container headers and requested reserved capacity, including
//! overlapping reallocations. Allocator bookkeeping and RSS are separate
//! qualification surfaces. Register ownership before changing a projection;
//! failed capture stays exhausted until that owned record is retired.

use crate::PeerId;
use std::mem::size_of;

pub(in crate::manager) use crate::update::EvpnRecoveryExhaustionCause as ExhaustionCause;
use rustbgpd_wire::EvpnRouteKey;
use smallvec::SmallVec;

/// A peer pays [`SLOT_BYTES`] per held key. 22 MiB keeps at least 262,144
/// held keys per peer, through a capture's own entry buffer, which the
/// earlier 64-byte charge per universe key allowed under 16 MiB. A lower
/// ceiling would refuse every recovery of a member between the two, and an
/// initial feed reserves through the same path, so such a session would
/// reset and reconnect in a loop.
pub(in crate::manager) const PEER_LIMIT_BYTES: usize = 22 * 1024 * 1024;
pub(in crate::manager) const DAEMON_LIMIT_BYTES: usize = 256 * 1024 * 1024;

type Keys = SmallVec<[EvpnRouteKey; 0]>;
type Records = SmallVec<[Record; 0]>;
type Words = SmallVec<[u64; 0]>;
type Slots = SmallVec<[u32; 0]>;

/// Index buckets per slot of capacity; linear probing stays at most half full.
const INDEX_BUCKETS_PER_SLOT: usize = 2;
/// The charge per held slot: the key, its holder count, a free-list entry and
/// its index buckets. Each peer pays it for every slot it holds, the cost it
/// would impose as that slot's only holder.
pub(in crate::manager) const SLOT_BYTES: usize =
    size_of::<EvpnRouteKey>() + 2 * size_of::<u32>() + INDEX_BUCKETS_PER_SLOT * size_of::<u32>();
const MIN_SLOT_CAPACITY: usize = 64;
/// Bitsets grow in steps of this many words (1024 slots).
const WORD_STEP: usize = 16;
/// Ledger loops offer a readiness checkpoint once per this many items.
const CHECKPOINT_STRIDE: usize = 64;
/// Slot IDs stay below 2^31, so a sparse entry is `slot << 1` and its low
/// bit can mark the entry within one validation or application.
const MARK: u32 = 1;
const MAX_SLOTS: usize = 1 << 31;

fn bit(words: &[u64], slot: u32) -> bool {
    let slot = slot as usize;
    words
        .get(slot / 64)
        .is_some_and(|word| word & (1_u64 << (slot % 64)) != 0)
}

fn set_bit(words: &mut [u64], slot: u32) {
    let slot = slot as usize;
    words[slot / 64] |= 1_u64 << (slot % 64);
}

fn clear_bit(words: &mut [u64], slot: u32) {
    let slot = slot as usize;
    words[slot / 64] &= !(1_u64 << (slot % 64));
}

fn words_for(slot: u32) -> usize {
    slot as usize / 64 + 1
}

/// Bitset bytes covering `top` in whole word steps.
fn dense_bytes(top: u32) -> usize {
    words_for(top).next_multiple_of(WORD_STEP) * size_of::<u64>()
}

fn sparse_bytes(count: usize) -> usize {
    count.saturating_mul(size_of::<u32>())
}

fn sparse_slot(entry: u32) -> u32 {
    entry >> 1
}

fn sparse_entry(slot: u32) -> u32 {
    slot << 1
}

/// The position of `slot` in sorted sparse entries, marks ignored.
fn sparse_position(entries: &[u32], slot: u32) -> Result<usize, usize> {
    entries.binary_search_by(|entry| sparse_slot(*entry).cmp(&slot))
}

/// The ledger's key slots. A free slot has zero holders, a free bit and no
/// index entry; the highest slot is never free.
#[derive(Debug, Default)]
struct SlotSpace {
    /// Slot to key; its length is the slot high-water mark.
    keys: Keys,
    /// Record entries plus reservation pins naming each slot.
    holders: Slots,
    /// One bit per slot below the high-water mark, set while it is free.
    free: Words,
    free_count: usize,
    /// No word below this one has a free bit.
    first_free: usize,
    /// Open addressing with linear probing: zero is empty, else slot + 1.
    index: Slots,
    /// A per-space random key for `SipHash`. Keys are peer-chosen, and an
    /// unkeyed hash lets a peer place any number of distinct keys in one
    /// probe run. Keyed, every chain has expected constant length, so the
    /// probe loops need no checkpoint of their own.
    hasher: std::collections::hash_map::RandomState,
    /// Probe and shift steps, for work-bound regressions.
    #[cfg(test)]
    probes: std::sync::atomic::AtomicU64,
    /// Entries moved from the start of the table back to its end.
    #[cfg(test)]
    wrapped_moves: std::sync::atomic::AtomicU64,
}

impl SlotSpace {
    /// Bytes of every array sized for `slots`.
    fn bytes_for(slots: usize) -> Option<usize> {
        let per_slot = size_of::<EvpnRouteKey>()
            + size_of::<u32>()
            + INDEX_BUCKETS_PER_SLOT * size_of::<u32>();
        slots
            .checked_mul(per_slot)?
            .checked_add(slots.div_ceil(64).checked_mul(size_of::<u64>())?)
    }

    /// Slots every array can hold without allocating.
    fn capacity(&self) -> usize {
        self.keys
            .capacity()
            .min(self.holders.capacity())
            .min(self.free.capacity() * 64)
            .min(self.index.len() / INDEX_BUCKETS_PER_SLOT)
    }

    fn bytes(&self) -> usize {
        self.keys.capacity() * size_of::<EvpnRouteKey>()
            + (self.holders.capacity() + self.index.capacity()) * size_of::<u32>()
            + self.free.capacity() * size_of::<u64>()
    }

    fn live(&self) -> usize {
        self.keys.len() - self.free_count
    }

    fn bucket(&self, key: &EvpnRouteKey) -> usize {
        use std::hash::BuildHasher;
        let hash = self.hasher.hash_one(key);
        // Multiply-shift maps the keyed hash onto any table length.
        usize::try_from((u128::from(hash) * self.index.len() as u128) >> 64)
            .expect("bucket is below the table length")
    }

    #[cfg(test)]
    fn probed(&self) {
        self.probes
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(not(test))]
    #[expect(
        clippy::unused_self,
        reason = "only test builds count probe steps for work-bound regressions"
    )]
    fn probed(&self) {}

    fn next(&self, bucket: usize) -> usize {
        if bucket + 1 == self.index.len() {
            0
        } else {
            bucket + 1
        }
    }

    fn find(&self, key: &EvpnRouteKey) -> Option<u32> {
        self.find_from(self.bucket_or_empty(key)?, key)
    }

    /// The key's bucket, or none while the table is unallocated.
    fn bucket_or_empty(&self, key: &EvpnRouteKey) -> Option<usize> {
        (!self.index.is_empty()).then(|| self.bucket(key))
    }

    /// Probe from a bucket the caller hashed once for this key.
    fn find_from(&self, mut bucket: usize, key: &EvpnRouteKey) -> Option<u32> {
        loop {
            self.probed();
            let entry = self.index[bucket];
            if entry == 0 {
                return None;
            }
            if self.keys[entry as usize - 1] == *key {
                return Some(entry - 1);
            }
            bucket = self.next(bucket);
        }
    }

    fn insert_index(&mut self, slot: u32) {
        self.insert_at(self.bucket(&self.keys[slot as usize]), slot);
    }

    fn insert_at(&mut self, mut bucket: usize, slot: u32) {
        while self.index[bucket] != 0 {
            self.probed();
            bucket = self.next(bucket);
        }
        self.index[bucket] = slot + 1;
    }

    /// Backward-shift deletion keeps every probe chain unbroken.
    fn remove_index(&mut self, slot: u32) {
        let length = self.index.len();
        let mut hole = self.bucket(&self.keys[slot as usize]);
        while self.index[hole] != slot + 1 {
            self.probed();
            hole = self.next(hole);
        }
        let mut probe = hole;
        loop {
            self.probed();
            probe = self.next(probe);
            let entry = self.index[probe];
            if entry == 0 {
                self.index[hole] = 0;
                return;
            }
            let preferred = self.bucket(&self.keys[entry as usize - 1]);
            let distance = |from: usize, to: usize| (to + length - from) % length;
            // Move the entry back unless the hole precedes its preferred bucket.
            if distance(preferred, probe) >= distance(hole, probe) {
                #[cfg(test)]
                if probe < hole {
                    self.wrapped_moves
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                self.index[hole] = entry;
                hole = probe;
            }
        }
    }

    /// The lowest free slot, found from the first word that can hold one.
    fn lowest_free(&mut self) -> Option<u32> {
        if self.free_count == 0 {
            return None;
        }
        while self.free[self.first_free] == 0 {
            self.first_free += 1;
        }
        let slot = self.first_free * 64 + self.free[self.first_free].trailing_zeros() as usize;
        Some(u32::try_from(slot).expect("slot capacity fits u32"))
    }

    /// Insert a key the caller just failed to find from `home`, its bucket
    /// in the current table, into the lowest free slot. Callers have already
    /// reserved capacity.
    fn insert_new(&mut self, home: usize, key: EvpnRouteKey) -> u32 {
        let slot = if let Some(slot) = self.lowest_free() {
            clear_bit(&mut self.free, slot);
            self.free_count -= 1;
            self.keys[slot as usize] = key;
            slot
        } else {
            assert!(self.keys.len() < self.capacity(), "slot capacity reserved");
            self.keys.push(key);
            self.holders.push(0);
            if self.keys.len() > self.free.len() * 64 {
                self.free.push(0);
            }
            u32::try_from(self.keys.len() - 1).expect("slot capacity fits u32")
        };
        self.insert_at(home, slot);
        slot
    }

    fn hold(&mut self, slot: u32) {
        self.holders[slot as usize] += 1;
    }

    /// The last release frees the slot; only then can it name another key.
    /// Free slots at the top leave the space, so the high-water mark falls
    /// as slots drain.
    fn release(&mut self, slot: u32) {
        let holders = &mut self.holders[slot as usize];
        debug_assert!(*holders > 0, "released slot has a holder");
        *holders -= 1;
        if *holders != 0 {
            return;
        }
        self.remove_index(slot);
        set_bit(&mut self.free, slot);
        self.free_count += 1;
        self.first_free = self.first_free.min(slot as usize / 64);
        while let Some(top) = self.keys.len().checked_sub(1) {
            let top = u32::try_from(top).expect("slot capacity fits u32");
            if !bit(&self.free, top) {
                break;
            }
            clear_bit(&mut self.free, top);
            self.free_count -= 1;
            self.keys.pop();
            self.holders.pop();
        }
        self.free.truncate(self.keys.len().div_ceil(64));
        self.first_free = self.first_free.min(self.free.len());
    }

    /// Resize every array to `slots`, at least the high-water mark, and
    /// rebuild the index. A refusal leaves arrays already resized in place;
    /// `capacity` reports the room every array still has.
    fn resize(&mut self, slots: usize, checkpoint: &mut impl FnMut(bool)) -> Result<(), ()> {
        debug_assert!(slots >= self.keys.len());
        self.keys.try_grow(slots).map_err(drop)?;
        self.holders.try_grow(slots).map_err(drop)?;
        self.free.try_grow(slots.div_ceil(64)).map_err(drop)?;
        let buckets = slots * INDEX_BUCKETS_PER_SLOT;
        let mut index = Slots::new();
        index.try_grow(buckets).map_err(drop)?;
        index.resize(buckets, 0);
        self.index = index;
        for slot in 0..self.keys.len() {
            if slot % 1024 == 0 {
                checkpoint(false);
            }
            if self.holders[slot] != 0 {
                self.insert_index(u32::try_from(slot).expect("slot capacity fits u32"));
            }
        }
        Ok(())
    }

    /// Free every array; the hasher key and test counters remain.
    fn clear(&mut self) {
        self.keys = Keys::new();
        self.holders = Slots::new();
        self.free = Words::new();
        self.free_count = 0;
        self.first_free = 0;
        self.index = Slots::new();
    }
}

/// A record's admitted slots.
#[derive(Debug)]
enum Held {
    /// Sorted unique sparse entries once sealed; capture appends unsorted.
    Sparse(Slots),
    /// One bit per slot ID.
    Dense(Words),
}

impl Default for Held {
    fn default() -> Self {
        Self::Sparse(Slots::new())
    }
}

impl Held {
    fn bytes(&self) -> usize {
        match self {
            Self::Sparse(entries) => entries.capacity() * size_of::<u32>(),
            Self::Dense(words) => words.capacity() * size_of::<u64>(),
        }
    }

    fn view(&self) -> HeldView<'_> {
        match self {
            Self::Sparse(entries) => HeldView::Sparse(entries),
            Self::Dense(words) => HeldView::Dense(words),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum HeldView<'a> {
    Sparse(&'a [u32]),
    Dense(&'a [u64]),
}

impl<'a> HeldView<'a> {
    fn contains(self, slot: u32) -> bool {
        match self {
            Self::Sparse(entries) => sparse_position(entries, slot).is_ok(),
            Self::Dense(words) => bit(words, slot),
        }
    }

    /// The highest held slot of a sealed record.
    fn top(self) -> Option<u32> {
        match self {
            Self::Sparse(entries) => entries.last().map(|entry| sparse_slot(*entry)),
            Self::Dense(words) => words.iter().rposition(|word| *word != 0).map(|index| {
                u32::try_from(index * 64 + 63 - words[index].leading_zeros() as usize)
                    .expect("slot IDs fit u32")
            }),
        }
    }

    /// Held slots in ID order, checkpointing once per 64 entries or words.
    fn slots<C: FnMut(bool)>(self, checkpoint: C) -> HeldSlots<'a, C> {
        HeldSlots {
            held: self,
            position: 0,
            base: 0,
            word: 0,
            checkpoint,
        }
    }
}

struct HeldSlots<'a, C> {
    held: HeldView<'a>,
    position: usize,
    base: usize,
    word: u64,
    checkpoint: C,
}

impl<C: FnMut(bool)> Iterator for HeldSlots<'_, C> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        match self.held {
            HeldView::Sparse(entries) => {
                let entry = *entries.get(self.position)?;
                if self.position.is_multiple_of(CHECKPOINT_STRIDE) {
                    (self.checkpoint)(false);
                }
                self.position += 1;
                Some(sparse_slot(entry))
            }
            HeldView::Dense(words) => loop {
                if self.word != 0 {
                    let offset = self.word.trailing_zeros() as usize;
                    self.word &= self.word - 1;
                    return Some(u32::try_from(self.base + offset).expect("slot IDs fit u32"));
                }
                let word = *words.get(self.position)?;
                (self.checkpoint)(false);
                self.base = self.position * 64;
                self.position += 1;
                self.word = word;
            },
        }
    }
}

/// Raw slot occupancy is not admission: only a record's own entries are.
#[derive(Clone, Copy, Debug)]
pub(in crate::manager) struct EvpnProofView<'a> {
    space: &'a SlotSpace,
    held: HeldView<'a>,
    masked: usize,
}

impl<'a> EvpnProofView<'a> {
    pub(in crate::manager) fn len(self) -> usize {
        self.masked
    }

    pub(in crate::manager) fn is_empty(self) -> bool {
        self.masked == 0
    }

    pub(in crate::manager) fn contains(self, key: &EvpnRouteKey) -> bool {
        self.space
            .find(key)
            .is_some_and(|slot| self.held.contains(slot))
    }

    /// Admitted keys in slot order, checkpointing once per 64 entries.
    pub(in crate::manager) fn iter_with_checkpoint<'c>(
        self,
        checkpoint: impl FnMut(bool) + 'c,
    ) -> impl Iterator<Item = EvpnRouteKey> + 'c
    where
        'a: 'c,
    {
        self.held
            .slots(checkpoint)
            .map(move |slot| self.space.keys[slot as usize])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(in crate::manager) struct PeerSession {
    pub(in crate::manager) peer: PeerId,
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
    pub(in crate::manager) limiting_peer: Option<PeerId>,
    pub(in crate::manager) attempted_peer_bytes: usize,
    pub(in crate::manager) attempted_daemon_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::manager) struct Usage {
    pub(in crate::manager) retained: usize,
    pub(in crate::manager) peak: usize,
}

/// Slot-space occupancy for qualification receipts.
#[cfg(any(test, feature = "bench-internals"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::manager) struct SlotUsage {
    pub(in crate::manager) live: usize,
    pub(in crate::manager) capacity: usize,
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
    /// Admitted slots: sorted entries or a bitset, whichever is smaller.
    held: Held,
    /// Slots held for the outstanding admission reservation.
    pins: Slots,
    masked: usize,
    peer_peak: usize,
    // Duplicated within the charged peer range; mutations maintain one total.
    peer_retained: usize,
}

impl Record {
    /// Daemon bytes this record owns beyond its array entry.
    fn owned_bytes(&self) -> usize {
        self.held.bytes() + self.pins.capacity() * size_of::<u32>()
    }

    /// Peer charge: the record, its storage and every slot it holds.
    fn charge(&self) -> usize {
        size_of::<Self>() + self.owned_bytes() + (self.masked + self.pins.len()) * SLOT_BYTES
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::manager) enum FinalAdmissionFault {
    Preflight,
    Apply,
}

#[derive(Debug)]
pub(in crate::manager) struct EvpnRecoveryProvenance {
    records: Records,
    space: SlotSpace,
    daemon_used: usize,
    daemon_peak: usize,
    peer_limit: usize,
    daemon_limit: usize,
    next_id: u64,
    #[cfg(test)]
    fail_next_allocation: bool,
    #[cfg(test)]
    allocation_countdown: Option<usize>,
    #[cfg(test)]
    final_admission_fault: Option<FinalAdmissionFault>,
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
            space: SlotSpace::default(),
            daemon_used: size_of::<Self>(),
            daemon_peak: size_of::<Self>(),
            peer_limit,
            daemon_limit,
            next_id: 1,
            #[cfg(test)]
            fail_next_allocation: false,
            #[cfg(test)]
            allocation_countdown: None,
            #[cfg(test)]
            final_admission_fault: None,
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
    pub(in crate::manager) fn fail_final_admission_for_test(&mut self, fault: FinalAdmissionFault) {
        self.final_admission_fault = Some(fault);
    }

    #[cfg(test)]
    pub(in crate::manager) fn final_admission_fault_pending(&self) -> bool {
        self.final_admission_fault.is_some()
    }

    #[cfg(test)]
    pub(in crate::manager) fn fail_allocation_after_for_test(&mut self, allowed: Option<usize>) {
        self.allocation_countdown = allowed;
    }

    pub(in crate::manager) fn limits(&self) -> (usize, usize) {
        (self.peer_limit, self.daemon_limit)
    }

    #[cfg_attr(
        not(any(test, feature = "bench-internals")),
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
    pub(in crate::manager) fn peer_usage(&self, peer: PeerId) -> Usage {
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

    fn peer_range(&self, peer: PeerId) -> std::ops::Range<usize> {
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

    fn check(&self, address: PeerId, peer: usize, daemon: usize) -> Result<(), Exhaustion> {
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

    fn note_peer_peak(&mut self, peer: PeerId, attempted: usize) {
        let range = self.peer_range(peer);
        for record in &mut self.records[range] {
            record.peer_peak = record.peer_peak.max(attempted);
        }
    }

    fn set_peer_retained(&mut self, peer: PeerId, retained: usize) {
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
                held: Held::default(),
                pins: Slots::new(),
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
    /// Recompute every holder count, free bit, index entry and credit from
    /// scratch and compare them with the running values.
    #[cfg(test)]
    pub(in crate::manager) fn assert_consistent(&self) {
        let space = &self.space;
        let high_water = space.keys.len();
        assert!(high_water <= space.capacity());
        assert_eq!(space.holders.len(), high_water);
        assert_eq!(space.free.len(), high_water.div_ceil(64));
        let mut holders = vec![0_u32; high_water];
        let mut daemon = size_of::<Self>() + self.records.capacity() * size_of::<Record>();
        daemon += space.bytes();
        for record in &self.records {
            daemon += record.owned_bytes();
            let held = record.held.view();
            if let HeldView::Sparse(entries) = held {
                assert!(
                    entries.iter().all(|entry| entry & MARK == 0),
                    "no mark left"
                );
                if !matches!(record.state, State::Capturing) {
                    assert!(entries.windows(2).all(|pair| pair[0] < pair[1]), "sorted");
                }
            }
            let mut count = 0;
            for slot in held.slots(|_| {}) {
                holders[slot as usize] += 1;
                count += 1;
            }
            assert_eq!(record.masked, count, "masked counts held entries");
            assert!(record.pins.windows(2).all(|pair| pair[0] <= pair[1]));
            for &slot in &record.pins {
                holders[slot as usize] += 1;
            }
            let expected = self
                .records
                .iter()
                .filter(|other| other.handle.owner.peer == record.handle.owner.peer)
                .map(Record::charge)
                .sum::<usize>();
            assert_eq!(record.peer_retained, expected);
            assert!(record.peer_peak >= expected);
        }
        assert_eq!(space.holders.as_slice(), holders.as_slice());
        let mut free = 0;
        for (slot, count) in holders.iter().enumerate() {
            let id = u32::try_from(slot).unwrap();
            assert_eq!(
                bit(&space.free, id),
                *count == 0,
                "free bits mark unheld slots"
            );
            if *count == 0 {
                free += 1;
            } else {
                assert_eq!(space.find(&space.keys[slot]), Some(id));
            }
        }
        assert_eq!(free, space.free_count);
        assert!(
            holders.last().is_none_or(|count| *count != 0),
            "top slot held"
        );
        assert!(
            space.free[..space.first_free.min(space.free.len())]
                .iter()
                .all(|word| *word == 0)
        );
        assert_eq!(
            space.index.iter().filter(|entry| **entry != 0).count(),
            space.live()
        );
        assert_eq!(self.daemon_used, daemon);
        assert!(self.daemon_peak >= daemon);
    }

    pub(in crate::manager) fn register(
        &mut self,
        owner: PeerSession,
    ) -> Result<ProvenanceHandle, Exhaustion> {
        if let Some(handle) = self.primary_handle(owner) {
            return Ok(handle);
        }
        self.insert_record(owner, None)
    }

    #[cfg(any(test, feature = "bench-internals"))]
    pub(in crate::manager) fn slot_usage(&self) -> SlotUsage {
        SlotUsage {
            live: self.space.live(),
            capacity: self.space.capacity(),
        }
    }

    fn allocation_failure(&self, peer: PeerId) -> Exhaustion {
        Exhaustion {
            cause: ExhaustionCause::AllocationFailure,
            limiting_peer: None,
            attempted_peer_bytes: self.peer_usage(peer).retained,
            attempted_daemon_bytes: self.daemon_used,
        }
    }

    /// Charge storage to the daemon and to `peer` before allocating it. The
    /// replaced allocation stays charged until the caller refunds it.
    fn credit(&mut self, peer: PeerId, bytes: usize) -> Result<(), Exhaustion> {
        let attempted = self
            .peer_usage(peer)
            .retained
            .checked_add(bytes)
            .ok_or_else(Self::overflow)?;
        let daemon = self
            .daemon_used
            .checked_add(bytes)
            .ok_or_else(Self::overflow)?;
        self.check(peer, attempted, daemon)?;
        self.daemon_used = daemon;
        self.daemon_peak = self.daemon_peak.max(daemon);
        self.note_peer_peak(peer, attempted);
        self.set_peer_retained(peer, attempted);
        Ok(())
    }

    fn refund(&mut self, peer: PeerId, bytes: usize) {
        self.daemon_used -= bytes;
        self.set_peer_retained(peer, self.peer_usage(peer).retained - bytes);
    }

    /// Re-derive the peer total after a record's holdings or storage moved.
    fn recharge(&mut self, index: usize, before: usize) {
        let peer = self.records[index].handle.owner.peer;
        let after = self.records[index].charge();
        let retained = self.peer_usage(peer).retained - before + after;
        self.note_peer_peak(peer, retained);
        self.set_peer_retained(peer, retained);
    }

    /// Room for `fresh` new keys. Growth charges the new arrays beside the
    /// old ones, then settles on the capacities that actually exist.
    fn ensure_space(
        &mut self,
        peer: PeerId,
        fresh: usize,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<(), Exhaustion> {
        let needed = self
            .space
            .keys
            .len()
            .checked_add(fresh.saturating_sub(self.space.free_count))
            .ok_or_else(Self::overflow)?;
        let current = self.space.capacity();
        if needed <= current {
            return Ok(());
        }
        let target = needed
            .max(current.saturating_add(current / 2))
            .max(MIN_SLOT_CAPACITY);
        if target >= MAX_SLOTS {
            return Err(Self::overflow());
        }
        let bytes = SlotSpace::bytes_for(target).ok_or_else(Self::overflow)?;
        let retained = self.peer_usage(peer).retained;
        let daemon = self
            .daemon_used
            .checked_add(bytes)
            .ok_or_else(Self::overflow)?;
        self.check(peer, retained, daemon)?;
        self.daemon_used = daemon;
        self.daemon_peak = self.daemon_peak.max(daemon);
        let before = self.space.bytes();
        checkpoint(true);
        let grown = self.allocation_permitted() && self.space.resize(target, checkpoint).is_ok();
        checkpoint(true);
        self.daemon_used = self.daemon_used - bytes - before + self.space.bytes();
        if grown {
            Ok(())
        } else {
            Err(Exhaustion {
                cause: ExhaustionCause::AllocationFailure,
                limiting_peer: None,
                attempted_peer_bytes: retained,
                attempted_daemon_bytes: daemon,
            })
        }
    }

    /// Free the space once nothing holds a slot, and shrink it once the
    /// high-water mark falls to a quarter of its capacity. Shrinking is
    /// optional: a daemon-cap or allocation refusal leaves the space as is.
    fn settle_space(&mut self, checkpoint: &mut impl FnMut(bool)) {
        if self.space.live() == 0 {
            self.daemon_used -= self.space.bytes();
            self.space.clear();
            return;
        }
        if self.space.keys.len() > MIN_SLOT_CAPACITY
            && self.space.live().saturating_mul(4) <= self.space.keys.len()
        {
            self.compact(checkpoint);
        }
        let capacity = self.space.capacity();
        let length = self.space.keys.len();
        if capacity <= MIN_SLOT_CAPACITY || length > capacity / 4 {
            return;
        }
        let target = (length * 2).max(MIN_SLOT_CAPACITY);
        let Some(daemon) = SlotSpace::bytes_for(target)
            .and_then(|bytes| self.daemon_used.checked_add(bytes))
            .filter(|daemon| *daemon <= self.daemon_limit)
        else {
            return;
        };
        let bytes = daemon - self.daemon_used;
        self.daemon_used = daemon;
        self.daemon_peak = self.daemon_peak.max(daemon);
        let before = self.space.bytes();
        checkpoint(true);
        let _ = self.space.resize(target, checkpoint);
        checkpoint(true);
        self.daemon_used = self.daemon_used - bytes - before + self.space.bytes();
    }

    /// Renumber held slots into a dense prefix once at most a quarter of the
    /// high-water mark is live, so slots held high cannot keep the space
    /// large after the rest drains. The renumbering keeps slot order, so
    /// sorted entries and pins stay sorted and a bitset is rewritten in
    /// place. Slot IDs never leave the ledger, so every reference is here:
    /// record entries, pins and the index. A refused temporary map skips it.
    fn compact(&mut self, checkpoint: &mut impl FnMut(bool)) {
        let length = self.space.keys.len();
        let Some(bytes) = length.checked_mul(size_of::<u32>()) else {
            return;
        };
        let Some(daemon) = self
            .daemon_used
            .checked_add(bytes)
            .filter(|daemon| *daemon <= self.daemon_limit)
        else {
            return;
        };
        let mut renumber = Slots::new();
        if renumber.try_grow(length).is_err() {
            return;
        }
        self.daemon_used = daemon;
        self.daemon_peak = self.daemon_peak.max(daemon);
        checkpoint(true);
        let space = &mut self.space;
        let mut live = 0_u32;
        for slot in 0..length {
            if slot % CHECKPOINT_STRIDE == 0 {
                checkpoint(false);
            }
            if space.holders[slot] == 0 {
                renumber.push(u32::MAX);
            } else {
                let target = live as usize;
                space.keys[target] = space.keys[slot];
                space.holders[target] = space.holders[slot];
                renumber.push(live);
                live += 1;
            }
        }
        space.keys.truncate(live as usize);
        space.holders.truncate(live as usize);
        space.free.clear();
        space.free.resize((live as usize).div_ceil(64), 0);
        space.free_count = 0;
        space.first_free = 0;
        space.index.iter_mut().for_each(|entry| *entry = 0);
        for slot in 0..live {
            if (slot as usize).is_multiple_of(CHECKPOINT_STRIDE) {
                checkpoint(false);
            }
            space.insert_index(slot);
        }
        for record in &mut self.records {
            match &mut record.held {
                Held::Sparse(entries) => {
                    for (n, entry) in entries.iter_mut().enumerate() {
                        if n % CHECKPOINT_STRIDE == 0 {
                            checkpoint(false);
                        }
                        *entry = sparse_entry(renumber[sparse_slot(*entry) as usize]);
                    }
                }
                Held::Dense(words) => {
                    // A slot only moves down, onto a position already read.
                    for word in 0..words.len() {
                        checkpoint(false);
                        let mut rest = words[word];
                        while rest != 0 {
                            let offset = rest.trailing_zeros();
                            rest &= rest - 1;
                            let old = u32::try_from(word * 64).expect("slot IDs fit u32") + offset;
                            clear_bit(words, old);
                            set_bit(words, renumber[old as usize]);
                        }
                    }
                }
            }
            for pin in &mut record.pins {
                *pin = renumber[*pin as usize];
            }
        }
        checkpoint(true);
        drop(renumber);
        self.daemon_used -= bytes;
    }

    /// Replace a record's held storage with `bytes` of new capacity built by
    /// `build`, charging it beside the old storage until that is freed.
    fn replace_held(
        &mut self,
        index: usize,
        bytes: usize,
        build: impl FnOnce(&Held) -> Option<Held>,
    ) -> Result<(), Exhaustion> {
        let peer = self.records[index].handle.owner.peer;
        self.credit(peer, bytes)?;
        let replacement = if self.allocation_permitted() {
            build(&self.records[index].held)
        } else {
            None
        };
        let Some(held) = replacement else {
            let error = self.allocation_failure(peer);
            self.refund(peer, bytes);
            return Err(error);
        };
        debug_assert_eq!(held.bytes(), bytes);
        let old = std::mem::replace(&mut self.records[index].held, held);
        self.refund(peer, old.bytes());
        Ok(())
    }

    /// Room for `count` sparse entries.
    fn grow_sparse(&mut self, index: usize, count: usize) -> Result<(), Exhaustion> {
        let Held::Sparse(entries) = &self.records[index].held else {
            return Err(Self::admission_invariant());
        };
        if count <= entries.capacity() {
            return Ok(());
        }
        let bytes = count
            .checked_mul(size_of::<u32>())
            .ok_or_else(Self::overflow)?;
        self.replace_held(index, bytes, |held| {
            let Held::Sparse(entries) = held else {
                return None;
            };
            let mut grown = Slots::new();
            grown.try_grow(count).ok()?;
            grown.extend_from_slice(entries);
            Some(Held::Sparse(grown))
        })
    }

    /// Cover `top` in a dense record's bitset.
    fn grow_dense(&mut self, index: usize, top: u32) -> Result<(), Exhaustion> {
        let Held::Dense(words) = &self.records[index].held else {
            return Err(Self::admission_invariant());
        };
        let target = dense_bytes(top) / size_of::<u64>();
        if target <= words.len() {
            return Ok(());
        }
        self.replace_held(index, target * size_of::<u64>(), |held| {
            let Held::Dense(words) = held else {
                return None;
            };
            let mut grown = Words::new();
            grown.try_grow(target).ok()?;
            grown.extend_from_slice(words);
            grown.resize(target, 0);
            Some(Held::Dense(grown))
        })
    }

    /// Rebuild sealed sparse entries as a bitset covering `top`.
    fn rebuild_dense(
        &mut self,
        index: usize,
        top: u32,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<(), Exhaustion> {
        let target = dense_bytes(top) / size_of::<u64>();
        self.replace_held(index, target * size_of::<u64>(), |held| {
            let mut words = Words::new();
            words.try_grow(target).ok()?;
            words.resize(target, 0);
            for slot in held.view().slots(&mut *checkpoint) {
                set_bit(&mut words, slot);
            }
            Some(Held::Dense(words))
        })
    }

    /// Rebuild a bitset as sorted sparse entries with room for `count`.
    fn rebuild_sparse(
        &mut self,
        index: usize,
        count: usize,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<(), Exhaustion> {
        let bytes = count
            .checked_mul(size_of::<u32>())
            .ok_or_else(Self::overflow)?;
        self.replace_held(index, bytes, |held| {
            let mut entries = Slots::new();
            entries.try_grow(count).ok()?;
            entries.extend(held.view().slots(&mut *checkpoint).map(sparse_entry));
            Some(Held::Sparse(entries))
        })
    }

    /// Size a sealed record for `extra` more slots up to `top`, choosing
    /// whichever representation is smaller. A switch back to sparse waits
    /// until sparse is at most half the bitset, so sizes cannot flap.
    fn fit_held(
        &mut self,
        index: usize,
        extra: usize,
        top: u32,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<(), Exhaustion> {
        let record = &self.records[index];
        let count = record
            .masked
            .checked_add(extra)
            .ok_or_else(Self::overflow)?;
        let top = record.held.view().top().map_or(top, |held| held.max(top));
        let dense = dense_bytes(top);
        checkpoint(true);
        let fitted = match &record.held {
            Held::Sparse(_) if sparse_bytes(count) > dense => {
                self.rebuild_dense(index, top, checkpoint)
            }
            Held::Sparse(_) => self.grow_sparse(index, count),
            Held::Dense(_) if sparse_bytes(count).saturating_mul(2) <= dense => {
                self.rebuild_sparse(index, count, checkpoint)
            }
            Held::Dense(_) => self.grow_dense(index, top),
        };
        checkpoint(true);
        fitted
    }

    fn grow_pins(
        &mut self,
        index: usize,
        count: usize,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<(), Exhaustion> {
        let old = self.records[index].pins.capacity();
        if count <= old {
            return Ok(());
        }
        let peer = self.records[index].handle.owner.peer;
        let bytes = count
            .checked_mul(size_of::<u32>())
            .ok_or_else(Self::overflow)?;
        self.credit(peer, bytes)?;
        checkpoint(true);
        let failed =
            !self.allocation_permitted() || self.records[index].pins.try_grow(count).is_err();
        checkpoint(true);
        if failed {
            let error = self.allocation_failure(peer);
            self.refund(peer, bytes);
            return Err(error);
        }
        self.refund(peer, old * size_of::<u32>());
        Ok(())
    }

    /// Credit held slots to `peer` without allocating.
    fn credit_slots(&mut self, peer: PeerId, slots: usize) -> Result<(), Exhaustion> {
        let attempted = slots
            .checked_mul(SLOT_BYTES)
            .and_then(|bytes| self.peer_usage(peer).retained.checked_add(bytes))
            .ok_or_else(Self::overflow)?;
        self.check(peer, attempted, self.daemon_used)?;
        self.note_peer_peak(peer, attempted);
        self.set_peer_retained(peer, attempted);
        Ok(())
    }

    fn view(&self, index: usize) -> EvpnProofView<'_> {
        let record = &self.records[index];
        EvpnProofView {
            space: &self.space,
            held: record.held.view(),
            masked: record.masked,
        }
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

    /// Admit one captured key: one keyed hash, one lookup, an insert on
    /// first sight and an appended entry. Capture order is irrelevant and a
    /// repeated key is merged at sealing; `checkpoint` brackets only
    /// allocations, callers checkpoint their walk.
    pub(in crate::manager) fn capture_key_with_checkpoint(
        &mut self,
        handle: ProvenanceHandle,
        key: EvpnRouteKey,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<bool, Exhaustion> {
        let Some(index) = self.checked_handle_index(handle)? else {
            return Ok(false);
        };
        if !matches!(self.records[index].state, State::Capturing) {
            return Ok(false);
        }
        self.capture_slot(index, key, checkpoint)
            .map(|()| true)
            .map_err(|error| self.mark_exhausted(handle, error))
    }

    fn capture_slot(
        &mut self,
        index: usize,
        key: EvpnRouteKey,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<(), Exhaustion> {
        // A new key reuses this hash to insert unless growth rebuilt the
        // table in between.
        let mut home = self.space.bucket_or_empty(&key);
        let existing = home.and_then(|home| self.space.find_from(home, &key));
        let peer = self.records[index].handle.owner.peer;
        if existing.is_none() {
            let buckets = self.space.index.len();
            self.ensure_space(peer, 1, checkpoint)?;
            if self.space.index.len() != buckets {
                home = None;
            }
        }
        let Held::Sparse(entries) = &self.records[index].held else {
            return Err(Self::admission_invariant());
        };
        let length = entries.len();
        if length == entries.capacity() {
            checkpoint(true);
            let grown = self.grow_sparse(index, length.saturating_mul(2).max(16));
            checkpoint(true);
            grown?;
        }
        self.credit_slots(peer, 1)?;
        let slot = existing.unwrap_or_else(|| {
            let home = home.unwrap_or_else(|| self.space.bucket(&key));
            self.space.insert_new(home, key)
        });
        self.space.hold(slot);
        let record = &mut self.records[index];
        let Held::Sparse(entries) = &mut record.held else {
            unreachable!("a capturing record stays sparse");
        };
        entries.push(sparse_entry(slot));
        record.masked += 1;
        Ok(())
    }

    /// Seal a capture: merge repeated keys and keep the smaller of sorted
    /// entries and a bitset. A bitset is built straight from the unsorted
    /// entries; only a sparse result, at most a 32nd of the span, is sorted.
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
        match self.seal_held(index, checkpoint) {
            Ok(()) => {
                self.records[index].state = State::Ready;
                Ok(true)
            }
            Err(error) => Err(self.mark_exhausted(handle, error)),
        }
    }

    fn seal_held(
        &mut self,
        index: usize,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<(), Exhaustion> {
        let peer = self.records[index].handle.owner.peer;
        let Held::Sparse(entries) = &self.records[index].held else {
            return Err(Self::admission_invariant());
        };
        let mut top = None;
        for (n, entry) in entries.iter().enumerate() {
            if n % CHECKPOINT_STRIDE == 0 {
                checkpoint(false);
            }
            top = top.max(Some(sparse_slot(*entry)));
        }
        let Some(top) = top else {
            return Ok(());
        };
        let repeats = if sparse_bytes(entries.len()) > dense_bytes(top) {
            let bytes = dense_bytes(top);
            self.credit(peer, bytes)?;
            let mut words = Words::new();
            checkpoint(true);
            let failed =
                !self.allocation_permitted() || words.try_grow(bytes / size_of::<u64>()).is_err();
            checkpoint(true);
            if failed {
                let error = self.allocation_failure(peer);
                self.refund(peer, bytes);
                return Err(error);
            }
            words.resize(bytes / size_of::<u64>(), 0);
            let Self { records, space, .. } = self;
            let Record { held, masked, .. } = &mut records[index];
            let Held::Sparse(entries) = &*held else {
                unreachable!("still sparse");
            };
            // Unsorted entries: a repeated key finds its bit already set
            // and gives back its extra hold.
            let mut repeats = 0;
            for (n, entry) in entries.iter().enumerate() {
                if n % CHECKPOINT_STRIDE == 0 {
                    checkpoint(false);
                }
                let slot = sparse_slot(*entry);
                if bit(&words, slot) {
                    space.release(slot);
                    repeats += 1;
                } else {
                    set_bit(&mut words, slot);
                }
            }
            *masked -= repeats;
            let old = std::mem::replace(held, Held::Dense(words));
            self.refund(peer, old.bytes());
            repeats
        } else {
            let Self { records, space, .. } = self;
            let Record { held, masked, .. } = &mut records[index];
            let Held::Sparse(entries) = held else {
                unreachable!("still sparse");
            };
            checkpoint(true);
            entries.sort_unstable();
            checkpoint(true);
            let mut write = 0;
            for read in 0..entries.len() {
                if read % CHECKPOINT_STRIDE == 0 {
                    checkpoint(false);
                }
                if write > 0 && entries[read] == entries[write - 1] {
                    space.release(sparse_slot(entries[read]));
                } else {
                    entries[write] = entries[read];
                    write += 1;
                }
            }
            let repeats = entries.len() - write;
            entries.truncate(write);
            *masked -= repeats;
            repeats
        };
        let retained = self.peer_usage(peer).retained - repeats * SLOT_BYTES;
        self.set_peer_retained(peer, retained);
        Ok(())
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

    /// Admitted keys in key order, for comparison with expected sets.
    #[cfg(test)]
    pub(in crate::manager) fn proof_keys(
        &self,
        handle: ProvenanceHandle,
    ) -> Result<Option<Vec<EvpnRouteKey>>, Exhaustion> {
        self.proof(handle).map(|proof| {
            proof.map(|proof| {
                let mut keys: Vec<_> = proof.iter_with_checkpoint(|_| {}).collect();
                keys.sort_unstable();
                keys
            })
        })
    }

    /// Inspect retained storage without granting an exhausted proof authority.
    #[cfg(test)]
    pub(in crate::manager) fn retained_keys_for_test(
        &self,
        handle: ProvenanceHandle,
    ) -> Option<Vec<EvpnRouteKey>> {
        self.index(handle).map(|index| {
            let mut keys: Vec<_> = self.view(index).iter_with_checkpoint(|_| {}).collect();
            keys.sort_unstable();
            keys
        })
    }

    /// Keep a charged immutable copy under the same peer/session ownership.
    /// The copy holds each of its slots, so none can be reused while it lives.
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
        if self.proof(handle)?.is_none() {
            return Ok(None);
        }
        let snapshot = match self.insert_record(handle.owner, Some(handle.generation)) {
            Ok(snapshot) => snapshot,
            Err(error) => return Err(self.mark_exhausted(handle, error)),
        };
        if let Err(error) = self.copy_snapshot(handle, snapshot) {
            self.retire(snapshot);
            return Err(self.mark_exhausted(handle, error));
        }
        Ok(Some(snapshot))
    }

    fn copy_snapshot(
        &mut self,
        handle: ProvenanceHandle,
        snapshot: ProvenanceHandle,
    ) -> Result<(), Exhaustion> {
        let peer = handle.owner.peer;
        let source = self.index(handle).expect("snapshot source remains owned");
        let masked = self.records[source].masked;
        let bytes = match &self.records[source].held {
            Held::Sparse(entries) => sparse_bytes(entries.len()),
            Held::Dense(words) => words.len() * size_of::<u64>(),
        };
        self.credit(peer, bytes)?;
        let built = if self.allocation_permitted() {
            copy_held(&self.records[source].held)
        } else {
            None
        };
        let Some(held) = built else {
            let error = self.allocation_failure(peer);
            self.refund(peer, bytes);
            return Err(error);
        };
        if let Err(error) = self.credit_slots(peer, masked) {
            drop(held);
            self.refund(peer, bytes);
            return Err(error);
        }
        let destination = self.index(snapshot).expect("new snapshot remains owned");
        let Self { records, space, .. } = self;
        let copy = &mut records[destination];
        copy.held = held;
        copy.masked = masked;
        for slot in copy.held.view().slots(|_| {}) {
            space.hold(slot);
        }
        Ok(())
    }

    /// Every withdrawal names a distinct admitted slot. Entries are marked
    /// to detect repeats and restored before returning.
    fn validate_withdrawals(
        &mut self,
        index: usize,
        withdrawals: &[EvpnRouteKey],
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<(), Exhaustion> {
        let Self { records, space, .. } = self;
        let held = &mut records[index].held;
        let mut marked = 0;
        for (n, key) in withdrawals.iter().enumerate() {
            if n % CHECKPOINT_STRIDE == 0 {
                checkpoint(false);
            }
            let Some(slot) = space.find(key) else {
                break;
            };
            let fresh = match held {
                Held::Dense(words) if bit(words, slot) => {
                    clear_bit(words, slot);
                    true
                }
                Held::Dense(_) => false,
                Held::Sparse(entries) => match sparse_position(entries, slot) {
                    Ok(position) if entries[position] & MARK == 0 => {
                        entries[position] |= MARK;
                        true
                    }
                    _ => false,
                },
            };
            if !fresh {
                break;
            }
            marked += 1;
        }
        for (n, key) in withdrawals[..marked].iter().enumerate() {
            if n % CHECKPOINT_STRIDE == 0 {
                checkpoint(false);
            }
            let slot = space.find(key).expect("validated withdrawal");
            match held {
                Held::Dense(words) => set_bit(words, slot),
                Held::Sparse(entries) => {
                    let position = sparse_position(entries, slot).expect("validated withdrawal");
                    entries[position] &= !MARK;
                }
            }
        }
        if marked == withdrawals.len() {
            Ok(())
        } else {
            Err(Self::admission_invariant())
        }
    }

    /// Final announcements are sorted and unique, each with an existing
    /// slot that the record already admits or that its reservation pinned.
    fn validate_announcements(
        &self,
        index: usize,
        announcements: impl Iterator<Item = EvpnRouteKey>,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<(), Exhaustion> {
        let record = &self.records[index];
        let held = record.held.view();
        let mut previous = None;
        for (n, key) in announcements.enumerate() {
            if n % CHECKPOINT_STRIDE == 0 {
                checkpoint(false);
            }
            if previous.is_some_and(|prior| prior >= key) {
                return Err(Self::admission_invariant());
            }
            previous = Some(key);
            let slot = self
                .space
                .find(&key)
                .ok_or_else(Self::admission_invariant)?;
            if !held.contains(slot) && record.pins.binary_search(&slot).is_err() {
                return Err(Self::admission_invariant());
            }
        }
        Ok(())
    }

    fn release_pins(&mut self, index: usize, checkpoint: &mut impl FnMut(bool)) {
        if self.records[index].pins.is_empty() {
            return;
        }
        let before = self.records[index].charge();
        let Self { records, space, .. } = self;
        for (n, slot) in records[index].pins.drain(..).enumerate() {
            if n % CHECKPOINT_STRIDE == 0 {
                checkpoint(false);
            }
            space.release(slot);
        }
        self.recharge(index, before);
    }

    /// Pin every announced key the record has not admitted, so final
    /// application only flips entries: it allocates nothing, and no release
    /// elsewhere can free a slot it still needs. Reserve after owning a queue
    /// slot and before export-side mutations; a later reservation replaces
    /// the pins of an earlier one.
    pub(in crate::manager) fn reserve_admission_with_checkpoint<A>(
        &mut self,
        handle: ProvenanceHandle,
        announcements: A,
        withdrawals: &[EvpnRouteKey],
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<bool, Exhaustion>
    where
        A: Iterator<Item = EvpnRouteKey> + Clone,
    {
        let Some(index) = self.checked_handle_index(handle)? else {
            return Ok(false);
        };
        if !self.records[index].primary || !matches!(self.records[index].state, State::Ready) {
            return Ok(false);
        }
        if let Err(error) = self.validate_withdrawals(index, withdrawals, checkpoint) {
            return Err(self.mark_exhausted(handle, error));
        }
        self.release_pins(index, checkpoint);
        self.pin_announcements(index, announcements, checkpoint)
            .map(|()| true)
            .map_err(|error| self.mark_exhausted(handle, error))
    }

    /// Count, make room, pin, then size the record for the pinned slots.
    /// Pins hold their slots first, so sizing needs no prediction of which
    /// slots new keys will take.
    fn pin_announcements(
        &mut self,
        index: usize,
        announcements: impl Iterator<Item = EvpnRouteKey> + Clone,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<(), Exhaustion> {
        let (mut fresh, mut pins) = (0_usize, 0_usize);
        let mut previous = None;
        let held = self.records[index].held.view();
        for (n, key) in announcements.clone().enumerate() {
            if n % CHECKPOINT_STRIDE == 0 {
                checkpoint(false);
            }
            // Sorted unique batches keep a repeated announcement off the wire.
            if previous.is_some_and(|prior| prior >= key) {
                return Err(Self::admission_invariant());
            }
            previous = Some(key);
            match self.space.find(&key) {
                Some(slot) if held.contains(slot) => continue,
                Some(_) => {}
                None => fresh += 1,
            }
            pins += 1;
        }
        if pins == 0 {
            return Ok(());
        }
        let peer = self.records[index].handle.owner.peer;
        self.ensure_space(peer, fresh, checkpoint)?;
        self.grow_pins(index, pins, checkpoint)?;
        self.credit_slots(peer, pins)?;
        let Self { records, space, .. } = self;
        let record = &mut records[index];
        for (n, key) in announcements.enumerate() {
            if n % CHECKPOINT_STRIDE == 0 {
                checkpoint(false);
            }
            let home = space.bucket(&key);
            let slot = match space.find_from(home, &key) {
                Some(slot) if record.held.view().contains(slot) => continue,
                Some(slot) => slot,
                None => space.insert_new(home, key),
            };
            space.hold(slot);
            record.pins.push(slot);
        }
        debug_assert_eq!(record.pins.len(), pins);
        checkpoint(true);
        record.pins.sort_unstable();
        checkpoint(true);
        let top = *record.pins.last().expect("pinned");
        self.fit_held(index, pins, top, checkpoint)
    }

    /// Apply final accepted batches after their reservation and before
    /// enqueue. Final filtering may only remove announcements or add admitted
    /// withdrawals. The whole batch is validated before any entry changes,
    /// and application allocates nothing. A key withdrawn and announced in
    /// one batch stays admitted. Withdrawals need only be distinct: the
    /// emitter sorts them, but the ledger does not depend on it.
    pub(in crate::manager) fn apply_admitted_with_checkpoint<A>(
        &mut self,
        handle: ProvenanceHandle,
        announcements: A,
        withdrawals: &[EvpnRouteKey],
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<bool, Exhaustion>
    where
        A: Iterator<Item = EvpnRouteKey> + Clone,
    {
        let Some(index) = self.checked_handle_index(handle)? else {
            return Ok(false);
        };
        if !self.records[index].primary || !matches!(self.records[index].state, State::Ready) {
            return Ok(false);
        }
        // A changed final reservation is an internal invariant failure. This
        // hook exercises the real manager's late refusal after normal probing.
        #[cfg(test)]
        if self.final_admission_fault == Some(FinalAdmissionFault::Apply) {
            self.final_admission_fault = None;
            return Err(self.mark_exhausted(handle, Self::admission_invariant()));
        }
        let valid = self
            .validate_withdrawals(index, withdrawals, checkpoint)
            .and_then(|()| self.validate_announcements(index, announcements.clone(), checkpoint));
        if let Err(error) = valid {
            return Err(self.mark_exhausted(handle, error));
        }
        let before = self.records[index].charge();
        if matches!(self.records[index].held, Held::Dense(_)) {
            self.apply_dense(index, announcements, withdrawals, checkpoint);
        } else {
            self.apply_sparse(index, announcements, withdrawals, checkpoint);
        }
        self.recharge(index, before);
        self.settle_space(checkpoint);
        Ok(true)
    }

    fn apply_dense(
        &mut self,
        index: usize,
        announcements: impl Iterator<Item = EvpnRouteKey>,
        withdrawals: &[EvpnRouteKey],
        checkpoint: &mut impl FnMut(bool),
    ) {
        let Self { records, space, .. } = self;
        let Record {
            held, pins, masked, ..
        } = &mut records[index];
        let Held::Dense(words) = held else {
            unreachable!("dense application");
        };
        for (n, key) in withdrawals.iter().enumerate() {
            if n % CHECKPOINT_STRIDE == 0 {
                checkpoint(false);
            }
            clear_bit(words, space.find(key).expect("validated withdrawal"));
        }
        for (n, key) in announcements.enumerate() {
            if n % CHECKPOINT_STRIDE == 0 {
                checkpoint(false);
            }
            let slot = space.find(&key).expect("validated announcement");
            if !bit(words, slot) {
                set_bit(words, slot);
                space.hold(slot);
                *masked += 1;
            }
        }
        // Withdrawal holds drop only after re-announcements took theirs.
        for (n, key) in withdrawals.iter().enumerate() {
            if n % CHECKPOINT_STRIDE == 0 {
                checkpoint(false);
            }
            *masked -= 1;
            space.release(space.find(key).expect("withdrawn slot is still held"));
        }
        for (n, slot) in pins.drain(..).enumerate() {
            if n % CHECKPOINT_STRIDE == 0 {
                checkpoint(false);
            }
            space.release(slot);
        }
    }

    /// Sorted entries: mark withdrawals, unmark re-announcements, append new
    /// slots, release, then merge the appended tail through the drained pin
    /// buffer. Reservation sized both buffers, so nothing allocates.
    fn apply_sparse(
        &mut self,
        index: usize,
        announcements: impl Iterator<Item = EvpnRouteKey>,
        withdrawals: &[EvpnRouteKey],
        checkpoint: &mut impl FnMut(bool),
    ) {
        let Self { records, space, .. } = self;
        let Record {
            held, pins, masked, ..
        } = &mut records[index];
        let Held::Sparse(entries) = held else {
            unreachable!("sparse application");
        };
        let sealed = entries.len();
        for (n, key) in withdrawals.iter().enumerate() {
            if n % CHECKPOINT_STRIDE == 0 {
                checkpoint(false);
            }
            let slot = space.find(key).expect("validated withdrawal");
            let position = sparse_position(&entries[..sealed], slot).expect("validated withdrawal");
            entries[position] |= MARK;
        }
        for (n, key) in announcements.enumerate() {
            if n % CHECKPOINT_STRIDE == 0 {
                checkpoint(false);
            }
            let slot = space.find(&key).expect("validated announcement");
            match sparse_position(&entries[..sealed], slot) {
                Ok(position) if entries[position] & MARK != 0 => {
                    entries[position] &= !MARK;
                    space.hold(slot);
                    *masked += 1;
                }
                Ok(_) => {}
                Err(_) => {
                    debug_assert!(entries.len() < entries.capacity(), "reserved room");
                    entries.push(sparse_entry(slot));
                    space.hold(slot);
                    *masked += 1;
                }
            }
        }
        // Withdrawal holds drop only after re-announcements took theirs.
        for (n, key) in withdrawals.iter().enumerate() {
            if n % CHECKPOINT_STRIDE == 0 {
                checkpoint(false);
            }
            *masked -= 1;
            space.release(space.find(key).expect("withdrawn slot is still held"));
        }
        for (n, slot) in pins.drain(..).enumerate() {
            if n % CHECKPOINT_STRIDE == 0 {
                checkpoint(false);
            }
            space.release(slot);
        }
        // Each appended slot was pinned, so the pin buffer has room for the
        // tail; sort it there and merge it with the compacted sealed entries.
        pins.extend_from_slice(&entries[sealed..]);
        entries.truncate(sealed);
        checkpoint(true);
        pins.sort_unstable();
        checkpoint(true);
        let mut kept = 0;
        for read in 0..sealed {
            if read % CHECKPOINT_STRIDE == 0 {
                checkpoint(false);
            }
            if entries[read] & MARK == 0 {
                entries[kept] = entries[read];
                kept += 1;
            }
        }
        entries.truncate(kept);
        let total = kept + pins.len();
        entries.resize(total, 0);
        let (mut left, mut right) = (kept, pins.len());
        for write in (0..total).rev() {
            if write % CHECKPOINT_STRIDE == 0 {
                checkpoint(false);
            }
            if right == 0 || (left > 0 && entries[left - 1] > pins[right - 1]) {
                left -= 1;
                entries[write] = entries[left];
            } else {
                right -= 1;
                entries[write] = pins[right];
            }
        }
        pins.clear();
    }

    /// Final gates must preserve the reservation. Check this before any
    /// other-family advertised/capacity state is committed.
    pub(in crate::manager) fn preflight_admitted_with_checkpoint<A>(
        &mut self,
        handle: ProvenanceHandle,
        announcements: A,
        withdrawals: &[EvpnRouteKey],
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<bool, Exhaustion>
    where
        A: Iterator<Item = EvpnRouteKey> + Clone,
    {
        let Some(index) = self.checked_handle_index(handle)? else {
            return Ok(false);
        };
        if !self.records[index].primary || !matches!(self.records[index].state, State::Ready) {
            return Ok(false);
        }
        // A changed final reservation is an internal invariant failure. This
        // hook exercises the real manager's late refusal after normal probing.
        #[cfg(test)]
        if self.final_admission_fault == Some(FinalAdmissionFault::Preflight) {
            self.final_admission_fault = None;
            return Err(self.mark_exhausted(handle, Self::admission_invariant()));
        }
        let valid = self
            .validate_withdrawals(index, withdrawals, checkpoint)
            .and_then(|()| self.validate_announcements(index, announcements, checkpoint));
        match valid {
            Ok(()) => Ok(true),
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
        A: Iterator<Item = EvpnRouteKey> + Clone,
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
        A: Iterator<Item = EvpnRouteKey> + Clone,
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
        A: Iterator<Item = EvpnRouteKey> + Clone,
    {
        self.preflight_admitted_with_checkpoint(handle, announcements, withdrawals, &mut |_| {})
    }

    /// Release every slot the record holds, then free its storage before
    /// refunding the credit. The last holder of a slot frees it.
    fn free_keys(&mut self, index: usize, checkpoint: &mut impl FnMut(bool)) {
        let before = self.records[index].charge();
        let Self { records, space, .. } = self;
        let record = &mut records[index];
        for slot in record.held.view().slots(&mut *checkpoint) {
            space.release(slot);
        }
        for (n, slot) in record.pins.drain(..).enumerate() {
            if n % CHECKPOINT_STRIDE == 0 {
                checkpoint(false);
            }
            space.release(slot);
        }
        let bytes = record.owned_bytes();
        record.masked = 0;
        record.held = Held::default();
        record.pins = Slots::new();
        self.daemon_used -= bytes;
        self.recharge(index, before);
        self.settle_space(checkpoint);
    }

    /// Exhaustion cannot become a fresh capture.
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
        self.free_keys(index, &mut |_| {});
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
        self.free_keys(index, &mut |_| {});
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

/// An exactly sized copy of sealed held slots.
fn copy_held(held: &Held) -> Option<Held> {
    Some(match held {
        Held::Sparse(entries) => {
            let mut copied = Slots::new();
            copied.try_grow(entries.len()).ok()?;
            copied.extend_from_slice(entries);
            Held::Sparse(copied)
        }
        Held::Dense(words) => {
            let mut copied = Words::new();
            copied.try_grow(words.len()).ok()?;
            copied.extend_from_slice(words);
            Held::Dense(copied)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeSet, HashMap};
    use std::net::IpAddr;
    use std::net::Ipv4Addr;

    use rustbgpd_wire::{EthernetTagId, MacAddress, RouteDistinguisher};

    fn owner(peer: u8, session_id: u64) -> PeerSession {
        PeerSession {
            peer: PeerId::from_addr(IpAddr::V4(Ipv4Addr::new(192, 0, 2, peer))),
            session_id,
        }
    }

    fn owner_wide(n: u16, session_id: u64) -> PeerSession {
        let [high, low] = n.to_be_bytes();
        PeerSession {
            peer: PeerId::from_addr(IpAddr::V4(Ipv4Addr::new(10, 0, high, low))),
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

    fn admit(
        ledger: &mut EvpnRecoveryProvenance,
        handle: ProvenanceHandle,
        announcements: &[EvpnRouteKey],
        withdrawals: &[EvpnRouteKey],
    ) {
        assert!(
            ledger
                .reserve_admission(handle, announcements.iter().copied(), withdrawals)
                .unwrap()
        );
        assert!(
            ledger
                .apply_admitted(handle, announcements.iter().copied(), withdrawals)
                .unwrap()
        );
    }

    fn record(ledger: &EvpnRecoveryProvenance, handle: ProvenanceHandle) -> &Record {
        &ledger.records[ledger.index(handle).unwrap()]
    }

    fn assert_running_charges(ledger: &EvpnRecoveryProvenance) {
        ledger.assert_consistent();
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
        assert_eq!(
            ledger.daemon_usage().retained,
            size_of::<EvpnRecoveryProvenance>()
        );
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
        assert_eq!(ledger.slot_usage().live, 3);
        let held = record(&ledger, handle).held.bytes();
        assert_eq!(held, 16 * size_of::<u32>(), "three sorted entries");
        let before_delete = ledger.daemon_usage().retained;
        let space = ledger.space.bytes();
        admit(&mut ledger, handle, &[], &[key(1), key(2), key(3)]);
        assert_eq!(ledger.proof_keys(handle).unwrap(), Some([].to_vec()));
        // The last holder released every slot, so the whole space went.
        assert_eq!(ledger.slot_usage().capacity, 0);
        assert_eq!(ledger.daemon_usage().retained, before_delete - space);
        assert_eq!(record(&ledger, handle).held.bytes(), held);
        assert!(ledger.finish_recovery(handle).unwrap());
        assert_eq!(record(&ledger, handle).held.bytes(), 0);
        assert!(ledger.retire_member(handle));
        assert_eq!(
            ledger.daemon_usage().retained,
            size_of::<EvpnRecoveryProvenance>()
        );
    }

    #[test]
    fn reserved_replay_does_not_allocate() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let handle = ledger.register(owner(1, 7)).unwrap();
        capture(&mut ledger, handle, &[key(1), key(3), key(5)]);
        assert!(
            ledger
                .reserve_admission(
                    handle,
                    [key(2), key(3), key(4)].into_iter(),
                    &[key(1), key(5)]
                )
                .unwrap()
        );
        let before = ledger.daemon_usage().peak;
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
        // A replay of admitted keys and a same-batch withdraw/announce need
        // no reservation and no allocation.
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
        assert_eq!(
            ledger.proof_keys(handle).unwrap(),
            Some([key(2), key(3), key(4)].to_vec())
        );
        assert_eq!(ledger.daemon_usage().peak, before);
        assert!(ledger.fail_next_allocation);
        assert_running_charges(&ledger);
        // Fresh keys need slot capacity; a refused grow is sticky.
        let error = ledger
            .reserve_admission(handle, (1000..3000).map(key), &[])
            .unwrap_err();
        assert_eq!(error.cause, ExhaustionCause::AllocationFailure);
        assert!(!ledger.fail_next_allocation);
        assert_running_charges(&ledger);
        assert_eq!(
            ledger.retained_keys_for_test(handle),
            Some([key(2), key(3), key(4)].to_vec())
        );
        assert_eq!(ledger.proof_keys(handle), Err(error));
        assert_eq!(ledger.begin_capture(handle), Err(error));
        assert_eq!(ledger.finish_recovery(handle), Err(error));
        assert!(ledger.retire_member(handle));
        assert_running_charges(&ledger);
    }

    #[test]
    fn ledger_loops_checkpoint_at_a_stride_and_bracket_allocations() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let handle = ledger.register(owner(1, 7)).unwrap();
        let original: Vec<_> = (0..640).map(key).collect();
        capture(&mut ledger, handle, &original);
        let announcements: Vec<_> = (640..1280).map(key).collect();
        let withdrawals: Vec<_> = (0..640).map(key).collect();
        let (mut visits, mut edges) = (0, 0);
        assert!(
            ledger
                .reserve_admission_with_checkpoint(
                    handle,
                    announcements.iter().copied(),
                    &withdrawals,
                    &mut |force| if force { edges += 1 } else { visits += 1 },
                )
                .unwrap()
        );
        // Withdrawal validation and its restore, two announcement passes and
        // one index rebuild stride: one visit per 64 items, never one per key
        // or per comparison.
        assert_eq!(visits, 4 * 640 / CHECKPOINT_STRIDE + 1);
        // Slot growth, pin allocation, pin sorting and record sizing are each
        // bracketed.
        assert_eq!(edges, 8);
        visits = 0;
        assert!(
            ledger
                .apply_admitted_with_checkpoint(
                    handle,
                    announcements.iter().copied(),
                    &withdrawals,
                    &mut |force| {
                        assert!(!force, "application never allocates");
                        visits += 1;
                    },
                )
                .unwrap()
        );
        // Validation of both lists and the withdrawal restore, then clearing,
        // setting, releasing and the pin drain.
        assert_eq!(visits, 7 * 640 / CHECKPOINT_STRIDE);
        let proof = ledger.proof(handle).unwrap().unwrap();
        visits = 0;
        assert_eq!(proof.iter_with_checkpoint(|_| visits += 1).count(), 640);
        let Held::Dense(words) = &record(&ledger, handle).held else {
            panic!("640 of 1280 slots is dense");
        };
        assert_eq!(visits, words.len());
        assert_running_charges(&ledger);
    }

    #[test]
    fn a_later_reservation_replaces_pins_and_dropped_announcements_release_them() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let handle = ledger.register(owner(1, 7)).unwrap();
        admit(&mut ledger, handle, &[key(1), key(3), key(5)], &[]);
        assert!(
            ledger
                .reserve_admission(
                    handle,
                    [key(2), key(3), key(4)].into_iter(),
                    &[key(1), key(5)]
                )
                .unwrap()
        );
        assert_eq!(record(&ledger, handle).pins.len(), 2);
        assert_eq!(ledger.slot_usage().live, 5);
        assert_running_charges(&ledger);
        // An unapplied reservation is replaced, never accumulated.
        assert!(
            ledger
                .reserve_admission(handle, [key(2), key(6)].into_iter(), &[])
                .unwrap()
        );
        assert_eq!(record(&ledger, handle).pins.len(), 2);
        assert_eq!(ledger.slot_usage().live, 5, "key(4) left, key(6) arrived");
        assert_running_charges(&ledger);
        // Final gates dropped key(6); its pin is released with no admission.
        assert!(
            ledger
                .apply_admitted(handle, [key(2)].into_iter(), &[])
                .unwrap()
        );
        assert_eq!(
            ledger.proof_keys(handle).unwrap(),
            Some([key(1), key(2), key(3), key(5)].to_vec())
        );
        assert_eq!(ledger.slot_usage().live, 4);
        assert!(record(&ledger, handle).pins.is_empty());
        assert_running_charges(&ledger);
        // More new bits than the reservation pinned is a typed refusal.
        assert!(
            ledger
                .reserve_admission(handle, [key(4)].into_iter(), &[])
                .unwrap()
        );
        let other = ledger.register(owner(2, 7)).unwrap();
        admit(&mut ledger, other, &[key(7)], &[]);
        assert_eq!(
            ledger
                .apply_admitted(handle, [key(4), key(7)].into_iter(), &[])
                .unwrap_err()
                .cause,
            ExhaustionCause::AdmissionInvariant
        );
        assert_running_charges(&ledger);
    }

    #[test]
    fn exhausted_reset_handoff_is_charged_primary_state_and_generation_fenced() {
        let mut ledger =
            EvpnRecoveryProvenance::with_test_limits(PEER_LIMIT_BYTES, DAEMON_LIMIT_BYTES);
        let handle = ledger.register(owner(1, 7)).unwrap();
        assert!(!ledger.is_dormant(handle));
        assert!(!ledger.mark_reset_admitted(handle));
        admit(&mut ledger, handle, &[key(1)], &[]);
        let snapshot = ledger.snapshot(handle).unwrap().unwrap();
        let retained = ledger.daemon_usage().retained;
        ledger.fail_next_allocation_for_test();
        let error = ledger
            .reserve_admission(handle, [key(2), key(3)].into_iter(), &[])
            .unwrap_err();
        assert_eq!(error.cause, ExhaustionCause::AllocationFailure);
        assert_eq!(ledger.daemon_usage().retained, retained);
        assert_eq!(
            ledger.retained_keys_for_test(handle),
            Some([key(1)].to_vec())
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
                    admit(&mut ledger, handle, &old, &[]);
                    admit(&mut ledger, handle, &announced, &withdrawn);
                    assert_eq!(
                        ledger.proof_keys(handle).unwrap().unwrap(),
                        expected.iter().copied().collect::<Vec<_>>()
                    );
                    assert_eq!(ledger.slot_usage().live, expected.len());
                    assert_running_charges(&ledger);
                }
            }
        }
    }

    #[test]
    fn peer_limit_counts_held_slots_and_bitset_overlap() {
        let record_bytes = size_of::<Record>();
        // Capture appends to a 16-entry sparse buffer first.
        let limit = record_bytes + 16 * size_of::<u32>() + 16 * SLOT_BYTES;
        let mut ledger = EvpnRecoveryProvenance::with_limits(limit, DAEMON_LIMIT_BYTES);
        let handle = ledger.register(owner(1, 7)).unwrap();
        assert!(ledger.finish_recovery(handle).unwrap());
        assert!(ledger.begin_capture(handle).unwrap());
        for n in 1..=16 {
            assert!(ledger.capture_key(handle, key(n)).unwrap());
        }
        assert_eq!(ledger.peer_usage(handle.owner.peer).retained, limit);
        assert_eq!(ledger.peer_usage(handle.owner.peer).peak, limit);
        let retained = ledger.daemon_usage().retained;
        let error = ledger.capture_key(handle, key(17)).unwrap_err();
        assert_eq!(error.cause, ExhaustionCause::PeerLimit);
        // The next entry needs a 32-entry buffer beside the old one.
        assert_eq!(error.attempted_peer_bytes, limit + 32 * size_of::<u32>());
        assert_eq!(ledger.daemon_usage().retained, retained);
        assert_eq!(ledger.seal_capture(handle), Err(error));
        assert_eq!(ledger.register(handle.owner).unwrap(), handle);
        assert_running_charges(&ledger);
        assert!(ledger.retire_member(handle));
        // Another peer holding the same slots is charged for them too.
        let mut ledger = EvpnRecoveryProvenance::with_limits(limit, DAEMON_LIMIT_BYTES);
        let first = ledger.register(owner(1, 7)).unwrap();
        let second = ledger.register(owner(2, 7)).unwrap();
        let keys: Vec<_> = (1..=16).map(key).collect();
        capture(&mut ledger, first, &keys);
        capture(&mut ledger, second, &keys);
        assert_eq!(ledger.peer_usage(second.owner.peer).retained, limit);
        assert_eq!(ledger.slot_usage().live, 16);
        assert_running_charges(&ledger);
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
        assert_eq!(record(&ledger, snapshot).held.bytes(), 2 * size_of::<u32>());
        admit(&mut ledger, handle, &[key(3)], &[key(1)]);
        let after_admission = ledger.daemon_usage().retained;
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
        assert_eq!(ledger.daemon_usage().retained, after_admission);
        assert_running_charges(&ledger);
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
        assert_running_charges(&ledger);
    }

    #[test]
    fn retained_snapshot_preserves_peer_peak_without_claiming_membership() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let session = owner(1, 7);
        let first = ledger.register(session).unwrap();
        let keys: Vec<_> = (1..=64).map(key).collect();
        admit(&mut ledger, first, &keys, &[]);
        let snapshot = ledger.snapshot(first).unwrap().unwrap();
        let peak = ledger.peer_usage(session.peer).peak;
        assert_eq!(ledger.primary_handle(session), Some(first));
        assert!(ledger.retire(first));
        assert_eq!(ledger.primary_handle(session), None);
        assert_eq!(ledger.peer_usage(session.peer).peak, peak);
        assert_eq!(ledger.proof_keys(snapshot).unwrap(), Some(keys.clone()));
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
    fn daemon_limit_covers_slot_growth_overlap_and_refuses_before_allocating() {
        let header = size_of::<EvpnRecoveryProvenance>();
        let full = MIN_SLOT_CAPACITY;
        let keys: Vec<_> = (0..u32::try_from(full).unwrap()).map(key).collect();
        let filled = |limit| {
            let mut ledger = EvpnRecoveryProvenance::with_limits(PEER_LIMIT_BYTES, limit);
            let first = ledger.register(owner(1, 7)).unwrap();
            let second = ledger.register(owner(2, 7)).unwrap();
            admit(&mut ledger, first, &keys, &[]);
            (ledger, first, second)
        };
        let before = filled(DAEMON_LIMIT_BYTES).0.daemon_usage().retained;
        // Growth charges every new array beside the old ones.
        let growth = SlotSpace::bytes_for(full + full / 2).unwrap();
        let (mut ledger, first, second) = filled(before + growth - 1);
        assert_eq!(ledger.slot_usage().capacity, full);
        assert_eq!(ledger.daemon_usage().retained, before);
        assert_running_charges(&ledger);
        let error = ledger
            .reserve_admission(second, [key(1_000_000)].into_iter(), &[])
            .unwrap_err();
        assert_eq!(error.cause, ExhaustionCause::DaemonLimit);
        assert_eq!(error.attempted_daemon_bytes, before + growth);
        assert_eq!(ledger.daemon_usage().retained, before);
        assert_eq!(ledger.slot_usage().capacity, full);
        assert_eq!(ledger.proof_keys(first).unwrap(), Some(keys.clone()));
        assert_running_charges(&ledger);
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
    fn capture_allocation_refusals_keep_exact_credit() {
        for allowed in 0..4 {
            let mut ledger = EvpnRecoveryProvenance::new();
            let handle = ledger.register(owner(1, 7)).unwrap();
            assert!(ledger.finish_recovery(handle).unwrap());
            assert!(ledger.begin_capture(handle).unwrap());
            ledger.fail_allocation_after_for_test(Some(allowed));
            let result = ledger.capture_key(handle, key(1));
            ledger.fail_allocation_after_for_test(None);
            assert_running_charges(&ledger);
            if allowed < 2 {
                // Slot growth, then the bitset, are the first two allocations.
                assert_eq!(
                    result.unwrap_err().cause,
                    ExhaustionCause::AllocationFailure
                );
            }
            assert!(ledger.retire_member(handle));
            assert_running_charges(&ledger);
            assert_eq!(
                ledger.daemon_usage().retained,
                size_of::<EvpnRecoveryProvenance>()
            );
        }
    }

    #[test]
    fn checked_overflow_fails_closed_without_allocation() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let handle = ledger.register(owner(1, 7)).unwrap();
        let before = ledger.daemon_usage().retained;
        let error = ledger
            .ensure_space(handle.owner.peer, usize::MAX, &mut |_| {})
            .unwrap_err();
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
    fn unordered_or_repeated_announcements_are_not_admitted() {
        for batch in [[key(2), key(1)], [key(1), key(1)]] {
            let mut ledger = EvpnRecoveryProvenance::new();
            let handle = ledger.register(owner(1, 7)).unwrap();
            assert_eq!(
                ledger
                    .reserve_admission(handle, batch.into_iter(), &[])
                    .unwrap_err()
                    .cause,
                ExhaustionCause::AdmissionInvariant
            );
            let handle = ledger.register(owner(2, 7)).unwrap();
            admit(&mut ledger, handle, &[key(1), key(2)], &[]);
            assert_eq!(
                ledger
                    .apply_admitted(handle, batch.into_iter(), &[])
                    .unwrap_err()
                    .cause,
                ExhaustionCause::AdmissionInvariant
            );
            assert_running_charges(&ledger);
        }
    }

    #[test]
    fn unknown_withdrawal_is_not_admitted() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let handle = ledger.register(owner(1, 7)).unwrap();
        let other = ledger.register(owner(2, 7)).unwrap();
        admit(&mut ledger, other, &[key(1)], &[]);
        // Another member's slot is not this member's admission.
        assert_eq!(
            ledger
                .apply_admitted(handle, [].into_iter(), &[key(1)])
                .unwrap_err()
                .cause,
            ExhaustionCause::AdmissionInvariant
        );
        assert_running_charges(&ledger);
    }

    #[test]
    fn duplicate_withdrawal_is_refused_before_any_bit_changes() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let handle = ledger.register(owner(1, 7)).unwrap();
        admit(&mut ledger, handle, &[key(1), key(2)], &[]);
        let error = ledger
            .apply_admitted(handle, [].into_iter(), &[key(2), key(1), key(1)])
            .unwrap_err();
        assert_eq!(error.cause, ExhaustionCause::AdmissionInvariant);
        assert_eq!(
            ledger.retained_keys_for_test(handle),
            Some([key(1), key(2)].to_vec())
        );
        assert_running_charges(&ledger);
    }

    #[test]
    fn final_preflight_rejects_unreserved_growth_without_growing_storage() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let handle = ledger.register(owner(1, 7)).unwrap();
        admit(&mut ledger, handle, &[key(1)], &[]);
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
            ledger.retained_keys_for_test(handle),
            Some([key(1)].to_vec())
        );
        assert_running_charges(&ledger);
    }

    /// Deterministic xorshift for the randomized controls.
    fn rng(seed: u64) -> impl FnMut(u64) -> u64 {
        let mut state = seed | 1;
        move |bound| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % bound
        }
    }

    #[test]
    fn slot_index_matches_a_model_through_backward_shift_deletion() {
        for seed in [1, 7, 42] {
            let mut next = rng(seed);
            let mut space = SlotSpace::default();
            space.resize(64, &mut |_| {}).unwrap();
            let mut model: HashMap<EvpnRouteKey, u32> = HashMap::new();
            for _ in 0..20_000 {
                let candidate = key(u32::try_from(next(96)).unwrap());
                if let Some(slot) = model.remove(&candidate) {
                    space.release(slot);
                } else if space.live() < 64 {
                    let slot = space.insert_new(space.bucket(&candidate), candidate);
                    space.hold(slot);
                    model.insert(candidate, slot);
                }
                for n in 0..96 {
                    assert_eq!(space.find(&key(n)), model.get(&key(n)).copied());
                }
            }
        }
    }

    /// A MAC/IP key whose MAC and IP bytes a peer chooses freely.
    fn mac_key(n: u64) -> EvpnRouteKey {
        let b = n.to_be_bytes();
        EvpnRouteKey::MacIp {
            rd: RouteDistinguisher([0, 0, 0xfd, 0xe8, 0, 0, 0, 1]),
            ethernet_tag: EthernetTagId(0),
            mac: MacAddress([b[2], b[3], b[4], b[5], b[6], b[7]]),
            ip: Some(IpAddr::V4(Ipv4Addr::new(10, b[5], b[6], b[7]))),
        }
    }

    /// Distinct keys whose unkeyed Fx hash, mixed and mapped as the first
    /// version of this index did, homes in the first 1/256 of any table.
    fn unkeyed_colliding_keys(count: usize) -> Vec<EvpnRouteKey> {
        use std::hash::BuildHasher;
        (0_u64..)
            .map(mac_key)
            .filter(|key| {
                crate::fast_hash::FastState::default()
                    .hash_one(key)
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                    >> 56
                    == 0
            })
            .take(count)
            .collect()
    }

    /// Keys a peer built to collide under the unkeyed index form one probe
    /// run, making every insert, rebuild, lookup and delete O(n). Keyed, the
    /// total probe work across two captures, every growth rebuild, lookups,
    /// withdrawals and both releases stays a small multiple of the keys.
    #[test]
    fn colliding_keys_cost_linear_index_work() {
        const KEYS: usize = 2048;
        let keys = unkeyed_colliding_keys(KEYS);
        let mut ledger = EvpnRecoveryProvenance::new();
        let first = ledger.register(owner(1, 7)).unwrap();
        let second = ledger.register(owner(2, 7)).unwrap();
        capture(&mut ledger, first, &keys);
        capture(&mut ledger, second, &keys);
        let proof = ledger.proof(second).unwrap().unwrap();
        assert!(keys.iter().all(|key| proof.contains(key)));
        admit(&mut ledger, first, &[], &keys);
        assert!(ledger.finish_recovery(first).unwrap());
        assert!(ledger.finish_recovery(second).unwrap());
        assert_eq!(ledger.slot_usage().live, 0);
        let probes = ledger
            .space
            .probes
            .load(std::sync::atomic::Ordering::Relaxed);
        // About ten index operations per key, each expected O(1).
        assert!(
            probes < 64 * KEYS as u64,
            "{probes} probe steps for {KEYS} keys"
        );
    }

    /// Six keys homed to the second-last bucket wrap past the table's end.
    /// Deleting the first shifts the whole run back, across the wrap.
    #[test]
    fn deletion_shifts_a_full_run_back_across_the_wrap() {
        let mut space = SlotSpace::default();
        space.resize(64, &mut |_| {}).unwrap();
        let buckets = space.index.len();
        let run: Vec<_> = (0_u32..)
            .map(key)
            .filter(|key| space.bucket(key) == buckets - 2)
            .take(6)
            .collect();
        let slots: Vec<_> = run
            .iter()
            .map(|key| {
                let slot = space.insert_new(space.bucket(key), *key);
                space.hold(slot);
                slot
            })
            .collect();
        let position = |space: &SlotSpace, slot: u32| {
            space
                .index
                .iter()
                .position(|entry| *entry == slot + 1)
                .unwrap()
        };
        assert_eq!(position(&space, slots[5]), 3, "the run wraps");
        space.release(slots[0]);
        assert!(
            space
                .wrapped_moves
                .load(std::sync::atomic::Ordering::Relaxed)
                >= 1
        );
        for (offset, slot) in slots[1..].iter().enumerate() {
            assert_eq!(
                position(&space, *slot),
                (buckets - 2 + offset) % buckets,
                "the whole run moved back one bucket"
            );
        }
        assert_eq!(space.find(&run[0]), None);
        assert!(
            run[1..]
                .iter()
                .zip(&slots[1..])
                .all(|(key, slot)| space.find(key) == Some(*slot))
        );
    }

    /// Random inserts and deletes of keys homed near the table's end match a
    /// model, moving entries across the wrap many times.
    #[test]
    fn index_matches_a_model_through_wrapping_deletions() {
        for seed in [1, 7, 42] {
            let mut next = rng(seed);
            let mut space = SlotSpace::default();
            space.resize(64, &mut |_| {}).unwrap();
            let buckets = space.index.len();
            let near_wrap: Vec<_> = (0_u32..)
                .map(key)
                .filter(|key| {
                    let bucket = space.bucket(key);
                    bucket + 6 >= buckets || bucket < 2
                })
                .take(96)
                .collect();
            let mut model = std::collections::HashMap::new();
            for _ in 0..20_000 {
                let candidate = near_wrap[usize::try_from(next(96)).unwrap()];
                if let Some(slot) = model.remove(&candidate) {
                    space.release(slot);
                } else if space.live() < 64 {
                    let slot = space.insert_new(space.bucket(&candidate), candidate);
                    space.hold(slot);
                    model.insert(candidate, slot);
                }
                for key in &near_wrap {
                    assert_eq!(space.find(key), model.get(key).copied());
                }
            }
            assert!(
                space
                    .wrapped_moves
                    .load(std::sync::atomic::Ordering::Relaxed)
                    > 100,
                "seed {seed}"
            );
        }
    }

    /// A record's cost follows its own keys, not the ledger's highest slot,
    /// and a drained peak gives its capacity back even while a slow holder
    /// keeps a slot at the top.
    #[test]
    fn skewed_peak_compacts_and_members_stay_proportional() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let peak = ledger.register(owner(1, 7)).unwrap();
        let slow = ledger.register(owner(2, 7)).unwrap();
        let spread = ledger.register(owner(3, 7)).unwrap();
        let big: Vec<_> = (0..10_000).map(key).collect();
        capture(&mut ledger, peak, &big);
        // The slow member holds the top slot; the spread member holds every
        // hundredth slot across the whole span.
        capture(&mut ledger, slow, &[key(9_999)]);
        let every: Vec<_> = (0..100).map(|n| key(n * 100)).collect();
        capture(&mut ledger, spread, &every);
        assert!(ledger.slot_usage().capacity >= 10_000);
        assert!(
            record(&ledger, spread).held.bytes() <= sparse_bytes(128),
            "100 keys over a 10,000-slot span stay sorted entries"
        );
        let peak_bytes = ledger.daemon_usage().retained;
        assert!(ledger.finish_recovery(peak).unwrap());
        // 101 live slots of 10,000: renumbered into a prefix and shrunk.
        assert_eq!(ledger.slot_usage().live, 101);
        assert_eq!(ledger.space.keys.len(), 101);
        assert!(ledger.slot_usage().capacity <= 256);
        assert!(ledger.daemon_usage().retained < peak_bytes / 20);
        assert_eq!(ledger.proof_keys(slow).unwrap().unwrap(), [key(9_999)]);
        assert_eq!(ledger.proof_keys(spread).unwrap().unwrap(), every);
        assert_running_charges(&ledger);
        // Fresh members take the low free slots and stay proportional.
        for member in 0..20_u16 {
            let handle = ledger.register(owner_wide(100 + member, 7)).unwrap();
            let own: Vec<_> = (0..100)
                .map(|n| key(100_000 + u32::from(member) * 100 + n))
                .collect();
            capture(&mut ledger, handle, &own);
            assert!(record(&ledger, handle).held.bytes() <= sparse_bytes(128));
        }
        assert!(ledger.slot_usage().capacity <= 4 * ledger.slot_usage().live);
        assert_running_charges(&ledger);
    }

    /// New keys pinned above a dense record's bitset must be covered before
    /// application sets their bits.
    #[test]
    fn reservation_sizes_a_dense_record_for_pins_above_its_bitset() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let wide = ledger.register(owner(1, 7)).unwrap();
        let dense = ledger.register(owner(2, 7)).unwrap();
        let table: Vec<_> = (0..2_000).map(key).collect();
        capture(&mut ledger, wide, &table);
        capture(&mut ledger, dense, &table[..200]);
        assert!(matches!(record(&ledger, dense).held, Held::Dense(_)));
        let fresh: Vec<_> = (5_000..5_008).map(key).collect();
        admit(&mut ledger, dense, &fresh, &[]);
        let mut expected = table[..200].to_vec();
        expected.extend_from_slice(&fresh);
        expected.sort_unstable();
        assert_eq!(ledger.proof_keys(dense).unwrap().unwrap(), expected);
        assert_running_charges(&ledger);
    }

    /// A reservation that never reaches application gives back its pins at
    /// finish and at retirement.
    #[test]
    fn unapplied_reservations_release_pins_at_finish_and_retirement() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let finished = ledger.register(owner(1, 7)).unwrap();
        let retired = ledger.register(owner(2, 7)).unwrap();
        admit(&mut ledger, finished, &[key(1)], &[]);
        for handle in [finished, retired] {
            assert!(
                ledger
                    .reserve_admission(handle, [key(2), key(3)].into_iter(), &[])
                    .unwrap()
            );
        }
        assert_eq!(ledger.slot_usage().live, 3);
        assert_running_charges(&ledger);
        assert!(ledger.finish_recovery(finished).unwrap());
        assert_eq!(
            ledger.slot_usage().live,
            2,
            "the retired member still pins two"
        );
        assert_running_charges(&ledger);
        assert!(ledger.retire_member(retired));
        assert_eq!(ledger.slot_usage().live, 0);
        assert_running_charges(&ledger);
    }

    /// The default peer cap admits a member holding the 262,144 keys the
    /// earlier charge allowed: capture, sealing and a later admission.
    #[test]
    fn default_peer_cap_admits_the_earlier_ceiling() {
        const CEILING: u32 = 262_144;
        let mut ledger = EvpnRecoveryProvenance::new();
        let handle = ledger.register(owner(1, 7)).unwrap();
        assert!(ledger.finish_recovery(handle).unwrap());
        assert!(ledger.begin_capture(handle).unwrap());
        for n in 0..CEILING {
            assert!(ledger.capture_key(handle, key(n)).unwrap(), "key {n}");
        }
        assert!(ledger.seal_capture(handle).unwrap());
        assert_eq!(
            ledger.proof(handle).unwrap().unwrap().len(),
            CEILING as usize
        );
        admit(&mut ledger, handle, &[key(CEILING)], &[key(0)]);
        assert!(ledger.peer_usage(handle.owner.peer).peak <= PEER_LIMIT_BYTES);
        assert_running_charges(&ledger);
    }

    /// Guarantee 1: a key and its mapping outlive churn, other members'
    /// release and slot reuse until every record naming the slot releases it.
    #[test]
    fn mapping_and_key_bytes_survive_until_every_holder_releases() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let slow = ledger.register(owner(1, 7)).unwrap();
        let fast = ledger.register(owner(2, 7)).unwrap();
        let table: Vec<_> = (0..256).map(key).collect();
        capture(&mut ledger, slow, &table);
        capture(&mut ledger, fast, &table);
        let snapshot = ledger.snapshot(slow).unwrap().unwrap();
        // The fast member follows 32 rounds of full-table churn and settles.
        let mut current = table.clone();
        for round in 1..=32_u32 {
            let next: Vec<_> = (0..256).map(|n| key(round * 1000 + n)).collect();
            admit(&mut ledger, fast, &next, &current);
            current = next;
        }
        assert!(ledger.finish_recovery(fast).unwrap());
        assert_running_charges(&ledger);
        // Every table key still resolves to its own bytes for both holders.
        let held = ledger.proof_keys(slow).unwrap().unwrap();
        assert_eq!(held, table);
        assert_eq!(ledger.proof_keys(snapshot).unwrap().unwrap(), table);
        assert!(
            current
                .iter()
                .all(|key| !ledger.proof(slow).unwrap().unwrap().contains(key))
        );
        assert_eq!(ledger.slot_usage().live, 256);
        // The primary releases; the snapshot alone keeps the mapping.
        assert!(ledger.finish_recovery(slow).unwrap());
        assert_eq!(ledger.proof_keys(snapshot).unwrap().unwrap(), table);
        assert_eq!(ledger.slot_usage().live, 256);
        assert!(ledger.retire(snapshot));
        assert_eq!(ledger.slot_usage().live, 0);
        assert!(table.iter().all(|key| ledger.space.find(key).is_none()));
        assert_running_charges(&ledger);
    }

    /// Guarantee 2: last-in first-out reuse is the most aggressive policy;
    /// a slot still named by a bit, a snapshot bit or a pin is never handed
    /// to another key.
    #[test]
    fn freed_slots_are_reused_only_after_every_bit_snapshot_and_pin_releases() {
        let mut ledger = EvpnRecoveryProvenance::new();
        let a = ledger.register(owner(1, 7)).unwrap();
        let b = ledger.register(owner(2, 7)).unwrap();
        let c = ledger.register(owner(3, 7)).unwrap();
        admit(&mut ledger, a, &[key(1), key(2)], &[]);
        admit(&mut ledger, b, &[key(1)], &[]);
        let snapshot = ledger.snapshot(b).unwrap().unwrap();
        let slot = ledger.space.find(&key(1)).unwrap();
        // A withdraws: B and B's snapshot still hold the slot.
        admit(&mut ledger, a, &[], &[key(1)]);
        admit(&mut ledger, c, &[key(100)], &[]);
        assert_ne!(ledger.space.find(&key(100)), Some(slot));
        // B withdraws: the snapshot alone holds it.
        admit(&mut ledger, b, &[], &[key(1)]);
        admit(&mut ledger, c, &[key(101)], &[]);
        assert_ne!(ledger.space.find(&key(101)), Some(slot));
        // A reservation pin holds a slot no bit names yet.
        assert!(
            ledger
                .reserve_admission(a, [key(1)].into_iter(), &[])
                .unwrap()
        );
        assert!(ledger.retire(snapshot));
        admit(&mut ledger, c, &[key(102)], &[]);
        assert_ne!(ledger.space.find(&key(102)), Some(slot));
        // Final gates dropped A's announcement: the pin was the last holder.
        assert!(ledger.apply_admitted(a, [].into_iter(), &[]).unwrap());
        assert_eq!(ledger.space.find(&key(1)), None);
        admit(&mut ledger, c, &[key(103)], &[]);
        assert_eq!(ledger.space.find(&key(103)), Some(slot), "LIFO reuse");
        // Nobody who held the old key sees the new one.
        for (handle, expected) in [
            (a, vec![key(2)]),
            (b, vec![]),
            (c, vec![key(100), key(101), key(102), key(103)]),
        ] {
            assert_eq!(ledger.proof_keys(handle).unwrap().unwrap(), expected);
        }
        assert!(!ledger.proof(b).unwrap().unwrap().contains(&key(103)));
        assert_running_charges(&ledger);
    }

    /// Guarantee 3: members churn through capture, admission and release
    /// while a slow member and its snapshot keep the first table. Accounting
    /// stays exact at every step and freed slots bound the space.
    #[test]
    fn sustained_churn_with_a_slow_peer_keeps_exact_bounded_accounting() {
        const MEMBERS: u16 = 24;
        const TABLE: u32 = 400;
        const CHURN: u32 = 40;
        const ROUNDS: u32 = 300;
        // 64, 96, ..., 729, 1093: the first capacity above 2 * TABLE + 4 * CHURN.
        const CAPACITY_BOUND: usize = 1093;
        let mut next = rng(0x5eed);
        let mut ledger = EvpnRecoveryProvenance::new();
        let mut table: Vec<_> = (0..TABLE).map(key).collect();
        let slow = ledger.register(owner_wide(0, 1)).unwrap();
        capture(&mut ledger, slow, &table);
        let snapshot = ledger.snapshot(slow).unwrap().unwrap();
        let members: Vec<_> = (1..MEMBERS)
            .map(|n| ledger.register(owner_wide(n, 1)).unwrap())
            .collect();
        let mut age = vec![None; members.len()];
        let mut fresh = TABLE;
        let peak_bound = size_of::<EvpnRecoveryProvenance>()
            + 32 * size_of::<Record>()
            + 2 * CAPACITY_BOUND * SLOT_BYTES
            + 32 * (32 * size_of::<u64>() + 64 * size_of::<u32>());
        for round in 0..ROUNDS {
            // Replace CHURN random table keys with new keys.
            let mut positions = BTreeSet::new();
            let mut withdrawn = Vec::new();
            let mut announced = Vec::new();
            for _ in 0..CHURN {
                let position = usize::try_from(next(u64::from(TABLE))).unwrap();
                if !positions.insert(position) {
                    continue;
                }
                withdrawn.push(table[position]);
                table[position] = key(fresh);
                announced.push(key(fresh));
                fresh += 1;
            }
            for (member, age) in members.iter().zip(age.iter_mut()) {
                match *age {
                    None if next(4) == 0 => {
                        if !ledger.is_dormant(*member) {
                            assert!(ledger.finish_recovery(*member).unwrap());
                        }
                        assert!(ledger.begin_capture(*member).unwrap());
                        for &key in &table {
                            assert!(ledger.capture_key(*member, key).unwrap());
                        }
                        assert!(ledger.seal_capture(*member).unwrap());
                        *age = Some(0);
                    }
                    Some(rounds) if rounds >= 3 => {
                        assert!(ledger.finish_recovery(*member).unwrap());
                        *age = None;
                    }
                    Some(rounds) => {
                        admit(&mut ledger, *member, &announced, &withdrawn);
                        *age = Some(rounds + 1);
                    }
                    None => {}
                }
            }
            assert_running_charges(&ledger);
            let usage = ledger.slot_usage();
            // The slow copy, the current table and the last few rounds'
            // replacements: never the whole churn history.
            assert!(
                usage.live <= 2 * TABLE as usize + 4 * CHURN as usize,
                "round {round}: {usage:?}"
            );
            assert!(
                ledger.space.keys.len() <= 2 * TABLE as usize + 4 * CHURN as usize,
                "round {round}: {usage:?}"
            );
            // Slot capacity never passes the first growth step above the
            // live bound, so the whole ledger stays under a fixed ceiling.
            assert!(usage.capacity <= CAPACITY_BOUND, "round {round}: {usage:?}");
            assert!(ledger.daemon_usage().peak <= peak_bound, "round {round}");
        }
        assert_eq!(
            ledger.proof_keys(snapshot).unwrap().unwrap().len(),
            TABLE as usize
        );
        for member in members {
            assert!(ledger.retire_member(member));
        }
        assert!(ledger.retire_member(slow));
        assert_running_charges(&ledger);
        assert_eq!(
            ledger.daemon_usage().retained,
            size_of::<EvpnRecoveryProvenance>()
        );
    }

    /// Ten times the measured mass-dirty receiver count against the same
    /// table shape. A third of the members never admit after capture and
    /// keep the keys they captured, so the slot space carries every churned
    /// version. Run with `--release --ignored --nocapture`.
    #[test]
    #[ignore = "probe: run with --release --ignored --nocapture"]
    fn probe_ten_times_receivers_keeps_five_times_headroom() {
        const MEMBERS: u16 = 1500;
        const TABLE: u32 = 75_000;
        const STEPS: u32 = 28;
        const CHURN: u32 = 1000;
        let mut ledger = EvpnRecoveryProvenance::new();
        let mut table: Vec<_> = (0..TABLE).map(key).collect();
        let members: Vec<_> = (0..MEMBERS)
            .map(|n| ledger.register(owner_wide(n, 1)).unwrap())
            .collect();
        let mut next_member = 0;
        let started = std::time::Instant::now();
        for step in 0..=STEPS {
            let captured = usize::from(MEMBERS) * (step as usize + 1) / (STEPS as usize + 1);
            while next_member < captured {
                let handle = members[next_member];
                assert!(ledger.finish_recovery(handle).unwrap());
                assert!(ledger.begin_capture(handle).unwrap());
                for &key in &table {
                    assert!(ledger.capture_key(handle, key).unwrap());
                }
                assert!(ledger.seal_capture(handle).unwrap());
                next_member += 1;
            }
            if step == STEPS {
                break;
            }
            let start = (step * CHURN) as usize;
            let withdrawn = table[start..start + CHURN as usize].to_vec();
            let announced: Vec<_> = (0..CHURN).map(|n| key(TABLE + step * CHURN + n)).collect();
            table[start..start + CHURN as usize].copy_from_slice(&announced);
            for (n, &handle) in members[..next_member].iter().enumerate() {
                if n % 3 != 0 {
                    admit(&mut ledger, handle, &announced, &withdrawn);
                }
            }
        }
        let peak = ledger.daemon_usage().peak;
        let usage = ledger.slot_usage();
        let bar = DAEMON_LIMIT_BYTES * 8 / 10;
        println!(
            "members={MEMBERS} table={TABLE} churned={} live_slots={} high_water={} capacity={} \
             daemon_retained={} daemon_peak={peak} max_peer={} bar={bar} headroom_percent={} elapsed={:?}",
            STEPS * CHURN,
            usage.live,
            ledger.space.keys.len(),
            usage.capacity,
            ledger.daemon_usage().retained,
            members
                .iter()
                .map(|handle| ledger.peer_usage(handle.owner.peer).peak)
                .max()
                .unwrap(),
            bar * 100 / peak,
            started.elapsed(),
        );
        assert!(
            peak * 5 <= bar,
            "peak {peak} lacks 5x headroom against {bar}"
        );
        for handle in members {
            assert!(ledger.retire_member(handle));
        }
        assert_eq!(
            ledger.daemon_usage().retained,
            size_of::<EvpnRecoveryProvenance>()
        );
    }

    /// Component timing, not a contract: one member's capture of a churned
    /// 75k-key projection in hash order, then a 20k-key replay admission
    /// (half already admitted, half new) with its membership probes. The
    /// matching probe on the universe ledger drives its production sequence.
    /// Run with `--release --ignored --nocapture`.
    #[test]
    #[ignore = "probe: run with --release --ignored --nocapture"]
    fn probe_capture_and_replay_cost() {
        const TABLE: u32 = 75_000;
        const CHURN: u32 = 20_000;
        const REPLAY: u32 = 20_000;
        let mut capture_ns = Vec::new();
        let mut replay_ns = Vec::new();
        let mut refresh_ns = Vec::new();
        for round in 0..7 {
            let mut ledger = EvpnRecoveryProvenance::new();
            let anchor = ledger.register(owner(1, 1)).unwrap();
            let target = ledger.register(owner(2, 1)).unwrap();
            let table: Vec<_> = (0..TABLE).map(key).collect();
            capture(&mut ledger, anchor, &table);
            // The table churned after the anchor captured it.
            let mut current: Vec<_> = (CHURN..TABLE + CHURN).map(key).collect();
            let mut next = rng(0x9e37 + round);
            for index in (1..current.len()).rev() {
                let other = usize::try_from(next(index as u64 + 1)).unwrap();
                current.swap(index, other);
            }
            let started = std::time::Instant::now();
            assert!(ledger.finish_recovery(target).unwrap());
            assert!(ledger.begin_capture(target).unwrap());
            for &key in &current {
                assert!(
                    ledger
                        .capture_key_with_checkpoint(target, key, &mut |_| {})
                        .unwrap()
                );
            }
            assert!(ledger.seal_capture(target).unwrap());
            capture_ns.push(started.elapsed().as_nanos());
            // A refresh replay re-announces admitted rows: the 4a shape.
            let refreshed: Vec<_> = (CHURN..CHURN + REPLAY).map(key).collect();
            let started = std::time::Instant::now();
            let proof = ledger.proof(target).unwrap().unwrap();
            assert!(refreshed.iter().all(|key| proof.contains(key)));
            assert!(refreshed.iter().all(|key| proof.contains(key)));
            assert!(
                ledger
                    .reserve_admission(target, refreshed.iter().copied(), &[])
                    .unwrap()
            );
            assert!(
                ledger
                    .preflight_admitted(target, refreshed.iter().copied(), &[])
                    .unwrap()
            );
            assert!(
                ledger
                    .apply_admitted(target, refreshed.iter().copied(), &[])
                    .unwrap()
            );
            refresh_ns.push(started.elapsed().as_nanos());
            let announcements: Vec<_> = (TABLE + CHURN - REPLAY / 2..TABLE + CHURN + REPLAY / 2)
                .map(key)
                .collect();
            let started = std::time::Instant::now();
            let proof = ledger.proof(target).unwrap().unwrap();
            let admitted = announcements
                .iter()
                .filter(|key| proof.contains(key))
                .count();
            assert_eq!(admitted, REPLAY as usize / 2);
            assert!(
                ledger
                    .reserve_admission(target, announcements.iter().copied(), &[])
                    .unwrap()
            );
            assert!(
                ledger
                    .preflight_admitted(target, announcements.iter().copied(), &[])
                    .unwrap()
            );
            assert!(
                ledger
                    .apply_admitted(target, announcements.iter().copied(), &[])
                    .unwrap()
            );
            replay_ns.push(started.elapsed().as_nanos());
            assert_eq!(
                ledger.proof(target).unwrap().unwrap().len(),
                (TABLE + REPLAY / 2) as usize
            );
        }
        capture_ns.sort_unstable();
        replay_ns.sort_unstable();
        refresh_ns.sort_unstable();
        println!(
            "dense capture_median_us={} refresh_median_us={} mixed_replay_median_us={} capture_us={:?} refresh_us={:?} mixed_us={:?}",
            capture_ns[3] / 1000,
            refresh_ns[3] / 1000,
            replay_ns[3] / 1000,
            capture_ns.iter().map(|ns| ns / 1000).collect::<Vec<_>>(),
            refresh_ns.iter().map(|ns| ns / 1000).collect::<Vec<_>>(),
            replay_ns.iter().map(|ns| ns / 1000).collect::<Vec<_>>(),
        );
    }
}
