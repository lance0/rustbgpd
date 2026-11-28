//! Bounded, actor-owned unicast/VPN recovery proofs.
//!
//! Credits cover owned headers and exact requested capacities, including the
//! full old/new overlap during growth. Allocator overhead and RSS need their
//! separate qualification receipt; a failed proof uses the actor's fallback.

use crate::PeerId;
use std::cmp::Ordering;
use std::mem::size_of;

use rustbgpd_wire::{Prefix, VpnPrefix, VpnRouteKey};
use smallvec::SmallVec;

use crate::adj_rib_out::{AdjRibOut, VpnKeyVersion};
use crate::fast_hash::FastState;
use crate::route::{Route, VpnRibRoute, VpnRibRouteKey};
use crate::update::ExactExportKey;

pub(in crate::manager) const PEER_LIMIT_BYTES: usize = 64 * 1024 * 1024;
pub(in crate::manager) const DAEMON_LIMIT_BYTES: usize = 512 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::manager) enum Key {
    Unicast(Prefix, u32),
    Vpn(VpnRouteKey, u32),
}

/// The derived order (variant, then fields), with both arms comparing
/// addresses and RDs as integers instead of bytewise. Proof lookups binary
/// search on this comparison once per admitted key.
impl Ord for Key {
    fn cmp(&self, other: &Self) -> Ordering {
        count_comparison();
        match (self, other) {
            (Self::Unicast(left, left_id), Self::Unicast(right, right_id)) => {
                prefix_cmp(left, right).then(left_id.cmp(right_id))
            }
            (Self::Vpn(left, left_id), Self::Vpn(right, right_id)) => {
                vpn_key_cmp(left, right).then(left_id.cmp(right_id))
            }
            (Self::Unicast(..), Self::Vpn(..)) => Ordering::Less,
            (Self::Vpn(..), Self::Unicast(..)) => Ordering::Greater,
        }
    }
}

impl PartialOrd for Key {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// `Prefix::cmp`: big-endian integer order equals octet order, and `V4`
/// sorts before `V6`.
#[inline]
fn prefix_cmp(left: &Prefix, right: &Prefix) -> Ordering {
    match (left, right) {
        (Prefix::V4(left), Prefix::V4(right)) => {
            (left.addr.to_bits(), left.len).cmp(&(right.addr.to_bits(), right.len))
        }
        (Prefix::V6(left), Prefix::V6(right)) => {
            (left.addr.to_bits(), left.len).cmp(&(right.addr.to_bits(), right.len))
        }
        (Prefix::V4(_), Prefix::V6(_)) => Ordering::Less,
        (Prefix::V6(_), Prefix::V4(_)) => Ordering::Greater,
    }
}

/// `VpnRouteKey::cmp`: big-endian integer order equals bytewise RD and
/// octet order, and `V4` sorts before `V6`.
#[inline]
fn vpn_key_cmp(left: &VpnRouteKey, right: &VpnRouteKey) -> Ordering {
    u64::from_be_bytes(left.route_distinguisher.0)
        .cmp(&u64::from_be_bytes(right.route_distinguisher.0))
        .then_with(|| match (left.prefix, right.prefix) {
            (
                VpnPrefix::V4 { addr, len },
                VpnPrefix::V4 {
                    addr: right_addr,
                    len: right_len,
                },
            ) => (addr.to_bits(), len).cmp(&(right_addr.to_bits(), right_len)),
            (
                VpnPrefix::V6 { addr, len },
                VpnPrefix::V6 {
                    addr: right_addr,
                    len: right_len,
                },
            ) => (addr.to_bits(), len).cmp(&(right_addr.to_bits(), right_len)),
            (VpnPrefix::V4 { .. }, VpnPrefix::V6 { .. }) => Ordering::Less,
            (VpnPrefix::V6 { .. }, VpnPrefix::V4 { .. }) => Ordering::Greater,
        })
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

/// Where a new initial replay's proof fits in the ledger's budgets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::manager) enum ReplayRoom {
    Fits,
    AfterReplays,
    Never,
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
    pub(in crate::manager) limiting_peer: Option<PeerId>,
    pub(in crate::manager) attempted_peer_bytes: usize,
    pub(in crate::manager) attempted_daemon_bytes: usize,
}

/// Whether a refused reservation can still send using conservative withdrawals.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(in crate::manager) enum OnReservationRefusal {
    #[default]
    ContinueWithFallback,
    StopBeforeSend,
}

type Keys = SmallVec<[Key; 0]>;
type Records = SmallVec<[Record; 0]>;

#[derive(Debug)]
#[cfg_attr(test, derive(Clone, PartialEq, Eq))]
pub(in crate::manager) struct AdmittedKeys(Keys);

/// Immutable pool identity; never reused even after its storage is released.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::manager) struct SnapshotHandle(u64);

#[cfg(any(test, feature = "bench-internals"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::manager) enum FullCaptureStrategy {
    Indexed,
    Flat,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::manager) enum FullCaptureFallback {
    SharingDisabled,
    MissingIndex,
    SlotChurn,
    Representation,
    ShareRefused,
}

#[derive(Clone, Copy, Debug)]
pub(in crate::manager) struct FullCaptureShape {
    pub(in crate::manager) count: usize,
    pub(in crate::manager) additions: usize,
    /// Capped at budget + 1: classification stops after selecting flat capture.
    pub(in crate::manager) mismatches: usize,
    pub(in crate::manager) comparisons: usize,
    pub(in crate::manager) fallback: Option<FullCaptureFallback>,
    /// Projected VPN rows; all of them are pool keys when the pool is current.
    pub(in crate::manager) vpn: usize,
    /// Every projected VPN key was its row's own key.
    pub(in crate::manager) vpn_identity: bool,
}

#[derive(Clone, Copy, Debug)]
pub(in crate::manager) struct FullCaptureOutcome {
    #[cfg(any(test, feature = "bench-internals"))]
    pub(in crate::manager) keys: usize,
    pub(in crate::manager) handle: Option<SnapshotHandle>,
    #[cfg(any(test, feature = "bench-internals"))]
    pub(in crate::manager) strategy: FullCaptureStrategy,
    #[cfg(any(test, feature = "bench-internals"))]
    pub(in crate::manager) fallback: Option<FullCaptureFallback>,
    #[cfg(any(test, feature = "bench-internals"))]
    pub(in crate::manager) mismatches: usize,
}

/// A cohort capture's members, each in exactly one list.
#[derive(Debug)]
pub(in crate::manager) struct CohortCapture {
    /// The pool every shared member references.
    pub(in crate::manager) handle: Option<SnapshotHandle>,
    /// Populated and still `Capturing`: the caller seals each.
    pub(in crate::manager) shared: Vec<PeerId>,
    /// Still `Capturing` and empty: the caller captures each on its own.
    pub(in crate::manager) individual: Vec<PeerId>,
    /// Failed; the caller records each refusal.
    pub(in crate::manager) failed: Vec<(PeerId, Failure)>,
}

type Words = SmallVec<[u64; 0]>;
type Snapshots = SmallVec<[Snapshot; 0]>;
type SlotPositions = SmallVec<[u32; 0]>;
const EMPTY_SLOT: u32 = u32::MAX;
// Each projection permits at most this many exact fallback searches. A successful
// two-pass capture can therefore perform twice this number under bounded churn.
const SLOT_MISMATCH_BUDGET: usize = 4_096;

#[derive(Debug)]
#[cfg_attr(test, derive(Clone, PartialEq, Eq))]
struct Snapshot {
    handle: SnapshotHandle,
    references: usize,
    keys: Keys,
    /// Unicast slab slot -> key position for `..vpn_base`, then open-addressed
    /// VPN key buckets: VPN rows have no slab slot to index. An initial
    /// replay's universe (`keyed`) buckets every key from `vpn_base` zero.
    slot_positions: SlotPositions,
    vpn_base: usize,
    /// The table's VPN key set this indexed pool was built from.
    vpn_keys: Option<VpnKeyVersion>,
    indexed: bool,
    keyed: bool,
}

/// A pool's VPN positions plus every VPN key change its source table made
/// since the pool was built; empty when the pool is exactly current.
type VpnChanges<'t> = (std::ops::Range<usize>, &'t [(VpnRibRouteKey, bool)]);

impl Snapshot {
    fn vpn_changes<'t>(&self, table: &'t AdjRibOut) -> Option<VpnChanges<'t>> {
        let changes = table.vpn_key_changes_since(self.vpn_keys?)?;
        let start = self
            .keys
            .partition_point(|key| matches!(key, Key::Unicast(..)));
        Some((start..self.keys.len(), changes))
    }
}

impl Snapshot {
    fn charge(&self) -> usize {
        size_of::<Self>()
            + self.keys.capacity() * size_of::<Key>()
            + self.slot_positions.capacity() * size_of::<u32>()
    }

    /// The keys a member's mask spans. A replay universe fills in pages, so
    /// its members' masks span its whole capacity from the start.
    fn mask_keys(&self) -> usize {
        if self.keyed {
            self.keys.capacity()
        } else {
            self.keys.len()
        }
    }

    /// The key buckets of a keyed universe; empty for any other pool.
    fn key_index(&self) -> &[u32] {
        if self.keyed {
            &self.slot_positions
        } else {
            &[]
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Ordered comparisons plus bucket probes of proof keys on this thread.
    pub(in crate::manager) static KEY_COMPARISONS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

#[inline]
fn count_comparison() {
    #[cfg(test)]
    KEY_COMPARISONS.with(|count| count.set(count.get() + 1));
}

/// Run a test-only cross-check without charging its lookups to
/// [`KEY_COMPARISONS`].
#[cfg(test)]
pub(in crate::manager) fn uncounted(check: impl FnOnce()) {
    let before = KEY_COMPARISONS.with(std::cell::Cell::get);
    check();
    KEY_COMPARISONS.with(|count| count.set(before));
}

/// Open-addressed buckets for `count` keys: at most two-thirds full and
/// never full, so every probe ends.
fn key_index_len(count: usize) -> usize {
    count.saturating_add(count / 2).saturating_add(1)
}

fn key_bucket(key: &Key, buckets: usize) -> usize {
    use std::hash::BuildHasher;

    match key {
        Key::Vpn(vpn, path_id) => AdmittedRecovery::vpn_bucket(vpn, *path_id, buckets),
        Key::Unicast(prefix, path_id) => {
            let hash = FastState::default().hash_one((prefix, path_id));
            usize::try_from(hash % buckets as u64).expect("bucket is below a usize length")
        }
    }
}

/// Record a universe key at `position`; the buckets are never full.
fn index_key(index: &mut [u32], key: &Key, position: u32) {
    let mut bucket = key_bucket(key, index.len());
    while index[bucket] != EMPTY_SLOT {
        bucket = (bucket + 1) % index.len();
    }
    index[bucket] = position;
}

/// The position of `key` in `universe`: a bucket probe where the universe
/// carries a key index, else a binary search.
fn universe_position(universe: &[Key], index: &[u32], key: &Key) -> Option<usize> {
    if index.is_empty() {
        return universe.binary_search(key).ok();
    }
    let mut bucket = key_bucket(key, index.len());
    loop {
        let position = index[bucket];
        if position == EMPTY_SLOT {
            return None;
        }
        count_comparison();
        if universe.get(position as usize) == Some(key) {
            return Some(position as usize);
        }
        bucket = (bucket + 1) % index.len();
    }
}

/// A borrowed exact set. Only mask bits and sparse keys prove admission;
/// membership in the raw immutable key universe never does.
#[derive(Clone, Copy, Debug)]
pub(in crate::manager) struct AdmittedKeyView<'a> {
    universe: &'a [Key],
    /// The universe's key buckets; empty where lookups binary search.
    index: &'a [u32],
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
        universe_position(self.universe, self.index, &key).is_some_and(|index| {
            self.words
                .get(index / 64)
                .is_some_and(|word| word & (1_u64 << (index % 64)) != 0)
        }) || self.sparse.binary_search(&key).is_ok()
    }

    pub(in crate::manager) fn contains(self, key: &ExactExportKey) -> bool {
        Key::try_from(key).is_ok_and(|key| self.contains_key(key))
    }

    /// How many of these unicast keys at path ID zero are admitted, given
    /// each key's position in this view's universe as
    /// [`AdmittedRecovery::replay_universe_positions`] resolved it. A
    /// universe key is admitted by its mask bit alone; any other key by the
    /// sparse overlay.
    pub(in crate::manager) fn admitted_unicast(
        self,
        rows: impl Iterator<Item = (u32, Prefix)>,
    ) -> usize {
        rows.filter(|&(position, prefix)| self.admitted_at(position, prefix))
            .count()
    }

    fn admitted_at(self, position: u32, prefix: Prefix) -> bool {
        if position == EMPTY_SLOT {
            !self.sparse.is_empty() && self.sparse.binary_search(&Key::Unicast(prefix, 0)).is_ok()
        } else {
            let index = position as usize;
            self.words
                .get(index / 64)
                .is_some_and(|word| word & (1_u64 << (index % 64)) != 0)
        }
    }

    /// The position of `prefix`, at path ID zero, in this view's universe
    /// (the empty marker where the universe lacks it), and whether the key
    /// is admitted: one lookup serves the admission test and the commit of
    /// the key's row.
    pub(in crate::manager) fn locate_unicast(self, prefix: Prefix) -> (u32, bool) {
        let position = universe_position(self.universe, self.index, &Key::Unicast(prefix, 0))
            .and_then(|position| u32::try_from(position).ok())
            .unwrap_or(EMPTY_SLOT);
        (position, self.admitted_at(position, prefix))
    }

    /// Visit one prefix's admitted path IDs without walking unrelated keys.
    pub(in crate::manager) fn visit_unicast_prefix_paths(
        self,
        prefix: Prefix,
        checkpoint: &mut impl FnMut(bool),
        visit: &mut impl FnMut(u32),
    ) {
        let lower = Key::Unicast(prefix, 0);
        // Path ID zero is the prefix's lowest key: where the universe holds
        // it, its bucket names the lower bound.
        let begin = (!self.index.is_empty())
            .then(|| universe_position(self.universe, self.index, &lower))
            .flatten()
            .unwrap_or_else(|| {
                self.universe.partition_point(|key| {
                    checkpoint(false);
                    *key < lower
                })
            });
        for (index, key) in self.universe.iter().enumerate().skip(begin) {
            checkpoint(false);
            let Key::Unicast(key_prefix, path_id) = key else {
                break;
            };
            if *key_prefix != prefix {
                break;
            }
            if self.words[index / 64] & (1_u64 << (index % 64)) != 0 {
                visit(*path_id);
            }
        }
        let begin = self.sparse.partition_point(|key| {
            checkpoint(false);
            *key < lower
        });
        for key in &self.sparse[begin..] {
            checkpoint(false);
            let Key::Unicast(key_prefix, path_id) = key else {
                break;
            };
            if *key_prefix != prefix {
                break;
            }
            visit(*path_id);
        }
    }

    /// Up to `visits` positions of an initial replay's proof after `after`,
    /// in key order: the admitted keys among them, the last key
    /// visited (`None` once the sweep reached the end) and the positions
    /// visited. Its universe and sparse overlay are sorted and disjoint.
    pub(in crate::manager) fn sweep_unicast(
        self,
        after: Option<Key>,
        visits: usize,
    ) -> (Vec<Key>, Option<Key>, usize) {
        let start =
            |keys: &[Key]| after.map_or(0, |after| keys.partition_point(|key| *key <= after));
        let (mut base, mut sparse) = (start(self.universe), start(self.sparse));
        let mut admitted = Vec::new();
        let mut last = None;
        for visited in 0..visits {
            let (key, admit) = match (self.universe.get(base), self.sparse.get(sparse)) {
                (None, None) => return (admitted, None, visited),
                (Some(&key), next) if next.is_none_or(|next| key < *next) => {
                    let index = base;
                    base += 1;
                    (key, self.words[index / 64] & (1_u64 << (index % 64)) != 0)
                }
                (_, next) => {
                    sparse += 1;
                    (*next.expect("the sparse key sorts first"), true)
                }
            };
            if admit {
                admitted.push(key);
            }
            last = Some(key);
        }
        let done = base == self.universe.len() && sparse == self.sparse.len();
        (admitted, if done { None } else { last }, visits)
    }

    pub(in crate::manager) fn unicast_prefix_paths(
        self,
        prefix: Prefix,
        checkpoint: &mut impl FnMut(bool),
    ) -> usize {
        let mut count = 0;
        self.visit_unicast_prefix_paths(prefix, checkpoint, &mut |_| count += 1);
        count
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
            index: &[],
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
    peer: PeerId,
    state: State,
    initial_replay: bool,
    keys: AdmittedKeys,
    snapshot: Option<SnapshotHandle>,
    words: Words,
    masked: usize,
}

impl Record {
    fn entries(&self) -> usize {
        self.masked + self.keys.0.len()
    }

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
    /// Sparse keys plus set mask bits across capturing and sealed records.
    entries: usize,
    used: usize,
    peak: usize,
    peer_limit: usize,
    daemon_limit: usize,
    #[cfg(test)]
    fail_next_allocation: bool,
    #[cfg(test)]
    allocation_countdown: Option<usize>,
    #[cfg(test)]
    optional_share_attempts: usize,
    #[cfg(test)]
    optional_share_refusals: usize,
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
            entries: 0,
            used: size_of::<Self>(),
            peak: size_of::<Self>(),
            peer_limit,
            daemon_limit,
            #[cfg(test)]
            fail_next_allocation: false,
            #[cfg(test)]
            allocation_countdown: None,
            #[cfg(test)]
            optional_share_attempts: 0,
            #[cfg(test)]
            optional_share_refusals: 0,
        }
    }

    #[cfg(feature = "bench-internals")]
    pub(in crate::manager) fn set_bench_peer_limit(&mut self, bytes: usize) {
        assert!(self.records.is_empty() && self.snapshots.is_empty());
        assert!(
            bytes <= self.peer_limit,
            "a control may only reduce the peer budget"
        );
        self.peer_limit = bytes;
    }

    #[cfg(test)]
    pub(in crate::manager) fn with_test_limits(peer: usize, daemon: usize) -> Self {
        Self::with_limits(peer, daemon)
    }

    #[cfg(test)]
    pub(in crate::manager) fn set_test_daemon_limit(&mut self, bytes: usize) {
        self.daemon_limit = bytes;
    }

    #[cfg(test)]
    pub(in crate::manager) fn set_test_peer_limit(&mut self, bytes: usize) {
        self.peer_limit = bytes;
    }

    #[cfg(test)]
    pub(in crate::manager) fn fail_next_allocation_for_test(&mut self) {
        self.fail_next_allocation = true;
    }

    /// Disarm an injected failure no allocation consumed, so it cannot
    /// land on another peer later.
    #[cfg(test)]
    pub(in crate::manager) fn disarm_allocation_failure_for_test(&mut self) {
        self.fail_next_allocation = false;
    }

    #[cfg(test)]
    pub(in crate::manager) fn optional_share_attempts_for_test(&self) -> usize {
        self.optional_share_attempts
    }

    #[cfg(test)]
    pub(in crate::manager) fn optional_share_refusals_for_test(&self) -> usize {
        self.optional_share_refusals
    }

    pub(in crate::manager) const fn entries(&self) -> usize {
        self.entries
    }

    pub(in crate::manager) fn bytes(&self) -> usize {
        self.used
    }

    pub(in crate::manager) fn peak_bytes(&self) -> usize {
        self.peak
    }

    pub(in crate::manager) fn contains_record(&self, peer: PeerId) -> bool {
        self.index(peer).is_ok()
    }

    /// Whether `peer`'s proof is a mask over universe `handle`, so a
    /// position resolved against that universe names the member's own bit.
    pub(in crate::manager) fn masks_universe(&self, peer: PeerId, handle: SnapshotHandle) -> bool {
        self.index(peer)
            .is_ok_and(|index| self.records[index].snapshot == Some(handle))
    }

    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "map-shaped accessor keeps the borrowed-key signature its callers share with HashMap"
    )]
    pub(in crate::manager) fn contains_key(&self, peer: &PeerId) -> bool {
        self.get(peer).is_some()
    }

    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "map-shaped accessor keeps the borrowed-key signature its callers share with HashMap"
    )]
    pub(in crate::manager) fn get(&self, peer: &PeerId) -> Option<AdmittedKeyView<'_>> {
        let record = &self.records[self.index(*peer).ok()?];
        if record.state != State::Complete {
            return None;
        }
        let (universe, index) = match record.snapshot {
            Some(handle) => {
                let snapshot = self.snapshots.get(self.snapshot_index(handle)?)?;
                (snapshot.keys.as_slice(), snapshot.key_index())
            }
            None => (&[][..], &[][..]),
        };
        Some(AdmittedKeyView {
            universe,
            index,
            words: &record.words,
            sparse: &record.keys.0,
            masked: record.masked,
        })
    }

    /// Lend out the ledger without visiting its OLD keys. Complete records
    /// keep their shared snapshot alive until their handle is released.
    pub(in crate::manager) fn complete_peers(
        &self,
        mut visit: impl FnMut(),
    ) -> std::collections::HashSet<PeerId> {
        self.records
            .iter()
            .inspect(|_| visit())
            .filter(|record| record.state == State::Complete)
            .map(|record| record.peer)
            .collect()
    }

    #[cfg(test)]
    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "map-shaped accessor keeps the borrowed-key signature its callers share with HashMap"
    )]
    pub(in crate::manager) fn owned_proof(&self, peer: &PeerId) -> Option<AdmittedKeys> {
        self.get(peer).map(|proof| proof.iter().collect())
    }

    #[cfg(test)]
    pub(in crate::manager) fn keys(&self) -> impl Iterator<Item = &PeerId> {
        self.records
            .iter()
            .filter_map(|record| (record.state == State::Complete).then_some(&record.peer))
    }

    fn snapshot_index(&self, handle: SnapshotHandle) -> Option<usize> {
        self.snapshots
            .binary_search_by_key(&handle.0, |snapshot| snapshot.handle.0)
            .ok()
    }

    /// A record's universe keys and their key buckets, borrowing only the pool.
    fn universe(snapshots: &Snapshots, handle: Option<SnapshotHandle>) -> (&[Key], &[u32]) {
        handle
            .and_then(|handle| {
                snapshots
                    .binary_search_by_key(&handle.0, |snapshot| snapshot.handle.0)
                    .ok()
            })
            .map_or((&[], &[]), |index| {
                let snapshot = &snapshots[index];
                (snapshot.keys.as_slice(), snapshot.key_index())
            })
    }

    #[cfg(feature = "bench-internals")]
    pub(in crate::manager) fn bench_peer_charge(&self, peer: PeerId) -> usize {
        self.index(peer).map_or(0, |index| self.peer_charge(index))
    }

    fn peer_charge(&self, index: usize) -> usize {
        let record = &self.records[index];
        record.charge()
            + record
                .snapshot
                .and_then(|handle| self.snapshot_index(handle))
                .map_or(0, |index| self.snapshots[index].charge())
    }

    /// Unicast slots plus VPN buckets for a pool of `count` keys over `table`.
    /// The VPN buckets stay at most two-thirds full and never full, so every
    /// probe ends.
    fn index_len(table: &AdjRibOut, count: usize) -> usize {
        let vpn = count.saturating_sub(table.len());
        let buckets = if vpn == 0 {
            0
        } else {
            vpn.saturating_add(vpn / 2).saturating_add(1)
        };
        table.unicast_slot_count().saturating_add(buckets)
    }

    /// Index entries a new pool of `count` keys carries: slab slots plus VPN
    /// buckets over a source table, or one bucket set over every key of an
    /// initial replay's universe.
    fn snapshot_index_len(slot_source: Option<&AdjRibOut>, keyed: bool, count: usize) -> usize {
        match slot_source {
            Some(table) => Self::index_len(table, count),
            None if keyed => key_index_len(count),
            None => 0,
        }
    }

    fn vpn_bucket(key: &VpnRouteKey, path_id: u32, buckets: usize) -> usize {
        use std::hash::BuildHasher;

        let hash = FastState::default().hash_one((key, path_id));
        usize::try_from(hash % buckets as u64).expect("bucket is below a usize length")
    }

    /// Exact O(1) VPN membership: each bucket hit compares the pool key.
    fn vpn_position(
        snapshot: &Snapshot,
        key: Key,
        comparisons: &mut usize,
        checkpoint: &mut impl FnMut(bool),
    ) -> Option<usize> {
        let Key::Vpn(vpn, path_id) = key else {
            return None;
        };
        let buckets = snapshot.slot_positions.get(snapshot.vpn_base..)?;
        if buckets.is_empty() {
            return None;
        }
        let mut bucket = Self::vpn_bucket(&vpn, path_id, buckets.len());
        loop {
            checkpoint(false);
            let position = buckets[bucket];
            if position == EMPTY_SLOT {
                return None;
            }
            *comparisons += 1;
            if snapshot.keys.get(position as usize) == Some(&key) {
                return Some(position as usize);
            }
            bucket = (bucket + 1) % buckets.len();
        }
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
        peer: PeerId,
        count: usize,
        keys: A,
        slot_source: Option<&AdjRibOut>,
        keyed: bool,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<SnapshotHandle, Failure> {
        let index = self.index(peer).map_err(|_| self.missing_proof(peer))?;
        let id = self.next_snapshot.ok_or_else(Self::overflow)?;
        let key_bytes = count
            .checked_mul(size_of::<Key>())
            .ok_or_else(Self::overflow)?;
        let slot_count = slot_source.map_or(0, AdjRibOut::unicast_slot_count);
        let index_len = Self::snapshot_index_len(slot_source, keyed, count);
        let slot_bytes = index_len
            .checked_mul(size_of::<u32>())
            .ok_or_else(Self::overflow)?;
        let temporary = key_bytes
            .checked_add(slot_bytes)
            .and_then(|n| n.checked_add(size_of::<SlotPositions>()))
            .and_then(|n| n.checked_add(size_of::<Snapshot>()))
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
        let mut slot_positions = SlotPositions::new();
        checkpoint(true);
        let failed = !self.allocation_permitted() || owned.try_grow(count).is_err();
        checkpoint(true);
        if failed {
            checkpoint(true);
            drop((owned, slot_positions));
            checkpoint(true);
            self.used -= temporary;
            return Err(Failure {
                cause: FailureCause::AllocationFailure,
                limiting_peer: None,
                attempted_peer_bytes: attempted_peer,
                attempted_daemon_bytes: daemon,
            });
        }
        if index_len != 0 {
            checkpoint(true);
            let failed =
                !self.allocation_permitted() || slot_positions.try_grow(index_len).is_err();
            checkpoint(true);
            if failed {
                checkpoint(true);
                drop((owned, slot_positions));
                checkpoint(true);
                self.used -= temporary;
                return Err(Failure {
                    cause: FailureCause::AllocationFailure,
                    limiting_peer: None,
                    attempted_peer_bytes: attempted_peer,
                    attempted_daemon_bytes: daemon,
                });
            }
        }
        for key in keys {
            checkpoint(false);
            if owned.len() == count {
                checkpoint(true);
                drop((owned, slot_positions));
                checkpoint(true);
                self.used -= temporary;
                return Err(self.missing_proof(peer));
            }
            owned.push(key);
        }
        Self::sort_keys(&mut owned, checkpoint);
        if let Some(table) = slot_source {
            for slot in 0..slot_count {
                checkpoint(false);
                let position = if let Some(route) = table.unicast_slot(slot) {
                    let key = Key::Unicast(route.prefix, route.path_id);
                    owned
                        .binary_search_by(|prior| {
                            checkpoint(false);
                            prior.cmp(&key)
                        })
                        .ok()
                        .and_then(|position| u32::try_from(position).ok())
                        .filter(|position| *position != EMPTY_SLOT)
                } else {
                    Some(EMPTY_SLOT)
                };
                let Some(position) = position else {
                    checkpoint(true);
                    drop((owned, slot_positions));
                    checkpoint(true);
                    self.used -= temporary;
                    return Err(self.missing_proof(peer));
                };
                slot_positions.push(position);
            }
            let buckets = index_len - slot_count;
            for _ in 0..buckets {
                checkpoint(false);
                slot_positions.push(EMPTY_SLOT);
            }
            let mut indexed_vpn = 0_usize;
            let mut unindexable = false;
            for (position, key) in owned.iter().enumerate() {
                checkpoint(false);
                let Key::Vpn(vpn, path_id) = key else {
                    continue;
                };
                indexed_vpn += 1;
                let Some(position) = u32::try_from(position)
                    .ok()
                    .filter(|position| *position != EMPTY_SLOT && indexed_vpn < buckets)
                else {
                    unindexable = true;
                    break;
                };
                let mut bucket = Self::vpn_bucket(vpn, *path_id, buckets);
                while slot_positions[slot_count + bucket] != EMPTY_SLOT {
                    checkpoint(false);
                    bucket = (bucket + 1) % buckets;
                }
                slot_positions[slot_count + bucket] = position;
            }
            if unindexable {
                checkpoint(true);
                drop((owned, slot_positions));
                checkpoint(true);
                self.used -= temporary;
                return Err(self.missing_proof(peer));
            }
        } else if keyed {
            // Every position must fit below the empty-bucket marker.
            if u32::try_from(count).is_ok_and(|count| count < EMPTY_SLOT) {
                checkpoint(true);
                slot_positions.resize(index_len, EMPTY_SLOT);
                checkpoint(true);
            } else {
                checkpoint(true);
                drop((owned, slot_positions));
                checkpoint(true);
                self.used -= temporary;
                return Err(Self::overflow());
            }
            for (position, key) in (0_u32..).zip(owned.iter()) {
                checkpoint(false);
                index_key(&mut slot_positions, key, position);
            }
        }

        let old_cap = self.snapshots.capacity();
        let new_cap = if old_cap == self.snapshots.len() {
            if let Some(cap) = old_cap.checked_mul(2) {
                cap.max(1)
            } else {
                checkpoint(true);
                drop((owned, slot_positions));
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
                drop((owned, slot_positions));
                checkpoint(true);
                self.used -= temporary;
                return Err(Self::overflow());
            }
        } else {
            0
        };
        let Some(daemon) = self.used.checked_add(extra) else {
            checkpoint(true);
            drop((owned, slot_positions));
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
                        drop((owned, slot_positions));
                        checkpoint(true);
                        self.used -= temporary;
                        return Err(error);
                    }
                }
            }
        }
        if let Err(error) = self.check(peer, attempted_peer, daemon) {
            checkpoint(true);
            drop((owned, slot_positions));
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
                drop((owned, slot_positions));
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
            slot_positions,
            vpn_base: slot_count,
            vpn_keys: slot_source.map(AdjRibOut::vpn_key_version),
            indexed: slot_source.is_some(),
            keyed,
        });
        checkpoint(true);
        self.next_snapshot = id.checked_add(1);
        self.used -= size_of::<Snapshot>() + size_of::<Keys>() + size_of::<SlotPositions>();
        Ok(handle)
    }

    fn release_snapshot(&mut self, handle: SnapshotHandle, checkpoint: &mut impl FnMut(bool)) {
        let Some(index) = self.snapshot_index(handle) else {
            return;
        };
        if self.snapshots[index].references != 0 {
            return;
        }
        let bytes = self.snapshots[index].keys.capacity() * size_of::<Key>()
            + self.snapshots[index].slot_positions.capacity() * size_of::<u32>();
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
    #[cfg(test)]
    pub(in crate::manager) fn share_capture_with_checkpoint<A: Iterator<Item = Key>>(
        &mut self,
        peer: PeerId,
        hint: Option<SnapshotHandle>,
        count: usize,
        keys: A,
        shape: (usize, usize),
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<Option<SnapshotHandle>, Failure> {
        self.share_capture_inner(peer, hint, count, keys, shape, None, checkpoint)
    }

    /// Group pools receive their immutable unicast slot and VPN bucket index
    /// before publication.
    pub(in crate::manager) fn share_group_capture_with_checkpoint(
        &mut self,
        peer: PeerId,
        hint: Option<SnapshotHandle>,
        table: &AdjRibOut,
        shape: (usize, usize),
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<Option<SnapshotHandle>, Failure> {
        self.share_capture_inner(
            peer,
            hint,
            table.len().saturating_add(table.vpn_len()),
            // Slab insertion order depends on the changed-prefix set. Start the
            // ordered trie walk only when a new snapshot needs its keys.
            std::iter::once_with(|| table.iter_unicast_in_key_order())
                .flatten()
                .map(|route| Key::Unicast(route.prefix, route.path_id))
                .chain(table.iter_vpn().map(|route| {
                    let key = route.key();
                    Key::Vpn(key.nlri_key, key.path_id)
                })),
            shape,
            Some(table),
            checkpoint,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "optional sparse storage and indexed or key-only pool publication share one rollback boundary"
    )]
    fn share_capture_inner<A: Iterator<Item = Key>>(
        &mut self,
        peer: PeerId,
        hint: Option<SnapshotHandle>,
        count: usize,
        keys: A,
        shape: (usize, usize),
        slot_source: Option<&AdjRibOut>,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<Option<SnapshotHandle>, Failure> {
        #[cfg(test)]
        {
            self.optional_share_attempts += 1;
        }
        let index = self.index(peer).map_err(|_| self.missing_proof(peer))?;
        // A replay builds its own ordered universe in pages. It is never
        // shared or replaced, even before its first successful admission.
        if self.records[index].initial_replay {
            return Ok(None);
        }
        if self.records[index].masked != 0 || !self.records[index].keys.0.is_empty() {
            return Ok(self.records[index].snapshot);
        }
        if self.records[index].snapshot.is_none() && count == 0 {
            return Ok(None);
        }
        if matches!(self.records[index].state, State::Failed(_)) {
            return Err(self.missing_proof(peer));
        }
        if slot_source.is_some()
            && self.records[index].snapshot.is_some_and(|handle| {
                self.snapshot_index(handle)
                    .is_none_or(|index| !self.snapshots[index].indexed)
            })
        {
            // Existing empty key-only ownership may have been sized against a
            // different universe. Let admission reserve its authoritative flat union.
            self.free_keys(index, checkpoint);
            return Ok(None);
        }
        let shared = self.grow_keys(index, shape.1, checkpoint).and_then(|()| {
            self.attach_snapshot_with_checkpoint(
                index,
                hint,
                count,
                keys,
                shape,
                slot_source,
                false,
                checkpoint,
            )
        });
        if matches!(shared, Ok(Some(_))) {
            return shared;
        }
        #[cfg(test)]
        if shared.is_err() {
            self.optional_share_refusals += 1;
        }
        self.free_keys(index, checkpoint);
        shared
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "pool identity, sparse sizing and optional slab source are checked before shared ownership is published"
    )]
    fn attach_snapshot_with_checkpoint<A: Iterator<Item = Key>>(
        &mut self,
        index: usize,
        hint: Option<SnapshotHandle>,
        count: usize,
        keys: A,
        shape: (usize, usize),
        slot_source: Option<&AdjRibOut>,
        replay: bool,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<Option<SnapshotHandle>, Failure> {
        if let Some(handle) = self.records[index].snapshot {
            return Ok(Some(handle));
        }
        let peer = self.records[index].peer;
        let words = Self::shared_words(count)?;
        let flat = shape
            .0
            .checked_mul(size_of::<Key>())
            .ok_or_else(Self::overflow)?;
        // A replay universe serves replays alone, and a group pool never does.
        let reused = hint.filter(|handle| {
            self.snapshot_index(*handle).is_some_and(|index| {
                let snapshot = &self.snapshots[index];
                snapshot.keyed == replay && (slot_source.is_none() || snapshot.indexed)
            })
        });
        let (actual_words, snapshot_charge) = if let Some(handle) = reused {
            let snapshot = &self.snapshots[self
                .snapshot_index(handle)
                .ok_or_else(|| self.missing_proof(peer))?];
            (Self::shared_words(snapshot.mask_keys())?, snapshot.charge())
        } else {
            (
                words,
                Self::snapshot_index_len(slot_source, replay, count)
                    .checked_mul(size_of::<u32>())
                    .and_then(|n| n.checked_add(count.checked_mul(size_of::<Key>())?))
                    .and_then(|n| n.checked_add(size_of::<Snapshot>()))
                    .ok_or_else(Self::overflow)?,
            )
        };
        let bytes = actual_words
            .checked_mul(size_of::<u64>())
            .ok_or_else(Self::overflow)?;
        let sparse = shape
            .1
            .checked_mul(size_of::<Key>())
            .ok_or_else(Self::overflow)?;
        if flat < bytes.checked_add(sparse).ok_or_else(Self::overflow)? {
            return Ok(None);
        }
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
            None => {
                match self.create_snapshot(peer, count, keys, slot_source, replay, checkpoint) {
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
                }
            }
        };
        let snapshot_index = self
            .snapshot_index(handle)
            .ok_or_else(|| self.missing_proof(peer))?;
        self.records[index].snapshot = Some(handle);
        self.snapshots[snapshot_index].references += 1;
        Ok(Some(handle))
    }

    fn walk_full_old<U, V, C>(
        table: &AdjRibOut,
        project_uc: &U,
        project_vpn: &V,
        checkpoint: &mut C,
        visit: impl FnMut(Option<usize>, Key, Option<&VpnRibRoute>, &mut C) -> Result<(), Failure>,
    ) -> Result<(), Failure>
    where
        U: Fn(&Route) -> Option<Key>,
        V: Fn(&VpnRibRoute) -> Option<Key>,
        C: FnMut(bool),
    {
        #[cfg(feature = "bench-internals")]
        let observed = crate::manager::bench_support::grouped_walk_observed();
        let result = Self::walk_projected_rows(table, project_uc, project_vpn, checkpoint, visit);
        // A completed walk projected each occupied unicast slot and each VPN
        // row exactly once, so the observer takes the row count here.
        #[cfg(feature = "bench-internals")]
        if observed && result.is_ok() {
            crate::manager::bench_support::record_completed_grouped_walk(
                table.len().saturating_add(table.vpn_len()),
            );
        }
        result
    }

    fn walk_projected_rows<U, V, C>(
        table: &AdjRibOut,
        project_uc: &U,
        project_vpn: &V,
        checkpoint: &mut C,
        mut visit: impl FnMut(Option<usize>, Key, Option<&VpnRibRoute>, &mut C) -> Result<(), Failure>,
    ) -> Result<(), Failure>
    where
        U: Fn(&Route) -> Option<Key>,
        V: Fn(&VpnRibRoute) -> Option<Key>,
        C: FnMut(bool),
    {
        for slot in 0..table.unicast_slot_count() {
            checkpoint(false);
            if let Some(key) = table.unicast_slot(slot).and_then(project_uc) {
                visit(Some(slot), key, None, checkpoint)?;
            }
        }
        for route in table.iter_vpn() {
            checkpoint(false);
            if let Some(key) = project_vpn(route) {
                visit(None, key, Some(route), checkpoint)?;
            }
        }
        Ok(())
    }

    /// Recycled or cleared slots cannot prove that a different key was admitted.
    fn indexed_position(
        snapshot: &Snapshot,
        slot: Option<usize>,
        key: Key,
        mismatches: &mut usize,
        comparisons: &mut usize,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<Option<usize>, ()> {
        let Some(slot) = slot else {
            return Ok(Self::vpn_position(snapshot, key, comparisons, checkpoint));
        };
        if let Some(position) = snapshot.slot_positions[..snapshot.vpn_base]
            .get(slot)
            .copied()
            .filter(|position| *position != EMPTY_SLOT)
            .map(|position| position as usize)
            && let Some(prior) = snapshot.keys.get(position)
        {
            checkpoint(false);
            *comparisons += 1;
            if *prior == key {
                return Ok(Some(position));
            }
        }
        *mismatches += 1;
        if *mismatches > SLOT_MISMATCH_BUDGET {
            return Err(());
        }
        Ok(snapshot
            .keys
            .binary_search_by(|prior| {
                checkpoint(false);
                *comparisons += 1;
                prior.cmp(&key)
            })
            .ok())
    }

    /// `project_vpn` normally returns the row's own key or `None`. The probe-free
    /// path for a current pool relies on that; any other key disqualifies it for
    /// this capture, and every VPN row then takes the exact probe.
    pub(in crate::manager) fn full_old_shape_with_checkpoint<U, V>(
        &self,
        hint: Option<SnapshotHandle>,
        table: &AdjRibOut,
        sharing_allowed: bool,
        project_uc: U,
        project_vpn: V,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<FullCaptureShape, Failure>
    where
        U: Fn(&Route) -> Option<Key>,
        V: Fn(&VpnRibRoute) -> Option<Key>,
    {
        let snapshot = hint
            .and_then(|handle| self.snapshot_index(handle))
            .map(|index| &self.snapshots[index]);
        let mut shape = FullCaptureShape {
            count: 0,
            additions: 0,
            mismatches: 0,
            comparisons: 0,
            fallback: if !sharing_allowed {
                Some(FullCaptureFallback::SharingDisabled)
            } else if snapshot.is_some_and(|snapshot| !snapshot.indexed) {
                Some(FullCaptureFallback::MissingIndex)
            } else {
                None
            },
            vpn: 0,
            vpn_identity: true,
        };
        let vpn_changes = snapshot.and_then(|snapshot| snapshot.vpn_changes(table));
        let current_vpn = vpn_changes.is_some();
        Self::walk_full_old(
            table,
            &project_uc,
            &project_vpn,
            checkpoint,
            |slot, key, row, checkpoint| {
                shape.count = shape.count.checked_add(1).ok_or_else(Self::overflow)?;
                if slot.is_none() {
                    shape.vpn += 1;
                    // Only a shared capture reads identity. Population's pool may be
                    // new, so check it regardless; a new pool holds only row keys.
                    if shape.fallback.is_none() && (shape.vpn_identity || snapshot.is_none()) {
                        let own = row.map(VpnRibRoute::key);
                        let identity =
                            own.is_some_and(|own| key == Key::Vpn(own.nlri_key, own.path_id));
                        shape.vpn_identity &= identity;
                        if snapshot.is_none() && !identity {
                            shape.additions =
                                shape.additions.checked_add(1).ok_or_else(Self::overflow)?;
                        }
                    }
                    // The pool holds every row key except logged additions, counted below.
                    if current_vpn && shape.vpn_identity {
                        return Ok(());
                    }
                }
                if shape.fallback.is_none()
                    && let Some(snapshot) = snapshot
                {
                    match Self::indexed_position(
                        snapshot,
                        slot,
                        key,
                        &mut shape.mismatches,
                        &mut shape.comparisons,
                        checkpoint,
                    ) {
                        Ok(None) => {
                            shape.additions =
                                shape.additions.checked_add(1).ok_or_else(Self::overflow)?;
                        }
                        Ok(Some(_)) => {}
                        Err(()) => shape.fallback = Some(FullCaptureFallback::SlotChurn),
                    }
                }
                Ok(())
            },
        )?;
        if shape.fallback.is_none()
            && let (Some(snapshot), Some((_, changes))) = (snapshot, vpn_changes)
        {
            // Every admitted row key outside the pool was inserted after it: an
            // upper bound even when the same key is logged more than once. Rows
            // the member does not project add nothing.
            for (key, _) in changes {
                if let Some(projected) = table.get_vpn(key).and_then(&project_vpn)
                    && Self::vpn_position(snapshot, projected, &mut shape.comparisons, checkpoint)
                        .is_none()
                {
                    shape.additions = shape.additions.checked_add(1).ok_or_else(Self::overflow)?;
                }
            }
        }
        Ok(shape)
    }

    /// Two actual projections: count/classify, then populate. No member sort or scratch.
    /// See [`Self::full_old_shape_with_checkpoint`] for the `project_vpn` contract.
    #[expect(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the full OLD capture keeps peer ownership, actual family projections and checkpoint at one fallible boundary"
    )]
    pub(in crate::manager) fn capture_full_old_with_checkpoint<U, V>(
        &mut self,
        peer: PeerId,
        hint: Option<SnapshotHandle>,
        table: &AdjRibOut,
        sharing_allowed: bool,
        project_uc: U,
        project_vpn: V,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<FullCaptureOutcome, Failure>
    where
        U: Fn(&Route) -> Option<Key>,
        V: Fn(&VpnRibRoute) -> Option<Key>,
    {
        let index = self.index(peer).map_err(|_| self.missing_proof(peer))?;
        if let State::Failed(error) = self.records[index].state {
            return Err(error);
        }
        if self.records[index].state != State::Capturing {
            return Err(self.fail(index, self.missing_proof(peer), checkpoint));
        }
        let shape = match self.full_old_shape_with_checkpoint(
            hint,
            table,
            sharing_allowed,
            &project_uc,
            &project_vpn,
            checkpoint,
        ) {
            Ok(shape) => shape,
            Err(error) => return Err(self.fail(index, error, checkpoint)),
        };
        let selection = if shape.fallback.is_none() {
            match self.share_group_capture_with_checkpoint(
                peer,
                hint,
                table,
                (shape.count, shape.additions),
                checkpoint,
            ) {
                Ok(Some(handle)) => (Some(handle), None),
                Ok(None) => (None, Some(FullCaptureFallback::Representation)),
                Err(_) => (None, Some(FullCaptureFallback::ShareRefused)),
            }
        } else {
            (None, shape.fallback)
        };
        let handle = selection.0;
        if handle.is_none() {
            self.reserve_capture_with_checkpoint(peer, shape.count, checkpoint)?;
        }
        let invalid = self.missing_proof(peer);
        let snapshot_index = handle.and_then(|handle| self.snapshot_index(handle));
        let snapshot = snapshot_index.map(|index| &self.snapshots[index]);
        // Every table VPN row projected as its own key: admit the pool's VPN
        // range, then apply the logged changes since the pool was built.
        let all_vpn = snapshot
            .and_then(|snapshot| snapshot.vpn_changes(table))
            .filter(|_| shape.vpn_identity && shape.vpn == table.vpn_len());
        let record = &mut self.records[index];
        let prior = record.entries();
        let mut count = 0_usize;
        let mut mismatches = 0;
        let mut comparisons = 0;
        let population = Self::walk_full_old(
            table,
            &project_uc,
            &project_vpn,
            checkpoint,
            |slot, key, _, checkpoint| {
                count = count.checked_add(1).ok_or_else(Self::overflow)?;
                if count > shape.count {
                    return Err(invalid);
                }
                if slot.is_none() && all_vpn.is_some() {
                    return Ok(());
                }
                let position = match snapshot {
                    Some(snapshot) => Self::indexed_position(
                        snapshot,
                        slot,
                        key,
                        &mut mismatches,
                        &mut comparisons,
                        checkpoint,
                    )
                    .map_err(|()| invalid)?,
                    None => None,
                };
                if let Some(position) = position {
                    let bit = 1_u64 << (position % 64);
                    if record.words[position / 64] & bit == 0 {
                        record.words[position / 64] |= bit;
                        record.masked += 1;
                    }
                } else {
                    if record.keys.0.len() == record.keys.0.capacity() {
                        return Err(invalid);
                    }
                    record.keys.0.push(key);
                }
                Ok(())
            },
        );
        self.entries = self.entries - prior + record.entries();
        if let Err(error) = population {
            return Err(self.fail(index, error, checkpoint));
        }
        if count != shape.count {
            return Err(self.fail(index, invalid, checkpoint));
        }
        if let (Some((range, changes)), Some(snapshot_index)) = (all_vpn, snapshot_index) {
            let snapshot = &self.snapshots[snapshot_index];
            let record = &mut self.records[index];
            let prior = record.entries();
            let mut position = range.start;
            while position < range.end {
                checkpoint(false);
                let word = position / 64;
                let high = (range.end - word * 64).min(64);
                let bits = (u64::MAX >> (64 - (high - position % 64))) << (position % 64);
                record.masked += (bits & !record.words[word]).count_ones() as usize;
                record.words[word] |= bits;
                position = word * 64 + high;
            }
            let mut overflow = false;
            for (key, _) in changes {
                let present = table.get_vpn(key).is_some();
                let pooled = Key::Vpn(key.nlri_key, key.path_id);
                match (
                    present,
                    Self::vpn_position(snapshot, pooled, &mut comparisons, checkpoint),
                ) {
                    (false, Some(position)) => {
                        let bit = 1_u64 << (position % 64);
                        if record.words[position / 64] & bit != 0 {
                            record.words[position / 64] &= !bit;
                            record.masked -= 1;
                        }
                    }
                    (true, None) => {
                        if record.keys.0.len() == record.keys.0.capacity() {
                            overflow = true;
                            break;
                        }
                        record.keys.0.push(pooled);
                    }
                    _ => {}
                }
            }
            self.entries = self.entries - prior + record.entries();
            if overflow {
                return Err(self.fail(index, invalid, checkpoint));
            }
        }
        Ok(FullCaptureOutcome {
            #[cfg(any(test, feature = "bench-internals"))]
            keys: count,
            handle,
            #[cfg(any(test, feature = "bench-internals"))]
            strategy: if handle.is_some() {
                FullCaptureStrategy::Indexed
            } else {
                FullCaptureStrategy::Flat
            },
            #[cfg(any(test, feature = "bench-internals"))]
            fallback: selection.1,
            #[cfg(any(test, feature = "bench-internals"))]
            mismatches: shape.mismatches,
        })
    }

    /// One walk of a cohort's base projection, with each row's excluded
    /// members. Same bench witness as [`Self::walk_full_old`].
    fn walk_cohort<P, X, C>(
        table: &AdjRibOut,
        project: &P,
        exclude: &X,
        checkpoint: &mut C,
        mut visit: impl FnMut(usize, Key, &[usize], &mut C) -> Result<(), Failure>,
    ) -> Result<(), Failure>
    where
        P: Fn(&Route) -> Option<Key>,
        X: Fn(&Route, &mut dyn FnMut(usize)),
        C: FnMut(bool),
    {
        #[cfg(feature = "bench-internals")]
        let observed = crate::manager::bench_support::grouped_walk_observed();
        let mut excluded = SmallVec::<[usize; 4]>::new();
        let mut result = Ok(());
        for slot in 0..table.unicast_slot_count() {
            checkpoint(false);
            let Some(route) = table.unicast_slot(slot) else {
                continue;
            };
            let Some(key) = project(route) else {
                continue;
            };
            excluded.clear();
            exclude(route, &mut |member| excluded.push(member));
            result = visit(slot, key, &excluded, checkpoint);
            if result.is_err() {
                break;
            }
        }
        #[cfg(feature = "bench-internals")]
        if observed && result.is_ok() {
            crate::manager::bench_support::record_completed_grouped_walk(table.len());
        }
        result
    }

    /// OLD for several fresh members of one unicast-only group from two walks
    /// of its table, instead of two per member. Each member's projection must
    /// be `project` minus the rows `exclude` names its index for, every row at
    /// its own key; the caller's predicate establishes that. Every member is
    /// `Capturing` and empty. A member the shared indexed pool cannot
    /// represent, or every member when the pool is unusable, is returned
    /// untouched for its own capture. Shared members' records are charged as
    /// their own captures would be; the base mask is one charged scratch.
    #[expect(
        clippy::too_many_lines,
        reason = "shape, attachment, population and rollback of one cohort share one ownership boundary"
    )]
    pub(in crate::manager) fn capture_cohort_old_with_checkpoint<P, X>(
        &mut self,
        members: &[PeerId],
        hint: Option<SnapshotHandle>,
        table: &AdjRibOut,
        project: P,
        exclude: X,
        checkpoint: &mut impl FnMut(bool),
    ) -> CohortCapture
    where
        P: Fn(&Route) -> Option<Key>,
        X: Fn(&Route, &mut dyn FnMut(usize)),
    {
        let mut capture = CohortCapture {
            handle: None,
            shared: Vec::new(),
            individual: members.to_vec(),
            failed: Vec::new(),
        };
        let snapshot = hint
            .and_then(|handle| self.snapshot_index(handle))
            .map(|index| &self.snapshots[index]);
        if table.vpn_len() != 0 || snapshot.is_some_and(|snapshot| !snapshot.indexed) {
            return capture;
        }
        // Shape: the base count and pool additions, and what each member drops.
        let (mut count, mut additions) = (0_usize, 0_usize);
        let mut dropped = vec![(0_usize, 0_usize); members.len()];
        let (mut mismatches, mut comparisons) = (0, 0);
        let shape = Self::walk_cohort(
            table,
            &project,
            &exclude,
            checkpoint,
            |slot, key, excluded, checkpoint| {
                count += 1;
                let sparse = match snapshot {
                    Some(snapshot) => Self::indexed_position(
                        snapshot,
                        Some(slot),
                        key,
                        &mut mismatches,
                        &mut comparisons,
                        checkpoint,
                    )
                    .map_err(|()| Self::overflow())?
                    .is_none(),
                    None => false,
                };
                additions += usize::from(sparse);
                for &member in excluded {
                    dropped[member].0 += 1;
                    dropped[member].1 += usize::from(sparse);
                }
                Ok(())
            },
        );
        if shape.is_err() {
            return capture;
        }
        // Charge the scratch base mask before any member attaches, so a
        // refusal leaves every member to its own capture.
        let pool_keys = snapshot.map_or(table.len(), |snapshot| snapshot.keys.len());
        let mut hint = snapshot.map(|snapshot| snapshot.handle);
        let Ok(words) = Self::shared_words(pool_keys) else {
            return capture;
        };
        let scratch = words * size_of::<u64>();
        let Some(daemon) = self.used.checked_add(scratch) else {
            return capture;
        };
        let mut template = Words::new();
        if daemon > self.daemon_limit
            || !self.allocation_permitted()
            || template.try_grow(words).is_err()
        {
            return capture;
        }
        self.used = daemon;
        self.peak = self.peak.max(daemon);
        template.extend(std::iter::repeat_n(0, words));

        // Attach every member that the shared indexed pool represents.
        let mut shared = Vec::new();
        capture.individual.clear();
        for (member, &peer) in members.iter().enumerate() {
            let (gone, gone_sparse) = dropped[member];
            let shape = (count - gone, additions - gone_sparse);
            match self.share_group_capture_with_checkpoint(peer, hint, table, shape, checkpoint) {
                Ok(Some(handle)) if hint.is_none_or(|hint| hint == handle) => {
                    hint = Some(handle);
                    shared.push((member, peer, shape.0));
                }
                Ok(Some(_)) => {
                    // Not the cohort's pool: undo the attachment.
                    if let Ok(index) = self.index(peer) {
                        self.free_keys(index, checkpoint);
                    }
                    capture.individual.push(peer);
                }
                Ok(None) | Err(_) => capture.individual.push(peer),
            }
        }
        capture.handle = hint.filter(|_| !shared.is_empty());
        // Population: the base mask once, each member's dropped rows as its
        // own bits, and sparse additions pushed to the members that keep them.
        let mut by_member = vec![None; members.len()];
        for &(member, peer, _) in &shared {
            by_member[member] = self.index(peer).ok();
        }
        let pool = capture
            .handle
            .and_then(|handle| self.snapshot_index(handle));
        let population = pool.map_or(Ok(()), |pool| {
            let snapshot = &self.snapshots[pool];
            let records = &mut self.records;
            let entries = &mut self.entries;
            let (mut mismatches, mut comparisons) = (0, 0);
            Self::walk_cohort(
                table,
                &project,
                &exclude,
                checkpoint,
                |slot, key, excluded, checkpoint| {
                    let position = Self::indexed_position(
                        snapshot,
                        Some(slot),
                        key,
                        &mut mismatches,
                        &mut comparisons,
                        checkpoint,
                    )
                    .map_err(|()| Self::overflow())?;
                    if let Some(position) = position {
                        let bit = 1_u64 << (position % 64);
                        template[position / 64] |= bit;
                        for index in excluded.iter().filter_map(|&member| by_member[member]) {
                            records[index].words[position / 64] |= bit;
                        }
                        return Ok(());
                    }
                    for (member, index) in by_member.iter().enumerate() {
                        let Some(index) = *index else {
                            continue;
                        };
                        if excluded.contains(&member) {
                            continue;
                        }
                        let keys = &mut records[index].keys.0;
                        if keys.len() == keys.capacity() {
                            return Err(Self::overflow());
                        }
                        keys.push(key);
                        *entries += 1;
                    }
                    Ok(())
                },
            )
        });
        for (member, peer, expected) in shared {
            let index = by_member[member].expect("a shared member holds a record");
            if population.is_ok() {
                let record = &mut self.records[index];
                let mut masked = 0;
                for (word, base) in record.words.iter_mut().zip(&template) {
                    checkpoint(false);
                    *word = base & !*word;
                    masked += word.count_ones() as usize;
                }
                record.masked = masked;
                self.entries += masked;
                if self.records[index].entries() == expected {
                    capture.shared.push(peer);
                    continue;
                }
            }
            let error = self.fail(index, self.missing_proof(peer), checkpoint);
            capture.failed.push((peer, error));
        }
        checkpoint(true);
        drop(template);
        self.used -= scratch;
        checkpoint(true);
        capture
    }

    /// An attached empty proof's universe takes precedence over a group hint.
    pub(in crate::manager) fn candidate_universe_contains(
        &self,
        peer: PeerId,
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
        peer: PeerId,
        count: usize,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<(), Failure> {
        let index = self.index(peer).map_err(|_| self.missing_proof(peer))?;
        if let Err(error) = self.grow_keys(index, count, checkpoint) {
            return Err(self.fail(index, error, checkpoint));
        }
        Ok(())
    }

    fn index(&self, peer: PeerId) -> Result<usize, usize> {
        self.records
            .binary_search_by_key(&peer, |record| record.peer)
    }

    fn index_with_checkpoint(
        &self,
        peer: PeerId,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<usize, usize> {
        self.records.binary_search_by(|record| {
            checkpoint(false);
            record.peer.cmp(&peer)
        })
    }

    fn missing_proof(&self, peer: PeerId) -> Failure {
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

    fn check(&self, address: PeerId, peer: usize, daemon: usize) -> Result<(), Failure> {
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

    #[cfg(test)]
    fn allocation_permitted(&mut self) -> bool {
        if let Some(remaining) = self.allocation_countdown {
            self.allocation_countdown = remaining.checked_sub(1);
            if remaining == 0 {
                return false;
            }
        }
        !std::mem::take(&mut self.fail_next_allocation)
    }

    #[cfg(not(test))]
    #[expect(
        clippy::unused_self,
        reason = "Test builds use the owned allocation failure hook"
    )]
    fn allocation_permitted(&mut self) -> bool {
        true
    }

    fn insert_record(
        &mut self,
        peer: PeerId,
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
                initial_replay: false,
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
        peer: PeerId,
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
        peer: PeerId,
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

    /// Start `peer`'s initial replay proof over a key universe of
    /// `table_rows` capacity, and return that universe's handle. `shared`
    /// names a live universe the member's join cohort already holds: the
    /// member then takes a reference and pays for its own mask alone.
    /// Otherwise the universe's two empty buffers are prepaid here, once for
    /// every member that later shares it. Neither path visits the table:
    /// [`Self::extend_initial_replay_universe`] appends the keys in pages.
    /// The group never receives this handle. `None` when the member's proof
    /// is not complete and empty.
    pub(in crate::manager) fn begin_initial_replay(
        &mut self,
        peer: PeerId,
        table_rows: usize,
        shared: Option<SnapshotHandle>,
    ) -> Result<Option<SnapshotHandle>, Failure> {
        let Ok(index) = self.index(peer) else {
            return Ok(None);
        };
        let record = &self.records[index];
        if record.state != State::Complete || record.entries() != 0 || record.snapshot.is_some() {
            return Ok(None);
        }
        let rows = shared
            .and_then(|handle| self.replay_universe_capacity(handle))
            .unwrap_or(table_rows);
        let handle = self.attach_snapshot_with_checkpoint(
            index,
            shared,
            rows,
            std::iter::empty(),
            (rows, 0),
            None,
            true,
            &mut |_| {},
        )?;
        self.records[index].initial_replay = handle.is_some();
        Ok(handle)
    }

    /// Live replay universes.
    #[cfg(test)]
    pub(in crate::manager) fn replay_universes(&self) -> usize {
        self.snapshots
            .iter()
            .filter(|snapshot| snapshot.keyed)
            .count()
    }

    /// The key capacity of a live replay universe.
    pub(in crate::manager) fn replay_universe_capacity(
        &self,
        handle: SnapshotHandle,
    ) -> Option<usize> {
        let snapshot = &self.snapshots[self.snapshot_index(handle)?];
        snapshot.keyed.then(|| snapshot.keys.capacity())
    }

    /// Adopt a member's captured proof, empty or not, for a paced reconcile.
    /// Its admitted keys stay as they are and no universe is built: the
    /// reconcile reads admission from this proof, sweeps it, and commits its
    /// pages into it as an initial replay's do. `false` without a complete
    /// proof.
    pub(in crate::manager) fn begin_reconcile(&mut self, peer: PeerId) -> bool {
        let Ok(index) = self.index(peer) else {
            return false;
        };
        let record = &mut self.records[index];
        if record.state != State::Complete {
            return false;
        }
        record.initial_replay = true;
        true
    }

    /// Where an initial replay over `rows` table rows fits: in the daemon
    /// budget now, only once the live initial replays release theirs, or
    /// under neither limit. A member of a join cohort that already holds the
    /// `shared` universe needs its own mask and header alone; any other
    /// replay also pays for its keyed universe.
    pub(in crate::manager) fn initial_replay_room(
        &self,
        rows: usize,
        shared: Option<SnapshotHandle>,
    ) -> ReplayRoom {
        let shared = shared.and_then(|handle| self.replay_universe_capacity(handle));
        let rows = shared.unwrap_or(rows);
        let growth = if self.snapshots.len() == self.snapshots.capacity() {
            (self.snapshots.capacity() * 2).max(1) * size_of::<Snapshot>() + size_of::<Snapshots>()
        } else {
            0
        };
        let Some((member, universe)) = Self::shared_words(rows).ok().and_then(|words| {
            Some((
                words
                    .checked_mul(size_of::<u64>())?
                    .checked_add(size_of::<Record>() + size_of::<Words>())?,
                rows.checked_mul(size_of::<Key>())?
                    .checked_add(key_index_len(rows).checked_mul(size_of::<u32>())?)?
                    .checked_add(
                        2 * size_of::<Snapshot>() + size_of::<Keys>() + size_of::<SlotPositions>(),
                    )?,
            ))
        }) else {
            return ReplayRoom::Never;
        };
        let Some(alone) = member.checked_add(universe) else {
            return ReplayRoom::Never;
        };
        // The universe counts toward each member's own limit, shared or not.
        if alone > self.peer_limit {
            return ReplayRoom::Never;
        }
        let now = if shared.is_some() {
            member
        } else {
            alone.saturating_add(growth)
        };
        if self.used.saturating_add(now) <= self.daemon_limit {
            return ReplayRoom::Fits;
        }
        // Once the live replays end, their universes go with them: each is
        // counted once, however many members share it.
        let replays: usize = self
            .records
            .iter()
            .filter(|record| record.initial_replay)
            .map(Record::charge)
            .chain(
                self.snapshots
                    .iter()
                    .filter(|snapshot| snapshot.keyed)
                    .map(Snapshot::charge),
            )
            .sum();
        let after = alone.saturating_add(growth);
        if self.used.saturating_sub(replays).saturating_add(after) <= self.daemon_limit {
            ReplayRoom::AfterReplays
        } else {
            ReplayRoom::Never
        }
    }

    /// Append one page of the group table's keys, in key order, to a replay
    /// universe every member of its join cohort shares. Group churn can
    /// shrink the table or add a prefix behind the walk. Such keys stay in a
    /// member's ordinary sparse overlay when first admitted, and so does a
    /// key a member's overlay already holds: a universe key is admitted by
    /// its mask bit alone. `false` once the universe is gone.
    pub(in crate::manager) fn extend_initial_replay_universe(
        &mut self,
        handle: SnapshotHandle,
        keys: impl Iterator<Item = Key>,
        enrolled: &[PeerId],
    ) -> bool {
        let Some(snapshot) = self
            .snapshot_index(handle)
            .filter(|index| self.snapshots[*index].keyed)
        else {
            return false;
        };
        // A member that fell back mid-walk keeps its record and reference
        // while it is dirty, and its resync, in one turn or adopted by a
        // reconcile, admits keys into its overlay while the others still
        // walk. A universe key must be admitted by its mask bit alone, so a
        // key any such overlay holds stays out of the universe.
        // Only a peer that enrolled with this universe references it.
        let overlays: SmallVec<[usize; 0]> = enrolled
            .iter()
            .filter_map(|peer| self.index(*peer).ok())
            .filter(|&index| {
                let record = &self.records[index];
                record.snapshot == Some(handle) && !record.keys.0.is_empty()
            })
            .collect();
        let records = &self.records;
        let Snapshot {
            keys: universe,
            slot_positions,
            ..
        } = &mut self.snapshots[snapshot];
        for key in keys {
            if universe.len() == universe.capacity() {
                break;
            }
            if universe.last().is_some_and(|last| key <= *last)
                || overlays
                    .iter()
                    .any(|&index| records[index].keys.0.binary_search(&key).is_ok())
            {
                continue;
            }
            // The pool's capacity is below the empty-bucket marker.
            let position = u32::try_from(universe.len()).expect("checked at creation");
            index_key(slot_positions, &key, position);
            universe.push(key);
        }
        true
    }

    /// Each unicast prefix's position, at path ID zero, in replay universe
    /// `handle`, or the empty marker for a key the universe lacks. One
    /// lookup per key then serves every member that shares the universe.
    pub(in crate::manager) fn replay_universe_positions(
        &self,
        handle: SnapshotHandle,
        prefixes: impl Iterator<Item = Prefix>,
    ) -> Vec<u32> {
        let (universe, index) = Self::universe(&self.snapshots, Some(handle));
        prefixes
            .map(|prefix| {
                universe_position(universe, index, &Key::Unicast(prefix, 0))
                    .and_then(|position| u32::try_from(position).ok())
                    .unwrap_or(EMPTY_SLOT)
            })
            .collect()
    }

    pub(in crate::manager) fn initial_replay_sparse_len(&self, peer: PeerId) -> Option<usize> {
        let record = &self.records[self.index(peer).ok()?];
        record.initial_replay.then_some(record.keys.0.len())
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
        self.entries -= record.entries();
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
        record.initial_replay = false;
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
        peer: PeerId,
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
                    self.entries += 1;
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
        self.entries += 1;
        Ok(())
    }

    pub(in crate::manager) fn seal_capture_with_checkpoint(
        &mut self,
        peer: PeerId,
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
        let prior = keys.len();
        Self::sort_keys(keys, checkpoint);
        self.entries -= prior - keys.len();
        self.records[index].state = State::Complete;
        Ok(())
    }

    fn complete_index(
        &mut self,
        peer: PeerId,
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
        (universe, key_index): (&[Key], &[u32]),
        announcements: A,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<usize, Failure>
    where
        A: Iterator<Item = Key>,
    {
        let mut len = keys.len();
        // One checkpoint per key: a lookup is a few dozen comparisons, far
        // below any readiness budget, and is not worth a seam per comparison.
        for key in announcements {
            checkpoint(false);
            if universe_position(universe, key_index, &key).is_none()
                && keys.binary_search(&key).is_err()
            {
                len = len.checked_add(1).ok_or_else(Self::overflow)?;
            }
        }
        Ok(len)
    }

    /// Reserve the union with unique, possibly unordered candidates; no withdrawal credit.
    pub(in crate::manager) fn reserve_admitted_with_checkpoint<A>(
        &mut self,
        peer: PeerId,
        announcements: A,
        on_refusal: OnReservationRefusal,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<bool, Failure>
    where
        A: Iterator<Item = Key>,
    {
        let Some(index) = self.complete_index(peer, checkpoint)? else {
            return Ok(false);
        };
        let (universe, key_index) = Self::universe(&self.snapshots, self.records[index].snapshot);
        let len = Self::union_len(
            &self.records[index].keys.0,
            (universe, key_index),
            announcements,
            checkpoint,
        );
        self.reserve_len(index, len, on_refusal, checkpoint)
    }

    /// [`Self::reserve_admitted_with_checkpoint`] for keys the member holds
    /// none of, given each key's position in the member's universe as the
    /// caller resolved it, or `None` for a key it did not resolve. Only a
    /// key outside the universe needs a slot, so no key is looked up. A
    /// key that was not resolved is counted as one.
    pub(in crate::manager) fn reserve_fresh_with_checkpoint(
        &mut self,
        peer: PeerId,
        positions: impl Iterator<Item = Option<u32>>,
        on_refusal: OnReservationRefusal,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<bool, Failure> {
        let Some(index) = self.complete_index(peer, checkpoint)? else {
            return Ok(false);
        };
        let outside = positions
            .filter(|position| position.is_none_or(|position| position == EMPTY_SLOT))
            .count();
        let len = self.records[index]
            .keys
            .0
            .len()
            .checked_add(outside)
            .ok_or_else(Self::overflow);
        self.reserve_len(index, len, on_refusal, checkpoint)
    }

    fn reserve_len(
        &mut self,
        index: usize,
        len: Result<usize, Failure>,
        on_refusal: OnReservationRefusal,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<bool, Failure> {
        let record = &self.records[index];
        let result = len
            .and_then(|len| {
                // An initial replay also reserves one slot per new key, where
                // its page merges into the sorted overlay.
                let scratch = if record.initial_replay {
                    len - record.keys.0.len()
                } else {
                    0
                };
                len.checked_add(scratch).ok_or_else(Self::overflow)
            })
            .and_then(|capacity| self.grow_keys(index, capacity, checkpoint));
        if let Err(error) = result {
            // A replay refuses the envelope before enqueue. Its old proof is
            // still exact and may be the sole record of a queued withdrawal.
            if on_refusal == OnReservationRefusal::StopBeforeSend {
                return Err(error);
            }
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
        (keys, key_index): (&[Key], &[u32]),
        cursor: &mut Option<usize>,
        key: Key,
        paged: bool,
        checkpoint: &mut impl FnMut(bool),
    ) -> Option<usize> {
        // Two repairs can be at opposite ends of the whole replay universe.
        if paged {
            return universe_position(keys, key_index, &key);
        }
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
    /// Production commits use [`Self::apply_reserved_admitted_with_checkpoint`]
    /// after their pre-send reservation.
    #[cfg(test)]
    pub(in crate::manager) fn apply_admitted_with_checkpoint<A, W>(
        &mut self,
        peer: PeerId,
        announcements: A,
        withdrawals: W,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<bool, Failure>
    where
        A: Clone + Iterator<Item = Key>,
        W: Clone + Iterator<Item = Key>,
    {
        self.apply_admitted_inner(
            peer,
            announcements.map(|key| (key, None)),
            withdrawals,
            true,
            checkpoint,
        )
    }

    /// Apply a sent batch whose announcements are a subset of a set this proof
    /// already reserved, with no proof mutation in between. Unique ANN may be
    /// unordered; W is sorted/unique. It skips a second union count; an
    /// announcement beyond the existing reservation fails the proof closed
    /// instead of growing it.
    pub(in crate::manager) fn apply_reserved_admitted_with_checkpoint<A, W>(
        &mut self,
        peer: PeerId,
        announcements: A,
        withdrawals: W,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<bool, Failure>
    where
        A: Clone + Iterator<Item = Key>,
        W: Clone + Iterator<Item = Key>,
    {
        self.apply_admitted_inner(
            peer,
            announcements.map(|key| (key, None)),
            withdrawals,
            false,
            checkpoint,
        )
    }

    /// [`Self::apply_reserved_admitted_with_checkpoint`] for announcements
    /// alone, each with its position in the member's universe as the caller
    /// resolved it (the empty marker where the universe lacks the key), or
    /// `None` for a key it did not resolve. A resolved universe key sets
    /// its mask bit without a lookup.
    pub(in crate::manager) fn apply_reserved_positioned_with_checkpoint<A>(
        &mut self,
        peer: PeerId,
        announcements: A,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<bool, Failure>
    where
        A: Clone + Iterator<Item = (Key, Option<u32>)>,
    {
        self.apply_admitted_inner(peer, announcements, std::iter::empty(), false, checkpoint)
    }

    fn apply_admitted_inner<A, W>(
        &mut self,
        peer: PeerId,
        announcements: A,
        withdrawals: W,
        reserve: bool,
        checkpoint: &mut impl FnMut(bool),
    ) -> Result<bool, Failure>
    where
        A: Clone + Iterator<Item = (Key, Option<u32>)>,
        W: Clone + Iterator<Item = Key>,
    {
        let Some(index) = self.complete_index(peer, checkpoint)? else {
            return Ok(false);
        };
        let (universe, key_index) = Self::universe(&self.snapshots, self.records[index].snapshot);
        let record = &self.records[index];
        let mut previous = None;
        let mut base_cursor = None;
        let mut sparse_cursor = None;
        for key in withdrawals.clone() {
            checkpoint(false);
            if previous.is_some_and(|prior| prior >= key) {
                return Err(self.fail(index, self.missing_proof(peer), checkpoint));
            }
            let admitted = if let Some(position) = Self::sorted_match(
                (universe, key_index),
                &mut base_cursor,
                key,
                record.initial_replay,
                checkpoint,
            ) {
                record.words[position / 64] & (1_u64 << (position % 64)) != 0
            } else {
                Self::sorted_match(
                    (&record.keys.0, &[]),
                    &mut sparse_cursor,
                    key,
                    record.initial_replay,
                    checkpoint,
                )
                .is_some()
            };
            if !admitted {
                return Err(self.fail(index, self.missing_proof(peer), checkpoint));
            }
            previous = Some(key);
        }
        if reserve
            && !self.reserve_admitted_with_checkpoint(
                peer,
                announcements.clone().map(|(key, _)| key),
                OnReservationRefusal::ContinueWithFallback,
                checkpoint,
            )?
        {
            return Ok(false);
        }
        let (universe, key_index) = Self::universe(&self.snapshots, self.records[index].snapshot);
        let record = &mut self.records[index];
        let prior = record.entries();
        // Every key the mutation touches passes a checkpoint.
        let mut visits = 0;
        let applied = Self::apply_reserved_keys(
            record,
            (universe, key_index),
            announcements,
            withdrawals,
            &mut |slice| {
                visits += 1;
                checkpoint(slice);
            },
        );
        #[cfg(test)]
        crate::manager::slice_timing::record_work("admitted_proof_visits", visits);
        #[cfg(not(test))]
        let _ = visits;
        self.entries = self.entries - prior + record.entries();
        if !applied {
            return Err(self.fail(index, self.missing_proof(peer), checkpoint));
        }
        Ok(true)
    }

    fn apply_reserved_keys<A, W>(
        record: &mut Record,
        (universe, key_index): (&[Key], &[u32]),
        announcements: A,
        withdrawals: W,
        checkpoint: &mut impl FnMut(bool),
    ) -> bool
    where
        A: Iterator<Item = (Key, Option<u32>)>,
        W: Clone + Iterator<Item = Key>,
    {
        // Replay only after complete validation and reservation. Each direct
        // position is retained for clearing; no matched-position allocation.
        let mut base_cursor = None;
        for key in withdrawals.clone() {
            checkpoint(false);
            if let Some(position) = Self::sorted_match(
                (universe, key_index),
                &mut base_cursor,
                key,
                record.initial_replay,
                checkpoint,
            ) {
                record.words[position / 64] &= !(1_u64 << (position % 64));
                record.masked -= 1;
            }
        }
        let merge_tail = record.initial_replay;
        let keys = &mut record.keys.0;
        Self::remove_sorted_keys(keys, withdrawals, checkpoint);
        let old_len = keys.len();
        let singleton = announcements.size_hint().1.is_some_and(|upper| upper <= 1);
        let mut needs_sort = false;
        for (key, known) in announcements {
            checkpoint(false);
            let position = match known {
                // The caller resolved the key against this universe.
                Some(position) => (position != EMPTY_SLOT).then_some(position as usize),
                None => universe_position(universe, key_index, &key),
            };
            if let Some(position) = position {
                debug_assert_eq!(universe.get(position), Some(&key));
                let bit = 1_u64 << (position % 64);
                let Some(word) = record.words.get_mut(position / 64) else {
                    return false;
                };
                if *word & bit == 0 {
                    *word |= bit;
                    record.masked += 1;
                }
            } else if singleton {
                // One search and one move of the keys above it: a low key
                // costs no per-key work however large the proof.
                let Err(position) = keys.binary_search(&key) else {
                    continue;
                };
                if keys.len() == keys.capacity() {
                    return false;
                }
                keys.insert(position, key);
            } else if keys[..old_len].binary_search(&key).is_err() {
                if keys.len() == keys.capacity() {
                    return false;
                }
                // Sorted appends preserve the proof without a full key walk.
                needs_sort |= keys.last().is_some_and(|last| *last >= key);
                keys.push(key);
            }
        }
        if needs_sort {
            // An initial replay's overlay grows a page per commit. Its
            // reserved scratch slots let the page merge into the sorted run
            // in work linear in the overlay, without allocating; a whole
            // re-sort per page would be quadratic over the join.
            if merge_tail && keys.capacity() - keys.len() >= keys.len() - old_len {
                Self::merge_sorted_tail(keys, old_len, checkpoint);
            } else {
                Self::sort_keys(keys, checkpoint);
            }
        }
        true
    }

    /// Remove the sorted, unique `withdrawals` from sorted `keys`. Each one
    /// costs a search, so a page of withdrawals touches a page of keys
    /// however large the proof; the keys after the first removal shift
    /// once, segment by segment.
    fn remove_sorted_keys(
        keys: &mut Keys,
        withdrawals: impl Iterator<Item = Key>,
        checkpoint: &mut impl FnMut(bool),
    ) {
        // Keys before `read` are settled; the kept ones end at `write`.
        let (mut read, mut write) = (0, None);
        for key in withdrawals {
            checkpoint(false);
            let Ok(found) = keys[read..].binary_search(&key) else {
                continue;
            };
            let at = read + found;
            let to = write.unwrap_or(read);
            keys.copy_within(read..at, to);
            write = Some(to + at - read);
            read = at + 1;
        }
        if let Some(to) = write {
            let len = keys.len();
            keys.copy_within(read..len, to);
            keys.truncate(to + len - read);
        }
    }

    /// Merge the unsorted, unique keys after `old_len` into the sorted run
    /// before it. The capacity holds a copy of the tail, so this allocates
    /// nothing. Each tail key finds its place by search, so a page of new
    /// keys touches a page of keys however large the run; the run keys above
    /// the smallest one shift once, segment by segment.
    fn merge_sorted_tail(keys: &mut Keys, old_len: usize, checkpoint: &mut impl FnMut(bool)) {
        checkpoint(true);
        keys[old_len..].sort_unstable_by(|left, right| {
            checkpoint(false);
            left.cmp(right)
        });
        let len = keys.len();
        for index in old_len..len {
            checkpoint(false);
            let key = keys[index];
            keys.push(key);
        }
        // Fill [0, len) from the back: the run is [0, run), the placed keys
        // [end, len), and the tail copy waits at [len, len + tail).
        let (mut run, mut tail, mut end) = (old_len, len - old_len, len);
        while tail > 0 {
            checkpoint(false);
            let next = keys[len + tail - 1];
            let at = keys[..run].partition_point(|prior| *prior < next);
            let duplicate = (at < run && keys[at] == next) || (end < len && keys[end] == next);
            keys.copy_within(at..run, end - (run - at));
            end -= run - at;
            run = at;
            if !duplicate {
                end -= 1;
                keys[end] = next;
            }
            tail -= 1;
        }
        // A dropped duplicate leaves a gap between the run and the placed keys.
        keys.copy_within(end..len, run);
        keys.truncate(run + len - end);
        checkpoint(true);
    }

    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "map-shaped accessor keeps the borrowed-key signature its callers share with HashMap"
    )]
    pub(in crate::manager) fn remove_with_checkpoint(
        &mut self,
        peer: &PeerId,
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
    pub(in crate::manager) fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub(in crate::manager) fn begin_capture(&mut self, peer: PeerId) -> Result<bool, Failure> {
        self.begin_capture_with_checkpoint(peer, &mut |_| {})
    }

    pub(in crate::manager) fn push_capture(
        &mut self,
        peer: PeerId,
        key: Key,
    ) -> Result<(), Failure> {
        self.push_capture_with_checkpoint(peer, key, &mut |_| {})
    }

    pub(in crate::manager) fn seal_capture(&mut self, peer: PeerId) -> Result<(), Failure> {
        self.seal_capture_with_checkpoint(peer, &mut |_| {})
    }

    pub(in crate::manager) fn insert_empty(&mut self, peer: PeerId) -> Result<(), Failure> {
        self.insert_empty_with_checkpoint(peer, &mut |_| {})
    }

    pub(in crate::manager) fn reserve_admitted<A: Iterator<Item = Key>>(
        &mut self,
        peer: PeerId,
        announcements: A,
    ) -> Result<bool, Failure> {
        self.reserve_admitted_with_checkpoint(
            peer,
            announcements,
            OnReservationRefusal::ContinueWithFallback,
            &mut |_| {},
        )
    }

    pub(in crate::manager) fn apply_admitted<A, W>(
        &mut self,
        peer: PeerId,
        announcements: A,
        withdrawals: W,
    ) -> Result<bool, Failure>
    where
        A: Clone + Iterator<Item = Key>,
        W: Clone + Iterator<Item = Key>,
    {
        self.apply_admitted_with_checkpoint(peer, announcements, withdrawals, &mut |_| {})
    }

    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "map-shaped accessor keeps the borrowed-key signature its callers share with HashMap"
    )]
    pub(in crate::manager) fn remove(&mut self, peer: &PeerId) -> bool {
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
    use std::net::IpAddr;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use rustbgpd_wire::{Ipv4Prefix, Ipv6Prefix, RouteDistinguisher, VpnPrefix};

    use super::*;

    fn peer(n: u8) -> PeerId {
        PeerId::from_addr(IpAddr::V4(Ipv4Addr::new(192, 0, 2, n)))
    }

    fn key(n: u8) -> Key {
        Key::Unicast(
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, n), 32)),
            u32::from(n),
        )
    }

    /// The hand-written `Key` order must equal the derived order it replaced:
    /// sorted proofs and their binary searches depend on it.
    #[test]
    fn key_order_matches_derived_order() {
        #[derive(PartialEq, Eq, PartialOrd, Ord)]
        enum Derived {
            Unicast(Prefix, u32),
            Vpn(VpnRouteKey, u32),
        }
        let derived = |key: &Key| match *key {
            Key::Unicast(prefix, id) => Derived::Unicast(prefix, id),
            Key::Vpn(vpn, id) => Derived::Vpn(vpn, id),
        };
        let rds = [
            [0; 8],
            [0, 0, 0, 0, 0, 0, 0, 1],
            [0, 0, 0, 0, 0, 0, 0, 0xff],
            [1, 0, 0, 0, 0, 0, 0, 0],
            [0x80, 0, 0, 0, 0, 0, 0, 0],
            [0xff; 8],
        ]
        .map(RouteDistinguisher);
        let v4 = |a, b, c, d, len| VpnPrefix::v4(Ipv4Addr::new(a, b, c, d), len).unwrap();
        let v6 = |addr: u128, len| VpnPrefix::v6(Ipv6Addr::from(addr), len).unwrap();
        let prefixes = [
            v4(0, 0, 0, 0, 0),
            v4(0, 0, 0, 255, 32),
            v4(1, 0, 0, 0, 8),
            v4(10, 0, 0, 0, 8),
            v4(10, 0, 0, 0, 24),
            v4(10, 0, 1, 0, 24),
            v4(128, 0, 0, 0, 1),
            v4(255, 255, 255, 255, 32),
            v6(0, 0),
            v6(1, 128),
            v6(0x2001_0db8 << 96, 32),
            v6(0x2001_0db8 << 96, 64),
            v6(0x2001_0db8_0000_0001 << 64, 64),
            v6(1 << 127, 1),
            v6(u128::MAX, 128),
        ];
        let mut keys = Vec::new();
        for route_distinguisher in rds {
            for prefix in prefixes {
                for path_id in [0, 1, u32::MAX] {
                    let vpn = VpnRouteKey {
                        route_distinguisher,
                        prefix,
                    };
                    keys.push(Key::Vpn(vpn, path_id));
                }
            }
        }
        for (n, path_id) in [(0, 0), (1, 0), (1, 1), (255, u32::MAX)] {
            keys.push(Key::Unicast(
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, n), 32)),
                path_id,
            ));
        }
        keys.push(Key::Unicast(
            Prefix::V6(Ipv6Prefix::new(Ipv6Addr::from(1), 128)),
            0,
        ));
        let unicast = [
            (Ipv4Addr::UNSPECIFIED, 0),
            (Ipv4Addr::new(0, 0, 0, 255), 32),
            (Ipv4Addr::new(1, 0, 0, 0), 8),
            (Ipv4Addr::new(10, 0, 0, 0), 24),
            (Ipv4Addr::new(10, 0, 1, 0), 24),
            (Ipv4Addr::new(128, 0, 0, 0), 1),
            (Ipv4Addr::BROADCAST, 32),
        ]
        .map(|(addr, len)| Prefix::V4(Ipv4Prefix::new(addr, len)))
        .into_iter()
        .chain(
            [
                (0, 0),
                (1, 128),
                (0x2001_0db8 << 96, 32),
                (0x2001_0db8 << 96, 64),
                (1 << 127, 1),
                (u128::MAX, 128),
            ]
            .map(|(addr, len)| Prefix::V6(Ipv6Prefix::new(Ipv6Addr::from(addr), len))),
        );
        for prefix in unicast {
            for path_id in [0, 1, u32::MAX] {
                keys.push(Key::Unicast(prefix, path_id));
            }
        }
        for left in &keys {
            for right in &keys {
                assert_eq!(
                    left.cmp(right),
                    derived(left).cmp(&derived(right)),
                    "{left:?} vs {right:?}"
                );
                assert_eq!(left.partial_cmp(right), Some(left.cmp(right)));
            }
        }
    }

    fn capture(ledger: &mut AdmittedRecovery, peer: PeerId, keys: &[Key]) {
        assert!(ledger.begin_capture(peer).unwrap());
        for &key in keys {
            ledger.push_capture(peer, key).unwrap();
        }
        ledger.seal_capture(peer).unwrap();
    }

    #[test]
    fn prefix_path_count_uses_only_its_masked_and_sparse_range() {
        let v4 = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24));
        let v6 = Prefix::V6(rustbgpd_wire::Ipv6Prefix::new(
            "2001:db8::".parse().unwrap(),
            64,
        ));
        let mut universe: Vec<_> = (0..4096_u32)
            .map(|n| Key::Unicast(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(n), 32)), 0))
            .collect();
        universe.extend([
            Key::Unicast(v4, 1),
            Key::Unicast(v4, 2),
            Key::Unicast(v6, 1),
        ]);
        universe.sort_unstable();
        let mut words = vec![0; universe.len().div_ceil(64)];
        for key in [Key::Unicast(v4, 2), Key::Unicast(v6, 1)] {
            let index = universe.binary_search(&key).unwrap();
            words[index / 64] |= 1_u64 << (index % 64);
        }
        let sparse = [Key::Unicast(v4, 3)];
        let view = AdmittedKeyView {
            universe: &universe,
            index: &[],
            words: &words,
            sparse: &sparse,
            masked: 2,
        };
        let mut visits = 0;
        assert_eq!(view.unicast_prefix_paths(v4, &mut |_| visits += 1), 2);
        assert_eq!(view.unicast_prefix_paths(v6, &mut |_| visits += 1), 1);
        assert_eq!(
            view.unicast_prefix_paths(
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0)),
                &mut |_| visits += 1
            ),
            0
        );
        assert!(
            visits < 100,
            "range count must not walk the unrelated 4096-key universe: {visits}"
        );
    }

    // A dirty member's captured proof is what it was sent. A reconcile
    // adopts it as it stands: no new universe, no new charge, and its
    // commits keep admission exact.
    #[test]
    fn a_reconcile_adopts_a_captured_proof_as_it_stands() {
        let mut ledger = AdmittedRecovery::new();
        let who = peer(1);
        assert!(!ledger.begin_reconcile(who), "no proof");
        assert!(ledger.begin_capture(who).unwrap());
        for n in [3, 9, 12] {
            ledger.push_capture(who, key(n)).unwrap();
        }
        assert!(!ledger.begin_reconcile(who), "a capture still open");
        ledger.seal_capture(who).unwrap();
        let charge = ledger.bytes();
        assert!(ledger.begin_reconcile(who));
        assert_eq!(ledger.initial_replay_sparse_len(who), Some(3));
        assert_eq!(ledger.bytes(), charge);
        let (swept, next, _) = ledger.get(&who).unwrap().sweep_unicast(None, 2);
        assert_eq!(swept, [key(3), key(9)]);
        let (swept, next, _) = ledger.get(&who).unwrap().sweep_unicast(next, 2);
        assert_eq!((swept.as_slice(), next), (&[key(12)][..], None));
        ledger.reserve_admitted(who, [key(5)].into_iter()).unwrap();
        ledger
            .apply_reserved_admitted_with_checkpoint(
                who,
                [key(5)].into_iter(),
                [key(9)].into_iter(),
                &mut |_| {},
            )
            .unwrap();
        assert_eq!(
            ledger.get(&who).unwrap().iter().collect::<Vec<_>>(),
            [key(3).into(), key(5).into(), key(12).into()]
        );
        assert!(ledger.remove(&who));
        assert_eq!(ledger.bytes(), size_of::<AdmittedRecovery>());
    }

    // A reconcile's commits edit an adopted flat proof a page at a time,
    // and its repairs admit single new keys low in it. Each commit touches
    // about its own keys, from 8 to 32 pages of proof, and the proof stays
    // exact.
    #[test]
    fn a_reconcile_page_edits_a_page_of_a_flat_proof_from_8_to_32_pages() {
        const PAGE: u32 = 1_024;
        let wide = |i: u32| {
            Key::Unicast(
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(0x0a00_0000 + i), 32)),
                0,
            )
        };
        let mut peaks = Vec::new();
        for pages in [8, 32] {
            let mut ledger = AdmittedRecovery::new();
            let who = peer(1);
            assert!(ledger.begin_capture(who).unwrap());
            // Even addresses are admitted; odd ones arrive during the reconcile.
            let mut model = std::collections::BTreeSet::new();
            for i in 0..pages * PAGE {
                ledger.push_capture(who, wide(2 * i)).unwrap();
                model.insert(wide(2 * i));
            }
            ledger.seal_capture(who).unwrap();
            assert!(ledger.begin_reconcile(who));
            let mut peak = 0;
            for round in 0..8 {
                // A page of withdrawals across the whole proof, and new keys
                // across it too.
                let withdrawals: Vec<Key> =
                    (0..PAGE).map(|j| wide(2 * (j * pages + round))).collect();
                let announcements: Vec<Key> = (0..64)
                    .map(|j| wide(2 * (j * pages * PAGE / 64 + round) + 1))
                    .collect();
                ledger
                    .reserve_admitted(who, announcements.iter().copied())
                    .unwrap();
                let mut visits = 0;
                assert!(
                    ledger
                        .apply_reserved_admitted_with_checkpoint(
                            who,
                            announcements.iter().copied(),
                            withdrawals.iter().copied(),
                            &mut |_| visits += 1,
                        )
                        .unwrap()
                );
                peak = usize::max(peak, visits);
                for key in &withdrawals {
                    model.remove(key);
                }
                model.extend(announcements);
                // A repair page that admits one new key below the rest of
                // the proof, a page of times over.
                for low in 0..PAGE {
                    let key = wide(2 * (round * PAGE + low) + 1);
                    if model.contains(&key) {
                        continue;
                    }
                    ledger.reserve_admitted(who, std::iter::once(key)).unwrap();
                    let mut visits = 0;
                    assert!(
                        ledger
                            .apply_reserved_admitted_with_checkpoint(
                                who,
                                std::iter::once(key),
                                std::iter::empty(),
                                &mut |_| visits += 1,
                            )
                            .unwrap()
                    );
                    peak = usize::max(peak, visits);
                    model.insert(key);
                }
            }
            eprintln!("pages={pages}: peak proof visits per commit={peak}");
            let proof: Vec<ExactExportKey> = ledger.get(&who).unwrap().iter().collect();
            let expected: Vec<ExactExportKey> = model.into_iter().map(Into::into).collect();
            assert_eq!(proof, expected, "pages={pages}: the proof");
            // Validation, the mask lookup and the edit: a few checkpoints
            // per key of the commit, none per key of the proof.
            assert!(
                peak <= 4 * usize::try_from(PAGE + 64).unwrap(),
                "pages={pages}: a commit touched {peak} proof keys"
            );
            peaks.push(peak);
        }
        assert!(
            peaks[1] <= peaks[0] + 64,
            "proof edits grew with the proof: {peaks:?}"
        );
    }

    #[test]
    fn initial_replay_pages_preserve_actual_membership_and_credit() {
        let mut ledger = AdmittedRecovery::new();
        let who = peer(1);
        let rows = 4_096;
        let key = slot_key;
        ledger.insert_empty(who).unwrap();
        let universe = ledger
            .begin_initial_replay(who, rows, None)
            .unwrap()
            .unwrap();
        let seed_charge = ledger.bytes();
        // An ordinary announcement before the preparation cursor sees this
        // identity stays sparse. Preparation must not mirror it in the mask.
        ledger
            .apply_admitted(who, [key(17)].into_iter(), [].into_iter())
            .unwrap();
        for start in (0..rows).step_by(63) {
            assert!(ledger.extend_initial_replay_universe(
                universe,
                (start..(start + 63).min(rows)).map(|n| key(u32::try_from(n).unwrap())),
                &[who],
            ));
        }
        let prepared = ledger.get(&who).unwrap();
        assert_eq!(prepared.iter().collect::<Vec<_>>(), [key(17).into()]);
        // Unordered partial admission, including one prefix added behind the
        // cursor after preparation. Non-admitted snapshot positions stay clear.
        let announce = [key(4095), key(2), key(17), key(4096)];
        ledger.reserve_admitted(who, announce.into_iter()).unwrap();
        let charge = ledger.bytes();
        assert!(charge >= seed_charge);
        ledger.fail_next_allocation_for_test();
        ledger
            .apply_reserved_admitted_with_checkpoint(
                who,
                [key(4095), key(2), key(4096)].into_iter(),
                [].into_iter(),
                &mut |_| {},
            )
            .unwrap();
        let mut visits = 0;
        ledger
            .apply_reserved_admitted_with_checkpoint(
                who,
                [].into_iter(),
                [key(2), key(4095)].into_iter(),
                &mut |_| visits += 1,
            )
            .unwrap();
        assert!(visits < 64, "two withdrawals scanned {visits} keys");
        let view = ledger.get(&who).unwrap();
        assert_eq!(
            view.iter().collect::<Vec<_>>(),
            [key(17).into(), key(4096).into()]
        );
        assert_eq!(ledger.initial_replay_sparse_len(who), Some(2));
        assert_eq!(ledger.bytes(), charge);
        assert_retained_credit(&ledger);
        assert!(ledger.remove(&who));
        assert_retained_credit(&ledger);
        assert_eq!(ledger.bytes(), size_of::<AdmittedRecovery>());
    }

    /// Checkpoints (one per comparison or visited key) to admit one page of
    /// new prefixes, in hash order, behind a sparse overlay of `sparse` keys.
    fn sparse_page_work(sparse: u32) -> usize {
        const PAGE: u32 = 1_024;
        let mut ledger = AdmittedRecovery::new();
        let who = peer(1);
        ledger.insert_empty(who).unwrap();
        let universe = ledger.begin_initial_replay(who, 64, None).unwrap().unwrap();
        assert!(ledger.extend_initial_replay_universe(universe, (0..64).map(slot_key), &[who]));
        // Even keys above the universe, admitted in order: one sorted run.
        for start in (0..sparse).step_by(PAGE as usize) {
            let page = (start..(start + PAGE).min(sparse)).map(|n| slot_key(1_000 + 2 * n));
            ledger.apply_admitted(who, page, [].into_iter()).unwrap();
        }
        assert_eq!(ledger.initial_replay_sparse_len(who), Some(sparse as usize));
        // Odd keys spread over the overlay, in a scrambled order.
        let page: Vec<_> = (0..PAGE)
            .map(|n| slot_key(1_001 + 2 * ((n * 7_919) % PAGE) * (sparse / PAGE)))
            .collect();
        ledger.reserve_admitted(who, page.iter().copied()).unwrap();
        let mut work = 0;
        ledger
            .apply_reserved_admitted_with_checkpoint(
                who,
                page.into_iter(),
                [].into_iter(),
                &mut |_| work += 1,
            )
            .unwrap();
        assert_eq!(
            ledger.initial_replay_sparse_len(who),
            Some((sparse + PAGE) as usize)
        );
        let view = ledger.get(&who).unwrap();
        let keys: Vec<_> = view.iter().collect();
        assert!(
            keys.windows(2).all(|pair| {
                Key::try_from(&pair[0]).unwrap() < Key::try_from(&pair[1]).unwrap()
            })
        );
        work
    }

    // A page of new prefixes merges into the sorted overlay. Re-sorting the
    // whole overlay per page would cost S log S comparisons, quadratic over
    // a join that keeps adding prefixes.
    #[test]
    fn a_page_of_new_sparse_keys_merges_in_linear_work() {
        for sparse in [16_384, 65_536] {
            let work = sparse_page_work(sparse);
            eprintln!("sparse={sparse}: {work}");
            assert!(
                work <= 4 * sparse as usize + 32 * 1_024,
                "sparse={sparse}: {work} checkpoints"
            );
        }
    }

    // Two members of one join cohort reference one universe. Each admits
    // and withdraws through its own mask and overlay: neither sees the
    // other's keys, a member that fails leaves the other's proof whole, and
    // the last reference retires the universe with all its credit.
    #[test]
    fn cohort_members_share_a_universe_and_keep_their_own_admission() {
        let mut ledger = AdmittedRecovery::new();
        let (a, b) = (peer(1), peer(2));
        let rows = 256_u32;
        let key = slot_key;
        ledger.insert_empty(a).unwrap();
        ledger.insert_empty(b).unwrap();
        let seeded = ledger.bytes();
        let universe = ledger
            .begin_initial_replay(a, rows as usize, None)
            .unwrap()
            .unwrap();
        let first = ledger.bytes() - seeded;
        assert_eq!(
            ledger.begin_initial_replay(b, 1, Some(universe)).unwrap(),
            Some(universe)
        );
        // The second member pays for one mask bit per universe key.
        assert_eq!(ledger.bytes() - seeded - first, rows as usize / 8);
        assert!(first - rows as usize / 8 >= rows as usize * size_of::<Key>());
        assert_eq!(ledger.snapshots.len(), 1);
        assert!(ledger.extend_initial_replay_universe(universe, (0..rows).map(key), &[a, b]));

        // The same keys with different outcomes, plus one outside the universe.
        let outside = key(rows + 7);
        ledger
            .apply_admitted(a, [key(1), key(2), outside].into_iter(), [].into_iter())
            .unwrap();
        ledger
            .apply_admitted(b, [key(2), key(3)].into_iter(), [].into_iter())
            .unwrap();
        ledger
            .apply_admitted(a, [].into_iter(), [key(2)].into_iter())
            .unwrap();
        let admitted = |ledger: &AdmittedRecovery, who| {
            ledger
                .get(&who)
                .unwrap()
                .iter()
                .collect::<Vec<ExactExportKey>>()
        };
        assert_eq!(admitted(&ledger, a), [key(1).into(), outside.into()]);
        assert_eq!(admitted(&ledger, b), [key(2).into(), key(3).into()]);
        assert!(!ledger.get(&b).unwrap().contains(&outside.into()));
        assert_retained_credit(&ledger);

        // B withdraws a key only A admitted: B's proof fails closed alone.
        assert_eq!(
            ledger
                .apply_admitted(b, [].into_iter(), [key(1)].into_iter())
                .unwrap_err()
                .cause,
            FailureCause::MissingProof
        );
        assert_eq!(admitted(&ledger, a), [key(1).into(), outside.into()]);
        assert_eq!(
            ledger.replay_universe_capacity(universe),
            Some(rows as usize)
        );
        assert_retained_credit(&ledger);

        // A late joiner naming the live universe shares it; a retired one
        // is replaced, never revived.
        let late = peer(3);
        ledger.insert_empty(late).unwrap();
        assert_eq!(
            ledger
                .begin_initial_replay(late, 1, Some(universe))
                .unwrap(),
            Some(universe)
        );
        assert_eq!(admitted(&ledger, late), []);
        assert!(ledger.remove(&a));
        assert_eq!(
            ledger.replay_universe_capacity(universe),
            Some(rows as usize)
        );
        assert!(ledger.remove(&late));
        assert_eq!(ledger.replay_universe_capacity(universe), None);
        assert!(ledger.snapshots.is_empty());
        assert_retained_credit(&ledger);
        ledger.insert_empty(late).unwrap();
        let fresh = ledger
            .begin_initial_replay(late, 64, Some(universe))
            .unwrap()
            .unwrap();
        assert_ne!(fresh, universe);
        assert_eq!(ledger.replay_universe_capacity(fresh), Some(64));
    }

    // A joiner whose cohort already holds its universe needs room for its
    // mask alone, where a first member needs the whole universe.
    #[test]
    fn a_cohort_member_fits_where_a_second_universe_would_not() {
        let rows = 4_096;
        let mut ledger = AdmittedRecovery::new();
        ledger.insert_empty(peer(1)).unwrap();
        let before = ledger.bytes();
        let universe = ledger.begin_initial_replay(peer(1), rows, None).unwrap();
        let table = ledger.bytes() - before;
        ledger.set_test_daemon_limit(ledger.bytes() + table / 2);
        assert_eq!(
            ledger.initial_replay_room(rows, None),
            ReplayRoom::AfterReplays
        );
        assert_eq!(ledger.initial_replay_room(rows, universe), ReplayRoom::Fits);
        // Sixty-three more members fit the room half a table leaves.
        for n in 2..=64 {
            ledger.insert_empty(peer(n)).unwrap();
            assert_eq!(
                ledger
                    .begin_initial_replay(peer(n), rows, universe)
                    .unwrap(),
                universe
            );
        }
        assert_eq!(ledger.snapshots.len(), 1);
        assert_retained_credit(&ledger);
    }

    #[test]
    fn initial_replay_refusal_leaves_the_empty_seed_for_fallback() {
        let who = peer(1);
        for fault in 0..3 {
            let mut ledger = AdmittedRecovery::new();
            ledger.insert_empty(who).unwrap();
            let before = ledger.bytes();
            ledger.allocation_countdown = Some(fault);
            assert_eq!(
                ledger
                    .begin_initial_replay(who, 256, None)
                    .unwrap_err()
                    .cause,
                FailureCause::AllocationFailure
            );
            assert_eq!(ledger.bytes(), before);
            assert!(ledger.get(&who).unwrap().is_empty());
            assert_eq!(ledger.initial_replay_sparse_len(who), None);
            assert_retained_credit(&ledger);
        }
        let mut ledger = AdmittedRecovery::with_test_limits(4096, DAEMON_LIMIT_BYTES);
        ledger.insert_empty(who).unwrap();
        let before = ledger.bytes();
        assert_eq!(
            ledger
                .begin_initial_replay(who, 100_000, None)
                .unwrap_err()
                .cause,
            FailureCause::PeerLimit
        );
        assert_eq!(ledger.bytes(), before);
        assert!(ledger.get(&who).unwrap().is_empty());
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
    fn reserved_apply_commits_within_the_reservation_and_fails_closed_beyond_it() {
        let mut ledger = AdmittedRecovery::new();
        capture(&mut ledger, peer(1), &[key(1)]);
        ledger
            .reserve_admitted(peer(1), [key(2), key(3)].into_iter())
            .unwrap();
        let peak = ledger.peak_bytes();
        ledger.fail_next_allocation_for_test();
        assert!(
            ledger
                .apply_reserved_admitted_with_checkpoint(
                    peer(1),
                    [key(3)].into_iter(),
                    [key(1)].into_iter(),
                    &mut |_| {},
                )
                .unwrap()
        );
        assert_eq!(
            ledger.owned_proof(&peer(1)).unwrap(),
            [ExactExportKey::from(key(3))].into_iter().collect()
        );
        // Three slots were reserved (one held plus two candidates); key(3)
        // holds one, so a third new key exceeds them.
        let error = ledger
            .apply_reserved_admitted_with_checkpoint(
                peer(1),
                [key(2), key(4), key(5)].into_iter(),
                [].into_iter(),
                &mut |_| {},
            )
            .unwrap_err();
        assert_eq!(error.cause, FailureCause::MissingProof);
        assert!(ledger.fail_next_allocation, "no growth was attempted");
        assert_eq!(ledger.peak_bytes(), peak);
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
        assert_eq!(ledger.entries(), 3);
        ledger
            .reserve_admitted_with_checkpoint(
                peer(1),
                [key(5), key(3), key(4)].iter().copied(),
                OnReservationRefusal::ContinueWithFallback,
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
        ledger.begin_capture(PeerId::from_addr(address)).unwrap();
        let additions = hint
            .and_then(|handle| ledger.snapshot_index(handle))
            .map_or(0, |index| {
                actual
                    .iter()
                    .filter(|key| ledger.snapshots[index].keys.binary_search(key).is_err())
                    .count()
            });
        let shape = (actual.len(), additions);
        let handle = ledger
            .share_capture_with_checkpoint(
                PeerId::from_addr(address),
                hint,
                raw.len(),
                raw.iter().copied(),
                shape,
                &mut |_| {},
            )
            .unwrap()
            .unwrap();
        for key in actual {
            ledger
                .push_capture(PeerId::from_addr(address), *key)
                .unwrap();
        }
        ledger.seal_capture(PeerId::from_addr(address)).unwrap();
        handle
    }

    #[test]
    fn shared_proof_checkpoints_excluded_trailing_keys_and_idempotent_candidates() {
        let mut ledger = AdmittedRecovery::new();
        let raw: Vec<_> = (1..=100).map(key).collect();
        shared_capture(&mut ledger, peer(1).addr(), None, &raw, &raw[..1]);
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
            .reserve_admitted_with_checkpoint(
                peer(1),
                raw.iter().copied(),
                OnReservationRefusal::ContinueWithFallback,
                &mut |force| {
                    if !force {
                        visited += 1;
                    }
                },
            )
            .unwrap();
        assert!(visited >= raw.len());
        assert_eq!(ledger.bytes(), before);
        assert_eq!(ledger.get(&peer(1)).unwrap().len(), 1);
    }

    #[test]
    fn shared_key_storage_is_charged_once_but_each_peer_references_its_full_charge() {
        let mut ledger = AdmittedRecovery::new();
        let raw: Vec<_> = (1..=100).map(key).collect();
        let handle = shared_capture(&mut ledger, peer(1).addr(), None, &raw, &raw);
        let first = ledger.bytes();
        assert_eq!(ledger.entries(), 100);
        let handle2 = shared_capture(&mut ledger, peer(2).addr(), Some(handle), &raw, &raw[..50]);
        assert_eq!(handle, handle2);
        assert_eq!(ledger.entries(), 150);
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
        assert_eq!(ledger.entries(), 50);
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
        let handle = shared_capture(&mut ledger, peer(1).addr(), None, &raw, &[key(1), vpn]);
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
        assert_eq!(ledger.entries(), 3);
        assert_eq!(ledger.records[0].snapshot, Some(handle));
        let error = ledger
            .apply_admitted(peer(1), [].into_iter(), [key(4)].into_iter())
            .unwrap_err();
        assert_eq!(error.cause, FailureCause::MissingProof);
        assert_eq!(ledger.entries(), 0);
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
            peer(1).addr(),
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
            let handle = shared_capture(
                &mut ledger,
                peer(1).addr(),
                None,
                &raw,
                &[key(2), bulk_vpn_key(2)],
            );
            shared_capture(&mut ledger, peer(2).addr(), Some(handle), &raw, &raw);
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
            let handle = shared_capture(
                &mut ledger,
                peer(1).addr(),
                None,
                &raw,
                &[key(2), bulk_vpn_key(2)],
            );
            shared_capture(&mut ledger, peer(2).addr(), Some(handle), &raw, &raw);
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
                    AdmittedRecovery::sorted_match(
                        (&raw, &[]),
                        &mut cursor,
                        key,
                        false,
                        &mut |force| {
                            assert!(!force);
                            comparisons += 1;
                        }
                    ),
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
                    AdmittedRecovery::sorted_match(
                        (&raw, &[]),
                        &mut cursor,
                        key,
                        false,
                        &mut |force| {
                            assert!(!force);
                            comparisons += 1;
                        }
                    ),
                    Some(position),
                );
            }
            assert!(comparisons <= 64, "tiny suffix walked {comparisons} keys");
        }
    }

    #[test]
    fn singleton_sparse_insertion_moves_only_two_high_sentinels() {
        let mut work = Vec::new();
        for count in [64_u32, 256] {
            let key = |n| Key::Unicast(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(n), 32)), 0);
            let all: Vec<_> = (0..count + 2).map(key).collect();
            let mut ledger = AdmittedRecovery::new();
            ledger.insert_empty(peer(1)).unwrap();
            ledger
                .reserve_admitted(peer(1), all.iter().copied())
                .unwrap();
            ledger
                .apply_reserved_admitted_with_checkpoint(
                    peer(1),
                    [key(count), key(count + 1)].into_iter(),
                    [].into_iter(),
                    &mut |_| {},
                )
                .unwrap();
            ledger.fail_next_allocation_for_test();
            let mut visits = 0;
            for n in 0..count {
                // Match production's filtered ANN iterator: lower bound zero,
                // while its upper bound still proves a singleton.
                ledger
                    .apply_reserved_admitted_with_checkpoint(
                        peer(1),
                        [key(n)].into_iter().filter(|_| true),
                        [].into_iter(),
                        &mut |_| visits += 1,
                    )
                    .unwrap();
            }
            assert!(
                ledger.fail_next_allocation,
                "reserved insertion performs no allocation"
            );
            assert_eq!(
                ledger.get(&peer(1)).unwrap().iter().collect::<Vec<_>>(),
                all.into_iter()
                    .map(ExactExportKey::from)
                    .collect::<Vec<_>>()
            );
            work.push(visits);
        }
        eprintln!("two-high-sentinel singleton work: {work:?}");
        assert!(
            work[1] <= work[0] * 8,
            "singleton sparse insertion grew {work:?}"
        );
    }

    #[test]
    fn singleton_sorted_sparse_admission_work_is_linear() {
        let mut work = Vec::new();
        for count in [64_u32, 256] {
            let raw: Vec<_> = (0..count)
                .map(|n| Key::Unicast(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(n), 32)), 0))
                .collect();
            let mut ledger = AdmittedRecovery::new();
            ledger.insert_empty(peer(1)).unwrap();
            ledger
                .reserve_admitted(peer(1), raw.iter().copied())
                .unwrap();
            let before = ledger.bytes();
            ledger.fail_next_allocation_for_test();
            let mut visits = 0;
            for key in &raw {
                ledger
                    .apply_reserved_admitted_with_checkpoint(
                        peer(1),
                        std::iter::once(*key),
                        std::iter::empty(),
                        &mut |_| visits += 1,
                    )
                    .unwrap();
            }
            assert_eq!(
                ledger.get(&peer(1)).unwrap().iter().collect::<Vec<_>>(),
                raw.iter()
                    .copied()
                    .map(ExactExportKey::from)
                    .collect::<Vec<_>>()
            );
            assert_eq!(ledger.bytes(), before);
            assert!(ledger.fail_next_allocation);
            assert!(visits >= raw.len());
            work.push(visits);
        }
        assert!(work[1] <= 8 * work[0], "sparse admission work: {work:?}");
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
            shared_capture(&mut ledger, peer(1).addr(), None, &raw, &masked);
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
        let handle = shared_capture(&mut ledger, peer(1).addr(), None, &raw, &raw);
        let actual = [bulk_vpn_key(2), key(99), key(2)]; // Deliberately unordered.
        // This fixture has one retained key and two known sparse additions.
        let (count, additions) = (actual.len(), 2);
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
            let handle = shared_capture(&mut ledger, peer(1).addr(), None, &raw, &raw);
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
            // The retained unicast key is already masked; both other keys are new.
            let additions = 2;
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
            let actual: Vec<_> = (1..=99).map(key).chain(std::iter::once(key(200))).collect();
            let handle = shared_capture(&mut ledger, peer(1).addr(), None, &raw, &raw);
            ledger.begin_capture(peer(2)).unwrap();
            let before = ledger.bytes();
            ledger.allocation_countdown = Some(stage);
            let error = ledger
                .share_capture_with_checkpoint(
                    peer(2),
                    Some(handle),
                    actual.len(),
                    actual.iter().copied(),
                    (actual.len(), 1),
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
        let first = shared_capture(
            &mut ledger,
            peer(1).addr(),
            None,
            &[key(1), key(2)],
            &[key(1)],
        );
        ledger.remove(&peer(1));
        let next = shared_capture(
            &mut ledger,
            peer(2).addr(),
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
        let handle = shared_capture(&mut ledger, peer(1).addr(), None, &raw, &raw);
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
        let table = slot_table(COUNT);
        let handle = ledger
            .share_group_capture_with_checkpoint(
                peer(1),
                None,
                &table,
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
        assert_eq!(
            ledger.snapshots[0].slot_positions.capacity(),
            COUNT as usize
        );
        assert_retained_credit(&ledger);
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
    fn slot_key(n: u32) -> Key {
        Key::Unicast(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(n), 32)), 0)
    }

    fn slot_route(n: u32) -> Route {
        crate::test_support::make_route(
            Ipv4Prefix::new(Ipv4Addr::from(n), 32),
            Ipv4Addr::new(192, 0, 2, 250),
        )
    }

    fn slot_table(count: u32) -> AdjRibOut {
        let mut table = AdjRibOut::with_capacity(peer(250), count as usize);
        let mut template = slot_route(0);
        for n in (0..count).rev() {
            template.prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(n), 32));
            table.insert(template.clone());
        }
        table
    }

    fn vpn_route(n: u32) -> VpnRibRoute {
        VpnRibRoute {
            nlri: rustbgpd_wire::VpnNlri {
                labels: vec![],
                route_distinguisher: RouteDistinguisher([0, 0, 0xfd, 0xe8, 0, 0, 0, 1]),
                prefix: VpnPrefix::v4(Ipv4Addr::from(n), 32).unwrap(),
            },
            path_id: 0,
            next_hop: peer(250).addr(),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: peer(250),
            attributes: crate::attr_set::AttrSet::new(vec![]),
            received_at: std::time::Instant::now(),
            origin_type: crate::route::RouteOrigin::Ibgp,
            peer_router_id: Ipv4Addr::LOCALHOST,
            is_stale: false,
            is_llgr_stale: false,
        }
    }

    fn vpn_table(count: u32) -> AdjRibOut {
        let mut table = AdjRibOut::new(peer(250));
        for n in 0..count {
            table.insert_vpn(vpn_route(n));
        }
        table
    }

    fn capture_vpn(
        ledger: &mut AdmittedRecovery,
        member: PeerId,
        hint: Option<SnapshotHandle>,
        table: &AdjRibOut,
        sharing: bool,
    ) -> FullCaptureOutcome {
        capture_vpn_where(ledger, member, hint, table, sharing, |_| true)
    }

    fn capture_vpn_where(
        ledger: &mut AdmittedRecovery,
        member: PeerId,
        hint: Option<SnapshotHandle>,
        table: &AdjRibOut,
        sharing: bool,
        admits: impl Fn(&VpnRibRoute) -> bool,
    ) -> FullCaptureOutcome {
        ledger.begin_capture(member).unwrap();
        let outcome = ledger
            .capture_full_old_with_checkpoint(
                member,
                hint,
                table,
                sharing,
                |_| None,
                |route| {
                    let key = route.key();
                    admits(route).then_some(Key::Vpn(key.nlri_key, key.path_id))
                },
                &mut |_| {},
            )
            .unwrap();
        ledger.seal_capture(member).unwrap();
        outcome
    }

    fn vpn_shape(
        ledger: &AdmittedRecovery,
        hint: Option<SnapshotHandle>,
        table: &AdjRibOut,
    ) -> FullCaptureShape {
        ledger
            .full_old_shape_with_checkpoint(
                hint,
                table,
                true,
                |_| None,
                |route| {
                    let key = route.key();
                    Some(Key::Vpn(key.nlri_key, key.path_id))
                },
                &mut |_| {},
            )
            .unwrap()
    }

    fn vpn_exact(n: u32) -> ExactExportKey {
        ExactExportKey::Vpn(vpn_route(n).key())
    }

    #[test]
    fn current_vpn_pool_admits_every_row_without_probing() {
        let mut table = vpn_table(200);
        let mut ledger = AdmittedRecovery::new();
        let anchor = capture_vpn(&mut ledger, peer(1), None, &table, true);
        let hint = anchor.handle;
        assert!(hint.is_some());
        // Replacing an existing route's value keeps the VPN key set current.
        let mut replaced = vpn_route(7);
        replaced.next_hop = peer(9).addr();
        table.insert_vpn(replaced);
        let shape = vpn_shape(&ledger, hint, &table);
        assert_eq!((shape.count, shape.vpn, shape.additions), (200, 200, 0));
        assert_eq!(shape.comparisons, 0, "a current pool needs no VPN probe");
        let warm = capture_vpn(&mut ledger, peer(2), hint, &table, true);
        assert_eq!(warm.handle, hint);
        let proof = ledger.get(&peer(2)).unwrap();
        assert_eq!(proof.len(), 200);
        assert!((0..200).all(|n| proof.contains(&vpn_exact(n))));
        assert!(!proof.contains(&vpn_exact(200)));
        assert_retained_credit(&ledger);
        // A partial projection on a current pool admits only its own rows.
        let partial = capture_vpn_where(&mut ledger, peer(3), hint, &table, true, |route| {
            route.nlri.prefix != VpnPrefix::v4(Ipv4Addr::from(5), 32).unwrap()
        });
        assert_eq!(partial.handle, hint);
        let proof = ledger.get(&peer(3)).unwrap();
        assert_eq!(proof.len(), 199);
        assert!(!proof.contains(&vpn_exact(5)));
        assert!(proof.contains(&vpn_exact(6)));
    }

    #[test]
    fn non_identity_vpn_projection_on_a_current_pool_keeps_an_exact_proof() {
        let table = vpn_table(200);
        let shifted = VpnRibRouteKey {
            path_id: 1,
            ..vpn_route(5).key()
        };
        let shift = |route: &VpnRibRoute| {
            let key = route.key();
            let path_id = key.path_id + u32::from(key == vpn_route(5).key());
            Some(Key::Vpn(key.nlri_key, path_id))
        };
        let mut ledger = AdmittedRecovery::new();
        // Cold: the pool is built during this capture. Warm: it is current.
        let mut hint = None;
        for member in [peer(1), peer(2)] {
            ledger.begin_capture(member).unwrap();
            let outcome = ledger
                .capture_full_old_with_checkpoint(
                    member,
                    hint,
                    &table,
                    true,
                    |_| None,
                    shift,
                    &mut |_| {},
                )
                .unwrap();
            ledger.seal_capture(member).unwrap();
            assert!(outcome.handle.is_some());
            hint = outcome.handle;
            let proof = ledger.get(&member).unwrap();
            assert!(
                proof.contains(&ExactExportKey::Vpn(shifted.clone())),
                "the projected key is admitted"
            );
            assert!(
                !proof.contains(&vpn_exact(5)),
                "the row's own key was never projected"
            );
            assert!(proof.contains(&vpn_exact(4)) && proof.contains(&vpn_exact(6)));
            assert_eq!(proof.len(), 200);
        }
    }

    #[test]
    fn logged_vpn_churn_brings_an_older_pool_current_without_probing_rows() {
        let mut table = vpn_table(0).with_vpn_key_log();
        for n in 0..200 {
            table.insert_vpn(vpn_route(n));
        }
        let mut ledger = AdmittedRecovery::new();
        let hint = capture_vpn(&mut ledger, peer(1), None, &table, true).handle;
        assert!(table.remove_vpn(&vpn_route(3).key()));
        table.insert_vpn(vpn_route(500));
        // Transient and restored keys are logged twice but change nothing.
        table.insert_vpn(vpn_route(600));
        assert!(table.remove_vpn(&vpn_route(600).key()));
        assert!(table.remove_vpn(&vpn_route(9).key()));
        table.insert_vpn(vpn_route(9));
        let shape = vpn_shape(&ledger, hint, &table);
        assert_eq!((shape.count, shape.vpn, shape.additions), (200, 200, 1));
        assert!(shape.comparisons < 20, "only logged keys are looked up");
        let warm = capture_vpn(&mut ledger, peer(2), hint, &table, true);
        assert_eq!(warm.handle, hint);
        let proof = ledger.get(&peer(2)).unwrap();
        assert!(
            !proof.contains(&vpn_exact(3)),
            "a removed key is never admitted"
        );
        assert!(!proof.contains(&vpn_exact(600)));
        assert!(proof.contains(&vpn_exact(500)) && proof.contains(&vpn_exact(9)));
        assert_eq!(proof.len(), 200);
        assert!(
            (0..200)
                .filter(|n| *n != 3)
                .all(|n| proof.contains(&vpn_exact(n)))
        );
        assert_retained_credit(&ledger);
        // A partial projection still probes every row and stays exact.
        let partial = capture_vpn_where(&mut ledger, peer(3), hint, &table, true, |route| {
            route.nlri.prefix != VpnPrefix::v4(Ipv4Addr::from(500), 32).unwrap()
        });
        assert_eq!(partial.handle, hint);
        let proof = ledger.get(&peer(3)).unwrap();
        assert_eq!(proof.len(), 199);
        assert!(!proof.contains(&vpn_exact(500)) && !proof.contains(&vpn_exact(3)));
    }

    #[test]
    fn checkpointed_vpn_growth_keeps_an_older_pool_on_the_key_log() {
        let mut table = logged_vpn_table(200);
        let mut ledger = AdmittedRecovery::new();
        let hint = capture_vpn(&mut ledger, peer(1), None, &table, true).handle;
        // A batch past the split threshold splits the table, then rebuilds
        // each shard through checkpoints, without changing the key set.
        let batch: Vec<_> = (200..20_000).map(vpn_route).collect();
        assert_eq!(table.vpn_shard_count(), 1);
        let mut checkpoints = 0;
        table.reserve_vpn_with(&batch, &mut || checkpoints += 1);
        assert_eq!(table.vpn_shard_count(), crate::fast_hash::SHARDS);
        assert!(checkpoints > 400, "every row moved through the reservation");
        let mut replaced = vpn_route(7);
        replaced.next_hop = peer(9).addr();
        table.insert_vpn(replaced);
        table.insert_vpn(vpn_route(500));
        let shape = vpn_shape(&ledger, hint, &table);
        assert_eq!((shape.count, shape.vpn, shape.additions), (201, 201, 1));
        assert!(shape.comparisons < 20, "only logged keys are looked up");
        let warm = capture_vpn(&mut ledger, peer(2), hint, &table, true);
        assert_eq!(warm.handle, hint);
        let proof = ledger.get(&peer(2)).unwrap();
        assert_eq!(proof.len(), 201);
        assert!(proof.contains(&vpn_exact(500)) && proof.contains(&vpn_exact(7)));
    }

    fn logged_vpn_table(count: u32) -> AdjRibOut {
        let mut table = vpn_table(0).with_vpn_key_log();
        for n in 0..count {
            table.insert_vpn(vpn_route(n));
        }
        table
    }

    #[test]
    fn every_vpn_clearing_writer_restarts_the_log_so_older_pools_probe() {
        type Writer = fn(&mut AdjRibOut);
        let writers: [(&str, Writer); 5] = [
            ("clear_vpn", AdjRibOut::clear_vpn),
            ("release_vpn", AdjRibOut::release_vpn),
            ("release_vpn_with", |table| {
                table.release_vpn_with(&mut || {});
            }),
            ("clear", AdjRibOut::clear),
            ("retire_with", |table| table.retire_with(&mut || {})),
        ];
        for (name, writer) in writers {
            // Re-inserting the same keys, or all but one plus a new key, after
            // a clear must never reuse the pre-clear view through the log.
            for replaced in [false, true] {
                let mut table = logged_vpn_table(200);
                let mut ledger = AdmittedRecovery::new();
                let hint = capture_vpn(&mut ledger, peer(1), None, &table, true).handle;
                writer(&mut table);
                for n in (0..200).filter(|n| !replaced || *n != 5) {
                    table.insert_vpn(vpn_route(n));
                }
                if replaced {
                    table.insert_vpn(vpn_route(900));
                }
                let shape = vpn_shape(&ledger, hint, &table);
                assert!(
                    shape.comparisons >= 199,
                    "{name}: the restarted log covers no older pool"
                );
                let warm = capture_vpn(&mut ledger, peer(2), hint, &table, true);
                assert_eq!(warm.handle, hint, "{name}");
                let proof = ledger.get(&peer(2)).unwrap();
                assert_eq!(proof.len(), 200, "{name}");
                assert_eq!(proof.contains(&vpn_exact(5)), !replaced, "{name}");
                assert_eq!(proof.contains(&vpn_exact(900)), replaced, "{name}");
            }
        }
    }

    #[test]
    fn released_vpn_tables_free_their_key_log() {
        let writers: [fn(&mut AdjRibOut); 3] = [
            AdjRibOut::release_vpn,
            |table| table.release_vpn_with(&mut || {}),
            |table| table.retire_with(&mut || {}),
        ];
        for writer in writers {
            let mut table = logged_vpn_table(0);
            for n in 0..64 {
                table.insert_vpn(vpn_route(n));
            }
            assert!(table.vpn_key_log_capacity().unwrap() >= 64);
            writer(&mut table);
            assert_eq!(table.vpn_key_log_capacity(), Some(0));
        }
    }

    #[test]
    fn a_key_logged_in_twice_after_the_pool_dedups_into_an_exact_proof() {
        let mut table = logged_vpn_table(200);
        let mut ledger = AdmittedRecovery::new();
        let hint = capture_vpn(&mut ledger, peer(1), None, &table, true).handle;
        table.insert_vpn(vpn_route(700));
        assert!(table.remove_vpn(&vpn_route(700).key()));
        table.insert_vpn(vpn_route(700));
        let shape = vpn_shape(&ledger, hint, &table);
        assert_eq!(
            (shape.count, shape.additions),
            (201, 3),
            "every log entry of a present, unpooled key reserves sparse capacity"
        );
        let warm = capture_vpn(&mut ledger, peer(2), hint, &table, true);
        assert_eq!(warm.handle, hint);
        let proof = ledger.get(&peer(2)).unwrap();
        assert_eq!(proof.len(), 201, "the duplicate sparse key dedups at seal");
        assert!(proof.contains(&vpn_exact(700)));
        assert!((0..200).all(|n| proof.contains(&vpn_exact(n))));
        assert_retained_credit(&ledger);
    }

    #[test]
    fn logged_keys_a_member_does_not_project_reserve_no_sparse_capacity() {
        let mut table = logged_vpn_table(200);
        let mut ledger = AdmittedRecovery::new();
        let admits = |route: &VpnRibRoute| match route.nlri.prefix {
            VpnPrefix::V4 { addr, .. } => addr.to_bits() < 1_000,
            VpnPrefix::V6 { .. } => false,
        };
        let hint = capture_vpn_where(&mut ledger, peer(1), None, &table, true, admits).handle;
        // As many filtered insertions as pooled keys: counting them as sparse
        // additions would make the shared view costlier than a flat proof.
        for n in 1_000..1_200 {
            table.insert_vpn(vpn_route(n));
        }
        let shape = ledger
            .full_old_shape_with_checkpoint(
                hint,
                &table,
                true,
                |_| None,
                |route| {
                    let key = route.key();
                    admits(route).then_some(Key::Vpn(key.nlri_key, key.path_id))
                },
                &mut |_| {},
            )
            .unwrap();
        assert_eq!((shape.count, shape.additions), (200, 0));
        let warm = capture_vpn_where(&mut ledger, peer(2), hint, &table, true, admits);
        assert_eq!(
            warm.handle, hint,
            "filtered churn must not force a flat proof"
        );
        assert_eq!(warm.fallback, None);
        let proof = ledger.get(&peer(2)).unwrap();
        assert_eq!(proof.len(), 200);
        assert!((0..200).all(|n| proof.contains(&vpn_exact(n))));
        assert!(!proof.contains(&vpn_exact(1_000)));
    }

    #[test]
    fn a_full_vpn_key_log_restarts_and_older_pools_probe_exactly() {
        let mut table = vpn_table(0).with_vpn_key_log();
        for n in 0..200 {
            table.insert_vpn(vpn_route(n));
        }
        let mut ledger = AdmittedRecovery::new();
        let hint = capture_vpn(&mut ledger, peer(1), None, &table, true).handle;
        for _ in 0..2049 {
            assert!(table.remove_vpn(&vpn_route(7).key()));
            table.insert_vpn(vpn_route(7));
        }
        assert!(table.remove_vpn(&vpn_route(8).key()));
        let shape = vpn_shape(&ledger, hint, &table);
        assert!(shape.comparisons >= 199, "an unlogged gap probes every row");
        capture_vpn(&mut ledger, peer(2), hint, &table, true);
        let proof = ledger.get(&peer(2)).unwrap();
        assert_eq!(proof.len(), 199);
        assert!(!proof.contains(&vpn_exact(8)) && proof.contains(&vpn_exact(7)));
    }

    #[test]
    fn vpn_key_churn_at_equal_size_never_admits_a_removed_key() {
        let mut table = vpn_table(200);
        let mut ledger = AdmittedRecovery::new();
        let hint = capture_vpn(&mut ledger, peer(1), None, &table, true).handle;
        // Same row count, different keys: only the key-set version tells them apart.
        assert!(table.remove_vpn(&vpn_route(3).key()));
        table.insert_vpn(vpn_route(500));
        let warm = capture_vpn(&mut ledger, peer(2), hint, &table, true);
        assert_eq!(warm.handle, hint);
        let proof = ledger.get(&peer(2)).unwrap();
        assert!(
            !proof.contains(&vpn_exact(3)),
            "a removed key is never admitted"
        );
        assert!(proof.contains(&vpn_exact(500)));
        assert!(proof.contains(&vpn_exact(4)));
        assert_eq!(proof.len(), 200);
        let shape = vpn_shape(&ledger, hint, &table);
        assert_eq!((shape.count, shape.vpn, shape.additions), (200, 200, 1));
        // A rebuilt table with the same keys is a different table version.
        let rebuilt = vpn_table(200);
        let shape = vpn_shape(&ledger, hint, &rebuilt);
        assert!(shape.comparisons > 0);
    }

    fn capture_slots(
        ledger: &mut AdmittedRecovery,
        member: PeerId,
        hint: Option<SnapshotHandle>,
        table: &AdjRibOut,
        checkpoint: &mut impl FnMut(bool),
    ) -> FullCaptureOutcome {
        ledger.begin_capture(member).unwrap();
        let outcome = ledger
            .capture_full_old_with_checkpoint(
                member,
                hint,
                table,
                true,
                |route| Some(Key::Unicast(route.prefix, route.path_id)),
                |_| None,
                checkpoint,
            )
            .unwrap();
        ledger.seal_capture(member).unwrap();
        outcome
    }

    fn assert_retained_credit(ledger: &AdmittedRecovery) {
        assert_eq!(
            ledger.entries(),
            ledger.records.iter().map(Record::entries).sum::<usize>()
        );
        let record_buffers = ledger
            .records
            .iter()
            .map(|record| {
                record.keys.0.capacity() * size_of::<Key>()
                    + record.words.capacity() * size_of::<u64>()
            })
            .sum::<usize>();
        let pool_buffers = ledger
            .snapshots
            .iter()
            .map(|snapshot| {
                snapshot.keys.capacity() * size_of::<Key>()
                    + snapshot.slot_positions.capacity() * size_of::<u32>()
            })
            .sum::<usize>();
        assert_eq!(
            ledger.bytes(),
            size_of::<AdmittedRecovery>()
                + ledger.records.capacity() * size_of::<Record>()
                + ledger.snapshots.capacity() * size_of::<Snapshot>()
                + record_buffers
                + pool_buffers
        );
    }

    #[test]
    fn indexed_tiny_reordered_old_bounds_work_by_slots_and_exact_lookups() {
        let mut table = slot_table(100_000);
        let mut ledger = AdmittedRecovery::new();
        let anchor = capture_slots(&mut ledger, peer(1), None, &table, &mut |_| {});
        table.clear_unicast();
        table.insert(slot_route(0));
        table.insert(slot_route(99_999));
        let mut visits = 0;
        let shape = ledger
            .full_old_shape_with_checkpoint(
                anchor.handle,
                &table,
                true,
                |route| Some(Key::Unicast(route.prefix, route.path_id)),
                |_| None,
                &mut |force| {
                    if !force {
                        visits += 1;
                    }
                },
            )
            .unwrap();
        assert_eq!((shape.count, shape.additions, shape.mismatches), (2, 0, 2));
        assert!(shape.comparisons < 64);
        assert_eq!(visits, table.unicast_slot_count() + shape.comparisons);
        let mut capture_visits = 0;
        let outcome = capture_slots(&mut ledger, peer(2), anchor.handle, &table, &mut |force| {
            if !force {
                capture_visits += 1;
            }
        });
        assert_eq!(outcome.strategy, FullCaptureStrategy::Flat);
        assert_eq!(outcome.fallback, Some(FullCaptureFallback::Representation));
        assert!(
            capture_visits < 128,
            "tiny current slab must not scan the older universe"
        );
        assert_eq!(
            ledger.get(&peer(2)).unwrap().iter().collect::<Vec<_>>(),
            [slot_key(0), slot_key(99_999)].map(ExactExportKey::from)
        );
        assert_eq!(ledger.get(&peer(1)).unwrap().len(), 100_000);
        assert_retained_credit(&ledger);
    }

    /// The bench observer takes a completed walk's projections from the
    /// table's row count instead of counting per row; this pins that equality.
    #[test]
    fn completed_full_old_walk_projects_each_occupied_row_once() {
        let mut table = slot_table(16);
        for n in 0..3 {
            table.insert_vpn(vpn_route(n));
        }
        assert!(table.withdraw(&Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(5), 32)), 0));
        assert!(table.unicast_slot_count() > table.len(), "one vacant slot");
        let projections = std::cell::Cell::new(0);
        let shape = AdmittedRecovery::new()
            .full_old_shape_with_checkpoint(
                None,
                &table,
                true,
                |route| {
                    projections.set(projections.get() + 1);
                    // Rejected rows are projected too.
                    (route.prefix != slot_route(0).prefix)
                        .then_some(Key::Unicast(route.prefix, route.path_id))
                },
                |route| {
                    projections.set(projections.get() + 1);
                    let key = route.key();
                    Some(Key::Vpn(key.nlri_key, key.path_id))
                },
                &mut |_| {},
            )
            .unwrap();
        assert_eq!(projections.get(), table.len() + table.vpn_len());
        assert_eq!(shape.count, projections.get() - 1);
    }

    #[test]
    fn full_old_count_drift_hides_partial_proof_and_preserves_other_owner() {
        const COUNT: u32 = 128;
        for omit_first in [false, true] {
            let table = slot_table(COUNT);
            let mut ledger = AdmittedRecovery::new();
            let anchor = capture_slots(&mut ledger, peer(1), None, &table, &mut |_| {});
            ledger.begin_capture(peer(2)).unwrap();
            let before = ledger.bytes();
            let visits = std::cell::Cell::new(0_u32);
            let excluded = slot_key(0);
            let error = ledger
                .capture_full_old_with_checkpoint(
                    peer(2),
                    anchor.handle,
                    &table,
                    true,
                    |route| {
                        let first = visits.get() < COUNT;
                        visits.set(visits.get() + 1);
                        let key = Key::Unicast(route.prefix, route.path_id);
                        (first != omit_first || key != excluded).then_some(key)
                    },
                    |_| None,
                    &mut |_| {},
                )
                .unwrap_err();
            assert_eq!(visits.get(), 2 * COUNT);
            assert_eq!(error.cause, FailureCause::MissingProof);
            assert_eq!(ledger.seal_capture(peer(2)), Err(error));
            assert!(ledger.get(&peer(2)).is_none());
            let failed = &ledger.records[ledger.index(peer(2)).unwrap()];
            assert_eq!(failed.words.capacity(), 0);
            assert_eq!(failed.keys.0.capacity(), 0);
            assert!(failed.snapshot.is_none());
            assert_eq!(ledger.bytes(), before);
            assert_eq!(ledger.snapshots[0].references, 1);
            let proof = ledger.get(&peer(1)).unwrap();
            assert_eq!(proof.len(), COUNT as usize);
            assert!((0..COUNT).all(|n| proof.contains(&slot_key(n).into())));
            assert_retained_credit(&ledger);
            ledger.remove(&peer(2));
            ledger.remove(&peer(1));
            assert_eq!(ledger.bytes(), size_of::<AdmittedRecovery>());
        }
    }

    #[test]
    fn indexed_capture_shape_and_population_have_bounded_dense_and_sparse_work() {
        const COUNT: u32 = 4_097;
        let mut table = slot_table(COUNT);
        let mut ledger = AdmittedRecovery::new();
        let anchor = capture_slots(&mut ledger, peer(1), None, &table, &mut |_| {});
        assert_eq!(anchor.strategy, FullCaptureStrategy::Indexed);
        let handle = anchor.handle.unwrap();
        for (member, sparse) in [(peer(2), 0), (peer(3), 480)] {
            for n in 0..sparse {
                let Key::Unicast(prefix, path_id) = slot_key(n) else {
                    unreachable!()
                };
                assert!(table.withdraw(&prefix, path_id));
                table.insert(slot_route(COUNT + n));
            }
            let mut shape_visits = 0;
            let shape = ledger
                .full_old_shape_with_checkpoint(
                    Some(handle),
                    &table,
                    true,
                    |route| Some(Key::Unicast(route.prefix, route.path_id)),
                    |_| None,
                    &mut |force| {
                        if !force {
                            shape_visits += 1;
                        }
                    },
                )
                .unwrap();
            assert_eq!(shape.count, COUNT as usize);
            assert_eq!(shape.additions, sparse as usize);
            assert_eq!(shape.mismatches, sparse as usize);
            assert_eq!(shape.fallback, None);
            assert!(shape.comparisons <= COUNT as usize + sparse as usize * 15);
            assert_eq!(shape_visits, COUNT as usize + shape.comparisons);
            let mut visits = 0;
            let result = capture_slots(&mut ledger, member, Some(handle), &table, &mut |force| {
                if !force {
                    visits += 1;
                }
            });
            assert_eq!(result.strategy, FullCaptureStrategy::Indexed);
            assert_eq!(result.handle, Some(handle));
            assert_eq!(result.keys, COUNT as usize);
            assert_eq!(result.mismatches, sparse as usize);
            assert!(visits >= 4 * COUNT as usize);
            assert!(
                visits <= 5 * COUNT as usize + 2 * sparse as usize * 15 + 128,
                "population must not repeat per-key binary lookup: {visits}"
            );
            let proof = ledger.get(&member).unwrap();
            assert_eq!(proof.len(), COUNT as usize);
            for n in 0..sparse {
                assert!(!proof.contains(&slot_key(n).into()));
                assert!(proof.contains(&slot_key(COUNT + n).into()));
                assert!(ledger.get(&peer(1)).unwrap().contains(&slot_key(n).into()));
            }
            assert_retained_credit(&ledger);
        }
    }

    #[test]
    fn indexed_capture_validates_recycled_slots_and_clear_reordering() {
        let mut table = slot_table(128);
        let mut ledger = AdmittedRecovery::new();
        let anchor = capture_slots(&mut ledger, peer(1), None, &table, &mut |_| {});
        table.clear_unicast();
        for n in 64..192 {
            table.insert(slot_route(n));
        }
        let result = capture_slots(&mut ledger, peer(2), anchor.handle, &table, &mut |_| {});
        assert_eq!(result.strategy, FullCaptureStrategy::Indexed);
        assert_eq!(result.handle, anchor.handle);
        let proof = ledger.get(&peer(2)).unwrap();
        for n in 0..192 {
            assert_eq!(proof.contains(&slot_key(n).into()), n >= 64);
            assert_eq!(
                ledger.get(&peer(1)).unwrap().contains(&slot_key(n).into()),
                n < 128
            );
        }
        assert_retained_credit(&ledger);
    }

    #[test]
    fn indexed_churn_budget_finishes_count_then_captures_exact_flat_old() {
        let mut table = slot_table(10_000);
        let mut ledger = AdmittedRecovery::new();
        let anchor = capture_slots(&mut ledger, peer(1), None, &table, &mut |_| {});
        table.clear_unicast();
        for n in 20_000..30_000 {
            table.insert(slot_route(n));
        }
        let shape = ledger
            .full_old_shape_with_checkpoint(
                anchor.handle,
                &table,
                true,
                |route| Some(Key::Unicast(route.prefix, route.path_id)),
                |_| None,
                &mut |_| {},
            )
            .unwrap();
        assert_eq!(shape.count, 10_000);
        assert_eq!(shape.mismatches, SLOT_MISMATCH_BUDGET + 1);
        assert_eq!(shape.fallback, Some(FullCaptureFallback::SlotChurn));
        assert!(shape.comparisons <= (SLOT_MISMATCH_BUDGET + 1) * 16);
        let result = capture_slots(&mut ledger, peer(2), anchor.handle, &table, &mut |_| {});
        assert_eq!(result.strategy, FullCaptureStrategy::Flat);
        assert_eq!(result.fallback, Some(FullCaptureFallback::SlotChurn));
        let record = &ledger.records[ledger.index(peer(2)).unwrap()];
        assert!(record.snapshot.is_none());
        assert_eq!(record.keys.0.capacity(), 10_000);
        let proof = ledger.get(&peer(2)).unwrap();
        assert_eq!(proof.len(), 10_000);
        assert!(!proof.contains(&slot_key(0).into()));
        assert!(!proof.contains(&slot_key(9_999).into()));
        assert!(proof.contains(&slot_key(20_000).into()));
        assert!(proof.contains(&slot_key(29_999).into()));
        assert_retained_credit(&ledger);
    }

    #[test]
    fn indexed_capture_counts_holes_and_preserves_mask_for_filtered_actual_rows() {
        let mut table = slot_table(128);
        for n in 0..64 {
            let Key::Unicast(prefix, path_id) = slot_key(n) else {
                unreachable!()
            };
            assert!(table.withdraw(&prefix, path_id));
        }
        let mut ledger = AdmittedRecovery::new();
        let anchor = capture_slots(&mut ledger, peer(1), None, &table, &mut |_| {});
        let mut visits = 0;
        let shape = ledger
            .full_old_shape_with_checkpoint(
                anchor.handle,
                &table,
                true,
                |route| {
                    (route.prefix == slot_route(127).prefix)
                        .then_some(Key::Unicast(route.prefix, 0))
                },
                |_| None,
                &mut |force| {
                    if !force {
                        visits += 1;
                    }
                },
            )
            .unwrap();
        assert_eq!(shape.count, 1);
        assert_eq!(shape.comparisons, 1);
        assert_eq!(visits, table.unicast_slot_count() + 1);
        let handle = anchor.handle.unwrap();
        assert_eq!(
            ledger.snapshots[ledger.snapshot_index(handle).unwrap()]
                .slot_positions
                .capacity(),
            128
        );
        ledger.remove(&peer(1));
        assert_eq!(ledger.bytes(), size_of::<AdmittedRecovery>());
    }

    #[test]
    fn indexed_pool_allocation_failures_roll_back_before_truthful_flat_capture() {
        let table = slot_table(128);
        for successful_allocations in 0..4 {
            let mut ledger = AdmittedRecovery::new();
            ledger.begin_capture(peer(1)).unwrap();
            let before = ledger.bytes();
            ledger.allocation_countdown = Some(successful_allocations);
            assert!(
                ledger
                    .share_group_capture_with_checkpoint(
                        peer(1),
                        None,
                        &table,
                        (128, 0),
                        &mut |_| {}
                    )
                    .is_err()
            );
            assert_eq!(ledger.bytes(), before);
            assert!(ledger.snapshots.is_empty());
            assert_retained_credit(&ledger);
            ledger
                .reserve_capture_with_checkpoint(peer(1), 128, &mut |_| {})
                .unwrap();
            for route in table.iter() {
                ledger
                    .push_capture(peer(1), Key::Unicast(route.prefix, 0))
                    .unwrap();
            }
            ledger.seal_capture(peer(1)).unwrap();
            assert_eq!(ledger.get(&peer(1)).unwrap().len(), 128);
            ledger.remove(&peer(1));
            assert_eq!(ledger.bytes(), size_of::<AdmittedRecovery>());
        }
    }

    #[test]
    fn indexed_missing_hint_is_flat_and_empty_key_only_conversion_is_optional() {
        let table = slot_table(128);
        let raw: Vec<_> = table
            .iter()
            .map(|route| Key::Unicast(route.prefix, 0))
            .collect();
        let mut ledger = AdmittedRecovery::new();
        let legacy = shared_capture(&mut ledger, peer(1).addr(), None, &raw, &raw);
        let result = capture_slots(&mut ledger, peer(2), Some(legacy), &table, &mut |_| {});
        assert_eq!(result.strategy, FullCaptureStrategy::Flat);
        assert_eq!(result.fallback, Some(FullCaptureFallback::MissingIndex));
        ledger.insert_empty(peer(3)).unwrap();
        ledger
            .share_capture_with_checkpoint(
                peer(3),
                Some(legacy),
                128,
                raw.iter().copied(),
                (128, 0),
                &mut |_| {},
            )
            .unwrap()
            .unwrap();
        assert!(
            ledger
                .share_group_capture_with_checkpoint(
                    peer(3),
                    Some(legacy),
                    &table,
                    (128, 0),
                    &mut |_| {}
                )
                .unwrap()
                .is_none()
        );
        assert!(ledger.get(&peer(3)).unwrap().is_empty());
        assert!(
            ledger.records[ledger.index(peer(3)).unwrap()]
                .snapshot
                .is_none()
        );
        assert_eq!(ledger.get(&peer(1)).unwrap().len(), 128);
        assert_retained_credit(&ledger);
    }

    #[test]
    fn indexed_selection_counts_reused_mask_and_actual_sparse_cost() {
        let table = slot_table(4_096);
        let mut ledger = AdmittedRecovery::new();
        let anchor = capture_slots(&mut ledger, peer(1), None, &table, &mut |_| {});
        let raw: Vec<_> = table
            .iter()
            .map(|route| Key::Unicast(route.prefix, 0))
            .collect();
        ledger.begin_capture(peer(2)).unwrap();
        // Two actual keys need64maskwords from the REUSED4,096-key U, not one
        // word from a current rawcount2. Flat64B is smaller than mask512B.
        assert!(
            ledger
                .share_capture_with_checkpoint(
                    peer(2),
                    anchor.handle,
                    2,
                    raw[..2].iter().copied(),
                    (2, 0),
                    &mut |_| {}
                )
                .unwrap()
                .is_none()
        );
        ledger.remove(&peer(2));
        ledger.begin_capture(peer(2)).unwrap();
        assert!(
            ledger
                .share_group_capture_with_checkpoint(
                    peer(2),
                    anchor.handle,
                    &table,
                    (128, 128),
                    &mut |_| {}
                )
                .unwrap()
                .is_none()
        );
        assert!(
            ledger.records[ledger.index(peer(2)).unwrap()]
                .snapshot
                .is_none()
        );
        assert_eq!(ledger.get(&peer(1)).unwrap().len(), 4_096);
        assert_retained_credit(&ledger);
    }
    #[test]
    fn indexed_ipv6_path_identity_and_last_owner_release_remain_exact() {
        let mut table = slot_table(128);
        for n in 0..128_u128 {
            let mut route = crate::test_support::make_v6_route(
                Ipv6Prefix::new(
                    Ipv6Addr::from(0x2001_0db8_0000_0000_0000_0000_0000_0000 + n),
                    128,
                ),
                Ipv6Addr::LOCALHOST,
            );
            route.path_id = u32::try_from(n % 3).unwrap();
            table.insert(route);
        }
        let mut ledger = AdmittedRecovery::new();
        let anchor = capture_slots(&mut ledger, peer(1), None, &table, &mut |_| {});
        let prefix = Prefix::V6(Ipv6Prefix::new(
            Ipv6Addr::from(0x2001_0db8_0000_0000_0000_0000_0000_0000),
            128,
        ));
        assert!(table.withdraw(&prefix, 0));
        let Prefix::V6(v6) = prefix else {
            unreachable!()
        };
        let mut replacement = crate::test_support::make_v6_route(v6, Ipv6Addr::LOCALHOST);
        replacement.path_id = 7;
        table.insert(replacement);
        let second = capture_slots(&mut ledger, peer(2), anchor.handle, &table, &mut |_| {});
        assert_eq!(second.handle, anchor.handle);
        assert_eq!(second.mismatches, 1);
        let expected: std::collections::HashSet<_> = table
            .iter()
            .map(|route| ExactExportKey::Unicast(route.prefix, route.path_id))
            .collect();
        assert_eq!(
            ledger
                .get(&peer(2))
                .unwrap()
                .iter()
                .collect::<std::collections::HashSet<_>>(),
            expected
        );
        assert!(
            !ledger
                .get(&peer(2))
                .unwrap()
                .contains(&ExactExportKey::Unicast(prefix, 0))
        );
        assert!(
            ledger
                .get(&peer(1))
                .unwrap()
                .contains(&ExactExportKey::Unicast(prefix, 0))
        );
        assert_retained_credit(&ledger);
        ledger.remove(&peer(1));
        assert_eq!(ledger.snapshots[0].references, 1);
        assert_eq!(
            ledger.snapshots[0].slot_positions.len(),
            table.unicast_slot_count()
        );
        assert_eq!(
            ledger
                .get(&peer(2))
                .unwrap()
                .iter()
                .collect::<std::collections::HashSet<_>>(),
            expected
        );
        assert_retained_credit(&ledger);
        let stale = anchor.handle;
        ledger.remove(&peer(2));
        assert_eq!(ledger.bytes(), size_of::<AdmittedRecovery>());
        let recreated = capture_slots(&mut ledger, peer(3), stale, &table, &mut |_| {});
        assert_eq!(recreated.strategy, FullCaptureStrategy::Indexed);
        assert_ne!(recreated.handle, stale);
        assert_retained_credit(&ledger);
        ledger.remove(&peer(3));
        assert_eq!(ledger.bytes(), size_of::<AdmittedRecovery>());
    }

    #[test]
    fn group_snapshot_holds_every_add_path_key_across_slot_reuse() {
        let mut table = AdjRibOut::new(peer(250));
        for n in (0..8_u32).rev() {
            for path_id in [9, 1, 7, 3, 0] {
                let mut route = slot_route(n);
                route.path_id = path_id;
                table.insert(route);
                let mut route = crate::test_support::make_v6_route(
                    Ipv6Prefix::new(Ipv6Addr::from(0x2001_0db8_u128 << 96 | u128::from(n)), 128),
                    Ipv6Addr::LOCALHOST,
                );
                route.path_id = path_id;
                table.insert(route);
            }
        }
        let reused = slot_route(5).prefix;
        assert!(table.withdraw(&reused, 3));
        let mut route = slot_route(5);
        route.path_id = 4;
        table.insert(route);
        let mut expected: Vec<_> = table
            .iter()
            .map(|route| Key::Unicast(route.prefix, route.path_id))
            .collect();
        expected.sort_unstable();
        assert_eq!(expected.len(), 80);
        let mut ledger = AdmittedRecovery::new();
        ledger.insert_empty(peer(1)).unwrap();
        ledger
            .share_group_capture_with_checkpoint(peer(1), None, &table, (80, 0), &mut |_| {})
            .unwrap()
            .expect("a complete Add-Path universe shares a snapshot");
        assert_eq!(ledger.snapshots[0].keys.as_slice(), expected.as_slice());
        ledger.remove(&peer(1));
        assert_eq!(ledger.bytes(), size_of::<AdmittedRecovery>());
    }
}
