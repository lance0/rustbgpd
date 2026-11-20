//! Owed-key sets for private families (ADR-0099 amendment, slice 1b).
//!
//! When a receiver's row credit is spent, a pass over a private family (one
//! the peer holds in its own Adj-RIB-Out) records *which keys* the peer is
//! owed instead of staging them, and the peer stays clean: no whole-peer
//! resync, no grouped-member capture. The resync tick drains owed keys once
//! credit returns, staging each from current state by diff against the
//! peer's admitted Adj-RIB-Out, so superseded versions are never built.
//!
//! - A key is a prefix or NLRI identity, never an Add-Path path ID.
//! - Owing is sticky: while a family owes anything, ordinary passes only
//!   mark its keys; the drain stages them.
//! - A family whose set outgrows its byte cap θ, and every `FlowSpec`,
//!   BGP-LS or RT-Constrain family, owes the whole family instead.
//! - A unicast, labeled-unicast or EVPN family owed whole is a row cursor
//!   ([`OwedRows`]):
//!   one list per family, shared by every receiver, of the keys passes
//!   carried since the oldest debt began, in the order they last changed.
//!   The receiver holds a sequence number; a drain step sends the next keys
//!   after it as an ordinary charged envelope, with no operation latch. Its
//!   set drains ahead of the cursor, which lives until the set is empty
//!   and the list has been read to its end. During a paced unicast release,
//!   a caught-up cursor parks until the next batch or the producer seals.
//!   Under a cursor the set takes
//!   no key a pass logged, so ordinary changes stop growing it at θ; it
//!   still takes the keys no list entry after the position names for this
//!   receiver (EVPN: an RT-Constrain restage, up to the table and what the
//!   receiver holds; a fanout parked when the cursor started, one inbound
//!   chunk), and so is not bounded at θ.
//! - Any other family owed whole drains as one family-scoped resync under
//!   an operation latch.
//! - A refresh answer and a replay first absorb their family's owed keys
//!   into their own operation, so none is left behind their markers. An
//!   End-of-RIB a hold release freed waits for the drain, which reads the
//!   peer's credit: a cursor family's marker leaves when its steps have
//!   caught up, any other is absorbed with its family, one per step.
//! - A key no source still offers and the peer does not hold is cancelled
//!   (the keep-set below mirrors the resync enumeration).
//!
//! # A receiver's EVPN or labeled-unicast debt as one state machine
//!
//! Written for EVPN; a labeled-unicast family (always private, so a group
//! member can owe it) follows the same table, with no parked fanout, no
//! unlogged restage and no recovery proof.
//!
//! | State | Record | Dirty | Evicted |
//! | --- | --- | --- | --- |
//! | `N` not owing | none | no | no |
//! | `K` keyed | set | no | no |
//! | `C` cursor | whole, live position | no | no |
//! | `W` waiting | whole with a dead position, a keyed set, or none | no | yes |
//! | `D` evicted, dirty | kept (member) or dropped | yes | yes |
//! | `R` ordinary resync | any | yes | no |
//!
//! `evicted` is [`RibManager::owed_row_evicted`]: the receiver's EVPN table
//! is owed to a whole-table unit of the resync tick. The owed-row cap puts
//! a group member that fell behind in `W`. A position is read only
//! through [`RibManager::live_cursor`], which has none for `W` and `D`:
//! the drain, the list trim and its cap, the settle check, an absorption
//! (refused as for capacity) and the shutdown flush all see no cursor.
//!
//! | Event | `K`/`C` | `W` | `D` |
//! | --- | --- | --- | --- |
//! | EVPN pass, parked slice | mark or log | nothing staged; an unlogged key joins the set | out of scope, left dirty |
//! | drain step | sends | none for EVPN | none |
//! | cap pass | `C` behind: `W` (member) or `D` | skipped | skipped |
//! | tick, unit admissible | – | `D` (one capture, lowest first), then its unit | unit: `N`, End-of-RIB behind it |
//! | tick, channel full or operation live | – | stays `W`, no capture | refused before the build, stays `D` |
//! | tick, channel gone | dropped | dropped | dropped, record and mark together |
//! | tick inside an EVPN selection hold | waits | stays `W` | stays `D`, nothing built |
//! | dirty resync inside the hold (`R`) | records a held EVPN rebuild if it holds EVPN rows or a private recovery proof | – | – |
//! | hold release | inventory logged | owes whole, position dead; next tick promotes | unchanged; next tick builds |
//! | peer refresh | absorbs the debt | deferred to the unit | deferred to the unit |
//! | operator refresh, failed send | `R` | `D` (that turn's one capture) | `D` |
//! | operator replay, limit recovery | absorbs the debt | absorption refused as for capacity; stays `W` | as any dirty peer |
//! | forced resync (ORF IMMEDIATE) | covers the record | record covered, stays evicted: one more unit | left to the tick |
//! | selection-partial mark (unicast, VPN) | `R` | `D`, no capture | `D` |
//! | regroup | `R` | `R` (mark and record dropped) | `R` |
//! | session end or registration | `N` | `N` | `N` |
//! | shutdown flush | set and remainder | set only | set only |
//!
//! A unit that builds an evicted receiver is the only exit from `W`/`D`
//! besides a session end, and it runs only when EVPN is enumerated
//! ([`RibManager::resync_unit_held`]), so the dead position is never read
//! again and the withdrawals its dropped entries named are sent by that
//! unit's diff against what the receiver holds. A regroup's `R` is resynced
//! in its own transaction: outside a hold that resync is the exit, inside
//! one it records a held EVPN rebuild instead.
//!
//! A held rebuild ([`RibManager::held_rebuilds`]) owes a diff against
//! the receiver's admitted EVPN rows. Other families retain their ordinary
//! resync and refresh behavior. Its EVPN cursor is dead. When selection
//! stages EVPN, the tick can run its rebuild on the same terms as an evicted
//! receiver. If a waiter re-arms the hold before admission, only EVPN waits
//! again. A session change drops the rebuild and a regroup takes it into its resync.
//!
//! Inside the hold the tick is not armed for `W` or `D` on their own
//! account. A ROUTE-REFRESH pending from such a receiver keeps it armed
//! through the deferred-refresh lane: each tick re-defers the answer and
//! builds nothing, until the release or the deferral timeout. During an
//! ordinary unicast or VPN selection hold a unit can run and stay dirty for
//! that family. While a paced unicast release is publishing a family the
//! receiver can send, `W` and `D` wait for its final batch. Other receivers'
//! evictions remain eligible under the usual EVPN selection rule.

use std::collections::{BTreeMap, HashSet};
use std::hash::Hash;

use rustbgpd_wire::{Afi, EvpnRouteKey, Prefix, Safi, VpnRouteKey};
use tracing::debug;

use super::RibManager;
use super::distribution::OutboundCommitFailure;
use crate::PeerId;
use crate::fast_hash::{FastMap, FastSet};
use crate::outbound_credit::{CHUNK_ROWS, OutboundOperation, OutboundSlot};

/// An owed-key set drained oldest first: insert-if-absent, remove and pop
/// in amortized O(1). A key keeps its place while it stays owed, so keys
/// re-marked on every pass never overtake an older one: any key is popped
/// within as many pops as there were keys ahead of it.
pub(super) struct OwedKeys<K> {
    /// Keys in marking order with their mark sequence; an entry whose
    /// sequence no longer matches `live` was removed (or re-marked later)
    /// and is skipped.
    order: std::collections::VecDeque<(K, u64)>,
    live: FastMap<K, u64>,
    next: u64,
}

impl<K> Default for OwedKeys<K> {
    fn default() -> Self {
        Self {
            order: std::collections::VecDeque::new(),
            live: FastMap::default(),
            next: 0,
        }
    }
}

impl<K: Clone + Eq + Hash> OwedKeys<K> {
    fn len(&self) -> usize {
        self.live.len()
    }

    fn insert(&mut self, key: K) {
        if self.live.contains_key(&key) {
            return;
        }
        let sequence = self.next;
        self.next = self.next.wrapping_add(1);
        self.live.insert(key.clone(), sequence);
        self.order.push_back((key, sequence));
    }

    fn remove(&mut self, key: &K) {
        if self.forget(key) {
            self.compact();
            self.shrink();
        }
    }

    /// [`Self::remove`] for a set that only drains (one kept under a
    /// cursor): no compaction and no capacity release, each of
    /// which moves a share of the set in one call. The set is freed when
    /// its last key leaves.
    fn remove_draining(&mut self, key: &K) {
        if self.forget(key) && self.live.is_empty() {
            self.clear();
        }
    }

    /// Forget `key` and pop the dead entries at the front of the queue,
    /// each once in the set's life. Returns whether the key was owed.
    fn forget(&mut self, key: &K) -> bool {
        if self.live.remove(key).is_none() {
            return false;
        }
        while self
            .order
            .front()
            .is_some_and(|(key, sequence)| self.live.get(key) != Some(sequence))
        {
            self.order.pop_front();
        }
        true
    }

    /// The oldest owed key.
    fn pop(&mut self) -> Option<K> {
        while let Some((key, sequence)) = self.order.pop_front() {
            if self.live.get(&key) == Some(&sequence) {
                self.live.remove(&key);
                return Some(key);
            }
        }
        None
    }

    /// Every owed key, oldest first.
    fn iter(&self) -> impl Iterator<Item = &K> {
        self.order
            .iter()
            .filter(|(key, sequence)| self.live.get(key) == Some(sequence))
            .map(|(key, _)| key)
    }

    /// Drop stale entries once they outnumber the live keys.
    fn compact(&mut self) {
        if self.order.len() > 2 * self.live.len() + 64 {
            let live = &self.live;
            self.order
                .retain(|(key, sequence)| live.get(key) == Some(sequence));
        }
    }

    /// Capacity-based byte estimate, including queue and map slack.
    fn bytes(&self) -> usize {
        self.order.capacity() * std::mem::size_of::<(K, u64)>()
            + self.live.capacity() * (std::mem::size_of::<(K, u64)>() + 1)
    }

    /// Release a drained set's peak capacity.
    fn shrink(&mut self) {
        let len = self.live.len();
        if self.order.capacity() > 4 * len + 64 {
            self.compact();
            self.order.shrink_to(2 * len);
        }
        if self.live.capacity() > 4 * len + 64 {
            self.live.shrink_to(2 * len);
        }
    }

    fn clear(&mut self) {
        *self = Self::default();
    }
}

/// Most list entries one [`OwedRows::trim`] drops. A cursor that leaves (a
/// flap, an eviction, the last one catching up) can put a table of entries
/// behind every other cursor at once; they are dropped this many per trim,
/// and two per key logged, never in one turn.
const TRIM_ROWS: usize = 4 * CHUNK_ROWS;

/// Keys a list may hold beyond twice its family's peak ([`OwedRows::peak`])
/// at the end of a pass: a receiver with more entries than that after its
/// cursor is resynced instead ([`RibManager::cap_owed_rows`]).
const OWED_ROWS_SLACK: usize = 4 * CHUNK_ROWS;

/// The keys of one cursor family (a unicast or labeled AFI, or EVPN) that passes
/// carried while some receiver owed
/// the family whole, in the order they last changed: a key that changes
/// again moves to the back. A receiver's debt is every entry after its
/// cursor, so a key changed behind a cursor is visited again and one changed
/// ahead of it is visited once, at its newest state.
///
/// Each key has one entry, moved in O(log n) when the key is logged again,
/// so the list has no dead entries to compact and a step reads only the
/// keys it sends. Both indexes are ordered maps: they have no capacity to
/// rehash or relocate as the list grows or shrinks, and they free their
/// nodes as entries leave. So no call does list work that grows with the
/// table: a logged key moves one entry and drops at most two, and a trim
/// drops at most [`TRIM_ROWS`].
pub(super) struct OwedRows<K> {
    /// Each key by the sequence it was last logged at.
    order: BTreeMap<u64, K>,
    /// The sequence each key is held at.
    live: BTreeMap<K, u64>,
    /// Sequence of the newest entry ever logged; it never goes back, so a
    /// cursor taken from it stays valid across a trim.
    head: u64,
    /// A phased unicast release can append another batch after consumers reach the head.
    release_open: bool,
    /// The slowest cursor at the last trim (the head with no cursor):
    /// entries up to it are behind every cursor and wait to be dropped.
    floor: u64,
    /// The most keys one pass has accounted for while a cursor was held:
    /// the family's Loc-RIB after the pass plus the keys the pass carried,
    /// so the rows a pass withdrew still count. The cap is taken from it:
    /// one large withdrawal, flap or selection release never exceeds it,
    /// and only fresh keys rotating past a receiver that falls behind do.
    /// Zero again once the list is freed.
    peak: usize,
    /// Most entries one `touch` or `trim` has dropped.
    #[cfg(test)]
    pub(super) dropped_max: usize,
}

impl<K> Default for OwedRows<K> {
    fn default() -> Self {
        Self {
            order: BTreeMap::new(),
            live: BTreeMap::new(),
            head: 0,
            release_open: false,
            floor: 0,
            peak: 0,
            #[cfg(test)]
            dropped_max: 0,
        }
    }
}

impl<K: Copy + Ord> OwedRows<K> {
    /// The cursor of a receiver that has caught up.
    pub(super) fn head(&self) -> u64 {
        self.head
    }

    /// Distinct keys held, those still to be dropped included.
    pub(super) fn len(&self) -> usize {
        self.live.len()
    }

    /// Whether entries behind every cursor are still to be dropped.
    pub(super) fn trimming(&self) -> bool {
        self.order
            .first_key_value()
            .is_some_and(|(sequence, _)| *sequence <= self.floor)
    }

    /// Log `key` as changed now: its entry moves to the back. While entries
    /// wait to be dropped two go with each key logged, so the list does not
    /// grow until they are gone.
    fn touch(&mut self, key: K) {
        self.head += 1;
        if let Some(logged) = self.live.insert(key, self.head) {
            self.order.remove(&logged);
        }
        self.order.insert(self.head, key);
        self.drop_some(2);
    }

    /// Drop up to `most` of the oldest entries behind every cursor.
    fn drop_behind(&mut self, most: usize) -> usize {
        let mut dropped = 0;
        while dropped < most
            && let Some(entry) = self.order.first_entry()
            && *entry.key() <= self.floor
        {
            self.live.remove(&entry.remove());
            dropped += 1;
        }
        dropped
    }

    /// [`Self::drop_behind`] for a `touch` or a `trim`, whose drops are
    /// bounded whatever the list holds.
    fn drop_some(&mut self, most: usize) {
        let dropped = self.drop_behind(most);
        #[cfg(test)]
        {
            self.dropped_max = self.dropped_max.max(dropped);
        }
        #[cfg(not(test))]
        let _ = dropped;
    }

    fn cap(&self) -> usize {
        2 * self.peak + OWED_ROWS_SLACK
    }

    /// With more than `cap` keys held: the sequence of the newest entry
    /// that has to go for `cap` to be left. A cursor before it has more
    /// than `cap` entries after it; a cursor at or past it has not. Reads
    /// the entries over the cap, which a pass that ended at or under the
    /// cap exceeds by at most the keys it logged.
    fn over(&self, cap: usize) -> Option<u64> {
        let over = self.len().checked_sub(cap).filter(|over| *over != 0)?;
        self.order.keys().nth(over - 1).copied()
    }

    fn cutoff(&self) -> Option<(usize, u64)> {
        let cap = self.cap();
        self.over(cap).map(|cut| (cap, cut))
    }

    /// Drop the oldest entries behind every cursor until `cap` are left:
    /// at most the keys the pass logged, as [`Self::over`] reads.
    fn drop_over(&mut self, cap: usize) {
        self.drop_behind(self.len().saturating_sub(cap));
    }

    /// Up to `count` keys after `cursor`, oldest first, and the cursor past
    /// them (the head when none is left).
    fn after(&self, cursor: u64, count: usize) -> (Vec<K>, u64) {
        let mut entries = self.order.range(cursor.saturating_add(1)..);
        let mut keys = Vec::new();
        let mut last = cursor;
        for (sequence, key) in entries.by_ref().take(count) {
            keys.push(*key);
            last = *sequence;
        }
        if entries.next().is_none() {
            last = self.head;
        }
        (keys, last)
    }

    /// Drop entries no cursor still waits for, at most [`TRIM_ROWS`] a
    /// call: those up to `floor`, the slowest cursor, or all of them when
    /// no receiver holds one. The peak is cleared when the list has
    /// emptied with no cursor.
    fn trim(&mut self, floor: Option<u64>) {
        self.floor = floor.unwrap_or(self.head);
        self.drop_some(TRIM_ROWS);
        if floor.is_none() && self.order.is_empty() {
            self.peak = 0;
        }
    }

    /// Byte estimate: each key has an entry in both maps, counted at a
    /// B-tree's worst fill (five of eleven slots a leaf) with a quarter
    /// more for the inner nodes.
    #[cfg(test)]
    pub(super) fn bytes(&self) -> usize {
        let entry = std::mem::size_of::<K>() + std::mem::size_of::<u64>();
        self.live.len() * 2 * (entry * 11 / 5 + entry / 4)
    }
}

/// Physical lists with readers. Inactive families reserve no per-peer slots.
#[derive(Clone, Copy)]
enum RowCursor {
    Ipv4Unicast,
    Ipv6Unicast,
    Ipv4Labeled,
    Ipv6Labeled,
    Evpn,
}

/// Which projection can own the receiver's advertised rows when it is grouped.
#[derive(Clone, Copy)]
enum KeyedOwner {
    UnicastGroup,
    VpnGroup,
    EvpnGroup,
    Peer,
}

/// Minimum live position per active list, also accumulated over paged releases.
pub(super) type CursorFloors = [Option<u64>; OwedFamily::CURSORS.len()];

/// Deferred families skipped or discharged by one resync unit.
pub(super) type HeldRebuilds = [bool; OwedFamily::GROUPED_CURSORS.len()];

/// One family a peer can owe, an index into [`OwedFamily::ALL`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) struct OwedFamily(u8);

impl OwedFamily {
    pub(super) const IPV4_UNICAST: Self = Self(0);
    pub(super) const IPV6_UNICAST: Self = Self(1);
    pub(super) const IPV4_LABELED: Self = Self(2);
    pub(super) const IPV6_LABELED: Self = Self(3);
    pub(super) const VPNV4: Self = Self(4);
    pub(super) const VPNV6: Self = Self(5);
    pub(super) const EVPN: Self = Self(6);
    pub(super) const IPV4_FLOWSPEC: Self = Self(7);
    pub(super) const IPV6_FLOWSPEC: Self = Self(8);
    pub(super) const BGP_LS: Self = Self(9);
    pub(super) const RTC: Self = Self(10);
    pub(super) const VPNV4_FLOWSPEC: Self = Self(11);
    pub(super) const BGP_LS_VPN: Self = Self(12);
    pub(super) const VPNV6_FLOWSPEC: Self = Self(13);
    const COUNT: u8 = 14;

    /// Every owed family, in drain rotation order.
    pub(super) const ALL: [Self; 14] = [
        Self::IPV4_UNICAST,
        Self::IPV6_UNICAST,
        Self::IPV4_LABELED,
        Self::IPV6_LABELED,
        Self::VPNV4,
        Self::VPNV6,
        Self::EVPN,
        Self::IPV4_FLOWSPEC,
        Self::IPV6_FLOWSPEC,
        Self::BGP_LS,
        Self::RTC,
        Self::VPNV4_FLOWSPEC,
        Self::BGP_LS_VPN,
        Self::VPNV6_FLOWSPEC,
    ];

    /// The owed family of a negotiated `(AFI, SAFI)`.
    pub(super) fn of(family: (Afi, Safi)) -> Option<Self> {
        Some(match family {
            (Afi::Ipv4, Safi::Unicast) => Self::IPV4_UNICAST,
            (Afi::Ipv6, Safi::Unicast) => Self::IPV6_UNICAST,
            (Afi::Ipv4, Safi::LabeledUnicast) => Self::IPV4_LABELED,
            (Afi::Ipv6, Safi::LabeledUnicast) => Self::IPV6_LABELED,
            (Afi::Ipv4, Safi::MplsVpn) => Self::VPNV4,
            (Afi::Ipv6, Safi::MplsVpn) => Self::VPNV6,
            (Afi::L2Vpn, Safi::Evpn) => Self::EVPN,
            (Afi::Ipv4, Safi::FlowSpec) => Self::IPV4_FLOWSPEC,
            (Afi::Ipv6, Safi::FlowSpec) => Self::IPV6_FLOWSPEC,
            (Afi::Ipv4, Safi::FlowSpecVpn) => Self::VPNV4_FLOWSPEC,
            (Afi::Ipv6, Safi::FlowSpecVpn) => Self::VPNV6_FLOWSPEC,
            (Afi::BgpLs, Safi::BgpLs) => Self::BGP_LS,
            (Afi::BgpLs, Safi::BgpLsVpn) => Self::BGP_LS_VPN,
            (Afi::Ipv4, Safi::RtConstrain) => Self::RTC,
            _ => return None,
        })
    }

    /// Every `(AFI, SAFI)` this family covers.
    pub(super) fn afi_safis(self) -> &'static [(Afi, Safi)] {
        match self {
            Self::IPV4_UNICAST => &[(Afi::Ipv4, Safi::Unicast)],
            Self::IPV6_UNICAST => &[(Afi::Ipv6, Safi::Unicast)],
            Self::IPV4_LABELED => &[(Afi::Ipv4, Safi::LabeledUnicast)],
            Self::IPV6_LABELED => &[(Afi::Ipv6, Safi::LabeledUnicast)],
            Self::VPNV4 => &[(Afi::Ipv4, Safi::MplsVpn)],
            Self::VPNV6 => &[(Afi::Ipv6, Safi::MplsVpn)],
            Self::EVPN => &[(Afi::L2Vpn, Safi::Evpn)],
            Self::IPV4_FLOWSPEC => &[(Afi::Ipv4, Safi::FlowSpec)],
            Self::IPV6_FLOWSPEC => &[(Afi::Ipv6, Safi::FlowSpec)],
            Self::VPNV4_FLOWSPEC => &[(Afi::Ipv4, Safi::FlowSpecVpn)],
            Self::VPNV6_FLOWSPEC => &[(Afi::Ipv6, Safi::FlowSpecVpn)],
            Self::BGP_LS => &[(Afi::BgpLs, Safi::BgpLs)],
            Self::BGP_LS_VPN => &[(Afi::BgpLs, Safi::BgpLsVpn)],
            _ => &[(Afi::Ipv4, Safi::RtConstrain)],
        }
    }

    fn bit(self) -> u16 {
        1 << self.0
    }

    /// The unicast families, by AFI index ([`afi_index`]).
    const UNICAST: [Self; 2] = [Self::IPV4_UNICAST, Self::IPV6_UNICAST];

    pub(super) fn is_unicast(self) -> bool {
        self == Self::IPV4_UNICAST || self == Self::IPV6_UNICAST
    }

    /// The AFI index of a unicast family.
    fn unicast_index(self) -> usize {
        debug_assert!(self.is_unicast());
        usize::from(self == Self::IPV6_UNICAST)
    }

    /// The seven keyed families, indexed by their existing owed-family ID.
    /// A missing list drains a whole-family operation when its key set fills.
    const KEYED: [(KeyedOwner, Option<RowCursor>); 7] = [
        (KeyedOwner::UnicastGroup, Some(RowCursor::Ipv4Unicast)),
        (KeyedOwner::UnicastGroup, Some(RowCursor::Ipv6Unicast)),
        (KeyedOwner::Peer, Some(RowCursor::Ipv4Labeled)),
        (KeyedOwner::Peer, Some(RowCursor::Ipv6Labeled)),
        (KeyedOwner::VpnGroup, None), // VPNv4
        (KeyedOwner::VpnGroup, None), // VPNv6
        (KeyedOwner::EvpnGroup, Some(RowCursor::Evpn)),
    ];

    const fn private_while_grouped(self) -> bool {
        let index = self.0 as usize;
        index < Self::KEYED.len()
            && matches!(
                Self::KEYED[index].0,
                KeyedOwner::Peer | KeyedOwner::EvpnGroup
            )
    }

    /// Active families in physical slot order. Unicast slots retain their AFI index.
    const CURSORS: [Self; 5] = Self::cursor_families(false);

    /// Active cursor families that may owe private rows as group members.
    pub(super) const GROUPED_CURSORS: [Self; 3] = Self::cursor_families(true);

    const fn cursor_families<const N: usize>(grouped_only: bool) -> [Self; N] {
        let mut families = [Self::IPV4_UNICAST; N];
        let mut count = 0;
        let mut i = 0;
        while i < Self::KEYED.len() {
            let family = Self::ALL[i];
            if let Some(list) = Self::KEYED[i].1
                && (!grouped_only || family.private_while_grouped())
            {
                if grouped_only {
                    families[count] = family;
                } else {
                    families[list as usize] = family;
                }
                count += 1;
            }
            i += 1;
        }
        assert!(count == N);
        families
    }

    const EVPN_CURSOR: usize = RowCursor::Evpn as usize;
    /// The first of the two labeled lists, which follow by AFI index.
    const LABELED_CURSOR: usize = RowCursor::Ipv4Labeled as usize;

    fn row_cursor(self) -> Option<RowCursor> {
        Self::KEYED.get(usize::from(self.0))?.1
    }

    fn cursor_index(self) -> Option<usize> {
        self.row_cursor().map(|cursor| cursor as usize)
    }

    pub(super) fn has_cursor(self) -> bool {
        self.row_cursor().is_some()
    }

    /// A `FlowSpec` family, global (SAFI 133) or VPN (SAFI 134).
    pub(super) fn is_flowspec(self) -> bool {
        matches!(
            self,
            Self::IPV4_FLOWSPEC | Self::IPV6_FLOWSPEC | Self::VPNV4_FLOWSPEC | Self::VPNV6_FLOWSPEC
        )
    }

    /// The owed unicast family of `prefix`.
    pub(super) fn unicast_of(prefix: &Prefix) -> Self {
        match prefix {
            Prefix::V4(_) => Self::IPV4_UNICAST,
            Prefix::V6(_) => Self::IPV6_UNICAST,
        }
    }

    pub(super) fn labeled_of(prefix: &Prefix) -> Self {
        match prefix {
            Prefix::V4(_) => Self::IPV4_LABELED,
            Prefix::V6(_) => Self::IPV6_LABELED,
        }
    }

    pub(super) fn vpn_of(key: &VpnRouteKey) -> Self {
        match key.prefix.family() {
            rustbgpd_wire::VpnAddressFamily::V4 => Self::VPNV4,
            rustbgpd_wire::VpnAddressFamily::V6 => Self::VPNV6,
        }
    }

    /// Bytes per key that size the 64-key floor of the byte cap.
    fn key_cost(self) -> usize {
        let entry = match self {
            Self::VPNV4 | Self::VPNV6 => std::mem::size_of::<(VpnRouteKey, u64)>(),
            Self::EVPN => std::mem::size_of::<(EvpnRouteKey, u64)>(),
            _ => std::mem::size_of::<(Prefix, u64)>(),
        };
        2 * entry + 1
    }
}

/// One owed key with its family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum OwedKey {
    Unicast(Prefix),
    Labeled(Prefix),
    Vpn(VpnRouteKey),
    Evpn(EvpnRouteKey),
}

impl OwedKey {
    pub(super) fn family(&self) -> OwedFamily {
        match self {
            Self::Unicast(prefix) => OwedFamily::unicast_of(prefix),
            Self::Labeled(prefix) => OwedFamily::labeled_of(prefix),
            Self::Vpn(key) => OwedFamily::vpn_of(key),
            Self::Evpn(_) => OwedFamily::EVPN,
        }
    }

    /// The key as the oracles render it.
    #[cfg(test)]
    fn render(&self) -> String {
        match self {
            Self::Unicast(prefix) | Self::Labeled(prefix) => prefix.to_string(),
            Self::Vpn(key) => format!("{key:?}"),
            Self::Evpn(key) => format!("{key:?}"),
        }
    }
}

/// Everything one peer owes, fenced to the session it was recorded for.
pub(super) struct PeerOwing {
    session_id: u64,
    unicast: [OwedKeys<Prefix>; 2],
    /// Subset of `unicast` exempt from a GR selection hold (local host and
    /// BLACKHOLE routes, `helpers::unicast_deferral_exempt`), classified when
    /// marked: they drain inside a hold, the rest wait for its release.
    unicast_exempt: [OwedKeys<Prefix>; 2],
    labeled: [OwedKeys<Prefix>; 2],
    vpn: [OwedKeys<VpnRouteKey>; 2],
    evpn: OwedKeys<EvpnRouteKey>,
    /// A bit per [`OwedFamily`] owed whole. For a cursor family the bit
    /// says `cursor` is live.
    whole: u16,
    /// Per cursor family ([`OwedFamily::CURSORS`]) owed whole: the
    /// [`OwedRows`] sequence drained up to.
    cursor: [u64; OwedFamily::CURSORS.len()],
    /// Per cursor family: how far past `cursor` the current selection hold
    /// has read for the rows it exempts (unicast only: EVPN has none).
    /// `cursor` does not move in a hold, so the release reads the held rows
    /// again.
    hold_cursor: [u64; OwedFamily::CURSORS.len()],
    /// A bit per whole family (not a cursor) already drained inside the
    /// current selection hold (its exempt rows); it stays owed for the
    /// release.
    hold_drained: u16,
    /// The drain's rotation cursor over [`OwedFamily::ALL`].
    next_family: u8,
}

/// Which owed keys of a family a drain step may take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DrainScope {
    /// Every owed key (or the whole family).
    All,
    /// Only keys exempt from the family's selection hold.
    Exempt,
}

fn afi_index(prefix: &Prefix) -> usize {
    usize::from(matches!(prefix, Prefix::V6(_)))
}

impl PeerOwing {
    fn new(session_id: u64) -> Self {
        Self {
            session_id,
            unicast: Default::default(),
            unicast_exempt: Default::default(),
            labeled: Default::default(),
            vpn: Default::default(),
            evpn: OwedKeys::default(),
            whole: 0,
            cursor: Default::default(),
            hold_cursor: Default::default(),
            hold_drained: 0,
            next_family: 0,
        }
    }

    /// Where a drain step of cursor `index` reads from: past what the
    /// current hold already read when `held`.
    fn cursor_from(&self, index: usize, held: bool) -> u64 {
        if held {
            self.cursor[index].max(self.hold_cursor[index])
        } else {
            self.cursor[index]
        }
    }

    pub(super) fn is_whole(&self, family: OwedFamily) -> bool {
        self.whole & family.bit() != 0
    }

    fn whole_drained_in_hold(&self, family: OwedFamily) -> bool {
        self.hold_drained & family.bit() != 0
    }

    /// Owed keys of `family` exempt from its selection hold.
    fn exempt_len(&self, family: OwedFamily) -> usize {
        match family {
            OwedFamily::IPV4_UNICAST => self.unicast_exempt[0].len(),
            OwedFamily::IPV6_UNICAST => self.unicast_exempt[1].len(),
            _ => 0,
        }
    }

    fn keyed_len(&self, family: OwedFamily) -> usize {
        match family {
            OwedFamily::IPV4_UNICAST => self.unicast[0].len(),
            OwedFamily::IPV6_UNICAST => self.unicast[1].len(),
            OwedFamily::IPV4_LABELED => self.labeled[0].len(),
            OwedFamily::IPV6_LABELED => self.labeled[1].len(),
            OwedFamily::VPNV4 => self.vpn[0].len(),
            OwedFamily::VPNV6 => self.vpn[1].len(),
            OwedFamily::EVPN => self.evpn.len(),
            _ => 0,
        }
    }

    pub(super) fn owes(&self, family: OwedFamily) -> bool {
        self.is_whole(family) || self.keyed_len(family) != 0
    }

    fn is_empty(&self) -> bool {
        self.whole == 0 && OwedFamily::ALL.iter().all(|&f| self.keyed_len(f) == 0)
    }

    /// Owe `key`, updating its hold exemption without changing its FIFO place.
    fn insert(&mut self, key: OwedKey, exempt: bool) {
        match key {
            OwedKey::Unicast(prefix) => {
                let index = afi_index(&prefix);
                self.unicast[index].insert(prefix);
                if exempt {
                    self.unicast_exempt[index].insert(prefix);
                } else {
                    self.unicast_exempt[index].remove(&prefix);
                }
            }
            OwedKey::Labeled(prefix) => self.labeled[afi_index(&prefix)].insert(prefix),
            OwedKey::Vpn(key) => {
                let index = usize::from(OwedFamily::vpn_of(&key) == OwedFamily::VPNV6);
                self.vpn[index].insert(key);
            }
            OwedKey::Evpn(key) => self.evpn.insert(key),
        }
    }

    fn remove(&mut self, key: &OwedKey) {
        match key {
            OwedKey::Unicast(prefix) => {
                let index = afi_index(prefix);
                if self.is_whole(OwedFamily::UNICAST[index]) {
                    // Kept under a cursor, the sets only drain.
                    self.unicast[index].remove_draining(prefix);
                    self.unicast_exempt[index].remove_draining(prefix);
                } else {
                    self.unicast[index].remove(prefix);
                    self.unicast_exempt[index].remove(prefix);
                }
            }
            // Kept under a cursor, the set only drains.
            OwedKey::Labeled(prefix) if self.is_whole(OwedFamily::labeled_of(prefix)) => {
                self.labeled[afi_index(prefix)].remove_draining(prefix);
            }
            OwedKey::Labeled(prefix) => self.labeled[afi_index(prefix)].remove(prefix),
            OwedKey::Vpn(key) => {
                let index = usize::from(OwedFamily::vpn_of(key) == OwedFamily::VPNV6);
                self.vpn[index].remove(key);
            }
            // Kept under a cursor, the set only drains.
            OwedKey::Evpn(key) if self.is_whole(OwedFamily::EVPN) => {
                self.evpn.remove_draining(key);
            }
            OwedKey::Evpn(key) => self.evpn.remove(key),
        }
    }

    fn set_bytes(&self, family: OwedFamily) -> usize {
        match family {
            OwedFamily::IPV4_UNICAST => self.unicast[0].bytes() + self.unicast_exempt[0].bytes(),
            OwedFamily::IPV6_UNICAST => self.unicast[1].bytes() + self.unicast_exempt[1].bytes(),
            OwedFamily::IPV4_LABELED => self.labeled[0].bytes(),
            OwedFamily::IPV6_LABELED => self.labeled[1].bytes(),
            OwedFamily::VPNV4 => self.vpn[0].bytes(),
            OwedFamily::VPNV6 => self.vpn[1].bytes(),
            OwedFamily::EVPN => self.evpn.bytes(),
            _ => 0,
        }
    }

    /// Bytes of every owed set plus the record itself.
    #[cfg(test)]
    pub(super) fn bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + OwedFamily::ALL
                .iter()
                .map(|&family| self.set_bytes(family))
                .sum::<usize>()
    }

    /// Forget everything owed for `family`, freeing its set.
    fn clear_family(&mut self, family: OwedFamily) {
        self.whole &= !family.bit();
        self.hold_drained &= !family.bit();
        if let Some(index) = family.cursor_index() {
            (self.cursor[index], self.hold_cursor[index]) = (0, 0);
        }
        match family {
            OwedFamily::IPV4_UNICAST => {
                self.unicast[0].clear();
                self.unicast_exempt[0].clear();
            }
            OwedFamily::IPV6_UNICAST => {
                self.unicast[1].clear();
                self.unicast_exempt[1].clear();
            }
            OwedFamily::IPV4_LABELED => self.labeled[0].clear(),
            OwedFamily::IPV6_LABELED => self.labeled[1].clear(),
            OwedFamily::VPNV4 => self.vpn[0].clear(),
            OwedFamily::VPNV6 => self.vpn[1].clear(),
            OwedFamily::EVPN => self.evpn.clear(),
            _ => {}
        }
    }

    /// Owe `family` whole: its set is dropped.
    fn flip_whole(&mut self, family: OwedFamily) {
        debug_assert!(!family.has_cursor(), "a cursor family starts a cursor");
        self.clear_family(family);
        self.whole |= family.bit();
    }

    /// Owe cursor family `index` whole from `head` of its [`OwedRows`]: every key
    /// a later pass carries. The keys already owed stay in their set, which
    /// takes no logged key from here on and drains ahead of the cursor; the
    /// cursor ends when the set is empty and the list has been read to its
    /// end.
    fn start_cursor(&mut self, index: usize, head: u64) {
        self.whole |= OwedFamily::CURSORS[index].bit();
        (self.cursor[index], self.hold_cursor[index]) = (head, 0);
    }

    /// The cursor of `index` caught up with its list.
    fn end_cursor(&mut self, index: usize) {
        self.whole &= !OwedFamily::CURSORS[index].bit();
        (self.cursor[index], self.hold_cursor[index]) = (0, 0);
    }

    /// Up to `count` of `family`'s oldest keys, restricted to the exempt
    /// subset only while the selection hold requires it.
    fn pop_keys(&mut self, family: OwedFamily, count: usize, scope: DrainScope) -> Vec<OwedKey> {
        fn pop<K: Clone + Eq + Hash>(
            set: &mut OwedKeys<K>,
            count: usize,
            wrap: impl Fn(K) -> OwedKey,
            into: &mut Vec<OwedKey>,
        ) {
            into.extend(std::iter::from_fn(|| set.pop()).take(count).map(wrap));
            set.shrink();
        }
        let mut keys = Vec::new();
        match family {
            OwedFamily::IPV4_UNICAST | OwedFamily::IPV6_UNICAST => {
                let index = usize::from(family == OwedFamily::IPV6_UNICAST);
                let (set, other) = if scope == DrainScope::All {
                    (&mut self.unicast[index], &mut self.unicast_exempt[index])
                } else {
                    (&mut self.unicast_exempt[index], &mut self.unicast[index])
                };
                for prefix in std::iter::from_fn(|| set.pop()).take(count) {
                    other.remove(&prefix);
                    keys.push(OwedKey::Unicast(prefix));
                }
                set.shrink();
                other.shrink();
            }
            OwedFamily::IPV4_LABELED => {
                pop(&mut self.labeled[0], count, OwedKey::Labeled, &mut keys);
            }
            OwedFamily::IPV6_LABELED => {
                pop(&mut self.labeled[1], count, OwedKey::Labeled, &mut keys);
            }
            OwedFamily::VPNV4 => pop(&mut self.vpn[0], count, OwedKey::Vpn, &mut keys),
            OwedFamily::VPNV6 => pop(&mut self.vpn[1], count, OwedKey::Vpn, &mut keys),
            OwedFamily::EVPN => pop(&mut self.evpn, count, OwedKey::Evpn, &mut keys),
            _ => {}
        }
        keys
    }

    /// Up to `count` keys of `family`, oldest first, left in place.
    fn copy_keys(&self, family: OwedFamily, scope: DrainScope, count: usize) -> Vec<OwedKey> {
        match family {
            OwedFamily::IPV4_UNICAST | OwedFamily::IPV6_UNICAST => {
                let index = usize::from(family == OwedFamily::IPV6_UNICAST);
                let set = if scope == DrainScope::Exempt {
                    &self.unicast_exempt[index]
                } else {
                    &self.unicast[index]
                };
                set.iter()
                    .take(count)
                    .copied()
                    .map(OwedKey::Unicast)
                    .collect()
            }
            OwedFamily::IPV4_LABELED => self.labeled[0]
                .iter()
                .take(count)
                .copied()
                .map(OwedKey::Labeled)
                .collect(),
            OwedFamily::IPV6_LABELED => self.labeled[1]
                .iter()
                .take(count)
                .copied()
                .map(OwedKey::Labeled)
                .collect(),
            OwedFamily::VPNV4 => self.vpn[0]
                .iter()
                .take(count)
                .copied()
                .map(OwedKey::Vpn)
                .collect(),
            OwedFamily::VPNV6 => self.vpn[1]
                .iter()
                .take(count)
                .copied()
                .map(OwedKey::Vpn)
                .collect(),
            OwedFamily::EVPN => self
                .evpn
                .iter()
                .take(count)
                .copied()
                .map(OwedKey::Evpn)
                .collect(),
            _ => Vec::new(),
        }
    }

    #[cfg(test)]
    pub(super) fn rendered(&self) -> Vec<((u16, u8), Option<String>)> {
        let mut out = Vec::new();
        for family in OwedFamily::ALL {
            let afi_safi = wire(family.afi_safis()[0]);
            if self.is_whole(family) {
                for &afi_safi in family.afi_safis() {
                    out.push((wire(afi_safi), None));
                }
            }
            out.extend(
                self.copy_keys(family, DrainScope::All, usize::MAX)
                    .iter()
                    .map(|key| (afi_safi, Some(key.render()))),
            );
        }
        out
    }
}

/// Owed keys (family, rendered key) and whole families (`None`) recorded
/// for one peer since the oracles last read them.
#[cfg(test)]
pub(super) type OwingLog = std::collections::BTreeSet<((u16, u8), Option<String>)>;

/// What a private-family producer may do for one family toward one peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum OwingGate {
    /// Stage up to `row_budget` rows, counted per complete key; then owe
    /// the rest. `usize::MAX`: the family is not owed-key managed (out of
    /// scope, a dirty or forced peer, or closing) and keeps slice 1a's path.
    Stream { row_budget: usize },
    /// Mark the keys owed and stage nothing.
    Owe,
    /// The family is owed whole: stage nothing, mark nothing.
    Whole,
}

impl OwingGate {
    pub(super) const UNBOUNDED: Self = Self::Stream {
        row_budget: usize::MAX,
    };
}

/// One drain step, a barrier's absorption or a close flush, run through the
/// distribution member body for one peer and one family.
pub(super) struct OwingDrain {
    pub(super) peer: PeerId,
    pub(super) family: OwedFamily,
    /// The family's resync enumeration instead of keys.
    pub(super) whole: bool,
    /// Rows to stage, counted per complete key.
    pub(super) budget: usize,
    /// Daemon shutdown: keep withdrawals and the announcements of keys they
    /// move; the other keys stay owed.
    pub(super) close: bool,
    /// A reserved slot of the operation the drain joins (an absorption).
    pub(super) slot: Option<OutboundSlot>,
    pub(super) unicast: HashSet<Prefix>,
    pub(super) labeled: FastSet<Prefix>,
    pub(super) vpn: FastSet<VpnRouteKey>,
    pub(super) evpn: HashSet<EvpnRouteKey>,
    /// Keys the body left unstaged; they stay owed.
    pub(super) unstaged: Vec<OwedKey>,
    /// How the body ended: `Some(Ok)` committed or found nothing to send,
    /// `Some(Err)` a refused commit, `None` nothing ran.
    pub(super) outcome: Option<Result<(), OutboundCommitFailure>>,
}

impl OwingDrain {
    fn new(peer: PeerId, family: OwedFamily, budget: usize) -> Self {
        Self {
            peer,
            family,
            whole: false,
            budget,
            close: false,
            slot: None,
            unicast: HashSet::new(),
            labeled: FastSet::default(),
            vpn: FastSet::default(),
            evpn: HashSet::new(),
            unstaged: Vec::new(),
            outcome: None,
        }
    }

    fn whole(peer: PeerId, family: OwedFamily) -> Self {
        debug_assert!(!family.has_cursor(), "a cursor family drains by cursor");
        let mut drain = Self::new(peer, family, usize::MAX);
        drain.whole = true;
        drain
    }

    fn keyed(peer: PeerId, family: OwedFamily, budget: usize, keys: Vec<OwedKey>) -> Self {
        let mut drain = Self::new(peer, family, budget);
        for key in keys {
            match key {
                OwedKey::Unicast(prefix) => {
                    drain.unicast.insert(prefix);
                }
                OwedKey::Labeled(prefix) => {
                    drain.labeled.insert(prefix);
                }
                OwedKey::Vpn(key) => {
                    drain.vpn.insert(key);
                }
                OwedKey::Evpn(key) => {
                    drain.evpn.insert(key);
                }
            }
        }
        drain
    }
}

/// Stage `keys` toward one peer within `budget` rows: all at once when
/// unbounded, else one complete key at a time, stopping after the first key
/// whose rows bring the total to the budget. `stage` stages a key set and
/// returns the rows it added. Returns the keys left unstaged.
pub(super) fn stage_within_budget<K, S>(
    keys: &std::collections::HashSet<K, S>,
    budget: usize,
    mut stage: impl FnMut(&std::collections::HashSet<K, S>) -> usize,
) -> Vec<K>
where
    K: Clone + Eq + Hash,
    S: std::hash::BuildHasher + Default,
{
    if budget == usize::MAX {
        stage(keys);
        return Vec::new();
    }
    let mut one = std::collections::HashSet::with_capacity_and_hasher(1, S::default());
    let mut rows = 0usize;
    let mut unstaged = Vec::new();
    for key in keys {
        if rows >= budget {
            unstaged.push(key.clone());
            continue;
        }
        one.clear();
        one.insert(key.clone());
        rows = rows.saturating_add(stage(&one));
    }
    unstaged
}

/// Whether a refused commit is a capacity or credit refusal the drain
/// retries; anything else escalates to a resync.
fn retryable(failure: OutboundCommitFailure) -> bool {
    failure == OutboundCommitFailure::WriterUnavailable
        || failure == super::outbound_credit::CREDIT_REFUSAL
}

impl RibManager {
    /// Fix the 64-key floor of every family's owed-set byte cap at `bytes`.
    /// For tests, the bench and the oracle.
    #[cfg(any(test, feature = "bench-internals"))]
    #[must_use]
    pub fn with_owing_theta_floor(mut self, bytes: usize) -> Self {
        self.owing_theta_floor = Some(bytes);
        self
    }

    pub(super) fn owing(&self, peer: PeerId) -> Option<&PeerOwing> {
        self.outbound_credit.get(&peer)?.owing.as_deref()
    }

    fn take_owing(&mut self, peer: PeerId) -> Option<Box<PeerOwing>> {
        self.outbound_credit.get_mut(&peer)?.owing.take()
    }

    /// Store `owing` back, dropping it once it owes nothing.
    fn put_owing(&mut self, peer: PeerId, owing: Box<PeerOwing>) {
        if owing.is_empty() {
            self.owing_peers.remove(&peer);
            return;
        }
        if let Some(entry) = self.outbound_credit.get_mut(&peer) {
            entry.owing = Some(owing);
            self.owing_peers.insert(peer);
        } else {
            self.owing_peers.remove(&peer);
        }
    }

    /// Drop everything `peer` owes (a session ended or registered, a
    /// regroup, an escalation). Returns whether it owed anything.
    pub(super) fn drop_peer_owing(&mut self, peer: PeerId) -> bool {
        self.owing_peers.remove(&peer);
        if self.owed_row_evicted.remove(&peer) {
            self.wake_evicted_late_join(peer);
        }
        let mut held = false;
        for peers in &mut self.held_rebuilds {
            held |= peers.remove(&peer);
        }
        let Some(owing) = self.take_owing(peer) else {
            return held;
        };
        if OwedFamily::CURSORS
            .iter()
            .any(|&family| owing.is_whole(family))
        {
            self.trim_owed_rows();
        }
        true
    }

    /// Keep the private cursors enrolled until the family inventory is complete.
    pub(super) fn set_owed_release_open(&mut self, family: (Afi, Safi), open: bool) {
        if let Some(family) = OwedFamily::of(family).filter(|family| family.is_unicast()) {
            self.owed_rows[family.unicast_index()].release_open = open;
        }
    }

    pub(super) fn owed_release_open(&self, family: (Afi, Safi)) -> bool {
        OwedFamily::of(family).is_some_and(|family| {
            family.is_unicast() && self.owed_rows[family.unicast_index()].release_open
        })
    }

    fn owed_rows_head(&self, list: RowCursor) -> u64 {
        match list {
            RowCursor::Evpn => self.owed_evpn_rows.head(),
            _ => self.owed_rows[list as usize].head(),
        }
    }

    /// Up to `count` keys after `cursor`, oldest first, and the position past them.
    fn owed_rows_after(&self, list: RowCursor, cursor: u64, count: usize) -> (Vec<OwedKey>, u64) {
        let wrap = match list {
            RowCursor::Evpn => {
                let (keys, position) = self.owed_evpn_rows.after(cursor, count);
                return (keys.into_iter().map(OwedKey::Evpn).collect(), position);
            }
            RowCursor::Ipv4Unicast | RowCursor::Ipv6Unicast => OwedKey::Unicast,
            RowCursor::Ipv4Labeled | RowCursor::Ipv6Labeled => OwedKey::Labeled,
        };
        let (keys, position) = self.owed_rows[list as usize].after(cursor, count);
        (keys.into_iter().map(wrap).collect(), position)
    }

    /// `peer`'s position in cursor family `index`'s shared list, or `None`
    /// when `owing` holds no cursor there or the owed-row cap evicted the
    /// receiver ([`Self::owed_row_evicted`]): the entries after an evicted
    /// position were dropped, so nothing reads the list from it. Every
    /// reader of a position asks here first (a drain step through
    /// [`Self::owed_family_drainable`]).
    fn live_cursor(&self, peer: PeerId, owing: &PeerOwing, index: usize) -> Option<u64> {
        (owing.is_whole(OwedFamily::CURSORS[index])
            && !self.owed_row_evicted.contains(&peer)
            && !self.owes_held_rebuild(peer, OwedFamily::CURSORS[index]))
        .then(|| owing.cursor[index])
    }

    /// Whether `peer` owes anything of `family` (keys or the whole family).
    pub(super) fn owes(&self, peer: PeerId, family: (Afi, Safi)) -> bool {
        OwedFamily::of(family).is_some_and(|family| {
            self.owes_held_rebuild(peer, family)
                || self.owing(peer).is_some_and(|owing| owing.owes(family))
        })
    }

    /// Whether `family` toward `peer` is held in the peer's own Adj-RIB-Out
    /// and so may owe keys: group-owned and handoff EVPN families keep
    /// slice 1a's path.
    pub(super) fn owing_family_in_scope(&self, peer: PeerId, family: OwedFamily) -> bool {
        match OwedFamily::KEYED
            .get(usize::from(family.0))
            .map(|spec| spec.0)
        {
            Some(KeyedOwner::UnicastGroup) => self.grouped_member_of(peer).is_none(),
            Some(KeyedOwner::VpnGroup) => self.vpn_grouped_member_of(peer).is_none(),
            Some(KeyedOwner::EvpnGroup) => {
                self.evpn_grouped_member_of(peer).is_none() && !self.has_private_evpn_handoff(peer)
            }
            Some(KeyedOwner::Peer) | None => true,
        }
    }

    /// Whether owed-key management applies to `peer` now: not dirty or
    /// forced (its resync covers every family), not closing.
    pub(super) fn owing_peer_in_scope(&self, peer: PeerId) -> bool {
        !self.outbound_closing
            && !self.dirty_peers.contains(&peer)
            && !self.force_outbound_peers.contains(&peer)
            && self.outbound_credit.contains_key(&peer)
    }

    /// Drop owed state recorded for an earlier session of `peer`.
    fn fence_owing(&mut self, peer: PeerId) {
        let current = self.outbound_session_ids.get(&peer).copied();
        if self
            .owing(peer)
            .is_some_and(|owing| Some(owing.session_id) != current)
        {
            self.drop_peer_owing(peer);
        }
    }

    /// The gate a private-family producer applies before staging `family`
    /// toward `peer`. The credit limit is read from the current peer count
    /// at every call.
    pub(super) fn owing_gate(&mut self, peer: PeerId, family: OwedFamily) -> OwingGate {
        if !self.owing_peer_in_scope(peer) || !self.owing_family_in_scope(peer, family) {
            return OwingGate::UNBOUNDED;
        }
        self.fence_owing(peer);
        if let Some(owing) = self.owing(peer) {
            if owing.is_whole(family) {
                // A new local change must re-arm the exempt pass even
                // while the rest of this whole family stays held. A cursor
                // needs no mark: the pass logged its keys.
                let held_exempt = family.is_flowspec()
                    && family
                        .afi_safis()
                        .iter()
                        .any(|&family| self.selection_deferred(family));
                return if held_exempt {
                    OwingGate::Owe
                } else {
                    OwingGate::Whole
                };
            }
            if owing.keyed_len(family) != 0 {
                return OwingGate::Owe;
            }
        }
        let limit = self.outbound_row_credit();
        let rows = self.outbound_credit[&peer].credit.rows();
        if rows >= limit || self.outbound_channel_full(peer) {
            OwingGate::Owe
        } else {
            OwingGate::Stream {
                row_budget: limit - rows,
            }
        }
    }

    /// The byte cap of `peer`'s `family` set: a quarter of the family's
    /// Loc-RIB plus the peer's Adj-RIB-Out, in bytes at the per-key cost that
    /// sizes the 64-key floor, and at least that floor.
    fn owing_theta(&self, peer: PeerId, family: OwedFamily) -> usize {
        let floor = self
            .owing_theta_floor
            .unwrap_or_else(|| 64 * family.key_cost());
        let local = self.loc_rib.family_lens();
        let out = self.adj_ribs_out.get(&peer);
        let sent = out.map(crate::adj_rib_out::AdjRibOut::family_lens);
        let pick = |lens: Option<crate::loc_rib::FamilyLens>,
                    f: fn(&crate::loc_rib::FamilyLens) -> usize| {
            lens.as_ref().map_or(0, f)
        };
        let size = match family {
            OwedFamily::IPV4_UNICAST => local.unicast[0] + pick(sent, |l| l.unicast[0]),
            OwedFamily::IPV6_UNICAST => local.unicast[1] + pick(sent, |l| l.unicast[1]),
            OwedFamily::IPV4_LABELED => local.labeled[0] + pick(sent, |l| l.labeled[0]),
            OwedFamily::IPV6_LABELED => local.labeled[1] + pick(sent, |l| l.labeled[1]),
            OwedFamily::VPNV4 => local.vpn[0] + pick(sent, |l| l.vpn[0]),
            OwedFamily::VPNV6 => local.vpn[1] + pick(sent, |l| l.vpn[1]),
            OwedFamily::EVPN => {
                self.loc_rib.evpn_len() + out.map_or(0, crate::adj_rib_out::AdjRibOut::evpn_len)
            }
            _ => 0,
        };
        // A quarter of the family, in the same bytes a key costs at the floor.
        floor.max((size / 4).saturating_mul(family.key_cost()))
    }

    /// Record `keys` as owed to `peer`: each key the peer could still need
    /// is inserted, and one it cannot is cancelled. A set past its byte cap
    /// is replaced by owing its family whole.
    pub(super) fn mark_owed(&mut self, peer: PeerId, keys: impl IntoIterator<Item = OwedKey>) {
        self.mark_owed_inner(peer, keys, false);
    }

    /// [`Self::mark_owed`] for keys no pass logged in the shared list (a
    /// change in what one receiver may be sent, with every winner as it
    /// was): under a cursor they join the receiver's own set, which drains
    /// ahead of the cursor, so a key the cursor has already read is visited
    /// again for this receiver alone.
    pub(super) fn mark_owed_unlogged(
        &mut self,
        peer: PeerId,
        keys: impl IntoIterator<Item = OwedKey>,
    ) {
        self.mark_owed_inner(peer, keys, true);
    }

    fn mark_owed_inner(
        &mut self,
        peer: PeerId,
        keys: impl IntoIterator<Item = OwedKey>,
        unlogged: bool,
    ) {
        let mut keys = keys.into_iter().peekable();
        if keys.peek().is_none() {
            return;
        }
        let session_id = self.outbound_session_ids.get(&peer).copied().unwrap_or(0);
        let mut owing = self
            .take_owing(peer)
            .unwrap_or_else(|| Box::new(PeerOwing::new(session_id)));
        let sendable = self.peer_sendable_families.get(&peer);
        let mut rejected = None;
        let mut pending_otc = None;
        let mut touched = 0u16;
        let mut evpn_cursor_started = false;
        for key in keys {
            self.replacement_checkpoint(false);
            let family = key.family();
            if !sendable.is_some_and(|families| families.contains(&family.afi_safis()[0])) {
                continue;
            }
            if owing.is_whole(family) && !(unlogged && family.has_cursor()) {
                owing.hold_drained &= !family.bit();
                continue;
            }
            touched |= family.bit();
            if self.owed_key_kept(peer, &key, &mut rejected, &mut pending_otc) {
                #[cfg(test)]
                self.owing_log
                    .entry(peer)
                    .or_default()
                    .insert((wire(family.afi_safis()[0]), Some(key.render())));
                let exempt = self.owed_key_exempt(peer, &key);
                owing.insert(key, exempt);
            } else {
                owing.remove(&key);
            }
        }
        if let Some(mut keys) = rejected {
            super::retire_hash_set(&mut keys, &mut || self.replacement_checkpoint(false));
        }
        if let Some(mut prefixes) = pending_otc {
            super::retire_hash_set(&mut prefixes, &mut || self.replacement_checkpoint(false));
        }
        for family in OwedFamily::ALL {
            // A live cursor stays where it is however large an unlogged
            // mark makes its set: the keys it has not read are named only
            // after its position.
            if touched & family.bit() != 0
                && !owing.is_whole(family)
                && owing.set_bytes(family) > self.owing_theta(peer, family)
            {
                if let Some(list) = family.row_cursor() {
                    owing.start_cursor(list as usize, self.owed_rows_head(list));
                    evpn_cursor_started |= family == OwedFamily::EVPN;
                } else {
                    owing.flip_whole(family);
                }
                self.note_owing_whole(peer, family);
            }
        }
        // A cancellation may have been a family's last owed key: a marker
        // that waited only for those keys leaves once this pass is over.
        let settled = self.eor.owes_peer(peer)
            && OwedFamily::ALL.into_iter().any(|family| {
                touched & family.bit() != 0
                    && !owing.owes(family)
                    && family
                        .afi_safis()
                        .iter()
                        .any(|&afi_safi| self.eor.owes(peer, afi_safi))
            });
        self.put_owing(peer, owing);
        if settled {
            self.defer_eor_settle(peer);
        }
        if evpn_cursor_started {
            self.owe_parked_evpn_fanout(peer);
        }
    }

    /// Re-insert keys a drain popped and did not stage: they were owed.
    fn reinsert_owed(&mut self, peer: PeerId, keys: Vec<OwedKey>) {
        if keys.is_empty() {
            return;
        }
        let session_id = self.outbound_session_ids.get(&peer).copied().unwrap_or(0);
        let mut owing = self
            .take_owing(peer)
            .unwrap_or_else(|| Box::new(PeerOwing::new(session_id)));
        for key in keys {
            // A cursor is already past the key: it goes to the set.
            if key.family().has_cursor() || !owing.is_whole(key.family()) {
                let exempt = self.owed_key_exempt(peer, &key);
                owing.insert(key, exempt);
            }
        }
        self.put_owing(peer, owing);
    }

    /// Owe `family` whole to `peer` (a whole-only family's refusal, a
    /// selection release). A cursor family starts its cursor at the head of
    /// the shared list, so the caller's pass must carry every key the
    /// receiver may lack; a cursor already running is left where it is.
    pub(super) fn owe_whole_family(&mut self, peer: PeerId, family: OwedFamily) {
        let session_id = self.outbound_session_ids.get(&peer).copied().unwrap_or(0);
        let mut owing = self
            .take_owing(peer)
            .unwrap_or_else(|| Box::new(PeerOwing::new(session_id)));
        let started = !owing.is_whole(family);
        if started {
            if let Some(list) = family.row_cursor() {
                owing.start_cursor(list as usize, self.owed_rows_head(list));
            } else {
                owing.flip_whole(family);
            }
            self.note_owing_whole(peer, family);
        }
        // New debt inside a selection hold gets its own exempt pass.
        owing.hold_drained &= !family.bit();
        self.put_owing(peer, owing);
        if started && family == OwedFamily::EVPN {
            self.owe_parked_evpn_fanout(peer);
        }
    }

    fn note_owing_whole(&mut self, peer: PeerId, family: OwedFamily) {
        self.metrics.record_rib_outbound_owing_flip();
        #[cfg(test)]
        for &afi_safi in family.afi_safis() {
            self.owing_log
                .entry(peer)
                .or_default()
                .insert((wire(afi_safi), None));
        }
        #[cfg(not(test))]
        let _ = (peer, family);
    }

    /// A resync committed (or found nothing to send) for `peer`: it covered
    /// every family it enumerated. A selection hold hides rows, and an
    /// open producer can still append more; both retain the debt.
    pub(super) fn owing_resync_covered(&mut self, peer: PeerId) {
        let Some(mut owing) = self.take_owing(peer) else {
            return;
        };
        let cursors = OwedFamily::CURSORS.map(|family| owing.is_whole(family));
        for family in OwedFamily::ALL {
            if !family.afi_safis().iter().any(|&afi_safi| {
                self.selection_deferred(afi_safi) || self.owed_release_open(afi_safi)
            }) {
                owing.clear_family(family);
            }
        }
        let ended = OwedFamily::CURSORS.map(|family| owing.is_whole(family)) != cursors;
        self.put_owing(peer, owing);
        if ended {
            self.trim_owed_rows();
        }
    }

    /// Whether owed `key` is exempt from a GR selection hold: a local host or
    /// BLACKHOLE route offers it, or `peer` holds a locally sourced row.
    /// Staging uses the original provenance to preserve frozen local rows.
    fn owed_key_exempt(&self, peer: PeerId, key: &OwedKey) -> bool {
        use super::helpers::unicast_deferral_exempt;
        let OwedKey::Unicast(prefix) = key else {
            return false;
        };
        self.ribs
            .get(&super::helpers::LOCAL_PEER)
            .is_some_and(|rib| rib.iter_prefix(prefix).any(unicast_deferral_exempt))
            || self.adj_ribs_out.get(&peer).is_some_and(|out| {
                out.iter_prefix(prefix)
                    .any(|route| route.peer == super::helpers::LOCAL_PEER)
            })
    }

    /// Whether `peer` may still need `key`: the key has a candidate, the
    /// peer holds it, the family carries recovery residue, or a per-key
    /// record (a rejection, an OTC block, a policy denial, a GR carried
    /// withdrawal) still names it. Mirrors the resync enumeration.
    /// Both indexes belong to one peer's immutable marking pass.
    #[expect(
        clippy::too_many_lines,
        reason = "one keep-set preserves lazy overlay lookup and short-circuit order for four typed families"
    )]
    pub(super) fn owed_key_kept(
        &self,
        peer: PeerId,
        key: &OwedKey,
        rejected_index: &mut Option<FastSet<OwedKey>>,
        pending_otc_index: &mut Option<FastSet<Prefix>>,
    ) -> bool {
        use crate::update::ExactExportKey;
        let out = self.adj_ribs_out.get(&peer);
        let rejected = self.peer_unexportable.get(&peer);
        // Normalize path IDs once, only if this pass needs a cancellation lookup.
        let mut was_rejected = || {
            rejected_index
                .get_or_insert_with(|| {
                    rejected
                        .into_iter()
                        .flatten()
                        .filter_map(|key| {
                            self.replacement_checkpoint_at("owing_cancel_overlay", false);
                            match key {
                                ExactExportKey::Unicast(prefix, _) => {
                                    Some(OwedKey::Unicast(*prefix))
                                }
                                ExactExportKey::Labeled(key) => Some(OwedKey::Labeled(key.prefix)),
                                ExactExportKey::Vpn(key) => Some(OwedKey::Vpn(key.nlri_key)),
                                _ => None,
                            }
                        })
                        .collect()
                })
                .contains(key)
        };
        let unicast_residue = || {
            self.pending_extra_withdraws
                .get(&peer)
                .is_some_and(|extras| !extras.unicast.is_empty())
                || self.pending_group_admitted.contains_key(&peer)
                || self.pending_regroup_baseline.contains_key(&peer)
        };
        match key {
            OwedKey::Unicast(prefix) => {
                self.unicast_prefix_peers.prefixes.contains_key(prefix)
                    || out.is_some_and(|out| out.iter_prefix(prefix).next().is_some())
                    || unicast_residue()
                    || was_rejected()
                    || self
                        .peer_otc_blocked
                        .get(&peer)
                        .is_some_and(|blocked| blocked.contains_key(prefix))
                    || pending_otc_index
                        .get_or_insert_with(|| {
                            self.pending_otc_blocked
                                .get(&peer)
                                .into_iter()
                                .flat_map(|pending| pending.keys())
                                .map(|&(prefix, _)| {
                                    self.replacement_checkpoint_at("owing_cancel_overlay", false);
                                    prefix
                                })
                                .collect()
                        })
                        .contains(prefix)
                    || self
                        .policy_filtered_routes
                        .get(&peer)
                        .is_some_and(|history| history.contains_key(prefix))
                    || self.helper_stale_exempt.get(&peer).is_some_and(|carried| {
                        carried
                            .keys
                            .range((*prefix, 0)..=(*prefix, u32::MAX))
                            .next()
                            .is_some()
                    })
            }
            OwedKey::Labeled(prefix) => {
                self.loc_rib.get_labeled(prefix).is_some()
                    || self.peer_labeled_add_path_send(peer)
                    || out.is_some_and(|out| {
                        out.get_labeled(&crate::route::LabeledRibRouteKey {
                            prefix: *prefix,
                            path_id: 0,
                        })
                        .is_some()
                    })
                    || was_rejected()
            }
            OwedKey::Vpn(nlri_key) => {
                self.loc_rib.get_vpn(nlri_key).is_some()
                    || self.peer_vpn_add_path_send(peer)
                    || out.is_some_and(|out| {
                        out.get_vpn(&crate::route::VpnRibRouteKey {
                            nlri_key: *nlri_key,
                            path_id: 0,
                        })
                        .is_some()
                    })
                    || self
                        .pending_extra_withdraws
                        .get(&peer)
                        .is_some_and(|extras| !extras.vpn.is_empty())
                    || self.pending_group_admitted.contains_key(&peer)
                    || self.pending_regroup_baseline.contains_key(&peer)
                    || was_rejected()
            }
            OwedKey::Evpn(evpn_key) => {
                self.loc_rib.get_evpn(evpn_key).is_some()
                    || out.is_some_and(|out| out.get_evpn(evpn_key).is_some())
                    || self.evpn_recovery_handle(peer).is_some_and(|handle| {
                        matches!(self.evpn_recovery.proof(handle), Ok(Some(_)))
                    })
                    || rejected.is_some_and(|keys| keys.contains(&ExactExportKey::Evpn(*evpn_key)))
            }
        }
    }

    /// What of `family`'s owed state toward `peer` may drain now, if
    /// anything. An RFC 5291 initial-advertisement gate holds all of it. A
    /// GR selection hold holds all but what its staging exempts: local host
    /// and BLACKHOLE unicast keys, and one pass of a whole `FlowSpec`
    /// family (its staging keeps local rules and withdrawals only). The
    /// other families have no exemption and wait for the release.
    fn owed_drain_scope(
        &self,
        peer: PeerId,
        owing: &PeerOwing,
        family: OwedFamily,
    ) -> Option<DrainScope> {
        if family.afi_safis().iter().any(|afi_safi| {
            self.peer_orf_pending
                .get(&peer)
                .is_some_and(|gated| gated.contains(afi_safi))
        }) {
            return None;
        }
        if !family
            .afi_safis()
            .iter()
            .any(|&afi_safi| self.selection_deferred(afi_safi))
        {
            return Some(DrainScope::All);
        }
        if family.is_unicast() {
            // Inside the hold a cursor reads on for exempt rows only, from
            // where the hold last stopped.
            let index = family.unicast_index();
            return (owing.exempt_len(family) != 0
                || (owing.is_whole(family)
                    && owing.cursor_from(index, true) < self.owed_rows[index].head()))
            .then_some(DrainScope::Exempt);
        }
        (family.is_flowspec() && owing.is_whole(family) && !owing.whole_drained_in_hold(family))
            .then_some(DrainScope::Exempt)
    }

    /// Whether `family` of `owing` is drainable now (`latch_free`: a whole
    /// family without a cursor needs `peer`'s operation latch).
    fn owed_family_drainable(
        &self,
        peer: PeerId,
        owing: &PeerOwing,
        family: OwedFamily,
        latch_free: bool,
    ) -> Option<DrainScope> {
        if !owing.owes(family) || (owing.is_whole(family) && !family.has_cursor() && !latch_free) {
            return None;
        }
        // The cap evicted this cursor: the tick's resync sends the family.
        if let Some(index) = family.cursor_index()
            && owing.is_whole(family)
        {
            let at = self.live_cursor(peer, owing, index)?;
            if family.is_unicast()
                && self.owed_rows[index].release_open
                && owing.keyed_len(family) == 0
                && at >= self.owed_rows[index].head()
            {
                // No work until the producer appends or seals the inventory.
                return None;
            }
        }
        self.owed_drain_scope(peer, owing, family)
    }

    /// Whether `peer` owes a whole family that waits only for its live
    /// operation latch: the resync timer stays armed so the latch release
    /// wakes it.
    fn owing_waits_on_latch(&self, peer: PeerId) -> bool {
        self.owing(peer).is_some_and(|owing| {
            self.outbound_operation_live(peer)
                && OwedFamily::ALL.iter().any(|&family| {
                    owing.is_whole(family)
                        && !family.has_cursor()
                        && self.owed_drain_scope(peer, owing, family).is_some()
                })
        })
    }

    /// Whether any owing peer waits on a live operation latch.
    pub(super) fn owing_latch_pending(&self) -> bool {
        self.owing_peers.iter().any(|&peer| {
            self.replacement_checkpoint(false);
            !self.dirty_peers.contains(&peer)
                && !self.force_outbound_peers.contains(&peer)
                && self.owing_waits_on_latch(peer)
        })
    }

    /// Whether `peer` has owed work the resync tick can run: a runnable
    /// family (a whole family needs its latch free). An End-of-RIB that
    /// waits only for its family's owed keys is covered: no ORF gate and no
    /// armed selection gate holds it, so that family drains whole. Credit
    /// is not part of it: the tick polls for returned credit.
    fn owing_peer_runnable(&self, peer: PeerId) -> bool {
        if self.dirty_peers.contains(&peer) || self.force_outbound_peers.contains(&peer) {
            return false;
        }
        let Some(owing) = self.owing(peer) else {
            return false;
        };
        let latch_free = !self.outbound_operation_live(peer);
        OwedFamily::ALL.iter().any(|&family| {
            self.owed_family_drainable(peer, owing, family, latch_free)
                .is_some()
        })
    }

    /// Whether a list still holds entries behind every cursor: the resync
    /// tick drops them a bounded number at a time.
    pub(super) fn owed_rows_trimming(&self) -> bool {
        self.owed_rows.iter().any(OwedRows::trimming) || self.owed_evpn_rows.trimming()
    }

    /// Whether any peer has owed work the resync tick can run.
    pub(super) fn owing_runnable(&self) -> bool {
        self.owing_peers.iter().any(|&peer| {
            self.replacement_checkpoint(false);
            self.owing_peer_runnable(peer)
        })
    }

    /// Whether some owing peer could make progress this tick: it has credit,
    /// channel room and runnable work. Read before taking the tick's
    /// executor handoff.
    pub(super) fn owing_tick_due(&self) -> bool {
        let limit = self.outbound_row_credit();
        self.owing_peers.iter().any(|&peer| {
            self.owing_peer_runnable(peer)
                && self
                    .outbound_credit
                    .get(&peer)
                    .is_some_and(|entry| entry.credit.rows() < limit)
                && !self.outbound_channel_full(peer)
        })
    }

    /// The next family of `peer` the drain can run, and what of it,
    /// rotating from its cursor.
    fn next_owed_family(&mut self, peer: PeerId) -> Option<(OwedFamily, DrainScope)> {
        let latch_free = !self.outbound_operation_live(peer);
        let owing = self.owing(peer)?;
        let start = owing.next_family;
        let (family, scope) = (0..OwedFamily::COUNT)
            .map(|offset| OwedFamily((start + offset) % OwedFamily::COUNT))
            .find_map(|family| {
                self.owed_family_drainable(peer, owing, family, latch_free)
                    .map(|scope| (family, scope))
            })?;
        if let Some(owing) = self
            .outbound_credit
            .get_mut(&peer)
            .and_then(|entry| entry.owing.as_deref_mut())
        {
            owing.next_family = (family.0 + 1) % OwedFamily::COUNT;
        }
        Some((family, scope))
    }

    /// Drain owed keys under the tick's poll budget, round-robin over the
    /// owing peers from [`Self::owing_cursor`]: per peer, with credit, retry
    /// a barrier waiting on an absorption, then run one step of its next
    /// runnable family. Rounds repeat while a step progressed. Returns
    /// whether the budget cut the slice short.
    pub(super) fn drain_owing_bounded(&mut self, poll_start: std::time::Instant) -> bool {
        self.trim_owed_rows();
        loop {
            let mut progressed = false;
            let mut ring: Vec<PeerId> = self.owing_peers.iter().copied().collect();
            if let Some(cursor) = self.owing_cursor {
                let after = ring.partition_point(|peer| *peer <= cursor);
                ring.rotate_left(after);
            }
            for peer in ring {
                self.replacement_checkpoint(false);
                self.owing_cursor = Some(peer);
                progressed |= self.owing_peer_step(peer);
                if poll_start.elapsed() >= self.flush_poll_budget {
                    return true;
                }
            }
            if !progressed {
                return false;
            }
        }
    }

    /// One peer's turn in [`Self::drain_owing_bounded`]; returns whether it
    /// made progress.
    fn owing_peer_step(&mut self, peer: PeerId) -> bool {
        self.fence_owing(peer);
        if self.owing(peer).is_none() {
            self.owing_peers.remove(&peer);
            return false;
        }
        if self.outbound_channel_gone(peer) {
            self.drop_peer_owing(peer);
            return false;
        }
        if self.dirty_peers.contains(&peer) || self.force_outbound_peers.contains(&peer) {
            return false;
        }
        // Spent credit holds the marker's absorption too: the family it
        // would stage waits for the receiver to read, and only this
        // receiver's own End-of-RIB waits with it.
        let limit = self.outbound_row_credit();
        let rows = self
            .outbound_credit
            .get(&peer)
            .map_or(limit, |entry| entry.credit.rows());
        if rows >= limit || self.outbound_channel_full(peer) {
            return false;
        }
        // One family per step: a waiting marker's family (a cursor family
        // never: its marker follows its own steps) is absorbed whole behind this
        // credit read, and the peer's next owed family waits for its next
        // step and a fresh read.
        if !self.outbound_operation_live(peer) {
            let started = std::time::Instant::now();
            let absorbed = self.absorb_owed_eor(peer);
            if absorbed {
                self.metrics
                    .observe_rib_outbound_owed_drain_step("whole", started.elapsed());
                return true;
            }
        }
        // An absorption that did not send its marker may still have used
        // credit.
        let rows = self
            .outbound_credit
            .get(&peer)
            .map_or(limit, |entry| entry.credit.rows());
        if rows >= limit || self.outbound_channel_full(peer) {
            return false;
        }
        let Some((family, scope)) = self.next_owed_family(peer) else {
            return false;
        };
        self.owing_drain_step(peer, family, scope, limit - rows)
    }

    /// One drain step of `family`'s `scope` toward `peer` within `budget`
    /// rows: the next keys of its set, then of its cursor, or a whole
    /// family of any other kind.
    pub(super) fn owing_drain_step(
        &mut self,
        peer: PeerId,
        family: OwedFamily,
        scope: DrainScope,
        budget: usize,
    ) -> bool {
        let Some(owing) = self.owing(peer) else {
            return false;
        };
        let set_len = if scope == DrainScope::Exempt {
            owing.exempt_len(family)
        } else {
            owing.keyed_len(family)
        };
        let step = match (owing.is_whole(family), family.has_cursor()) {
            (true, false) => "whole",
            (true, true) if set_len == 0 => "cursor",
            _ => "keyed",
        };
        #[cfg(test)]
        let read_before = self.adj_rib_out_commit_stats.owed_drain_rows_read;
        let started = std::time::Instant::now();
        let progressed = match step {
            "whole" => self.owing_whole_step(peer, family, scope),
            "cursor" => self.owing_cursor_step(peer, family, scope, budget),
            _ => self.owing_keyed_step(peer, family, scope, budget),
        };
        self.metrics
            .observe_rib_outbound_owed_drain_step(step, started.elapsed());
        #[cfg(test)]
        {
            let stats = &mut self.adj_rib_out_commit_stats;
            let read = stats.owed_drain_rows_read - read_before;
            stats.owed_drain_steps += usize::from(read != 0);
            stats.owed_drain_step_rows_max = stats.owed_drain_step_rows_max.max(read);
        }
        progressed
    }

    /// One step of a family owed whole that has no cursor:
    /// a family-scoped resync as one whole-table operation.
    fn owing_whole_step(&mut self, peer: PeerId, family: OwedFamily, scope: DrainScope) -> bool {
        if self.outbound_operation_live(peer) {
            return false;
        }
        let mut drain = OwingDrain::whole(peer, family);
        self.distribute_owing_drain(&mut drain);
        match drain.outcome {
            // Inside a selection hold the pass sent only what the hold
            // exempts: the family stays owed for the release.
            Some(Ok(())) if scope == DrainScope::Exempt => {
                if let Some(owing) = self
                    .outbound_credit
                    .get_mut(&peer)
                    .and_then(|entry| entry.owing.as_deref_mut())
                {
                    owing.hold_drained |= family.bit();
                }
                true
            }
            Some(Ok(())) => {
                self.owing_family_settled(peer, family);
                true
            }
            Some(Err(failure)) if !retryable(failure) => {
                self.owing_fallback(peer, failure);
                false
            }
            _ => false,
        }
    }

    /// How many keys of `family` one step toward `peer` takes: the FIFO
    /// batch is fitted before unordered staging, and an unbounded Add-Path
    /// key takes a credit window by itself.
    fn owing_step_keys(&self, peer: PeerId, family: OwedFamily, budget: usize) -> usize {
        let add_path = match family {
            OwedFamily::IPV4_LABELED | OwedFamily::IPV6_LABELED => {
                self.peer_labeled_add_path_send(peer)
            }
            OwedFamily::VPNV4 | OwedFamily::VPNV6 => self.peer_vpn_add_path_send(peer),
            _ => family.is_unicast() && self.peer_has_any_add_path_send(peer),
        };
        self.owing_rows_per_key(peer, add_path, family.afi_safis())
            .map_or(1, |rows| CHUNK_ROWS.min((budget / rows).max(1)))
    }

    /// The budget a step of `keys` keys is staged under. An EVPN key stages
    /// at most two rows, so a step fitted by [`Self::owing_step_keys`] is
    /// one staging call; the other families stage key by key.
    fn owing_step_budget(family: OwedFamily, keys: usize, budget: usize) -> usize {
        if family == OwedFamily::EVPN {
            pass_budget(keys, Some(2), budget)
        } else {
            budget
        }
    }

    /// One step of a cursor: the next live keys after it in the
    /// shared list, staged by diff as an ordinary envelope charged against
    /// the peer's credit, with no operation latch. The cursor moves past
    /// what the step read once the envelope is admitted. Inside a selection
    /// hold a unicast step sends only the rows the hold exempts and moves
    /// the hold's own position, so the release reads the held rows again
    /// (EVPN has no exemption and does not step inside its hold).
    fn owing_cursor_step(
        &mut self,
        peer: PeerId,
        family: OwedFamily,
        scope: DrainScope,
        budget: usize,
    ) -> bool {
        let Some(list) = family.row_cursor() else {
            return false;
        };
        let index = list as usize;
        let held = scope == DrainScope::Exempt;
        let Some(from) = self.owing(peer).map(|owing| owing.cursor_from(index, held)) else {
            return false;
        };
        let count = self.owing_step_keys(peer, family, budget);
        let (mut keys, position) = self.owed_rows_after(list, from, count);
        if held {
            keys.retain(|key| self.owed_key_exempt(peer, key));
        }
        let mut unstaged = Vec::new();
        if !keys.is_empty() {
            let budget = Self::owing_step_budget(family, keys.len(), budget);
            let mut drain = OwingDrain::keyed(peer, family, budget, keys);
            self.distribute_owing_drain(&mut drain);
            match drain.outcome {
                Some(Ok(())) => unstaged = drain.unstaged,
                Some(Err(failure)) if !retryable(failure) => {
                    self.owing_fallback(peer, failure);
                    return false;
                }
                // Refused for capacity or credit: the cursor stays.
                _ => return false,
            }
        }
        if let Some(mut owing) = self.take_owing(peer) {
            if held {
                owing.hold_cursor[index] = position;
            } else {
                (owing.cursor[index], owing.hold_cursor[index]) = (position, 0);
            }
            self.put_owing(peer, owing);
        }
        // A key the envelope left out stays owed in the peer's own set.
        self.reinsert_owed(peer, unstaged);
        self.owing_family_settled(peer, family);
        true
    }

    /// One step of `family`'s owed-key set.
    fn owing_keyed_step(
        &mut self,
        peer: PeerId,
        family: OwedFamily,
        scope: DrainScope,
        budget: usize,
    ) -> bool {
        let count = self.owing_step_keys(peer, family, budget);
        // Keep unstaged and refused keys in place until admission succeeds.
        let keys = self
            .owing(peer)
            .expect("the peer still owes keys")
            .copy_keys(family, scope, count);
        let popped = keys.len();
        let budget = Self::owing_step_budget(family, popped, budget);
        let mut drain = OwingDrain::keyed(peer, family, budget, keys.clone());
        self.distribute_owing_drain(&mut drain);
        match drain.outcome {
            Some(Ok(())) => {
                let unstaged = drain.unstaged.len();
                let unstaged_keys: FastSet<_> = drain.unstaged.into_iter().collect();
                if let Some(mut owing) = self.take_owing(peer) {
                    for key in &keys {
                        if !unstaged_keys.contains(key) {
                            owing.remove(key);
                        }
                    }
                    self.put_owing(peer, owing);
                }
                self.owing_family_settled(peer, family);
                unstaged < popped
            }
            Some(Err(failure)) if !retryable(failure) => {
                self.owing_fallback(peer, failure);
                false
            }
            _ => false,
        }
    }

    /// The slowest cursor per cursor family, after dropping a bounded
    /// number of the list entries behind it; `None` where no receiver holds
    /// one (that list is being freed).
    pub(super) fn trim_owed_rows(&mut self) -> CursorFloors {
        let mut floors = CursorFloors::default();
        #[cfg(test)]
        {
            self.adj_rib_out_commit_stats.owed_peer_scans += self.owing_peers.len();
        }
        for &peer in &self.owing_peers {
            self.fold_owed_floors(peer, &mut floors);
        }
        self.trim_at_owed_floors(floors);
        floors
    }

    /// A release classifies its live peers in pages under one distribution
    /// transaction. Fold their cursor positions without another roster walk.
    pub(super) fn collect_owed_floors(&mut self, peer: PeerId, floors: &mut CursorFloors) {
        #[cfg(test)]
        {
            self.adj_rib_out_commit_stats.owed_peer_scans += 1;
        }
        self.fold_owed_floors(peer, floors);
    }

    fn fold_owed_floors(&self, peer: PeerId, floors: &mut CursorFloors) {
        let Some(owing) = self.owing(peer) else {
            return;
        };
        for (index, floor) in floors.iter_mut().enumerate() {
            if let Some(cursor) = self.live_cursor(peer, owing, index) {
                *floor = Some(floor.map_or(cursor, |floor| floor.min(cursor)));
            }
        }
    }

    fn trim_at_owed_floors(&mut self, floors: CursorFloors) {
        for list in OwedFamily::CURSORS
            .into_iter()
            .filter_map(OwedFamily::row_cursor)
        {
            let index = list as usize;
            match list {
                RowCursor::Evpn => self.owed_evpn_rows.trim(floors[index]),
                _ => self.owed_rows[index].trim(floors[index]),
            }
        }
    }

    /// Whether no cursor list holds a key and no receiver owes anything:
    /// a pass then has nothing to log.
    fn owed_rows_idle(&self) -> bool {
        self.owing_peers.is_empty()
            && self.owed_rows.iter().all(|rows| rows.len() == 0)
            && self.owed_evpn_rows.len() == 0
    }

    /// An EVPN pass selected `keys` (the keys whose winner changed, or a
    /// selection release's whole inventory): log them once for the
    /// receivers that owe EVPN whole, whose gate stages and marks nothing.
    /// Once per mutation, never per receiver or paced slice. With no such
    /// receiver nothing is logged.
    pub(super) fn log_owed_evpn_rows(&mut self, keys: &HashSet<EvpnRouteKey>) {
        if self.owed_rows_idle() {
            return;
        }
        if self.trim_owed_rows()[OwedFamily::EVPN_CURSOR].is_none() {
            return;
        }
        #[cfg(test)]
        {
            self.adj_rib_out_commit_stats.owed_evpn_logs += 1;
        }
        for key in keys {
            self.replacement_checkpoint(false);
            self.owed_evpn_rows.touch(*key);
        }
        let table = self.loc_rib.evpn_len();
        let rows = &mut self.owed_evpn_rows;
        rows.peak = rows.peak.max(table + keys.len());
    }

    /// A unicast pass is about to stage `best_changed` and `all_affected`:
    /// log them once for the receivers that owe their family whole, whose
    /// gate stages and marks nothing. With no such receiver nothing is
    /// logged.
    pub(super) fn log_owed_rows(
        &mut self,
        best_changed: &HashSet<Prefix>,
        all_affected: &HashSet<Prefix>,
    ) {
        if self.owed_rows_idle() {
            return;
        }
        let floors = self.trim_owed_rows();
        let changed = best_changed.iter().chain(
            all_affected
                .iter()
                .filter(|prefix| !best_changed.contains(*prefix)),
        );
        self.log_prefix_keys(0, changed.copied(), floors);
    }

    pub(super) fn log_release_owed_rows(&mut self, keys: &HashSet<Prefix>, floors: CursorFloors) {
        self.trim_at_owed_floors(floors);
        self.log_prefix_keys(0, keys.iter().copied(), floors);
    }

    /// A labeled pass selected among `affected` (every prefix an input
    /// changed for, or a selection release's whole inventory): log them
    /// once for the receivers that owe their family whole, whose gate
    /// stages and marks nothing. Not only the changed winners: an Add-Path
    /// or ORR receiver stages a non-best change, and a receiver that joined
    /// during a hold has none of the unchanged winners. With no such
    /// receiver nothing is logged.
    pub(super) fn log_owed_labeled_rows(&mut self, affected: &HashSet<Prefix>) {
        if self.owed_rows_idle() {
            return;
        }
        let floors = self.trim_owed_rows();
        #[cfg(test)]
        if floors[OwedFamily::LABELED_CURSOR..][..2] != [None, None] {
            self.adj_rib_out_commit_stats.owed_labeled_logs += 1;
        }
        self.log_prefix_keys(OwedFamily::LABELED_CURSOR, affected.iter().copied(), floors);
    }

    /// Log `changed` in the two prefix lists that start at slot `first`
    /// (unicast or labeled), each prefix in its AFI's list.
    fn log_prefix_keys(
        &mut self,
        first: usize,
        changed: impl Iterator<Item = Prefix>,
        floors: CursorFloors,
    ) {
        if floors[first..first + 2] == [None, None] {
            return;
        }
        let mut carried = [0usize; 2];
        for prefix in changed {
            self.replacement_checkpoint(false);
            let index = afi_index(&prefix);
            if floors[first + index].is_some() {
                self.owed_rows[first + index].touch(prefix);
                carried[index] += 1;
            }
        }
        let lens = self.loc_rib.family_lens();
        let table = if first == 0 {
            lens.unicast
        } else {
            lens.labeled
        };
        for index in 0..2 {
            if floors[first + index].is_some() {
                let rows = &mut self.owed_rows[first + index];
                rows.peak = rows.peak.max(table[index] + carried[index]);
            }
        }
    }

    /// After a pass's member loop: a list that outgrew its cap (fresh keys
    /// rotating through the table past a receiver that does not keep up) is
    /// cut back to it. Every receiver with more than the cap after its
    /// cursor is marked dirty, slice 1a's path, in one scan of the owing
    /// receivers and one trim however many are evicted; the entries over
    /// the cap are then behind every cursor and are dropped, at most the
    /// keys this pass logged. Entries an earlier trim left are the oldest,
    /// so they are dropped first and no receiver is evicted for them.
    /// Nothing is built here, and no later pass builds it either: an
    /// evicted receiver is resynced only by the resync tick, one receiver
    /// per unit ([`Self::owed_row_evicted`]). A group member is not made
    /// dirty here either: the capture of its group's table belongs to the
    /// tick too.
    pub(super) fn cap_owed_rows(&mut self) {
        for list in [RowCursor::Ipv4Unicast, RowCursor::Ipv6Unicast] {
            self.cap_owed_rows_of(list);
        }
    }

    /// [`Self::cap_owed_rows`] for the labeled lists, after a labeled
    /// pass's receiver loop.
    pub(super) fn cap_owed_labeled_rows(&mut self) {
        for list in [RowCursor::Ipv4Labeled, RowCursor::Ipv6Labeled] {
            self.cap_owed_rows_of(list);
        }
    }

    /// [`Self::cap_owed_rows`] for the EVPN list, after an EVPN pass's
    /// receiver loop.
    pub(super) fn cap_owed_evpn_rows(&mut self) {
        self.cap_owed_rows_of(RowCursor::Evpn);
    }

    /// A release has logged at most its prefix batch. Only an overflowing
    /// list requires another (paged) pass over the peers.
    pub(super) fn release_owed_over_cap(&self) -> [Option<u64>; 2] {
        [0, 1].map(|index| self.owed_rows[index].over(self.owed_rows[index].cap()))
    }

    pub(super) fn cap_release_owed_peer(
        &mut self,
        peer: PeerId,
        over: [Option<u64>; 2],
        floors: &mut CursorFloors,
    ) {
        if let Some(owing) = self.owing(peer) {
            for (index, cut) in over.into_iter().enumerate() {
                if let Some(cut) = cut
                    && self
                        .live_cursor(peer, owing, index)
                        .is_some_and(|at| at < cut)
                {
                    self.evict_owed_cursor(peer, OwedFamily::CURSORS[index]);
                    break;
                }
            }
        }
        self.collect_owed_floors(peer, floors);
    }

    pub(super) fn finish_release_owed_cap(&mut self, over: [Option<u64>; 2], floors: CursorFloors) {
        self.trim_at_owed_floors(floors);
        for (rows, cut) in self.owed_rows.iter_mut().zip(over) {
            if cut.is_some() {
                rows.drop_over(rows.cap());
            }
        }
    }

    fn cap_owed_rows_of(&mut self, list: RowCursor) {
        let index = list as usize;
        let family = OwedFamily::CURSORS[index];
        let cutoff = match list {
            RowCursor::Evpn => self.owed_evpn_rows.cutoff(),
            _ => self.owed_rows[index].cutoff(),
        };
        let Some((cap, over)) = cutoff else {
            return;
        };
        #[cfg(test)]
        {
            self.adj_rib_out_commit_stats.owed_peer_scans += self.owing_peers.len();
        }
        let behind: Vec<PeerId> = self
            .owing_peers
            .iter()
            .copied()
            .filter(|&peer| {
                self.owing(peer).is_some_and(|owing| {
                    self.live_cursor(peer, owing, index)
                        .is_some_and(|cursor| cursor < over)
                })
            })
            .collect();
        for peer in behind {
            self.evict_owed_cursor(peer, family);
        }
        self.trim_owed_rows();
        match list {
            RowCursor::Evpn => self.owed_evpn_rows.drop_over(cap),
            _ => self.owed_rows[index].drop_over(cap),
        }
    }

    fn evict_owed_cursor(&mut self, peer: PeerId, family: OwedFamily) {
        debug!(%peer, ?family, "owed-row list over its cap — receiver resyncs");
        self.metrics.record_rib_outbound_owing_fallback();
        // Only private rows can acquire a cursor. If its receiver is now a
        // group member, dirtying it captures the group's table regardless
        // of which list overflowed. Leave that capture to the tick.
        if self.grouped_member_of(peer).is_some() {
            self.owed_row_evicted.insert(peer);
            return;
        }
        self.owing_peers.remove(&peer);
        drop(self.take_owing(peer));
        if self.mark_outbound_dirty(peer) {
            self.owed_row_evicted.insert(peer);
        }
    }

    fn cursor_selection_deferred(&self, family: OwedFamily) -> bool {
        family
            .afi_safis()
            .iter()
            .any(|&pair| self.selection_deferred(pair))
    }

    /// Paced unicast waits for the producer. A cap eviction also needs
    /// every other sendable cursor family's selection to be open.
    pub(super) fn resync_unit_held(&self, peer: PeerId) -> bool {
        if self.release_resync_waits(peer) {
            return true;
        }
        self.owed_row_evicted.contains(&peer)
            && OwedFamily::CURSORS
                .into_iter()
                .filter(|family| !family.is_unicast())
                .flat_map(OwedFamily::afi_safis)
                .any(|pair| {
                    self.selection_deferred(*pair)
                        && self
                            .peer_sendable_families
                            .get(&peer)
                            .is_some_and(|sendable| sendable.contains(pair))
                })
    }

    pub(super) fn owes_held_rebuild(&self, peer: PeerId, family: OwedFamily) -> bool {
        OwedFamily::GROUPED_CURSORS
            .iter()
            .zip(&self.held_rebuilds)
            .any(|(&held, peers)| held == family && peers.contains(&peer))
    }

    /// An in-hold dirty resync cannot cover the peer's admitted rows of a
    /// deferred family. A private EVPN handoff may hold only a recovery proof.
    pub(super) fn skipped_held_rebuilds(
        &self,
        peer: PeerId,
        evpn_held: bool,
        evpn_recovery: bool,
    ) -> HeldRebuilds {
        OwedFamily::GROUPED_CURSORS.map(|family| match family {
            OwedFamily::EVPN => {
                evpn_held
                    && (evpn_recovery
                        || self
                            .adj_ribs_out
                            .get(&peer)
                            .is_some_and(|out| out.evpn_len() != 0))
            }
            OwedFamily::IPV4_LABELED | OwedFamily::IPV6_LABELED => {
                self.cursor_selection_deferred(family)
                    && self.adj_ribs_out.get(&peer).is_some_and(|out| {
                        out.family_lens().labeled[usize::from(family == OwedFamily::IPV6_LABELED)]
                            != 0
                    })
            }
            _ => false,
        })
    }

    pub(super) fn record_held_rebuilds(&mut self, peer: PeerId, owed: HeldRebuilds) {
        for (peers, owed) in self.held_rebuilds.iter_mut().zip(owed) {
            if owed {
                peers.insert(peer);
            }
        }
    }

    /// A new waiter can defer selection again after collision staging.
    pub(super) fn held_rebuild_due(&self, peer: PeerId) -> bool {
        OwedFamily::GROUPED_CURSORS
            .iter()
            .zip(&self.held_rebuilds)
            .any(|(&family, peers)| {
                peers.contains(&peer) && !self.cursor_selection_deferred(family)
            })
    }

    /// The unit can discharge only the families that are open when it starts.
    pub(super) fn take_due_held_rebuilds(&mut self, peer: PeerId) -> HeldRebuilds {
        std::array::from_fn(|i| {
            self.held_rebuilds[i].contains(&peer)
                && !self.cursor_selection_deferred(OwedFamily::GROUPED_CURSORS[i])
                && self.held_rebuilds[i].remove(&peer)
        })
    }

    fn rebuild_candidates(&self) -> impl Iterator<Item = &PeerId> {
        let open = OwedFamily::GROUPED_CURSORS
            .into_iter()
            .zip(&self.held_rebuilds)
            .filter(|(family, peers)| !peers.is_empty() && !self.cursor_selection_deferred(*family))
            .flat_map(|(_, peers)| peers);
        self.owed_row_evicted.iter().chain(open)
    }

    /// Whether a group member the cap evicted still waits to be made dirty
    /// and no selection hold keeps it waiting.
    pub(super) fn owed_eviction_pending(&self) -> bool {
        self.rebuild_candidates()
            .any(|&peer| !self.dirty_peers.contains(&peer) && !self.resync_unit_held(peer))
    }

    /// The resync tick makes at most one waiting evicted group member
    /// dirty: one capture of a group's table per tick, ahead of that
    /// receiver's whole-table unit. It takes the lowest receiver whose unit
    /// could be admitted now (no selection hold, room in its channel, no
    /// live whole-table operation) and passes over the rest at no cost, so
    /// no receiver waits behind another, dirty or not, that cannot build.
    /// One scan of the evicted receivers.
    pub(super) fn promote_evicted_receiver(&mut self) {
        let waiting: Vec<PeerId> = self
            .rebuild_candidates()
            .copied()
            .filter(|peer| !self.dirty_peers.contains(peer))
            .collect();
        let mut next = None::<PeerId>;
        for peer in waiting {
            if self.outbound_channel_gone(peer) {
                // Its session is gone: nothing is owed to it.
                self.drop_peer_owing(peer);
            } else if !self.resync_unit_held(peer)
                && !self.outbound_channel_full(peer)
                && !self.outbound_operation_live(peer)
            {
                next = Some(next.map_or(peer, |lowest| lowest.min(peer)));
            }
        }
        if let Some(peer) = next {
            self.mark_outbound_dirty(peer);
        }
    }

    /// After a drain of `family` ended without a refusal: a whole family
    /// clears its bit (a cursor family once its kept set is empty and its
    /// cursor has caught up with the list: until both hold, passes log
    /// their keys for the cursor and the set takes only unlogged marks). An open
    /// release keeps its cursor between batches. The
    /// End-of-RIB of a family that no longer owes anything, if one waits,
    /// goes out now.
    fn owing_family_settled(&mut self, peer: PeerId, family: OwedFamily) {
        if let Some(mut owing) = self.take_owing(peer) {
            let cursor = family.row_cursor();
            let caught_up = cursor.is_some_and(|list| {
                let index = list as usize;
                (!family.is_unicast() || !self.owed_rows[index].release_open)
                    && owing.keyed_len(family) == 0
                    && self
                        .live_cursor(peer, &owing, index)
                        .is_some_and(|at| at >= self.owed_rows_head(list))
            });
            if let Some(list) = cursor.filter(|_| caught_up) {
                owing.end_cursor(list as usize);
            } else if owing.is_whole(family) && cursor.is_none() {
                owing.clear_family(family);
            }
            self.put_owing(peer, owing);
            if caught_up {
                self.trim_owed_rows();
            }
        }
        if !self.owing(peer).is_some_and(|owing| owing.owes(family))
            && family
                .afi_safis()
                .iter()
                .any(|&afi_safi| self.eor.owes(peer, afi_safi))
        {
            // Every owed row was admitted. A marker the channel refuses
            // (the last envelope may have taken its last slot) waits for
            // the tick's marker retry: a resync would send the table again.
            self.settle_free_eor(peer);
        }
    }

    /// A drain refused for anything but capacity or credit (a missing
    /// encoder, EVPN recovery, a selection gate): owed state cannot make
    /// progress, so the peer resyncs instead.
    fn owing_fallback(&mut self, peer: PeerId, failure: OutboundCommitFailure) {
        debug!(%peer, reason = failure.as_str(), "owed keys cannot drain — peer resyncs");
        self.drop_peer_owing(peer);
        self.metrics.record_rib_outbound_owing_fallback();
        self.mark_outbound_dirty(peer);
    }

    /// Count a private ordinary batch refused for credit despite its gate
    /// (it takes slice 1a's resync).
    pub(super) fn note_owing_credit_fallback(&self) {
        self.metrics.record_rib_outbound_owing_fallback();
    }

    /// Run `drain` through the distribution member body.
    pub(super) fn distribute_owing_drain(&mut self, drain: &mut OwingDrain) {
        let empty = HashSet::new();
        let targets = HashSet::from([drain.peer]);
        super::with_executor_handoff(|| {
            self.distribute_owing_with_readiness(&empty, &targets, drain);
        });
    }

    /// Absorb `peer`'s owed state of `family` into `operation` ahead of the
    /// operation's barrier: the owed keys, or the whole family, are staged
    /// by diff into one envelope on a reserved slot. Nothing owed is a no-op.
    /// `Err` means the owed routes were not admitted, so the caller keeps its
    /// barrier: a capacity or credit refusal leaves the owed state as it
    /// was; any other refusal also escalates the peer to a resync, which
    /// sends the barrier after its own diff.
    pub(super) fn absorb_owed_family(
        &mut self,
        peer: PeerId,
        family: (Afi, Safi),
        operation: &mut OutboundOperation,
    ) -> Result<(), OutboundCommitFailure> {
        if self.owed_release_open(family) {
            // A refresh cannot absorb the rows of batches still to be published.
            return Err(OutboundCommitFailure::Refused(
                rustbgpd_telemetry::reason_labels::OutboundCommitRefusal::SelectionGate,
            ));
        }
        let Some(family) = OwedFamily::of(family) else {
            return Ok(());
        };
        // A dirty or forced peer's resync covers what it owes.
        if self.dirty_peers.contains(&peer) || self.force_outbound_peers.contains(&peer) {
            return Ok(());
        }
        if self.owes_held_rebuild(peer, family) {
            return Err(super::outbound_credit::CREDIT_REFUSAL);
        }
        let Some(owing) = self.owing(peer) else {
            return Ok(());
        };
        if !owing.owes(family) {
            return Ok(());
        }
        let mut drain = if owing.is_whole(family) && !family.has_cursor() {
            OwingDrain::whole(peer, family)
        } else {
            // Copied, not popped: a refusal leaves the set and the cursor
            // as they were. A cursor's remainder joins the keys.
            let mut keys = owing.copy_keys(family, DrainScope::All, usize::MAX);
            if let Some(list) = family.row_cursor().filter(|_| owing.is_whole(family)) {
                // An evicted cursor has no remainder to absorb: the family
                // stays owed for the tick's resync, as after a refusal.
                let Some(cursor) = self.live_cursor(peer, owing, list as usize) else {
                    return Err(super::outbound_credit::CREDIT_REFUSAL);
                };
                keys.extend(self.owed_rows_after(list, cursor, usize::MAX).0);
            }
            OwingDrain::keyed(peer, family, usize::MAX, keys)
        };
        drain.slot = Some(
            operation
                .slot()
                .ok_or(OutboundCommitFailure::WriterUnavailable)?,
        );
        self.distribute_owing_drain(&mut drain);
        match drain.outcome {
            Some(Ok(())) => {
                if let Some(mut owing) = self.take_owing(peer) {
                    owing.clear_family(family);
                    self.put_owing(peer, owing);
                }
                if family.has_cursor() {
                    self.trim_owed_rows();
                }
                self.reinsert_owed(peer, drain.unstaged);
                Ok(())
            }
            Some(Err(failure)) if retryable(failure) => Err(failure),
            Some(Err(failure)) => {
                self.owing_fallback(peer, failure);
                Err(failure)
            }
            None => Err(OutboundCommitFailure::WriterUnavailable),
        }
    }

    /// How many of `families` `peer` owes, each needing one absorption
    /// envelope in an operation.
    pub(super) fn owed_absorptions(&self, peer: PeerId, families: &[(Afi, Safi)]) -> usize {
        families
            .iter()
            .filter(|&&family| self.owes(peer, family))
            .count()
    }

    /// Daemon shutdown began: send every owing peer's owed withdrawals, and
    /// the announcements of keys they move, ahead of its Cease. Keys that
    /// only announce stay owed; a whole family whose latch is busy is
    /// skipped. Nothing waits.
    pub(super) fn owing_close_flush(&mut self) {
        let peers: Vec<PeerId> = self.owing_peers.iter().copied().collect();
        for peer in peers {
            self.fence_owing(peer);
            for family in OwedFamily::ALL {
                let Some(owing) = self.owing(peer) else {
                    break;
                };
                if !owing.owes(family) {
                    continue;
                }
                // A cursor's remainder is flushed with the set and stays
                // behind the cursor, which does not move.
                let cursor_keys = family
                    .row_cursor()
                    .and_then(|list| Some((list, self.live_cursor(peer, owing, list as usize)?)))
                    .map_or_else(Vec::new, |(list, cursor)| {
                        self.owed_rows_after(list, cursor, usize::MAX).0
                    });
                let mut popped = Vec::new();
                let mut drain = if owing.is_whole(family) && !family.has_cursor() {
                    if self.outbound_operation_live(peer) {
                        debug!(%peer, ?family, "owed family not flushed at close: a whole-table update is still live");
                        continue;
                    }
                    OwingDrain::whole(peer, family)
                } else {
                    popped = match self
                        .outbound_credit
                        .get_mut(&peer)
                        .and_then(|entry| entry.owing.as_deref_mut())
                    {
                        Some(owing) => owing.pop_keys(family, usize::MAX, DrainScope::All),
                        None => continue,
                    };
                    let mut keys = popped.clone();
                    keys.extend(cursor_keys);
                    OwingDrain::keyed(peer, family, usize::MAX, keys)
                };
                drain.close = true;
                self.distribute_owing_drain(&mut drain);
                match drain.outcome {
                    Some(Ok(())) => {
                        let set: FastSet<OwedKey> = popped.into_iter().collect();
                        drain.unstaged.retain(|key| set.contains(key));
                        self.reinsert_owed(peer, drain.unstaged);
                    }
                    _ => self.reinsert_owed(peer, popped),
                }
            }
            // Settle only freed markers; announcements left owed must not be absorbed.
            self.settle_free_eor(peer);
        }
    }

    /// Owed state toward `peer` for tests and the oracles: every key and
    /// whole family owed now or marked since the last read.
    #[cfg(test)]
    pub(super) fn take_owing_log(&mut self, peer: PeerId) -> Vec<((u16, u8), Option<String>)> {
        let mut log = self.owing_log.remove(&peer).unwrap_or_default();
        if let Some(owing) = self.owing(peer) {
            log.extend(owing.rendered());
        }
        log.into_iter().collect()
    }

    /// Bytes `peer`'s owed state holds.
    #[cfg(test)]
    pub(super) fn owing_bytes(&self, peer: PeerId) -> usize {
        self.owing(peer).map_or(0, PeerOwing::bytes)
    }

    /// Keys of `family` owed to `peer`.
    #[cfg(test)]
    pub(super) fn owed_key_count(&self, peer: PeerId, family: OwedFamily) -> usize {
        self.owing(peer).map_or(0, |owing| owing.keyed_len(family))
    }

    /// Whether `peer`'s EVPN cursor has read past `key`'s list entry.
    #[cfg(test)]
    pub(super) fn owed_evpn_cursor_passed(&self, peer: PeerId, key: &EvpnRouteKey) -> bool {
        self.owing(peer).is_some_and(|owing| {
            owing.is_whole(OwedFamily::EVPN)
                && self
                    .owed_evpn_rows
                    .live
                    .get(key)
                    .is_some_and(|logged| *logged <= owing.cursor[OwedFamily::EVPN_CURSOR])
        })
    }

    /// Whether `family` is owed whole to `peer`.
    #[cfg(test)]
    pub(super) fn owes_whole(&self, peer: PeerId, family: OwedFamily) -> bool {
        self.owing(peer).is_some_and(|owing| owing.is_whole(family))
    }
}

/// A family as the oracles number it.
#[cfg(test)]
fn wire((afi, safi): (Afi, Safi)) -> (u16, u8) {
    (afi as u16, safi as u8)
}

/// What a VPN or labeled pass toward one peer stages after the owed-key
/// gate (P3, P4).
pub(super) enum KeyedPass<'k, T: Clone> {
    /// Out of scope: slice 1a's preflight decides.
    Preflight,
    /// Stage `keys` within `budget` rows; the rest of the pass was marked.
    Stage {
        keys: std::borrow::Cow<'k, T>,
        budget: usize,
    },
    /// Nothing streams: every key was marked owed or its family is whole.
    Skip,
}

/// What a `FlowSpec`, BGP-LS or RT-Constrain pass toward one peer does after
/// the owed-key gate (P5 to P7): these families owe only whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WholePass {
    /// Out of scope: slice 1a's preflight decides.
    Preflight,
    /// Stage the pass; credit holds it.
    Stage,
    /// Owed whole: stage nothing.
    Skip,
}

impl RibManager {
    /// The P3/P4 gate over a pass's `keys` toward `peer`, whose two AFI
    /// families are `families` (`index` picks a key's). `carried` belongs
    /// to the pass and this key set: which of the two AFIs the keys carry,
    /// read once for the first peer that owes one of them whole.
    pub(super) fn owing_keyed_pass<'k, K, S>(
        &mut self,
        peer: PeerId,
        keys: &'k std::collections::HashSet<K, S>,
        families: [OwedFamily; 2],
        index: impl Fn(&K) -> usize,
        owed: impl Fn(&K) -> OwedKey,
        carried: &mut Option<[bool; 2]>,
    ) -> KeyedPass<'k, std::collections::HashSet<K, S>>
    where
        K: Clone + Eq + Hash,
        S: std::hash::BuildHasher + Default + Clone,
    {
        let gates = [
            self.owing_gate(peer, families[0]),
            self.owing_gate(peer, families[1]),
        ];
        if gates.iter().all(|gate| *gate == OwingGate::UNBOUNDED) {
            return KeyedPass::Preflight;
        }
        // Every AFI the pass carries is owed whole (a selection release
        // toward each private receiver): nothing is staged or marked, so
        // the keys are not visited per peer.
        if gates.contains(&OwingGate::Whole) {
            let carried = *carried.get_or_insert_with(|| {
                let mut carried = [false; 2];
                for key in keys {
                    carried[index(key)] = true;
                }
                carried
            });
            if (0..2).all(|afi| !carried[afi] || gates[afi] == OwingGate::Whole) {
                return KeyedPass::Skip;
            }
        }
        let budget = gates
            .iter()
            .filter_map(|gate| match gate {
                OwingGate::Stream { row_budget } => Some(*row_budget),
                _ => None,
            })
            .min();
        if gates
            .iter()
            .all(|gate| matches!(gate, OwingGate::Stream { .. }))
        {
            return KeyedPass::Stage {
                keys: std::borrow::Cow::Borrowed(keys),
                budget: budget.unwrap_or(usize::MAX),
            };
        }
        let sendable = self.peer_sendable_families.get(&peer);
        let mut kept = std::collections::HashSet::with_hasher(S::default());
        let mut marks = Vec::new();
        for key in keys {
            let family = families[index(key)];
            match gates[index(key)] {
                OwingGate::Stream { .. } => {
                    kept.insert(key.clone());
                }
                OwingGate::Owe
                    if sendable
                        .is_some_and(|sendable| sendable.contains(&family.afi_safis()[0])) =>
                {
                    marks.push(owed(key));
                }
                OwingGate::Owe | OwingGate::Whole => {}
            }
        }
        self.mark_owed(peer, marks);
        match budget {
            Some(budget) if !kept.is_empty() => KeyedPass::Stage {
                keys: std::borrow::Cow::Owned(kept),
                budget,
            },
            _ => KeyedPass::Skip,
        }
    }

    /// The P5-P7 gate for a pass of the whole-only `families` toward
    /// `peer`: spent credit or existing whole debt defers the whole pass.
    pub(super) fn owing_whole_pass(&mut self, peer: PeerId, families: &[OwedFamily]) -> WholePass {
        let gates: Vec<(OwedFamily, OwingGate)> = families
            .iter()
            .map(|&family| (family, self.owing_gate(peer, family)))
            .collect();
        if gates.iter().all(|(_, gate)| *gate == OwingGate::UNBOUNDED) {
            return WholePass::Preflight;
        }
        if gates
            .iter()
            .any(|(_, gate)| matches!(gate, OwingGate::Owe | OwingGate::Whole))
        {
            for (family, gate) in gates {
                if gate != OwingGate::UNBOUNDED {
                    self.owe_whole_family(peer, family);
                }
            }
            return WholePass::Skip;
        }
        WholePass::Stage
    }

    /// The P2 gate over a private EVPN pass's `keys` toward `peer`: the
    /// keys to stage and whether a credit budget bounded them, or `None`
    /// when nothing is staged (the keys were owed, the family is owed
    /// whole, or, out of scope, slice 1a's preflight refused). A streaming
    /// peer stages as many keys as its remaining credit holds, two rows a
    /// key at most, and owes the rest. `logged`: the pass logged `keys` for
    /// the cursors ([`Self::log_owed_evpn_rows`]); a restage of one
    /// receiver's view with every winner unchanged did not, so under a
    /// cursor its keys join that receiver's own set.
    pub(super) fn owing_evpn_pass<'k>(
        &mut self,
        peer: PeerId,
        keys: &'k HashSet<EvpnRouteKey>,
        logged: bool,
    ) -> Option<(std::borrow::Cow<'k, HashSet<EvpnRouteKey>>, bool)> {
        match self.owing_gate(peer, OwedFamily::EVPN) {
            OwingGate::Stream { row_budget } if row_budget == usize::MAX => (!self
                .outbound_preflight_refused(peer))
            .then_some((std::borrow::Cow::Borrowed(keys), false)),
            OwingGate::Stream { row_budget } => {
                let fits = (row_budget / 2).max(1);
                if keys.len() <= fits {
                    return Some((std::borrow::Cow::Borrowed(keys), true));
                }
                let mut staged = HashSet::with_capacity(fits);
                let mut marks = Vec::new();
                for &key in keys {
                    if staged.len() < fits {
                        staged.insert(key);
                    } else {
                        marks.push(OwedKey::Evpn(key));
                    }
                }
                self.mark_owed(peer, marks);
                Some((std::borrow::Cow::Owned(staged), true))
            }
            OwingGate::Owe => {
                self.mark_owed(peer, keys.iter().copied().map(OwedKey::Evpn));
                None
            }
            OwingGate::Whole => {
                if !logged {
                    self.mark_owed_unlogged(peer, keys.iter().copied().map(OwedKey::Evpn));
                }
                None
            }
        }
    }

    /// The most rows one key of `families` can stage toward `peer`: a
    /// withdrawal and an announcement per path, at the largest effective
    /// Add-Path cap among the families (the scalar send limit is the
    /// smallest). `None` for send-all, whose paths per key are unbounded.
    pub(super) fn owing_rows_per_key(
        &self,
        peer: PeerId,
        add_path: bool,
        families: &[(Afi, Safi)],
    ) -> Option<usize> {
        if !add_path {
            return Some(2);
        }
        let scalar = self.peer_add_path_send_max.get(&peer).copied().unwrap_or(0);
        let limits = self.peer_add_path_send_limits.get(&peer);
        let cap = families
            .iter()
            .map(|family| {
                limits
                    .and_then(|limits| limits.get(family))
                    .copied()
                    .unwrap_or(scalar)
            })
            .max()
            .unwrap_or(scalar);
        (cap != u32::MAX)
            .then(|| usize::try_from(cap).ok())
            .flatten()
            .map(|cap| 2 * cap.max(1))
    }

    /// A gated producer's send failed: count a credit refusal that got past
    /// a bounded gate, then take slice 1a's resync path.
    pub(super) fn owing_send_failed(
        &mut self,
        peer: PeerId,
        bounded: bool,
        failure: OutboundCommitFailure,
    ) -> bool {
        if bounded && failure == super::outbound_credit::CREDIT_REFUSAL {
            self.note_owing_credit_fallback();
        }
        self.mark_dirty_after_family_send_failure(peer, failure)
    }
}

/// The budget a pass of `keys` keys, at most `rows_per_key` rows each, is
/// staged under: unbounded (one staging call) when `budget` holds them all.
pub(super) fn pass_budget(keys: usize, rows_per_key: Option<usize>, budget: usize) -> usize {
    match rows_per_key {
        Some(rows) if keys.saturating_mul(rows) <= budget => usize::MAX,
        _ => budget,
    }
}

#[cfg(test)]
mod fifo_tests {
    use super::*;

    /// Cases of the list model test: a few seconds unoptimized.
    const MODEL_CASES: usize = 60;

    #[test]
    fn capacity_bytes_include_both_allocations_and_map_control_bytes() {
        fn check<K: Clone + Eq + Hash>() {
            let mut keys = OwedKeys::<K>::default();
            let entry_bytes = std::mem::size_of::<(K, u64)>();
            assert_eq!(keys.bytes(), 0);
            keys.order.reserve(17);
            assert_eq!(keys.bytes(), keys.order.capacity() * entry_bytes);
            keys.live.reserve(37);
            let entries = keys.order.capacity() + keys.live.capacity();
            assert_eq!(keys.bytes(), entries * entry_bytes + keys.live.capacity());
        }

        check::<Prefix>();
        check::<VpnRouteKey>();
        check::<EvpnRouteKey>();
    }

    #[test]
    fn family_key_cost_counts_two_entries_and_one_map_control_byte() {
        let prefix = std::mem::size_of::<(Prefix, u64)>();
        let vpn = std::mem::size_of::<(VpnRouteKey, u64)>();
        let evpn = std::mem::size_of::<(EvpnRouteKey, u64)>();
        for (family, entry_bytes) in [
            (OwedFamily::IPV4_UNICAST, prefix),
            (OwedFamily::IPV6_UNICAST, prefix),
            (OwedFamily::IPV4_LABELED, prefix),
            (OwedFamily::IPV6_LABELED, prefix),
            (OwedFamily::VPNV4, vpn),
            (OwedFamily::VPNV6, vpn),
            (OwedFamily::EVPN, evpn),
        ] {
            assert_eq!(
                family.key_cost(),
                entry_bytes + entry_bytes + std::mem::size_of::<u8>(),
                "{family:?}"
            );
        }
    }

    #[test]
    fn unicast_capacity_includes_the_exempt_index_for_each_afi() {
        let capacity_bytes = |keys: &OwedKeys<Prefix>| {
            (keys.order.capacity() + keys.live.capacity()) * std::mem::size_of::<(Prefix, u64)>()
                + keys.live.capacity()
        };
        let mut owing = PeerOwing::new(1);
        for (index, prefix) in [
            Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
                std::net::Ipv4Addr::new(192, 0, 2, 1),
                32,
            )),
            Prefix::V6(rustbgpd_wire::Ipv6Prefix::new(
                "2001:db8::1".parse().unwrap(),
                128,
            )),
        ]
        .into_iter()
        .enumerate()
        {
            let key = OwedKey::Unicast(prefix);
            let family = key.family();
            owing.insert(key, false);
            let main_bytes = capacity_bytes(&owing.unicast[index]);
            assert!(main_bytes > 0);
            assert_eq!(owing.set_bytes(family), main_bytes, "{family:?}");
            owing.insert(key, true);
            let exempt_bytes = capacity_bytes(&owing.unicast_exempt[index]);
            assert!(exempt_bytes > 0);
            assert_eq!(owing.keyed_len(family), 1);
            assert_eq!(owing.exempt_len(family), 1);
            assert_eq!(
                owing.set_bytes(family),
                main_bytes + exempt_bytes,
                "{family:?}"
            );
        }
        let v4_bytes = owing.set_bytes(OwedFamily::IPV4_UNICAST);
        owing.clear_family(OwedFamily::IPV6_UNICAST);
        assert_eq!(owing.keyed_len(OwedFamily::IPV6_UNICAST), 0);
        assert_eq!(owing.exempt_len(OwedFamily::IPV6_UNICAST), 0);
        assert_eq!(owing.set_bytes(OwedFamily::IPV6_UNICAST), 0);
        assert_eq!(owing.set_bytes(OwedFamily::IPV4_UNICAST), v4_bytes);
        owing.clear_family(OwedFamily::IPV4_UNICAST);
        assert_eq!(owing.set_bytes(OwedFamily::IPV4_UNICAST), 0);
    }

    #[test]
    fn clearing_a_family_preserves_sibling_whole_and_held_state() {
        let v4 = OwedFamily::IPV4_FLOWSPEC;
        let v6 = OwedFamily::IPV6_FLOWSPEC;
        for (drained, after_v4, after_v6) in [
            (0, 0, 0),
            (v4.bit(), 0, v4.bit()),
            (v6.bit(), v6.bit(), 0),
            (v4.bit() | v6.bit(), v6.bit(), v4.bit()),
        ] {
            for (family, whole, held) in [(v4, v6.bit(), after_v4), (v6, v4.bit(), after_v6)] {
                let mut owing = PeerOwing::new(1);
                owing.flip_whole(v4);
                owing.flip_whole(v6);
                owing.hold_drained = drained;
                owing.clear_family(family);
                assert_eq!(owing.whole, whole, "{family:?}, drained={drained}");
                assert_eq!(owing.hold_drained, held, "{family:?}, drained={drained}");
            }
        }
    }

    /// A unicast cursor keeps the keys already owed, and ending or clearing
    /// one AFI's cursor leaves the other's position alone.
    #[test]
    fn a_unicast_cursor_keeps_the_set_and_its_sibling() {
        let key = OwedKey::Unicast(Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
            std::net::Ipv4Addr::new(192, 0, 2, 1),
            32,
        )));
        let (v4, v6) = (OwedFamily::IPV4_UNICAST, OwedFamily::IPV6_UNICAST);
        for clear in [false, true] {
            let mut owing = PeerOwing::new(1);
            owing.insert(key, true);
            owing.start_cursor(0, 5);
            owing.start_cursor(1, 6);
            owing.hold_cursor = [7, 8, 0, 0, 0];
            assert_eq!(owing.keyed_len(v4), 1, "the set survives the flip");
            assert_eq!(owing.exempt_len(v4), 1);
            assert_eq!(owing.cursor_from(0, false), 5);
            assert_eq!(owing.cursor_from(0, true), 7);
            if clear {
                owing.clear_family(v4);
                assert_eq!(owing.keyed_len(v4), 0);
            } else {
                owing.end_cursor(0);
                assert_eq!(owing.keyed_len(v4), 1, "ending a cursor keeps the set");
                assert!(owing.owes(v4));
            }
            assert!(!owing.is_whole(v4));
            assert_eq!((owing.cursor[0], owing.hold_cursor[0]), (0, 0));
            assert!(owing.is_whole(v6));
            assert_eq!((owing.cursor[1], owing.hold_cursor[1]), (6, 8));
        }
    }

    fn row(index: u32) -> Prefix {
        Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
            std::net::Ipv4Addr::from(0x0a00_0000 + index),
            32,
        ))
    }

    /// The shared list: a key logged again moves to the back, a read
    /// resumes after its cursor and is bounded in keys, and a trim keeps
    /// the head.
    #[test]
    fn owed_rows_move_a_changed_key_to_the_back() {
        let key = row;
        let mut rows = OwedRows::default();
        for index in 0..5 {
            rows.touch(key(index));
        }
        assert_eq!(rows.after(0, 2), (vec![key(0), key(1)], 2));
        // Key 1 changes behind a cursor at 2, key 3 ahead of it.
        rows.touch(key(1));
        rows.touch(key(3));
        assert_eq!(rows.head(), 7);
        assert_eq!(rows.len(), 5);
        assert_eq!(
            rows.after(2, usize::MAX),
            (vec![key(2), key(4), key(1), key(3)], 7)
        );
        assert_eq!(rows.after(0, 2), (vec![key(0), key(2)], 3));
        assert_eq!(rows.after(5, 2), (vec![key(1), key(3)], 7), "the last keys");
        assert_eq!(rows.after(7, 9), (vec![], 7), "caught up");
        rows.trim(Some(5));
        assert_eq!(rows.len(), 2, "keys 1 and 3 are still ahead of a cursor");
        assert_eq!(rows.after(5, 9), (vec![key(1), key(3)], 7));
        rows.trim(None);
        assert_eq!(
            (rows.len(), rows.head()),
            (0, 7),
            "the head never goes back"
        );
        assert_eq!(rows.bytes(), 0);
    }

    /// Work count: no call does list maintenance that grows with the list.
    /// A cursor that reads nothing keeps `ROWS` keys in the list while one
    /// key changes over and over: every change moves that key's one entry,
    /// so the list holds no dead entries and no `touch` drops or scans any.
    /// When the cursor then leaves, the whole list is behind every cursor:
    /// each trim drops at most `TRIM_ROWS` entries and each key logged two,
    /// and the list still empties. Nothing is relocated or rehashed on the
    /// way down: the list has no capacity. Red when changed keys leave dead
    /// entries that one call compacts, and when a trim drops all it can.
    #[test]
    fn no_call_does_list_work_that_grows_with_the_list() {
        const ROWS: u32 = 50_000;
        let mut rows = OwedRows::default();
        for index in 0..ROWS {
            rows.touch(row(index));
        }
        // The stalled cursor sits before the first key.
        rows.trim(Some(0));
        for _ in 0..3 * ROWS {
            rows.touch(row(7));
            assert_eq!(rows.order.len(), rows.len(), "one entry per key");
        }
        rows.trim(Some(0));
        assert_eq!(rows.len(), ROWS as usize);
        assert_eq!(rows.dropped_max, 0, "nothing is behind the cursor");
        // The cursor leaves; another one waits at the head.
        let head = rows.head();
        let mut trims = 0;
        while rows.len() != 0 {
            let before = rows.len();
            rows.trim(Some(head));
            assert!(before - rows.len() <= TRIM_ROWS, "one trim dropped more");
            trims += 1;
        }
        assert_eq!(trims, (ROWS as usize).div_ceil(TRIM_ROWS));
        assert_eq!(rows.dropped_max, TRIM_ROWS);
        // Logging keys while entries wait drops two of them per key, so the
        // list does not grow, and never more.
        let mut rows = OwedRows::default();
        for index in 0..ROWS {
            rows.touch(row(index));
        }
        rows.floor = rows.head();
        for index in 0..1000 {
            let before = rows.len();
            rows.touch(row(ROWS + index));
            assert_eq!(rows.len(), before - 1, "two dropped, one logged");
        }
        assert_eq!(rows.dropped_max, 2);
    }

    /// An entry at the floor is behind every cursor: it still waits to be
    /// dropped, so the tick stays armed for it. Red when the entry at the
    /// floor is not counted: it is never dropped.
    #[test]
    fn an_entry_at_the_floor_still_waits_to_be_dropped() {
        let mut rows = OwedRows::default();
        for index in 0..=u32::try_from(TRIM_ROWS).unwrap() {
            rows.touch(row(index));
        }
        assert!(!rows.trimming(), "no cursor has moved");
        // The only cursor catches up: one trim leaves the newest entry.
        rows.trim(Some(rows.head()));
        assert_eq!(rows.len(), 1);
        assert!(rows.trimming(), "the entry at the floor");
        rows.trim(Some(rows.head()));
        assert_eq!(rows.len(), 0);
        assert!(!rows.trimming());
    }

    /// The cap reads the entries over it and no more: a cursor before the
    /// newest of them has more than the cap after it, one at or past it has
    /// not, and the entries over the cap are dropped once they are behind
    /// every cursor. Red when a cursor with exactly the cap after it is
    /// evicted, and when entries a cursor still waits for are dropped.
    #[test]
    fn the_cap_names_the_cursors_with_more_than_it_after_them() {
        let mut rows = OwedRows::default();
        for index in 0..10 {
            rows.touch(row(index));
        }
        assert_eq!(rows.over(10), None);
        assert_eq!(rows.over(11), None);
        // Three entries over a cap of seven: sequences 1, 2 and 3.
        assert_eq!(rows.over(7), Some(3));
        assert_eq!(rows.after(3, usize::MAX).0.len(), 7, "a cursor at 3 keeps");
        assert_eq!(rows.after(2, usize::MAX).0.len(), 8, "one at 2 is evicted");
        // A key logged again leaves no entry at its old sequence.
        rows.touch(row(1));
        assert_eq!(rows.over(7), Some(4), "sequences 1, 3 and 4 are left");
        // With a cursor at 3 only the entries behind it go.
        rows.trim(Some(3));
        assert_eq!(rows.len(), 8);
        rows.touch(row(20));
        rows.touch(row(21));
        rows.floor = 3;
        rows.drop_over(7);
        assert_eq!(rows.len(), 10, "nothing a cursor waits for is dropped");
        rows.floor = 6;
        rows.drop_over(7);
        assert_eq!(rows.len(), 7);
        assert_eq!(rows.after(6, usize::MAX).0.len(), 7);
    }

    /// The list against a model, under random operations: keys logged,
    /// steps of random size (with keys logged between a step's read and
    /// its cursor move), cursors that start and leave, and bounded trims.
    /// Every key logged after a cursor started is read after its last
    /// change before that cursor has caught up, no key is read without a
    /// change, and no key a cursor still waits for is dropped.
    #[test]
    fn the_list_matches_a_model_under_random_operations() {
        type Cursor = Option<(u64, HashSet<Prefix>)>;
        fn trim(rows: &mut OwedRows<Prefix>, cursors: &[Cursor]) {
            rows.trim(cursors.iter().flatten().map(|(cursor, _)| *cursor).min());
        }
        let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut random = move |below: u64| {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (seed >> 33) % below
        };
        let (mut reads, mut catch_ups) = (0usize, 0usize);
        for _ in 0..MODEL_CASES {
            let mut rows = OwedRows::default();
            let keyspace = 1 + random(9000);
            let mut cursors: Vec<Cursor> = vec![None; 5];
            for _ in 0..3000 {
                match random(10) {
                    0..=3 => {
                        let key = row(u32::try_from(random(keyspace)).unwrap());
                        rows.touch(key);
                        for (_, pending) in cursors.iter_mut().flatten() {
                            pending.insert(key);
                        }
                    }
                    4..=6 => {
                        let index = usize::try_from(random(5)).unwrap();
                        let Some((cursor, mut pending)) = cursors[index].take() else {
                            continue;
                        };
                        let count = usize::try_from(1 + random(2000)).unwrap();
                        let (keys, last) = rows.after(cursor, count);
                        assert!(keys.len() <= count);
                        for key in &keys {
                            assert!(pending.remove(key), "read with no change: {key}");
                        }
                        reads += keys.len();
                        // Keys logged between the read and the cursor move.
                        for _ in 0..random(3) {
                            let key = row(u32::try_from(random(keyspace)).unwrap());
                            rows.touch(key);
                            pending.insert(key);
                            for (_, pending) in cursors.iter_mut().flatten() {
                                pending.insert(key);
                            }
                        }
                        if last >= rows.head() {
                            assert!(pending.is_empty(), "caught up, {} unread", pending.len());
                            catch_ups += 1;
                            trim(&mut rows, &cursors);
                        } else {
                            cursors[index] = Some((last, pending));
                        }
                    }
                    7 => {
                        let index = usize::try_from(random(5)).unwrap();
                        if cursors[index].is_none() {
                            cursors[index] = Some((rows.head(), HashSet::new()));
                        }
                    }
                    8 => {
                        let index = usize::try_from(random(5)).unwrap();
                        if cursors[index].take().is_some() {
                            trim(&mut rows, &cursors);
                        }
                    }
                    _ => trim(&mut rows, &cursors),
                }
                assert_eq!(rows.order.len(), rows.live.len());
                for (cursor, pending) in cursors.iter().flatten() {
                    for key in pending {
                        let logged = rows.live.get(key).expect("a pending key was dropped");
                        assert!(logged > cursor, "a pending key behind its cursor");
                    }
                }
                assert!(rows.dropped_max <= TRIM_ROWS);
            }
        }
        assert!(
            reads > 1000 && catch_ups > 100,
            "{reads} reads, {catch_ups}"
        );
    }

    /// Work count: a set kept under a unicast cursor only drains, and no
    /// removal rebuilds it. Steps of one chunk remove its keys oldest
    /// first: no call changes a capacity or drops more than its own entry
    /// from the queue while keys are left, and the set is freed when its
    /// last key leaves. Red when a removal compacts the queue or releases
    /// capacity as the set shrinks: one call moves a share of the set.
    #[test]
    fn a_set_kept_under_a_cursor_drains_without_rebuilding() {
        const KEYS: u32 = 50_000;
        let family = OwedFamily::IPV4_UNICAST;
        let mut owing = PeerOwing::new(1);
        for index in 0..KEYS {
            owing.insert(OwedKey::Unicast(row(index)), index % 3 == 0);
        }
        owing.start_cursor(0, 0);
        let shape = |owing: &PeerOwing| {
            [&owing.unicast[0], &owing.unicast_exempt[0]]
                .map(|set| (set.order.capacity(), set.live.capacity(), set.order.len()))
        };
        let mut left = KEYS as usize;
        while left != 0 {
            for key in owing.copy_keys(family, DrainScope::All, CHUNK_ROWS) {
                let before = shape(&owing);
                owing.remove(&key);
                left -= 1;
                let sets = [&owing.unicast[0], &owing.unicast_exempt[0]];
                for ((set, before), after) in sets.into_iter().zip(before).zip(shape(&owing)) {
                    if set.len() == 0 {
                        assert_eq!(set.bytes(), 0, "an empty set is freed");
                        continue;
                    }
                    // A removal may leave a tombstone, which the map
                    // counts against its capacity; nothing is reallocated.
                    assert!(
                        after.0 == before.0 && before.1 - after.1 <= 1,
                        "a capacity changed with {} keys left: {before:?} to {after:?}",
                        set.len()
                    );
                    assert!(
                        before.2 - after.2 <= 1,
                        "{} entries moved",
                        before.2 - after.2
                    );
                }
            }
            assert_eq!(owing.keyed_len(family), left);
        }
        assert_eq!(owing.set_bytes(family), 0);
        assert!(owing.is_whole(family), "the cursor is ended by its step");
    }

    /// As above for the EVPN set, whose removal has its own arm: under a
    /// cursor it only drains, with no compaction and no capacity release.
    #[test]
    fn an_evpn_set_kept_under_a_cursor_drains_without_rebuilding() {
        const KEYS: u32 = 50_000;
        let family = OwedFamily::EVPN;
        let key = |index: u32| {
            rustbgpd_wire::EvpnRoute::Imet(rustbgpd_wire::EvpnImet {
                rd: rustbgpd_wire::RouteDistinguisher([0; 8]),
                ethernet_tag: rustbgpd_wire::EthernetTagId(index),
                originator_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            })
            .key()
        };
        let mut owing = PeerOwing::new(1);
        for index in 0..KEYS {
            owing.insert(OwedKey::Evpn(key(index)), false);
        }
        owing.start_cursor(OwedFamily::EVPN_CURSOR, 0);
        let shape = |owing: &PeerOwing| {
            let set = &owing.evpn;
            (set.order.capacity(), set.live.capacity(), set.order.len())
        };
        let mut left = KEYS as usize;
        while left != 0 {
            for key in owing.copy_keys(family, DrainScope::All, CHUNK_ROWS) {
                let before = shape(&owing);
                owing.remove(&key);
                left -= 1;
                if left == 0 {
                    assert_eq!(owing.set_bytes(family), 0, "an empty set is freed");
                    continue;
                }
                let after = shape(&owing);
                assert!(
                    after.0 == before.0 && before.1 - after.1 <= 1,
                    "a capacity changed with {left} keys left: {before:?} to {after:?}"
                );
                assert!(
                    before.2 - after.2 <= 1,
                    "{} entries moved",
                    before.2 - after.2
                );
            }
            assert_eq!(owing.keyed_len(family), left);
        }
        assert!(owing.is_whole(family), "the cursor is ended by its step");
    }

    #[test]
    fn canceled_tail_compaction_has_linear_hash_work() {
        #[derive(Clone)]
        struct CountedKey<'a> {
            value: usize,
            hashes: &'a std::cell::Cell<usize>,
        }

        impl PartialEq for CountedKey<'_> {
            fn eq(&self, other: &Self) -> bool {
                self.value == other.value
            }
        }

        impl Eq for CountedKey<'_> {}

        impl Hash for CountedKey<'_> {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                self.hashes.set(self.hashes.get() + 1);
                self.value.hash(state);
            }
        }

        const LIVE: usize = 1_024;
        const CHURN: usize = 4 * LIVE;
        let hashes = std::cell::Cell::new(0);
        let key = |value| CountedKey {
            value,
            hashes: &hashes,
        };
        let mut keys = OwedKeys::default();
        for value in 0..LIVE {
            keys.insert(key(value));
        }
        hashes.set(0);
        for value in LIVE..LIVE + CHURN {
            keys.insert(key(value));
            keys.remove(&key(value));
        }
        // Leave room for map growth as well as the amortized compaction scans.
        assert!(
            hashes.get() <= 12 * CHURN,
            "{} hashes for {CHURN} canceled tail keys",
            hashes.get()
        );
        assert_eq!(keys.len(), LIVE);
        assert!(keys.order.len() <= 2 * LIVE + 64);
        assert!(keys.iter().map(|key| key.value).eq(0..LIVE));
    }

    #[test]
    fn gradual_drain_shrinks_with_linear_queue_reallocation_work() {
        const PEAK: usize = 4_096;
        let mut keys = OwedKeys::default();
        for key in 0..PEAK {
            keys.insert(key);
        }
        let mut reallocated_entries = 0;
        for key in 0..PEAK {
            let capacity = keys.order.capacity();
            keys.remove(&key);
            let bound = 4 * keys.len() + 64;
            assert!(keys.order.capacity() <= bound);
            assert!(
                keys.live.capacity() <= bound,
                "{} map slots for {} live keys exceed {bound}",
                keys.live.capacity(),
                keys.len()
            );
            if keys.order.capacity() < capacity {
                // A capacity reduction may move every retained queue entry.
                reallocated_entries += keys.order.len();
            }
        }
        assert!(
            reallocated_entries <= 2 * PEAK,
            "{reallocated_entries} entries across queue capacity reductions"
        );
        assert_eq!(keys.len(), 0);
        assert!(keys.order.capacity() <= 64);
        assert!(keys.live.capacity() <= 64);
    }

    #[test]
    fn bulk_pop_releases_peak_capacity_with_small_or_empty_remainders() {
        let family = OwedFamily::IPV4_LABELED;
        let expected: Vec<_> = (0..1_024_u32)
            .map(|index| {
                OwedKey::Labeled(Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
                    std::net::Ipv4Addr::from(0x0a00_0000 + index),
                    32,
                )))
            })
            .collect();
        for remaining in [16, 0] {
            let mut owing = PeerOwing::new(1);
            for &key in &expected {
                owing.insert(key, false);
            }
            let count = expected.len() - remaining;
            assert_eq!(
                owing.pop_keys(family, count, DrainScope::All),
                expected[..count]
            );
            assert_eq!(
                owing.copy_keys(family, DrainScope::All, usize::MAX),
                expected[count..]
            );
            let keys = &owing.labeled[0];
            assert_eq!(keys.len(), remaining);
            assert!(keys.order.capacity() <= 4 * remaining + 64);
            assert!(keys.live.capacity() <= 4 * remaining + 64);
        }
    }

    #[test]
    fn marks_keep_fifo_order_and_canceled_entries_are_compacted() {
        let mut keys = OwedKeys::default();
        keys.insert(0);
        keys.insert(1);
        keys.insert(0);
        keys.remove(&1);
        keys.insert(2);
        keys.insert(1);
        for key in 3..1_000 {
            keys.insert(key);
            keys.remove(&key);
        }
        assert!(keys.order.len() <= 2 * keys.live.len() + 64);
        assert_eq!(keys.pop(), Some(0));
        assert_eq!(keys.pop(), Some(2));
        assert_eq!(keys.pop(), Some(1));
        assert_eq!(keys.pop(), None);
    }

    #[test]
    fn exempt_index_preserves_normal_fifo_and_updates_existing_marks() {
        let key = |index| {
            OwedKey::Unicast(Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
                std::net::Ipv4Addr::new(192, 0, 2, index),
                32,
            )))
        };
        let mut owing = PeerOwing::new(1);
        let family = OwedFamily::IPV4_UNICAST;
        owing.insert(key(1), false);
        owing.insert(key(2), true);
        assert_eq!(owing.copy_keys(family, DrainScope::All, 1), [key(1)]);
        assert_eq!(owing.copy_keys(family, DrainScope::Exempt, 1), [key(2)]);
        owing.insert(key(1), true);
        assert_eq!(owing.keyed_len(family), 2);
        assert_eq!(owing.exempt_len(family), 2);
        assert_eq!(
            owing.copy_keys(family, DrainScope::All, 2),
            [key(1), key(2)]
        );
        owing.remove(&key(2));
        assert_eq!(owing.copy_keys(family, DrainScope::Exempt, 1), [key(1)]);
        owing.insert(key(1), false);
        assert_eq!(owing.exempt_len(family), 0);
        assert_eq!(owing.keyed_len(family), 1);
    }
}

#[cfg(test)]
mod family_tests {
    use super::*;

    #[test]
    fn cursor_slots_and_private_group_ownership_match_enabled_families() {
        use OwedFamily as F;
        assert_eq!(
            F::CURSORS,
            [
                F::IPV4_UNICAST,
                F::IPV6_UNICAST,
                F::IPV4_LABELED,
                F::IPV6_LABELED,
                F::EVPN
            ]
        );
        assert_eq!(
            F::GROUPED_CURSORS,
            [F::IPV4_LABELED, F::IPV6_LABELED, F::EVPN]
        );
        for family in F::ALL {
            assert_eq!(
                family.cursor_index(),
                F::CURSORS.iter().position(|&active| active == family),
                "{family:?}",
            );
            assert_eq!(
                family.private_while_grouped(),
                matches!(family, F::IPV4_LABELED | F::IPV6_LABELED | F::EVPN),
                "{family:?}",
            );
        }
    }

    /// Every `FlowSpec` family a rule can carry has its own owed family, and
    /// the table is a consistent index. A new AFI fails the known-set check
    /// until someone decides whether its `FlowSpec` families are owed.
    #[test]
    fn every_flowspec_family_has_an_owed_family() {
        let afis: Vec<Afi> = (0..=u16::MAX).filter_map(Afi::from_u16).collect();
        assert_eq!(
            afis,
            [Afi::Ipv4, Afi::Ipv6, Afi::L2Vpn, Afi::BgpLs],
            "a new AFI: decide whether its FlowSpec families are owed"
        );
        let rd = rustbgpd_wire::RouteDistinguisher([0, 0, 0, 0, 0, 0, 0, 1]);
        let mut flowspec = HashSet::new();
        for afi in [Afi::Ipv4, Afi::Ipv6] {
            for rd in [None, Some(&rd)] {
                let family = crate::route::flowspec_family(afi, rd);
                let owed = OwedFamily::of(family)
                    .unwrap_or_else(|| panic!("{family:?} has no owed family"));
                assert!(owed.is_flowspec(), "{family:?}");
                assert_eq!(owed.afi_safis(), [family]);
                flowspec.insert(owed);
            }
        }
        assert_eq!(
            flowspec,
            OwedFamily::ALL
                .into_iter()
                .filter(|family| family.is_flowspec())
                .collect()
        );
        assert_eq!(OwedFamily::ALL.len(), usize::from(OwedFamily::COUNT));
        assert!(
            u32::from(OwedFamily::COUNT) <= u16::BITS,
            "`whole` is a u16"
        );
        for (index, family) in OwedFamily::ALL.into_iter().enumerate() {
            assert_eq!(usize::from(family.0), index);
            for &afi_safi in family.afi_safis() {
                assert_eq!(OwedFamily::of(afi_safi), Some(family), "{afi_safi:?}");
            }
        }
    }
}
