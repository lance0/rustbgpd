//! Owed-key sets for private families (ADR-0145 slice 1b).
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
//!   BGP-LS or RT-Constrain family, owes the whole family instead; the
//!   drain then runs one family-scoped resync under an operation latch.
//! - Every barrier (End-of-RIB, a refresh's markers, a replay terminal)
//!   first absorbs its family's owed keys into the same operation, so no
//!   owed key of that family is left behind the marker.
//! - A key no source still offers and the peer does not hold is cancelled
//!   (the keep-set below mirrors the resync enumeration).

use std::collections::HashSet;
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
        if self.live.remove(key).is_some() {
            while self
                .order
                .front()
                .is_some_and(|(key, sequence)| self.live.get(key) != Some(sequence))
            {
                self.order.pop_front();
            }
            self.compact();
            self.shrink();
        }
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
            self.live.shrink_to(2 * len);
        }
    }

    fn clear(&mut self) {
        *self = Self::default();
    }
}

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
    const COUNT: u8 = 11;

    /// Every owed family, in drain rotation order.
    pub(super) const ALL: [Self; 11] = [
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
    ];

    /// The owed family of a negotiated `(AFI, SAFI)`; both BGP-LS families
    /// share one.
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
            (Afi::BgpLs, _) => Self::BGP_LS,
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
            Self::BGP_LS => &[(Afi::BgpLs, Safi::BgpLs), (Afi::BgpLs, Safi::BgpLsVpn)],
            _ => &[(Afi::Ipv4, Safi::RtConstrain)],
        }
    }

    fn bit(self) -> u16 {
        1 << self.0
    }

    pub(super) fn is_unicast(self) -> bool {
        self == Self::IPV4_UNICAST || self == Self::IPV6_UNICAST
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
    /// A bit per [`OwedFamily`] owed whole.
    whole: u16,
    /// A bit per whole family already drained inside the current selection
    /// hold (its exempt rows); it stays owed for the release.
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
            hold_drained: 0,
            next_family: 0,
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
                self.unicast[afi_index(prefix)].remove(prefix);
                self.unicast_exempt[afi_index(prefix)].remove(prefix);
            }
            OwedKey::Labeled(prefix) => self.labeled[afi_index(prefix)].remove(prefix),
            OwedKey::Vpn(key) => {
                let index = usize::from(OwedFamily::vpn_of(key) == OwedFamily::VPNV6);
                self.vpn[index].remove(key);
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
        self.clear_family(family);
        self.whole |= family.bit();
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
        self.take_owing(peer).is_some()
    }

    /// Whether `peer` owes anything of `family` (keys or the whole family).
    pub(super) fn owes(&self, peer: PeerId, family: (Afi, Safi)) -> bool {
        OwedFamily::of(family)
            .is_some_and(|family| self.owing(peer).is_some_and(|owing| owing.owes(family)))
    }

    /// Whether `family` toward `peer` is held in the peer's own Adj-RIB-Out
    /// and so may owe keys: group-owned and handoff EVPN families keep
    /// slice 1a's path.
    fn owing_family_in_scope(&self, peer: PeerId, family: OwedFamily) -> bool {
        match family {
            OwedFamily::IPV4_UNICAST | OwedFamily::IPV6_UNICAST => {
                self.grouped_member_of(peer).is_none()
            }
            OwedFamily::VPNV4 | OwedFamily::VPNV6 => self.vpn_grouped_member_of(peer).is_none(),
            OwedFamily::EVPN => {
                self.evpn_grouped_member_of(peer).is_none() && !self.has_private_evpn_handoff(peer)
            }
            _ => true,
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
                // while the rest of this whole family stays held.
                let held_exempt = (family.is_unicast()
                    || family == OwedFamily::IPV4_FLOWSPEC
                    || family == OwedFamily::IPV6_FLOWSPEC)
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
        if rows >= limit {
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
        let mut keys = keys.into_iter().peekable();
        if keys.peek().is_none() {
            return;
        }
        let session_id = self.outbound_session_ids.get(&peer).copied().unwrap_or(0);
        let mut owing = self
            .take_owing(peer)
            .unwrap_or_else(|| Box::new(PeerOwing::new(session_id)));
        let mut touched = 0u16;
        for key in keys {
            self.replacement_checkpoint(false);
            let family = key.family();
            if owing.is_whole(family) {
                owing.hold_drained &= !family.bit();
                continue;
            }
            touched |= family.bit();
            if self.owed_key_kept(peer, &key) {
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
        for family in OwedFamily::ALL {
            if touched & family.bit() != 0
                && owing.set_bytes(family) > self.owing_theta(peer, family)
            {
                owing.flip_whole(family);
                self.note_owing_whole(peer, family);
            }
        }
        self.put_owing(peer, owing);
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
            if !owing.is_whole(key.family()) {
                let exempt = self.owed_key_exempt(peer, &key);
                owing.insert(key, exempt);
            }
        }
        self.put_owing(peer, owing);
    }

    /// Owe `family` whole to `peer` (a whole-only family's refusal).
    pub(super) fn owe_whole_family(&mut self, peer: PeerId, family: OwedFamily) {
        let session_id = self.outbound_session_ids.get(&peer).copied().unwrap_or(0);
        let mut owing = self
            .take_owing(peer)
            .unwrap_or_else(|| Box::new(PeerOwing::new(session_id)));
        if !owing.is_whole(family) {
            owing.flip_whole(family);
            self.note_owing_whole(peer, family);
        }
        // New debt inside a selection hold gets its own exempt pass.
        owing.hold_drained &= !family.bit();
        self.put_owing(peer, owing);
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
    /// every family it enumerated, so nothing of those is owed any more.
    /// Selection-deferred families were not enumerated and stay owed.
    pub(super) fn owing_resync_covered(&mut self, peer: PeerId) {
        let Some(mut owing) = self.take_owing(peer) else {
            return;
        };
        for family in OwedFamily::ALL {
            if !family
                .afi_safis()
                .iter()
                .any(|&afi_safi| self.selection_deferred(afi_safi))
            {
                owing.clear_family(family);
            }
        }
        self.put_owing(peer, owing);
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
                out.iter_prefix(prefix).any(|route| {
                    route.peer == super::helpers::LOCAL_PEER
                        || out.local_export_source(prefix, route.path_id).is_some()
                })
            })
    }

    /// Whether `peer` may still need `key`: the key has a candidate, the
    /// peer holds it, the family carries recovery residue, or a per-key
    /// record (a rejection, an OTC block, a policy denial, a GR carried
    /// withdrawal) still names it. Mirrors the resync enumeration.
    pub(super) fn owed_key_kept(&self, peer: PeerId, key: &OwedKey) -> bool {
        use crate::update::ExactExportKey;
        let out = self.adj_ribs_out.get(&peer);
        let rejected = self.peer_unexportable.get(&peer);
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
                    || rejected.is_some_and(|keys| {
                        keys.iter()
                            .any(|key| matches!(key, ExactExportKey::Unicast(p, _) if p == prefix))
                    })
                    || self
                        .peer_otc_blocked
                        .get(&peer)
                        .is_some_and(|blocked| blocked.contains_key(prefix))
                    || self
                        .pending_otc_blocked
                        .get(&peer)
                        .is_some_and(|pending| pending.keys().any(|(p, _)| p == prefix))
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
                    || rejected.is_some_and(|keys| {
                        keys.iter().any(
                            |key| matches!(key, ExactExportKey::Labeled(k) if k.prefix == *prefix),
                        )
                    })
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
                    || rejected.is_some_and(|keys| {
                        keys.iter().any(
                            |key| matches!(key, ExactExportKey::Vpn(k) if k.nlri_key == *nlri_key),
                        )
                    })
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
        if family.is_unicast() && owing.exempt_len(family) != 0 {
            return Some(DrainScope::Exempt);
        }
        let exempt_whole = family.is_unicast()
            || family == OwedFamily::IPV4_FLOWSPEC
            || family == OwedFamily::IPV6_FLOWSPEC;
        (exempt_whole && owing.is_whole(family) && !owing.whole_drained_in_hold(family))
            .then_some(DrainScope::Exempt)
    }

    /// Whether `family` of `owing` is drainable now (`latch_free`: a whole
    /// family needs `peer`'s operation latch).
    fn owed_family_drainable(
        &self,
        peer: PeerId,
        owing: &PeerOwing,
        family: OwedFamily,
        latch_free: bool,
    ) -> Option<DrainScope> {
        if !owing.owes(family) || (owing.is_whole(family) && !latch_free) {
            return None;
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
                    owing.is_whole(family) && self.owed_drain_scope(peer, owing, family).is_some()
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

    /// A pending End-of-RIB of `peer` that waits only for its family's owed
    /// keys to be absorbed.
    pub(super) fn owed_eor_ready(&self, peer: PeerId) -> bool {
        self.pending_eor.get(&peer).is_some_and(|families| {
            families.iter().any(|&family| {
                self.owes(peer, family) && self.pending_marker_family_ready_unowed(peer, family)
            })
        })
    }

    /// Whether `peer` has owed work the resync tick can run: a runnable
    /// family (a whole family needs its latch free), or an End-of-RIB that
    /// waits for an absorption with the latch free. Credit is not part of
    /// it: the tick polls for returned credit.
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
        }) || (latch_free && self.owed_eor_ready(peer))
    }

    /// Whether any peer has owed work the resync tick can run.
    pub(super) fn owing_runnable(&self) -> bool {
        self.owing_peers.iter().any(|&peer| {
            self.replacement_checkpoint(false);
            self.owing_peer_runnable(peer)
        })
    }

    /// Whether some owing peer could make progress this tick: it has credit
    /// and runnable work, or an End-of-RIB waits on an absorption with its
    /// latch free. Read before taking the tick's executor handoff.
    pub(super) fn owing_tick_due(&self) -> bool {
        let limit = self.outbound_row_credit();
        self.owing_peers.iter().any(|&peer| {
            self.owing_peer_runnable(peer)
                && (self
                    .outbound_credit
                    .get(&peer)
                    .is_some_and(|entry| entry.credit.rows() < limit)
                    || (!self.outbound_operation_live(peer) && self.owed_eor_ready(peer)))
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
    /// owing peers from [`Self::owing_cursor`]: per peer, retry a barrier
    /// waiting on an absorption, then, with credit, run one step of its next
    /// runnable family. Rounds repeat while a step progressed. Returns
    /// whether the budget cut the slice short.
    pub(super) fn drain_owing_bounded(&mut self, poll_start: std::time::Instant) -> bool {
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
        let mut progressed = false;
        if !self.outbound_operation_live(peer) && self.owed_eor_ready(peer) {
            let before = self.pending_eor.get(&peer).map_or(0, HashSet::len);
            self.flush_pending_eor(peer);
            progressed |= self.pending_eor.get(&peer).map_or(0, HashSet::len) < before;
        }
        let limit = self.outbound_row_credit();
        let rows = self
            .outbound_credit
            .get(&peer)
            .map_or(limit, |entry| entry.credit.rows());
        if rows >= limit {
            return progressed;
        }
        let Some((family, scope)) = self.next_owed_family(peer) else {
            return progressed;
        };
        self.owing_drain_step(peer, family, scope, limit - rows) || progressed
    }

    /// One drain step of `family`'s `scope` toward `peer` within `budget`
    /// rows.
    fn owing_drain_step(
        &mut self,
        peer: PeerId,
        family: OwedFamily,
        scope: DrainScope,
        budget: usize,
    ) -> bool {
        let Some(owing) = self.owing(peer) else {
            return false;
        };
        if owing.is_whole(family) {
            if self.outbound_operation_live(peer) {
                return false;
            }
            let mut drain = OwingDrain::whole(peer, family);
            self.distribute_owing_drain(&mut drain);
            return match drain.outcome {
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
            };
        }
        let add_path = match family {
            OwedFamily::IPV4_LABELED | OwedFamily::IPV6_LABELED => {
                self.peer_labeled_add_path_send(peer)
            }
            OwedFamily::VPNV4 | OwedFamily::VPNV6 => self.peer_vpn_add_path_send(peer),
            _ => false,
        };
        // Fit the FIFO batch before unordered staging; an unbounded
        // Add-Path key takes a credit window by itself.
        let add_path = add_path || (family.is_unicast() && self.peer_has_any_add_path_send(peer));
        let count = self
            .owing_rows_per_key(peer, add_path, family.afi_safis())
            .map_or(1, |rows| CHUNK_ROWS.min((budget / rows).max(1)));
        // Keep unstaged and refused keys in place until admission succeeds.
        let keys = self
            .owing(peer)
            .expect("the peer still owes keys")
            .copy_keys(family, scope, count);
        let popped = keys.len();
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

    /// After a drain of `family` ended without a refusal: a family that no
    /// longer owes anything clears its whole bit, and its End-of-RIB, if one
    /// waits, goes out now.
    fn owing_family_settled(&mut self, peer: PeerId, family: OwedFamily) {
        if let Some(mut owing) = self.take_owing(peer) {
            if owing.is_whole(family) {
                owing.clear_family(family);
            }
            self.put_owing(peer, owing);
        }
        if !self.owing(peer).is_some_and(|owing| owing.owes(family))
            && self.pending_eor.get(&peer).is_some_and(|families| {
                family
                    .afi_safis()
                    .iter()
                    .any(|afi_safi| families.contains(afi_safi))
            })
        {
            self.flush_pending_eor(peer);
        }
    }

    /// A drain refused for anything but capacity or credit (a missing
    /// encoder, EVPN recovery, a selection gate): owed state cannot make
    /// progress, so the peer resyncs instead.
    fn owing_fallback(&mut self, peer: PeerId, failure: OutboundCommitFailure) {
        debug!(%peer, reason = failure.as_str(), "owed keys cannot drain — peer resyncs");
        self.drop_peer_owing(peer);
        self.metrics.record_rib_outbound_owing_fallback();
        self.mark_outbound_dirty_inner(peer, false);
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
        let Some(family) = OwedFamily::of(family) else {
            return Ok(());
        };
        // A dirty or forced peer's resync covers what it owes.
        if self.dirty_peers.contains(&peer) || self.force_outbound_peers.contains(&peer) {
            return Ok(());
        }
        let Some(owing) = self.owing(peer) else {
            return Ok(());
        };
        if !owing.owes(family) {
            return Ok(());
        }
        let mut drain = if owing.is_whole(family) {
            OwingDrain::whole(peer, family)
        } else {
            // Copied, not popped: a refusal leaves the set as it was.
            OwingDrain::keyed(
                peer,
                family,
                usize::MAX,
                owing.copy_keys(family, DrainScope::All, usize::MAX),
            )
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
                let mut drain = if owing.is_whole(family) {
                    if self.outbound_operation_live(peer) {
                        debug!(%peer, ?family, "owed family not flushed at close: a whole-table update is still live");
                        continue;
                    }
                    OwingDrain::whole(peer, family)
                } else {
                    let keys = match self
                        .outbound_credit
                        .get_mut(&peer)
                        .and_then(|entry| entry.owing.as_deref_mut())
                    {
                        Some(owing) => owing.pop_keys(family, usize::MAX, DrainScope::All),
                        None => continue,
                    };
                    OwingDrain::keyed(peer, family, usize::MAX, keys)
                };
                drain.close = true;
                let popped: Vec<OwedKey> = drain_keys(&drain);
                self.distribute_owing_drain(&mut drain);
                match drain.outcome {
                    Some(Ok(())) => self.reinsert_owed(peer, drain.unstaged),
                    _ => self.reinsert_owed(peer, popped),
                }
            }
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

/// The keys a keyed drain carries, to re-insert after a refusal.
fn drain_keys(drain: &OwingDrain) -> Vec<OwedKey> {
    drain
        .unicast
        .iter()
        .copied()
        .map(OwedKey::Unicast)
        .chain(drain.labeled.iter().copied().map(OwedKey::Labeled))
        .chain(drain.vpn.iter().copied().map(OwedKey::Vpn))
        .chain(drain.evpn.iter().copied().map(OwedKey::Evpn))
        .collect()
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
    /// families are `families` (`index` picks a key's).
    pub(super) fn owing_keyed_pass<'k, K, S>(
        &mut self,
        peer: PeerId,
        keys: &'k std::collections::HashSet<K, S>,
        families: [OwedFamily; 2],
        index: impl Fn(&K) -> usize,
        owed: impl Fn(&K) -> OwedKey,
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
    /// `peer`: spent credit owes each of them whole.
    pub(super) fn owing_whole_pass(&mut self, peer: PeerId, families: &[OwedFamily]) -> WholePass {
        let gates: Vec<(OwedFamily, OwingGate)> = families
            .iter()
            .map(|&family| (family, self.owing_gate(peer, family)))
            .collect();
        if gates.iter().all(|(_, gate)| *gate == OwingGate::UNBOUNDED) {
            return WholePass::Preflight;
        }
        if gates.iter().any(|(_, gate)| *gate == OwingGate::Owe) {
            for (family, gate) in gates {
                if gate != OwingGate::UNBOUNDED {
                    self.owe_whole_family(peer, family);
                }
            }
            return WholePass::Skip;
        }
        if gates.iter().all(|(_, gate)| *gate == OwingGate::Whole) {
            WholePass::Skip
        } else {
            WholePass::Stage
        }
    }

    /// The P2 gate over a private EVPN pass's `keys` toward `peer`: the
    /// keys to stage and whether a credit budget bounded them, or `None`
    /// when nothing is staged (the keys were owed, the family is owed
    /// whole, or, out of scope, slice 1a's preflight refused). A streaming
    /// peer stages as many keys as its remaining credit holds, two rows a
    /// key at most, and owes the rest.
    pub(super) fn owing_evpn_pass<'k>(
        &mut self,
        peer: PeerId,
        keys: &'k HashSet<EvpnRouteKey>,
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
            OwingGate::Whole => None,
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
