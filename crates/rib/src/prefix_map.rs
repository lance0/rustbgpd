//! Family-split prefix map.
//!
//! `prefix_trie::PrefixMap` is single-family, while the RIB keys its maps by the
//! mixed-family [`Prefix`] enum. This wraps one IPv4 and one IPv6 trie behind the
//! `HashMap<Prefix, V>` subset the RIB's prefix indexes actually use
//! (`entry_or_default` / `get` / `get_mut` / `remove` / `clear`).
//!
//! Motivation (2026-06-02 whole-daemon dhat profile): the live-at-peak heap is
//! ~76% RIB map/index `hashbrown` bucket arrays. A trie stores prefixes in a
//! bit-tree rather than an over-allocated bucket array, which is more compact for
//! large prefix sets. Backs `AdjRibIn::prefix_index` and
//! `AdjRibOut::prefix_path_ids`; the Loc-RIB best-path map deliberately stays on
//! `HashMap` because the trie regressed its lookup-hot recompute (see
//! `docs/BENCHMARKS.md`).

use ipnet::{Ipv4Net, Ipv6Net};
use prefix_trie::PrefixMap;
use rustbgpd_wire::{Ipv4Prefix, Ipv6Prefix, Prefix};

/// A `Prefix`-keyed map backed by per-family prefix tries.
#[derive(Debug)]
pub(crate) struct FamilyPrefixMap<V> {
    v4: PrefixMap<Ipv4Net, V>,
    v6: PrefixMap<Ipv6Net, V>,
}

impl<V> Default for FamilyPrefixMap<V> {
    fn default() -> Self {
        Self {
            v4: PrefixMap::new(),
            v6: PrefixMap::new(),
        }
    }
}

// rustbgpd's `Prefix` is canonical by construction: `Ipv4Prefix::new` /
// `Ipv6Prefix::new` clamp the length and zero host bits. The fields are public,
// so this relies on callers preserving that constructor invariant. `Ipv?Net::new`
// only validates the length (it preserves host bits rather than rejecting them),
// so this conversion is infallible for canonical `Prefix` values that reached
// the RIB.
fn v4_net(p: Ipv4Prefix) -> Ipv4Net {
    Ipv4Net::new(p.addr, p.len).expect("valid IPv4 prefix length")
}
fn v6_net(p: Ipv6Prefix) -> Ipv6Net {
    Ipv6Net::new(p.addr, p.len).expect("valid IPv6 prefix length")
}

impl<V> FamilyPrefixMap<V> {
    pub(crate) fn get(&self, prefix: &Prefix) -> Option<&V> {
        match prefix {
            Prefix::V4(p) => self.v4.get(&v4_net(*p)),
            Prefix::V6(p) => self.v6.get(&v6_net(*p)),
        }
    }

    pub(crate) fn get_mut(&mut self, prefix: &Prefix) -> Option<&mut V> {
        match prefix {
            Prefix::V4(p) => self.v4.get_mut(&v4_net(*p)),
            Prefix::V6(p) => self.v6.get_mut(&v6_net(*p)),
        }
    }

    pub(crate) fn remove(&mut self, prefix: &Prefix) -> Option<V> {
        match prefix {
            Prefix::V4(p) => self.v4.remove(&v4_net(*p)),
            Prefix::V6(p) => self.v6.remove(&v6_net(*p)),
        }
    }

    pub(crate) fn clear(&mut self) {
        self.v4.clear();
        self.v6.clear();
    }
}

impl<V: Default> FamilyPrefixMap<V> {
    /// Return a mutable reference to the value for `prefix`, inserting `V::default()`
    /// if absent — mirrors `HashMap::entry(_).or_default()`.
    pub(crate) fn entry_or_default(&mut self, prefix: Prefix) -> &mut V {
        match prefix {
            Prefix::V4(p) => self.v4.entry(v4_net(p)).or_default(),
            Prefix::V6(p) => self.v6.entry(v6_net(p)).or_default(),
        }
    }
}
