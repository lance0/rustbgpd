//! The hasher behind the RIB's route-bearing maps, named in one place so a
//! hasher change is a one-line edit. The `HashDoS` rationale for the choice
//! is the block at the top of `adj_rib_in`.

/// `BuildHasher` for the route-bearing maps. Construct it with
/// `FastState::default()`, never a unit literal, so a seeded hasher can
/// replace it here without touching call sites.
pub(crate) type FastState = rustc_hash::FxBuildHasher;
pub(crate) type FastMap<K, V> = std::collections::HashMap<K, V, FastState>;
pub(crate) type FastSet<T> = std::collections::HashSet<T, FastState>;

/// Entries a [`ShardedMap`] holds in one table before it splits.
pub(crate) const SHARD_SPLIT_AT: usize = 1 << 14;
/// Tables in a split [`ShardedMap`]. At a million VPN routes 16 shards keep
/// each grown shard large enough that the allocator returns the replaced
/// table at once; 64 shards held about 330 MB of replaced tables at the peak
/// of a 1.23M-key load.
pub(crate) const SHARDS: usize = 16;

/// The shard a key occupies once a [`ShardedMap`] is split: a multiplicative
/// mix of the key's hash, so each shard still spreads over hashbrown's tag
/// (top) and bucket (low) bits.
pub(crate) fn shard_index<Q: std::hash::Hash + ?Sized>(key: &Q) -> usize {
    use std::hash::BuildHasher;
    let mixed = FastState::default()
        .hash_one(key)
        .wrapping_mul(0x9e37_79b9_7f4a_7c15);
    // The top four bits select one of 16 shards.
    usize::try_from(mixed >> 60).expect("four bits fit usize")
}

/// Grow `table` through `insert` past one table's split limit and assert that
/// no single insert grew `capacity` by more than [`SHARD_SPLIT_AT`] slots.
/// A plain map that doubles at that size rehashes every entry inside one
/// insert, which at full-table scale stalls the RIB actor for a whole UPDATE.
#[cfg(test)]
pub(crate) fn assert_growth_bounded<T>(
    name: &str,
    table: &mut T,
    mut insert: impl FnMut(&mut T, u32),
    capacity: impl Fn(&T) -> usize,
) {
    let count = u32::try_from(SHARD_SPLIT_AT * 2).expect("test size fits u32");
    let mut before = capacity(table);
    for i in 0..count {
        insert(table, i);
        let after = capacity(table);
        assert!(
            after.saturating_sub(before) <= SHARD_SPLIT_AT,
            "{name}: insert {i} grew capacity {before} -> {after}, rehashing the whole table"
        );
        before = after;
    }
}

/// A [`FastMap`] that splits into fixed hash shards once it is large.
///
/// A plain map doubles by rehashing every entry inside one insert: about
/// 180 ms for a 1M-entry VPN route map, and several such maps can grow in
/// one UPDATE. A split map grows one shard at a time, so an insert rehashes
/// at most about 1/16 of the entries and the total rehash work is unchanged.
/// Iteration order is unspecified, as for any hash map.
#[derive(Debug)]
pub(crate) enum ShardedMap<K, V> {
    One(FastMap<K, V>),
    Split(Box<[FastMap<K, V>]>),
}

impl<K, V> Default for ShardedMap<K, V> {
    fn default() -> Self {
        Self::One(FastMap::default())
    }
}

impl<K, V> ShardedMap<K, V> {
    pub(crate) fn shards(&self) -> &[FastMap<K, V>] {
        match self {
            Self::One(map) => std::slice::from_ref(map),
            Self::Split(shards) => shards,
        }
    }

    pub(crate) fn shards_mut(&mut self) -> &mut [FastMap<K, V>] {
        match self {
            Self::One(map) => std::slice::from_mut(map),
            Self::Split(shards) => shards,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.shards().iter().map(FastMap::len).sum()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.shards().iter().all(FastMap::is_empty)
    }

    pub(crate) fn capacity(&self) -> usize {
        self.shards().iter().map(FastMap::capacity).sum()
    }

    /// Keep only the entries `keep` accepts, shard by shard.
    pub(crate) fn retain(&mut self, mut keep: impl FnMut(&K, &mut V) -> bool) {
        for shard in self.shards_mut() {
            shard.retain(&mut keep);
        }
    }

    /// Remove every entry, keeping the shard tables' allocations.
    pub(crate) fn clear(&mut self) {
        self.shards_mut().iter_mut().for_each(FastMap::clear);
    }

    pub(crate) fn iter(&self) -> impl ExactSizeIterator<Item = (&K, &V)> {
        ShardIter::new(self.len(), self.shards().iter().map(FastMap::iter))
    }

    pub(crate) fn iter_mut(&mut self) -> impl ExactSizeIterator<Item = (&K, &mut V)> {
        let len = self.len();
        ShardIter::new(len, self.shards_mut().iter_mut().map(FastMap::iter_mut))
    }

    pub(crate) fn keys(&self) -> impl ExactSizeIterator<Item = &K> {
        self.iter().map(|(key, _)| key)
    }

    pub(crate) fn values(&self) -> impl ExactSizeIterator<Item = &V> {
        self.iter().map(|(_, value)| value)
    }
}

impl<K: Eq + std::hash::Hash, V> ShardedMap<K, V> {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        if capacity < SHARD_SPLIT_AT {
            return Self::One(FastMap::with_capacity_and_hasher(
                capacity,
                FastState::default(),
            ));
        }
        let per_shard = capacity.div_ceil(SHARDS);
        Self::Split(
            (0..SHARDS)
                .map(|_| FastMap::with_capacity_and_hasher(per_shard, FastState::default()))
                .collect(),
        )
    }

    fn shard<Q>(&self, key: &Q) -> &FastMap<K, V>
    where
        K: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        match self {
            Self::One(map) => map,
            Self::Split(shards) => &shards[shard_index(key)],
        }
    }

    fn shard_mut<Q>(&mut self, key: &Q) -> &mut FastMap<K, V>
    where
        K: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        match self {
            Self::One(map) => map,
            Self::Split(shards) => &mut shards[shard_index(key)],
        }
    }

    /// Split before an insert would grow the single table past the limit.
    fn split_if_full(&mut self) {
        if matches!(self, Self::One(map) if map.len() >= SHARD_SPLIT_AT) {
            self.split();
        }
    }

    /// Move a single table's entries into the shards. Inserts split at
    /// `SHARD_SPLIT_AT`, so this moves at most that many entries.
    pub(crate) fn split(&mut self) {
        let Self::One(map) = self else {
            return;
        };
        let per_shard = map.len().div_ceil(SHARDS);
        let mut shards: Box<[FastMap<K, V>]> = (0..SHARDS)
            .map(|_| FastMap::with_capacity_and_hasher(per_shard, FastState::default()))
            .collect();
        for (key, value) in std::mem::take(map) {
            shards[shard_index(&key)].insert(key, value);
        }
        *self = Self::Split(shards);
    }

    pub(crate) fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        self.shard(key).get(key)
    }

    /// The stored key and value equal to `key`.
    pub(crate) fn get_key_value<Q>(&self, key: &Q) -> Option<(&K, &V)>
    where
        K: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        self.shard(key).get_key_value(key)
    }

    pub(crate) fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        self.shard_mut(key).get_mut(key)
    }

    pub(crate) fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        self.shard(key).contains_key(key)
    }

    pub(crate) fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.split_if_full();
        self.shard_mut(&key).insert(key, value)
    }

    pub(crate) fn entry(&mut self, key: K) -> std::collections::hash_map::Entry<'_, K, V> {
        self.split_if_full();
        self.shard_mut(&key).entry(key)
    }

    pub(crate) fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        self.shard_mut(key).remove(key)
    }
}

/// Walks a [`ShardedMap`] shard by shard with an exact remaining count, so
/// a collector reserves the whole map once instead of growing per shard.
struct ShardIter<S, I> {
    shards: S,
    current: Option<I>,
    remaining: usize,
}

impl<S, I> ShardIter<S, I> {
    fn new(len: usize, shards: S) -> Self {
        Self {
            shards,
            current: None,
            remaining: len,
        }
    }
}

impl<S: Iterator<Item = I>, I: ExactSizeIterator> Iterator for ShardIter<S, I> {
    type Item = I::Item;

    fn next(&mut self) -> Option<I::Item> {
        loop {
            if let Some(item) = self.current.as_mut().and_then(Iterator::next) {
                self.remaining -= 1;
                return Some(item);
            }
            self.current = Some(self.shards.next()?);
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }

    /// Skips whole shards by their length instead of stepping through them.
    fn nth(&mut self, mut n: usize) -> Option<I::Item> {
        loop {
            let Some(current) = self.current.as_mut() else {
                self.current = Some(self.shards.next()?);
                continue;
            };
            let len = current.len();
            if n < len {
                self.remaining -= n + 1;
                return current.nth(n);
            }
            n -= len;
            self.remaining -= len;
            self.current = None;
        }
    }
}

impl<S: Iterator<Item = I>, I: ExactSizeIterator> ExactSizeIterator for ShardIter<S, I> {}

impl<S: std::iter::FusedIterator<Item = I>, I: ExactSizeIterator> std::iter::FusedIterator
    for ShardIter<S, I>
{
}

impl<K, Q, V> std::ops::Index<&Q> for ShardedMap<K, V>
where
    K: Eq + std::hash::Hash + std::borrow::Borrow<Q>,
    Q: Eq + std::hash::Hash + ?Sized,
{
    type Output = V;

    fn index(&self, key: &Q) -> &V {
        self.get(key).expect("key present in ShardedMap")
    }
}

/// `FxHasher` with 128-bit words, which in practice means `Ipv6Addr`,
/// hashed through Fx's byte-string path, as `Ipv6Prefix` hashes its
/// address. Core hashes an `Ipv6Addr` as one native-endian `u128`, and Fx
/// only carries input bits upward, so sequentially numbered IPv6 peers
/// (`::1`, `::2`, ...) otherwise share one hashbrown control byte and one
/// starting bucket. Every other write is forwarded unchanged.
#[derive(Default)]
pub struct AddrHasher(rustc_hash::FxHasher);

impl std::hash::Hasher for AddrHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes);
    }
    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.0.write_u8(i);
    }
    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.0.write_u16(i);
    }
    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.0.write_u32(i);
    }
    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.0.write_u64(i);
    }
    #[inline]
    fn write_u128(&mut self, i: u128) {
        self.0.write(&i.to_ne_bytes());
    }
    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.0.write_usize(i);
    }
    #[inline]
    fn finish(&self) -> u64 {
        self.0.finish()
    }
}

/// `BuildHasher` for maps keyed by a peer or next-hop address.
pub(crate) type AddrState = std::hash::BuildHasherDefault<AddrHasher>;
pub(crate) type AddrMap<K, V> = std::collections::HashMap<K, V, AddrState>;

/// Changed-customer ASN set carried by `rustbgpd_rpki`'s published
/// `AspaTableUpdate`. Its hasher belongs to that crate's public API, so it
/// does not follow `FastState`.
pub(crate) type AspaAsnSet = rustc_hash::FxHashSet<u32>;

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::hash::BuildHasher;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::Instant;

    use rustbgpd_wire::{Ipv6Prefix, Prefix, RouteDistinguisher, VpnPrefix, VpnRouteKey};

    use super::{AddrState, FastMap, FastState, SHARD_SPLIT_AT, SHARDS, ShardedMap};

    const RD: RouteDistinguisher = RouteDistinguisher([0, 0, 0xfd, 0xe8, 0, 0, 0, 1]);

    /// Field-for-field stand-in for the derived `Hash` of a `VpnRouteKey`:
    /// the RD, the variant discriminant as `isize`, the address through its
    /// own `Hash`, then the length.
    #[derive(PartialEq, Eq, Hash)]
    struct DerivedVpnKey<A> {
        route_distinguisher: RouteDistinguisher,
        discriminant: isize,
        addr: A,
        len: u8,
    }

    /// Sequential `VPNv6` keys under one RD, varying the address at `shift`.
    fn sequential_vpnv6_keys(count: u64, len: u8, shift: u32) -> Vec<VpnRouteKey> {
        (0..count)
            .map(|i| VpnRouteKey {
                route_distinguisher: RD,
                prefix: VpnPrefix::v6(
                    Ipv6Addr::from(0x2001_0db8_u128 << 96 | u128::from(i) << shift),
                    len,
                )
                .unwrap(),
            })
            .collect()
    }

    /// hashbrown takes its control byte from the top seven hash bits and
    /// its starting group from the low bits. Sequential /128 and /64 keys
    /// must spread across both, or every lookup walks one long probe chain.
    #[test]
    fn sequential_ipv6_prefixes_spread_hashbrown_tag_and_bucket_bits() {
        const KEYS: u64 = 4096;
        for (len, shift) in [(128, 0), (64, 64)] {
            let hashes: Vec<u64> = (0..KEYS)
                .map(|i| {
                    let addr = Ipv6Addr::from(0x2001_0db8_u128 << 96 | u128::from(i) << shift);
                    FastState::default().hash_one(Prefix::V6(Ipv6Prefix::new(addr, len)))
                })
                .collect();
            let tags = hashes.iter().map(|h| h >> 57).collect::<HashSet<_>>();
            let starts = hashes
                .iter()
                .map(|h| h & (KEYS - 1))
                .collect::<HashSet<_>>();
            // Uniform hashing gives all 128 tags and about 63% of the
            // 4096 starting buckets; the old derived hash gave 1 and 4.
            assert!(tags.len() >= 120, "/{len}: {} distinct tags", tags.len());
            assert!(
                starts.len() >= 2300,
                "/{len}: {} distinct starting buckets",
                starts.len()
            );
        }
    }

    /// The VPN analogue of the test above: sequential `VPNv6` /128 and /64
    /// keys under one RD must spread across hashbrown's tag and bucket bits.
    #[test]
    fn sequential_vpnv6_keys_spread_hashbrown_tag_and_bucket_bits() {
        const KEYS: u64 = 4096;
        for (len, shift) in [(128, 0), (64, 64)] {
            let mut tags = HashSet::new();
            let mut per_start: HashMap<u64, u32> = HashMap::new();
            for key in sequential_vpnv6_keys(KEYS, len, shift) {
                let hash = FastState::default().hash_one(key);
                tags.insert(hash >> 57);
                *per_start.entry(hash & (KEYS - 1)).or_default() += 1;
            }
            let max_per_start = per_start.values().copied().max().unwrap_or(0);
            // Uniform hashing gives all 128 tags, about 63% of the starting
            // buckets and a busiest bucket of about 7 keys; the derived hash
            // gave 1 tag, 4 starting buckets and 1,024 keys in one bucket.
            assert!(tags.len() >= 120, "/{len}: {} distinct tags", tags.len());
            assert!(
                per_start.len() >= 2300,
                "/{len}: {} distinct starting buckets",
                per_start.len()
            );
            assert!(
                max_per_start <= 16,
                "/{len}: {max_per_start} keys share one starting bucket"
            );
        }
    }

    /// Per-source maps key sequentially numbered IPv6 peers (`::1`, `::2`,
    /// ...), alone or with an Add-Path ID. They must spread across
    /// hashbrown's tag and bucket bits; core's `u128` hash under plain Fx
    /// gives 1 tag and 1 starting bucket, so every lookup walks all keys.
    #[test]
    fn sequential_ipv6_peers_spread_hashbrown_tag_and_bucket_bits() {
        const KEYS: u64 = 4096;
        let peer = |i: u64| IpAddr::V6(Ipv6Addr::from(0x2001_0db8_u128 << 96 | u128::from(i)));
        let hashes: [Vec<u64>; 2] = [
            (1..=KEYS)
                .map(|i| AddrState::default().hash_one(peer(i)))
                .collect(),
            (1..=KEYS)
                .map(|i| AddrState::default().hash_one((peer(i), 0_u32)))
                .collect(),
        ];
        for (shape, hashes) in ["IpAddr", "(IpAddr, u32)"].iter().zip(hashes) {
            let tags = hashes.iter().map(|h| h >> 57).collect::<HashSet<_>>();
            let mut per_start: HashMap<u64, u32> = HashMap::new();
            for h in &hashes {
                *per_start.entry(h & (KEYS - 1)).or_default() += 1;
            }
            let max_per_start = per_start.values().copied().max().unwrap_or(0);
            assert!(tags.len() >= 120, "{shape}: {} distinct tags", tags.len());
            assert!(
                per_start.len() >= 2300,
                "{shape}: {} distinct starting buckets",
                per_start.len()
            );
            assert!(
                max_per_start <= 16,
                "{shape}: {max_per_start} keys share one starting bucket"
            );
        }
    }

    /// `AddrState` changes only 128-bit words: IPv4 peers and prefix keys
    /// hash exactly as under `FastState`.
    #[test]
    fn addr_state_matches_fast_state_without_u128_words() {
        for i in 0..256u32 {
            let v4 = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 | i));
            assert_eq!(
                AddrState::default().hash_one((v4, i)),
                FastState::default().hash_one((v4, i))
            );
            let v6 = Prefix::V6(Ipv6Prefix::new(
                Ipv6Addr::from(0x2001_0db8_u128 << 96 | u128::from(i)),
                128,
            ));
            assert_eq!(
                AddrState::default().hash_one(v6),
                FastState::default().hash_one(v6)
            );
        }
    }

    /// The manual `VpnPrefix` hash keeps VPN-IPv4 hash values identical to
    /// the derived form; only VPN-IPv6 changes.
    #[test]
    fn vpnv4_key_hash_matches_derived_form() {
        let state = FastState::default();
        for i in 0..256u32 {
            let addr = Ipv4Addr::from(0x0a00_0000 | i << 8);
            let key = VpnRouteKey {
                route_distinguisher: RD,
                prefix: VpnPrefix::v4(addr, 24).unwrap(),
            };
            let derived = DerivedVpnKey {
                route_distinguisher: RD,
                discriminant: 0,
                addr,
                len: 24,
            };
            assert_eq!(state.hash_one(key), state.hash_one(derived));
        }
    }

    fn vpnv4_key(i: u32) -> VpnRouteKey {
        VpnRouteKey {
            route_distinguisher: RD,
            prefix: VpnPrefix::v4(Ipv4Addr::from(0x0a00_0000 + i), 32).unwrap(),
        }
    }

    /// Inserts split the map at the limit; afterwards an insert grows at most
    /// one shard, so no insert rehashes more than one shard's entries.
    #[test]
    fn sharded_map_splits_once_then_grows_one_shard_per_insert() {
        let total = u32::try_from(SHARD_SPLIT_AT * 4).unwrap();
        let mut map = ShardedMap::default();
        for i in 0..total {
            let capacities: Vec<usize> = map.shards().iter().map(FastMap::capacity).collect();
            let was_split = map.shards().len() == SHARDS;
            assert!(map.insert(vpnv4_key(i), i).is_none());
            if !was_split {
                continue;
            }
            let grown = map
                .shards()
                .iter()
                .zip(&capacities)
                .filter(|(shard, before)| shard.capacity() != **before)
                .count();
            assert!(grown <= 1, "insert {i} grew {grown} shards");
        }
        assert_eq!(map.shards().len(), SHARDS);
        assert_eq!(map.len(), usize::try_from(total).unwrap());
        assert!(
            map.shards()
                .iter()
                .all(|shard| shard.len() < SHARD_SPLIT_AT / 2)
        );
        for i in 0..total {
            assert_eq!(map.get(&vpnv4_key(i)), Some(&i));
        }
        assert_eq!(map.remove(&vpnv4_key(7)), Some(7));
        assert!(map.get(&vpnv4_key(7)).is_none());
        *map.entry(vpnv4_key(7)).or_insert(0) += 70;
        assert_eq!(map[&vpnv4_key(7)], 70);
        assert_eq!(map.iter().count(), map.len());
    }

    /// Sharded iteration reports its exact remaining length, so collectors
    /// reserve once, and `nth` skips shards without changing the order.
    #[test]
    fn sharded_map_iterators_report_exact_size_and_skip_shards() {
        let total = SHARD_SPLIT_AT * 4 + 3;
        let mut map = ShardedMap::default();
        let mut reference = FastMap::default();
        for i in 0..u32::try_from(total).unwrap() {
            map.insert(vpnv4_key(i), i);
            reference.insert(vpnv4_key(i), i);
        }
        assert_eq!(map.shards().len(), SHARDS);
        let mut iter = map.iter();
        assert_eq!(iter.size_hint(), (total, Some(total)));
        for _ in 0..1000 {
            iter.next();
        }
        assert_eq!(iter.len(), total - 1000);
        assert_eq!(map.keys().len(), total);
        assert_eq!(map.values().size_hint(), (total, Some(total)));
        // An exact hint lets `collect` allocate once; a lower bound of one
        // shard grows the vector and leaves spare capacity.
        let keys: Vec<_> = map.keys().collect();
        assert_eq!(keys.capacity(), total);
        let order: Vec<_> = map.iter().collect();
        assert_eq!(order.len(), reference.len());
        assert!(
            order
                .iter()
                .all(|(key, value)| reference.get(*key) == Some(*value))
        );
        for (start, step) in [(0, 0), (5, 1), (4000, 9000), (1, total - 3), (total - 1, 0)] {
            let mut iter = map.iter();
            assert_eq!(iter.nth(start), order.get(start).copied());
            assert_eq!(iter.len(), total - start - 1);
            assert_eq!(iter.nth(step), order.get(start + 1 + step).copied());
            assert_eq!(iter.len(), total.saturating_sub(start + step + 2));
        }
        let mut past = map.iter();
        assert_eq!(past.nth(total), None);
        assert_eq!((past.len(), past.next()), (0, None));
        let sum =
            |map: &ShardedMap<VpnRouteKey, u32>| map.values().copied().map(u64::from).sum::<u64>();
        drop((iter, past, keys, order));
        let before = sum(&map);
        let mut mutable = map.iter_mut();
        assert_eq!(mutable.len(), total);
        *mutable.nth(total / 2).unwrap().1 += 1;
        assert_eq!(mutable.len(), total - total / 2 - 1);
        drop(mutable);
        assert_eq!(sum(&map), before + 1);
    }

    /// Each shard still spreads sequential VPN keys across hashbrown's tag
    /// and bucket bits, and the shards stay balanced.
    #[test]
    fn sharded_map_shards_spread_sequential_vpn_keys() {
        const KEYS: u64 = 1 << 18;
        let v6 = sequential_vpnv6_keys(KEYS, 128, 0);
        let v4: Vec<_> = (0..u32::try_from(KEYS).unwrap()).map(vpnv4_key).collect();
        for (family, keys) in [("v4", v4), ("v6", v6)] {
            let mut map = ShardedMap::default();
            for key in keys {
                map.insert(key, ());
            }
            for shard in map.shards() {
                let expected = KEYS / u64::try_from(SHARDS).unwrap();
                let len = u64::try_from(shard.len()).unwrap();
                assert!(
                    len.abs_diff(expected) < expected / 8,
                    "{family}: shard of {len}"
                );
                let buckets = u64::try_from(shard.len().next_power_of_two()).unwrap();
                let mut tags = HashSet::new();
                let mut starts = HashSet::new();
                for key in shard.keys() {
                    let hash = FastState::default().hash_one(key);
                    tags.insert(hash >> 57);
                    starts.insert(hash & (buckets - 1));
                }
                assert!(tags.len() >= 120, "{family}: {} distinct tags", tags.len());
                // Uniform hashing reaches 1 - e^(-len/buckets) of the buckets.
                let float = |n: usize| f64::from(u32::try_from(n).unwrap());
                let buckets = float(usize::try_from(buckets).unwrap());
                let uniform = buckets * (1.0 - (-float(shard.len()) / buckets).exp());
                assert!(
                    float(starts.len()) >= uniform * 0.9,
                    "{family}: {} starting buckets, uniform {uniform:.0}",
                    starts.len()
                );
            }
        }
    }

    /// Timed lookups over 200k sequential `VPNv6` keys under one RD, derived
    /// versus manual hash. Run with
    /// `cargo test --release -p rustbgpd-rib vpnv6_lookup_timing -- --ignored --nocapture`.
    #[test]
    #[ignore = "timing diagnostic; run in release with --nocapture"]
    fn vpnv6_lookup_timing() {
        fn median_lookup_ns<K: std::hash::Hash + Eq>(keys: &[K]) -> f64 {
            let map: FastMap<&K, u32> = keys.iter().zip(0..).collect();
            let mut runs: Vec<f64> = (0..7)
                .map(|_| {
                    let start = Instant::now();
                    let hits = keys.iter().filter(|k| map.contains_key(k)).count();
                    let elapsed = start.elapsed();
                    assert_eq!(std::hint::black_box(hits), keys.len());
                    elapsed.as_secs_f64() * 1e9 / f64::from(u32::try_from(keys.len()).unwrap())
                })
                .collect();
            runs.sort_by(f64::total_cmp);
            runs[runs.len() / 2]
        }
        const KEYS: u64 = 200_000;
        for (len, shift) in [(128, 0), (64, 64)] {
            let manual = sequential_vpnv6_keys(KEYS, len, shift);
            let derived: Vec<_> = manual
                .iter()
                .map(|key| match key.prefix {
                    VpnPrefix::V6 { addr, len } => DerivedVpnKey {
                        route_distinguisher: key.route_distinguisher,
                        discriminant: 1,
                        addr,
                        len,
                    },
                    VpnPrefix::V4 { .. } => unreachable!(),
                })
                .collect();
            let derived_ns = median_lookup_ns(&derived);
            let manual_ns = median_lookup_ns(&manual);
            println!(
                "/{len}: {KEYS} keys, median ns/lookup derived {derived_ns:.1}, manual {manual_ns:.1}"
            );
        }
    }
}
