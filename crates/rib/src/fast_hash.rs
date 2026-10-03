//! The hasher behind the RIB's route-bearing maps, named in one place so a
//! hasher change is a one-line edit. The `HashDoS` rationale for the choice
//! is the block at the top of `adj_rib_in`.

/// `BuildHasher` for the route-bearing maps. Construct it with
/// `FastState::default()`, never a unit literal, so a seeded hasher can
/// replace it here without touching call sites.
pub(crate) type FastState = rustc_hash::FxBuildHasher;
pub(crate) type FastMap<K, V> = std::collections::HashMap<K, V, FastState>;
pub(crate) type FastSet<T> = std::collections::HashSet<T, FastState>;

/// Changed-customer ASN set carried by `rustbgpd_rpki`'s published
/// `AspaTableUpdate`. Its hasher belongs to that crate's public API, so it
/// does not follow `FastState`.
pub(crate) type AspaAsnSet = rustc_hash::FxHashSet<u32>;

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::hash::BuildHasher;
    use std::net::Ipv6Addr;

    use rustbgpd_wire::{Ipv6Prefix, Prefix};

    use super::FastState;

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
}
