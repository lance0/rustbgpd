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
    use std::collections::{HashMap, HashSet};
    use std::hash::BuildHasher;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Instant;

    use rustbgpd_wire::{Ipv6Prefix, Prefix, RouteDistinguisher, VpnPrefix, VpnRouteKey};

    use super::{FastMap, FastState};

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
