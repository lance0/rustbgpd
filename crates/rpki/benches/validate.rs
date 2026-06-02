//! RPKI origin-validation (`VrpTable::validate`) microbench — RFC 6811.
//!
//! Validation runs on every inbound NLRI and on every RTR cache-update
//! revalidation, scanning the VRP table for the route's family. This bench
//! measures `validate` at realistic table sizes (1k → 800k VRPs) across the
//! five RFC 6811 outcomes, so the linear-scan → bucketed-index rework can be
//! A/B'd on the same harness.
//!
//! Cases per size:
//!   - `exact_valid`    — route exactly matches a VRP (covered, ASN ok, len ok)
//!   - `ancestor_valid` — covered only by a less-specific supernet VRP
//!   - `invalid_as`     — covered, wrong origin ASN
//!   - `invalid_len`    — covered but more specific than max_len
//!   - `notfound`       — no covering VRP

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use rustbgpd_rpki::{VrpEntry, VrpTable};
use rustbgpd_wire::{Ipv4Prefix, Ipv6Prefix, Prefix};

/// (family label, VRP count) matrix.
const SIZES: &[(&str, usize)] = &[
    ("v4", 1_000),
    ("v4", 100_000),
    ("v4", 800_000),
    ("v6", 1_000),
    ("v6", 100_000),
];

const SUPERNET_ASN: u32 = 64_500;

fn leaf_asn(i: usize) -> u32 {
    65_000 + (i % 100) as u32
}

/// Distinct IPv4 /24 leaf network for index `i` (spread across 10.0.0.0/8 and
/// up — ~65k /24s per first octet, so 800k stays within 10..=22).
fn v4_leaf(i: usize) -> Ipv4Addr {
    let first = 10 + u8::try_from((i >> 16) & 0xff).unwrap();
    let b = u8::try_from((i >> 8) & 0xff).unwrap();
    let c = u8::try_from(i & 0xff).unwrap();
    Ipv4Addr::new(first, b, c, 0)
}

/// Distinct IPv6 /48 leaf network for index `i` under 2001::/16 (32 bits of
/// variation at the /48 boundary).
fn v6_leaf(i: usize) -> Ipv6Addr {
    let net = (0x2001_u128 << 112) | ((i as u128) << 80);
    Ipv6Addr::from(net)
}

/// Build `n` leaf VRPs for the family plus one less-specific supernet (for the
/// `ancestor_valid` case) that does not overlap the leaf range.
fn generate(fam: &str, n: usize) -> Vec<VrpEntry> {
    let mut v = Vec::with_capacity(n + 1);
    if fam == "v4" {
        for i in 0..n {
            v.push(VrpEntry {
                prefix: IpAddr::V4(v4_leaf(i)),
                prefix_len: 24,
                max_len: 24,
                origin_asn: leaf_asn(i),
            });
        }
        // Supernet clear of the 10..=22 leaf range.
        v.push(VrpEntry {
            prefix: IpAddr::V4(Ipv4Addr::new(100, 0, 0, 0)),
            prefix_len: 8,
            max_len: 24,
            origin_asn: SUPERNET_ASN,
        });
    } else {
        for i in 0..n {
            v.push(VrpEntry {
                prefix: IpAddr::V6(v6_leaf(i)),
                prefix_len: 48,
                max_len: 48,
                origin_asn: leaf_asn(i),
            });
        }
        // Supernet under 2a00::/16, clear of the 2001::/16 leaf range.
        v.push(VrpEntry {
            prefix: IpAddr::V6(Ipv6Addr::from(0x2a00_u128 << 112)),
            prefix_len: 16,
            max_len: 48,
            origin_asn: SUPERNET_ASN,
        });
    }
    v
}

/// Representative (case, route prefix, origin ASN) tuples for a family/size.
fn cases(fam: &str, n: usize) -> Vec<(&'static str, Prefix, u32)> {
    let k = n / 2;
    if fam == "v4" {
        let leaf = v4_leaf(k);
        vec![
            (
                "exact_valid",
                Prefix::V4(Ipv4Prefix::new(leaf, 24)),
                leaf_asn(k),
            ),
            (
                "ancestor_valid",
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(100, 0, 0, 0), 24)),
                SUPERNET_ASN,
            ),
            ("invalid_as", Prefix::V4(Ipv4Prefix::new(leaf, 24)), 1),
            (
                "invalid_len",
                Prefix::V4(Ipv4Prefix::new(leaf, 25)),
                leaf_asn(k),
            ),
            (
                "notfound",
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24)),
                65_000,
            ),
        ]
    } else {
        let leaf = v6_leaf(k);
        vec![
            (
                "exact_valid",
                Prefix::V6(Ipv6Prefix::new(leaf, 48)),
                leaf_asn(k),
            ),
            (
                "ancestor_valid",
                Prefix::V6(Ipv6Prefix::new(Ipv6Addr::from(0x2a00_u128 << 112), 48)),
                SUPERNET_ASN,
            ),
            ("invalid_as", Prefix::V6(Ipv6Prefix::new(leaf, 48)), 1),
            (
                "invalid_len",
                Prefix::V6(Ipv6Prefix::new(leaf, 64)),
                leaf_asn(k),
            ),
            (
                "notfound",
                Prefix::V6(Ipv6Prefix::new("2003:db8::".parse().unwrap(), 48)),
                65_000,
            ),
        ]
    }
}

fn bench_validate(c: &mut Criterion) {
    let mut group = c.benchmark_group("validate");
    for &(fam, n) in SIZES {
        let table = VrpTable::new(generate(fam, n));
        let label = format!("{fam}/{n}");
        for (case, prefix, asn) in cases(fam, n) {
            group.bench_with_input(
                BenchmarkId::new(&label, case),
                &(prefix, asn),
                |b, (p, a)| {
                    b.iter(|| black_box(table.validate(black_box(p), black_box(*a))));
                },
            );
        }
    }
    group.finish();
}

criterion_group!(benches, bench_validate);
criterion_main!(benches);
