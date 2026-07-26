use std::net::Ipv4Addr;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use rustbgpd_wire::attribute::{
    decode_path_attributes, decode_path_attributes_revised, encode_path_attributes,
};
use rustbgpd_wire::nlri::{decode_nlri, encode_nlri};
use rustbgpd_wire::validate::validate_update_attributes;
use rustbgpd_wire::{
    Aggregator, AsPath, AsPathSegment, ErrorDisposition, ExtendedCommunity, Ipv4NlriEntry,
    Ipv4Prefix, Ipv4UnicastMode, LargeCommunity, Origin, PathAttribute, UpdateMessage,
};

fn generate_ipv4_prefixes(count: usize) -> Vec<Ipv4Prefix> {
    (0..count)
        .map(|i| {
            let b1 = ((i >> 8) & 0xFF) as u8;
            let b2 = (i & 0xFF) as u8;
            Ipv4Prefix::new(Ipv4Addr::new(10, b1, b2, 0), 24)
        })
        .collect()
}

fn typical_attributes() -> Vec<PathAttribute> {
    vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65001, 65002, 65003])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
        PathAttribute::LocalPref(100),
        PathAttribute::Med(50),
        PathAttribute::Communities(vec![0xFFFF_0001, 0xFFFF_0002]),
    ]
}

/// A wider attribute set than [`typical_attributes`]: multi-segment
/// `AS_PATH`, communities of every flavor, route-reflection attributes, an
/// aggregator, and an extended-length (>255 B value) attribute.
///
/// `AS_SET` is deliberately absent — RFC 9774 §3 prohibits originating it, so
/// `encode_path_attributes` rejects it and the whole `attr_encode` group would
/// panic. Multi-segment coverage comes from a second `AS_SEQUENCE` instead;
/// received-side `AS_SET` coverage lives in [`as_set_as_path_wire`].
fn rich_attributes() -> Vec<PathAttribute> {
    vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![
                AsPathSegment::AsSequence(vec![65001, 65002, 65003, 65004, 65005]),
                AsPathSegment::AsSequence(vec![65010, 65011]),
            ],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
        PathAttribute::LocalPref(100),
        PathAttribute::Med(50),
        // 128 communities = 512-byte value, which forces the extended-length
        // header path on both encode and decode.
        PathAttribute::Communities((0..128).map(|i| 0x0001_0000 + i).collect()),
        PathAttribute::ExtendedCommunities(vec![ExtendedCommunity::new(0x0002_FDE8_0000_0007)]),
        PathAttribute::LargeCommunities(vec![LargeCommunity {
            global_admin: 65001,
            local_data1: 7,
            local_data2: 9,
        }]),
        PathAttribute::OriginatorId(Ipv4Addr::new(10, 0, 0, 9)),
        PathAttribute::ClusterList(vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)]),
        PathAttribute::Aggregator(Aggregator {
            asn: 65001,
            router_id: Ipv4Addr::new(10, 0, 0, 9),
            partial: false,
        }),
    ]
}

/// A hand-framed `AS_PATH` carrying a single `AS_SET` segment.
///
/// Framed by hand because `encode_path_attributes` refuses to originate one
/// (RFC 9774 §3). Receiving one is still a real shape with a defined RFC 7606
/// treat-as-withdraw disposition, and the raw segment scan that reaches that
/// verdict runs on every UPDATE, so it stays on the decode side of the bench.
fn as_set_as_path_wire() -> Vec<u8> {
    let asns: [u32; 2] = [65010, 65011];
    let count = u8::try_from(asns.len()).expect("fixture segment fits one octet");
    let mut buf = vec![
        0x40,          // flags: well-known transitive
        2,             // type: AS_PATH
        2 + count * 4, // value length: segment header + 4-octet ASNs
        1,             // segment type: AS_SET
        count,
    ];
    for asn in asns {
        buf.extend_from_slice(&asn.to_be_bytes());
    }
    buf
}

fn bench_nlri_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("nlri_decode");
    for count in [1, 10, 100, 500] {
        let prefixes = generate_ipv4_prefixes(count);
        let mut buf = Vec::new();
        encode_nlri(&prefixes, &mut buf);
        group.bench_with_input(BenchmarkId::from_parameter(count), &buf, |b, buf| {
            b.iter(|| decode_nlri(buf).unwrap());
        });
    }
    group.finish();
}

fn bench_nlri_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("nlri_encode");
    for count in [1, 10, 100, 500] {
        let prefixes = generate_ipv4_prefixes(count);
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &prefixes,
            |b, prefixes| {
                b.iter(|| {
                    let mut buf = Vec::with_capacity(prefixes.len() * 4);
                    encode_nlri(prefixes, &mut buf);
                    buf
                });
            },
        );
    }
    group.finish();
}

fn bench_update_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("update_build");
    let attrs = typical_attributes();
    for count in [1, 10, 100, 500] {
        let entries: Vec<Ipv4NlriEntry> = generate_ipv4_prefixes(count)
            .into_iter()
            .map(|p| Ipv4NlriEntry {
                path_id: 0,
                prefix: p,
            })
            .collect();
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &entries,
            |b, entries| {
                b.iter(|| {
                    UpdateMessage::build(entries, &[], &attrs, true, false, Ipv4UnicastMode::Body)
                });
            },
        );
    }
    group.finish();
}

fn bench_update_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("update_parse");
    let attrs = typical_attributes();
    for count in [1, 10, 100, 500] {
        let entries: Vec<Ipv4NlriEntry> = generate_ipv4_prefixes(count)
            .into_iter()
            .map(|p| Ipv4NlriEntry {
                path_id: 0,
                prefix: p,
            })
            .collect();
        let msg = UpdateMessage::build(&entries, &[], &attrs, true, false, Ipv4UnicastMode::Body);
        group.bench_with_input(BenchmarkId::from_parameter(count), &msg, |b, msg| {
            b.iter(|| msg.parse(true, false, &[]).unwrap());
        });
    }
    group.finish();
}

fn bench_attr_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("attr_decode");

    let typical = typical_attributes();
    let mut typical_buf = Vec::new();
    encode_path_attributes(&typical, &mut typical_buf, true, false).unwrap();
    group.bench_with_input(
        BenchmarkId::new("typical", typical.len()),
        &typical_buf,
        |b, buf| {
            b.iter(|| decode_path_attributes(buf, true, &[]).unwrap());
        },
    );

    let rich = rich_attributes();
    let mut rich_buf = Vec::new();
    encode_path_attributes(&rich, &mut rich_buf, true, false).unwrap();
    group.bench_with_input(BenchmarkId::new("rich", rich.len()), &rich_buf, |b, buf| {
        b.iter(|| decode_path_attributes(buf, true, &[]).unwrap());
    });

    // RFC 9774 §3 leaves `AS_SET` un-originatable but still receivable, so the
    // revised decoder is the only side that can carry the shape. The RFC 7606
    // treat-as-withdraw verdict is what makes the fixture load-bearing; assert
    // it once outside the measurement so a silently-clean decode cannot pass
    // for coverage.
    let as_set_buf = as_set_as_path_wire();
    let verdict = decode_path_attributes_revised(&as_set_buf, true, false, &[])
        .expect("AS_SET in AS_PATH is recoverable, not session-reset");
    assert!(
        verdict
            .malformed
            .iter()
            .any(|m| m.disposition == ErrorDisposition::TreatAsWithdraw),
        "AS_SET fixture must keep its RFC 7606 treat-as-withdraw disposition"
    );
    group.bench_with_input(
        BenchmarkId::new("as_set_revised", 1),
        &as_set_buf,
        |b, buf| {
            b.iter(|| decode_path_attributes_revised(buf, true, false, &[]).unwrap());
        },
    );

    group.finish();
}

fn bench_attr_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("attr_encode");

    let typical = typical_attributes();
    group.bench_with_input(
        BenchmarkId::new("typical", typical.len()),
        &typical,
        |b, attrs| {
            b.iter(|| {
                let mut buf = Vec::with_capacity(128);
                encode_path_attributes(attrs, &mut buf, true, false).unwrap();
                buf
            });
        },
    );

    let rich = rich_attributes();
    group.bench_with_input(BenchmarkId::new("rich", rich.len()), &rich, |b, attrs| {
        b.iter(|| {
            let mut buf = Vec::with_capacity(256);
            encode_path_attributes(attrs, &mut buf, true, false).unwrap();
            buf
        });
    });

    group.finish();
}

fn bench_validate_update(c: &mut Criterion) {
    let attrs = typical_attributes();
    c.bench_function("validate_update", |b| {
        b.iter(|| validate_update_attributes(&attrs, true, true, true).unwrap());
    });
}

criterion_group!(
    benches,
    bench_nlri_decode,
    bench_nlri_encode,
    bench_update_build,
    bench_update_parse,
    bench_attr_decode,
    bench_attr_encode,
    bench_validate_update,
);
criterion_main!(benches);
