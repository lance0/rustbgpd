use std::net::Ipv4Addr;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use rustbgpd_wire::attribute::{decode_path_attributes, encode_path_attributes};
use rustbgpd_wire::nlri::{decode_nlri, encode_nlri};
use rustbgpd_wire::validate::validate_update_attributes;
use rustbgpd_wire::{
    AsPath, AsPathSegment, Ipv4NlriEntry, Ipv4Prefix, Ipv4UnicastMode, Origin, PathAttribute,
    UpdateMessage,
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

fn rich_attributes() -> Vec<PathAttribute> {
    let mut attrs = typical_attributes();
    attrs.push(PathAttribute::AsPath(AsPath {
        segments: vec![
            AsPathSegment::AsSequence(vec![65001, 65002, 65003, 65004, 65005]),
            AsPathSegment::AsSet(vec![65010, 65011]),
        ],
    }));
    attrs.push(PathAttribute::Communities(vec![
        0xFFFF_0001,
        0xFFFF_0002,
        0xFFFF_0003,
        0x0001_0001,
        0x0001_0002,
    ]));
    attrs
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
    encode_path_attributes(&typical, &mut typical_buf, true, false);
    group.bench_with_input(
        BenchmarkId::new("typical", typical.len()),
        &typical_buf,
        |b, buf| {
            b.iter(|| decode_path_attributes(buf, true, &[]).unwrap());
        },
    );

    let rich = rich_attributes();
    let mut rich_buf = Vec::new();
    encode_path_attributes(&rich, &mut rich_buf, true, false);
    group.bench_with_input(BenchmarkId::new("rich", rich.len()), &rich_buf, |b, buf| {
        b.iter(|| decode_path_attributes(buf, true, &[]).unwrap());
    });

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
                encode_path_attributes(attrs, &mut buf, true, false);
                buf
            });
        },
    );

    let rich = rich_attributes();
    group.bench_with_input(BenchmarkId::new("rich", rich.len()), &rich, |b, attrs| {
        b.iter(|| {
            let mut buf = Vec::with_capacity(256);
            encode_path_attributes(attrs, &mut buf, true, false);
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
