//! Export-roster costs (ADR-0136 "Cost and measurement").
//!
//! `publish` times one republication as the RIB performs it: project every
//! per-peer export-map entry to its counter instance, sort, store the roster
//! in the cell and release the previous one. `capture` times one
//! `GetPolicyStats` export capture, reading every counter once. Targets at
//! 1,000 peers: publication <= 100 us, capture <= 1 ms with two terms per
//! peer. Each peer owns its instance (ungrouped peers, the worst case).

use std::collections::HashMap;
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use rustbgpd_policy::rpol::compile_rpol;
use rustbgpd_policy::sets::SetStore;
use rustbgpd_policy::{NamedPolicy, PolicyChain};
use rustbgpd_rib::export_roster::{ExportRosterPublisher, capture_export};

/// One export policy with `terms` named terms whose labels are
/// `label_bytes` long (0 keeps short native names).
fn chain(terms: usize, label_bytes: usize) -> PolicyChain {
    let label = |prefix: &str, index: usize| {
        let name = format!("{prefix}{index}");
        if label_bytes == 0 {
            name
        } else {
            format!("{name}{}", "x".repeat(label_bytes - name.len()))
        }
    };
    let policy = label("member-out-", 0);
    let body: String = (0..terms)
        .map(|index| {
            let action = if index + 1 == terms {
                "accept".to_string()
            } else {
                format!("if route.prefix == 192.0.{index}.0/24 {{ reject }}")
            };
            format!(" term {} {{ {action} }}\n", label("term-", index))
        })
        .collect();
    let source = format!("policy {policy} {{\n{body}}}");
    let compiled = compile_rpol(&source, &mut SetStore::new()).expect("valid bench policy");
    PolicyChain::from_named(vec![NamedPolicy::from_rpol(policy, Arc::new(compiled))])
}

fn address(index: usize) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(
        0x0a00_0000 + u32::try_from(index).expect("bench peer count fits"),
    ))
}

/// The RIB's per-peer export map: `peers` installed chains, each with its
/// own counter instance.
fn export_map(peers: usize, template: &PolicyChain) -> HashMap<IpAddr, Option<PolicyChain>> {
    (0..peers)
        .map(|index| {
            let chain = template.clone();
            let _ = chain.hit_counters();
            (address(index), Some(chain))
        })
        .collect()
}

fn publisher_for(map: &HashMap<IpAddr, Option<PolicyChain>>) -> ExportRosterPublisher {
    let mut publisher = ExportRosterPublisher::new();
    publish(&mut publisher, map);
    publisher
}

fn publish(publisher: &mut ExportRosterPublisher, map: &HashMap<IpAddr, Option<PolicyChain>>) {
    let peers = map
        .iter()
        .map(|(peer, chain)| {
            (
                *peer,
                chain.as_ref().map(|chain| Arc::clone(chain.hit_counters())),
            )
        })
        .collect();
    publisher.publish(peers, None);
}

fn bench_publish(c: &mut Criterion) {
    let mut group = c.benchmark_group("export_roster_publish");
    let template = chain(2, 0);
    for peers in [1_000, 10_000] {
        let map = export_map(peers, &template);
        let mut publisher = publisher_for(&map);
        group.throughput(Throughput::Elements(peers as u64));
        group.bench_function(format!("{peers}_peers"), |b| {
            b.iter(|| publish(&mut publisher, &map));
        });
    }
    group.finish();
}

fn bench_capture(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("bench runtime");
    let mut group = c.benchmark_group("export_roster_capture");
    for (name, peers, terms, label_bytes) in [
        ("1000_peers_2_terms", 1_000, 2, 0),
        ("10000_peers_2_terms", 10_000, 2, 0),
        ("1000_peers_32_terms_256b_labels", 1_000, 32, 256),
    ] {
        let map = export_map(peers, &chain(terms, label_bytes));
        let publisher = publisher_for(&map);
        let roster = publisher.reader().load();
        group.throughput(Throughput::Elements(peers as u64));
        group.bench_function(name, |b| {
            b.iter(|| {
                let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
                let rows = runtime
                    .block_on(capture_export(&roster, None, deadline))
                    .expect("capture completes");
                black_box(rows)
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_publish, bench_capture);
criterion_main!(benches);
