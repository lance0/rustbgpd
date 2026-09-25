//! Import-roster costs (ADR-0136 "Cost and measurement").
//!
//! `publish` times one republication as the peer table performs it: build a
//! roster row per managed peer (key clone, session identity, publication
//! receiver clone), sort, store it in the cell and release the previous
//! roster. `capture` times one `GetPolicyStats` import capture over installed
//! publications, reading every counter once. Targets at 1,000 peers:
//! publication <= 100 us, capture <= 1 ms with two terms per peer.
//! `bulk_insert` compares a bulk operation publishing after every peer with
//! one publication per operation.

use std::collections::HashMap;
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use rustbgpd_api::import_roster::{
    ImportCaptureProgress, ImportRosterPeer, ImportRosterPublisher, capture_import,
};
use rustbgpd_api::peer_types::PeerKey;
use rustbgpd_policy::rpol::compile_rpol;
use rustbgpd_policy::sets::SetStore;
use rustbgpd_policy::{NamedPolicy, PolicyChain};
use rustbgpd_transport::SessionIdentity;
use rustbgpd_transport::handle::InstalledImportPolicy;
use tokio::sync::watch;

type Publication = watch::Sender<Option<Arc<InstalledImportPolicy>>>;
type Receiver = watch::Receiver<Option<Arc<InstalledImportPolicy>>>;

/// One import policy with `terms` named terms whose labels are `label_bytes`
/// long (0 keeps short native names).
fn chain(terms: usize, label_bytes: usize) -> PolicyChain {
    let label = |prefix: &str, index: usize| {
        let name = format!("{prefix}{index}");
        if label_bytes == 0 {
            name
        } else {
            format!("{name}{}", "x".repeat(label_bytes - name.len()))
        }
    };
    let policy = label("member-in-", 0);
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

/// `peers` installed sessions sharing one chain shape; each owns a fresh
/// counter instance.
fn installed_fleet(peers: usize, template: &PolicyChain) -> Vec<(PeerKey, Publication, Receiver)> {
    (0..peers)
        .map(|index| {
            let chain = template.clone();
            let installed = Arc::new(InstalledImportPolicy::new(
                SessionIdentity::default(),
                0,
                Some(&chain),
            ));
            let (publication, receiver) = watch::channel(Some(installed));
            (PeerKey::new(address(index), None), publication, receiver)
        })
        .collect()
}

fn bench_publish(c: &mut Criterion) {
    let mut group = c.benchmark_group("import_roster_publish");
    let template = chain(2, 0);
    for peers in [1_000, 10_000] {
        let fleet = installed_fleet(peers, &template);
        // The peer table's shape: a map from key to session identity and the
        // current session's publication.
        let table: HashMap<PeerKey, (u64, Receiver)> = fleet
            .iter()
            .enumerate()
            .map(|(index, (key, _, receiver))| (key.clone(), (index as u64 + 1, receiver.clone())))
            .collect();
        let mut publisher = ImportRosterPublisher::new();
        let datasets: Arc<[_]> = Vec::new().into();
        group.throughput(Throughput::Elements(peers as u64));
        group.bench_function(format!("{peers}_peers"), |b| {
            b.iter(|| {
                let rows = table
                    .iter()
                    .map(|(key, (session_id, publication))| ImportRosterPeer {
                        key: key.clone(),
                        session_id: *session_id,
                        publication: publication.clone(),
                    })
                    .collect();
                publisher.publish(rows, Arc::clone(&datasets));
            });
        });
        black_box(&fleet);
    }
    group.finish();
}

fn bench_capture(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("bench runtime");
    let mut group = c.benchmark_group("import_roster_capture");
    for (name, peers, terms, label_bytes) in [
        ("1000_peers_2_terms", 1_000, 2, 0),
        ("10000_peers_2_terms", 10_000, 2, 0),
        ("1000_peers_32_terms_256b_labels", 1_000, 32, 256),
    ] {
        let fleet = installed_fleet(peers, &chain(terms, label_bytes));
        let mut publisher = ImportRosterPublisher::new();
        publisher.publish(
            fleet
                .iter()
                .map(|(key, _, receiver)| ImportRosterPeer {
                    key: key.clone(),
                    session_id: 1,
                    publication: receiver.clone(),
                })
                .collect(),
            Vec::new().into(),
        );
        let reader = publisher.reader();
        group.throughput(Throughput::Elements(peers as u64));
        group.bench_function(name, |b| {
            b.iter_batched(
                || reader.load(),
                |roster| {
                    runtime.block_on(async {
                        let mut progress = ImportCaptureProgress::default();
                        let rows = capture_import(
                            roster.peers(),
                            tokio::time::Instant::now() + Duration::from_secs(2),
                            &mut progress,
                        )
                        .await
                        .expect("installed fleet captures");
                        assert_eq!(rows.len(), peers);
                        black_box(rows)
                    })
                },
                BatchSize::SmallInput,
            );
        });
        black_box(&fleet);
    }
    group.finish();
}

/// A bulk operation inserting `peers` peers into an empty table: publishing
/// after every insert (O(peers^2) roster rows built) against one publication
/// when the operation ends.
fn bench_bulk_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("import_roster_bulk_insert");
    group.sample_size(10);
    let template = chain(2, 0);
    for peers in [1_000, 10_000] {
        let fleet = installed_fleet(peers, &template);
        let datasets: Arc<[_]> = Vec::new().into();
        let row = |index: usize| {
            let (key, _, receiver) = &fleet[index];
            (key.clone(), (index as u64 + 1, receiver.clone()))
        };
        let publish = |publisher: &mut ImportRosterPublisher,
                       table: &HashMap<PeerKey, (u64, Receiver)>| {
            let rows = table
                .iter()
                .map(|(key, (session_id, publication))| ImportRosterPeer {
                    key: key.clone(),
                    session_id: *session_id,
                    publication: publication.clone(),
                })
                .collect();
            publisher.publish(rows, Arc::clone(&datasets));
        };
        group.bench_function(format!("{peers}_peers_per_peer"), |b| {
            b.iter_batched(
                || (ImportRosterPublisher::new(), HashMap::with_capacity(peers)),
                |(mut publisher, mut table)| {
                    for index in 0..peers {
                        let (key, value) = row(index);
                        table.insert(key, value);
                        publish(&mut publisher, &table);
                    }
                    publisher
                },
                BatchSize::PerIteration,
            );
        });
        group.bench_function(format!("{peers}_peers_batched"), |b| {
            b.iter_batched(
                || (ImportRosterPublisher::new(), HashMap::with_capacity(peers)),
                |(mut publisher, mut table)| {
                    for index in 0..peers {
                        let (key, value) = row(index);
                        table.insert(key, value);
                    }
                    publish(&mut publisher, &table);
                    publisher
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_publish, bench_capture, bench_bulk_insert);
criterion_main!(benches);
