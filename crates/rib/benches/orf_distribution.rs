//! Distribution to one IPv4-unicast peer through the production manager seam,
//! with and without a full prefix-ORF table (RFC 5291/5292).
//!
//! Each timed iteration replaces every route's attributes (outside the timer),
//! then distributes the changed set to the peer: the per-prefix ORF check sits
//! on that path. `orf_off` is an ordinary peer without ORF. `orf_4096` installs
//! the per-family entry cap, where only the highest-sequence entry
//! (`0.0.0.0/0 le 32`) matches the distributed prefixes, so a first-match scan
//! visits every entry for every prefix.
//!
//! cargo bench -p rustbgpd-rib --features bench-internals --bench orf_distribution

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rustbgpd_rib::{
    AttrSet, ExactExportCandidate, ExactExportEncoder, ExactExportError, ExactExportResult,
    ExactExportSnapshot, PeerId, RibManager, Route, RouteOrigin,
};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{
    AddressPrefixOrf, AsPath, AsPathSegment, Ipv4Prefix, OrfAction, OrfMatch, Origin,
    PathAttribute, Prefix, RpkiValidation,
};
use tokio::sync::mpsc;

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

const PREFIXES: u32 = 10_000;
const ORF_ENTRIES: u32 = 4096;

struct PermissiveExactExport;

impl ExactExportSnapshot for PermissiveExactExport {
    fn owner_id(&self) -> u64 {
        1
    }

    fn generation(&self) -> u64 {
        0
    }

    fn probe_announcement(
        &self,
        _candidate: ExactExportCandidate<'_>,
    ) -> Result<ExactExportResult, ExactExportError> {
        Ok(ExactExportResult {
            encoded_len: 0,
            max_len: usize::MAX,
            generation: 0,
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl ExactExportEncoder for PermissiveExactExport {
    fn owner_id(&self) -> u64 {
        1
    }

    fn snapshot(&self) -> Arc<dyn ExactExportSnapshot> {
        Arc::new(Self)
    }
}

/// `PREFIXES` /24s from 10.0.0.0, announced by one eBGP source; `variant`
/// changes a community so every replacement changes each Loc-RIB best.
fn routes(variant: u32) -> Vec<Route> {
    let source = Ipv4Addr::new(198, 51, 100, 1);
    (0..PREFIXES)
        .map(|i| Route {
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(0x0a00_0000 + (i << 8)), 24)),
            next_hop: IpAddr::V4(source),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: PeerId::from_addr(IpAddr::V4(source)),
            attributes: AttrSet::new(vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65001])],
                }),
                PathAttribute::NextHop(source),
                PathAttribute::Communities(vec![variant]),
            ]),
            received_at: rustbgpd_rib::route::ReceivedAt::now(),
            origin_type: RouteOrigin::Ebgp,
            peer_router_id: source,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            received_as_path: None,
            aspa_context: rustbgpd_rib::route::AspaContextId::DEFAULT,
        })
        .collect()
}

/// `ORF_ENTRIES - 1` exact 172.16.x.y/32 permits that match nothing
/// distributed, then `0.0.0.0/0 le 32` permit at the highest sequence.
fn orf_entries() -> Vec<AddressPrefixOrf> {
    let entry = |sequence: u32, prefix: Ipv4Prefix, max_len: u8| AddressPrefixOrf {
        action: OrfAction::Add,
        match_: OrfMatch::Permit,
        sequence,
        min_len: 0,
        max_len,
        prefix: Some(Prefix::V4(prefix)),
    };
    (0..ORF_ENTRIES - 1)
        .map(|seq| {
            entry(
                seq,
                Ipv4Prefix::new(Ipv4Addr::from(0xac10_0000 + seq), 32),
                0,
            )
        })
        .chain(std::iter::once(entry(
            ORF_ENTRIES - 1,
            Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0),
            32,
        )))
        .collect()
}

fn bench_orf_distribution(c: &mut Criterion) {
    let mut group = c.benchmark_group("orf_distribution");
    group.sample_size(10);
    for (name, orf) in [("orf_off", None), ("orf_4096", Some(orf_entries()))] {
        let (_tx, rx) = mpsc::channel(8);
        let (_query_tx, query_rx) = mpsc::channel(8);
        let mut manager = RibManager::new(rx, query_rx, None, None, BgpMetrics::new());
        manager.bench_seed_loc_rib(routes(0));
        let mut out =
            manager.bench_register_orf_peer(0, 1 << 16, orf, Arc::new(PermissiveExactExport));
        let mut variant = 0;
        group.bench_function(BenchmarkId::new(name, PREFIXES), |b| {
            b.iter_custom(|iterations| {
                let mut elapsed = Duration::ZERO;
                for _ in 0..iterations {
                    variant += 1;
                    let changed = manager.bench_prepare_unicast_replacement(routes(variant));
                    let start = Instant::now();
                    manager.bench_distribute(&changed);
                    elapsed += start.elapsed();
                    let mut announced = 0;
                    while let Ok(update) = out.try_recv() {
                        announced += update.announce.len();
                    }
                    assert_eq!(
                        announced, PREFIXES as usize,
                        "{name}: every prefix exported"
                    );
                }
                elapsed
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_orf_distribution);
criterion_main!(benches);
