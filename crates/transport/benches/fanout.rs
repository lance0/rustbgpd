//! Manager-level export/distribution fanout microbench.
//!
//! Drives the real `RibManager::distribute_changes` hot path — the per-peer
//! export work (policy eval + Adj-RIB-Out staging + bounded-channel send) that a
//! route reflector / route server pays when a batch of best paths changes and
//! must be re-advertised to N clients. Unlike `rib_ops`, which exercises bare
//! `AdjRibIn`/`LocRib`/`AdjRibOut` structs, this drives the manager itself via
//! the `bench-internals` fanout driver (synthetic peer registration + Loc-RIB
//! seed + `distribute_changes`).
//!
//! Shape: seed `CHANGED` best paths, then fan that batch out to N peers, scaling
//! N to expose the fanout factor. `no_policy` vs `with_policy` isolates the
//! per-peer export-policy share. Each measured pass is a *first* advertise
//! (Adj-RIB-Out starts empty, so the Adj-RIB-Out equality suppression never
//! short-circuits) — the conservative upper bound on per-peer cost.
//!
//! Gated behind `bench-internals`; run with:
//!   cargo bench -p rustbgpd-transport --features bench-internals --bench fanout

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Instant;

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};

use rustbgpd_policy::{Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications};
use rustbgpd_rib::RibManager;
use rustbgpd_rib::route::{Route, RouteOrigin};
use rustbgpd_rib::update::{OutboundRouteUpdate, RibUpdate};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_transport::fanout_bench_export_encoder;
use rustbgpd_wire::{
    AsPath, AsPathSegment, Ipv4Prefix, Origin, PathAttribute, Prefix, RpkiValidation,
};
use tokio::sync::mpsc;

/// Best paths flapping in a single `distribute_changes` pass.
const CHANGED: usize = 64;
/// Peer fanout factors (the independent variable).
const PEER_COUNTS: [usize; 4] = [1, 8, 64, 256];
/// Per-peer channel capacity — one pass of `CHANGED` announces fits without
/// filling (a full channel would divert the peer to the dirty-resync path).
const CHANNEL_CAP: usize = CHANGED + 8;

fn typical_attributes() -> Vec<PathAttribute> {
    vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65000, 65100, 65200])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(198, 51, 100, 1)),
        PathAttribute::LocalPref(100),
        PathAttribute::Med(50),
    ]
}

fn make_route(prefix: Prefix) -> Route {
    Route {
        prefix,
        next_hop: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        attributes: Arc::new(typical_attributes()),
        received_at: Instant::now(),
        // eBGP-learned so it reflects freely to the iBGP / RR clients (no
        // iBGP-to-iBGP split-horizon suppression in the way).
        origin_type: RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::new(198, 51, 100, 1),
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    }
}

fn changed_prefixes() -> Vec<Prefix> {
    (0..CHANGED)
        .map(|i| {
            let b1 = ((i >> 8) & 0xFF) as u8;
            let b2 = (i & 0xFF) as u8;
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(172, 16 + b1, b2, 0), 24))
        })
        .collect()
}

/// A `PolicyStatement` with every field unset (matches any prefix, permits).
fn blank_stmt() -> PolicyStatement {
    PolicyStatement {
        prefix: None,
        ge: None,
        le: None,
        action: PolicyAction::Permit,
        match_community: Vec::new(),
        match_as_path: None,
        match_neighbor_set: None,
        match_route_type: None,
        match_evpn_route_type: None,
        match_rpki_validation: None,
        match_aspa_validation: None,
        match_as_path_length_ge: None,
        match_as_path_length_le: None,
        match_local_pref_ge: None,
        match_local_pref_le: None,
        match_med_ge: None,
        match_med_le: None,
        match_next_hop: None,
        modifications: RouteModifications::default(),
    }
}

/// A representative export filter: several cheap-miss statements the route falls
/// through (it carries `LOCAL_PREF` 100, so a `>= 64000` guard misses on a
/// tier-1 scalar compare — the common "this clause doesn't apply" case) ending
/// in a catch-all permit, so every route is evaluated against the whole chain.
fn representative_export_chain() -> PolicyChain {
    let mut entries = Vec::with_capacity(8);
    for _ in 0..7 {
        let mut s = blank_stmt();
        s.match_local_pref_ge = Some(64_000);
        s.action = PolicyAction::Deny;
        entries.push(s);
    }
    entries.push(blank_stmt()); // catch-all permit
    PolicyChain::new(vec![Policy {
        entries,
        default_action: PolicyAction::Deny,
    }])
}

type FanoutState = (
    RibManager,
    Vec<mpsc::Receiver<OutboundRouteUpdate>>,
    HashSet<Prefix>,
);

/// Build a manager with `n_peers` registered and `CHANGED` best paths seeded.
/// The receivers are returned so the caller keeps the bounded channels open
/// across the measured `distribute_changes`.
fn build(n_peers: usize, export_policy: Option<PolicyChain>) -> FanoutState {
    let (_tx, rx) = mpsc::channel::<RibUpdate>(16);
    let (_qtx, qrx) = mpsc::channel::<RibUpdate>(16);
    let mut mgr = RibManager::new(
        rx,
        qrx,
        None,
        Some(Ipv4Addr::new(10, 255, 255, 255)), // cluster id (RR path)
        BgpMetrics::new(),
    );
    let prefixes = changed_prefixes();
    // Register peers first (Loc-RIB empty → the initial-table dump only emits an
    // EoR marker, which the driver drains → channels start empty), then seed the
    // table to fan out.
    let receivers = mgr.bench_register_peers(
        n_peers,
        export_policy.as_ref(),
        true,
        CHANNEL_CAP,
        fanout_bench_export_encoder,
    );
    mgr.bench_seed_loc_rib(prefixes.iter().copied().map(make_route).collect());
    let changed: HashSet<Prefix> = prefixes.into_iter().collect();
    (mgr, receivers, changed)
}

fn bench_fanout(c: &mut Criterion) {
    let mut group = c.benchmark_group("distribute_fanout");
    for &n in &PEER_COUNTS {
        group.bench_with_input(BenchmarkId::new("no_policy", n), &n, |b, &n| {
            b.iter_batched_ref(
                || build(n, None),
                |(mgr, _recv, changed)| mgr.bench_distribute(changed),
                BatchSize::PerIteration,
            );
        });
        group.bench_with_input(BenchmarkId::new("with_policy", n), &n, |b, &n| {
            b.iter_batched_ref(
                || build(n, Some(representative_export_chain())),
                |(mgr, _recv, changed)| mgr.bench_distribute(changed),
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_fanout);
criterion_main!(benches);
