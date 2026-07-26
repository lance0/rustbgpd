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
//! per-peer export-policy share. The family-gauge target separately prewarms a
//! first advertise, mutates every route's MED outside accumulated time, and
//! measures the resulting second changed-route pass on persistent fleets.
//! All peers occupy one update group and ordinary members share the same
//! unicast route/next-hop payload Arcs. The exact-export path may therefore
//! encode each route once per compatible wire-profile cohort and reapply each
//! target's negotiated ceiling; it does not perform a full exact encode per
//! peer. This is not a resync or full-table convergence benchmark.
//!
//! Gated behind `bench-internals`; run with:
//!   cargo bench -p rustbgpd-transport --features bench-internals --bench fanout
//!
//! Pinned A/B receipts: `docs/perf/exact-export-fanout-2026-07.md`,
//! `docs/perf/adj-rib-out-family-gauge-2026-07.md`,
//! `docs/perf/fanout-metrics-handle-2026-07.md`, and
//! `docs/perf/otc-pristine-reconcile-2026-07.md`.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};

use rustbgpd_policy::{Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications};
use rustbgpd_rib::RibManager;
use rustbgpd_rib::manager::{AdjRibOutFanoutBenchReceipt, PolicyTransitionBenchReceipt};
use rustbgpd_rib::route::{Route, RouteOrigin};
use rustbgpd_rib::update::{OutboundRouteUpdate, RibUpdate};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_transport::{fanout_bench_export_encoder, fanout_bench_route_server_export_encoder};
use rustbgpd_wire::{
    AsPath, AsPathSegment, Ipv4Prefix, Origin, PathAttribute, Prefix, RpkiValidation,
};
use tokio::sync::mpsc;

/// Best paths flapping in a single `distribute_changes` pass.
const CHANGED: usize = 64;
/// Peer fanout factors (the independent variable).
const PEER_COUNTS: [usize; 4] = [1, 8, 64, 256];
/// IXP route-server fanout factors retained in the exact-export receipt.
const IXP_PEER_COUNTS: [usize; 3] = [8, 64, 256];
/// Route-server fleets retained for the real-encoder grouped fanout receipts.
const ADJ_RIB_OUT_GAUGE_PEER_COUNTS: [usize; 5] = [1, 8, 64, 256, 1_000];
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

fn make_route_with_med(prefix: Prefix, med: u32) -> Route {
    let mut attributes = typical_attributes();
    let med_attr = attributes
        .iter_mut()
        .find(|attribute| matches!(attribute, PathAttribute::Med(_)))
        .expect("benchmark attributes include MED");
    *med_attr = PathAttribute::Med(med);
    Route {
        prefix,
        next_hop: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        attributes: Arc::new(attributes),
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

fn make_route(prefix: Prefix) -> Route {
    make_route_with_med(prefix, 50)
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

fn community_export_chain(community: u32) -> PolicyChain {
    let mut statement = blank_stmt();
    statement.modifications.communities_add.push(community);
    PolicyChain::new(vec![Policy {
        entries: vec![statement],
        default_action: PolicyAction::Deny,
    }])
}

fn policy_regroup_routes(count: usize) -> Vec<Route> {
    (0..count)
        .map(|index| {
            let bytes = u32::try_from(index)
                .expect("benchmark route count fits u32")
                .to_be_bytes();
            let prefix = Prefix::V4(Ipv4Prefix::new(
                Ipv4Addr::new(100, bytes[1], bytes[2], bytes[3]),
                32,
            ));
            make_route(prefix)
        })
        .collect()
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

fn route_server_remote_asns(n_peers: usize, distinct: bool) -> Vec<u32> {
    (0..n_peers)
        .map(|index| {
            if distinct {
                65_001 + u32::try_from(index).expect("benchmark peer count fits u32")
            } else {
                65_001
            }
        })
        .collect()
}

fn build_ixp(n_peers: usize, distinct_remote_asns: bool) -> FanoutState {
    let (_tx, rx) = mpsc::channel::<RibUpdate>(16);
    let (_qtx, qrx) = mpsc::channel::<RibUpdate>(16);
    let mut manager = RibManager::new(rx, qrx, None, None, BgpMetrics::new());
    let prefixes = changed_prefixes();
    let remote_asns = route_server_remote_asns(n_peers, distinct_remote_asns);
    let receivers = manager.bench_register_route_server_peers(
        &remote_asns,
        None,
        CHANNEL_CAP,
        fanout_bench_route_server_export_encoder,
    );
    manager.bench_seed_loc_rib(prefixes.iter().copied().map(make_route).collect());
    let changed = prefixes.into_iter().collect();
    (manager, receivers, changed)
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

fn bench_ixp_exact_export_fanout(c: &mut Criterion) {
    let mut group = c.benchmark_group("ixp_exact_export_fanout");
    for &n in &IXP_PEER_COUNTS {
        group.bench_with_input(
            BenchmarkId::new("homogeneous_remote_asn", n),
            &n,
            |b, &n| {
                b.iter_batched_ref(
                    || build_ixp(n, false),
                    |(manager, _receivers, changed)| manager.bench_distribute(changed),
                    BatchSize::PerIteration,
                );
            },
        );
        group.bench_with_input(BenchmarkId::new("distinct_remote_asns", n), &n, |b, &n| {
            b.iter_batched_ref(
                || build_ixp(n, true),
                |(manager, _receivers, changed)| manager.bench_distribute(changed),
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

struct AdjRibOutGaugeFanoutState {
    manager: RibManager,
    receivers: Vec<mpsc::Receiver<OutboundRouteUpdate>>,
    prefixes: Vec<Prefix>,
    med: u32,
}

fn drain_one_route_bearing_envelope_per_peer(
    receivers: &mut [mpsc::Receiver<OutboundRouteUpdate>],
) {
    for receiver in receivers {
        let update = receiver
            .try_recv()
            .expect("each changed-route pass enqueues one envelope per peer");
        assert_eq!(update.announce.len(), CHANGED);
        assert!(update.withdraw.is_empty());
        assert!(update.flowspec_announce.is_empty());
        assert!(update.flowspec_withdraw.is_empty());
        assert!(update.evpn_announce.is_empty());
        assert!(update.evpn_withdraw.is_empty());
        assert!(update.bgpls_announce.is_empty());
        assert!(update.bgpls_withdraw.is_empty());
        assert!(update.vpn_announce.is_empty());
        assert!(update.vpn_withdraw.is_empty());
        assert!(update.labeled_announce.is_empty());
        assert!(update.labeled_withdraw.is_empty());
        assert!(update.rtc_announce.is_empty());
        assert!(update.rtc_withdraw.is_empty());
        assert!(
            update.exact_export_snapshot.is_some(),
            "route-bearing benchmark envelopes retain the real session snapshot"
        );
        assert!(
            receiver.try_recv().is_err(),
            "one changed-route pass must enqueue exactly one envelope per peer"
        );
    }
}

fn build_adj_rib_out_gauge_fanout(peers: usize) -> AdjRibOutGaugeFanoutState {
    let (manager, mut receivers, _changed) = build_ixp(peers, false);
    // The production seed already distributed the first advertisement. Drain
    // it outside measured time: this both prewarms every metric label and
    // proves the next pass starts with empty writer channels.
    drain_one_route_bearing_envelope_per_peer(&mut receivers);
    AdjRibOutGaugeFanoutState {
        manager,
        receivers,
        prefixes: changed_prefixes(),
        med: 50,
    }
}

fn assert_adj_rib_out_gauge_receipt(receipt: AdjRibOutFanoutBenchReceipt, peers: usize) {
    assert_eq!(
        receipt.update_groups, 1,
        "fixture must use one update group"
    );
    assert_eq!(receipt.grouped_peers, peers);
    assert_eq!(
        receipt.ungrouped_peers, 0,
        "fallback peers invalidate the A/B"
    );
    assert_eq!(receipt.dirty_peers, 0, "dirty resync invalidates the A/B");
    assert_eq!(
        receipt.exact_probe_batches, 1,
        "one real full exact probe batch seeds compatible grouped reuse"
    );
    assert_eq!(
        receipt.exact_probe_candidates, CHANGED,
        "every changed route must traverse the real exact encoder"
    );
    assert_eq!(
        receipt.exact_probe_cache_reuses,
        CHANGED * peers.saturating_sub(1),
        "every remaining grouped member must reuse compatible exact lengths"
    );
    assert_eq!(
        receipt.successful_commits, peers,
        "equality suppression or commit failure invalidates the A/B"
    );
    assert_eq!(
        receipt.successful_enqueues, peers,
        "every committed route-bearing envelope must be enqueued"
    );
    assert_eq!(
        receipt.family_gauge_writes, peers,
        "unicast-only fanout refreshes one family gauge per peer"
    );
    assert_eq!(
        receipt.pristine_otc_reconcile_candidates, peers,
        "every peer must satisfy the exact pristine predicate used by the target early return"
    );
    assert_eq!(receipt.last_family_gauge_write_mask, 0x01);
    assert_eq!(
        receipt.first_peer_family_values,
        [
            i64::try_from(CHANGED).expect("fixture size fits i64"),
            0,
            0,
            0,
            0,
            0,
            0
        ],
        "group-derived unicast truth and untouched zero families must remain exact"
    );
}

fn bench_adj_rib_out_family_gauge(c: &mut Criterion) {
    let mut group = c.benchmark_group("adj_rib_out_family_gauge");
    group.sample_size(10);
    for &peers in &ADJ_RIB_OUT_GAUGE_PEER_COUNTS {
        group.bench_with_input(
            BenchmarkId::new("homogeneous_route_server_second_pass", peers),
            &peers,
            |bench, &peers| {
                let mut state = build_adj_rib_out_gauge_fanout(peers);
                bench.iter_custom(|iterations| {
                    let mut accumulated = Duration::ZERO;
                    for _ in 0..iterations {
                        state.med = if state.med == 50 { 51 } else { 50 };
                        let changed = state.manager.bench_prepare_unicast_replacement(
                            state
                                .prefixes
                                .iter()
                                .copied()
                                .map(|prefix| make_route_with_med(prefix, state.med))
                                .collect(),
                        );
                        assert_eq!(changed.len(), CHANGED);
                        state.manager.bench_reset_adj_rib_out_fanout_receipt();
                        let started = Instant::now();
                        state.manager.bench_distribute(&changed);
                        accumulated += started.elapsed();
                        assert_adj_rib_out_gauge_receipt(
                            state.manager.bench_adj_rib_out_fanout_receipt(),
                            peers,
                        );
                        // Channel inspection is deliberately outside the
                        // accumulated actor/probe/commit/enqueue duration.
                        drain_one_route_bearing_envelope_per_peer(&mut state.receivers);
                    }
                    accumulated
                });
            },
        );
    }
    group.finish();
}

type PolicyRegroupState = (
    RibManager,
    Vec<mpsc::Receiver<OutboundRouteUpdate>>,
    PolicyChain,
);

fn assert_shared_transition_receipt(
    fast: bool,
    receipt: &PolicyTransitionBenchReceipt,
    routes: usize,
    peers: usize,
) {
    assert_eq!(
        fast,
        peers > 1,
        "only multi-peer fixtures are eligible for the clean shared transition"
    );
    if fast {
        assert_eq!(receipt.plan_builds, 1, "one shared plan per transition");
        assert_eq!(
            receipt.full_exact_probes, routes,
            "one full exact probe per route"
        );
        assert_eq!(
            receipt.route_shell_materializations, routes,
            "one route-shell materialization per route"
        );
        assert_eq!(
            receipt.authoritative_peer_applies, 0,
            "the clean shared transition must not use per-peer fallback"
        );
    } else {
        assert_eq!(
            receipt.plan_builds, 0,
            "fallback must not build a shared plan"
        );
        assert_eq!(
            receipt.full_exact_probes, 0,
            "fallback must not run a shared exact probe"
        );
        assert_eq!(
            receipt.route_shell_materializations, 0,
            "fallback must not materialize shared route shells"
        );
        assert_eq!(
            receipt.authoritative_peer_applies, 1,
            "the one-peer fixture must use one authoritative apply"
        );
    }
}

fn build_policy_regroup(routes: usize, peers: usize) -> PolicyRegroupState {
    let (_tx, rx) = mpsc::channel::<RibUpdate>(16);
    let (_qtx, qrx) = mpsc::channel::<RibUpdate>(16);
    let mut manager = RibManager::new(
        rx,
        qrx,
        None,
        Some(Ipv4Addr::new(10, 255, 255, 255)),
        BgpMetrics::new(),
    );
    let old_policy = community_export_chain(0xFDE8_0001);
    let mut receivers = manager.bench_register_peers(
        peers,
        Some(&old_policy),
        true,
        4,
        fanout_bench_export_encoder,
    );
    let seeded = policy_regroup_routes(routes);
    let changed = seeded
        .iter()
        .map(|route| route.prefix)
        .collect::<HashSet<_>>();
    manager.bench_seed_loc_rib(seeded);
    manager.bench_distribute(&changed);
    for receiver in &mut receivers {
        while receiver.try_recv().is_ok() {}
    }
    (manager, receivers, community_export_chain(0xFDE8_0002))
}

fn build_ixp_policy_regroup(
    routes: usize,
    peers: usize,
    distinct_remote_asns: bool,
) -> PolicyRegroupState {
    let (_tx, rx) = mpsc::channel::<RibUpdate>(16);
    let (_qtx, qrx) = mpsc::channel::<RibUpdate>(16);
    let mut manager = RibManager::new(rx, qrx, None, None, BgpMetrics::new());
    let old_policy = community_export_chain(0xFDE8_0001);
    let remote_asns = route_server_remote_asns(peers, distinct_remote_asns);
    let mut receivers = manager.bench_register_route_server_peers(
        &remote_asns,
        Some(&old_policy),
        4,
        fanout_bench_route_server_export_encoder,
    );
    let seeded = policy_regroup_routes(routes);
    let changed = seeded
        .iter()
        .map(|route| route.prefix)
        .collect::<HashSet<_>>();
    manager.bench_seed_loc_rib(seeded);
    manager.bench_distribute(&changed);
    for receiver in &mut receivers {
        while receiver.try_recv().is_ok() {}
    }
    (manager, receivers, community_export_chain(0xFDE8_0002))
}

fn bench_ixp_policy_regroup_resync(c: &mut Criterion) {
    let mut group = c.benchmark_group("ixp_policy_regroup_resync");
    group.sample_size(10);
    let mut peer_counts = vec![64usize];
    if std::env::var_os("RUSTBGPD_IXP_LARGE_RECEIPT").is_some() {
        peer_counts.push(700);
    }
    for peers in peer_counts {
        for (shape, distinct) in [
            ("homogeneous_remote_asn", false),
            ("distinct_remote_asns", true),
        ] {
            let parameter = format!("{shape}/4096/{peers}");
            group.bench_with_input(
                BenchmarkId::new("shared_plan", &parameter),
                &(peers, distinct),
                |bench, &(peers, distinct)| {
                    bench.iter_batched_ref(
                        || build_ixp_policy_regroup(4_096, peers, distinct),
                        |(manager, _receivers, next)| {
                            let fast = manager.bench_replace_export_policy_cohort(peers, next);
                            let receipt = manager.bench_policy_transition_receipt();
                            assert_shared_transition_receipt(fast, &receipt, 4_096, peers);
                            std::hint::black_box((fast, receipt))
                        },
                        BatchSize::PerIteration,
                    );
                },
            );
        }
    }
    group.finish();
}

fn bench_policy_regroup_resync(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_regroup_resync");
    group.sample_size(10);
    for routes in [4_096usize, 65_536] {
        for peers in [1usize, 8, 64] {
            let parameter = format!("{routes}/{peers}");
            group.bench_with_input(
                BenchmarkId::new("shared_plan", &parameter),
                &(routes, peers),
                |bench, &(routes, peers)| {
                    bench.iter_batched_ref(
                        || build_policy_regroup(routes, peers),
                        |(manager, _receivers, next)| {
                            let fast = manager.bench_replace_export_policy_cohort(peers, next);
                            let receipt = manager.bench_policy_transition_receipt();
                            assert_shared_transition_receipt(fast, &receipt, routes, peers);
                            std::hint::black_box((fast, receipt))
                        },
                        BatchSize::PerIteration,
                    );
                },
            );
            group.bench_with_input(
                BenchmarkId::new("forced_per_peer", &parameter),
                &(routes, peers),
                |bench, &(routes, peers)| {
                    bench.iter_batched_ref(
                        || build_policy_regroup(routes, peers),
                        |(manager, _receivers, next)| {
                            manager.bench_replace_export_policy_per_peer(peers, next);
                        },
                        BatchSize::PerIteration,
                    );
                },
            );
        }
    }
    if std::env::var_os("RUSTBGPD_POLICY_TRANSITION_LARGE_RECEIPT").is_some() {
        let routes = 4_096usize;
        let peers = 700usize;
        group.bench_function("shared_plan/4096/700", |bench| {
            bench.iter_batched_ref(
                || build_policy_regroup(routes, peers),
                |(manager, _receivers, next)| {
                    let fast = manager.bench_replace_export_policy_cohort(peers, next);
                    let receipt = manager.bench_policy_transition_receipt();
                    assert_shared_transition_receipt(fast, &receipt, routes, peers);
                    std::hint::black_box((fast, receipt))
                },
                BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_fanout,
    bench_ixp_exact_export_fanout,
    bench_adj_rib_out_family_gauge,
    bench_policy_regroup_resync,
    bench_ixp_policy_regroup_resync
);
criterion_main!(benches);
