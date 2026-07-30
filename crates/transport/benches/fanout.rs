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
//! Shape: advertise `CHANGED` MED-50 best paths to N peers, drain and verify
//! that setup, then replace every best path with a MED-51 route outside
//! accumulated time. One production `distribute_changes` pass is timed and its
//! receipt and wire envelopes are verified afterward. `no_policy` vs
//! `with_policy` isolates the per-peer export-policy share. The family-gauge
//! target separately prewarms a first advertise, mutates every route's MED
//! outside accumulated time, and measures the resulting second changed-route
//! pass on persistent fleets.
//! All peers occupy one update group and ordinary members share the same
//! unicast route/next-hop payload Arcs. The exact-export path may therefore
//! encode each route once per compatible wire-profile cohort and reapply each
//! target's negotiated ceiling; it does not perform a full exact encode per
//! peer. This is not a resync or full-table convergence benchmark.
//!
//! `initial_table_peer_join` is a separate one-peer RR shape: it pre-seeds the
//! Loc-RIB through production `RoutesReceived` handling before the timed call,
//! then measures the production `PeerUp` registration and initial-table dump.
//! Loc-RIB fixture construction, channel allocation, encoder construction, and
//! envelope inspection stay outside accumulated time; the joining peer's first
//! update-group construction remains inside it. The fixture uses one eBGP
//! source, IPv4 /32 routes with the representative attribute set below, one
//! joining iBGP RR client, no export policy, no Add-Path, and one negotiated
//! IPv4 unicast family.
//!
//! `grouped_withdrawal_fanout` is the complementary route-server withdrawal
//! shape. It pre-advertises 64 routes to one real update group, drains setup
//! output, and times one production `RoutesReceived` withdrawal through direct
//! manager dispatch, bounded route-chunk processing, Loc-RIB recompute, grouped
//! distribution, commit, and enqueue at 8/64/256/1,000 members. Manager-channel
//! dequeue, Tokio actor scheduling, receipt checks, and queue inspection remain
//! outside accumulated time. Its synthetic, unregistered source uses the
//! production legacy-producer `session_id = 0` compatibility branch.
//!
//! `add_path_export_staging` measures one negotiated IPv4-unicast Add-Path
//! peer's production top-N selection, policy evaluation, private Adj-RIB-Out
//! staging, exact transport probe, commit, and enqueue. Its 12 rows cross
//! permit-all/deny-best policy, 8/64/256 candidates, and send_max 1/4.
//! Candidate replacement and recompute stay outside timing; every pass
//! alternates a wire-visible MED while fixed LOCAL_PREF values preserve rank.
//! This ref introduces the instrument, so it makes no performance claim.
//!
//! `grouped_policy_denial_fanout` covers the grouped export-policy deny arm.
//! Setup advertises and drains 64 MED-50 routes, then a MED-51 replacement is
//! prepared outside timing. One production distribution pass evaluates the
//! shared deny policy, retires the prior group-owned Adj-RIB-Out inventory, and
//! enqueues one exact withdrawal-only envelope per member. This instrument also
//! makes no performance claim.
//!
//! Gated behind `bench-internals`; run with:
//!   cargo bench -p rustbgpd-transport --features bench-internals --bench fanout
//!
//! Historical first-advertise A/B receipt:
//! `docs/perf/exact-export-fanout-2026-07.md`.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};

use rustbgpd_policy::{Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications};
use rustbgpd_rib::RibManager;
use rustbgpd_rib::manager::{AdjRibOutFanoutBenchReceipt, PolicyTransitionBenchReceipt};
use rustbgpd_rib::route::{Route, RouteOrigin};
use rustbgpd_rib::update::{ExactExportEncoder, OutboundRouteUpdate, RibUpdate};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_transport::{
    FanoutBenchExportSnapshotEvidence, fanout_bench_add_path_export_encoder,
    fanout_bench_export_encoder, fanout_bench_export_snapshot_evidence,
    fanout_bench_route_server_export_encoder,
};
use rustbgpd_wire::{
    Afi, AsPath, AsPathSegment, Ipv4Prefix, Origin, PathAttribute, Prefix, RpkiValidation, Safi,
};
use tokio::sync::mpsc;

/// Best paths flapping in a single `distribute_changes` pass.
const CHANGED: usize = 64;
/// Peer fanout factors (the independent variable).
const PEER_COUNTS: [usize; 4] = [1, 8, 64, 256];
/// IXP route-server fanout factors retained in the exact-export receipt.
const IXP_PEER_COUNTS: [usize; 3] = [8, 64, 256];
/// Route-server fleets retained for the family-gauge A/B receipt.
const ADJ_RIB_OUT_GAUGE_PEER_COUNTS: [usize; 5] = [1, 8, 64, 256, 1_000];
/// Route-server fleets for the production grouped-withdrawal measurement.
const GROUPED_WITHDRAWAL_PEER_COUNTS: [usize; 4] = [8, 64, 256, 1_000];
/// Route-server fleets for grouped export-policy denial staging.
const GROUPED_POLICY_DENIAL_PEER_COUNTS: [usize; 3] = [8, 64, 256];
/// Loc-RIB sizes for the late RR-client initial-table join instrument.
const INITIAL_TABLE_JOIN_ROUTE_COUNTS: [usize; 2] = [4_096, 65_536];
/// Candidate-set sizes for Add-Path top-N export staging.
const ADD_PATH_CANDIDATE_COUNTS: [usize; 3] = [8, 64, 256];
/// Negotiated Add-Path send ceilings exercised by every candidate set.
const ADD_PATH_SEND_MAXES: [u32; 2] = [1, 4];
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

fn deny_replacement_export_chain() -> PolicyChain {
    let mut deny = blank_stmt();
    deny.match_med_ge = Some(51);
    deny.action = PolicyAction::Deny;
    PolicyChain::new(vec![Policy {
        entries: vec![deny, blank_stmt()],
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

fn deny_best_export_chain(best_local_pref: u32) -> PolicyChain {
    let mut deny = blank_stmt();
    deny.match_local_pref_ge = Some(best_local_pref);
    deny.action = PolicyAction::Deny;
    PolicyChain::new(vec![Policy {
        entries: vec![deny, blank_stmt()],
        default_action: PolicyAction::Deny,
    }])
}

fn add_path_source(index: usize) -> Ipv4Addr {
    let index_u32 = u32::try_from(index).expect("benchmark candidate index fits u32");
    let [_, _, b2, b3] = index_u32.to_be_bytes();
    Ipv4Addr::new(198, 18, b2, b3)
}

fn add_path_route(index: usize, candidates: usize, med: u32) -> Route {
    let mut route = make_route_with_med(add_path_prefix(), med);
    let source = add_path_source(index);
    route.peer = IpAddr::V4(source);
    route.peer_router_id = source;
    let local_pref =
        10_000 + u32::try_from(candidates - index).expect("benchmark candidate count fits u32");
    let mut attributes = typical_attributes();
    *attributes
        .iter_mut()
        .find(|attribute| matches!(attribute, PathAttribute::LocalPref(_)))
        .expect("benchmark attributes include LOCAL_PREF") = PathAttribute::LocalPref(local_pref);
    *attributes
        .iter_mut()
        .find(|attribute| matches!(attribute, PathAttribute::Med(_)))
        .expect("benchmark attributes include MED") = PathAttribute::Med(med);
    route.attributes = Arc::new(attributes);
    route
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

struct ReplacementFanoutState {
    manager: RibManager,
    receivers: Vec<mpsc::Receiver<OutboundRouteUpdate>>,
    changed: HashSet<Prefix>,
    expected_inventory: HashSet<Prefix>,
}

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

fn build_ixp_with_policy(
    n_peers: usize,
    distinct_remote_asns: bool,
    export_policy: Option<&PolicyChain>,
) -> FanoutState {
    let (_tx, rx) = mpsc::channel::<RibUpdate>(16);
    let (_qtx, qrx) = mpsc::channel::<RibUpdate>(16);
    let mut manager = RibManager::new(rx, qrx, None, None, BgpMetrics::new());
    let prefixes = changed_prefixes();
    let remote_asns = route_server_remote_asns(n_peers, distinct_remote_asns);
    let receivers = manager.bench_register_route_server_peers(
        &remote_asns,
        export_policy,
        CHANNEL_CAP,
        fanout_bench_route_server_export_encoder,
    );
    manager.bench_seed_loc_rib(prefixes.iter().copied().map(make_route).collect());
    let changed = prefixes.into_iter().collect();
    (manager, receivers, changed)
}

fn build_ixp(n_peers: usize, distinct_remote_asns: bool) -> FanoutState {
    build_ixp_with_policy(n_peers, distinct_remote_asns, None)
}

fn expected_fanout_receipt(
    peers: usize,
    routes_received_dispatches: usize,
) -> AdjRibOutFanoutBenchReceipt {
    AdjRibOutFanoutBenchReceipt {
        update_groups: 1,
        grouped_peers: peers,
        ungrouped_peers: 0,
        dirty_peers: 0,
        grouped_unicast_routes: CHANGED,
        private_unicast_routes: 0,
        routes_received_dispatches,
        routes_received_withdrawals: 0,
        exact_probe_batches: 1,
        exact_probe_candidates: CHANGED,
        exact_probe_nonzero_encoded_lengths: CHANGED * peers,
        exact_probe_cache_reuses: CHANGED * peers.saturating_sub(1),
        successful_commits: peers,
        successful_enqueues: peers,
        family_gauge_writes: peers,
        last_family_gauge_write_mask: 0x01,
        pristine_otc_reconcile_candidates: peers
            * if routes_received_dispatches == 0 {
                1
            } else {
                2
            },
        add_path_bounded_dispatches: 0,
        add_path_full_sort_dispatches: 0,
        add_path_sorted_tail_fallbacks: 0,
        first_peer_family_values: [
            i64::try_from(CHANGED).expect("fixture size fits i64"),
            0,
            0,
            0,
            0,
            0,
            0,
        ],
    }
}

fn route_med(route: &Route) -> u32 {
    route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            PathAttribute::Med(med) => Some(*med),
            _ => None,
        })
        .expect("every fanout route must retain its MED")
}

fn drain_fanout_envelopes(
    receivers: &mut [mpsc::Receiver<OutboundRouteUpdate>],
    expected_inventory: &HashSet<Prefix>,
    expected_med: u32,
) {
    for receiver in receivers {
        let update = receiver
            .try_recv()
            .expect("every fanout member must receive one route-bearing envelope");
        assert_eq!(update.announce.len(), CHANGED);
        assert!(update.withdraw.is_empty());
        assert_unicast_only_envelope(&update);
        assert_real_transport_snapshot(&update);
        let actual_inventory = update
            .announce
            .iter()
            .map(|route| {
                assert_eq!(
                    route_med(route),
                    expected_med,
                    "the envelope must carry the prepared wire-visible replacement"
                );
                assert_eq!(route.path_id, 0);
                route.prefix
            })
            .collect::<HashSet<_>>();
        assert_eq!(
            actual_inventory, *expected_inventory,
            "the envelope must contain the exact replacement inventory"
        );
        assert!(
            matches!(receiver.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
            "one distribution pass must leave a live channel with no second envelope"
        );
    }
}

fn prepare_replacement_fanout(
    (mut manager, mut receivers, expected_inventory): FanoutState,
    peers: usize,
) -> ReplacementFanoutState {
    assert_eq!(expected_inventory.len(), CHANGED);
    assert_eq!(
        manager.bench_adj_rib_out_fanout_receipt(),
        expected_fanout_receipt(peers, 1),
        "the production MED-50 seed must populate the exact grouped fixture"
    );
    drain_fanout_envelopes(&mut receivers, &expected_inventory, 50);

    let replacements = changed_prefixes()
        .into_iter()
        .map(|prefix| make_route_with_med(prefix, 51))
        .collect();
    let changed = manager.bench_prepare_unicast_replacement(replacements);
    assert_eq!(
        changed, expected_inventory,
        "every prepared MED-51 best path must be wire-visible"
    );
    manager.bench_reset_adj_rib_out_fanout_receipt();
    ReplacementFanoutState {
        manager,
        receivers,
        changed,
        expected_inventory,
    }
}

fn measure_replacement_fanout<F>(iterations: u64, peers: usize, build: F) -> Duration
where
    F: Fn(usize) -> FanoutState,
{
    let mut accumulated = Duration::ZERO;
    for _ in 0..iterations {
        let mut state = prepare_replacement_fanout(build(peers), peers);
        let started = Instant::now();
        state.manager.bench_distribute(&state.changed);
        accumulated += started.elapsed();
        assert_eq!(
            state.manager.bench_adj_rib_out_fanout_receipt(),
            expected_fanout_receipt(peers, 0),
            "the timed replacement must use one clean production group and commit every member"
        );
        drain_fanout_envelopes(&mut state.receivers, &state.expected_inventory, 51);
    }
    accumulated
}

fn bench_fanout(c: &mut Criterion) {
    let mut group = c.benchmark_group("distribute_fanout");
    for &n in &PEER_COUNTS {
        group.bench_with_input(BenchmarkId::new("no_policy", n), &n, |b, &n| {
            b.iter_custom(|iterations| {
                measure_replacement_fanout(iterations, n, |peers| build(peers, None))
            });
        });
        group.bench_with_input(BenchmarkId::new("with_policy", n), &n, |b, &n| {
            b.iter_custom(|iterations| {
                measure_replacement_fanout(iterations, n, |peers| {
                    build(peers, Some(representative_export_chain()))
                })
            });
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
                b.iter_custom(|iterations| {
                    measure_replacement_fanout(iterations, n, |peers| build_ixp(peers, false))
                });
            },
        );
        group.bench_with_input(BenchmarkId::new("distinct_remote_asns", n), &n, |b, &n| {
            b.iter_custom(|iterations| {
                measure_replacement_fanout(iterations, n, |peers| build_ixp(peers, true))
            });
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

fn assert_unicast_only_envelope(update: &OutboundRouteUpdate) {
    assert!(update.end_of_rib.is_empty());
    assert!(update.refresh_markers.is_empty());
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
    assert!(update.otc_blocked.is_empty());
    assert!(!update.request_refresh_all_negotiated);
}

fn assert_real_transport_snapshot(update: &OutboundRouteUpdate) {
    let snapshot = update
        .exact_export_snapshot
        .as_ref()
        .expect("route-bearing benchmark envelope must retain an exact-export snapshot");
    let evidence = fanout_bench_export_snapshot_evidence(snapshot.as_ref())
        .expect("benchmark envelope must use the concrete transport-session snapshot");
    assert_ne!(
        evidence.owner_id, 0,
        "the concrete transport snapshot must have a real session owner"
    );
    assert_eq!(
        evidence.max_message_len,
        usize::from(rustbgpd_wire::MAX_MESSAGE_LEN),
        "the benchmark fleet must use classic-message session profiles"
    );
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
        assert_unicast_only_envelope(&update);
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

struct GroupedWithdrawalFanoutState {
    manager: RibManager,
    receivers: Vec<mpsc::Receiver<OutboundRouteUpdate>>,
    source_peer: IpAddr,
    routes: Vec<Route>,
    withdrawals: Vec<(Prefix, u32)>,
    expected_inventory: HashSet<(Prefix, u32)>,
}

fn drain_grouped_withdrawal_setup(
    receivers: &mut [mpsc::Receiver<OutboundRouteUpdate>],
    expected_inventory: &HashSet<(Prefix, u32)>,
) {
    for receiver in receivers {
        let update = receiver
            .try_recv()
            .expect("pre-advertisement must enqueue one setup envelope per peer");
        assert_eq!(
            update.announce.len(),
            expected_inventory.len(),
            "setup must advertise every route exactly once"
        );
        let actual = update
            .announce
            .iter()
            .map(|route| (route.prefix, route.path_id))
            .collect::<HashSet<_>>();
        assert_eq!(
            actual, *expected_inventory,
            "setup must advertise the fixed withdrawal inventory"
        );
        assert!(update.withdraw.is_empty());
        assert_unicast_only_envelope(&update);
        assert_real_transport_snapshot(&update);
        assert!(
            receiver.try_recv().is_err(),
            "setup must enqueue exactly one envelope per peer"
        );
    }
}

fn build_grouped_withdrawal_fanout(peers: usize) -> GroupedWithdrawalFanoutState {
    let (manager, mut receivers, _changed) = build_ixp(peers, false);
    let routes = changed_prefixes()
        .into_iter()
        .map(make_route)
        .collect::<Vec<_>>();
    let withdrawals = routes
        .iter()
        .map(|route| (route.prefix, route.path_id))
        .collect::<Vec<_>>();
    let expected_inventory = withdrawals.iter().copied().collect::<HashSet<_>>();
    assert_eq!(expected_inventory.len(), CHANGED);
    drain_grouped_withdrawal_setup(&mut receivers, &expected_inventory);
    GroupedWithdrawalFanoutState {
        manager,
        receivers,
        source_peer: routes
            .first()
            .expect("grouped-withdrawal fixture must contain routes")
            .peer,
        routes,
        withdrawals,
        expected_inventory,
    }
}

fn assert_grouped_withdrawal_setup_receipt(receipt: AdjRibOutFanoutBenchReceipt, peers: usize) {
    assert_eq!(
        receipt.routes_received_dispatches, 1,
        "setup must traverse one accepted production RoutesReceived dispatch"
    );
    assert_eq!(
        receipt.routes_received_withdrawals, 0,
        "setup must be a pure pre-advertisement"
    );
    assert_eq!(
        receipt.update_groups, 1,
        "setup must populate one production update group"
    );
    assert_eq!(receipt.grouped_peers, peers);
    assert_eq!(
        receipt.ungrouped_peers, 0,
        "private fallback invalidates the grouped-withdrawal setup"
    );
    assert_eq!(
        receipt.dirty_peers, 0,
        "dirty resync invalidates the grouped-withdrawal setup"
    );
    assert_eq!(
        receipt.grouped_unicast_routes, CHANGED,
        "setup must populate the group-owned Adj-RIB-Out before withdrawal"
    );
    assert_eq!(
        receipt.private_unicast_routes, 0,
        "setup must not populate a private unicast Adj-RIB-Out"
    );
    assert_eq!(
        receipt.exact_probe_batches, 1,
        "one real exact probe batch must seed compatible grouped reuse"
    );
    assert_eq!(
        receipt.exact_probe_candidates, CHANGED,
        "every setup route must traverse the real exact encoder"
    );
    assert_eq!(
        receipt.exact_probe_nonzero_encoded_lengths,
        CHANGED * peers,
        "every member must retain a nonzero real-encoder result per route"
    );
    assert_eq!(
        receipt.exact_probe_cache_reuses,
        CHANGED * peers.saturating_sub(1),
        "every member after the first must reuse compatible exact lengths"
    );
    assert_eq!(
        receipt.successful_commits, peers,
        "every grouped member must commit the setup advertisement"
    );
    assert_eq!(
        receipt.successful_enqueues, peers,
        "every grouped member must enqueue the setup advertisement"
    );
    assert_eq!(receipt.family_gauge_writes, peers);
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
        "the first member's grouped IPv4-unicast gauge must reflect setup state"
    );
}

fn expected_grouped_withdrawal_exact_probe_batches(peers: usize) -> usize {
    const ENV: &str = "RUSTBGPD_GROUPED_WITHDRAWAL_EXPECT_EXACT_PROBE_BATCHES";

    match std::env::var(ENV) {
        Ok(value) if value == "0" => 0,
        Ok(value) if value == "per-peer" => peers,
        Ok(value) => panic!("{ENV} must be unset, \"0\", or \"per-peer\", got {value:?}"),
        Err(std::env::VarError::NotPresent) => 0,
        Err(std::env::VarError::NotUnicode(_)) => panic!("{ENV} must be valid Unicode"),
    }
}

fn assert_grouped_withdrawal_receipt(receipt: AdjRibOutFanoutBenchReceipt, peers: usize) {
    assert_eq!(
        receipt.routes_received_dispatches, 1,
        "the timed pass must traverse one accepted production RoutesReceived dispatch"
    );
    assert_eq!(
        receipt.routes_received_withdrawals, CHANGED,
        "the production dispatch must carry the complete withdrawal inventory"
    );
    assert_eq!(
        receipt.update_groups, 1,
        "the fleet must remain one production update group"
    );
    assert_eq!(receipt.grouped_peers, peers);
    assert_eq!(
        receipt.ungrouped_peers, 0,
        "private fallback invalidates the grouped-withdrawal shape"
    );
    assert_eq!(receipt.dirty_peers, 0, "dirty resync invalidates the shape");
    assert_eq!(
        receipt.grouped_unicast_routes, 0,
        "the folded group-owned Adj-RIB-Out must contain no withdrawn route"
    );
    assert_eq!(
        receipt.private_unicast_routes, 0,
        "no private Adj-RIB-Out may retain or receive a withdrawn route"
    );
    assert_eq!(
        receipt.exact_probe_batches,
        expected_grouped_withdrawal_exact_probe_batches(peers),
        "withdrawal-only grouped envelopes must skip exact-export announcement probes; \
         set RUSTBGPD_GROUPED_WITHDRAWAL_EXPECT_EXACT_PROBE_BATCHES=per-peer to measure the \
         harness-only parent"
    );
    assert_eq!(receipt.exact_probe_candidates, 0);
    assert_eq!(receipt.exact_probe_nonzero_encoded_lengths, 0);
    assert_eq!(receipt.exact_probe_cache_reuses, 0);
    assert_eq!(
        receipt.successful_commits, peers,
        "every grouped member must commit one route-bearing withdrawal"
    );
    assert_eq!(
        receipt.successful_enqueues, peers,
        "every grouped member must enqueue one withdrawal envelope"
    );
    assert_eq!(receipt.family_gauge_writes, peers);
    assert_eq!(receipt.last_family_gauge_write_mask, 0x01);
    assert_eq!(
        receipt.first_peer_family_values, [0; 7],
        "the final folded Adj-RIB-Out gauges must be empty"
    );
}

fn drain_grouped_withdrawals(
    receivers: &mut [mpsc::Receiver<OutboundRouteUpdate>],
    expected_inventory: &HashSet<(Prefix, u32)>,
) {
    for receiver in receivers {
        let update = receiver
            .try_recv()
            .expect("every grouped member must receive one withdrawal envelope");
        assert!(update.announce.is_empty());
        assert!(update.next_hop_override.is_empty());
        assert_eq!(
            update.withdraw.len(),
            expected_inventory.len(),
            "withdrawal envelope must contain every route exactly once"
        );
        let actual = update.withdraw.iter().copied().collect::<HashSet<_>>();
        assert_eq!(
            actual, *expected_inventory,
            "withdrawal envelope must match the pre-advertised inventory"
        );
        assert_unicast_only_envelope(&update);
        assert_real_transport_snapshot(&update);
        assert!(
            receiver.try_recv().is_err(),
            "one source withdrawal must enqueue exactly one envelope per peer"
        );
    }
}

fn bench_grouped_withdrawal_fanout(c: &mut Criterion) {
    let mut group = c.benchmark_group("grouped_withdrawal_fanout");
    group.sample_size(10);
    for &peers in &GROUPED_WITHDRAWAL_PEER_COUNTS {
        let shape = format!("{CHANGED}/{peers}");
        group.bench_with_input(
            BenchmarkId::new("homogeneous_route_server", &shape),
            &peers,
            |bench, &peers| {
                let mut state = build_grouped_withdrawal_fanout(peers);
                bench.iter_custom(|iterations| {
                    let mut accumulated = Duration::ZERO;
                    for _ in 0..iterations {
                        assert_grouped_withdrawal_setup_receipt(
                            state.manager.bench_adj_rib_out_fanout_receipt(),
                            peers,
                        );
                        let withdrawn = state.withdrawals.clone();
                        state.manager.bench_reset_adj_rib_out_fanout_receipt();
                        let started = Instant::now();
                        state
                            .manager
                            .bench_withdraw_loc_rib(state.source_peer, withdrawn);
                        accumulated += started.elapsed();
                        assert_grouped_withdrawal_receipt(
                            state.manager.bench_adj_rib_out_fanout_receipt(),
                            peers,
                        );
                        drain_grouped_withdrawals(&mut state.receivers, &state.expected_inventory);

                        // Restore the identical pre-advertised inventory and
                        // isolate its receipt before the next timed withdrawal.
                        state.manager.bench_reset_adj_rib_out_fanout_receipt();
                        state.manager.bench_seed_loc_rib(state.routes.clone());
                        drain_grouped_withdrawal_setup(
                            &mut state.receivers,
                            &state.expected_inventory,
                        );
                    }
                    accumulated
                });
            },
        );
    }
    group.finish();
}

struct GroupedPolicyDenialState {
    manager: RibManager,
    receivers: Vec<mpsc::Receiver<OutboundRouteUpdate>>,
    changed: HashSet<Prefix>,
    expected_inventory: HashSet<(Prefix, u32)>,
}

fn build_grouped_policy_denial_fanout(peers: usize) -> GroupedPolicyDenialState {
    let policy = deny_replacement_export_chain();
    let (mut manager, mut receivers, expected_prefixes) =
        build_ixp_with_policy(peers, false, Some(&policy));
    assert_eq!(
        manager.bench_adj_rib_out_fanout_receipt(),
        expected_fanout_receipt(peers, 1),
        "the MED-50 setup must traverse policy and populate one clean update group"
    );
    drain_fanout_envelopes(&mut receivers, &expected_prefixes, 50);

    let expected_inventory = expected_prefixes
        .iter()
        .copied()
        .map(|prefix| (prefix, 0))
        .collect::<HashSet<_>>();
    let replacements = changed_prefixes()
        .into_iter()
        .map(|prefix| make_route_with_med(prefix, 51))
        .collect();
    let changed = manager.bench_prepare_unicast_replacement(replacements);
    assert_eq!(
        changed, expected_prefixes,
        "every denied MED-51 replacement must reach production distribution"
    );
    manager.bench_reset_adj_rib_out_fanout_receipt();
    GroupedPolicyDenialState {
        manager,
        receivers,
        changed,
        expected_inventory,
    }
}

fn assert_grouped_policy_denial_receipt(receipt: AdjRibOutFanoutBenchReceipt, peers: usize) {
    assert_eq!(receipt.update_groups, 1);
    assert_eq!(receipt.grouped_peers, peers);
    assert_eq!(
        receipt.ungrouped_peers, 0,
        "private fallback invalidates grouped policy-denial staging"
    );
    assert_eq!(
        receipt.dirty_peers, 0,
        "dirty resync invalidates grouped policy-denial staging"
    );
    assert_eq!(
        receipt.grouped_unicast_routes, 0,
        "the denied replacement must retire the prior group-owned inventory"
    );
    assert_eq!(
        receipt.private_unicast_routes, 0,
        "no private Adj-RIB-Out may retain the denied replacement"
    );
    assert_eq!(receipt.routes_received_dispatches, 0);
    assert_eq!(receipt.routes_received_withdrawals, 0);
    assert_eq!(
        receipt.exact_probe_batches, 0,
        "withdrawal-only policy-denial envelopes must skip announcement probes"
    );
    assert_eq!(receipt.exact_probe_candidates, 0);
    assert_eq!(receipt.exact_probe_nonzero_encoded_lengths, 0);
    assert_eq!(receipt.exact_probe_cache_reuses, 0);
    assert_eq!(
        receipt.successful_commits, peers,
        "every grouped member must commit the policy withdrawal"
    );
    assert_eq!(
        receipt.successful_enqueues, peers,
        "every grouped member must enqueue the policy withdrawal"
    );
    assert_eq!(receipt.family_gauge_writes, peers);
    assert_eq!(receipt.last_family_gauge_write_mask, 0x01);
    assert_eq!(
        receipt.first_peer_family_values, [0; 7],
        "the denied inventory must leave the first member's Adj-RIB-Out empty"
    );
}

fn drain_grouped_policy_denials(
    receivers: &mut [mpsc::Receiver<OutboundRouteUpdate>],
    expected_inventory: &HashSet<(Prefix, u32)>,
) {
    for receiver in receivers {
        let update = receiver
            .try_recv()
            .expect("every grouped member must receive one policy withdrawal");
        assert!(
            update.announce.is_empty(),
            "the denied MED-51 replacement must never be announced"
        );
        assert!(update.next_hop_override.is_empty());
        assert_eq!(
            update.withdraw.iter().copied().collect::<HashSet<_>>(),
            *expected_inventory,
            "the withdrawal must exactly retire the MED-50 setup inventory"
        );
        assert_eq!(
            update.withdraw.len(),
            expected_inventory.len(),
            "the policy withdrawal must not contain duplicate identities"
        );
        assert_unicast_only_envelope(&update);
        assert_real_transport_snapshot(&update);
        assert!(
            matches!(receiver.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
            "one denied replacement must leave a live channel with no residue"
        );
    }
}

fn bench_grouped_policy_denial_fanout(c: &mut Criterion) {
    let mut group = c.benchmark_group("grouped_policy_denial_fanout");
    group.sample_size(10);
    for &peers in &GROUPED_POLICY_DENIAL_PEER_COUNTS {
        group.bench_with_input(
            BenchmarkId::new("homogeneous_route_server", peers),
            &peers,
            |bench, &peers| {
                bench.iter_custom(|iterations| {
                    let mut accumulated = Duration::ZERO;
                    for _ in 0..iterations {
                        let mut state = build_grouped_policy_denial_fanout(peers);
                        let started = Instant::now();
                        state.manager.bench_distribute(&state.changed);
                        accumulated += started.elapsed();
                        assert_grouped_policy_denial_receipt(
                            state.manager.bench_adj_rib_out_fanout_receipt(),
                            peers,
                        );
                        drain_grouped_policy_denials(
                            &mut state.receivers,
                            &state.expected_inventory,
                        );
                    }
                    accumulated
                });
            },
        );
    }
    group.finish();
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

struct InitialTableJoinState {
    manager: RibManager,
    sender: Option<mpsc::Sender<OutboundRouteUpdate>>,
    receiver: mpsc::Receiver<OutboundRouteUpdate>,
    encoder: Option<Arc<dyn ExactExportEncoder>>,
    snapshot_evidence: FanoutBenchExportSnapshotEvidence,
    expected_inventory: HashSet<(Prefix, u32)>,
}

fn build_initial_table_join(routes: usize) -> InitialTableJoinState {
    let (_tx, rx) = mpsc::channel::<RibUpdate>(16);
    let (_qtx, qrx) = mpsc::channel::<RibUpdate>(16);
    let mut manager = RibManager::new(
        rx,
        qrx,
        None,
        Some(Ipv4Addr::new(10, 255, 255, 255)),
        BgpMetrics::new(),
    );
    // Pre-seeding is the defining control: registering first would time no
    // initial inventory and leave the EoR as the first queued envelope.
    let seeded = policy_regroup_routes(routes);
    let expected_inventory = seeded
        .iter()
        .map(|route| (route.prefix, route.path_id))
        .collect::<HashSet<_>>();
    assert_eq!(
        expected_inventory.len(),
        routes,
        "the deterministic seed must contain one unique route identity per row"
    );
    manager.bench_seed_loc_rib(seeded);
    manager.bench_reset_adj_rib_out_fanout_receipt();

    // Two synchronous envelopes are expected: one route-bearing dump and one
    // EoR. Channel allocation and encoder construction remain outside the
    // timed PeerUp call.
    let (sender, receiver) = mpsc::channel(2);
    let encoder = fanout_bench_export_encoder();
    let snapshot = encoder.snapshot();
    let snapshot_evidence = fanout_bench_export_snapshot_evidence(snapshot.as_ref())
        .expect("the fixture must use the authoritative transport-session snapshot");
    assert_ne!(
        snapshot_evidence.owner_id, 0,
        "the authoritative snapshot must be owned by a real session encoder"
    );
    assert_eq!(snapshot_evidence.owner_id, encoder.owner_id());
    assert_eq!(
        snapshot_evidence.max_message_len,
        usize::from(rustbgpd_wire::MAX_MESSAGE_LEN),
        "the fixture models a classic-message negotiated session"
    );

    InitialTableJoinState {
        manager,
        sender: Some(sender),
        receiver,
        encoder: Some(encoder),
        snapshot_evidence,
        expected_inventory,
    }
}

fn assert_initial_table_join_receipt(state: &mut InitialTableJoinState, routes: usize) {
    let receipt = state.manager.bench_adj_rib_out_fanout_receipt();
    assert_eq!(
        receipt.update_groups, 1,
        "the joining RR client must build and replay one production update group"
    );
    assert_eq!(receipt.grouped_peers, 1);
    assert_eq!(
        receipt.ungrouped_peers, 0,
        "a private fallback would measure the wrong initial-table join shape"
    );
    assert_eq!(receipt.dirty_peers, 0);
    assert_eq!(
        receipt.exact_probe_batches, 1,
        "the initial inventory must traverse one real exact-export batch"
    );
    assert_eq!(
        receipt.exact_probe_candidates, routes,
        "every pre-seeded route must traverse the authoritative encoder"
    );
    assert_eq!(
        receipt.exact_probe_nonzero_encoded_lengths, routes,
        "every production probe must report a nonzero encoded UPDATE length"
    );
    assert_eq!(receipt.exact_probe_cache_reuses, 0);
    assert_eq!(receipt.successful_commits, 1);
    assert_eq!(receipt.successful_enqueues, 1);
    assert_eq!(receipt.family_gauge_writes, 1);
    assert_eq!(receipt.last_family_gauge_write_mask, 0x01);
    assert_eq!(
        receipt.first_peer_family_values,
        [
            i64::try_from(routes).expect("fixture size fits i64"),
            0,
            0,
            0,
            0,
            0,
            0
        ],
        "the committed Adj-RIB-Out inventory must match the pre-seeded table exactly"
    );

    let initial = state
        .receiver
        .try_recv()
        .expect("initial-table join must enqueue one route-bearing envelope");
    assert_eq!(initial.announce.len(), routes);
    assert_eq!(initial.next_hop_override.len(), routes);
    assert!(
        initial.next_hop_override.iter().all(Option::is_none),
        "the no-policy fixture must not carry any next-hop override"
    );
    let actual_inventory = initial
        .announce
        .iter()
        .map(|route| (route.prefix, route.path_id))
        .collect::<HashSet<_>>();
    assert_eq!(
        actual_inventory, state.expected_inventory,
        "the initial envelope must contain exactly the deterministic seed inventory"
    );
    assert!(initial.announce_source_exclusion.is_none());
    assert!(initial.withdraw.is_empty());
    assert!(initial.end_of_rib.is_empty());
    assert!(initial.refresh_markers.is_empty());
    assert!(initial.flowspec_announce.is_empty());
    assert!(initial.flowspec_withdraw.is_empty());
    assert!(initial.evpn_announce.is_empty());
    assert!(initial.evpn_withdraw.is_empty());
    assert!(initial.bgpls_announce.is_empty());
    assert!(initial.bgpls_withdraw.is_empty());
    assert!(initial.vpn_announce.is_empty());
    assert!(initial.vpn_withdraw.is_empty());
    assert!(initial.labeled_announce.is_empty());
    assert!(initial.labeled_withdraw.is_empty());
    assert!(initial.rtc_announce.is_empty());
    assert!(initial.rtc_withdraw.is_empty());
    assert!(initial.otc_blocked.is_empty());
    assert!(!initial.request_refresh_all_negotiated);
    assert!(initial.shared_group_encode.is_none());
    let snapshot = initial
        .exact_export_snapshot
        .expect("route-bearing initial dump must retain the real session snapshot");
    assert_eq!(
        fanout_bench_export_snapshot_evidence(snapshot.as_ref()),
        Some(state.snapshot_evidence),
        "the envelope must retain the authoritative transport-session snapshot"
    );

    let eor = state
        .receiver
        .try_recv()
        .expect("initial-table inventory must be followed by one EoR envelope");
    assert!(eor.exact_export_snapshot.is_none());
    assert!(eor.announce_source_exclusion.is_none());
    assert!(eor.announce.is_empty());
    assert!(eor.withdraw.is_empty());
    assert_eq!(eor.end_of_rib, vec![(Afi::Ipv4, Safi::Unicast)]);
    assert!(eor.refresh_markers.is_empty());
    assert!(eor.next_hop_override.is_empty());
    assert!(eor.flowspec_announce.is_empty());
    assert!(eor.flowspec_withdraw.is_empty());
    assert!(eor.evpn_announce.is_empty());
    assert!(eor.evpn_withdraw.is_empty());
    assert!(eor.bgpls_announce.is_empty());
    assert!(eor.bgpls_withdraw.is_empty());
    assert!(eor.vpn_announce.is_empty());
    assert!(eor.vpn_withdraw.is_empty());
    assert!(eor.labeled_announce.is_empty());
    assert!(eor.labeled_withdraw.is_empty());
    assert!(eor.rtc_announce.is_empty());
    assert!(eor.rtc_withdraw.is_empty());
    assert!(eor.otc_blocked.is_empty());
    assert!(!eor.request_refresh_all_negotiated);
    assert!(eor.shared_group_encode.is_none());
    assert!(
        matches!(
            state.receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ),
        "one initial-table join must enqueue exactly one inventory and one EoR envelope"
    );
}

fn bench_initial_table_peer_join(c: &mut Criterion) {
    let mut group = c.benchmark_group("initial_table_peer_join");
    group.sample_size(10);
    for &routes in &INITIAL_TABLE_JOIN_ROUTE_COUNTS {
        group.bench_with_input(
            BenchmarkId::new("rr_client_ipv4_unicast", routes),
            &routes,
            |bench, &routes| {
                bench.iter_custom(|iterations| {
                    let mut accumulated = Duration::ZERO;
                    for _ in 0..iterations {
                        let mut state = build_initial_table_join(routes);
                        let sender = state.sender.take().expect("one timed join");
                        let encoder = state.encoder.take().expect("one timed join");
                        let started = Instant::now();
                        state
                            .manager
                            .bench_join_route_reflector_peer(0, sender, encoder);
                        accumulated += started.elapsed();
                        // Production-path and queue inspection deliberately
                        // stay outside the accumulated join duration.
                        assert_initial_table_join_receipt(&mut state, routes);
                    }
                    accumulated
                });
            },
        );
    }
    group.finish();
}

#[derive(Clone, Copy)]
enum AddPathPolicy {
    PermitAll,
    DenyBest,
}

impl AddPathPolicy {
    const fn label(self) -> &'static str {
        match self {
            Self::PermitAll => "permit_all",
            Self::DenyBest => "deny_best",
        }
    }

    const fn first_eligible_index(self) -> usize {
        match self {
            Self::PermitAll => 0,
            Self::DenyBest => 1,
        }
    }
}

struct AddPathStagingState {
    manager: RibManager,
    receiver: mpsc::Receiver<OutboundRouteUpdate>,
    candidates: usize,
    send_max: u32,
    policy: AddPathPolicy,
    med: u32,
}

fn build_add_path_staging(
    candidates: usize,
    send_max: u32,
    policy: AddPathPolicy,
) -> AddPathStagingState {
    let (_tx, rx) = mpsc::channel::<RibUpdate>(16);
    let (_qtx, qrx) = mpsc::channel::<RibUpdate>(16);
    let mut manager = RibManager::new(
        rx,
        qrx,
        None,
        Some(Ipv4Addr::new(10, 255, 255, 255)),
        BgpMetrics::new(),
    );
    let best_local_pref =
        10_000 + u32::try_from(candidates).expect("benchmark candidate count fits u32");
    let export_policy = match policy {
        AddPathPolicy::PermitAll => None,
        AddPathPolicy::DenyBest => Some(deny_best_export_chain(best_local_pref)),
    };
    manager.bench_seed_loc_rib(
        (0..candidates)
            .map(|index| add_path_route(index, candidates, 40))
            .collect(),
    );
    manager.bench_reset_adj_rib_out_fanout_receipt();
    let mut receiver = manager.bench_register_add_path_peer(
        export_policy.as_ref(),
        send_max,
        4,
        fanout_bench_add_path_export_encoder(),
    );
    let setup = receiver
        .try_recv()
        .expect("Add-Path setup must enqueue one route-bearing initial table");
    assert_add_path_envelope(&setup, candidates, send_max, policy, 40);
    let eor = receiver
        .try_recv()
        .expect("Add-Path setup inventory must be followed by one EoR");
    assert_add_path_eor(&eor);
    assert!(
        matches!(receiver.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "Add-Path setup must leave a live channel with no residue"
    );
    assert_add_path_receipt(
        manager.bench_adj_rib_out_fanout_receipt(),
        candidates,
        send_max,
    );
    assert_eq!(
        manager.bench_unicast_candidate_count(add_path_prefix()),
        candidates,
        "setup must retain the complete reverse-index candidate inventory"
    );
    manager.bench_reset_adj_rib_out_fanout_receipt();
    AddPathStagingState {
        manager,
        receiver,
        candidates,
        send_max,
        policy,
        med: 40,
    }
}

fn add_path_prefix() -> Prefix {
    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 7), 32))
}

fn assert_add_path_eor(update: &OutboundRouteUpdate) {
    assert!(update.announce.is_empty());
    assert!(update.withdraw.is_empty());
    assert_eq!(update.end_of_rib, vec![(Afi::Ipv4, Safi::Unicast)]);
    assert!(update.refresh_markers.is_empty());
    assert!(update.next_hop_override.is_empty());
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
    assert!(update.otc_blocked.is_empty());
    assert!(update.exact_export_snapshot.is_none());
    assert!(!update.request_refresh_all_negotiated);
}

fn assert_add_path_envelope(
    update: &OutboundRouteUpdate,
    candidates: usize,
    send_max: u32,
    policy: AddPathPolicy,
    med: u32,
) {
    let expected_count = usize::try_from(send_max).expect("send_max fits usize");
    assert_eq!(
        update.announce.len(),
        expected_count,
        "policy must run before the Add-Path cap"
    );
    assert!(update.withdraw.is_empty());
    assert_unicast_only_envelope(update);
    let expected_path_ids = (1..=send_max).collect::<Vec<_>>();
    assert_eq!(
        update
            .announce
            .iter()
            .map(|route| route.path_id)
            .collect::<Vec<_>>(),
        expected_path_ids,
        "eligible Add-Path candidates must receive compact path IDs"
    );
    let first = policy.first_eligible_index();
    let expected_local_prefs = (first..first + expected_count)
        .map(|index| {
            10_000 + u32::try_from(candidates - index).expect("benchmark candidate rank fits u32")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        update
            .announce
            .iter()
            .map(Route::local_pref)
            .collect::<Vec<_>>(),
        expected_local_prefs,
        "the top eligible candidates must fill send_max in best-path order"
    );
    assert_eq!(
        update
            .announce
            .iter()
            .map(|route| route.peer)
            .collect::<Vec<_>>(),
        (first..first + expected_count)
            .map(|index| IpAddr::V4(add_path_source(index)))
            .collect::<Vec<_>>(),
        "the exact eligible source inventory must fill send_max"
    );
    assert!(
        update.announce.iter().all(|route| {
            route
                .attributes
                .iter()
                .any(|attribute| *attribute == PathAttribute::Med(med))
        }),
        "every measured pass must carry the alternating wire-visible MED"
    );
    let snapshot = update
        .exact_export_snapshot
        .as_ref()
        .expect("Add-Path envelope must retain the real transport snapshot");
    let evidence = fanout_bench_export_snapshot_evidence(snapshot.as_ref())
        .expect("Add-Path envelope must use the concrete transport snapshot");
    assert_ne!(evidence.owner_id, 0);
    assert!(
        evidence.add_path_ipv4_unicast,
        "the transport encoder must have negotiated IPv4-unicast Add-Path send"
    );
    assert_eq!(
        evidence.max_message_len,
        usize::from(rustbgpd_wire::MAX_MESSAGE_LEN)
    );
}

fn assert_add_path_receipt(receipt: AdjRibOutFanoutBenchReceipt, candidates: usize, send_max: u32) {
    let send_max = usize::try_from(send_max).expect("send_max fits usize");
    assert_eq!(receipt.update_groups, 0);
    assert_eq!(receipt.grouped_peers, 0);
    assert_eq!(receipt.ungrouped_peers, 1);
    assert_eq!(receipt.dirty_peers, 0);
    assert_eq!(receipt.grouped_unicast_routes, 0);
    assert_eq!(
        receipt.private_unicast_routes, send_max,
        "Add-Path must retain a private per-peer inventory"
    );
    assert_eq!(receipt.exact_probe_batches, 1);
    assert_eq!(receipt.exact_probe_candidates, send_max);
    assert_eq!(receipt.exact_probe_nonzero_encoded_lengths, send_max);
    assert_eq!(receipt.successful_commits, 1);
    assert_eq!(receipt.successful_enqueues, 1);
    assert_eq!(
        receipt.add_path_bounded_dispatches,
        usize::from(candidates >= 64)
    );
    assert_eq!(
        receipt.add_path_full_sort_dispatches,
        usize::from(candidates < 64)
    );
    assert_eq!(receipt.add_path_sorted_tail_fallbacks, 0);
    assert_eq!(receipt.first_peer_family_values[0], send_max as i64);
}

fn measure_add_path_staging(
    iterations: u64,
    candidates: usize,
    send_max: u32,
    policy: AddPathPolicy,
) -> Duration {
    let mut state = build_add_path_staging(candidates, send_max, policy);
    let mut accumulated = Duration::ZERO;
    for _ in 0..iterations {
        state.med = if state.med == 50 { 51 } else { 50 };
        let affected = state.manager.bench_prepare_multipath_replacement(
            (0..state.candidates)
                .map(|index| add_path_route(index, state.candidates, state.med))
                .collect(),
        );
        assert_eq!(affected.len(), 1);
        assert_eq!(
            state
                .manager
                .bench_unicast_candidate_count(add_path_prefix()),
            state.candidates,
            "replacement must retain the complete reverse-index candidate inventory"
        );
        state.manager.bench_reset_adj_rib_out_fanout_receipt();
        assert_eq!(
            state
                .manager
                .bench_unicast_candidate_count(add_path_prefix()),
            state.candidates,
            "the timed distribution must start with the exact candidate inventory"
        );
        let started = Instant::now();
        state.manager.bench_distribute(&affected);
        accumulated += started.elapsed();
        assert_add_path_receipt(
            state.manager.bench_adj_rib_out_fanout_receipt(),
            state.candidates,
            state.send_max,
        );
        let update = state
            .receiver
            .try_recv()
            .expect("measured Add-Path pass must enqueue one envelope");
        assert_add_path_envelope(
            &update,
            state.candidates,
            state.send_max,
            state.policy,
            state.med,
        );
        assert!(
            matches!(
                state.receiver.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ),
            "draining the measured envelope must leave a live channel with no residue"
        );
    }
    accumulated
}

fn bench_add_path_export_staging(c: &mut Criterion) {
    let mut group = c.benchmark_group("add_path_export_staging");
    for policy in [AddPathPolicy::PermitAll, AddPathPolicy::DenyBest] {
        for &candidates in &ADD_PATH_CANDIDATE_COUNTS {
            for &send_max in &ADD_PATH_SEND_MAXES {
                let parameter = format!("{candidates}/send_max_{send_max}");
                group.bench_with_input(
                    BenchmarkId::new(policy.label(), parameter),
                    &(candidates, send_max),
                    |bench, &(candidates, send_max)| {
                        bench.iter_custom(|iterations| {
                            measure_add_path_staging(iterations, candidates, send_max, policy)
                        });
                    },
                );
            }
        }
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
    bench_grouped_withdrawal_fanout,
    bench_grouped_policy_denial_fanout,
    bench_initial_table_peer_join,
    bench_add_path_export_staging,
    bench_policy_regroup_resync,
    bench_ixp_policy_regroup_resync
);
criterion_main!(benches);
