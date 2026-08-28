//! Internal bounded dataplane prefix pages.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use rustbgpd_wire::{
    AsPath, AsPathSegment, ExtendedCommunity, Ipv4Prefix, Ipv6Prefix, Origin, PathAttribute, Prefix,
};
use tokio::sync::{mpsc, oneshot};

use super::*;
use crate::adj_rib_in::AdjRibIn;
use crate::manager::queries::{DATAPLANE_PAGE_MAX_NEXT_HOPS, DATAPLANE_PAGE_MAX_PREFIXES};
use crate::route::{FibInstallCandidate, NextHopScope, Route};
use crate::update::{
    BestRoutesPage, DataplanePageError, FibInstallCandidatesPage, RoutePageVersion,
};

fn manager(eager: bool) -> RibManager {
    let (_tx, rx) = mpsc::channel(1);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    if eager {
        manager.with_eager_dataplane_prefix_index()
    } else {
        manager
    }
}

fn prefix(index: usize) -> Prefix {
    let host = 0x0a00_0000u32
        .checked_add(u32::try_from(index).expect("fixture index fits IPv4"))
        .expect("fixture stays in IPv4 space");
    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(host), 32))
}

fn peer(index: usize) -> Ipv4Addr {
    Ipv4Addr::from(
        0xc633_6401u32
            .checked_add(u32::try_from(index).expect("fixture peer index fits IPv4"))
            .expect("fixture peers stay in IPv4 space"),
    )
}

fn route(prefix: Prefix, peer: Ipv4Addr, next_hop: IpAddr, as_path: &[u32]) -> Route {
    let mut route = match prefix {
        Prefix::V4(prefix) => crate::test_support::make_route_with_lp(prefix, peer, 100),
        Prefix::V6(prefix) => crate::test_support::make_v6_route(
            prefix,
            match next_hop {
                IpAddr::V6(next_hop) => next_hop,
                IpAddr::V4(_) => Ipv6Addr::LOCALHOST,
            },
        ),
    };
    route.peer = IpAddr::V4(peer);
    route.peer_router_id = peer;
    route.next_hop = next_hop;
    route.attributes = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(as_path.to_vec())],
        }),
        PathAttribute::LocalPref(100),
    ]);
    route
}

fn apply_routes(manager: &mut RibManager, peer: Ipv4Addr, announced: Vec<Route>) {
    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(peer),
        announced,
        withdrawn: Vec::new(),
        flowspec_announced: Vec::new(),
        flowspec_withdrawn: Vec::new(),
        evpn_announced: Vec::new(),
        evpn_withdrawn: Vec::new(),
    });
    while manager.process_next_route_chunk() {}
}

fn withdraw(manager: &mut RibManager, peer: Ipv4Addr, prefixes: &[Prefix]) {
    manager.handle_update(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V4(peer),
        announced: Vec::new(),
        withdrawn: prefixes.iter().copied().map(|prefix| (prefix, 0)).collect(),
        flowspec_announced: Vec::new(),
        flowspec_withdrawn: Vec::new(),
        evpn_announced: Vec::new(),
        evpn_withdrawn: Vec::new(),
    });
    while manager.process_next_route_chunk() {}
}

fn best_page(
    manager: &mut RibManager,
    after: Option<Prefix>,
) -> Result<BestRoutesPage, DataplanePageError> {
    let (reply, mut response) = oneshot::channel();
    manager.handle_query_best_routes_page(
        after,
        tokio::time::Instant::now() + Duration::from_secs(60),
        reply,
    );
    response
        .try_recv()
        .expect("best page handler replies synchronously")
}

fn fib_page(
    manager: &mut RibManager,
    after: Option<Prefix>,
    max_paths: u32,
    relax: bool,
    weighted: bool,
) -> Result<FibInstallCandidatesPage, DataplanePageError> {
    let (reply, mut response) = oneshot::channel();
    manager.handle_query_fib_install_candidates_page(
        after,
        max_paths,
        relax,
        weighted,
        tokio::time::Instant::now() + Duration::from_secs(60),
        reply,
    );
    response
        .try_recv()
        .expect("FIB page handler replies synchronously")
}

fn full_fib(
    manager: &mut RibManager,
    max_paths: u32,
    relax: bool,
    weighted: bool,
) -> Vec<FibInstallCandidate> {
    let (reply, mut response) = oneshot::channel();
    manager.handle_query_fib_install_candidates(
        max_paths,
        relax,
        weighted,
        tokio::time::Instant::now() + Duration::from_secs(60),
        reply,
    );
    response
        .try_recv()
        .expect("full FIB handler replies synchronously")
}

fn assert_route_field_equivalent(actual: &Route, expected: &Route) {
    assert_eq!(actual.prefix, expected.prefix);
    assert_eq!(actual.next_hop, expected.next_hop);
    assert_eq!(actual.link_local_next_hop, expected.link_local_next_hop);
    assert_eq!(actual.next_hop_scope, expected.next_hop_scope);
    assert_eq!(actual.peer, expected.peer);
    assert_eq!(actual.attributes, expected.attributes);
    assert_eq!(actual.received_at, expected.received_at);
    assert_eq!(actual.origin_type, expected.origin_type);
    assert_eq!(actual.peer_router_id, expected.peer_router_id);
    assert_eq!(actual.is_stale, expected.is_stale);
    assert_eq!(actual.is_llgr_stale, expected.is_llgr_stale);
    assert_eq!(actual.path_id, expected.path_id);
    assert_eq!(actual.validation_state, expected.validation_state);
    assert_eq!(actual.aspa_state, expected.aspa_state);
    assert_eq!(actual.aspa_context, expected.aspa_context);
}

#[test]
fn eager_index_is_ready_and_default_lazy_mode_never_rebuilds_for_dataplane() {
    let source = peer(0);
    let routes = (0..3)
        .map(|index| route(prefix(index), source, IpAddr::V4(source), &[65001]))
        .collect();
    let mut eager = manager(true);
    apply_routes(&mut eager, source, routes);
    assert_eq!(eager.loc_rib.dataplane_index_probe(), (true, 3, 0, false));
    assert_eq!(best_page(&mut eager, None).unwrap().routes.len(), 3);
    assert_eq!(eager.loc_rib.dataplane_index_probe(), (true, 3, 0, false));

    let mut lazy = manager(false);
    apply_routes(
        &mut lazy,
        source,
        vec![route(prefix(0), source, IpAddr::V4(source), &[65001])],
    );
    let before = lazy.loc_rib.dataplane_index_probe();
    assert_eq!(
        best_page(&mut lazy, None).unwrap_err(),
        DataplanePageError::IndexDisabled
    );
    assert_eq!(lazy.loc_rib.dataplane_index_probe(), before);
}

#[test]
fn best_pages_order_ipv4_before_ipv6_and_match_the_full_snapshot() {
    let source = peer(0);
    let mut manager = manager(true);
    let routes = vec![
        route(
            Prefix::V6(Ipv6Prefix::new("2001:db8:2::".parse().unwrap(), 48)),
            source,
            "2001:db8::2".parse().unwrap(),
            &[65001],
        ),
        route(prefix(2), source, IpAddr::V4(source), &[65001]),
        route(
            Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32)),
            source,
            "2001:db8::1".parse().unwrap(),
            &[65001],
        ),
        route(prefix(1), source, IpAddr::V4(source), &[65001]),
    ];
    apply_routes(&mut manager, source, routes);

    let page = best_page(&mut manager, None).unwrap();
    let prefixes = page
        .routes
        .iter()
        .map(|route| route.prefix)
        .collect::<Vec<_>>();
    assert!(prefixes.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(page.next_cursor, None);

    let (reply, mut response) = oneshot::channel();
    manager.handle_query_best_routes(tokio::time::Instant::now() + Duration::from_secs(60), reply);
    let mut full = response.try_recv().unwrap();
    full.sort_by_key(|route| route.prefix);
    for (actual, expected) in page.routes.iter().zip(&full) {
        assert_route_field_equivalent(actual, expected);
    }
}

#[test]
fn prefix_cursor_has_live_churn_semantics() {
    let source = peer(0);
    let mut manager = manager(true);
    apply_routes(
        &mut manager,
        source,
        [10usize, 20, 30]
            .into_iter()
            .map(|index| route(prefix(index), source, IpAddr::V4(source), &[65001]))
            .collect(),
    );
    let cursor = prefix(20);
    let before = best_page(&mut manager, Some(cursor)).unwrap();
    assert_eq!(before.routes[0].prefix, prefix(30));

    // A behind-cursor insertion is not revisited; an ahead insertion may
    // appear; a withdrawn ahead row disappears.
    apply_routes(
        &mut manager,
        source,
        vec![
            route(prefix(15), source, IpAddr::V4(source), &[65001]),
            route(prefix(25), source, IpAddr::V4(source), &[65001]),
        ],
    );
    withdraw(&mut manager, source, &[prefix(30)]);
    let page = best_page(&mut manager, Some(cursor)).unwrap();
    assert_ne!(page.observed_version, before.observed_version);
    assert_eq!(
        page.routes
            .iter()
            .map(|route| route.prefix)
            .collect::<Vec<_>>(),
        vec![prefix(25)]
    );

    // Payload and best-peer churn changes the row but never its cursor key.
    let replacement_peer = peer(1);
    let mut replacement = route(
        prefix(25),
        replacement_peer,
        IpAddr::V4(replacement_peer),
        &[65001],
    );
    replacement.attributes = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65001])],
        }),
        PathAttribute::LocalPref(200),
    ]);
    apply_routes(&mut manager, replacement_peer, vec![replacement]);
    let again = best_page(&mut manager, Some(cursor)).unwrap();
    assert_ne!(again.observed_version, page.observed_version);
    assert_eq!(again.routes.len(), 1);
    assert_eq!(again.routes[0].prefix, prefix(25));
    assert_eq!(again.routes[0].peer, IpAddr::V4(replacement_peer));
}

#[test]
fn exact_thousand_prefix_boundary_never_revisits_or_splits() {
    let source = peer(0);
    let mut manager = manager(true);
    let final_v6 = Prefix::V6(Ipv6Prefix::new("2001:db8:ffff::".parse().unwrap(), 48));
    let mut routes = (0..=DATAPLANE_PAGE_MAX_PREFIXES)
        .map(|index| route(prefix(index), source, IpAddr::V4(source), &[65001]))
        .collect::<Vec<_>>();
    routes.push(route(
        final_v6,
        source,
        "2001:db8::ffff".parse().unwrap(),
        &[65001],
    ));
    apply_routes(&mut manager, source, routes);

    let first = best_page(&mut manager, None).unwrap();
    assert_eq!(first.routes.len(), DATAPLANE_PAGE_MAX_PREFIXES);
    assert_eq!(first.next_cursor, Some(prefix(999)));
    let second = best_page(&mut manager, first.next_cursor).unwrap();
    assert_eq!(second.routes.len(), 2);
    assert_eq!(second.routes[0].prefix, prefix(1_000));
    assert_eq!(second.routes[1].prefix, final_v6);
    assert_eq!(second.next_cursor, None);

    let first = fib_page(&mut manager, None, 1, false, false).unwrap();
    assert_eq!(first.candidates.len(), DATAPLANE_PAGE_MAX_PREFIXES);
    assert_eq!(first.next_cursor, Some(prefix(999)));
    let second = fib_page(&mut manager, first.next_cursor, 1, false, false).unwrap();
    assert_eq!(second.candidates.len(), 2);
    assert_eq!(second.candidates[0].best.prefix, prefix(1_000));
    assert_eq!(second.candidates[1].best.prefix, final_v6);
    assert_eq!(second.next_cursor, None);
}

#[test]
fn paged_fib_matches_full_single_strict_relaxed_and_weighted_views() {
    let mut manager = manager(true);
    let strict_prefix = prefix(10);
    let weighted_prefix = prefix(20);
    for (index, source) in [peer(0), peer(1)].into_iter().enumerate() {
        let mut strict = route(
            strict_prefix,
            source,
            IpAddr::V4(source),
            &[65001 + u32::try_from(index).unwrap()],
        );
        strict.path_id = u32::try_from(index).unwrap();
        let mut weighted = route(weighted_prefix, source, IpAddr::V4(source), &[65100]);
        Arc::make_mut(&mut weighted.attributes).push(PathAttribute::ExtendedCommunities(vec![
            ExtendedCommunity::link_bandwidth(65001, if index == 0 { 40e9 } else { 10e9 }),
        ]));
        apply_routes(&mut manager, source, vec![strict, weighted]);
    }

    for (max_paths, relax, weighted) in [
        (1, false, false),
        (2, false, false),
        (2, true, false),
        (2, false, true),
    ] {
        let page = fib_page(&mut manager, None, max_paths, relax, weighted).unwrap();
        let mut full = full_fib(&mut manager, max_paths, relax, weighted);
        full.sort_by_key(|candidate| candidate.best.prefix);
        assert_eq!(page.candidates.len(), full.len());
        for (actual, expected) in page.candidates.iter().zip(&full) {
            assert_route_field_equivalent(&actual.best, &expected.best);
            assert_eq!(actual.next_hops, expected.next_hops);
        }
    }

    let strict = fib_page(&mut manager, None, 2, false, false).unwrap();
    assert_eq!(strict.candidates[0].next_hops.len(), 1);
    let relaxed = fib_page(&mut manager, None, 2, true, false).unwrap();
    assert_eq!(relaxed.candidates[0].next_hops.len(), 2);
    let weighted = fib_page(&mut manager, None, 2, false, true).unwrap();
    let weighted = weighted
        .candidates
        .iter()
        .find(|candidate| candidate.best.prefix == weighted_prefix)
        .unwrap();
    assert_eq!(weighted.next_hops[0].weight, 256);
    assert_eq!(weighted.next_hops[1].weight, 64);
}

#[test]
fn fib_dedup_preserves_link_local_scope_and_normalizes_max_paths() {
    let mut manager = manager(true);
    let dedup_prefix = prefix(40);
    let scoped_prefix = Prefix::V6(Ipv6Prefix::new("2001:db8:40::".parse().unwrap(), 48));
    for index in 0..300usize {
        let source = peer(index);
        let mut dedup = route(
            dedup_prefix,
            source,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            &[65001],
        );
        dedup.path_id = u32::try_from(index).unwrap();
        let mut rows = vec![dedup];
        if index < 2 {
            let mut scoped = route(scoped_prefix, source, "fe80::1".parse().unwrap(), &[65001]);
            scoped.next_hop_scope = Some(Box::new(NextHopScope {
                interface: Arc::from(format!("eth{index}")),
                ifindex: u32::try_from(index + 1).unwrap(),
            }));
            rows.push(scoped);
        }
        apply_routes(&mut manager, source, rows);
    }

    let page = fib_page(&mut manager, None, u32::MAX, false, false).unwrap();
    let dedup = page
        .candidates
        .iter()
        .find(|candidate| candidate.best.prefix == dedup_prefix)
        .unwrap();
    assert_eq!(dedup.next_hops.len(), 1, "same egress must dedupe");
    let scoped = page
        .candidates
        .iter()
        .find(|candidate| candidate.best.prefix == scoped_prefix)
        .unwrap();
    assert_eq!(scoped.next_hops.len(), 2);
    assert_ne!(
        scoped.next_hops[0].next_hop_scope,
        scoped.next_hops[1].next_hop_scope
    );

    // Give one prefix 300 distinct egresses; the page-specific normalization
    // caps it at 256 without splitting the prefix.
    let capped_prefix = prefix(50);
    for index in 0..300usize {
        let source = peer(index);
        apply_routes(
            &mut manager,
            source,
            vec![route(capped_prefix, source, IpAddr::V4(source), &[65001])],
        );
    }
    let capped = fib_page(&mut manager, Some(prefix(40)), u32::MAX, false, false).unwrap();
    let capped = capped
        .candidates
        .iter()
        .find(|candidate| candidate.best.prefix == capped_prefix)
        .unwrap();
    assert_eq!(capped.next_hops.len(), 256);
}

#[test]
fn exact_next_hop_budget_stops_before_a_complete_prefix() {
    let mut manager = manager(true);
    let prefix_count = DATAPLANE_PAGE_MAX_NEXT_HOPS / 256 + 1;
    for peer_index in 0..256usize {
        let source = peer(peer_index);
        apply_routes(
            &mut manager,
            source,
            (0..prefix_count)
                .map(|prefix_index| {
                    route(prefix(prefix_index), source, IpAddr::V4(source), &[65001])
                })
                .collect(),
        );
    }

    let first = fib_page(&mut manager, None, 256, false, false).unwrap();
    assert_eq!(first.candidates.len(), 32);
    assert_eq!(
        first
            .candidates
            .iter()
            .map(|candidate| candidate.next_hops.len())
            .sum::<usize>(),
        DATAPLANE_PAGE_MAX_NEXT_HOPS
    );
    assert_eq!(first.next_cursor, Some(prefix(31)));
    let second = fib_page(&mut manager, first.next_cursor, 256, false, false).unwrap();
    assert_eq!(second.candidates.len(), 1);
    assert_eq!(second.candidates[0].next_hops.len(), 256);
    assert_eq!(second.candidates[0].best.prefix, prefix(32));
    assert_eq!(second.next_cursor, None);
}

#[test]
fn fib_page_probes_only_indexed_announcers_for_each_prefix() {
    let source = peer(0);
    let mut manager = manager(true);
    apply_routes(
        &mut manager,
        source,
        vec![route(prefix(0), source, IpAddr::V4(source), &[65001])],
    );
    for index in 1..=300usize {
        let unrelated_peer = peer(index);
        let mut rib = AdjRibIn::new(IpAddr::V4(unrelated_peer));
        rib.insert(route(
            prefix(10_000 + index),
            unrelated_peer,
            IpAddr::V4(unrelated_peer),
            &[65001],
        ));
        manager.ribs.insert(IpAddr::V4(unrelated_peer), rib);
    }

    manager
        .dataplane_page_announcer_visits
        .store(0, Ordering::Relaxed);
    manager
        .dataplane_page_sibling_visits
        .store(0, Ordering::Relaxed);
    let page = fib_page(&mut manager, None, 2, false, false).unwrap();
    assert_eq!(page.candidates.len(), 1);
    assert_eq!(
        manager
            .dataplane_page_announcer_visits
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        manager
            .dataplane_page_sibling_visits
            .load(Ordering::Relaxed),
        1
    );
}

#[test]
fn mid_page_and_mid_sibling_cancellation_publish_nothing() {
    let source = peer(0);
    let mut best_manager = manager(true);
    apply_routes(
        &mut best_manager,
        source,
        (0..300)
            .map(|index| route(prefix(index), source, IpAddr::V4(source), &[65001]))
            .collect(),
    );
    let observed = best_manager.route_page_table_version;
    let mut checks = 0usize;
    let result = best_manager.materialize_best_routes_page(None, observed, &mut || {
        checks += 1;
        checks == 2
    });
    assert!(result.is_none(), "partial best page must be dropped");

    let sibling_prefix = prefix(1_000);
    let mut sibling_manager = manager(true);
    for index in 0..300usize {
        let source = peer(index);
        apply_routes(
            &mut sibling_manager,
            source,
            vec![route(sibling_prefix, source, IpAddr::V4(source), &[65001])],
        );
    }
    let observed = sibling_manager.route_page_table_version;
    let mut checks = 0usize;
    let result = sibling_manager.materialize_fib_install_candidates_page(
        None,
        256,
        false,
        false,
        observed,
        &mut || {
            checks += 1;
            checks == 2
        },
    );
    assert!(
        result.is_none(),
        "announcer-walk cancellation drops the page"
    );
    assert_eq!(
        sibling_manager
            .dataplane_page_announcer_visits
            .load(Ordering::Relaxed),
        256
    );
    assert_eq!(
        sibling_manager
            .dataplane_page_sibling_visits
            .load(Ordering::Relaxed),
        0
    );

    sibling_manager
        .dataplane_page_announcer_visits
        .store(0, Ordering::Relaxed);
    sibling_manager
        .dataplane_page_sibling_visits
        .store(0, Ordering::Relaxed);
    let mut checks = 0usize;
    let result = sibling_manager.materialize_fib_install_candidates_page(
        None,
        256,
        false,
        false,
        observed,
        &mut || {
            checks += 1;
            checks == 3
        },
    );
    assert!(result.is_none(), "partial FIB page must be dropped");
    assert_eq!(
        sibling_manager
            .dataplane_page_announcer_visits
            .load(Ordering::Relaxed),
        300
    );
    assert_eq!(
        sibling_manager
            .dataplane_page_sibling_visits
            .load(Ordering::Relaxed),
        256
    );
}

#[tokio::test]
async fn expired_and_preclosed_pages_publish_nothing_then_light_query_runs() {
    let (tx, rx) = mpsc::channel(8);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_eager_dataplane_prefix_index();
    let handle = tokio::spawn(manager.run());

    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutesPage {
        after: None,
        deadline: tokio::time::Instant::now(),
        reply,
    })
    .await
    .unwrap();
    assert!(response.await.is_err());

    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::QueryFibInstallCandidatesPage {
        after: None,
        max_paths: 2,
        relax: false,
        weighted: false,
        deadline: tokio::time::Instant::now(),
        reply,
    })
    .await
    .unwrap();
    assert!(response.await.is_err());

    let (reply, response) = oneshot::channel::<Result<BestRoutesPage, DataplanePageError>>();
    drop(response);
    tx.send(RibUpdate::QueryBestRoutesPage {
        after: None,
        deadline: full_snapshot_query_deadline(),
        reply,
    })
    .await
    .unwrap();
    let (reply, response) =
        oneshot::channel::<Result<FibInstallCandidatesPage, DataplanePageError>>();
    drop(response);
    tx.send(RibUpdate::QueryFibInstallCandidatesPage {
        after: None,
        max_paths: 2,
        relax: false,
        weighted: false,
        deadline: full_snapshot_query_deadline(),
        reply,
    })
    .await
    .unwrap();

    assert_lightweight_query_is_serviced(&tx).await;
    drop(tx);
    handle.await.unwrap();
}

#[test]
fn generation_exhaustion_fails_closed_for_both_page_types() {
    let mut manager = manager(true);
    manager.route_page_table_version = None;
    assert_eq!(
        best_page(&mut manager, None).unwrap_err(),
        DataplanePageError::GenerationExhausted
    );
    assert_eq!(
        fib_page(&mut manager, None, 1, false, false).unwrap_err(),
        DataplanePageError::GenerationExhausted
    );

    manager.route_page_table_version = Some(RoutePageVersion {
        epoch: 7,
        generation: 11,
    });
    assert_eq!(
        best_page(&mut manager, None).unwrap().observed_version,
        RoutePageVersion {
            epoch: 7,
            generation: 11
        }
    );
}
