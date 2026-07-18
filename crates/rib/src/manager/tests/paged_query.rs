//! Bounded, resumable paged route queries (`QueryRoutesPage`): page
//! unions match the single-shot queries across page sizes, filters run
//! inside the actor, and a canceled query (dropped reply receiver)
//! skips the scan entirely.

use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::update::{RoutePage, RouteQueryFilter, RouteQueryKey, RouteQueryScope, route_query_key};

async fn query_page(
    tx: &mpsc::Sender<RibUpdate>,
    scope: RouteQueryScope,
    filter: Option<RouteQueryFilter>,
    after: Option<RouteQueryKey>,
    page_size: usize,
) -> RoutePage {
    query_page_at(tx, scope, filter, after, None, page_size)
        .await
        .unwrap()
}

async fn query_page_at(
    tx: &mpsc::Sender<RibUpdate>,
    scope: RouteQueryScope,
    filter: Option<RouteQueryFilter>,
    after: Option<RouteQueryKey>,
    expected_version: Option<RoutePageVersion>,
    page_size: usize,
) -> Result<RoutePage, RoutePageError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryRoutesPage {
        scope,
        filter,
        after,
        expected_version,
        page_size,
        reply: reply_tx,
    })
    .await
    .unwrap();
    reply_rx.await.unwrap()
}

/// Drive the resumable loop: follow `has_more` + last-key cursors until
/// the listing completes, returning the union of all pages.
async fn collect_pages(
    tx: &mpsc::Sender<RibUpdate>,
    scope: RouteQueryScope,
    page_size: usize,
) -> Vec<Route> {
    let mut out: Vec<Route> = Vec::new();
    let mut after = None;
    let mut expected_version = None;
    loop {
        let page = query_page_at(tx, scope, None, after, expected_version, page_size)
            .await
            .unwrap();
        assert!(
            page.routes.len() <= page_size,
            "page exceeded requested size"
        );
        let has_more = page.has_more;
        expected_version = Some(page.version);
        after = page.routes.last().map(route_query_key);
        out.extend(page.routes);
        if !has_more {
            return out;
        }
    }
}

async fn collect_pages_matching_prefix(
    tx: &mpsc::Sender<RibUpdate>,
    scope: RouteQueryScope,
    page_size: usize,
    wanted: Prefix,
) -> Vec<Route> {
    let mut out = Vec::new();
    let mut after = None;
    let mut expected_version = None;
    let mut reported_total = None;
    loop {
        let page = query_page_at(
            tx,
            scope,
            Some(Box::new(move |route: &Route| route.prefix == wanted)),
            after,
            expected_version,
            page_size,
        )
        .await
        .unwrap();
        assert_eq!(
            *reported_total.get_or_insert(page.total),
            page.total,
            "unchanged fixture must report one cursor-independent total"
        );
        let has_more = page.has_more;
        expected_version = Some(page.version);
        after = page.routes.last().map(route_query_key);
        out.extend(page.routes);
        if !has_more {
            assert_eq!(reported_total, Some(u64::try_from(out.len()).unwrap()));
            return out;
        }
    }
}

fn keys(routes: &[Route]) -> Vec<RouteQueryKey> {
    routes.iter().map(route_query_key).collect()
}

fn sorted_keys(routes: &[Route]) -> Vec<RouteQueryKey> {
    let mut keys = keys(routes);
    keys.sort_unstable();
    keys
}

fn direct_page(
    manager: &mut RibManager,
    scope: RouteQueryScope,
    after: Option<RouteQueryKey>,
    page_size: usize,
) -> RoutePage {
    direct_page_at(manager, scope, after, None, page_size).unwrap()
}

fn direct_page_at(
    manager: &mut RibManager,
    scope: RouteQueryScope,
    after: Option<RouteQueryKey>,
    expected_version: Option<RoutePageVersion>,
    page_size: usize,
) -> Result<RoutePage, RoutePageError> {
    let (reply, mut response) = oneshot::channel();
    manager.handle_query_routes_page_versioned(
        scope,
        None,
        after,
        expected_version,
        page_size,
        reply,
    );
    response
        .try_recv()
        .expect("route page handler replies synchronously")
}

fn direct_advertised_snapshot(manager: &mut RibManager, peer: IpAddr) -> Vec<Route> {
    let (reply, mut response) = oneshot::channel();
    manager.handle_query_advertised_routes(peer, reply);
    response
        .try_recv()
        .expect("advertised snapshot handler replies synchronously")
}

fn peer_up_direct(manager: &mut RibManager, peer: IpAddr) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (outbound_tx, outbound_rx) = mpsc::channel(64);
    manager.handle_update(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    });
    outbound_rx
}

fn receive_direct(
    manager: &mut RibManager,
    peer: IpAddr,
    announced: Vec<Route>,
    withdrawn: Vec<(Prefix, u32)>,
) {
    manager.handle_update(RibUpdate::RoutesReceived {
        peer,
        session_id: 0,
        announced,
        withdrawn,
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    });
    while manager.process_next_route_chunk() {}
}

/// Seed a running manager with 3 peers × 4 prefixes = 12 received routes
/// (4 distinct Loc-RIB bests) and register one outbound target peer, so
/// all three scopes have content.
async fn seeded_manager() -> (
    mpsc::Sender<RibUpdate>,
    IpAddr,
    mpsc::Receiver<OutboundRouteUpdate>,
    tokio::task::JoinHandle<()>,
) {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99));
    let (out_tx, out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer: target,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();

    for peer_octet in 1..=3u8 {
        let peer_addr = Ipv4Addr::new(10, 0, 0, peer_octet);
        let announced = (0..4u8)
            .map(|p| {
                make_route(
                    Ipv4Prefix::new(Ipv4Addr::new(192, 168, p, 0), 24),
                    peer_addr,
                )
            })
            .collect();
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer: IpAddr::V4(peer_addr),
            announced,
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        })
        .await
        .unwrap();
    }

    (tx, target, out_rx, handle)
}

#[tokio::test]
async fn paged_union_matches_single_shot_across_page_sizes() {
    let (tx, target, _out_rx, handle) = seeded_manager().await;

    // Single-shot references for every scope.
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryReceivedRoutes {
        peer: None,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let full_received = reply_rx.await.unwrap();
    assert_eq!(full_received.len(), 12);

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let full_best = reply_rx.await.unwrap();
    assert_eq!(full_best.len(), 4);

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedRoutes {
        peer: target,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let full_advertised = reply_rx.await.unwrap();
    assert_eq!(full_advertised.len(), 4);

    let one_peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryReceivedRoutes {
        peer: Some(one_peer),
        reply: reply_tx,
    })
    .await
    .unwrap();
    let full_one_peer = reply_rx.await.unwrap();
    assert_eq!(full_one_peer.len(), 4);

    for page_size in [1, 2, 3, 5, 100] {
        let scopes: [(RouteQueryScope, &[Route]); 4] = [
            (RouteQueryScope::Received { peer: None }, &full_received),
            (
                RouteQueryScope::Received {
                    peer: Some(one_peer),
                },
                &full_one_peer,
            ),
            (RouteQueryScope::Best, &full_best),
            (
                RouteQueryScope::Advertised { peer: target },
                &full_advertised,
            ),
        ];
        for (scope, full) in scopes {
            let paged = collect_pages(&tx, scope, page_size).await;
            assert_eq!(
                keys(&paged),
                sorted_keys(full),
                "paged union diverged for {scope:?} at page_size {page_size}"
            );
        }
    }

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn paged_query_reports_total_and_has_more() {
    let (tx, _target, _out_rx, handle) = seeded_manager().await;

    let first = query_page(&tx, RouteQueryScope::Received { peer: None }, None, None, 5).await;
    assert_eq!(first.total, 12);
    assert!(first.has_more);
    assert_eq!(first.routes.len(), 5);

    // Resuming from the final key reports completion.
    let all = query_page(
        &tx,
        RouteQueryScope::Received { peer: None },
        None,
        None,
        100,
    )
    .await;
    assert!(!all.has_more);
    let last = query_page_at(
        &tx,
        RouteQueryScope::Received { peer: None },
        None,
        all.routes.last().map(route_query_key),
        Some(all.version),
        100,
    )
    .await
    .unwrap();
    assert!(last.routes.is_empty());
    assert!(!last.has_more);
    assert_eq!(last.total, 12, "total stays cursor-independent");

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn paged_query_filters_inside_the_actor() {
    let (tx, _target, _out_rx, handle) = seeded_manager().await;

    // Keep only one prefix; total and pages both reflect the filter.
    let wanted = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24));
    let mut after = None;
    let mut expected_version = None;
    let mut got = Vec::new();
    loop {
        let page = query_page_at(
            &tx,
            RouteQueryScope::Received { peer: None },
            Some(Box::new(move |route: &Route| route.prefix == wanted)),
            after,
            expected_version,
            2,
        )
        .await
        .unwrap();
        assert_eq!(page.total, 3, "one route per peer matches the filter");
        let has_more = page.has_more;
        expected_version = Some(page.version);
        after = page.routes.last().map(route_query_key);
        got.extend(page.routes);
        if !has_more {
            break;
        }
    }
    assert_eq!(got.len(), 3);
    assert!(got.iter().all(|route| route.prefix == wanted));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn filtered_page_unions_match_authoritative_snapshots_for_every_scope() {
    let (tx, target, _out_rx, handle) = seeded_manager().await;
    let wanted = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24));
    let one_peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let scopes = [
        RouteQueryScope::Received { peer: None },
        RouteQueryScope::Received {
            peer: Some(one_peer),
        },
        RouteQueryScope::Best,
        RouteQueryScope::Advertised { peer: target },
    ];
    for page_size in [1, 2, 1_000, usize::MAX] {
        for scope in scopes {
            let actual = collect_pages_matching_prefix(&tx, scope, page_size, wanted).await;
            assert!(actual.iter().all(|route| route.prefix == wanted));
            assert!(
                actual
                    .windows(2)
                    .all(|rows| { route_query_key(&rows[0]) < route_query_key(&rows[1]) }),
                "filtered {scope:?} page union must stay strictly ordered"
            );
        }
    }

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn empty_scopes_return_a_terminal_zero_total_page() {
    let (tx, _target, _out_rx, handle) = seeded_manager().await;
    let missing = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 250));

    for scope in [
        RouteQueryScope::Received {
            peer: Some(missing),
        },
        RouteQueryScope::Advertised { peer: missing },
    ] {
        for page_size in [0, 1, 1_000, usize::MAX] {
            let page = query_page(&tx, scope, None, None, page_size).await;
            assert!(page.routes.is_empty(), "empty {scope:?}");
            assert_eq!(page.total, 0, "empty {scope:?}");
            assert!(!page.has_more, "empty {scope:?}");
        }
    }

    drop(tx);
    handle.await.unwrap();
}

#[test]
fn page_core_matches_full_sort_for_adversarial_order_filters_and_cursors() {
    let peer_a = Ipv4Addr::new(192, 0, 2, 1);
    let peer_b = Ipv4Addr::new(192, 0, 2, 2);
    let mut routes = Vec::new();
    for last in (0..=63u8).rev() {
        let mut route = make_route(
            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, last), 32),
            if last % 2 == 0 { peer_a } else { peer_b },
        );
        route.path_id = u32::from(last % 3);
        routes.push(route);
    }

    let cursor_cases = [
        None,
        routes.get(48).map(route_query_key),
        Some((
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 31), 32)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)),
            99,
        )),
    ];
    for after in cursor_cases {
        for page_size in [0, 1, 7, 1_000, usize::MAX] {
            for filtered in [false, true] {
                let filter: Option<RouteQueryFilter> = filtered
                    .then(|| Box::new(|route: &Route| route.path_id != 1) as RouteQueryFilter);
                let page = page_routes(routes.iter(), filter.as_ref(), after, page_size);

                let mut authoritative: Vec<_> = routes
                    .iter()
                    .filter(|route| filter.as_ref().is_none_or(|f| f(route)))
                    .cloned()
                    .collect();
                authoritative.sort_unstable_by_key(route_query_key);
                let total = authoritative.len();
                let eligible: Vec<_> = authoritative
                    .into_iter()
                    .filter(|route| after.is_none_or(|cursor| route_query_key(route) > cursor))
                    .collect();
                let cap = page_size.clamp(1, ROUTE_QUERY_MAX_PAGE_SIZE);
                assert_eq!(page.total, u64::try_from(total).unwrap());
                assert_eq!(
                    keys(&page.routes),
                    keys(&eligible[..eligible.len().min(cap)])
                );
                assert_eq!(page.has_more, eligible.len() > cap);
            }
        }
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one differential fixture checks both ordered table implementations across mixed families and Add-Path replacement"
)]
fn ordered_table_indices_match_full_sort_across_add_path_and_replacement() {
    let peer_a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let peer_b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let make = |peer: IpAddr, path_id: u32| {
        let IpAddr::V4(peer) = peer else {
            unreachable!()
        };
        let mut route = make_route(prefix, peer);
        route.path_id = path_id;
        route
    };

    let inserted = vec![
        make(peer_b, 9),
        make(peer_a, 7),
        make(peer_b, 1),
        make(peer_a, 3),
    ];

    let mut inbound = AdjRibIn::new(peer_a);
    for mut route in inserted.clone() {
        route.peer = peer_a;
        inbound.insert(route);
    }
    let mut inbound_expected: Vec<_> = inbound.iter().map(route_query_key).collect();
    inbound_expected.sort_unstable();
    assert_eq!(
        inbound
            .iter_ordered_from(None)
            .map(route_query_key)
            .collect::<Vec<_>>(),
        inbound_expected
    );
    let inbound_cursor = inbound_expected[1];
    assert_eq!(
        inbound
            .iter_ordered_from(Some(inbound_cursor))
            .map(route_query_key)
            .collect::<Vec<_>>(),
        inbound_expected[2..]
    );

    let mut outbound = AdjRibOut::new(peer_a);
    for route in inserted {
        outbound.insert(route);
    }
    let mut outbound_expected: Vec<_> = outbound.iter().map(route_query_key).collect();
    outbound_expected.sort_unstable();
    assert_eq!(
        outbound
            .iter_ordered_from(None)
            .map(route_query_key)
            .collect::<Vec<_>>(),
        outbound_expected
    );
    let replacement = make(peer_a, 9);
    outbound.insert(replacement);
    outbound_expected = outbound.iter().map(route_query_key).collect();
    outbound_expected.sort_unstable();
    assert_eq!(
        outbound
            .iter_ordered_from(None)
            .map(route_query_key)
            .collect::<Vec<_>>(),
        outbound_expected,
        "replacing a path with a different source peer reorders its identity"
    );
    assert!(outbound.withdraw(&Prefix::V4(prefix), 3));
    outbound_expected = outbound.iter().map(route_query_key).collect();
    outbound_expected.sort_unstable();
    assert_eq!(
        outbound
            .iter_ordered_from(None)
            .map(route_query_key)
            .collect::<Vec<_>>(),
        outbound_expected,
        "withdraw removes the ordered-index row"
    );

    let mut loc = LocRib::new();
    let best_a = make(peer_a, 0);
    assert!(loc.recompute(best_a.prefix, std::iter::once(&best_a)));
    assert_eq!(
        loc.iter_ordered_from(None)
            .map(route_query_key)
            .collect::<Vec<_>>(),
        vec![route_query_key(&best_a)]
    );
    let best_b = make(peer_b, 0);
    assert!(loc.recompute(best_b.prefix, std::iter::once(&best_b)));
    assert_eq!(
        loc.iter_ordered_from(None)
            .map(route_query_key)
            .collect::<Vec<_>>(),
        vec![route_query_key(&best_b)],
        "best replacement updates the route body without duplicating the prefix index"
    );
    assert!(loc.recompute(best_b.prefix, std::iter::empty()));
    assert!(loc.iter_ordered_from(None).next().is_none());

    for step in 0..64u32 {
        let mut route = make(if step % 2 == 0 { peer_a } else { peer_b }, step % 5);
        route.prefix = if step % 3 == 0 {
            Prefix::V6(Ipv6Prefix::new(
                format!("2001:db8:{:x}::", step % 7).parse().unwrap(),
                48,
            ))
        } else {
            Prefix::V4(Ipv4Prefix::new(
                Ipv4Addr::new(10, 0, u8::try_from(step % 7).unwrap(), 0),
                24,
            ))
        };
        assert!(loc.recompute(route.prefix, std::iter::once(&route)));
        if step % 5 == 4 {
            assert!(loc.recompute(route.prefix, std::iter::empty()));
        }
        let mut authoritative: Vec<_> = loc.iter().map(route_query_key).collect();
        authoritative.sort_unstable();
        assert_eq!(
            loc.iter_ordered_from(None)
                .map(route_query_key)
                .collect::<Vec<_>>(),
            authoritative,
            "Loc-RIB prefix-index parity after source flip step {step}"
        );
    }
}

/// Ordered keys the Loc-RIB's lazily synced index must produce: the
/// authoritative hash table's keys, fully sorted.
fn loc_rib_sorted_keys(loc: &LocRib) -> Vec<RouteQueryKey> {
    let mut expected: Vec<_> = loc.iter().map(route_query_key).collect();
    expected.sort_unstable();
    expected
}

#[test]
fn loc_rib_ordered_listing_replays_journaled_membership_changes() {
    let peer = Ipv4Addr::new(192, 0, 2, 1);
    let prefix_at = |octet: u8| Ipv4Prefix::new(Ipv4Addr::new(10, 0, octet, 0), 24);
    let route_at = |octet: u8| make_route(prefix_at(octet), peer);

    let mut loc = LocRib::new();
    for octet in 0..5u8 {
        let route = route_at(octet);
        assert!(loc.recompute(route.prefix, std::iter::once(&route)));
    }
    // Force a sync so the later mutations exercise journal replay, not the
    // initial population.
    assert_eq!(
        loc.iter_ordered_from(None)
            .map(route_query_key)
            .collect::<Vec<_>>(),
        loc_rib_sorted_keys(&loc)
    );

    // Without listing in between: remove one prefix, remove-then-readd
    // another (two journal entries resolving to present), add a new one.
    assert!(loc.recompute(Prefix::V4(prefix_at(1)), std::iter::empty()));
    assert!(loc.recompute(Prefix::V4(prefix_at(3)), std::iter::empty()));
    let readded = route_at(3);
    assert!(loc.recompute(readded.prefix, std::iter::once(&readded)));
    let fresh = route_at(9);
    assert!(loc.recompute(fresh.prefix, std::iter::once(&fresh)));

    let listed: Vec<_> = loc.iter_ordered_from(None).map(route_query_key).collect();
    assert_eq!(listed, loc_rib_sorted_keys(&loc));
    assert_eq!(
        listed
            .iter()
            .filter(|(prefix, _, _)| *prefix == Prefix::V4(prefix_at(3)))
            .count(),
        1,
        "removed-then-readded prefix must appear exactly once"
    );
}

#[test]
fn loc_rib_ordered_listing_rebuilds_after_journal_cap_and_resyncs() {
    let peer = Ipv4Addr::new(192, 0, 2, 1);
    let prefix_at = |octet: u8| Ipv4Prefix::new(Ipv4Addr::new(10, 0, octet, 0), 24);
    let route_at = |octet: u8| make_route(prefix_at(octet), peer);

    let mut loc = LocRib::new();
    for octet in 0..4u8 {
        let route = route_at(octet);
        assert!(loc.recompute(route.prefix, std::iter::once(&route)));
    }
    // Flap one prefix's membership past the journal floor (64 entries) with
    // no listing running, tripping the full-rebuild path.
    let flapper = route_at(0);
    for _ in 0..40 {
        assert!(loc.recompute(flapper.prefix, std::iter::empty()));
        assert!(loc.recompute(flapper.prefix, std::iter::once(&flapper)));
    }
    assert_eq!(
        loc.iter_ordered_from(None)
            .map(route_query_key)
            .collect::<Vec<_>>(),
        loc_rib_sorted_keys(&loc)
    );

    // The index must keep tracking mutations after a rebuild consumed the
    // flag: mutate again and list a second time.
    assert!(loc.recompute(Prefix::V4(prefix_at(2)), std::iter::empty()));
    let fresh = route_at(7);
    assert!(loc.recompute(fresh.prefix, std::iter::once(&fresh)));
    assert_eq!(
        loc.iter_ordered_from(None)
            .map(route_query_key)
            .collect::<Vec<_>>(),
        loc_rib_sorted_keys(&loc)
    );
}

#[test]
fn randomized_mixed_family_add_path_continuations_match_full_key_sort() {
    let mut outbound = AdjRibOut::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)));
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for index in 0..512u32 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let mut route = make_route(
            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 32),
            Ipv4Addr::new(192, 0, 2, 1),
        );
        route.prefix = if state & 1 == 0 {
            let len = u8::try_from(8 + ((state >> 8) % 25)).unwrap();
            Prefix::V4(Ipv4Prefix::new(
                Ipv4Addr::from(u32::try_from((state >> 16) & u64::from(u32::MAX)).unwrap()),
                len,
            ))
        } else {
            let len = u8::try_from(16 + ((state >> 8) % 113)).unwrap();
            let high = u128::from(state) << 64;
            let low = u128::from(index).wrapping_mul(0x0001_0001_0001_0001);
            Prefix::V6(Ipv6Prefix::new(Ipv6Addr::from(high | low), len))
        };
        route.peer = if state & 2 == 0 {
            IpAddr::V4(Ipv4Addr::from(
                0xc000_0200u32 | u32::try_from((state >> 32) & 0xff).unwrap(),
            ))
        } else {
            IpAddr::V6(Ipv6Addr::from(
                0x2001_0db8_ffff_0000_0000_0000_0000_0000u128 | u128::from(index % 251),
            ))
        };
        route.path_id = u32::try_from((state >> 40) & 0x0f).unwrap();
        outbound.insert(route);
    }

    let mut authoritative: Vec<_> = outbound.iter().map(route_query_key).collect();
    authoritative.sort_unstable();
    authoritative.dedup();
    assert_eq!(
        outbound
            .iter_ordered_from(None)
            .map(route_query_key)
            .collect::<Vec<_>>(),
        authoritative
    );

    let absent_cursors = [
        (
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(127, 1, 2, 0), 24)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 250)),
            77,
        ),
        (
            Prefix::V6(Ipv6Prefix::new("2001:db8:abcd::".parse().unwrap(), 64)),
            IpAddr::V6("2001:db8::ffff".parse().unwrap()),
            99,
        ),
    ];
    for cursor in authoritative.iter().copied().chain(absent_cursors) {
        let expected: Vec<_> = authoritative
            .iter()
            .copied()
            .filter(|key| *key > cursor)
            .collect();
        let actual: Vec<_> = outbound
            .iter_ordered_from(Some(cursor))
            .map(route_query_key)
            .collect();
        assert_eq!(actual, expected, "cursor {cursor:?}");
    }
}

#[tokio::test]
async fn canceled_paged_query_skips_the_scan() {
    let (tx, _target, _out_rx, handle) = seeded_manager().await;

    // Probe: the filter runs once per scanned route, so zero calls
    // proves the actor skipped the scan for the abandoned query.
    let probe = Arc::new(AtomicUsize::new(0));
    let probe_in_filter = Arc::clone(&probe);
    let (reply_tx, reply_rx) = oneshot::channel();
    drop(reply_rx); // caller gone before the actor dequeues the query
    tx.send(RibUpdate::QueryRoutesPage {
        scope: RouteQueryScope::Received { peer: None },
        filter: Some(Box::new(move |_: &Route| {
            probe_in_filter.fetch_add(1, Ordering::Relaxed);
            true
        })),
        after: None,
        expected_version: None,
        page_size: 100,
        reply: reply_tx,
    })
    .await
    .unwrap();

    // A follow-up live query proves the canceled one was processed
    // (single actor, in-order) and still answers normally.
    let live = query_page(
        &tx,
        RouteQueryScope::Received { peer: None },
        None,
        None,
        100,
    )
    .await;
    assert_eq!(live.routes.len(), 12);
    assert_eq!(
        probe.load(Ordering::Relaxed),
        0,
        "canceled query must not scan any route"
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn paged_query_page_size_is_capped() {
    let (tx, _target, _out_rx, handle) = seeded_manager().await;

    // A zero page size is clamped up to 1 rather than looping forever.
    let page = query_page(&tx, RouteQueryScope::Received { peer: None }, None, None, 0).await;
    assert_eq!(page.routes.len(), 1);
    assert!(page.has_more);

    drop(tx);
    handle.await.unwrap();
}

#[test]
fn grouped_pages_match_snapshot_with_split_horizon_and_exact_rejection() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let target_v4 = Ipv4Addr::new(10, 0, 0, 1);
    let source_v4 = Ipv4Addr::new(192, 0, 2, 100);
    let target = IpAddr::V4(target_v4);
    let sibling = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let source = IpAddr::V4(source_v4);
    let _target_rx = peer_up_direct(&mut manager, target);
    let _sibling_rx = peer_up_direct(&mut manager, sibling);

    let external_base = u32::from(Ipv4Addr::new(203, 0, 0, 0));
    let external_routes: Vec<_> = (0..1_002u32)
        .map(|offset| {
            make_route(
                Ipv4Prefix::new(Ipv4Addr::from(external_base + offset), 32),
                source_v4,
            )
        })
        .collect();
    receive_direct(&mut manager, source, external_routes.clone(), vec![]);
    let own_route = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 1), 32),
        target_v4,
    );
    receive_direct(&mut manager, target, vec![own_route.clone()], vec![]);

    let rejected = &external_routes[500];
    manager
        .peer_unexportable
        .entry(target)
        .or_default()
        .insert(ExactExportKey::Unicast(rejected.prefix, rejected.path_id));
    assert!(
        manager.grouped_member_of(target).is_some(),
        "identical peers share a grouped advertised view"
    );
    let snapshot = direct_advertised_snapshot(&mut manager, target);
    let expected = sorted_keys(&snapshot);
    assert_eq!(expected.len(), 1_001);
    assert!(!expected.contains(&route_query_key(&own_route)));
    assert!(!expected.contains(&route_query_key(rejected)));

    for page_size in [1, 100, 1_000] {
        let mut actual = Vec::new();
        let mut after = None;
        let mut expected_version = None;
        loop {
            let page = direct_page_at(
                &mut manager,
                RouteQueryScope::Advertised { peer: target },
                after,
                expected_version,
                page_size,
            )
            .unwrap();
            assert_eq!(page.total, expected.len() as u64);
            assert!(page.routes.len() <= page_size);
            actual.extend(page.routes.iter().map(route_query_key));
            expected_version = Some(page.version);
            after = page.routes.last().map(route_query_key);
            if !page.has_more {
                break;
            }
        }
        assert_eq!(actual, expected, "grouped page size {page_size}");
    }
}

#[test]
fn grouped_high_exclusion_pages_match_snapshot_and_terminal_empty_view() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let target_v4 = Ipv4Addr::new(10, 0, 0, 1);
    let target = IpAddr::V4(target_v4);
    let sibling = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let external_v4 = Ipv4Addr::new(192, 0, 2, 100);
    let external = IpAddr::V4(external_v4);
    let _target_rx = peer_up_direct(&mut manager, target);
    let _sibling_rx = peer_up_direct(&mut manager, sibling);

    // Put 1,024 target-sourced rows ahead of the sole eligible row. The
    // grouped iterator resumes from its ordered index but must stream past
    // member-local split-horizon exclusions before yielding the page.
    let own_base = u32::from(Ipv4Addr::new(10, 64, 0, 0));
    let own_routes = (0..1_024u32)
        .map(|offset| {
            make_route(
                Ipv4Prefix::new(Ipv4Addr::from(own_base + offset), 32),
                target_v4,
            )
        })
        .collect();
    receive_direct(&mut manager, target, own_routes, vec![]);
    let external_route = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 1), 32),
        external_v4,
    );
    receive_direct(&mut manager, external, vec![external_route.clone()], vec![]);

    let scope = RouteQueryScope::Advertised { peer: target };
    assert_eq!(
        keys(&direct_advertised_snapshot(&mut manager, target)),
        vec![route_query_key(&external_route)]
    );
    let page = direct_page(&mut manager, scope, None, 1);
    assert_eq!(page.total, 1);
    assert_eq!(keys(&page.routes), vec![route_query_key(&external_route)]);
    assert!(!page.has_more);

    // Exact-export rejection leaves a terminal zero-row member view even
    // though the shared group table remains populated by every source row.
    manager
        .peer_unexportable
        .entry(target)
        .or_default()
        .insert(ExactExportKey::Unicast(
            external_route.prefix,
            external_route.path_id,
        ));
    manager.advance_advertised_pages();
    let page = direct_page(&mut manager, scope, None, 1);
    assert_eq!(page.total, 0);
    assert!(page.routes.is_empty());
    assert!(!page.has_more);
}

#[cfg(feature = "bench-internals")]
#[test]
fn benchmark_write_controls_drive_production_chunk_invalidation() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let source = Ipv4Addr::new(192, 0, 2, 1);
    let route = make_route(Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 1), 32), source);
    let versions = |manager: &RibManager| {
        (
            manager.route_page_received_version,
            manager.route_page_best_version,
            manager.route_page_advertised_version,
        )
    };

    let before_seed = versions(&manager);
    manager.bench_seed_loc_rib(vec![route.clone()]);
    assert_ne!(versions(&manager), before_seed);
    assert_eq!(manager.ribs.values().map(AdjRibIn::len).sum::<usize>(), 1);
    assert_eq!(manager.loc_rib.len(), 1);

    let before_churn = versions(&manager);
    manager.bench_churn_loc_rib(vec![route]);
    assert_ne!(versions(&manager), before_churn);
    assert_eq!(manager.ribs.values().map(AdjRibIn::len).sum::<usize>(), 1);
    assert_eq!(manager.loc_rib.len(), 1);
}

#[test]
fn mutation_invalidates_cursor_and_restart_reads_current_table() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = Ipv4Addr::new(192, 0, 2, 1);
    let route = |last_octet| {
        make_route(
            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, last_octet), 32),
            peer,
        )
    };
    receive_direct(
        &mut manager,
        IpAddr::V4(peer),
        [10, 20, 30, 40].into_iter().map(route).collect(),
        vec![],
    );

    let scope = RouteQueryScope::Received {
        peer: Some(IpAddr::V4(peer)),
    };
    let first = direct_page(&mut manager, scope, None, 2);
    assert_eq!(
        keys(&first.routes),
        [route(10), route(20)]
            .iter()
            .map(route_query_key)
            .collect::<Vec<_>>()
    );
    let cursor = first.routes.last().map(route_query_key);
    let version = Some(first.version);

    receive_direct(
        &mut manager,
        IpAddr::V4(peer),
        [15, 35, 50].into_iter().map(route).collect(),
        vec![(route(30).prefix, 0)],
    );

    assert_eq!(
        direct_page_at(&mut manager, scope, cursor, version, 2).unwrap_err(),
        RoutePageError::Invalidated,
        "a changed scope must force an explicit restart"
    );

    let mut restarted = Vec::new();
    let mut after = None;
    let mut expected_version = None;
    loop {
        let page = direct_page_at(&mut manager, scope, after, expected_version, 2).unwrap();
        assert_eq!(page.total, 6, "restart sees the current table");
        restarted.extend(page.routes.iter().map(route_query_key));
        expected_version = Some(page.version);
        after = page.routes.last().map(route_query_key);
        if !page.has_more {
            break;
        }
    }
    let expected: Vec<_> = [10, 15, 20, 35, 40, 50]
        .into_iter()
        .map(route)
        .map(|route| route_query_key(&route))
        .collect();
    assert_eq!(restarted, expected);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one lifecycle scenario preserves the cursor while exercising every required generation invalidation seam"
)]
fn scope_generations_cover_other_peer_group_overlay_and_peer_recreate() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let sibling = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let source_a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let source_b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
    let _target_rx = peer_up_direct(&mut manager, target);
    let _sibling_rx = peer_up_direct(&mut manager, sibling);
    receive_direct(
        &mut manager,
        source_a,
        vec![make_route(
            Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 24),
            source_a.to_string().parse().unwrap(),
        )],
        vec![],
    );

    let received_scope = RouteQueryScope::Received { peer: None };
    let received = direct_page(&mut manager, received_scope, None, 1);
    let received_cursor = received.routes.last().map(route_query_key);
    receive_direct(
        &mut manager,
        source_b,
        vec![make_route(
            Ipv4Prefix::new(Ipv4Addr::new(10, 2, 0, 0), 24),
            source_b.to_string().parse().unwrap(),
        )],
        vec![],
    );
    assert_eq!(
        direct_page_at(
            &mut manager,
            received_scope,
            received_cursor,
            Some(received.version),
            1,
        )
        .unwrap_err(),
        RoutePageError::Invalidated,
        "a different peer mutating Received(all) invalidates the walk"
    );

    let advertised_scope = RouteQueryScope::Advertised { peer: target };
    let advertised = direct_page(&mut manager, advertised_scope, None, 1);
    let advertised_cursor = advertised.routes.last().map(route_query_key);
    receive_direct(
        &mut manager,
        source_b,
        vec![make_route(
            Ipv4Prefix::new(Ipv4Addr::new(10, 3, 0, 0), 24),
            source_b.to_string().parse().unwrap(),
        )],
        vec![],
    );
    assert_eq!(
        direct_page_at(
            &mut manager,
            advertised_scope,
            advertised_cursor,
            Some(advertised.version),
            1,
        )
        .unwrap_err(),
        RoutePageError::Invalidated,
        "a shared group-table mutation invalidates member continuations"
    );

    let advertised = direct_page(&mut manager, advertised_scope, None, 1);
    let advertised_cursor = advertised.routes.last().map(route_query_key);
    let rejected = manager
        .grouped_advertised_routes_iter(target)
        .and_then(|mut routes| routes.next())
        .map(|route| ExactExportKey::Unicast(route.prefix, route.path_id))
        .unwrap();
    manager
        .peer_unexportable
        .entry(target)
        .or_default()
        .insert(rejected);
    manager.advance_advertised_pages();
    assert_eq!(
        direct_page_at(
            &mut manager,
            advertised_scope,
            advertised_cursor,
            Some(advertised.version),
            1,
        )
        .unwrap_err(),
        RoutePageError::Invalidated,
        "member-local rejection-overlay mutation invalidates its walk"
    );

    let advertised = direct_page(&mut manager, advertised_scope, None, 1);
    let old_version = advertised.version;
    manager.handle_update(RibUpdate::PeerDown {
        peer: target,
        session_id: 0,
    });
    let after_delete = direct_page(&mut manager, advertised_scope, None, 1);
    assert_ne!(after_delete.version, old_version);
    let _replacement_rx = peer_up_direct(&mut manager, target);
    let after_recreate = direct_page(&mut manager, advertised_scope, None, 1);
    assert_ne!(after_recreate.version, after_delete.version);

    // PeerUp is usually an outbound-only registration, but a collision-window
    // replacement clears the predecessor session's Adj-RIB-In and Loc-RIB.
    // Its conservative classification must therefore fence all three views.
    receive_direct(
        &mut manager,
        target,
        vec![make_route(
            Ipv4Prefix::new(Ipv4Addr::new(10, 4, 0, 0), 24),
            target.to_string().parse().unwrap(),
        )],
        vec![],
    );
    let received_scope = RouteQueryScope::Received { peer: Some(target) };
    let best_scope = RouteQueryScope::Best;
    let received = direct_page(&mut manager, received_scope, None, 1);
    let best = direct_page(&mut manager, best_scope, None, 1);
    let _collision_replacement_rx = peer_up_direct(&mut manager, target);
    assert_ne!(
        direct_page(&mut manager, received_scope, None, 1).version,
        received.version,
        "replacement PeerUp invalidates the cleared received view"
    );
    assert_ne!(
        direct_page(&mut manager, best_scope, None, 1).version,
        best.version,
        "replacement PeerUp invalidates the recomputed best view"
    );
}

#[test]
fn route_page_generation_rollover_reseeds_then_fails_closed_at_full_exhaustion() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());

    manager.route_page_received_version = Some(RoutePageVersion {
        epoch: 7,
        generation: u64::MAX,
    });
    manager.advance_received_pages();
    assert_eq!(
        manager.route_page_received_version,
        Some(RoutePageVersion {
            epoch: 8,
            generation: 0,
        })
    );

    manager.route_page_received_version = Some(RoutePageVersion {
        epoch: u64::MAX,
        generation: u64::MAX,
    });
    manager.advance_received_pages();
    assert_eq!(manager.route_page_received_version, None);
    assert_eq!(
        direct_page_at(
            &mut manager,
            RouteQueryScope::Received { peer: None },
            None,
            None,
            1,
        )
        .unwrap_err(),
        RoutePageError::GenerationExhausted
    );
}

#[test]
fn timer_driven_gr_sweep_invalidates_received_and_best_continuations() {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let IpAddr::V4(peer_v4) = peer else {
        unreachable!()
    };
    receive_direct(
        &mut manager,
        peer,
        [1, 2]
            .into_iter()
            .map(|octet| {
                make_route(
                    Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, octet), 32),
                    peer_v4,
                )
            })
            .collect(),
        vec![],
    );
    manager.handle_update(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer,
        restart_time: 120,
        stale_routes_time: 120,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    });
    let (outbound_tx, _outbound_rx) = mpsc::channel(8);
    manager.outbound_peers.insert(peer, outbound_tx);

    let received_scope = RouteQueryScope::Received { peer: None };
    let best_scope = RouteQueryScope::Best;
    let received = direct_page(&mut manager, received_scope, None, 1);
    let best = direct_page(&mut manager, best_scope, None, 1);
    assert!(received.has_more && best.has_more);

    // This is the same direct seam invoked by both GR timer arms in `run`;
    // there is no intervening RibUpdate to advance the versions for us.
    manager.sweep_gr_stale(peer);
    assert_eq!(
        direct_page_at(
            &mut manager,
            received_scope,
            received.routes.last().map(route_query_key),
            Some(received.version),
            1,
        )
        .unwrap_err(),
        RoutePageError::Invalidated
    );
    assert_eq!(
        direct_page_at(
            &mut manager,
            best_scope,
            best.routes.last().map(route_query_key),
            Some(best.version),
            1,
        )
        .unwrap_err(),
        RoutePageError::Invalidated
    );
    assert!(manager.ribs.get(&peer).is_none_or(AdjRibIn::is_empty));
    assert!(manager.loc_rib.is_empty());
}

#[test]
fn every_direct_timer_mutation_seam_advances_route_page_versions() {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let family = (Afi::Ipv4, Safi::Unicast);
    let versions = |manager: &RibManager| {
        (
            manager.route_page_received_version,
            manager.route_page_best_version,
            manager.route_page_advertised_version,
        )
    };

    let before = versions(&manager);
    manager.sweep_llgr_stale(peer, &[family]);
    assert_ne!(versions(&manager), before, "LLGR expiry seam");

    manager
        .refresh_in_progress
        .entry(peer)
        .or_default()
        .insert(family);
    let before = versions(&manager);
    manager.finish_route_refresh(peer, family.0, family.1, true);
    assert_ne!(versions(&manager), before, "refresh-timeout seam");

    let before = versions(&manager);
    manager.release_selection_families(&[family], "test timer expiry");
    assert_ne!(versions(&manager), before, "selection-release seam");
}

/// A shared clean export-policy transition commits its group-membership and
/// export-overlay flips in `Finalize`, which does not always reach the
/// distribution-pass fence (no dirty or forced peers). General queries stay
/// queued while the transition owns the actor, so fencing at command
/// acceptance covers the whole transaction, including the fallback handoff.
#[test]
fn accepting_a_shared_policy_transition_invalidates_advertised_continuations() {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let before = manager.route_page_advertised_version;
    let (reply, _response) = oneshot::channel();
    manager.handle_update(RibUpdate::ReplacePeerExportPolicies {
        replacements: vec![crate::update::PeerExportPolicyReplacement {
            peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            export_policy: None,
        }],
        reply,
    });
    assert_ne!(
        manager.route_page_advertised_version, before,
        "cohort export-policy replacement must fence advertised continuations at acceptance"
    );
}
