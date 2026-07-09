//! Bounded, resumable paged route queries (`QueryRoutesPage`): page
//! unions match the single-shot queries across page sizes, filters run
//! inside the actor, and a canceled query (dropped reply receiver)
//! skips the scan entirely.

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
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryRoutesPage {
        scope,
        filter,
        after,
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
    loop {
        let page = query_page(tx, scope, None, after, page_size).await;
        assert!(
            page.routes.len() <= page_size,
            "page exceeded requested size"
        );
        let has_more = page.has_more;
        after = page.routes.last().map(route_query_key);
        out.extend(page.routes);
        if !has_more {
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
    let last = query_page(
        &tx,
        RouteQueryScope::Received { peer: None },
        None,
        all.routes.last().map(route_query_key),
        100,
    )
    .await;
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
    let mut got = Vec::new();
    loop {
        let page = query_page(
            &tx,
            RouteQueryScope::Received { peer: None },
            Some(Box::new(move |route: &Route| route.prefix == wanted)),
            after,
            2,
        )
        .await;
        assert_eq!(page.total, 3, "one route per peer matches the filter");
        let has_more = page.has_more;
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
