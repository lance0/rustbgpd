use std::future::Future;
use std::task::{Context, Waker};

use super::*;

fn timer_manager(rx: mpsc::Receiver<RibUpdate>, query_rx: mpsc::Receiver<RibUpdate>) -> RibManager {
    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let mut manager = RibManager::new(rx, query_rx, None, None, BgpMetrics::new())
        .with_selection_deferral(crate::SelectionDeferralConfig {
            timeout: Duration::from_secs(1),
            waiters: vec![crate::SelectionDeferralWaiterConfig {
                peer: source,
                // The timer exercises the shared drain, while IPv4 ingest
                // remains selected and observable by count/page queries.
                families: vec![(Afi::Ipv6, Safi::Unicast)],
            }],
        });
    manager.ribs.insert(source, AdjRibIn::new(source));
    manager
}

fn routes(peer: Ipv4Addr, first: usize, count: usize) -> RibUpdate {
    RibUpdate::RoutesReceived {
        peer: IpAddr::V4(peer),
        session_id: 0,
        announced: (first..first + count)
            .map(|index| {
                make_route(
                    Ipv4Prefix::new(
                        Ipv4Addr::from(0xC000_0000 + u32::try_from(index).unwrap()),
                        32,
                    ),
                    peer,
                )
            })
            .collect(),
        withdrawn: Vec::new(),
        flowspec_announced: Vec::new(),
        flowspec_withdrawn: Vec::new(),
        evpn_announced: Vec::new(),
        evpn_withdrawn: Vec::new(),
    }
}

async fn assert_timer_drain_yields_before_backlog_is_empty(pending_chunk: bool) {
    let source = Ipv4Addr::new(10, 0, 0, 1);
    let (tx, rx) = mpsc::channel(8);
    let (query_tx, query_rx) = mpsc::channel(8);
    let (readiness_tx, readiness_rx) = mpsc::channel(8);
    let (summary_tx, summary_rx) = mpsc::channel(8);
    let mut manager = timer_manager(rx, query_rx)
        .with_readiness_queries(readiness_rx)
        .with_summary_queries(summary_rx);
    let total = 3 * ROUTES_RECEIVED_CHUNK_SIZE;
    if pending_chunk {
        manager.handle_update(routes(source, 0, total));
    } else {
        tx.try_send(routes(source, 0, total)).unwrap();
    }
    // A later primary message must stay behind every chunk of the batch.
    let (barrier, mut barrier_response) = oneshot::channel();
    tx.try_send(RibUpdate::QueryLocRibCount { reply: barrier })
        .unwrap();
    let (query, mut query_response) = oneshot::channel();
    query_tx
        .try_send(RibUpdate::QueryLocRibCount { reply: query })
        .unwrap();
    let (reply, mut summary_response) = oneshot::channel();
    summary_tx
        .try_send(crate::update::RibSummaryQuery::ExportPolicyTermHits { peer: None, reply })
        .unwrap();
    let (readiness, mut readiness_response) = oneshot::channel();
    readiness_tx
        .try_send(RibReadinessQuery::LocRibCount {
            reply: readiness,
            enqueued: Instant::now(),
        })
        .unwrap();

    tokio::time::advance(Duration::from_secs(1)).await;
    let mut actor = Box::pin(manager.run());
    // Poll the real event loop once: a genuine executor yield is required,
    // independently of how fast this machine handles the queued work.
    assert!(
        actor
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    let observed = query_response
        .try_recv()
        .expect("general read must be served at the first drain seam");
    assert!(
        observed < total,
        "general read waited for the whole ingest backlog: {observed}/{total}"
    );
    assert!(readiness_response.try_recv().unwrap().unwrap() < total);
    assert!(
        summary_response
            .try_recv()
            .expect("typed summary must be served at the first drain seam")
            .is_empty()
    );
    assert!(
        matches!(
            barrier_response.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ),
        "one actor poll consumed a later primary message before yielding"
    );
    assert!(
        tx.capacity() < tx.max_capacity(),
        "primary backlog must remain at the yield"
    );

    let handle = tokio::spawn(actor);
    assert_eq!(barrier_response.await.unwrap(), total);
    drop(tx);
    handle.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn timer_drain_yields_between_already_deferred_route_chunks() {
    assert_timer_drain_yields_before_backlog_is_empty(true).await;
}

#[tokio::test(start_paused = true)]
async fn timer_drain_yields_between_queued_primary_updates() {
    assert_timer_drain_yields_before_backlog_is_empty(false).await;
}

#[tokio::test(start_paused = true)]
async fn timer_drain_invalidates_a_page_before_the_next_route_chunk() {
    let source = Ipv4Addr::new(10, 0, 0, 1);
    let (tx, rx) = mpsc::channel(8);
    let (query_tx, query_rx) = mpsc::channel(8);
    let mut manager = timer_manager(rx, query_rx);
    manager.handle_update(routes(source, 0, 3 * ROUTES_RECEIVED_CHUNK_SIZE));
    let (reply, mut response) = oneshot::channel();
    query_tx
        .try_send(RibUpdate::QueryRoutesPage {
            scope: RouteQueryScope::Best,
            filter: None,
            after: None,
            expected_version: None,
            page_size: 1,
            reply,
        })
        .unwrap();
    tokio::time::advance(Duration::from_secs(1)).await;
    let mut actor = Box::pin(manager.run());
    assert!(
        actor
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    let page = response.try_recv().unwrap().unwrap();
    assert_eq!(
        page.total,
        u64::try_from(ROUTES_RECEIVED_CHUNK_SIZE).unwrap()
    );
    assert!(page.has_more);
    let (reply, mut continuation) = oneshot::channel();
    query_tx
        .try_send(RibUpdate::QueryRoutesPage {
            scope: RouteQueryScope::Best,
            filter: None,
            after: page.routes.last().map(route_query_key),
            expected_version: Some(page.version),
            page_size: 1,
            reply,
        })
        .unwrap();
    assert!(
        actor
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert!(matches!(
        continuation.try_recv().unwrap(),
        Err(RoutePageError::Invalidated)
    ));
    drop(tx);
    actor.await;
}

#[tokio::test(start_paused = true)]
async fn timer_drain_preserves_newly_accepted_policy_transition_fence() {
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let (tx, rx) = mpsc::channel(8);
    let (query_tx, query_rx) = mpsc::channel(8);
    let (readiness_tx, readiness_rx) = mpsc::channel(8);
    let (summary_tx, summary_rx) = mpsc::channel(8);
    let mut manager = timer_manager(rx, query_rx)
        .with_readiness_queries(readiness_rx)
        .with_summary_queries(summary_rx);
    let (outbound_tx, _outbound_rx) = mpsc::channel(8);
    manager.outbound_peers.insert(peer, outbound_tx);
    let (reply, mut transition) = oneshot::channel();
    tx.try_send(RibUpdate::ReplacePeerExportPolicies {
        replacements: vec![crate::update::PeerExportPolicyReplacement {
            peer,
            export_policy: None,
        }],
        reply,
    })
    .unwrap();
    let (reply, mut primary) = oneshot::channel();
    tx.try_send(RibUpdate::QueryLocRibCount { reply }).unwrap();
    let (reply, mut query) = oneshot::channel();
    query_tx
        .try_send(RibUpdate::QueryLocRibCount { reply })
        .unwrap();
    let (reply, mut summary) = oneshot::channel();
    summary_tx
        .try_send(crate::update::RibSummaryQuery::ExportPolicyTermHits { peer: None, reply })
        .unwrap();
    let (reply, mut readiness) = oneshot::channel();
    readiness_tx
        .try_send(RibReadinessQuery::LocRibCount {
            reply,
            enqueued: Instant::now(),
        })
        .unwrap();
    tokio::time::advance(Duration::from_secs(1)).await;
    let mut actor = Box::pin(manager.run());
    assert!(
        actor
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert_eq!(readiness.try_recv().unwrap().unwrap(), 0);
    assert!(matches!(
        query.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert!(matches!(
        summary.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert!(matches!(
        primary.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert!(matches!(
        transition.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    let handle = tokio::spawn(actor);
    assert_eq!(query.await.unwrap(), 0);
    assert!(summary.await.unwrap().is_empty());
    let _outcome = transition.await.unwrap();
    assert_eq!(primary.await.unwrap(), 0);
    drop(tx);
    handle.await.unwrap();
}
