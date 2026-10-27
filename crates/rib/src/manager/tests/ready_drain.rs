use crate::test_support::peer_v4;
use std::future::Future;
use std::task::{Context, Waker};

use super::*;

fn timer_manager(rx: mpsc::Receiver<RibUpdate>, query_rx: mpsc::Receiver<RibUpdate>) -> RibManager {
    let source = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
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
        peer: peer_v4(peer),
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
        validated_with: None,
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
        .try_send(crate::update::RibSummaryQuery::NeighborRibSnapshots {
            peers: Vec::new(),
            comparison: None,
            reply,
            include_retained: false,
        })
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
    assert_eq!(
        summary_response
            .try_recv()
            .expect("typed summary must be served at the first drain seam")
            .snapshots
            .len(),
        0
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
    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
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
        .try_send(crate::update::RibSummaryQuery::NeighborRibSnapshots {
            peers: Vec::new(),
            comparison: None,
            reply,
            include_retained: false,
        })
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
    assert_eq!(summary.await.unwrap().snapshots.len(), 0);
    let _outcome = transition.await.unwrap();
    assert_eq!(primary.await.unwrap(), 0);
    drop(tx);
    handle.await.unwrap();
}

/// The ordinary event loop bounds one actor poll by the flush budget, as the
/// timer drain bounds its units. Draining a deep backlog inside one poll, up
/// to Tokio's whole cooperative budget, holds the worker: a task woken
/// meanwhile, such as a readiness probe answered mid-backlog, waits behind the
/// rest of that poll. Within the budget, updates still apply back to back.
async fn applied_in_one_poll(armed_timer: bool, budget: Duration) -> usize {
    const QUEUED: usize = 16;
    let (tx, rx) = mpsc::channel(QUEUED);
    // An armed (not yet due) timer selects the loop's timer-aware wait.
    let mut manager = if armed_timer {
        timer_manager(rx, dummy_query_rx())
    } else {
        RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
    };
    manager.flush_poll_budget = budget;
    let mut responses = Vec::new();
    for _ in 0..QUEUED {
        let (reply, response) = oneshot::channel();
        tx.try_send(RibUpdate::QueryLocRibCount { reply }).unwrap();
        responses.push(response);
    }
    let mut actor = Box::pin(manager.run());
    assert!(
        actor
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    let answered = responses
        .iter_mut()
        .flat_map(oneshot::Receiver::try_recv)
        .count();
    drop(tx);
    actor.await;
    let rest = responses
        .iter_mut()
        .flat_map(oneshot::Receiver::try_recv)
        .count();
    assert_eq!(answered + rest, QUEUED);
    answered
}

#[tokio::test(start_paused = true)]
async fn event_loop_yields_once_the_poll_budget_is_spent() {
    assert_eq!(applied_in_one_poll(false, Duration::ZERO).await, 1);
}

#[tokio::test(start_paused = true)]
async fn timer_wait_yields_once_the_poll_budget_is_spent() {
    assert_eq!(applied_in_one_poll(true, Duration::ZERO).await, 1);
}

#[tokio::test(start_paused = true)]
async fn event_loop_batches_primary_updates_within_the_poll_budget() {
    assert_eq!(
        applied_in_one_poll(false, Duration::from_secs(3600)).await,
        16
    );
}

#[expect(
    clippy::too_many_lines,
    reason = "one actor transcript pins readiness before injection acknowledgement and ordinary reads after it"
)]
async fn assert_injected_unicast_readiness_during_deferral(leased: bool) {
    let (tx, rx) = mpsc::channel(8);
    let (query_tx, query_rx) = mpsc::channel(8);
    let (readiness_tx, readiness_rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, query_rx, None, None, BgpMetrics::new())
        .with_readiness_queries(readiness_rx)
        .with_selection_deferral(crate::SelectionDeferralConfig {
            timeout: Duration::from_mins(2),
            waiters: vec![crate::SelectionDeferralWaiterConfig {
                peer: peer_v4(Ipv4Addr::new(192, 0, 2, 1)),
                families: vec![(Afi::Ipv4, Safi::Unicast)],
            }],
        });
    manager.flush_poll_budget = Duration::ZERO;
    let (entered_tx, mut entered_rx) = mpsc::unbounded_channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let release_rx = std::sync::Mutex::new(release_rx);
    let calls = std::sync::atomic::AtomicUsize::new(0);
    manager.replacement_readiness_test_hook = Some(Arc::new(move |stage| {
        if stage != "selection_candidates" {
            return;
        }
        let call = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if call < 2 {
            entered_tx.send(call).unwrap();
            release_rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(10))
                .unwrap();
        }
    }));
    let actor = tokio::spawn(manager.run());
    let injected_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 17), 32);
    let mut route = make_route(injected_prefix, Ipv4Addr::UNSPECIFIED);
    route.peer = LOCAL_PEER;
    route.origin_type = crate::route::RouteOrigin::Local;
    route.path_id = 17;
    route.attributes = AttrSet::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        PathAttribute::NextHop(Ipv4Addr::UNSPECIFIED),
        PathAttribute::Communities(vec![0xFFFF_029A]),
    ]);
    let injection_tx = tx.clone();
    let mut injection = tokio::spawn(async move {
        if leased {
            let (reply, response) = oneshot::channel();
            injection_tx
                .send(RibUpdate::InjectLeasedRoute {
                    route,
                    owner: "readiness".to_string(),
                    lease_seconds: 30,
                    reply,
                })
                .await
                .unwrap();
            response.await.unwrap().map(|(outcome, _)| outcome)
        } else {
            let (reply, response) = oneshot::channel();
            injection_tx
                .send(RibUpdate::InjectRoute { route, reply })
                .await
                .unwrap();
            response.await.unwrap()
        }
    });

    let entered = tokio::select! {
        entry = entered_rx.recv() => entry,
        outcome = &mut injection => {
            panic!("injection completed without entering selection readiness: {outcome:?}");
        }
    };
    assert_eq!(entered, Some(0));
    let (reply, mut readiness) = oneshot::channel();
    readiness_tx
        .try_send(RibReadinessQuery::LocRibCount {
            reply,
            enqueued: Instant::now(),
        })
        .unwrap();
    let (reply, mut ordinary) = oneshot::channel();
    query_tx
        .try_send(RibUpdate::QueryLocRibCount { reply })
        .unwrap();
    release_tx.send(()).unwrap();
    let entered = tokio::select! {
        entry = entered_rx.recv() => entry,
        outcome = &mut injection => {
            panic!("injection completed without entering its next selection checkpoint: {outcome:?}");
        }
    };
    assert_eq!(entered, Some(1));
    let observed = readiness.try_recv();
    let ordinary_waited = matches!(
        ordinary.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    );
    let injection_waited = !injection.is_finished();
    release_tx.send(()).unwrap();
    assert_eq!(
        observed,
        Ok(Ok(0)),
        "readiness must answer before selection mutates the count"
    );
    assert!(
        ordinary_waited,
        "ordinary reads must remain behind the injection"
    );
    assert!(
        injection_waited,
        "readiness must answer before the injection acknowledgement"
    );
    assert_eq!(
        injection.await.unwrap().unwrap(),
        crate::update::InjectOutcome::Created
    );
    assert_eq!(ordinary.await.unwrap(), 1);

    let (reply, response) = oneshot::channel();
    readiness_tx
        .send(RibReadinessQuery::LocRibCount {
            reply,
            enqueued: Instant::now(),
        })
        .await
        .unwrap();
    assert_eq!(response.await.unwrap().unwrap(), 1);
    let retained = query_received_routes(&tx, LOCAL_PEER).await;
    assert_eq!(retained.len(), 1);
    assert_eq!(
        (retained[0].prefix, retained[0].path_id),
        (Prefix::V4(injected_prefix), 17)
    );
    assert!(!retained[0].is_stale && !retained[0].is_llgr_stale);
    drop(tx);
    drop(query_tx);
    drop(readiness_tx);
    actor.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn injected_unicast_keeps_answering_readiness_during_selection_deferral() {
    assert_injected_unicast_readiness_during_deferral(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn leased_unicast_keeps_answering_readiness_during_selection_deferral() {
    assert_injected_unicast_readiness_during_deferral(true).await;
}
