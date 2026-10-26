use super::*;
use crate::PeerId;
use crate::manager::distribution::OutboundCommitBatch;
use crate::test_support::peer_v4;

#[cfg(target_pointer_width = "64")]
#[test]
fn event_storage_layout_and_lazy_history_capacity_are_pinned() {
    use std::mem::size_of;

    // Events name peers by the address they had when the event was built
    // (17 B each), not by a handle whose endpoint can move.
    assert_eq!(size_of::<crate::event::RouteEvent>(), 120);
    // SMET widens the Copy key from 36 to 64 B while the full route stays
    // 68 B; the millisecond `i64` event time replaced a 24 B `String`; the
    // two routes' peer handles are 8 B where addresses were 17 B, and the
    // event's own two peers are event-time addresses.
    // Their frozen interface Arcs add 32 B, independently of handle reuse.
    // Neither Arc slots nor the lazy history's initial capacity grow.
    assert_eq!(size_of::<crate::event::EvpnRouteEvent>(), 432);
    assert_eq!(size_of::<Arc<crate::event::RouteEvent>>(), 8);
    assert_eq!(size_of::<Arc<crate::event::EvpnRouteEvent>>(), 8);

    let (_tx, rx) = mpsc::channel(1);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    assert_eq!(manager.route_event_history.capacity(), 0);
    assert_eq!(manager.evpn_route_event_history.capacity(), 0);
}

#[tokio::test]
async fn route_history_and_live_broadcast_share_arc_but_queries_are_owned() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let mut live = manager.route_events_tx.subscribe();
    manager.publish_route_event(crate::event::RouteEvent {
        event_id: 0,
        event_type: RouteEventType::Added,
        prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24)),
        peer: None,
        previous_peer: None,
        target_peer: None,
        peer_scope: crate::route::AspaContextId::DEFAULT,
        previous_peer_scope: crate::route::AspaContextId::DEFAULT,
        target_peer_scope: crate::route::AspaContextId::DEFAULT,
        timestamp_unix_ms: 1_000,
        path_id: 0,
        reason: "original".to_string(),
    });

    let broadcast = live.try_recv().unwrap();
    assert!(Arc::ptr_eq(
        manager.route_event_history.back().unwrap(),
        &broadcast
    ));

    let (reply, result) = oneshot::channel();
    manager.handle_query_route_event_history(None, None, None, 0, reply);
    let mut owned = result.await.unwrap();
    owned[0].reason = "caller mutation".to_string();
    assert_eq!(
        manager.route_event_history.back().unwrap().reason,
        "original"
    );
}

async fn subscribe_events(
    tx: &mpsc::Sender<RibUpdate>,
) -> tokio::sync::broadcast::Receiver<Arc<crate::event::RouteEvent>> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::SubscribeRouteEvents { reply: reply_tx })
        .await
        .unwrap();
    reply_rx.await.unwrap()
}

#[test]
fn route_event_id_exhaustion_saturates_instead_of_panicking() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.next_route_event_id = u64::MAX;

    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24));
    for _ in 0..2 {
        manager.publish_route_event(crate::event::RouteEvent {
            event_id: 0,
            event_type: RouteEventType::Added,
            prefix,
            peer: None,
            previous_peer: None,
            target_peer: None,
            peer_scope: crate::route::AspaContextId::DEFAULT,
            previous_peer_scope: crate::route::AspaContextId::DEFAULT,
            target_peer_scope: crate::route::AspaContextId::DEFAULT,
            timestamp_unix_ms: 0,
            path_id: 0,
            reason: String::new(),
        });
    }

    assert_eq!(manager.route_event_history.len(), 2);
    assert!(manager.route_event_id_exhausted);
    assert!(
        manager
            .route_event_history
            .iter()
            .all(|event| event.event_id == u64::MAX)
    );
    assert_eq!(
        manager.next_route_event_id,
        u64::MAX,
        "saturated id should remain stable after exhaustion"
    );
}

#[tokio::test]
async fn route_event_added_on_new_best() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let mut events_rx = subscribe_events(&tx).await;

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    let event = events_rx.recv().await.unwrap();
    assert_eq!(event.event_id, 1);
    assert_eq!(event.event_type, crate::event::RouteEventType::Added);
    assert_eq!(event.prefix, Prefix::V4(prefix));
    assert_eq!(event.peer, Some(peer.addr()));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_history_records_events_without_subscriber() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    let history = query_route_event_history(&tx, None, Some(Afi::Ipv4), None, 100).await;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].event_id, 1);
    assert_eq!(history[0].event_type, crate::event::RouteEventType::Added);
    assert_eq!(history[0].prefix, Prefix::V4(prefix));
    assert_eq!(history[0].peer, Some(peer.addr()));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_history_empty_query_returns_empty_vec() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let history = query_route_event_history(&tx, None, None, None, 0).await;
    assert!(history.is_empty());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_history_records_withdrawn_events() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![],
        withdrawn: vec![(Prefix::V4(prefix), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    let history = query_route_event_history(&tx, None, Some(Afi::Ipv4), None, 10).await;
    assert_eq!(history.len(), 2);
    assert_eq!(
        history[1].event_type,
        crate::event::RouteEventType::Withdrawn
    );
    assert_eq!(history[1].prefix, Prefix::V4(prefix));
    assert_eq!(history[1].peer, None);
    assert_eq!(history[1].previous_peer, Some(peer.addr()));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_history_filters_previous_peer_and_limit() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let peer1 = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = peer_v4(Ipv4Addr::new(10, 0, 0, 2));

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![
            make_route_with_lp(prefix1, Ipv4Addr::new(10, 0, 0, 1), 100),
            make_route(prefix2, Ipv4Addr::new(10, 0, 0, 1)),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer2,
        announced: vec![make_route_with_lp(prefix1, Ipv4Addr::new(10, 0, 0, 2), 200)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    let history = query_route_event_history(&tx, Some(peer1), Some(Afi::Ipv4), None, 2).await;
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].event_id, 2);
    assert_eq!(history[0].event_type, crate::event::RouteEventType::Added);
    assert!(matches!(history[0].prefix, Prefix::V4(_)));
    assert_eq!(history[0].peer, Some(peer1.addr()));
    assert_eq!(
        history[1].event_type,
        crate::event::RouteEventType::BestChanged
    );
    assert_eq!(history[1].event_id, 3);
    assert_eq!(history[1].prefix, Prefix::V4(prefix1));
    assert_eq!(history[1].peer, Some(peer2.addr()));
    assert_eq!(history[1].previous_peer, Some(peer1.addr()));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_history_filters_exact_ipv4_prefix() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let target = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let other = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);

    for prefix in [other, target] {
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
        })
        .await
        .unwrap();
    }

    let history = query_route_event_history(&tx, None, None, Some(Prefix::V4(target)), 10).await;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].prefix, Prefix::V4(target));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_history_filters_exact_ipv6_prefix() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = PeerId::from_addr(IpAddr::V6(Ipv6Addr::LOCALHOST));
    let target = Ipv6Prefix::new("2001:db8:100::".parse().unwrap(), 64);
    let other = Ipv6Prefix::new("2001:db8:200::".parse().unwrap(), 64);

    for prefix in [other, target] {
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer,
            announced: vec![make_v6_route(prefix, Ipv6Addr::LOCALHOST)],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
        })
        .await
        .unwrap();
    }

    let history = query_route_event_history(&tx, None, None, Some(Prefix::V6(target)), 10).await;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].prefix, Prefix::V6(target));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_history_prefix_peer_and_limit_interact() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let target = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let other = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let peer1 = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = peer_v4(Ipv4Addr::new(10, 0, 0, 2));

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![make_route_with_lp(target, Ipv4Addr::new(10, 0, 0, 1), 100)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![make_route(other, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer2,
        announced: vec![make_route_with_lp(target, Ipv4Addr::new(10, 0, 0, 2), 200)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer2,
        announced: vec![],
        withdrawn: vec![(Prefix::V4(target), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    let history = query_route_event_history(
        &tx,
        Some(peer1),
        Some(Afi::Ipv4),
        Some(Prefix::V4(target)),
        2,
    )
    .await;
    assert_eq!(history.len(), 2);
    assert_eq!(
        history[0].event_type,
        crate::event::RouteEventType::BestChanged
    );
    assert_eq!(history[0].peer, Some(peer2.addr()));
    assert_eq!(history[0].previous_peer, Some(peer1.addr()));
    assert_eq!(
        history[1].event_type,
        crate::event::RouteEventType::BestChanged
    );
    assert_eq!(history[1].peer, Some(peer1.addr()));
    assert_eq!(history[1].previous_peer, Some(peer2.addr()));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_history_prefix_filter_no_matches_returns_empty() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let observed = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let missing = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![make_route(observed, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    let history = query_route_event_history(&tx, None, None, Some(Prefix::V4(missing)), 10).await;
    assert!(history.is_empty());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_history_filters_ipv6_and_preserves_limited_order() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let v4_prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let v6_prefix = Ipv6Prefix::new("2001:db8:100::".parse().unwrap(), 64);
    let v4_prefix2 = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![make_route(v4_prefix1, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: PeerId::from_addr(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        announced: vec![make_v6_route(v6_prefix, Ipv6Addr::LOCALHOST)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![make_route(v4_prefix2, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    let v6_history = query_route_event_history(&tx, None, Some(Afi::Ipv6), None, 10).await;
    assert_eq!(v6_history.len(), 1);
    assert_eq!(v6_history[0].prefix, Prefix::V6(v6_prefix));

    let recent_two = query_route_event_history(&tx, None, None, None, 2).await;
    assert_eq!(recent_two.len(), 2);
    assert_eq!(recent_two[0].prefix, Prefix::V6(v6_prefix));
    assert_eq!(recent_two[1].prefix, Prefix::V4(v4_prefix2));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_history_limit_zero_returns_all_available() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 1), 32);
    let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 2), 32);
    for prefix in [prefix1, prefix2] {
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
        })
        .await
        .unwrap();
    }

    let history = query_route_event_history(&tx, None, None, None, 0).await;
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].prefix, Prefix::V4(prefix1));
    assert_eq!(history[1].prefix, Prefix::V4(prefix2));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_history_capacity_evicts_oldest_event() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    for index in 0..=ROUTE_EVENT_HISTORY_CAPACITY {
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer,
            announced: vec![make_indexed_route(
                u32::try_from(index).unwrap(),
                Ipv4Addr::new(10, 0, 0, 1),
            )],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
        })
        .await
        .unwrap();
    }

    let history = query_route_event_history(&tx, None, Some(Afi::Ipv4), None, 0).await;
    assert_eq!(history.len(), ROUTE_EVENT_HISTORY_CAPACITY);
    assert_eq!(history[0].event_id, 2);
    assert_eq!(
        history[0].prefix,
        make_indexed_route(1, Ipv4Addr::new(10, 0, 0, 1)).prefix
    );
    assert_eq!(
        history[ROUTE_EVENT_HISTORY_CAPACITY - 1].event_id,
        u64::try_from(ROUTE_EVENT_HISTORY_CAPACITY + 1).unwrap()
    );
    assert_eq!(
        history[ROUTE_EVENT_HISTORY_CAPACITY - 1].prefix,
        make_indexed_route(
            u32::try_from(ROUTE_EVENT_HISTORY_CAPACITY).unwrap(),
            Ipv4Addr::new(10, 0, 0, 1)
        )
        .prefix
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
#[expect(
    clippy::cast_possible_truncation,
    reason = "test fixture counts are small and cast only for gauge comparison"
)]
async fn route_event_history_gauges_track_depth_and_capacity() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let capacity = metrics
        .registry()
        .gather()
        .iter()
        .find(|family| family.name() == "bgp_route_event_history_capacity")
        .expect("capacity gauge registered")
        .get_metric()[0]
        .get_gauge()
        .get_value();
    assert_eq!(
        capacity as i64,
        i64::try_from(ROUTE_EVENT_HISTORY_CAPACITY).unwrap()
    );

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    for index in 0..3 {
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer,
            announced: vec![make_indexed_route(index, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
        })
        .await
        .unwrap();
    }

    let _ = query_route_event_history(&tx, None, Some(Afi::Ipv4), None, 0).await;

    let depth = metrics
        .registry()
        .gather()
        .iter()
        .find(|family| family.name() == "bgp_route_event_history_depth")
        .expect("depth gauge registered")
        .get_metric()[0]
        .get_gauge()
        .get_value();
    assert_eq!(depth as i64, 3);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_withdrawn_on_last_removed() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    // Subscribe after route is added
    let mut events_rx = subscribe_events(&tx).await;

    // Withdraw the route
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![],
        withdrawn: vec![(Prefix::V4(prefix), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    let event = events_rx.recv().await.unwrap();
    assert_eq!(event.event_type, crate::event::RouteEventType::Withdrawn);
    assert_eq!(event.prefix, Prefix::V4(prefix));
    assert!(event.peer.is_none());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_best_changed_on_better_path() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let peer1 = peer_v4(Ipv4Addr::new(1, 0, 0, 1));
    let peer2 = peer_v4(Ipv4Addr::new(1, 0, 0, 2));

    // Peer1 announces first
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 1), 100)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    // Subscribe after first route is installed
    let mut events_rx = subscribe_events(&tx).await;

    // Peer2 announces with higher local-pref — best changes
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer2,
        announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 2), 200)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    let event = events_rx.recv().await.unwrap();
    assert_eq!(event.event_type, crate::event::RouteEventType::BestChanged);
    assert_eq!(event.prefix, Prefix::V4(prefix));
    assert_eq!(event.peer, Some(peer2.addr()));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn multiple_subscribers_receive_same_events() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let mut sub1 = subscribe_events(&tx).await;
    let mut sub2 = subscribe_events(&tx).await;

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    let e1 = sub1.recv().await.unwrap();
    let e2 = sub2.recv().await.unwrap();
    assert_eq!(e1.prefix, Prefix::V4(prefix));
    assert_eq!(e2.prefix, Prefix::V4(prefix));
    assert_eq!(e1.event_type, e2.event_type);

    drop(tx);
    handle.await.unwrap();
}

// --- Route event shape tests ---

#[tokio::test]
async fn route_event_withdrawn_carries_previous_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    let mut events_rx = subscribe_events(&tx).await;

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![],
        withdrawn: vec![(Prefix::V4(prefix), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    let event = events_rx.recv().await.unwrap();
    assert_eq!(event.event_type, RouteEventType::Withdrawn);
    assert!(event.peer.is_none());
    assert_eq!(event.previous_peer, Some(peer.addr()));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_best_changed_carries_both_peers() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let peer1 = peer_v4(Ipv4Addr::new(1, 0, 0, 1));
    let peer2 = peer_v4(Ipv4Addr::new(1, 0, 0, 2));

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 1), 100)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    let mut events_rx = subscribe_events(&tx).await;

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer2,
        announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 2), 200)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    let event = events_rx.recv().await.unwrap();
    assert_eq!(event.event_type, RouteEventType::BestChanged);
    assert_eq!(event.peer, Some(peer2.addr()));
    assert_eq!(event.previous_peer, Some(peer1.addr()));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_has_timestamp() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let mut events_rx = subscribe_events(&tx).await;

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    let event = events_rx.recv().await.unwrap();
    // Stamped with the wall clock in Unix epoch milliseconds.
    assert!(event.timestamp_unix_ms > 1_700_000_000_000);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_added_has_no_previous_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let mut events_rx = subscribe_events(&tx).await;

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    let event = events_rx.recv().await.unwrap();
    assert_eq!(event.event_type, RouteEventType::Added);
    assert_eq!(event.peer, Some(peer.addr()));
    assert!(event.previous_peer.is_none());

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_carries_best_path_id() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let mut events_rx = subscribe_events(&tx).await;

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let mut route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
    route.path_id = 42;
    let peer = route.peer;

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    let event = events_rx.recv().await.unwrap();
    assert_eq!(event.event_type, RouteEventType::Added);
    assert_eq!(event.peer, Some(peer.addr()));
    assert_eq!(event.path_id, 42);

    drop(tx);
    handle.await.unwrap();
}

// --- Prometheus gauge tests ---

/// Every canonical family, in `CONFIGURED_FAMILIES` order.
const ADJ_RIB_OUT_FAMILIES: [&str; 12] = [
    "ipv4_unicast",
    "ipv6_unicast",
    "ipv4_flowspec",
    "ipv6_flowspec",
    "l2vpn_evpn",
    "linkstate",
    "linkstate_vpn",
    "l3vpn_ipv4_unicast",
    "l3vpn_ipv6_unicast",
    "ipv4_labeled_unicast",
    "ipv6_labeled_unicast",
    "rtc",
];

#[test]
fn peer_up_initializes_every_adj_rib_out_family_series() {
    let metrics = BgpMetrics::new();
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 2));
    let peer_label = peer.to_string();
    let (outbound_tx, _outbound_rx) = mpsc::channel(8);

    manager.handle_peer_up(
        peer,
        PeerUpRegistration {
            session_id: 1,
            peer_asn: 65_000,
            peer_router_id: Ipv4Addr::new(192, 0, 2, 2),
            outbound_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            orr_vantage: None,
            per_client_best: false,
            interpret_rfc1997: true,
            add_path_send_families: Vec::new(),
            add_path_send_max: 0,
            negotiated_orf_recv: Vec::new(),
            negotiated_llgr_families: Vec::new(),
        },
    );

    // Load-bearing proof: deleting any family from PeerUp's eager-zero loop
    // removes that labeled series and fails the lookup below.
    let gathered = metrics.registry().gather();
    let gauge = gathered
        .iter()
        .find(|family| family.name() == "bgp_rib_adj_out_prefixes")
        .expect("Adj-RIB-Out gauge family remains registered");
    for family in ADJ_RIB_OUT_FAMILIES {
        let observed = gauge
            .get_metric()
            .iter()
            .find(|metric| {
                metric
                    .get_label()
                    .iter()
                    .any(|label| label.name() == "peer" && label.value() == peer_label)
                    && metric
                        .get_label()
                        .iter()
                        .any(|label| label.name() == "family" && label.value() == family)
            })
            .unwrap_or_else(|| panic!("PeerUp omitted the {family} Adj-RIB-Out series"))
            .get_gauge()
            .get_value();
        assert!(
            observed.abs() < f64::EPSILON,
            "PeerUp initialized {family} to {observed}"
        );
    }
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "fixture gauge values are exact small nonnegative integers"
)]
fn commit_family_gauge_fixture(
    announce: Vec<Route>,
    vpn_announce: Vec<VpnRibRoute>,
) -> (AdjRibOutCommitStats, [i64; 12]) {
    let metrics = BgpMetrics::new();
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let peer = peer_v4(Ipv4Addr::new(192, 0, 2, 44));
    let peer_label = peer.to_string();
    for (index, family) in ADJ_RIB_OUT_FAMILIES.iter().enumerate() {
        metrics.set_adj_rib_out_prefixes(
            &peer_label,
            family,
            i64::try_from(index + 10).expect("sentinel fits i64"),
        );
    }
    let (outbound_tx, _outbound_rx) = mpsc::channel(8);
    manager.outbound_peers.insert(peer, outbound_tx);
    manager
        .peer_export_encoders
        .insert(peer, permissive_test_exact_export_encoder());
    manager.adj_rib_out_commit_stats = AdjRibOutCommitStats::default();
    let next_hop_override = vec![None; announce.len()].into();
    assert!(
        manager
            .try_send_and_commit_outbound_update(
                peer,
                OutboundCommitBatch {
                    vpn_announce: vpn_announce.into(),
                    ..OutboundCommitBatch::with_unicast(announce.into(), next_hop_override)
                },
            )
            .is_ok()
    );
    let gathered = metrics.registry().gather();
    let gauge = gathered
        .iter()
        .find(|family| family.name() == "bgp_rib_adj_out_prefixes")
        .expect("Adj-RIB-Out gauge family remains registered");
    let values = std::array::from_fn(|index| {
        gauge
            .get_metric()
            .iter()
            .find(|metric| {
                metric
                    .get_label()
                    .iter()
                    .any(|label| label.name() == "peer" && label.value() == peer_label)
                    && metric.get_label().iter().any(|label| {
                        label.name() == "family" && label.value() == ADJ_RIB_OUT_FAMILIES[index]
                    })
            })
            .unwrap_or_else(|| {
                panic!(
                    "commit removed the {} Adj-RIB-Out series",
                    ADJ_RIB_OUT_FAMILIES[index]
                )
            })
            .get_gauge()
            .get_value() as i64
    });
    (manager.adj_rib_out_commit_stats, values)
}

#[test]
fn adj_rib_out_commit_refreshes_only_touched_family_gauges() {
    let source = Ipv4Addr::new(198, 51, 100, 44);
    let (vpn_only, vpn_only_values) =
        commit_family_gauge_fixture(Vec::new(), vec![make_vpn_rib_route(source, 44, 1044, 100)]);
    assert_eq!(vpn_only.successful_commits, 1);
    assert_eq!(vpn_only.successful_enqueues, 1);
    assert_eq!(vpn_only.family_gauge_writes, 1);
    assert_eq!(vpn_only.last_family_gauge_write_mask, 0x10);
    assert_eq!(
        vpn_only_values,
        [10, 11, 12, 13, 14, 15, 16, 1, 0, 19, 20, 21],
        "VPN-only commit changes VPN truth and preserves every untouched sentinel"
    );

    let unicast = make_route(Ipv4Prefix::new(Ipv4Addr::new(10, 44, 0, 0), 24), source);
    let (mixed, mixed_values) = commit_family_gauge_fixture(
        vec![unicast],
        vec![make_vpn_rib_route(source, 45, 1045, 100)],
    );
    // Load-bearing proof: restoring unconditional seven-family refresh makes
    // these counts/masks 7/0x7f; omitting either final-vector predicate makes
    // the VPN-only or mixed assertion fail.
    assert_eq!(mixed.successful_commits, 1);
    assert_eq!(mixed.successful_enqueues, 1);
    assert_eq!(mixed.family_gauge_writes, 2);
    assert_eq!(mixed.last_family_gauge_write_mask, 0x11);
    assert_eq!(
        mixed_values,
        [1, 0, 12, 13, 14, 15, 16, 1, 0, 19, 20, 21],
        "mixed commit changes unicast/VPN truth and preserves untouched sentinels"
    );
}

#[test]
fn peer_down_zeroes_all_adj_rib_out_family_gauges() {
    let metrics = BgpMetrics::new();
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 2));
    let peer_label = peer.to_string();
    let families = ADJ_RIB_OUT_FAMILIES;

    for (index, family) in families.iter().enumerate() {
        metrics.set_adj_rib_out_prefixes(
            &peer_label,
            family,
            i64::try_from(index + 1).expect("fixture count fits i64"),
        );
    }

    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    });

    // Load-bearing proof: removing any family from the production teardown
    // reset leaves that family's seeded nonzero series behind and fails here.
    let gathered = metrics.registry().gather();
    let gauge = gathered
        .iter()
        .find(|family| family.name() == "bgp_rib_adj_out_prefixes")
        .expect("Adj-RIB-Out gauge family remains registered");
    for family in families {
        let observed = gauge
            .get_metric()
            .iter()
            .find(|metric| {
                metric
                    .get_label()
                    .iter()
                    .any(|label| label.name() == "peer" && label.value() == peer_label)
                    && metric
                        .get_label()
                        .iter()
                        .any(|label| label.name() == "family" && label.value() == family)
            })
            .unwrap_or_else(|| panic!("PeerDown removed the {family} Adj-RIB-Out series"))
            .get_gauge()
            .get_value();
        assert!(
            observed.abs() < f64::EPSILON,
            "PeerDown left the {family} Adj-RIB-Out gauge at {observed}"
        );
    }
}

/// Graceful-restart entry empties the peer's Adj-RIB-Out exactly as a
/// `PeerDown` does (`clear_outbound_peer_state` removes the table on both
/// paths), so the gauge must read zero for the whole hold window. RFC 4724
/// retention is an Adj-RIB-*In* property: `bgp_rib_prefixes`,
/// `bgp_gr_active_peers` and `bgp_gr_stale_routes` are the series that stay
/// nonzero for a peer expected back. Pinning the zero here keeps this path
/// from drifting away from the `PeerDown` reset again.
#[test]
fn graceful_restart_zeroes_all_adj_rib_out_family_gauges() {
    let metrics = BgpMetrics::new();
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 2));
    let peer_label = peer.to_string();
    let families = ADJ_RIB_OUT_FAMILIES;

    for (index, family) in families.iter().enumerate() {
        metrics.set_adj_rib_out_prefixes(
            &peer_label,
            family,
            i64::try_from(index + 1).expect("fixture count fits i64"),
        );
    }

    manager.handle_update(RibUpdate::PeerGracefulRestart {
        peer,
        session_id: 0,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: Vec::new(),
        llgr_stale_time: 0,
    });

    // The assertions below only describe the hold window if the peer is
    // actually in it — a GR entry that fell through to a full teardown
    // would zero the gauges for the wrong reason.
    assert!(
        manager.gr_peers.contains_key(&peer),
        "fixture must leave the peer inside the GR hold window"
    );

    // Load-bearing proof: dropping the zero-all loop from
    // `clear_outbound_peer_state` (or moving it back to the `PeerDown` call
    // site) leaves every seeded sentinel behind and fails here.
    let gathered = metrics.registry().gather();
    let gauge = gathered
        .iter()
        .find(|family| family.name() == "bgp_rib_adj_out_prefixes")
        .expect("Adj-RIB-Out gauge family remains registered");
    for family in families {
        let observed = gauge
            .get_metric()
            .iter()
            .find(|metric| {
                metric
                    .get_label()
                    .iter()
                    .any(|label| label.name() == "peer" && label.value() == peer_label)
                    && metric
                        .get_label()
                        .iter()
                        .any(|label| label.name() == "family" && label.value() == family)
            })
            .unwrap_or_else(|| panic!("graceful restart removed the {family} Adj-RIB-Out series"))
            .get_gauge()
            .get_value();
        assert!(
            observed.abs() < f64::EPSILON,
            "graceful restart left the {family} Adj-RIB-Out gauge at {observed}"
        );
    }
}

#[tokio::test]
#[expect(
    clippy::cast_possible_truncation,
    reason = "test fixture counts are small and cast only for gauge comparison"
)]
async fn rib_prefixes_gauge_tracks_adjribin() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    // Serialize
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes {
        deadline: full_snapshot_query_deadline(),
        reply: reply_tx,
    })
    .await
    .unwrap();
    let _ = reply_rx.await;

    let families = metrics.registry().gather();
    let rib_gauge = families
        .iter()
        .find(|f| f.name() == "bgp_rib_prefixes")
        .expect("bgp_rib_prefixes metric not found");
    let sample = rib_gauge
        .get_metric()
        .iter()
        .find(|metric| {
            metric
                .get_label()
                .iter()
                .any(|label| label.name() == "family" && label.value() == "ipv4_unicast")
        })
        .expect("ipv4_unicast series")
        .get_gauge()
        .get_value();
    assert_eq!(sample as i64, 1);

    // PeerDown should zero the gauge
    tx.send(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    })
    .await
    .unwrap();
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes {
        deadline: full_snapshot_query_deadline(),
        reply: reply_tx,
    })
    .await
    .unwrap();
    let _ = reply_rx.await;

    let families = metrics.registry().gather();
    let rib_gauge = families
        .iter()
        .find(|f| f.name() == "bgp_rib_prefixes")
        .expect("bgp_rib_prefixes metric not found");
    let sample = rib_gauge
        .get_metric()
        .iter()
        .find(|metric| {
            metric
                .get_label()
                .iter()
                .any(|label| label.name() == "family" && label.value() == "ipv4_unicast")
        })
        .expect("ipv4_unicast series")
        .get_gauge()
        .get_value();
    assert_eq!(sample as i64, 0);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
#[expect(
    clippy::cast_possible_truncation,
    reason = "test fixture counts are small and cast only for gauge comparison"
)]
async fn loc_rib_gauge_tracks_best() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes {
        deadline: full_snapshot_query_deadline(),
        reply: reply_tx,
    })
    .await
    .unwrap();
    let _ = reply_rx.await;

    let families = metrics.registry().gather();
    let loc_gauge = families
        .iter()
        .find(|f| f.name() == "bgp_rib_loc_prefixes")
        .expect("bgp_loc_rib_prefixes metric not found");
    let sample = loc_gauge
        .get_metric()
        .iter()
        .find(|metric| {
            metric
                .get_label()
                .iter()
                .any(|label| label.name() == "family" && label.value() == "ipv4_unicast")
        })
        .expect("ipv4_unicast series")
        .get_gauge()
        .get_value();
    assert_eq!(sample as i64, 1);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
#[expect(
    clippy::cast_possible_truncation,
    reason = "test fixture counts are small and cast only for gauge comparison"
)]
async fn adj_rib_out_gauge_tracks_advertised() {
    let metrics = BgpMetrics::new();
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let handle = tokio::spawn(manager.run());

    let source = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let target = peer_v4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    let (out_tx, mut _out_rx) = mpsc::channel(64);
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

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes {
        deadline: full_snapshot_query_deadline(),
        reply: reply_tx,
    })
    .await
    .unwrap();
    let _ = reply_rx.await;

    let families = metrics.registry().gather();
    let out_gauge = families
        .iter()
        .find(|f| f.name() == "bgp_rib_adj_out_prefixes")
        .expect("bgp_adj_rib_out_prefixes metric not found");
    let sample = out_gauge
        .get_metric()
        .iter()
        .find(|metric| {
            metric
                .get_label()
                .iter()
                .any(|label| label.name() == "family" && label.value() == "ipv4_unicast")
        })
        .expect("ipv4_unicast series")
        .get_gauge()
        .get_value();
    assert_eq!(sample as i64, 1);

    drop(tx);
    handle.await.unwrap();
}

// --- Query count tests ---

#[tokio::test]
async fn query_loc_rib_count() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
    let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24);
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![
            make_route(prefix1, Ipv4Addr::new(10, 0, 0, 1)),
            make_route(prefix2, Ipv4Addr::new(10, 0, 0, 1)),
        ],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply: reply_tx })
        .await
        .unwrap();
    let count = reply_rx.await.unwrap();
    assert_eq!(count, 2);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn query_advertised_count() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let source = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    let target = peer_v4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    let (out_tx, mut _out_rx) = mpsc::channel(64);
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

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();

    // Serialize
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes {
        deadline: full_snapshot_query_deadline(),
        reply: reply_tx,
    })
    .await
    .unwrap();
    let _ = reply_rx.await;

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedCount {
        peer: target,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let count = reply_rx.await.unwrap();
    assert_eq!(count, 1);

    // Unknown peer returns 0
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryAdvertisedCount {
        peer: peer_v4(Ipv4Addr::new(10, 0, 0, 99)),
        reply: reply_tx,
    })
    .await
    .unwrap();
    let count = reply_rx.await.unwrap();
    assert_eq!(count, 0);

    drop(tx);
    handle.await.unwrap();
}

// --- Sendable families filtering tests ---

#[test]
fn test_ingest_stall_override_parse_rules() {
    // Unset → no stall.
    assert_eq!(test_ingest_stall_override(None), None);
    // Valid positive milliseconds → stall, whitespace tolerated.
    assert_eq!(
        test_ingest_stall_override(Some("1500")),
        Some(Duration::from_millis(1500))
    );
    assert_eq!(
        test_ingest_stall_override(Some(" 250 ")),
        Some(Duration::from_millis(250))
    );
    // Zero disables (a zero-length stall is not a stall).
    assert_eq!(test_ingest_stall_override(Some("0")), None);
    // Garbage and empty values disable rather than erroring.
    assert_eq!(test_ingest_stall_override(Some("")), None);
    assert_eq!(test_ingest_stall_override(Some("fast")), None);
    assert_eq!(test_ingest_stall_override(Some("-5")), None);
    assert_eq!(test_ingest_stall_override(Some("1.5")), None);
}

#[test]
fn peer_up_panic_override_accepts_only_trimmed_one() {
    assert!(!test_panic_on_peer_up_override(None));
    assert!(test_panic_on_peer_up_override(Some("1")));
    assert!(test_panic_on_peer_up_override(Some(" 1 ")));
    for value in ["", "0", "2", "true", "-1"] {
        assert!(!test_panic_on_peer_up_override(Some(value)), "{value:?}");
    }
}

#[tokio::test]
async fn peer_deleted_reaps_metric_series_peer_down_does_not() {
    fn peer_series_count(metrics: &BgpMetrics, peer: &str) -> usize {
        metrics
            .registry()
            .gather()
            .iter()
            .flat_map(|family| family.get_metric().iter())
            .filter(|metric| {
                metric
                    .get_label()
                    .iter()
                    .any(|label| label.name() == "peer" && label.value() == peer)
            })
            .count()
    }

    let metrics = BgpMetrics::new();
    let (_tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 2));
    // Seed per-peer series the way the RIB emitters do (bare address).
    metrics.set_rib_prefixes("10.0.0.2", "ipv4_unicast", 42);
    metrics.set_gr_active("10.0.0.2", true);

    // A session flap: PeerDown zeroes / rewrites gauges but must keep
    // the label sets — the peer still exists.
    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    });
    assert!(
        peer_series_count(&metrics, "10.0.0.2") > 0,
        "PeerDown must not remove the peer's label sets"
    );

    // An interface-only neighbor leaving one endpoint for the next clears
    // its RIB state but keeps its series (ADR-0142).
    manager.handle_update(RibUpdate::PeerDeleted {
        peer,
        label: None,
        keep_series: true,
    });
    assert!(
        peer_series_count(&metrics, "10.0.0.2") > 0,
        "keep_series must keep the label sets"
    );

    // A deletion: the PeerDeleted marker (queued by the peer manager
    // behind the session's PeerDown) removes the label sets entirely.
    manager.handle_update(RibUpdate::PeerDeleted {
        peer,
        label: None,
        keep_series: false,
    });
    assert_eq!(peer_series_count(&metrics, "10.0.0.2"), 0);

    // Re-deleting an already-reaped peer is a no-op (no panic).
    manager.handle_update(RibUpdate::PeerDeleted {
        peer,
        label: None,
        keep_series: false,
    });
    assert_eq!(peer_series_count(&metrics, "10.0.0.2"), 0);
}

/// Scoped neighbor provenance in route events: each event records the
/// interface its routes were learned on, keeps it after the neighbor is
/// deleted, and a scoped history filter matches only that interface.
/// Red proof: building events with the default scope, or dropping the
/// interface from `RouteEvent::involves`, fails the interface assertions.
#[tokio::test]
async fn route_events_keep_the_scope_their_routes_were_learned_on() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let first_peer = PeerId::from_addr("fe80::1".parse().unwrap());
    let second_peer = PeerId::from_addr("fe80::2".parse().unwrap());
    let scoped = |peer: PeerId, interface: &str, local_pref: u32| {
        let mut route = make_route_with_lp(prefix, Ipv4Addr::new(10, 0, 0, 1), local_pref);
        route.peer = peer;
        route.aspa_context = crate::route::AspaContextId::intern_scoped(
            rustbgpd_wire::AspaValidationContext::default(),
            Some(interface),
        );
        route
    };
    for (peer, route) in [
        (first_peer, scoped(first_peer, "eth0", 100)),
        (second_peer, scoped(second_peer, "eth1", 200)),
    ] {
        tx.send(RibUpdate::RoutesReceived {
            session_id: 0,
            peer,
            announced: vec![route],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
        })
        .await
        .unwrap();
    }
    // Deleting the winner withdraws its routes; the events already
    // recorded keep its interface.
    tx.send(RibUpdate::PeerDeleted {
        peer: second_peer,
        label: Some("fe80::2%eth1".into()),
        keep_series: false,
    })
    .await
    .unwrap();

    let history = |peer: Option<PeerId>, interface: Option<&str>| {
        let tx = tx.clone();
        let interface = interface.map(Arc::<str>::from);
        async move {
            let (reply, response) = oneshot::channel();
            tx.send(RibUpdate::QueryRouteEventHistory {
                peer: peer.map(PeerId::addr),
                peer_interface: interface,
                afi: None,
                prefix: None,
                limit: 0,
                reply,
            })
            .await
            .unwrap();
            response.await.unwrap()
        }
    };
    let all = history(None, None).await;
    let recorded: Vec<_> = all
        .iter()
        .map(|event| {
            (
                event.event_type,
                event.peer_interface().as_deref().map(str::to_string),
                event
                    .previous_peer_interface()
                    .as_deref()
                    .map(str::to_string),
            )
        })
        .collect();
    assert_eq!(
        recorded,
        vec![
            (RouteEventType::Added, Some("eth0".into()), None),
            (
                RouteEventType::BestChanged,
                Some("eth1".into()),
                Some("eth0".into())
            ),
            (
                RouteEventType::BestChanged,
                Some("eth0".into()),
                Some("eth1".into())
            ),
        ]
    );
    assert_eq!(history(Some(second_peer), Some("eth1")).await.len(), 2);
    assert_eq!(history(Some(first_peer), Some("eth0")).await.len(), 3);
    assert!(history(Some(second_peer), Some("eth0")).await.is_empty());
    assert!(history(Some(second_peer), None).await.is_empty());

    drop(tx);
    handle.await.unwrap();
}

/// Acceptance: an interface move replaces `fe80::1%eth0` with
/// `fe80::1%eth1`. The old neighbor's teardown writes (a withdrawal, then
/// the delete and its final reap) run in the RIB after the replacement has
/// registered and published its own series, and none of them lands on the
/// replacement. The actor applies its messages in order, which fixes the
/// interleaving: announce old, announce new, old's late withdrawal, delete
/// old. Labelled by bare address, the late write overwrites the
/// replacement's gauge and the final reap removes it.
#[tokio::test]
async fn an_interface_move_never_misattributes_the_old_neighbors_teardown() {
    let metrics = BgpMetrics::new();
    let (_tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let scoped = |name: &str| {
        PeerId::allocate(crate::PeerEndpoint::new(
            "fe80::1".parse().unwrap(),
            Some(name),
        ))
    };
    let routes = |peer: PeerId, count: u8| -> Vec<Route> {
        (1..=count)
            .map(|octet| Route {
                peer,
                ..make_route(
                    Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, octet), 32),
                    Ipv4Addr::new(198, 51, 100, 1),
                )
            })
            .collect()
    };
    let receive = |manager: &mut RibManager, peer, announced, withdrawn, session_id| {
        manager.handle_update(RibUpdate::RoutesReceived {
            peer,
            session_id,
            announced,
            withdrawn,
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
        });
        while manager.process_next_route_chunk() {}
    };
    let rib_prefixes = || -> Vec<(String, i64)> {
        let mut rows: Vec<_> = metrics
            .registry()
            .gather()
            .iter()
            .filter(|family| family.name() == "bgp_rib_prefixes")
            .flat_map(|family| family.get_metric().iter())
            .filter(|metric| {
                metric
                    .get_label()
                    .iter()
                    .any(|label| label.name() == "family" && label.value() == "ipv4_unicast")
            })
            .map(|metric| {
                let peer = metric
                    .get_label()
                    .iter()
                    .find(|label| label.name() == "peer")
                    .map(|label| label.value().to_owned())
                    .unwrap_or_default();
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "test gauges hold small integer counts"
                )]
                let value = metric.get_gauge().get_value() as i64;
                (peer, value)
            })
            .collect();
        rows.sort();
        rows
    };

    let old = scoped("eth0");
    receive(&mut manager, old, routes(old, 3), vec![], 1);
    assert_eq!(rib_prefixes(), [("fe80::1%eth0".to_owned(), 3)]);
    let new = scoped("eth1");
    receive(&mut manager, new, routes(new, 7), vec![], 2);
    // The old neighbor's write queued before its delete runs only now.
    let late = routes(old, 1).remove(0).prefix;
    receive(&mut manager, old, vec![], vec![(late, 0)], 1);
    assert_eq!(
        rib_prefixes(),
        [
            ("fe80::1%eth0".to_owned(), 2),
            ("fe80::1%eth1".to_owned(), 7)
        ]
    );
    manager.handle_update(RibUpdate::PeerDeleted {
        peer: old,
        label: Some(old.label().into()),
        keep_series: false,
    });
    assert_eq!(rib_prefixes(), [("fe80::1%eth1".to_owned(), 7)]);
    assert!(old.release() && new.release());
}
