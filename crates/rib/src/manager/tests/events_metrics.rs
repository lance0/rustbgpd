use super::*;

async fn subscribe_events(
    tx: &mpsc::Sender<RibUpdate>,
) -> tokio::sync::broadcast::Receiver<crate::event::RouteEvent> {
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
            timestamp: String::new(),
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

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
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
    })
    .await
    .unwrap();

    let event = events_rx.recv().await.unwrap();
    assert_eq!(event.event_id, 1);
    assert_eq!(event.event_type, crate::event::RouteEventType::Added);
    assert_eq!(event.prefix, Prefix::V4(prefix));
    assert_eq!(event.peer, Some(peer));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_history_records_events_without_subscriber() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
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
    })
    .await
    .unwrap();

    let history = query_route_event_history(&tx, None, Some(Afi::Ipv4), None, 100).await;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].event_id, 1);
    assert_eq!(history[0].event_type, crate::event::RouteEventType::Added);
    assert_eq!(history[0].prefix, Prefix::V4(prefix));
    assert_eq!(history[0].peer, Some(peer));

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

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
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
    assert_eq!(history[1].previous_peer, Some(peer));

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
    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

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
    })
    .await
    .unwrap();

    let history = query_route_event_history(&tx, Some(peer1), Some(Afi::Ipv4), None, 2).await;
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].event_id, 2);
    assert_eq!(history[0].event_type, crate::event::RouteEventType::Added);
    assert!(matches!(history[0].prefix, Prefix::V4(_)));
    assert_eq!(history[0].peer, Some(peer1));
    assert_eq!(
        history[1].event_type,
        crate::event::RouteEventType::BestChanged
    );
    assert_eq!(history[1].event_id, 3);
    assert_eq!(history[1].prefix, Prefix::V4(prefix1));
    assert_eq!(history[1].peer, Some(peer2));
    assert_eq!(history[1].previous_peer, Some(peer1));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_history_filters_exact_ipv4_prefix() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
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

    let peer = IpAddr::V6(Ipv6Addr::LOCALHOST);
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
    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![make_route_with_lp(target, Ipv4Addr::new(10, 0, 0, 1), 100)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    assert_eq!(history[0].peer, Some(peer2));
    assert_eq!(history[0].previous_peer, Some(peer1));
    assert_eq!(
        history[1].event_type,
        crate::event::RouteEventType::BestChanged
    );
    assert_eq!(history[1].peer, Some(peer1));
    assert_eq!(history[1].previous_peer, Some(peer2));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_history_prefix_filter_no_matches_returns_empty() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
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

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
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
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: IpAddr::V6(Ipv6Addr::LOCALHOST),
        announced: vec![make_v6_route(v6_prefix, Ipv6Addr::LOCALHOST)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
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

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
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
        .metric[0]
        .gauge
        .value();
    assert_eq!(
        capacity as i64,
        i64::try_from(ROUTE_EVENT_HISTORY_CAPACITY).unwrap()
    );

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
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
        .metric[0]
        .gauge
        .value();
    assert_eq!(depth as i64, 3);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_withdrawn_on_last_removed() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
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
    let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

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
    })
    .await
    .unwrap();

    let event = events_rx.recv().await.unwrap();
    assert_eq!(event.event_type, crate::event::RouteEventType::BestChanged);
    assert_eq!(event.prefix, Prefix::V4(prefix));
    assert_eq!(event.peer, Some(peer2));

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

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
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

// --- WatchRoutes event tests ---

#[tokio::test]
async fn route_event_withdrawn_carries_previous_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
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
    })
    .await
    .unwrap();

    let event = events_rx.recv().await.unwrap();
    assert_eq!(event.event_type, RouteEventType::Withdrawn);
    assert!(event.peer.is_none());
    assert_eq!(event.previous_peer, Some(peer));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_best_changed_carries_both_peers() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
    let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 1), 100)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
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
    })
    .await
    .unwrap();

    let event = events_rx.recv().await.unwrap();
    assert_eq!(event.event_type, RouteEventType::BestChanged);
    assert_eq!(event.peer, Some(peer2));
    assert_eq!(event.previous_peer, Some(peer1));

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_has_timestamp() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let mut events_rx = subscribe_events(&tx).await;

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
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
    })
    .await
    .unwrap();

    let event = events_rx.recv().await.unwrap();
    assert!(!event.timestamp.is_empty());
    // Should be a valid integer (Unix seconds)
    let ts: u64 = event
        .timestamp
        .parse()
        .expect("timestamp should be numeric");
    assert!(ts > 0);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn route_event_added_has_no_previous_peer() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let mut events_rx = subscribe_events(&tx).await;

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
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
    })
    .await
    .unwrap();

    let event = events_rx.recv().await.unwrap();
    assert_eq!(event.event_type, RouteEventType::Added);
    assert_eq!(event.peer, Some(peer));
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
    })
    .await
    .unwrap();

    let event = events_rx.recv().await.unwrap();
    assert_eq!(event.event_type, RouteEventType::Added);
    assert_eq!(event.peer, Some(peer));
    assert_eq!(event.path_id, 42);

    drop(tx);
    handle.await.unwrap();
}

// --- Prometheus gauge tests ---

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

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
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
    })
    .await
    .unwrap();

    // Serialize
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let _ = reply_rx.await;

    let families = metrics.registry().gather();
    let rib_gauge = families
        .iter()
        .find(|f| f.name() == "bgp_rib_prefixes")
        .expect("bgp_rib_prefixes metric not found");
    let sample = rib_gauge.metric[0].gauge.value();
    assert_eq!(sample as i64, 1);

    // PeerDown should zero the gauge
    tx.send(RibUpdate::PeerDown {
        peer,
        session_id: 0,
    })
    .await
    .unwrap();
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let _ = reply_rx.await;

    let families = metrics.registry().gather();
    let rib_gauge = families
        .iter()
        .find(|f| f.name() == "bgp_rib_prefixes")
        .expect("bgp_rib_prefixes metric not found");
    let sample = rib_gauge.metric[0].gauge.value();
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

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
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
    })
    .await
    .unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let _ = reply_rx.await;

    let families = metrics.registry().gather();
    let loc_gauge = families
        .iter()
        .find(|f| f.name() == "bgp_rib_loc_prefixes")
        .expect("bgp_loc_rib_prefixes metric not found");
    let sample = loc_gauge.metric[0].gauge.value();
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

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    let (out_tx, mut _out_rx) = mpsc::channel(64);
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

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
        .await
        .unwrap();
    let _ = reply_rx.await;

    let families = metrics.registry().gather();
    let out_gauge = families
        .iter()
        .find(|f| f.name() == "bgp_rib_adj_out_prefixes")
        .expect("bgp_adj_rib_out_prefixes metric not found");
    let sample = out_gauge.metric[0].gauge.value();
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

    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
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

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

    let (out_tx, mut _out_rx) = mpsc::channel(64);
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

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: source,
        announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Serialize
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
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
        peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)),
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
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
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

    // A deletion: the PeerDeleted marker (queued by the peer manager
    // behind the session's PeerDown) removes the label sets entirely.
    manager.handle_update(RibUpdate::PeerDeleted { peer });
    assert_eq!(peer_series_count(&metrics, "10.0.0.2"), 0);

    // Re-deleting an already-reaped peer is a no-op (no panic).
    manager.handle_update(RibUpdate::PeerDeleted { peer });
    assert_eq!(peer_series_count(&metrics, "10.0.0.2"), 0);
}
