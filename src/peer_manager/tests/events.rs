use super::*;

fn test_policy_event(target: &str, peer: Option<IpAddr>) -> PolicyEvent {
    PolicyEvent {
        operation: "set",
        target_type: "policy",
        target: target.to_string(),
        peer,
        peer_label: None,
        affected_peer_count: usize::from(peer.is_some()),
        timestamp: "1".to_string(),
        reason: format!("policy set policy {target}"),
    }
}

#[tokio::test]
async fn session_events_publish_state_changes() {
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let handle = tokio::spawn(mgr.run());
    let mut events = subscribe_session_events(&tx).await;

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::AddPeer {
        config: make_config(addr, 65002),
        sync_config_snapshot: false,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok());

    let event = wait_for_session_event(&mut events, SessionLifecycleEventType::StateChanged).await;
    assert_eq!(event.peer, addr);
    assert_eq!(event.session_role.as_deref(), Some("primary"));
    assert!(event.old_state.is_some());
    assert!(event.new_state.is_some());

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn dynamic_accept_any_peer_snapshot_learns_negotiated_asn() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    insert_test_managed_peer_with_asn(
        &mut mgr,
        addr,
        0,
        fake_peer_handle(
            addr,
            SessionState::Established,
            None,
            Arc::new(FakePeerCounters::default()),
        ),
        false,
    );
    mgr.peers.get_mut(&key(addr)).unwrap().is_dynamic = true;

    mgr.handle_session_lifecycle_notification(&SessionLifecycleNotification::StateChanged {
        session_id: 1,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr: addr,
        peer_asn: Some(65099),
        old: SessionState::OpenConfirm,
        new: SessionState::Established,
    });

    let managed = mgr.peers.get(&key(addr)).unwrap();
    assert_eq!(managed.remote_asn, 65099);
    assert_eq!(managed.transport_config.peer.remote_asn, 65099);
    assert_eq!(
        mgr.get_peer_info(&key(addr)).await.unwrap().remote_asn,
        65099
    );
}

#[tokio::test]
async fn lifecycle_notification_matches_scoped_static_peer_by_session_id() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );

    let peer = IpAddr::V6("fe80::2".parse().unwrap());
    insert_test_scoped_managed_peer(
        &mut mgr,
        peer,
        "eth0",
        10,
        1,
        fake_peer_handle(
            peer,
            SessionState::Established,
            None,
            Arc::new(FakePeerCounters::default()),
        ),
    );
    insert_test_scoped_managed_peer(
        &mut mgr,
        peer,
        "eth1",
        11,
        2,
        fake_peer_handle(
            peer,
            SessionState::Established,
            None,
            Arc::new(FakePeerCounters::default()),
        ),
    );

    let mut events = mgr.session_events_tx.subscribe();
    mgr.handle_session_lifecycle_notification(&SessionLifecycleNotification::StateChanged {
        session_id: 2,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr: peer,
        peer_asn: None,
        old: SessionState::OpenConfirm,
        new: SessionState::Established,
    });

    let event = tokio::time::timeout(Duration::from_millis(250), events.recv())
        .await
        .expect("session event timeout")
        .expect("session event channel closed");
    let SessionEvent::Lifecycle(event) = event else {
        panic!("expected lifecycle event");
    };
    assert_eq!(event.peer, peer);
    assert_eq!(event.peer_label.as_deref(), Some("fe80::2%eth1"));
    assert_eq!(event.session_role.as_deref(), Some("primary"));
}

#[tokio::test]
async fn session_events_publish_peer_enable_disable() {
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let handle = tokio::spawn(mgr.run());

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::AddPeer {
        config: make_config(addr, 65002),
        sync_config_snapshot: false,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok());

    let mut events = subscribe_session_events(&tx).await;
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::DisablePeer {
        peer: key(addr),
        reason: None,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok());
    let event = wait_for_session_event(&mut events, SessionLifecycleEventType::PeerDisabled).await;
    assert_eq!(event.peer, addr);

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::EnablePeer {
        peer: key(addr),
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok());
    let event = wait_for_session_event(&mut events, SessionLifecycleEventType::PeerEnabled).await;
    assert_eq!(event.peer, addr);

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn session_event_history_records_events_without_subscriber() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    mgr.publish_peer_lifecycle_event(
        &key(addr),
        SessionLifecycleEventType::PeerEnabled,
        "peer enabled".to_string(),
    );

    let events = query_session_event_history(&mgr, None, BTreeSet::new(), 0).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].peer, addr);
    assert_eq!(events[0].event_type, SessionLifecycleEventType::PeerEnabled);
}

/// Load-bearing: omitting the bounded cause from notification-history
/// projection removes the exact suffix while changing the canonical BGP
/// description or shutdown reason breaks the remaining field assertions.
#[tokio::test]
async fn notification_event_reason_includes_bounded_failure_cause() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut events = mgr.session_events_tx.subscribe();
    mgr.publish_notification_event(rustbgpd_transport::SessionNotificationEvent {
        session_id: 1,
        peer_addr: addr,
        role: rustbgpd_transport::SessionRole::Primary,
        direction: rustbgpd_transport::SessionNotificationDirection::Sent,
        code: rustbgpd_wire::notification::NotificationCode::Cease.as_u8(),
        subcode: rustbgpd_wire::notification::cease_subcode::OUT_OF_RESOURCES,
        description: "Out of Resources".to_string(),
        shutdown_reason: None,
        failure_cause: Some(rustbgpd_transport::handle::SessionFailureCause::OutboundSaturation),
    });

    let rustbgpd_api::peer_types::SessionEvent::Notification(event) = events.try_recv().unwrap()
    else {
        panic!("expected notification event");
    };
    assert_eq!(
        event.reason,
        "BGP NOTIFICATION sent for peer 10.0.0.2: 6/8 (Out of Resources); transport failure: outbound writer queue saturated"
    );
    assert_eq!(event.code, 6);
    assert_eq!(event.subcode, 8);
    assert_eq!(event.description, "Out of Resources");
    assert_eq!(event.shutdown_reason, None);
}

/// Cross-stream correlation: notification events for interface-scoped
/// (link-local) peers must carry the same scoped peer label that lifecycle
/// events publish, not the bare address.
#[tokio::test]
async fn notification_event_uses_scoped_peer_label_for_interface_scoped_peer() {
    let mut mgr = test_peer_manager();
    let addr: IpAddr = "fe80::2".parse().unwrap();
    insert_test_scoped_managed_peer(
        &mut mgr,
        addr,
        "eth0",
        10,
        7,
        fake_peer_handle(
            addr,
            SessionState::Established,
            None,
            Arc::new(FakePeerCounters::default()),
        ),
    );
    let mut events = mgr.session_events_tx.subscribe();
    mgr.publish_notification_event(rustbgpd_transport::SessionNotificationEvent {
        session_id: 7,
        peer_addr: addr,
        role: rustbgpd_transport::SessionRole::Primary,
        direction: rustbgpd_transport::SessionNotificationDirection::Received,
        code: rustbgpd_wire::notification::NotificationCode::Cease.as_u8(),
        subcode: rustbgpd_wire::notification::cease_subcode::ADMINISTRATIVE_RESET,
        description: "Administrative Reset".to_string(),
        shutdown_reason: None,
        failure_cause: None,
    });

    let rustbgpd_api::peer_types::SessionEvent::Notification(event) = events.try_recv().unwrap()
    else {
        panic!("expected notification event");
    };
    assert!(
        event.reason.contains("fe80::2%eth0"),
        "notification reason must use the scoped peer label, got: {}",
        event.reason
    );
    assert_eq!(event.peer_label.as_deref(), Some("fe80::2%eth0"));
    assert_eq!(event.peer, addr);
}

/// Policy events scoped to an interface-scoped peer carry the scoped label so
/// they correlate with the lifecycle stream.
#[tokio::test]
async fn policy_event_uses_scoped_peer_label_for_interface_scoped_peer() {
    let mut mgr = test_peer_manager();
    let addr: IpAddr = "fe80::2".parse().unwrap();
    insert_test_scoped_managed_peer(
        &mut mgr,
        addr,
        "eth0",
        10,
        7,
        fake_peer_handle(
            addr,
            SessionState::Established,
            None,
            Arc::new(FakePeerCounters::default()),
        ),
    );
    let mut events = mgr.policy_events_tx.subscribe();
    mgr.publish_policy_config_event(
        &ConfigEvent::SetNeighborImportChain {
            address: addr,
            policy_names: Vec::new(),
            ack: None,
        },
        1,
    );

    let event = events.try_recv().unwrap();
    assert_eq!(event.peer, Some(addr));
    assert_eq!(event.peer_label.as_deref(), Some("fe80::2%eth0"));
}

/// Successful configured-peer installs publish their current admin event only
/// after installation; failed duplicate adds must not fabricate one.
#[tokio::test]
async fn peer_presence_add_and_readd_publish_current_admin_state_without_failed_add_noise() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let metrics = mgr.metrics.clone();
    let admin_types = [
        SessionLifecycleEventType::PeerEnabled,
        SessionLifecycleEventType::PeerDisabled,
    ]
    .into_iter()
    .collect();

    mgr.add_peer(make_config(addr, 65002), false).await.unwrap();
    assert_eq!(
        peer_identity_gauge(&metrics, "bgp_peer_admin_enabled", "10.0.0.2", ""),
        Some(1.0)
    );
    assert_eq!(
        peer_identity_gauge(&metrics, "bgp_peer_session_established", "10.0.0.2", ""),
        Some(0.0)
    );
    assert!(mgr.add_peer(make_config(addr, 65002), false).await.is_err());
    mgr.disable_peer(key(addr), None).await.unwrap();
    mgr.delete_peer(key(addr), false).await.unwrap();
    mgr.add_peer(make_config(addr, 65002), false).await.unwrap();
    mgr.delete_peer(key(addr), false).await.unwrap();
    mgr.add_peer_with_admin_state(make_config(addr, 65002), false, false)
        .await
        .unwrap();

    let events = query_session_event_history(&mgr, Some(addr), admin_types, 0).await;
    assert_eq!(
        events
            .iter()
            .map(|event| event.event_type)
            .collect::<Vec<_>>(),
        vec![
            SessionLifecycleEventType::PeerEnabled,
            SessionLifecycleEventType::PeerDisabled,
            SessionLifecycleEventType::PeerEnabled,
            SessionLifecycleEventType::PeerDisabled,
        ]
    );
    assert!(!mgr.list_peers().await[0].enabled);

    let presence_types = [
        SessionLifecycleEventType::PeerAdded,
        SessionLifecycleEventType::PeerRemoved,
    ]
    .into_iter()
    .collect();
    let presence = query_session_event_history(&mgr, Some(addr), presence_types, 0).await;
    assert_eq!(
        presence
            .iter()
            .map(|event| (event.event_type, event.reason.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (SessionLifecycleEventType::PeerAdded, "peer 10.0.0.2 added"),
            (
                SessionLifecycleEventType::PeerRemoved,
                "peer 10.0.0.2 removed"
            ),
            (SessionLifecycleEventType::PeerAdded, "peer 10.0.0.2 added"),
            (
                SessionLifecycleEventType::PeerRemoved,
                "peer 10.0.0.2 removed"
            ),
        ]
    );
    assert_eq!(presence[0].old_state, None);
    assert_eq!(presence[0].new_state, Some(SessionState::Idle));
    assert_eq!(presence[1].old_state, None);
    assert_eq!(presence[1].new_state, None);
}

#[tokio::test]
async fn session_event_history_filters_peer_type_and_limit_in_order() {
    let mut mgr = test_peer_manager();
    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    mgr.publish_peer_lifecycle_event(
        &key(peer1),
        SessionLifecycleEventType::PeerEnabled,
        "old match".to_string(),
    );
    mgr.publish_peer_lifecycle_event(
        &key(peer2),
        SessionLifecycleEventType::PeerEnabled,
        "wrong peer".to_string(),
    );
    mgr.publish_peer_lifecycle_event(
        &key(peer1),
        SessionLifecycleEventType::PeerDisabled,
        "wrong type".to_string(),
    );
    mgr.publish_peer_lifecycle_event(
        &key(peer1),
        SessionLifecycleEventType::PeerEnabled,
        "middle match".to_string(),
    );
    mgr.publish_peer_lifecycle_event(
        &key(peer1),
        SessionLifecycleEventType::PeerEnabled,
        "newest match".to_string(),
    );

    let events = query_session_event_history(
        &mgr,
        Some(peer1),
        [SessionLifecycleEventType::PeerEnabled]
            .into_iter()
            .collect(),
        2,
    )
    .await;
    let reasons: Vec<_> = events.iter().map(|event| event.reason.as_str()).collect();
    assert_eq!(reasons, vec!["middle match", "newest match"]);
}

#[tokio::test]
async fn session_event_history_capacity_evicts_oldest() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    for idx in 0..=SESSION_EVENT_HISTORY_CAPACITY {
        mgr.publish_peer_lifecycle_event(
            &key(addr),
            SessionLifecycleEventType::StateChanged,
            format!("event-{idx}"),
        );
    }

    let events = query_session_event_history(&mgr, None, BTreeSet::new(), 0).await;
    assert_eq!(events.len(), SESSION_EVENT_HISTORY_CAPACITY);
    assert_eq!(events[0].reason, "event-1");
    let expected_last = format!("event-{SESSION_EVENT_HISTORY_CAPACITY}");
    assert_eq!(
        events.last().map(|event| event.reason.as_str()),
        Some(expected_last.as_str())
    );
}

#[tokio::test]
async fn policy_event_history_records_events_without_subscriber() {
    let mut mgr = test_peer_manager();

    mgr.publish_policy_event(test_policy_event("policy-a", None));

    let events = query_policy_event_history(&mgr, None, 0).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].target, "policy-a");
    assert_eq!(events[0].reason, "policy set policy policy-a");
}

#[tokio::test]
async fn policy_event_history_filters_peer_and_limit_in_order() {
    let mut mgr = test_peer_manager();
    let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    mgr.publish_policy_event(test_policy_event("old-match", Some(peer1)));
    mgr.publish_policy_event(test_policy_event("wrong-peer", Some(peer2)));
    mgr.publish_policy_event(test_policy_event("global", None));
    mgr.publish_policy_event(test_policy_event("middle-match", Some(peer1)));
    mgr.publish_policy_event(test_policy_event("newest-match", Some(peer1)));

    let events = query_policy_event_history(&mgr, Some(peer1), 2).await;
    let targets: Vec<_> = events.iter().map(|event| event.target.as_str()).collect();
    assert_eq!(targets, vec!["middle-match", "newest-match"]);
}

#[tokio::test]
async fn policy_event_history_capacity_evicts_oldest() {
    let mut mgr = test_peer_manager();

    for idx in 0..=POLICY_EVENT_HISTORY_CAPACITY {
        mgr.publish_policy_event(test_policy_event(&format!("policy-{idx}"), None));
    }

    let events = query_policy_event_history(&mgr, None, 0).await;
    assert_eq!(events.len(), POLICY_EVENT_HISTORY_CAPACITY);
    assert_eq!(events[0].target, "policy-1");
    let expected_last = format!("policy-{POLICY_EVENT_HISTORY_CAPACITY}");
    assert_eq!(
        events.last().map(|event| event.target.as_str()),
        Some(expected_last.as_str())
    );
}
