use super::*;

async fn localhost_inbound_stream() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server_stream, _) = listener.accept().await.unwrap();
    let client_stream = client.await.unwrap();
    (server_stream, client_stream)
}

/// Load-bearing unconfigured-source accounting proof (ADR-0120): the
/// pre-existing unmatched-source drop must count under the bounded
/// drop-reason vocabulary even with the limiter disabled (the default).
#[tokio::test]
async fn unmatched_inbound_source_counts_unconfigured_drop() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let metrics_view = metrics.clone();
    let mut config = make_dynamic_manager_config();
    config.dynamic_neighbors.clear();
    let mut mgr = PeerManager::new_with_config(
        rx,
        mpsc::unbounded_channel().1,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
        None,
        config,
    );

    let (server_stream, client_stream) = localhost_inbound_stream().await;
    mgr.handle_inbound(
        server_stream,
        sock(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))),
        None,
        None,
    )
    .await;

    assert!(mgr.peers.is_empty());
    assert_eq!(
        inbound_drop_metric(&metrics_view, "unconfigured"),
        Some(1.0)
    );
    drop(client_stream);
}

/// ADR-0120 default-off invariant: without `[inbound_admission]`, rapid
/// re-accept churn from one dynamic source behaves exactly as before —
/// every cycle is admitted and nothing is rate-limited.
#[tokio::test]
async fn inbound_admission_disabled_by_default_admits_rapid_dynamic_reaccepts() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let metrics_view = metrics.clone();
    let mut mgr = PeerManager::new_with_config(
        rx,
        mpsc::unbounded_channel().1,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
        None,
        make_dynamic_manager_config(),
    );

    let churny = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9));
    let mut client_streams = Vec::new();
    for cycle in 0..3 {
        let (server_stream, client_stream) = localhost_inbound_stream().await;
        client_streams.push(client_stream);
        mgr.handle_inbound(server_stream, sock(churny), None, None)
            .await;
        assert!(
            mgr.peers.contains_key(&key(churny)),
            "cycle {cycle}: default config must admit every re-accept"
        );
        let session_id = mgr.peers.get(&key(churny)).unwrap().session_id;
        mgr.handle_session_notification(SessionNotification::BackToIdle {
            session_id,
            role: rustbgpd_transport::SessionRole::Primary,
            peer_addr: churny,
        })
        .await;
        assert!(
            mgr.peers.is_empty(),
            "cycle {cycle}: peer should be removed"
        );
    }
    assert_eq!(inbound_drop_metric(&metrics_view, "rate_limited"), None);
    drop(client_streams);
}

/// Load-bearing ADR-0120 enforcement proof: with `[inbound_admission]`
/// enabled at burst 1, a dynamic source's re-accept inside the same v4
/// aggregate is dropped before session spawn and counted, while a static
/// neighbor inside the very same aggregate is exempt by admission path.
#[tokio::test]
async fn enabled_inbound_admission_rate_limits_dynamic_source_but_exempts_static_neighbor() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let metrics_view = metrics.clone();
    let mut config = make_dynamic_manager_config();
    config.inbound_admission = crate::config::InboundAdmissionConfig {
        enabled: true,
        rate_per_minute: 1,
        burst: 1,
        v4_aggregation_len: 24,
        v6_aggregation_len: 64,
        table_capacity: 64,
    };
    let mut mgr = PeerManager::new_with_config(
        rx,
        mpsc::unbounded_channel().1,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
        None,
        config,
    );

    // First accept consumes the aggregate's whole burst.
    let first_source = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9));
    let (server_stream, first_client) = localhost_inbound_stream().await;
    mgr.handle_inbound(server_stream, sock(first_source), None, None)
        .await;
    assert!(
        mgr.peers.contains_key(&key(first_source)),
        "the first accept within burst must be admitted"
    );
    let session_id = mgr.peers.get(&key(first_source)).unwrap().session_id;
    mgr.handle_session_notification(SessionNotification::BackToIdle {
        session_id,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr: first_source,
    })
    .await;
    assert!(mgr.peers.is_empty());

    // A different host inside the same /24 aggregate shares the empty
    // bucket: dropped before session spawn, counted, logged.
    let second_source = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 10));
    let (server_stream, second_client) = localhost_inbound_stream().await;
    mgr.handle_inbound(server_stream, sock(second_source), None, None)
        .await;
    assert!(
        mgr.peers.is_empty(),
        "an over-rate source aggregate must not spawn a session"
    );
    assert_eq!(
        inbound_drop_metric(&metrics_view, "rate_limited"),
        Some(1.0)
    );
    assert_dynamic_neighbor_capacity(&metrics_view, 0.0, 100.0, 100.0, 0.0);

    // A statically configured neighbor inside the very same exhausted
    // aggregate is exempt: its inbound takes the static path and never
    // consults the limiter.
    let static_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 20));
    insert_test_managed_peer_with_asn(
        &mut mgr,
        static_addr,
        65002,
        acking_policy_handle(static_addr, SessionState::Established),
        false,
    );
    let (server_stream, static_client) = localhost_inbound_stream().await;
    mgr.handle_inbound(server_stream, sock(static_addr), None, None)
        .await;
    assert!(
        mgr.peers.contains_key(&key(static_addr)),
        "static neighbor must survive its inbound untouched"
    );
    assert_eq!(
        inbound_drop_metric(&metrics_view, "rate_limited"),
        Some(1.0),
        "the static path must not consult the ADR-0120 limiter"
    );

    drop(first_client);
    drop(second_client);
    drop(static_client);
}

#[tokio::test]
async fn dynamic_inbound_peer_records_most_specific_accepted_range() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut config = make_dynamic_manager_config();
    config.peer_groups.insert(
        "narrow-members".to_string(),
        crate::config::PeerGroupConfig {
            families: vec!["ipv4_unicast".to_string()],
            ..Default::default()
        },
    );
    config.dynamic_neighbors = vec![
        crate::config::DynamicNeighborConfig {
            prefix: "127.0.0.9/16".to_string(),
            peer_group: "ix-members".to_string(),
            remote_asn: 0,
            description: Some("wide".to_string()),
            tcp_ao: None,
        },
        crate::config::DynamicNeighborConfig {
            prefix: "127.0.0.9/24".to_string(),
            peer_group: "narrow-members".to_string(),
            remote_asn: 0,
            description: Some("narrow".to_string()),
            tcp_ao: None,
        },
    ];
    let mut mgr = PeerManager::new_with_config(
        rx,
        mpsc::unbounded_channel().1,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
        None,
        config,
    );

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server_stream, remote_addr) = listener.accept().await.unwrap();
    let client_stream = client.await.unwrap();
    let peer_addr = remote_addr.ip();

    mgr.handle_inbound(server_stream, sock(peer_addr), None, None)
        .await;

    let managed = mgr.peers.get(&key(peer_addr)).unwrap();
    assert!(managed.is_dynamic);
    assert_eq!(managed.peer_group.as_deref(), Some("narrow-members"));
    let accepted = managed
        .accepted_dynamic_range
        .as_ref()
        .expect("dynamic peer should record accepted range");
    assert_eq!(accepted.addr, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)));
    assert_eq!(accepted.prefix_len, 24);
    assert_eq!(accepted.peer_group, "narrow-members");

    mgr.delete_dynamic_range("127.0.0.9/24").unwrap();
    let current_match = mgr
        .match_dynamic_range(peer_addr)
        .expect("covering /16 remains in the live matcher");
    assert_eq!(current_match.prefix_len, 16);
    assert_eq!(current_match.peer_group, "ix-members");

    let managed = mgr.peers.get(&key(peer_addr)).unwrap();
    let snapshot = super::snapshot::build_peer_info(&key(peer_addr), managed, None, false);
    assert_eq!(
        snapshot.accepted_dynamic_range,
        Some(DynamicRangeTarget {
            addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
            prefix_len: 24,
            peer_group: "narrow-members".to_string(),
        }),
        "snapshot provenance stays pinned to the accepted /24 after the live matcher falls back to /16"
    );

    drop(client_stream);
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "fresh-start regression keeps dynamic config, accepted metadata, manager retention, and session preflight together"
)]
async fn fresh_dynamic_tcp_ao_inbound_seeds_selected_owner_keyring_for_manager_and_session() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let mut config = make_dynamic_manager_config();
    let current = test_tcp_ao();
    let successor = crate::config::TcpAoConfig {
        key: "fresh-start-successor".to_string(),
        send_id: 2,
        recv_id: 2,
        algorithm: "hmac(sha256)".to_string(),
        preferred: false,
        deprecated: false,
    };
    config.dynamic_neighbors[0].tcp_ao = Some(crate::config::TcpAoKeyringConfig(vec![
        current.clone(),
        successor,
    ]));
    let mut manager = PeerManager::new_with_config(
        rx,
        mpsc::unbounded_channel().1,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
        None,
        config,
    );

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let connect = TcpStream::connect(listener.local_addr().unwrap());
    let accept = listener.accept();
    let (client, accepted) = tokio::join!(connect, accept);
    let client = client.unwrap();
    let (server, remote_addr) = accepted.unwrap();
    let peer_addr = remote_addr.ip();
    let owner_peer: IpAddr = "127.0.0.0".parse().unwrap();
    let key_state = |send_id, is_selected| rustbgpd_transport::TcpAoKeyState {
        peer: owner_peer,
        prefix_len: 8,
        send_id,
        recv_id: send_id,
        algorithm: rustbgpd_transport::TcpAoAlgorithm::HmacSha256,
        is_current: is_selected,
        is_rnext: is_selected,
        preferred: false,
        deprecated: false,
        vrf_ifindex: None,
        pkt_good: u64::from(is_selected),
        pkt_bad: 0,
    };
    manager
        .handle_inbound(
            server,
            sock(peer_addr),
            Some(rustbgpd_transport::TcpAoInfoSnapshot {
                has_current_key: true,
                has_rnext_key: true,
                ao_required: false,
                accept_icmps: false,
                current_key: 1,
                rnext_key: 1,
                pkt_good: 1,
                pkt_bad: 0,
                pkt_key_not_found: 0,
                pkt_ao_required: 0,
                pkt_dropped_icmp: 0,
                keys: vec![key_state(1, true), key_state(2, false)],
            }),
            Some(rustbgpd_transport::TcpAoRotationGeneration::STARTUP),
        )
        .await;

    let peer_key = key(peer_addr);
    let dynamic_peer = manager
        .peers
        .get(&peer_key)
        .expect("fresh protected dynamic peer must be created");
    let current_keyring = dynamic_peer
        .transport_config
        .tcp_ao
        .clone()
        .expect("ManagedPeer must retain the explicit direct-range keyring");
    assert_eq!(current_keyring.0.len(), 2);
    let commands = dynamic_peer.handle.commands_sender();
    let mut desired_keyring = current_keyring.clone();
    desired_keyring.0[0].deprecated = true;
    desired_keyring.0[1].preferred = true;
    let selected_owner = rustbgpd_transport::listener::TcpAoSelectedOwner {
        owner: rustbgpd_transport::TcpAoListenerOwnerKind::Dynamic,
        peer: owner_peer,
        prefix_len: 8,
    };
    let desired = rustbgpd_transport::TcpAoSessionSelection {
        generation: rustbgpd_transport::TcpAoRotationGeneration::new(2).unwrap(),
        active_keyring: Some(desired_keyring.clone()),
        accepted_owners: vec![rustbgpd_transport::TcpAoRotationOwner {
            owner: rustbgpd_transport::TcpAoListenerOwnerKind::Dynamic,
            peer: owner_peer,
            prefix_len: 8,
            keyring: desired_keyring,
        }]
        .into(),
        accepted_selected_owner: Some(selected_owner),
    };
    let (reply, response) = oneshot::channel();
    commands
        .send(rustbgpd_transport::PeerCommand::PreflightTcpAoSelection { desired, reply })
        .await
        .unwrap();
    let error = tokio::time::timeout(Duration::from_secs(1), response)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err()
        .to_string();
    // The test stream is deliberately plaintext, so low-level kernel
    // preflight fails. Reaching that boundary proves PeerSession received the
    // same selected-owner keyring; without seeding it fails earlier with
    // "lacks its current selected-owner keyring".
    assert!(
        error.contains("failed to preflight exact TCP-AO selection inventory"),
        "PeerSession did not retain the fresh-start direct-range keyring: {error}"
    );
    assert!(!error.contains("lacks its current selected-owner keyring"));

    manager.peers[&peer_key].handle.abort_for_transport_safety();
    drop(client);
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "queued-accept regression keeps stale config, staged listener metadata, and manager rotation truth together"
)]
async fn queued_dynamic_selection_accept_reconciles_metadata_and_rotation_status() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let mut config = make_dynamic_manager_config();
    config.dynamic_neighbors[0].tcp_ao = Some(crate::config::TcpAoKeyringConfig(vec![
        test_tcp_ao(),
        crate::config::TcpAoConfig {
            key: "queued-selection-successor".to_string(),
            send_id: 2,
            recv_id: 2,
            algorithm: "hmac(sha256)".to_string(),
            preferred: false,
            deprecated: false,
        },
    ]));
    let mut manager = PeerManager::new_with_config(
        rx,
        mpsc::unbounded_channel().1,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
        None,
        config,
    );

    // Model an accept queued by the listener after its desired-generation
    // selection snapshot was staged but before PeerManager installed the new
    // config snapshot. The direct-owner secrets and key identities still come
    // exclusively from the old current config; only redacted selection
    // metadata is reconciled from the already-validated accepted socket.
    let desired_generation = rustbgpd_transport::TcpAoRotationGeneration::STARTUP
        .next()
        .unwrap();
    let selection_status = TcpAoRotationStatus {
        desired: desired_generation,
        applied: rustbgpd_transport::TcpAoRotationGeneration::STARTUP,
        phase: rustbgpd_transport::TcpAoRotationPhase::Selecting,
        last_error: None,
    };
    manager.tcp_ao_rotation = selection_status.clone();
    let mut expected_keyring = manager.dynamic_ranges[0].tcp_ao.clone().unwrap();
    expected_keyring.0[1].preferred = true;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let connect = TcpStream::connect(listener.local_addr().unwrap());
    let accept = listener.accept();
    let (client, accepted) = tokio::join!(connect, accept);
    let client = client.unwrap();
    let (server, remote_addr) = accepted.unwrap();
    let peer_addr = remote_addr.ip();
    let owner_peer: IpAddr = "127.0.0.0".parse().unwrap();
    let key_state =
        |peer, prefix_len, send_id, preferred, is_selected| rustbgpd_transport::TcpAoKeyState {
            peer,
            prefix_len,
            send_id,
            recv_id: send_id,
            algorithm: rustbgpd_transport::TcpAoAlgorithm::HmacSha256,
            is_current: is_selected,
            is_rnext: is_selected,
            preferred,
            deprecated: false,
            vrf_ifindex: None,
            pkt_good: u64::from(is_selected),
            pkt_bad: 0,
        };
    manager
        .handle_inbound(
            server,
            sock(peer_addr),
            Some(rustbgpd_transport::TcpAoInfoSnapshot {
                has_current_key: true,
                has_rnext_key: true,
                ao_required: false,
                accept_icmps: false,
                current_key: 2,
                rnext_key: 2,
                pkt_good: 1,
                pkt_bad: 0,
                pkt_key_not_found: 0,
                pkt_ao_required: 0,
                pkt_dropped_icmp: 0,
                keys: vec![
                    // A covering owner with the same key identity must not
                    // influence the explicit /8 owner's local metadata.
                    key_state("0.0.0.0".parse().unwrap(), 0, 2, false, false),
                    key_state(owner_peer, 8, 1, false, false),
                    key_state(owner_peer, 8, 2, true, true),
                ],
            }),
            Some(desired_generation),
        )
        .await;

    let peer_key = key(peer_addr);
    let accepted_peer = manager
        .peers
        .get(&peer_key)
        .expect("queued desired-generation dynamic peer must be created");
    assert_eq!(
        accepted_peer.transport_config.tcp_ao.as_ref(),
        Some(&expected_keyring),
        "accepted selection metadata must update the configured direct-owner keyring without replacing its secrets"
    );
    assert_eq!(
        accepted_peer.tcp_ao_rotation, selection_status,
        "a desired-generation accept must retain the in-progress global rotation truth"
    );

    accepted_peer.handle.abort_for_transport_safety();
    drop(client);
}

#[tokio::test]
async fn inbound_link_local_is_not_accepted_as_dynamic_peer() {
    // ADR-0069: a link-local inbound that matches no configured scoped peer must
    // be dropped, not promoted to a dynamic peer. Dynamic peers are keyed by
    // bare address (`PeerKey::new(ip, None)`), so accepting a `fe80::` source
    // would create an unscoped link-local peer and re-introduce the RFC 4007
    // scope ambiguity that scoped static peers exist to remove. The dynamic
    // range below covers `fe80::/10`, so without the guard this inbound would
    // succeed — the guard must reject it first.
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut config = make_dynamic_manager_config();
    config.dynamic_neighbors = vec![crate::config::DynamicNeighborConfig {
        prefix: "fe80::/10".to_string(),
        peer_group: "ix-members".to_string(),
        remote_asn: 0,
        description: Some("ll-auto".to_string()),
        tcp_ao: None,
    }];
    let mut mgr = PeerManager::new_with_config(
        rx,
        mpsc::unbounded_channel().1,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
        None,
        config,
    );

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server_stream, _remote_addr) = listener.accept().await.unwrap();
    let client_stream = client.await.unwrap();

    let link_local: IpAddr = "fe80::1".parse().unwrap();
    mgr.handle_inbound(server_stream, sock(link_local), None, None)
        .await;

    assert_eq!(
        mgr.dynamic_peer_count, 0,
        "link-local inbound must not create a dynamic peer"
    );
    assert!(
        mgr.peers.is_empty(),
        "link-local inbound must not be added to the peer table"
    );

    drop(client_stream);
}

#[tokio::test]
async fn dynamic_peer_auto_removal_drains_pending_inbound_candidate() {
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let primary = Arc::new(FakePeerCounters::default());
    let pending = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer_with_asn(
        &mut mgr,
        peer_addr,
        65002,
        fake_peer_handle(
            peer_addr,
            SessionState::Established,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            primary,
        ),
        false,
    );
    mgr.peers.get_mut(&key(peer_addr)).unwrap().is_dynamic = true;
    mgr.dynamic_peer_count = 1;
    attach_test_pending_inbound(
        &mut mgr,
        peer_addr,
        fake_peer_handle(
            peer_addr,
            SessionState::OpenConfirm,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            pending.clone(),
        ),
        2,
    );

    mgr.handle_session_notification(SessionNotification::BackToIdle {
        session_id: 1,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr,
    })
    .await;

    wait_counter(&pending.shutdown, 1).await;
    assert!(mgr.peers.is_empty());
    assert_eq!(mgr.dynamic_peer_count, 0);
    assert!(mgr.peer_key_for_session(1).is_none());
    assert!(mgr.peer_key_for_session(2).is_none());
}

#[tokio::test]
async fn dead_lettered_pending_survives_dynamic_peer_auto_removal_and_re_establish() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new_with_config(
        rx,
        mpsc::unbounded_channel().1,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
        None,
        make_dynamic_manager_config(),
    );

    // First incarnation: accept the dynamic peer, then mark it as
    // carrying both unfired hot-apply flags. We set the flags
    // directly on the ManagedPeer rather than driving a path that
    // sets them — the regression covered here is the BackToIdle
    // → handle_inbound carry, not the flag-setting paths (which
    // are covered by `pending_refresh_re_arms_when_peer_still_not_established`).
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server_stream, remote_addr) = listener.accept().await.unwrap();
    let client_stream = client.await.unwrap();
    let peer_addr = remote_addr.ip();

    mgr.handle_inbound(server_stream, sock(peer_addr), None, None)
        .await;
    assert_eq!(mgr.dynamic_peer_count, 1);

    let managed = mgr.peers.get_mut(&key(peer_addr)).unwrap();
    managed.pending_refresh = true;
    managed.pending_export_apply = true;

    // Tear down — peer auto-removes, flags should land in the
    // dead-letter side table rather than evaporating.
    let session_id = mgr.peers.get(&key(peer_addr)).unwrap().session_id;
    mgr.handle_session_notification(SessionNotification::BackToIdle {
        session_id,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr,
    })
    .await;
    assert_eq!(mgr.dynamic_peer_count, 0);
    assert!(mgr.peers.is_empty());
    let dead = mgr
        .dead_lettered_pending
        .get(&peer_addr)
        .copied()
        .expect("dead-lettered pending entry should exist after auto-removal");
    assert!(dead.refresh, "pending_refresh should be carried");
    assert!(dead.export_apply, "pending_export_apply should be carried");
    drop(client_stream);

    // Second incarnation at the same address: the new ManagedPeer
    // must inherit the dead-lettered flags, and the side-table
    // entry must drain.
    let next_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let next_listener_addr = next_listener.local_addr().unwrap();
    let next_client =
        tokio::spawn(async move { TcpStream::connect(next_listener_addr).await.unwrap() });
    let (server2, remote_addr2) = next_listener.accept().await.unwrap();
    let next_client_stream = next_client.await.unwrap();
    let peer_addr2 = remote_addr2.ip();
    // Both incarnations bind LOCALHOST so the IpAddr key (the unit
    // we dead-letter on) is identical even though the ephemeral
    // TCP port differs. Pin the precondition explicitly so any
    // future change that diverges the bind address gets caught.
    assert_eq!(
        peer_addr2, peer_addr,
        "test relies on both incarnations sharing an IpAddr key"
    );

    mgr.handle_inbound(server2, sock(peer_addr2), None, None)
        .await;

    let managed2 = mgr.peers.get(&key(peer_addr2)).expect("re-established");
    assert!(
        managed2.pending_refresh,
        "new ManagedPeer must inherit pending_refresh from dead-letter table"
    );
    assert!(
        managed2.pending_export_apply,
        "new ManagedPeer must inherit pending_export_apply from dead-letter table"
    );
    assert!(
        !mgr.dead_lettered_pending.contains_key(&peer_addr2),
        "dead-letter entry must drain on restore"
    );
    drop(next_client_stream);
}

#[tokio::test]
async fn dead_lettered_gshut_survives_dynamic_peer_auto_removal_and_re_establish() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new_with_config(
        rx,
        mpsc::unbounded_channel().1,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
        None,
        make_dynamic_manager_config(),
    );

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server_stream, remote_addr) = listener.accept().await.unwrap();
    let client_stream = client.await.unwrap();
    let peer_addr = remote_addr.ip();

    mgr.handle_inbound(server_stream, sock(peer_addr), None, None)
        .await;
    assert_eq!(mgr.dynamic_peer_count, 1);
    mgr.peers
        .get_mut(&key(peer_addr))
        .expect("dynamic peer present")
        .advertise_graceful_shutdown = true;

    let session_id = mgr.peers.get(&key(peer_addr)).unwrap().session_id;
    mgr.handle_session_notification(SessionNotification::BackToIdle {
        session_id,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr,
    })
    .await;
    assert!(mgr.peers.is_empty());
    let dead = mgr
        .dead_lettered_pending
        .get(&peer_addr)
        .copied()
        .expect("GShut-only dead-letter entry should be preserved");
    assert!(
        dead.graceful_shutdown,
        "GShut toggle should be carried even when no pending policy flags exist"
    );
    assert!(!dead.refresh);
    assert!(!dead.export_apply);
    drop(client_stream);

    let next_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let next_listener_addr = next_listener.local_addr().unwrap();
    let next_client =
        tokio::spawn(async move { TcpStream::connect(next_listener_addr).await.unwrap() });
    let (server2, remote_addr2) = next_listener.accept().await.unwrap();
    let next_client_stream = next_client.await.unwrap();
    let peer_addr2 = remote_addr2.ip();
    assert_eq!(
        peer_addr2, peer_addr,
        "test relies on both incarnations sharing an IpAddr key"
    );

    mgr.handle_inbound(server2, sock(peer_addr2), None, None)
        .await;

    let managed2 = mgr.peers.get(&key(peer_addr2)).expect("re-established");
    assert!(
        managed2.advertise_graceful_shutdown,
        "new dynamic ManagedPeer must inherit advertise_graceful_shutdown"
    );
    assert!(
        !managed2.pending_refresh && !managed2.pending_export_apply,
        "GShut-only restore must not synthesize policy retry flags"
    );
    assert!(
        !mgr.dead_lettered_pending.contains_key(&peer_addr2),
        "dead-letter entry must drain on restore"
    );
    drop(next_client_stream);
}

#[tokio::test]
async fn dead_lettered_pending_over_cap_evicts_oldest_entry() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut config = make_dynamic_manager_config();
    config.global.dynamic_neighbor_limit = Some(2);
    let mut mgr = PeerManager::new_with_config(
        rx,
        mpsc::unbounded_channel().1,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
        None,
        config,
    );
    let counters = Arc::new(FakePeerCounters::default());
    let first = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let second = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
    let third = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3));

    for addr in [first, second, third] {
        insert_test_managed_peer(
            &mut mgr,
            addr,
            fake_peer_handle(addr, SessionState::Established, None, counters.clone()),
            true,
        );
        mgr.dead_letter_pending_for(addr);
    }

    assert!(
        !mgr.dead_lettered_pending.contains_key(&first),
        "oldest pending entry should be evicted at cap"
    );
    assert!(
        mgr.dead_lettered_pending.contains_key(&second),
        "newer pending entry should be retained"
    );
    assert!(
        mgr.dead_lettered_pending.contains_key(&third),
        "newly inserted pending entry should be retained"
    );
}
