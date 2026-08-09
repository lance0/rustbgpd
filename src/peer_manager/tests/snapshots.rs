use super::*;

fn warm_checkpoint_peer_handle(response: Option<WarmCheckpointSessionState>) -> PeerHandle {
    use rustbgpd_transport::PeerCommand;

    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let task = tokio::spawn(async move {
        let mut held_replies = Vec::new();
        while let Some(cmd) = session_rx.recv().await {
            match cmd {
                PeerCommand::QueryWarmCheckpointState { reply } => {
                    if let Some(state) = response.clone() {
                        let _ = reply.send(state);
                    } else {
                        held_replies.push(reply);
                    }
                }
                PeerCommand::Shutdown | PeerCommand::Stop { .. } => break,
                _ => {}
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(session_tx, task)
}

#[tokio::test]
async fn warm_checkpoint_capture_uses_live_actor_config_identity() {
    let mut mgr = test_peer_manager();
    let startup = mgr.current_config.effective_redacted_toml().unwrap();
    mgr.current_config.global.honor_blackhole = true;
    let addr: IpAddr = "10.0.0.2".parse().unwrap();
    let mut neighbor = config_neighbor(addr, 65002);
    neighbor.gr_restart_time = Some(17);
    mgr.current_config.neighbors.push(neighbor);

    let capture = mgr.query_warm_checkpoint_capture().await.unwrap();
    assert_ne!(capture.effective_config_toml, startup);
    assert!(
        capture
            .effective_config_toml
            .contains("honor_blackhole = true")
    );
    assert_eq!(capture.restart_time_secs, Some(17));
}

#[tokio::test]
async fn warm_checkpoint_rejects_sighup_desired_live_global_identity_drift() {
    let mut mgr = test_peer_manager();

    // SIGHUP accepts restart-required global fields into the desired runtime
    // snapshot, but the listener/session actors retain their boot identity.
    mgr.current_config.global.asn = 65123;
    let error = mgr.query_warm_checkpoint_capture().await.unwrap_err();
    assert!(error.contains("restart-required local identity"), "{error}");
    assert!(error.contains("65123/10.0.0.1"), "{error}");
    assert!(error.contains("65001/10.0.0.1"), "{error}");

    mgr.current_config.global.asn = 65001;
    mgr.current_config.global.router_id = "192.0.2.99".to_string();
    let error = mgr.query_warm_checkpoint_capture().await.unwrap_err();
    assert!(error.contains("restart-required local identity"), "{error}");
    assert!(error.contains("65001/192.0.2.99"), "{error}");
    assert!(error.contains("65001/10.0.0.1"), "{error}");
}

#[tokio::test]
async fn warm_checkpoint_session_query_returns_current_negotiated_identity() {
    let mut mgr = test_peer_manager();
    let addr: IpAddr = "10.0.0.2".parse().unwrap();
    insert_test_managed_peer(
        &mut mgr,
        addr,
        warm_checkpoint_peer_handle(Some(eligible_warm_checkpoint_state())),
        false,
    );
    let mut neighbor = config_neighbor(addr, 65002);
    neighbor.graceful_restart = Some(true);
    neighbor.gr_restart_time = Some(120);
    mgr.current_config.neighbors.push(neighbor);

    let capture = mgr.query_warm_checkpoint_capture().await.unwrap();
    assert_eq!(capture.local_asn, 65001);
    assert_eq!(capture.local_router_id, Ipv4Addr::new(10, 0, 0, 1));
    assert!(capture.effective_config_toml.contains("asn = 65001"));
    assert_eq!(capture.restart_time_secs, Some(120));
    let sessions = capture.sessions;
    assert_eq!(sessions.len(), 1);
    let session = &sessions[0];
    assert_eq!(session.peer, key(addr));
    assert_eq!(session.session_id, 1);
    assert_eq!(session.peer_asn, 65002);
    assert_eq!(session.peer_router_id, Ipv4Addr::new(10, 0, 0, 2));
    assert_eq!(
        session.add_path_receive_families,
        vec![(Afi::Ipv4, Safi::Unicast)]
    );
    assert_eq!(
        session.canonical_import_policy,
        b"rustbgpd/policy-chain/warm-checkpoint/v1/implicit-permit\n"
    );
}

#[tokio::test]
async fn warm_checkpoint_session_query_rejects_pending_collision() {
    let mut mgr = test_peer_manager();
    let addr: IpAddr = "10.0.0.2".parse().unwrap();
    insert_test_managed_peer(
        &mut mgr,
        addr,
        warm_checkpoint_peer_handle(Some(eligible_warm_checkpoint_state())),
        false,
    );
    attach_test_pending_inbound(
        &mut mgr,
        addr,
        warm_checkpoint_peer_handle(Some(eligible_warm_checkpoint_state())),
        2,
    );

    let error = mgr.query_warm_checkpoint_capture().await.unwrap_err();
    assert!(error.contains("unresolved collision candidate"), "{error}");
}

#[tokio::test(start_paused = true)]
async fn warm_checkpoint_session_query_timeout_rejects_complete_snapshot() {
    let mut mgr = test_peer_manager();
    let addr: IpAddr = "10.0.0.2".parse().unwrap();
    insert_test_managed_peer(&mut mgr, addr, warm_checkpoint_peer_handle(None), false);

    let error = mgr.query_warm_checkpoint_capture().await.unwrap_err();
    assert!(error.contains("bounded checkpoint query"), "{error}");
}

#[tokio::test]
async fn warm_checkpoint_session_query_skips_unusable_gr_sessions() {
    let mut mgr = test_peer_manager();
    let no_family_addr: IpAddr = "10.0.0.2".parse().unwrap();
    let zero_restart_addr: IpAddr = "10.0.0.3".parse().unwrap();
    let mut no_family = eligible_warm_checkpoint_state();
    no_family.peer_gr_families.clear();
    let mut zero_restart = eligible_warm_checkpoint_state();
    zero_restart.peer_gr_restart_time = 0;
    insert_test_managed_peer(
        &mut mgr,
        no_family_addr,
        warm_checkpoint_peer_handle(Some(no_family)),
        false,
    );
    insert_test_managed_peer(
        &mut mgr,
        zero_restart_addr,
        warm_checkpoint_peer_handle(Some(zero_restart)),
        false,
    );

    assert!(
        mgr.query_warm_checkpoint_capture()
            .await
            .unwrap()
            .sessions
            .is_empty()
    );
}

#[tokio::test]
async fn unavailable_session_authentication_uses_durable_managed_protection() {
    // Mutation-red for min_hold_time: deleting snapshot propagation yields
    // None instead of the configured 30.
    let mut mgr = test_peer_manager();
    let addr: IpAddr = "10.0.0.44".parse().unwrap();
    let handle = fake_peer_handle(
        addr,
        SessionState::Idle,
        None,
        Arc::new(FakePeerCounters::default()),
    );
    insert_test_managed_peer(&mut mgr, addr, handle, false);
    let peer_key = key(addr);

    {
        let managed = mgr.peers.get_mut(&peer_key).unwrap();
        managed.is_dynamic = true;
        managed.tcp_ao_protected = true;
        managed.transport_config.peer.min_hold_time = Some(30);
        assert!(managed.transport_config.tcp_ao.is_none());
        let info = super::snapshot::build_peer_info(&peer_key, managed, None, false);
        assert_eq!(info.authentication, "tcp_ao");
        assert_eq!(info.min_hold_time, Some(30));
        assert!(info.tcp_ao_info.is_none());
        assert!(info.stale);

        managed.is_dynamic = false;
        managed.tcp_ao_protected = true;
        assert_eq!(
            super::snapshot::build_peer_info(&peer_key, managed, None, false).authentication,
            "tcp_ao"
        );

        managed.tcp_ao_protected = false;
        assert_eq!(
            super::snapshot::build_peer_info(&peer_key, managed, None, false).authentication,
            "plaintext"
        );

        managed.transport_config.md5_password = Some("test-password".into());
        assert_eq!(
            super::snapshot::build_peer_info(&peer_key, managed, None, false).authentication,
            "md5"
        );
    }

    let managed = mgr.peers.remove(&peer_key).unwrap();
    managed.handle.shutdown().await.unwrap().unwrap();
}

/// Load-bearing: sourcing this from unavailable session state, or omitting the
/// `ManagedPeer` copy, makes the asserted true intent disappear.
#[tokio::test]
async fn unavailable_session_preserves_graceful_shutdown_advertise_intent() {
    let mut mgr = test_peer_manager();
    let addr: IpAddr = "10.0.0.45".parse().unwrap();
    let handle = fake_peer_handle(
        addr,
        SessionState::Idle,
        None,
        Arc::new(FakePeerCounters::default()),
    );
    insert_test_managed_peer(&mut mgr, addr, handle, false);
    let peer_key = key(addr);
    let managed = mgr.peers.get_mut(&peer_key).unwrap();
    managed.advertise_graceful_shutdown = true;

    let info = super::snapshot::build_peer_info(&peer_key, managed, None, false);
    assert!(info.graceful_shutdown_advertise_intent);
    assert!(info.stale);

    let managed = mgr.peers.remove(&peer_key).unwrap();
    managed.handle.shutdown().await.unwrap().unwrap();
}

fn effective_posture(
    info: &rustbgpd_api::peer_types::PeerInfo,
) -> (bool, bool, bool, Option<IpAddr>) {
    (
        info.next_hop_ownership_strict_peer,
        info.interpret_rfc1997,
        info.rs_control_communities,
        info.orr_vantage,
    )
}

const EFFECTIVE_POSTURE_TOML: &str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"
[peer_groups.inherited_rs]
route_server_client = true
next_hop_ownership = "strict_peer"
interpret_rfc1997 = true
rs_control_communities = false
[peer_groups.rr_clients]
route_reflector_client = true
orr_vantage = "192.0.2.7"
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
route_server_client = true
[[neighbors]]
address = "10.0.0.4"
remote_asn = 65004
route_server_client = true
next_hop_ownership = "strict_peer"
interpret_rfc1997 = true
rs_control_communities = false
[[neighbors]]
address = "10.0.0.5"
remote_asn = 65005
peer_group = "inherited_rs"
[[neighbors]]
address = "10.0.0.6"
remote_asn = 65001
peer_group = "rr_clients"
[[dynamic_neighbors]]
prefix = "127.0.0.0/8"
peer_group = "inherited_rs"
remote_asn = 0
"#;

/// Load-bearing snapshot proof across the supported resolution shapes:
/// deleting any `ManagedPeer.transport_config` posture assignment makes at
/// least one exact tuple fall back to the `PeerInfo` fixture defaults.
#[tokio::test]
async fn effective_posture_snapshot_reports_resolved_static_values() {
    let config = load_test_config(EFFECTIVE_POSTURE_TOML);
    let mut mgr = test_peer_manager();
    for (index, resolved) in config.resolved_neighbors().unwrap().into_iter().enumerate() {
        mgr.install_established_policy_test_peer(resolved, index as u64 + 1);
    }

    let snapshot = |address: &str| {
        let peer = key(address.parse().unwrap());
        super::snapshot::build_peer_info(&peer, mgr.peers.get(&peer).unwrap(), None, false)
    };
    let cases = [
        ("10.0.0.2", (false, true, false, None), "plain eBGP"),
        ("10.0.0.3", (false, false, true, None), "RS defaults"),
        ("10.0.0.4", (true, true, false, None), "neighbor override"),
        ("10.0.0.5", (true, true, false, None), "group inheritance"),
        (
            "10.0.0.6",
            (false, true, false, Some("192.0.2.7".parse().unwrap())),
            "ORR inheritance",
        ),
    ];
    for (address, expected, shape) in cases {
        assert_eq!(effective_posture(&snapshot(address)), expected, "{shape}");
    }

    for (_, managed) in mgr.peers.drain() {
        managed.handle.shutdown().await.unwrap().unwrap();
    }
}

/// Load-bearing accepted-dynamic parity proof: dropping resolved posture while
/// retaining the live inbound child makes its snapshot differ from the static
/// member inheriting the same peer group.
#[tokio::test]
async fn effective_posture_snapshot_keeps_dynamic_inheritance_at_static_parity() {
    let config = load_test_config(EFFECTIVE_POSTURE_TOML);
    let static_rs = config
        .resolved_neighbors()
        .unwrap()
        .into_iter()
        .find(|peer| {
            peer.transport_config.remote_addr.ip() == "10.0.0.5".parse::<IpAddr>().unwrap()
        })
        .unwrap();
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let mut mgr = PeerManager::new_with_config(
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
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server_stream, remote_addr) = listener.accept().await.unwrap();
    let client_stream = client.await.unwrap();
    mgr.handle_inbound(server_stream, sock(remote_addr.ip()), None, None)
        .await;
    mgr.install_established_policy_test_peer(static_rs, 99);

    let snapshot = |address: &str| {
        let peer = key(address.parse().unwrap());
        super::snapshot::build_peer_info(&peer, mgr.peers.get(&peer).unwrap(), None, false)
    };
    let static_rs = snapshot("10.0.0.5");
    let dynamic_rs = snapshot(&remote_addr.ip().to_string());
    assert_eq!(
        effective_posture(&static_rs),
        effective_posture(&dynamic_rs)
    );
    assert!(!static_rs.is_dynamic && dynamic_rs.is_dynamic);

    drop(client_stream);
    for (_, managed) in mgr.peers.drain() {
        managed.handle.shutdown().await.unwrap().unwrap();
    }
}

/// Load-bearing: sourcing live counts from config or deriving stale headroom
/// from zero placeholders makes at least one exact snapshot assertion fail.
#[tokio::test]
async fn max_prefix_snapshot_uses_live_accounting_and_withholds_stale_headroom() {
    let mut mgr = test_peer_manager();
    let addr: IpAddr = "10.0.0.46".parse().unwrap();
    let handle = fake_peer_handle(
        addr,
        SessionState::Idle,
        None,
        Arc::new(FakePeerCounters::default()),
    );
    insert_test_managed_peer(&mut mgr, addr, handle, false);
    let peer_key = key(addr);
    let managed = mgr.peers.get_mut(&peer_key).unwrap();
    managed.max_prefixes = Some(30);
    managed.transport_config.max_prefixes_ipv4 = Some(20);
    managed.transport_config.max_prefixes_ipv6 = Some(10);

    let mut state = policy_test_peer_state(addr, SessionState::Established);
    state.prefix_count = 11;
    state.max_prefix.prefix_count_ipv4 = 7;
    state.max_prefix.prefix_count_ipv6 = 3;
    state.max_prefix.max_prefixes = Some(25);
    state.max_prefix.max_prefixes_ipv4 = Some(15);
    state.max_prefix.max_prefixes_ipv6 = None;
    state.max_prefix.headroom = Some(14);
    state.max_prefix.headroom_ipv4 = Some(8);

    let live = super::snapshot::build_peer_info(&peer_key, managed, Some(&state), false);
    assert_eq!(
        (
            live.prefix_count,
            live.prefix_count_ipv4,
            live.prefix_count_ipv6
        ),
        (11, 7, 3)
    );
    assert_eq!(live.max_prefixes_effective, Some(25));
    assert_eq!(live.max_prefixes_ipv4_effective, Some(15));
    assert_eq!(live.max_prefixes_ipv6_effective, None);
    assert_eq!(live.max_prefix_headroom, Some(14));
    assert_eq!(live.max_prefix_headroom_ipv4, Some(8));
    assert_eq!(live.max_prefix_headroom_ipv6, None);

    let stale_info = super::snapshot::build_peer_info(&peer_key, managed, None, false);
    assert_eq!(stale_info.max_prefixes_effective, Some(30));
    assert_eq!(stale_info.max_prefixes_ipv4_effective, Some(20));
    assert_eq!(stale_info.max_prefixes_ipv6_effective, Some(10));
    assert_eq!(
        (
            stale_info.max_prefix_headroom,
            stale_info.max_prefix_headroom_ipv4,
            stale_info.max_prefix_headroom_ipv6,
        ),
        (None, None, None)
    );

    let managed = mgr.peers.remove(&peer_key).unwrap();
    managed.handle.shutdown().await.unwrap().unwrap();
}

/// Load-bearing proof: copying configured families or the `OpenConfirm` identity
/// fields when the actor snapshot is absent makes the stale assertion fail;
/// dropping the live actor projection makes the exact live assertion fail.
#[tokio::test]
async fn negotiated_snapshot_uses_only_fresh_established_actor_state() {
    let mut mgr = test_peer_manager();
    let addr: IpAddr = "10.0.0.47".parse().unwrap();
    let handle = fake_peer_handle(
        addr,
        SessionState::Idle,
        None,
        Arc::new(FakePeerCounters::default()),
    );
    insert_test_managed_peer(&mut mgr, addr, handle, false);
    let peer_key = key(addr);
    let managed = mgr.peers.get_mut(&peer_key).unwrap();
    managed.transport_config.peer.families = vec![(Afi::Ipv4, Safi::Unicast)];

    let mut state = policy_test_peer_state(addr, SessionState::Established);
    state.negotiated_hold_time = Some(90);
    state.four_octet_as = Some(true);
    state.remote_router_id = Some(Ipv4Addr::new(198, 51, 100, 1));
    state.negotiated_session = Some(rustbgpd_transport::NegotiatedSessionState {
        hold_time: 33,
        remote_router_id: Ipv4Addr::new(192, 0, 2, 7),
        four_octet_as: false,
        families: vec![(Afi::Ipv6, Safi::Unicast)],
        peer_route_refresh: true,
        peer_enhanced_route_refresh: true,
        peer_extended_message: true,
        outbound_max_message_bytes: rustbgpd_wire::EXTENDED_MAX_MESSAGE_LEN,
        graceful_restart: None,
    });

    let live = super::snapshot::build_peer_info(&peer_key, managed, Some(&state), false);
    assert_eq!(live.negotiated_session, state.negotiated_session);

    let stale_info = super::snapshot::build_peer_info(&peer_key, managed, None, false);
    assert!(stale_info.stale);
    assert!(stale_info.negotiated_session.is_none());

    state.fsm_state = SessionState::Idle;
    state.negotiated_session = None;
    let fresh_down = super::snapshot::build_peer_info(&peer_key, managed, Some(&state), false);
    assert!(!fresh_down.stale);
    assert!(fresh_down.negotiated_session.is_none());

    let managed = mgr.peers.remove(&peer_key).unwrap();
    managed.handle.shutdown().await.unwrap().unwrap();
}
