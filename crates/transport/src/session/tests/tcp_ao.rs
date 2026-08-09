use super::*;

#[test]
fn recreated_active_session_starts_at_committed_tcp_ao_generation() {
    let peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    let config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, _rib_rx) = mpsc::channel(8);
    let generation = crate::TcpAoRotationGeneration::new(7).unwrap();
    let session = PeerSession::new_at_tcp_ao_generation(
        config,
        BgpMetrics::new(),
        cmd_rx,
        rib_tx,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        SessionIdentity::default(),
        generation,
    );
    assert_eq!(session.tcp_ao_generation, generation);
}

#[test]
fn disconnected_tcp_ao_deletion_commits_exact_metadata_and_is_idempotent() {
    let (mut session, deletion) = tcp_ao_deletion_test_fixture();
    session.apply_tcp_ao_delete(&deletion).unwrap();
    assert_eq!(session.tcp_ao_generation, deletion.generation);
    assert_eq!(session.config.tcp_ao.as_ref().unwrap().0.len(), 1);
    let expected_metadata = super::tcp_ao_key_metadata(&session.config, None, None);
    assert!(session.tcp_ao_key_metadata == expected_metadata);

    session.apply_tcp_ao_delete(&deletion).unwrap();
    assert_eq!(session.tcp_ao_generation, deletion.generation);
    assert_eq!(session.config.tcp_ao.as_ref().unwrap().0.len(), 1);
    assert_eq!(session.tcp_ao_key_metadata.len(), 1);
}

#[tokio::test]
async fn connected_tcp_ao_deletion_preserves_session_on_current_rnext_refusal() {
    let (mut session, deletion) = tcp_ao_deletion_test_fixture();
    install_test_tcp_stream(&mut session).await;
    let original_metadata = session.tcp_ao_key_metadata.clone();
    let result = session.apply_tcp_ao_delete_with(
        &deletion,
        |_stream, current, desired, _connected_peer| {
            assert_eq!(current[0].keyring.0.len(), 2);
            assert!(current[0].keyring.0[0].deprecated);
            assert_eq!(desired[0].keyring.0.len(), 1);
            Err(PeerCommandError::CommandFailed(
                "refusing to delete a Current/RNext MKT".to_string(),
            ))
        },
    );

    assert!(matches!(result, Err(PeerCommandError::CommandFailed(_))));
    assert!(session.read_half.is_some());
    assert_eq!(
        session.tcp_ao_generation,
        crate::TcpAoRotationGeneration::STARTUP
    );
    assert_eq!(session.config.tcp_ao.as_ref().unwrap().0.len(), 2);
    assert!(session.tcp_ao_key_metadata == original_metadata);
}

#[tokio::test]
async fn mutation_started_tcp_ao_deletion_closes_and_reset_discards_replacement_stream() {
    let (mut session, deletion) = tcp_ao_deletion_test_fixture();
    install_test_tcp_stream(&mut session).await;
    let result = session.apply_tcp_ao_delete_with(
        &deletion,
        |_stream, _current, _desired, _connected_peer| {
            Err(PeerCommandError::TcpAoMutationFailed(
                "DEL_KEY began before inventory verification failed".to_string(),
            ))
        },
    );
    assert!(matches!(
        result,
        Err(PeerCommandError::TcpAoMutationFailed(_))
    ));
    assert!(session.read_half.is_none());
    assert_eq!(
        session.tcp_ao_generation,
        crate::TcpAoRotationGeneration::STARTUP
    );
    assert_eq!(session.config.tcp_ao.as_ref().unwrap().0.len(), 2);

    install_test_tcp_stream(&mut session).await;
    let (reply, applied) = oneshot::channel();
    assert_eq!(
        session
            .handle_command(PeerCommand::ResetTcpAoAfterFailedMutation {
                desired_generation: deletion.generation,
                reply,
            })
            .await,
        ControlFlow::Continue(())
    );
    applied.await.unwrap();
    assert!(session.read_half.is_none());
}

#[test]
fn disconnected_active_session_accepts_only_immediate_append_only_generation() {
    let peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    let mut config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    let old = crate::TcpAoConfig {
        key: "old-secret".into(),
        send_id: 1,
        recv_id: 11,
        algorithm: crate::TcpAoAlgorithm::HmacSha256,
        preferred: false,
        deprecated: false,
    };
    config.tcp_ao = Some(crate::TcpAoKeyring(vec![old.clone()]));
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, _rib_rx) = mpsc::channel(8);
    let mut session = PeerSession::new_at_tcp_ao_generation(
        config,
        BgpMetrics::new(),
        cmd_rx,
        rib_tx,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        SessionIdentity::default(),
        crate::TcpAoRotationGeneration::STARTUP,
    );
    let mut successor = old.clone();
    successor.key = "successor-secret".into();
    successor.send_id = 2;
    successor.recv_id = 12;
    let generation_two = crate::TcpAoRotationGeneration::new(2).unwrap();
    session
        .apply_tcp_ao_add_only(crate::TcpAoSessionGeneration {
            generation: generation_two,
            active_keyring: Some(crate::TcpAoKeyring(vec![old.clone(), successor])),
            accepted_owners: Vec::new().into(),
        })
        .unwrap();
    assert_eq!(session.tcp_ao_generation, generation_two);
    assert_eq!(session.config.tcp_ao.as_ref().unwrap().0.len(), 2);

    let skipped = session.apply_tcp_ao_add_only(crate::TcpAoSessionGeneration {
        generation: crate::TcpAoRotationGeneration::new(4).unwrap(),
        active_keyring: Some(crate::TcpAoKeyring(vec![old.clone()])),
        accepted_owners: Vec::new().into(),
    });
    assert!(skipped.is_err());

    let removal = session.apply_tcp_ao_add_only(crate::TcpAoSessionGeneration {
        generation: crate::TcpAoRotationGeneration::new(3).unwrap(),
        active_keyring: Some(crate::TcpAoKeyring(vec![old])),
        accepted_owners: Vec::new().into(),
    });
    assert!(removal.is_err());
    assert_eq!(session.tcp_ao_generation, generation_two);
}

#[test]
fn disconnected_protected_session_cannot_advance_without_active_owner_inventory() {
    let peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    let mut config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    config.tcp_ao = Some(crate::TcpAoKeyring(vec![crate::TcpAoConfig {
        key: "old-secret".into(),
        send_id: 1,
        recv_id: 11,
        algorithm: crate::TcpAoAlgorithm::HmacSha256,
        preferred: false,
        deprecated: false,
    }]));
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, _rib_rx) = mpsc::channel(8);
    let mut session = PeerSession::new_at_tcp_ao_generation(
        config,
        BgpMetrics::new(),
        cmd_rx,
        rib_tx,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        SessionIdentity::default(),
        crate::TcpAoRotationGeneration::STARTUP,
    );
    let result = session.apply_tcp_ao_add_only(crate::TcpAoSessionGeneration {
        generation: crate::TcpAoRotationGeneration::new(2).unwrap(),
        active_keyring: None,
        accepted_owners: Vec::new().into(),
    });
    assert!(result.is_err());
    assert_eq!(
        session.tcp_ao_generation,
        crate::TcpAoRotationGeneration::STARTUP
    );
    assert!(session.config.tcp_ao.is_some());
}

#[tokio::test]
async fn tcp_ao_generation_does_not_advance_past_inflight_old_inventory_connect() {
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 30;
    let mut config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    let old = crate::TcpAoConfig {
        key: "old-secret".into(),
        send_id: 1,
        recv_id: 11,
        algorithm: crate::TcpAoAlgorithm::HmacSha256,
        preferred: false,
        deprecated: false,
    };
    config.tcp_ao = Some(crate::TcpAoKeyring(vec![old.clone()]));
    let (_cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, _rib_rx) = mpsc::channel(8);
    let mut session = PeerSession::new_at_tcp_ao_generation(
        config,
        BgpMetrics::new(),
        cmd_rx,
        rib_tx,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        SessionIdentity::default(),
        crate::TcpAoRotationGeneration::STARTUP,
    );
    session.connect_task = Some(tokio::spawn(async {
        std::future::pending::<ConnectResult>().await
    }));
    let mut successor = old.clone();
    successor.key = "successor-secret".into();
    successor.send_id = 2;
    successor.recv_id = 12;
    let result = session.apply_tcp_ao_add_only(crate::TcpAoSessionGeneration {
        generation: crate::TcpAoRotationGeneration::new(2).unwrap(),
        active_keyring: Some(crate::TcpAoKeyring(vec![old, successor])),
        accepted_owners: Vec::new().into(),
    });
    assert!(result.is_err());
    assert_eq!(
        session.tcp_ao_generation,
        crate::TcpAoRotationGeneration::STARTUP
    );
    assert_eq!(session.config.tcp_ao.as_ref().unwrap().0.len(), 1);
    assert!(session.connect_task.is_some());
    session.close_tcp();
}

#[cfg(target_os = "linux")]
#[test]
fn active_open_second_key_install_failure_abandons_socket_before_connect() {
    use socket2::Socket;
    use std::cell::{Cell, RefCell};
    use std::io::Read as _;
    use std::time::Duration;

    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    let mut config = TransportConfig::new(peer_config, "192.0.2.2:179".parse().unwrap());
    config.tcp_ao = Some(crate::TcpAoKeyring(vec![
        crate::TcpAoConfig {
            key: "selected".into(),
            send_id: 1,
            recv_id: 11,
            algorithm: crate::TcpAoAlgorithm::HmacSha256,
            preferred: true,
            deprecated: false,
        },
        crate::TcpAoConfig {
            key: "standby".into(),
            send_id: 2,
            recv_id: 12,
            algorithm: crate::TcpAoAlgorithm::HmacSha256,
            preferred: false,
            deprecated: false,
        },
    ]));

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let socket = Socket::from(client);
    let installed = RefCell::new(Vec::new());
    let connect_attempts = Cell::new(0usize);
    let result = super::io::prepare_active_socket_for_test(
        socket,
        &config,
        "192.0.2.2",
        |_socket, _peer, _prefix_len, key, role| {
            installed.borrow_mut().push((key.send_id, role));
            if key.send_id == 2 {
                Err(std::io::Error::other("injected second-key failure"))
            } else {
                Ok(())
            }
        },
        |_socket, _addr| {
            connect_attempts.set(connect_attempts.get() + 1);
            Ok(())
        },
    );
    let Err(error) = result else {
        panic!("a partial TCP-AO keyring install must abandon the active-open socket");
    };

    assert_eq!(
        installed.into_inner(),
        vec![
            (1, crate::socket_opts::TcpAoSocketRole::ActiveOpen),
            (2, crate::socket_opts::TcpAoSocketRole::Listener),
        ]
    );
    assert_eq!(connect_attempts.get(), 0, "connect must not be attempted");
    assert!(error.to_string().contains("send_id=2"), "{error}");
    assert!(error.to_string().contains("recv_id=12"), "{error}");

    // The peer observes EOF on this exact connection, proving the consumed
    // partially programmed socket was closed rather than retained for a
    // plaintext retry. The timeout keeps a retained descriptor from hanging
    // the suite indefinitely.
    let mut byte = [0u8; 1];
    assert_eq!(peer.read(&mut byte).unwrap(), 0);
}

#[tokio::test]
async fn tcp_ao_query_refreshes_degraded_cumulative_counters() {
    let mut session = tcp_ao_query_test_session().await;
    session.refresh_tcp_ao_info_with(|_| Ok(tcp_ao_snapshot(43, 1)));
    let snapshot = session.tcp_ao_info.unwrap();
    assert_eq!(snapshot.pkt_good, 43);
    assert_eq!(snapshot.pkt_bad, 1);
}

#[tokio::test]
async fn tcp_ao_disconnect_physically_clears_socket_selected_owner_and_observation_baseline() {
    let mut session = accepted_query_test_session(None).await;
    // A disconnect must clear only evidence tied to the dead socket. Clearing
    // either durable field below would make an identical-generation retry lose
    // its candidate or misclassify an accepted dynamic session as active-open.
    let selected_owner = crate::listener::TcpAoSelectedOwner {
        owner: crate::TcpAoListenerOwnerKind::Dynamic,
        peer: "127.0.0.0".parse().unwrap(),
        prefix_len: 24,
    };
    let pending = crate::TcpAoSessionSelection {
        generation: crate::TcpAoRotationGeneration::new(2).unwrap(),
        active_keyring: None,
        accepted_owners: vec![crate::TcpAoRotationOwner {
            owner: crate::TcpAoListenerOwnerKind::Dynamic,
            peer: selected_owner.peer,
            prefix_len: selected_owner.prefix_len,
            keyring: crate::TcpAoKeyring(vec![crate::TcpAoConfig {
                key: "retained-selection-secret".into(),
                send_id: 7,
                recv_id: 9,
                algorithm: crate::TcpAoAlgorithm::HmacSha256,
                preferred: true,
                deprecated: false,
            }]),
        }]
        .into(),
        accepted_selected_owner: Some(selected_owner),
    };
    session.tcp_ao_stream_was_accepted = true;
    session.tcp_ao_accept_only_session = true;
    session.tcp_ao_selected_owner = Some(selected_owner);
    session.tcp_ao_pending_selection = Some(pending.clone());
    session.tcp_ao_successor_pkt_good_baseline = Some(41);
    session.tcp_ao_selection_observed = true;

    session.close_tcp();

    assert!(!session.tcp_ao_stream_was_accepted);
    assert!(session.tcp_ao_accept_only_session);
    assert!(session.tcp_ao_selected_owner.is_none());
    assert_eq!(session.tcp_ao_pending_selection.as_ref(), Some(&pending));
    assert!(session.tcp_ao_successor_pkt_good_baseline.is_none());
    assert!(!session.tcp_ao_selection_observed);
}

#[tokio::test]
async fn tcp_ao_query_clears_stale_snapshot_and_recovers() {
    let mut session = tcp_ao_query_test_session().await;
    session.tcp_ao_info = Some(tcp_ao_snapshot(12, 0));
    session.refresh_tcp_ao_info_with(|_| {
        Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "TCP-AO INFO and key inventory remained inconsistent",
        ))
    });
    assert!(session.tcp_ao_info.is_none());

    session.refresh_tcp_ao_info_with(|_| Ok(tcp_ao_snapshot(44, 0)));
    assert_eq!(session.tcp_ao_info.as_ref().unwrap().pkt_good, 44);
    assert!(session.tcp_ao_info.as_ref().unwrap().keys[0].preferred);
}

#[tokio::test]
async fn accepted_tcp_ao_snapshot_seeds_durable_refresh_across_failure_and_recovery() {
    let mut initial = tcp_ao_snapshot(20, 0);
    initial.keys[0].preferred = true;
    let mut session = accepted_query_test_session(Some(initial)).await;
    assert!(session.config.tcp_ao.is_none());
    assert!(session.tcp_ao_protected);

    session.refresh_tcp_ao_info_with(|_| Ok(tcp_ao_snapshot(43, 0)));
    assert_eq!(session.tcp_ao_info.as_ref().unwrap().pkt_good, 43);
    assert!(session.tcp_ao_info.as_ref().unwrap().keys[0].preferred);
    session.refresh_tcp_ao_info_with(|_| Err(std::io::Error::other("inspection failed")));
    assert!(session.tcp_ao_info.is_none());
    assert!(
        session.tcp_ao_protected,
        "inspection failure must not erase protection identity"
    );
    session.refresh_tcp_ao_info_with(|_| Ok(tcp_ao_snapshot(44, 0)));
    assert_eq!(session.tcp_ao_info.as_ref().unwrap().pkt_good, 44);
    assert!(session.tcp_ao_info.as_ref().unwrap().keys[0].preferred);
}

#[tokio::test]
async fn accepted_tcp_ao_refresh_restores_overlapping_owner_selectors_after_host_normalization() {
    let connected: IpAddr = "127.0.0.1".parse().unwrap();
    let mut initial = tcp_ao_snapshot(20, 0);
    initial.current_key = 8;
    initial.rnext_key = 12;
    initial.keys = vec![
        tcp_ao_key_state("127.0.0.0", 24, 7, 9, false, false, false, false, 20),
        tcp_ao_key_state("127.0.0.1", 32, 8, 10, true, false, false, true, 20),
        tcp_ao_key_state("127.0.0.1", 32, 11, 12, false, true, true, false, 20),
    ];
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    let mut config = TransportConfig::new(peer_config, "127.0.0.1:179".parse().unwrap());
    config.tcp_ao = Some(crate::TcpAoKeyring(vec![
        crate::TcpAoConfig {
            key: "static-current".into(),
            send_id: 8,
            recv_id: 10,
            algorithm: crate::TcpAoAlgorithm::HmacSha256,
            preferred: false,
            deprecated: true,
        },
        crate::TcpAoConfig {
            key: "static-selected".into(),
            send_id: 11,
            recv_id: 12,
            algorithm: crate::TcpAoAlgorithm::HmacSha256,
            preferred: true,
            deprecated: false,
        },
    ]));
    let mut session = accepted_query_test_session_with_config(config, Some(initial)).await;

    let mut refreshed = tcp_ao_snapshot(43, 0);
    refreshed.current_key = 8;
    refreshed.rnext_key = 12;
    refreshed.keys = vec![
        tcp_ao_key_state("127.0.0.1", 32, 7, 9, false, false, false, false, 43),
        tcp_ao_key_state("127.0.0.1", 32, 8, 10, true, false, false, false, 43),
        tcp_ao_key_state("127.0.0.1", 32, 11, 12, false, true, false, false, 43),
    ];
    session.refresh_tcp_ao_info_with(|_| Ok(refreshed));

    let keys = &session.tcp_ao_info.as_ref().unwrap().keys;
    let covering = keys.iter().find(|key| key.send_id == 7).unwrap();
    assert_eq!(covering.peer, "127.0.0.0".parse::<IpAddr>().unwrap());
    assert_eq!(covering.prefix_len, 24);
    let deprecated_current = keys.iter().find(|key| key.send_id == 8).unwrap();
    assert_eq!(deprecated_current.peer, connected);
    assert_eq!(deprecated_current.prefix_len, 32);
    assert!(deprecated_current.is_current);
    assert!(deprecated_current.deprecated);
    let selected_rnext = keys.iter().find(|key| key.send_id == 11).unwrap();
    assert_eq!(selected_rnext.peer, connected);
    assert_eq!(selected_rnext.prefix_len, 32);
    assert!(selected_rnext.is_rnext);
    assert!(selected_rnext.preferred);
}

#[tokio::test]
async fn plaintext_accepted_session_does_not_inherit_tcp_ao_protection() {
    let mut session = accepted_query_test_session(None).await;
    assert!(!session.tcp_ao_protected);
    session.refresh_tcp_ao_info_with(|_| -> std::io::Result<crate::TcpAoInfoSnapshot> {
        panic!("plaintext accepted session must not inspect TCP_AO_INFO")
    });
    assert!(session.tcp_ao_info.is_none());
}

#[test]
fn non_tcp_ao_query_does_not_invoke_inspector() {
    let mut session = make_test_session(65001, 65002);
    session.tcp_ao_info = Some(tcp_ao_snapshot(12, 0));
    session.refresh_tcp_ao_info_with(|_| -> std::io::Result<crate::TcpAoInfoSnapshot> {
        panic!("non-AO session must not inspect TCP_AO_INFO")
    });
    assert!(session.tcp_ao_info.is_none());
}
