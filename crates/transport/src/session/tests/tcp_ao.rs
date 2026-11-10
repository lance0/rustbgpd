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

#[tokio::test]
async fn disconnected_tcp_ao_deletion_commits_exact_metadata_and_is_idempotent() {
    let (mut session, deletion) = tcp_ao_deletion_test_fixture();
    session.apply_tcp_ao_delete(&deletion).await.unwrap();
    assert_eq!(session.tcp_ao_generation, deletion.generation);
    assert_eq!(session.config.tcp_ao.as_ref().unwrap().0.len(), 1);
    let expected_metadata = super::tcp_ao_key_metadata(&session.config, None, None);
    assert!(session.tcp_ao_key_metadata == expected_metadata);

    session.apply_tcp_ao_delete(&deletion).await.unwrap();
    assert_eq!(session.tcp_ao_generation, deletion.generation);
    assert_eq!(session.config.tcp_ao.as_ref().unwrap().0.len(), 1);
    assert_eq!(session.tcp_ao_key_metadata.len(), 1);
}

#[tokio::test]
async fn connected_tcp_ao_deletion_preserves_session_on_current_rnext_refusal() {
    let (mut session, deletion) = tcp_ao_deletion_test_fixture();
    install_test_tcp_stream(&mut session).await;
    let original_metadata = session.tcp_ao_key_metadata.clone();
    let result = session
        .apply_tcp_ao_delete_with(&deletion, |_stream, current, desired, _connected_peer| {
            assert_eq!(current[0].keyring.0.len(), 2);
            assert!(current[0].keyring.0[0].deprecated);
            assert_eq!(desired[0].keyring.0.len(), 1);
            Err(PeerCommandError::CommandFailed(
                "refusing to delete a Current/RNext MKT".to_string(),
            ))
        })
        .await;

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
    let result = session
        .apply_tcp_ao_delete_with(&deletion, |_stream, _current, _desired, _connected_peer| {
            Err(PeerCommandError::TcpAoMutationFailed(
                "DEL_KEY began before inventory verification failed".to_string(),
            ))
        })
        .await;
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

#[tokio::test]
async fn disconnected_active_session_accepts_only_immediate_append_only_generation() {
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
        .await
        .unwrap();
    assert_eq!(session.tcp_ao_generation, generation_two);
    assert_eq!(session.config.tcp_ao.as_ref().unwrap().0.len(), 2);

    let skipped = session
        .apply_tcp_ao_add_only(crate::TcpAoSessionGeneration {
            generation: crate::TcpAoRotationGeneration::new(4).unwrap(),
            active_keyring: Some(crate::TcpAoKeyring(vec![old.clone()])),
            accepted_owners: Vec::new().into(),
        })
        .await;
    assert!(skipped.is_err());

    let removal = session
        .apply_tcp_ao_add_only(crate::TcpAoSessionGeneration {
            generation: crate::TcpAoRotationGeneration::new(3).unwrap(),
            active_keyring: Some(crate::TcpAoKeyring(vec![old])),
            accepted_owners: Vec::new().into(),
        })
        .await;
    assert!(removal.is_err());
    assert_eq!(session.tcp_ao_generation, generation_two);
}

#[tokio::test]
async fn disconnected_protected_session_cannot_advance_without_active_owner_inventory() {
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
    let result = session
        .apply_tcp_ao_add_only(crate::TcpAoSessionGeneration {
            generation: crate::TcpAoRotationGeneration::new(2).unwrap(),
            active_keyring: None,
            accepted_owners: Vec::new().into(),
        })
        .await;
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
    let result = session
        .apply_tcp_ao_add_only(crate::TcpAoSessionGeneration {
            generation: crate::TcpAoRotationGeneration::new(2).unwrap(),
            active_keyring: Some(crate::TcpAoKeyring(vec![old, successor])),
            accepted_owners: Vec::new().into(),
        })
        .await;
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
fn active_open_binds_local_source_before_tcp_ao_installation() {
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    let mut config = TransportConfig::new(peer_config, "127.0.0.1:179".parse().unwrap());
    config.local_address = Some("127.0.0.2".parse().unwrap());
    config.tcp_ao = Some(crate::TcpAoKeyring(vec![crate::TcpAoConfig {
        key: "selected".into(),
        send_id: 1,
        recv_id: 2,
        algorithm: crate::TcpAoAlgorithm::HmacSha256,
        preferred: true,
        deprecated: false,
    }]));
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )
    .unwrap();
    let result = super::io::prepare_active_socket_for_test(
        socket,
        &config,
        "127.0.0.1",
        |socket, _, _, _, _| {
            assert_eq!(
                socket.local_addr()?.as_socket().unwrap().ip(),
                config.local_address.unwrap()
            );
            Err(std::io::Error::other("ordering proof stop"))
        },
        |_, _| panic!("connect must not run after injected AO failure"),
    );
    let Err(error) = result else {
        panic!("injected AO installation failure must stop active open");
    };
    assert!(error.to_string().contains("ordering proof stop"));
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
    let snapshot = session.tcp_ao_info.take().unwrap();
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

// A TCP-AO key mutation that fails after it started discards the connection.
// The session must take that as a transport failure at once, not stay in its
// FSM state on a closed socket until the hold timer.

const TCP_AO_MUTATION_CAUSE: &str = "TCP-AO key mutation failed; connection discarded";

fn open_with_hold(hold_time: u16) -> rustbgpd_wire::OpenMessage {
    rustbgpd_wire::OpenMessage {
        version: 4,
        my_as: 65002,
        hold_time,
        bgp_identifier: Ipv4Addr::new(10, 0, 0, 2),
        capabilities: vec![
            Capability::MultiProtocol {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            },
            Capability::FourOctetAs { asn: 65002 },
        ],
    }
}

async fn establish_with(session: &mut PeerSession, open: rustbgpd_wire::OpenMessage) {
    session.drive_fsm(Event::ManualStart).await;
    session.drive_fsm(Event::OpenReceived(open)).await;
    session.drive_fsm(Event::KeepaliveReceived).await;
    assert_eq!(session.fsm.state(), SessionState::Established);
}

/// The TCP-AO fixture session with a RIB receiver, connected over loopback;
/// the peer's end is returned so the connection stays open from its side.
async fn connected_tcp_ao_session() -> (
    PeerSession,
    crate::TcpAoSessionDeletion,
    mpsc::Receiver<RibUpdate>,
    TcpStream,
) {
    let (mut session, deletion) = tcp_ao_deletion_test_fixture();
    let (rib_tx, rib_rx) = mpsc::channel(64);
    session.rib_tx = rib_tx;
    let (client, peer) = connected_stream_pair().await;
    session.test_install_stream(client);
    (session, deletion, rib_rx, peer)
}

async fn established_tcp_ao_session() -> (
    PeerSession,
    crate::TcpAoSessionDeletion,
    mpsc::Receiver<RibUpdate>,
    TcpStream,
) {
    let (mut session, deletion, mut rib_rx, peer) = connected_tcp_ao_session().await;
    establish_with(&mut session, open_with_hold(90)).await;
    while rib_rx.try_recv().is_ok() {}
    (session, deletion, rib_rx, peer)
}

fn selection_of(session: &PeerSession) -> crate::TcpAoSessionSelection {
    crate::TcpAoSessionSelection {
        generation: crate::TcpAoRotationGeneration::new(2).unwrap(),
        active_keyring: session.config.tcp_ao.clone(),
        accepted_owners: Vec::new().into(),
        accepted_selected_owner: None,
    }
}

fn add_only_of(session: &PeerSession) -> crate::TcpAoSessionGeneration {
    let mut keyring = session.config.tcp_ao.clone().unwrap();
    keyring.0.push(crate::TcpAoConfig {
        key: "added-secret".into(),
        send_id: 3,
        recv_id: 13,
        algorithm: crate::TcpAoAlgorithm::HmacSha256,
        preferred: false,
        deprecated: false,
    });
    crate::TcpAoSessionGeneration {
        generation: crate::TcpAoRotationGeneration::new(2).unwrap(),
        active_keyring: Some(keyring),
        accepted_owners: Vec::new().into(),
    }
}

fn mutation_failed<T>() -> Result<T, PeerCommandError> {
    Err(PeerCommandError::TcpAoMutationFailed(
        "injected failure after the mutation started".to_string(),
    ))
}

fn mutation_not_started<T>() -> Result<T, PeerCommandError> {
    Err(PeerCommandError::CommandFailed(
        "injected refusal before any mutation".to_string(),
    ))
}

/// Every session-loss message queued for the RIB, in order.
fn rib_losses(rib_rx: &mut mpsc::Receiver<RibUpdate>) -> Vec<&'static str> {
    std::iter::from_fn(|| rib_rx.try_recv().ok())
        .filter_map(|update| match update {
            RibUpdate::PeerDown { .. } => Some("PeerDown"),
            RibUpdate::PeerGracefulRestart { .. } => Some("PeerGracefulRestart"),
            _ => None,
        })
        .collect()
}

async fn reset_after_failed_mutation(session: &mut PeerSession) {
    let (reply, acknowledged) = oneshot::channel();
    assert_eq!(
        session
            .handle_command(PeerCommand::ResetTcpAoAfterFailedMutation {
                desired_generation: crate::TcpAoRotationGeneration::new(2).unwrap(),
                reply,
            })
            .await,
        ControlFlow::Continue(())
    );
    acknowledged.await.expect("the reset is still acknowledged");
}

/// The Established session went down as for a transport loss: Idle, one
/// `PeerDown`, socket and writer gone, no hold timer left, reconnect armed.
fn assert_failed_as_transport_loss(
    site: &str,
    session: &mut PeerSession,
    rib_rx: &mut mpsc::Receiver<RibUpdate>,
) {
    assert_eq!(session.fsm.state(), SessionState::Idle, "{site}");
    assert_eq!(rib_losses(rib_rx), ["PeerDown"], "{site}");
    assert!(session.read_half.is_none(), "{site}: socket discarded");
    assert!(
        session.writer_join.is_none(),
        "{site}: the writer is aborted and joined, so it cannot report an exit later"
    );
    assert!(
        session.timers.hold.is_none(),
        "{site}: no hold timer is left to end the session a second time"
    );
    assert!(
        session.reconnect_timer.is_some(),
        "{site}: the session reconnects"
    );
    assert_eq!(session.last_error, TCP_AO_MUTATION_CAUSE, "{site}");
    let downs = counter_samples(&session.metrics, "bgp_session_down_total");
    assert!(
        downs.iter().any(|(labels, value)| {
            labels.get("reason").map(String::as_str) == Some("local_no_notification")
                && (*value - 1.0).abs() < f64::EPSILON
        }),
        "{site}: {downs:?}"
    );
}

fn assert_mutation_failed(result: &Result<(), PeerCommandError>) {
    assert!(matches!(
        result,
        Err(PeerCommandError::TcpAoMutationFailed(_))
    ));
}

#[tokio::test]
async fn failed_tcp_ao_selection_fails_the_established_session() {
    let (mut session, _deletion, mut rib_rx, _peer) = established_tcp_ao_session().await;
    let desired = selection_of(&session);
    let result = session
        .apply_tcp_ao_selection_with(desired, |_, _, _, _| mutation_failed())
        .await;
    assert_mutation_failed(&result);
    assert_failed_as_transport_loss("selection", &mut session, &mut rib_rx);
    assert!(session.tcp_ao_pending_selection.is_none());
}

#[tokio::test]
async fn failed_tcp_ao_deletion_fails_the_established_session() {
    let (mut session, deletion, mut rib_rx, _peer) = established_tcp_ao_session().await;
    let result = session
        .apply_tcp_ao_delete_with(&deletion, |_, _, _, _| mutation_failed())
        .await;
    assert_mutation_failed(&result);
    assert_failed_as_transport_loss("deletion", &mut session, &mut rib_rx);
    assert_eq!(
        session.tcp_ao_generation,
        crate::TcpAoRotationGeneration::STARTUP
    );
}

#[tokio::test]
async fn tcp_ao_deletion_without_a_snapshot_fails_the_established_session() {
    let (mut session, deletion, mut rib_rx, _peer) = established_tcp_ao_session().await;
    let result = session
        .apply_tcp_ao_delete_with(&deletion, |_, _, _, _| Ok(None))
        .await;
    assert_mutation_failed(&result);
    assert_failed_as_transport_loss("deletion without snapshot", &mut session, &mut rib_rx);
}

#[tokio::test]
async fn failed_tcp_ao_add_only_fails_the_established_session() {
    let (mut session, _deletion, mut rib_rx, _peer) = established_tcp_ao_session().await;
    let desired = add_only_of(&session);
    let result = session
        .apply_tcp_ao_add_only_with(desired, |_, _, _, _| mutation_failed())
        .await;
    assert_mutation_failed(&result);
    assert_failed_as_transport_loss("add-only", &mut session, &mut rib_rx);
    assert_eq!(
        session.tcp_ao_generation,
        crate::TcpAoRotationGeneration::STARTUP
    );
}

#[tokio::test]
async fn tcp_ao_add_only_without_a_snapshot_fails_the_established_session() {
    let (mut session, _deletion, mut rib_rx, _peer) = established_tcp_ao_session().await;
    let desired = add_only_of(&session);
    let result = session
        .apply_tcp_ao_add_only_with(desired, |_, _, _, _| Ok(None))
        .await;
    assert_mutation_failed(&result);
    assert_failed_as_transport_loss("add-only without snapshot", &mut session, &mut rib_rx);
}

/// Control: a refusal before any key changed keeps the connection and the
/// Established session, for each of the three mutations.
#[tokio::test]
async fn tcp_ao_refusal_before_mutation_keeps_the_established_session() {
    let (mut session, deletion, mut rib_rx, _peer) = established_tcp_ao_session().await;
    let selection = selection_of(&session);
    let add_only = add_only_of(&session);
    let results = [
        session
            .apply_tcp_ao_selection_with(selection, |_, _, _, _| mutation_not_started())
            .await,
        session
            .apply_tcp_ao_delete_with(&deletion, |_, _, _, _| mutation_not_started())
            .await,
        session
            .apply_tcp_ao_add_only_with(add_only, |_, _, _, _| mutation_not_started())
            .await,
    ];
    for result in results {
        assert!(matches!(result, Err(PeerCommandError::CommandFailed(_))));
    }
    assert_eq!(session.fsm.state(), SessionState::Established);
    assert!(session.read_half.is_some());
    assert_eq!(rib_losses(&mut rib_rx), [""; 0]);
    assert_eq!(session.last_error, "");
}

#[tokio::test]
async fn tcp_ao_reset_fails_the_established_session() {
    let (mut session, _deletion, mut rib_rx, _peer) = established_tcp_ao_session().await;
    reset_after_failed_mutation(&mut session).await;
    assert_failed_as_transport_loss("reset", &mut session, &mut rib_rx);
}

/// The peer negotiated Graceful Restart: the reset retains its routes exactly
/// as an ordinary transport loss does.
#[tokio::test]
async fn tcp_ao_reset_retains_routes_under_graceful_restart() {
    let (mut session, _deletion, mut rib_rx, _peer) = connected_tcp_ao_session().await;
    session.config.peer.graceful_restart = true;
    establish_with(&mut session, notification_gr_open(false)).await;
    while rib_rx.try_recv().is_ok() {}
    reset_after_failed_mutation(&mut session).await;
    assert_eq!(session.fsm.state(), SessionState::Idle);
    assert_eq!(rib_losses(&mut rib_rx), ["PeerGracefulRestart"]);
    assert!(session.reconnect_timer.is_some());

    let (mut control, _deletion, mut control_rib, _peer) = connected_tcp_ao_session().await;
    control.config.peer.graceful_restart = true;
    establish_with(&mut control, notification_gr_open(false)).await;
    while control_rib.try_recv().is_ok() {}
    control.handle_tcp_disconnect();
    control.drive_fsm(Event::TcpConnectionFails).await;
    assert_eq!(rib_losses(&mut control_rib), ["PeerGracefulRestart"]);
}

/// A writer that would fail after the reset cannot report it: the reset
/// aborts and joins the writer, so the run loop's writer-exit arm, which is
/// gated on that join handle, has nothing left to observe.
#[tokio::test]
async fn writer_error_after_tcp_ao_reset_reports_no_second_loss() {
    let (mut session, _deletion, mut rib_rx, peer) = established_tcp_ao_session().await;
    drop(peer);
    reset_after_failed_mutation(&mut session).await;
    assert_failed_as_transport_loss("reset", &mut session, &mut rib_rx);
    assert!(session.writer_join.is_none());
}

/// A local hard teardown has closed the connection and waits for its writer
/// to exit before the session goes down. The reset stops that writer, so it
/// sends nothing more, and delivers its exit: one `PeerDown`, as the run
/// loop's writer-exit arm would have produced, with the teardown's own cause.
#[tokio::test]
async fn tcp_ao_reset_stops_a_writer_still_flushing_a_closed_connection() {
    let (mut session, _deletion, mut rib_rx, _peer) = established_tcp_ao_session().await;
    session.trigger_outbound_saturation_teardown();
    assert!(session.read_half.is_none() && session.writer_join.is_some());
    assert_eq!(session.fsm.state(), SessionState::Established);
    assert_eq!(rib_losses(&mut rib_rx), [""; 0]);

    reset_after_failed_mutation(&mut session).await;
    assert!(session.writer_join.is_none(), "the writer is stopped");
    assert_eq!(session.fsm.state(), SessionState::Idle);
    assert_eq!(rib_losses(&mut rib_rx), ["PeerDown"]);
    assert_eq!(
        session.last_error,
        crate::handle::SessionFailureCause::OutboundSaturation.to_string()
    );
    assert!(session.pending_outbound_teardown_cause.is_none());
}

/// Without a connection or a connect attempt there is nothing to fail: the
/// reset is acknowledged and the FSM, its timers and the recorded error stay
/// as they were, in Idle and in Active.
#[tokio::test]
async fn tcp_ao_reset_without_a_connection_changes_nothing() {
    let (mut session, _deletion, mut rib_rx) = {
        let (mut session, deletion) = tcp_ao_deletion_test_fixture();
        let (rib_tx, rib_rx) = mpsc::channel(64);
        session.rib_tx = rib_tx;
        (session, deletion, rib_rx)
    };
    reset_after_failed_mutation(&mut session).await;
    assert_eq!(session.fsm.state(), SessionState::Idle);
    assert_eq!(session.last_error, "");

    let (client, _peer) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.drive_fsm(Event::ManualStart).await;
    session.handle_tcp_disconnect();
    session.drive_fsm(Event::TcpConnectionFails).await;
    assert_eq!(session.fsm.state(), SessionState::Active);
    let retries = session.fsm.connect_retry_counter();
    reset_after_failed_mutation(&mut session).await;
    assert_eq!(session.fsm.state(), SessionState::Active);
    assert_eq!(session.fsm.connect_retry_counter(), retries);
    assert!(
        session.writer_join.is_none(),
        "the closed connection's writer is stopped"
    );
    assert_eq!(session.last_error, "");
    assert_eq!(rib_losses(&mut rib_rx), [""; 0]);
}

/// Before Established there is no RIB registration to withdraw: the reset
/// discards the connection, or the connect attempt still in flight, and the
/// FSM takes the failure, with no `PeerDown`.
#[tokio::test]
async fn tcp_ao_reset_before_established_reports_no_loss() {
    // Connect: the attempt dials a loopback listener and is never polled.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.remote_addr = listener.local_addr().unwrap();
    session.drive_fsm(Event::ManualStart).await;
    assert_eq!(session.fsm.state(), SessionState::Connect);
    assert!(session.connect_task.is_some());
    reset_after_failed_mutation(&mut session).await;
    assert_eq!(session.fsm.state(), SessionState::Active);
    assert!(session.connect_task.is_none());
    assert_eq!(session.last_error, TCP_AO_MUTATION_CAUSE);
    assert_eq!(rib_losses(&mut rib_rx), [""; 0]);

    let (mut session, _deletion, mut rib_rx, _peer) = connected_tcp_ao_session().await;
    session.drive_fsm(Event::ManualStart).await;
    assert_eq!(session.fsm.state(), SessionState::OpenSent);
    reset_after_failed_mutation(&mut session).await;
    assert_eq!(session.fsm.state(), SessionState::Active);
    assert!(session.read_half.is_none());
    assert!(session.writer_join.is_none());
    assert_eq!(rib_losses(&mut rib_rx), [""; 0]);

    let (mut session, _deletion, mut rib_rx, _peer) = connected_tcp_ao_session().await;
    session.drive_fsm(Event::ManualStart).await;
    session
        .drive_fsm(Event::OpenReceived(open_with_hold(90)))
        .await;
    assert_eq!(session.fsm.state(), SessionState::OpenConfirm);
    while rib_rx.try_recv().is_ok() {}
    reset_after_failed_mutation(&mut session).await;
    assert_eq!(session.fsm.state(), SessionState::Idle);
    assert!(session.read_half.is_none());
    assert_eq!(rib_losses(&mut rib_rx), [""; 0]);
}

async fn query_fsm_state(commands: &mpsc::Sender<PeerCommand>) -> SessionState {
    let (reply, state) = oneshot::channel();
    commands
        .send(PeerCommand::QueryState { reply })
        .await
        .unwrap();
    state.await.unwrap().fsm_state
}

/// The reset through the run loop, for a session Established with
/// `hold_time`. By the time the reset is acknowledged the RIB has its
/// `PeerDown` and the session reports Idle, the state in which the peer
/// manager accepts the peer's reconnect instead of dropping it against an
/// Established session. Nothing reports the loss a second time afterwards.
/// The listener stays bound and unaccepted, so the session's own reconnect
/// attempts stay on loopback and never complete a handshake.
async fn tcp_ao_reset_in_the_run_loop(hold_time: u16) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
    let _peer = accepted.unwrap().0;
    let (mut session, commands, mut rib_rx) = make_test_session_with_channels(65001, 65002, 64);
    session.config.remote_addr = addr;
    session.test_install_stream(client.unwrap());
    establish_with(&mut session, open_with_hold(hold_time)).await;
    assert_eq!(session.timers.hold.is_some(), hold_time != 0);
    while rib_rx.try_recv().is_ok() {}
    let task = tokio::spawn(async move { session.run().await });

    let (reply, acknowledged) = oneshot::channel();
    commands
        .send(PeerCommand::ResetTcpAoAfterFailedMutation {
            desired_generation: crate::TcpAoRotationGeneration::new(2).unwrap(),
            reply,
        })
        .await
        .unwrap();
    acknowledged.await.expect("the reset is still acknowledged");
    assert_eq!(rib_losses(&mut rib_rx), ["PeerDown"]);
    assert_eq!(query_fsm_state(&commands).await, SessionState::Idle);

    // Past the hold time the session had, and past its first reconnect.
    let second_loss = tokio::time::timeout(Duration::from_secs(200), async {
        loop {
            match rib_rx.recv().await {
                Some(RibUpdate::PeerDown { .. } | RibUpdate::PeerGracefulRestart { .. }) => break,
                Some(_) => {}
                None => std::future::pending::<()>().await,
            }
        }
    })
    .await;
    assert!(second_loss.is_err(), "the loss is reported once");

    commands.send(PeerCommand::Shutdown).await.unwrap();
    task.await
        .expect("session task must not panic")
        .expect("run() must return Ok");
}

#[tokio::test(start_paused = true)]
async fn tcp_ao_reset_ends_an_established_session_in_the_run_loop() {
    tcp_ao_reset_in_the_run_loop(90).await;
}

/// With a hold time of zero no timer would ever end the session.
#[tokio::test(start_paused = true)]
async fn tcp_ao_reset_ends_an_established_session_with_hold_time_zero() {
    tcp_ao_reset_in_the_run_loop(0).await;
}
