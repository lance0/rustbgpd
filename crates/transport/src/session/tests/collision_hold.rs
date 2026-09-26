//! RFC 4271 §6.8: an inbound collision candidate holds its KEEPALIVE in
//! `OpenConfirm` until `PeerManager` promotes or closes it.

use super::*;

fn encoded_peer_open_and_keepalive() -> Vec<u8> {
    let open = Message::Open(rustbgpd_wire::OpenMessage {
        version: 4,
        my_as: 65002,
        hold_time: 90,
        bgp_identifier: Ipv4Addr::new(10, 0, 0, 2),
        capabilities: vec![
            Capability::MultiProtocol {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            },
            Capability::FourOctetAs { asn: 65002 },
        ],
    });
    let mut bytes = rustbgpd_wire::encode_message(&open).unwrap();
    bytes.extend(rustbgpd_wire::encode_message(&Message::Keepalive).unwrap());
    bytes.to_vec()
}

/// A candidate whose peer's OPEN and KEEPALIVE arrive in one read: the OPEN
/// moves it to `OpenConfirm`, and nothing more happens until the verdict.
async fn candidate_waiting_for_verdict() -> (PeerSession, mpsc::Receiver<RibUpdate>, TcpStream) {
    let (mut candidate, rib_rx) = make_test_session_with_metrics_and_identity(
        BgpMetrics::new(),
        SessionIdentity::inbound_candidate(2),
    );
    let (local, mut remote) = connected_stream_pair().await;
    candidate.test_install_stream(local);
    candidate.drive_fsm(Event::ManualStart).await;
    assert!(matches!(
        read_single_bgp_message(&mut remote).await,
        Message::Open(_)
    ));

    candidate
        .read_buf
        .buf
        .extend_from_slice(&encoded_peer_open_and_keepalive());
    candidate.process_read_buffer().await;
    assert_eq!(
        candidate.fsm.state(),
        SessionState::OpenConfirm,
        "the peer KEEPALIVE must stay unread until the collision verdict"
    );
    assert!(candidate.collision_verdict_pending());
    (candidate, rib_rx, remote)
}

#[tokio::test]
async fn collision_candidate_holds_keepalive_and_input_until_promotion() {
    let (mut candidate, mut rib_rx, mut remote) = candidate_waiting_for_verdict().await;
    assert!(
        rib_rx.try_recv().is_err(),
        "an unpromoted candidate must not register with the RIB"
    );

    let (reply, done) = oneshot::channel();
    assert_eq!(
        candidate
            .handle_command(PeerCommand::ActivateMaxPrefixMetrics {
                notification_idle_failures: 0,
                reply,
            })
            .await,
        ControlFlow::Continue(())
    );
    done.await.unwrap();

    // Promotion sends the held KEEPALIVE and consumes the buffered one.
    assert!(matches!(
        read_single_bgp_message(&mut remote).await,
        Message::Keepalive
    ));
    assert_eq!(candidate.fsm.state(), SessionState::Established);
    assert!(!candidate.collision_verdict_pending());
    assert!(candidate.collision_verdict_timer.is_none());
    assert!(matches!(
        recv_peer_up_after_export_context(&mut rib_rx).await,
        RibUpdate::PeerUp { session_id: 2, .. }
    ));
}

#[tokio::test]
async fn collision_candidate_loser_sends_cease_without_keepalive() {
    let (mut candidate, mut rib_rx, mut remote) = candidate_waiting_for_verdict().await;

    assert_eq!(
        candidate.handle_command(PeerCommand::CollisionDump).await,
        ControlFlow::Break(())
    );

    // The first message after our OPEN is the Cease: the peer never saw a
    // KEEPALIVE from the losing connection.
    let Message::Notification(notification) = read_single_bgp_message(&mut remote).await else {
        panic!("the loser must send Cease 6/7 before any KEEPALIVE");
    };
    assert_eq!(notification.code, NotificationCode::Cease);
    assert_eq!(
        notification.subcode,
        cease_subcode::CONNECTION_COLLISION_RESOLUTION
    );
    assert!(
        rib_rx.try_recv().is_err(),
        "the loser never reached the RIB"
    );
}

#[tokio::test]
async fn primary_session_is_not_held_for_a_collision_verdict() {
    let (mut primary, _rib_rx) =
        make_test_session_with_metrics_and_identity(BgpMetrics::new(), SessionIdentity::primary(1));
    let (local, _remote) = connected_stream_pair().await;
    primary.test_install_stream(local);
    primary.drive_fsm(Event::ManualStart).await;
    primary
        .read_buf
        .buf
        .extend_from_slice(&encoded_peer_open_and_keepalive());
    primary.process_read_buffer().await;
    assert_eq!(primary.fsm.state(), SessionState::Established);
    assert!(primary.collision_verdict_timer.is_none());
}

/// A lost verdict must not wedge the candidate: through the real run loop it
/// leaves `OpenConfirm` after `COLLISION_VERDICT_TIMEOUT` and reports
/// `BackToIdle`, which is what makes `PeerManager` drop it.
#[tokio::test(start_paused = true)]
async fn collision_candidate_without_verdict_falls_to_idle() {
    let (local, mut remote) = connected_stream_pair().await;
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    let config = TransportConfig::new(peer_config, "10.0.0.2:179".parse().unwrap());
    let metrics = BgpMetrics::new();
    let (notify_tx, mut notify_rx) = crate::handle::session_notification_channel(metrics.clone());
    let (cmd_tx, cmd_rx) = mpsc::channel(8);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let mut candidate = PeerSession::new_inbound_with_identity_and_lifecycle(
        config,
        metrics,
        cmd_rx,
        rib_tx,
        None,
        None,
        local,
        Some(notify_tx),
        None,
        None,
        None,
        None,
        false,
        SessionIdentity::inbound_candidate(7),
        None,
        None,
        crate::TcpAoRotationGeneration::STARTUP,
    );
    let session = tokio::spawn(async move { candidate.run().await });
    cmd_tx.send(PeerCommand::Start).await.unwrap();
    assert!(matches!(
        read_single_bgp_message(&mut remote).await,
        Message::Open(_)
    ));
    remote
        .write_all(&encoded_peer_open_and_keepalive())
        .await
        .unwrap();

    let entered_open_confirm = tokio::time::Instant::now();
    assert!(matches!(
        notify_rx.recv().await.unwrap(),
        SessionNotification::OpenReceived { session_id: 7, .. }
    ));
    // The deadline is the verdict timer, not the 90 s hold timer.
    let Message::Notification(notification) = read_single_bgp_message(&mut remote).await else {
        panic!("a candidate without a verdict must close with a NOTIFICATION, not KEEPALIVE");
    };
    assert_eq!(notification.code, NotificationCode::HoldTimerExpired);
    let waited = entered_open_confirm.elapsed();
    assert!(
        waited >= fsm::COLLISION_VERDICT_TIMEOUT && waited < Duration::from_secs(90),
        "closed after {waited:?}"
    );
    assert!(matches!(
        notify_rx.recv().await.unwrap(),
        SessionNotification::BackToIdle { session_id: 7, .. }
    ));
    assert!(rib_rx.try_recv().is_err(), "never registered with the RIB");

    cmd_tx.send(PeerCommand::Shutdown).await.unwrap();
    session.await.unwrap().unwrap();
}

/// Reply delivery alone must not transfer ownership: cancellation after send
/// and cancellation after consumption both release through the real run loop.
#[tokio::test]
async fn canceled_primary_collision_preparation_releases_handshake() {
    for consume_reply in [false, true] {
        for receive_open in [false, true] {
            let (mut primary, mut rib_rx) = make_test_session_with_metrics_and_identity(
                BgpMetrics::new(),
                SessionIdentity::primary(1),
            );
            let (local, mut remote) = connected_stream_pair().await;
            primary.test_install_stream(local);
            primary.drive_fsm(Event::ManualStart).await;
            assert!(matches!(
                read_single_bgp_message(&mut remote).await,
                Message::Open(_)
            ));
            let (reply, snapshot) = oneshot::channel();
            let (lease, released) = oneshot::channel();
            let _ = primary
                .handle_command(PeerCommand::PrepareCollisionCandidate {
                    reply,
                    lease: released,
                })
                .await;
            assert!(matches!(primary.collision_hold, fsm::CollisionHold::Armed));
            // Armed after command handling proves the synchronous send succeeded.
            if consume_reply {
                assert_eq!(snapshot.await.unwrap().fsm_state, SessionState::OpenSent);
            } else {
                drop(snapshot);
            }
            if receive_open {
                primary
                    .read_buf
                    .buf
                    .extend_from_slice(&encoded_peer_open_and_keepalive());
                primary.process_read_buffer().await;
                assert!(primary.collision_verdict_pending());
            }
            drop(lease);
            let (commands, receiver) = mpsc::channel(8);
            primary.commands = receiver;
            let task = tokio::spawn(async move {
                primary.run().await.unwrap();
                primary
            });
            if !receive_open {
                remote
                    .write_all(&encoded_peer_open_and_keepalive())
                    .await
                    .unwrap();
            }
            assert!(matches!(
                tokio::time::timeout(Duration::from_secs(2), read_single_bgp_message(&mut remote))
                    .await
                    .unwrap(),
                Message::Keepalive
            ));
            assert!(matches!(
                recv_peer_up_after_export_context(&mut rib_rx).await,
                RibUpdate::PeerUp { session_id: 1, .. }
            ));
            commands.send(PeerCommand::Shutdown).await.unwrap();
            let primary = task.await.unwrap();
            assert!(matches!(
                primary.collision_hold,
                fsm::CollisionHold::Released
            ));
            assert!(primary.primary_collision_lease.is_none());
            assert!(primary.collision_verdict_timer.is_none());
        }
    }
}

#[tokio::test]
async fn primary_collision_preparation_does_not_replace_a_live_lease() {
    let (mut primary, _rib_rx) =
        make_test_session_with_metrics_and_identity(BgpMetrics::new(), SessionIdentity::primary(1));
    let (local, _remote) = connected_stream_pair().await;
    primary.test_install_stream(local);
    primary.drive_fsm(Event::ManualStart).await;
    let (reply, snapshot) = oneshot::channel();
    let (first, released) = oneshot::channel();
    let _ = primary
        .handle_command(PeerCommand::PrepareCollisionCandidate {
            reply,
            lease: released,
        })
        .await;
    snapshot.await.unwrap();
    let (reply, snapshot) = oneshot::channel();
    let (second, released) = oneshot::channel();
    let _ = primary
        .handle_command(PeerCommand::PrepareCollisionCandidate {
            reply,
            lease: released,
        })
        .await;
    snapshot.await.unwrap();
    assert!(
        second.is_closed(),
        "another preparation cannot replace a live attempt"
    );
    assert!(!first.is_closed());
    drop(first);
    let (reply, snapshot) = oneshot::channel();
    let (third, released) = oneshot::channel();
    let _ = primary
        .handle_command(PeerCommand::PrepareCollisionCandidate {
            reply,
            lease: released,
        })
        .await;
    snapshot.await.unwrap();
    drop(second); // An obsolete lease cannot release the new attempt.
    assert!(!third.is_closed());
    primary
        .read_buf
        .buf
        .extend_from_slice(&encoded_peer_open_and_keepalive());
    primary.process_read_buffer().await;
    assert_eq!(primary.fsm.state(), SessionState::OpenConfirm);
    assert!(primary.collision_verdict_pending());
}

#[tokio::test]
async fn dropping_unpublished_candidate_releases_primary_without_candidate_keepalive() {
    for candidate_open_received in [false, true] {
        let (mut primary, mut rib_rx) = make_test_session_with_metrics_and_identity(
            BgpMetrics::new(),
            SessionIdentity::primary(1),
        );
        let (local, mut primary_remote) = connected_stream_pair().await;
        primary.test_install_stream(local);
        primary.drive_fsm(Event::ManualStart).await;
        assert!(matches!(
            read_single_bgp_message(&mut primary_remote).await,
            Message::Open(_)
        ));
        let (reply, snapshot) = oneshot::channel();
        let (lease, released) = oneshot::channel();
        let _ = primary
            .handle_command(PeerCommand::PrepareCollisionCandidate {
                reply,
                lease: released,
            })
            .await;
        snapshot.await.unwrap();
        primary
            .read_buf
            .buf
            .extend_from_slice(&encoded_peer_open_and_keepalive());
        primary.process_read_buffer().await;
        assert!(primary.collision_verdict_pending());
        let (primary_commands, receiver) = mpsc::channel(8);
        primary.commands = receiver;
        let primary_task = tokio::spawn(async move { primary.run().await });

        let (mut candidate, mut candidate_rib) = make_test_session_with_metrics_and_identity(
            BgpMetrics::new(),
            SessionIdentity::inbound_candidate(2),
        );
        let (local, mut candidate_remote) = connected_stream_pair().await;
        candidate.test_install_stream(local);
        let (notify, mut notices) = crate::handle::session_notification_channel(BgpMetrics::new());
        candidate.session_notify_tx = Some(notify);
        let (commands, receiver) = mpsc::channel(8);
        candidate.commands = receiver;
        let (finished, done) = oneshot::channel();
        let task = tokio::spawn(async move {
            let result = candidate.run().await;
            let _ = finished.send(candidate.fsm.state());
            result
        });
        let mut candidate = crate::handle::PeerHandle::from_parts(commands, task);
        candidate.hold_primary_for_collision(lease);
        candidate.start().await.unwrap();
        assert!(matches!(
            read_single_bgp_message(&mut candidate_remote).await,
            Message::Open(_)
        ));
        candidate_remote
            .write_all(&encoded_peer_open_and_keepalive())
            .await
            .unwrap();
        if candidate_open_received {
            assert!(matches!(
                notices.recv().await.unwrap(),
                SessionNotification::OpenReceived { session_id: 2, .. }
            ));
        }
        // No pending-inbound publication or promotion: drop during admission.
        drop(candidate);
        assert_ne!(
            tokio::time::timeout(Duration::from_secs(2), done)
                .await
                .unwrap()
                .unwrap(),
            SessionState::Established
        );
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), candidate_remote.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0,
            "unpublished candidate must close without KEEPALIVE"
        );
        assert!(candidate_rib.try_recv().is_err());
        assert!(matches!(
            tokio::time::timeout(
                Duration::from_secs(2),
                read_single_bgp_message(&mut primary_remote)
            )
            .await
            .unwrap(),
            Message::Keepalive
        ));
        assert!(matches!(
            recv_peer_up_after_export_context(&mut rib_rx).await,
            RibUpdate::PeerUp { session_id: 1, .. }
        ));
        primary_commands.send(PeerCommand::Shutdown).await.unwrap();
        primary_task.await.unwrap().unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn abandoned_primary_lease_wins_over_ready_verdict_timeout() {
    let (mut primary, mut rib_rx) =
        make_test_session_with_metrics_and_identity(BgpMetrics::new(), SessionIdentity::primary(1));
    let (local, mut remote) = connected_stream_pair().await;
    primary.test_install_stream(local);
    primary.drive_fsm(Event::ManualStart).await;
    assert!(matches!(
        read_single_bgp_message(&mut remote).await,
        Message::Open(_)
    ));
    let (reply, snapshot) = oneshot::channel();
    let (lease, released) = oneshot::channel();
    let _ = primary
        .handle_command(PeerCommand::PrepareCollisionCandidate {
            reply,
            lease: released,
        })
        .await;
    snapshot.await.unwrap();
    primary
        .read_buf
        .buf
        .extend_from_slice(&encoded_peer_open_and_keepalive());
    primary.process_read_buffer().await;
    drop(lease);
    tokio::time::advance(fsm::COLLISION_VERDICT_TIMEOUT).await;
    // Explicitly choose the timer branch while cancellation is also ready.
    primary.expire_collision_verdict_wait().await;
    assert!(matches!(
        read_single_bgp_message(&mut remote).await,
        Message::Keepalive
    ));
    assert_eq!(primary.fsm.state(), SessionState::Established);
    assert!(primary.collision_verdict_timer.is_none());
    assert!(matches!(
        recv_peer_up_after_export_context(&mut rib_rx).await,
        RibUpdate::PeerUp { session_id: 1, .. }
    ));
}
