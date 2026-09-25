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
