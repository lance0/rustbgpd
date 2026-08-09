use super::*;

#[tokio::test]
async fn shutdown_aborts_inflight_connect_task() {
    let mut session = make_test_session(65001, 65002);
    session.connect_task = Some(tokio::spawn(async {
        tokio::time::sleep(Duration::from_mins(1)).await;
        unreachable!("connect task should have been aborted by shutdown");
    }));
    assert_eq!(
        session.handle_command(PeerCommand::Shutdown).await,
        ControlFlow::Break(())
    );
    assert!(session.connect_task.is_none());
}

/// Mutant: removing the sent-cause assignment leaves this snapshot empty.
#[tokio::test]
async fn required_family_rejection_reports_descriptive_sent_notification() {
    let mut config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    config.families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
    config.required_families = vec![(Afi::Ipv6, Safi::Unicast)];
    let mut session = make_test_session_with_peer_config(config);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.drive_fsm(Event::ManualStart).await;
    session
        .drive_fsm(Event::OpenReceived(rustbgpd_wire::OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 90,
            bgp_identifier: Ipv4Addr::new(10, 0, 0, 2),
            capabilities: vec![Capability::MultiProtocol {
                afi: Afi::BgpLs,
                safi: Safi::BgpLs,
            }],
        }))
        .await;

    let (reply, state) = oneshot::channel();
    let _ = session
        .handle_command(PeerCommand::QueryState { reply })
        .await;
    assert_eq!(
        state.await.unwrap().last_error,
        "sent NOTIFICATION 2/7 (Unsupported Capability)"
    );
}

/// Mutant: restoring numeric-only receive state loses direction and description.
#[tokio::test]
async fn received_notification_reports_direction_and_description() {
    let mut session = make_test_session(65001, 65002);
    let notification = NotificationMessage::new(
        NotificationCode::Cease,
        cease_subcode::OUT_OF_RESOURCES,
        Bytes::new(),
    );
    session.read_buf.buf.extend_from_slice(
        &rustbgpd_wire::encode_message(&Message::Notification(notification)).unwrap(),
    );
    session.process_read_buffer().await;
    assert_eq!(
        session.last_error,
        "received NOTIFICATION 6/8 (Out of Resources)"
    );
}

/// Load-bearing RFC 9003/RFC 8538 receive proof: restoring the direct-only
/// decoder drops the Hard Reset reason, while omitting either administrative
/// subcode drops that direct reason. The event retains the actual outer
/// notification code/subcode so extracting the reason cannot disguise teardown
/// semantics.
#[tokio::test]
async fn received_notification_events_report_direct_and_hard_reset_shutdown_reasons() {
    let reason = "planned maintenance";
    let encoded_reason = rustbgpd_wire::notification::encode_shutdown_communication(reason);
    let mut hard_reset_data = vec![
        NotificationCode::Cease.as_u8(),
        cease_subcode::ADMINISTRATIVE_RESET,
    ];
    hard_reset_data.extend_from_slice(&encoded_reason);

    for notification in [
        NotificationMessage::new(
            NotificationCode::Cease,
            cease_subcode::ADMINISTRATIVE_SHUTDOWN,
            encoded_reason.clone(),
        ),
        NotificationMessage::new(
            NotificationCode::Cease,
            cease_subcode::ADMINISTRATIVE_RESET,
            encoded_reason.clone(),
        ),
        NotificationMessage::new(
            NotificationCode::Cease,
            cease_subcode::HARD_RESET,
            hard_reset_data.into(),
        ),
    ] {
        let expected_subcode = notification.subcode;
        let mut session = make_test_session(65001, 65002);
        let (event_tx, mut event_rx) = mpsc::channel(2);
        session.session_event_tx = Some(event_tx);
        session.read_buf.buf.extend_from_slice(
            &rustbgpd_wire::encode_message(&Message::Notification(notification)).unwrap(),
        );

        session.process_read_buffer().await;

        let event = event_rx
            .try_recv()
            .expect("one received-notification event");
        assert_eq!(event.direction, SessionNotificationDirection::Received);
        assert_eq!(event.code, NotificationCode::Cease.as_u8());
        assert_eq!(event.subcode, expected_subcode);
        assert_eq!(event.shutdown_reason.as_deref(), Some(reason));
        assert_eq!(event.failure_cause, None);
    }
}

/// Load-bearing malformed-input boundary proof: switching the strict decoder
/// to lossy UTF-8 or accepting trailing data produces a reason in these events;
/// dropping the typed-error mapping prevents the event entirely. Every case
/// still reports and tears down for the actual outer NOTIFICATION, including a
/// short Hard Reset envelope.
#[tokio::test]
async fn malformed_shutdown_communication_is_not_interpreted_or_exempted_from_teardown() {
    for notification in [
        NotificationMessage::new(
            NotificationCode::Cease,
            cease_subcode::ADMINISTRATIVE_SHUTDOWN,
            Bytes::from_static(&[1, 0xff]),
        ),
        NotificationMessage::new(
            NotificationCode::Cease,
            cease_subcode::ADMINISTRATIVE_RESET,
            Bytes::from_static(&[1, b'x', b'y']),
        ),
        NotificationMessage::new(
            NotificationCode::Cease,
            cease_subcode::HARD_RESET,
            Bytes::from_static(&[6]),
        ),
    ] {
        let expected_subcode = notification.subcode;
        let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
        let (client, _server) = connected_stream_pair().await;
        session.test_install_stream(client);
        establish_test_session(&mut session, 65002).await;
        while rib_rx.try_recv().is_ok() {}
        let (event_tx, mut event_rx) = mpsc::channel(2);
        session.session_event_tx = Some(event_tx);
        session.read_buf.buf.extend_from_slice(
            &rustbgpd_wire::encode_message(&Message::Notification(notification)).unwrap(),
        );

        session.process_read_buffer().await;

        let event = event_rx
            .try_recv()
            .expect("malformed communication still emits the outer notification");
        assert_eq!(event.direction, SessionNotificationDirection::Received);
        assert_eq!(event.code, NotificationCode::Cease.as_u8());
        assert_eq!(event.subcode, expected_subcode);
        assert_eq!(event.shutdown_reason, None);
        assert!(
            matches!(rib_rx.try_recv(), Ok(RibUpdate::PeerDown { .. })),
            "malformed optional data must still drive the normal PeerDown path"
        );
        assert_eq!(session.fsm.state(), SessionState::Idle);
    }
}

/// Load-bearing local-event proof: replacing the extractor result with `None`
/// makes every reason assertion red. The direct Administrative Shutdown/Reset
/// cases and single RFC 8538 envelope also prove the sent-event path reports
/// the final on-wire notification without lossy reconstruction.
#[tokio::test]
async fn locally_sent_notification_events_report_direct_and_hard_reset_shutdown_reasons() {
    let reason = "operator requested";
    let encoded_reason = rustbgpd_wire::notification::encode_shutdown_communication(reason);
    let mut hard_reset_data = vec![
        NotificationCode::Cease.as_u8(),
        cease_subcode::ADMINISTRATIVE_SHUTDOWN,
    ];
    hard_reset_data.extend_from_slice(&encoded_reason);

    for notification in [
        NotificationMessage::new(
            NotificationCode::Cease,
            cease_subcode::ADMINISTRATIVE_SHUTDOWN,
            encoded_reason.clone(),
        ),
        NotificationMessage::new(
            NotificationCode::Cease,
            cease_subcode::ADMINISTRATIVE_RESET,
            encoded_reason.clone(),
        ),
        NotificationMessage::new(
            NotificationCode::Cease,
            cease_subcode::HARD_RESET,
            hard_reset_data.into(),
        ),
    ] {
        let expected_subcode = notification.subcode;
        let mut session = make_test_session(65001, 65002);
        let (event_tx, mut event_rx) = mpsc::channel(2);
        session.session_event_tx = Some(event_tx);

        session
            .execute_actions(vec![Action::SendNotification(notification)])
            .await;

        let event = event_rx.try_recv().expect("one sent-notification event");
        assert_eq!(event.direction, SessionNotificationDirection::Sent);
        assert_eq!(event.code, NotificationCode::Cease.as_u8());
        assert_eq!(event.subcode, expected_subcode);
        assert_eq!(event.shutdown_reason.as_deref(), Some(reason));
        assert_eq!(event.failure_cause, None);
    }
}

/// Load-bearing shipped-command proof: dropping the reason while translating
/// `PeerCommand::Stop` to `ManualStop`, or replacing the sent-event extractor
/// result with `None`, loses the exact event reason; dropping the FSM payload
/// propagation changes the on-wire data assertion.
#[tokio::test]
async fn stop_command_sends_and_reports_exact_shutdown_communication() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    while rib_rx.try_recv().is_ok() {}
    let (event_tx, mut event_rx) = mpsc::channel(2);
    session.session_event_tx = Some(event_tx);
    let encoded_reason =
        rustbgpd_wire::notification::encode_shutdown_communication("planned maintenance");

    assert_eq!(
        session
            .handle_command(PeerCommand::Stop {
                reason: Some(encoded_reason.clone()),
            })
            .await,
        ControlFlow::Continue(())
    );

    let event = event_rx.try_recv().expect("one sent-notification event");
    assert_eq!(event.direction, SessionNotificationDirection::Sent);
    assert_eq!(event.code, NotificationCode::Cease.as_u8());
    assert_eq!(event.subcode, cease_subcode::ADMINISTRATIVE_SHUTDOWN);
    assert_eq!(
        event.shutdown_reason.as_deref(),
        Some("planned maintenance")
    );
    assert_eq!(event.failure_cause, None);
    let notification = read_until_notification(&mut server).await;
    assert_eq!(notification.code, NotificationCode::Cease);
    assert_eq!(notification.subcode, cease_subcode::ADMINISTRATIVE_SHUTDOWN);
    assert_eq!(notification.data, encoded_reason);
}

/// Mutant: removing the sent-admin guard mislabels intentional local maintenance.
#[test]
fn administrative_notifications_keep_directional_maintenance_semantics() {
    let mut session = make_test_session(65001, 65002);
    session.last_error = "previous actionable failure".to_string();
    for subcode in [
        cease_subcode::ADMINISTRATIVE_SHUTDOWN,
        cease_subcode::ADMINISTRATIVE_RESET,
    ] {
        let notification = NotificationMessage::new(NotificationCode::Cease, subcode, Bytes::new());
        session.record_notification_cause(SessionNotificationDirection::Sent, &notification);
        assert_eq!(session.last_error, "previous actionable failure");
    }
    let reset = NotificationMessage::new(
        NotificationCode::Cease,
        cease_subcode::ADMINISTRATIVE_RESET,
        Bytes::new(),
    );
    session.record_notification_cause(SessionNotificationDirection::Received, &reset);
    assert_eq!(
        session.last_error,
        "received NOTIFICATION 6/4 (Administrative Reset)"
    );
}

#[test]
fn notification_teardown_detects_inbound_notification() {
    let event = Event::NotificationReceived(NotificationMessage::new(
        NotificationCode::Cease,
        cease_subcode::ADMINISTRATIVE_SHUTDOWN,
        Bytes::new(),
    ));
    let actions = vec![Action::SessionDown];
    assert!(notification_teardown_event(&event, &actions));
}

#[test]
fn notification_teardown_detects_local_notification_path() {
    let event = Event::ManualStop { reason: None };
    let actions = vec![
        Action::SessionDown,
        Action::SendNotification(NotificationMessage::new(
            NotificationCode::Cease,
            cease_subcode::ADMINISTRATIVE_SHUTDOWN,
            Bytes::new(),
        )),
    ];
    assert!(notification_teardown_event(&event, &actions));
}

#[test]
fn hard_reset_detected_in_actions() {
    let actions = vec![Action::SendNotification(NotificationMessage::new(
        NotificationCode::Cease,
        cease_subcode::HARD_RESET,
        Bytes::new(),
    ))];
    assert!(hard_reset_notification_in_actions(&actions));
}

#[tokio::test]
async fn notification_teardown_without_n_bit_uses_peer_down() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut neg = negotiated_session(65002, false);
    neg.peer_gr_capable = true;
    neg.peer_restart_time = 120;
    neg.peer_gr_families = vec![rustbgpd_wire::GracefulRestartFamily {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        forwarding_preserved: false,
    }];
    neg.peer_notification_gr = false;
    session.config.peer.graceful_restart = true;
    session.negotiated = Some(neg);
    session.notification_teardown = true;
    session.execute_actions(vec![Action::SessionDown]).await;
    match rib_rx.try_recv().unwrap() {
        RibUpdate::PeerDown { peer, .. } => assert_eq!(peer, session.peer_ip),
        _ => panic!("expected PeerDown"),
    }
}

#[tokio::test]
async fn notification_teardown_with_n_bit_uses_peer_graceful_restart() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut neg = negotiated_session(65002, false);
    neg.peer_gr_capable = true;
    neg.peer_restart_time = 120;
    neg.peer_gr_families = vec![rustbgpd_wire::GracefulRestartFamily {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        forwarding_preserved: false,
    }];
    neg.peer_notification_gr = true;
    session.config.peer.graceful_restart = true;
    session.negotiated = Some(neg);
    session.notification_teardown = true;
    session.execute_actions(vec![Action::SessionDown]).await;
    match rib_rx.try_recv().unwrap() {
        RibUpdate::PeerGracefulRestart { peer, .. } => assert_eq!(peer, session.peer_ip),
        _ => panic!("expected PeerGracefulRestart"),
    }
}

#[tokio::test]
async fn peer_gr_restart_time_is_capped_before_rib_retention() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut neg = negotiated_session(65002, false);
    neg.peer_gr_capable = true;
    neg.peer_restart_time = 4095;
    neg.peer_gr_families = vec![rustbgpd_wire::GracefulRestartFamily {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        forwarding_preserved: false,
    }];
    session.config.peer.graceful_restart = true;
    session.config.gr_peer_restart_time_max = 300;
    session.negotiated = Some(neg);

    session.execute_actions(vec![Action::SessionDown]).await;

    // Load-bearing regression proof: removing the `.min()` at the
    // SessionDown-to-RIB boundary makes this observe the peer's 4095 instead
    // of the local 300-second safety bound.
    match rib_rx.try_recv().unwrap() {
        RibUpdate::PeerGracefulRestart { restart_time, .. } => {
            assert_eq!(restart_time, 300);
        }
        _ => panic!("expected PeerGracefulRestart"),
    }
}

#[tokio::test]
async fn hard_reset_always_bypasses_gr_even_with_n_bit() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut neg = negotiated_session(65002, false);
    neg.peer_gr_capable = true;
    neg.peer_restart_time = 120;
    neg.peer_gr_families = vec![rustbgpd_wire::GracefulRestartFamily {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        forwarding_preserved: false,
    }];
    neg.peer_notification_gr = true;
    session.config.peer.graceful_restart = true;
    session.negotiated = Some(neg);
    session.notification_teardown = true;
    session.received_hard_reset = true;
    session.execute_actions(vec![Action::SessionDown]).await;
    match rib_rx.try_recv().unwrap() {
        RibUpdate::PeerDown { peer, .. } => assert_eq!(peer, session.peer_ip),
        _ => panic!("expected PeerDown"),
    }
}
