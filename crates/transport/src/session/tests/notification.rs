use super::*;

type NotificationLogFields = std::collections::BTreeMap<String, String>;
type NotificationLogBuckets =
    std::collections::HashMap<std::thread::ThreadId, Vec<NotificationLogFields>>;

#[derive(Clone, Default)]
struct NotificationLogCapture {
    events: Arc<std::sync::Mutex<NotificationLogBuckets>>,
}

fn notification_log_capture() -> &'static NotificationLogCapture {
    static CAPTURE: std::sync::OnceLock<NotificationLogCapture> = std::sync::OnceLock::new();
    CAPTURE.get_or_init(|| {
        let capture = NotificationLogCapture::default();
        tracing::subscriber::set_global_default(capture.clone())
            .expect("notification tests require an unclaimed global tracing subscriber");
        capture
    })
}

impl tracing::Subscriber for NotificationLogCapture {
    fn register_callsite(
        &self,
        metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        if notification_log_metadata(metadata) {
            tracing::subscriber::Interest::sometimes()
        } else {
            tracing::subscriber::Interest::never()
        }
    }

    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        notification_log_metadata(metadata)
            && self
                .events
                .lock()
                .unwrap()
                .contains_key(&std::thread::current().id())
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        struct Visitor(std::collections::BTreeMap<String, String>);
        impl tracing::field::Visit for Visitor {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0
                    .insert(field.name().to_string(), format!("{value:?}"));
            }

            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                self.0.insert(field.name().to_string(), value.to_string());
            }

            fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
                self.0.insert(field.name().to_string(), value.to_string());
            }
        }

        let mut visitor = Visitor(std::collections::BTreeMap::new());
        event.record(&mut visitor);
        if let Some(events) = self
            .events
            .lock()
            .unwrap()
            .get_mut(&std::thread::current().id())
        {
            events.push(visitor.0);
        }
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

fn notification_log_metadata(metadata: &tracing::Metadata<'_>) -> bool {
    *metadata.level() == tracing::Level::INFO
        && ["direction", "code", "subcode", "description"]
            .into_iter()
            .all(|field| metadata.fields().field(field).is_some())
}

fn capture_notification_log(
    direction: SessionNotificationDirection,
    notification: &NotificationMessage,
    reason: Option<&str>,
) -> Vec<NotificationLogFields> {
    let session = make_test_session(65001, 65002);
    let capture = notification_log_capture();
    let thread_id = std::thread::current().id();
    assert!(
        capture
            .events
            .lock()
            .unwrap()
            .insert(thread_id, Vec::new())
            .is_none(),
        "notification log capture bucket was already armed for this thread"
    );
    session.log_notification(direction, notification, reason);
    capture
        .events
        .lock()
        .unwrap()
        .remove(&thread_id)
        .expect("armed notification log capture bucket")
}

#[test]
fn notification_logs_are_structured_once_per_direction() {
    let notification = NotificationMessage::new(
        NotificationCode::Cease,
        cease_subcode::ADMINISTRATIVE_SHUTDOWN,
        Bytes::new(),
    );
    for (direction, expected) in [
        (SessionNotificationDirection::Received, "received"),
        (SessionNotificationDirection::Sent, "sent"),
    ] {
        let events = capture_notification_log(direction, &notification, Some("maintenance"));
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].get("message").map(String::as_str),
            Some("BGP NOTIFICATION")
        );
        assert_eq!(
            events[0].get("direction").map(String::as_str),
            Some(expected)
        );
        assert_eq!(events[0].get("code").map(String::as_str), Some("6"));
        assert_eq!(events[0].get("subcode").map(String::as_str), Some("2"));
        assert_eq!(
            events[0].get("description").map(String::as_str),
            Some("Administrative Shutdown")
        );
        assert_eq!(
            events[0].get("reason").map(String::as_str),
            Some("maintenance")
        );
    }
}

#[test]
fn hard_reset_log_keeps_outer_code_and_decodes_inner_description() {
    let notification = NotificationMessage::new(
        NotificationCode::Cease,
        cease_subcode::HARD_RESET,
        Bytes::from(vec![
            NotificationCode::Cease.as_u8(),
            cease_subcode::ADMINISTRATIVE_RESET,
        ]),
    );
    let events =
        capture_notification_log(SessionNotificationDirection::Received, &notification, None);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].get("code").map(String::as_str), Some("6"));
    assert_eq!(events[0].get("subcode").map(String::as_str), Some("9"));
    assert_eq!(
        events[0].get("description").map(String::as_str),
        Some("Hard Reset: Administrative Reset")
    );
    assert!(!events[0].contains_key("reason"));
}

#[test]
fn notification_log_omits_invalid_or_missing_reason() {
    let notification = NotificationMessage::new(
        NotificationCode::Cease,
        cease_subcode::ADMINISTRATIVE_RESET,
        Bytes::from_static(&[1, 0xff]),
    );
    let decoded = rustbgpd_wire::notification::extract_shutdown_communication(&notification)
        .ok()
        .flatten();
    let events = capture_notification_log(
        SessionNotificationDirection::Received,
        &notification,
        decoded,
    );
    assert_eq!(events.len(), 1);
    assert!(!events[0].contains_key("reason"));
}

#[test]
fn notification_log_reason_is_escaped_ascii_and_bounded() {
    let notification = NotificationMessage::new(
        NotificationCode::Cease,
        cease_subcode::ADMINISTRATIVE_RESET,
        Bytes::new(),
    );
    let reason = format!("line\n🦀{}", "x".repeat(600));
    let events = capture_notification_log(
        SessionNotificationDirection::Sent,
        &notification,
        Some(&reason),
    );
    assert_eq!(events.len(), 1);
    let logged = events[0].get("reason").unwrap();
    assert_eq!(logged.len(), 512);
    assert!(logged.is_ascii());
    assert!(!logged.contains('\n'));
    assert!(logged.contains("\\n"));
    assert!(logged.contains("\\u{1f980}"));
}

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

#[tokio::test]
async fn bfd_down_command_sends_direct_or_hard_reset_and_retains_inner_cause() {
    for notification_gr in [false, true] {
        let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
        let (client, mut server) = connected_stream_pair().await;
        session.test_install_stream(client);
        establish_test_session(&mut session, 65002).await;
        while rib_rx.try_recv().is_ok() {}
        Arc::make_mut(session.negotiated.as_mut().expect("negotiated")).peer_notification_gr =
            notification_gr;
        let (event_tx, mut event_rx) = mpsc::channel(2);
        session.session_event_tx = Some(event_tx);

        assert_eq!(
            session.handle_command(PeerCommand::BfdDown).await,
            ControlFlow::Continue(())
        );

        let notification = read_until_notification(&mut server).await;
        assert_eq!(notification.code, NotificationCode::Cease);
        let event = event_rx.try_recv().expect("one sent notification event");
        if notification_gr {
            assert_eq!(notification.subcode, cease_subcode::HARD_RESET);
            assert_eq!(
                notification.data,
                Bytes::from(vec![
                    NotificationCode::Cease.as_u8(),
                    cease_subcode::BFD_DOWN,
                ])
            );
            assert_eq!(event.description, "Hard Reset: BFD Down");
            assert_eq!(
                session.last_error,
                "sent NOTIFICATION 6/9 (Hard Reset: BFD Down)"
            );
        } else {
            assert_eq!(notification.subcode, cease_subcode::BFD_DOWN);
            assert!(notification.data.is_empty());
            assert_eq!(event.description, "BFD Down");
            assert_eq!(session.last_error, "sent NOTIFICATION 6/10 (BFD Down)");
        }
        assert!(matches!(rib_rx.try_recv(), Ok(RibUpdate::PeerDown { .. })));
        assert_eq!(session.fsm.state(), SessionState::Idle);
    }
}

#[tokio::test]
async fn purge_reset_sends_administrative_reset_or_hard_reset_and_forces_peer_down() {
    for notification_gr in [false, true] {
        let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
        let (client, mut server) = connected_stream_pair().await;
        session.test_install_stream(client);
        establish_test_session(&mut session, 65002).await;
        while rib_rx.try_recv().is_ok() {}
        Arc::make_mut(session.negotiated.as_mut().expect("negotiated")).peer_notification_gr =
            notification_gr;

        assert_eq!(
            session.handle_command(PeerCommand::PurgeReset).await,
            ControlFlow::Break(())
        );

        let notification = read_until_notification(&mut server).await;
        assert_eq!(notification.code, NotificationCode::Cease);
        let (subcode, reason_data) = if notification_gr {
            assert_eq!(notification.subcode, cease_subcode::HARD_RESET);
            assert_eq!(
                notification.data.get(..2),
                Some(
                    &[
                        NotificationCode::Cease.as_u8(),
                        cease_subcode::ADMINISTRATIVE_RESET,
                    ][..]
                )
            );
            (notification.data[1], &notification.data[2..])
        } else {
            assert_eq!(notification.subcode, cease_subcode::ADMINISTRATIVE_RESET);
            (notification.subcode, notification.data.as_ref())
        };
        assert_eq!(subcode, cease_subcode::ADMINISTRATIVE_RESET);
        assert_eq!(
            rustbgpd_wire::notification::decode_shutdown_communication(reason_data).unwrap(),
            "path-attribute discard configuration changed"
        );
        assert!(matches!(rib_rx.try_recv(), Ok(RibUpdate::PeerDown { .. })));
        assert!(
            !matches!(rib_rx.try_recv(), Ok(RibUpdate::PeerGracefulRestart { .. })),
            "purge reset must never retain routes under GR"
        );
    }
}

#[tokio::test]
async fn purge_reset_in_idle_clears_routes_retained_by_a_prior_gr_down() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.peer_gr_capable = true;
    negotiated.peer_restart_time = 120;
    negotiated.peer_gr_families = vec![rustbgpd_wire::GracefulRestartFamily {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        forwarding_preserved: false,
    }];
    session.config.peer.graceful_restart = true;
    session.negotiated = Some(Arc::new(negotiated));

    session.execute_actions(vec![Action::SessionDown]).await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::PeerGracefulRestart { .. })
    ));
    assert_eq!(session.fsm.state(), SessionState::Idle);

    assert_eq!(
        session.handle_command(PeerCommand::PurgeReset).await,
        ControlFlow::Break(())
    );
    assert!(matches!(rib_rx.try_recv(), Ok(RibUpdate::PeerDown { .. })));
}

#[tokio::test]
async fn open_sent_bfd_down_clears_a_stale_down_reason() {
    let mut session = make_test_session(65001, 65002);
    session.last_down_reason = Some(PeerDownReason::RemoteNoNotification);
    session.fsm.handle_event(Event::ManualStart);
    session.fsm.handle_event(Event::TcpConnectionConfirmed);
    assert_eq!(session.fsm.state(), SessionState::OpenSent);

    session.drive_fsm(Event::BfdDown).await;

    assert_eq!(session.fsm.state(), SessionState::Idle);
    assert!(session.last_down_reason.is_none());
}

#[tokio::test]
async fn open_confirm_bfd_down_uses_negotiated_notification_gr() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.peer.graceful_restart = true;
    session.fsm = Session::new(session.config.peer.clone());
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.drive_fsm(Event::ManualStart).await;
    session
        .drive_fsm(Event::OpenReceived(rustbgpd_wire::OpenMessage {
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
                Capability::GracefulRestart {
                    restart_state: false,
                    notification: true,
                    restart_time: 120,
                    families: vec![rustbgpd_wire::GracefulRestartFamily {
                        afi: Afi::Ipv4,
                        safi: Safi::Unicast,
                        forwarding_preserved: false,
                    }],
                },
            ],
        }))
        .await;
    assert_eq!(session.fsm.state(), SessionState::OpenConfirm);
    assert!(session.negotiated.is_none());

    session.drive_fsm(Event::BfdDown).await;

    let notification = read_until_notification(&mut server).await;
    assert_eq!(notification.code, NotificationCode::Cease);
    assert_eq!(notification.subcode, cease_subcode::HARD_RESET);
    assert_eq!(
        notification.data,
        Bytes::from(vec![
            NotificationCode::Cease.as_u8(),
            cease_subcode::BFD_DOWN,
        ])
    );
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
    session.negotiated = Some(Arc::new(neg));
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
    session.negotiated = Some(Arc::new(neg));
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
    session.negotiated = Some(Arc::new(neg));

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
    session.negotiated = Some(Arc::new(neg));
    session.notification_teardown = true;
    session.received_hard_reset = true;
    session.execute_actions(vec![Action::SessionDown]).await;
    match rib_rx.try_recv().unwrap() {
        RibUpdate::PeerDown { peer, .. } => assert_eq!(peer, session.peer_ip),
        _ => panic!("expected PeerDown"),
    }
}
