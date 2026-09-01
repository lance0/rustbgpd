use super::*;

type SessionLogFields = std::collections::BTreeMap<String, String>;
type SessionLogBuckets = std::collections::HashMap<std::thread::ThreadId, Vec<SessionLogFields>>;

#[derive(Clone, Default)]
struct SessionLogCapture {
    events: Arc<std::sync::Mutex<SessionLogBuckets>>,
}

fn session_log_capture() -> &'static SessionLogCapture {
    static CAPTURE: std::sync::OnceLock<SessionLogCapture> = std::sync::OnceLock::new();
    CAPTURE.get_or_init(|| {
        let capture = SessionLogCapture::default();
        tracing::subscriber::set_global_default(capture.clone())
            .expect("session log tests require an unclaimed global tracing subscriber");
        capture
    })
}

impl tracing::Subscriber for SessionLogCapture {
    fn register_callsite(
        &self,
        metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        if session_log_metadata(metadata) {
            tracing::subscriber::Interest::sometimes()
        } else {
            tracing::subscriber::Interest::never()
        }
    }

    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        session_log_metadata(metadata)
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

            fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
                self.0.insert(field.name().to_string(), value.to_string());
            }
        }

        let mut visitor = Visitor(std::collections::BTreeMap::new());
        visitor
            .0
            .insert("level".to_string(), event.metadata().level().to_string());
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

fn session_log_metadata(metadata: &tracing::Metadata<'_>) -> bool {
    notification_log_metadata(metadata) || connect_failure_log_metadata(metadata)
}

fn notification_log_metadata(metadata: &tracing::Metadata<'_>) -> bool {
    *metadata.level() == tracing::Level::INFO
        && ["direction", "code", "subcode", "description"]
            .into_iter()
            .all(|field| metadata.fields().field(field).is_some())
}

fn connect_failure_log_metadata(metadata: &tracing::Metadata<'_>) -> bool {
    ["peer", "error", "failure_source", "previously_established"]
        .into_iter()
        .all(|field| metadata.fields().field(field).is_some())
}

fn capture_session_logs(action: impl FnOnce()) -> Vec<SessionLogFields> {
    let capture = session_log_capture();
    let thread_id = std::thread::current().id();
    assert!(
        capture
            .events
            .lock()
            .unwrap()
            .insert(thread_id, Vec::new())
            .is_none(),
        "session log capture bucket was already armed for this thread"
    );
    action();
    capture
        .events
        .lock()
        .unwrap()
        .remove(&thread_id)
        .expect("armed session log capture bucket")
}

fn capture_notification_log(
    direction: SessionNotificationDirection,
    notification: &NotificationMessage,
    reason: Option<&str>,
) -> Vec<SessionLogFields> {
    let session = make_test_session(65001, 65002);
    capture_session_logs(|| session.log_notification(direction, notification, reason))
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

fn assert_connect_log(
    event: &SessionLogFields,
    level: &str,
    message: &str,
    source: &str,
    previously_established: bool,
    error: &str,
) {
    assert_eq!(event.get("level").map(String::as_str), Some(level));
    assert_eq!(event.get("message").map(String::as_str), Some(message));
    assert_eq!(event.get("peer").map(String::as_str), Some("10.0.0.2"));
    assert_eq!(
        event.get("failure_source").map(String::as_str),
        Some(source)
    );
    assert_eq!(
        event.get("previously_established").map(String::as_str),
        Some(if previously_established {
            "true"
        } else {
            "false"
        })
    );
    assert_eq!(event.get("error").map(String::as_str), Some(error));
}

/// Mutants: raising every retry, suppressing the cold first failure, or using
/// `last_error` as the episode latch changes this exact INFO/DEBUG pair.
#[test]
fn cold_connect_failure_logs_once_and_keeps_refreshing_last_error() {
    let mut session = make_test_session(65001, 65002);
    session.last_error = "prior non-connect failure".to_string();
    let first = "Cannot assign requested address (os error 99)";
    let retry = "Connection refused (os error 111)";

    let events = capture_session_logs(|| {
        session.record_connect_failure(&std::io::Error::other(first));
        session.record_connect_failure(&std::io::Error::other(retry));
    });

    assert_eq!(events.len(), 2);
    assert_connect_log(
        &events[0],
        "INFO",
        "TCP connect failed",
        "socket",
        false,
        first,
    );
    assert_connect_log(
        &events[1],
        "DEBUG",
        "TCP connect failed",
        "socket",
        false,
        retry,
    );
    assert_eq!(session.last_error, retry);
}

/// Mutants: consulting current FSM state rather than completed-epoch history,
/// or sharing the socket/task bit, loses one of these warnings.
#[tokio::test(flavor = "current_thread")]
async fn established_socket_and_first_task_failures_warn_independently() {
    let mut session = make_test_session(65001, 65002);
    session.flap_count = 1;
    let socket = "Network is unreachable (os error 101)";
    let task = tokio::spawn(std::future::pending::<()>());
    task.abort();
    let task = task.await.unwrap_err();
    let exact_task_error = task.to_string();

    let events = capture_session_logs(|| {
        session.record_connect_failure(&std::io::Error::other(socket));
        session.record_connect_task_failure(&task);
        session.record_connect_task_failure(&task);
    });

    assert_eq!(events.len(), 3);
    assert_connect_log(
        &events[0],
        "WARN",
        "TCP connect failed",
        "socket",
        true,
        socket,
    );
    assert_connect_log(
        &events[1],
        "WARN",
        "TCP connect task failed",
        "task",
        true,
        "connect task cancelled",
    );
    assert_connect_log(
        &events[2],
        "DEBUG",
        "TCP connect task failed",
        "task",
        true,
        "connect task cancelled",
    );
    assert_eq!(session.last_error, exact_task_error);
}

/// Mutant: omitting the successful-connect reset leaves the second episode at
/// DEBUG and hides the next outage from default-level logs.
#[test]
fn successful_connect_rearms_failure_visibility() {
    let mut session = make_test_session(65001, 65002);
    let error = "Connection timed out (os error 110)";

    let events = capture_session_logs(|| {
        session.record_connect_failure(&std::io::Error::other(error));
        session.record_connect_failure(&std::io::Error::other(error));
        session.reset_connect_failure_episode();
        session.record_connect_failure(&std::io::Error::other(error));
    });

    assert_eq!(events.len(), 3);
    assert_eq!(events[0].get("level").map(String::as_str), Some("INFO"));
    assert_eq!(events[1].get("level").map(String::as_str), Some("DEBUG"));
    assert_eq!(events[2].get("level").map(String::as_str), Some("INFO"));
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

/// An operator reset is a NOTIFICATION teardown that leaves administrative
/// state alone: Cease/Administrative Reset carries the communication (wrapped
/// in Cease/Hard Reset when the peer negotiated Notification GR), the actor
/// keeps running, and the Idle transition arms the ordinary reconnect timer.
#[tokio::test]
async fn administrative_reset_sends_cease_with_reason_and_arms_reconnect() {
    for notification_gr in [false, true] {
        let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
        let (client, mut server) = connected_stream_pair().await;
        session.test_install_stream(client);
        establish_test_session(&mut session, 65002).await;
        while rib_rx.try_recv().is_ok() {}
        Arc::make_mut(session.negotiated.as_mut().expect("negotiated")).peer_notification_gr =
            notification_gr;

        let reason =
            rustbgpd_wire::notification::encode_shutdown_communication("maintenance window");
        assert_eq!(
            session
                .handle_command(PeerCommand::AdministrativeReset {
                    reason: Some(reason),
                })
                .await,
            ControlFlow::Continue(())
        );

        let notification = read_until_notification(&mut server).await;
        assert_eq!(notification.code, NotificationCode::Cease);
        let reason_data = if notification_gr {
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
            &notification.data[2..]
        } else {
            assert_eq!(notification.subcode, cease_subcode::ADMINISTRATIVE_RESET);
            notification.data.as_ref()
        };
        assert_eq!(
            rustbgpd_wire::notification::decode_shutdown_communication(reason_data).unwrap(),
            "maintenance window"
        );
        assert!(matches!(rib_rx.try_recv(), Ok(RibUpdate::PeerDown { .. })));
        assert_eq!(session.fsm.state(), SessionState::Idle);
        assert!(
            !session.stop_requested,
            "a reset must not latch the administrative stop"
        );
        assert!(
            session.reconnect_timer.is_some(),
            "the Idle transition must arm the reconnect timer"
        );
    }
}

#[tokio::test]
async fn administrative_reset_in_idle_is_a_no_op() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    assert_eq!(session.fsm.state(), SessionState::Idle);

    assert_eq!(
        session
            .handle_command(PeerCommand::AdministrativeReset { reason: None })
            .await,
        ControlFlow::Continue(())
    );

    assert!(
        rib_rx.try_recv().is_err(),
        "an idle session has nothing to tear down"
    );
    assert_eq!(session.fsm.state(), SessionState::Idle);
    assert!(session.reconnect_timer.is_none());
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

// ── NOTIFICATION Idle reconnect backoff ──────────────────────────────

/// Seconds until the armed deferred reconnect fires, read under paused time.
fn pending_reconnect_secs(session: &PeerSession) -> u64 {
    session
        .reconnect_timer
        .as_ref()
        .expect("fall to Idle must arm the deferred reconnect")
        .deadline()
        .saturating_duration_since(tokio::time::Instant::now())
        .as_secs()
}

fn peer_cease() -> Event {
    Event::NotificationReceived(NotificationMessage::new(
        NotificationCode::Cease,
        cease_subcode::ADMINISTRATIVE_SHUTDOWN,
        Bytes::new(),
    ))
}

fn peer_open(my_as: u16) -> Event {
    Event::OpenReceived(rustbgpd_wire::OpenMessage {
        version: 4,
        my_as,
        hold_time: 90,
        bgp_identifier: Ipv4Addr::new(10, 0, 0, 2),
        capabilities: vec![
            Capability::MultiProtocol {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            },
            Capability::FourOctetAs {
                asn: u32::from(my_as),
            },
        ],
    })
}

/// Let the pending reconnect "fire" the way the run loop does, bring the
/// session to Established over a fresh loopback stream, then tear it down
/// with a peer NOTIFICATION. Returns the wait armed for the next reconnect.
async fn notification_cycle(session: &mut PeerSession) -> u64 {
    session.reconnect_timer = None;
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(session, 65002).await;
    session.drive_fsm(peer_cease()).await;
    assert_eq!(session.fsm.state(), SessionState::Idle);
    pending_reconnect_secs(session)
}

async fn queried_reconnect_in_secs(session: &mut PeerSession) -> u64 {
    let (reply, state) = oneshot::channel();
    assert!(matches!(
        session
            .handle_command(PeerCommand::QueryState { reply })
            .await,
        ControlFlow::Continue(())
    ));
    state.await.unwrap().reconnect_in_secs
}

#[tokio::test(start_paused = true)]
async fn notification_idle_reconnect_doubles_per_failure_up_to_cap() {
    let mut session = make_test_session(65001, 65002);
    let mut waits = Vec::new();
    for _ in 0..6 {
        waits.push(notification_cycle(&mut session).await);
    }
    assert_eq!(waits, [30, 60, 120, 240, 300, 300]);
    assert_eq!(session.notification_idle_failures, 6);
}

#[tokio::test(start_paused = true)]
async fn notification_idle_backoff_never_shrinks_a_connect_retry_above_the_cap() {
    let mut peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    peer_config.connect_retry_secs = 600;
    peer_config.families = vec![(Afi::Ipv4, Safi::Unicast)];
    let mut session = make_test_session_with_peer_config(peer_config);
    assert_eq!(notification_cycle(&mut session).await, 600);
    assert_eq!(notification_cycle(&mut session).await, 600);
}

#[tokio::test(start_paused = true)]
async fn open_rejected_with_notification_counts_toward_idle_backoff() {
    let mut session = make_test_session(65001, 65002);
    for expected in [30, 60, 120] {
        session.reconnect_timer = None;
        let (client, _server) = connected_stream_pair().await;
        session.test_install_stream(client);
        session.drive_fsm(Event::ManualStart).await;
        assert_eq!(session.fsm.state(), SessionState::OpenSent);
        let sent_before = session.notifications_sent;
        session.drive_fsm(peer_open(65003)).await;
        assert_eq!(session.fsm.state(), SessionState::Idle);
        assert_eq!(session.notifications_sent, sent_before + 1);
        assert_eq!(pending_reconnect_secs(&session), expected);
    }
}

#[tokio::test(start_paused = true)]
async fn healthy_established_session_forgets_notification_idle_backoff() {
    let mut session = make_test_session(65001, 65002);
    notification_cycle(&mut session).await;
    assert_eq!(notification_cycle(&mut session).await, 60);

    // One second short of the healthy window keeps the streak.
    session.reconnect_timer = None;
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    tokio::time::advance(
        fsm::HEALTHY_ESTABLISHED
            .checked_sub(Duration::from_secs(1))
            .unwrap(),
    )
    .await;
    session.drive_fsm(peer_cease()).await;
    assert_eq!(pending_reconnect_secs(&session), 120);

    // A session that lasts the full window restarts from the base interval.
    session.reconnect_timer = None;
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    tokio::time::advance(fsm::HEALTHY_ESTABLISHED).await;
    session.drive_fsm(peer_cease()).await;
    assert_eq!(pending_reconnect_secs(&session), 30);
    assert_eq!(session.notification_idle_failures, 1);
}

#[tokio::test(start_paused = true)]
async fn tcp_failures_keep_fixed_retries_alongside_notification_idle_backoff() {
    let mut session = make_test_session(65001, 65002);
    notification_cycle(&mut session).await;
    assert_eq!(notification_cycle(&mut session).await, 60);

    // Connect-phase TCP misses stay on the FSM's fast retry curve and never
    // arm the deferred reconnect.
    session.reconnect_timer = None;
    session.drive_fsm(Event::ManualStart).await;
    assert_eq!(session.fsm.state(), SessionState::Connect);
    for _ in 0..2 {
        session.drive_fsm(Event::TcpConnectionFails).await;
        assert_eq!(session.fsm.state(), SessionState::Active);
        let retry = session
            .timers
            .connect_retry
            .as_ref()
            .expect("TCP miss restarts the FSM connect-retry timer")
            .deadline()
            .saturating_duration_since(tokio::time::Instant::now());
        assert_eq!(retry, Duration::from_secs(1));
        assert!(session.reconnect_timer.is_none());
    }
    assert_eq!(session.notification_idle_failures, 2);

    // An Established session lost to a TCP failure keeps the configured
    // Idle wait and neither advances nor forgets the NOTIFICATION streak.
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.drive_fsm(Event::TcpConnectionConfirmed).await;
    session.drive_fsm(peer_open(65002)).await;
    session.drive_fsm(Event::KeepaliveReceived).await;
    assert_eq!(session.fsm.state(), SessionState::Established);
    session.drive_fsm(Event::TcpConnectionFails).await;
    assert_eq!(session.fsm.state(), SessionState::Idle);
    assert_eq!(pending_reconnect_secs(&session), 30);
    assert_eq!(session.notification_idle_failures, 2);
    assert_eq!(notification_cycle(&mut session).await, 120);
}

#[tokio::test(start_paused = true)]
async fn max_prefix_latch_ignores_notification_idle_backoff() {
    let mut session = make_test_session(65001, 65002);
    session.config.max_prefixes = Some(1);
    notification_cycle(&mut session).await;
    assert_eq!(notification_cycle(&mut session).await, 60);

    session.reconnect_timer = None;
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    install_test_negotiated_session(&mut session, negotiated_session(65002, false));
    session
        .process_update(ipv4_announce(v4_prefix(1), 0, false))
        .await;
    session
        .process_update(ipv4_announce(v4_prefix(2), 0, false))
        .await;
    assert_eq!(session.fsm.state(), SessionState::Idle);
    assert!(session.stop_requested, "max-prefix must stay latched");
    assert!(
        session.reconnect_timer.is_none(),
        "the latch must not arm a deferred reconnect"
    );
    assert_eq!(session.notification_idle_failures, 2);

    // Explicit enable recovers the latch and clears the streak together.
    assert!(matches!(
        session.handle_command(PeerCommand::Start).await,
        ControlFlow::Continue(())
    ));
    assert!(!session.stop_requested);
    assert_eq!(session.notification_idle_failures, 0);
}

#[tokio::test(start_paused = true)]
async fn enable_clears_notification_idle_backoff() {
    let mut session = make_test_session(65001, 65002);
    notification_cycle(&mut session).await;
    assert_eq!(notification_cycle(&mut session).await, 60);

    assert!(matches!(
        session
            .handle_command(PeerCommand::Stop { reason: None })
            .await,
        ControlFlow::Continue(())
    ));
    assert_eq!(session.fsm.state(), SessionState::Idle);
    assert!(session.reconnect_timer.is_none());
    assert_eq!(session.notification_idle_failures, 2);

    assert!(matches!(
        session.handle_command(PeerCommand::Start).await,
        ControlFlow::Continue(())
    ));
    assert_eq!(session.fsm.state(), SessionState::Connect);
    assert!(session.reconnect_timer.is_none());
    assert_eq!(session.notification_idle_failures, 0);
}

#[tokio::test(start_paused = true)]
async fn administrative_reset_clears_notification_idle_backoff() {
    let mut session = make_test_session(65001, 65002);
    notification_cycle(&mut session).await;
    assert_eq!(notification_cycle(&mut session).await, 60);

    session.reconnect_timer = None;
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    session
        .drive_fsm(Event::AdministrativeReset { reason: None })
        .await;
    assert_eq!(session.fsm.state(), SessionState::Idle);
    assert_eq!(pending_reconnect_secs(&session), 30);
    assert_eq!(session.notification_idle_failures, 0);
    assert_eq!(notification_cycle(&mut session).await, 30);
}

#[tokio::test(start_paused = true)]
async fn query_state_reports_pending_reconnect_wait() {
    let mut session = make_test_session(65001, 65002);
    assert_eq!(queried_reconnect_in_secs(&mut session).await, 0);
    notification_cycle(&mut session).await;
    assert_eq!(notification_cycle(&mut session).await, 60);
    assert_eq!(queried_reconnect_in_secs(&mut session).await, 60);
    tokio::time::advance(Duration::from_secs(10)).await;
    assert_eq!(queried_reconnect_in_secs(&mut session).await, 50);
    tokio::time::advance(Duration::from_millis(49_500)).await;
    assert_eq!(queried_reconnect_in_secs(&mut session).await, 1);

    session.reconnect_timer = None;
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    assert_eq!(queried_reconnect_in_secs(&mut session).await, 0);
}
