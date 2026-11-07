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
    notification_log_metadata(metadata)
        || connect_failure_log_metadata(metadata)
        || writer_failure_log_metadata(metadata)
        || malformed_attribute_warn_metadata(metadata)
        || validation_warn_metadata(metadata)
        || downstream_malformed_warn_metadata(metadata)
        || (*metadata.level() == tracing::Level::WARN
            && metadata.target() == "rustbgpd_transport::session::inbound")
        || (*metadata.level() == tracing::Level::WARN
            && ["peer", "family", "route_type", "discarded"]
                .into_iter()
                .all(|field| metadata.fields().field(field).is_some()))
}

/// The treat-as-withdraw action WARN, the ASPA first-AS WARN, and the OTC
/// rejection WARN.
fn downstream_malformed_warn_metadata(metadata: &tracing::Metadata<'_>) -> bool {
    *metadata.level() == tracing::Level::WARN
        && ["announced", "received_first_as", "rejected"]
            .into_iter()
            .any(|field| metadata.fields().field(field).is_some())
}

/// The `UPDATE validation error` WARN.
fn validation_warn_metadata(metadata: &tracing::Metadata<'_>) -> bool {
    *metadata.level() == tracing::Level::WARN
        && metadata.fields().field("max_as_path_length").is_some()
}

/// Any per-attribute or per-UPDATE RFC 7606 malformed-attribute WARN.
fn malformed_attribute_warn_metadata(metadata: &tracing::Metadata<'_>) -> bool {
    *metadata.level() == tracing::Level::WARN
        && ["peer", "attr_type", "disposition", "error"]
            .into_iter()
            .all(|field| metadata.fields().field(field).is_some())
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

fn writer_failure_log_metadata(metadata: &tracing::Metadata<'_>) -> bool {
    *metadata.level() == tracing::Level::WARN && metadata.fields().field("error_kind").is_some()
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
    // An earlier registration can overwrite subscriber installation's rebuild.
    tracing::callsite::rebuild_interest_cache();
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
async fn administrative_reset_in_idle_reconnects_without_teardown() {
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
    assert_eq!(session.fsm.state(), SessionState::Connect);
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
    for helper_only in [false, true] {
        let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
        session.config.peer.graceful_restart = true;
        session.fsm = Session::new(session.config.peer.clone());
        let (client, mut server) = connected_stream_pair().await;
        session.test_install_stream(client);
        session.drive_fsm(Event::ManualStart).await;
        session
            .drive_fsm(Event::OpenReceived(notification_gr_open(helper_only)))
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
        session.record_notification_cause(SessionNotificationDirection::Sent, &notification, None);
        assert_eq!(session.last_error, "previous actionable failure");
    }
    let reset = NotificationMessage::new(
        NotificationCode::Cease,
        cease_subcode::ADMINISTRATIVE_RESET,
        Bytes::new(),
    );
    session.record_notification_cause(SessionNotificationDirection::Received, &reset, None);
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
        RibUpdate::PeerDown { peer, .. } => assert_eq!(peer, PeerId::from_addr(session.peer_ip)),
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
        RibUpdate::PeerGracefulRestart { peer, .. } => {
            assert_eq!(peer, PeerId::from_addr(session.peer_ip));
        }
        _ => panic!("expected PeerGracefulRestart"),
    }
}

/// RFC 9494 §4.2: a peer whose GR capability lists no family, but whose LLGR
/// capability lists one, still gets that family retained under LLGR when LLGR
/// is configured locally.
#[tokio::test]
async fn llgr_only_peer_session_down_enters_retention_when_llgr_configured() {
    for (local_llgr_stale_time, expect_retention) in [(3600, true), (0, false)] {
        let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
        let mut neg = negotiated_session(65002, false);
        neg.peer_gr_capable = false;
        neg.peer_llgr_capable = true;
        neg.peer_llgr_families = vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            forwarding_preserved: true,
            stale_time: 3600,
        }];
        session.config.peer.graceful_restart = true;
        session.config.llgr_stale_time = local_llgr_stale_time;
        session.negotiated = Some(Arc::new(neg));
        session.execute_actions(vec![Action::SessionDown]).await;
        match rib_rx.try_recv().unwrap() {
            RibUpdate::PeerGracefulRestart {
                gr_families,
                peer_llgr_families,
                ..
            } => {
                assert!(
                    expect_retention,
                    "LLGR not configured locally: no retention"
                );
                assert_eq!(gr_families.len(), 0);
                assert_eq!(peer_llgr_families.len(), 1);
            }
            RibUpdate::PeerDown { .. } => {
                assert!(!expect_retention, "LLGR-only peer must enter retention");
            }
            _ => panic!("expected PeerGracefulRestart or PeerDown"),
        }
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
        RibUpdate::PeerDown { peer, .. } => assert_eq!(peer, PeerId::from_addr(session.peer_ip)),
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
        let sent_before = session.config.neighbor_counters.notifications_sent();
        session.drive_fsm(peer_open(65003)).await;
        assert_eq!(session.fsm.state(), SessionState::Idle);
        assert_eq!(
            session.config.neighbor_counters.notifications_sent(),
            sent_before + 1
        );
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

/// An outbound envelope without its exact export snapshot: admitting it
/// raises a local Cease/8.
fn update_without_export_snapshot() -> OutboundRouteUpdate {
    OutboundRouteUpdate {
        announce: vec![make_route(100)].into(),
        next_hop_override: vec![None].into(),
        ..OutboundRouteUpdate::default()
    }
}

/// Finish a local Cease/8 teardown as the run loop's writer-exit arm does.
async fn finish_writer_teardown(session: &mut PeerSession) {
    let join = session.writer_join.take().expect("writer join");
    let exit = tokio::time::timeout(Duration::from_secs(30), join)
        .await
        .expect("the torn-down writer exits");
    session.handle_writer_exit(exit).await;
}

/// A local Cease/8 sent from Established (the outbound admission class)
/// escalates the Idle backoff as any sent NOTIFICATION does.
/// Mutation-red: without the local-NOTIFICATION latch the transport-failure
/// batch keeps the base wait and the streak.
#[tokio::test(start_paused = true)]
async fn local_outbound_cease8_escalates_notification_idle_backoff() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    notification_cycle(&mut session).await;
    assert_eq!(notification_cycle(&mut session).await, 60);
    session.reconnect_timer = None;
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    session
        .handle_outbound_route_update(update_without_export_snapshot())
        .await;
    assert_eq!(
        session.pending_outbound_teardown_cause,
        Some(crate::handle::SessionFailureCause::ExportSnapshotMissing)
    );
    finish_writer_teardown(&mut session).await;
    assert_eq!(session.fsm.state(), SessionState::Idle);
    assert_eq!(
        (
            pending_reconnect_secs(&session),
            session.notification_idle_failures
        ),
        (120, 3)
    );
    // A later plain TCP loss is not a NOTIFICATION teardown.
    session.reconnect_timer = None;
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    session.handle_tcp_read_result(Ok(0)).await;
    assert_eq!(
        (
            pending_reconnect_secs(&session),
            session.notification_idle_failures
        ),
        (30, 3)
    );
}

/// A local Cease/8 before Established (an OPEN exchange that ends in one)
/// escalates the backoff too.
#[tokio::test(start_paused = true)]
async fn local_open_confirm_cease8_escalates_notification_idle_backoff() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    notification_cycle(&mut session).await;
    assert_eq!(notification_cycle(&mut session).await, 60);
    session.reconnect_timer = None;
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.drive_fsm(Event::ManualStart).await;
    session.drive_fsm(peer_open(65002)).await;
    assert_eq!(session.fsm.state(), SessionState::OpenConfirm);
    session.trigger_outbound_out_of_resources_teardown(
        crate::handle::SessionFailureCause::OutboundSaturation,
    );
    finish_writer_teardown(&mut session).await;
    assert_eq!(session.fsm.state(), SessionState::Idle);
    assert_eq!(
        (
            pending_reconnect_secs(&session),
            session.notification_idle_failures
        ),
        (120, 3)
    );
}

/// An administrative reset whose close drain raises a Cease/8 is still the
/// operator's reset: it clears the streak and keeps the base wait.
/// Mutation-red: without the reset arm's clear the drained Cease/8 escalates.
#[tokio::test(start_paused = true)]
async fn administrative_reset_drain_cease8_clears_notification_idle_backoff() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    notification_cycle(&mut session).await;
    assert_eq!(notification_cycle(&mut session).await, 60);
    session.reconnect_timer = None;
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    session
        .outbound_tx
        .send(update_without_export_snapshot())
        .await
        .unwrap();
    let reset = session.handle_command(PeerCommand::AdministrativeReset { reason: None });
    let _ = tokio::time::timeout(Duration::from_secs(30), reset)
        .await
        .expect("the reset settles");
    assert_eq!(
        session.config.neighbor_counters.notifications_sent(),
        1,
        "the drain's Cease/8 is the only NOTIFICATION"
    );
    assert_eq!(session.fsm.state(), SessionState::Idle);
    assert_eq!(
        (
            pending_reconnect_secs(&session),
            session.notification_idle_failures
        ),
        (30, 0)
    );
    assert_eq!(notification_cycle(&mut session).await, 30);
}

/// A reset handled after a local Cease/8 but before its writer exit is
/// observed is still the operator's reset: the exclusion wins over the
/// latch the reset batch takes.
/// Mutation-red: counting the taken latch ahead of the exclusion leaves
/// `(30, 1)`.
#[tokio::test(start_paused = true)]
async fn reset_before_cease8_writer_exit_clears_notification_idle_backoff() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    notification_cycle(&mut session).await;
    assert_eq!(notification_cycle(&mut session).await, 60);
    session.reconnect_timer = None;
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    session
        .handle_outbound_route_update(update_without_export_snapshot())
        .await;
    assert!(session.local_notification_teardown);
    let _ = session
        .handle_command(PeerCommand::AdministrativeReset { reason: None })
        .await;
    assert_eq!(session.fsm.state(), SessionState::Idle);
    assert!(
        !session.local_notification_teardown,
        "reset batch took the latch"
    );
    assert_eq!(
        (
            pending_reconnect_secs(&session),
            session.notification_idle_failures
        ),
        (30, 0)
    );
    finish_writer_teardown(&mut session).await;
    assert_eq!(
        (
            pending_reconnect_secs(&session),
            session.notification_idle_failures
        ),
        (30, 0)
    );
}

/// A Stop handled after a local Cease/8 but before its writer exit leaves no
/// latch behind for a later Start's session.
#[tokio::test(start_paused = true)]
async fn stop_then_start_after_cease8_does_not_leak_the_latch() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    session
        .handle_outbound_route_update(update_without_export_snapshot())
        .await;
    let _ = session
        .handle_command(PeerCommand::Stop { reason: None })
        .await;
    assert!(!session.local_notification_teardown);
    finish_writer_teardown(&mut session).await;
    assert!(!session.local_notification_teardown);
    let _ = session.handle_command(PeerCommand::Start).await;
    if let Some(task) = session.connect_task.take() {
        task.abort();
    }
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.drive_fsm(Event::TcpConnectionConfirmed).await;
    session.drive_fsm(peer_open(65002)).await;
    session.drive_fsm(Event::KeepaliveReceived).await;
    assert_eq!(session.fsm.state(), SessionState::Established);
    session.handle_tcp_read_result(Ok(0)).await;
    assert_eq!(
        (
            pending_reconnect_secs(&session),
            session.notification_idle_failures
        ),
        (30, 0)
    );
}

#[tokio::test(start_paused = true)]
async fn administrative_reset_in_idle_clears_notification_backoff_and_reconnects() {
    let mut session = make_test_session(65001, 65002);
    notification_cycle(&mut session).await;
    assert_eq!(notification_cycle(&mut session).await, 60);
    assert_eq!(session.fsm.state(), SessionState::Idle);
    assert!(session.reconnect_timer.is_some());
    assert_eq!(session.notification_idle_failures, 2);

    assert!(matches!(
        session
            .handle_command(PeerCommand::AdministrativeReset { reason: None })
            .await,
        ControlFlow::Continue(())
    ));
    assert_eq!(session.fsm.state(), SessionState::Connect);
    assert!(session.reconnect_timer.is_none());
    assert_eq!(session.notification_idle_failures, 0);

    // Complete the reconnect handshake and tear it down with a NOTIFICATION.
    // Backoff restarts from the base 30s instead of continuing from 120s.
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.drive_fsm(Event::TcpConnectionConfirmed).await;
    session.drive_fsm(peer_open(65002)).await;
    session.drive_fsm(Event::KeepaliveReceived).await;
    assert_eq!(session.fsm.state(), SessionState::Established);

    session.drive_fsm(peer_cease()).await;
    assert_eq!(session.fsm.state(), SessionState::Idle);
    assert_eq!(pending_reconnect_secs(&session), 30);
    assert_eq!(session.notification_idle_failures, 1);
}

#[tokio::test(start_paused = true)]
async fn administrative_reset_in_idle_when_stopped_clears_backoff_without_reconnecting() {
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
    assert!(session.stop_requested);

    assert!(matches!(
        session
            .handle_command(PeerCommand::AdministrativeReset { reason: None })
            .await,
        ControlFlow::Continue(())
    ));
    assert_eq!(session.fsm.state(), SessionState::Idle);
    assert!(session.reconnect_timer.is_none());
    assert_eq!(session.notification_idle_failures, 0);
    assert!(session.stop_requested);
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

async fn queried_notification_failures(session: &mut PeerSession) -> u32 {
    let (reply, state) = oneshot::channel();
    assert!(matches!(
        session
            .handle_command(PeerCommand::QueryState { reply })
            .await,
        ControlFlow::Continue(())
    ));
    state.await.unwrap().notification_idle_failures
}

/// A neighbor that reconnects to us after each NOTIFICATION teardown gets a
/// fresh session every cycle. `StartInbound` carries the replaced session's
/// streak, so the backoff keeps escalating across those replacements; an
/// operator `Start` still clears it.
#[tokio::test(start_paused = true)]
async fn inbound_replacement_keeps_escalating_the_notification_backoff() {
    let mut replaced = make_test_session(65001, 65002);
    notification_cycle(&mut replaced).await;
    assert_eq!(notification_cycle(&mut replaced).await, 60);
    let carried = queried_notification_failures(&mut replaced).await;
    assert_eq!(carried, 2);

    let mut replacement = make_test_session(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    replacement.test_install_stream(client);
    assert!(matches!(
        replacement
            .handle_command(PeerCommand::StartInbound {
                notification_idle_failures: carried,
            })
            .await,
        ControlFlow::Continue(())
    ));
    assert_eq!(replacement.fsm.state(), SessionState::OpenSent);
    replacement.drive_fsm(peer_open(65002)).await;
    replacement.drive_fsm(Event::KeepaliveReceived).await;
    replacement.drive_fsm(peer_cease()).await;
    assert_eq!(
        pending_reconnect_secs(&replacement),
        120,
        "the third consecutive NOTIFICATION must keep doubling the wait"
    );

    replacement.reconnect_timer = None;
    assert!(matches!(
        replacement.handle_command(PeerCommand::Start).await,
        ControlFlow::Continue(())
    ));
    assert_eq!(queried_notification_failures(&mut replacement).await, 0);
}

/// A neighbor that *sends* the NOTIFICATION (the `OpenBGPD` UPDATE-error 3/9
/// reset loop) feeds the same streak as one we send. After two such teardowns
/// the queried state is exactly what `PeerManager` holds inbound on: Idle, a
/// pending reconnect, and a streak of 2.
#[tokio::test(start_paused = true)]
async fn received_notification_teardowns_arm_the_inbound_hold_state() {
    let mut session = make_test_session(65001, 65002);
    for expected_wait in [30, 60] {
        session.reconnect_timer = None;
        let (client, _server) = connected_stream_pair().await;
        session.test_install_stream(client);
        establish_test_session(&mut session, 65002).await;
        session
            .drive_fsm(Event::NotificationReceived(NotificationMessage::new(
                NotificationCode::UpdateMessage,
                9,
                Bytes::new(),
            )))
            .await;
        assert_eq!(session.fsm.state(), SessionState::Idle);
        assert_eq!(pending_reconnect_secs(&session), expected_wait);
    }
    let (reply, state) = oneshot::channel();
    assert!(matches!(
        session
            .handle_command(PeerCommand::QueryState { reply })
            .await,
        ControlFlow::Continue(())
    ));
    let state = state.await.unwrap();
    assert_eq!(state.fsm_state, SessionState::Idle);
    assert_eq!(state.notification_idle_failures, 2);
    assert_eq!(state.reconnect_in_secs, 60);
}

/// Collision promotion hands the retiring primary's streak to the survivor,
/// keeping whichever streak is longer.
#[tokio::test]
async fn promotion_keeps_the_longer_notification_streak() {
    for (own, carried, expected) in [(0, 2, 2), (3, 1, 3)] {
        let mut candidate = make_test_session(65001, 65002);
        candidate.notification_idle_failures = own;
        let (reply, done) = oneshot::channel();
        assert!(matches!(
            candidate
                .handle_command(PeerCommand::ActivateMaxPrefixMetrics {
                    notification_idle_failures: carried,
                    reply,
                })
                .await,
            ControlFlow::Continue(())
        ));
        done.await.unwrap();
        assert_eq!(candidate.notification_idle_failures, expected);
    }
}

/// Hold the first registration until the capture has rebuilt callsite interest.
struct DelayedWriterCallsite {
    first: std::sync::atomic::AtomicBool,
    entered: std::sync::mpsc::Sender<()>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

impl tracing::Subscriber for DelayedWriterCallsite {
    fn register_callsite(
        &self,
        metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        if writer_failure_log_metadata(metadata)
            && self.first.swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            self.entered.send(()).unwrap();
            self.release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .expect("capture must install before registration finishes");
        }
        tracing::subscriber::Interest::never()
    }

    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        false
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, _: &tracing::Event<'_>) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// A TCP write failure is logged with the peer and the OS error, like the
/// connect-failure and OPEN-send warnings, so the operator can tell which
/// session failed and why without correlating a bare `error_kind`.
#[test]
fn writer_failure_log_names_peer_and_error() {
    // Callsite registration and the global subscriber are process-wide.
    const CHILD: &str = "RUSTBGPD_WRITER_LOG_REGISTRATION_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "session::tests::notification::writer_failure_log_names_peer_and_error",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let fail_writer = || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let connect =
                tokio::spawn(async move { tokio::net::TcpStream::connect(addr).await.unwrap() });
            let (mut server, _) = listener.accept().await.unwrap();
            let peer = connect.await.unwrap();
            socket2::SockRef::from(&peer)
                .set_linger(Some(Duration::ZERO))
                .unwrap();
            drop(peer);
            // Consume the peer's reset before asking the writer to send.
            let reset = tokio::time::timeout(Duration::from_secs(5), server.read_u8())
                .await
                .expect("peer reset must arrive")
                .unwrap_err();
            assert_eq!(reset.kind(), std::io::ErrorKind::ConnectionReset);
            let (_read, write) = server.into_split();
            let handle = super::writer::spawn(
                write,
                8,
                BgpMetrics::with_registry(prometheus::Registry::new()),
                "10.0.0.2".to_string(),
                None,
            );
            handle.priority_tx.send(Bytes::from_static(&[0])).unwrap();
            let exit = tokio::time::timeout(Duration::from_secs(5), handle.join)
                .await
                .expect("writer must exit once the peer resets the connection")
                .unwrap();
            assert!(
                matches!(exit, Err(super::writer::WriterExit::Io(_))),
                "expected an I/O writer exit, got {exit:?}"
            );
        });
    };
    let (entered_tx, entered) = std::sync::mpsc::channel();
    let (release, release_rx) = std::sync::mpsc::channel();
    let registering = std::thread::spawn(move || {
        tracing::subscriber::with_default(
            DelayedWriterCallsite {
                first: std::sync::atomic::AtomicBool::new(true),
                entered: entered_tx,
                release: std::sync::Mutex::new(release_rx),
            },
            fail_writer,
        );
    });
    entered
        .recv_timeout(Duration::from_secs(5))
        .expect("writer warning must start registering before capture installation");
    session_log_capture();
    // The old registration now overwrites the new capture's cached interest.
    release.send(()).unwrap();
    registering.join().unwrap();
    let events = capture_session_logs(fail_writer);
    let event = events
        .iter()
        .find(|event| {
            event.get("message").map(String::as_str) == Some("writer: write/flush failed")
        })
        .expect("writer failure warning was not logged");
    assert_eq!(event.get("peer").map(String::as_str), Some("10.0.0.2"));
    assert!(
        event.get("error").is_some_and(|error| !error.is_empty()),
        "writer failure warning must carry the OS error: {event:?}"
    );
    assert!(event.contains_key("error_kind"), "{event:?}");
}

#[test]
fn evpn_discard_warnings_are_bounded_per_type_and_connection() {
    let mut session = make_test_session(65001, 65002);
    let events = capture_session_logs(|| {
        for route_type in [0, 6, 255] {
            session.record_evpn_discard(route_type, 2);
            session.record_evpn_discard(route_type, 3);
        }
    });
    assert_eq!(events.len(), 3);
    for (event, route_type) in events.iter().zip(["0", "6", "255"]) {
        assert_eq!(event["level"], "WARN");
        assert_eq!(event["peer"], session.peer_label);
        assert_eq!(event["family"], "evpn");
        assert_eq!(event["route_type"], route_type);
        assert_eq!(event["discarded"], "2");
    }
    let samples = counter_samples(&session.metrics, "bgp_evpn_nlri_discarded_by_type_total");
    assert_eq!(samples.len(), 3);
    assert!(
        samples
            .iter()
            .all(|(_, count)| (*count - 5.0).abs() < f64::EPSILON)
    );
    assert!(
        (counter_samples(&session.metrics, "bgp_evpn_nlri_discarded_total")[0].1 - 15.0).abs()
            < f64::EPSILON
    );

    session.close_tcp();
    assert_eq!(
        capture_session_logs(|| session.record_evpn_discard(6, 1)).len(),
        1
    );
    assert_eq!(
        capture_session_logs(|| session.record_evpn_discard(6, 1)).len(),
        0
    );
    session.handle_tcp_disconnect();
    assert_eq!(
        capture_session_logs(|| session.record_evpn_discard(6, 1)).len(),
        1
    );
    assert!(
        (counter_samples(&session.metrics, "bgp_evpn_nlri_discarded_total")[0].1 - 18.0).abs()
            < f64::EPSILON
    );
}

/// Load-bearing log-volume proof: one WARN per malformed attribute record,
/// or per UPDATE without the per-connection power-of-two gate, fails here.
#[test]
fn duplicate_attribute_warnings_are_bounded_per_update_and_connection() {
    const DUPLICATES: usize = 2_000;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let _server = runtime.block_on(async {
        let (client, server) = connected_stream_pair().await;
        session.test_install_stream(client);
        establish_test_session(&mut session, 65002).await;
        server
    });
    rfc7606_drain(&mut rib_rx);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let mut update = aspa_first_as_update(prefix, 65002, true);
    let mut attributes = update.path_attributes.to_vec();
    for med in 0..=DUPLICATES {
        attributes.extend([0x80, 4, 4, 0, 0, 0, if med == 0 { 42 } else { 9 }]);
    }
    update.path_attributes = Bytes::from(attributes);

    let process = |session: &mut PeerSession| {
        capture_session_logs(|| runtime.block_on(session.process_update(update.clone())))
    };
    let events = process(&mut session);
    assert_eq!(events.len(), 1, "one WARN per UPDATE: {:?}", events.first());
    assert_eq!(events[0]["malformed_attributes"], "1");
    assert_eq!(
        events[0]["coalesced_duplicates"],
        (DUPLICATES - 1).to_string()
    );
    assert_eq!(events[0]["disposition"], "attribute-discard");
    assert_eq!(process(&mut session).len(), 1, "second UPDATE warns");
    assert_eq!(process(&mut session).len(), 0, "third UPDATE is DEBUG only");
    assert_eq!(process(&mut session).len(), 1, "fourth UPDATE warns");
    session.close_tcp();
    let warned: Vec<_> = (0..5).map(|_| process(&mut session).len()).collect();
    assert_eq!(warned, [1, 1, 0, 1, 0], "a new connection re-arms");
    session.handle_tcp_disconnect();
    assert_eq!(process(&mut session).len(), 1, "a disconnect re-arms");

    // RFC 7606 §3 (g) disposition is unchanged: the first MED survives.
    assert_eq!(update_malformed_count(&session, "attribute_discard"), 10);
    assert_eq!(update_malformed_count(&session, "treat_as_withdraw"), 0);
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("attribute-discard keeps the route");
    };
    assert_eq!(announced.len(), 1);
    assert_eq!(announced[0].med(), 42);
}

/// Load-bearing: naming the first record pairs treat-as-withdraw with the
/// earlier duplicate MED instead of the `AS_SET` that caused it.
#[test]
fn malformed_attribute_warning_names_the_cause_of_the_applied_disposition() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let _server = runtime.block_on(async {
        let (client, server) = connected_stream_pair().await;
        session.test_install_stream(client);
        establish_test_session(&mut session, 65002).await;
        server
    });
    rfc7606_drain(&mut rib_rx);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let mut update = aspa_first_as_update(prefix, 65002, true);
    let mut attributes = update.path_attributes.to_vec();
    attributes.extend([0x80, 4, 4, 0, 0, 0, 1, 0x80, 4, 4, 0, 0, 0, 2]); // MED twice
    attributes.extend([0x40, 2, 6, 1, 1, 0, 0, 0xFD, 0xEA]); // AS_PATH again, AS_SET
    update.path_attributes = Bytes::from(attributes);

    let mut events = capture_session_logs(|| runtime.block_on(session.process_update(update)));
    events.retain(|event| !event.contains_key("announced")); // the action, not a cause
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["disposition"], "treat-as-withdraw");
    assert_eq!(events[0]["attr_type"], "2", "{events:?}");
    assert_eq!(update_malformed_count(&session, "treat_as_withdraw"), 1);
}

/// An Established session, its runtime and RIB receiver, and a valid
/// body-NLRI UPDATE (ORIGIN, `AS_PATH`, `NEXT_HOP`) for one prefix.
fn malformed_update_fixture() -> (
    tokio::runtime::Runtime,
    PeerSession,
    tokio::net::TcpStream,
    UpdateMessage,
) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let server = runtime.block_on(async {
        let (client, server) = connected_stream_pair().await;
        session.test_install_stream(client);
        establish_test_session(&mut session, 65002).await;
        server
    });
    rfc7606_drain(&mut rib_rx);
    std::mem::forget(rib_rx);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let update = aspa_first_as_update(prefix, 65002, true);
    assert_eq!(
        &update.path_attributes[..4],
        &[0x40, 1, 1, 0],
        "ORIGIN first"
    );
    (runtime, session, server, update)
}

/// Load-bearing: the summary reports the action finally applied. Duplicate
/// MEDs alone are attribute-discard, but a missing ORIGIN makes validation
/// withdraw the routes; reporting the decoder's discard would misstate it.
#[test]
fn malformed_attribute_warning_reports_the_disposition_validation_applied() {
    let (runtime, mut session, _server, mut update) = malformed_update_fixture();
    let mut attributes = update.path_attributes[4..].to_vec(); // drop ORIGIN
    attributes.extend([0x80, 4, 4, 0, 0, 0, 1, 0x80, 4, 4, 0, 0, 0, 2]); // MED twice
    update.path_attributes = Bytes::from(attributes);

    let events = capture_session_logs(|| runtime.block_on(session.process_update(update)));
    let summary: Vec<_> = events
        .iter()
        .filter(|event| event.contains_key("decoder_disposition"))
        .collect();
    assert_eq!(summary.len(), 1, "{events:?}");
    assert_eq!(summary[0]["disposition"], "treat-as-withdraw", "{events:?}");
    assert_eq!(summary[0]["decoder_disposition"], "attribute-discard");
    assert_eq!(summary[0]["attr_type"], "4");
    assert_eq!(update_malformed_count(&session, "treat_as_withdraw"), 1);
}

/// Load-bearing: a decoder treat-as-withdraw on an UPDATE with no reachable
/// NLRI escalates to a session reset (RFC 7606 §5.2), and the summary says
/// so rather than treat-as-withdraw.
#[test]
fn malformed_attribute_warning_reports_the_section_5_2_session_reset() {
    let (runtime, mut session, _server, mut update) = malformed_update_fixture();
    update.nlri = Bytes::new();
    let mut attributes = update.path_attributes.to_vec();
    attributes.extend([0x40, 2, 6, 1, 1, 0, 0, 0xFD, 0xEA]); // AS_PATH again, AS_SET
    update.path_attributes = Bytes::from(attributes);

    let events = capture_session_logs(|| runtime.block_on(session.process_update(update)));
    let summary: Vec<_> = events
        .iter()
        .filter(|event| event.contains_key("decoder_disposition"))
        .collect();
    assert_eq!(summary.len(), 1, "{events:?}");
    assert_eq!(summary[0]["disposition"], "session-reset", "{events:?}");
    assert_eq!(summary[0]["decoder_disposition"], "treat-as-withdraw");
    assert!(
        events
            .iter()
            .any(|event| event.get("direction").map(String::as_str) == Some("sent")),
        "the reset sends a NOTIFICATION: {events:?}"
    );
    assert_eq!(update_malformed_count(&session, "session_reset"), 1);
}

/// Load-bearing: when the decoder removed a malformed ORIGIN, the
/// validator's missing-ORIGIN finding is the same cause; only the summary
/// reports it.
#[test]
fn decoder_removed_attribute_is_not_reported_again_by_validation() {
    let (runtime, mut session, _server, mut update) = malformed_update_fixture();
    let mut attributes = update.path_attributes.to_vec();
    attributes[3] = 9; // ORIGIN value out of range
    update.path_attributes = Bytes::from(attributes);

    let mut events = capture_session_logs(|| runtime.block_on(session.process_update(update)));
    events.retain(|event| !event.contains_key("announced")); // the action, not a cause
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["attr_type"], "1");
    assert!(events[0].contains_key("decoder_disposition"), "{events:?}");
}

/// Load-bearing log-volume proof: the treat-as-withdraw, validation and ASPA
/// WARNs share the summary's per-connection gate, so a repeated malformed
/// UPDATE warns at counts 1, 2, 4 and 8. Any of them logging once per
/// UPDATE fails here; metrics still count every UPDATE.
#[test]
fn downstream_malformed_update_warnings_share_the_connection_gate() {
    const UPDATES: usize = 8;
    const GATED: usize = 4; // counts 1, 2, 4, 8
    let count = |events: &[SessionLogFields], key: &str| {
        events.iter().filter(|e| e.contains_key(key)).count()
    };
    let stream = |edit: &dyn Fn(&mut UpdateMessage)| {
        let (runtime, mut session, server, mut update) = malformed_update_fixture();
        edit(&mut update);
        let mut events = Vec::new();
        for _ in 0..UPDATES {
            events.extend(capture_session_logs(|| {
                runtime.block_on(session.process_update(update.clone()));
            }));
        }
        session.close_tcp();
        let rearmed =
            capture_session_logs(|| runtime.block_on(session.process_update(update.clone())));
        (session, server, events, rearmed)
    };

    // Decoder treat-as-withdraw: ORIGIN out of range.
    let (session, _server, events, rearmed) = stream(&|update| {
        let mut attributes = update.path_attributes.to_vec();
        attributes[3] = 9;
        update.path_attributes = Bytes::from(attributes);
    });
    assert_eq!(count(&events, "announced"), GATED, "{events:?}");
    assert_eq!(count(&events, "decoder_disposition"), GATED);
    assert_eq!(count(&rearmed, "announced"), 1, "a new connection re-arms");
    assert_eq!(update_malformed_count(&session, "treat_as_withdraw"), 9);

    // Validation treat-as-withdraw: ORIGIN missing.
    let (session, _server, events, _) = stream(&|update| {
        update.path_attributes = update.path_attributes.slice(4..);
    });
    assert_eq!(count(&events, "max_as_path_length"), GATED, "{events:?}");
    assert_eq!(count(&events, "announced"), GATED);
    assert_eq!(update_malformed_count(&session, "treat_as_withdraw"), 9);

    // ASPA first-AS treat-as-withdraw.
    let (session, _server, events, rearmed) = stream(&|update| {
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
        *update = aspa_first_as_update(prefix, 65003, true);
    });
    assert_eq!(count(&events, "received_first_as"), GATED, "{events:?}");
    assert_eq!(count(&rearmed, "received_first_as"), 1);
    assert_eq!(update_malformed_count(&session, "treat_as_withdraw"), 9);
}

/// Process `update` once and return its WARN events.
fn warn_events(
    runtime: &tokio::runtime::Runtime,
    session: &mut PeerSession,
    update: &UpdateMessage,
) -> Vec<SessionLogFields> {
    capture_session_logs(|| runtime.block_on(session.process_update(update.clone())))
}

fn with_attributes(update: &UpdateMessage, edit: impl FnOnce(&mut Vec<u8>)) -> UpdateMessage {
    let mut update = update.clone();
    let mut attributes = update.path_attributes.to_vec();
    edit(&mut attributes);
    update.path_attributes = Bytes::from(attributes);
    update
}

/// Load-bearing: attribute-discard and treat-as-withdraw UPDATEs keep
/// separate WARN schedules, so earlier benign discards do not hold back the
/// first withdrawal's WARNs. One shared counter would put this
/// treat-as-withdraw at count 3 and log nothing.
#[test]
fn attribute_discards_do_not_delay_the_first_withdrawal_warning() {
    let (runtime, mut session, _server, update) = malformed_update_fixture();
    // ATOMIC_AGGREGATE with a value byte: a length error, attribute-discard.
    let discard = with_attributes(&update, |attrs| attrs.extend([0x40, 6, 1, 0]));
    let withdraw = with_attributes(&update, |attrs| attrs[3] = 9); // ORIGIN 9
    for _ in 0..2 {
        warn_events(&runtime, &mut session, &discard);
    }
    let events = warn_events(&runtime, &mut session, &withdraw);
    let count = |key: &str| events.iter().filter(|e| e.contains_key(key)).count();
    assert_eq!(count("announced"), 1, "{events:?}");
    assert_eq!(count("decoder_disposition"), 1, "{events:?}");
    assert_eq!(update_malformed_count(&session, "attribute_discard"), 2);
    assert_eq!(update_malformed_count(&session, "treat_as_withdraw"), 1);
}

/// Load-bearing: the malformed-OTC rejection WARN follows its UPDATE's
/// gate, while the OTC counters still count every rejected announcement.
#[test]
fn malformed_otc_warnings_share_the_connection_gate() {
    let (runtime, mut session, _server, update) = malformed_update_fixture();
    // ONLY_TO_CUSTOMER with a three-byte value: a length error.
    let otc = with_attributes(&update, |attrs| attrs.extend([0xC0, 35, 3, 0, 0, 1]));
    let warned: Vec<_> = (0..8)
        .map(|_| {
            warn_events(&runtime, &mut session, &otc)
                .iter()
                .filter(|e| e.contains_key("rejected"))
                .count()
        })
        .collect();
    assert_eq!(warned, [1, 1, 0, 1, 0, 0, 0, 1]);
    assert_eq!(session.config.neighbor_counters.otc_routes_blocked(), 8);
    session.close_tcp();
    let rearmed = warn_events(&runtime, &mut session, &otc);
    assert_eq!(
        rearmed
            .iter()
            .filter(|e| e.contains_key("rejected"))
            .count(),
        1,
        "a new connection re-arms: {rearmed:?}"
    );
}

/// Load-bearing: an UPDATE that resets the session logs its cause however
/// many malformed UPDATEs came before it. Here the third withdrawal-class
/// UPDATE, not a power of two, escalates under RFC 7606 §5.2: ORIGIN is
/// missing and the only NLRI carrier is an empty `MP_REACH_NLRI`.
#[test]
fn session_reset_logs_its_validation_cause_past_the_first_update() {
    let (runtime, mut session, _server, update) = malformed_update_fixture();
    let withdraw = with_attributes(&update, |attrs| attrs[3] = 9); // ORIGIN 9
    for _ in 0..2 {
        warn_events(&runtime, &mut session, &withdraw);
    }
    let mut reset = with_attributes(&update, |attrs| {
        attrs.drain(..4); // drop ORIGIN
        // MP_REACH_NLRI: IPv4 unicast, next hop 10.0.0.2, no NLRI.
        attrs.extend([0x80, 14, 9, 0, 1, 1, 4, 10, 0, 0, 2, 0]);
    });
    reset.nlri = Bytes::new();
    let events = warn_events(&runtime, &mut session, &reset);
    assert_eq!(
        events
            .iter()
            .filter(|e| e.contains_key("max_as_path_length"))
            .count(),
        1,
        "the reset's validation cause must log: {events:?}"
    );
    assert_eq!(update_malformed_count(&session, "session_reset"), 1);
}

#[derive(Clone, Copy, Debug)]
enum PeerWarningCase {
    UnnegotiatedMpReach,
    ScopedIpv4Body,
    NextHopOwnership,
    OtcPolicy,
}

impl PeerWarningCase {
    const ALL: [Self; 4] = [
        Self::UnnegotiatedMpReach,
        Self::ScopedIpv4Body,
        Self::NextHopOwnership,
        Self::OtcPolicy,
    ];

    fn message(self) -> &'static str {
        match self {
            Self::UnnegotiatedMpReach => "Ignoring MP_REACH_NLRI for non-negotiated family",
            Self::ScopedIpv4Body => "Ignoring IPv4 body NLRI from scoped link-local peer",
            Self::NextHopOwnership => {
                "strict-peer next-hop ownership rejected unicast announcements"
            }
            Self::OtcPolicy => "OTC rule rejected unicast announcements",
        }
    }
}

/// One scoped Established peer can trigger all four classes without changing
/// configuration between UPDATEs. Frames enter through the real read buffer.
struct PeerWarningFixture {
    runtime: tokio::runtime::Runtime,
    session: PeerSession,
    peer: Option<TcpStream>,
    rib_rx: mpsc::Receiver<RibUpdate>,
}

impl PeerWarningFixture {
    fn new() -> Self {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (mut session, rib_rx) = make_test_session_with_rib(65001, 65002);
        configure_scoped_link_local_peer(&mut session);
        session.config.peer.families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
        session.config.peer.link_local_next_hop = true;
        session.config.peer.local_role = Some(BgpRole::Provider);
        session.config.next_hop_ownership_strict_peer = true;
        session.fsm = Session::new(session.config.peer.clone());
        let mut fixture = Self {
            runtime,
            session,
            peer: None,
            rib_rx,
        };
        fixture.connect();
        fixture
    }

    fn connect(&mut self) {
        self.peer = Some(self.runtime.block_on(async {
            let (client, server) = connected_stream_pair().await;
            self.session.test_install_stream(client);
            self.session.drive_fsm(Event::ManualStart).await;
            self.session
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
                        Capability::MultiProtocol {
                            afi: Afi::Ipv6,
                            safi: Safi::Unicast,
                        },
                        Capability::FourOctetAs { asn: 65002 },
                        Capability::LinkLocalNextHop,
                        Capability::Role {
                            role: BgpRole::Customer,
                        },
                    ],
                }))
                .await;
            self.session.drive_fsm(Event::KeepaliveReceived).await;
            server
        }));
        assert_eq!(self.session.fsm.state(), SessionState::Established);
        rfc7606_drain(&mut self.rib_rx);
    }

    fn receive(&mut self, update: &UpdateMessage) -> Vec<SessionLogFields> {
        let encoded = rustbgpd_wire::encode_message(&Message::Update(update.clone())).unwrap();
        self.session.read_buf.buf.extend_from_slice(&encoded);
        let events = capture_session_logs(|| {
            self.runtime.block_on(self.session.process_read_buffer());
        });
        assert_eq!(self.session.fsm.state(), SessionState::Established);
        rfc7606_drain(&mut self.rib_rx);
        events
    }

    fn reconnect(&mut self, tcp_failure: bool) {
        self.runtime.block_on(async {
            if tcp_failure {
                self.session.handle_tcp_disconnect();
                self.session.drive_fsm(Event::TcpConnectionFails).await;
            } else {
                self.session
                    .drive_fsm(Event::ManualStop { reason: None })
                    .await;
            }
        });
        assert_eq!(self.session.fsm.state(), SessionState::Idle);
        self.peer = None;
        self.connect();
    }
}

fn peer_warning_update(case: Option<PeerWarningCase>) -> UpdateMessage {
    let mut attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
    ];
    if matches!(case, Some(PeerWarningCase::ScopedIpv4Body)) {
        attrs.push(PathAttribute::NextHop(Ipv4Addr::new(192, 0, 2, 1)));
        return UpdateMessage::build(
            &[Ipv4NlriEntry {
                path_id: 0,
                prefix: Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
            }],
            &[],
            &attrs,
            true,
            false,
            Ipv4UnicastMode::Body,
        );
    }
    let next_hop = if matches!(case, Some(PeerWarningCase::NextHopOwnership)) {
        "2001:db8::9".parse().unwrap()
    } else {
        "fe80::2".parse().unwrap()
    };
    let mut reach = empty_nonunicast_reach(Afi::Ipv6, Safi::Unicast, next_hop);
    if matches!(case, Some(PeerWarningCase::UnnegotiatedMpReach)) {
        reach.afi = Afi::Ipv4;
        reach.safi = Safi::FlowSpec;
        reach.next_hop = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        reach.flowspec_announced.push(make_flowspec_route().rule);
    } else {
        reach.announced.push(NlriEntry {
            path_id: 0,
            prefix: Prefix::V6(Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 64)),
        });
    }
    if matches!(case, Some(PeerWarningCase::OtcPolicy)) {
        attrs.push(PathAttribute::OnlyToCustomer(65002));
    }
    nonunicast_update(attrs, reach, None, false)
}

fn peer_warning_count(events: &[SessionLogFields], case: PeerWarningCase) -> usize {
    events
        .iter()
        .filter(|event| {
            event
                .get("message")
                .is_some_and(|text| text.starts_with(case.message()))
        })
        .count()
}

fn assert_peer_warning_stream(case: PeerWarningCase) {
    let mut fixture = PeerWarningFixture::new();
    // Valid negotiated MP NLRI with the peer's next hop and no OTC must not
    // consume any class's warning schedule.
    for _ in 0..2 {
        assert_eq!(fixture.receive(&peer_warning_update(None)), Vec::new());
    }
    let update = peer_warning_update(Some(case));
    let warned: Vec<_> = (1..=16)
        .map(|_| peer_warning_count(&fixture.receive(&update), case))
        .collect();
    assert_eq!(
        warned,
        [1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1],
        "{case:?} must emit five actual WARNs over sixteen UPDATEs"
    );
    assert_eq!(
        fixture.session.config.neighbor_counters.updates_received(),
        18
    );
    if matches!(case, PeerWarningCase::OtcPolicy) {
        assert_eq!(
            fixture
                .session
                .config
                .neighbor_counters
                .otc_routes_blocked(),
            16
        );
        let samples = counter_samples(&fixture.session.metrics, "bgp_otc_routes_blocked_total");
        assert!(samples.iter().any(|(labels, count)| {
            labels.get("reason").map(String::as_str) == Some("ingress_from_customer_rsclient")
                && (*count - 16.0).abs() < f64::EPSILON
        }));
    }
    for tcp_failure in [false, true] {
        fixture.reconnect(tcp_failure);
        assert_eq!(peer_warning_count(&fixture.receive(&update), case), 1);
        assert_eq!(peer_warning_count(&fixture.receive(&update), case), 1);
        assert_eq!(peer_warning_count(&fixture.receive(&update), case), 0);
    }
}

#[test]
fn unnegotiated_mp_reach_warnings_are_bounded_per_connection() {
    assert_peer_warning_stream(PeerWarningCase::UnnegotiatedMpReach);
}

#[test]
fn scoped_body_nlri_warnings_are_bounded_per_connection() {
    assert_peer_warning_stream(PeerWarningCase::ScopedIpv4Body);
}

#[test]
fn strict_next_hop_warnings_are_bounded_per_connection() {
    assert_peer_warning_stream(PeerWarningCase::NextHopOwnership);
}

#[test]
fn policy_otc_warnings_are_bounded_per_connection() {
    assert_peer_warning_stream(PeerWarningCase::OtcPolicy);
}

#[test]
fn peer_warning_classes_keep_independent_schedules() {
    let mut fixture = PeerWarningFixture::new();
    let malformed = with_attributes(&peer_warning_update(None), |attrs| attrs[3] = 9);
    for _ in 0..2 {
        fixture.receive(&malformed);
    }
    for count in 1_u64..=16 {
        for case in PeerWarningCase::ALL {
            let events = fixture.receive(&peer_warning_update(Some(case)));
            assert_eq!(
                peer_warning_count(&events, case),
                usize::from(count.is_power_of_two())
            );
            for event in events {
                assert_eq!(event.get("warning_updates"), Some(&count.to_string()));
            }
        }
    }
    assert_eq!(
        fixture.session.config.neighbor_counters.updates_received(),
        66
    );
}

#[test]
fn notification_descriptions_preserve_registered_and_numeric_inner_causes() {
    for (code, subcode, expected) in [
        (6, cease_subcode::CONNECTION_REJECTED, "Connection Rejected"),
        (
            6,
            cease_subcode::OTHER_CONFIGURATION_CHANGE,
            "Other Configuration Change",
        ),
        (5, 3, "Receive Unexpected Message in Established State"),
        (7, 1, "Invalid Message Length"),
        (9, 0, "Loss of LSDB Synchronization"),
        (2, 5, "Deprecated OPEN Message Error Subcode 5"),
        (6, 42, "unassigned(6/42)"),
        (5, 42, "unassigned(5/42)"),
        (4, 42, "unassigned(4/42)"),
        (8, 42, "unassigned(8/42)"),
        (255, 255, "unassigned(255/255)"),
        (0, 0, "reserved(0/0)"),
        (6, 0, "reserved(6/0)"),
        (7, 0, "reserved(7/0)"),
    ] {
        let direct =
            NotificationMessage::new(NotificationCode::from_u8(code), subcode, Bytes::new());
        assert_eq!(
            super::super::fsm::notification_description(&direct),
            expected
        );
        let nested = NotificationMessage::new(
            NotificationCode::Cease,
            cease_subcode::HARD_RESET,
            Bytes::copy_from_slice(&[code, subcode]),
        );
        assert_eq!(
            super::super::fsm::notification_description(&nested),
            format!("Hard Reset: {expected}")
        );
    }
    // A short Hard Reset envelope has no inner pair to render.
    for data in [Bytes::new(), Bytes::from_static(&[6])] {
        let notification =
            NotificationMessage::new(NotificationCode::Cease, cease_subcode::HARD_RESET, data);
        assert_eq!(
            super::super::fsm::notification_description(&notification),
            "Hard Reset"
        );
    }
}

/// What the peer, as our helper, may hold of ours once the session leaves
/// Established: our restart time whenever it advertised any GR capability,
/// families or not (RFC 4724 §3), plus our LLGR stale time only when both
/// sides advertised LLGR; nothing after a Hard Reset either way, a
/// NOTIFICATION without the N bit (RFC 8538 §3), with local GR off, or from
/// a peer with no GR capability. Red proof: dropping any guard, or keying on
/// listed families, changes its row.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "a table test: one row per session-end input, then one shared check"
)]
async fn session_end_reports_how_long_the_peer_may_hold_our_routes() {
    #[derive(Clone, Copy)]
    #[expect(
        clippy::struct_excessive_bools,
        reason = "one row per independent session-end input in a table test"
    )]
    struct Case {
        name: &'static str,
        peer_gr: bool,
        families: bool,
        peer_llgr: bool,
        local_gr: bool,
        local_llgr: u32,
        notification: bool,
        n_bit: bool,
        received_hard_reset: bool,
        sent_hard_reset: bool,
        expect: Option<u64>,
    }
    let base = Case {
        name: "transport loss",
        peer_gr: true,
        families: true,
        peer_llgr: false,
        local_gr: true,
        local_llgr: 0,
        notification: false,
        n_bit: false,
        received_hard_reset: false,
        sent_hard_reset: false,
        expect: Some(90),
    };
    for case in [
        base,
        Case {
            name: "helper-only GR capability",
            families: false,
            ..base
        },
        Case {
            name: "helper-only GR capability with LLGR",
            families: false,
            peer_llgr: true,
            local_llgr: 600,
            expect: Some(690),
            ..base
        },
        Case {
            name: "both advertised LLGR",
            peer_llgr: true,
            local_llgr: 600,
            expect: Some(690),
            ..base
        },
        Case {
            name: "only the peer advertised LLGR",
            peer_llgr: true,
            ..base
        },
        Case {
            name: "only we advertised LLGR",
            local_llgr: 600,
            ..base
        },
        Case {
            name: "local GR off",
            local_gr: false,
            expect: None,
            ..base
        },
        Case {
            name: "NOTIFICATION without the N bit",
            notification: true,
            expect: None,
            ..base
        },
        Case {
            name: "NOTIFICATION with the N bit",
            notification: true,
            n_bit: true,
            ..base
        },
        Case {
            name: "Hard Reset received",
            notification: true,
            n_bit: true,
            received_hard_reset: true,
            expect: None,
            ..base
        },
        Case {
            name: "Hard Reset sent",
            notification: true,
            n_bit: true,
            sent_hard_reset: true,
            expect: None,
            ..base
        },
        Case {
            name: "no GR capability",
            peer_gr: false,
            expect: None,
            ..base
        },
    ] {
        let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
        let mut neg = negotiated_session(65002, false);
        let gr_families = if case.families {
            vec![rustbgpd_wire::GracefulRestartFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                forwarding_preserved: false,
            }]
        } else {
            vec![]
        };
        if case.peer_gr {
            neg.peer_capabilities
                .push(rustbgpd_wire::Capability::GracefulRestart {
                    restart_state: false,
                    notification: case.n_bit,
                    restart_time: 120,
                    families: gr_families.clone(),
                });
        }
        // As negotiation derives them: listed families make it GR-capable.
        neg.peer_gr_capable = case.peer_gr && case.families;
        neg.peer_gr_families = gr_families;
        if case.peer_llgr {
            neg.peer_capabilities
                .push(rustbgpd_wire::Capability::LongLivedGracefulRestart(vec![
                    rustbgpd_wire::LlgrFamily {
                        afi: Afi::Ipv4,
                        safi: Safi::Unicast,
                        forwarding_preserved: false,
                        stale_time: 3600,
                    },
                ]));
        }
        neg.peer_llgr_capable = case.peer_llgr;
        neg.peer_notification_gr = case.n_bit;
        session.config.peer.graceful_restart = case.local_gr;
        session.config.peer.gr_restart_time = 90;
        session.config.llgr_stale_time = case.local_llgr;
        session.negotiated = Some(Arc::new(neg));
        session.notification_teardown = case.notification;
        session.received_hard_reset = case.received_hard_reset;
        session.sent_hard_reset = case.sent_hard_reset;
        session.execute_actions(vec![Action::SessionDown]).await;
        let end = session.established.end_retention();
        assert!(end.established, "{}", case.name);
        assert_eq!(
            end.ours_for,
            case.expect.map(std::time::Duration::from_secs),
            "{}",
            case.name
        );
    }

    // Down before Established, as by a reset in OpenSent: nothing negotiated,
    // nothing held, and not reported as an Established period.
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.peer.graceful_restart = true;
    session.negotiated = None;
    session.execute_actions(vec![Action::SessionDown]).await;
    assert_eq!(
        session.established.end_retention(),
        crate::handle::SessionEndRetention::default()
    );
}

/// The window negotiated from a real OPEN: a helper-only GR capability with
/// an LLGR capability whose stale times are all zero, FRR's default, leaves
/// `peer_llgr_capable` clear, yet the LLGR capability was exchanged, so the
/// peer keeps our routes for the Long-Lived Stale Time we advertised (RFC
/// 9494 §4.2). Without the LLGR capability it keeps them for our restart
/// time only. Red proof: keying the LLGR window on `peer_llgr_capable`
/// drops our stale time.
#[tokio::test]
async fn negotiated_window_counts_our_llgr_time_whatever_the_peers_stale_times() {
    for (llgr_capability, expect) in [(true, 90 + 600), (false, 90)] {
        let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
        session.config.peer.graceful_restart = true;
        session.config.peer.gr_restart_time = 90;
        session.config.llgr_stale_time = 600;
        let mut capabilities = vec![
            rustbgpd_wire::Capability::MultiProtocol {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            },
            rustbgpd_wire::Capability::FourOctetAs { asn: 65002 },
            rustbgpd_wire::Capability::GracefulRestart {
                restart_state: false,
                notification: false,
                restart_time: 120,
                families: vec![],
            },
        ];
        if llgr_capability {
            capabilities.push(rustbgpd_wire::Capability::LongLivedGracefulRestart(vec![
                rustbgpd_wire::LlgrFamily {
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                    forwarding_preserved: false,
                    stale_time: 0,
                },
            ]));
        }
        let open = rustbgpd_wire::OpenMessage {
            version: 4,
            my_as: 65002,
            hold_time: 90,
            bgp_identifier: Ipv4Addr::new(10, 0, 0, 2),
            capabilities,
        };
        let neg = rustbgpd_fsm::negotiation::validate_open(&open, &session.config.peer)
            .expect("the OPEN validates");
        assert!(!neg.peer_gr_capable && !neg.peer_llgr_capable);
        session.negotiated = Some(Arc::new(neg));
        session.execute_actions(vec![Action::SessionDown]).await;
        assert_eq!(
            session.established.end_retention().ours_for,
            Some(std::time::Duration::from_secs(expect)),
            "LLGR capability {llgr_capability}"
        );
    }
}

/// RFC 4271 §8.2.2: an operator Start outside Idle is ignored in every
/// non-Idle state. The state, the NOTIFICATION backoff streak and the sent
/// NOTIFICATION count all stay as they were.
#[tokio::test(start_paused = true)]
async fn start_outside_idle_keeps_state_streak_and_sends_nothing() {
    for target in [
        SessionState::Connect,
        SessionState::Active,
        SessionState::OpenSent,
        SessionState::OpenConfirm,
        SessionState::Established,
    ] {
        let mut session = make_test_session(65001, 65002);
        notification_cycle(&mut session).await;
        assert_eq!(notification_cycle(&mut session).await, 60);
        session.reconnect_timer = None;
        let mut _peer = None;
        if matches!(target, SessionState::Connect | SessionState::Active) {
            session.drive_fsm(Event::ManualStart).await;
            if let Some(task) = session.connect_task.take() {
                task.abort();
            }
            if target == SessionState::Active {
                session.drive_fsm(Event::TcpConnectionFails).await;
            }
        } else {
            let (client, server) = connected_stream_pair().await;
            _peer = Some(server);
            session.test_install_stream(client);
            session.drive_fsm(Event::ManualStart).await;
            if target != SessionState::OpenSent {
                session.drive_fsm(peer_open(65002)).await;
            }
            if target == SessionState::Established {
                session.drive_fsm(Event::KeepaliveReceived).await;
            }
        }
        assert_eq!(session.fsm.state(), target);
        let sent = session.config.neighbor_counters.notifications_sent();
        let _ = session.handle_command(PeerCommand::Start).await;
        assert_eq!(session.fsm.state(), target, "{target:?}");
        assert_eq!(session.notification_idle_failures, 2, "{target:?}");
        assert_eq!(
            session.config.neighbor_counters.notifications_sent(),
            sent,
            "{target:?}"
        );
    }
}

/// An operator Start in Idle while the NOTIFICATION backoff holds the
/// reconnect starts the session now and clears the streak.
#[tokio::test(start_paused = true)]
async fn start_in_idle_during_the_backoff_hold_connects_now() {
    let mut session = make_test_session(65001, 65002);
    notification_cycle(&mut session).await;
    assert_eq!(notification_cycle(&mut session).await, 60);
    assert_eq!(session.fsm.state(), SessionState::Idle);
    assert!(session.reconnect_timer.is_some());

    let _ = session.handle_command(PeerCommand::Start).await;
    assert_eq!(session.fsm.state(), SessionState::Connect);
    assert!(session.reconnect_timer.is_none());
    assert_eq!(session.notification_idle_failures, 0);
}
