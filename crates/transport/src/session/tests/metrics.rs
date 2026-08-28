use super::*;
use rustbgpd_telemetry::reason_labels::SessionDownReason;

const STATES: [SessionState; 6] = [
    SessionState::Idle,
    SessionState::Connect,
    SessionState::Active,
    SessionState::OpenSent,
    SessionState::OpenConfirm,
    SessionState::Established,
];

fn gauge_rows(metrics: &BgpMetrics, family_name: &str) -> HashMap<String, f64> {
    metrics
        .registry()
        .gather()
        .into_iter()
        .find(|family| family.name() == family_name)
        .map_or_else(HashMap::new, |family| {
            family
                .get_metric()
                .iter()
                .filter_map(|metric| {
                    let labels: HashMap<_, _> = metric
                        .get_label()
                        .iter()
                        .map(|label| (label.name(), label.value()))
                        .collect();
                    (labels.get("peer") == Some(&"10.0.0.2")
                        && labels.get("interface") == Some(&""))
                    .then(|| {
                        (
                            labels.get("state").copied().unwrap_or("").to_string(),
                            metric.get_gauge().value(),
                        )
                    })
                })
                .collect()
        })
}

fn down_value(metrics: &BgpMetrics, reason: SessionDownReason) -> f64 {
    counter_samples(metrics, "bgp_session_down_total")
        .into_iter()
        .find_map(|(labels, value)| {
            (labels.get("peer").map(String::as_str) == Some("10.0.0.2")
                && labels.get("interface").map(String::as_str) == Some("")
                && labels.get("reason").map(String::as_str) == Some(reason.as_str()))
            .then_some(value)
        })
        .unwrap_or(0.0)
}

fn assert_sample(actual: f64, expected: f64, context: impl std::fmt::Display) {
    assert!(
        (actual - expected).abs() < f64::EPSILON,
        "{context}: expected {expected}, got {actual}"
    );
}

fn assert_only_down_reason(metrics: &BgpMetrics, expected: SessionDownReason) {
    for reason in SessionDownReason::ALL {
        assert_sample(
            down_value(metrics, reason),
            f64::from(reason == expected),
            format_args!("only {expected} may advance; inspected {reason}"),
        );
    }
}

fn install_closed_priority_sender(session: &mut PeerSession) {
    let (tx, rx) = mpsc::unbounded_channel();
    drop(rx);
    assert!(tx.is_closed(), "test seam must reject the next enqueue");
    session.writer_priority_tx = Some(tx);
}

async fn transition(session: &mut PeerSession, old: SessionState, new: SessionState) {
    session
        .execute_actions(vec![Action::StateChanged { old, new }])
        .await;
}

#[test]
fn notification_batches_are_preclassified_without_action_reordering() {
    let notification = rustbgpd_wire::NotificationMessage::new(
        NotificationCode::Cease,
        cease_subcode::ADMINISTRATIVE_RESET,
        Bytes::new(),
    );
    let actions = vec![
        Action::SessionDown,
        Action::SendNotification(notification.clone()),
    ];
    assert_eq!(
        fsm::session_down_reason_for_batch(&Event::HoldTimerExpires, &actions),
        Some(SessionDownReason::LocalNotification)
    );
    assert!(matches!(actions[0], Action::SessionDown));
    assert!(matches!(actions[1], Action::SendNotification(_)));
    assert_eq!(
        fsm::session_down_reason_for_batch(&Event::NotificationReceived(notification), &actions),
        Some(SessionDownReason::RemoteNotification),
        "received NOTIFICATION owns the classification even if the batch also sends one"
    );
    assert_eq!(
        fsm::session_down_reason_for_batch(&Event::TcpConnectionFails, &[Action::SessionDown]),
        Some(SessionDownReason::TransportError)
    );
}

#[tokio::test]
async fn active_primary_publishes_all_six_states_as_exact_one_hot() {
    let metrics = BgpMetrics::new();
    let (mut session, _rib_rx) =
        make_test_session_with_metrics_and_identity(metrics.clone(), SessionIdentity::primary(1));

    let mut old = SessionState::Idle;
    for new in STATES {
        transition(&mut session, old, new).await;
        let rows = gauge_rows(&metrics, "bgp_peer_session_state");
        assert_eq!(rows.len(), 6, "all bounded state rows must exist");
        assert_sample(
            rows.values().sum::<f64>(),
            1.0,
            "state vector must be one-hot",
        );
        for state in STATES {
            assert_eq!(
                rows.get(state.as_str()),
                Some(&f64::from(state == new)),
                "wrong one-hot value for {} while current state is {new}",
                state.as_str()
            );
        }
        old = new;
    }
}

#[tokio::test]
async fn never_established_reset_does_not_count_a_down() {
    let metrics = BgpMetrics::new();
    let (mut session, _rib_rx) =
        make_test_session_with_metrics_and_identity(metrics.clone(), SessionIdentity::primary(2));
    transition(&mut session, SessionState::Idle, SessionState::Connect).await;
    session
        .session_telemetry_metric_lease
        .latch_down_reason(SessionDownReason::TransportError);
    session.execute_actions(vec![Action::SessionDown]).await;

    for reason in SessionDownReason::ALL {
        assert_sample(down_value(&metrics, reason), 0.0, reason);
    }
}

#[tokio::test]
async fn every_bounded_down_reason_counts_without_bmp() {
    for (index, reason) in SessionDownReason::ALL.into_iter().enumerate() {
        let metrics = BgpMetrics::new();
        let (mut session, _rib_rx) = make_test_session_with_metrics_and_identity(
            metrics.clone(),
            SessionIdentity::primary(index as u64 + 10),
        );
        assert!(session.bmp_tx.is_none());
        transition(
            &mut session,
            SessionState::OpenConfirm,
            SessionState::Established,
        )
        .await;
        session
            .session_telemetry_metric_lease
            .latch_down_reason(reason);
        session.execute_actions(vec![Action::SessionDown]).await;

        for candidate in SessionDownReason::ALL {
            assert_sample(
                down_value(&metrics, candidate),
                f64::from(candidate == reason),
                format_args!("only {reason} may advance; inspected {candidate}"),
            );
        }
    }
}

#[tokio::test]
async fn real_fsm_batches_classify_local_remote_and_transport_teardown() {
    for (index, reason) in [
        SessionDownReason::LocalNotification,
        SessionDownReason::RemoteNotification,
        SessionDownReason::TransportError,
    ]
    .into_iter()
    .enumerate()
    {
        let metrics = BgpMetrics::new();
        let (mut session, _rib_rx) = make_test_session_with_metrics_and_identity(
            metrics.clone(),
            SessionIdentity::primary(index as u64 + 30),
        );
        let (client, _server) = connected_stream_pair().await;
        session.test_install_stream(client);
        establish_test_session(&mut session, 65002).await;
        assert!(session.bmp_tx.is_none());

        match reason {
            SessionDownReason::LocalNotification => {
                session.drive_fsm(Event::ManualStop { reason: None }).await;
            }
            SessionDownReason::RemoteNotification => {
                session
                    .drive_fsm(Event::NotificationReceived(
                        rustbgpd_wire::NotificationMessage::new(
                            NotificationCode::Cease,
                            cease_subcode::ADMINISTRATIVE_SHUTDOWN,
                            Bytes::new(),
                        ),
                    ))
                    .await;
            }
            SessionDownReason::TransportError => {
                session.drive_fsm(Event::TcpConnectionFails).await;
            }
            _ => unreachable!("loop contains only directly driven FSM reasons"),
        }
        drop(session);

        assert_sample(down_value(&metrics, reason), 1.0, reason);
        assert_sample(
            down_value(&metrics, SessionDownReason::Unknown),
            0.0,
            "known teardown must not advance unknown",
        );
    }
}

#[tokio::test]
async fn established_tcp_eof_counts_remote_no_notification_exactly_once() {
    let metrics = BgpMetrics::new();
    let (mut session, _rib_rx) =
        make_test_session_with_metrics_and_identity(metrics.clone(), SessionIdentity::primary(33));
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;

    assert!(matches!(
        read_single_bgp_message(&mut server).await,
        Message::Open(_)
    ));
    assert!(matches!(
        read_single_bgp_message(&mut server).await,
        Message::Keepalive
    ));
    drop(server);

    let mut byte = [0_u8; 1];
    let read = session
        .read_half
        .as_mut()
        .expect("established session has a reader")
        .read(&mut byte)
        .await;
    assert!(
        matches!(&read, Ok(0)),
        "peer close must reach EOF: {read:?}"
    );
    session.handle_tcp_read_result(read).await;
    drop(session);

    assert_only_down_reason(&metrics, SessionDownReason::RemoteNoNotification);
}

#[tokio::test]
async fn send_hold_writer_exit_counts_local_no_notification_exactly_once() {
    let metrics = BgpMetrics::new();
    let (mut session, _rib_rx) =
        make_test_session_with_metrics_and_identity(metrics.clone(), SessionIdentity::primary(34));
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;

    session
        .handle_writer_exit(Ok(Err(super::writer::WriterExit::SendHoldExpired {
            limit: Duration::from_secs(2),
        })))
        .await;
    drop(session);

    assert_only_down_reason(&metrics, SessionDownReason::LocalNoNotification);
}

#[tokio::test]
async fn established_keepalive_enqueue_failure_counts_transport_error() {
    let metrics = BgpMetrics::new();
    let (mut session, _rib_rx) =
        make_test_session_with_metrics_and_identity(metrics.clone(), SessionIdentity::primary(35));
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    install_closed_priority_sender(&mut session);

    session.drive_fsm(Event::KeepaliveTimerExpires).await;
    drop(session);

    assert_only_down_reason(&metrics, SessionDownReason::TransportError);
}

#[tokio::test]
async fn failed_notification_enqueue_retains_local_notification_cause() {
    let metrics = BgpMetrics::new();
    let (mut session, _rib_rx) =
        make_test_session_with_metrics_and_identity(metrics.clone(), SessionIdentity::primary(36));
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    install_closed_priority_sender(&mut session);

    session.drive_fsm(Event::ManualStop { reason: None }).await;
    drop(session);

    assert_only_down_reason(&metrics, SessionDownReason::LocalNotification);
}

#[tokio::test]
async fn duplicate_established_and_session_down_actions_keep_one_epoch_sample() {
    let metrics = BgpMetrics::new();
    let (mut session, _rib_rx) =
        make_test_session_with_metrics_and_identity(metrics.clone(), SessionIdentity::primary(37));
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;

    session
        .execute_actions(vec![
            Action::StateChanged {
                old: SessionState::Established,
                new: SessionState::Established,
            },
            Action::StateChanged {
                old: SessionState::Established,
                new: SessionState::Established,
            },
        ])
        .await;
    session.handle_tcp_read_result(Ok(0)).await;
    session
        .execute_actions(vec![Action::SessionDown, Action::SessionDown])
        .await;
    drop(session);

    assert_only_down_reason(&metrics, SessionDownReason::RemoteNoNotification);
}

#[tokio::test]
async fn collision_candidate_is_silent_until_exact_promotion() {
    let metrics = BgpMetrics::new();
    let (mut candidate, _rib_rx) = make_test_session_with_metrics_and_identity(
        metrics.clone(),
        SessionIdentity::inbound_candidate(40),
    );
    let (client, _server) = connected_stream_pair().await;
    candidate.test_install_stream(client);
    establish_test_session(&mut candidate, 65002).await;
    assert!(gauge_rows(&metrics, "bgp_peer_session_state").is_empty());
    assert_sample(
        down_value(&metrics, SessionDownReason::Unknown),
        0.0,
        "inactive candidate unknown count",
    );

    let (reply, done) = oneshot::channel();
    assert_eq!(
        candidate
            .handle_command(PeerCommand::ActivateMaxPrefixMetrics { reply })
            .await,
        ControlFlow::Continue(())
    );
    done.await.unwrap();
    let rows = gauge_rows(&metrics, "bgp_peer_session_state");
    assert_eq!(rows.len(), 6);
    assert_eq!(rows.get("established"), Some(&1.0));
    assert_sample(rows.values().sum::<f64>(), 1.0, "promoted one-hot sum");

    candidate
        .session_telemetry_metric_lease
        .latch_down_reason(SessionDownReason::TransportError);
    candidate.execute_actions(vec![Action::SessionDown]).await;
    assert_sample(
        down_value(&metrics, SessionDownReason::TransportError),
        1.0,
        "promoted candidate transport down",
    );
}

#[tokio::test]
async fn unpromoted_candidate_establishment_and_drop_remain_silent() {
    let metrics = BgpMetrics::new();
    let (mut candidate, _rib_rx) = make_test_session_with_metrics_and_identity(
        metrics.clone(),
        SessionIdentity::inbound_candidate(41),
    );
    transition(
        &mut candidate,
        SessionState::OpenConfirm,
        SessionState::Established,
    )
    .await;
    drop(candidate);
    assert!(gauge_rows(&metrics, "bgp_peer_session_state").is_empty());
    for reason in SessionDownReason::ALL {
        assert_sample(down_value(&metrics, reason), 0.0, reason);
    }
}

#[tokio::test]
async fn collision_dump_and_abrupt_drop_each_count_once() {
    let collision_metrics = BgpMetrics::new();
    let (mut collision, _rib_rx) = make_test_session_with_metrics_and_identity(
        collision_metrics.clone(),
        SessionIdentity::primary(50),
    );
    transition(
        &mut collision,
        SessionState::OpenConfirm,
        SessionState::Established,
    )
    .await;
    assert_eq!(
        collision.handle_command(PeerCommand::CollisionDump).await,
        ControlFlow::Break(())
    );
    drop(collision);
    assert_sample(
        down_value(&collision_metrics, SessionDownReason::LocalNotification),
        1.0,
        "collision dump local notification",
    );
    let collision_rows = gauge_rows(&collision_metrics, "bgp_peer_session_state");
    assert_eq!(collision_rows.get("idle"), Some(&1.0));
    assert_sample(
        collision_rows.values().sum::<f64>(),
        1.0,
        "collision one-hot sum",
    );

    let abrupt_metrics = BgpMetrics::new();
    let (mut abrupt, _rib_rx) = make_test_session_with_metrics_and_identity(
        abrupt_metrics.clone(),
        SessionIdentity::primary(51),
    );
    transition(
        &mut abrupt,
        SessionState::OpenConfirm,
        SessionState::Established,
    )
    .await;
    drop(abrupt);
    assert_sample(
        down_value(&abrupt_metrics, SessionDownReason::Unknown),
        1.0,
        "abrupt drop unknown",
    );
    let abrupt_rows = gauge_rows(&abrupt_metrics, "bgp_peer_session_state");
    assert_eq!(abrupt_rows.get("idle"), Some(&1.0));
    assert_sample(abrupt_rows.values().sum::<f64>(), 1.0, "abrupt one-hot sum");
}

#[tokio::test]
async fn reconnect_opens_a_fresh_exactly_once_down_epoch() {
    let metrics = BgpMetrics::new();
    let (mut session, _rib_rx) =
        make_test_session_with_metrics_and_identity(metrics.clone(), SessionIdentity::primary(60));
    transition(
        &mut session,
        SessionState::OpenConfirm,
        SessionState::Established,
    )
    .await;
    session
        .session_telemetry_metric_lease
        .latch_down_reason(SessionDownReason::TransportError);
    session.execute_actions(vec![Action::SessionDown]).await;
    transition(&mut session, SessionState::Established, SessionState::Idle).await;
    transition(
        &mut session,
        SessionState::OpenConfirm,
        SessionState::Established,
    )
    .await;
    session
        .session_telemetry_metric_lease
        .latch_down_reason(SessionDownReason::RemoteNoNotification);
    session.execute_actions(vec![Action::SessionDown]).await;
    drop(session);

    assert_sample(
        down_value(&metrics, SessionDownReason::TransportError),
        1.0,
        "first reconnect epoch",
    );
    assert_sample(
        down_value(&metrics, SessionDownReason::RemoteNoNotification),
        1.0,
        "second reconnect epoch",
    );
    assert_sample(
        down_value(&metrics, SessionDownReason::Unknown),
        0.0,
        "reconnect epochs remain classified",
    );
}
