use super::*;

/// Load-bearing: storing raw I/O text leaks the sentinel, dropping the read
/// cause loses the bounded value, and treating clean EOF as an error replaces
/// the seeded diagnostic.
#[tokio::test]
async fn tcp_reader_error_is_bounded_but_clean_eof_is_not_an_error() {
    let (mut failed, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (event_tx, mut event_rx) = mpsc::channel(1);
    failed.session_event_tx = Some(event_tx);
    failed.last_error = "prior".to_string();
    failed
        .handle_tcp_read_result(Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "secret reader detail",
        )))
        .await;
    assert_eq!(
        failed.last_error,
        "TCP reader I/O failure (ConnectionReset)"
    );
    assert!(!failed.last_error.contains("secret"));
    assert!(matches!(
        event_rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));

    let (mut eof, _rib_rx) = make_test_session_with_rib(65001, 65002);
    eof.last_error = "prior".to_string();
    eof.handle_tcp_read_result(Ok(0)).await;
    assert_eq!(eof.last_error, "prior");
}

/// Load-bearing: raw writer or `JoinError` rendering leaks either sentinel;
/// collapsing panic and cancellation or changing a clean exit replaces one of
/// the exact bounded/seeded assertions.
#[tokio::test]
async fn writer_io_and_join_failure_are_bounded() {
    let (mut io_session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (event_tx, mut event_rx) = mpsc::channel(1);
    io_session.session_event_tx = Some(event_tx);
    io_session
        .handle_writer_exit(Ok(Err(super::writer::WriterExit::Io(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "secret writer detail",
        )))))
        .await;
    assert_eq!(io_session.last_error, "TCP writer I/O failure (BrokenPipe)");
    assert!(!io_session.last_error.contains("secret"));
    assert!(matches!(
        event_rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));

    let join = tokio::spawn(async { panic!("secret panic detail") }).await;
    let (mut panic_session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    panic_session.handle_writer_exit(join.map(|_| Ok(()))).await;
    assert_eq!(panic_session.last_error, "TCP writer task panicked");
    assert!(!panic_session.last_error.contains("secret"));

    let cancelled = tokio::spawn(std::future::pending::<()>());
    cancelled.abort();
    let cancelled = cancelled.await;
    let (mut cancelled_session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    cancelled_session
        .handle_writer_exit(cancelled.map(|()| Ok(())))
        .await;
    assert_eq!(cancelled_session.last_error, "TCP writer task cancelled");

    let (mut clean, _rib_rx) = make_test_session_with_rib(65001, 65002);
    clean.last_error = "prior actionable failure".to_string();
    clean.handle_writer_exit(Ok(Ok(()))).await;
    assert_eq!(clean.last_error, "prior actionable failure");
}

/// Load-bearing: removing the pending-cause guards lets consequential writer
/// or reader I/O replace the exact-export cause; never clearing the latch keeps
/// the final independent read failure from becoming visible.
#[tokio::test]
async fn outbound_root_cause_survives_writer_exit() {
    let cause = crate::handle::SessionFailureCause::PostCommitInvariant;
    for exit in [
        super::writer::WriterExit::TornDown,
        super::writer::WriterExit::Io(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "secondary writer detail",
        )),
    ] {
        let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
        session.pending_outbound_teardown_cause = Some(cause);
        session.last_error = cause.to_string();
        session.handle_writer_exit(Ok(Err(exit))).await;
        assert_eq!(session.last_error, cause.to_string());
        assert!(session.pending_outbound_teardown_cause.is_none());
    }

    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    session.pending_outbound_teardown_cause = Some(cause);
    session.last_error = cause.to_string();
    session
        .handle_tcp_read_result(Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "consequential reader detail",
        )))
        .await;
    assert_eq!(session.last_error, cause.to_string());
    assert_eq!(session.pending_outbound_teardown_cause, Some(cause));
    session
        .handle_writer_exit(Ok(Err(super::writer::WriterExit::TornDown)))
        .await;
    assert!(session.pending_outbound_teardown_cause.is_none());
    session
        .handle_tcp_read_result(Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "later independent reader detail",
        )))
        .await;
    assert_eq!(
        session.last_error,
        "TCP reader I/O failure (ConnectionAborted)"
    );
}

/// Load-bearing: omitting a cause, classifying a snapshot breach as generic
/// post-commit failure, or labeling any exact-export site as saturation changes
/// one of these production-source inventory counts.
#[test]
fn outbound_out_of_resources_sites_have_specific_cause_inventory() {
    let source = include_str!("../outbound.rs");
    let production = source
        .split_once("\n#[cfg(test)]\nmod tests")
        .expect("outbound module keeps production before tests")
        .0;
    assert_eq!(
        production
            .matches("trigger_outbound_out_of_resources_teardown(")
            .count(),
        17
    );
    assert_eq!(
        production
            .matches("SessionFailureCause::ExportSnapshotMissing")
            .count(),
        1
    );
    assert_eq!(
        production
            .matches("SessionFailureCause::ExportSnapshotIncompatible")
            .count(),
        1
    );
    assert_eq!(
        production
            .matches("SessionFailureCause::ExportSnapshotWrongOwner")
            .count(),
        1
    );
    assert_eq!(
        production
            .matches("SessionFailureCause::PostCommitInvariant")
            .count(),
        14
    );
    assert!(!production.contains("SessionFailureCause::OutboundSaturation"));
}

/// ADR-0051: when the writer's bulk channel saturates, the session must
/// emit a `Cease` / `Out of Resources` (RFC 4486 §4 subcode 8)
/// NOTIFICATION on the priority channel and tear the session down,
/// rather than blackholing routes silently. Drives
/// `trigger_outbound_saturation_teardown` directly to verify the
/// invariants without trying to force kernel TCP buffer saturation
/// from a unit test. Load-bearing idempotency proof: removing the live-writer
/// guard makes the second trigger increment both notification counters and
/// emit a second `SessionNotificationEvent`, while removing the cause recorder
/// loses the exact `last_error`; its notification cannot reach the closed writer.
#[tokio::test]
async fn outbound_saturation_teardown_emits_cease_out_of_resources() {
    use rustbgpd_wire::notification::{NotificationCode, cease_subcode};
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (event_tx, mut event_rx) = mpsc::channel(4);
    session.session_event_tx = Some(event_tx);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    // Sanity: writer is up before the trigger.
    assert!(session.read_half.is_some());
    assert!(session.writer_bulk_tx.is_some());
    assert!(session.writer_priority_tx.is_some());
    assert!(session.writer_join.is_some());
    session.trigger_outbound_saturation_teardown();
    session.trigger_outbound_saturation_teardown();
    assert_eq!(
        session.notifications_sent, 1,
        "a duplicate saturation trigger must not invent another sent notification"
    );
    assert_eq!(session.last_error, "outbound writer queue saturated");
    let prometheus_count = counter_value(
        &session.metrics,
        "bgp_notifications_sent_total",
        &session.peer_label,
    );
    assert!(
        (prometheus_count - 1.0).abs() < f64::EPSILON,
        "Prometheus must count the Cease/8 once"
    );
    let event = event_rx.try_recv().expect("one sent-notification event");
    assert_eq!(event.direction, SessionNotificationDirection::Sent);
    assert_eq!(event.code, NotificationCode::Cease.as_u8());
    assert_eq!(event.subcode, cease_subcode::OUT_OF_RESOURCES);
    assert_eq!(
        event.failure_cause,
        Some(crate::handle::SessionFailureCause::OutboundSaturation)
    );
    assert!(
        matches!(event_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "duplicate trigger must not publish another sent-notification event"
    );
    // Post-trigger invariants: read half + writer senders dropped, but
    // the JoinHandle stays in place so the run loop's writer-exit arm
    // can still observe the writer's natural exit.
    assert!(
        session.read_half.is_none(),
        "trigger_outbound_saturation_teardown must clear read_half"
    );
    assert!(
        session.writer_bulk_tx.is_none(),
        "writer_bulk_tx must be dropped to signal writer to exit"
    );
    assert!(
        session.writer_priority_tx.is_none(),
        "writer_priority_tx must be dropped to signal writer to exit"
    );
    let join = session
        .writer_join
        .take()
        .expect("writer_join should outlive the trigger so the run loop observes exit");
    // The writer pulled the Cease/8 from the priority channel before
    // seeing both senders dropped, so it should be on the wire now.
    let msg = read_single_bgp_message(&mut server).await;
    let Message::Notification(notif) = msg else {
        panic!("expected NOTIFICATION on saturation, got {msg:?}");
    };
    assert_eq!(notif.code, NotificationCode::Cease);
    assert_eq!(
        notif.subcode,
        cease_subcode::OUT_OF_RESOURCES,
        "saturation must surface as Cease/Out-of-Resources, not silent drop"
    );
    // After flushing the Cease the writer hard-closes with `TornDown`
    // (never draining any bulk backlog), which is what the run loop's
    // writer-exit arm maps to `TcpConnectionFails` + FSM/RIB cleanup.
    let result = tokio::time::timeout(Duration::from_secs(2), join)
        .await
        .expect("writer should exit within 2s of the teardown signal")
        .expect("writer task should not panic");
    assert!(
        matches!(result, Err(super::writer::WriterExit::TornDown)),
        "writer should exit TornDown after the saturation hard close, got: {result:?}"
    );
}

/// LAN-280 end-to-end regression: outbound saturation detected on the
/// REAL run-loop path — a peer draining too slowly while outbound
/// updates flood in through the RIB channel — must:
///
/// 1. put the `Cease/8` NOTIFICATION on the wire as the FINAL frame:
///    the queued UPDATE backlog is discarded, never drained after the
///    NOTIFICATION;
/// 2. deregister the peer from the RIB (`PeerDown`) via the
///    writer-exit → `TcpConnectionFails` wiring, with **no manually
///    injected FSM events** (the vacuity this test exists to prevent);
/// 3. leave the session task alive and responsive afterwards.
#[tokio::test]
async fn saturation_teardown_from_run_loop_ceases_closes_and_deregisters() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    // The harness drops its command sender, which would end `run()`
    // immediately — install a live command channel instead.
    let (cmd_tx, cmd_rx) = mpsc::channel(8);
    session.commands = cmd_rx;
    // Small socket buffers so the writer wedges in `write_all` after a
    // few KiB and the bounded bulk queue actually fills.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connect = tokio::spawn(async move {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(4096).unwrap();
        socket.connect(addr).await.unwrap()
    });
    let (server, _) = listener.accept().await.unwrap();
    socket2::SockRef::from(&server)
        .set_send_buffer_size(4096)
        .unwrap();
    let peer = connect.await.unwrap();
    session.test_install_stream(server);
    establish_test_session(&mut session, 65002).await;
    match recv_peer_up_after_export_context(&mut rib_rx).await {
        RibUpdate::PeerUp { .. } => {}
        _ => panic!("expected RIB PeerUp after establishment"),
    }
    let outbound_tx = session.outbound_tx.clone();
    let exact_export_snapshot: Arc<dyn rustbgpd_rib::ExactExportSnapshot> =
        session.publish_export_profile();
    let session_task = tokio::spawn(async move { session.run().await });
    // Slow reader: trickles just enough that the writer stays wedged
    // while the flood fills the bulk queue, but keeps draining so the
    // in-flight frame completes within the teardown linger and the
    // whole wire (including the final Cease) is observable to EOF.
    let reader = tokio::spawn(async move {
        let mut peer = peer;
        let mut collected = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            tokio::time::sleep(Duration::from_millis(20)).await;
            match peer.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => collected.extend_from_slice(&buf[..n]),
            }
        }
        collected
    });
    // Flood through the REAL outbound path (outbound channel → run
    // loop → send_route_update → enqueue_bulk). 3× the writer queue
    // depth guarantees `try_send` hits `Full` and the production
    // saturation detection fires. No `trigger_outbound_saturation_-
    // teardown` call, no injected FSM events.
    let flood_total = 3 * OUTBOUND_BUFFER;
    for _ in 0..flood_total {
        let mut update = empty_outbound_update();
        update.exact_export_snapshot = Some(Arc::clone(&exact_export_snapshot));
        update.announce = vec![make_route(100)].into();
        update.next_hop_override = vec![None].into();
        if outbound_tx.send(update).await.is_err() {
            // SessionDown already recreated the outbound channel.
            break;
        }
    }
    // (2) Production wiring: the RIB observes the PeerDown without any
    // manually injected `TcpConnectionFails`. Skip other session-up
    // messages (e.g. `SetPeerPolicyContext`) on the way.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let msg = tokio::time::timeout_at(deadline, rib_rx.recv())
            .await
            .expect("RIB must observe the saturation teardown (writer-exit → TcpConnectionFails)")
            .expect("rib channel must stay open");
        match msg {
            RibUpdate::PeerDown { peer, .. } => {
                assert_eq!(peer, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
                break;
            }
            RibUpdate::PeerGracefulRestart { .. } => {
                panic!("saturation teardown must deregister via PeerDown, not GR-preserve")
            }
            _ => {}
        }
    }
    // (3) The session task survived the teardown and terminates
    // cleanly on command.
    cmd_tx.send(PeerCommand::Shutdown).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), session_task)
        .await
        .expect("session task must terminate on Shutdown")
        .expect("session task must not panic")
        .expect("run() must return Ok");
    // (1) The wire: the writer hard-closed, so the peer reaches EOF;
    // the Cease/8 is the FINAL frame and no UPDATE follows it.
    let wire = tokio::time::timeout(Duration::from_secs(15), reader)
        .await
        .expect("peer must observe EOF after the hard close")
        .unwrap();
    let frames = parse_wire_frames(&wire);
    let notif_idx = frames
        .iter()
        .position(|(msg_type, _)| *msg_type == 3)
        .expect("the Cease NOTIFICATION must reach the wire");
    assert_eq!(
        &frames[notif_idx].1[19..21],
        &[6, 8],
        "NOTIFICATION must be Cease/Out of Resources"
    );
    assert_eq!(
        notif_idx,
        frames.len() - 1,
        "the NOTIFICATION must be the final frame — the saturated backlog \
         must be discarded, never drained after the Cease"
    );
    let updates_on_wire = frames.iter().filter(|(t, _)| *t == 2).count();
    assert!(
        updates_on_wire > 0,
        "sanity: UPDATEs must have flowed before saturation"
    );
    assert!(
        updates_on_wire < flood_total,
        "sanity: the flood must have outrun the wire"
    );
}

/// ADR-0078 rule 1: a full RIB channel parks the session task instead of
/// dropping the batch — the routes arrive once the channel drains, and
/// the saturation counter records the blocked send.
#[tokio::test]
async fn full_rib_channel_parks_session_and_never_drops_routes() {
    let (mut session, mut rib_rx, metrics) = backpressure_test_session(1);
    session.negotiated = Some(negotiated_session(65002, false));
    session.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast)];
    // Fill the capacity-1 channel so the delivery must block.
    session
        .rib_tx
        .try_send(placeholder_routes_received())
        .unwrap();
    session
        .read_buf
        .buf
        .extend_from_slice(&sample_update_message());
    let peer_label = session.peer_label.clone();
    let process = session.process_read_buffer();
    tokio::pin!(process);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut process)
            .await
            .is_err(),
        "processing must park on the full RIB channel, not drop the batch"
    );
    // Drain the pre-fill; the parked delivery completes.
    let placeholder = rib_rx.recv().await.expect("pre-filled update");
    assert!(matches!(
        placeholder,
        RibUpdate::RoutesReceived { peer, .. } if peer == IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99))
    ));
    tokio::time::timeout(Duration::from_secs(5), &mut process)
        .await
        .expect("processing must complete once the RIB drains");
    match rib_rx.recv().await.expect("delivered batch") {
        RibUpdate::RoutesReceived { announced, .. } => {
            assert_eq!(announced.len(), 1);
            assert_eq!(
                announced[0].prefix,
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24))
            );
        }
        _ => panic!("expected RoutesReceived"),
    }
    let blocked = counter_value(&metrics, "bgp_inbound_rib_backpressure_total", &peer_label);
    assert!((blocked - 1.0).abs() < f64::EPSILON, "got {blocked}");
}

/// ADR-0078 rule 3: a hold-timer expiry with an unprocessed COMPLETE
/// frame already in the read buffer re-arms instead of expiring — we
/// were the bottleneck, not the peer. The buffered bytes are a full
/// encoded KEEPALIVE on purpose: liveness is counted in complete
/// frames, so partial bytes would not qualify (see
/// `hold_expiry_with_partial_frame_expires`).
#[tokio::test]
async fn hold_expiry_with_buffered_input_rearms_instead_of_expiring() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    assert_eq!(session.fsm.state(), SessionState::Established);
    let keepalive = rustbgpd_wire::encode_message(&Message::Keepalive).unwrap();
    session.read_buf.buf.extend_from_slice(&keepalive);
    session.timers.hold = None; // the expiry the select loop observed
    session.handle_hold_timer_expiry().await;
    assert_eq!(
        session.fsm.state(),
        SessionState::Established,
        "pending input must not let the hold timer tear the session down"
    );
    assert!(
        session.timers.hold.is_some(),
        "processing the buffered KEEPALIVE must re-arm the hold timer"
    );
    let rearmed = counter_value(
        &session.metrics.clone(),
        "bgp_hold_timer_rearmed_pending_input_total",
        &session.peer_label,
    );
    assert!((rearmed - 1.0).abs() < f64::EPSILON, "got {rearmed}");
}

/// ADR-0078 rule 3, socket flavor: a complete frame sitting unread in
/// the kernel receive buffer also counts as liveness at hold expiry.
/// As above, the peer writes a full encoded KEEPALIVE — completeness
/// is what qualifies it as liveness, not the mere presence of bytes.
#[tokio::test]
async fn hold_expiry_with_unread_socket_data_rearms() {
    use tokio::io::AsyncWriteExt;
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    let keepalive = rustbgpd_wire::encode_message(&Message::Keepalive).unwrap();
    server.write_all(&keepalive).await.unwrap();
    server.flush().await.unwrap();
    // Let the bytes land in the local receive buffer.
    tokio::time::sleep(Duration::from_millis(50)).await;
    session.timers.hold = None;
    session.handle_hold_timer_expiry().await;
    assert_eq!(session.fsm.state(), SessionState::Established);
    assert!(session.timers.hold.is_some());
}

/// A partial frame in the read buffer is NOT liveness: a peer whose
/// application hangs mid-frame while its kernel keeps acknowledging must not
/// re-arm the hold timer forever (zombie session). RFC 4271 resets the
/// hold timer on receipt of a complete message; ten bytes of a header
/// don't qualify, so the expiry stands.
#[tokio::test]
async fn hold_expiry_with_partial_frame_expires() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    let keepalive = rustbgpd_wire::encode_message(&Message::Keepalive).unwrap();
    session.read_buf.buf.extend_from_slice(&keepalive[..10]);
    session.timers.hold = None;
    session.handle_hold_timer_expiry().await;
    assert_ne!(
        session.fsm.state(),
        SessionState::Established,
        "a permanently incomplete frame must not hold the session open"
    );
    assert!(
        session.timers.hold.is_none(),
        "partial input must not re-arm the hold timer"
    );
}

/// Partial frame, socket flavor: the peer wrote ten bytes of a frame
/// and then hung. The socket probe drains them into the read buffer,
/// but without a complete frame there is no liveness — the session
/// expires instead of zombieing.
#[tokio::test]
async fn hold_expiry_with_partial_socket_frame_expires() {
    use tokio::io::AsyncWriteExt;
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    let keepalive = rustbgpd_wire::encode_message(&Message::Keepalive).unwrap();
    server.write_all(&keepalive[..10]).await.unwrap();
    server.flush().await.unwrap();
    // Let the bytes land in the local receive buffer.
    tokio::time::sleep(Duration::from_millis(50)).await;
    session.timers.hold = None;
    session.handle_hold_timer_expiry().await;
    assert_ne!(
        session.fsm.state(),
        SessionState::Established,
        "a peer hung mid-frame must still expire the hold timer"
    );
}

/// Boundary: one complete frame followed by a partial second frame
/// re-arms — the complete frame is liveness, and the trailing partial
/// simply waits in the buffer for the rest of its bytes.
#[tokio::test]
async fn hold_expiry_with_complete_frame_then_partial_rearms() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    let keepalive = rustbgpd_wire::encode_message(&Message::Keepalive).unwrap();
    session.read_buf.buf.extend_from_slice(&keepalive);
    session.read_buf.buf.extend_from_slice(&keepalive[..10]);
    session.timers.hold = None;
    session.handle_hold_timer_expiry().await;
    assert_eq!(
        session.fsm.state(),
        SessionState::Established,
        "the complete leading frame is liveness even with a partial tail"
    );
    assert!(
        session.timers.hold.is_some(),
        "processing the complete KEEPALIVE must re-arm the hold timer"
    );
    assert_eq!(
        session.read_buf.buf.len(),
        10,
        "the partial second frame stays buffered for the normal read path"
    );
}

/// When the pending input itself tears the session down (here: a
/// NOTIFICATION), the manual re-arm after processing must be skipped.
/// The FSM stopped the hold timer and closed the connection during
/// teardown; re-arming would plant a hold timer on the dead session
/// that later fires in Idle and logs a spurious stale-timer
/// "daemon-side timer-management bug" warning.
#[tokio::test]
async fn hold_expiry_teardown_during_processing_does_not_rearm() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    let notification =
        rustbgpd_wire::encode_message(&Message::Notification(NotificationMessage::new(
            NotificationCode::Cease,
            cease_subcode::ADMINISTRATIVE_SHUTDOWN,
            Bytes::new(),
        )))
        .unwrap();
    session.read_buf.buf.extend_from_slice(&notification);
    session.timers.hold = None;
    session.handle_hold_timer_expiry().await;
    assert_ne!(
        session.fsm.state(),
        SessionState::Established,
        "the buffered NOTIFICATION must tear the session down"
    );
    assert!(
        session.read_half.is_none(),
        "teardown must have dropped the read half"
    );
    assert!(
        session.timers.hold.is_none(),
        "a torn-down session must not get its hold timer re-armed"
    );
}

/// A genuinely silent peer still expires: no buffered or readable input
/// means the hold expiry stands and the session leaves Established.
#[tokio::test]
async fn hold_expiry_without_pending_input_expires() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    session.timers.hold = None;
    session.handle_hold_timer_expiry().await;
    assert_ne!(
        session.fsm.state(),
        SessionState::Established,
        "a silent peer must still expire the hold timer"
    );
}

/// ADR-0078 rule 2: negotiating a session routes the KEEPALIVE cadence
/// to the writer task (watch holds the negotiated interval) instead of
/// arming the session-loop keepalive timer.
#[tokio::test]
async fn established_session_routes_keepalive_cadence_to_writer() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    assert!(
        session.timers.keepalive.is_none(),
        "the session loop must not own the keepalive cadence"
    );
    let cadence = *session
        .writer_keepalive_tx
        .as_ref()
        .expect("writer keepalive control must exist")
        .borrow();
    assert_eq!(
        cadence,
        Some(Duration::from_secs(30)),
        "hold 90 negotiates a 30 s keepalive cadence owned by the writer"
    );
}

/// RFC 9687 §4.3 teardown semantics at the session layer: a writer
/// exit of `SendHoldExpired` must (1) tear the session down to Idle
/// through the TCP-failure path, (2) emit a BMP Peer Down with reason
/// 2 — local close, *no* NOTIFICATION — carrying FSM event code 29
/// (`SendHoldTimer_Expires`, RFC 9687 §4.2), (3) increment
/// `bgp_send_hold_expirations_total`, and (4) put no NOTIFICATION on
/// the wire (the peer observes a bare FIN after the handshake bytes).
#[tokio::test]
async fn send_hold_expiry_tears_down_without_notification() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;

    // Drain the handshake bytes we sent (OPEN + KEEPALIVE) and the BMP
    // Peer Up so the assertions below observe only the teardown.
    assert!(matches!(
        read_single_bgp_message(&mut server).await,
        Message::Open(_)
    ));
    assert!(matches!(
        read_single_bgp_message(&mut server).await,
        Message::Keepalive
    ));
    assert!(matches!(
        bmp_rx.recv().await.unwrap(),
        BmpEvent::PeerUp { .. }
    ));

    // The writer observed a wedged peer and exited with SendHoldExpired.
    session
        .handle_writer_exit(Ok(Err(super::writer::WriterExit::SendHoldExpired {
            limit: Duration::from_secs(2),
        })))
        .await;

    assert_eq!(session.fsm.state(), SessionState::Idle);
    match bmp_rx.recv().await.unwrap() {
        BmpEvent::PeerDown { reason, .. } => {
            assert!(
                matches!(reason, PeerDownReason::LocalNoNotification(29)),
                "expected reason 2 with FSM event 29, got {reason:?}"
            );
        }
        other => panic!("expected BMP PeerDown, got {other:?}"),
    }
    let expirations = counter_value(
        &session.metrics.clone(),
        "bgp_send_hold_expirations_total",
        &session.peer_label,
    );
    assert!(
        (expirations - 1.0).abs() < f64::EPSILON,
        "got {expirations}"
    );
    assert!(session.last_error.contains("send hold timer expired"));

    // No NOTIFICATION follows the handshake: the teardown dropped the
    // writer senders, so the peer sees EOF as the very next event.
    let mut trailing = [0_u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), server.read(&mut trailing))
        .await
        .expect("peer must observe EOF promptly")
        .unwrap();
    assert_eq!(
        n,
        0,
        "unexpected bytes after teardown: {:?}",
        &trailing[..n]
    );
}

/// RFC 8654 §2 directionality, inbound: OUR advertised Extended Message
/// capability governs what we accept. The peer here did NOT advertise the
/// capability (see `establish_test_session`'s OPEN), yet a >4096-byte
/// UPDATE from it must be accepted because we always advertise it.
#[tokio::test]
async fn inbound_extended_message_accepted_from_peer_without_capability() {
    let (mut session, mut rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    let initial_capacity = session.read_buf.buf.capacity();
    assert_eq!(
        initial_capacity,
        usize::from(rustbgpd_wire::MAX_MESSAGE_LEN)
    );
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    assert!(
        !session.negotiated.as_ref().unwrap().peer_extended_message,
        "test premise: the peer did not advertise Extended Messages"
    );
    assert_eq!(
        session.read_buf.buf.capacity(),
        initial_capacity,
        "negotiating the extended inbound limit must not eagerly grow the buffer"
    );
    // ~1100 /24 prefixes at 4 bytes of NLRI each pushes the UPDATE past 4096.
    let entries: Vec<Ipv4NlriEntry> = (0..1100_u32)
        .map(|i| Ipv4NlriEntry {
            path_id: 0,
            prefix: Ipv4Prefix::new(
                Ipv4Addr::new(
                    10,
                    u8::try_from(i / 256).unwrap(),
                    u8::try_from(i % 256).unwrap(),
                    0,
                ),
                24,
            ),
        })
        .collect();
    let update = rustbgpd_wire::UpdateMessage::build(
        &entries,
        &[],
        &[
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        ],
        true,
        false,
        rustbgpd_wire::Ipv4UnicastMode::Body,
    );
    let encoded = rustbgpd_wire::encode_message_with_limit(
        &Message::Update(update),
        rustbgpd_wire::EXTENDED_MAX_MESSAGE_LEN,
    )
    .unwrap();
    assert!(
        encoded.len() > usize::from(rustbgpd_wire::MAX_MESSAGE_LEN),
        "test premise: the UPDATE exceeds 4096 bytes (got {})",
        encoded.len()
    );
    server.write_all(&encoded).await.unwrap();
    while !session.read_buf.has_complete_frame() {
        let bytes_read = tokio::time::timeout(
            Duration::from_secs(5),
            read_tcp(&mut session.read_half, &mut session.read_buf.buf),
        )
        .await
        .expect("session must read the extended UPDATE promptly")
        .unwrap();
        assert!(bytes_read > 0, "peer closed before the UPDATE was complete");
    }
    assert!(
        session.read_buf.buf.capacity() > initial_capacity,
        "the buffer must grow on demand after extended UPDATE bytes arrive"
    );
    session.process_read_buffer().await;
    assert_eq!(
        session.fsm.state(),
        SessionState::Established,
        "an extended inbound message must not tear the session down"
    );
    // Establishment emits its own RibUpdate first; skip to the routes.
    loop {
        if let RibUpdate::RoutesReceived { announced, .. } =
            rib_rx.recv().await.expect("routes delivered")
        {
            assert_eq!(announced.len(), 1100);
            break;
        }
    }
    loop {
        if let BmpEvent::RouteMonitoring { update_pdu, .. } =
            bmp_rx.recv().await.expect("BMP event delivered")
        {
            assert_eq!(update_pdu.as_ref(), encoded.as_ref());
            break;
        }
    }
}

/// RFC 8654 §2 directionality, outbound: the PEER's advertised Extended
/// Message capability governs what we may send. Without it, an oversized
/// message must fail to encode; with it, the extended limit applies.
#[tokio::test]
async fn outbound_extended_message_gated_on_peer_capability() {
    let mut session = make_test_session(65001, 65002);
    session.negotiated = Some(negotiated_session(65002, false));
    assert_eq!(
        session.outbound_max_message_len(),
        rustbgpd_wire::MAX_MESSAGE_LEN
    );
    let big = Message::Notification(rustbgpd_wire::NotificationMessage::new(
        rustbgpd_wire::NotificationCode::Cease,
        2,
        Bytes::from(vec![0_u8; 5000]),
    ));
    assert!(
        session.enqueue_priority(&big).is_err(),
        "oversized NOTIFICATION must not encode toward a peer without the capability"
    );
    session.negotiated.as_mut().unwrap().peer_extended_message = true;
    assert_eq!(
        session.outbound_max_message_len(),
        rustbgpd_wire::EXTENDED_MAX_MESSAGE_LEN
    );
    assert!(
        session.enqueue_priority(&big).is_ok(),
        "the peer advertised Extended Messages — the extended limit applies"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Slow-peer detection (LAN-470)
// ─────────────────────────────────────────────────────────────────────

/// End-to-end detector proof on a real wedged socket (the #962 writer
/// test pattern: shrunk socket buffers + burst): the flag must NOT
/// raise before the configured duration, MUST raise once the backlog
/// has persisted past it, and MUST clear — flag and `bgp_peer_slow`
/// gauge both — after the peer drains. A flag that never clears is a
/// false-alarm generator.
#[tokio::test]
async fn slow_peer_flag_fires_on_wedged_backlog_and_clears_after_drain() {
    const FRAMES: usize = 3000;
    const FRAME_LEN: usize = 1024;

    let mut session = make_test_session(65001, 65002);
    session.config.slow_peer_duration = 1;
    session.config.slow_peer_threshold_pct = 50;

    // Wedged TCP pair: tiny buffers on both sides, peer never reads.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connect = tokio::spawn(async move {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(4096).unwrap();
        socket.connect(addr).await.unwrap()
    });
    let (server, _) = listener.accept().await.unwrap();
    socket2::SockRef::from(&server)
        .set_send_buffer_size(4096)
        .unwrap();
    let mut peer = connect.await.unwrap();
    session.test_install_stream(server);

    // Burst far beyond the wedged socket: > threshold (50% of
    // OUTBOUND_BUFFER = 2048) frames stay queued behind the parked
    // writer.
    let bulk_tx = session.writer_bulk_tx.clone().unwrap();
    for _ in 0..FRAMES {
        bulk_tx
            .send(Bytes::from(vec![0u8; FRAME_LEN]))
            .await
            .unwrap();
    }

    // Above threshold but duration not yet elapsed: candidate, not slow.
    session.evaluate_slow_peer();
    assert!(
        !session.slow_peer,
        "flag must not raise before the configured duration"
    );
    assert!(
        session.slow_peer_backlog_since.is_some(),
        "backlog episode must be tracked from the first over-threshold sample"
    );
    assert_eq!(session.metrics.peer_slow(&session.peer_label), 0);

    // Backlog persists past the duration: the flag raises.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    session.evaluate_slow_peer();
    assert!(session.slow_peer, "flag must raise after the duration");
    assert_eq!(session.metrics.peer_slow(&session.peer_label), 1);

    // Peer recovers: drain everything the writer sends.
    let mut sink = vec![0u8; FRAMES * FRAME_LEN];
    peer.read_exact(&mut sink).await.unwrap();

    // Fully drained: the flag and the gauge both clear.
    session.evaluate_slow_peer();
    assert!(!session.slow_peer, "flag must clear after the queue drains");
    assert_eq!(session.metrics.peer_slow(&session.peer_label), 0);
    assert!(session.slow_peer_backlog_since.is_none());

    // Teardown resets detector state without leaving the gauge high.
    session.handle_tcp_disconnect();
    assert_eq!(session.metrics.peer_slow(&session.peer_label), 0);
}

/// `slow_peer_duration = 0` disables detection entirely: no episode
/// tracking, no flag, no re-check timer — the documented off switch.
#[tokio::test]
async fn slow_peer_detection_disabled_by_zero_duration() {
    let mut session = make_test_session(65001, 65002);
    session.config.slow_peer_duration = 0;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connect = tokio::spawn(async move {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(4096).unwrap();
        socket.connect(addr).await.unwrap()
    });
    let (server, _) = listener.accept().await.unwrap();
    socket2::SockRef::from(&server)
        .set_send_buffer_size(4096)
        .unwrap();
    let _peer = connect.await.unwrap();
    session.test_install_stream(server);

    let bulk_tx = session.writer_bulk_tx.clone().unwrap();
    for _ in 0..3000 {
        bulk_tx.send(Bytes::from(vec![0u8; 1024])).await.unwrap();
    }
    session.evaluate_slow_peer();
    assert!(!session.slow_peer);
    assert!(session.slow_peer_backlog_since.is_none());
    assert!(session.slow_peer_timer.is_none());
}
