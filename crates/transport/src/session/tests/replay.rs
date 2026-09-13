use super::*;
use crate::session::replay::{PendingReplay, ReplayProgress, poll_completion};
use rustbgpd_bmp::BmpReplay;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplayAdmissionWait {
    Bmp,
    Enrollment,
    Rib,
}

#[tokio::test(start_paused = true)]
async fn replay_caller_cancellation_releases_bmp_admission() {
    exercise_canceled_replay_admission(ReplayAdmissionWait::Bmp).await;
}

#[tokio::test(start_paused = true)]
async fn replay_caller_cancellation_releases_enrollment_wait() {
    exercise_canceled_replay_admission(ReplayAdmissionWait::Enrollment).await;
}

#[tokio::test(start_paused = true)]
async fn replay_caller_cancellation_releases_rib_admission() {
    exercise_canceled_replay_admission(ReplayAdmissionWait::Rib).await;
}

async fn enroll_replay_with_real_bmp_manager(
    peer_up: BmpEvent,
    begin: BmpEvent,
) -> (
    mpsc::Sender<rustbgpd_bmp::BmpControlEvent>,
    tokio::task::JoinHandle<()>,
    mpsc::Receiver<Bytes>,
) {
    use rustbgpd_bmp::{BmpControlEvent, BmpManager, BmpMonitorFilter, BmpVersion};

    let (events, event_rx) = mpsc::channel(8);
    let (control, control_rx) = mpsc::channel(8);
    let (collector, mut collector_rx) = mpsc::channel(8);
    let address = "127.0.0.1:11019".parse().unwrap();
    let manager = BmpManager::new(
        event_rx,
        control_rx,
        vec![(
            address,
            BmpMonitorFilter {
                rib_in_pre: false,
                rib_out_post: true,
                ..BmpMonitorFilter::default()
            },
            BmpVersion::V3,
        )],
        BgpMetrics::new(),
    );
    let manager = tokio::spawn(manager.run());
    let (bootstrap, initial) = oneshot::channel();
    control
        .send(BmpControlEvent::CollectorConnected {
            collector_id: 0,
            collector_addr: address,
            sender: collector,
            bootstrap,
        })
        .await
        .unwrap();
    let initial = initial.await.unwrap();
    control
        .send(BmpControlEvent::CollectorBootstrapComplete {
            collector_id: 0,
            generation: initial.generation,
        })
        .await
        .unwrap();
    // Let the manager consume its only queued control before publishing PeerUp.
    while control.capacity() != control.max_capacity() {
        tokio::task::yield_now().await;
    }
    events.send(peer_up).await.unwrap();
    assert_eq!(collector_rx.recv().await.unwrap()[5], 3);
    events.send(begin).await.unwrap();
    assert_eq!(collector_rx.recv().await.unwrap()[5], 2);
    assert_eq!(collector_rx.recv().await.unwrap()[5], 3);
    (control, manager, collector_rx)
}

#[expect(
    clippy::too_many_lines,
    reason = "three real admission waits retain cancellation, query recovery, exact token and wire/BMP EoR evidence"
)]
async fn exercise_canceled_replay_admission(wait: ReplayAdmissionWait) {
    use std::future::{Future, poll_fn};
    use std::task::Poll;

    let (mut session, mut old_rib_rx, mut old_bmp_rx) =
        make_test_session_with_rib_and_bmp(65001, 65002);
    session.config.bmp_rib_out = true;
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    read_single_bgp_message(&mut server).await;
    read_single_bgp_message(&mut server).await;
    while old_rib_rx.try_recv().is_ok() {}
    while old_bmp_rx.try_recv().is_ok() {}
    let peer_up = session.build_bmp_peer_up_event();
    session.install_import_policy(Some(rustbgpd_policy::PolicyChain::new(vec![])));
    let generation = session.import_policy_generation;
    let (bmp_tx, mut bmp_rx) = mpsc::channel(1);
    session.bmp_tx = Some(bmp_tx.clone());
    if wait == ReplayAdmissionWait::Bmp {
        bmp_tx
            .try_send(BmpEvent::RouteMonitoring {
                peer_info: session.build_bmp_peer_info(),
                update_pdu: Bytes::from_static(b"held admission"),
            })
            .unwrap();
    }
    let (rib_tx, mut rib_rx) = mpsc::channel(1);
    session.rib_tx = rib_tx.clone();
    let (held, _held_reply) = oneshot::channel();
    rib_tx
        .try_send(RibUpdate::QueryLocRibCount { reply: held })
        .unwrap();

    let (reply, response) = oneshot::channel();
    let mut scheduling = Box::pin(session.handle_command(PeerCommand::ReplayOutbound { reply }));
    assert!(
        poll_fn(|cx| Poll::Ready(scheduling.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    let mut manager = None;
    let token = if wait == ReplayAdmissionWait::Bmp {
        None
    } else {
        let begin = bmp_rx
            .try_recv()
            .expect("Begin admitted before enrollment wait");
        let BmpEvent::OutboundReplayBegin { replay, .. } = &begin else {
            panic!("expected the operation's exact Begin token");
        };
        let token = Arc::clone(replay);
        if wait == ReplayAdmissionWait::Rib {
            manager = Some(enroll_replay_with_real_bmp_manager(peer_up, begin).await);
            // Enrollment is acknowledged; this poll reaches the full RIB queue.
            assert!(
                poll_fn(|cx| Poll::Ready(scheduling.as_mut().poll(cx)))
                    .await
                    .is_pending()
            );
        }
        Some(token)
    };
    drop(response);
    let released = tokio::time::timeout(Duration::from_secs(2), scheduling.as_mut())
        .await
        .is_ok();
    drop(scheduling);
    let canceled =
        session.pending_replay.is_none() && token.as_ref().is_none_or(|token| !token.is_valid());
    let suppressed = session.replay_eor_suppressed;

    // These real handlers must run before either bounded downstream queue is
    // released. They read the installed session, not a cached/fabricated reply.
    let (state_reply, state) = oneshot::channel();
    assert!(
        session
            .handle_command(PeerCommand::QueryState { reply: state_reply })
            .await
            .is_continue()
    );
    let state = state.await.unwrap();
    let (counter_reply, counter_result) = oneshot::channel();
    assert!(
        session
            .handle_command(PeerCommand::QueryImportPolicyTermHits {
                reply: counter_reply
            })
            .await
            .is_continue()
    );
    let counters = counter_result.await.unwrap().unwrap();
    assert_eq!(rib_tx.capacity(), 0);
    session.cancel_outbound_replay(); // Reap the pending operation on the red control too.
    if wait == ReplayAdmissionWait::Bmp {
        assert!(matches!(
            bmp_rx.try_recv().unwrap(),
            BmpEvent::RouteMonitoring { .. }
        ));
    }
    assert!(matches!(
        rib_rx.try_recv().unwrap(),
        RibUpdate::QueryLocRibCount { .. }
    ));
    tokio::task::yield_now().await;
    let no_late_admission = bmp_rx.try_recv().is_err() && rib_rx.try_recv().is_err();

    let eor = session
        .export_encoder
        .snapshot()
        .build_end_of_rib(Afi::Ipv4, Safi::Unicast)
        .unwrap();
    session.enqueue_bulk(&Message::Update(eor)).unwrap();
    // A paused-time timeout may leave the writer's independent KEEPALIVE in
    // front of the bulk EoR. It does not certify or replace the replay marker.
    let eor = loop {
        let message = read_single_raw_bgp_message(&mut server).await;
        if message[18] != 4 {
            break message;
        }
    };
    assert_eq!(eor[18], 2, "ordinary BGP UPDATE still reaches the peer");
    assert_eq!(&eor[19..], &[0, 0, 0, 0], "empty IPv4 unicast EoR");
    let mirrored = bmp_rx.try_recv().is_ok();
    let writer = session.writer_join.take().unwrap();
    writer.abort();
    let _ = writer.await;
    if let Some((control, manager, _collector)) = manager {
        control
            .send(rustbgpd_bmp::BmpControlEvent::Shutdown)
            .await
            .unwrap();
        manager.await.unwrap();
    }
    assert!(
        released,
        "{wait:?}: canceled replay retained the session past the read budget"
    );
    assert!(canceled, "{wait:?}: exact replay token remains live");
    assert_eq!(state.fsm_state, SessionState::Established);
    assert_eq!(counters.generation, generation);
    assert!(
        no_late_admission,
        "{wait:?}: canceled work admitted after capacity returned"
    );
    assert_eq!(
        mirrored,
        wait == ReplayAdmissionWait::Bmp,
        "{wait:?}: ordinary BMP EoR mirroring must follow the Begin admission boundary"
    );
    assert_eq!(suppressed, wait != ReplayAdmissionWait::Bmp);
}

fn pending(session: &PeerSession, token: Arc<BmpReplay>) -> PendingReplay {
    PendingReplay {
        replay: token,
        target: None,
        deadline: tokio::time::Instant::now() + Duration::from_secs(5),
        peer_info: session.build_bmp_peer_info(),
        end_of_rib: vec![],
        handed_off: false,
        scheduling: None,
        reply: None,
    }
}

#[tokio::test]
async fn replay_scheduling_drains_one_slot_queue_and_ack_precedes_completion() {
    exercise_replay_actor(false).await;
}

#[tokio::test]
async fn replay_held_completion_keeps_commands_responsive_and_later_rows_queued() {
    exercise_replay_actor(true).await;
}

#[expect(
    clippy::too_many_lines,
    reason = "real actor fixture verifies the complete scheduling, writer, and BMP ordering boundary"
)]
async fn exercise_replay_actor(hold_completion: bool) {
    let (mut session, mut rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.config.bmp_rib_out = true;
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    recv_peer_up_after_export_context(&mut rib_rx).await;
    read_single_bgp_message(&mut server).await;
    read_single_bgp_message(&mut server).await;
    while bmp_rx.try_recv().is_ok() {}
    let (outbound_tx, outbound_rx) = mpsc::channel(1);
    session.outbound_rx = outbound_rx;
    session.outbound_tx = outbound_tx.clone();
    let (cmd_tx, cmd_rx) = mpsc::channel(8);
    session.commands = cmd_rx;
    let (token, _enrolled) = BmpReplay::new(Duration::from_secs(5));
    let (admit_tx, admit_rx) = oneshot::channel();
    let (reply, response) = oneshot::channel();
    let mut operation = pending(&session, Arc::clone(&token));
    operation.scheduling = Some(admit_rx);
    operation.reply = Some(reply);
    session.pending_replay = Some(operation);
    session.replay_eor_suppressed = true;
    let exact: Arc<dyn rustbgpd_rib::ExactExportSnapshot> = session.publish_export_profile();
    let actual_completed = session.writer_completed.as_ref().unwrap().clone();
    let (release, held) = tokio::sync::watch::channel(0);
    if hold_completion {
        session.writer_completed = Some(held);
    }
    let actor = tokio::spawn(async move { session.run().await });
    for _ in 0..4 {
        let mut update = empty_outbound_update();
        update.exact_export_snapshot = Some(Arc::clone(&exact));
        update.announce = vec![make_route(100)].into();
        update.next_hop_override = vec![None].into();
        tokio::time::timeout(Duration::from_secs(1), outbound_tx.send(update))
            .await
            .unwrap()
            .unwrap();
    }
    let mut terminal = empty_outbound_update();
    terminal.replay = Some(Arc::clone(&token));
    terminal.end_of_rib = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
    outbound_tx.send(terminal).await.unwrap();
    admit_tx.send(Ok(())).unwrap();
    tokio::time::timeout(Duration::from_secs(1), response)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let mut later = empty_outbound_update();
    later.exact_export_snapshot = Some(exact);
    later.announce = vec![make_route(200)].into();
    later.next_hop_override = vec![None].into();
    outbound_tx.send(later).await.unwrap();
    let mut rows = 0;
    if hold_completion {
        for _ in 0..6 {
            assert!(matches!(
                read_single_bgp_message(&mut server).await,
                Message::Update(_)
            ));
        }
        for _ in 0..4 {
            assert!(matches!(
                bmp_rx.recv().await.unwrap(),
                BmpEvent::RouteMonitoring { .. }
            ));
            rows += 1;
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(10), bmp_rx.recv())
                .await
                .is_err()
        );
        let (reply, response) = oneshot::channel();
        cmd_tx
            .send(PeerCommand::QueryState { reply })
            .await
            .unwrap();
        let state = tokio::time::timeout(Duration::from_secs(1), response)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.fsm_state, SessionState::Established);
        assert_eq!(
            outbound_tx.capacity(),
            0,
            "later UPDATE must remain in the existing bounded queue"
        );
        release.send(*actual_completed.borrow()).unwrap();
    }
    let mut complete = false;
    while rows < 5 {
        match tokio::time::timeout(Duration::from_secs(1), bmp_rx.recv())
            .await
            .unwrap()
            .unwrap()
        {
            BmpEvent::RouteMonitoring { .. } => {
                rows += 1;
                assert_eq!(
                    complete,
                    rows == 5,
                    "later row must follow replay completion"
                );
            }
            BmpEvent::OutboundReplayComplete { end_of_rib, .. } => {
                assert_eq!(rows, 4);
                assert_eq!(end_of_rib.len(), 2);
                assert_eq!(&end_of_rib[0][19..], &[0, 0, 0, 0]);
                assert_eq!(&end_of_rib[1][19..], &[0, 0, 0, 6, 0x80, 15, 3, 0, 2, 1]);
                complete = true;
            }
            other => panic!("unexpected event {other:?}"),
        }
    }
    for _ in 0..if hold_completion { 1 } else { 7 } {
        assert!(matches!(
            read_single_bgp_message(&mut server).await,
            Message::Update(_)
        ));
    }
    drop(cmd_tx);
    tokio::time::timeout(Duration::from_secs(1), actor)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn replay_fence_waits_for_bulk_watermark_and_cancellation_is_permanent() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    let (token, _enrolled) = BmpReplay::new(Duration::from_secs(5));
    let mut operation = pending(&session, Arc::clone(&token));
    operation.target = Some(10);
    operation.end_of_rib = vec![Bytes::from_static(b"terminal")];
    session.pending_replay = Some(operation);
    let (written, receiver) = tokio::sync::watch::channel(9);
    session.writer_completed = Some(receiver);
    assert!(
        tokio::time::timeout(
            Duration::from_millis(10),
            poll_completion(&mut session.pending_replay, &mut session.writer_completed)
        )
        .await
        .is_err()
    );
    token.cancel();
    written.send(10).unwrap();
    let progress =
        poll_completion(&mut session.pending_replay, &mut session.writer_completed).await;
    assert!(matches!(progress, ReplayProgress::Completed(false)));
    session.finish_outbound_replay(progress);
    assert!(bmp_rx.try_recv().is_err());
    assert!(!token.is_valid());
}

#[tokio::test]
async fn replay_caller_drop_during_scheduling_cancels_without_completion() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    let (token, _enrolled) = BmpReplay::new(Duration::from_secs(5));
    let (_admit_tx, admit_rx) = oneshot::channel();
    let (reply, response) = oneshot::channel();
    let mut operation = pending(&session, Arc::clone(&token));
    operation.scheduling = Some(admit_rx);
    operation.reply = Some(reply);
    session.pending_replay = Some(operation);
    drop(response);
    let progress =
        poll_completion(&mut session.pending_replay, &mut session.writer_completed).await;
    session.finish_outbound_replay(progress);
    assert!(!token.is_valid());
    assert!(session.pending_replay.is_none());
    assert!(bmp_rx.try_recv().is_err());
}

#[tokio::test]
async fn replay_suppresses_ordinary_eor_after_cancel_and_writer_replacement_invalidates() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.config.bmp_rib_out = true;
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let (token, _enrolled) = BmpReplay::new(Duration::from_secs(5));
    session.pending_replay = Some(pending(&session, Arc::clone(&token)));
    session.replay_eor_suppressed = true;
    session.cancel_outbound_replay();
    let eor = session
        .export_encoder
        .snapshot()
        .build_end_of_rib(Afi::Ipv4, Safi::Unicast)
        .unwrap();
    session.enqueue_bulk(&Message::Update(eor)).unwrap();
    assert!(bmp_rx.try_recv().is_err());
    assert!(!token.is_valid());
    let (next, _enrolled) = BmpReplay::new(Duration::from_secs(5));
    session.pending_replay = Some(pending(&session, Arc::clone(&next)));
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    assert!(!next.is_valid());
    assert!(session.pending_replay.is_none());
}

#[tokio::test]
async fn replay_expiry_and_full_bmp_source_never_certify_completion() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    let (token, _enrolled) = BmpReplay::new(Duration::from_secs(5));
    let mut operation = pending(&session, Arc::clone(&token));
    operation.deadline = tokio::time::Instant::now();
    operation.target = Some(1);
    session.pending_replay = Some(operation);
    let (_written, receiver) = tokio::sync::watch::channel(0);
    session.writer_completed = Some(receiver);
    let progress =
        poll_completion(&mut session.pending_replay, &mut session.writer_completed).await;
    session.finish_outbound_replay(progress);
    assert!(!token.is_valid());
    let (token, _enrolled) = BmpReplay::new(Duration::from_secs(5));
    let mut operation = pending(&session, Arc::clone(&token));
    operation.end_of_rib = vec![Bytes::from_static(b"terminal")];
    session.pending_replay = Some(operation);
    let sender = session.bmp_tx.as_ref().unwrap();
    for _ in 0..sender.max_capacity() {
        sender
            .try_send(BmpEvent::RouteMonitoring {
                peer_info: session.build_bmp_peer_info(),
                update_pdu: Bytes::from_static(b"old"),
            })
            .unwrap();
    }
    session.finish_outbound_replay(ReplayProgress::Completed(true));
    assert!(!token.is_valid());
    while let Ok(event) = bmp_rx.try_recv() {
        assert!(!matches!(event, BmpEvent::OutboundReplayComplete { .. }));
    }
}

#[tokio::test]
async fn replay_queued_completion_expiry_cannot_be_replaced_by_an_ordinary_eor() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.config.bmp_rib_out = true;
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let (token, _enrolled) = BmpReplay::new(Duration::from_secs(5));
    let mut operation = pending(&session, Arc::clone(&token));
    operation.end_of_rib = vec![Bytes::from_static(b"terminal")];
    session.pending_replay = Some(operation);
    session.replay_eor_suppressed = true;
    session.finish_outbound_replay(ReplayProgress::Completed(true));
    assert!(matches!(
        bmp_rx.try_recv().unwrap(),
        BmpEvent::OutboundReplayComplete { .. }
    ));
    token.cancel(); // Models rejection/expiry while Complete waits in the BMP queue.
    let eor = session
        .export_encoder
        .snapshot()
        .build_end_of_rib(Afi::Ipv4, Safi::Unicast)
        .unwrap();
    session.enqueue_bulk(&Message::Update(eor)).unwrap();
    assert!(session.replay_eor_suppressed);
    assert!(bmp_rx.try_recv().is_err());
}

#[tokio::test]
async fn replay_outbound_rejects_empty_or_mixed_families_before_enrollment_or_traffic() {
    for families in [
        vec![],
        vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv4, Safi::FlowSpec)],
    ] {
        let (mut session, mut rib_rx, mut bmp_rx) =
            make_test_session_with_rib_and_bmp(65001, 65002);
        session.config.bmp_rib_out = true;
        let (client, mut server) = connected_stream_pair().await;
        session.test_install_stream(client);
        establish_test_session(&mut session, 65002).await;
        read_single_bgp_message(&mut server).await;
        read_single_bgp_message(&mut server).await;
        while rib_rx.try_recv().is_ok() {}
        while bmp_rx.try_recv().is_ok() {}
        let mut negotiated = negotiated_session(65002, false);
        negotiated.negotiated_families = families;
        install_test_negotiated_session(&mut session, negotiated);
        let admitted = session.writer_bulk_admitted;
        let (reply, response) = oneshot::channel();
        session.start_outbound_replay(reply).await;
        assert!(
            matches!(response.await.unwrap(), Err(PeerCommandError::ReplayUnavailable(message)) if message.contains("unicast-only"))
        );
        assert!(session.pending_replay.is_none());
        assert!(!session.replay_eor_suppressed);
        assert_eq!(session.writer_bulk_admitted, admitted);
        assert!(bmp_rx.try_recv().is_err());
        assert!(rib_rx.try_recv().is_err());
        let mut byte = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(10), server.read(&mut byte))
                .await
                .is_err()
        );
    }
}
