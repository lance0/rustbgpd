use super::*;
use rustbgpd_api::peer_types::{PeerManagerOperatorQuery, PeerManagerReadinessQuery};

#[tokio::test(start_paused = true)]
async fn refresh_outbound_bounds_full_rib_queue_admission() {
    let address = "192.0.2.1".parse().unwrap();
    let (commands, command_rx) = mpsc::channel(4);
    let (operator, operator_rx) = mpsc::channel(4);
    let (rib_tx, mut rib_rx) = mpsc::channel(1);
    rib_tx
        .send(RibUpdate::PeerDown {
            peer: address,
            session_id: 99,
        })
        .await
        .unwrap();
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    )
    .with_operator_queries(operator_rx);
    insert_test_managed_peer(&mut manager, address, stalled_policy_query_handle(), false);
    let manager_task = tokio::spawn(manager.run());
    let (reply, mut response) = oneshot::channel();
    commands
        .send(PeerManagerCommand::RefreshOutbound {
            peer: key(address),
            reply,
        })
        .await
        .unwrap();

    // The RIB receiver stays alive and full: admission, not its reply, is held.
    let started = tokio::time::Instant::now();
    let returned =
        tokio::time::timeout(RIB_REPLY_TIMEOUT + Duration::from_secs(1), &mut response).await;
    let bounded = returned.is_ok();
    let elapsed = started.elapsed();
    drop(response);
    let (reply, read) = oneshot::channel();
    operator
        .send(PeerManagerOperatorQuery::HasPeerAddress { address, reply }.into())
        .await
        .unwrap();
    let read_after_cancellation = matches!(
        tokio::time::timeout(Duration::from_secs(2), read).await,
        Ok(Ok(true))
    );

    // Release admission and finish the owned command before asserting. If it
    // was already bounded, there is no late refresh to acknowledge.
    assert!(matches!(
        rib_rx.recv().await,
        Some(RibUpdate::PeerDown { .. })
    ));
    let late_refresh = match tokio::time::timeout(Duration::from_millis(1), rib_rx.recv()).await {
        Ok(Some(RibUpdate::RefreshPeerOutbound { reply, .. })) => {
            let _ = reply.send(Ok(()));
            true
        }
        Err(_) => false,
        _ => panic!("unexpected RIB delivery"),
    };
    let rib_drain = tokio::spawn(async move { while rib_rx.recv().await.is_some() {} });
    drop(commands);
    drop(operator);
    tokio::time::timeout(Duration::from_secs(1), manager_task)
        .await
        .expect("manager exits after releasing the full queue")
        .unwrap();
    rib_drain.await.unwrap();
    println!(
        "refresh: bounded={bounded}, wait={elapsed:?}, read_after_cancellation={read_after_cancellation}, late_refresh={late_refresh}"
    );
    assert!(
        bounded,
        "outbound refresh must bound RIB queue admission as well as its reply; still parked after {elapsed:?}"
    );
    assert_eq!(elapsed, RIB_REPLY_TIMEOUT);
    assert!(read_after_cancellation);
    assert!(
        !late_refresh,
        "an expired refresh must not enter the RIB queue"
    );
}

#[tokio::test(start_paused = true)]
async fn replay_scheduling_keeps_readiness_and_operator_reads_responsive() {
    let address = "192.0.2.1".parse().unwrap();
    let (session_commands, mut session_rx) = mpsc::channel(4);
    let (held, held_rx) = oneshot::channel();
    let (release, release_rx) = oneshot::channel();
    let session = tokio::spawn(async move {
        let Some(PeerCommand::ReplayOutbound { reply }) = session_rx.recv().await else {
            panic!("expected outbound replay scheduling command");
        };
        held.send(()).unwrap();
        release_rx.await.unwrap();
        reply.send(Ok(())).unwrap();
        while let Some(command) = session_rx.recv().await {
            if matches!(command, PeerCommand::Shutdown) {
                break;
            }
        }
        Ok(())
    });
    let (commands, command_rx) = mpsc::channel(4);
    let (operator, operator_rx) = mpsc::channel(4);
    let (readiness, readiness_rx) = mpsc::channel(4);
    let (rib_tx, mut rib_rx) = mpsc::channel(4);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    )
    .with_operator_queries(operator_rx)
    .with_readiness_queries(readiness_rx);
    insert_test_managed_peer(
        &mut manager,
        address,
        PeerHandle::from_parts(session_commands, session),
        false,
    );
    let manager_task = tokio::spawn(manager.run());
    let (reply, mut response) = oneshot::channel();
    commands
        .send(PeerManagerCommand::ReplayOutbound {
            peer: key(address),
            reply,
        })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), held_rx)
        .await
        .expect("session must hold scheduling before the probes begin")
        .unwrap();
    let (reply, ping) = oneshot::channel();
    readiness
        .send(PeerManagerReadinessQuery::Ping { reply })
        .await
        .unwrap();
    let (reply, read) = oneshot::channel();
    operator
        .send(PeerManagerOperatorQuery::HasPeerAddress { address, reply }.into())
        .await
        .unwrap();
    let (ping, read) = tokio::join!(
        tokio::time::timeout(Duration::from_millis(500), ping),
        tokio::time::timeout(Duration::from_secs(2), read),
    );
    let ping_ok = matches!(ping, Ok(Ok(())));
    let read_ok = matches!(read, Ok(Ok(true)));
    let scheduling_still_held = matches!(
        response.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    );
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), response)
        .await
        .expect("replay scheduling completes after its reply is released")
        .unwrap()
        .unwrap();
    let rib_drain = tokio::spawn(async move { while rib_rx.recv().await.is_some() {} });
    drop(commands);
    drop(operator);
    drop(readiness);
    tokio::time::timeout(Duration::from_secs(1), manager_task)
        .await
        .expect("manager exits after replay scheduling settles")
        .unwrap();
    rib_drain.await.unwrap();
    println!(
        "replay: readiness={ping_ok}, operator={read_ok}, scheduling_still_held={scheduling_still_held}"
    );
    assert!(scheduling_still_held, "the probes must overlap scheduling");
    assert!(
        ping_ok && read_ok,
        "replay scheduling must serve readiness and operator reads while its own reply remains held"
    );
}

/// An owner finishing while a consumed session read is parked must not drop
/// that read's reply. Refresh also releases queue capacity after its deadline.
#[expect(
    clippy::too_many_lines,
    reason = "one paused-time proof keeps setup, overlapping owners, release, and cleanup together"
)]
#[tokio::test(start_paused = true)]
async fn admitted_reads_survive_owner_expiry_and_replay_cancellation() {
    for (replay, cancel) in [(false, false), (true, false), (true, true)] {
        let address = "192.0.2.1".parse().unwrap();
        let (session_commands, mut session_rx) = mpsc::channel(4);
        let (replays, mut replay_rx) = mpsc::channel(1);
        let (states, mut state_rx) = mpsc::channel(1);
        let session = tokio::spawn(async move {
            while let Some(command) = session_rx.recv().await {
                match command {
                    PeerCommand::ReplayOutbound { reply } => replays.send(reply).await.unwrap(),
                    PeerCommand::QueryState { reply } => states.send(reply).await.unwrap(),
                    PeerCommand::Shutdown => break,
                    _ => {}
                }
            }
            Ok(())
        });
        let (commands, command_rx) = mpsc::channel(4);
        let (operator, operator_rx) = mpsc::channel(4);
        let (rib_tx, mut rib_rx) = mpsc::channel(1);
        if !replay {
            rib_tx
                .send(RibUpdate::PeerDown {
                    peer: address,
                    session_id: 99,
                })
                .await
                .unwrap();
        }
        let mut manager = PeerManager::new(
            command_rx,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            None,
            BgpMetrics::new(),
            rib_tx,
            None,
        )
        .with_operator_queries(operator_rx);
        insert_test_managed_peer(
            &mut manager,
            address,
            PeerHandle::from_parts(session_commands, session),
            false,
        );
        let manager_task = tokio::spawn(manager.run());
        let (reply, response) = oneshot::channel();
        commands
            .send(if replay {
                PeerManagerCommand::ReplayOutbound {
                    peer: key(address),
                    reply,
                }
            } else {
                PeerManagerCommand::RefreshOutbound {
                    peer: key(address),
                    reply,
                }
            })
            .await
            .unwrap();
        let held_replay = if replay {
            Some(
                tokio::time::timeout(Duration::from_secs(1), replay_rx.recv())
                    .await
                    .unwrap()
                    .unwrap(),
            )
        } else {
            while commands.capacity() != commands.max_capacity() {
                tokio::task::yield_now().await;
            }
            None
        };
        tokio::time::advance(
            RIB_REPLY_TIMEOUT
                .checked_sub(Duration::from_millis(50))
                .unwrap(),
        )
        .await;
        let (reply, read) = oneshot::channel();
        operator
            .send(
                PeerManagerOperatorQuery::GetPeerState {
                    peer: key(address),
                    reply,
                }
                .into(),
            )
            .await
            .unwrap();
        let state_reply = tokio::time::timeout(Duration::from_millis(25), state_rx.recv())
            .await
            .expect("operator read must be admitted before owner expiry")
            .unwrap();
        let (reply, mut mutation) = oneshot::channel();
        commands
            .send(PeerManagerCommand::DisablePeer {
                peer: key(address),
                reason: None,
                reply,
            })
            .await
            .unwrap();
        let mut response = Some(response);
        if cancel {
            drop(response.take());
        }
        // The read's own 100 ms session budget still has 25 ms remaining.
        tokio::time::advance(Duration::from_millis(75)).await;
        if !replay {
            assert!(matches!(
                rib_rx.recv().await,
                Some(RibUpdate::PeerDown { .. })
            ));
        }
        let mutation_fenced = matches!(
            mutation.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        );
        let read_delivered = state_reply
            .send(policy_test_peer_state(address, SessionState::Established))
            .is_ok();
        let read_survived = matches!(
            tokio::time::timeout(Duration::from_secs(1), read).await,
            Ok(Ok(Some(info))) if info.state == SessionState::Established,
        );
        if let Some(response) = response {
            let error = response.await.unwrap().unwrap_err();
            assert!(error.to_string().contains("timed out"), "{error}");
        }
        mutation.await.unwrap().unwrap();
        let no_late_refresh = matches!(rib_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty));
        let replay_canceled = held_replay.as_ref().is_none_or(oneshot::Sender::is_closed);
        drop(held_replay);
        drop(commands);
        drop(operator);
        tokio::time::timeout(Duration::from_secs(1), manager_task)
            .await
            .unwrap()
            .unwrap();
        assert!(
            mutation_fenced,
            "replay={replay}, cancel={cancel}: mutation bypassed the admitted read"
        );
        assert!(
            read_delivered && read_survived,
            "replay={replay}, cancel={cancel}: owner completion dropped the admitted read"
        );
        assert!(
            no_late_refresh,
            "expired refresh admitted after capacity returned"
        );
        assert!(
            replay_canceled,
            "expired or canceled scheduling retained its session reply"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn refresh_admission_and_reply_share_one_budget() {
    let address = "192.0.2.1".parse().unwrap();
    let (rib_tx, mut rib_rx) = mpsc::channel(1);
    rib_tx
        .send(RibUpdate::PeerDown {
            peer: address,
            session_id: 99,
        })
        .await
        .unwrap();
    let mut manager = test_peer_manager();
    manager.rib_tx = rib_tx;
    insert_test_managed_peer(&mut manager, address, stalled_policy_query_handle(), false);
    let started = tokio::time::Instant::now();
    let operation = tokio::spawn(async move {
        let result = manager.refresh_outbound(key(address)).await;
        (manager, result)
    });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(4)).await;
    assert!(!operation.is_finished());
    assert!(matches!(
        rib_rx.recv().await,
        Some(RibUpdate::PeerDown { .. })
    ));
    let Some(RibUpdate::RefreshPeerOutbound { reply, .. }) = rib_rx.recv().await else {
        panic!("refresh should be admitted while one second remains");
    };
    let (manager, result) = operation.await.unwrap();
    assert!(result.unwrap_err().to_string().contains("timed out"));
    assert_eq!(
        started.elapsed(),
        RIB_REPLY_TIMEOUT,
        "admission must consume the reply budget"
    );
    assert!(reply.is_closed());
    drop(manager);
}

#[tokio::test(start_paused = true)]
async fn expired_replay_does_not_enter_newly_available_session_capacity() {
    let address = "192.0.2.1".parse().unwrap();
    let (session_commands, mut session_rx) = mpsc::channel(1);
    session_commands.send(PeerCommand::Start).await.unwrap();
    // The test owns the full command receiver; no real session is launched.
    let session = tokio::spawn(async { Ok(()) });
    let (commands, command_rx) = mpsc::channel(4);
    let (operator, operator_rx) = mpsc::channel(4);
    let (rib_tx, _rib_rx) = mpsc::channel(4);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    )
    .with_operator_queries(operator_rx);
    insert_test_managed_peer(
        &mut manager,
        address,
        PeerHandle::from_parts(session_commands, session),
        false,
    );
    let manager_task = tokio::spawn(manager.run());
    let (reply, response) = oneshot::channel();
    commands
        .send(PeerManagerCommand::ReplayOutbound {
            peer: key(address),
            reply,
        })
        .await
        .unwrap();
    while commands.capacity() != commands.max_capacity() {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(
        RIB_REPLY_TIMEOUT
            .checked_sub(Duration::from_millis(50))
            .unwrap(),
    )
    .await;
    let (reply, read) = oneshot::channel();
    operator
        .send(
            PeerManagerOperatorQuery::GetPeerState {
                peer: key(address),
                reply,
            }
            .into(),
        )
        .await
        .unwrap();
    while operator.capacity() != operator.max_capacity() {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_millis(75)).await;
    assert!(matches!(session_rx.recv().await, Some(PeerCommand::Start)));
    // The bounded session-state query may report unknown state, but its
    // consumed operator reply must survive the replay's earlier expiry.
    assert!(matches!(read.await, Ok(Some(_))));
    let error = response.await.unwrap().unwrap_err();
    assert!(error.to_string().contains("timed out"), "{error}");
    let no_late_replay = matches!(session_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty));
    drop(commands);
    drop(operator);
    tokio::time::timeout(Duration::from_secs(1), manager_task)
        .await
        .unwrap()
        .unwrap();
    assert!(
        no_late_replay,
        "expired replay was admitted after queue capacity returned"
    );
}
