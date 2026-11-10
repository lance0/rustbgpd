//! Interface-only session checks make progress independently within one round.

use super::super::session_wait_rounds::{
    ROUND_WINDOW, established_round_session, fill_round_rib, pause_round_clock, poll_round_tasks,
    receive_round_idle, round_ping,
};
use super::*;
use rustbgpd_api::peer_types::PeerManagerReadinessQuery;

async fn parked_reconcile_fixture() -> (
    Harness,
    mpsc::Sender<PeerManagerReadinessQuery>,
    Vec<mpsc::Sender<PeerCommand>>,
) {
    let mut h = harness(
        &["swp1", "swp2", "swp3"],
        &[("swp1", 7, true), ("swp2", 8, true), ("swp3", 9, true)],
    );
    let (readiness, receiver) = mpsc::channel(4);
    h.mgr = h.mgr.with_readiness_queries(receiver);
    let mut clients = Vec::new();
    let mut commands = Vec::new();
    for (index, name) in ["swp1", "swp2"].into_iter().enumerate() {
        let scope = u32::try_from(index + 7).unwrap();
        h.bind(name, Some(endpoint(2, scope))).await;
        let key = PeerKey::new(IpAddr::V6(ll(2)), Some(name.into()));
        let config = h.mgr.peers[&key].transport_config.clone();
        let id = h.mgr.allocate_session_id();
        let (handle, client) = established_round_session(
            config,
            id,
            h.mgr.rib_tx.clone(),
            &mut h.rib_rx,
            h.mgr.session_notify_tx.clone(),
        )
        .await;
        commands.push(handle.commands_sender());
        let (old, old_id) = h.mgr.peers.replace_handle(&key, handle, id).unwrap();
        old.shutdown_timeout(Duration::from_secs(1))
            .await
            .unwrap()
            .unwrap();
        h.mgr.unregister_session(old_id);
        h.mgr.register_session(id, &key);
        clients.push((key, id, client));
    }
    h.bind("swp3", Some(endpoint(2, 9))).await;
    let healthy = PeerKey::new(IpAddr::V6(ll(2)), Some("swp3".into()));
    h.replace_session(
        &healthy,
        fake_peer_handle(
            IpAddr::V6(ll(2)),
            SessionState::Established,
            None,
            Arc::new(FakePeerCounters::default()),
        ),
    );
    fill_round_rib(&h.mgr.rib_tx, &mut h.rib_rx);
    for (key, id, client) in clients {
        drop(client);
        receive_round_idle(&mut h.mgr.session_notify_rx, id).await;
        assert_eq!(
            h.mgr.peers[&key]
                .handle()
                .query_state()
                .await
                .unwrap()
                .fsm_state,
            SessionState::Idle,
            "a parked real session still answers reads before conditional retirement"
        );
    }
    h.drain();
    for (name, scope) in [("swp1", 7), ("swp2", 8), ("swp3", 9)] {
        h.mgr
            .handle_discovery_event(DiscoveryEvent::BindingChanged {
                interface: name.into(),
                previous: Some(endpoint(2, scope)),
                current: Some(endpoint(3, scope)),
            });
    }
    (h, readiness, commands)
}

async fn check_held_bindings_and_withdrawn_commands(
    h: &mut Harness,
    commands: Vec<mpsc::Sender<PeerCommand>>,
) {
    for name in ["swp1", "swp2", "swp3"] {
        let key = PeerKey::new(IpAddr::V6(ll(2)), Some(name.into()));
        assert!(
            h.mgr.peers.contains_key(&key),
            "the existing binding remains on {name}"
        );
        assert!(
            !h.mgr
                .peers
                .contains_key(&PeerKey::new(IpAddr::V6(ll(3)), Some(name.into())))
        );
    }
    assert!(
        h.mgr.unnumbered_retry_at().is_some(),
        "refused held targets are retried"
    );
    // Once admission resumes, the conditional commands timed out before claim
    // and must remain no-ops, even though the actual actor is now free to run.
    let mut ends = 0;
    tokio::time::timeout(Duration::from_secs(1), async {
        while ends < 2 {
            if matches!(
                h.rib_rx
                    .recv()
                    .await
                    .expect("RIB lane remains open during cleanup"),
                RibUpdate::PeerDown { .. }
            ) {
                ends += 1;
            }
        }
    })
    .await
    .expect("both real sessions admit their held PeerDown");
    for sender in commands {
        assert!(
            matches!(PeerHandle::query_state_outcome_with(sender, Duration::from_secs(1)).await,
            rustbgpd_transport::StateQueryOutcome::State(state) if state.fsm_state == SessionState::Idle),
            "a withdrawn conditional command cannot retire the real session after the round"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn unnumbered_round_serves_readiness_while_real_conditional_retirement_is_parked() {
    let clock_origin = tokio::time::Instant::now();
    tokio::time::resume();
    let (mut h, readiness, commands) = parked_reconcile_fixture().await;
    pause_round_clock(clock_origin).await;
    let ping = round_ping(&readiness).await;
    let task = tokio::spawn(async move {
        h.reconcile().await;
        h
    });
    tokio::time::timeout(Duration::from_millis(200), ping)
        .await
        .expect("unnumbered retirement must answer readiness before its unchanged 200 ms deadline")
        .unwrap();
    let mut h = task.await.unwrap();
    check_held_bindings_and_withdrawn_commands(&mut h, commands).await;
}

#[tokio::test(start_paused = true)]
async fn unnumbered_round_reports_a_healthy_port_before_held_ports_settle() {
    let clock_origin = tokio::time::Instant::now();
    tokio::time::resume();
    let (mut h, _, commands) = parked_reconcile_fixture().await;
    let (_, receiver) = mpsc::unbounded_channel();
    let mut discovery = std::mem::replace(&mut h.commands, receiver);
    pause_round_clock(clock_origin).await;
    let started = tokio::time::Instant::now();
    let task = tokio::spawn(async move {
        h.reconcile().await;
        h
    });
    poll_round_tasks().await;
    assert_eq!(started.elapsed(), Duration::ZERO);
    let recorded: Vec<_> = std::iter::from_fn(|| discovery.try_recv().ok()).collect();
    assert!(
        recorded.contains(&Command::SessionEstablished("swp3".into(), ll(2))),
        "the healthy port's result reaches discovery before any held retirement expires: {recorded:?}"
    );
    let mut h = task.await.unwrap();
    check_held_bindings_and_withdrawn_commands(&mut h, commands).await;
}

#[tokio::test(start_paused = true)]
async fn unnumbered_round_uses_one_window_for_all_held_ports() {
    let clock_origin = tokio::time::Instant::now();
    tokio::time::resume();
    let (mut h, _, commands) = parked_reconcile_fixture().await;
    pause_round_clock(clock_origin).await;
    let started = tokio::time::Instant::now();
    let task = tokio::spawn(async move {
        h.reconcile().await;
        h
    });
    poll_round_tasks().await;
    let mut entered = Vec::new();
    for sender in &commands {
        let (reply, response) = oneshot::channel();
        sender
            .send(PeerCommand::QueryState { reply })
            .await
            .unwrap();
        entered.push(response);
    }
    poll_round_tasks().await;
    for response in &mut entered {
        assert!(
            matches!(
                response.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ),
            "each held actor must already own a conditional command ahead of its follow-up read"
        );
    }
    tokio::time::advance(ROUND_WINDOW).await;
    poll_round_tasks().await;
    assert!(
        task.is_finished(),
        "all held ports share the original 500 ms round deadline"
    );
    assert_eq!(started.elapsed(), ROUND_WINDOW);
    let mut h = task.await.unwrap();
    check_held_bindings_and_withdrawn_commands(&mut h, commands).await;
}

#[tokio::test(start_paused = true)]
async fn unnumbered_retention_refuses_a_full_mailbox_without_waiting() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    fill_round_rib(&h.mgr.rib_tx, &mut h.rib_rx);
    let started = tokio::time::Instant::now();
    let key = swp1_key(2);
    let query = crate::peer_manager::unnumbered::query_peer_retention_until(
        h.mgr.rib_tx.clone(),
        h.mgr.rib_peer_of(&key),
        started + ROUND_WINDOW,
    );
    tokio::pin!(query);
    let result = std::future::poll_fn(|cx| std::task::Poll::Ready(query.as_mut().poll(cx))).await;
    assert!(
        matches!(result, std::task::Poll::Ready(None)),
        "a full RIB lane refuses the retention query before any fenced wait"
    );
    assert_eq!(started.elapsed(), Duration::ZERO);
}

/// Delay the state response, then hold an admitted conditional command until
/// after the round. The ticket remains unclaimed until release, as on the real
/// actor's parked-command path.
#[tokio::test(start_paused = true)]
async fn unnumbered_round_does_not_renew_the_budget_after_the_state_reply() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    let (tx, mut rx) = mpsc::channel(8);
    let (state_seen, seen) = oneshot::channel();
    let (release_state, state_permission) = oneshot::channel();
    let (retirement_seen, retirement_admitted) = oneshot::channel();
    let (release_retirement, retirement_permission) = oneshot::channel();
    let (retirement_finished, finished) = oneshot::channel();
    let task = tokio::spawn(async move {
        let PeerCommand::QueryState { reply } = rx.recv().await.unwrap() else {
            panic!("state first")
        };
        state_seen.send(()).unwrap();
        state_permission.await.unwrap();
        reply
            .send(policy_test_peer_state(
                IpAddr::V6(ll(2)),
                SessionState::Active,
            ))
            .unwrap();
        let PeerCommand::ShutdownUnlessEstablished { reply, ticket } = rx.recv().await.unwrap()
        else {
            panic!("conditional second")
        };
        retirement_seen.send(()).unwrap();
        retirement_permission.await.unwrap();
        let acted = ticket.claim();
        if acted {
            let _ = reply.send(true);
        }
        retirement_finished.send(acted).unwrap();
        while let Some(command) = rx.recv().await {
            match command {
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(policy_test_peer_state(
                        IpAddr::V6(ll(2)),
                        SessionState::Active,
                    ));
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    h.replace_session(&swp1_key(2), PeerHandle::from_parts(tx, task));
    h.mgr
        .handle_discovery_event(DiscoveryEvent::BindingChanged {
            interface: "swp1".into(),
            previous: Some(endpoint(2, 7)),
            current: Some(endpoint(3, 7)),
        });
    let started = tokio::time::Instant::now();
    let round = tokio::spawn(async move {
        h.reconcile().await;
        h
    });
    seen.await.unwrap();
    tokio::time::advance(Duration::from_millis(300)).await;
    release_state.send(()).unwrap();
    retirement_admitted.await.unwrap();
    tokio::time::advance(Duration::from_millis(200)).await;
    poll_round_tasks().await;
    assert!(
        round.is_finished(),
        "the conditional phase gets the remaining 200 ms, not another 500 ms"
    );
    assert_eq!(started.elapsed(), ROUND_WINDOW);
    let h = round.await.unwrap();
    release_retirement.send(()).unwrap();
    assert!(
        !finished.await.unwrap(),
        "round timeout withdraws the still-unclaimed command"
    );
    assert!(h.mgr.peers.contains_key(&swp1_key(2)));
}

/// A timed-out retirement never acts later. The old settlement fixture ignored
/// `CommandTicket` and therefore modeled an outcome the real actor forbids.
#[tokio::test(start_paused = true)]
async fn unnumbered_withdrawn_retirement_does_not_end_a_returning_binding() {
    let mut h = harness(&["swp1"], &[("swp1", 7, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    let (tx, mut rx) = mpsc::channel(8);
    let (release, released) = oneshot::channel();
    let (checked, result) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut release = Some(released);
        let mut checked = Some(checked);
        while let Some(command) = rx.recv().await {
            match command {
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(policy_test_peer_state(
                        IpAddr::V6(ll(2)),
                        SessionState::Active,
                    ));
                }
                PeerCommand::ShutdownUnlessEstablished { reply, ticket } => {
                    release.take().unwrap().await.unwrap();
                    let claimed = ticket.claim();
                    checked.take().unwrap().send(claimed).unwrap();
                    if claimed {
                        let _ = reply.send(true);
                        break;
                    }
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    h.replace_session(&swp1_key(2), PeerHandle::from_parts(tx, task));
    let session_id = h.mgr.peers[&swp1_key(2)].session_id();
    h.bind("swp1", Some(endpoint(3, 7))).await;
    release.send(()).unwrap();
    assert!(
        !result.await.unwrap(),
        "timeout withdrew the admitted but unclaimed retirement"
    );
    h.bind("swp1", Some(endpoint(2, 7))).await;
    assert_eq!(h.mgr.peers[&swp1_key(2)].session_id(), session_id);
    assert!(
        matches!(h.mgr.peers[&swp1_key(2)].handle().query_state_outcome(Duration::from_secs(1)).await,
        rustbgpd_transport::StateQueryOutcome::State(state) if state.fsm_state == SessionState::Active)
    );
}

#[tokio::test(start_paused = true)]
#[expect(
    clippy::too_many_lines,
    reason = "the handshakes jointly prove admitted RIB delay, healthy bookkeeping, and conditional-ticket withdrawal"
)]
async fn admitted_retention_reply_does_not_hold_healthy_or_conditional_ports() {
    let mut h = harness(
        &["swp1", "swp2", "swp3"],
        &[("swp1", 7, true), ("swp2", 8, true), ("swp3", 9, true)],
    );
    let (readiness, receiver) = mpsc::channel(4);
    h.mgr = h.mgr.with_readiness_queries(receiver);
    for (name, scope) in [("swp1", 7), ("swp2", 8), ("swp3", 9)] {
        h.bind(name, Some(endpoint(2, scope))).await;
        let key = PeerKey::new(IpAddr::V6(ll(2)), Some(name.into()));
        h.replace_session(
            &key,
            fake_peer_handle(
                key.address,
                if name == "swp3" {
                    SessionState::Established
                } else {
                    SessionState::Active
                },
                None,
                Arc::default(),
            ),
        );
    }
    let (commands, mut receiver) = mpsc::channel(8);
    let (entered, mut conditional_entered) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let (acted, action) = oneshot::channel();
    let actor = tokio::spawn(async move {
        let PeerCommand::QueryState { reply } = receiver.recv().await.unwrap() else {
            panic!("state first")
        };
        reply
            .send(policy_test_peer_state(
                IpAddr::V6(ll(2)),
                SessionState::Active,
            ))
            .unwrap();
        let PeerCommand::ShutdownUnlessEstablished { reply, ticket } =
            receiver.recv().await.unwrap()
        else {
            panic!("conditional next")
        };
        entered.send(()).unwrap();
        released.await.unwrap();
        let claimed = ticket.claim();
        if claimed {
            let _ = reply.send(true);
        }
        acted.send(claimed).unwrap();
        while let Some(command) = receiver.recv().await {
            if let PeerCommand::Shutdown = command {
                break;
            }
        }
        Ok(())
    });
    let held_key = PeerKey::new(IpAddr::V6(ll(2)), Some("swp2".into()));
    h.replace_session(&held_key, PeerHandle::from_parts(commands, actor));
    let (_, placeholder) = mpsc::channel(1);
    let mut rib = std::mem::replace(&mut h.rib_rx, placeholder);
    let (admitted, mut retention_admitted) = oneshot::channel();
    let rib_actor = tokio::spawn(async move {
        while let Some(update) = rib.recv().await {
            if let RibUpdate::QueryPeerRetention { reply, .. } = update {
                admitted.send(reply).unwrap();
                break;
            }
        }
        rib
    });
    h.drain();
    for (name, desired) in [
        ("swp1", None),
        ("swp2", Some(endpoint(3, 8))),
        ("swp3", Some(endpoint(3, 9))),
    ] {
        h.mgr
            .handle_discovery_event(DiscoveryEvent::BindingChanged {
                interface: name.into(),
                previous: None,
                current: desired,
            });
    }
    let (_, placeholder) = mpsc::unbounded_channel();
    let mut discovery = std::mem::replace(&mut h.commands, placeholder);
    let started = tokio::time::Instant::now();
    let round = tokio::spawn(async move {
        h.reconcile().await;
        h
    });
    poll_round_tasks().await;
    let retention_reply = retention_admitted
        .try_recv()
        .expect("retention query is admitted before measuring its held reply");
    conditional_entered
        .try_recv()
        .expect("another port already entered its independent conditional command");
    assert!(
        std::iter::from_fn(|| discovery.try_recv().ok())
            .any(|command| command == Command::SessionEstablished("swp3".into(), ll(2)))
    );
    let mut ping = round_ping(&readiness).await;
    poll_round_tasks().await;
    ping.try_recv()
        .expect("readiness is served while the admitted retention reply is held");
    assert_eq!(started.elapsed(), Duration::ZERO);
    tokio::time::advance(ROUND_WINDOW).await;
    poll_round_tasks().await;
    assert!(
        round.is_finished(),
        "admitted retention and conditional phases share the round deadline"
    );
    assert_eq!(started.elapsed(), ROUND_WINDOW);
    let h = round.await.unwrap();
    for name in ["swp1", "swp2", "swp3"] {
        assert!(
            h.mgr
                .peers
                .contains_key(&PeerKey::new(IpAddr::V6(ll(2)), Some(name.into())))
        );
    }
    release.send(()).unwrap();
    assert!(
        !action.await.unwrap(),
        "timeout withdrew the owned conditional request"
    );
    assert!(
        retention_reply
            .send(PeerRetention {
                stale_routes: 0,
                next_deadline: None
            })
            .is_err()
    );
    drop(rib_actor.await.unwrap());
}

#[tokio::test(start_paused = true)]
async fn lost_links_retire_real_held_sessions_in_one_round_without_holding_a_healthy_port() {
    let clock_origin = tokio::time::Instant::now();
    tokio::time::resume();
    let (mut h, _, commands) = parked_reconcile_fixture().await;
    h.links_changed(snapshot(
        true,
        &[("swp1", 7, false), ("swp2", 8, false), ("swp3", 9, true)],
    ));
    let (_, placeholder) = mpsc::unbounded_channel();
    let mut discovery = std::mem::replace(&mut h.commands, placeholder);
    pause_round_clock(clock_origin).await;
    let started = tokio::time::Instant::now();
    let round = tokio::spawn(async move {
        h.reconcile().await;
        h
    });
    poll_round_tasks().await;
    assert!(
        std::iter::from_fn(|| discovery.try_recv().ok())
            .any(|command| command == Command::SessionEstablished("swp3".into(), ll(2)))
    );
    assert!(commands.iter().all(|commands| !commands.is_closed()));
    assert_eq!(started.elapsed(), Duration::ZERO);
    tokio::time::advance(ROUND_WINDOW).await;
    poll_round_tasks().await;
    assert!(
        round.is_finished(),
        "both lost-link producers settle in the original window"
    );
    assert_eq!(started.elapsed(), ROUND_WINDOW);
    let h = round.await.unwrap();
    assert!(
        commands.iter().all(mpsc::Sender::is_closed),
        "joined before the held RIB ends are admitted"
    );
    for name in ["swp1", "swp2"] {
        assert!(
            !h.mgr
                .peers
                .contains_key(&PeerKey::new(IpAddr::V6(ll(2)), Some(name.into())))
        );
    }
    assert!(
        h.mgr
            .peers
            .contains_key(&PeerKey::new(IpAddr::V6(ll(2)), Some("swp3".into())))
    );
    assert!(h.mgr.retiring_sessions.is_empty());
}
