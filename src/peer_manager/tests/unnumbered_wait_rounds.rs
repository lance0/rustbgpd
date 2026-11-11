//! Interface-only session checks make progress independently within one round.

use super::super::session_wait_rounds::{
    ROUND_WINDOW, established_round_session, fill_round_rib, gated_round_shutdown,
    pause_round_clock, poll_round_tasks, receive_round_idle, round_breach, round_ping,
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

/// A session holding messages for a full RIB mailbox answers a conditional
/// retirement at once: it would retire, and refuses until they are admitted.
/// The round therefore spends none of its window on it, keeps the binding and
/// asks again; the refused command never acts later.
#[tokio::test(start_paused = true)]
async fn a_parked_session_refuses_conditional_retirement_at_once_and_is_retried() {
    let clock_origin = tokio::time::Instant::now();
    tokio::time::resume();
    let (mut h, _, commands) = parked_reconcile_fixture().await;
    pause_round_clock(clock_origin).await;
    let started = tokio::time::Instant::now();
    h.reconcile().await;
    assert_eq!(
        started.elapsed(),
        Duration::ZERO,
        "a refusal is an answer: no port waits out the round"
    );
    check_held_bindings_and_withdrawn_commands(&mut h, commands).await;
}

/// What a test learns from a session that admits a conditional retirement
/// and neither claims nor answers it until released.
struct HeldConditional {
    entered: oneshot::Receiver<()>,
    release: oneshot::Sender<()>,
    claimed: oneshot::Receiver<bool>,
}

/// A session that reports Active, then holds the conditional retirement it
/// is sent, as an actor busy in an owned wait would.
fn held_conditional_session() -> (PeerHandle, HeldConditional) {
    let (commands, mut receiver) = mpsc::channel(8);
    let (entered_tx, entered) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let (claimed_tx, claimed) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut hold = Some((entered_tx, released, claimed_tx));
        while let Some(command) = receiver.recv().await {
            match command {
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(policy_test_peer_state(
                        IpAddr::V6(ll(2)),
                        SessionState::Active,
                    ));
                }
                PeerCommand::ShutdownUnlessEstablished { reply, ticket } => {
                    let (entered, released, claimed) = hold.take().expect("one retirement");
                    entered.send(()).unwrap();
                    released.await.unwrap();
                    let acted = ticket.claim();
                    if acted {
                        let _ = reply.send(Ok(true));
                    }
                    claimed.send(acted).unwrap();
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    (
        PeerHandle::from_parts(commands, task),
        HeldConditional {
            entered,
            release,
            claimed,
        },
    )
}

/// `swp1` and `swp2` each hold their conditional retirement; `swp3` is
/// Established and answers. All three have a new binding to act on.
async fn held_reconcile_fixture() -> (
    Harness,
    mpsc::Sender<PeerManagerReadinessQuery>,
    Vec<HeldConditional>,
) {
    let mut h = harness(
        &["swp1", "swp2", "swp3"],
        &[("swp1", 7, true), ("swp2", 8, true), ("swp3", 9, true)],
    );
    let (readiness, receiver) = mpsc::channel(4);
    h.mgr = h.mgr.with_readiness_queries(receiver);
    let mut held = Vec::new();
    for (name, scope) in [("swp1", 7), ("swp2", 8), ("swp3", 9)] {
        h.bind(name, Some(endpoint(2, scope))).await;
        let key = PeerKey::new(IpAddr::V6(ll(2)), Some(name.into()));
        if name == "swp3" {
            h.replace_session(
                &key,
                fake_peer_handle(key.address, SessionState::Established, None, Arc::default()),
            );
        } else {
            let (handle, conditional) = held_conditional_session();
            h.replace_session(&key, handle);
            held.push(conditional);
        }
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
    (h, readiness, held)
}

/// Every binding stands, the held ports are retried, and a retirement the
/// round withdrew does nothing once its session gets to it.
async fn check_held_ports_kept_and_withdrawn(h: &Harness, held: Vec<HeldConditional>) {
    for name in ["swp1", "swp2", "swp3"] {
        assert!(
            h.mgr
                .peers
                .contains_key(&PeerKey::new(IpAddr::V6(ll(2)), Some(name.into()))),
            "the existing binding remains on {name}"
        );
    }
    assert!(h.mgr.unnumbered_retry_at().is_some());
    for hold in held {
        hold.release.send(()).unwrap();
        assert!(
            !hold.claimed.await.unwrap(),
            "the round's timeout withdrew the unclaimed retirement"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn unnumbered_round_serves_readiness_while_conditional_retirements_are_held() {
    let (mut h, readiness, held) = held_reconcile_fixture().await;
    let ping = round_ping(&readiness).await;
    let task = tokio::spawn(async move {
        h.reconcile().await;
        h
    });
    tokio::time::timeout(Duration::from_millis(200), ping)
        .await
        .expect("unnumbered retirement must answer readiness before its unchanged 200 ms deadline")
        .unwrap();
    let h = task.await.unwrap();
    check_held_ports_kept_and_withdrawn(&h, held).await;
}

#[tokio::test(start_paused = true)]
async fn unnumbered_round_reports_a_healthy_port_before_held_ports_settle() {
    let (mut h, _, held) = held_reconcile_fixture().await;
    let (_, receiver) = mpsc::unbounded_channel();
    let mut discovery = std::mem::replace(&mut h.commands, receiver);
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
    assert!(!task.is_finished(), "the held ports still own the round");
    let h = task.await.unwrap();
    check_held_ports_kept_and_withdrawn(&h, held).await;
}

#[tokio::test(start_paused = true)]
async fn unnumbered_round_uses_one_window_for_all_held_ports() {
    let (mut h, _, mut held) = held_reconcile_fixture().await;
    let started = tokio::time::Instant::now();
    let task = tokio::spawn(async move {
        h.reconcile().await;
        h
    });
    poll_round_tasks().await;
    for hold in &mut held {
        hold.entered
            .try_recv()
            .expect("each held session owns its conditional command before any time passes");
    }
    assert_eq!(started.elapsed(), Duration::ZERO);
    tokio::time::advance(ROUND_WINDOW).await;
    poll_round_tasks().await;
    assert!(
        task.is_finished(),
        "all held ports share one 500 ms round window"
    );
    assert_eq!(started.elapsed(), ROUND_WINDOW);
    let h = task.await.unwrap();
    check_held_ports_kept_and_withdrawn(&h, held).await;
}

/// Give `key`'s peer `handle` under a session id no other peer has.
async fn own_session(h: &mut Harness, key: &PeerKey, handle: PeerHandle) -> u64 {
    h.mgr.next_session_id = h.mgr.next_session_id.max(100);
    let id = h.mgr.allocate_session_id();
    let (old, old_id) = h.mgr.peers.replace_handle(key, handle, id).unwrap();
    old.abort_for_transport_safety_and_wait().await;
    h.mgr.unregister_session(old_id);
    h.mgr.register_session(id, key);
    id
}

/// `swp1` loses its link; preparing its retirement drains a queued breach
/// whose primary cannot take its Stop, which costs a whole command window
/// inside the round. That time is the preparation's: `swp1`'s own session is
/// still stopped with a Shutdown, and `swp2`'s state query, asked afterwards,
/// is still sent.
#[tokio::test(start_paused = true)]
async fn a_slow_retirement_preparation_does_not_spend_another_ports_window() {
    let mut h = harness(&["swp1", "swp2"], &[("swp1", 7, true), ("swp2", 8, true)]);
    let mut counters = Vec::new();
    for (name, scope) in [("swp1", 7), ("swp2", 8)] {
        h.bind(name, Some(endpoint(2, scope))).await;
        let key = PeerKey::new(IpAddr::V6(ll(2)), Some(name.into()));
        let counted = Arc::new(FakePeerCounters::default());
        let session = fake_peer_handle(key.address, SessionState::Active, None, counted.clone());
        own_session(&mut h, &key, session).await;
        counters.push(counted);
    }
    let unstoppable: IpAddr = "10.0.0.50".parse().unwrap();
    insert_test_managed_peer(
        &mut h.mgr,
        unstoppable,
        super::super::command_fan_out::wedged_session(),
        false,
    );
    let breached = h.mgr.peers[&key(unstoppable)].session_id();
    h.mgr
        .session_notify_tx
        .send(round_breach(breached, unstoppable))
        .unwrap();
    h.links_changed(snapshot(true, &[("swp1", 7, false), ("swp2", 8, true)]));
    h.mgr
        .handle_discovery_event(DiscoveryEvent::BindingChanged {
            interface: "swp2".into(),
            previous: Some(endpoint(2, 8)),
            current: Some(endpoint(3, 8)),
        });
    let started = tokio::time::Instant::now();
    h.reconcile().await;
    assert!(
        started.elapsed() >= ROUND_WINDOW,
        "the preparation waited out the unstoppable primary"
    );
    assert_ne!(h.mgr.peers[&key(unstoppable)].session_id(), breached);
    assert_eq!(
        counters[0].shutdown.load(Ordering::SeqCst),
        1,
        "swp1's session gets its Shutdown after the slow preparation"
    );
    assert_eq!(
        counters[1].query_state.load(Ordering::SeqCst),
        1,
        "swp2's state query is sent, not timed out unsent"
    );
    assert!(
        h.mgr
            .peers
            .contains_key(&PeerKey::new(IpAddr::V6(ll(3)), Some("swp2".into()))),
        "swp2 went on to its new binding in the same round"
    );
}

/// A state answer belongs to the session that gave it. `swp1`'s session
/// reports Established, but is replaced (an unstoppable primary after a
/// max-prefix breach, handled while `swp2`'s deletion settles) before the
/// round reads the answer: the answer is dropped and the port retried, so
/// discovery is never told the replacement is Established.
#[tokio::test(start_paused = true)]
async fn a_state_answer_from_a_session_replaced_mid_round_is_dropped() {
    let mut h = harness(&["swp1", "swp2"], &[("swp1", 7, true), ("swp2", 8, true)]);
    h.bind("swp1", Some(endpoint(2, 7))).await;
    h.bind("swp2", Some(endpoint(2, 8))).await;
    let swp2 = PeerKey::new(IpAddr::V6(ll(2)), Some("swp2".into()));
    // Reported first: the link checks it dispatches go to the sessions the
    // bindings started, not to the scripted ones installed below.
    h.links_changed(snapshot(true, &[("swp1", 7, true), ("swp2", 8, false)]));
    let (commands, mut receiver) = mpsc::channel(1);
    let (asked_tx, asked) = oneshot::channel();
    let (answer, answered) = oneshot::channel();
    let stale = tokio::spawn(async move {
        let Some(PeerCommand::QueryState { reply }) = receiver.recv().await else {
            panic!("the round asks for the bound session's state")
        };
        asked_tx.send(()).unwrap();
        answered.await.unwrap();
        reply
            .send(policy_test_peer_state(
                IpAddr::V6(ll(2)),
                SessionState::Established,
            ))
            .unwrap();
        // Reads nothing further: the Stop sent to it later finds no room.
        std::future::pending::<Result<(), rustbgpd_transport::TransportError>>().await
    });
    let stale = PeerHandle::from_parts(commands.clone(), stale);
    let stale_id = own_session(&mut h, &swp1_key(2), stale).await;
    let (stopping, stop_entered, release_stop) = gated_round_shutdown(None);
    own_session(&mut h, &swp2, stopping).await;
    h.drain();
    h.mgr
        .handle_discovery_event(DiscoveryEvent::BindingChanged {
            interface: "swp1".into(),
            previous: Some(endpoint(2, 7)),
            current: Some(endpoint(3, 7)),
        });
    let notices = h.mgr.session_notify_tx.clone();
    let round = tokio::spawn(async move {
        h.reconcile().await;
        h
    });
    asked.await.unwrap();
    stop_entered.await.unwrap();
    // swp1's session breaches and cannot take a Stop. swp2's deletion then
    // settles, and its drain handles the breach for a whole command window.
    commands
        .try_send(PeerCommand::Start)
        .expect("fill the session's only command slot");
    notices
        .send(round_breach(stale_id, IpAddr::V6(ll(2))))
        .unwrap();
    release_stop.send(()).unwrap();
    poll_round_tasks().await;
    // The old session answers while the manager is inside that drain.
    tokio::time::advance(Duration::from_millis(100)).await;
    answer.send(()).unwrap();
    let mut h = round.await.unwrap();
    let replacement = &h.mgr.peers[&swp1_key(2)];
    assert_ne!(replacement.session_id(), stale_id);
    assert!(!replacement.enabled);
    assert!(
        !h.drain()
            .contains(&Command::SessionEstablished("swp1".into(), ll(2))),
        "the replaced session's answer must not be reported for its replacement"
    );
    assert!(h.mgr.unnumbered_retry_at().is_some());
    assert!(!h.mgr.peers.contains_key(&swp1_key(3)));
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
            let _ = reply.send(Ok(true));
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
                        let _ = reply.send(Ok(true));
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
            let _ = reply.send(Ok(true));
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
