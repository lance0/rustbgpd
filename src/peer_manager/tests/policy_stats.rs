use super::*;

fn chainless_policy_query_handle() -> PeerHandle {
    let (commands, mut command_rx) = mpsc::channel(4);
    let task = tokio::spawn(async move {
        while let Some(command) = command_rx.recv().await {
            match command {
                rustbgpd_transport::PeerCommand::QueryImportPolicyTermHits { reply } => {
                    let _ = reply.send(None);
                }
                rustbgpd_transport::PeerCommand::Shutdown => break,
                other => panic!("unexpected peer command: {other:?}"),
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(commands, task)
}

fn gone_policy_query_handle() -> PeerHandle {
    let (commands, command_rx) = mpsc::channel(1);
    drop(command_rx);
    PeerHandle::from_parts(commands, tokio::spawn(async { Ok(()) }))
}

type ControlledPolicyAdmission = (
    IpAddr,
    oneshot::Sender<Option<rustbgpd_transport::ImportPolicyTermHits>>,
);

fn controlled_policy_query_handle(
    address: IpAddr,
    admitted: mpsc::UnboundedSender<ControlledPolicyAdmission>,
) -> PeerHandle {
    let (commands, mut command_rx) = mpsc::channel(4);
    let task = tokio::spawn(async move {
        while let Some(command) = command_rx.recv().await {
            match command {
                rustbgpd_transport::PeerCommand::QueryImportPolicyTermHits { reply } => {
                    let _ = admitted.send((address, reply));
                }
                rustbgpd_transport::PeerCommand::Shutdown => break,
                other => panic!("unexpected peer command: {other:?}"),
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(commands, task)
}

fn disappearing_policy_query_handle(
    admitted: oneshot::Sender<()>,
    disappear: oneshot::Receiver<()>,
) -> PeerHandle {
    let (commands, mut command_rx) = mpsc::channel(4);
    let task = tokio::spawn(async move {
        let Some(command) = command_rx.recv().await else {
            return Ok(());
        };
        match command {
            rustbgpd_transport::PeerCommand::QueryImportPolicyTermHits { reply } => {
                let _ = admitted.send(());
                let _ = disappear.await;
                drop(reply);
                Ok(())
            }
            rustbgpd_transport::PeerCommand::Shutdown => Ok(()),
            other => panic!("unexpected peer command: {other:?}"),
        }
    });
    PeerHandle::from_parts(commands, task)
}

fn controlled_policy_snapshot(address: IpAddr) -> rustbgpd_transport::ImportPolicyTermHits {
    let generation = match address {
        IpAddr::V4(address) => u64::from(address.octets()[3]),
        IpAddr::V6(_) => 0,
    };
    rustbgpd_transport::ImportPolicyTermHits {
        generation,
        evals: generation,
        eval_errors: 0,
        last_error: None,
        terms: Vec::new(),
    }
}

async fn receive_controlled_policy_admissions(
    admitted: &mut mpsc::UnboundedReceiver<ControlledPolicyAdmission>,
    count: usize,
) -> Vec<ControlledPolicyAdmission> {
    tokio::time::timeout(Duration::from_millis(1), async {
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(admitted.recv().await.expect("controlled session task"));
        }
        out
    })
    .await
    .expect("expected policy queries were not admitted")
}

/// LAN-661 red proof: validating against static config rejects the accepted
/// dynamic peer; replacing the typed forwarding result with the old `Option`
/// path makes its stalled task return `SessionGone`; silently omitting a
/// timed-out term-hit query makes the second timeout assertion return
/// `Reply([])`. Each production break fails its corresponding assertion.
#[tokio::test(start_paused = true)]
async fn policy_query_timeout_does_not_masquerade_as_missing_session() {
    let (tx, rx) = mpsc::channel(4);
    let (rib_tx, _rib_rx) = mpsc::channel(4);
    let mut manager = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let configured = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    insert_test_managed_peer(
        &mut manager,
        configured,
        stalled_policy_query_handle(),
        false,
    );
    manager.peers.get_mut(&key(configured)).unwrap().is_dynamic = true;
    let manager_task = tokio::spawn(manager.run());

    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::HasPeerAddress {
        address: configured,
        reply,
    })
    .await
    .unwrap();
    assert!(
        response.await.unwrap(),
        "runtime validation must include an accepted dynamic peer"
    );

    let prefix = rustbgpd_wire::Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
        Ipv4Addr::new(198, 51, 100, 0),
        24,
    ));
    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::ExplainImportPolicy {
        address: configured,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        prefix,
        path_id: None,
        reply,
    })
    .await
    .unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(EXPLAIN_QUERY_TIMEOUT).await;
    assert!(matches!(
        response.await.unwrap(),
        SessionQueryOutcome::TimedOut
    ));

    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::QueryImportPolicyTermHits {
        peer: Some(configured),
        deadline: tokio::time::Instant::now() + EXPLAIN_QUERY_TIMEOUT,
        reply,
    })
    .await
    .unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(EXPLAIN_QUERY_TIMEOUT).await;
    assert!(
        matches!(response.await.unwrap(), SessionQueryOutcome::TimedOut),
        "a stalled term-hit query must fail the snapshot instead of being omitted"
    );

    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::ExplainImportPolicy {
        address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)),
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        prefix,
        path_id: None,
        reply,
    })
    .await
    .unwrap();
    assert!(matches!(
        response.await.unwrap(),
        SessionQueryOutcome::SessionGone
    ));

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    manager_task.await.unwrap();
}

/// LAN-661 red proof: changing the production `Reply(None)` arm to
/// `SessionGone` (or treating it as a row) makes this healthy, answered
/// chainless query fail instead of returning a successful empty snapshot.
#[tokio::test]
async fn import_policy_stats_omit_an_answered_chainless_peer() {
    let (tx, rx) = mpsc::channel(4);
    let (rib_tx, _rib_rx) = mpsc::channel(4);
    let mut manager = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    insert_test_managed_peer(&mut manager, peer, chainless_policy_query_handle(), false);
    let manager_task = tokio::spawn(manager.run());

    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::QueryImportPolicyTermHits {
        peer: Some(peer),
        deadline: tokio::time::Instant::now() + EXPLAIN_QUERY_TIMEOUT,
        reply,
    })
    .await
    .unwrap();
    let outcome = response.await.unwrap();
    assert!(
        matches!(&outcome, SessionQueryOutcome::Reply(rows) if rows.is_empty()),
        "a healthy session without an import chain must answer with no row, got {outcome:?}"
    );

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    manager_task.await.unwrap();
}

/// LAN-661: more stalled sessions than the collector's concurrency cap still
/// consume one aggregate deadline. The actor must remain available while the
/// detached collector waits, so an unrelated address query answers promptly.
#[tokio::test(start_paused = true)]
async fn import_policy_stats_over_concurrency_cap_use_one_deadline_without_blocking_actor() {
    let (tx, rx) = mpsc::channel(4);
    let (rib_tx, _rib_rx) = mpsc::channel(4);
    let mut manager = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let peer_count = IMPORT_POLICY_QUERY_CONCURRENCY + 1;
    for host in 1..=peer_count {
        let address = IpAddr::V4(Ipv4Addr::new(198, 51, 100, u8::try_from(host).unwrap()));
        insert_test_managed_peer(&mut manager, address, stalled_policy_query_handle(), false);
    }
    let manager_task = tokio::spawn(manager.run());
    let started = tokio::time::Instant::now();
    let deadline = started + EXPLAIN_QUERY_TIMEOUT;

    let (reply, mut response) = oneshot::channel();
    tx.send(PeerManagerCommand::QueryImportPolicyTermHits {
        peer: None,
        deadline,
        reply,
    })
    .await
    .unwrap();
    tokio::task::yield_now().await;

    let (reply, has_peer) = oneshot::channel();
    tx.send(PeerManagerCommand::HasPeerAddress {
        address: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        reply,
    })
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(1), has_peer)
            .await
            .expect("peer manager actor must not wait for fleet collection")
            .unwrap()
    );
    assert!(
        matches!(
            response.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ),
        "stalled sessions must not fabricate an early partial snapshot"
    );

    tokio::time::advance(deadline - tokio::time::Instant::now()).await;
    assert!(matches!(
        response.await.unwrap(),
        SessionQueryOutcome::TimedOut
    ));
    assert_eq!(
        tokio::time::Instant::now() - started,
        EXPLAIN_QUERY_TIMEOUT,
        "N > concurrency cap must still finish at the one fleet deadline"
    );

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    manager_task.await.unwrap();
}

/// LAN-661: bounded unordered collection admits exactly 64 queries, lets
/// later-ready members of that wave open slots for the remainder, and
/// completes every row under the original absolute deadline.
#[tokio::test(start_paused = true)]
async fn import_policy_stats_concurrency_gate_is_64_and_makes_unordered_two_wave_progress() {
    const EXPECTED_CONCURRENCY: usize = 64;

    assert_eq!(
        IMPORT_POLICY_QUERY_CONCURRENCY, EXPECTED_CONCURRENCY,
        "the fleet collector's documented concurrency cap must remain 64"
    );
    let (tx, rx) = mpsc::channel(4);
    let (rib_tx, _rib_rx) = mpsc::channel(4);
    let mut manager = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let (admitted_tx, mut admitted_rx) = mpsc::unbounded_channel();
    let peer_count = EXPECTED_CONCURRENCY + 8;
    let mut expected_addresses = Vec::with_capacity(peer_count);
    for host in 1..=peer_count {
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, u8::try_from(host).unwrap()));
        expected_addresses.push(address);
        insert_test_managed_peer(
            &mut manager,
            address,
            controlled_policy_query_handle(address, admitted_tx.clone()),
            false,
        );
    }
    // Production snapshots this same HashMap iteration order. Holding its
    // first target makes the unordered proof deterministic: ordered buffering
    // cannot yield any later completion to open a second-wave slot.
    let first_target = manager
        .peers
        .keys()
        .next()
        .expect("controlled fleet is non-empty")
        .address;
    let manager_task = tokio::spawn(manager.run());

    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::QueryImportPolicyTermHits {
        peer: None,
        deadline: tokio::time::Instant::now() + EXPLAIN_QUERY_TIMEOUT,
        reply,
    })
    .await
    .unwrap();

    let mut first_wave =
        receive_controlled_policy_admissions(&mut admitted_rx, EXPECTED_CONCURRENCY).await;
    assert!(
        matches!(
            admitted_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ),
        "the collector must admit exactly 64 initial queries, not a 65th"
    );

    let first_target_index = first_wave
        .iter()
        .position(|(address, _)| *address == first_target)
        .expect("the source-order first target must be in the initial wave");
    let held_first_target = first_wave.swap_remove(first_target_index);
    // Keep the source-order first future pending while eight later futures
    // complete. Only unordered buffering can use them to open eight slots.
    for (address, reply) in first_wave.drain(..8) {
        reply
            .send(Some(controlled_policy_snapshot(address)))
            .unwrap();
    }
    // Give the single-threaded test runtime ample scheduling turns, then use
    // nonblocking receives. An ordered buffer must fail here promptly rather
    // than hanging the regression proof behind the fleet deadline.
    for _ in 0..(EXPECTED_CONCURRENCY * 4) {
        tokio::task::yield_now().await;
    }
    let second_wave: Vec<_> = (0..8)
        .map(|_| {
            admitted_rx
                .try_recv()
                .expect("later-ready replies must open second-wave slots without source ordering")
        })
        .collect();
    assert!(
        matches!(
            admitted_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ),
        "only the eight newly available slots may admit the remainder"
    );

    for (address, reply) in std::iter::once(held_first_target)
        .chain(first_wave)
        .chain(second_wave)
    {
        reply
            .send(Some(controlled_policy_snapshot(address)))
            .unwrap();
    }
    let SessionQueryOutcome::Reply(rows) = response.await.unwrap() else {
        panic!("all controlled sessions answered before the deadline");
    };
    let actual_addresses: Vec<_> = rows.into_iter().map(|(address, _)| address).collect();
    expected_addresses.sort_unstable();
    assert_eq!(
        actual_addresses, expected_addresses,
        "the complete fleet snapshot must be sorted by peer address"
    );

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    manager_task.await.unwrap();
}

/// LAN-661: dropping the RPC reply before dispatch prevents session queries;
/// dropping it with 64 in-flight queries cancels all of their reply futures
/// promptly instead of retaining the fleet until the deadline.
#[tokio::test(start_paused = true)]
async fn import_policy_stats_caller_drop_cancels_snapshot_and_in_flight_queries() {
    let (tx, rx) = mpsc::channel(4);
    let (rib_tx, _rib_rx) = mpsc::channel(4);
    let mut manager = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let (admitted_tx, mut admitted_rx) = mpsc::unbounded_channel();
    for host in 1..=(IMPORT_POLICY_QUERY_CONCURRENCY + 1) {
        let address = IpAddr::V4(Ipv4Addr::new(198, 18, 0, u8::try_from(host).unwrap()));
        insert_test_managed_peer(
            &mut manager,
            address,
            controlled_policy_query_handle(address, admitted_tx.clone()),
            false,
        );
    }

    // Queue a request whose receiver is already gone before the actor starts.
    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::QueryImportPolicyTermHits {
        peer: None,
        deadline: tokio::time::Instant::now() + EXPLAIN_QUERY_TIMEOUT,
        reply,
    })
    .await
    .unwrap();
    drop(response);
    let manager_task = tokio::spawn(manager.run());
    let (reply, barrier) = oneshot::channel();
    tx.send(PeerManagerCommand::HasPeerAddress {
        address: IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)),
        reply,
    })
    .await
    .unwrap();
    assert!(barrier.await.unwrap());
    assert!(
        matches!(
            admitted_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ),
        "a pre-cancelled request must not query the fleet"
    );

    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::QueryImportPolicyTermHits {
        peer: None,
        deadline: tokio::time::Instant::now() + EXPLAIN_QUERY_TIMEOUT,
        reply,
    })
    .await
    .unwrap();
    let mut admissions =
        receive_controlled_policy_admissions(&mut admitted_rx, IMPORT_POLICY_QUERY_CONCURRENCY)
            .await;
    drop(response);
    tokio::time::timeout(Duration::from_millis(1), async {
        for (_, reply) in &mut admissions {
            reply.closed().await;
        }
    })
    .await
    .expect("caller cancellation must drop every in-flight reply receiver");
    assert!(
        matches!(
            admitted_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ),
        "caller cancellation must not admit the remaining target"
    );

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    manager_task.await.unwrap();
}

/// LAN-661: one successful fleet row followed by a stalled session fails the
/// complete snapshot at the shared deadline; the successful row is not
/// returned as a partial response.
#[tokio::test(start_paused = true)]
async fn import_policy_stats_mixed_success_and_timeout_is_atomic() {
    let (tx, rx) = mpsc::channel(4);
    let (rib_tx, _rib_rx) = mpsc::channel(4);
    let mut manager = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let (admitted_tx, mut admitted_rx) = mpsc::unbounded_channel();
    for host in 1..=2 {
        let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, host));
        insert_test_managed_peer(
            &mut manager,
            address,
            controlled_policy_query_handle(address, admitted_tx.clone()),
            false,
        );
    }
    let manager_task = tokio::spawn(manager.run());
    let deadline = tokio::time::Instant::now() + EXPLAIN_QUERY_TIMEOUT;

    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::QueryImportPolicyTermHits {
        peer: None,
        deadline,
        reply,
    })
    .await
    .unwrap();
    let mut admissions = receive_controlled_policy_admissions(&mut admitted_rx, 2).await;
    let (address, success) = admissions.pop().unwrap();
    success
        .send(Some(controlled_policy_snapshot(address)))
        .unwrap();
    let mut stalled = admissions.pop().unwrap().1;

    tokio::time::advance(deadline - tokio::time::Instant::now()).await;
    assert!(matches!(
        response.await.unwrap(),
        SessionQueryOutcome::TimedOut
    ));
    stalled.closed().await;

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    manager_task.await.unwrap();
}

/// LAN-661: an all-peers query remains atomic when one session disappears
/// after its command was admitted. A completed sibling row cannot turn that
/// `SessionGone` into partial success.
#[tokio::test(start_paused = true)]
async fn import_policy_stats_all_peers_session_gone_after_admission_is_atomic() {
    let (tx, rx) = mpsc::channel(4);
    let (rib_tx, _rib_rx) = mpsc::channel(4);
    let mut manager = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let (admitted_tx, mut admitted_rx) = mpsc::unbounded_channel();
    let successful_peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    insert_test_managed_peer(
        &mut manager,
        successful_peer,
        controlled_policy_query_handle(successful_peer, admitted_tx),
        false,
    );
    let disappearing_peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
    let (gone_admitted, gone_admission) = oneshot::channel();
    let (disappear, disappear_signal) = oneshot::channel();
    insert_test_managed_peer(
        &mut manager,
        disappearing_peer,
        disappearing_policy_query_handle(gone_admitted, disappear_signal),
        false,
    );
    let manager_task = tokio::spawn(manager.run());

    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::QueryImportPolicyTermHits {
        peer: None,
        deadline: tokio::time::Instant::now() + EXPLAIN_QUERY_TIMEOUT,
        reply,
    })
    .await
    .unwrap();
    let mut admissions = receive_controlled_policy_admissions(&mut admitted_rx, 1).await;
    gone_admission.await.unwrap();
    let (address, success) = admissions.pop().unwrap();
    success
        .send(Some(controlled_policy_snapshot(address)))
        .unwrap();
    disappear.send(()).unwrap();

    assert!(matches!(
        response.await.unwrap(),
        SessionQueryOutcome::SessionGone
    ));

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    manager_task.await.unwrap();
}

/// LAN-661: a selected managed peer whose command channel is closed is
/// truthfully distinct from both an empty chain and aggregate timeout.
#[tokio::test(start_paused = true)]
async fn import_policy_stats_selected_session_gone_is_truthful() {
    let (tx, rx) = mpsc::channel(4);
    let (rib_tx, _rib_rx) = mpsc::channel(4);
    let mut manager = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    insert_test_managed_peer(&mut manager, peer, gone_policy_query_handle(), false);
    let manager_task = tokio::spawn(manager.run());

    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::QueryImportPolicyTermHits {
        peer: Some(peer),
        deadline: tokio::time::Instant::now() + EXPLAIN_QUERY_TIMEOUT,
        reply,
    })
    .await
    .unwrap();
    assert!(matches!(
        response.await.unwrap(),
        SessionQueryOutcome::SessionGone
    ));

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    manager_task.await.unwrap();
}

/// LAN-661: the actor must reject an expired fleet deadline before resolving
/// a selected peer or observing its already-closed session channel.
#[tokio::test(start_paused = true)]
async fn import_policy_stats_expired_deadline_precedes_resolution_and_selected_session_gone() {
    let (tx, rx) = mpsc::channel(4);
    let (rib_tx, _rib_rx) = mpsc::channel(4);
    let mut manager = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    insert_test_managed_peer(&mut manager, peer, gone_policy_query_handle(), false);
    let manager_task = tokio::spawn(manager.run());

    let (reply, missing_response) = oneshot::channel();
    tx.send(PeerManagerCommand::QueryImportPolicyTermHits {
        peer: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99))),
        deadline: tokio::time::Instant::now(),
        reply,
    })
    .await
    .unwrap();
    assert!(
        matches!(
            missing_response.await.unwrap(),
            SessionQueryOutcome::TimedOut
        ),
        "deadline rejection must happen before selected-peer resolution"
    );

    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::QueryImportPolicyTermHits {
        peer: Some(peer),
        deadline: tokio::time::Instant::now(),
        reply,
    })
    .await
    .unwrap();
    assert!(matches!(
        response.await.unwrap(),
        SessionQueryOutcome::TimedOut
    ));

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    manager_task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn prestage_import_snapshot_finishes_before_ready_ack_and_services_readiness() {
    use rustbgpd_api::peer_types::{PeerManagerOperatorQuery, PeerManagerReadinessQuery};

    // Completion, caller cancellation, and the unchanged aggregate deadline
    // must all release the read without allowing its counters to cross apply.
    for finish in ["reply", "cancel", "timeout"] {
        let (_command_tx, command_rx) = mpsc::channel(4);
        let (rib_tx, _rib_rx) = mpsc::channel(4);
        let (operator_tx, operator_rx) = mpsc::channel(4);
        let (readiness_tx, readiness_rx) = mpsc::channel(4);
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
        let address = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1));
        let (admitted_tx, mut admitted_rx) = mpsc::unbounded_channel();
        insert_test_managed_peer(
            &mut manager,
            address,
            controlled_policy_query_handle(address, admitted_tx),
            false,
        );
        let (ack, ack_rx) = oneshot::channel();
        let (finished, mut finished_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let outcome = manager
                .await_with_readiness_and_operator_budget(ack_rx, Duration::from_secs(10), true)
                .await;
            let _ = finished.send(outcome);
            manager
        });
        let (reply, response) = oneshot::channel();
        operator_tx
            .send(
                PeerManagerOperatorQuery::QueryImportPolicyTermHits {
                    peer: Some(address),
                    deadline: tokio::time::Instant::now() + Duration::from_secs(2),
                    reply,
                }
                .into(),
            )
            .await
            .unwrap();
        let (_, session_reply) = admitted_rx.recv().await.unwrap();
        ack.send(()).unwrap();
        let (reply, ping) = oneshot::channel();
        readiness_tx
            .send(PeerManagerReadinessQuery::Ping { reply })
            .await
            .unwrap();
        ping.await.unwrap();
        assert!(
            matches!(
                finished_rx.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ),
            "a ready prestage ACK must wait for the admitted import snapshot"
        );
        match finish {
            "reply" => {
                session_reply
                    .send(Some(controlled_policy_snapshot(address)))
                    .unwrap();
                assert!(
                    matches!(response.await.unwrap(), SessionQueryOutcome::Reply(rows)
                    if rows.len() == 1 && rows[0].1.generation == 1)
                );
            }
            "cancel" => {
                drop(response);
                tokio::task::yield_now().await;
            }
            "timeout" => {
                tokio::time::advance(Duration::from_secs(2)).await;
                assert!(matches!(
                    response.await.unwrap(),
                    SessionQueryOutcome::TimedOut
                ));
            }
            _ => unreachable!(),
        }
        assert!(matches!(finished_rx.await.unwrap(), Some(Ok(()))));
        let mut manager = task.await.unwrap();
        for (_, managed) in manager.peers.drain() {
            managed.handle.shutdown().await.unwrap().unwrap();
        }
    }
}

#[tokio::test(start_paused = true)]
async fn normal_operator_import_snapshot_does_not_block_other_operator_reads() {
    use rustbgpd_api::peer_types::PeerManagerOperatorQuery;

    let (_command_tx, command_rx) = mpsc::channel(4);
    let (rib_tx, _rib_rx) = mpsc::channel(4);
    let (operator_tx, operator_rx) = mpsc::channel(4);
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
    let address = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1));
    let (admitted_tx, mut admitted_rx) = mpsc::unbounded_channel();
    insert_test_managed_peer(
        &mut manager,
        address,
        controlled_policy_query_handle(address, admitted_tx),
        false,
    );
    let task = tokio::spawn(manager.run());
    let (reply, response) = oneshot::channel();
    operator_tx
        .send(
            PeerManagerOperatorQuery::QueryImportPolicyTermHits {
                peer: Some(address),
                deadline: tokio::time::Instant::now() + Duration::from_secs(2),
                reply,
            }
            .into(),
        )
        .await
        .unwrap();
    let (_, session_reply) = admitted_rx.recv().await.unwrap();
    let (reply, existence) = oneshot::channel();
    operator_tx
        .send(PeerManagerOperatorQuery::HasPeerAddress { address, reply }.into())
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(1), existence)
            .await
            .unwrap()
            .unwrap()
    );
    session_reply.send(None).unwrap();
    assert!(matches!(response.await.unwrap(), SessionQueryOutcome::Reply(rows) if rows.is_empty()));
    task.abort();
    let _ = task.await;
}

/// A neighbor snapshot must not consume the remaining stats budget while its
/// session is free to answer counters. Ordinary mutations still wait until
/// the snapshot completes or its caller cancels it.
fn held_neighbor_query_handle(
    address: IpAddr,
    state_admitted: mpsc::UnboundedSender<oneshot::Sender<PeerSessionState>>,
    imports: Arc<AtomicUsize>,
) -> PeerHandle {
    let (commands, mut commands_rx) = mpsc::channel(4);
    let session = tokio::spawn(async move {
        while let Some(command) = commands_rx.recv().await {
            match command {
                PeerCommand::QueryState { reply } => {
                    // Hold only this reply; the session keeps receiving and
                    // can answer import counters immediately.
                    let _ = state_admitted.send(reply);
                }
                PeerCommand::QueryImportPolicyTermHits { reply } => {
                    imports.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Some(controlled_policy_snapshot(address)));
                }
                PeerCommand::Stop { .. } => {}
                PeerCommand::Shutdown => break,
                other => panic!("unexpected peer command: {other:?}"),
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(commands, session)
}

#[tokio::test(start_paused = true)]
#[expect(
    clippy::too_many_lines,
    reason = "one actor scenario checks five read routes, both caller outcomes, and mutation ordering"
)]
async fn normal_operator_neighbor_snapshot_does_not_exhaust_import_stats_deadline() {
    use rustbgpd_api::peer_types::{PeerManagerOperatorQuery, PeerManagerReadinessQuery};

    let mut outcomes = Vec::new();
    for (lane, cancel_snapshot) in [
        "operator_list",
        "ordinary_list",
        "readiness_list",
        "operator_get",
        "ordinary_get",
    ]
    .into_iter()
    .flat_map(|lane| [false, true].map(|cancel| (lane, cancel)))
    {
        let (command_tx, command_rx) = mpsc::channel(4);
        let (operator_tx, operator_rx) = mpsc::channel(4);
        let (readiness_tx, readiness_rx) = mpsc::channel(4);
        let mut manager = test_peer_manager()
            .with_operator_queries(operator_rx)
            .with_readiness_queries(readiness_rx);
        manager.rx = command_rx;
        let address: IpAddr = "192.0.2.1".parse().unwrap();
        let (state_admitted, mut state_replies) = mpsc::unbounded_channel();
        let imports = Arc::new(AtomicUsize::new(0));
        insert_test_managed_peer(
            &mut manager,
            address,
            held_neighbor_query_handle(address, state_admitted, imports.clone()),
            false,
        );
        let actor = tokio::spawn(manager.run());
        let (reply, mut snapshot) = oneshot::channel();
        let (single_reply, mut single_snapshot) = oneshot::channel();
        match lane {
            "operator_list" => operator_tx
                .send(PeerManagerOperatorQuery::ListPeers { reply }.into())
                .await
                .unwrap(),
            "ordinary_list" => command_tx
                .send(PeerManagerCommand::ListPeers { reply })
                .await
                .unwrap(),
            "readiness_list" => readiness_tx
                .send(PeerManagerReadinessQuery::ListPeers { reply })
                .await
                .unwrap(),
            "operator_get" => operator_tx
                .send(
                    PeerManagerOperatorQuery::GetPeerState {
                        peer: key(address),
                        reply: single_reply,
                    }
                    .into(),
                )
                .await
                .unwrap(),
            "ordinary_get" => command_tx
                .send(PeerManagerCommand::GetPeerState {
                    peer: key(address),
                    reply: single_reply,
                })
                .await
                .unwrap(),
            _ => unreachable!(),
        }
        let state_reply = tokio::time::timeout(Duration::from_secs(1), state_replies.recv())
            .await
            .expect("neighbor query must reach the session")
            .unwrap();

        // Further neighbor reads ahead of stats must stay deferred, without
        // starting another state-query cohort or hiding the import request.
        let (reply, deferred_list) = oneshot::channel();
        operator_tx
            .send(PeerManagerOperatorQuery::ListPeers { reply }.into())
            .await
            .unwrap();
        let (reply, deferred_get) = oneshot::channel();
        operator_tx
            .send(
                PeerManagerOperatorQuery::GetPeerState {
                    peer: key(address),
                    reply,
                }
                .into(),
            )
            .await
            .unwrap();

        // Model the last 50 ms of the existing absolute RPC budget after
        // earlier stages. This changes no production timeout constant.
        let deadline = tokio::time::Instant::now() + Duration::from_millis(50);
        let (reply, mut stats) = oneshot::channel();
        operator_tx
            .send(
                PeerManagerOperatorQuery::QueryImportPolicyTermHits {
                    peer: None,
                    deadline,
                    reply,
                }
                .into(),
            )
            .await
            .unwrap();
        let (reply, mut mutation) = oneshot::channel();
        command_tx
            .send(PeerManagerCommand::DisablePeer {
                peer: key(address),
                reason: None,
                reply,
            })
            .await
            .unwrap();
        let timely = tokio::time::timeout_at(deadline, &mut stats).await;
        assert!(matches!(
            mutation.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        if lane.ends_with("_get") {
            assert!(matches!(
                single_snapshot.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
        } else {
            assert!(matches!(
                snapshot.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
        }
        assert!(
            state_replies.try_recv().is_err(),
            "deferred neighbors must not fan out"
        );
        drop((deferred_list, deferred_get));
        assert!(!state_reply.is_closed());

        let canceled_state_reply = if cancel_snapshot {
            drop((snapshot, single_snapshot));
            Some(state_reply)
        } else {
            state_reply
                .send(policy_test_peer_state(address, SessionState::Established))
                .unwrap();
            let peers = if lane.ends_with("_get") {
                vec![single_snapshot.await.unwrap().unwrap()]
            } else {
                snapshot.await.unwrap()
            };
            assert_eq!(peers.len(), 1);
            assert_eq!(peers[0].address, address);
            assert!(peers[0].enabled && !peers[0].stale);
            None
        };
        let (on_time, outcome) = match timely {
            Ok(result) => (true, result.unwrap()),
            Err(_) => (false, stats.await.unwrap()),
        };
        mutation.await.unwrap().unwrap();
        if let Some(state_reply) = canceled_state_reply {
            assert!(
                state_reply.is_closed(),
                "cancellation closes the state query"
            );
        }
        command_tx.send(PeerManagerCommand::Shutdown).await.unwrap();
        actor.await.unwrap();
        assert!(
            state_replies.try_recv().is_err(),
            "canceled deferred reads must not query sessions"
        );
        outcomes.push((
            lane,
            cancel_snapshot,
            on_time,
            imports.load(Ordering::SeqCst),
            outcome,
        ));
    }

    // Check after cleanup, retaining both the completion and cancellation
    // cases when the current inline ListPeers handler exhausts the deadline.
    for (lane, cancel_snapshot, on_time, dispatched, outcome) in outcomes {
        assert!(
            on_time,
            "{lane} cancellation={cancel_snapshot}: import missed its remaining deadline; \
             dispatched={dispatched}, outcome={outcome:?}"
        );
        assert_eq!(dispatched, 1);
        assert!(matches!(outcome, SessionQueryOutcome::Reply(rows)
            if rows.len() == 1 && rows[0].0 == "192.0.2.1".parse::<IpAddr>().unwrap()
                && rows[0].1.generation == 1 && rows[0].1.evals == 1));
    }
}

#[tokio::test(start_paused = true)]
async fn normal_snapshot_admission_budget_yields_to_completion_and_cancellation() {
    use rustbgpd_api::peer_types::PeerManagerOperatorQuery;

    for (cancel, exhaust_budget) in [(false, true), (true, true), (true, false)] {
        let (operator_tx, operator_rx) = mpsc::channel(2);
        let mut manager = test_peer_manager().with_operator_queries(operator_rx);
        let address: IpAddr = "192.0.2.1".parse().unwrap();
        let (state_admitted, mut state_replies) = mpsc::unbounded_channel();
        insert_test_managed_peer(
            &mut manager,
            address,
            held_neighbor_query_handle(address, state_admitted, Arc::new(AtomicUsize::new(0))),
            false,
        );
        let (reply, response) = oneshot::channel();
        let worker = tokio::spawn(async move {
            manager
                .answer_normal_operator_query(PeerManagerOperatorQuery::ListPeers { reply })
                .await;
            manager
        });
        let state_reply = state_replies.recv().await.unwrap();
        let started = tokio::time::Instant::now();
        // Refill after each reply: limiting just the deferred queue would
        // admit these lightweight reads forever while the snapshot is held.
        for _ in 0..if exhaust_budget { 2 } else { 1 } {
            let (reply, response) = oneshot::channel();
            operator_tx
                .send(PeerManagerOperatorQuery::HasPeerAddress { address, reply }.into())
                .await
                .unwrap();
            assert!(response.await.unwrap());
        }
        let (reply, mut excess) = oneshot::channel();
        operator_tx
            .try_send(PeerManagerOperatorQuery::HasPeerAddress { address, reply }.into())
            .unwrap();
        let (reply, mut datasets) = oneshot::channel();
        operator_tx
            .try_send(PeerManagerOperatorQuery::QueryPolicyDatasets { reply }.into())
            .unwrap();
        // With an open slot, close the snapshot before yielding so its
        // cancellation and the queued read are ready in the same poll.
        if exhaust_budget {
            for _ in 0..5 {
                tokio::task::yield_now().await;
            }
        }
        assert!(matches!(
            excess.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert!(matches!(
            datasets.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert_eq!(
            operator_tx.capacity(),
            0,
            "the admission cap leaves excess reads queued"
        );
        if cancel {
            drop(response);
        } else {
            state_reply
                .send(policy_test_peer_state(address, SessionState::Established))
                .unwrap();
            assert_eq!(response.await.unwrap().len(), 1);
        }
        let mut manager = worker.await.unwrap();
        assert_eq!(
            tokio::time::Instant::now(),
            started,
            "a ready read flood cannot delay snapshot release"
        );
        assert_eq!(
            operator_tx.capacity(),
            0,
            "snapshot completion wins before another read is consumed"
        );
        for _ in 0..2 {
            let query = PeerManager::receive_operator_query(
                &mut manager.operator_rx,
                &mut manager.deferred_operator_queries,
            )
            .await
            .unwrap();
            manager.handle_operator_query(query, false).await;
        }
        assert!(excess.await.unwrap());
        assert!(datasets.await.unwrap().is_empty());
        assert_eq!(
            operator_tx.capacity(),
            2,
            "the original receiver is restored and remains usable"
        );
        assert!(state_replies.try_recv().is_err());
        for (_, managed) in manager.peers.drain() {
            managed.handle.shutdown().await.unwrap().unwrap();
        }
    }
}

#[tokio::test(start_paused = true)]
#[expect(
    clippy::too_many_lines,
    reason = "two consecutive snapshots share one deferred queue to prove its bound and ordering"
)]
async fn normal_snapshot_deferred_limit_and_order_survive_repeated_reads() {
    use rustbgpd_api::peer_types::PeerManagerOperatorQuery;

    let (operator_tx, operator_rx) = mpsc::channel(2);
    let mut manager = test_peer_manager().with_operator_queries(operator_rx);
    let address: IpAddr = "192.0.2.1".parse().unwrap();
    let (state_admitted, mut state_replies) = mpsc::unbounded_channel();
    insert_test_managed_peer(
        &mut manager,
        address,
        held_neighbor_query_handle(address, state_admitted, Arc::new(AtomicUsize::new(0))),
        false,
    );
    let (reply, response) = oneshot::channel();
    let worker = tokio::spawn(async move {
        manager
            .answer_normal_operator_query(PeerManagerOperatorQuery::ListPeers { reply })
            .await;
        manager
    });
    let state_reply = state_replies.recv().await.unwrap();
    let (reply, first_list) = oneshot::channel();
    operator_tx
        .send(PeerManagerOperatorQuery::ListPeers { reply }.into())
        .await
        .unwrap();
    let (reply, first_get) = oneshot::channel();
    operator_tx
        .send(
            PeerManagerOperatorQuery::GetPeerState {
                peer: key(address),
                reply,
            }
            .into(),
        )
        .await
        .unwrap();
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    assert_eq!(operator_tx.capacity(), 2);
    let (reply, second_list) = oneshot::channel();
    operator_tx
        .send(PeerManagerOperatorQuery::ListPeers { reply }.into())
        .await
        .unwrap();
    let (reply, second_get) = oneshot::channel();
    operator_tx
        .send(
            PeerManagerOperatorQuery::GetPeerState {
                peer: key(address),
                reply,
            }
            .into(),
        )
        .await
        .unwrap();
    state_reply
        .send(policy_test_peer_state(address, SessionState::Established))
        .unwrap();
    assert_eq!(response.await.unwrap().len(), 1);
    let mut manager = worker.await.unwrap();
    assert_eq!(manager.deferred_operator_queries.len(), 2);
    assert_eq!(operator_tx.capacity(), 0);
    assert!(
        state_replies.try_recv().is_err(),
        "only one neighbor cohort may run"
    );
    let first = PeerManager::receive_operator_query(
        &mut manager.operator_rx,
        &mut manager.deferred_operator_queries,
    )
    .await
    .unwrap();
    assert!(matches!(
        first.query,
        PeerManagerOperatorQuery::ListPeers { .. }
    ));
    let worker = tokio::spawn(async move {
        manager.answer_normal_operator_query(first.query).await;
        manager
    });
    let state_reply = state_replies.recv().await.unwrap();
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    // One old deferred request plus one new request fills the same cap.
    assert_eq!(
        operator_tx.capacity(),
        1,
        "the deferred bound spans successive snapshots"
    );
    assert!(state_replies.try_recv().is_err());
    drop(first_list);
    let mut manager = worker.await.unwrap();
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    assert!(state_reply.is_closed());
    assert_eq!(manager.deferred_operator_queries.len(), 2);
    drop((first_get, second_list, second_get));
    for expected_get in [true, false, true] {
        let query = PeerManager::receive_operator_query(
            &mut manager.operator_rx,
            &mut manager.deferred_operator_queries,
        )
        .await
        .unwrap();
        assert_eq!(
            matches!(query.query, PeerManagerOperatorQuery::GetPeerState { .. }),
            expected_get
        );
        manager.handle_operator_query(query, false).await;
    }
    assert!(manager.deferred_operator_queries.is_empty());
    assert_eq!(operator_tx.capacity(), 2);
    assert!(
        state_replies.try_recv().is_err(),
        "preclosed deferred requests never start drivers"
    );
    for (_, managed) in manager.peers.drain() {
        managed.handle.shutdown().await.unwrap().unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn deferred_neighbor_read_survives_receiver_close_and_fences_prestage_ack() {
    use rustbgpd_api::peer_types::PeerManagerOperatorQuery;

    for cancel in [false, true] {
        let (operator_tx, operator_rx) = mpsc::channel(4);
        let mut manager = test_peer_manager().with_operator_queries(operator_rx);
        let address: IpAddr = "192.0.2.1".parse().unwrap();
        let (state_admitted, mut state_replies) = mpsc::unbounded_channel();
        insert_test_managed_peer(
            &mut manager,
            address,
            held_neighbor_query_handle(address, state_admitted, Arc::new(AtomicUsize::new(0))),
            false,
        );
        let (reply, response) = oneshot::channel();
        let worker = tokio::spawn(async move {
            manager
                .answer_normal_operator_query(PeerManagerOperatorQuery::ListPeers { reply })
                .await;
            manager
        });
        let state_reply = state_replies.recv().await.unwrap();
        let (reply, deferred_response) = oneshot::channel();
        operator_tx
            .send(PeerManagerOperatorQuery::ListPeers { reply }.into())
            .await
            .unwrap();
        let (reply, marker) = oneshot::channel();
        operator_tx
            .send(PeerManagerOperatorQuery::HasPeerAddress { address, reply }.into())
            .await
            .unwrap();
        assert!(
            marker.await.unwrap(),
            "the preceding neighbor read has been deferred"
        );
        drop(operator_tx);
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        state_reply
            .send(policy_test_peer_state(address, SessionState::Established))
            .unwrap();
        assert_eq!(response.await.unwrap().len(), 1);
        let mut manager = worker.await.unwrap();
        assert!(
            manager.operator_rx.is_none(),
            "closed receiver must not become a ready-loop source"
        );
        assert_eq!(manager.deferred_operator_queries.len(), 1);
        let (ack, ack_rx) = oneshot::channel();
        let worker = tokio::spawn(async move {
            let result = manager
                .await_with_readiness_and_operator_budget(ack_rx, Duration::from_secs(1), true)
                .await;
            assert!(matches!(result, Some(Ok(()))));
            manager
        });
        let state_reply = state_replies.recv().await.unwrap();
        ack.send(()).unwrap();
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        assert!(
            !worker.is_finished(),
            "an admitted deferred read must finish before prestage advances"
        );
        if cancel {
            drop(deferred_response);
        } else {
            state_reply
                .send(policy_test_peer_state(address, SessionState::Established))
                .unwrap();
            assert_eq!(deferred_response.await.unwrap().len(), 1);
        }
        let mut manager = worker.await.unwrap();
        assert!(manager.deferred_operator_queries.is_empty());
        assert!(manager.operator_rx.is_none());
        let mut receive = Box::pin(PeerManager::receive_operator_query(
            &mut manager.operator_rx,
            &mut manager.deferred_operator_queries,
        ));
        assert!(matches!(
            futures::poll!(receive.as_mut()),
            std::task::Poll::Pending
        ));
        drop(receive);
        for (_, managed) in manager.peers.drain() {
            managed.handle.shutdown().await.unwrap().unwrap();
        }
    }
}
