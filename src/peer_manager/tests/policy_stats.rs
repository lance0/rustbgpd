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
