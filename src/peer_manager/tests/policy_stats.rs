use super::*;
use rustbgpd_transport::handle::{ImportPolicyStatsError, InstalledImportPolicy};
use tokio::sync::watch;

fn policy_counter_context() -> rustbgpd_policy::RouteContext<'static> {
    rustbgpd_policy::RouteContext {
        prefix: None,
        next_hop: None,
        extended_communities: &[],
        communities: &[],
        large_communities: &[],
        as_path_str: "",
        as_path: None,
        as_path_len: 0,
        origin_asn: None,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        peer_address: None,
        peer_asn: None,
        peer_group: None,
        route_type: None,
        family: None,
        evpn_route_type: None,
        local_pref: None,
        med: None,
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one real RPC fixture retains the session hold, counter values, live readiness and cleanup"
)]
async fn import_policy_stats_rpc_reads_live_counters_while_real_session_is_held() {
    use rustbgpd_api::proto::policy_service_server::PolicyService as PolicyServiceRpc;
    use rustbgpd_api::server::{AccessMode, RuntimeConfigCoordinator};

    let (commands, command_rx) = mpsc::channel(8);
    let (operator, operator_rx) = mpsc::channel(8);
    let (readiness, readiness_rx) = mpsc::channel(8);
    let (manager_rib, _manager_rib_rx) = mpsc::channel(8);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        "192.0.2.1".parse().unwrap(),
        None,
        None,
        BgpMetrics::new(),
        manager_rib.clone(),
        None,
    )
    .with_operator_queries(operator_rx)
    .with_readiness_queries(readiness_rx);
    let (session_rib, held_rib) = mpsc::channel(1);
    let (held, _response) = oneshot::channel();
    session_rib
        .try_send(RibUpdate::QueryLocRibCount { reply: held })
        .unwrap();
    let mut chain = validation_policy_chain(ImportValidationDependency::Rpki);
    chain.policies[0].name = Some("held-import".to_string());
    let context = rustbgpd_policy::RouteContext {
        validation_state: rustbgpd_wire::RpkiValidation::Invalid,
        ..policy_counter_context()
    };
    for _ in 0..7 {
        let _ = chain.evaluate(&context);
    }
    let address = "192.0.2.2".parse::<IpAddr>().unwrap();
    let config = rustbgpd_transport::TransportConfig::new(
        rustbgpd_fsm::PeerConfig::new(65001, 65002, "192.0.2.1".parse().unwrap()),
        std::net::SocketAddr::new(address, 179),
    );
    let handle = PeerHandle::spawn(
        config,
        BgpMetrics::new(),
        session_rib,
        Some(chain),
        None,
        None,
        None,
        None,
        false,
    );
    let session_commands = handle.commands_sender();
    let (reply, mut export_ack) = oneshot::channel();
    session_commands
        .send(PeerCommand::UpdateExportPolicy {
            policy: None,
            reply,
        })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while session_commands.capacity() != session_commands.max_capacity() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("actual session parks in export RIB admission");
    insert_test_managed_peer(&mut manager, address, handle, false);
    let import_roster = manager.import_roster();
    let (hold_manager, hold_requested) = oneshot::channel();
    let (manager_held, pause_ack) = oneshot::channel();
    let actor = tokio::spawn(async move {
        let run = manager.run();
        tokio::pin!(run);
        tokio::select! {
            () = &mut run => {}
            _ = hold_requested => {
                manager_held.send(()).unwrap();
                std::future::pending::<()>().await;
            }
        }
    });
    let probe = rustbgpd_api::health_probe::CoreReadinessProbe::new(commands.clone(), manager_rib)
        .with_peer_manager_readiness(readiness.clone());
    let service = rustbgpd_api::PolicyService::with_runtime_config_coordinator(
        AccessMode::ReadOnly,
        commands,
        None,
        None,
        RuntimeConfigCoordinator::new(),
    )
    .with_operator_queries(operator)
    .with_import_roster(import_roster);
    let started = tokio::time::Instant::now();
    let result = service
        .get_policy_stats(tonic::Request::new(
            rustbgpd_api::proto::GetPolicyStatsRequest {
                peer_address: address.to_string(),
                direction: "import".to_string(),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(result.chains.len(), 1);
    assert_eq!(result.chains[0].peer_address, address.to_string());
    assert_eq!(result.chains[0].routes_evaluated, 7);
    assert_eq!(result.chains[0].policy_generation, 0);
    assert_eq!(result.chains[0].eval_errors, 0);
    assert_eq!(result.chains[0].terms.len(), 1);
    assert_eq!(result.chains[0].terms[0].policy, "held-import");
    assert_eq!(result.chains[0].terms[0].hits, 7);
    assert!(result.chains[0].last_error.is_empty());
    assert!(matches!(
        export_ack.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert!(
        matches!(
            PeerHandle::query_state_outcome_with(
                session_commands.clone(),
                Duration::from_millis(20)
            )
            .await,
            rustbgpd_transport::StateQueryOutcome::TimedOut
        ),
        "counter availability does not prove live session progress"
    );
    let (reply, ping) = oneshot::channel();
    readiness
        .send(rustbgpd_api::peer_types::PeerManagerReadinessQuery::Ping { reply })
        .await
        .unwrap();
    ping.await.unwrap();
    hold_manager.send(()).unwrap();
    pause_ack.await.unwrap();
    assert!(
        matches!(
            probe.check().await,
            Err(rustbgpd_api::health_probe::CoreReadinessError::PeerManagerTimedOut)
        ),
        "published counter success cannot replace live core actor progress"
    );
    actor.abort();
    let _ = actor.await;
    // PeerHandle drop does not stop the held session: release its RIB owner,
    // then explicitly wait for the command receiver to close.
    drop(held_rib);
    session_commands.send(PeerCommand::Shutdown).await.unwrap();
    session_commands.closed().await;
}

fn chainless_policy_query_handle() -> PeerHandle {
    let (commands, mut command_rx) = mpsc::channel(4);
    let (publication, receiver) = watch::channel(Some(installed_policy(0, None)));
    let task = tokio::spawn(async move {
        while let Some(command) = command_rx.recv().await {
            if matches!(command, PeerCommand::Shutdown) {
                break;
            }
        }
        drop(publication);
        Ok(())
    });
    PeerHandle::from_parts_with_import_policy_counters(commands, task, receiver)
}

/// LAN-661 red proof: validating against static config rejects the accepted
/// dynamic peer; replacing the typed forwarding result with the old `Option`
/// path makes its stalled task return `SessionGone`; silently omitting a
/// Pending publication makes the import capture return `Ok([])`. Each
/// production break fails its corresponding assertion.
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
    let import_roster = manager.import_roster();
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

    let roster = import_roster.load();
    let selected = roster
        .unique_peer(configured)
        .expect("the dynamic peer is managed");
    assert!(
        matches!(
            rustbgpd_api::import_roster::capture_import(
                std::slice::from_ref(selected),
                tokio::time::Instant::now() + EXPLAIN_QUERY_TIMEOUT,
                &mut rustbgpd_api::import_roster::ImportCaptureProgress::default(),
            )
            .await,
            Err(ImportPolicyStatsError::TimedOut)
        ),
        "a Pending publication must fail the capture instead of being omitted"
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

/// LAN-661 red proof: treating a published chainless session as closed (or
/// as a row) makes this healthy chainless capture fail instead of returning
/// a successful empty result.
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
    let import_roster = manager.import_roster();
    let manager_task = tokio::spawn(manager.run());

    let outcome = roster_import_rows(&import_roster).await;
    assert!(
        matches!(&outcome, Ok(rows) if rows.is_empty()),
        "a healthy session without an import chain must answer with no row, got {outcome:?}"
    );

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    manager_task.await.unwrap();
}

fn controlled_policy_snapshot(address: IpAddr) -> Arc<InstalledImportPolicy> {
    let generation = match address {
        IpAddr::V4(address) => u64::from(address.octets()[3]),
        IpAddr::V6(_) => 0,
    };
    let chain = PolicyChain::new(vec![]);
    for _ in 0..generation {
        let _ = chain.evaluate(&policy_counter_context());
    }
    installed_policy(generation, Some(&chain))
}

/// A session that holds each state query while answering everything else.
fn held_neighbor_query_handle(
    address: IpAddr,
    state_admitted: mpsc::UnboundedSender<oneshot::Sender<PeerSessionState>>,
    imports: Arc<AtomicUsize>,
) -> PeerHandle {
    let (commands, mut commands_rx) = mpsc::channel(4);
    let (publication, receiver) = watch::channel(Some(controlled_policy_snapshot(address)));
    let session = tokio::spawn(async move {
        while let Some(command) = commands_rx.recv().await {
            match command {
                PeerCommand::QueryState { reply } => {
                    // Hold only this reply; the session keeps receiving.
                    let _ = state_admitted.send(reply);
                }
                PeerCommand::QueryImportPolicyTermHits { reply } => {
                    imports.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Some(rustbgpd_transport::ImportPolicyTermHits {
                        generation: 1,
                        evals: 1,
                        eval_errors: 0,
                        last_error: None,
                        terms: Vec::new(),
                    }));
                }
                PeerCommand::Stop { .. } => {}
                PeerCommand::Shutdown => break,
                other => panic!("unexpected peer command: {other:?}"),
            }
        }
        drop(publication);
        Ok(())
    });
    PeerHandle::from_parts_with_import_policy_counters(commands, session, receiver)
}

#[tokio::test(start_paused = true)]
#[expect(
    clippy::too_many_lines,
    reason = "one actor scenario checks five read routes, both caller outcomes, and mutation ordering"
)]
async fn normal_operator_neighbor_snapshot_does_not_delay_import_stats() {
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
        let import_roster = manager.import_roster();
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

        // Further neighbor reads must stay deferred, without starting
        // another state-query cohort.
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
        // earlier stages. Import statistics read the published roster, so
        // the held snapshot cannot spend it; a lightweight lookup queued
        // behind the snapshot is still served inline.
        let deadline = tokio::time::Instant::now() + Duration::from_millis(50);
        let roster = import_roster.load();
        let mut progress = rustbgpd_api::import_roster::ImportCaptureProgress::default();
        let stats =
            rustbgpd_api::import_roster::capture_import(roster.peers(), deadline, &mut progress);
        let (reply, mut lookup) = oneshot::channel();
        operator_tx
            .send(PeerManagerOperatorQuery::HasPeerAddress { address, reply }.into())
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
        let timely = tokio::time::timeout_at(deadline, stats).await;
        assert!(
            tokio::time::timeout_at(deadline, &mut lookup)
                .await
                .unwrap()
                .unwrap(),
            "{lane}: the lookup is served inline during the snapshot"
        );
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
            Ok(result) => (true, result),
            Err(_) => (false, Err(ImportPolicyStatsError::TimedOut)),
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
    // cases.
    for (lane, cancel_snapshot, on_time, dispatched, outcome) in outcomes {
        assert!(
            on_time,
            "{lane} cancellation={cancel_snapshot}: import missed its remaining deadline; \
             dispatched={dispatched}, outcome={outcome:?}"
        );
        assert_eq!(
            dispatched, 0,
            "published reads do not send session commands"
        );
        assert!(matches!(outcome, Ok(rows)
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
        let (reply, mut second) = oneshot::channel();
        operator_tx
            .try_send(PeerManagerOperatorQuery::HasPeerAddress { address, reply }.into())
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
            second.try_recv(),
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
        assert!(second.await.unwrap());
        assert_eq!(
            operator_tx.capacity(),
            2,
            "the original receiver is restored and remains usable"
        );
        assert!(state_replies.try_recv().is_err());
        for (_, managed) in manager.peers.drain() {
            managed.into_parts().0.shutdown().await.unwrap().unwrap();
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
        managed.into_parts().0.shutdown().await.unwrap().unwrap();
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
                .await_with_readiness_budget(
                    ack_rx,
                    Duration::from_secs(1),
                    OperatorReadAdmission::Served,
                )
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
            managed.into_parts().0.shutdown().await.unwrap().unwrap();
        }
    }
}
