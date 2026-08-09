use super::*;

#[tokio::test]
async fn closed_internal_command_lane_disables_after_first_poll() {
    // Load-bearing: removing the close-to-disabled transition leaves the
    // receiver present and makes every later receive immediately ready.
    let (internal_tx, internal_rx) = mpsc::unbounded_channel();
    drop(internal_tx);
    let mut internal_rx = Some(internal_rx);

    assert!(
        PeerManager::receive_internal_command(&mut internal_rx)
            .await
            .is_none()
    );
    assert!(internal_rx.is_none());

    let mut second = Box::pin(PeerManager::receive_internal_command(&mut internal_rx));
    assert!(matches!(
        futures::poll!(second.as_mut()),
        std::task::Poll::Pending
    ));
}

#[tokio::test]
async fn closed_internal_command_lane_keeps_public_actor_live() {
    // Load-bearing: treating private-lane closure as actor shutdown makes the
    // initial poll Ready and prevents the bounded public command round-trip.
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let manager = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let mut actor = Box::pin(manager.run());
    assert!(matches!(
        futures::poll!(actor.as_mut()),
        std::task::Poll::Pending
    ));
    let handle = tokio::spawn(actor);

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::ListDynamicRanges { reply: reply_tx })
        .await
        .unwrap();
    let ranges = tokio::time::timeout(Duration::from_secs(1), reply_rx)
        .await
        .expect("public command stalled after the private lane closed")
        .unwrap();
    assert!(ranges.is_empty());

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), handle)
        .await
        .expect("peer manager did not shut down")
        .unwrap();
}

fn blocked_snapshot_query_handle(
    peer: IpAddr,
    release: oneshot::Receiver<()>,
    observed: mpsc::UnboundedSender<&'static str>,
) -> PeerHandle {
    use rustbgpd_transport::PeerCommand;

    let (commands, mut receiver) = mpsc::channel(1);
    commands
        .try_send(PeerCommand::Start)
        .expect("pre-fill the session command channel");
    let task = tokio::spawn(async move {
        let _ = release.await;
        assert!(matches!(receiver.recv().await, Some(PeerCommand::Start)));
        while let Some(command) = receiver.recv().await {
            match command {
                PeerCommand::QueryState { reply } => {
                    let _ = observed.send("state");
                    let _ = reply.send(policy_test_peer_state(peer, SessionState::Established));
                }
                PeerCommand::QueryWarmCheckpointState { reply } => {
                    let _ = observed.send("warm");
                    let _ = reply.send(eligible_warm_checkpoint_state());
                }
                PeerCommand::Shutdown | PeerCommand::Stop { .. } | PeerCommand::CollisionDump => {
                    break;
                }
                _ => {}
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(commands, task)
}

async fn assert_canceled_list_peers_releases_driver(use_readiness_lane: bool) {
    use rustbgpd_api::peer_types::PeerManagerReadinessQuery;

    let (tx, rx) = mpsc::channel(1);
    let (readiness_tx, readiness_rx) = mpsc::channel(1);
    let (rib_tx, _rib_rx) = mpsc::channel(8);
    let mut manager = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    )
    .with_readiness_queries(readiness_rx);
    let peer: IpAddr = "192.0.2.1".parse().unwrap();
    let (release, release_rx) = oneshot::channel();
    let (observed, mut observations) = mpsc::unbounded_channel();
    insert_test_managed_peer(
        &mut manager,
        peer,
        blocked_snapshot_query_handle(peer, release_rx, observed),
        false,
    );
    let actor = tokio::spawn(manager.run());

    let (canceled_reply, canceled_response) = oneshot::channel();
    if use_readiness_lane {
        readiness_tx
            .send(PeerManagerReadinessQuery::ListPeers {
                reply: canceled_reply,
            })
            .await
            .unwrap();
    } else {
        tx.send(PeerManagerCommand::ListPeers {
            reply: canceled_reply,
        })
        .await
        .unwrap();
    }
    // The bounded peer-manager/readiness channel accepting another item proves
    // the actor consumed the snapshot request. Its one session query is then
    // synchronously spawned and parked behind the deliberately full channel.
    while if use_readiness_lane {
        readiness_tx.capacity() == 0
    } else {
        tx.capacity() == 0
    } {
        tokio::task::yield_now().await;
    }
    tokio::task::yield_now().await;

    let later_tx = tx.clone();
    let later_command = tokio::spawn(async move { subscribe_session_events(&later_tx).await });
    tokio::task::yield_now().await;
    assert!(
        !later_command.is_finished(),
        "later manager command waits behind the live snapshot"
    );
    drop(canceled_response);
    for _ in 0..10 {
        tokio::task::yield_now().await;
        if later_command.is_finished() {
            break;
        }
    }
    assert!(
        later_command.is_finished(),
        "canceling the snapshot releases the manager without advancing time"
    );
    drop(later_command.await.unwrap());

    release.send(()).unwrap();
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    assert!(
        observations.try_recv().is_err(),
        "the canceled driver must not admit a late QueryState"
    );

    let (reply, response) = oneshot::channel();
    if use_readiness_lane {
        readiness_tx
            .send(PeerManagerReadinessQuery::ListPeers { reply })
            .await
            .unwrap();
    } else {
        tx.send(PeerManagerCommand::ListPeers { reply })
            .await
            .unwrap();
    }
    let peers = response.await.unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(observations.recv().await, Some("state"));
    assert!(observations.try_recv().is_err());

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    actor.await.unwrap();
}

/// Load-bearing ordinary-lane proof: detaching the spawned `QueryState` driver
/// leaves it queued after aggregate cancellation, so freeing the slot observes
/// a late first query and the exact-one assertion fails.
#[tokio::test(start_paused = true)]
async fn canceled_ordinary_list_peers_aborts_blocked_session_driver() {
    assert_canceled_list_peers_releases_driver(false).await;
}

/// Load-bearing readiness-lane proof: bypassing the shared complete-only
/// answer path or detaching its driver admits a late `QueryState` after the
/// health caller is gone.
#[tokio::test(start_paused = true)]
async fn canceled_readiness_list_peers_aborts_blocked_session_driver() {
    assert_canceled_list_peers_releases_driver(true).await;
}

/// Load-bearing warm-capture proof: detaching `QueryWarmCheckpointState` leaves
/// it queued after cancellation, so freeing the slot observes a late warm
/// query before the next all-or-nothing capture.
#[tokio::test(start_paused = true)]
async fn canceled_warm_checkpoint_aborts_blocked_session_driver() {
    let (tx, rx) = mpsc::channel(1);
    let (rib_tx, _rib_rx) = mpsc::channel(8);
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
    let peer: IpAddr = "192.0.2.1".parse().unwrap();
    let (release, release_rx) = oneshot::channel();
    let (observed, mut observations) = mpsc::unbounded_channel();
    insert_test_managed_peer(
        &mut manager,
        peer,
        blocked_snapshot_query_handle(peer, release_rx, observed),
        false,
    );
    let actor = tokio::spawn(manager.run());

    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::QueryWarmCheckpointCapture { reply })
        .await
        .unwrap();
    while tx.capacity() == 0 {
        tokio::task::yield_now().await;
    }
    tokio::task::yield_now().await;
    let later_tx = tx.clone();
    let later_command = tokio::spawn(async move { subscribe_session_events(&later_tx).await });
    tokio::task::yield_now().await;
    assert!(!later_command.is_finished());
    drop(response);
    for _ in 0..10 {
        tokio::task::yield_now().await;
        if later_command.is_finished() {
            break;
        }
    }
    assert!(later_command.is_finished());
    drop(later_command.await.unwrap());

    release.send(()).unwrap();
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    assert!(observations.try_recv().is_err());

    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::QueryWarmCheckpointCapture { reply })
        .await
        .unwrap();
    let capture = response.await.unwrap().unwrap();
    assert_eq!(capture.sessions.len(), 1);
    assert_eq!(observations.recv().await, Some("warm"));
    assert!(observations.try_recv().is_err());

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    actor.await.unwrap();
}

enum HeldSnapshotReply {
    State(IpAddr, oneshot::Sender<PeerSessionState>),
    Warm(IpAddr, oneshot::Sender<WarmCheckpointSessionState>),
}

impl HeldSnapshotReply {
    fn peer(&self) -> IpAddr {
        match self {
            Self::State(peer, _) | Self::Warm(peer, _) => *peer,
        }
    }

    fn is_closed(&self) -> bool {
        match self {
            Self::State(_, reply) => reply.is_closed(),
            Self::Warm(_, reply) => reply.is_closed(),
        }
    }
}

fn held_snapshot_query_handle(
    peer: IpAddr,
    warm: bool,
    admitted: mpsc::UnboundedSender<HeldSnapshotReply>,
) -> PeerHandle {
    use rustbgpd_transport::PeerCommand;

    let (commands, mut receiver) = mpsc::channel(1);
    let task = tokio::spawn(async move {
        while let Some(command) = receiver.recv().await {
            match command {
                PeerCommand::QueryState { reply } if !warm => {
                    let _ = admitted.send(HeldSnapshotReply::State(peer, reply));
                    break;
                }
                PeerCommand::QueryWarmCheckpointState { reply } if warm => {
                    let _ = admitted.send(HeldSnapshotReply::Warm(peer, reply));
                    break;
                }
                _ => {}
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(commands, task)
}

fn blocked_cohort_query_handle(
    release: oneshot::Receiver<()>,
    settled: mpsc::UnboundedSender<bool>,
) -> PeerHandle {
    use rustbgpd_transport::PeerCommand;

    let (commands, mut receiver) = mpsc::channel(1);
    commands
        .try_send(PeerCommand::Start)
        .expect("pre-fill cohort command channel");
    let task = tokio::spawn(async move {
        let _ = release.await;
        assert!(matches!(receiver.recv().await, Some(PeerCommand::Start)));
        let admitted = receiver.recv().await.is_some_and(|command| {
            matches!(
                command,
                PeerCommand::QueryState { .. } | PeerCommand::QueryWarmCheckpointState { .. }
            )
        });
        let _ = settled.send(admitted);
        Ok(())
    });
    PeerHandle::from_parts(commands, task)
}

async fn assert_canceled_snapshot_cohort_aborts_every_driver(warm: bool) {
    const PEERS: usize = 32;
    const ADMITTED: usize = 7;

    let mut manager = test_peer_manager();
    let (admitted, mut admitted_rx) = mpsc::unbounded_channel();
    let (settled, mut settled_rx) = mpsc::unbounded_channel();
    let mut releases = Vec::new();
    for index in 1..=PEERS {
        let peer = IpAddr::V4(Ipv4Addr::new(198, 51, 100, u8::try_from(index).unwrap()));
        let handle = if index <= ADMITTED {
            held_snapshot_query_handle(peer, warm, admitted.clone())
        } else {
            let (release, release_rx) = oneshot::channel();
            releases.push(release);
            blocked_cohort_query_handle(release_rx, settled.clone())
        };
        insert_test_managed_peer(&mut manager, peer, handle, false);
    }
    drop(admitted);
    drop(settled);

    let collector = tokio::spawn(async move {
        if warm {
            let _ = manager.query_warm_checkpoint_capture().await;
        } else {
            let _ = manager.list_peers().await;
        }
    });
    let mut admitted_replies = Vec::with_capacity(ADMITTED);
    for _ in 0..ADMITTED {
        admitted_replies.push(admitted_rx.recv().await.unwrap());
    }
    let admitted_peers: BTreeSet<_> = admitted_replies
        .iter()
        .map(HeldSnapshotReply::peer)
        .collect();
    assert_eq!(admitted_peers.len(), ADMITTED);

    collector.abort();
    assert!(collector.await.unwrap_err().is_cancelled());
    assert!(
        admitted_replies.iter().all(HeldSnapshotReply::is_closed),
        "every admitted session reply receiver closes synchronously"
    );

    for release in releases {
        release.send(()).unwrap();
    }
    for _ in ADMITTED..PEERS {
        assert_eq!(
            settled_rx.recv().await,
            Some(false),
            "a driver waiting for a remaining session slot must not be admitted"
        );
    }
    assert!(settled_rx.try_recv().is_err());
}

/// Load-bearing high-cardinality `QueryState` proof: plain `JoinHandles` detach
/// when the collector is canceled, so all 25 blocked drivers become admitted
/// after their slots are freed and the exact-empty assertion fails.
#[tokio::test(start_paused = true)]
async fn canceled_list_peers_cohort_aborts_admitted_and_blocked_drivers() {
    assert_canceled_snapshot_cohort_aborts_every_driver(false).await;
}

/// Load-bearing high-cardinality warm proof: plain `JoinHandles` detach when the
/// capture is canceled, so blocked `QueryWarmCheckpointState` drivers enter the
/// session channels and admitted reply senders stay open.
#[tokio::test(start_paused = true)]
async fn canceled_warm_checkpoint_cohort_aborts_admitted_and_blocked_drivers() {
    assert_canceled_snapshot_cohort_aborts_every_driver(true).await;
}

#[tokio::test]
async fn canceled_ordinary_list_peers_skips_session_queries() {
    let (tx, rx) = mpsc::channel(8);
    let (rib_tx, _rib_rx) = mpsc::channel(8);
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
    let peer: IpAddr = "192.0.2.1".parse().unwrap();
    let counters = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer(
        &mut manager,
        peer,
        fake_peer_handle(peer, SessionState::Established, None, counters.clone()),
        false,
    );
    let stale_peer: IpAddr = "192.0.2.2".parse().unwrap();
    let (stale_commands, stale_receiver) = mpsc::channel(1);
    let stale_task = tokio::spawn(async move {
        drop(stale_receiver);
        Ok::<(), rustbgpd_transport::TransportError>(())
    });
    insert_test_managed_peer(
        &mut manager,
        stale_peer,
        PeerHandle::from_parts(stale_commands, stale_task),
        false,
    );
    let actor = tokio::spawn(manager.run());
    tokio::task::yield_now().await;

    let (reply, receiver) = oneshot::channel();
    drop(receiver);
    tx.send(PeerManagerCommand::ListPeers { reply })
        .await
        .unwrap();

    let (reply, receiver) = oneshot::channel();
    tx.send(PeerManagerCommand::ListPeers { reply })
        .await
        .unwrap();
    let peers = receiver.await.unwrap();
    assert_eq!(peers.len(), 2);
    assert!(
        peers.iter().any(|row| row.address == peer && !row.stale),
        "live row remains fresh"
    );
    assert!(
        peers
            .iter()
            .any(|row| row.address == stale_peer && row.stale),
        "unanswered row keeps the existing stale fallback"
    );
    assert_eq!(counters.query_state.load(Ordering::SeqCst), 1);

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    actor.await.unwrap();
}

#[tokio::test]
async fn canceled_plan_drops_rib_snapshot_and_actor_answers_later_command() {
    let config = load_test_config(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "127.0.0.1:9179"
log_format = "json"
"#,
    );
    let candidate = toml::to_string_pretty(&config).unwrap();
    let (tx, rx) = mpsc::channel(8);
    let (rib_tx, mut rib_rx) = mpsc::channel(8);
    let manager = PeerManager::new_with_config(
        rx,
        mpsc::unbounded_channel().1,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
        None,
        config,
    );
    let actor = tokio::spawn(manager.run());

    let (plan_reply, plan_receiver) = oneshot::channel();
    tx.send(PeerManagerCommand::PlanConfigTransaction {
        candidate_toml: candidate,
        expected_runtime_snapshot_token: None,
        reply: plan_reply,
    })
    .await
    .unwrap();
    let RibUpdate::QueryUpdateGroupSnapshot { mut reply } = rib_rx.recv().await.unwrap() else {
        panic!("plan did not request its RIB snapshot");
    };
    drop(plan_receiver);
    tokio::time::timeout(Duration::from_secs(1), reply.closed())
        .await
        .expect("abandoned plan kept its RIB snapshot receiver alive");

    let (policies_reply, policies_receiver) = oneshot::channel();
    tx.send(PeerManagerCommand::ListPolicies {
        reply: policies_reply,
    })
    .await
    .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(1), policies_receiver)
        .await
        .expect("actor remained blocked on the abandoned RIB snapshot")
        .unwrap();

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    actor.await.unwrap();
}
