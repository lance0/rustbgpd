use super::*;

/// Established session that acknowledges an export hot-apply only after
/// `ack_delay`: healthy, but busy with concurrent reload work. State queries
/// answer immediately so cohort preflight sees Established.
fn busy_established_export_session(
    addr: IpAddr,
    ack_delay: Duration,
    installs: Arc<AtomicUsize>,
) -> PeerHandle {
    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(16);
    let task = tokio::spawn(async move {
        while let Some(command) = session_rx.recv().await {
            match command {
                PeerCommand::UpdateExportPolicy { reply, .. } => {
                    tokio::time::sleep(ack_delay).await;
                    installs.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(policy_test_peer_state(addr, SessionState::Established));
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(session_tx, task)
}

/// Cohort-setup starvation, RIB shape: the destination-prestage answer sits
/// behind queued reload work in the RIB for ten (virtual) minutes. The wait
/// must be bounded by `RIB_REPLY_TIMEOUT` and degrade to an unprestaged
/// cohort, not park the whole reload behind the RIB's dequeue latency.
#[tokio::test(start_paused = true)]
async fn cohort_prestage_wait_is_bounded_when_rib_dequeue_lags() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let first = IpAddr::V4(Ipv4Addr::new(10, 37, 0, 1));
    let second = IpAddr::V4(Ipv4Addr::new(10, 37, 0, 2));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(8);
    let rib = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::PrepareExportPolicyDestination { reply, .. } => {
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_mins(10)).await;
                        let _ = reply.send(Err("test: prestage dequeued late".to_string()));
                    });
                }
                RibUpdate::ReplacePeerExportPolicies { reply, .. } => {
                    let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
                }
                _ => {}
            }
        }
    });

    let (_command_tx, command_rx) = mpsc::channel(16);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let installs = Arc::new(AtomicUsize::new(0));
    for peer in [first, second] {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(peer, Arc::clone(&installs), None),
            false,
        );
    }
    let next = deny_policy_chain();
    let targets = [first, second]
        .into_iter()
        .map(|address| ResolvedPeerPolicy {
            address,
            interface: None,
            import_policy: None,
            export_policy: Some(next.clone()),
        })
        .collect::<Vec<_>>();

    let started = tokio::time::Instant::now();
    manager
        .apply_resolved_policy_snapshot(targets)
        .await
        .expect("healthy sessions must commit despite a lagging prestage answer");
    let elapsed = started.elapsed();
    assert!(
        elapsed >= RIB_REPLY_TIMEOUT,
        "the live prestage round trip still waits its bounded budget: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_mins(1),
        "the prestage wait must be bounded, not tied to RIB dequeue latency: {elapsed:?}"
    );
    assert_eq!(installs.load(Ordering::SeqCst), 2);
    assert_eq!(
        manager.peers.get(&key(first)).unwrap().export_policy,
        Some(next)
    );

    drop(manager);
    rib.await.unwrap();
}

/// Cohort-setup starvation, readiness shape: a continuous readiness-query
/// flood is serviced while each session command is in flight. Servicing time
/// must not be charged against `PEER_POLICY_UPDATE_TIMEOUT`, so a session
/// that acknowledges while the actor is busy with the flood (650 ms wall, of
/// which almost none is time the actor spent waiting on the session) still
/// commits instead of timing out the reload.
#[tokio::test(start_paused = true)]
async fn readiness_servicing_is_not_charged_to_cohort_session_deadlines() {
    use rustbgpd_api::peer_types::{PeerManagerReadinessQuery, ResolvedPeerPolicy};

    let first = IpAddr::V4(Ipv4Addr::new(10, 37, 1, 1));
    let second = IpAddr::V4(Ipv4Addr::new(10, 37, 1, 2));
    let parked = IpAddr::V4(Ipv4Addr::new(10, 37, 1, 3));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(8);
    let rib = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::PrepareExportPolicyDestination { reply, .. } => {
                    let _ = reply.send(Err("test: prestage skipped".to_string()));
                }
                RibUpdate::ReplacePeerExportPolicies { reply, .. } => {
                    let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
                }
                _ => {}
            }
        }
    });

    let (_command_tx, command_rx) = mpsc::channel(16);
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
    .with_readiness_queries(readiness_rx);
    let installs = Arc::new(AtomicUsize::new(0));
    for peer in [first, second] {
        insert_test_managed_peer(
            &mut manager,
            peer,
            busy_established_export_session(
                peer,
                Duration::from_millis(650),
                Arc::clone(&installs),
            ),
            false,
        );
    }
    // A parked bystander session that never answers state queries makes every
    // serviced `ListPeers` cost the full `PEER_QUERY_TIMEOUT`.
    insert_test_managed_peer(&mut manager, parked, stalled_policy_query_handle(), false);

    // Continuous flood: one query queued at all times, the next sent as soon
    // as the previous one is answered.
    let flooder = tokio::spawn(async move {
        loop {
            let (reply_tx, reply_rx) = oneshot::channel();
            if readiness_tx
                .send(PeerManagerReadinessQuery::ListPeers { reply: reply_tx })
                .await
                .is_err()
            {
                break;
            }
            if reply_rx.await.is_err() {
                break;
            }
        }
    });

    let next = deny_policy_chain();
    let targets = [first, second]
        .into_iter()
        .map(|address| ResolvedPeerPolicy {
            address,
            interface: None,
            import_policy: None,
            export_policy: Some(next.clone()),
        })
        .collect::<Vec<_>>();
    manager
        .apply_resolved_policy_snapshot(targets)
        .await
        .expect("readiness servicing must not consume the session hot-apply deadlines");
    assert_eq!(installs.load(Ordering::SeqCst), 2);
    assert_eq!(
        manager.peers.get(&key(first)).unwrap().export_policy,
        Some(next.clone())
    );
    assert_eq!(
        manager.peers.get(&key(second)).unwrap().export_policy,
        Some(next)
    );

    drop(manager);
    flooder.abort();
    rib.await.unwrap();
}

/// A per-client-best source group is statically excluded from the clean
/// transition (its RIB preflight answers `None` unconditionally), so the
/// cohort must not queue the destination-prestage round trip at all: the
/// only RIB command in the dialogue is the batched replacement.
#[tokio::test]
async fn per_client_best_cohort_skips_statically_dead_prestage() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let first = IpAddr::V4(Ipv4Addr::new(10, 37, 2, 1));
    let second = IpAddr::V4(Ipv4Addr::new(10, 37, 2, 2));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(8);
    let rib = tokio::spawn(async move {
        let mut sequence = Vec::new();
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::PrepareExportPolicyDestination { reply, .. } => {
                    sequence.push("prestage");
                    let _ = reply.send(Err("test: statically dead".to_string()));
                }
                RibUpdate::ReplacePeerExportPolicies { reply, .. } => {
                    sequence.push("batch");
                    let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
                }
                _ => {}
            }
        }
        sequence
    });

    let (_command_tx, command_rx) = mpsc::channel(16);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let installs = Arc::new(AtomicUsize::new(0));
    for peer in [first, second] {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(peer, Arc::clone(&installs), None),
            false,
        );
        manager
            .peers
            .get_mut(&key(peer))
            .unwrap()
            .transport_config
            .per_client_best = true;
    }
    let next = deny_policy_chain();
    let targets = [first, second]
        .into_iter()
        .map(|address| ResolvedPeerPolicy {
            address,
            interface: None,
            import_policy: None,
            export_policy: Some(next.clone()),
        })
        .collect::<Vec<_>>();
    manager
        .apply_resolved_policy_snapshot(targets)
        .await
        .expect("per-client-best cohort must commit through the batched seam");
    assert_eq!(installs.load(Ordering::SeqCst), 2);

    drop(manager);
    assert_eq!(
        rib.await.unwrap(),
        vec!["batch"],
        "no statically-dead prestage command may reach the RIB"
    );
}

/// The attention-time budget still bounds a genuinely stalled session: a
/// peer that never acknowledges within the budget fails the apply with the
/// same timed-out error as before, rather than hanging the actor.
#[tokio::test(start_paused = true)]
async fn cohort_hot_apply_budget_still_bounds_a_stalled_session() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let first = IpAddr::V4(Ipv4Addr::new(10, 37, 3, 1));
    let second = IpAddr::V4(Ipv4Addr::new(10, 37, 3, 2));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(8);
    let rib = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::PrepareExportPolicyDestination { reply, .. } = update {
                let _ = reply.send(Err("test: prestage skipped".to_string()));
            }
        }
    });

    let (_command_tx, command_rx) = mpsc::channel(16);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let installs = Arc::new(AtomicUsize::new(0));
    for peer in [first, second] {
        insert_test_managed_peer(
            &mut manager,
            peer,
            busy_established_export_session(peer, Duration::from_secs(30), Arc::clone(&installs)),
            false,
        );
    }
    let next = deny_policy_chain();
    let targets = [first, second]
        .into_iter()
        .map(|address| ResolvedPeerPolicy {
            address,
            interface: None,
            import_policy: None,
            export_policy: Some(next.clone()),
        })
        .collect::<Vec<_>>();
    let error = manager
        .apply_resolved_policy_snapshot(targets)
        .await
        .expect_err("a stalled session must still fail the apply within its budget");
    assert!(
        error.contains("update_export_policy timed out"),
        "budget exhaustion must surface as the timed-out command error: {error}"
    );

    drop(manager);
    rib.await.unwrap();
}
