//! `bgp_peer_manager_operator_query_wait_seconds{seam}`: an operator read's
//! send-to-service wait, labelled by the current or latest completed command's policy marker.

use super::cohort_budgets::cohort_session_with_import_stats;
use super::*;

use rustbgpd_api::peer_types::{PeerManagerOperatorQuery, ResolvedPeerPolicy};

/// Sample count, sample sum, and `(upper_bound, cumulative_count)` buckets of
/// one seam series.
fn wait_series(metrics: &BgpMetrics, seam: &str) -> (u64, f64, Vec<(f64, u64)>) {
    metrics
        .registry()
        .gather()
        .into_iter()
        .find(|family| family.name() == "bgp_peer_manager_operator_query_wait_seconds")
        .expect("operator-read wait family is registered")
        .get_metric()
        .iter()
        .find(|metric| {
            metric
                .get_label()
                .iter()
                .any(|label| label.name() == "seam" && label.value() == seam)
        })
        .map_or_else(
            || panic!("seam {seam} is pre-registered"),
            |metric| {
                let histogram = metric.get_histogram();
                (
                    histogram.get_sample_count(),
                    histogram.get_sample_sum(),
                    histogram
                        .get_bucket()
                        .iter()
                        .map(|bucket| (bucket.upper_bound(), bucket.cumulative_count()))
                        .collect(),
                )
            },
        )
}

/// Cumulative count at the 2 s caller-budget edge: the samples at or under
/// budget, so the over-budget share is a subtraction.
fn within_two_seconds(buckets: &[(f64, u64)]) -> u64 {
    // The edge is registered as the literal `2.0`, so its bit pattern is an
    // exact key; no float tolerance is involved.
    buckets
        .iter()
        .find(|(upper, _)| upper.to_bits() == 2.0_f64.to_bits())
        .map(|(_, count)| *count)
        .expect("2 s is an exact bucket edge")
}

fn manager_with_operator_lane(
    command_rx: mpsc::Receiver<PeerManagerCommand>,
    operator_rx: mpsc::Receiver<EnqueuedOperatorQuery>,
    rib_tx: mpsc::Sender<RibUpdate>,
) -> (PeerManager, BgpMetrics) {
    let metrics = BgpMetrics::new();
    let manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics.clone(),
        rib_tx,
        None,
    )
    .with_operator_queries(operator_rx);
    (manager, metrics)
}

fn export_targets(peers: &[IpAddr], next: &PolicyChain) -> Vec<ResolvedPeerPolicy> {
    peers
        .iter()
        .map(|&address| ResolvedPeerPolicy {
            address,
            interface: None,
            import_policy: None,
            export_policy: Some(next.clone()),
        })
        .collect()
}

/// Stub RIB for a cohort reload: prestage succeeds, the cohort reply is
/// `cohort`, and the rollback batch (if the cohort was rejected) is held
/// after signalling `held` until `release` fires.
fn rib_with_cohort_outcome(
    mut rib_rx: mpsc::Receiver<RibUpdate>,
    cohort: Result<rustbgpd_rib::ExportPolicyCohortOutcome, String>,
    held: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut cohort = Some(cohort);
        let mut held = Some(held);
        let mut release = Some(release);
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::PrepareExportPolicyDestination { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                RibUpdate::ReplacePeerExportPolicies { reply, .. } => {
                    let outcome = cohort.take().expect("one cohort transition");
                    if outcome.is_ok() {
                        if let Some(held) = held.take() {
                            let _ = held.send(());
                        }
                        let release = release.take();
                        tokio::spawn(async move {
                            if let Some(release) = release {
                                let _ = release.await;
                            }
                            let _ = reply.send(outcome);
                        });
                    } else {
                        let _ = reply.send(outcome);
                    }
                }
                RibUpdate::RestorePeerExportPoliciesAuthoritatively {
                    replacements,
                    reply,
                } => {
                    if let Some(held) = held.take() {
                        let _ = held.send(());
                    }
                    if let Some(release) = release.take() {
                        let _ = release.await;
                    }
                    let _ = reply.send(Ok(replacements
                        .iter()
                        .map(
                            |replacement| rustbgpd_rib::PeerExportPolicyRestoreReceipt::Restored {
                                peer: replacement.peer,
                            },
                        )
                        .collect()));
                }
                _ => {}
            }
        }
    })
}

/// A read serviced by the idle normal loop lands in `unfenced` with a wait
/// of (virtually) zero; no transaction seam records a sample.
#[tokio::test(start_paused = true)]
async fn idle_loop_read_is_timed_as_unfenced() {
    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(8);
    let (command_tx, command_rx) = mpsc::channel(4);
    let (operator_tx, operator_rx) = mpsc::channel(4);
    let (manager, metrics) = manager_with_operator_lane(command_rx, operator_rx, rib_tx);
    let actor = tokio::spawn(manager.run());

    let (reply, response) = oneshot::channel();
    operator_tx
        .send(PeerManagerOperatorQuery::ListPeers { reply }.into())
        .await
        .unwrap();
    assert!(response.await.unwrap().is_empty());

    let (count, sum, buckets) = wait_series(&metrics, "unfenced");
    assert_eq!(count, 1, "the idle loop records the read it served");
    assert!(sum < 0.001, "idle service is immediate, got {sum}s");
    assert_eq!(within_two_seconds(&buckets), 1);
    for seam in [
        "prestage",
        "forward_transition",
        "commit_batches",
        "rollback",
    ] {
        assert_eq!(wait_series(&metrics, seam).0, 0, "{seam} stays empty");
    }

    drop(command_tx);
    tokio::time::timeout(Duration::from_secs(5), actor)
        .await
        .expect("the actor exits once the command lane closes")
        .unwrap();
}

/// Ordinary and internal commands cannot erase a named phase while an older
/// stamped send is still waiting for channel admission or actor service.
#[tokio::test(start_paused = true)]
async fn ordinary_commands_preserve_the_last_completed_policy_seam() {
    for internal in [false, true] {
        let (rib_tx, _rib_rx) = mpsc::channel(4);
        let (command_tx, command_rx) = mpsc::channel(4);
        let (operator_tx, operator_rx) = mpsc::channel(4);
        let (internal_tx, internal_rx) = mpsc::channel(4);
        let (mut manager, metrics) = manager_with_operator_lane(command_rx, operator_rx, rib_tx);
        manager.internal_rx = Some(internal_rx);
        let config = Box::new(manager.current_config.clone());

        let (reply, response) = oneshot::channel();
        let queued = EnqueuedOperatorQuery::from(PeerManagerOperatorQuery::ListPeers { reply });
        manager.operator_read_seam = OperatorReadSeam::Rollback;
        tokio::time::advance(Duration::from_secs(3)).await;
        manager.finish_operator_seam();
        let actor = tokio::spawn(manager.run());

        let (reply, marker) = oneshot::channel();
        if internal {
            internal_tx
                .send(InternalCommand::ReplaceConfigSnapshot {
                    config,
                    ack: Some(reply),
                })
                .await
                .unwrap();
        } else {
            command_tx
                .send(PeerManagerCommand::Ping { reply })
                .await
                .unwrap();
        }
        marker.await.unwrap();
        operator_tx.send(queued).await.unwrap();
        assert!(response.await.unwrap().is_empty());
        assert_eq!(wait_series(&metrics, "rollback").0, 1);
        assert_eq!(within_two_seconds(&wait_series(&metrics, "rollback").2), 0);

        let (reply, response) = oneshot::channel();
        operator_tx
            .send(PeerManagerOperatorQuery::ListPeers { reply }.into())
            .await
            .unwrap();
        assert!(response.await.unwrap().is_empty());
        assert_eq!(wait_series(&metrics, "unfenced").0, 1);
        drop(command_tx);
        actor.await.unwrap();
    }
}

/// A new unmarked admitting wait must retain the policy seam that held an
/// older read, while a read sent after that policy command remains unfenced.
#[tokio::test(start_paused = true)]
async fn unmarked_refresh_wait_preserves_the_completed_policy_seam() {
    let peer = IpAddr::V4(Ipv4Addr::new(10, 44, 0, 1));
    let (rib_tx, mut rib_rx) = mpsc::channel(4);
    let (command_tx, command_rx) = mpsc::channel(4);
    let (operator_tx, operator_rx) = mpsc::channel(4);
    let (mut manager, metrics) = manager_with_operator_lane(command_rx, operator_rx, rib_tx);
    insert_test_managed_peer(
        &mut manager,
        peer,
        acking_policy_handle(peer, SessionState::Established),
        false,
    );
    let (reply, response) = oneshot::channel();
    let queued = EnqueuedOperatorQuery::from(PeerManagerOperatorQuery::HasPeerAddress {
        address: peer,
        reply,
    });
    manager.operator_read_seam = OperatorReadSeam::Rollback;
    tokio::time::advance(Duration::from_secs(3)).await;
    manager.finish_operator_seam();
    let actor = tokio::spawn(manager.run());
    let (reply, refreshed) = oneshot::channel();
    command_tx
        .send(PeerManagerCommand::RefreshOutbound {
            peer: key(peer),
            reply,
        })
        .await
        .unwrap();
    let RibUpdate::RefreshPeerOutbound { reply: held, .. } = rib_rx.recv().await.unwrap() else {
        panic!("refresh must hold its RIB acknowledgement before reads arrive");
    };
    operator_tx.send(queued).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), response)
            .await
            .expect("the read must be admitted while refresh acknowledgement stays held")
            .unwrap()
    );
    let (count, sum, buckets) = wait_series(&metrics, "rollback");
    assert_eq!(
        count, 1,
        "an unmarked wait retains the seam that held this read"
    );
    assert!(sum >= 3.0);
    assert_eq!(within_two_seconds(&buckets), 0);
    assert_eq!(wait_series(&metrics, "unfenced").0, 0);

    let (reply, response) = oneshot::channel();
    operator_tx
        .send(
            PeerManagerOperatorQuery::HasPeerAddress {
                address: peer,
                reply,
            }
            .into(),
        )
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), response)
            .await
            .expect("the read must be admitted while refresh acknowledgement stays held")
            .unwrap()
    );
    assert_eq!(wait_series(&metrics, "unfenced").0, 1);
    held.send(Ok(())).unwrap();
    refreshed.await.unwrap().unwrap();
    drop(command_tx);
    actor.await.unwrap();
}

/// An import-presence preflight can reject before any destination prestage
/// or commit. Reads waiting on its retained-route proof still get a phase.
#[tokio::test(start_paused = true)]
async fn rejected_preflight_read_is_labelled_prestage() {
    let peer = IpAddr::V4(Ipv4Addr::new(10, 43, 0, 1));
    let (rib_tx, mut rib_rx) = mpsc::channel(4);
    let (command_tx, command_rx) = mpsc::channel(4);
    let (operator_tx, operator_rx) = mpsc::channel(4);
    let (mut manager, metrics) = manager_with_operator_lane(command_rx, operator_rx, rib_tx);
    insert_test_managed_peer(
        &mut manager,
        peer,
        acking_policy_handle(peer, SessionState::Idle),
        false,
    );
    manager.peers.get_mut(&key(peer)).unwrap().import_policy = Some(
        crate::config::reserved_rfc8212_deny_chain(crate::config::RFC8212_MISSING_IMPORT_POLICY),
    );
    let actor = tokio::spawn(manager.run());
    let (reply, applied) = oneshot::channel();
    command_tx
        .send(PeerManagerCommand::ApplyResolvedPolicySnapshot {
            targets: vec![ResolvedPeerPolicy {
                address: peer,
                interface: None,
                import_policy: Some(deny_policy_chain()),
                export_policy: None,
            }],
            reply,
        })
        .await
        .unwrap();
    let RibUpdate::QueryPeerRetainedStale { reply: held, .. } = rib_rx.recv().await.unwrap() else {
        panic!("preflight must ask for retained routes before applying policy");
    };
    let (reply, response) = oneshot::channel();
    operator_tx
        .send(PeerManagerOperatorQuery::ListPeers { reply }.into())
        .await
        .unwrap();
    tokio::time::advance(Duration::from_secs(3)).await;
    held.send(1).unwrap();
    assert!(applied.await.unwrap().is_err());
    assert_eq!(response.await.unwrap().len(), 1);
    let (count, sum, buckets) = wait_series(&metrics, "prestage");
    assert_eq!(
        count, 1,
        "a rejected preflight retains its preparation phase"
    );
    assert!(sum >= 3.0);
    assert_eq!(within_two_seconds(&buckets), 0);
    assert_eq!(wait_series(&metrics, "unfenced").0, 0);
    assert!(
        rib_rx.try_recv().is_err(),
        "preflight must not mutate the RIB"
    );
    drop(command_tx);
    actor.await.unwrap();
}

/// A read admitted while the forward reload owner awaits the held cohort RIB
/// reply is served inside that wait and attributed to `forward_transition`.
#[tokio::test(start_paused = true)]
async fn read_admitted_during_the_cohort_transition_is_labelled_forward_transition() {
    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 39, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 39, 0, 2)),
    ];
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(8);
    let (held_tx, held_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let rib = rib_with_cohort_outcome(
        rib_rx,
        Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed),
        held_tx,
        release_rx,
    );
    let (_command_tx, command_rx) = mpsc::channel(4);
    let (operator_tx, operator_rx) = mpsc::channel(4);
    let (mut manager, metrics) = manager_with_operator_lane(command_rx, operator_rx, rib_tx);
    let installs = Arc::new(AtomicUsize::new(0));
    for peer in peers {
        insert_test_managed_peer(
            &mut manager,
            peer,
            cohort_session_with_import_stats(peer, Arc::clone(&installs), false),
            false,
        );
    }
    let targets = export_targets(&peers, &deny_policy_chain());
    let reload = tokio::spawn(async move {
        let result = manager
            .apply_resolved_policy_snapshot_with_prestage_reads(
                targets,
                false,
                OperatorReadAdmission::Served,
            )
            .await;
        (manager, result)
    });

    held_rx.await.unwrap();
    let (reply, response) = oneshot::channel();
    operator_tx
        .send(PeerManagerOperatorQuery::ListPeers { reply }.into())
        .await
        .unwrap();
    let infos = tokio::time::timeout(Duration::from_secs(1), response)
        .await
        .expect("the read is admitted while the cohort reply is held")
        .unwrap();
    assert_eq!(infos.len(), 2);

    let (count, _, buckets) = wait_series(&metrics, "forward_transition");
    assert_eq!(
        count, 1,
        "the admitted read is attributed to the transition wait"
    );
    assert_eq!(
        within_two_seconds(&buckets),
        1,
        "served within the caller budget"
    );
    assert_eq!(wait_series(&metrics, "unfenced").0, 0);
    assert_eq!(wait_series(&metrics, "prestage").0, 0);

    release_tx.send(()).unwrap();
    let (mut manager, result) = reload.await.unwrap();
    result.expect("the cohort commits once released");
    for (_, managed) in manager.peers.drain() {
        managed.handle.shutdown().await.unwrap().unwrap();
    }
    drop(manager);
    rib.await.unwrap();
}

/// A read that arrives while a rejected reload's rollback fences the lane is
/// drained only after the transaction returns to the run loop. Its wait is
/// still measured from the send, attributed to `rollback`, and lands above
/// the 2 s caller-budget edge, so the over-budget share is a bucket
/// subtraction rather than an estimate.
#[tokio::test(start_paused = true)]
async fn read_fenced_by_rollback_is_timed_when_drained_after_release() {
    const FENCED_FOR: Duration = Duration::from_secs(3);

    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 40, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 40, 0, 2)),
    ];
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(8);
    let (held_tx, held_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let rib = rib_with_cohort_outcome(
        rib_rx,
        Err("test: cohort rejected".to_string()),
        held_tx,
        release_rx,
    );
    let (command_tx, command_rx) = mpsc::channel(4);
    let (operator_tx, operator_rx) = mpsc::channel(4);
    let (mut manager, metrics) = manager_with_operator_lane(command_rx, operator_rx, rib_tx);
    let installs = Arc::new(AtomicUsize::new(0));
    for peer in peers {
        insert_test_managed_peer(
            &mut manager,
            peer,
            cohort_session_with_import_stats(peer, Arc::clone(&installs), false),
            false,
        );
    }
    let actor = tokio::spawn(manager.run());

    let (reply, apply_response) = oneshot::channel();
    command_tx
        .send(PeerManagerCommand::ApplyResolvedPolicySnapshot {
            targets: export_targets(&peers, &deny_policy_chain()),
            reply,
        })
        .await
        .unwrap();

    // The rollback batch is now held in the RIB; the operator lane is fenced.
    held_rx.await.unwrap();
    let (reply, response) = oneshot::channel();
    operator_tx
        .send(PeerManagerOperatorQuery::ListPeers { reply }.into())
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), response)
            .await
            .is_err(),
        "the caller times out and drops its reply receiver while fenced"
    );
    tokio::time::sleep(FENCED_FOR.checked_sub(Duration::from_secs(2)).unwrap()).await;
    assert!(
        wait_series(&metrics, "rollback").0 == 0 && wait_series(&metrics, "unfenced").0 == 0,
        "nothing is observed while the read is still fenced"
    );
    release_tx.send(()).unwrap();

    assert!(
        apply_response.await.unwrap().is_err(),
        "the reload was rejected"
    );
    // A later read proves the earlier canceled query was drained in FIFO order.
    let (reply, response) = oneshot::channel();
    operator_tx
        .send(PeerManagerOperatorQuery::ListPeers { reply }.into())
        .await
        .unwrap();
    assert_eq!(response.await.unwrap().len(), 2);

    let (count, sum, buckets) = wait_series(&metrics, "rollback");
    assert_eq!(
        count, 1,
        "the drained read is attributed to the rollback that held it"
    );
    assert!(
        sum >= FENCED_FOR.as_secs_f64(),
        "wait covers the fenced time, got {sum}s"
    );
    assert_eq!(
        within_two_seconds(&buckets),
        0,
        "the sample is over the 2 s budget edge"
    );
    assert_eq!(wait_series(&metrics, "unfenced").0, 1, "the follow-up read");
    assert_eq!(wait_series(&metrics, "forward_transition").0, 0);

    drop(command_tx);
    tokio::time::timeout(Duration::from_secs(5), actor)
        .await
        .expect("the actor exits once the command lane closes")
        .unwrap();
    rib.await.unwrap();
}

/// A read admitted while the forward reload owner awaits a held destination
/// prestage reply is served inside that wait and attributed to `prestage`.
#[tokio::test(start_paused = true)]
async fn read_admitted_during_prestage_is_labelled_prestage() {
    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 41, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 41, 0, 2)),
    ];
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(8);
    let (held_tx, held_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let rib = tokio::spawn(async move {
        let mut held = Some(held_tx);
        let mut release = Some(release_rx);
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::PrepareExportPolicyDestination { reply, .. } => {
                    if let Some(held) = held.take() {
                        let _ = held.send(());
                    }
                    let release = release.take();
                    tokio::spawn(async move {
                        if let Some(release) = release {
                            let _ = release.await;
                        }
                        let _ = reply.send(Ok(()));
                    });
                }
                RibUpdate::ReplacePeerExportPolicies { reply, .. } => {
                    let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
                }
                _ => {}
            }
        }
    });
    let (_command_tx, command_rx) = mpsc::channel(4);
    let (operator_tx, operator_rx) = mpsc::channel(4);
    let (mut manager, metrics) = manager_with_operator_lane(command_rx, operator_rx, rib_tx);
    let installs = Arc::new(AtomicUsize::new(0));
    for peer in peers {
        insert_test_managed_peer(
            &mut manager,
            peer,
            cohort_session_with_import_stats(peer, Arc::clone(&installs), false),
            false,
        );
    }
    let targets = export_targets(&peers, &deny_policy_chain());
    let reload = tokio::spawn(async move {
        let result = manager
            .apply_resolved_policy_snapshot_with_prestage_reads(
                targets,
                false,
                OperatorReadAdmission::Served,
            )
            .await;
        (manager, result)
    });

    // The prestage reply is held: no session has a new chain yet.
    held_rx.await.unwrap();
    assert_eq!(installs.load(Ordering::SeqCst), 0);
    let (reply, response) = oneshot::channel();
    operator_tx
        .send(PeerManagerOperatorQuery::ListPeers { reply }.into())
        .await
        .unwrap();
    let infos = tokio::time::timeout(Duration::from_secs(1), response)
        .await
        .expect("the read is admitted while the prestage reply is held")
        .unwrap();
    assert_eq!(infos.len(), 2);

    let (count, _, buckets) = wait_series(&metrics, "prestage");
    assert_eq!(
        count, 1,
        "the admitted read is attributed to the prestage wait"
    );
    assert_eq!(
        within_two_seconds(&buckets),
        1,
        "served within the caller budget"
    );
    assert_eq!(wait_series(&metrics, "unfenced").0, 0);
    assert_eq!(wait_series(&metrics, "forward_transition").0, 0);

    release_tx.send(()).unwrap();
    let (mut manager, result) = reload.await.unwrap();
    result.expect("the cohort commits once the prestage reply is released");
    for (_, managed) in manager.peers.drain() {
        managed.handle.shutdown().await.unwrap().unwrap();
    }
    drop(manager);
    rib.await.unwrap();
}

/// A single-target reload runs the authoritative per-peer walk, which keeps
/// the operator lane fenced. A read that arrives while the walk's RIB reply
/// is held is drained only after the transaction returns to the run loop;
/// its wait covers the fenced time and is attributed to `commit_batches`.
#[tokio::test(start_paused = true)]
async fn read_fenced_by_the_authoritative_walk_is_timed_when_drained_after_release() {
    const FENCED_FOR: Duration = Duration::from_secs(3);

    let peer = IpAddr::V4(Ipv4Addr::new(10, 42, 0, 1));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(8);
    let (held_tx, held_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let rib = tokio::spawn(async move {
        let mut held = Some(held_tx);
        let mut release = Some(release_rx);
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                if let Some(held) = held.take() {
                    let _ = held.send(());
                }
                if let Some(release) = release.take() {
                    let _ = release.await;
                }
                let _ = reply.send(Ok(()));
            }
        }
    });
    let (command_tx, command_rx) = mpsc::channel(4);
    let (operator_tx, operator_rx) = mpsc::channel(4);
    let (mut manager, metrics) = manager_with_operator_lane(command_rx, operator_rx, rib_tx);
    let installs = Arc::new(AtomicUsize::new(0));
    insert_test_managed_peer(
        &mut manager,
        peer,
        cohort_session_with_import_stats(peer, Arc::clone(&installs), false),
        false,
    );
    let actor = tokio::spawn(manager.run());

    let (reply, apply_response) = oneshot::channel();
    command_tx
        .send(PeerManagerCommand::ApplyResolvedPolicySnapshot {
            targets: export_targets(&[peer], &deny_policy_chain()),
            reply,
        })
        .await
        .unwrap();

    // The walk's RIB reply is held; the operator lane is fenced.
    held_rx.await.unwrap();
    assert_eq!(installs.load(Ordering::SeqCst), 1);
    let (reply, response) = oneshot::channel();
    operator_tx
        .send(PeerManagerOperatorQuery::ListPeers { reply }.into())
        .await
        .unwrap();
    tokio::time::sleep(FENCED_FOR).await;
    assert!(
        wait_series(&metrics, "commit_batches").0 == 0 && wait_series(&metrics, "unfenced").0 == 0,
        "nothing is observed while the read is still fenced"
    );
    release_tx.send(()).unwrap();

    let infos = tokio::time::timeout(Duration::from_secs(30), response)
        .await
        .expect("the fenced read is drained once the walk releases the actor")
        .unwrap();
    assert_eq!(infos.len(), 1);
    apply_response
        .await
        .unwrap()
        .expect("the single-target walk commits once released");

    let (count, sum, buckets) = wait_series(&metrics, "commit_batches");
    assert_eq!(
        count, 1,
        "the drained read is attributed to the walk that held it"
    );
    assert!(
        sum >= FENCED_FOR.as_secs_f64(),
        "wait covers the fenced time, got {sum}s"
    );
    assert_eq!(
        within_two_seconds(&buckets),
        0,
        "the sample is over the 2 s budget edge"
    );
    assert_eq!(wait_series(&metrics, "unfenced").0, 0);
    assert_eq!(wait_series(&metrics, "forward_transition").0, 0);

    drop(command_tx);
    tokio::time::timeout(Duration::from_secs(5), actor)
        .await
        .expect("the actor exits once the command lane closes")
        .unwrap();
    rib.await.unwrap();
}
