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

/// The authoritative forward walk's RIB commands ride the RIB manager's
/// primary lane, which is not polled while route chunks pend, and each one
/// performs a full Loc-RIB distribution pass. A single peer's reply therefore
/// legitimately outlives `RIB_REPLY_TIMEOUT` under load, and that must not
/// reject the generation.
///
/// LOAD-BEARING: restoring a fresh per-peer `RIB_REPLY_TIMEOUT` on the walk
/// makes this apply fail with `policy_rib_apply_rejected` instead of `Ok`.
/// Coverage that the batched cohort path cannot provide: a single target can
/// never form a cohort, so this exercises the fallback the fast path skips.
#[tokio::test(start_paused = true)]
async fn forward_walk_rib_reply_may_outlive_the_single_command_deadline() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let peer = IpAddr::V4(Ipv4Addr::new(10, 41, 0, 1));
    let attempts = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel(16);
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
    insert_test_managed_peer(
        &mut manager,
        peer,
        established_export_policy_test_session(peer, attempts, None),
        false,
    );

    // One target can never reach the two-member cohort, so this snapshot takes
    // the wholly authoritative walk.
    let apply = manager.apply_resolved_policy_snapshot(vec![ResolvedPeerPolicy {
        address: peer,
        interface: None,
        import_policy: None,
        export_policy: Some(deny_policy_chain()),
    }]);
    let rib = async {
        let RibUpdate::ReplacePeerExportPolicy {
            peer: target,
            reply,
            ..
        } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected the forward remainder command");
        };
        assert_eq!(target, peer);
        tokio::time::sleep(RIB_REPLY_TIMEOUT + Duration::from_secs(6)).await;
        reply.send(Ok(())).unwrap();
    };
    let (result, ()) = tokio::join!(apply, rib);
    assert!(
        result.is_ok(),
        "an eleven-second forward walk reply must still apply: {result:?}"
    );
    let peer_state = manager.peers.get(&key(peer)).unwrap();
    assert!(!peer_state.pending_export_apply);
    assert!(!peer_state.pending_refresh);
}

/// The walk budget is one absolute deadline for the whole walk, not a fresh
/// one per peer. A fleet-wide fallback whose cumulative RIB time exceeds the
/// budget must still be rejected — otherwise the change above reads as
/// "the walk timeout was removed", and a 1000-peer walk would tolerate hours.
///
/// Every peer here replies well inside a fresh `RIB_BATCH_REPLY_TIMEOUT`, so
/// the rejection can only come from the budget they share.
///
/// LOAD-BEARING: anchoring the deadline inside the per-peer call (or handing
/// each peer its own `RIB_BATCH_REPLY_TIMEOUT`) makes this apply succeed.
#[tokio::test(start_paused = true)]
async fn forward_walk_rib_budget_is_shared_across_the_whole_walk() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    const PEER_COUNT: u8 = 3;
    // Each peer alone fits inside the walk budget; two together exhaust it.
    let per_peer_delay = RIB_BATCH_REPLY_TIMEOUT * 2 / 3;

    let peers = (1..=PEER_COUNT)
        .map(|last| IpAddr::V4(Ipv4Addr::new(10, 41, 1, last)))
        .collect::<Vec<_>>();
    let attempts = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel(16);
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
    for peer in peers.iter().copied() {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(peer, Arc::clone(&attempts), None),
            false,
        );
    }

    // Distinct target chains: no two peers are export-identical, so cohort
    // selection finds no two-member group and the whole fleet walks.
    let apply = manager.apply_resolved_policy_snapshot(
        peers
            .iter()
            .copied()
            .enumerate()
            .map(|(index, address)| ResolvedPeerPolicy {
                address,
                interface: None,
                import_policy: None,
                export_policy: Some(distinct_deny_policy_chain(index)),
            })
            .collect(),
    );
    let drive_rib = async {
        let mut served = 0_usize;
        // The walk stops at the peer that exhausts the shared budget, so only
        // the commands actually issued are answered; the rollback aggregate
        // that follows ends the dialogue.
        loop {
            match rib_rx.recv().await.unwrap() {
                RibUpdate::ReplacePeerExportPolicy { reply, .. } => {
                    served += 1;
                    tokio::time::sleep(per_peer_delay).await;
                    let _ = reply.send(Ok(()));
                }
                RibUpdate::RestorePeerExportPoliciesAuthoritatively {
                    replacements,
                    reply,
                } => {
                    let _ = reply.send(Ok(replacements
                        .iter()
                        .rev()
                        .map(
                            |replacement| rustbgpd_rib::PeerExportPolicyRestoreReceipt::Restored {
                                peer: replacement.peer,
                            },
                        )
                        .collect()));
                    break served;
                }
                _ => panic!("unexpected RIB command during the forward walk"),
            }
        }
    };
    let (result, served) = tokio::time::timeout(RIB_BATCH_REPLY_TIMEOUT * 3, async {
        tokio::join!(apply, drive_rib)
    })
    .await
    .expect("the walk must reject and complete its rollback within the bound");
    assert!(
        per_peer_delay < RIB_BATCH_REPLY_TIMEOUT,
        "every individual reply must fit inside a fresh budget, so only a \
         shared one can reject this walk"
    );
    assert_eq!(
        served, 2,
        "the second reply exhausts the shared budget; the third command must not be issued"
    );
    assert!(
        result
            .as_ref()
            .is_err_and(|error| error.contains("shared policy-walk budget")),
        "a walk whose cumulative RIB time exceeds the budget must still be rejected: {result:?}"
    );
}

/// Session work before the first RIB command cannot spend its lazy budget.
#[tokio::test(start_paused = true)]
async fn forward_walk_rib_budget_starts_after_session_apply() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let peer = IpAddr::V4(Ipv4Addr::new(10, 41, 2, 1));
    let (mut manager, mut rib_rx) = rfc8212_status_manager();
    let (session_tx, mut session_rx) = mpsc::channel(16);
    let session = tokio::spawn(async move {
        while let Some(command) = session_rx.recv().await {
            match command {
                PeerCommand::QueryState { reply } => {
                    let mut state = policy_test_peer_state(peer, SessionState::Established);
                    state.negotiated_session = Some(test_negotiated_session(true));
                    let _ = reply.send(state);
                }
                PeerCommand::UpdateExportPolicy { reply, .. } => {
                    tokio::time::sleep(Duration::from_millis(400)).await;
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::UpdateImportPolicy { reply, .. }
                | PeerCommand::SendRouteRefresh { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                _ => {}
            }
        }
        Ok(())
    });
    insert_test_managed_peer(
        &mut manager,
        peer,
        PeerHandle::from_parts(session_tx, session),
        false,
    );
    manager.peers.get_mut(&key(peer)).unwrap().import_policy = Some(
        crate::config::reserved_rfc8212_deny_chain(crate::config::RFC8212_MISSING_IMPORT_POLICY),
    );
    let apply = manager.apply_resolved_policy_snapshot(vec![ResolvedPeerPolicy {
        address: peer,
        interface: None,
        import_policy: Some(deny_policy_chain()),
        export_policy: Some(deny_policy_chain()),
    }]);
    let rib = async {
        let RibUpdate::ReplacePeerExportPolicy { reply, .. } = rib_rx.recv().await.unwrap() else {
            panic!("expected forward export replacement");
        };
        tokio::time::sleep(
            RIB_BATCH_REPLY_TIMEOUT
                .checked_sub(Duration::from_millis(200))
                .unwrap(),
        )
        .await;
        reply
            .send(Ok(()))
            .expect("session work must not spend the RIB budget");
    };
    let (result, ()) = tokio::join!(apply, rib);
    assert!(
        result.is_ok(),
        "first RIB use must get the whole budget: {result:?}"
    );
}

/// Saturating the primary lane must bound both the read-only preflight and
/// export admission. A canceled send must not become a late forward mutation.
#[tokio::test(start_paused = true)]
async fn forward_walk_rib_budget_bounds_full_channel_admission() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    for retained_proof in [false, true] {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 41, 3, 1));
        let (mut manager, _) = rfc8212_status_manager();
        let (rib_tx, mut rib_rx) = mpsc::channel(1);
        let (marker_reply, _marker_rx) = oneshot::channel();
        rib_tx
            .send(RibUpdate::QueryPeerRetainedStale {
                peer,
                reply: marker_reply,
            })
            .await
            .unwrap();
        manager.rib_tx = rib_tx;
        insert_test_managed_peer(
            &mut manager,
            peer,
            acking_policy_handle(
                peer,
                if retained_proof {
                    SessionState::Idle
                } else {
                    SessionState::Established
                },
            ),
            false,
        );
        if retained_proof {
            manager.peers.get_mut(&key(peer)).unwrap().import_policy =
                Some(crate::config::reserved_rfc8212_deny_chain(
                    crate::config::RFC8212_MISSING_IMPORT_POLICY,
                ));
        }
        let started = tokio::time::Instant::now();
        let result = tokio::time::timeout(
            RIB_BATCH_REPLY_TIMEOUT * 3,
            manager.apply_resolved_policy_snapshot(vec![ResolvedPeerPolicy {
                address: peer,
                interface: None,
                import_policy: retained_proof.then(deny_policy_chain),
                export_policy: Some(deny_policy_chain()),
            }]),
        )
        .await
        .expect("full-channel admission must not park the snapshot forever");
        assert!(result.is_err(), "an unserved RIB cannot commit");
        assert_eq!(
            started.elapsed(),
            RIB_BATCH_REPLY_TIMEOUT * if retained_proof { 1 } else { 2 }
        );
        assert!(matches!(
            rib_rx.recv().await.unwrap(),
            RibUpdate::QueryPeerRetainedStale { .. }
        ));
        if retained_proof {
            assert!(matches!(
                rib_rx.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
        } else {
            let RibUpdate::RestorePeerExportPoliciesAuthoritatively {
                reply,
                replacements,
            } = rib_rx.recv().await.unwrap()
            else {
                panic!("only the detached exact rollback may follow the canceled admission");
            };
            reply
                .send(Ok(replacements
                    .iter()
                    .rev()
                    .map(
                        |replacement| rustbgpd_rib::PeerExportPolicyRestoreReceipt::Restored {
                            peer: replacement.peer,
                        },
                    )
                    .collect()))
                .unwrap();
            assert!(manager.peers.get(&key(peer)).unwrap().pending_export_apply);
        }
    }
}

/// Preflight reports every rejection, so later peers still reach the proof
/// helper after the first timeout. They must not enqueue already-expired work.
#[tokio::test(start_paused = true)]
async fn forward_walk_rib_budget_stops_expired_retained_proofs() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let (mut manager, mut rib_rx) = rfc8212_status_manager();
    let mut targets = Vec::new();
    for last in 1..=3 {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 41, 4, last));
        insert_test_managed_peer(
            &mut manager,
            peer,
            acking_policy_handle(peer, SessionState::Idle),
            false,
        );
        manager.peers.get_mut(&key(peer)).unwrap().import_policy =
            Some(crate::config::reserved_rfc8212_deny_chain(
                crate::config::RFC8212_MISSING_IMPORT_POLICY,
            ));
        targets.push(ResolvedPeerPolicy {
            address: peer,
            interface: None,
            import_policy: Some(deny_policy_chain()),
            export_policy: None,
        });
    }
    let rib = tokio::spawn(async move {
        let mut served = 0;
        while let Some(update) = rib_rx.recv().await {
            let RibUpdate::QueryPeerRetainedStale { reply, .. } = update else {
                panic!("preflight must reject without applying policies");
            };
            served += 1;
            tokio::time::sleep(RIB_BATCH_REPLY_TIMEOUT * 2 / 3).await;
            let _ = reply.send(0);
        }
        served
    });
    let started = tokio::time::Instant::now();
    let result = manager.apply_resolved_policy_snapshot(targets).await;
    assert!(result.is_err());
    assert_eq!(started.elapsed(), RIB_BATCH_REPLY_TIMEOUT);
    drop(manager);
    assert_eq!(
        rib.await.unwrap(),
        2,
        "the expired third proof must not be admitted"
    );
}

/// Session for cohort read tests. A rejected restore leaves its live state
/// Idle with an error; other commands acknowledge immediately.
pub(super) fn cohort_session_with_import_stats(
    addr: IpAddr,
    installs: Arc<AtomicUsize>,
    reject_restore: bool,
) -> PeerHandle {
    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(16);
    let task = tokio::spawn(async move {
        let mut restore_failed = false;
        while let Some(command) = session_rx.recv().await {
            match command {
                PeerCommand::UpdateExportPolicy { policy, reply } => {
                    installs.fetch_add(1, Ordering::SeqCst);
                    restore_failed = reject_restore && policy.is_none();
                    let result = if restore_failed {
                        Err(rustbgpd_transport::PeerCommandError::CommandFailed(
                            "test: session restore rejected".to_string(),
                        ))
                    } else {
                        Ok(())
                    };
                    let _ = reply.send(result);
                }
                PeerCommand::QueryState { reply } => {
                    let mut state = policy_test_peer_state(addr, SessionState::Established);
                    if restore_failed {
                        state.fsm_state = SessionState::Idle;
                        state.last_error = "test: session restore rejected".to_string();
                    }
                    let _ = reply.send(state);
                }
                PeerCommand::QueryImportPolicyTermHits { reply } => {
                    let _ = reply.send(Some(rustbgpd_transport::ImportPolicyTermHits {
                        generation: 1,
                        evals: 0,
                        eval_errors: 0,
                        last_error: None,
                        terms: Vec::new(),
                    }));
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(session_tx, task)
}

/// Stub RIB that holds the cohort reply: signals `held` once the batched
/// replacement arrives and answers `Committed` only after `release` fires.
fn rib_holding_cohort_reply(
    mut rib_rx: mpsc::Receiver<RibUpdate>,
    held: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut held = Some(held);
        let mut release = Some(release);
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::PrepareExportPolicyDestination { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                RibUpdate::ReplacePeerExportPolicies { reply, .. } => {
                    if let Some(held) = held.take() {
                        let _ = held.send(());
                    }
                    let release = release.take();
                    tokio::spawn(async move {
                        if let Some(release) = release {
                            let _ = release.await;
                        }
                        let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
                    });
                }
                _ => {}
            }
        }
    })
}

/// Operator reads admitted while the forward reload awaits the cohort RIB
/// reply: with the RIB still owning the transition (its reply held here),
/// a neighbor snapshot and the fleet import-stats collection both complete
/// on the operator lane instead of waiting behind the transition. Awaiting
/// the reply with the readiness-only helper parks both reads until the
/// held reply is released and fails the bounded expectations below.
#[tokio::test(start_paused = true)]
async fn operator_reads_are_served_while_the_cohort_rib_reply_is_held() {
    use rustbgpd_api::peer_types::{PeerManagerOperatorQuery, ResolvedPeerPolicy};

    let first = IpAddr::V4(Ipv4Addr::new(10, 38, 0, 1));
    let second = IpAddr::V4(Ipv4Addr::new(10, 38, 0, 2));
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(8);
    let (held_tx, held_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let rib = rib_holding_cohort_reply(rib_rx, held_tx, release_rx);

    let (_command_tx, command_rx) = mpsc::channel(16);
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
    let installs = Arc::new(AtomicUsize::new(0));
    for peer in [first, second] {
        insert_test_managed_peer(
            &mut manager,
            peer,
            cohort_session_with_import_stats(peer, Arc::clone(&installs), false),
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

    // The RIB owns the transition: every cohort session already runs the
    // new chain and the reply is held until released below.
    held_rx.await.unwrap();
    assert_eq!(installs.load(Ordering::SeqCst), 2);
    let (reply, response) = oneshot::channel();
    operator_tx
        .send(PeerManagerOperatorQuery::ListPeers { reply }.into())
        .await
        .unwrap();
    let infos = tokio::time::timeout(Duration::from_secs(1), response)
        .await
        .expect("a neighbor snapshot is answered while the cohort RIB reply is awaited")
        .unwrap();
    assert_eq!(infos.len(), 2);
    let (reply, response) = oneshot::channel();
    operator_tx
        .send(
            PeerManagerOperatorQuery::QueryImportPolicyTermHits {
                peer: None,
                deadline: tokio::time::Instant::now() + Duration::from_secs(2),
                reply,
            }
            .into(),
        )
        .await
        .unwrap();
    let rows = tokio::time::timeout(Duration::from_secs(1), response)
        .await
        .expect("the import-stats collection is answered while the cohort RIB reply is awaited")
        .unwrap();
    assert!(
        matches!(rows, SessionQueryOutcome::Reply(ref rows) if rows.len() == 2),
        "{rows:?}"
    );
    assert!(
        !reload.is_finished(),
        "the transaction stays parked on the held reply"
    );

    release_tx.send(()).unwrap();
    let (mut manager, result) = reload.await.unwrap();
    result.expect("the cohort commits once the held reply is released");
    assert_eq!(
        manager.peers.get(&key(first)).unwrap().export_policy,
        Some(next)
    );
    for (_, managed) in manager.peers.drain() {
        managed.handle.shutdown().await.unwrap().unwrap();
    }
    drop(manager);
    rib.await.unwrap();
}

/// Stub RIB that rejects the cohort transition and then holds the rollback
/// aggregate: signals `held` once `RestorePeerExportPoliciesAuthoritatively`
/// arrives and answers ordered `Restored` receipts only after `release`.
fn rib_rejecting_cohort_and_holding_rollback_reply(
    mut rib_rx: mpsc::Receiver<RibUpdate>,
    held: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut held = Some(held);
        let mut release = Some(release);
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::PrepareExportPolicyDestination { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                RibUpdate::ReplacePeerExportPolicies { reply, .. } => {
                    let _ = reply.send(Err("test: cohort transition rejected".to_string()));
                }
                RibUpdate::RestorePeerExportPoliciesAuthoritatively {
                    replacements,
                    reply,
                } => {
                    if let Some(held) = held.take() {
                        let _ = held.send(());
                    }
                    let release = release.take();
                    tokio::spawn(async move {
                        if let Some(release) = release {
                            let _ = release.await;
                        }
                        // Receipts are in rollback execution order, the
                        // reverse of the forward-ordered replacements.
                        let receipts = replacements
                            .iter()
                            .rev()
                            .map(|replacement| {
                                rustbgpd_rib::PeerExportPolicyRestoreReceipt::Restored {
                                    peer: replacement.peer,
                                }
                            })
                            .collect();
                        let _ = reply.send(Ok(receipts));
                    });
                }
                _ => {}
            }
        }
    })
}

/// Operator reads admitted while a rejected reload's rollback awaits its RIB
/// aggregate: with the restore reply held here, a peer-manager snapshot and the
/// fleet import-stats collection both complete on the operator lane instead
/// of waiting up to the two-minute batch budget. A failed session restore is
/// visible in its live snapshot; admission does not imply successful rollback
/// or a common generation. Awaiting the aggregate with a fenced helper parks both
/// reads until the held reply is released and fails the bounded expectations.
#[expect(
    clippy::too_many_lines,
    reason = "the rejected transition, the held rollback aggregate, and the served reads share one fixture"
)]
async fn assert_operator_reads_during_rollback(reject_first_restore: bool) {
    use super::super::policy::PolicySnapshotFailureKind;
    use rustbgpd_api::peer_types::{PeerManagerOperatorQuery, ResolvedPeerPolicy};

    let first = IpAddr::V4(Ipv4Addr::new(10, 39, 0, 1));
    let second = IpAddr::V4(Ipv4Addr::new(10, 39, 0, 2));
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(8);
    let (held_tx, held_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let rib = rib_rejecting_cohort_and_holding_rollback_reply(rib_rx, held_tx, release_rx);

    let (_command_tx, command_rx) = mpsc::channel(16);
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
    let installs = Arc::new(AtomicUsize::new(0));
    for peer in [first, second] {
        insert_test_managed_peer(
            &mut manager,
            peer,
            cohort_session_with_import_stats(
                peer,
                Arc::clone(&installs),
                reject_first_restore && peer == first,
            ),
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

    // The cohort was rejected and both session restores were attempted. The
    // successful restores' aggregate is held even if one session rejected.
    tokio::time::timeout(Duration::from_secs(5), held_rx)
        .await
        .expect("the rollback reaches its RIB aggregate")
        .unwrap();
    assert_eq!(installs.load(Ordering::SeqCst), 4);
    let (reply, response) = oneshot::channel();
    operator_tx
        .send(PeerManagerOperatorQuery::ListPeers { reply }.into())
        .await
        .unwrap();
    let infos = tokio::time::timeout(Duration::from_secs(1), response)
        .await
        .expect("a neighbor snapshot is answered while the rollback RIB reply is awaited")
        .unwrap();
    assert_eq!(infos.len(), 2);
    let first_info = infos.iter().find(|info| info.address == first).unwrap();
    assert_eq!(
        first_info.state,
        if reject_first_restore {
            SessionState::Idle
        } else {
            SessionState::Established
        },
        "the admitted snapshot reports the session's live state"
    );
    assert_eq!(
        first_info.last_error,
        if reject_first_restore {
            "test: session restore rejected"
        } else {
            ""
        }
    );
    let (reply, response) = oneshot::channel();
    operator_tx
        .send(
            PeerManagerOperatorQuery::QueryImportPolicyTermHits {
                peer: None,
                deadline: tokio::time::Instant::now() + Duration::from_secs(2),
                reply,
            }
            .into(),
        )
        .await
        .unwrap();
    let rows = tokio::time::timeout(Duration::from_secs(1), response)
        .await
        .expect("the import-stats collection is answered while the rollback RIB reply is awaited")
        .unwrap();
    assert!(
        matches!(rows, SessionQueryOutcome::Reply(ref rows) if rows.len() == 2),
        "{rows:?}"
    );
    assert!(
        !reload.is_finished(),
        "the transaction stays parked on the held rollback reply"
    );

    release_tx.send(()).unwrap();
    let (mut manager, result) = reload.await.unwrap();
    let failure = result.expect_err("the rejected cohort transition compensates");
    assert_eq!(
        failure.kind,
        if reject_first_restore {
            PolicySnapshotFailureKind::CompensationAmbiguous
        } else {
            PolicySnapshotFailureKind::FullyCompensated
        },
        "{}",
        failure.message
    );
    for peer in [first, second] {
        let restored = manager.peers.get(&key(peer)).unwrap();
        assert_eq!(
            (
                restored.export_policy.as_ref(),
                restored.pending_export_apply
            ),
            if reject_first_restore && peer == first {
                (Some(&next), true)
            } else {
                (None, false)
            },
            "{peer} keeps the acknowledged policy and any outstanding restore intent"
        );
    }
    for (_, managed) in manager.peers.drain() {
        managed.handle.shutdown().await.unwrap().unwrap();
    }
    drop(manager);
    rib.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn operator_reads_are_served_while_the_rollback_rib_reply_is_held() {
    assert_operator_reads_during_rollback(false).await;
}

#[tokio::test(start_paused = true)]
async fn operator_reads_report_a_failed_session_restore_while_rollback_is_held() {
    assert_operator_reads_during_rollback(true).await;
}
