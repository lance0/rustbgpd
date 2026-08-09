use super::*;

async fn assert_session_state_query_count(counter: &AtomicUsize, expected: usize) {
    for _ in 0..3 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        counter.load(Ordering::SeqCst),
        expected,
        "expired readiness requests must not query every session"
    );
}

/// Session model for the LAN-462 import-tolerant cohort tests: acks import,
/// export, refresh, and state queries while counting each, tracks the live
/// import chain, and optionally fails one export attempt.
#[derive(Default)]
struct CohortSessionCounters {
    import_installs: AtomicUsize,
    export_installs: AtomicUsize,
    refreshes: AtomicUsize,
    live_import: Mutex<Option<rustbgpd_policy::PolicyChain>>,
}

fn import_tolerant_cohort_test_session(
    addr: IpAddr,
    counters: Arc<CohortSessionCounters>,
    fail_export_on_attempt: Option<usize>,
) -> PeerHandle {
    import_tolerant_cohort_test_session_with_states(addr, counters, fail_export_on_attempt, None)
}

/// Like `import_tolerant_cohort_test_session`, but the session answers
/// Established only for the first `established_queries` state queries and
/// Connect afterwards (`None` = always Established), so tests can model a
/// session that drops out of Established mid-transaction.
fn import_tolerant_cohort_test_session_with_states(
    addr: IpAddr,
    counters: Arc<CohortSessionCounters>,
    fail_export_on_attempt: Option<usize>,
    established_queries: Option<usize>,
) -> PeerHandle {
    use rustbgpd_transport::PeerCommand;

    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(16);
    let task = tokio::spawn(async move {
        let mut state_queries = 0usize;
        while let Some(command) = session_rx.recv().await {
            match command {
                PeerCommand::UpdateImportPolicy { policy, reply } => {
                    counters.import_installs.fetch_add(1, Ordering::SeqCst);
                    *counters.live_import.lock().unwrap() = policy;
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::UpdateExportPolicy { reply, .. } => {
                    let attempt = counters.export_installs.fetch_add(1, Ordering::SeqCst) + 1;
                    let result = if fail_export_on_attempt == Some(attempt) {
                        Err(rustbgpd_transport::PeerCommandError::CommandFailed(
                            "injected export-policy apply failure".to_string(),
                        ))
                    } else {
                        Ok(())
                    };
                    let _ = reply.send(result);
                }
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    counters.refreshes.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::QueryState { reply } => {
                    state_queries += 1;
                    let state = if established_queries.is_some_and(|limit| state_queries > limit) {
                        SessionState::Connect
                    } else {
                        SessionState::Established
                    };
                    let _ = reply.send(policy_test_peer_state(addr, state));
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(session_tx, task)
}

/// LAN-462: a reload that moves import AND export chains must still engage the
/// batched cohort (previously the import delta disqualified every member and
/// the whole fleet fell onto the per-peer authoritative path), and each
/// import-moving member's Route Refresh must fire exactly once, only after the
/// cohort RIB commit acknowledges. Import-unchanged members get no refresh.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the regression pins partition engagement, deferred-refresh ordering, and the unchanged-member exemption together"
)]
async fn import_tolerant_cohort_defers_refresh_past_committed_batch() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let first = IpAddr::V4(Ipv4Addr::new(10, 42, 0, 1));
    let second = IpAddr::V4(Ipv4Addr::new(10, 42, 0, 2));
    let export_only = IpAddr::V4(Ipv4Addr::new(10, 42, 0, 3));
    let peers = [first, second, export_only];
    let counters: Vec<Arc<CohortSessionCounters>> = peers
        .iter()
        .map(|_| Arc::new(CohortSessionCounters::default()))
        .collect();
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
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
    for (peer, counter) in peers.iter().zip(&counters) {
        insert_test_managed_peer(
            &mut manager,
            *peer,
            import_tolerant_cohort_test_session(*peer, Arc::clone(counter), None),
            false,
        );
    }

    let shared_export = deny_policy_chain();
    let changed_import = validation_policy_chain(ImportValidationDependency::Rpki);
    let targets = vec![
        ResolvedPeerPolicy {
            address: first,
            interface: None,
            import_policy: Some(changed_import.clone()),
            export_policy: Some(shared_export.clone()),
        },
        ResolvedPeerPolicy {
            address: second,
            interface: None,
            import_policy: Some(changed_import.clone()),
            export_policy: Some(shared_export.clone()),
        },
        ResolvedPeerPolicy {
            address: export_only,
            interface: None,
            import_policy: None,
            export_policy: Some(shared_export.clone()),
        },
    ];
    let apply = manager.apply_resolved_policy_snapshot(targets);
    let refresh_watch = counters.clone();
    let drive_rib = async {
        skip_destination_prestage(&mut rib_rx).await;
        let RibUpdate::ReplacePeerExportPolicies {
            replacements,
            reply,
        } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected cohort RIB command");
        };
        assert_eq!(
            replacements.len(),
            peers.len(),
            "the partition must cover the whole fleet despite import deltas"
        );
        assert!(
            refresh_watch
                .iter()
                .all(|counter| counter.refreshes.load(Ordering::SeqCst) == 0),
            "no Route Refresh may fire before the cohort RIB commit acknowledges"
        );
        reply
            .send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed))
            .unwrap();
    };
    let (result, ()) = tokio::join!(apply, drive_rib);
    let priors = result.expect("import+export cohort snapshot must commit");

    assert_eq!(priors.len(), peers.len());
    assert!(
        matches!(rib_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "no per-peer authoritative RIB command may run after the committed batch"
    );
    for (peer, counter) in peers.iter().zip(&counters) {
        let expected_refreshes = usize::from(*peer != export_only);
        assert_eq!(
            counter.refreshes.load(Ordering::SeqCst),
            expected_refreshes,
            "deferred refresh fires exactly once per import-moving member ({peer})"
        );
        assert_eq!(
            counter.import_installs.load(Ordering::SeqCst),
            expected_refreshes,
            "import hot-apply runs only for import-moving members ({peer})"
        );
        assert_eq!(counter.export_installs.load(Ordering::SeqCst), 1);
        let peer_state = manager.peers.get(&key(*peer)).unwrap();
        assert_eq!(peer_state.export_policy, Some(shared_export.clone()));
        assert!(!peer_state.pending_refresh);
        assert!(!peer_state.pending_export_apply);
    }
    assert_eq!(
        manager.peers.get(&key(first)).unwrap().import_policy,
        Some(changed_import.clone())
    );
    assert_eq!(
        manager.peers.get(&key(second)).unwrap().import_policy,
        Some(changed_import)
    );
    assert_eq!(
        manager.peers.get(&key(export_only)).unwrap().import_policy,
        None
    );

    for peer in peers {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
}

/// LAN-462: when the RIB batch hands the cohort back for the per-peer
/// authoritative RIB seam (`RequiresAuthoritativePerPeerApply`), the deferred
/// refresh still fires exactly once per member — after the handoff completes —
/// with no double refresh from the handoff itself.
#[tokio::test]
async fn import_tolerant_cohort_handoff_fires_deferred_refresh_once() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 43, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 43, 0, 2)),
    ];
    let counters: Vec<Arc<CohortSessionCounters>> = peers
        .iter()
        .map(|_| Arc::new(CohortSessionCounters::default()))
        .collect();
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
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
    for (peer, counter) in peers.iter().zip(&counters) {
        insert_test_managed_peer(
            &mut manager,
            *peer,
            import_tolerant_cohort_test_session(*peer, Arc::clone(counter), None),
            false,
        );
    }

    let shared_export = deny_policy_chain();
    let changed_import = validation_policy_chain(ImportValidationDependency::Rpki);
    let apply = manager.apply_resolved_policy_snapshot(
        peers
            .iter()
            .map(|&address| ResolvedPeerPolicy {
                address,
                interface: None,
                import_policy: Some(changed_import.clone()),
                export_policy: Some(shared_export.clone()),
            })
            .collect(),
    );
    let refresh_watch = counters.clone();
    let drive_rib = async {
        skip_destination_prestage(&mut rib_rx).await;
        let RibUpdate::ReplacePeerExportPolicies { reply, .. } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected cohort RIB command");
        };
        reply
            .send(Ok(
                rustbgpd_rib::ExportPolicyCohortOutcome::RequiresAuthoritativePerPeerApply,
            ))
            .unwrap();
        let RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
            replacements,
            reply,
        } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected batched authoritative RIB command");
        };
        assert_eq!(replacements.len(), peers.len());
        assert!(
            refresh_watch
                .iter()
                .all(|counter| counter.refreshes.load(Ordering::SeqCst) == 0),
            "no Route Refresh may fire before the authoritative handoff completes"
        );
        reply.send(Ok(())).unwrap();
    };
    let (result, ()) = tokio::join!(apply, drive_rib);
    result.expect("handoff cohort snapshot must commit");

    for counter in &counters {
        assert_eq!(
            counter.refreshes.load(Ordering::SeqCst),
            1,
            "the deferred refresh fires exactly once per member — no handoff double refresh"
        );
        assert_eq!(counter.import_installs.load(Ordering::SeqCst), 1);
        assert_eq!(counter.export_installs.load(Ordering::SeqCst), 1);
    }
    for peer in peers {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
}

/// LAN-462: a cohort RIB commit failure must restore BOTH chains — the import
/// delta hot-applied during setup and the export chain — and fire no forward
/// refresh (only the rollback's post-reassert refresh), leaving no pending
/// retry intent behind after a clean restore.
#[tokio::test]
async fn import_tolerant_cohort_rib_failure_restores_both_chains() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 44, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 44, 0, 2)),
    ];
    let counters: Vec<Arc<CohortSessionCounters>> = peers
        .iter()
        .map(|_| Arc::new(CohortSessionCounters::default()))
        .collect();
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let rib_task = tokio::spawn(async move {
        let mut singles = Vec::new();
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPolicies { reply, .. } => {
                    let _ = reply.send(Err("injected cohort failure".to_string()));
                }
                RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } => {
                    singles.push(peer);
                    let _ = reply.send(Ok(()));
                }
                _ => {}
            }
        }
        singles
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
    for (peer, counter) in peers.iter().zip(&counters) {
        insert_test_managed_peer(
            &mut manager,
            *peer,
            import_tolerant_cohort_test_session(*peer, Arc::clone(counter), None),
            false,
        );
    }

    let shared_export = deny_policy_chain();
    let changed_import = validation_policy_chain(ImportValidationDependency::Rpki);
    let result = manager
        .apply_resolved_policy_snapshot(
            peers
                .iter()
                .map(|&address| ResolvedPeerPolicy {
                    address,
                    interface: None,
                    import_policy: Some(changed_import.clone()),
                    export_policy: Some(shared_export.clone()),
                })
                .collect(),
        )
        .await;
    assert!(
        result.as_ref().is_err_and(|error| {
            error.contains("failed to update export policy cohort: injected cohort failure")
                && error.contains("already-applied peers restored")
        }),
        "the RIB failure must surface with a successful rollback: {result:?}"
    );

    for (peer, counter) in peers.iter().zip(&counters) {
        assert_eq!(
            counter.import_installs.load(Ordering::SeqCst),
            2,
            "the session must observe the forward install and the rollback reassert ({peer})"
        );
        assert_eq!(
            *counter.live_import.lock().unwrap(),
            None,
            "the rollback must reassert the prior import chain ({peer})"
        );
        assert_eq!(counter.export_installs.load(Ordering::SeqCst), 2);
        assert_eq!(
            counter.refreshes.load(Ordering::SeqCst),
            1,
            "the rollback refresh runs only after the prior chain is reasserted ({peer})"
        );
        let peer_state = manager.peers.get(&key(*peer)).unwrap();
        assert_eq!(peer_state.import_policy, None);
        assert_eq!(peer_state.export_policy, None);
        assert!(!peer_state.pending_refresh);
        assert!(!peer_state.pending_export_apply);
    }

    for peer in peers {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
    drop(manager);
    let singles = rib_task.await.unwrap();
    assert_eq!(
        singles,
        vec![peers[1], peers[0]],
        "rollback RIB restores run newest-first"
    );
}

/// LAN-462/LAN-464: an export hot-apply failure on a member whose import
/// delta was already acknowledged must reassert that member's prior import
/// chain directly (its bookkeeping had advanced) AND fire a Route Refresh to
/// reconcile routes the session accepted under the new chain during the
/// window, while the previously captured members restore through the
/// ordinary rollback — and the failing member still gets no RIB
/// compensation, matching the export-only discipline.
#[tokio::test]
async fn import_tolerant_cohort_export_failure_reasserts_failing_member_import() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let first = IpAddr::V4(Ipv4Addr::new(10, 45, 0, 1));
    let failing = IpAddr::V4(Ipv4Addr::new(10, 45, 0, 2));
    let first_counters = Arc::new(CohortSessionCounters::default());
    let failing_counters = Arc::new(CohortSessionCounters::default());
    let rib_single_restores = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let restores = Arc::clone(&rib_single_restores);
    let _rib_task = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPolicy { reply, .. } => {
                    restores.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                RibUpdate::ReplacePeerExportPolicies { .. } => {
                    panic!("the RIB batch must not run after a session-side cohort failure");
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
    insert_test_managed_peer(
        &mut manager,
        first,
        import_tolerant_cohort_test_session(first, Arc::clone(&first_counters), None),
        false,
    );
    insert_test_managed_peer(
        &mut manager,
        failing,
        import_tolerant_cohort_test_session(failing, Arc::clone(&failing_counters), Some(1)),
        false,
    );

    let shared_export = deny_policy_chain();
    let changed_import = validation_policy_chain(ImportValidationDependency::Rpki);
    let result = manager
        .apply_resolved_policy_snapshot(
            [first, failing]
                .into_iter()
                .map(|address| ResolvedPeerPolicy {
                    address,
                    interface: None,
                    import_policy: Some(changed_import.clone()),
                    export_policy: Some(shared_export.clone()),
                })
                .collect(),
        )
        .await;
    assert!(
        result.as_ref().is_err_and(|error| {
            error.contains(&format!(
                "failed to apply resolved policy to {failing}: export:"
            )) && error.contains("already-applied peers restored")
        }),
        "the export failure must surface with a successful rollback: {result:?}"
    );

    // The failing member: forward import install + direct prior reassert, a
    // post-reassert refresh for the acked-import window, no RIB compensation.
    assert_eq!(failing_counters.import_installs.load(Ordering::SeqCst), 2);
    assert_eq!(
        *failing_counters.live_import.lock().unwrap(),
        None,
        "the failing member's prior import chain must be reasserted"
    );
    assert_eq!(failing_counters.export_installs.load(Ordering::SeqCst), 2);
    assert_eq!(
        failing_counters.refreshes.load(Ordering::SeqCst),
        1,
        "the repair must fire a refresh for routes accepted under the new import chain during the window"
    );
    // The captured member restores through the ordinary rollback: reassert,
    // RIB restore, then the conservative post-reassert refresh.
    assert_eq!(first_counters.import_installs.load(Ordering::SeqCst), 2);
    assert_eq!(*first_counters.live_import.lock().unwrap(), None);
    assert_eq!(first_counters.export_installs.load(Ordering::SeqCst), 2);
    assert_eq!(first_counters.refreshes.load(Ordering::SeqCst), 1);
    assert_eq!(
        rib_single_restores.load(Ordering::SeqCst),
        1,
        "no RIB compensation may be planned for the member whose forward apply failed"
    );
    for peer in [first, failing] {
        let peer_state = manager.peers.get(&key(peer)).unwrap();
        assert_eq!(peer_state.import_policy, None);
        assert_eq!(peer_state.export_policy, None);
        assert!(!peer_state.pending_refresh);
        assert!(!peer_state.pending_export_apply);
    }

    for peer in [first, failing] {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
}

/// LAN-464 companion: when the failing member is no longer Established at
/// repair time, the acked-import-window reconciliation cannot refresh
/// immediately — it must arm `pending_refresh` instead so the retry pipeline
/// fires it once the session is reachable again.
#[tokio::test]
async fn cohort_export_failure_repair_arms_pending_refresh_when_not_established() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let first = IpAddr::V4(Ipv4Addr::new(10, 46, 0, 1));
    let failing = IpAddr::V4(Ipv4Addr::new(10, 46, 0, 2));
    let first_counters = Arc::new(CohortSessionCounters::default());
    let failing_counters = Arc::new(CohortSessionCounters::default());
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let _rib_task = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                let _ = reply.send(Ok(()));
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
    insert_test_managed_peer(
        &mut manager,
        first,
        import_tolerant_cohort_test_session(first, Arc::clone(&first_counters), None),
        false,
    );
    // Established for the cohort-selection state query only: by the time the
    // repair checks the session again it reports Connect.
    insert_test_managed_peer(
        &mut manager,
        failing,
        import_tolerant_cohort_test_session_with_states(
            failing,
            Arc::clone(&failing_counters),
            Some(1),
            Some(1),
        ),
        false,
    );

    let shared_export = deny_policy_chain();
    let changed_import = validation_policy_chain(ImportValidationDependency::Rpki);
    let result = manager
        .apply_resolved_policy_snapshot(
            [first, failing]
                .into_iter()
                .map(|address| ResolvedPeerPolicy {
                    address,
                    interface: None,
                    import_policy: Some(changed_import.clone()),
                    export_policy: Some(shared_export.clone()),
                })
                .collect(),
        )
        .await;
    assert!(
        result.as_ref().is_err_and(|error| {
            error.contains(&format!(
                "failed to apply resolved policy to {failing}: export:"
            ))
        }),
        "the export failure must surface: {result:?}"
    );

    // The failing member: prior import chain reasserted, no immediate
    // refresh (not Established), retry intent armed instead.
    assert_eq!(failing_counters.import_installs.load(Ordering::SeqCst), 2);
    assert_eq!(*failing_counters.live_import.lock().unwrap(), None);
    assert_eq!(failing_counters.refreshes.load(Ordering::SeqCst), 0);
    let failing_state = manager.peers.get(&key(failing)).unwrap();
    assert!(
        failing_state.pending_refresh,
        "a non-Established failing member must carry the refresh intent as pending_refresh"
    );
    // The captured member still restores through the ordinary rollback.
    assert_eq!(first_counters.refreshes.load(Ordering::SeqCst), 1);
    assert!(!manager.peers.get(&key(first)).unwrap().pending_refresh);

    for peer in [first, failing] {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the handoff fixture scripts the full prestage + cohort + batch dialogue"
)]
async fn export_only_snapshot_handoff_batches_the_authoritative_apply() {
    use rustbgpd_api::peer_types::{PeerManagerReadinessQuery, ResolvedPeerPolicy};

    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 35, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 35, 0, 2)),
    ];
    let installs = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
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
    for peer in peers {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(peer, Arc::clone(&installs), None),
            false,
        );
    }
    let next = deny_policy_chain();
    let apply = manager.apply_resolved_policy_snapshot(
        peers
            .iter()
            .map(|&address| ResolvedPeerPolicy {
                address,
                interface: None,
                import_policy: None,
                export_policy: Some(next.clone()),
            })
            .collect(),
    );
    let drive_rib = async {
        skip_destination_prestage(&mut rib_rx).await;
        let RibUpdate::ReplacePeerExportPolicies { reply, .. } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected cohort RIB command");
        };
        reply
            .send(Ok(
                rustbgpd_rib::ExportPolicyCohortOutcome::RequiresAuthoritativePerPeerApply,
            ))
            .unwrap();

        // The handoff is ONE batched command carrying the whole cohort in
        // caller order — never a serial per-peer dialogue.
        let RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
            replacements,
            reply,
        } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected batched authoritative RIB command");
        };
        assert_eq!(
            replacements
                .iter()
                .map(|replacement| replacement.peer)
                .collect::<Vec<_>>(),
            peers.to_vec()
        );
        assert!(
            matches!(rib_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
            "no per-peer command may accompany the batch"
        );
        let (readiness_reply, readiness_response) = oneshot::channel();
        readiness_tx
            .send(PeerManagerReadinessQuery::ListPeers {
                reply: readiness_reply,
            })
            .await
            .unwrap();
        let infos = tokio::time::timeout(
            rustbgpd_api::health_probe::CORE_READINESS_DEADLINE,
            readiness_response,
        )
        .await
        .expect("readiness must remain live while the batched RIB reply is held")
        .unwrap();
        assert_eq!(infos.len(), peers.len());
        reply.send(Ok(())).unwrap();
    };
    let (result, ()) = tokio::join!(apply, drive_rib);

    let priors = result.unwrap();
    assert_eq!(priors.len(), peers.len());
    assert_eq!(
        installs.load(Ordering::SeqCst),
        peers.len(),
        "the handoff must not hot-apply session policy a second time"
    );
    assert!(peers.iter().all(|peer| {
        manager
            .peers
            .get(&key(*peer))
            .is_some_and(|peer_state| peer_state.export_policy == Some(next.clone()))
    }));
    for peer in peers {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
}

/// A peer that deregistered from the RIB between the cohort hot-apply
/// and the handoff must stay benign: the skip now happens INSIDE the
/// batched authoritative apply (the RIB logs and continues — proven at
/// the RIB seam by
/// `batched_authoritative_apply_skips_unregistered_and_degrades_dead_channels`),
/// so the peer manager observes one successful batch reply and performs
/// no rollback.
#[tokio::test]
async fn export_only_snapshot_handoff_skips_missing_peer_and_continues_without_rollback() {
    use rustbgpd_api::peer_types::{PeerManagerReadinessQuery, ResolvedPeerPolicy};

    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 35, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 35, 1, 2)),
    ];
    let installs = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
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
    for peer in peers {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(peer, Arc::clone(&installs), None),
            false,
        );
    }
    let next = deny_policy_chain();
    let apply = manager.apply_resolved_policy_snapshot(
        peers
            .iter()
            .map(|&address| ResolvedPeerPolicy {
                address,
                interface: None,
                import_policy: None,
                export_policy: Some(next.clone()),
            })
            .collect(),
    );
    let drive_rib = async {
        skip_destination_prestage(&mut rib_rx).await;
        let RibUpdate::ReplacePeerExportPolicies { reply, .. } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected cohort RIB command");
        };
        reply
            .send(Ok(
                rustbgpd_rib::ExportPolicyCohortOutcome::RequiresAuthoritativePerPeerApply,
            ))
            .unwrap();

        let RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
            replacements,
            reply,
        } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected batched authoritative RIB command");
        };
        // The departed peer still rides the batch; the RIB skips it
        // internally and the whole apply succeeds.
        assert_eq!(replacements.len(), peers.len());

        let (readiness_reply, readiness_response) = oneshot::channel();
        readiness_tx
            .send(PeerManagerReadinessQuery::ListPeers {
                reply: readiness_reply,
            })
            .await
            .unwrap();
        let infos = readiness_response.await.unwrap();
        assert_eq!(infos.len(), peers.len());

        reply.send(Ok(())).unwrap();
        tokio::task::yield_now().await;
        assert!(matches!(
            rib_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    };
    let (result, ()) = tokio::join!(apply, drive_rib);

    assert!(
        result.is_ok(),
        "a departed-peer handoff race must be benign: {result:?}"
    );
    assert_eq!(
        installs.load(Ordering::SeqCst),
        peers.len(),
        "handoff must neither duplicate the forward session apply nor roll it back"
    );
    assert!(peers.iter().all(|peer| {
        manager
            .peers
            .get(&key(*peer))
            .is_some_and(|managed| managed.export_policy == Some(next.clone()))
    }));
    for peer in peers {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the handoff failure regression keeps forward ordering and complete reverse rollback together"
)]
async fn export_only_snapshot_handoff_failure_restores_every_peer_newest_first() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 36, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 36, 0, 2)),
    ];
    let installs = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let rib_task = tokio::spawn(async move {
        skip_destination_prestage(&mut rib_rx).await;
        let RibUpdate::ReplacePeerExportPolicies { reply, .. } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected cohort RIB command");
        };
        reply
            .send(Ok(
                rustbgpd_rib::ExportPolicyCohortOutcome::RequiresAuthoritativePerPeerApply,
            ))
            .unwrap();

        // Forward: ONE batched command for the whole cohort; its failure
        // fails the whole handoff at once.
        let RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
            replacements,
            reply,
        } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected batched authoritative RIB command");
        };
        assert_eq!(
            replacements
                .iter()
                .map(|replacement| replacement.peer)
                .collect::<Vec<_>>(),
            peers.to_vec()
        );
        reply
            .send(Err(rustbgpd_rib::RibCommandError::internal(
                "synthetic batch failure",
            )))
            .unwrap();

        // Rollback stays on the per-peer restore seam, newest first.
        let mut order = Vec::new();
        for expected_peer in peers.into_iter().rev() {
            let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } =
                rib_rx.recv().await.unwrap()
            else {
                panic!("expected rollback ordinary RIB command");
            };
            assert_eq!(peer, expected_peer);
            order.push(peer);
            reply.send(Ok(())).unwrap();
        }
        order
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
    for peer in peers {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(peer, Arc::clone(&installs), None),
            false,
        );
    }
    let next = deny_policy_chain();
    let result = manager
        .apply_resolved_policy_snapshot(
            peers
                .iter()
                .map(|&address| ResolvedPeerPolicy {
                    address,
                    interface: None,
                    import_policy: None,
                    export_policy: Some(next.clone()),
                })
                .collect(),
        )
        .await;
    assert!(
        result.as_ref().is_err_and(|error| {
            error.contains("synthetic batch failure")
                && error.contains("already-applied peers restored")
        }),
        "a handoff failure must surface after a complete rollback: {result:?}"
    );
    assert_eq!(
        installs.load(Ordering::SeqCst),
        peers.len() * 2,
        "handoff must avoid a second forward session apply and restore every session once"
    );
    assert_eq!(rib_task.await.unwrap(), vec![peers[1], peers[0]]);
    for peer in peers {
        let peer_state = manager.peers.get(&key(peer)).unwrap();
        assert!(peer_state.export_policy.is_none());
        assert!(!peer_state.pending_export_apply);
        assert!(!peer_state.pending_refresh);
        manager.delete_peer(key(peer), false).await.unwrap();
    }
}

#[tokio::test(start_paused = true)]
#[expect(
    clippy::too_many_lines,
    reason = "the timeout regression keeps the late forward reply and ordered rollback in one paused-time proof"
)]
async fn export_only_snapshot_handoff_timeout_restores_after_the_owned_forward_command() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 37, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 37, 0, 2)),
    ];
    let installs = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
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
    for peer in peers {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(peer, Arc::clone(&installs), None),
            false,
        );
    }
    let next = deny_policy_chain();
    let apply = manager.apply_resolved_policy_snapshot(
        peers
            .iter()
            .map(|&address| ResolvedPeerPolicy {
                address,
                interface: None,
                import_policy: None,
                export_policy: Some(next.clone()),
            })
            .collect(),
    );
    let drive_rib = async {
        skip_destination_prestage(&mut rib_rx).await;
        let RibUpdate::ReplacePeerExportPolicies { reply, .. } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected cohort RIB command");
        };
        reply
            .send(Ok(
                rustbgpd_rib::ExportPolicyCohortOutcome::RequiresAuthoritativePerPeerApply,
            ))
            .unwrap();

        let RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
            replacements,
            reply: late_forward_reply,
        } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected batched authoritative forward command");
        };
        assert_eq!(
            replacements
                .iter()
                .map(|replacement| replacement.peer)
                .collect::<Vec<_>>(),
            peers.to_vec()
        );
        assert!(
            replacements
                .iter()
                .all(|replacement| replacement.export_policy == Some(next.clone()))
        );
        assert!(matches!(
            rib_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        tokio::task::yield_now().await;
        tokio::time::advance(RIB_BATCH_REPLY_TIMEOUT + Duration::from_millis(1)).await;
        tokio::task::yield_now().await;

        assert!(
            late_forward_reply.send(Ok(())).is_err(),
            "the timed-out forward receiver must be gone before the RIB actor advances to rollback"
        );
        let mut rollback_order = Vec::new();
        for expected_peer in peers.into_iter().rev() {
            let RibUpdate::ReplacePeerExportPolicy {
                peer,
                export_policy,
                reply,
            } = rib_rx.recv().await.unwrap()
            else {
                panic!("expected ordinary rollback command");
            };
            assert_eq!(peer, expected_peer);
            assert!(export_policy.is_none());
            rollback_order.push(peer);
            reply.send(Ok(())).unwrap();
        }
        rollback_order
    };
    let (result, rollback_order) = tokio::join!(apply, drive_rib);

    assert!(
        result.as_ref().is_err_and(|error| {
            error.contains("did not reply within")
                && error.contains("already-applied peers restored")
        }),
        "a timed-out handoff must fail only after complete rollback: {result:?}"
    );
    assert_eq!(rollback_order, vec![peers[1], peers[0]]);
    assert_eq!(installs.load(Ordering::SeqCst), peers.len() * 2);
    for peer in peers {
        let peer_state = manager.peers.get(&key(peer)).unwrap();
        assert!(peer_state.export_policy.is_none());
        assert!(!peer_state.pending_export_apply);
        assert!(!peer_state.pending_refresh);
        manager.delete_peer(key(peer), false).await.unwrap();
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the bounded-channel proof keeps registration, refresh, and later lifecycle ordering together"
)]
async fn policy_rollback_registers_every_rib_restore_before_refresh_and_lifecycle_work() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    const PEER_COUNT: u8 = 160;
    let peers = (1..=PEER_COUNT)
        .map(|last| IpAddr::V4(Ipv4Addr::new(10, 40, 0, last)))
        .collect::<Vec<_>>();
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(1);
    let lifecycle_tx = rib_tx.clone();
    let (_command_tx, command_rx) = mpsc::channel(16);
    let mut manager = PeerManager::new(
        command_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx.clone(),
        None,
    );
    for (index, peer) in peers.iter().copied().enumerate() {
        insert_test_managed_peer(
            &mut manager,
            peer,
            rollback_ordering_policy_session(peer, rib_tx.clone(), index + 1 == peers.len(), None),
            false,
        );
    }

    let next = deny_policy_chain();
    // Distinct export targets keep this snapshot off the LAN-462
    // import-tolerant cohort (no repeated export pair) and on the per-peer
    // authoritative transaction whose rollback ordering this proof pins.
    let apply = manager.apply_resolved_policy_snapshot(
        peers
            .iter()
            .copied()
            .enumerate()
            .map(|(index, address)| ResolvedPeerPolicy {
                address,
                interface: None,
                import_policy: Some(next.clone()),
                export_policy: Some(distinct_deny_policy_chain(index)),
            })
            .collect(),
    );
    let drive_rib = async {
        for expected_peer in peers.iter().take(peers.len() - 1) {
            let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } =
                rib_rx.recv().await.unwrap()
            else {
                panic!("expected forward RIB restore");
            };
            assert_eq!(peer, *expected_peer);
            reply.send(Ok(())).unwrap();
        }

        let mut lifecycle_task = None;
        let mut restores = Vec::new();
        let mut refresh_markers = 0;
        let mut saw_delete = false;
        let mut saw_recreate = false;
        while restores.len() < peers.len()
            || refresh_markers < peers.len() - 1
            || !saw_delete
            || !saw_recreate
        {
            match rib_rx.recv().await.unwrap() {
                RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } => {
                    if restores.is_empty() {
                        let later_tx = lifecycle_tx.clone();
                        let recreated = peers[0];
                        lifecycle_task = Some(tokio::spawn(async move {
                            later_tx
                                .send(RibUpdate::PeerDeleted { peer: recreated })
                                .await
                                .unwrap();
                            let (outbound_tx, _outbound_rx) = mpsc::channel(1);
                            later_tx
                                .send(RibUpdate::PeerUp {
                                    peer: recreated,
                                    session_id: 99,
                                    peer_asn: 65002,
                                    peer_router_id: Ipv4Addr::new(192, 0, 2, 1),
                                    outbound_tx,
                                    export_policy: None,
                                    sendable_families: vec![(Afi::Ipv4, Safi::Unicast)],
                                    is_ebgp: true,
                                    route_reflector_client: false,
                                    orr_vantage: None,
                                    per_client_best: false,
                                    interpret_rfc1997: true,
                                    add_path_send_families: Vec::new(),
                                    add_path_send_max: 0,
                                    negotiated_orf_recv: Vec::new(),
                                    negotiated_llgr_families: Vec::new(),
                                })
                                .await
                                .unwrap();
                        }));
                    }
                    assert_eq!(peer, peers[peers.len() - 1 - restores.len()]);
                    restores.push(peer);
                    reply.send(Ok(())).unwrap();
                }
                RibUpdate::QueryLocRibCount { reply } => {
                    // LOAD-BEARING: moving Route Refresh ahead of aggregate
                    // registration lets this marker overtake a restore.
                    assert_eq!(restores.len(), peers.len());
                    refresh_markers += 1;
                    reply.send(0).unwrap();
                }
                RibUpdate::PeerDeleted { peer } => {
                    // LOAD-BEARING: removing reverse-order pre-registration
                    // lets this later delete overtake an unregistered restore.
                    assert_eq!(restores.len(), peers.len());
                    assert_eq!(peer, peers[0]);
                    saw_delete = true;
                }
                RibUpdate::PeerUp {
                    peer, session_id, ..
                } => {
                    assert!(saw_delete);
                    assert_eq!(restores.len(), peers.len());
                    assert_eq!(peer, peers[0]);
                    assert_eq!(session_id, 99);
                    saw_recreate = true;
                }
                _ => panic!("unexpected RIB command in rollback ordering proof"),
            }
        }
        lifecycle_task.unwrap().await.unwrap();
    };
    let (result, ()) = tokio::join!(apply, drive_rib);

    assert!(
        result
            .as_ref()
            .is_err_and(|error| error.contains("injected final session failure")),
        "the forced final failure must drive a complete rollback: {result:?}"
    );
}

#[tokio::test]
async fn policy_rollback_registered_rib_futures_survive_caller_cancellation() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let peers = (1..=8)
        .map(|last| IpAddr::V4(Ipv4Addr::new(10, 41, 0, last)))
        .collect::<Vec<_>>();
    let attempts = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(1);
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
    for (index, peer) in peers.iter().copied().enumerate() {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(
                peer,
                Arc::clone(&attempts),
                (index + 1 == peers.len()).then_some(peers.len()),
            ),
            false,
        );
    }
    let task_peers = peers.clone();
    let apply_task = tokio::spawn(async move {
        manager
            .apply_resolved_policy_snapshot(
                task_peers
                    .iter()
                    .copied()
                    .map(|address| ResolvedPeerPolicy {
                        address,
                        interface: None,
                        import_policy: None,
                        export_policy: Some(deny_policy_chain()),
                    })
                    .collect(),
            )
            .await
    });

    skip_destination_prestage(&mut rib_rx).await;
    let RibUpdate::ReplacePeerExportPolicy {
        peer: first_restore,
        reply,
        ..
    } = rib_rx.recv().await.unwrap()
    else {
        panic!("expected the first registered rollback restore");
    };
    assert_eq!(first_restore, peers[peers.len() - 2]);
    apply_task.abort();
    assert!(apply_task.await.unwrap_err().is_cancelled());
    reply.send(Ok(())).unwrap();

    let mut restored = vec![first_restore];
    while restored.len() < peers.len() - 1 {
        let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected detached rollback restore");
        };
        restored.push(peer);
        reply.send(Ok(())).unwrap();
    }
    // LOAD-BEARING: awaiting rollback futures directly in the caller drops
    // this suffix on cancellation, closing the channel before all peers arrive.
    assert_eq!(
        restored,
        peers[..peers.len() - 1]
            .iter()
            .rev()
            .copied()
            .collect::<Vec<_>>()
    );
}

#[tokio::test(start_paused = true)]
#[expect(
    clippy::too_many_lines,
    reason = "the readiness regression keeps direct-lane and complete core-probe assertions in one held transaction"
)]
async fn export_only_snapshot_services_readiness_without_admitting_mutations() {
    use rustbgpd_api::peer_types::{PeerManagerReadinessQuery, ResolvedPeerPolicy};

    let peers = (1..=16)
        .map(|last| IpAddr::V4(Ipv4Addr::new(10, 33, 0, last)))
        .collect::<Vec<_>>();
    let attempts = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (command_tx, command_rx) = mpsc::channel(16);
    let (readiness_tx, readiness_rx) = mpsc::channel(16);
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
    for peer in peers.iter().copied() {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(peer, Arc::clone(&attempts), None),
            false,
        );
    }
    let manager_task = tokio::spawn(manager.run());

    let (apply_reply, mut apply_response) = oneshot::channel();
    command_tx
        .send(PeerManagerCommand::ApplyResolvedPolicySnapshot {
            targets: peers
                .iter()
                .copied()
                .map(|address| ResolvedPeerPolicy {
                    address,
                    interface: None,
                    import_policy: None,
                    export_policy: Some(deny_policy_chain()),
                })
                .collect(),
            reply: apply_reply,
        })
        .await
        .unwrap();
    skip_destination_prestage(&mut rib_rx).await;
    let RibUpdate::ReplacePeerExportPolicies {
        reply: rib_reply, ..
    } = rib_rx.recv().await.unwrap()
    else {
        panic!("expected cohort RIB command");
    };

    let (mutation_reply, mut mutation_response) = oneshot::channel();
    command_tx
        .send(PeerManagerCommand::SyncExplainConfig {
            enabled: false,
            cache_size: 17,
            reject_retention_enabled: true,
            reject_retention_capacity: 1024,
            reply: mutation_reply,
        })
        .await
        .unwrap();

    for _ in 0..8 {
        let (readiness_reply, readiness_response) = oneshot::channel();
        readiness_tx
            .send(PeerManagerReadinessQuery::ListPeers {
                reply: readiness_reply,
            })
            .await
            .unwrap();
        let infos = tokio::time::timeout(
            rustbgpd_api::health_probe::CORE_READINESS_DEADLINE,
            readiness_response,
        )
        .await
        .expect("live readiness must stay inside the unchanged 200ms deadline")
        .unwrap();
        assert_eq!(infos.len(), peers.len());
    }
    let (health_rib_tx, mut health_rib_rx) = mpsc::channel(1);
    let probe =
        rustbgpd_api::health_probe::CoreReadinessProbe::new(command_tx.clone(), health_rib_tx)
            .with_peer_manager_readiness(readiness_tx.clone());
    let (health, ()) = tokio::join!(probe.snapshot(), async {
        let RibUpdate::QueryLocRibCount { reply } =
            health_rib_rx.recv().await.expect("core RIB query")
        else {
            panic!("core readiness must use the read-only RIB count query");
        };
        reply.send(17).unwrap();
    });
    assert_eq!(
        health
            .expect("complete core readiness must beat its unchanged deadline")
            .total_routes,
        17
    );
    assert!(
        matches!(
            mutation_response.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ),
        "ordinary mutation lane must stay blocked behind the policy transaction"
    );
    assert!(
        matches!(
            apply_response.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ),
        "readiness must not fabricate cohort completion"
    );

    // The successfully enqueued RIB transaction owns its reply. Advancing
    // beyond the ordinary per-peer five-second deadline must not start a
    // competing rollback while the forward RIB commit can still complete.
    tokio::time::advance(RIB_REPLY_TIMEOUT + Duration::from_secs(1)).await;
    for _ in 0..3 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        peers.len(),
        "no session rollback may race an owned forward RIB transaction"
    );
    assert!(
        matches!(rib_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "the prior timeout would enqueue a per-peer rollback while the forward reply remained owned"
    );
    assert!(matches!(
        mutation_response.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert!(matches!(
        apply_response.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));

    let (late_readiness_reply, late_readiness_response) = oneshot::channel();
    readiness_tx
        .send(PeerManagerReadinessQuery::ListPeers {
            reply: late_readiness_reply,
        })
        .await
        .unwrap();
    let late_infos = tokio::time::timeout(
        rustbgpd_api::health_probe::CORE_READINESS_DEADLINE,
        late_readiness_response,
    )
    .await
    .expect("readiness must remain live beyond the former five-second cohort timeout")
    .unwrap();
    assert_eq!(late_infos.len(), peers.len());
    assert_eq!(attempts.load(Ordering::SeqCst), peers.len());

    rib_reply
        .send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed))
        .unwrap();
    apply_response.await.unwrap().unwrap();
    mutation_response.await.unwrap();
    command_tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    manager_task.await.unwrap();
}

#[tokio::test(start_paused = true)]
#[expect(
    clippy::too_many_lines,
    reason = "the readiness regression keeps cancellation and live probing in one held transaction"
)]
async fn export_only_snapshot_services_readiness_during_stalled_session_apply() {
    use rustbgpd_api::peer_types::{PeerManagerReadinessQuery, ResolvedPeerPolicy};

    let stalled = IpAddr::V4(Ipv4Addr::new(10, 34, 0, 1));
    let responsive = IpAddr::V4(Ipv4Addr::new(10, 34, 0, 2));
    let attempts = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (command_tx, command_rx) = mpsc::channel(16);
    let (readiness_tx, readiness_rx) = mpsc::channel(16);
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
    let (stalled_handle, entered, release, state_queries) =
        stalled_export_policy_test_session(stalled);
    insert_test_managed_peer(&mut manager, stalled, stalled_handle, false);
    insert_test_managed_peer(
        &mut manager,
        responsive,
        established_export_policy_test_session(responsive, attempts, None),
        false,
    );
    let manager_task = tokio::spawn(manager.run());

    let (apply_reply, mut apply_response) = oneshot::channel();
    command_tx
        .send(PeerManagerCommand::ApplyResolvedPolicySnapshot {
            targets: [stalled, responsive]
                .into_iter()
                .map(|address| ResolvedPeerPolicy {
                    address,
                    interface: None,
                    import_policy: None,
                    export_policy: Some(deny_policy_chain()),
                })
                .collect(),
            reply: apply_reply,
        })
        .await
        .unwrap();
    skip_destination_prestage(&mut rib_rx).await;
    entered.await.unwrap();
    state_queries.store(0, Ordering::SeqCst);
    tokio::time::advance(std::time::Duration::from_millis(250)).await;
    tokio::task::yield_now().await;
    assert!(matches!(
        apply_response.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));

    let (cancelled_reply, cancelled_response) = oneshot::channel();
    drop(cancelled_response);
    readiness_tx
        .send(PeerManagerReadinessQuery::ListPeers {
            reply: cancelled_reply,
        })
        .await
        .unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(std::time::Duration::from_millis(100)).await;
    tokio::task::yield_now().await;

    let (readiness_reply, readiness_response) = oneshot::channel();
    readiness_tx
        .send(PeerManagerReadinessQuery::ListPeers {
            reply: readiness_reply,
        })
        .await
        .unwrap();
    let infos = tokio::time::timeout(
        rustbgpd_api::health_probe::CORE_READINESS_DEADLINE,
        readiness_response,
    )
    .await
    .expect("readiness must beat the unchanged 200ms deadline")
    .unwrap();
    assert_eq!(infos.len(), 2);
    assert!(
        infos
            .iter()
            .find(|info| info.address == stalled)
            .is_some_and(|info| info.stale),
        "the independently stalled session must be reported as stale, not fabricated healthy"
    );
    assert!(
        infos
            .iter()
            .find(|info| info.address == responsive)
            .is_some_and(|info| !info.stale)
    );

    release.notify_one();
    let RibUpdate::ReplacePeerExportPolicies {
        reply: rib_reply, ..
    } = rib_rx.recv().await.unwrap()
    else {
        panic!("expected cohort RIB command after the stalled session resumes");
    };
    rib_reply
        .send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed))
        .unwrap();
    apply_response.await.unwrap().unwrap();
    assert_session_state_query_count(&state_queries, 1).await;
    command_tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    manager_task.await.unwrap();
}

#[tokio::test]
async fn export_only_snapshot_restores_newest_first_after_session_failure() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let first = IpAddr::V4(Ipv4Addr::new(10, 31, 0, 1));
    let second = IpAddr::V4(Ipv4Addr::new(10, 31, 0, 2));
    let first_attempts = Arc::new(AtomicUsize::new(0));
    let second_attempts = Arc::new(AtomicUsize::new(0));
    let rib_single_restores = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let restores = Arc::clone(&rib_single_restores);
    let rib_task = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPolicy { reply, .. } => {
                    restores.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                RibUpdate::ReplacePeerExportPolicies { .. } => {
                    panic!("the RIB batch must not run after a session-side cohort failure");
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
    insert_test_managed_peer(
        &mut manager,
        first,
        established_export_policy_test_session(first, Arc::clone(&first_attempts), None),
        false,
    );
    insert_test_managed_peer(
        &mut manager,
        second,
        established_export_policy_test_session(second, Arc::clone(&second_attempts), Some(1)),
        false,
    );
    let next = deny_policy_chain();
    let result = manager
        .apply_resolved_policy_snapshot(
            [first, second]
                .into_iter()
                .map(|address| ResolvedPeerPolicy {
                    address,
                    interface: None,
                    import_policy: None,
                    export_policy: Some(next.clone()),
                })
                .collect(),
        )
        .await;
    assert!(
        result
            .as_ref()
            .is_err_and(|error| error.contains("already-applied peers restored")),
        "cohort failure must surface with an explicit successful rollback: {result:?}"
    );
    assert_eq!(first_attempts.load(Ordering::SeqCst), 2);
    assert_eq!(
        second_attempts.load(Ordering::SeqCst),
        2,
        "the failing session must have its prior chain reasserted too"
    );
    // LOAD-BEARING: planning RIB compensation for the session whose forward
    // command failed increases this to two and makes the assertion red.
    assert_eq!(rib_single_restores.load(Ordering::SeqCst), 1);
    for peer in [first, second] {
        let peer_state = manager.peers.get(&key(peer)).unwrap();
        assert!(peer_state.export_policy.is_none());
        assert!(!peer_state.pending_export_apply);
        assert!(!peer_state.pending_refresh);
    }

    for peer in [first, second] {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
    drop(manager);
    rib_task.await.unwrap();
}

#[tokio::test]
async fn export_only_snapshot_restores_newest_first_after_rib_batch_failure() {
    use rustbgpd_api::peer_types::{PeerManagerReadinessQuery, ResolvedPeerPolicy};

    let first = IpAddr::V4(Ipv4Addr::new(10, 32, 0, 1));
    let second = IpAddr::V4(Ipv4Addr::new(10, 32, 0, 2));
    let attempts = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let (batch_seen_tx, batch_seen_rx) = oneshot::channel();
    let release_batch = Arc::new(tokio::sync::Notify::new());
    let task_release = Arc::clone(&release_batch);
    let rib_task = tokio::spawn(async move {
        let mut restore_order = Vec::new();
        let mut batch_seen_tx = Some(batch_seen_tx);
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPolicies { reply, .. } => {
                    if let Some(batch_seen) = batch_seen_tx.take() {
                        let _ = batch_seen.send(());
                    }
                    task_release.notified().await;
                    drop(reply);
                }
                RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } => {
                    restore_order.push(peer);
                    let _ = reply.send(Ok(()));
                }
                _ => {}
            }
        }
        restore_order
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
    for peer in [first, second] {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(peer, Arc::clone(&attempts), None),
            false,
        );
    }
    let next = deny_policy_chain();
    let apply = manager.apply_resolved_policy_snapshot(
        [first, second]
            .into_iter()
            .map(|address| ResolvedPeerPolicy {
                address,
                interface: None,
                import_policy: None,
                export_policy: Some(next.clone()),
            })
            .collect(),
    );
    let readiness = async {
        batch_seen_rx.await.unwrap();
        let (reply, response) = oneshot::channel();
        readiness_tx
            .send(PeerManagerReadinessQuery::ListPeers { reply })
            .await
            .unwrap();
        let infos = response.await.unwrap();
        assert_eq!(infos.len(), 2);
        release_batch.notify_one();
    };
    let (result, ()) = tokio::join!(apply, readiness);
    assert!(
        result
            .as_ref()
            .is_err_and(|error| error.contains("RIB manager dropped cohort reply")
                && error.contains("already-applied peers restored")),
        "a dropped owned RIB reply must restore every session and RIB policy: {result:?}"
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 4);
    for peer in [first, second] {
        let peer_state = manager.peers.get(&key(peer)).unwrap();
        assert!(peer_state.export_policy.is_none());
        assert!(!peer_state.pending_export_apply);
        assert!(!peer_state.pending_refresh);
    }

    for peer in [first, second] {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
    drop(manager);
    assert_eq!(rib_task.await.unwrap(), vec![second, first]);
}
