use super::*;

/// Session model for an ambiguous import apply: it installs every supplied
/// chain, drops the first reply after mutation, and acknowledges subsequent
/// installs. Rollback must therefore reassert the prior chain before refresh.
fn import_ack_loss_policy_handle(
    peer_addr: IpAddr,
    live_import: Arc<Mutex<Option<rustbgpd_policy::PolicyChain>>>,
    import_installs: Arc<AtomicUsize>,
    refreshes: Arc<AtomicUsize>,
) -> PeerHandle {
    use rustbgpd_transport::PeerCommand;

    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let first_import = Arc::new(AtomicBool::new(true));
    let task = tokio::spawn(async move {
        while let Some(command) = session_rx.recv().await {
            match command {
                PeerCommand::QueryState { reply } => {
                    let _ =
                        reply.send(policy_test_peer_state(peer_addr, SessionState::Established));
                }
                PeerCommand::UpdateImportPolicy { policy, reply } => {
                    *live_import.lock().unwrap() = policy;
                    import_installs.fetch_add(1, Ordering::SeqCst);
                    if first_import.swap(false, Ordering::SeqCst) {
                        drop(reply);
                    } else {
                        let _ = reply.send(Ok(()));
                    }
                }
                PeerCommand::UpdateExportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    refreshes.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::Shutdown | PeerCommand::Stop { .. } | PeerCommand::CollisionDump => {
                    break;
                }
                _ => {}
            }
        }
        Ok(())
    });
    PeerHandle::from_parts(session_tx, task)
}

/// LAN-311: a policy fan-out (SIGHUP rpol overlay, catalog edit, and
/// the ADR-0076 txn snapshot all funnel through
/// `update_runtime_policies_for_peer_key`) must scope reinstallation to
/// peers whose resolved chain CONTENT moved. A peer re-resolving to a
/// content-equal chain gets no session command at all — the session
/// bumps its import-policy generation (and swaps the counter-bearing
/// chain instance) inside the `UpdateImportPolicy` handler, so "no
/// command" IS the #761 generation-unchanged / counters-survive
/// guarantee (the M80 finding: SIGHUP bumped generation 0→1 on peers
/// whose chains didn't change) — and no RIB `ReplacePeerExportPolicy`.
/// The peer whose content moved gets exactly the prior behavior:
/// session installs, RIB replace, and a Route Refresh.
#[allow(
    clippy::too_many_lines,
    reason = "the fanout regression keeps affected and unaffected peer assertions together"
)]
#[tokio::test]
async fn content_equal_policy_fanout_skips_unaffected_peers() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;
    use rustbgpd_transport::PeerCommand;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[derive(Default)]
    struct SessionCounters {
        import_installs: AtomicU32,
        export_installs: AtomicU32,
        refreshes: AtomicU32,
    }

    fn fake_session(addr: IpAddr) -> (PeerHandle, Arc<SessionCounters>) {
        let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(16);
        let counters = Arc::new(SessionCounters::default());
        let counters_in_task = counters.clone();
        let task = tokio::spawn(async move {
            while let Some(cmd) = session_rx.recv().await {
                match cmd {
                    PeerCommand::UpdateImportPolicy { reply, .. } => {
                        counters_in_task
                            .import_installs
                            .fetch_add(1, Ordering::SeqCst);
                        let _ = reply.send(Ok(()));
                    }
                    PeerCommand::UpdateExportPolicy { reply, .. } => {
                        counters_in_task
                            .export_installs
                            .fetch_add(1, Ordering::SeqCst);
                        let _ = reply.send(Ok(()));
                    }
                    PeerCommand::SendRouteRefresh { reply, .. } => {
                        counters_in_task.refreshes.fetch_add(1, Ordering::SeqCst);
                        let _ = reply.send(Ok(()));
                    }
                    PeerCommand::QueryState { reply } => {
                        let _ = reply.send(PeerSessionState {
                            fsm_state: SessionState::Established,
                            peer_ip: addr,
                            peer_asn: None,
                            prefix_count: 0,
                            max_prefix: MaxPrefixState::default(),
                            negotiated_hold_time: Some(90),
                            four_octet_as: Some(true),
                            remote_router_id: None,
                            negotiated_session: None,
                            local_role: None,
                            remote_role: None,
                            role_negotiated: false,
                            peer_paths_limits: Vec::new(),
                            effective_add_path_send_limits: Vec::new(),
                            updates_received: 0,
                            updates_sent: 0,
                            notifications_received: 0,
                            notifications_sent: 0,
                            messages_received: 0,
                            messages_sent: 0,
                            otc_routes_blocked: 0,
                            import_policy_routes_permitted: 0,
                            import_policy_routes_denied: 0,
                            flap_count: 0,
                            uptime_secs: 1,
                            last_error: String::new(),
                            tcp_ao_info: None,
                            tcp_ao_protected: false,
                            slow_peer: false,
                        });
                    }
                    PeerCommand::Shutdown => break,
                    _ => {}
                }
            }
            Ok(())
        });
        (PeerHandle::from_parts(session_tx, task), counters)
    }

    fn permit_policy_chain() -> PolicyChain {
        use rustbgpd_policy::{Policy, PolicyAction};
        PolicyChain::new(vec![Policy {
            entries: Vec::new(),
            default_action: PolicyAction::Permit,
        }])
    }

    let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let (handle_a, counters_a) = fake_session(a);
    let (handle_b, counters_b) = fake_session(b);

    // RIB drainer counting ReplacePeerExportPolicy per peer.
    let rib_replaces_a = Arc::new(AtomicU32::new(0));
    let rib_replaces_b = Arc::new(AtomicU32::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
    let (replaces_a, replaces_b) = (rib_replaces_a.clone(), rib_replaces_b.clone());
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } => {
                    if peer == a {
                        replaces_a.fetch_add(1, Ordering::SeqCst);
                    } else {
                        replaces_b.fetch_add(1, Ordering::SeqCst);
                    }
                    let _ = reply.send(Ok(()));
                }
                // LAN-462: the initial uniform install rides the batched
                // import-tolerant cohort — one member replacement per peer.
                RibUpdate::ReplacePeerExportPolicies {
                    replacements,
                    reply,
                } => {
                    for replacement in replacements {
                        if replacement.peer == a {
                            replaces_a.fetch_add(1, Ordering::SeqCst);
                        } else {
                            replaces_b.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
                }
                _ => {}
            }
        }
    });

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    insert_test_managed_peer(&mut mgr, a, handle_a, false);
    insert_test_managed_peer(&mut mgr, b, handle_b, false);

    // Initial install through the atomic fan-out both edits ride.
    let target = |address: IpAddr, chain: PolicyChain| ResolvedPeerPolicy {
        address,
        interface: None,
        import_policy: Some(chain.clone()),
        export_policy: Some(chain),
    };
    mgr.apply_resolved_policy_snapshot(vec![
        target(a, permit_policy_chain()),
        target(b, permit_policy_chain()),
    ])
    .await
    .expect("initial install");
    assert_eq!(counters_a.import_installs.load(Ordering::SeqCst), 1);
    assert_eq!(counters_a.refreshes.load(Ordering::SeqCst), 1);
    assert_eq!(rib_replaces_a.load(Ordering::SeqCst), 1);

    // The M80 shape: an edit re-resolves BOTH peers, but only B's chain
    // content moved; A resolves to a content-equal (fresh-instance)
    // chain.
    mgr.apply_resolved_policy_snapshot(vec![
        target(a, permit_policy_chain()),
        target(b, deny_policy_chain()),
    ])
    .await
    .expect("scoped re-apply");

    // (ii) Unaffected peer: NO reinstall of any kind — generation and
    // live counters in the session survive untouched.
    assert_eq!(
        counters_a.import_installs.load(Ordering::SeqCst),
        1,
        "content-equal re-resolve must not send UpdateImportPolicy \
         (each send bumps the session's import generation and resets its counters)"
    );
    assert_eq!(
        counters_a.export_installs.load(Ordering::SeqCst),
        1,
        "content-equal re-resolve must not send UpdateExportPolicy"
    );
    assert_eq!(
        rib_replaces_a.load(Ordering::SeqCst),
        1,
        "content-equal re-resolve must not send ReplacePeerExportPolicy \
         (a fresh instance would strand the update group's term-hit counters)"
    );
    assert_eq!(
        counters_a.refreshes.load(Ordering::SeqCst),
        1,
        "content-equal re-resolve must not fire Route Refresh"
    );

    // (iii) Changed peer: full reinstall — session installs, RIB
    // replace, Route Refresh — and bookkeeping advances to the new
    // chain.
    assert_eq!(counters_b.import_installs.load(Ordering::SeqCst), 2);
    assert_eq!(counters_b.export_installs.load(Ordering::SeqCst), 2);
    assert_eq!(rib_replaces_b.load(Ordering::SeqCst), 2);
    assert_eq!(counters_b.refreshes.load(Ordering::SeqCst), 2);
    assert_eq!(
        mgr.peers.get(&key(b)).unwrap().import_policy,
        Some(deny_policy_chain()),
        "changed peer's bookkeeping must advance to the new chain"
    );

    rib_drainer.abort();
}

#[tokio::test]
async fn export_only_snapshot_uses_one_batched_rib_commit_and_preserves_priors() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 30, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 30, 0, 2)),
    ];
    let installs = Arc::new(AtomicUsize::new(0));
    let batches = Arc::new(AtomicUsize::new(0));
    let singles = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let batch_count = Arc::clone(&batches);
    let single_count = Arc::clone(&singles);
    let rib_task = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPolicies {
                    replacements,
                    reply,
                } => {
                    assert_eq!(replacements.len(), peers.len());
                    batch_count.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
                }
                RibUpdate::ReplacePeerExportPolicy { reply, .. } => {
                    single_count.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
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
    for peer in peers {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(peer, Arc::clone(&installs), None),
            false,
        );
    }
    let next = deny_policy_chain();
    let priors = manager
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
        .await
        .unwrap();

    assert_eq!(installs.load(Ordering::SeqCst), peers.len());
    assert_eq!(batches.load(Ordering::SeqCst), 1);
    assert_eq!(singles.load(Ordering::SeqCst), 0);
    assert_eq!(priors.len(), peers.len());
    assert!(priors.iter().all(|prior| prior.export_policy.is_none()));
    assert!(peers.iter().all(|peer| {
        manager
            .peers
            .get(&key(*peer))
            .is_some_and(|managed| managed.export_policy == Some(next.clone()))
    }));

    for peer in peers {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
    drop(manager);
    rib_task.await.unwrap();
}

#[tokio::test]
async fn export_only_snapshot_skips_probe_without_repeated_policy_pair() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 35, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 35, 0, 2)),
    ];
    let (rib_tx, _rib_rx) = mpsc::channel(1);
    let (_command_tx, command_rx) = mpsc::channel(1);
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
    let mut query_counts = Vec::new();
    for peer in peers {
        let (handle, _entered, _release, queries) = stalled_export_policy_test_session(peer);
        query_counts.push(queries);
        insert_test_managed_peer(&mut manager, peer, handle, false);
    }

    let targets = [
        ResolvedPeerPolicy {
            address: peers[0],
            interface: None,
            import_policy: None,
            export_policy: Some(deny_policy_chain()),
        },
        ResolvedPeerPolicy {
            address: peers[1],
            interface: None,
            import_policy: None,
            export_policy: Some(validation_policy_chain(ImportValidationDependency::Rpki)),
        },
    ];
    let selected = manager.export_only_policy_cohort_mask(&targets).await;

    assert_eq!(selected, vec![false, false]);
    assert!(
        query_counts
            .iter()
            .all(|queries| queries.load(Ordering::SeqCst) == 0)
    );

    drop(manager);
}

/// Load-bearing LAN-521 regression: restoring first-viable anchoring selects
/// the leading two-peer pair, making the six-peer batch, single order, and
/// cohort-first prior order below go red.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the actor regression keeps fleet partitioning, RIB dialogue, and prior order in one fixture"
)]
async fn export_only_snapshot_selects_largest_local_policy_pair() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let peers = (1..=10)
        .map(|last| IpAddr::V4(Ipv4Addr::new(10, 36, 1, last)))
        .collect::<Vec<_>>();
    let small = &peers[0..2];
    let large = &peers[2..8];
    let ninth = peers[8];
    let tenth = peers[9];
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(32);
    let rib_task = tokio::spawn(async move {
        let mut batches = Vec::new();
        let mut singles = Vec::new();
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPolicies {
                    replacements,
                    reply,
                } => {
                    batches.push(
                        replacements
                            .into_iter()
                            .map(|replacement| replacement.peer)
                            .collect::<Vec<_>>(),
                    );
                    let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
                }
                RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } => {
                    singles.push(peer);
                    let _ = reply.send(Ok(()));
                }
                _ => {}
            }
        }
        (batches, singles)
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
    for &peer in &peers {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(peer, Arc::clone(&installs), None),
            false,
        );
    }

    let pair_two_chain = distinct_deny_policy_chain(0);
    let pair_six_chain = distinct_deny_policy_chain(1);
    let ninth_chain = distinct_deny_policy_chain(2);
    let tenth_chain = distinct_deny_policy_chain(3);
    let targets = peers
        .iter()
        .copied()
        .map(|address| ResolvedPeerPolicy {
            address,
            interface: None,
            import_policy: None,
            export_policy: Some(if small.contains(&address) {
                pair_two_chain.clone()
            } else if large.contains(&address) {
                pair_six_chain.clone()
            } else if address == ninth {
                ninth_chain.clone()
            } else {
                tenth_chain.clone()
            }),
        })
        .collect::<Vec<_>>();
    let priors = manager
        .apply_resolved_policy_snapshot(targets)
        .await
        .expect("largest-pair snapshot must commit");
    assert_eq!(
        priors.iter().map(|prior| prior.address).collect::<Vec<_>>(),
        large
            .iter()
            .chain(small)
            .copied()
            .chain([ninth, tenth])
            .collect::<Vec<_>>(),
        "apply order remains winning cohort then caller-ordered remainder"
    );
    assert_eq!(installs.load(Ordering::SeqCst), peers.len());

    for &peer in &peers {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
    drop(manager);
    let (batches, singles) = rib_task.await.unwrap();
    assert_eq!(batches, vec![large.to_vec()]);
    assert_eq!(
        singles,
        small
            .iter()
            .copied()
            .chain([ninth, tenth])
            .collect::<Vec<_>>()
    );
}

/// Load-bearing LAN-521 regression: replacing the canonical tie-break with
/// first-seen selection makes the two permutations disagree; querying beyond
/// the winning pair makes one of the losing-pair zero counters go red.
#[tokio::test]
async fn export_only_cohort_tie_break_is_stable_and_queries_only_winner() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let a1 = IpAddr::V4(Ipv4Addr::new(10, 36, 2, 1));
    let b1 = IpAddr::V4(Ipv4Addr::new(10, 36, 2, 2));
    let b2 = IpAddr::V4(Ipv4Addr::new(10, 36, 2, 3));
    let a2 = IpAddr::V4(Ipv4Addr::new(10, 36, 2, 4));
    let all = [a1, b1, b2, a2];
    let permutations = [[a1, b1, b2, a2], [b2, a2, a1, b1]];
    let winner_policy = distinct_deny_policy_chain(4);
    let loser_policy = distinct_deny_policy_chain(5);

    for order in permutations {
        let (rib_tx, _rib_rx) = mpsc::channel(1);
        let (_command_tx, command_rx) = mpsc::channel(1);
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
        let mut queries = Vec::new();
        for &peer in &all {
            let (handle, peer_queries) = established_export_policy_test_session_with_queries(
                peer,
                Arc::clone(&installs),
                None,
            );
            insert_test_managed_peer(&mut manager, peer, handle, false);
            queries.push((peer, peer_queries));
        }
        let targets = order
            .iter()
            .copied()
            .map(|address| ResolvedPeerPolicy {
                address,
                interface: None,
                import_policy: None,
                export_policy: Some(if [a1, a2].contains(&address) {
                    winner_policy.clone()
                } else {
                    loser_policy.clone()
                }),
            })
            .collect::<Vec<_>>();
        let mask = manager.export_only_policy_cohort_mask(&targets).await;
        let selected = order
            .iter()
            .zip(&mask)
            .filter_map(|(&peer, &selected)| selected.then_some(peer))
            .collect::<Vec<_>>();
        let remainder = order
            .iter()
            .zip(mask)
            .filter_map(|(&peer, selected)| (!selected).then_some(peer))
            .collect::<Vec<_>>();
        for (peer, count) in &queries {
            assert_eq!(
                count.load(Ordering::SeqCst),
                usize::from([a1, a2].contains(peer)),
                "only the canonical winning pair may receive state queries"
            );
        }
        assert_eq!(
            selected,
            order
                .iter()
                .copied()
                .filter(|peer| [a1, a2].contains(peer))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            remainder,
            order
                .iter()
                .copied()
                .filter(|peer| [b1, b2].contains(peer))
                .collect::<Vec<_>>()
        );
        drop(manager);
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the mixed-fleet regression pins cohort selection, reconnect fallback, and prior-token ordering together"
)]
async fn export_only_snapshot_partitions_first_eligible_cohort_and_stable_remainder() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let unchanged = IpAddr::V4(Ipv4Addr::new(10, 36, 0, 1));
    let reconnecting = IpAddr::V4(Ipv4Addr::new(10, 36, 0, 2));
    let first = IpAddr::V4(Ipv4Addr::new(10, 36, 0, 3));
    let import_changing = IpAddr::V4(Ipv4Addr::new(10, 36, 0, 4));
    let second = IpAddr::V4(Ipv4Addr::new(10, 36, 0, 5));
    let different_chain = IpAddr::V4(Ipv4Addr::new(10, 36, 0, 6));
    let all_peers = [
        unchanged,
        reconnecting,
        first,
        import_changing,
        second,
        different_chain,
    ];
    let cohort_installs = Arc::new(AtomicUsize::new(0));
    let different_installs = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(32);
    let rib_task = tokio::spawn(async move {
        let mut batches = Vec::new();
        let mut singles = Vec::new();
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPolicies {
                    replacements,
                    reply,
                } => {
                    batches.push(
                        replacements
                            .into_iter()
                            .map(|replacement| replacement.peer)
                            .collect::<Vec<_>>(),
                    );
                    let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
                }
                RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } => {
                    singles.push(peer);
                    let _ = reply.send(Ok(()));
                }
                _ => {}
            }
        }
        (batches, singles)
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
        unchanged,
        acking_policy_handle(unchanged, SessionState::Established),
        false,
    );
    insert_test_managed_peer(
        &mut manager,
        reconnecting,
        acking_policy_handle(reconnecting, SessionState::Active),
        false,
    );
    for peer in [first, second] {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(peer, Arc::clone(&cohort_installs), None),
            false,
        );
    }
    insert_test_managed_peer(
        &mut manager,
        import_changing,
        acking_policy_handle(import_changing, SessionState::Established),
        false,
    );
    insert_test_managed_peer(
        &mut manager,
        different_chain,
        established_export_policy_test_session(
            different_chain,
            Arc::clone(&different_installs),
            None,
        ),
        false,
    );

    let shared_next = deny_policy_chain();
    let other_next = validation_policy_chain(ImportValidationDependency::Aspa);
    let import_next = validation_policy_chain(ImportValidationDependency::Rpki);
    let targets = vec![
        ResolvedPeerPolicy {
            address: unchanged,
            interface: None,
            import_policy: None,
            export_policy: None,
        },
        ResolvedPeerPolicy {
            address: reconnecting,
            interface: None,
            import_policy: None,
            export_policy: Some(shared_next.clone()),
        },
        ResolvedPeerPolicy {
            address: first,
            interface: None,
            import_policy: None,
            export_policy: Some(shared_next.clone()),
        },
        ResolvedPeerPolicy {
            address: import_changing,
            interface: None,
            import_policy: Some(import_next.clone()),
            export_policy: None,
        },
        ResolvedPeerPolicy {
            address: second,
            interface: None,
            import_policy: None,
            export_policy: Some(shared_next.clone()),
        },
        ResolvedPeerPolicy {
            address: different_chain,
            interface: None,
            import_policy: None,
            export_policy: Some(other_next.clone()),
        },
    ];
    let priors = manager
        .apply_resolved_policy_snapshot(targets)
        .await
        .expect("mixed policy snapshot must commit");

    assert_eq!(
        priors.iter().map(|prior| prior.address).collect::<Vec<_>>(),
        vec![
            first,
            second,
            unchanged,
            reconnecting,
            import_changing,
            different_chain,
        ],
        "rollback tokens follow actual apply order: cohort, then stable remainder"
    );
    assert_eq!(cohort_installs.load(Ordering::SeqCst), 2);
    assert_eq!(different_installs.load(Ordering::SeqCst), 1);
    assert_eq!(
        manager.peers.get(&key(reconnecting)).unwrap().export_policy,
        Some(shared_next),
        "a reconnecting peer remains authoritative and keeps the desired session policy for PeerUp"
    );
    assert_eq!(
        manager
            .peers
            .get(&key(import_changing))
            .unwrap()
            .import_policy,
        Some(import_next)
    );
    assert_eq!(
        manager
            .peers
            .get(&key(different_chain))
            .unwrap()
            .export_policy,
        Some(other_next)
    );

    for peer in all_peers {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
    drop(manager);
    let (batches, singles) = rib_task.await.unwrap();
    assert_eq!(batches, vec![vec![first, second]]);
    assert_eq!(singles, vec![different_chain]);
}

#[tokio::test]
async fn export_only_snapshot_duplicate_key_disables_partitioning_wholesale() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let first = IpAddr::V4(Ipv4Addr::new(10, 37, 0, 1));
    let second = IpAddr::V4(Ipv4Addr::new(10, 37, 0, 2));
    let peers = [first, second];
    let attempts = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let rib_task = tokio::spawn(async move {
        let mut batches = 0usize;
        let mut singles = Vec::new();
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPolicies { reply, .. } => {
                    batches += 1;
                    let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
                }
                RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } => {
                    singles.push(peer);
                    let _ = reply.send(Ok(()));
                }
                _ => {}
            }
        }
        (batches, singles)
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
            established_export_policy_test_session(peer, Arc::clone(&attempts), None),
            false,
        );
    }
    let next = deny_policy_chain();
    let priors = manager
        .apply_resolved_policy_snapshot(
            [first, second, first]
                .into_iter()
                .map(|address| ResolvedPeerPolicy {
                    address,
                    interface: None,
                    import_policy: None,
                    export_policy: Some(next.clone()),
                })
                .collect(),
        )
        .await
        .expect("duplicate targets retain the pre-existing authoritative behavior");
    assert_eq!(
        priors.iter().map(|prior| prior.address).collect::<Vec<_>>(),
        vec![first, second, first]
    );

    for peer in peers {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
    drop(manager);
    let (batches, singles) = rib_task.await.unwrap();
    assert_eq!(batches, 0, "duplicate keys disable batching wholesale");
    assert_eq!(singles, vec![first, second]);
}

#[tokio::test]
async fn export_only_snapshot_cohort_failure_leaves_remainder_untouched() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let first = IpAddr::V4(Ipv4Addr::new(10, 38, 0, 1));
    let second = IpAddr::V4(Ipv4Addr::new(10, 38, 0, 2));
    let remainder = IpAddr::V4(Ipv4Addr::new(10, 38, 0, 3));
    let cohort_attempts = Arc::new(AtomicUsize::new(0));
    let remainder_attempts = Arc::new(AtomicUsize::new(0));
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
    for peer in [first, second] {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(peer, Arc::clone(&cohort_attempts), None),
            false,
        );
    }
    insert_test_managed_peer(
        &mut manager,
        remainder,
        established_export_policy_test_session(remainder, Arc::clone(&remainder_attempts), None),
        false,
    );
    let shared_next = deny_policy_chain();
    let other_next = validation_policy_chain(ImportValidationDependency::Aspa);
    let result = manager
        .apply_resolved_policy_snapshot(vec![
            ResolvedPeerPolicy {
                address: first,
                interface: None,
                import_policy: None,
                export_policy: Some(shared_next.clone()),
            },
            ResolvedPeerPolicy {
                address: second,
                interface: None,
                import_policy: None,
                export_policy: Some(shared_next),
            },
            ResolvedPeerPolicy {
                address: remainder,
                interface: None,
                import_policy: None,
                export_policy: Some(other_next),
            },
        ])
        .await;
    assert!(
        result
            .as_ref()
            .is_err_and(|error| error.contains("injected cohort failure"))
    );
    assert_eq!(cohort_attempts.load(Ordering::SeqCst), 4);
    assert_eq!(
        remainder_attempts.load(Ordering::SeqCst),
        0,
        "cohort failure must leave the authoritative remainder untouched"
    );
    assert!(
        manager
            .peers
            .get(&key(remainder))
            .unwrap()
            .export_policy
            .is_none()
    );

    for peer in [first, second, remainder] {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
    drop(manager);
    assert_eq!(rib_task.await.unwrap(), vec![second, first]);
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the cross-phase rollback regression pins failing remainder restoration before committed cohort unwind"
)]
async fn export_only_snapshot_remainder_failure_restores_remainder_then_cohort() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let first = IpAddr::V4(Ipv4Addr::new(10, 39, 0, 1));
    let second = IpAddr::V4(Ipv4Addr::new(10, 39, 0, 2));
    let remainder_first = IpAddr::V4(Ipv4Addr::new(10, 39, 0, 3));
    let remainder_failing = IpAddr::V4(Ipv4Addr::new(10, 39, 0, 4));
    let cohort_attempts = Arc::new(AtomicUsize::new(0));
    let remainder_first_attempts = Arc::new(AtomicUsize::new(0));
    let remainder_failing_attempts = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(32);
    let rib_task = tokio::spawn(async move {
        let mut singles = Vec::new();
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPolicies { reply, .. } => {
                    let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
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
    for peer in [first, second] {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(peer, Arc::clone(&cohort_attempts), None),
            false,
        );
    }
    insert_test_managed_peer(
        &mut manager,
        remainder_first,
        established_export_policy_test_session(
            remainder_first,
            Arc::clone(&remainder_first_attempts),
            None,
        ),
        false,
    );
    insert_test_managed_peer(
        &mut manager,
        remainder_failing,
        established_export_policy_test_session(
            remainder_failing,
            Arc::clone(&remainder_failing_attempts),
            Some(1),
        ),
        false,
    );
    let shared_next = deny_policy_chain();
    let other_next = validation_policy_chain(ImportValidationDependency::Aspa);
    let result = manager
        .apply_resolved_policy_snapshot(
            [
                (first, shared_next.clone()),
                (second, shared_next),
                (remainder_first, other_next.clone()),
                (remainder_failing, other_next),
            ]
            .into_iter()
            .map(|(address, export_policy)| ResolvedPeerPolicy {
                address,
                interface: None,
                import_policy: None,
                export_policy: Some(export_policy),
            })
            .collect(),
        )
        .await;
    assert!(
        result.as_ref().is_err_and(|error| {
            error.contains("failed to apply authoritative policy remainder")
                && error.contains("committed cohort restored")
        }),
        "remainder failure must compose its self-heal with cohort rollback: {result:?}"
    );
    for peer in [first, second, remainder_first, remainder_failing] {
        assert!(
            manager
                .peers
                .get(&key(peer))
                .unwrap()
                .export_policy
                .is_none(),
            "{peer} must finish on its prior export policy"
        );
    }
    assert_eq!(cohort_attempts.load(Ordering::SeqCst), 4);
    assert_eq!(remainder_first_attempts.load(Ordering::SeqCst), 2);
    assert_eq!(remainder_failing_attempts.load(Ordering::SeqCst), 2);

    for peer in [first, second, remainder_first, remainder_failing] {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
    drop(manager);
    assert_eq!(
        rib_task.await.unwrap(),
        vec![
            remainder_first,
            remainder_failing,
            remainder_first,
            second,
            first,
        ],
        "authoritative self-heal completes newest-first before cohort rollback"
    );
}

#[tokio::test(start_paused = true)]
#[expect(
    clippy::too_many_lines,
    reason = "the cross-partition deadline proof must hold both rollback partitions at once"
)]
async fn policy_rollback_rib_wait_has_one_cross_partition_deadline() {
    use rustbgpd_api::peer_types::{PeerManagerReadinessQuery, ResolvedPeerPolicy};

    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 39, 2, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 39, 2, 2)),
        IpAddr::V4(Ipv4Addr::new(10, 39, 2, 3)),
        IpAddr::V4(Ipv4Addr::new(10, 39, 2, 4)),
    ];
    let attempts = Arc::new(AtomicUsize::new(0));
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
            established_export_policy_test_session(peer, Arc::clone(&attempts), None),
            false,
        );
    }

    let cohort_policy = deny_policy_chain();
    let remainder_policy = validation_policy_chain(ImportValidationDependency::Aspa);
    let started = tokio::time::Instant::now();
    let apply = manager.apply_resolved_policy_snapshot(
        peers
            .into_iter()
            .zip([
                cohort_policy.clone(),
                cohort_policy,
                remainder_policy.clone(),
                remainder_policy,
            ])
            .map(|(address, export_policy)| ResolvedPeerPolicy {
                address,
                interface: None,
                import_policy: None,
                export_policy: Some(export_policy),
            })
            .collect(),
    );
    let drive_rib = async {
        skip_destination_prestage(&mut rib_rx).await;
        let RibUpdate::ReplacePeerExportPolicies { reply, .. } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected cohort commit");
        };
        reply
            .send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed))
            .unwrap();

        for (index, expected_peer) in peers[2..].iter().copied().enumerate() {
            let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } =
                rib_rx.recv().await.unwrap()
            else {
                panic!("expected remainder forward command");
            };
            assert_eq!(peer, expected_peer);
            if index == 0 {
                reply.send(Ok(())).unwrap();
            } else {
                reply
                    .send(Err(rustbgpd_rib::RibCommandError::internal(
                        "force cross-partition rollback",
                    )))
                    .unwrap();
            }
        }

        let mut late_replies = Vec::new();
        for expected_peer in peers[2..].iter().rev() {
            let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } =
                rib_rx.recv().await.unwrap()
            else {
                panic!("expected remainder rollback command");
            };
            assert_eq!(peer, *expected_peer);
            late_replies.push(reply);
        }

        let (readiness_reply, readiness_response) = oneshot::channel();
        readiness_tx
            .send(PeerManagerReadinessQuery::ListPeers {
                reply: readiness_reply,
            })
            .await
            .unwrap();
        // LOAD-BEARING: awaiting the registered aggregate without the
        // read-only readiness lane makes this deadline expire.
        assert_eq!(
            tokio::time::timeout(
                rustbgpd_api::health_probe::CORE_READINESS_DEADLINE,
                readiness_response,
            )
            .await
            .expect("readiness must remain live during rollback RIB congestion")
            .unwrap()
            .len(),
            peers.len()
        );

        tokio::time::advance(RIB_REPLY_TIMEOUT + Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        for expected_peer in peers[..2].iter().rev() {
            let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } =
                rib_rx.recv().await.unwrap()
            else {
                panic!("expected cohort rollback command");
            };
            assert_eq!(peer, *expected_peer);
            late_replies.push(reply);
        }
        late_replies
    };
    let (result, late_replies) = tokio::join!(apply, drive_rib);

    // LOAD-BEARING: constructing a fresh five-second timeout for the cohort
    // unwind makes elapsed time ten seconds and this assertion goes red.
    assert!(
        tokio::time::Instant::now().duration_since(started)
            < RIB_REPLY_TIMEOUT + Duration::from_secs(1),
        "all rollback partitions must share the first rollback RIB deadline"
    );
    assert!(
        result.as_ref().is_err_and(|error| {
            error.contains("force cross-partition rollback")
                && error.matches("shared 5s deadline").count() == 2
        }),
        "both timed-out partitions must report the shared deadline: {result:?}"
    );
    for reply in late_replies {
        assert!(
            reply.send(Ok(())).is_ok(),
            "the exact timed-out RIB future must remain detached for late repair"
        );
    }
    for peer in peers {
        let peer_state = manager.peers.get(&key(peer)).unwrap();
        assert!(peer_state.pending_export_apply);
    }
}

#[tokio::test(start_paused = true)]
async fn policy_rollback_rib_deadline_starts_after_session_restores() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    const PEER_COUNT: u8 = 13;
    const ROLLBACK_EXPORT_DELAY: Duration = Duration::from_millis(450);

    let peers = (1..=PEER_COUNT)
        .map(|last| IpAddr::V4(Ipv4Addr::new(10, 39, 5, last)))
        .collect::<Vec<_>>();
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
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
            rollback_ordering_policy_session(
                peer,
                rib_tx.clone(),
                index + 1 == peers.len(),
                Some(ROLLBACK_EXPORT_DELAY),
            ),
            false,
        );
    }

    let started = tokio::time::Instant::now();
    let apply = manager.apply_resolved_policy_snapshot(
        peers
            .iter()
            .copied()
            .map(|address| ResolvedPeerPolicy {
                address,
                interface: None,
                import_policy: None,
                export_policy: Some(deny_policy_chain()),
            })
            .collect(),
    );
    let drive_rib = async {
        skip_destination_prestage(&mut rib_rx).await;
        let mut replies = Vec::new();
        for expected_peer in peers[..peers.len() - 1].iter().rev() {
            let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } =
                rib_rx.recv().await.unwrap()
            else {
                panic!("expected rollback RIB restore");
            };
            assert_eq!(peer, *expected_peer);
            replies.push(reply);
        }
        assert!(
            tokio::time::Instant::now().duration_since(started) > RIB_REPLY_TIMEOUT,
            "successful session restores must consume more than the RIB-only deadline"
        );

        tokio::time::advance(
            RIB_REPLY_TIMEOUT
                .checked_sub(Duration::from_millis(1))
                .expect("RIB reply timeout exceeds one millisecond"),
        )
        .await;
        tokio::task::yield_now().await;
        for reply in replies {
            reply.send(Ok(())).unwrap();
        }
    };
    let (result, ()) = tokio::join!(apply, drive_rib);

    // LOAD-BEARING: moving `budget.deadline()` to the start of
    // `restore_resolved_policies` makes this red because the successful session
    // restores consume that prematurely anchored RIB-only wait budget.
    assert!(
        result.as_ref().is_err_and(|error| {
            error.contains("injected final session failure")
                && error.contains("already-applied peers restored")
        }),
        "rollback RIB waiting must receive a fresh deadline after session restores: {result:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn timed_out_policy_rollback_rearms_import_and_export_retry_intent() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 39, 3, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 39, 3, 2)),
    ];
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(8);
    let (_command_tx, command_rx) = mpsc::channel(8);
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
            acking_policy_handle(peer, SessionState::Established),
            false,
        );
    }
    let next = deny_policy_chain();
    // Distinct export targets keep this snapshot off the LAN-462
    // import-tolerant cohort (no repeated export pair) and on the per-peer
    // authoritative transaction whose rollback this regression pins.
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
        for (index, expected_peer) in peers.iter().copied().enumerate() {
            let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } =
                rib_rx.recv().await.unwrap()
            else {
                panic!("expected forward RIB command");
            };
            assert_eq!(peer, expected_peer);
            if index == 0 {
                reply.send(Ok(())).unwrap();
            } else {
                reply
                    .send(Err(rustbgpd_rib::RibCommandError::internal(
                        "force rollback timeout",
                    )))
                    .unwrap();
            }
        }
        let mut held = Vec::new();
        for expected_peer in peers.iter().rev() {
            let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } =
                rib_rx.recv().await.unwrap()
            else {
                panic!("expected rollback RIB command");
            };
            assert_eq!(peer, *expected_peer);
            held.push(reply);
        }
        tokio::time::advance(RIB_REPLY_TIMEOUT + Duration::from_millis(1)).await;
        held
    };
    let (result, held) = tokio::join!(apply, drive_rib);
    assert!(result.is_err());

    for peer in peers {
        let peer_state = manager.peers.get(&key(peer)).unwrap();
        // LOAD-BEARING: clearing rollback refresh state before a timed-out RIB
        // aggregate without rearming it makes pending_refresh false here.
        assert!(peer_state.pending_refresh);
        assert!(peer_state.pending_export_apply);
    }
    for reply in held {
        assert!(reply.send(Ok(())).is_ok());
    }
}

#[tokio::test]
async fn policy_rollback_skips_refresh_when_rib_restore_cannot_register() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let peers = [
        IpAddr::V4(Ipv4Addr::new(10, 39, 4, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 39, 4, 2)),
    ];
    let counters = [
        Arc::new(FakePeerCounters::default()),
        Arc::new(FakePeerCounters::default()),
    ];
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(8);
    let (_command_tx, command_rx) = mpsc::channel(8);
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
    for (peer, counter) in peers.iter().copied().zip(&counters) {
        insert_test_managed_peer(
            &mut manager,
            peer,
            acking_counted_policy_handle(peer, Arc::clone(counter)),
            false,
        );
    }

    let next = deny_policy_chain();
    // Distinct export targets keep this snapshot off the LAN-462
    // import-tolerant cohort (no repeated export pair) and on the per-peer
    // authoritative transaction whose rollback this regression pins.
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
    let close_rib_before_rollback = async {
        let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected first forward RIB command");
        };
        assert_eq!(peer, peers[0]);
        reply.send(Ok(())).unwrap();

        let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected second forward RIB command");
        };
        assert_eq!(peer, peers[1]);
        reply
            .send(Err(rustbgpd_rib::RibCommandError::internal(
                "force rollback after one completed peer",
            )))
            .unwrap();
        drop(rib_rx);
    };
    let (result, ()) = tokio::join!(apply, close_rib_before_rollback);

    assert!(
        result
            .as_ref()
            .is_err_and(|error| error.contains("force rollback after one completed peer")),
        "the injected second-peer failure must drive rollback: {result:?}"
    );
    // LOAD-BEARING: removing the immediate-registration-failure refresh gate
    // sends a second Route Refresh to peer 1 even though its RIB restore was
    // never queued, making this exact count red. Peer 2 failed before its
    // forward refresh, so it must remain at zero as well.
    assert_eq!(counters[0].route_refresh.load(Ordering::SeqCst), 1);
    assert_eq!(counters[1].route_refresh.load(Ordering::SeqCst), 0);
    for peer in peers {
        let peer_state = manager.peers.get(&key(peer)).unwrap();
        assert!(peer_state.pending_refresh);
        assert!(peer_state.pending_export_apply);
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the mutation-sensitive cross-phase regression keeps the ambiguous session state and exact rollback order in one proof"
)]
async fn export_only_snapshot_reasserts_prior_import_after_remainder_ack_loss() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let first = IpAddr::V4(Ipv4Addr::new(10, 39, 1, 1));
    let second = IpAddr::V4(Ipv4Addr::new(10, 39, 1, 2));
    let remainder = IpAddr::V4(Ipv4Addr::new(10, 39, 1, 3));
    let cohort_installs = Arc::new(AtomicUsize::new(0));
    let live_import = Arc::new(Mutex::new(None));
    let import_installs = Arc::new(AtomicUsize::new(0));
    let refreshes = Arc::new(AtomicUsize::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(16);
    let rib_task = tokio::spawn(async move {
        let mut batches = Vec::new();
        let mut singles = Vec::new();
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPolicies {
                    replacements,
                    reply,
                } => {
                    batches.push(
                        replacements
                            .into_iter()
                            .map(|replacement| replacement.peer)
                            .collect::<Vec<_>>(),
                    );
                    let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
                }
                RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } => {
                    singles.push(peer);
                    let _ = reply.send(Ok(()));
                }
                _ => {}
            }
        }
        (batches, singles)
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
    for peer in [first, second] {
        insert_test_managed_peer(
            &mut manager,
            peer,
            established_export_policy_test_session(peer, Arc::clone(&cohort_installs), None),
            false,
        );
    }
    insert_test_managed_peer(
        &mut manager,
        remainder,
        import_ack_loss_policy_handle(
            remainder,
            Arc::clone(&live_import),
            Arc::clone(&import_installs),
            Arc::clone(&refreshes),
        ),
        false,
    );

    let shared_export = deny_policy_chain();
    let changed_import = validation_policy_chain(ImportValidationDependency::Rpki);
    let result = manager
        .apply_resolved_policy_snapshot(vec![
            ResolvedPeerPolicy {
                address: first,
                interface: None,
                import_policy: None,
                export_policy: Some(shared_export.clone()),
            },
            ResolvedPeerPolicy {
                address: second,
                interface: None,
                import_policy: None,
                export_policy: Some(shared_export),
            },
            ResolvedPeerPolicy {
                address: remainder,
                interface: None,
                import_policy: Some(changed_import),
                export_policy: None,
            },
        ])
        .await;
    assert!(
        result.as_ref().is_err_and(|error| {
            error.contains("failed to apply authoritative policy remainder")
                && error.contains("committed cohort restored")
        }),
        "the ambiguous remainder failure must unwind both phases: {result:?}"
    );
    // LOAD-BEARING: treating the ambiguous forward import command as complete
    // suppresses its rollback reassertion; the live chain and install count
    // below then remain on the changed policy and make this test red.
    assert_eq!(
        *live_import.lock().unwrap(),
        None,
        "rollback must reassert the prior import chain after the forward command mutated then lost its reply"
    );
    assert_eq!(
        import_installs.load(Ordering::SeqCst),
        2,
        "the session must observe the ambiguous forward install and the explicit prior reassert"
    );
    assert_eq!(
        refreshes.load(Ordering::SeqCst),
        1,
        "the rollback refresh must run only after the prior chain is reasserted"
    );
    let remainder_state = manager.peers.get(&key(remainder)).unwrap();
    assert!(remainder_state.import_policy.is_none());
    assert!(!remainder_state.pending_refresh);
    assert_eq!(cohort_installs.load(Ordering::SeqCst), 4);

    for peer in [first, second, remainder] {
        manager.delete_peer(key(peer), false).await.unwrap();
    }
    drop(manager);
    let (batches, singles) = rib_task.await.unwrap();
    assert_eq!(batches, vec![vec![first, second]]);
    assert_eq!(singles, vec![second, first]);
}
