use super::*;
use rustbgpd_rib::PeerId;

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
                    *live_import.lock().unwrap() = policy.map(|policy| *policy);
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
#[expect(
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
                            rejected_routes_retained: 0,
                            policy_reject_counts: None,
                            pre_policy_route_counts: None,
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
                            reconnect_in_secs: 0,
                            notification_idle_failures: 0,
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

    let a = PeerId::from_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let (handle_a, counters_a) = fake_session(a.addr());
    let (handle_b, counters_b) = fake_session(b);

    // RIB drainer counting export-policy replacements per peer.
    let rib_replaces_a = Arc::new(AtomicU32::new(0));
    let rib_replaces_b = Arc::new(AtomicU32::new(0));
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
    let (replaces_a, replaces_b) = (rib_replaces_a.clone(), rib_replaces_b.clone());
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            match update {
                // The scoped re-apply: the one changed peer is alone in its
                // export pair and goes to the RIB as a batch of one.
                RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
                    replacements,
                    reply,
                } => {
                    if sole_replacement(replacements).peer == a {
                        replaces_a.fetch_add(1, Ordering::SeqCst);
                    } else {
                        replaces_b.fetch_add(1, Ordering::SeqCst);
                    }
                    let _ = reply.send(Ok(Vec::new()));
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
    insert_test_managed_peer(&mut mgr, a.addr(), handle_a, false);
    insert_test_managed_peer(&mut mgr, b, handle_b, false);

    // Initial install through the atomic fan-out both edits ride.
    let target = |address: IpAddr, chain: PolicyChain| ResolvedPeerPolicy {
        address,
        interface: None,
        import_policy: Some(chain.clone()),
        export_policy: Some(chain),
    };
    mgr.apply_resolved_policy_snapshot(vec![
        target(a.addr(), permit_policy_chain()),
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
        target(a.addr(), permit_policy_chain()),
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
        "content-equal re-resolve must not send an export-policy replacement \
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
    let selected = manager
        .export_only_policy_cohort_mask(&targets, OperatorReadAdmission::Served)
        .await;

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
        let mut authoritative = Vec::new();
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
                            .map(|replacement| replacement.peer.addr())
                            .collect::<Vec<_>>(),
                    );
                    let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
                }
                RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
                    replacements,
                    reply,
                } => {
                    authoritative.push(
                        replacements
                            .into_iter()
                            .map(|replacement| replacement.peer.addr())
                            .collect::<Vec<_>>(),
                    );
                    let _ = reply.send(Ok(Vec::new()));
                }
                RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } => {
                    singles.push(peer.addr());
                    let _ = reply.send(Ok(()));
                }
                _ => {}
            }
        }
        (batches, authoritative, singles)
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
    let (batches, authoritative, singles) = rib_task.await.unwrap();
    assert_eq!(batches, vec![large.to_vec()]);
    assert_eq!(
        authoritative,
        vec![small.to_vec(), vec![ninth], vec![tenth]],
        "a losing pair takes one authoritative batch, not a command per member; a peer \
         alone in its pair takes a batch of one"
    );
    assert!(
        singles.is_empty(),
        "no remainder peer takes the per-peer command: {singles:?}"
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
        let mask = manager
            .export_only_policy_cohort_mask(&targets, OperatorReadAdmission::Served)
            .await;
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
                            .map(|replacement| replacement.peer.addr())
                            .collect::<Vec<_>>(),
                    );
                    let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
                }
                RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
                    replacements,
                    reply,
                } => {
                    singles.push(sole_replacement(replacements).peer.addr());
                    let _ = reply.send(Ok(Vec::new()));
                }
                RibUpdate::ReplacePeerExportPolicy { peer, .. } => {
                    panic!("{peer} must not take a per-peer command in a snapshot walk");
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
                    singles.push(peer.addr());
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
#[expect(
    clippy::too_many_lines,
    reason = "the partition regression keeps the failed cohort batch, exact rollback receipt, and untouched remainder assertions together"
)]
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
                    singles.push(peer.addr());
                    let _ = reply.send(Ok(()));
                }
                RibUpdate::RestorePeerExportPoliciesAuthoritatively {
                    replacements,
                    reply,
                } => {
                    // A failed cohort is compensated by one exact batch. Append
                    // its actual reverse execution order for the existing proof.
                    let receipts = replacements
                        .iter()
                        .rev()
                        .map(|replacement| {
                            singles.push(replacement.peer.addr());
                            rustbgpd_rib::PeerExportPolicyRestoreReceipt::Restored {
                                peer: replacement.peer,
                            }
                        })
                        .collect();
                    let _ = reply.send(Ok(receipts));
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
                    singles.push(peer.addr());
                    let _ = reply.send(Ok(()));
                }
                RibUpdate::RestorePeerExportPoliciesAuthoritatively {
                    replacements,
                    reply,
                } => {
                    // Preserve the old cross-partition execution-order proof:
                    // each partition is now one aggregate whose RIB execution
                    // and receipt order are reverse supplied order.
                    let receipts = replacements
                        .iter()
                        .rev()
                        .map(|replacement| {
                            singles.push(replacement.peer.addr());
                            rustbgpd_rib::PeerExportPolicyRestoreReceipt::Restored {
                                peer: replacement.peer,
                            }
                        })
                        .collect();
                    let _ = reply.send(Ok(receipts));
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
        // The remainder pair shares one export pair, so its RIB step is
        // deferred past both session legs and was never sent: the session
        // failure comes first. Both members are restored all the same: a
        // member can register with the RIB during the walk, and that
        // registration installs the candidate chain its session holds.
        vec![remainder_failing, remainder_first, second, first],
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

        let RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
            replacements,
            reply,
        } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected the remainder pair's forward batch");
        };
        assert_eq!(
            replacements
                .iter()
                .map(|replacement| replacement.peer)
                .collect::<Vec<_>>(),
            peers[2..]
                .iter()
                .copied()
                .map(PeerId::from_addr)
                .collect::<Vec<_>>()
        );
        reply
            .send(Err(rustbgpd_rib::RibCommandError::internal(
                "force cross-partition rollback",
            )))
            .unwrap();

        // Each rollback partition now registers one exact aggregate. The RIB
        // reverses supplied forward order and receipts that execution order.
        let mut late_replies = Vec::new();
        let RibUpdate::RestorePeerExportPoliciesAuthoritatively {
            replacements,
            reply,
        } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected remainder rollback batch");
        };
        assert_eq!(
            replacements
                .iter()
                .map(|replacement| replacement.peer.addr())
                .collect::<Vec<_>>(),
            peers[2..]
        );
        late_replies.push((
            reply,
            replacements
                .iter()
                .rev()
                .map(
                    |replacement| rustbgpd_rib::PeerExportPolicyRestoreReceipt::Restored {
                        peer: replacement.peer,
                    },
                )
                .collect::<Vec<_>>(),
        ));

        let (readiness_reply, readiness_response) = oneshot::channel();
        readiness_tx
            .send(PeerManagerReadinessQuery::Ping {
                reply: readiness_reply,
            })
            .await
            .unwrap();
        // LOAD-BEARING: awaiting the registered aggregate without the
        // read-only readiness lane makes this deadline expire.
        tokio::time::timeout(
            rustbgpd_api::health_probe::CORE_READINESS_DEADLINE,
            readiness_response,
        )
        .await
        .expect("readiness must remain live during rollback RIB congestion")
        .unwrap();

        tokio::time::advance(RIB_BATCH_REPLY_TIMEOUT + Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        let RibUpdate::RestorePeerExportPoliciesAuthoritatively {
            replacements,
            reply,
        } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected cohort rollback batch");
        };
        assert_eq!(
            replacements
                .iter()
                .map(|replacement| replacement.peer.addr())
                .collect::<Vec<_>>(),
            peers[..2]
        );
        late_replies.push((
            reply,
            replacements
                .iter()
                .rev()
                .map(
                    |replacement| rustbgpd_rib::PeerExportPolicyRestoreReceipt::Restored {
                        peer: replacement.peer,
                    },
                )
                .collect::<Vec<_>>(),
        ));
        late_replies
    };
    let (result, late_replies) = tokio::join!(apply, drive_rib);

    // LOAD-BEARING: constructing a fresh two-minute timeout for the cohort
    // unwind makes elapsed time four minutes and this assertion goes red.
    assert!(
        tokio::time::Instant::now().duration_since(started)
            < RIB_BATCH_REPLY_TIMEOUT + Duration::from_secs(1),
        "all rollback partitions must share the first rollback RIB deadline"
    );
    assert!(
        result.as_ref().is_err_and(|error| {
            error.contains("force cross-partition rollback")
                && error.matches("policy_rollback_batch_timeout").count() == 2
        }),
        "both timed-out partitions must report the shared deadline: {result:?}"
    );
    for (reply, receipts) in late_replies {
        assert!(
            reply.send(Ok(receipts)).is_ok(),
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
        // Session compensation may be slow, but the RIB-only deadline is
        // anchored lazily when this aggregate is registered afterwards.
        let RibUpdate::RestorePeerExportPoliciesAuthoritatively {
            replacements,
            reply,
        } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected exact rollback RIB batch");
        };
        assert_eq!(
            replacements
                .iter()
                .map(|replacement| replacement.peer.addr())
                .collect::<Vec<_>>(),
            peers[..peers.len() - 1]
        );
        assert!(
            tokio::time::Instant::now().duration_since(started) > RIB_REPLY_TIMEOUT,
            "successful session restores must consume more than the RIB-only deadline"
        );

        tokio::time::advance(
            RIB_BATCH_REPLY_TIMEOUT
                .checked_sub(Duration::from_millis(1))
                .expect("RIB batch reply timeout exceeds one millisecond"),
        )
        .await;
        tokio::task::yield_now().await;
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
            let RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
                replacements,
                reply,
            } = rib_rx.recv().await.unwrap()
            else {
                panic!("expected forward RIB command");
            };
            assert_eq!(
                sole_replacement(replacements).peer,
                PeerId::from_addr(expected_peer)
            );
            if index == 0 {
                reply.send(Ok(Vec::new())).unwrap();
            } else {
                reply
                    .send(Err(rustbgpd_rib::RibCommandError::internal(
                        "force rollback timeout",
                    )))
                    .unwrap();
            }
        }
        let RibUpdate::RestorePeerExportPoliciesAuthoritatively {
            replacements,
            reply,
        } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected exact rollback RIB batch");
        };
        assert_eq!(
            replacements
                .iter()
                .map(|replacement| replacement.peer.addr())
                .collect::<Vec<_>>(),
            peers
        );
        let receipts = replacements
            .iter()
            .rev()
            .map(
                |replacement| rustbgpd_rib::PeerExportPolicyRestoreReceipt::Restored {
                    peer: replacement.peer,
                },
            )
            .collect::<Vec<_>>();
        tokio::time::advance(RIB_BATCH_REPLY_TIMEOUT + Duration::from_millis(1)).await;
        (reply, receipts)
    };
    let (result, (held_reply, receipts)) = tokio::join!(apply, drive_rib);
    assert!(result.is_err());

    for peer in peers {
        let peer_state = manager.peers.get(&key(peer)).unwrap();
        // LOAD-BEARING: clearing rollback refresh state before a timed-out RIB
        // aggregate without rearming it makes pending_refresh false here.
        assert!(peer_state.pending_refresh);
        assert!(peer_state.pending_export_apply);
    }
    assert!(held_reply.send(Ok(receipts)).is_ok());
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
        let RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
            replacements,
            reply,
        } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected first forward RIB command");
        };
        assert_eq!(
            sole_replacement(replacements).peer,
            PeerId::from_addr(peers[0])
        );
        reply.send(Ok(Vec::new())).unwrap();

        let RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
            replacements,
            reply,
        } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected second forward RIB command");
        };
        assert_eq!(
            sole_replacement(replacements).peer,
            PeerId::from_addr(peers[1])
        );
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
                            .map(|replacement| replacement.peer.addr())
                            .collect::<Vec<_>>(),
                    );
                    let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
                }
                RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } => {
                    singles.push(peer.addr());
                    let _ = reply.send(Ok(()));
                }
                RibUpdate::RestorePeerExportPoliciesAuthoritatively {
                    replacements,
                    reply,
                } => {
                    // The remainder has no export delta; the committed cohort
                    // unwind is the single exact rollback batch recorded here.
                    let receipts = replacements
                        .iter()
                        .rev()
                        .map(|replacement| {
                            singles.push(replacement.peer.addr());
                            rustbgpd_rib::PeerExportPolicyRestoreReceipt::Restored {
                                peer: replacement.peer,
                            }
                        })
                        .collect();
                    let _ = reply.send(Ok(receipts));
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

/// The stable remainder's work is counted in RIB commands: every export pair
/// shared by two or more Established remainder peers costs one authoritative
/// batch, and a peer whose pair is its own is a batch of one. The batches
/// follow every session leg, one export pair at a time in the order each
/// pair first appears. Each RIB command here takes 35 s, so the remainder
/// (two pairs of two and one single) is three commands and 105 s; one
/// command per member would be five.
#[tokio::test(start_paused = true)]
#[expect(
    clippy::too_many_lines,
    reason = "one fixture holds the timed RIB stub, the interleaved fleet and the command-order proof"
)]
async fn authoritative_remainder_batches_each_shared_export_pair() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let peer = |last| IpAddr::V4(Ipv4Addr::new(10, 36, 4, last));
    let cohort = [peer(1), peer(2), peer(3)];
    let pair_b = [peer(4), peer(5)];
    let pair_c = [peer(6), peer(7)];
    let single = peer(8);
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(32);
    let rib_task = tokio::spawn(async move {
        let mut commands: Vec<(&'static str, Vec<IpAddr>)> = Vec::new();
        let addrs = |replacements: &[rustbgpd_rib::PeerExportPolicyReplacement]| {
            replacements
                .iter()
                .map(|replacement| replacement.peer.addr())
                .collect::<Vec<_>>()
        };
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPolicies {
                    replacements,
                    reply,
                } => {
                    commands.push(("cohort", addrs(&replacements)));
                    let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
                }
                RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
                    replacements,
                    reply,
                } => {
                    commands.push(("batch", addrs(&replacements)));
                    tokio::time::sleep(Duration::from_secs(35)).await;
                    let _ = reply.send(Ok(Vec::new()));
                }
                RibUpdate::ReplacePeerExportPolicy { peer, .. } => {
                    panic!("{peer} must not take a per-peer command in a snapshot walk");
                }
                RibUpdate::RestorePeerExportPoliciesAuthoritatively {
                    replacements,
                    reply,
                } => {
                    commands.push(("restore", addrs(&replacements)));
                    let _ = reply.send(Ok(replacements
                        .iter()
                        .rev()
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
        commands
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
    let all = cohort
        .into_iter()
        .chain(pair_b)
        .chain(pair_c)
        .chain([single])
        .collect::<Vec<_>>();
    for &address in &all {
        insert_test_managed_peer(
            &mut manager,
            address,
            established_export_policy_test_session(address, Arc::clone(&installs), None),
            false,
        );
    }
    let chain_of = |address: IpAddr| {
        distinct_deny_policy_chain(if cohort.contains(&address) {
            0
        } else if pair_b.contains(&address) {
            1
        } else if pair_c.contains(&address) {
            2
        } else {
            3
        })
    };
    // Interleaved caller order: sharing a pair does not depend on adjacency.
    let order = [
        cohort[0], pair_b[0], pair_c[0], single, cohort[1], pair_b[1], pair_c[1], cohort[2],
    ];
    let result = manager
        .apply_resolved_policy_snapshot(
            order
                .into_iter()
                .map(|address| ResolvedPeerPolicy {
                    address,
                    interface: None,
                    import_policy: None,
                    export_policy: Some(chain_of(address)),
                })
                .collect(),
        )
        .await;
    for &address in &all {
        manager.delete_peer(key(address), false).await.unwrap();
    }
    drop(manager);
    let commands = rib_task.await.unwrap();
    assert!(
        result.is_ok(),
        "the remainder must commit: {result:?}; RIB commands: {commands:?}"
    );
    assert_eq!(
        commands,
        vec![
            ("cohort", cohort.to_vec()),
            // Pairs in first-occurrence order: the caller named a member of
            // each shared pair before the single.
            ("batch", pair_b.to_vec()),
            ("batch", pair_c.to_vec()),
            ("batch", vec![single]),
        ],
        "one RIB batch per export pair, not one command per member"
    );
}

/// A remainder pair whose import chain also moves fires each member's Route
/// Refresh only after the pair's RIB batch has committed, and exactly once.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one fixture holds the recording RIB stub, both partitions and the ordering proof"
)]
async fn batched_remainder_pair_defers_route_refresh_past_its_rib_batch() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let peer = |last| IpAddr::V4(Ipv4Addr::new(10, 36, 5, last));
    let cohort = [peer(1), peer(2), peer(3)];
    let pair = [peer(4), peer(5)];
    let counters = pair.map(|_| Arc::new(FakePeerCounters::default()));
    let refreshes = {
        let counters = counters.clone();
        move || {
            counters
                .iter()
                .map(|counters| counters.route_refresh.load(Ordering::SeqCst))
                .collect::<Vec<_>>()
        }
    };
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(32);
    let refreshes_at_batch = refreshes.clone();
    let rib_task = tokio::spawn(async move {
        let mut seen = Vec::new();
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPolicies { reply, .. } => {
                    let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
                }
                RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
                    replacements,
                    reply,
                } => {
                    seen.push((
                        replacements
                            .iter()
                            .map(|replacement| replacement.peer.addr())
                            .collect::<Vec<_>>(),
                        refreshes_at_batch(),
                    ));
                    let _ = reply.send(Ok(Vec::new()));
                }
                RibUpdate::ReplacePeerExportPolicy { peer, .. } => {
                    panic!("{peer} shares its export pair and must not take a per-peer command");
                }
                _ => {}
            }
        }
        seen
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
    for address in cohort {
        insert_test_managed_peer(
            &mut manager,
            address,
            established_export_policy_test_session(address, Arc::clone(&installs), None),
            false,
        );
    }
    for (address, counters) in pair.into_iter().zip(&counters) {
        insert_test_managed_peer(
            &mut manager,
            address,
            acking_counted_policy_handle(address, Arc::clone(counters)),
            false,
        );
    }
    let import_next = validation_policy_chain(ImportValidationDependency::Rpki);
    manager
        .apply_resolved_policy_snapshot(
            cohort
                .into_iter()
                .map(|address| (address, None, distinct_deny_policy_chain(0)))
                .chain(pair.into_iter().map(|address| {
                    (
                        address,
                        Some(import_next.clone()),
                        distinct_deny_policy_chain(1),
                    )
                }))
                .map(
                    |(address, import_policy, export_policy)| ResolvedPeerPolicy {
                        address,
                        interface: None,
                        import_policy,
                        export_policy: Some(export_policy),
                    },
                )
                .collect(),
        )
        .await
        .expect("import and export remainder pair must commit");
    assert_eq!(
        refreshes(),
        vec![1, 1],
        "each pair member's import change fires one Route Refresh"
    );
    for address in pair {
        let state = manager.peers.get(&key(address)).unwrap();
        assert_eq!(state.import_policy, Some(import_next.clone()));
        assert!(!state.pending_refresh && !state.pending_export_apply);
    }
    for address in cohort.into_iter().chain(pair) {
        manager.delete_peer(key(address), false).await.unwrap();
    }
    drop(manager);
    assert_eq!(
        rib_task.await.unwrap(),
        vec![(pair.to_vec(), vec![0, 0])],
        "the pair's one RIB batch precedes both Route Refreshes"
    );
}

/// Two shared pairs in the remainder, the second pair's batch failing. The
/// first pair's Route Refreshes are sent as soon as that pair commits, before
/// the second pair's batch, and the rollback restores every remainder member
/// of both pairs, then the cohort.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one fixture holds the recording RIB stub, three partitions and the rollback order proof"
)]
async fn second_remainder_pair_failure_restores_both_pairs_after_first_pair_refreshes() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let peer = |last| IpAddr::V4(Ipv4Addr::new(10, 36, 7, last));
    let cohort = [peer(1), peer(2), peer(3)];
    let pair_b = [peer(4), peer(5)];
    let pair_c = [peer(6), peer(7)];
    let counters = pair_b.map(|_| Arc::new(FakePeerCounters::default()));
    let refreshes = {
        let counters = counters.clone();
        move || {
            counters
                .iter()
                .map(|counters| counters.route_refresh.load(Ordering::SeqCst))
                .collect::<Vec<_>>()
        }
    };
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(32);
    let rib_task = tokio::spawn(async move {
        let mut seen: Vec<(&'static str, Vec<IpAddr>, Vec<u32>)> = Vec::new();
        let addrs = |replacements: &[rustbgpd_rib::PeerExportPolicyReplacement]| {
            replacements
                .iter()
                .map(|replacement| replacement.peer.addr())
                .collect::<Vec<_>>()
        };
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPolicies { reply, .. } => {
                    let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
                }
                RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
                    replacements,
                    reply,
                } => {
                    let members = addrs(&replacements);
                    let fails = members == pair_c;
                    seen.push(("batch", members, refreshes()));
                    let _ = reply.send(if fails {
                        Err(rustbgpd_rib::RibCommandError::internal(
                            "second pair refused",
                        ))
                    } else {
                        Ok(Vec::new())
                    });
                }
                RibUpdate::RestorePeerExportPoliciesAuthoritatively {
                    replacements,
                    reply,
                } => {
                    seen.push(("restore", addrs(&replacements), Vec::new()));
                    let _ = reply.send(Ok(replacements
                        .iter()
                        .rev()
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
        seen
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
    for address in cohort.into_iter().chain(pair_c) {
        insert_test_managed_peer(
            &mut manager,
            address,
            established_export_policy_test_session(address, Arc::clone(&installs), None),
            false,
        );
    }
    for (address, counters) in pair_b.into_iter().zip(&counters) {
        insert_test_managed_peer(
            &mut manager,
            address,
            acking_counted_policy_handle(address, Arc::clone(counters)),
            false,
        );
    }
    let import_next = validation_policy_chain(ImportValidationDependency::Rpki);
    let target = |address: IpAddr| ResolvedPeerPolicy {
        address,
        interface: None,
        import_policy: pair_b.contains(&address).then(|| import_next.clone()),
        export_policy: Some(distinct_deny_policy_chain(if cohort.contains(&address) {
            0
        } else if pair_b.contains(&address) {
            1
        } else {
            2
        })),
    };
    let all: Vec<IpAddr> = cohort.into_iter().chain(pair_b).chain(pair_c).collect();
    let result = manager
        .apply_resolved_policy_snapshot(all.iter().copied().map(target).collect())
        .await;
    assert!(
        result.as_ref().is_err_and(|error| {
            error.contains("second pair refused")
                && error.contains("already-applied peers restored")
                && error.contains("committed cohort restored")
        }),
        "{result:?}"
    );
    for &address in &all {
        let state = manager.peers.get(&key(address)).unwrap();
        assert!(state.export_policy.is_none() && state.import_policy.is_none());
        assert!(!state.pending_refresh && !state.pending_export_apply);
        manager.delete_peer(key(address), false).await.unwrap();
    }
    drop(manager);
    assert_eq!(
        rib_task.await.unwrap(),
        vec![
            ("batch", pair_b.to_vec(), vec![0, 0]),
            // The first pair's refreshes went out before the second batch.
            ("batch", pair_c.to_vec(), vec![1, 1]),
            // Every remainder member is restored, whichever batch failed.
            (
                "restore",
                pair_b.into_iter().chain(pair_c).collect(),
                Vec::new()
            ),
            ("restore", cohort.to_vec(), Vec::new()),
        ]
    );
}

type RollbackCommands = Arc<std::sync::Mutex<Vec<(&'static str, Vec<IpAddr>)>>>;

/// What a paced rollback fixture run leaves to read back.
struct PacedRollback {
    result: Result<Vec<rustbgpd_api::peer_types::ResolvedPeerPolicy>, String>,
    elapsed: Duration,
    /// RIB restore commands seen so far; the stub keeps running.
    commands: RollbackCommands,
    /// Each peer's `pending_export_apply` when the snapshot returned.
    pending: Vec<bool>,
    /// Releases the paced command `stall_at` held.
    release: Arc<tokio::sync::Notify>,
}

/// Drive one rollback whose RIB restore is paced: three peers with their own
/// export changes are applied, the fourth's session apply fails, and the RIB
/// stub acknowledges every member of a rollback batch as `Deferred`, then
/// restores one member per paced command, 50 s each, reporting one member as
/// departed. With `stall_at`, that paced command (counted from 1) is held
/// until `release`. With `distinct_priors`, every peer returns to a prior
/// chain of its own; otherwise all four return to one.
#[expect(
    clippy::too_many_lines,
    reason = "one fixture holds the paced RIB stub, the failing fleet and what the rollback tests read back"
)]
async fn paced_policy_rollback(stall_at: Option<usize>, distinct_priors: bool) -> PacedRollback {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let peers: Vec<IpAddr> = (1..=4)
        .map(|last| IpAddr::V4(Ipv4Addr::new(10, 39, 6, last)))
        .collect();
    let departed = peers[1];
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(32);
    let commands = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = Arc::clone(&commands);
    let release = Arc::new(tokio::sync::Notify::new());
    let released = Arc::clone(&release);
    tokio::spawn(async move {
        let mut paced = 0;
        let addrs = |replacements: &[rustbgpd_rib::PeerExportPolicyReplacement]| {
            replacements
                .iter()
                .map(|replacement| replacement.peer.addr())
                .collect::<Vec<_>>()
        };
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                RibUpdate::RestorePeerExportPoliciesAuthoritatively {
                    replacements,
                    reply,
                } => {
                    seen.lock().unwrap().push(("batch", addrs(&replacements)));
                    let _ = reply.send(Ok(replacements
                        .iter()
                        .rev()
                        .map(
                            |replacement| rustbgpd_rib::PeerExportPolicyRestoreReceipt::Deferred {
                                peer: replacement.peer,
                            },
                        )
                        .collect()));
                }
                RibUpdate::RestorePacedExportPolicies {
                    replacements,
                    reply,
                    ..
                } => {
                    paced += 1;
                    seen.lock().unwrap().push(("paced", addrs(&replacements)));
                    if stall_at == Some(paced) {
                        released.notified().await;
                    }
                    tokio::time::sleep(Duration::from_secs(50)).await;
                    // One member restored per command; a departed member is
                    // skipped without costing the command its one.
                    let mut skipped = Vec::new();
                    let mut applied = 0;
                    let mut pending = Vec::new();
                    for peer in replacements.iter().map(|replacement| replacement.peer) {
                        if peer.addr() == departed {
                            skipped.push(peer);
                        } else if applied == 0 {
                            applied = 1;
                        } else {
                            pending.push(peer);
                        }
                    }
                    let _ = reply.send(Ok(rustbgpd_rib::PacedApplyOutcome {
                        pending,
                        skipped,
                        applied,
                        cost: None,
                    }));
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
    for (index, &address) in peers.iter().enumerate() {
        insert_test_managed_peer(
            &mut manager,
            address,
            established_export_policy_test_session(
                address,
                Arc::new(AtomicUsize::new(0)),
                // The last peer's forward session apply fails; its rollback
                // reassert is acknowledged.
                (index == 3).then_some(1),
            ),
            false,
        );
        if distinct_priors {
            manager.peers.get_mut(&key(address)).unwrap().export_policy =
                Some(distinct_deny_policy_chain(10 + index));
        }
    }
    let started = tokio::time::Instant::now();
    let result = manager
        .apply_resolved_policy_snapshot(
            peers
                .iter()
                .enumerate()
                .map(|(index, &address)| ResolvedPeerPolicy {
                    address,
                    interface: None,
                    import_policy: None,
                    export_policy: Some(distinct_deny_policy_chain(index)),
                })
                .collect(),
        )
        .await;
    let elapsed = started.elapsed();
    let pending = peers
        .iter()
        .map(|&address| {
            manager
                .peers
                .get(&key(address))
                .unwrap()
                .pending_export_apply
        })
        .collect();
    for &address in &peers {
        manager.delete_peer(key(address), false).await.unwrap();
    }
    PacedRollback {
        result,
        elapsed,
        commands,
        pending,
        release,
    }
}

fn rollback_peer(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 39, 6, last))
}

/// A rollback whose restore keeps completing RIB commands is not cut off on
/// elapsed time: three 50 s paced commands take longer than the two-minute
/// rollback budget and the rollback still ends exact. Deferred members are
/// restored newest first, a few per command; a member that left the RIB
/// mid-restore is skipped and acknowledged, not waited on.
#[tokio::test(start_paused = true)]
async fn paced_policy_rollback_completes_past_the_rollback_budget() {
    let run = paced_policy_rollback(None, false).await;
    assert!(
        run.result.as_ref().is_err_and(|error| {
            error.contains("already-applied peers restored") && !error.contains("also failed")
        }),
        "a progressing restore must end as an exact compensation: {:?}",
        run.result
    );
    assert!(
        run.elapsed >= Duration::from_secs(150) && run.elapsed > RIB_BATCH_REPLY_TIMEOUT,
        "the restore ran {:?}",
        run.elapsed
    );
    assert_eq!(
        *run.commands.lock().unwrap(),
        vec![
            // The four members return to one prior chain: one batch, supplied
            // in forward order and executed newest first.
            (
                "batch",
                vec![
                    rollback_peer(1),
                    rollback_peer(2),
                    rollback_peer(3),
                    rollback_peer(4)
                ]
            ),
            ("paced", vec![rollback_peer(4)]),
            ("paced", vec![rollback_peer(3), rollback_peer(2)]),
            ("paced", vec![rollback_peer(1)]),
        ],
        "deferred members are restored newest first, each command offering at most twice the previous command's restored members"
    );
    assert_eq!(
        run.pending,
        vec![false; 4],
        "no retry intent after an exact restore"
    );
}

/// Members returning to prior chains of their own are restored one prior
/// chain at a time, newest first: each chain's batch, then the paced command
/// for the member that batch deferred, before the next chain's batch. Every
/// member's receipt maps back to its own plan, so the rollback is exact; the
/// departed member's `NotFound` is accepted.
#[tokio::test(start_paused = true)]
async fn paced_policy_rollback_walks_each_prior_chain_in_turn() {
    let run = paced_policy_rollback(None, true).await;
    assert!(
        run.result.as_ref().is_err_and(|error| {
            error.contains("already-applied peers restored") && !error.contains("also failed")
        }),
        "{:?}",
        run.result
    );
    let expected: Vec<(&'static str, Vec<IpAddr>)> = [4, 3, 2, 1]
        .into_iter()
        .flat_map(|last| {
            [
                ("batch", vec![rollback_peer(last)]),
                ("paced", vec![rollback_peer(last)]),
            ]
        })
        .collect();
    assert_eq!(*run.commands.lock().unwrap(), expected);
    assert_eq!(run.pending, vec![false; 4]);
}

/// A restore that stops completing commands is a stall: the wait expires
/// `RIB_BATCH_REPLY_TIMEOUT` after the last completed command, the retry
/// intent stays armed and the rollback is reported unproven. The restore is
/// not abandoned with the wait: once the RIB answers again, the detached
/// task sends the remaining restore commands.
#[tokio::test(start_paused = true)]
async fn stalled_paced_policy_rollback_times_out_after_its_last_completed_command() {
    let run = paced_policy_rollback(Some(2), false).await;
    assert!(
        run.result
            .as_ref()
            .is_err_and(|error| error.contains("policy_rollback_batch_timeout")),
        "{:?}",
        run.result
    );
    // One paced command completed at 50 s; the second is held.
    let expected = Duration::from_secs(50) + RIB_BATCH_REPLY_TIMEOUT;
    assert!(
        run.elapsed >= expected && run.elapsed < expected + Duration::from_secs(1),
        "the stall must be measured from the last completed command: {:?}",
        run.elapsed
    );
    assert_eq!(run.pending, vec![true; 4], "retry intent stays armed");
    let before = run.commands.lock().unwrap().len();
    assert_eq!(before, 3, "the batch and two paced commands");
    run.release.notify_one();
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(
        run.commands.lock().unwrap().last(),
        Some(&("paced", vec![rollback_peer(1)])),
        "the detached restore must keep going after its caller's wait ended"
    );
}

/// What a recording RIB stub saw: the command kind and its members in
/// command order.
type RecordedRibCommands = Vec<(&'static str, Vec<IpAddr>)>;

fn replacement_addrs(replacements: &[rustbgpd_rib::PeerExportPolicyReplacement]) -> Vec<IpAddr> {
    replacements
        .iter()
        .map(|replacement| replacement.peer.addr())
        .collect()
}

/// The receipts an exact restore batch returns: every member restored,
/// newest first.
fn restored_receipts(
    replacements: &[rustbgpd_rib::PeerExportPolicyReplacement],
) -> Vec<rustbgpd_rib::PeerExportPolicyRestoreReceipt> {
    replacements
        .iter()
        .rev()
        .map(
            |replacement| rustbgpd_rib::PeerExportPolicyRestoreReceipt::Restored {
                peer: replacement.peer,
            },
        )
        .collect()
}

/// An export-only target moving `address` to the chain numbered `chain`.
fn export_pair_target(
    address: IpAddr,
    chain: usize,
) -> rustbgpd_api::peer_types::ResolvedPeerPolicy {
    rustbgpd_api::peer_types::ResolvedPeerPolicy {
        address,
        interface: None,
        import_policy: None,
        export_policy: Some(distinct_deny_policy_chain(chain)),
    }
}

/// One export-only snapshot: a cohort of three, then three remainder pairs
/// whose RIB batches each take 50 s. With `stall_at`, that pair's batch
/// (counted from 1) is never answered. Returns the snapshot result and the
/// RIB commands with the second each arrived at.
async fn timed_remainder_pair_batches(
    stall_at: Option<usize>,
) -> (
    Result<Vec<rustbgpd_api::peer_types::ResolvedPeerPolicy>, String>,
    [IpAddr; 3],
    [[IpAddr; 2]; 3],
    Vec<(&'static str, Vec<IpAddr>, u64)>,
) {
    let peer = |last| IpAddr::V4(Ipv4Addr::new(10, 36, 8, last));
    let cohort = [peer(1), peer(2), peer(3)];
    let pairs = [[peer(4), peer(5)], [peer(6), peer(7)], [peer(8), peer(9)]];
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(32);
    let rib_task = tokio::spawn(async move {
        let started = tokio::time::Instant::now();
        let mut commands: Vec<(&'static str, Vec<IpAddr>, u64)> = Vec::new();
        let (mut batches, mut held) = (0, Vec::new());
        while let Some(update) = rib_rx.recv().await {
            let at = started.elapsed().as_secs();
            match update {
                RibUpdate::ReplacePeerExportPolicies {
                    replacements,
                    reply,
                } => {
                    commands.push(("cohort", replacement_addrs(&replacements), at));
                    let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
                }
                RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
                    replacements,
                    reply,
                } => {
                    commands.push(("batch", replacement_addrs(&replacements), at));
                    batches += 1;
                    if stall_at == Some(batches) {
                        held.push(reply);
                        continue;
                    }
                    // Answer late without blocking the stub, so a rollback
                    // is recorded when the walk sends it.
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(50)).await;
                        let _ = reply.send(Ok(Vec::new()));
                    });
                }
                RibUpdate::RestorePeerExportPoliciesAuthoritatively {
                    replacements,
                    reply,
                } => {
                    commands.push(("restore", replacement_addrs(&replacements), at));
                    let _ = reply.send(Ok(restored_receipts(&replacements)));
                }
                _ => {}
            }
        }
        commands
    });
    let mut manager = test_peer_manager();
    manager.rib_tx = rib_tx;
    let installs = Arc::new(AtomicUsize::new(0));
    let all: Vec<IpAddr> = cohort
        .into_iter()
        .chain(pairs.into_iter().flatten())
        .collect();
    for &address in &all {
        insert_test_managed_peer(
            &mut manager,
            address,
            established_export_policy_test_session(address, Arc::clone(&installs), None),
            false,
        );
    }
    let chain_of = |address: IpAddr| {
        pairs
            .iter()
            .position(|pair| pair.contains(&address))
            .map_or(0, |pair| pair + 1)
    };
    let result = manager
        .apply_resolved_policy_snapshot(
            all.iter()
                .map(|&address| export_pair_target(address, chain_of(address)))
                .collect(),
        )
        .await;
    for &address in &all {
        assert_eq!(
            manager
                .peers
                .get(&key(address))
                .unwrap()
                .export_policy
                .is_some(),
            result.is_ok(),
            "{address} must finish on the chain the snapshot's outcome names"
        );
        manager.delete_peer(key(address), false).await.unwrap();
    }
    drop(manager);
    (result, cohort, pairs, rib_task.await.unwrap())
}

/// Each completed pair batch renews the remainder walk's forward budget, so
/// the budget bounds one batch, not the walk: three pairs whose batches each
/// take 50 s commit 150 s after the first was sent. One budget shared by the
/// whole walk would cut the third batch off at 120 s and roll the walk back.
#[tokio::test(start_paused = true)]
async fn remainder_pair_batches_renew_the_stall_timeout_as_each_completes() {
    let (result, cohort, pairs, commands) = timed_remainder_pair_batches(None).await;
    assert!(
        result.is_ok(),
        "a walk whose every pair batch completes must commit: {result:?}; RIB commands: {commands:?}"
    );
    assert_eq!(
        commands,
        vec![
            ("cohort", cohort.to_vec(), 0),
            ("batch", pairs[0].to_vec(), 0),
            ("batch", pairs[1].to_vec(), 50),
            ("batch", pairs[2].to_vec(), 100),
        ]
    );
}

/// A pair batch the RIB never answers is a stall: the walk rolls back
/// `RIB_BATCH_REPLY_TIMEOUT` after the last completed batch, not after its
/// first command, sends no further pair, and restores every remainder
/// member, then the cohort.
#[tokio::test(start_paused = true)]
async fn remainder_pair_batch_stall_rolls_back_from_the_last_completed_batch() {
    let (result, cohort, pairs, commands) = timed_remainder_pair_batches(Some(2)).await;
    assert!(
        result.as_ref().is_err_and(|error| {
            error.contains("policy-walk stall timeout")
                && error.contains("already-applied peers restored")
                && error.contains("committed cohort restored")
        }),
        "a stalled pair batch must roll the walk back: {result:?}; RIB commands: {commands:?}"
    );
    let stalled_at = 50 + RIB_BATCH_REPLY_TIMEOUT.as_secs();
    assert_eq!(
        commands,
        vec![
            ("cohort", cohort.to_vec(), 0),
            ("batch", pairs[0].to_vec(), 0),
            // Sent when the first batch completed, and never answered.
            ("batch", pairs[1].to_vec(), 50),
            // The third pair's batch is never sent.
            ("restore", pairs.into_iter().flatten().collect(), stalled_at),
            ("restore", cohort.to_vec(), stalled_at),
        ]
    );
}

/// How the stub answers the paced commands of
/// [`run_remainder_pair_with_deferred_members`]: given the command's number
/// (from 0) and its members, the members it reports pending and skipped.
type PacedScript = fn(usize, &[PeerId]) -> (Vec<PeerId>, Vec<PeerId>);

/// One export-only snapshot: a cohort of six, then a remainder pair of
/// five whose import chain also moves. The pair's RIB batch shares its first
/// member and hands the other four back; `paced` answers the paced commands
/// that follow. Returns the snapshot result, the manager, the pair, and what
/// the RIB saw, with each member's Route Refresh count when the command
/// arrived.
#[expect(
    clippy::too_many_lines,
    reason = "one fixture holds the scripted RIB stub, both partitions and what the paced-walk tests read back"
)]
async fn run_remainder_pair_with_deferred_members(
    paced: PacedScript,
) -> (
    Result<Vec<rustbgpd_api::peer_types::ResolvedPeerPolicy>, String>,
    PeerManager,
    [IpAddr; 5],
    Vec<(&'static str, Vec<IpAddr>, Vec<u32>)>,
) {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let peer = |last| IpAddr::V4(Ipv4Addr::new(10, 36, 9, last));
    // The cohort is the largest pair, so it outnumbers the remainder pair.
    let cohort = [1, 2, 3, 4, 5, 6].map(peer);
    let pair = [7, 8, 9, 10, 11].map(peer);
    let counters = pair.map(|_| Arc::new(FakePeerCounters::default()));
    let refreshes = {
        let counters = counters.clone();
        move || {
            counters
                .iter()
                .map(|counters| counters.route_refresh.load(Ordering::SeqCst))
                .collect::<Vec<_>>()
        }
    };
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(32);
    let rib_task = tokio::spawn(async move {
        let mut seen = Vec::new();
        let mut paced_commands = 0;
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPolicies { reply, .. } => {
                    let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
                }
                RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
                    replacements,
                    reply,
                } => {
                    seen.push(("batch", replacement_addrs(&replacements), refreshes()));
                    let _ = reply.send(Ok(replacements[1..]
                        .iter()
                        .map(|replacement| replacement.peer)
                        .collect()));
                }
                RibUpdate::ApplyPacedExportPolicies {
                    replacements,
                    reply,
                    ..
                } => {
                    assert!(
                        replacements.iter().all(|replacement| {
                            replacement.export_policy == Some(distinct_deny_policy_chain(1))
                        }),
                        "a paced member carries the pair's target chain"
                    );
                    seen.push(("paced", replacement_addrs(&replacements), refreshes()));
                    let sent: Vec<PeerId> = replacements
                        .iter()
                        .map(|replacement| replacement.peer)
                        .collect();
                    let (pending, skipped) = paced(paced_commands, &sent);
                    paced_commands += 1;
                    let _ = reply.send(Ok(rustbgpd_rib::PacedApplyOutcome {
                        applied: sent.len() - pending.len() - skipped.len(),
                        pending,
                        skipped,
                        cost: Some(rustbgpd_rib::PacedMemberCost::default()),
                    }));
                }
                RibUpdate::RestorePeerExportPoliciesAuthoritatively {
                    replacements,
                    reply,
                } => {
                    seen.push(("restore", replacement_addrs(&replacements), Vec::new()));
                    let _ = reply.send(Ok(restored_receipts(&replacements)));
                }
                _ => {}
            }
        }
        seen
    });
    let mut manager = test_peer_manager();
    manager.rib_tx = rib_tx;
    let installs = Arc::new(AtomicUsize::new(0));
    for address in cohort {
        insert_test_managed_peer(
            &mut manager,
            address,
            established_export_policy_test_session(address, Arc::clone(&installs), None),
            false,
        );
    }
    for (address, counters) in pair.into_iter().zip(&counters) {
        insert_test_managed_peer(
            &mut manager,
            address,
            acking_counted_policy_handle(address, Arc::clone(counters)),
            false,
        );
    }
    let import_next = validation_policy_chain(ImportValidationDependency::Rpki);
    let result = manager
        .apply_resolved_policy_snapshot(
            cohort
                .into_iter()
                .map(|address| export_pair_target(address, 0))
                .chain(pair.into_iter().map(|address| ResolvedPeerPolicy {
                    import_policy: Some(import_next.clone()),
                    ..export_pair_target(address, 1)
                }))
                .collect(),
        )
        .await;
    // Close the manager's RIB sender to end the stub; the caller keeps the
    // manager and its peers for assertions.
    manager.rib_tx = mpsc::channel(1).0;
    let seen = rib_task.await.unwrap();
    (result, manager, pair, seen)
}

/// Members a pair's RIB batch hands back are applied through the paced walk
/// before the pair counts as committed: each paced command offers a window
/// of the remaining members in caller order, a member the RIB reports
/// pending is sent again first, and no member's Route Refresh fires until
/// the last paced command has been answered.
#[tokio::test]
async fn remainder_pair_batch_hands_deferred_members_to_the_paced_walk() {
    // The second command applies only its first member.
    let paced: PacedScript = |command, sent| {
        if command == 1 {
            (sent[1..].to_vec(), Vec::new())
        } else {
            (Vec::new(), Vec::new())
        }
    };
    let (result, mut manager, pair, seen) = run_remainder_pair_with_deferred_members(paced).await;
    result.expect("a pair whose deferred members the paced walk applies must commit");
    assert_eq!(
        seen,
        vec![
            ("batch", pair.to_vec(), vec![0; 5]),
            ("paced", vec![pair[1]], vec![0; 5]),
            ("paced", vec![pair[2], pair[3]], vec![0; 5]),
            ("paced", vec![pair[3], pair[4]], vec![0; 5]),
        ],
        "the deferred members follow the batch through paced commands, ahead of every refresh"
    );
    for address in pair {
        let state = manager.peers.get(&key(address)).unwrap();
        assert_eq!(state.export_policy, Some(distinct_deny_policy_chain(1)));
        assert!(!state.pending_refresh && !state.pending_export_apply);
        manager.delete_peer(key(address), false).await.unwrap();
    }
}

/// A deferred member the RIB reports as no longer registered is skipped: the
/// walk goes on to the remaining members and the reload commits, with the
/// skipped member's bookkeeping on the new chain (its next registration
/// installs the chain its session accepted). Nothing is rolled back.
#[tokio::test]
async fn remainder_pair_commits_past_a_deferred_member_that_left_the_rib() {
    // The first paced command's only member has left the RIB.
    let paced: PacedScript = |command, sent| {
        if command == 0 {
            (Vec::new(), sent.to_vec())
        } else {
            (Vec::new(), Vec::new())
        }
    };
    let (result, mut manager, pair, seen) = run_remainder_pair_with_deferred_members(paced).await;
    result.expect("an unregistered deferred member must not fail the walk");
    assert_eq!(
        seen.iter()
            .map(|(kind, members, _)| (*kind, members.clone()))
            .collect::<RecordedRibCommands>(),
        vec![
            ("batch", pair.to_vec()),
            ("paced", vec![pair[1]]),
            // Nothing was applied, so the window stays at one member.
            ("paced", vec![pair[2]]),
            ("paced", vec![pair[3], pair[4]]),
        ],
        "the walk continues past the skipped member and restores nothing"
    );
    for address in pair {
        let state = manager.peers.get(&key(address)).unwrap();
        assert_eq!(
            state.export_policy,
            Some(distinct_deny_policy_chain(1)),
            "{address}: a replacement session starts from the new chain"
        );
        assert!(!state.pending_export_apply);
        manager.delete_peer(key(address), false).await.unwrap();
    }
}

/// A session that acknowledges policy updates and rejects every Route
/// Refresh.
fn refresh_rejecting_policy_handle(peer_addr: IpAddr, refreshes: Arc<AtomicUsize>) -> PeerHandle {
    use rustbgpd_transport::PeerCommand;

    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let task = tokio::spawn(async move {
        while let Some(command) = session_rx.recv().await {
            match command {
                PeerCommand::QueryState { reply } => {
                    let mut state = policy_test_peer_state(peer_addr, SessionState::Established);
                    state.negotiated_session = Some(test_negotiated_session(true));
                    let _ = reply.send(state);
                }
                PeerCommand::UpdateImportPolicy { reply, .. }
                | PeerCommand::UpdateExportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    refreshes.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Err(rustbgpd_transport::PeerCommandError::CommandFailed(
                        "injected route refresh failure".to_string(),
                    )));
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

/// A pair member whose deferred Route Refresh fails after the pair's RIB
/// batch committed fails the walk: every remainder member is restored, then
/// the cohort, and the member whose refresh already went out is refreshed
/// back.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one fixture holds the recording RIB stub, the refresh-rejecting member and the rollback proof"
)]
async fn remainder_pair_deferred_refresh_failure_rolls_the_walk_back() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let peer = |last| IpAddr::V4(Ipv4Addr::new(10, 36, 10, last));
    let cohort = [peer(1), peer(2), peer(3)];
    let pair = [peer(4), peer(5)];
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(32);
    let rib_task = tokio::spawn(async move {
        let mut seen: RecordedRibCommands = Vec::new();
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPolicies { reply, .. } => {
                    let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
                }
                RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
                    replacements,
                    reply,
                } => {
                    seen.push(("batch", replacement_addrs(&replacements)));
                    let _ = reply.send(Ok(Vec::new()));
                }
                RibUpdate::RestorePeerExportPoliciesAuthoritatively {
                    replacements,
                    reply,
                } => {
                    seen.push(("restore", replacement_addrs(&replacements)));
                    let _ = reply.send(Ok(restored_receipts(&replacements)));
                }
                _ => {}
            }
        }
        seen
    });
    let mut manager = test_peer_manager();
    manager.rib_tx = rib_tx;
    let installs = Arc::new(AtomicUsize::new(0));
    for address in cohort {
        insert_test_managed_peer(
            &mut manager,
            address,
            established_export_policy_test_session(address, Arc::clone(&installs), None),
            false,
        );
    }
    let refreshed = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer(
        &mut manager,
        pair[0],
        acking_counted_policy_handle(pair[0], Arc::clone(&refreshed)),
        false,
    );
    let rejected_refreshes = Arc::new(AtomicUsize::new(0));
    insert_test_managed_peer(
        &mut manager,
        pair[1],
        refresh_rejecting_policy_handle(pair[1], Arc::clone(&rejected_refreshes)),
        false,
    );
    let import_next = validation_policy_chain(ImportValidationDependency::Rpki);
    let all: Vec<IpAddr> = cohort.into_iter().chain(pair).collect();
    let result = manager
        .apply_resolved_policy_snapshot(
            cohort
                .into_iter()
                .map(|address| export_pair_target(address, 0))
                .chain(pair.into_iter().map(|address| ResolvedPeerPolicy {
                    import_policy: Some(import_next.clone()),
                    ..export_pair_target(address, 1)
                }))
                .collect(),
        )
        .await;
    assert!(
        result.as_ref().is_err_and(|error| {
            error.contains(&format!("failed to apply resolved policy to {}", pair[1]))
                && error.contains("route refresh: ")
                && error.contains("already-applied peers restored")
                && error.contains("committed cohort restored")
        }),
        "a failed deferred refresh must roll the walk back: {result:?}"
    );
    for &address in &all {
        let state = manager.peers.get(&key(address)).unwrap();
        assert!(
            state.export_policy.is_none() && state.import_policy.is_none(),
            "{address} must finish on its prior chains"
        );
        manager.delete_peer(key(address), false).await.unwrap();
    }
    assert_eq!(
        refreshed.route_refresh.load(Ordering::SeqCst),
        2,
        "the member refreshed under the candidate import chain is refreshed back"
    );
    assert!(rejected_refreshes.load(Ordering::SeqCst) >= 1);
    drop(manager);
    assert_eq!(
        rib_task.await.unwrap(),
        vec![
            ("batch", pair.to_vec()),
            ("restore", pair.to_vec()),
            ("restore", cohort.to_vec()),
        ]
    );
}

/// One export-only snapshot whose remainder is one shared pair of 250
/// members behind a cohort of 251. Returns the snapshot result, the cohort,
/// the pair and the RIB commands; the pair's batch that starts at member
/// `fail_batch_from` is refused.
async fn run_large_remainder_pair(
    fail_batch_from: Option<usize>,
) -> (
    Result<Vec<rustbgpd_api::peer_types::ResolvedPeerPolicy>, String>,
    Vec<IpAddr>,
    Vec<IpAddr>,
    RecordedRibCommands,
) {
    let peer = |index: usize| {
        IpAddr::V4(Ipv4Addr::new(
            10,
            37,
            u8::try_from(index / 250).unwrap(),
            u8::try_from(index % 250 + 1).unwrap(),
        ))
    };
    let cohort: Vec<IpAddr> = (0..251).map(peer).collect();
    let pair: Vec<IpAddr> = (251..501).map(peer).collect();
    let refused = fail_batch_from.map(|member| pair[member]);
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(32);
    let rib_task = tokio::spawn(async move {
        let mut seen: RecordedRibCommands = Vec::new();
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPolicies { reply, .. } => {
                    let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
                }
                RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
                    replacements,
                    reply,
                } => {
                    let members = replacement_addrs(&replacements);
                    let fails = Some(members[0]) == refused;
                    seen.push(("batch", members));
                    let _ = reply.send(if fails {
                        Err(rustbgpd_rib::RibCommandError::internal("batch refused"))
                    } else {
                        Ok(Vec::new())
                    });
                }
                RibUpdate::RestorePeerExportPoliciesAuthoritatively {
                    replacements,
                    reply,
                } => {
                    seen.push(("restore", replacement_addrs(&replacements)));
                    let _ = reply.send(Ok(restored_receipts(&replacements)));
                }
                _ => {}
            }
        }
        seen
    });
    let mut manager = test_peer_manager();
    manager.rib_tx = rib_tx;
    let installs = Arc::new(AtomicUsize::new(0));
    for &address in cohort.iter().chain(&pair) {
        insert_test_managed_peer(
            &mut manager,
            address,
            established_export_policy_test_session(address, Arc::clone(&installs), None),
            false,
        );
    }
    let result = manager
        .apply_resolved_policy_snapshot(
            cohort
                .iter()
                .map(|&address| export_pair_target(address, 0))
                .chain(pair.iter().map(|&address| export_pair_target(address, 1)))
                .collect(),
        )
        .await;
    for &address in cohort.iter().chain(&pair) {
        manager.delete_peer(key(address), false).await.unwrap();
    }
    drop(manager);
    (result, cohort, pair, rib_task.await.unwrap())
}

/// A shared pair larger than `PAIR_BATCH_MEMBERS` is sent as several RIB
/// batches in caller order, so no one batch turn grows with the pair; a
/// failure in a later batch restores every captured member of the pair,
/// whichever batch it was in, including the members of a batch that was
/// never sent.
#[tokio::test]
async fn large_remainder_pair_is_sent_in_bounded_batches_and_restored_whole() {
    let (result, _, pair, commands) = run_large_remainder_pair(None).await;
    result.expect("a 250-member pair commits");
    assert_eq!(
        commands,
        vec![
            ("batch", pair[..100].to_vec()),
            ("batch", pair[100..200].to_vec()),
            ("batch", pair[200..].to_vec()),
        ],
        "a 250-member pair takes three batches of at most 100 members, in caller order"
    );

    let (result, cohort, pair, commands) = run_large_remainder_pair(Some(100)).await;
    assert!(
        result.as_ref().is_err_and(|error| {
            error.contains("batch refused")
                && error.contains("already-applied peers restored")
                && error.contains("committed cohort restored")
        }),
        "{result:?}"
    );
    assert_eq!(
        commands,
        vec![
            ("batch", pair[..100].to_vec()),
            ("batch", pair[100..200].to_vec()),
            ("restore", pair),
            ("restore", cohort),
        ],
        "the refused second batch restores all 250 captured members, then the cohort"
    );
}

/// A rollback partition that restored renews the shared rollback budget for
/// the partition after it. The remainder partition here restores through
/// three 50 s paced commands, ending 150 s into the rollback and past the
/// 120 s budget anchored at its first command; the cohort partition's
/// restore batch then takes another 60 s. Both partitions restore and the
/// rollback is exact. Without the renewal the cohort partition's wait would
/// start already expired and report a timeout although the RIB answered
/// every command.
#[tokio::test(start_paused = true)]
#[expect(
    clippy::too_many_lines,
    reason = "one fixture holds the paced RIB stub, both rollback partitions and the timing proof"
)]
async fn restored_rollback_partition_renews_the_budget_for_the_next_partition() {
    let peer = |last| IpAddr::V4(Ipv4Addr::new(10, 39, 7, last));
    let cohort = [1, 2, 3, 4].map(peer);
    let pair = [5, 6, 7].map(peer);
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(32);
    let rib_task = tokio::spawn(async move {
        let started = tokio::time::Instant::now();
        let mut seen: Vec<(&'static str, Vec<IpAddr>, u64)> = Vec::new();
        while let Some(update) = rib_rx.recv().await {
            let at = started.elapsed().as_secs();
            match update {
                RibUpdate::ReplacePeerExportPolicies { reply, .. } => {
                    let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
                }
                RibUpdate::ReplacePeerExportPoliciesAuthoritatively { reply, .. } => {
                    let _ = reply.send(Err(rustbgpd_rib::RibCommandError::internal(
                        "force cross-partition rollback",
                    )));
                }
                RibUpdate::RestorePeerExportPoliciesAuthoritatively {
                    replacements,
                    reply,
                } => {
                    let members = replacement_addrs(&replacements);
                    let is_cohort = members == cohort;
                    seen.push(("batch", members, at));
                    if is_cohort {
                        // The second partition: one slow shared batch.
                        tokio::time::sleep(Duration::from_secs(60)).await;
                        let _ = reply.send(Ok(restored_receipts(&replacements)));
                    } else {
                        // The first partition: every member is handed to the
                        // paced restore.
                        let _ = reply.send(Ok(replacements
                            .iter()
                            .rev()
                            .map(|replacement| {
                                rustbgpd_rib::PeerExportPolicyRestoreReceipt::Deferred {
                                    peer: replacement.peer,
                                }
                            })
                            .collect()));
                    }
                }
                RibUpdate::RestorePacedExportPolicies {
                    replacements,
                    reply,
                    ..
                } => {
                    seen.push(("paced", replacement_addrs(&replacements), at));
                    tokio::time::sleep(Duration::from_secs(50)).await;
                    // One member restored per command.
                    let _ = reply.send(Ok(rustbgpd_rib::PacedApplyOutcome {
                        pending: replacements[1..]
                            .iter()
                            .map(|replacement| replacement.peer)
                            .collect(),
                        skipped: Vec::new(),
                        applied: 1,
                        cost: None,
                    }));
                }
                _ => {}
            }
        }
        seen
    });
    let mut manager = test_peer_manager();
    manager.rib_tx = rib_tx;
    let installs = Arc::new(AtomicUsize::new(0));
    let all: Vec<IpAddr> = cohort.into_iter().chain(pair).collect();
    for &address in &all {
        insert_test_managed_peer(
            &mut manager,
            address,
            established_export_policy_test_session(address, Arc::clone(&installs), None),
            false,
        );
    }
    let started = tokio::time::Instant::now();
    let result = manager
        .apply_resolved_policy_snapshot(
            all.iter()
                .map(|&address| export_pair_target(address, usize::from(pair.contains(&address))))
                .collect(),
        )
        .await;
    let elapsed = started.elapsed();
    assert!(
        result.as_ref().is_err_and(|error| {
            error.contains("force cross-partition rollback")
                && error.contains("already-applied peers restored")
                && error.contains("committed cohort restored")
                && !error.contains("policy_rollback_batch_timeout")
        }),
        "both partitions restored, so the rollback must be exact: {result:?}"
    );
    assert_eq!(
        elapsed,
        Duration::from_secs(210),
        "three 50 s paced commands, then the cohort's 60 s batch"
    );
    for &address in &all {
        let state = manager.peers.get(&key(address)).unwrap();
        assert!(
            state.export_policy.is_none() && !state.pending_export_apply,
            "{address} must finish on its prior export policy with no retry intent"
        );
        manager.delete_peer(key(address), false).await.unwrap();
    }
    drop(manager);
    assert_eq!(
        rib_task.await.unwrap(),
        vec![
            ("batch", pair.to_vec(), 0),
            ("paced", vec![pair[2]], 0),
            ("paced", vec![pair[1], pair[0]], 50),
            ("paced", vec![pair[0]], 100),
            // 150 s into the rollback, past the budget its first command
            // anchored.
            ("batch", cohort.to_vec(), 150),
        ]
    );
}
