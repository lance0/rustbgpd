use super::*;

/// A policy-acking peer with a controllable first and subsequent state-query
/// result. `None` drops the reply and keeps the observation explicitly unknown.
fn sequenced_policy_state_handle(
    peer_addr: IpAddr,
    first_state: Option<SessionState>,
    subsequent_state: Option<SessionState>,
) -> PeerHandle {
    use rustbgpd_transport::PeerCommand;
    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let state_queries = Arc::new(AtomicU32::new(0));
    let state_queries_in_task = Arc::clone(&state_queries);
    let task = tokio::spawn(async move {
        while let Some(cmd) = session_rx.recv().await {
            match cmd {
                PeerCommand::QueryState { reply } => {
                    let first = state_queries_in_task.fetch_add(1, Ordering::SeqCst) == 0;
                    let Some(state) = (if first { first_state } else { subsequent_state }) else {
                        drop(reply);
                        continue;
                    };
                    let _ = reply.send(PeerSessionState {
                        fsm_state: state,
                        peer_ip: peer_addr,
                        peer_asn: None,
                        prefix_count: 0,
                        max_prefix: MaxPrefixState::default(),
                        negotiated_hold_time: None,
                        four_octet_as: None,
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
                        flap_count: 1,
                        uptime_secs: 0,
                        last_error: String::new(),
                        tcp_ao_info: None,
                        tcp_ao_protected: false,
                        slow_peer: false,
                    });
                }
                PeerCommand::UpdateImportPolicy { reply, .. }
                | PeerCommand::UpdateExportPolicy { reply, .. }
                | PeerCommand::SendRouteRefresh { reply, .. } => {
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

/// A peer handle that accepts import-policy hot-apply but fails the first export
/// hot-apply, then accepts later export updates. This forces the transaction
/// primitive's partial-mutation path: the peer's import bookkeeping can advance
/// before export fails, and rollback must restore the same peer too.
fn export_fails_once_policy_handle(peer_addr: IpAddr, state: SessionState) -> PeerHandle {
    use rustbgpd_transport::{PeerCommand, PeerCommandError};
    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let export_failed = Arc::new(AtomicBool::new(false));
    let task = tokio::spawn(async move {
        while let Some(cmd) = session_rx.recv().await {
            match cmd {
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(PeerSessionState {
                        fsm_state: state,
                        peer_ip: peer_addr,
                        peer_asn: None,
                        prefix_count: 0,
                        max_prefix: MaxPrefixState::default(),
                        negotiated_hold_time: None,
                        four_octet_as: None,
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
                        uptime_secs: 0,
                        last_error: String::new(),
                        tcp_ao_info: None,
                        tcp_ao_protected: false,
                        slow_peer: false,
                    });
                }
                PeerCommand::UpdateImportPolicy { reply, .. }
                | PeerCommand::SendRouteRefresh { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::UpdateExportPolicy { reply, .. } => {
                    if export_failed.swap(true, Ordering::SeqCst) {
                        let _ = reply.send(Ok(()));
                    } else {
                        let _ = reply.send(Err(PeerCommandError::CommandFailed(
                            "export apply failed once".to_string(),
                        )));
                    }
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

/// A peer handle that acks policy hot-applies but rejects Route Refresh, as a
/// peer that did not negotiate the Route Refresh capability would (the session
/// returns "peer lacks Route Refresh capability"). Used to verify a live-impact
/// apply rejects an Established non-RR peer cleanly.
fn route_refresh_failing_handle(peer_addr: IpAddr, state: SessionState) -> PeerHandle {
    use rustbgpd_transport::{PeerCommand, PeerCommandError};
    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let task = tokio::spawn(async move {
        while let Some(cmd) = session_rx.recv().await {
            match cmd {
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(PeerSessionState {
                        fsm_state: state,
                        peer_ip: peer_addr,
                        peer_asn: None,
                        prefix_count: 0,
                        max_prefix: MaxPrefixState::default(),
                        negotiated_hold_time: None,
                        four_octet_as: None,
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
                        uptime_secs: 0,
                        last_error: String::new(),
                        tcp_ao_info: None,
                        tcp_ao_protected: false,
                        slow_peer: false,
                    });
                }
                PeerCommand::UpdateImportPolicy { reply, .. }
                | PeerCommand::UpdateExportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    let _ = reply.send(Err(PeerCommandError::RouteRefreshUnsupported));
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

/// A peer handle that acks policy hot-applies, reports Established, and acks the
/// FIRST Route Refresh but fails every subsequent one. Drives the compound
/// rollback path: the forward apply succeeds (peer captured
/// `forward_completed = true`), but the refresh issued while rolling back fails,
/// exercising `RefreshFailureHandling::BestEffortRearm`.
fn route_refresh_failing_after_first_handle(peer_addr: IpAddr, state: SessionState) -> PeerHandle {
    use rustbgpd_transport::{PeerCommand, PeerCommandError};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let refresh_calls = Arc::new(AtomicU32::new(0));
    let task = tokio::spawn(async move {
        while let Some(cmd) = session_rx.recv().await {
            match cmd {
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(PeerSessionState {
                        fsm_state: state,
                        peer_ip: peer_addr,
                        peer_asn: None,
                        prefix_count: 0,
                        max_prefix: MaxPrefixState::default(),
                        negotiated_hold_time: None,
                        four_octet_as: None,
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
                        uptime_secs: 0,
                        last_error: String::new(),
                        tcp_ao_info: None,
                        tcp_ao_protected: false,
                        slow_peer: false,
                    });
                }
                PeerCommand::UpdateImportPolicy { reply, .. }
                | PeerCommand::UpdateExportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    if refresh_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        let _ = reply.send(Ok(()));
                    } else {
                        let _ = reply.send(Err(PeerCommandError::CommandFailed(
                            "transient route refresh failure".to_string(),
                        )));
                    }
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

#[derive(Clone, Copy)]
enum NonEstablishedRollbackRibOutcome {
    Registered,
    NotFound,
    UnknownStateNotFound,
    Internal,
}

#[allow(
    clippy::too_many_lines,
    reason = "the rollback helper keeps all peer and RIB outcome assertions together"
)]
async fn assert_non_established_rollback_rib_outcome(
    rollback_outcome: NonEstablishedRollbackRibOutcome,
) {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
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
    let flapping = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let failing = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    insert_test_managed_peer(
        &mut mgr,
        flapping,
        sequenced_policy_state_handle(
            flapping,
            Some(SessionState::Established),
            (!matches!(
                rollback_outcome,
                NonEstablishedRollbackRibOutcome::UnknownStateNotFound
            ))
            .then_some(SessionState::Idle),
        ),
        false,
    );
    insert_test_managed_peer(
        &mut mgr,
        failing,
        acking_policy_handle(failing, SessionState::Established),
        false,
    );

    let prior_import = validation_policy_chain(ImportValidationDependency::Rpki);
    let prior_export = validation_policy_chain(ImportValidationDependency::Aspa);
    for peer in [flapping, failing] {
        let managed = mgr.peers.get_mut(&key(peer)).unwrap();
        managed.import_policy = Some(prior_import.clone());
        managed.export_policy = Some(prior_export.clone());
    }
    let next = deny_policy_chain();
    let expected_next = format!("{:?}", Some(next.clone()));
    let expected_prior = format!("{:?}", Some(prior_export.clone()));
    let rib_driver = tokio::spawn(async move {
        let RibUpdate::ReplacePeerExportPolicy {
            peer,
            export_policy,
            reply,
        } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected flapping peer forward RIB replacement");
        };
        assert_eq!(peer, flapping);
        assert_eq!(format!("{export_policy:?}"), expected_next);
        reply.send(Ok(())).unwrap();

        let RibUpdate::ReplacePeerExportPolicy { peer, reply, .. } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected failing peer forward RIB replacement");
        };
        assert_eq!(peer, failing);
        reply
            .send(Err(rustbgpd_rib::RibCommandError::internal(
                "force transaction rollback",
            )))
            .unwrap();

        let RibUpdate::ReplacePeerExportPolicy {
            peer,
            export_policy,
            reply,
        } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected failing peer rollback RIB replacement");
        };
        assert_eq!(peer, failing);
        assert_eq!(format!("{export_policy:?}"), expected_prior);
        reply.send(Ok(())).unwrap();

        let RibUpdate::ReplacePeerExportPolicy {
            peer,
            export_policy,
            reply,
        } = rib_rx.recv().await.unwrap()
        else {
            panic!("non-Established rollback must still attempt the RIB replacement");
        };
        assert_eq!(peer, flapping);
        assert_eq!(format!("{export_policy:?}"), expected_prior);
        let reply_result = match rollback_outcome {
            NonEstablishedRollbackRibOutcome::Registered => Ok(()),
            NonEstablishedRollbackRibOutcome::NotFound => Err(
                rustbgpd_rib::RibCommandError::not_found("peer already absent during rollback"),
            ),
            NonEstablishedRollbackRibOutcome::UnknownStateNotFound => Err(
                rustbgpd_rib::RibCommandError::not_found("peer absent after unknown state query"),
            ),
            NonEstablishedRollbackRibOutcome::Internal => Err(
                rustbgpd_rib::RibCommandError::internal("rollback RIB transport failed"),
            ),
        };
        reply.send(reply_result).unwrap();
    });

    // Distinct export targets keep this snapshot off the LAN-462
    // import-tolerant cohort (no repeated export pair) and on the per-peer
    // authoritative transaction whose rollback this regression pins.
    let result = mgr
        .apply_resolved_policy_snapshot(
            [flapping, failing]
                .into_iter()
                .enumerate()
                .map(|(index, address)| ResolvedPeerPolicy {
                    address,
                    interface: None,
                    import_policy: Some(next.clone()),
                    export_policy: Some(if index == 0 {
                        next.clone()
                    } else {
                        distinct_deny_policy_chain(1)
                    }),
                })
                .collect(),
        )
        .await;
    let error = result.expect_err("the second peer's forward RIB failure must abort the apply");
    rib_driver.await.unwrap();

    let managed = mgr.peers.get(&key(flapping)).unwrap();
    assert_eq!(
        format!("{:?}", managed.import_policy),
        format!("{:?}", Some(prior_import)),
        "rollback must restore the flapping peer's session import policy"
    );
    assert_eq!(
        format!("{:?}", managed.export_policy),
        format!("{:?}", Some(prior_export)),
        "rollback must restore the flapping peer's session export policy"
    );
    assert!(
        managed.pending_refresh,
        "the non-Established rollback must defer its import refresh"
    );
    match rollback_outcome {
        NonEstablishedRollbackRibOutcome::Registered
        | NonEstablishedRollbackRibOutcome::NotFound => {
            assert!(
                error.contains("already-applied peers restored")
                    && !error.contains("restoring already-applied peers also failed"),
                "a completed restore or typed absence must not manufacture a compound failure: {error}"
            );
            assert!(
                !managed.pending_export_apply,
                "a restored registered object or typed absence leaves no stale RIB export work"
            );
        }
        NonEstablishedRollbackRibOutcome::UnknownStateNotFound
        | NonEstablishedRollbackRibOutcome::Internal => {
            assert!(
                error.contains("restoring already-applied peers also failed")
                    && (error.contains("rollback RIB transport failed")
                        || error.contains("peer absent after unknown state query")),
                "an ambiguous rollback RIB failure must compose into the transaction error: {error}"
            );
            assert!(
                managed.pending_export_apply,
                "an ambiguous rollback RIB failure must retain authoritative export intent"
            );
        }
    }

    mgr.delete_peer(key(flapping), false).await.unwrap();
    mgr.delete_peer(key(failing), false).await.unwrap();
}

#[tokio::test]
async fn non_established_rollback_restores_registered_rib_entry() {
    assert_non_established_rollback_rib_outcome(NonEstablishedRollbackRibOutcome::Registered).await;
}

#[tokio::test]
async fn non_established_rollback_accepts_typed_rib_absence() {
    assert_non_established_rollback_rib_outcome(NonEstablishedRollbackRibOutcome::NotFound).await;
}

#[tokio::test]
async fn unknown_state_rollback_treats_typed_rib_absence_as_fatal() {
    assert_non_established_rollback_rib_outcome(
        NonEstablishedRollbackRibOutcome::UnknownStateNotFound,
    )
    .await;
}

#[tokio::test]
async fn non_established_rollback_internal_rib_failure_is_composed_and_rearmed() {
    assert_non_established_rollback_rib_outcome(NonEstablishedRollbackRibOutcome::Internal).await;
}

#[tokio::test]
async fn ordinary_export_apply_unknown_state_rearms_until_established_retry() {
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(8);
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
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    insert_test_managed_peer(
        &mut mgr,
        peer,
        sequenced_policy_state_handle(peer, None, Some(SessionState::Established)),
        false,
    );
    let next = deny_policy_chain();

    mgr.update_runtime_policies(peer, None, Some(next.clone()))
        .await
        .expect("an unknown state keeps ordinary forward compatibility");
    assert!(
        mgr.peers.get(&key(peer)).unwrap().pending_export_apply,
        "an unknown state must retain fresh export intent because the peer may actually be Established"
    );
    assert!(
        matches!(rib_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "the unknown-state call must not blindly address an unconfirmed RIB registration"
    );

    let retry = mgr.update_runtime_policies(peer, None, Some(next));
    let drive_rib = async {
        let RibUpdate::ReplacePeerExportPolicy {
            peer: actual,
            reply,
            ..
        } = rib_rx.recv().await.unwrap()
        else {
            panic!("expected the Established retry to reach the RIB");
        };
        assert_eq!(actual, peer);
        reply.send(Ok(())).unwrap();
    };
    let (result, ()) = tokio::join!(retry, drive_rib);
    result.expect("the Established retry must consume the retained RIB intent");
    assert!(
        !mgr.peers.get(&key(peer)).unwrap().pending_export_apply,
        "a successful authoritative retry must clear export intent"
    );

    mgr.delete_peer(key(peer), false).await.unwrap();
}

#[tokio::test]
async fn apply_resolved_policy_snapshot_captures_priors_and_applies() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let mut mgr = live_policy_test_manager();
    let a1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let a2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    insert_test_managed_peer(
        &mut mgr,
        a1,
        acking_policy_handle(a1, SessionState::Idle),
        false,
    );
    insert_test_managed_peer(
        &mut mgr,
        a2,
        acking_policy_handle(a2, SessionState::Idle),
        false,
    );
    let peer_a_prior = validation_policy_chain(ImportValidationDependency::Rpki);
    mgr.peers.get_mut(&key(a1)).unwrap().import_policy = Some(peer_a_prior.clone());
    // a2 starts with no import policy (None).

    let new_chain = deny_policy_chain();
    let targets = vec![
        ResolvedPeerPolicy {
            address: a1,
            interface: None,
            import_policy: Some(new_chain.clone()),
            export_policy: None,
        },
        ResolvedPeerPolicy {
            address: a2,
            interface: None,
            import_policy: Some(new_chain.clone()),
            export_policy: None,
        },
    ];
    let priors = mgr
        .apply_resolved_policy_snapshot(targets)
        .await
        .expect("apply must succeed");

    assert_eq!(priors.len(), 2);
    assert_eq!(priors[0].address, a1);
    assert_eq!(
        format!("{:?}", priors[0].import_policy),
        format!("{:?}", Some(peer_a_prior))
    );
    assert_eq!(priors[1].address, a2);
    assert_eq!(
        format!("{:?}", priors[1].import_policy),
        format!("{:?}", Option::<PolicyChain>::None)
    );

    let expect_new = format!("{:?}", Some(new_chain));
    assert_eq!(
        format!("{:?}", mgr.peers.get(&key(a1)).unwrap().import_policy),
        expect_new,
        "peer 1 import policy must advance to the new chain"
    );
    assert_eq!(
        format!("{:?}", mgr.peers.get(&key(a2)).unwrap().import_policy),
        expect_new,
        "peer 2 import policy must advance to the new chain"
    );
}

#[tokio::test]
async fn apply_resolved_policy_snapshot_mid_fanout_failure_self_heals() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let mut mgr = live_policy_test_manager();
    let a1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let a2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)); // its apply fails
    let a3 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    insert_test_managed_peer(
        &mut mgr,
        a1,
        acking_policy_handle(a1, SessionState::Idle),
        false,
    );
    insert_test_managed_peer(&mut mgr, a2, closed_peer_handle(), false);
    insert_test_managed_peer(
        &mut mgr,
        a3,
        acking_policy_handle(a3, SessionState::Idle),
        false,
    );
    let prior = validation_policy_chain(ImportValidationDependency::Rpki);
    for a in [a1, a2, a3] {
        mgr.peers.get_mut(&key(a)).unwrap().import_policy = Some(prior.clone());
    }

    let new_chain = deny_policy_chain();
    let targets = [a1, a2, a3]
        .into_iter()
        .map(|address| ResolvedPeerPolicy {
            address,
            interface: None,
            import_policy: Some(new_chain.clone()),
            export_policy: None,
        })
        .collect();
    let result = mgr.apply_resolved_policy_snapshot(targets).await;
    assert!(
        result.is_err(),
        "a mid-fanout per-peer failure must surface as Err: {result:?}"
    );

    let expect_prior = format!("{:?}", Some(prior));
    assert_eq!(
        format!("{:?}", mgr.peers.get(&key(a1)).unwrap().import_policy),
        expect_prior,
        "peer 1 must be restored to its prior chain after the self-heal"
    );
    assert_eq!(
        format!("{:?}", mgr.peers.get(&key(a3)).unwrap().import_policy),
        expect_prior,
        "peer 3 was never reached and must keep its prior chain"
    );
}

#[tokio::test]
async fn apply_resolved_policy_snapshot_restores_partially_mutated_failing_peer() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let mut mgr = live_policy_test_manager();
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    insert_test_managed_peer(
        &mut mgr,
        address,
        export_fails_once_policy_handle(address, SessionState::Idle),
        false,
    );
    let import_prior = validation_policy_chain(ImportValidationDependency::Rpki);
    let export_prior = validation_policy_chain(ImportValidationDependency::Aspa);
    {
        let managed = mgr.peers.get_mut(&key(address)).unwrap();
        managed.import_policy = Some(import_prior.clone());
        managed.export_policy = Some(export_prior.clone());
    }

    let new_chain = deny_policy_chain();
    let result = mgr
        .apply_resolved_policy_snapshot(vec![ResolvedPeerPolicy {
            address,
            interface: None,
            import_policy: Some(new_chain.clone()),
            export_policy: Some(new_chain),
        }])
        .await;
    assert!(
        result.is_err(),
        "the one-shot export failure must surface as Err: {result:?}"
    );

    let managed = mgr.peers.get(&key(address)).unwrap();
    assert_eq!(
        format!("{:?}", managed.import_policy),
        format!("{:?}", Some(import_prior)),
        "failing peer's import policy must be restored after partial mutation"
    );
    assert_eq!(
        format!("{:?}", managed.export_policy),
        format!("{:?}", Some(export_prior)),
        "failing peer's export policy must be restored too"
    );
}

#[tokio::test]
async fn apply_resolved_policy_snapshot_skips_non_live_targets() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    let mut mgr = live_policy_test_manager();
    let live = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let missing = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    insert_test_managed_peer(
        &mut mgr,
        live,
        acking_policy_handle(live, SessionState::Idle),
        false,
    );

    let new_chain = deny_policy_chain();
    let targets = vec![
        ResolvedPeerPolicy {
            address: missing,
            interface: None,
            import_policy: Some(new_chain.clone()),
            export_policy: None,
        },
        ResolvedPeerPolicy {
            address: live,
            interface: None,
            import_policy: Some(new_chain.clone()),
            export_policy: None,
        },
    ];
    let priors = mgr
        .apply_resolved_policy_snapshot(targets)
        .await
        .expect("apply must succeed");

    assert_eq!(priors.len(), 1, "non-live target must be skipped");
    assert_eq!(priors[0].address, live);
    assert_eq!(
        format!("{:?}", mgr.peers.get(&key(live)).unwrap().import_policy),
        format!("{:?}", Some(new_chain))
    );
}

#[tokio::test]
async fn apply_policy_impact_snapshot_expands_dynamic_range_targets() {
    let mut mgr = live_policy_test_manager();
    let candidate_toml = tier_authorized_uds_test_config(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.ix]
import_policy_chain = ["deny-import"]

[policy.definitions.deny-import]
default_action = "deny"

[[dynamic_neighbors]]
prefix = "10.30.0.0/16"
peer_group = "ix"
remote_asn = 65030
"#,
    );
    let candidate = crate::config::Config::load_toml_with_diagnostics(
        &candidate_toml,
        "dynamic policy candidate",
    )
    .expect("test config must parse");
    mgr.current_config = candidate;

    let peer = IpAddr::V4(Ipv4Addr::new(10, 30, 0, 7));
    insert_test_managed_peer_with_asn(
        &mut mgr,
        peer,
        65030,
        acking_policy_handle(peer, SessionState::Idle),
        false,
    );
    let prior = validation_policy_chain(ImportValidationDependency::Rpki);
    {
        let managed = mgr.peers.get_mut(&key(peer)).unwrap();
        managed.is_dynamic = true;
        managed.peer_group = Some("ix".to_string());
        managed.description = "dynamic:ix".to_string();
        managed.accepted_dynamic_range = Some(AcceptedDynamicRange {
            addr: IpAddr::V4(Ipv4Addr::new(10, 30, 0, 0)),
            prefix_len: 16,
            peer_group: "ix".to_string(),
        });
        managed.import_policy = Some(prior.clone());
    }

    let priors = mgr
        .apply_policy_impact_snapshot(
            Vec::new(),
            vec![DynamicRangeTarget {
                addr: IpAddr::V4(Ipv4Addr::new(10, 30, 0, 0)),
                prefix_len: 16,
                peer_group: "ix".to_string(),
            }],
        )
        .await
        .expect("dynamic policy impact apply must succeed");

    assert_eq!(priors.len(), 1);
    assert_eq!(priors[0].address, peer);
    assert_eq!(
        format!("{:?}", priors[0].import_policy),
        format!("{:?}", Some(prior)),
        "rollback token must capture the peer's prior import policy"
    );
    let applied_action = mgr
        .peers
        .get(&key(peer))
        .unwrap()
        .import_policy
        .as_ref()
        .and_then(|chain| chain.policies.first())
        .map(|policy| policy.default_action);
    assert_eq!(
        applied_action,
        Some(rustbgpd_policy::PolicyAction::Deny),
        "dynamic peer must resolve the candidate peer-group policy"
    );
}

#[tokio::test]
async fn apply_resolved_policy_snapshot_rejects_non_route_refresh_peer_cleanly() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    // An Established peer that never negotiated Route Refresh can't be
    // soft-refreshed, so a live-impact apply that needs to re-evaluate its
    // existing AdjRibIn under the new policy must reject. The rollback must be
    // clean (prior chain restored) — not a compound "restore also failed", since
    // the doomed rollback refresh is best-effort.
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                let _ = reply.send(Ok(()));
            }
        }
    });
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
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    insert_test_managed_peer(
        &mut mgr,
        addr,
        route_refresh_failing_handle(addr, SessionState::Established),
        false,
    );
    let prior = validation_policy_chain(ImportValidationDependency::Rpki);
    mgr.peers.get_mut(&key(addr)).unwrap().import_policy = Some(prior.clone());

    let targets = vec![ResolvedPeerPolicy {
        address: addr,
        interface: None,
        import_policy: Some(deny_policy_chain()),
        export_policy: None,
    }];
    let err = mgr
        .apply_resolved_policy_snapshot(targets)
        .await
        .unwrap_err();

    assert!(
        err.to_lowercase().contains("route refresh"),
        "rejection should cite the Route Refresh failure: {err}"
    );
    assert!(
        err.contains("already-applied peers restored"),
        "rollback should be clean: {err}"
    );
    assert!(
        !err.contains("restoring already-applied peers also failed"),
        "rollback must not be a compound failure for a non-RR peer: {err}"
    );
    assert_eq!(
        format!("{:?}", mgr.peers.get(&key(addr)).unwrap().import_policy),
        format!("{:?}", Some(prior)),
        "the peer's import policy must be restored to its prior chain"
    );
    assert!(
        !mgr.peers.get(&key(addr)).unwrap().pending_refresh,
        "a rejected non-RR apply must restore the prior pending_refresh state"
    );
    rib_drainer.abort();
}

#[tokio::test]
async fn apply_resolved_policy_snapshot_rearms_refresh_on_compound_rollback_failure() {
    use rustbgpd_api::peer_types::ResolvedPeerPolicy;

    // Compound failure: peer A's forward apply fully succeeds (its AdjRibIn is
    // moved to the new policy via a successful Route Refresh), then peer B's
    // forward refresh fails and forces a rollback. While restoring A, its
    // rollback-time refresh also fails. Because A's forward completed, its
    // AdjRibIn is stale at the new policy, so pending_refresh must be RE-ARMED
    // (true) — whereas B never completed, so B restores its prior pending state
    // (false). Pins the RefreshFailureHandling::BestEffortRearm vs
    // BestEffortRestorePrior asymmetry under a rollback-time refresh failure.
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                let _ = reply.send(Ok(()));
            }
        }
    });
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

    // Peer A: forward succeeds (first refresh acked), rollback refresh fails.
    let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    insert_test_managed_peer(
        &mut mgr,
        a,
        route_refresh_failing_after_first_handle(a, SessionState::Established),
        false,
    );
    // Peer B: applied second; its forward refresh fails, forcing the rollback.
    let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    insert_test_managed_peer(
        &mut mgr,
        b,
        route_refresh_failing_handle(b, SessionState::Established),
        false,
    );
    let prior = validation_policy_chain(ImportValidationDependency::Rpki);
    for p in [a, b] {
        mgr.peers.get_mut(&key(p)).unwrap().import_policy = Some(prior.clone());
    }

    let new_chain = deny_policy_chain();
    let targets = [a, b]
        .into_iter()
        .map(|address| ResolvedPeerPolicy {
            address,
            interface: None,
            import_policy: Some(new_chain.clone()),
            export_policy: None,
        })
        .collect();
    let result = mgr.apply_resolved_policy_snapshot(targets).await;
    assert!(
        result.is_err(),
        "peer B's forward refresh failure must surface as Err: {result:?}"
    );

    let a_peer = mgr.peers.get(&key(a)).unwrap();
    assert_eq!(
        format!("{:?}", a_peer.import_policy),
        format!("{:?}", Some(prior.clone())),
        "peer A's import policy must be restored to its prior chain"
    );
    assert!(
        a_peer.pending_refresh,
        "peer A completed its forward apply, so a failed rollback refresh must re-arm pending_refresh"
    );
    assert!(
        !mgr.peers.get(&key(b)).unwrap().pending_refresh,
        "peer B never completed its forward apply, so it must restore prior pending_refresh, not re-arm"
    );
    rib_drainer.abort();
}

#[allow(
    clippy::too_many_lines,
    reason = "the regression drives both updates through one complete pending-refresh receipt"
)]
#[tokio::test]
async fn back_to_back_updates_do_not_lose_pending_refresh() {
    use rustbgpd_transport::PeerCommand;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let established = Arc::new(AtomicBool::new(false));
    let refresh_calls = Arc::new(AtomicU32::new(0));
    let established_in_task = established.clone();
    let refresh_calls_in_task = refresh_calls.clone();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let task = tokio::spawn(async move {
        while let Some(cmd) = session_rx.recv().await {
            match cmd {
                PeerCommand::UpdateImportPolicy { reply, .. }
                | PeerCommand::UpdateExportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::QueryState { reply } => {
                    let state = if established_in_task.load(Ordering::SeqCst) {
                        SessionState::Established
                    } else {
                        SessionState::Idle
                    };
                    let _ = reply.send(PeerSessionState {
                        fsm_state: state,
                        peer_ip: addr,
                        peer_asn: None,
                        prefix_count: 0,
                        max_prefix: MaxPrefixState::default(),
                        negotiated_hold_time: Some(90),
                        four_octet_as: Some(true),
                        remote_router_id: Some(Ipv4Addr::new(10, 0, 0, 2)),
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
                        uptime_secs: u64::from(state == SessionState::Established),
                        last_error: String::new(),
                        tcp_ao_info: None,
                        tcp_ao_protected: false,
                        slow_peer: false,
                    });
                }
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    refresh_calls_in_task.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    let handle = PeerHandle::from_parts(session_tx, task);

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                let _ = reply.send(Ok(()));
            }
        }
    });
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
    insert_test_managed_peer(&mut mgr, addr, handle, true);

    let first = mgr.update_runtime_policies(addr, None, None).await;
    assert!(
        first.is_ok(),
        "first update should re-arm the pending refresh while the peer is idle: {first:?}"
    );
    assert!(
        mgr.peers.get(&key(addr)).unwrap().pending_refresh,
        "pending_refresh must survive the first back-to-back update while the peer is idle"
    );
    assert_eq!(
        refresh_calls.load(Ordering::SeqCst),
        0,
        "idle peer must not receive route refresh yet"
    );

    established.store(true, Ordering::SeqCst);
    let second = mgr.update_runtime_policies(addr, None, None).await;
    assert!(
        second.is_ok(),
        "second update should consume the carried refresh once the peer is Established: {second:?}"
    );
    assert!(
        !mgr.peers.get(&key(addr)).unwrap().pending_refresh,
        "pending_refresh must clear after the retry successfully sends Route Refresh"
    );
    assert_eq!(
        refresh_calls.load(Ordering::SeqCst),
        1,
        "second update must fire the previously carried Route Refresh exactly once"
    );

    mgr.delete_peer(key(addr), false).await.unwrap();
    drop(mgr);
    let _ = rib_drainer.await;
}

#[tokio::test]
async fn peer_deletion_after_failed_update_drops_pending_retry_cleanly() {
    use rustbgpd_transport::PeerCommand;

    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let task = tokio::spawn(async move {
        while let Some(cmd) = session_rx.recv().await {
            match cmd {
                PeerCommand::UpdateImportPolicy { reply, .. } => {
                    drop(reply);
                }
                PeerCommand::UpdateExportPolicy { reply, .. } => {
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
                        remote_router_id: Some(Ipv4Addr::new(10, 0, 0, 2)),
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
    let handle = PeerHandle::from_parts(session_tx, task);

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
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
    insert_test_managed_peer(&mut mgr, addr, handle, false);

    let failed = mgr
        .update_runtime_policies(addr, Some(deny_policy_chain()), None)
        .await;
    assert!(
        failed.is_err(),
        "first update should fail and leave pending retry intent: {failed:?}"
    );
    assert!(
        mgr.peers.get(&key(addr)).unwrap().pending_refresh,
        "failed update must set pending_refresh before deletion"
    );

    mgr.delete_peer(key(addr), false)
        .await
        .expect("peer deletion after failed update must complete");
    assert!(
        mgr.peers.is_empty(),
        "deleting the peer must drop the ManagedPeer that held pending retry state"
    );

    let retry_after_delete = mgr
        .update_runtime_policies(addr, Some(deny_policy_chain()), None)
        .await;
    assert!(
        retry_after_delete.is_ok(),
        "a queued or follow-up policy update for a peer deleted during the failure window \
         must no-op cleanly, not resurrect stale pending state: {retry_after_delete:?}"
    );
}
