use super::*;

#[tokio::test(start_paused = true)]
async fn gshut_toggle_times_out_when_rib_reply_wedges() {
    use rustbgpd_transport::PeerCommand;

    // LAN-286: a wedged RIB (accepts RefreshPeerOutbound but never
    // replies) must surface as a bounded error — not park the
    // peer-manager actor (and the reload/apply path driving the
    // toggle) forever.
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let session_task = tokio::spawn(async move {
        while let Some(cmd) = session_rx.recv().await {
            if let PeerCommand::UpdateGracefulShutdown { reply, .. } = cmd {
                let _ = reply.send(Ok(()));
            }
        }
        Ok(())
    });
    let handle = PeerHandle::from_parts(session_tx, session_task);

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::RefreshPeerOutbound { reply, .. } = update {
                // Wedged RIB: hold the reply channel open, never answer.
                held.push(reply);
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
    insert_test_managed_peer(&mut mgr, addr, handle, false);

    let err = mgr
        .set_graceful_shutdown(Some(key(addr)), true)
        .await
        .expect_err("wedged RIB reply must fail the toggle, not hang it");
    assert!(
        err.to_string().contains("timed out"),
        "error must name the RIB reply timeout: {err}"
    );
}

#[allow(
    clippy::too_many_lines,
    reason = "the timeout regression keeps its full transaction and recovery receipt together"
)]
#[tokio::test(start_paused = true)]
async fn export_policy_apply_times_out_when_rib_reply_wedges() {
    use rustbgpd_transport::PeerCommand;

    // LAN-286: same wedge class as the gshut refresh — the
    // ReplacePeerExportPolicy reply await must be bounded so a wedged
    // RIB cannot hang a SIGHUP reload / gRPC policy apply forever.
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
    let session_task = tokio::spawn(async move {
        while let Some(cmd) = session_rx.recv().await {
            match cmd {
                PeerCommand::UpdateImportPolicy { reply, .. }
                | PeerCommand::UpdateExportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(PeerSessionState {
                        fsm_state: SessionState::Established,
                        peer_ip: addr,
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
                _ => {}
            }
        }
        Ok(())
    });
    let handle = PeerHandle::from_parts(session_tx, session_task);

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
    let rib_attempts = Arc::new(AtomicU32::new(0));
    let rib_attempts_in_task = Arc::clone(&rib_attempts);
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                if rib_attempts_in_task.fetch_add(1, Ordering::SeqCst) == 0 {
                    // First attempt wedges; the content-equal retry succeeds.
                    held.push(reply);
                } else {
                    let _ = reply.send(Ok(()));
                }
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
    insert_test_managed_peer(&mut mgr, addr, handle, false);

    let err = mgr
        .update_runtime_policies(addr, None, Some(deny_policy_chain()))
        .await
        .expect_err("wedged RIB reply must fail the export apply, not hang it");
    assert!(
        err.contains("did not reply within"),
        "error must name the RIB reply timeout: {err}"
    );
    assert!(
        mgr.peers.get(&key(addr)).unwrap().pending_export_apply,
        "RIB reply timeout must retain export intent for a content-equal retry"
    );

    mgr.update_runtime_policies(addr, None, Some(deny_policy_chain()))
        .await
        .expect("content-equal retry must revisit the RIB after the timeout");
    assert_eq!(rib_attempts.load(Ordering::SeqCst), 2);
    assert!(!mgr.peers.get(&key(addr)).unwrap().pending_export_apply);
}

/// Load-bearing error classification proof: removing the managed-peer check
/// emits a RIB command and turns an operator typo into `FAILED_PRECONDITION`;
/// changing the forwarded address or collapsing the typed RIB error makes the
/// exact-target/unavailable assertions red.
#[tokio::test]
async fn refresh_outbound_forwards_exact_peer_and_classifies_failures() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel(4);
    let mut mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
    let peer = key(address);

    let unknown = mgr.refresh_outbound(peer.clone()).await.unwrap_err();
    assert!(matches!(
        unknown,
        rustbgpd_api::peer_types::OutboundRefreshError::PeerNotFound(ref key) if key == &peer
    ));
    assert!(
        rib_rx.try_recv().is_err(),
        "an unknown peer must be rejected before the RIB"
    );

    insert_test_managed_peer(&mut mgr, address, closed_peer_handle(), false);
    let success = mgr.refresh_outbound(peer.clone());
    let respond = async {
        let RibUpdate::RefreshPeerOutbound {
            peer: target,
            reply,
        } = rib_rx.recv().await.expect("refresh command")
        else {
            panic!("expected outbound refresh");
        };
        assert_eq!(target, address);
        let _ = reply.send(Ok(()));
    };
    let (result, ()) = tokio::join!(success, respond);
    result.unwrap();

    let unavailable = mgr.refresh_outbound(peer.clone());
    let respond = async {
        let RibUpdate::RefreshPeerOutbound { reply, .. } =
            rib_rx.recv().await.expect("refresh command")
        else {
            panic!("expected outbound refresh");
        };
        let _ = reply.send(Err(rustbgpd_rib::RibCommandError::not_found(
            "peer not registered",
        )));
    };
    let (unavailable, ()) = tokio::join!(unavailable, respond);
    let unavailable = unavailable.unwrap_err();
    assert!(matches!(
        unavailable,
        rustbgpd_api::peer_types::OutboundRefreshError::PeerUnavailable(ref key)
            if key == &peer
    ));
}

#[tokio::test]
async fn gshut_not_found_preserves_scoped_peer_label() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let peer = scoped_key(IpAddr::V6("fe80::2".parse().unwrap()), "eth1");

    let err = mgr
        .set_graceful_shutdown(Some(peer), true)
        .await
        .unwrap_err();

    assert_eq!(err.to_string(), "peer fe80::2%eth1 not found");
}

#[allow(
    clippy::too_many_lines,
    reason = "the hot-apply regression keeps all eBGP and iBGP peer assertions together"
)]
#[tokio::test]
async fn honor_graceful_shutdown_hot_apply_targets_ebgp_only() {
    use rustbgpd_transport::PeerCommand;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn fake_established_peer(
        addr: IpAddr,
        import_updates: Arc<AtomicU32>,
        refresh_calls: Arc<AtomicU32>,
    ) -> PeerHandle {
        let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(8);
        let task = tokio::spawn(async move {
            while let Some(cmd) = session_rx.recv().await {
                match cmd {
                    PeerCommand::UpdateImportPolicy { reply, .. } => {
                        import_updates.fetch_add(1, Ordering::SeqCst);
                        let _ = reply.send(Ok(()));
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
                    PeerCommand::SendRouteRefresh { reply, .. } => {
                        refresh_calls.fetch_add(1, Ordering::SeqCst);
                        let _ = reply.send(Ok(()));
                    }
                    PeerCommand::Shutdown => break,
                    _ => {}
                }
            }
            Ok(())
        });
        PeerHandle::from_parts(session_tx, task)
    }

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

    let ebgp = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let ibgp = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    mgr.current_config.neighbors = vec![config_neighbor(ebgp, 65002), config_neighbor(ibgp, 65001)];

    let ebgp_import_updates = Arc::new(AtomicU32::new(0));
    let ebgp_refresh_calls = Arc::new(AtomicU32::new(0));
    let ibgp_import_updates = Arc::new(AtomicU32::new(0));
    let ibgp_refresh_calls = Arc::new(AtomicU32::new(0));
    insert_test_managed_peer_with_asn(
        &mut mgr,
        ebgp,
        65002,
        fake_established_peer(
            ebgp,
            ebgp_import_updates.clone(),
            ebgp_refresh_calls.clone(),
        ),
        false,
    );
    insert_test_managed_peer_with_asn(
        &mut mgr,
        ibgp,
        65001,
        fake_established_peer(
            ibgp,
            ibgp_import_updates.clone(),
            ibgp_refresh_calls.clone(),
        ),
        false,
    );

    let result = mgr.set_honor_graceful_shutdown(true).await;
    assert!(result.is_ok(), "hot-apply must succeed: {result:?}");
    assert!(mgr.current_config.global.honor_graceful_shutdown);
    assert_eq!(
        ebgp_import_updates.load(Ordering::SeqCst),
        1,
        "EBGP peer must receive recomputed import policy with the implicit GShut rule"
    );
    assert_eq!(
        ebgp_refresh_calls.load(Ordering::SeqCst),
        1,
        "Established EBGP peer must get route refresh after the import chain changes"
    );
    assert_eq!(
        ibgp_import_updates.load(Ordering::SeqCst),
        0,
        "iBGP peer must be exempt from RFC 8326 receiver hot-apply"
    );
    assert_eq!(
        ibgp_refresh_calls.load(Ordering::SeqCst),
        0,
        "iBGP exemption also means no route refresh"
    );

    mgr.delete_peer(key(ebgp), false).await.unwrap();
    mgr.delete_peer(key(ibgp), false).await.unwrap();
    drop(mgr);
    let _ = rib_drainer.await;
}

/// Regression for a high-severity gap in the prior code: when
/// `update_import_policy_timeout` failed against an Established
/// peer, the warn-and-continue path then fired `soft_reset_in`
/// regardless. The session task still held the *old* import
/// policy, so Route Refresh would re-evaluate `AdjRibIn` against
/// the old policy — silently keeping forbidden routes flowing
/// on a permit→deny edit, with the daemon believing
/// the new policy was live and clearing any retry intent.
///
/// Fix and assertion: when the session-side import-policy update
/// fails AND the peer is Established AND there's a refresh
/// intent, the function must (a) leave `managed.import_policy`
/// at the prior value (so the next call's `import_changed` still
/// fires), (b) set `pending_refresh` for retry, (c) NOT call
/// `soft_reset_in`, and (d) return Err so the caller surfaces
/// the failure. The fake session here drops the import-policy
/// reply oneshot (sender side gets "session task dropped reply")
/// but answers `QueryState` with Established. This reproduces
/// the production race: the session task can drop a reply
/// mid-shutdown while the FSM is still reporting Established
/// for one more poll.
#[allow(
    clippy::too_many_lines,
    reason = "the failure regression keeps the rejected import and no-refresh receipt together"
)]
#[tokio::test]
async fn import_apply_failure_on_established_peer_bails_without_refresh() {
    use rustbgpd_policy::{Policy, PolicyAction};
    use rustbgpd_transport::PeerCommand;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    // Fake session task: drops UpdateImportPolicy replies (induces
    // "session task dropped reply" Err on the caller side), replies
    // OK to UpdateExportPolicy, replies Established to QueryState,
    // and counts SendRouteRefresh invocations so the test can
    // assert refresh was NOT issued. Subsequent commands process
    // sequentially after the dropped import reply because we drop
    // the reply oneshot inside the same arm — no parking.
    let (tx, mut rx) = mpsc::channel::<PeerCommand>(8);
    let route_refresh_calls = Arc::new(AtomicU32::new(0));
    let route_refresh_calls_in_task = route_refresh_calls.clone();
    let task_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let task = tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                PeerCommand::UpdateImportPolicy { reply, .. } => {
                    // Drop reply without responding → caller's
                    // reply_rx.await yields RecvError → the
                    // bounded variant maps that to "session task
                    // dropped reply".
                    drop(reply);
                }
                PeerCommand::UpdateExportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(PeerSessionState {
                        fsm_state: SessionState::Established,
                        peer_ip: task_addr,
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
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    route_refresh_calls_in_task.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    let handle = PeerHandle::from_parts(tx, task);

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    // RIB receiver is held but never expected to receive: the bail
    // path returns Err *before* the `ReplacePeerExportPolicy`
    // send. Holding rib_rx alive prevents the
    // `RibUpdate::ReplacePeerExportPolicy` send from failing
    // spuriously if the bail logic ever regresses.
    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let peer_config = make_config(task_addr, 65002);
    let transport = mgr.build_transport_config(&peer_config);
    let hold = transport.peer.hold_time;
    mgr.peers.insert(
        key(task_addr),
        ManagedPeer {
            handle,
            session_id: 1,
            remote_asn: 65002,
            description: "test".to_string(),
            peer_group: None,
            enabled: true,
            hold_time: Some(hold),
            max_prefixes: None,
            max_prefix_restart_seconds: None,
            transport_config: transport,
            import_policy: None,
            export_policy: None,
            pending_inbound: None,
            is_dynamic: false,
            rfc8212_external: false,
            tcp_ao_protected: false,
            accepted_dynamic_range: None,
            pending_refresh: false,
            pending_export_apply: false,
            tcp_ao_rotation: TcpAoRotationStatus::default(),
            advertise_graceful_shutdown: false,
        },
    );

    // Build a non-empty PolicyChain so import_changed flips true
    // (None → Some(...)). The chain content doesn't matter for
    // the test — only that it's distinct from the prior None.
    let chain = PolicyChain::new(vec![Policy {
        entries: Vec::new(),
        default_action: PolicyAction::Deny,
    }]);

    let result = mgr
        .update_runtime_policies(task_addr, Some(chain), None)
        .await;

    assert!(
        result.is_err(),
        "Established peer with import-changing intent must surface session-side \
         import-apply failure as Err — silently logging-and-continuing would let \
         the daemon believe the new policy is live while the session still has the \
         old one. Got: {result:?}"
    );
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("policy hot-apply") && err_msg.contains("import:"),
        "error message must explain the failure mode for the operator: {err_msg}"
    );

    let managed = mgr.peers.get(&key(task_addr)).expect("peer present");
    assert!(
        managed.pending_refresh,
        "pending_refresh must be set so the next update_runtime_policies call \
         retries the session-side update + Route Refresh as a unit."
    );
    assert!(
        managed.import_policy.is_none(),
        "managed.import_policy must remain at the prior value when the \
         session-side update failed — advancing it would mask the delta from \
         the next call's import_changed comparison and skip the retry. \
         Got: {:?}",
        managed.import_policy
    );

    assert_eq!(
        route_refresh_calls.load(Ordering::SeqCst),
        0,
        "soft_reset_in must NOT have run: firing Route Refresh against a session \
         that still holds the prior import policy would re-evaluate AdjRibIn \
         against the OLD policy — the silent-stale-routes regression this test pins."
    );
}

/// Non-Established variant of the import-apply failure regression.
/// The prior bail condition
/// (`is_established && import_apply_failed && needs_refresh`)
/// gated the failure surface on Established, which let an Idle /
/// Connect peer with a dropped `UpdateImportPolicy` command
/// silently return Ok. The caller (`apply_policy_change`) then
/// advanced `current_config`, leaving no retry signal — if the
/// session task subsequently died before processing the queued
/// command, the peer would reach Established holding the prior
/// import policy with no record that the edit didn't land.
///
/// The fix dropped the `is_established` gate from `import_bail`
/// (Route Refresh stays gated by `soft_reset_in`'s own check —
/// the gates serve different purposes). This test pins that
/// behavior: an Idle peer with a session that drops the
/// `UpdateImportPolicy` reply must bail with Err, set
/// `pending_refresh = true`, leave `managed.import_policy` at
/// the prior value, and (because peer is Idle) NOT fire Route
/// Refresh.
#[allow(
    clippy::too_many_lines,
    reason = "the idle-peer failure regression keeps pending-refresh state and wire assertions together"
)]
#[tokio::test]
async fn import_apply_failure_on_idle_peer_bails_and_sets_pending_refresh() {
    use rustbgpd_policy::{Policy, PolicyAction};
    use rustbgpd_transport::PeerCommand;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    let (tx, mut rx) = mpsc::channel::<PeerCommand>(8);
    let route_refresh_calls = Arc::new(AtomicU32::new(0));
    let route_refresh_calls_in_task = route_refresh_calls.clone();
    let task_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let task = tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                PeerCommand::UpdateImportPolicy { reply, .. } => {
                    // Drop without replying — caller observes
                    // "session task dropped reply".
                    drop(reply);
                }
                PeerCommand::UpdateExportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(PeerSessionState {
                        fsm_state: SessionState::Idle,
                        peer_ip: task_addr,
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
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    route_refresh_calls_in_task.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    let handle = PeerHandle::from_parts(tx, task);

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let peer_config = make_config(task_addr, 65002);
    let transport = mgr.build_transport_config(&peer_config);
    let hold = transport.peer.hold_time;
    mgr.peers.insert(
        key(task_addr),
        ManagedPeer {
            handle,
            session_id: 1,
            remote_asn: 65002,
            description: "test".to_string(),
            peer_group: None,
            enabled: true,
            hold_time: Some(hold),
            max_prefixes: None,
            max_prefix_restart_seconds: None,
            transport_config: transport,
            import_policy: None,
            export_policy: None,
            pending_inbound: None,
            is_dynamic: false,
            rfc8212_external: false,
            tcp_ao_protected: false,
            accepted_dynamic_range: None,
            pending_refresh: false,
            pending_export_apply: false,
            tcp_ao_rotation: TcpAoRotationStatus::default(),
            advertise_graceful_shutdown: false,
        },
    );

    let chain = PolicyChain::new(vec![Policy {
        entries: Vec::new(),
        default_action: PolicyAction::Deny,
    }]);

    let result = mgr
        .update_runtime_policies(task_addr, Some(chain), None)
        .await;

    assert!(
        result.is_err(),
        "Idle peer with import-changing intent and session-side apply failure must \
         surface as Err — silently returning Ok would let `apply_policy_change` \
         advance current_config with no retry signal, so a subsequently dying \
         session task would leak the stale import policy when the peer establishes. \
         Got: {result:?}"
    );
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("policy hot-apply") && err_msg.contains("import:"),
        "error message must call out the import side specifically: {err_msg}"
    );

    let managed = mgr.peers.get(&key(task_addr)).expect("peer present");
    assert!(
        managed.pending_refresh,
        "pending_refresh must be set so the next update_runtime_policies call \
         retries the session-side import update."
    );
    assert!(
        managed.import_policy.is_none(),
        "managed.import_policy must remain at the prior value when the session-side \
         update failed — advancing it would mask the delta from the next call's \
         import_changed comparison and skip the retry. Got: {:?}",
        managed.import_policy
    );

    assert_eq!(
        route_refresh_calls.load(Ordering::SeqCst),
        0,
        "Route Refresh must NOT fire for an Idle peer regardless of the bail \
         outcome — that's `soft_reset_in`'s own Established gate, which is a \
         separate concern from the failure-surfacing decision."
    );
}

/// Symmetric counterpart for the export side: the prior code
/// swallowed `update_export_policy_timeout` failures, logging a
/// warning and returning Ok. That left the peer announcing
/// under the old export policy even though the daemon's
/// bookkeeping had no record that the edit didn't land.
/// Different blast radius from the import gap
/// (no Route Refresh involved), but the same silent-stale-policy
/// class — and crucially, no `is_established` gate: a session
/// that's mid-handshake can still drop policy commands, and once
/// it reaches Established the registration with the RIB
/// (`PeerUp` path) uses whatever export policy the session task
/// holds. Failure must propagate, the bookkeeping must not
/// advance, and `pending_export_apply` must be set so the next
/// call retries.
#[allow(
    clippy::too_many_lines,
    reason = "the export failure regression keeps bookkeeping and wire assertions together"
)]
#[tokio::test]
async fn export_apply_failure_bails_without_advancing_bookkeeping() {
    use rustbgpd_policy::{Policy, PolicyAction};
    use rustbgpd_transport::PeerCommand;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    let (tx, mut rx) = mpsc::channel::<PeerCommand>(8);
    let rib_replace_calls = Arc::new(AtomicU32::new(0));
    let route_refresh_calls = Arc::new(AtomicU32::new(0));
    let route_refresh_calls_in_task = route_refresh_calls.clone();
    let task_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let task = tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                PeerCommand::UpdateImportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::UpdateExportPolicy { reply, .. } => {
                    // Drop without replying — caller observes
                    // "session task dropped reply".
                    drop(reply);
                }
                PeerCommand::QueryState { reply } => {
                    // Idle is enough: the export-side bail does
                    // not require Established. Using Idle here
                    // proves the export gap fires regardless of
                    // session state, which the prior code's
                    // warn-and-continue would have masked for
                    // every non-Established peer.
                    let _ = reply.send(PeerSessionState {
                        fsm_state: SessionState::Idle,
                        peer_ip: task_addr,
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
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    route_refresh_calls_in_task.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    let handle = PeerHandle::from_parts(tx, task);

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    // Hold rib_rx but spawn a task to assert ReplacePeerExportPolicy
    // is never received: the bail must run *before* the RIB step.
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
    let rib_replace_calls_clone = rib_replace_calls.clone();
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if matches!(update, RibUpdate::ReplacePeerExportPolicy { .. }) {
                rib_replace_calls_clone.fetch_add(1, Ordering::SeqCst);
            }
        }
    });

    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let peer_config = make_config(task_addr, 65002);
    let transport = mgr.build_transport_config(&peer_config);
    let hold = transport.peer.hold_time;
    mgr.peers.insert(
        key(task_addr),
        ManagedPeer {
            handle,
            session_id: 1,
            remote_asn: 65002,
            description: "test".to_string(),
            peer_group: None,
            enabled: true,
            hold_time: Some(hold),
            max_prefixes: None,
            max_prefix_restart_seconds: None,
            transport_config: transport,
            import_policy: None,
            export_policy: None,
            pending_inbound: None,
            is_dynamic: false,
            rfc8212_external: false,
            tcp_ao_protected: false,
            accepted_dynamic_range: None,
            pending_refresh: false,
            pending_export_apply: false,
            tcp_ao_rotation: TcpAoRotationStatus::default(),
            advertise_graceful_shutdown: false,
        },
    );

    let chain = PolicyChain::new(vec![Policy {
        entries: Vec::new(),
        default_action: PolicyAction::Deny,
    }]);

    // Pass the chain on the export side; import stays None so
    // import_apply succeeds and only the export path drives the
    // bail. This isolates the export-side regression from the
    // import-side coverage already in place.
    let result = mgr
        .update_runtime_policies(task_addr, None, Some(chain))
        .await;

    assert!(
        result.is_err(),
        "Export-changing intent with session-side apply failure must propagate as \
         Err — silently logging-and-continuing would let the daemon believe the \
         new export policy is live while the session keeps announcing under the \
         prior one. Got: {result:?}"
    );
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("policy hot-apply") && err_msg.contains("export:"),
        "error message must call out the export side specifically so the operator \
         can diagnose: {err_msg}"
    );

    let managed = mgr.peers.get(&key(task_addr)).expect("peer present");
    assert!(
        managed.pending_export_apply,
        "pending_export_apply must be set so the next update_runtime_policies call \
         retries the session-side export update."
    );
    assert!(
        managed.export_policy.is_none(),
        "managed.export_policy must remain at the prior value when the session-side \
         update failed — advancing it would mask the delta from the next call's \
         export_changed comparison and skip the retry. Got: {:?}",
        managed.export_policy
    );

    assert_eq!(
        rib_replace_calls.load(Ordering::SeqCst),
        0,
        "RIB ReplacePeerExportPolicy must NOT fire when the session-side export \
         update failed: the RIB and session would otherwise diverge, with the RIB \
         computing routes against the new policy and the session re-applying the \
         old one on outbound."
    );
    assert_eq!(
        route_refresh_calls.load(Ordering::SeqCst),
        0,
        "Export-only failure must not trigger Route Refresh — that is import-side \
         machinery and has no business firing on an export edit."
    );

    // Drain rib_rx so the spawned task can exit cleanly when mgr drops.
    drop(mgr);
    let _ = rib_drainer.await;
}

/// Cross-side regression: import apply succeeds (advancing
/// `managed.import_policy`) but export apply fails on the same
/// call. The bail must carry forward the unfired Route Refresh
/// intent so a subsequent retry — even one that finds
/// `import_changed = false` because bookkeeping already advanced
/// — still fires `soft_reset_in`. Without this, an operator
/// applying a policy referenced by both import and export chains
/// would land the new import policy for *future* UPDATEs but
/// leave `AdjRibIn` routes accepted under the prior import
/// policy stuck, with no signal that the refresh ever needed
/// to run.
///
/// First call: fake session ACKs `UpdateImportPolicy`, drops
/// `UpdateExportPolicy` reply → bail with both `pending_refresh`
/// and `pending_export_apply` set.
///
/// Second call (same target policies): fake session ACKs both →
/// no bail, `had_pending_refresh = true` carries
/// `needs_refresh = true`, `soft_reset_in` fires.
///
/// Asserts: first call returns Err with both flags set; second
/// call returns Ok with `route_refresh_calls > 0`.
#[allow(
    clippy::too_many_lines,
    reason = "the retry regression keeps import, export failure, and refresh receipt together"
)]
#[tokio::test]
async fn import_succeeds_export_fails_then_retry_fires_refresh() {
    use rustbgpd_policy::{Policy, PolicyAction};
    use rustbgpd_transport::PeerCommand;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    let (tx, mut rx) = mpsc::channel::<PeerCommand>(8);
    let drop_export_replies = Arc::new(AtomicBool::new(true));
    let route_refresh_calls = Arc::new(AtomicU32::new(0));
    let drop_export_replies_in_task = drop_export_replies.clone();
    let route_refresh_calls_in_task = route_refresh_calls.clone();
    let task_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let task = tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                PeerCommand::UpdateImportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::UpdateExportPolicy { reply, .. } => {
                    if drop_export_replies_in_task.load(Ordering::SeqCst) {
                        drop(reply);
                    } else {
                        let _ = reply.send(Ok(()));
                    }
                }
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(PeerSessionState {
                        fsm_state: SessionState::Established,
                        peer_ip: task_addr,
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
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    route_refresh_calls_in_task.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    let handle = PeerHandle::from_parts(tx, task);

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    // Drain RIB so the second call's ReplacePeerExportPolicy doesn't
    // wedge waiting for a reply.
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                let _ = reply.send(Ok(()));
            }
        }
    });

    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let peer_config = make_config(task_addr, 65002);
    let transport = mgr.build_transport_config(&peer_config);
    let hold = transport.peer.hold_time;
    mgr.peers.insert(
        key(task_addr),
        ManagedPeer {
            handle,
            session_id: 1,
            remote_asn: 65002,
            description: "test".to_string(),
            peer_group: None,
            enabled: true,
            hold_time: Some(hold),
            max_prefixes: None,
            max_prefix_restart_seconds: None,
            transport_config: transport,
            import_policy: None,
            export_policy: None,
            pending_inbound: None,
            is_dynamic: false,
            rfc8212_external: false,
            tcp_ao_protected: false,
            accepted_dynamic_range: None,
            pending_refresh: false,
            pending_export_apply: false,
            tcp_ao_rotation: TcpAoRotationStatus::default(),
            advertise_graceful_shutdown: false,
        },
    );

    let import_chain = PolicyChain::new(vec![Policy {
        entries: Vec::new(),
        default_action: PolicyAction::Deny,
    }]);
    let export_chain = PolicyChain::new(vec![Policy {
        entries: Vec::new(),
        default_action: PolicyAction::Deny,
    }]);

    // First call: import succeeds, export drops reply → bail.
    let result_1 = mgr
        .update_runtime_policies(
            task_addr,
            Some(import_chain.clone()),
            Some(export_chain.clone()),
        )
        .await;

    assert!(
        result_1.is_err(),
        "First call must fail: export apply dropped reply. Got: {result_1:?}"
    );

    let managed = mgr.peers.get(&key(task_addr)).expect("peer present");
    assert!(
        managed.import_policy.is_some(),
        "managed.import_policy must have advanced — import apply succeeded. Got: {:?}",
        managed.import_policy
    );
    assert!(
        managed.export_policy.is_none(),
        "managed.export_policy must NOT have advanced — export apply failed. Got: {:?}",
        managed.export_policy
    );
    assert!(
        managed.pending_refresh,
        "pending_refresh MUST be set even though import_bail did not trigger — \
         the refresh intent (import_changed) survives across an export-side bail. \
         Without this, the retry would see import_changed=false, no pending refresh, \
         and silently skip Route Refresh, leaving AdjRibIn stuck on prior policy."
    );
    assert!(
        managed.pending_export_apply,
        "pending_export_apply must be set so the next retry attempts export again."
    );
    assert_eq!(
        route_refresh_calls.load(Ordering::SeqCst),
        0,
        "First call must NOT have fired Route Refresh — it bailed before that step."
    );

    // Flip the fake to ACK export replies, then retry with the
    // SAME target policies. import_changed will be false on the
    // retry (bookkeeping already advanced), so the retry must
    // rely on had_pending_refresh to decide to fire refresh.
    drop_export_replies.store(false, Ordering::SeqCst);

    let result_2 = mgr
        .update_runtime_policies(task_addr, Some(import_chain), Some(export_chain))
        .await;

    assert!(
        result_2.is_ok(),
        "Second call (export now succeeds) must return Ok. Got: {result_2:?}"
    );

    let managed = mgr.peers.get(&key(task_addr)).expect("peer present");
    assert!(
        managed.export_policy.is_some(),
        "managed.export_policy must now be advanced after the successful retry."
    );
    assert!(
        !managed.pending_refresh,
        "pending_refresh must be cleared after the retry's soft_reset_in succeeded."
    );
    assert!(
        !managed.pending_export_apply,
        "pending_export_apply must be cleared after the retry's export apply succeeded."
    );

    assert!(
        route_refresh_calls.load(Ordering::SeqCst) >= 1,
        "Retry MUST have fired Route Refresh: this is the regression — without \
         carrying pending_refresh across the export bail on the first call, \
         needs_refresh would be false on retry and refresh would silently never \
         fire, leaving AdjRibIn stuck on prior import policy. \
         Got: {} refresh calls",
        route_refresh_calls.load(Ordering::SeqCst)
    );

    drop(mgr);
    let _ = rib_drainer.await;
}

/// Multi-agent quality audit caught a third partial-success
/// failure mode: session-side hot-apply succeeds (advancing
/// `managed.import_policy` AND `managed.export_policy`), the
/// peer is Established, then the RIB step fails — `rib_tx.send`
/// hits a closed channel, the reply oneshot is dropped, or the
/// RIB returns Err. The prior code returned Err via `?` without
/// re-arming `pending_refresh`, so a retry with the same target
/// would see `import_changed = false` (bookkeeping advanced)
/// and `had_pending_refresh = false`, compute `needs_refresh =
/// false`, and silently never fire `soft_reset_in`. `AdjRibIn`
/// routes accepted under the prior import policy would stay
/// stuck against a session that now had the new policy — same
/// silent-stale-routes class as the cross-side bail bug, just
/// at a different downstream step.
///
/// Fix: every RIB failure re-arms `pending_export_apply`, while
/// import-side intent independently re-arms `pending_refresh`. A
/// content-equal retry must therefore revisit the RIB, then refresh
/// Adj-RIB-In and clear both intents after success.
#[allow(
    clippy::too_many_lines,
    reason = "the RIB failure regression keeps transaction and retry state together"
)]
#[tokio::test]
async fn rib_failure_preserves_pending_refresh_for_retry() {
    use rustbgpd_policy::{Policy, PolicyAction};
    use rustbgpd_transport::PeerCommand;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    let (tx, mut rx) = mpsc::channel::<PeerCommand>(8);
    let route_refresh_calls = Arc::new(AtomicU32::new(0));
    let route_refresh_calls_in_task = route_refresh_calls.clone();
    let task_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let task = tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                PeerCommand::UpdateImportPolicy { reply, .. }
                | PeerCommand::UpdateExportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::QueryState { reply } => {
                    let _ = reply.send(PeerSessionState {
                        fsm_state: SessionState::Established,
                        peer_ip: task_addr,
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
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    route_refresh_calls_in_task.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    let handle = PeerHandle::from_parts(tx, task);

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    // RIB drainer that rejects the first ReplacePeerExportPolicy and
    // accepts the content-equal retry.
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(64);
    let rib_attempts = Arc::new(AtomicU32::new(0));
    let rib_attempts_in_task = Arc::clone(&rib_attempts);
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                if rib_attempts_in_task.fetch_add(1, Ordering::SeqCst) == 0 {
                    let _ = reply.send(Err(rustbgpd_rib::RibCommandError::internal(
                        "simulated RIB failure",
                    )));
                } else {
                    let _ = reply.send(Ok(()));
                }
            }
        }
    });

    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let peer_config = make_config(task_addr, 65002);
    let transport = mgr.build_transport_config(&peer_config);
    let hold = transport.peer.hold_time;
    mgr.peers.insert(
        key(task_addr),
        ManagedPeer {
            handle,
            session_id: 1,
            remote_asn: 65002,
            description: "test".to_string(),
            peer_group: None,
            enabled: true,
            hold_time: Some(hold),
            max_prefixes: None,
            max_prefix_restart_seconds: None,
            transport_config: transport,
            import_policy: None,
            export_policy: None,
            pending_inbound: None,
            is_dynamic: false,
            rfc8212_external: false,
            tcp_ao_protected: false,
            accepted_dynamic_range: None,
            pending_refresh: false,
            pending_export_apply: false,
            tcp_ao_rotation: TcpAoRotationStatus::default(),
            advertise_graceful_shutdown: false,
        },
    );

    let chain = PolicyChain::new(vec![Policy {
        entries: Vec::new(),
        default_action: PolicyAction::Deny,
    }]);

    // Both sides changed; both session-side applies succeed
    // (advancing bookkeeping); RIB step fails; before fix this
    // would return Err with no `pending_refresh` set, leaving
    // the next retry to silently skip Route Refresh.
    let result = mgr
        .update_runtime_policies(task_addr, Some(chain.clone()), Some(chain.clone()))
        .await;

    assert!(
        result.is_err(),
        "RIB failure must propagate as Err. Got: {result:?}"
    );
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("simulated RIB failure")
            || err_msg.contains("failed to update export policy"),
        "error message must surface the RIB failure for the operator: {err_msg}"
    );

    let managed = mgr.peers.get(&key(task_addr)).expect("peer present");
    assert!(
        managed.pending_refresh,
        "pending_refresh MUST be set: bookkeeping already advanced (session-side \
         apply succeeded) so the next retry would see import_changed=false; \
         without pending_refresh the retry's needs_refresh would be false and \
         soft_reset_in would silently never fire, leaving AdjRibIn stuck on \
         the prior import policy."
    );
    assert!(
        managed.pending_export_apply,
        "pending_export_apply must re-arm on every RIB error so a content-equal retry reaches the RIB"
    );
    assert!(
        managed.import_policy.is_some(),
        "managed.import_policy correctly advanced — session ACKed the new policy."
    );
    assert!(
        managed.export_policy.is_some(),
        "managed.export_policy correctly advanced — session ACKed the new policy."
    );
    assert_eq!(
        route_refresh_calls.load(Ordering::SeqCst),
        0,
        "Route Refresh must NOT have run — the RIB-failure bail returned Err \
         before reaching the soft_reset_in step."
    );

    mgr.update_runtime_policies(task_addr, Some(chain.clone()), Some(chain))
        .await
        .expect("content-equal retry must revisit and successfully update the RIB");
    assert_eq!(
        rib_attempts.load(Ordering::SeqCst),
        2,
        "the retained export intent must drive exactly one retry"
    );
    assert_eq!(
        route_refresh_calls.load(Ordering::SeqCst),
        1,
        "the independently retained import intent must refresh after the RIB retry succeeds"
    );
    let managed = mgr.peers.get(&key(task_addr)).expect("peer present");
    assert!(!managed.pending_export_apply);
    assert!(!managed.pending_refresh);

    drop(mgr);
    let _ = rib_drainer.await;
}

/// Stale-state-query regression: when
/// `query_state_timeout` returns None — because the session task
/// is back-pressured past the deadline and missed answering
/// `QueryState` — `is_established` reads false even for a peer
/// that is genuinely Established. With a fresh
/// `import_changed = true`, the prior code (`else if
/// had_pending_refresh && !is_established`) wouldn't re-arm
/// `pending_refresh` because nothing was inherited; the function
/// would advance bookkeeping, return Ok, and the next call would
/// see `import_changed = false` and silently never fire refresh.
/// `AdjRibIn` routes accepted under the prior import policy
/// would stay stuck against a session that now had the new
/// policy.
///
/// Fix: re-arm `pending_refresh` whenever
/// `needs_refresh && !is_established`, regardless of whether
/// the intent was inherited or freshly generated. This subsumes
/// the prior `had_pending_refresh && !is_established` branch and
/// covers the stale-query case that's indistinguishable from
/// genuine Idle from this side.
///
/// The "wasted refresh on truly-Idle peer" cost is real but
/// small (Route Refresh against an empty `AdjRibIn` is a no-op
/// on the wire) and is the right tradeoff against silent
/// stale-routes.
#[allow(
    clippy::too_many_lines,
    reason = "the stale-query regression keeps fencing and retry assertions together"
)]
#[tokio::test]
async fn stale_query_state_re_arms_pending_refresh() {
    use rustbgpd_policy::{Policy, PolicyAction};
    use rustbgpd_transport::PeerCommand;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    let (tx, mut rx) = mpsc::channel::<PeerCommand>(8);
    let route_refresh_calls = Arc::new(AtomicU32::new(0));
    let route_refresh_calls_in_task = route_refresh_calls.clone();
    let task = tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                PeerCommand::UpdateImportPolicy { reply, .. }
                | PeerCommand::UpdateExportPolicy { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::QueryState { reply } => {
                    // Drop the reply — caller observes None,
                    // simulating a back-pressured session that
                    // missed the deadline. From `update_runtime_policies`'s
                    // perspective this is indistinguishable from
                    // a genuinely Idle peer; the fix must re-arm
                    // pending_refresh regardless.
                    drop(reply);
                }
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    route_refresh_calls_in_task.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::Shutdown => break,
                _ => {}
            }
        }
        Ok(())
    });
    let handle = PeerHandle::from_parts(tx, task);

    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let task_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let peer_config = make_config(task_addr, 65002);
    let transport = mgr.build_transport_config(&peer_config);
    let hold = transport.peer.hold_time;
    mgr.peers.insert(
        key(task_addr),
        ManagedPeer {
            handle,
            session_id: 1,
            remote_asn: 65002,
            description: "test".to_string(),
            peer_group: None,
            enabled: true,
            hold_time: Some(hold),
            max_prefixes: None,
            max_prefix_restart_seconds: None,
            transport_config: transport,
            import_policy: None,
            export_policy: None,
            pending_inbound: None,
            is_dynamic: false,
            rfc8212_external: false,
            tcp_ao_protected: false,
            accepted_dynamic_range: None,
            pending_refresh: false,
            pending_export_apply: false,
            tcp_ao_rotation: TcpAoRotationStatus::default(),
            advertise_graceful_shutdown: false,
        },
    );

    let chain = PolicyChain::new(vec![Policy {
        entries: Vec::new(),
        default_action: PolicyAction::Deny,
    }]);

    // Fresh import_changed=true; both apply paths succeed; query
    // returns None (stale). Without the fix, this call returns
    // Ok and silently loses refresh intent.
    let result = mgr
        .update_runtime_policies(task_addr, Some(chain), None)
        .await;

    assert!(
        result.is_ok(),
        "Stale query state must NOT be treated as a failure — the call should \
         succeed (apply paths did) and just defer the refresh via pending_refresh. \
         Got: {result:?}"
    );

    let managed = mgr.peers.get(&key(task_addr)).expect("peer present");
    assert!(
        managed.pending_refresh,
        "pending_refresh MUST be re-armed when query_state_timeout returned None \
         with a fresh import_changed=true. The prior code only re-armed when the \
         pending flag was *inherited*; a fresh refresh intent under a stale query \
         was silently lost. Without this re-arm, the retry would see \
         import_changed=false (bookkeeping advanced) and never fire refresh, \
         leaving AdjRibIn stuck on the prior import policy."
    );
    assert!(
        managed.import_policy.is_some(),
        "managed.import_policy correctly advanced — session ACKed the new policy. \
         The query was stale, but the apply itself succeeded."
    );
    assert_eq!(
        route_refresh_calls.load(Ordering::SeqCst),
        0,
        "Route Refresh must NOT have fired in this call — soft_reset_in is gated \
         on Established (via query_state_timeout result), and the query was stale. \
         The retry-on-next-call path is what fires refresh once the query unblocks."
    );
}
