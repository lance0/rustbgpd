use super::*;
use rustbgpd_rib::PeerId;

/// `reset_peer` retires any pending inbound collision candidate before the
/// enabled primary receives one `AdministrativeReset`; the peer stays enabled,
/// and unknown or disabled peers are refused without any session command.
#[tokio::test]
async fn reset_peer_sends_administrative_reset_and_keeps_peer_enabled() {
    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let counters = Arc::new(FakePeerCounters::default());
    let pending = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer(
        &mut mgr,
        addr,
        fake_peer_handle(
            addr,
            SessionState::Established,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            counters.clone(),
        ),
        false,
    );
    attach_test_pending_inbound(
        &mut mgr,
        addr,
        fake_peer_handle(
            addr,
            SessionState::OpenConfirm,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            pending.clone(),
        ),
        2,
    );

    let reason = Some(rustbgpd_wire::notification::encode_shutdown_communication(
        "maintenance",
    ));
    mgr.reset_peer(key(addr), reason).await.unwrap();
    wait_counter(&pending.shutdown, 1).await;
    wait_counter(&counters.administrative_reset, 1).await;
    assert_eq!(counters.stop.load(Ordering::SeqCst), 0);
    assert_eq!(counters.shutdown.load(Ordering::SeqCst), 0);
    assert_eq!(pending.administrative_reset.load(Ordering::SeqCst), 0);
    assert_eq!(pending.stop.load(Ordering::SeqCst), 0);
    let managed = &mgr.peers[&key(addr)];
    assert!(managed.enabled);
    assert!(managed.pending_inbound.is_none());
    assert_eq!(managed.session_id(), 1);
    assert_eq!(mgr.peer_key_for_session(1), Some(key(addr)));
    assert!(mgr.peer_key_for_session(2).is_none());

    let missing = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    assert!(matches!(
        mgr.reset_peer(key(missing), None).await,
        Err(rustbgpd_api::peer_types::PeerLifecycleError::NotFound(_))
    ));

    mgr.peers.get_mut(&key(addr)).unwrap().enabled = false;
    assert!(matches!(
        mgr.reset_peer(key(addr), None).await,
        Err(rustbgpd_api::peer_types::PeerLifecycleError::RestartRequired(_))
    ));
    assert_eq!(counters.administrative_reset.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn manager_shutdown_bounds_many_stalled_peers_by_concurrent_waves() {
    let (tx, rx) = mpsc::channel(1);
    let (rib_tx, _rib_rx) = mpsc::channel(1);
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
    let peer_count = PEER_SHUTDOWN_CONCURRENCY + 1;
    let dropped = Arc::new(AtomicU32::new(0));

    for index in 0..peer_count {
        let host = u8::try_from(index + 1).expect("test peer count fits one IPv4 /24");
        let addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, host));
        let primary = stalled_shutdown_peer_handle(dropped.clone()).await;
        insert_test_managed_peer(&mut mgr, addr, primary, false);
        let pending = stalled_shutdown_peer_handle(dropped.clone()).await;
        mgr.peers.get_mut(&key(addr)).unwrap().pending_inbound = Some(PendingInbound {
            recovery_reset: None,
            handle: pending,
            session_id: (index + peer_count + 1) as u64,
        });
    }

    let started = tokio::time::Instant::now();
    let manager = tokio::spawn(mgr.run());
    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    manager.await.unwrap();
    let elapsed = started.elapsed();

    assert!(
        elapsed <= PEER_LIFECYCLE_COMMAND_TIMEOUT * 5,
        "bounded cross-peer shutdown should take two pending+primary waves, took {elapsed:?}"
    );
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        u32::try_from(peer_count * 2).expect("test handle count fits u32"),
        "every timed-out pending and primary task must be aborted and reaped"
    );
}

#[tokio::test]
async fn add_duplicate_returns_error() {
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let handle = tokio::spawn(mgr.run());

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::AddPeer {
        config: make_config(addr, 65002),
        sync_config_snapshot: false,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok());

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::AddPeer {
        config: make_config(addr, 65002),
        sync_config_snapshot: false,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_err());

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn delete_peer_removes() {
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let handle = tokio::spawn(mgr.run());

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::AddPeer {
        config: make_config(addr, 65002),
        sync_config_snapshot: false,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok());

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::DeletePeer {
        peer: key(addr),
        sync_config_snapshot: false,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let removed = reply_rx.await.unwrap().unwrap();
    assert_eq!(removed.address, addr);
    assert_eq!(removed.remote_asn, 65002);

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::ListPeers { reply: reply_tx })
        .await
        .unwrap();
    let peers = reply_rx.await.unwrap();
    assert!(peers.is_empty());

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn delete_peer_drains_pending_inbound_candidate() {
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
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
    let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let primary = Arc::new(FakePeerCounters::default());
    let pending = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer_with_asn(
        &mut mgr,
        peer_addr,
        65002,
        fake_peer_handle(
            peer_addr,
            SessionState::OpenConfirm,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            primary.clone(),
        ),
        false,
    );
    attach_test_pending_inbound(
        &mut mgr,
        peer_addr,
        fake_peer_handle(
            peer_addr,
            SessionState::OpenConfirm,
            Some(Ipv4Addr::new(10, 0, 0, 2)),
            pending.clone(),
        ),
        2,
    );

    mgr.delete_peer(key(peer_addr), false).await.unwrap();

    wait_counter(&primary.shutdown, 1).await;
    wait_counter(&pending.shutdown, 1).await;
    assert!(mgr.peers.is_empty());
    assert!(mgr.peer_key_for_session(1).is_none());
    assert!(mgr.peer_key_for_session(2).is_none());
}

#[tokio::test]
async fn delete_tcp_ao_peer_is_restart_required() {
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let handle = tokio::spawn(mgr.run());

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut config = make_config(addr, 65002);
    config.tcp_ao = Some(
        rustbgpd_transport::TcpAoConfig {
            key: "secret".into(),
            send_id: 1,
            recv_id: 1,
            algorithm: rustbgpd_transport::TcpAoAlgorithm::HmacSha256,
            preferred: false,
            deprecated: false,
        }
        .into(),
    );

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::AddPeer {
        config,
        sync_config_snapshot: false,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok());

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::DeletePeer {
        peer: key(addr),
        sync_config_snapshot: true,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let result = reply_rx.await.unwrap();
    assert!(
        result.is_err(),
        "TCP-AO peer deletion must be restart-required"
    );
    let err = result.err().unwrap();
    assert!(err.to_string().contains("requires restart"), "{err}");

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::ListPeers { reply: reply_tx })
        .await
        .unwrap();
    let peers = reply_rx.await.unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].address, addr);

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn same_key_tcp_ao_peer_reconfigure_is_allowed() {
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let handle = tokio::spawn(mgr.run());

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let tcp_ao: rustbgpd_transport::TcpAoKeyring = rustbgpd_transport::TcpAoConfig {
        key: "secret".into(),
        send_id: 1,
        recv_id: 1,
        algorithm: rustbgpd_transport::TcpAoAlgorithm::HmacSha256,
        preferred: false,
        deprecated: false,
    }
    .into();
    let mut config = make_config(addr, 65002);
    config.tcp_ao = Some(tcp_ao.clone());

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::AddPeer {
        config,
        sync_config_snapshot: false,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok());

    let mut changed = make_config(addr, 65002);
    changed.description = "updated-description".to_string();
    changed.tcp_ao = Some(tcp_ao);
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::ReconcilePeers {
        added: Vec::new(),
        removed: Vec::new(),
        changed: vec![changed],
        reply: reply_tx,
    })
    .await
    .unwrap();
    let result = reply_rx.await.unwrap();
    assert!(result.failures.is_empty(), "{:?}", result.failures);

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::ListPeers { reply: reply_tx })
        .await
        .unwrap();
    let peers = reply_rx.await.unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].address, addr);
    assert_eq!(peers[0].description, "updated-description");

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn delete_nonexistent_returns_error() {
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let handle = tokio::spawn(mgr.run());

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99));
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::DeletePeer {
        peer: key(addr),
        sync_config_snapshot: false,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_err());

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn get_peer_state_existing() {
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let handle = tokio::spawn(mgr.run());

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::AddPeer {
        config: make_config(addr, 65002),
        sync_config_snapshot: false,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let _ = reply_rx.await;

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::GetPeerState {
        peer: key(addr),
        reply: reply_tx,
    })
    .await
    .unwrap();
    let info = reply_rx.await.unwrap();
    assert!(info.is_some());
    assert_eq!(info.unwrap().address, addr);

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn get_peer_state_nonexistent_returns_none() {
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let handle = tokio::spawn(mgr.run());

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::GetPeerState {
        peer: key(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99))),
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_none());

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn shutdown_stops_all_peers() {
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let metrics = BgpMetrics::new();
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics,
        rib_tx,
        None,
    );
    let handle = tokio::spawn(mgr.run());

    for i in 2..=3 {
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(PeerManagerCommand::AddPeer {
            config: make_config(addr, 65000 + u32::from(i)),
            sync_config_snapshot: false,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let _ = reply_rx.await;
    }

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

/// Regression: `DeleteNeighbor` must refuse dynamic-range peers. Deleting
/// one through the static surface permanently leaked its
/// `dynamic_neighbor_limit` slot (the `BackToIdle` decrement never runs for a
/// peer removed this way), and the persist-failure rollback would resurrect
/// it as a persisted static neighbor.
#[tokio::test]
async fn delete_peer_rejects_dynamic_targets() {
    use rustbgpd_api::peer_types::PeerLifecycleError;

    let mut mgr = test_peer_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    insert_test_managed_peer(
        &mut mgr,
        addr,
        fake_peer_handle(
            addr,
            SessionState::Established,
            None,
            Arc::new(FakePeerCounters::default()),
        ),
        false,
    );
    mgr.peers.get_mut(&key(addr)).unwrap().is_dynamic = true;

    let Err(err) = mgr.delete_peer(key(addr), false).await else {
        panic!("deleting a dynamic peer must be rejected");
    };
    assert!(
        matches!(err, PeerLifecycleError::Invalid(_)),
        "expected Invalid, got {err:?}"
    );
    assert!(
        mgr.peers.contains_key(&key(addr)),
        "rejected delete must leave the dynamic peer managed"
    );
}

fn scoped_config(interface: &str, scope_id: u32) -> PeerManagerNeighborConfig {
    let mut config = make_config("fe80::1".parse().unwrap(), 65002);
    config.interface = Some(interface.to_string());
    config.scope_id = Some(scope_id);
    config
}

/// A runtime neighbor add that would put a second neighbor on a link-local
/// address while BMP runs is refused before any effect, naming both
/// neighbors and BMP (BMP running first, then the neighbor).
#[tokio::test]
async fn runtime_add_of_a_same_address_neighbor_is_refused_while_bmp_runs() {
    let mut mgr = test_peer_manager();
    mgr.current_config.bmp = Some(crate::config::BmpConfig {
        sys_name: "rustbgpd".to_string(),
        sys_descr: String::new(),
        collectors: vec![crate::config::BmpCollector {
            address: "127.0.0.1:11019".to_string(),
            reconnect_interval: 30,
            monitor: vec![crate::config::BmpMonitorView::RibInPre],
            version: 3,
            on_identity_conflict: crate::config::BmpIdentityConflict::Refuse,
        }],
    });
    // The persisted add resolves its interface, so the first neighbor uses
    // one that exists; the admission check refuses before the second
    // neighbor's interface is ever resolved.
    mgr.add_peer(scoped_config("lo", 1), true).await.unwrap();
    let error = mgr
        .add_peer(scoped_config("eth1", 3), true)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("bmp_identity_conflict"), "{error}");
    assert!(
        error.contains("fe80::1%eth1") && error.contains("fe80::1%lo"),
        "{error}"
    );
    assert!(error.contains("BMP"), "{error}");
    assert_eq!(mgr.peers.len(), 1, "the refused add has no effect");
    assert_eq!(mgr.current_config.neighbors.len(), 1);
    for (_, managed) in mgr.peers.drain() {
        let _ = managed.into_parts().0.shutdown().await;
    }
}

/// Every neighbor on a shared link-local address is known by that address,
/// and operations on one reach that neighbor's own RIB handle, never its
/// sibling's: an outbound refresh for eth1 names eth1's handle.
#[tokio::test]
async fn same_address_neighbors_reach_their_own_rib_handles() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
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
    mgr.add_peer(scoped_config("eth0", 2), false).await.unwrap();
    mgr.add_peer(scoped_config("eth1", 3), false).await.unwrap();
    assert!(mgr.has_peer_address("fe80::1".parse().unwrap()));
    let eth1 = scoped_key("fe80::1".parse().unwrap(), "eth1");
    let expected = mgr.rib_peer_of(&eth1);
    assert_ne!(
        expected,
        mgr.rib_peer_of(&scoped_key("fe80::1".parse().unwrap(), "eth0"))
    );
    let rib = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::RefreshPeerOutbound { peer, reply } = update {
                let _ = reply.send(Ok(()));
                return peer;
            }
        }
        panic!("RefreshPeerOutbound never arrived");
    });
    mgr.refresh_outbound(eth1).await.unwrap();
    assert_eq!(rib.await.unwrap(), expected);
    for (_, managed) in mgr.peers.drain() {
        let _ = managed.into_parts().0.shutdown().await;
    }
}

/// The update-group planner keeps two neighbors that share a link-local
/// address apart: a change to one is planned for that one only.
#[test]
fn update_group_plan_keeps_same_address_neighbors_apart() {
    let pair = |eth0_extra: &str| -> crate::config::Config {
        toml::from_str(&format!(
            "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\nlisten_port = 179\n\
             [global.telemetry]\nlog_format = \"json\"\n\
             [[neighbors]]\naddress = \"fe80::1\"\ninterface = \"eth0\"\nremote_asn = 65001\n\
             {eth0_extra}\n\
             [[neighbors]]\naddress = \"fe80::1\"\ninterface = \"eth1\"\nremote_asn = 65001\n"
        ))
        .unwrap()
    };
    let mut mgr = test_peer_manager();
    mgr.current_config = pair("");
    let link_local: IpAddr = "fe80::1".parse().unwrap();
    let endpoint = |interface| rustbgpd_rib::PeerEndpoint::new(link_local, Some(interface));
    let handles = [
        rustbgpd_rib::PeerId::allocate(endpoint("eth0")),
        rustbgpd_rib::PeerId::allocate(endpoint("eth1")),
    ];
    let input = rustbgpd_rib::UpdateGroupClassifierInput {
        policy_fingerprint: None,
        policy_provenance: None,
        policy_requires_peer_context: false,
        target_is_ebgp: false,
        target_is_rr_client: false,
        target_local_role: None,
        interpret_rfc1997: true,
        sendable_families: vec![(1, 1)],
        llgr_families: Vec::new(),
        add_path_send: false,
        per_client_best: false,
        orr_vantage: None,
        orf_installed: false,
        conditional_advertisement: false,
    };
    let snapshot = rustbgpd_rib::UpdateGroupSnapshot {
        peers: handles
            .iter()
            .map(|&peer| rustbgpd_rib::UpdateGroupPeerSnapshot {
                peer,
                input: input.clone(),
                classification: rustbgpd_rib::classify_update_group(input.clone()),
                runtime_membership: String::new(),
            })
            .collect(),
    };

    let plan = mgr
        .plan_update_group_impact(&pair("route_reflector_client = true"), snapshot)
        .unwrap();

    let transitions = plan
        .entries
        .iter()
        .map(|row| (row.peer.to_string(), row.transition.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(
        transitions,
        [
            ("fe80::1%eth0".to_string(), "regroup"),
            ("fe80::1%eth1".to_string(), "no_op")
        ]
    );
    assert_eq!(plan.rollup.affected_peers, 1);
    for handle in handles {
        assert!(handle.release());
    }
}

/// With every collector set to exclude, the second of two static neighbors
/// on one link-local address is admitted with its session left out of BMP.
/// Reconfiguring the first keeps it monitored (an excluded neighbor is not
/// a monitored holder), and deleting the second ends its exclusion.
#[tokio::test]
async fn second_static_neighbor_at_an_address_is_excluded_when_every_collector_excludes() {
    let mut mgr = test_peer_manager();
    let collector = |address: &str| crate::config::BmpCollector {
        address: address.to_string(),
        reconnect_interval: 30,
        monitor: vec![crate::config::BmpMonitorView::RibInPre],
        version: 3,
        on_identity_conflict: crate::config::BmpIdentityConflict::Exclude,
    };
    mgr.current_config.bmp = Some(crate::config::BmpConfig {
        sys_name: "rustbgpd".to_string(),
        sys_descr: String::new(),
        collectors: vec![collector("127.0.0.1:11019"), collector("127.0.0.1:11020")],
    });
    let (bmp_tx, _bmp_rx) = mpsc::channel(8);
    mgr.bmp_tx = Some(bmp_tx);
    mgr.add_peer(scoped_config("eth0", 10), false)
        .await
        .unwrap();
    mgr.add_peer(scoped_config("eth1", 11), false)
        .await
        .unwrap();
    let address: IpAddr = "fe80::1".parse().unwrap();
    let (eth0, eth1) = (scoped_key(address, "eth0"), scoped_key(address, "eth1"));
    assert!(mgr.session_bmp_tx(&eth0).is_some());
    assert!(mgr.session_bmp_tx(&eth1).is_none());

    let mut changed = scoped_config("eth0", 10);
    changed.description = "reconfigured".to_string();
    mgr.reconfigure_peer(changed).await.unwrap();
    assert!(mgr.session_bmp_tx(&eth0).is_some(), "still monitored");
    assert!(mgr.session_bmp_tx(&eth1).is_none());

    mgr.delete_peer(eth1.clone(), false).await.unwrap();
    assert!(mgr.bmp_excluded.is_empty());
    mgr.delete_peer(eth0, false).await.unwrap();
}

/// The kind and handle of each RIB update a deletion test expects, in the
/// order the RIB received them.
fn deletion_trace(updates: &[RibUpdate]) -> Vec<(&'static str, PeerId)> {
    updates
        .iter()
        .map(|update| match update {
            RibUpdate::PeerDeleted { peer, .. } => ("PeerDeleted", *peer),
            RibUpdate::ReleasePeer { peer } => ("ReleasePeer", *peer),
            RibUpdate::RetireEorGraceInterface { .. } => ("RetireEorGraceInterface", PeerId::LOCAL),
            _ => panic!("unexpected RIB update"),
        })
        .collect()
}

/// Join a drain task; an update that never reaches the RIB fails the test
/// instead of hanging it.
async fn joined<T>(drain: tokio::task::JoinHandle<T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), drain)
        .await
        .expect("every expected update reaches the RIB")
        .unwrap()
}

/// Occupies the only slot of a capacity-1 RIB mailbox.
fn mailbox_filler() -> RibUpdate {
    RibUpdate::ReleasePeer {
        peer: PeerId::UNASSIGNED,
    }
}

/// A deletion behind a RIB mailbox that the RIB never drains does not hold
/// the actor: the operator's delete is answered, and a dynamic neighbor's
/// `BackToIdle` is handled, auto-removing it, while that deletion's cleanup
/// is still not admitted. Once the RIB drains, both deletions arrive in
/// order, each `PeerDeleted` before its `ReleasePeer`.
#[tokio::test]
async fn deletion_behind_a_stalled_rib_mailbox_does_not_hold_the_actor() {
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel(1);
    let mut mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx.clone(),
        None,
    );
    let deleted = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let idle = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    for addr in [deleted, idle] {
        let counters = Arc::new(FakePeerCounters::default());
        let handle = fake_peer_handle(addr, SessionState::Established, None, counters);
        insert_test_managed_peer(&mut mgr, addr, handle, false);
    }
    mgr.peers.get_mut(&key(idle)).unwrap().is_dynamic = true;
    let idle_session = mgr.peers.get(&key(idle)).unwrap().session_id();
    let notify_tx = mgr.session_notify_tx.clone();
    let mut events = mgr.session_events_tx.subscribe();
    // The RIB's only mailbox slot is taken, and nothing receives until the
    // actor has handled both removals.
    rib_tx.try_send(mailbox_filler()).unwrap();
    drop(rib_tx);
    let actor = tokio::spawn(mgr.run());

    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::DeletePeer {
        peer: key(deleted),
        sync_config_snapshot: false,
        reply,
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(5), response)
        .await
        .expect("the delete is answered while its RIB cleanup waits for mailbox room")
        .unwrap()
        .expect("the delete succeeds");

    notify_tx
        .send(SessionNotification::BackToIdle {
            session_id: idle_session,
            role: rustbgpd_transport::SessionRole::Primary,
            peer_addr: idle,
        })
        .unwrap();
    while wait_for_session_event(&mut events, SessionLifecycleEventType::PeerRemoved)
        .await
        .peer
        != idle
    {}

    let mut admitted = Vec::new();
    for _ in 0..5 {
        let update = tokio::time::timeout(Duration::from_secs(5), rib_rx.recv())
            .await
            .expect("the deferred cleanup reaches the RIB once it drains")
            .unwrap();
        admitted.push(update);
    }
    let (deleted_handle, idle_handle) = (PeerId::from_addr(deleted), PeerId::from_addr(idle));
    assert_eq!(
        deletion_trace(&admitted),
        [
            ("ReleasePeer", PeerId::UNASSIGNED),
            ("PeerDeleted", deleted_handle),
            ("ReleasePeer", deleted_handle),
            ("PeerDeleted", idle_handle),
            ("ReleasePeer", idle_handle),
        ]
    );

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    actor.await.unwrap();
}

/// A deferred deletion stays ahead of what follows it. A session start at
/// another label does not wait for it; one at the deleted neighbor's label
/// waits until its `PeerDeleted` and `ReleasePeer` are admitted; and a later
/// ordered update is admitted behind it.
#[tokio::test]
async fn deferred_deletion_stays_ahead_of_later_updates_and_its_label() {
    let (rib_tx, mut rib_rx) = mpsc::channel(1);
    let mut mgr = test_peer_manager();
    mgr.rib_tx = rib_tx.clone();
    let deleted = key(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    let other = key(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)));
    let (deleted_handle, other_handle) = (
        PeerId::from_addr(deleted.address),
        PeerId::from_addr(other.address),
    );

    rib_tx.try_send(mailbox_filler()).unwrap();
    mgr.reap_deleted_peer_metric_series_for_key(&deleted);
    assert_eq!(
        mgr.deferred_rib.queue.len(),
        2,
        "deferred behind the full mailbox"
    );
    tokio::time::timeout(
        Duration::from_secs(5),
        mgr.admit_deferred_rib_updates_for(&other),
    )
    .await
    .expect("a session at another label does not wait for mailbox room");
    assert_eq!(
        mgr.deferred_rib.queue.len(),
        2,
        "another label does not wait"
    );

    let drain = tokio::spawn(async move {
        let mut admitted = Vec::new();
        for _ in 0..3 {
            admitted.push(rib_rx.recv().await.unwrap());
        }
        (admitted, rib_rx)
    });
    mgr.admit_deferred_rib_updates_for(&deleted).await;
    assert!(mgr.deferred_rib.queue.is_empty());
    let (admitted, mut rib_rx) = joined(drain).await;
    assert_eq!(
        deletion_trace(&admitted),
        [
            ("ReleasePeer", PeerId::UNASSIGNED),
            ("PeerDeleted", deleted_handle),
            ("ReleasePeer", deleted_handle),
        ]
    );
    let RibUpdate::PeerDeleted {
        label: Some(label), ..
    } = &admitted[1]
    else {
        panic!("the deletion reaps its neighbor's label");
    };
    assert_eq!(&**label, "10.0.0.2");

    rib_tx.try_send(mailbox_filler()).unwrap();
    mgr.reap_deleted_peer_metric_series_for_key(&other);
    let drain = tokio::spawn(async move {
        let mut admitted = Vec::new();
        for _ in 0..4 {
            admitted.push(rib_rx.recv().await.unwrap());
        }
        admitted
    });
    mgr.send_rib_update(
        RibUpdate::RetireEorGraceInterface {
            interface: "eth0".into(),
        },
        OperatorReadAdmission::Served,
    )
    .await
    .unwrap();
    assert_eq!(
        deletion_trace(&joined(drain).await),
        [
            ("ReleasePeer", PeerId::UNASSIGNED),
            ("PeerDeleted", other_handle),
            ("ReleasePeer", other_handle),
            ("RetireEorGraceInterface", PeerId::LOCAL),
        ]
    );
}

/// Re-adding a deleted neighbor while its cleanup waits for mailbox room
/// starts the new session only after that cleanup is admitted.
#[tokio::test]
async fn readd_waits_for_the_deleted_neighbors_deferred_cleanup() {
    let (rib_tx, mut rib_rx) = mpsc::channel(1);
    let mut mgr = test_peer_manager();
    mgr.rib_tx = rib_tx.clone();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    mgr.add_peer(make_config(addr, 65002), false).await.unwrap();
    let old_handle = mgr.rib_peer_of(&key(addr));
    while rib_rx.try_recv().is_ok() {}

    rib_tx.try_send(mailbox_filler()).unwrap();
    mgr.delete_peer(key(addr), false).await.unwrap();
    assert_eq!(
        mgr.deferred_rib.queue.len(),
        2,
        "deferred behind the full mailbox"
    );
    let drain = tokio::spawn(async move {
        let mut admitted = Vec::new();
        for _ in 0..3 {
            admitted.push(rib_rx.recv().await.unwrap());
        }
        (admitted, rib_rx)
    });
    mgr.add_peer(make_config(addr, 65002), false).await.unwrap();
    assert!(
        mgr.deferred_rib.queue.is_empty(),
        "the re-added neighbor's session started behind its predecessor's cleanup"
    );
    let (admitted, _rib_rx) = joined(drain).await;
    assert_eq!(
        deletion_trace(&admitted),
        [
            ("ReleasePeer", PeerId::UNASSIGNED),
            ("PeerDeleted", old_handle),
            ("ReleasePeer", old_handle),
        ]
    );
    assert_ne!(mgr.rib_peer_of(&key(addr)), old_handle);
    mgr.delete_peer(key(addr), false).await.unwrap();
}

/// A deferred deletion's reservation takes the first slot a resumed RIB
/// frees. A wait for a direct round trip sends it, so on a capacity-1
/// mailbox the round trip still completes, behind the deletion, instead of
/// waiting out its deadline beside a slot the actor holds but never uses.
#[tokio::test]
async fn a_direct_round_trip_behind_a_deferred_deletion_completes_once_the_rib_resumes() {
    let (rib_tx, mut rib_rx) = mpsc::channel(1);
    let mut mgr = test_peer_manager();
    mgr.rib_tx = rib_tx.clone();
    let deleted = key(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    let retiring = key(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)));
    rib_tx.try_send(mailbox_filler()).unwrap();
    mgr.reap_deleted_peer_metric_series_for_key(&deleted);
    // The run loop polls the oldest reservation between turns; it stays
    // queued for the first free slot when a turn takes another branch.
    tokio::select! {
        biased;
        _ = mgr.deferred_rib.send_oldest() => panic!("the mailbox is full"),
        () = std::future::ready(()) => {}
    }

    let rib = tokio::spawn(async move {
        let mut admitted = Vec::new();
        while let Some(update) = rib_rx.recv().await {
            let kind = match update {
                RibUpdate::QueryLocRibCount { reply } => {
                    let _ = reply.send(0);
                    "QueryLocRibCount"
                }
                RibUpdate::PeerDown { .. } => "PeerDown",
                RibUpdate::PeerDeleted { .. } => "PeerDeleted",
                RibUpdate::ReleasePeer { .. } => "ReleasePeer",
                _ => "other",
            };
            admitted.push(kind);
            if admitted.len() == 5 {
                return admitted;
            }
        }
        admitted
    });
    mgr.dampening_retirement_barrier(&retiring, &[7])
        .await
        .expect("the barrier completes once the RIB resumes");
    mgr.flush_deferred_rib_updates(OperatorReadAdmission::Served)
        .await
        .unwrap();
    // The filler, then the deletion that held the first freed slot, ahead of
    // the barrier. The deletion's release queued for a slot after the
    // barrier's first send did, and the two interleave in that order.
    let mut admitted = joined(rib).await;
    assert_eq!(admitted[..2], ["ReleasePeer", "PeerDeleted"]);
    admitted[2..].sort_unstable();
    assert_eq!(
        admitted[2..],
        ["PeerDown", "QueryLocRibCount", "ReleasePeer"]
    );
}

/// Once the RIB has exited, the deferred updates are discarded rather than
/// retried, so neither the run loop nor a flush polls the closed lane again.
#[tokio::test]
async fn deferred_updates_are_discarded_once_the_rib_exits() {
    let (rib_tx, rib_rx) = mpsc::channel(1);
    let mut mgr = test_peer_manager();
    mgr.rib_tx = rib_tx.clone();
    rib_tx.try_send(mailbox_filler()).unwrap();
    mgr.reap_deleted_peer_metric_series_for_key(&key(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    mgr.reap_deleted_peer_metric_series_for_key(&key(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3))));
    assert_eq!(mgr.deferred_rib.queue.len(), 4);
    drop(rib_rx);

    assert!(!mgr.deferred_rib.send_oldest().await, "the RIB has exited");
    assert!(
        mgr.deferred_rib.queue.is_empty(),
        "nothing is left to retry"
    );
    assert!(!mgr.deferred_rib.ready());

    let (rib_tx, rib_rx) = mpsc::channel(1);
    mgr.rib_tx = rib_tx.clone();
    rib_tx.try_send(mailbox_filler()).unwrap();
    mgr.reap_deleted_peer_metric_series_for_key(&key(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4))));
    drop(rib_rx);
    assert_eq!(
        mgr.flush_deferred_rib_updates(OperatorReadAdmission::Served)
            .await,
        Err(())
    );
    assert!(mgr.deferred_rib.queue.is_empty());
}
