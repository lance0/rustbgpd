use super::*;
use rustbgpd_transport::{ForwardingStateSource, LocalForwardingState};

fn kernel(config: &TransportConfig) -> Vec<(Afi, Safi)> {
    match config
        .local_forwarding_state
        .as_ref()
        .expect("daemon role source")
    {
        ForwardingStateSource::Configured(families) => families.clone(),
        ForwardingStateSource::Live(source) => source.kernel_families(),
    }
}

#[tokio::test]
async fn forwarding_state_static_dynamic_and_managed_construction_agree() {
    let mut mgr = dynamic_test_manager();
    let mut table = crate::test_support::basic_fib_table("v4", 1001);
    table.families = vec!["ipv4_unicast".into()];
    mgr.current_config.fib_tables = vec![table];
    mgr.local_forwarding_state
        .publish_fib(&mgr.current_config.fib_tables);
    let neighbor = config_neighbor("192.0.2.1".parse().unwrap(), 65002);
    let resolved = mgr.current_config.resolve_neighbor(&neighbor).unwrap();
    let expected = vec![(Afi::Ipv4, Safi::Unicast)];
    assert_eq!(kernel(&resolved.transport_config), expected);
    let dynamic = mgr
        .current_config
        .resolve_dynamic_neighbor(
            "192.0.2.2".parse().unwrap(),
            65002,
            "dynamic",
            &mgr.current_config.peer_groups["ix-members"],
            "ix-members",
            true,
        )
        .unwrap();
    assert_eq!(kernel(&dynamic.transport_config), expected);
    let managed_config = PeerManager::peer_manager_config_from_resolved(resolved, false);
    assert_eq!(
        kernel(&mgr.build_transport_config(&managed_config)),
        expected
    );
    mgr.add_peer(managed_config, false).await.unwrap();
    let managed = &mgr.peers[&key("192.0.2.1".parse().unwrap())];
    assert!(matches!(
        managed.transport_config.local_forwarding_state,
        Some(ForwardingStateSource::Live(_))
    ));
    let retained = managed.transport_config.clone();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
    let (stream, remote) = listener.accept().await.unwrap();
    let _client = client.await.unwrap();
    mgr.handle_inbound(stream, sock(remote.ip()), None, None)
        .await;
    let dynamic = &mgr.peers[&key(remote.ip())];
    assert!(dynamic.is_dynamic);
    assert!(matches!(
        dynamic.transport_config.local_forwarding_state,
        Some(ForwardingStateSource::Live(_))
    ));
    assert_eq!(kernel(&dynamic.transport_config), expected);
    mgr.local_forwarding_state.publish_fib(&[]);
    assert!(
        kernel(&retained).is_empty(),
        "already retained actor/candidate config sees removal"
    );
}

#[tokio::test]
async fn forwarding_state_transaction_stage_commit_rollback_and_reload_publication() {
    let (tx, rx) = mpsc::channel(8);
    let (internal_tx, internal_rx) = mpsc::channel(8);
    let (rib_tx, mut rib_rx) = mpsc::channel(8);
    let base = make_dynamic_manager_config();
    let mut candidate = base.clone();
    let mut table = crate::test_support::basic_fib_table("v4", 1001);
    table.families = vec!["ipv4_unicast".into()];
    candidate.fib_tables = vec![table];
    let mgr = PeerManager::new_with_config(
        rx,
        internal_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
        None,
        base.clone(),
    );
    let roles = mgr.local_forwarding_state.clone();
    let task = tokio::spawn(mgr.run());
    acknowledge_initial_dampening_owners(&mut rib_rx).await;

    for (config, before, after) in [
        (candidate, vec![], vec![(Afi::Ipv4, Safi::Unicast)]),
        (base.clone(), vec![(Afi::Ipv4, Safi::Unicast)], vec![]),
    ] {
        let (reply, done) = oneshot::channel();
        internal_tx
            .send(InternalCommand::StageTransactionConfig {
                candidate: Box::new(config),
                scope: TransactionConfigScope::FibTablesOnly,
                reply,
            })
            .await
            .unwrap();
        done.await.unwrap().unwrap();
        assert_eq!(
            roles.kernel_families(),
            before,
            "staged candidate is invisible to OPEN"
        );
        let (reply, done) = oneshot::channel();
        tx.send(PeerManagerCommand::CommitConfigSnapshotStage { reply })
            .await
            .unwrap();
        done.await.unwrap();
        assert_eq!(
            roles.kernel_families(),
            after,
            "commit and committed rollback both publish"
        );
    }
    // The ordinary SIGHUP snapshot publication is distinct from transaction staging.
    let mut reload = base;
    reload.fib_tables = vec![crate::test_support::basic_fib_table("dual", 1001)];
    reload.fib_tables[0].families = vec!["ipv4_unicast".into(), "ipv6_unicast".into()];
    let (ack, done) = oneshot::channel();
    internal_tx
        .send(InternalCommand::ReplaceConfigSnapshot {
            config: Box::new(reload),
            ack: Some(ack),
        })
        .await
        .unwrap();
    done.await.unwrap();
    assert_eq!(
        roles.kernel_families(),
        vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)]
    );
    let (reply, done) = oneshot::channel();
    tx.send(PeerManagerCommand::StageFibTables {
        tables: vec![],
        reply,
    })
    .await
    .unwrap();
    done.await.unwrap().unwrap();
    assert_eq!(
        roles.kernel_families().len(),
        2,
        "CRUD stage cannot leak deletion"
    );
    let (reply, done) = oneshot::channel();
    tx.send(PeerManagerCommand::SetFibTablesSnapshot {
        tables: vec![],
        reply,
    })
    .await
    .unwrap();
    done.await.unwrap();
    assert!(
        roles.kernel_families().is_empty(),
        "acknowledged runtime deletion publishes"
    );
    task.abort();
    let _ = task.await;
}

/// GR and LLGR forwarding bits from one real dynamic-session OPEN on the wire.
async fn dynamic_open_forwarding(
    mgr: &mut PeerManager,
    source: Ipv4Addr,
) -> Vec<(Afi, Safi, bool)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind(SocketAddr::new(source.into(), 0)).unwrap();
        socket.connect(addr).await.unwrap()
    });
    let (stream, remote) = listener.accept().await.unwrap();
    let mut client = client.await.unwrap();
    mgr.handle_inbound(stream, sock(remote.ip()), None, None)
        .await;
    let mut buf = BytesMut::new();
    let Message::Open(open) = tokio::time::timeout(
        Duration::from_secs(2),
        super::collision::read_bgp_message(&mut client, &mut buf),
    )
    .await
    .expect("dynamic session must emit OPEN") else {
        panic!("expected OPEN");
    };
    let gr = open.capabilities.iter().find_map(|cap| match cap {
        Capability::GracefulRestart { families, .. } => Some(
            families
                .iter()
                .map(|f| (f.afi, f.safi, f.forwarding_preserved))
                .collect::<Vec<_>>(),
        ),
        _ => None,
    });
    let llgr = open.capabilities.iter().find_map(|cap| match cap {
        Capability::LongLivedGracefulRestart(families) => Some(
            families
                .iter()
                .map(|f| (f.afi, f.safi, f.forwarding_preserved))
                .collect::<Vec<_>>(),
        ),
        _ => None,
    });
    let gr = gr.expect("GR capability");
    assert_eq!(
        llgr.as_ref(),
        Some(&gr),
        "LLGR uses the same snapshot as GR"
    );
    gr
}

async fn assert_poisoned_writer_fails_closed() {
    use rustbgpd_api::health_probe::DaemonGate;
    use rustbgpd_api::runtime_config_settlement::{
        RuntimeConfigOperationKind, RuntimeConfigSettlementWatchdog,
    };
    use rustbgpd_api::server::RuntimeConfigCoordinator;

    let ipv4 = (Afi::Ipv4, Safi::Unicast);
    let ipv6 = (Afi::Ipv6, Safi::Unicast);
    let evpn = (Afi::L2Vpn, Safi::Evpn);
    let mut startup = make_dynamic_manager_config();
    let mut v6 = crate::test_support::basic_fib_table("v6", 1001);
    v6.families = vec!["ipv6_unicast".into()];
    startup.fib_tables = vec![v6];
    let group = startup.peer_groups.get_mut("ix-members").unwrap();
    group.families = vec!["ipv4_unicast".into(), "ipv6_unicast".into()];
    group.graceful_restart = Some(true);
    group.llgr_stale_time = Some(120);

    let watchdog = RuntimeConfigSettlementWatchdog::new();
    let state = Arc::new(
        crate::forwarding_state::ForwardingState::new(&startup).with_settlement(watchdog.clone()),
    );
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let mut mgr = PeerManager::new_with_config(
        rx,
        mpsc::channel(1).1,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
        None,
        startup,
    )
    .with_local_forwarding_state(state.clone());

    // Healthy snapshot: IPv6 is FIB-backed, IPv4 is control-plane only.
    assert_eq!(state.kernel_families(), vec![ipv6]);
    assert_eq!(
        dynamic_open_forwarding(&mut mgr, Ipv4Addr::new(127, 0, 0, 2)).await,
        vec![
            (Afi::Ipv4, Safi::Unicast, true),
            (Afi::Ipv6, Safi::Unicast, false)
        ]
    );

    // A registered owner's task records a possible IPv4 effect, then panics
    // inside the roles critical section. Join completes only after unwinding
    // dropped both the roles guard (poison) and the executor guard (fence).
    let coordinator = RuntimeConfigCoordinator::new();
    let permit = coordinator.acquire().await.unwrap();
    let (_operation, executor_guard) = watchdog.register_owned(
        RuntimeConfigOperationKind::FibSet,
        coordinator,
        permit,
        DaemonGate::new(),
        None,
        None,
        Arc::new(AtomicBool::new(true)),
    );
    let writer = state.clone();
    let owner = tokio::spawn(async move {
        let _owner = executor_guard;
        writer.record_fib_attempt(&[crate::test_support::basic_fib_table("v4", 1002)]);
        writer.panic_holding_roles_for_test();
    });
    assert!(owner.await.unwrap_err().is_panic());
    assert!(state.roles_poisoned_for_test());
    assert_eq!(watchdog.owner_fence_reason(), Some("executor_lost"));
    assert_eq!(
        state.kernel_families(),
        vec![ipv4, ipv6],
        "the fenced reader keeps the possible IPv4 effect"
    );

    // Late publication after poison cannot clear possible effects.
    state.publish_fib(&[]);
    assert_eq!(state.kernel_families(), vec![ipv4, ipv6]);
    // An unsettled EVPN attempt unwinding over the poisoned lock records
    // uncertainty instead of aborting on a second panic.
    let writer = state.clone();
    let unwinding = tokio::spawn(async move {
        let _attempt = writer.begin_evpn_attempt(true);
        panic!("injected panic with an unsettled EVPN attempt");
    });
    assert!(unwinding.await.unwrap_err().is_panic());
    assert_eq!(state.kernel_families(), vec![ipv4, ipv6, evpn]);
    state.begin_evpn_attempt(false).reject_no_effect();
    state.publish_evpn(false);
    assert_eq!(
        state.kernel_families(),
        vec![ipv4, ipv6, evpn],
        "neither rejection nor publication restores authority after the fence"
    );

    // An OPEN inside the fail-stop grace certifies no family.
    assert_eq!(
        dynamic_open_forwarding(&mut mgr, Ipv4Addr::new(127, 0, 0, 3)).await,
        vec![
            (Afi::Ipv4, Safi::Unicast, false),
            (Afi::Ipv6, Safi::Unicast, false)
        ]
    );
}

#[tokio::test]
async fn forwarding_state_poisoned_writer_fails_closed_through_settlement_fence() {
    const CHILD_ENV: &str = "RUSTBGPD_FORWARDING_POISON_CHILD";
    const MARKER: &str = "forwarding poison fence proof complete";
    if std::env::var_os(CHILD_ENV).is_some() {
        assert_poisoned_writer_fails_closed().await;
        println!("{MARKER}");
        // The real watchdog ends this process once the parent releases it.
        std::future::pending::<()>().await;
    }
    let child = crate::test_support::run_fail_stop_child(
        "peer_manager::tests::forwarding_state::forwarding_state_poisoned_writer_fails_closed_through_settlement_fence",
        CHILD_ENV,
        MARKER,
    )
    .await;
    assert!(
        child.stdout.contains(MARKER),
        "subprocess must complete the selected proof: {}\n{}\n{}",
        child.status,
        child.stdout,
        child.stderr,
    );
    assert_eq!(
        child.status.code(),
        Some(rustbgpd_api::runtime_config_settlement::AMBIGUOUS_CONFIG_EXIT_STATUS),
        "the fenced owner must fail-stop the process"
    );
}
