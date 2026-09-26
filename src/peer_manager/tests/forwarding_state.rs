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
    let (rib_tx, _rib_rx) = mpsc::channel(8);
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
