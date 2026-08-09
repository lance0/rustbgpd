use super::*;

/// Load-bearing producer-path proof: dropping the field at either
/// `ResolvedNeighbor` -> `PeerManagerConfig` or `PeerManagerConfig` -> `ManagedPeer`
/// makes the final assertion `None` while parsing/inheritance still passes.
#[tokio::test]
async fn inherited_max_prefix_restart_reaches_managed_peer() {
    let config = load_test_config(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "127.0.0.1:9179"
log_format = "json"

[peer_groups.ix-members]
max_prefix_restart_seconds = 30

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "ix-members"
"#,
    );
    let resolved = config.resolved_neighbors().unwrap().pop().unwrap();
    let peer_config = PeerManager::peer_manager_config_from_resolved(resolved, false);
    assert_eq!(peer_config.max_prefix_restart_seconds, Some(30));

    let mut mgr = test_peer_manager();
    let peer = key(peer_config.address);
    mgr.add_peer(peer_config, false).await.unwrap();
    assert_eq!(
        mgr.peers[&peer].max_prefix_restart_seconds,
        Some(30),
        "manager must own the fully resolved restart policy"
    );
}

#[test]
fn add_dynamic_range_appends_and_is_matchable() {
    let mut mgr = dynamic_test_manager();
    let before = mgr.dynamic_ranges.len();
    let cfg_before = mgr.current_config.dynamic_neighbors.len();
    mgr.add_dynamic_range("10.0.0.0/24".into(), "ix-members".into(), 65002, None)
        .expect("add should succeed");
    assert_eq!(mgr.dynamic_ranges.len(), before + 1);
    assert_eq!(mgr.current_config.dynamic_neighbors.len(), cfg_before + 1);
    assert!(
        mgr.match_dynamic_range("10.0.0.5".parse().unwrap())
            .is_some(),
        "newly added range should match"
    );
}

#[test]
fn add_dynamic_range_rejects_duplicate_effective_prefix() {
    let mut mgr = dynamic_test_manager();
    mgr.add_dynamic_range("10.0.0.0/24".into(), "ix-members".into(), 0, None)
        .unwrap();
    let count = mgr.dynamic_ranges.len();
    // 10.0.0.9/24 normalizes to the same 10.0.0.0/24 — must be rejected.
    let err = mgr
        .add_dynamic_range("10.0.0.9/24".into(), "ix-members".into(), 0, None)
        .expect_err("duplicate effective prefix should be rejected");
    assert!(
        matches!(
            err,
            rustbgpd_api::peer_types::DynamicRangeError::AlreadyExists(_)
        ),
        "{err}"
    );
    assert_eq!(
        mgr.dynamic_ranges.len(),
        count,
        "no range added on duplicate"
    );
}

#[test]
fn add_dynamic_range_rejects_unknown_peer_group() {
    let mut mgr = dynamic_test_manager();
    let err = mgr
        .add_dynamic_range("10.0.0.0/24".into(), "nonexistent".into(), 0, None)
        .expect_err("unknown peer group should be rejected");
    assert!(
        matches!(
            err,
            rustbgpd_api::peer_types::DynamicRangeError::NotFound(_)
        ),
        "{err}"
    );
}

#[test]
fn add_dynamic_range_rejects_listener_enforced_group_auth() {
    let mut mgr = dynamic_test_manager();
    // Listener MD5/GTSM inventories are startup/reload-pinned; a runtime
    // range referencing a group with either knob would report authentication
    // as configured while enforcing it on no socket.
    for (name, group) in [
        (
            "md5-members",
            crate::config::PeerGroupConfig {
                md5_password: Some("secret".to_string()),
                ..Default::default()
            },
        ),
        (
            "gtsm-members",
            crate::config::PeerGroupConfig {
                ttl_security: Some(true),
                ..Default::default()
            },
        ),
    ] {
        mgr.current_config
            .peer_groups
            .insert(name.to_string(), group);
        let err = mgr
            .add_dynamic_range("10.9.0.0/24".into(), name.into(), 0, None)
            .expect_err("listener-enforced group auth must be rejected at runtime");
        assert!(
            matches!(
                &err,
                rustbgpd_api::peer_types::DynamicRangeError::Invalid(reason)
                    if reason.contains("startup-pinned BGP listener")
            ),
            "{err}"
        );
    }
}

#[tokio::test]
async fn runtime_create_peer_rejects_listener_enforced_group_auth() {
    let mut mgr = dynamic_test_manager();
    mgr.current_config.peer_groups.insert(
        "gtsm-members".to_string(),
        crate::config::PeerGroupConfig {
            ttl_security: Some(true),
            ..Default::default()
        },
    );
    let err = mgr
        .runtime_create_peer(Box::new(
            rustbgpd_api::peer_types::PresenceAwareNeighborCreate {
                address: "10.0.0.9".parse().unwrap(),
                interface: None,
                remote_asn: 65009,
                description: None,
                peer_group: Some("gtsm-members".to_string()),
                hold_time: None,
                min_hold_time: None,
                send_hold_time: None,
                max_prefixes: None,
                max_prefix_restart_seconds: None,
                remove_private_as: None,
                local_role: None,
                families: None,
                required_families: None,
                route_server_client: None,
                per_client_best: None,
                strict_role: None,
                add_path: None,
            },
        ))
        .await
        .expect_err("runtime create resolving listener-enforced auth must be rejected");
    assert!(
        matches!(
            &err,
            rustbgpd_api::peer_types::PeerLifecycleError::RestartRequired(reason)
                if reason.contains("startup or SIGHUP reload")
        ),
        "{err}"
    );
    assert!(
        !mgr.current_config
            .neighbors
            .iter()
            .any(|neighbor| neighbor.address == "10.0.0.9"),
        "rejected create must not advance the config snapshot"
    );
}

#[test]
fn add_dynamic_range_rejects_overlap_with_md5_protected_range() {
    let mut mgr = dynamic_test_manager();
    mgr.current_config.peer_groups.insert(
        "md5-members".to_string(),
        crate::config::PeerGroupConfig {
            md5_password: Some("secret".to_string()),
            ..Default::default()
        },
    );
    mgr.current_config
        .dynamic_neighbors
        .push(crate::config::DynamicNeighborConfig {
            prefix: "10.8.0.0/16".to_string(),
            peer_group: "md5-members".to_string(),
            remote_asn: 0,
            description: None,
            tcp_ao: None,
        });
    let err = mgr
        .add_dynamic_range("10.8.4.0/24".into(), "ix-members".into(), 0, None)
        .expect_err("overlap with an MD5-protected startup range must be rejected");
    assert!(
        matches!(
            &err,
            rustbgpd_api::peer_types::DynamicRangeError::Invalid(reason)
                if reason.contains("startup-pinned MD5-protected range")
        ),
        "{err}"
    );
}

/// LAN-910: the delete counterpart of the runtime-create fence. A protected
/// peer's inbound MD5 key / GTSM selector live on the startup/SIGHUP-pinned
/// listener; a runtime delete would leave the stale key installed and wedge
/// a delete-then-re-add. (`delete_peer_removes` keeps proving the unprotected
/// runtime delete path clean.)
#[tokio::test]
async fn delete_peer_rejects_listener_enforced_auth() {
    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let mgr = PeerManager::new(
        rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
    );
    let handle = tokio::spawn(mgr.run());

    let mut md5_config = make_config(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 65002);
    md5_config.md5_password = Some("secret".to_string().into());
    let mut gtsm_config = make_config(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), 65003);
    gtsm_config.ttl_security = true;

    for config in [md5_config, gtsm_config] {
        let addr = config.address;
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
            sync_config_snapshot: false,
            reply: reply_tx,
        })
        .await
        .unwrap();
        match reply_rx.await.unwrap() {
            Ok(_) => panic!("runtime delete of a listener-protected peer must be refused"),
            Err(err) => assert!(
                matches!(
                    &err,
                    rustbgpd_api::peer_types::PeerLifecycleError::RestartRequired(reason)
                        if reason.contains("startup or SIGHUP reload")
                ),
                "{err}"
            ),
        }
    }

    let (list_tx, list_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::ListPeers { reply: list_tx })
        .await
        .unwrap();
    assert_eq!(
        list_rx.await.unwrap().len(),
        2,
        "refused deletes must leave the peers configured"
    );

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

/// LAN-910: the delete counterpart of the runtime range-add fence. The
/// protected range models a startup-configured one (the add fence refuses to
/// create it at runtime). (`delete_dynamic_range_removes_and_stops_future_match`
/// keeps proving the unprotected runtime range delete clean.)
#[test]
fn delete_dynamic_range_rejects_listener_enforced_group_auth() {
    let mut mgr = dynamic_test_manager();
    for (name, group, prefix) in [
        (
            "md5-members",
            crate::config::PeerGroupConfig {
                md5_password: Some("secret".to_string()),
                ..Default::default()
            },
            "10.9.0.0/24",
        ),
        (
            "gtsm-members",
            crate::config::PeerGroupConfig {
                ttl_security: Some(true),
                ..Default::default()
            },
            "10.10.0.0/24",
        ),
    ] {
        mgr.current_config
            .peer_groups
            .insert(name.to_string(), group);
        mgr.current_config
            .dynamic_neighbors
            .push(crate::config::DynamicNeighborConfig {
                prefix: prefix.to_string(),
                peer_group: name.to_string(),
                remote_asn: 0,
                description: None,
                tcp_ao: None,
            });
        mgr.dynamic_ranges = PeerManager::parse_dynamic_ranges(&mgr.current_config);
        let err = mgr
            .delete_dynamic_range(prefix)
            .expect_err("runtime delete of a listener-protected range must be refused");
        assert!(
            matches!(
                &err,
                rustbgpd_api::peer_types::DynamicRangeError::Invalid(reason)
                    if reason.contains("startup or SIGHUP reload")
            ),
            "{err}"
        );
        assert!(
            mgr.current_config
                .dynamic_neighbors
                .iter()
                .any(|range| range.prefix == prefix),
            "refused delete must keep the range configured"
        );
    }
}

/// LAN-910 Gap B verdict: `DeletePeerGroup` needs no `md5_password` /
/// `ttl_security` fence
/// of its own. A group's authentication reaches the listener only through
/// its members (static host keys, dynamic-range prefix keys), and any such
/// member already blocks the delete with `StillReferenced` — including
/// `[[dynamic_neighbors]]` ranges since LAN-906. An unreferenced group
/// contributes nothing to the listener inventory, so deleting it is safe.
#[tokio::test]
async fn delete_peer_group_referenced_by_md5_dynamic_range_is_refused() {
    let mut mgr = dynamic_test_manager();
    mgr.current_config.peer_groups.insert(
        "md5-members".to_string(),
        crate::config::PeerGroupConfig {
            md5_password: Some("secret".to_string()),
            ..Default::default()
        },
    );
    mgr.current_config
        .dynamic_neighbors
        .push(crate::config::DynamicNeighborConfig {
            prefix: "10.9.0.0/24".to_string(),
            peer_group: "md5-members".to_string(),
            remote_asn: 0,
            description: None,
            tcp_ao: None,
        });
    let err = mgr
        .apply_peer_group_change(
            rustbgpd_api::peer_types::ConfigEvent::DeletePeerGroup {
                name: "md5-members".to_string(),
                ack: None,
            },
            Vec::new(),
        )
        .await
        .expect_err("deleting a group still referenced by a dynamic range must be refused");
    assert!(
        matches!(&err, CatalogMutationError::StillReferenced { .. }),
        "{err:?}"
    );
    assert!(
        mgr.current_config.peer_groups.contains_key("md5-members"),
        "refused delete must keep the group"
    );
}

#[test]
fn runtime_dynamic_crud_rejects_startup_pinned_tcp_ao_ranges_and_overlaps() {
    let mut mgr = dynamic_test_manager();
    mgr.current_config.dynamic_neighbors[0].tcp_ao = Some(test_tcp_ao().into());

    let add_err = mgr
        .add_dynamic_range("127.0.1.0/24".into(), "ix-members".into(), 0, None)
        .expect_err("runtime add overlapping protected prefix must fail");
    assert!(add_err.to_string().contains("startup-pinned TCP-AO"));

    let delete_err = mgr
        .delete_dynamic_range("127.0.0.0/8")
        .expect_err("runtime delete of protected prefix must fail");
    assert!(delete_err.to_string().contains("startup-pinned"));
}

#[test]
fn runtime_dynamic_add_rejects_static_tcp_ao_neighbor_coverage() {
    let mut mgr = dynamic_test_manager();
    let mut neighbor = config_neighbor("10.20.30.40".parse().unwrap(), 65002);
    neighbor.tcp_ao = Some(test_tcp_ao().into());
    mgr.current_config.neighbors.push(neighbor);

    let err = mgr
        .add_dynamic_range("10.0.0.0/8".into(), "ix-members".into(), 0, None)
        .expect_err("runtime range must not introduce plaintext over static TCP-AO");
    assert!(err.to_string().contains("static TCP-AO neighbor"), "{err}");
    assert!(
        mgr.dynamic_ranges
            .iter()
            .all(|range| range.addr != "10.0.0.0".parse::<IpAddr>().unwrap()),
        "rejected range must not mutate runtime state"
    );
}

#[tokio::test]
async fn dynamic_tcp_ao_snapshot_reports_protected_from_explicit_range_keyring() {
    let (tx, rx) = mpsc::channel(16);
    let (_internal_tx, internal_rx) = mpsc::unbounded_channel();
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let mut config = make_dynamic_manager_config();
    config.dynamic_neighbors[0].tcp_ao = Some(test_tcp_ao().into());
    let manager = PeerManager::new_with_config(
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
        config,
    );
    let handle = tokio::spawn(manager.run());

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let connect = TcpStream::connect(listener.local_addr().unwrap());
    let accept = listener.accept();
    let (client, accepted) = tokio::join!(connect, accept);
    let client = client.unwrap();
    let (server, remote_addr) = accepted.unwrap();
    tx.send(PeerManagerCommand::AcceptInbound {
        stream: server,
        peer_addr: remote_addr,
        tcp_ao_info: Some(rustbgpd_transport::TcpAoInfoSnapshot {
            has_current_key: true,
            has_rnext_key: true,
            ao_required: false,
            accept_icmps: false,
            current_key: 1,
            rnext_key: 1,
            pkt_good: 1,
            pkt_bad: 0,
            pkt_key_not_found: 0,
            pkt_ao_required: 0,
            pkt_dropped_icmp: 0,
            keys: vec![rustbgpd_transport::TcpAoKeyState {
                peer: "127.0.0.0".parse().unwrap(),
                prefix_len: 8,
                send_id: 1,
                recv_id: 1,
                algorithm: rustbgpd_transport::TcpAoAlgorithm::HmacSha256,
                is_current: true,
                is_rnext: true,
                preferred: false,
                deprecated: false,
                vrf_ifindex: None,
                pkt_good: 1,
                pkt_bad: 0,
            }],
        }),
        tcp_ao_generation: Some(rustbgpd_transport::TcpAoRotationGeneration::STARTUP),
    })
    .await
    .unwrap();

    let (list_tx, list_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::ListPeers { reply: list_tx })
        .await
        .unwrap();
    let peers = list_rx.await.unwrap();
    assert_eq!(peers.len(), 1);
    assert!(peers[0].is_dynamic);
    assert_eq!(peers[0].authentication, "tcp_ao");

    drop(client);
    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[test]
fn delete_dynamic_range_removes_and_stops_future_match() {
    let mut mgr = dynamic_test_manager();
    mgr.add_dynamic_range("10.0.0.0/24".into(), "ix-members".into(), 0, None)
        .unwrap();
    let before = mgr.dynamic_ranges.len();
    assert!(
        mgr.match_dynamic_range("10.0.0.5".parse().unwrap())
            .is_some()
    );
    // Delete by a host-bit variant of the same network — effective-prefix match.
    let removed = mgr
        .delete_dynamic_range("10.0.0.7/24")
        .expect("delete by effective prefix should succeed");
    assert_eq!(mgr.dynamic_ranges.len(), before - 1);
    assert!(
        mgr.match_dynamic_range("10.0.0.5".parse().unwrap())
            .is_none(),
        "deleted range must no longer match (future accepts stop)"
    );
    assert_eq!(removed.prefix, "10.0.0.0/24");
    assert_eq!(removed.peer_group, "ix-members");
}

#[test]
fn delete_dynamic_range_unknown_returns_error() {
    let mut mgr = dynamic_test_manager();
    let err = mgr
        .delete_dynamic_range("192.0.2.0/24")
        .expect_err("deleting a missing range should error");
    assert!(
        matches!(
            err,
            rustbgpd_api::peer_types::DynamicRangeError::NotFound(_)
        ),
        "{err}"
    );
}

#[tokio::test]
async fn replace_config_snapshot_rebuilds_dynamic_range_matcher() {
    let (tx, rx) = mpsc::channel(16);
    let (internal_tx, internal_rx) = mpsc::unbounded_channel();
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let config = make_dynamic_manager_config();
    let mut replacement = config.clone();
    replacement.dynamic_neighbors = vec![crate::config::DynamicNeighborConfig {
        prefix: "10.10.0.0/16".to_string(),
        peer_group: "ix-members".to_string(),
        remote_asn: 65010,
        description: Some("reload range".to_string()),
        tcp_ao: None,
    }];

    let manager = PeerManager::new_with_config(
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
        config,
    );
    let handle = tokio::spawn(manager.run());

    let (ack_tx, ack_rx) = oneshot::channel();
    internal_tx
        .send(InternalCommand::ReplaceConfigSnapshot {
            config: Box::new(replacement),
            ack: Some(ack_tx),
        })
        .unwrap();
    ack_rx.await.unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::ListDynamicRanges { reply: reply_tx })
        .await
        .unwrap();
    let ranges = reply_rx.await.unwrap();
    assert_eq!(ranges.len(), 1);
    assert_eq!(ranges[0].prefix, "10.10.0.0/16");
    assert_eq!(ranges[0].peer_group, "ix-members");
    assert_eq!(ranges[0].remote_asn, 65010);

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}
