use super::*;

fn edge_group_definition(hold_time: Option<u16>) -> rustbgpd_api::peer_types::PeerGroupDefinition {
    rustbgpd_api::peer_types::PeerGroupDefinition {
        min_hold_time: None,
        hold_time,
        send_hold_time: None,
        max_prefixes: None,
        max_prefix_restart_seconds: None,
        md5_password: None,
        ttl_security: None,
        families: Vec::new(),
        required_families: Vec::new(),
        graceful_restart: None,
        gr_restart_time: None,
        gr_peer_restart_time_max: None,
        gr_stale_routes_time: None,
        llgr_stale_time: None,
        local_ipv6_nexthop: None,
        route_reflector_client: None,
        orr_vantage: None,
        route_server_client: None,
        per_client_best: None,
        remove_private_as: None,
        add_path: None,
        import_policy: Vec::new(),
        export_policy: Vec::new(),
        import_policy_chain: Vec::new(),
        export_policy_chain: Vec::new(),
    }
}

fn set_edge_hold_time_event(hold_time: u16) -> rustbgpd_api::peer_types::ConfigEvent {
    rustbgpd_api::peer_types::ConfigEvent::SetPeerGroup {
        name: "edge".to_string(),
        definition: edge_group_definition(Some(hold_time)),
        ack: None,
    }
}

fn peer_group_reshape_manager(config: Config) -> PeerManager {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, rib_rx) = mpsc::channel::<RibUpdate>(64);
    // Leak the RIB receiver so session sends during delete/re-add never fail.
    Box::leak(Box::new(rib_rx));
    PeerManager::new_with_config(
        rx,
        mpsc::unbounded_channel().1,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
        None,
        config,
    )
}

#[tokio::test]
async fn targeted_required_family_edit_revalidates_dynamic_consumers() {
    // Load-bearing: skipping whole-config validation in SetPeerGroup commits
    // IPv6 as required even though the existing IPv4 dynamic range defaults
    // to IPv4 only. The static IPv6 member proves the group is referenced by
    // both consumer shapes without itself making the edit invalid.
    let config = load_test_config(&format!(
        "{}\n[[dynamic_neighbors]]\nprefix = \"192.0.2.0/24\"\npeer_group = \"edge\"\n",
        EDGE_GROUP_TOML
            .replace("10.0.0.2", "2001:db8::2")
            .replace("10.0.0.3", "2001:db8::3")
            .replace("10.0.0.4", "2001:db8::4")
    ));
    let prior = config.clone();
    let mut mgr = peer_group_reshape_manager(config);
    let mut definition = edge_group_definition(Some(90));
    definition.required_families = vec!["ipv6_unicast".to_string()];
    let err = mgr
        .apply_peer_group_change(
            rustbgpd_api::peer_types::ConfigEvent::SetPeerGroup {
                name: "edge".to_string(),
                definition,
                ack: None,
            },
            vec!["2001:db8::2".parse().unwrap()],
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("required family"), "{err}");
    assert_eq!(mgr.current_config, prior);
}

const EDGE_GROUP_TOML: &str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.edge]
hold_time = 90

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "edge"

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "edge"

[[neighbors]]
address = "10.0.0.4"
remote_asn = 65004
peer_group = "edge"
"#;

#[tokio::test]
async fn peer_group_reshape_noop_update_does_not_bounce_or_publish() {
    let config = load_test_config(EDGE_GROUP_TOML);
    let mut mgr = peer_group_reshape_manager(config.clone());
    for resolved in config.resolved_neighbors().unwrap() {
        mgr.add_peer(
            PeerManager::peer_manager_config_from_resolved(resolved, false),
            false,
        )
        .await
        .unwrap();
    }
    let addresses = [
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)),
    ];
    let before: Vec<_> = addresses
        .iter()
        .map(|addr| {
            (
                *addr,
                mgr.peers.get(&key(*addr)).expect("managed peer").session_id,
            )
        })
        .collect();
    let config_before = mgr.current_config.clone();

    mgr.apply_peer_group_change(set_edge_hold_time_event(90), addresses.to_vec())
        .await
        .unwrap();

    for (addr, session_id) in before {
        let managed = mgr.peers.get(&key(addr)).expect("managed peer");
        assert_eq!(
            managed.session_id, session_id,
            "no-op peer-group set must not rebuild {addr}"
        );
        assert_eq!(managed.hold_time, Some(90));
    }
    assert_eq!(
        mgr.current_config
            .peer_groups
            .get("edge")
            .expect("group definition")
            .hold_time,
        Some(90),
        "no-op update must leave current_config unchanged"
    );
    assert_eq!(
        mgr.current_config, config_before,
        "no-op update must leave the full resolved config structurally unchanged"
    );
    assert!(
        query_policy_event_history(&mgr, None, 8).await.is_empty(),
        "no-op update must not publish a catalog policy event"
    );
}

/// ADR-0081 success path: a targeted `SetPeerGroup` reshapes every static
/// member through the captured-prior snapshot primitive, advances
/// `current_config`, and publishes the applied member count.
#[tokio::test]
async fn peer_group_reshape_applies_to_all_members_and_advances_config() {
    let config = load_test_config(EDGE_GROUP_TOML);
    let mut mgr = peer_group_reshape_manager(config.clone());
    for resolved in config.resolved_neighbors().unwrap() {
        mgr.add_peer(
            PeerManager::peer_manager_config_from_resolved(resolved, false),
            false,
        )
        .await
        .unwrap();
    }
    let a1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let a2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let a3 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    let before: Vec<_> = [a1, a2, a3]
        .into_iter()
        .map(|addr| {
            (
                addr,
                mgr.peers.get(&key(addr)).expect("managed peer").session_id,
            )
        })
        .collect();

    mgr.apply_peer_group_change(set_edge_hold_time_event(45), vec![a1, a2, a3])
        .await
        .unwrap();

    for (addr, session_id) in before {
        let managed = mgr.peers.get(&key(addr)).expect("reshaped member");
        assert_eq!(managed.hold_time, Some(45));
        assert_ne!(
            managed.session_id, session_id,
            "real peer-group reshape must rebuild {addr}"
        );
    }
    assert_eq!(
        mgr.current_config
            .peer_groups
            .get("edge")
            .expect("group definition")
            .hold_time,
        Some(45),
        "successful reshape must advance current_config"
    );
    let events = query_policy_event_history(&mgr, None, 8).await;
    let event = events
        .iter()
        .find(|event| event.target_type == "peer_group")
        .expect("peer-group policy event");
    assert_eq!(event.affected_peer_count, 3);
}

/// ADR-0081: a mid-fanout reconfigure failure on the targeted peer-group
/// path restores already-reshaped members from their captured priors, never
/// reaches later members, leaves the failing member in place, and does not
/// advance `current_config`.
///
/// Every config-shaped failure is rejected before any peer is touched
/// (event validation, phase-1 resolution, the primitive's preflight), so
/// the surviving mid-fanout failure class is a transient runtime fault —
/// induced here with the manager's test-only reconfigure injection.
#[tokio::test]
async fn peer_group_reshape_mid_fanout_failure_restores_prior_members() {
    let config = load_test_config(EDGE_GROUP_TOML);
    let mut mgr = peer_group_reshape_manager(config.clone());
    for resolved in config.resolved_neighbors().unwrap() {
        mgr.add_peer(
            PeerManager::peer_manager_config_from_resolved(resolved, false),
            false,
        )
        .await
        .unwrap();
    }
    let a1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let a2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)); // its reconfigure fails
    let a3 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    mgr.inject_reconfigure_failures.insert(key(a2), 0);

    let result = mgr
        .apply_peer_group_change(
            set_edge_hold_time_event(45),
            // Explicit order so member 1 is reshaped before member 2 fails.
            vec![a1, a2, a3],
        )
        .await;
    let Err(error) = result else {
        panic!("mid-fanout reconfigure failure must surface as Err");
    };
    assert!(
        matches!(error, CatalogMutationError::Internal(_)),
        "{error:?}"
    );
    let message = error.to_string();
    assert!(message.contains("prior peers restored"), "{message}");
    assert!(message.contains("10.0.0.3"), "{message}");

    assert_eq!(
        mgr.peers
            .get(&key(a1))
            .expect("restored member 1")
            .hold_time,
        Some(90),
        "member reshaped before the failure must be back on its prior config"
    );
    assert_eq!(
        mgr.peers.get(&key(a2)).expect("failing member").hold_time,
        Some(90),
        "the failing member must still exist on its prior config, not be left deleted"
    );
    assert_eq!(
        mgr.peers
            .get(&key(a3))
            .expect("untouched member 3")
            .hold_time,
        Some(90),
        "member after the failure must never be touched"
    );
    assert_eq!(
        mgr.current_config
            .peer_groups
            .get("edge")
            .expect("group definition")
            .hold_time,
        Some(90),
        "failed reshape must not advance current_config"
    );
}

/// ADR-0081: rollback of the captured priors is best-effort — a failed
/// restore must not short-circuit the reverse sweep, so every earlier
/// member is still attempted, and the compound error names exactly which
/// members were left in the reshaped state (members it does not name were
/// restored).
#[tokio::test]
async fn peer_group_reshape_rollback_failure_still_restores_other_priors() {
    let config = load_test_config(EDGE_GROUP_TOML);
    let mut mgr = peer_group_reshape_manager(config.clone());
    for resolved in config.resolved_neighbors().unwrap() {
        mgr.add_peer(
            PeerManager::peer_manager_config_from_resolved(resolved, false),
            false,
        )
        .await
        .unwrap();
    }
    let a1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let a2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)); // its rollback fails
    let a3 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)); // its apply fails
    // a3 fails on its first reconfigure (the apply), triggering rollback of
    // the captured priors [a1, a2] in reverse order; a2's first reconfigure
    // (the apply) succeeds and its second (the rollback) fails.
    mgr.inject_reconfigure_failures.insert(key(a3), 0);
    mgr.inject_reconfigure_failures.insert(key(a2), 1);

    let result = mgr
        .apply_peer_group_change(
            set_edge_hold_time_event(45),
            // Explicit order so members 1 and 2 are reshaped before member 3
            // fails.
            vec![a1, a2, a3],
        )
        .await;
    let Err(error) = result else {
        panic!("apply failure with a partial rollback failure must surface as Err");
    };
    assert!(
        matches!(error, CatalogMutationError::Internal(_)),
        "{error:?}"
    );
    let message = error.to_string();
    assert!(
        message.contains("10.0.0.4"),
        "compound error must carry the original apply failure: {message}"
    );
    assert!(
        message.contains("10.0.0.3"),
        "compound error must name the member left reshaped: {message}"
    );
    assert!(
        !message.contains("10.0.0.2"),
        "compound error must not claim the restored member failed: {message}"
    );

    assert_eq!(
        mgr.peers
            .get(&key(a1))
            .expect("restored member 1")
            .hold_time,
        Some(90),
        "member 1's rollback must still be attempted after member 2's fails"
    );
    assert_eq!(
        mgr.peers
            .get(&key(a2))
            .expect("rollback-failed member 2")
            .hold_time,
        Some(45),
        "member 2 stays in the reshaped state its failed rollback left it in"
    );
    assert_eq!(
        mgr.peers
            .get(&key(a3))
            .expect("apply-failed member 3")
            .hold_time,
        Some(90),
        "member 3's apply failed up front, leaving its prior config in place"
    );
    assert_eq!(
        mgr.current_config
            .peer_groups
            .get("edge")
            .expect("group definition")
            .hold_time,
        Some(90),
        "failed reshape must not advance current_config"
    );
}

/// ADR-0081 decision 2: a member whose resolved next config changes TCP-AO
/// is rejected by the primitive's preflight with `RestartRequired` BEFORE
/// any session is bounced — no delete/re-add, no partial apply.
#[tokio::test]
async fn peer_group_reshape_rejects_tcp_ao_delta_before_any_bounce() {
    let config = load_test_config(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.edge]
hold_time = 90

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "edge"
tcp_ao = { key = "secret", send_id = 7, recv_id = 9, algorithm = "hmac(sha256)" }
"#,
    );
    let mut mgr = peer_group_reshape_manager(config);
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let counters = Arc::new(FakePeerCounters::default());
    // The running peer carries NO TCP-AO key, so the resolved next config
    // (tcp_ao set) is a restart-required delta.
    insert_test_managed_peer(
        &mut mgr,
        addr,
        fake_peer_handle(addr, SessionState::Idle, None, counters.clone()),
        false,
    );

    let Err(error) = mgr
        .apply_peer_group_change(set_edge_hold_time_event(45), vec![addr])
        .await
    else {
        panic!("TCP-AO delta must be rejected up front");
    };
    assert!(
        matches!(error, CatalogMutationError::RestartRequired(_)),
        "{error:?}"
    );
    assert!(error.to_string().contains("changes tcp_ao"), "{error}");

    assert_eq!(
        counters.shutdown.load(Ordering::SeqCst),
        0,
        "preflight rejection must not bounce any session"
    );
    let managed = mgr.peers.get(&key(addr)).expect("untouched peer");
    assert_eq!(managed.hold_time, Some(90));
    assert_eq!(managed.session_id, 1, "peer generation unchanged");
    assert_eq!(
        mgr.current_config
            .peer_groups
            .get("edge")
            .expect("group definition")
            .hold_time,
        Some(90)
    );
}

/// ADR-0081 decision 3: rollback re-reads live admin state, so a member
/// that was admin-disabled before the failed fan-out is still disabled
/// after its prior config is restored.
#[tokio::test]
async fn peer_group_reshape_rollback_preserves_admin_disabled_state() {
    let config = load_test_config(EDGE_GROUP_TOML);
    let mut mgr = peer_group_reshape_manager(config.clone());
    for resolved in config.resolved_neighbors().unwrap() {
        mgr.add_peer(
            PeerManager::peer_manager_config_from_resolved(resolved, false),
            false,
        )
        .await
        .unwrap();
    }
    let a1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let a2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    mgr.disable_peer(key(a1), None).await.unwrap();
    // Member 2 fails after member 1 was reshaped, forcing member 1's
    // rollback while it is admin-disabled.
    mgr.inject_reconfigure_failures.insert(key(a2), 0);

    let result = mgr
        .apply_peer_group_change(set_edge_hold_time_event(45), vec![a1, a2])
        .await;
    assert!(result.is_err(), "{result:?}");

    let managed = mgr.peers.get(&key(a1)).expect("restored member");
    assert_eq!(managed.hold_time, Some(90));
    assert!(
        !managed.enabled,
        "rollback must preserve the member's admin-disabled state"
    );
}

/// ADR-0081 decision 4: a dynamic peer at an affected address is never
/// bounced by a targeted peer-group reshape — its running session keeps its
/// config until it reconnects. The definition edit itself still commits.
#[tokio::test]
async fn peer_group_reshape_skips_dynamic_peers_without_bouncing() {
    let config = load_test_config(EDGE_GROUP_TOML);
    let mut mgr = peer_group_reshape_manager(config);
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let counters = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer(
        &mut mgr,
        addr,
        fake_peer_handle(addr, SessionState::Established, None, counters.clone()),
        false,
    );
    mgr.peers.get_mut(&key(addr)).unwrap().is_dynamic = true;

    mgr.apply_peer_group_change(set_edge_hold_time_event(45), vec![addr])
        .await
        .unwrap();

    assert_eq!(
        counters.shutdown.load(Ordering::SeqCst),
        0,
        "dynamic peer must not be bounced by a peer-group reshape"
    );
    let managed = mgr.peers.get(&key(addr)).expect("dynamic peer");
    assert!(managed.is_dynamic);
    assert_eq!(managed.hold_time, Some(90), "running config unchanged");
    assert_eq!(
        mgr.current_config
            .peer_groups
            .get("edge")
            .expect("group definition")
            .hold_time,
        Some(45),
        "the definition edit itself still commits"
    );
}

// ── peer-group edits partitioned by `ConfigFieldImpact` ───────────────

fn edge_group_max_prefixes_event(
    hold_time: u16,
    max_prefixes: u32,
) -> rustbgpd_api::peer_types::ConfigEvent {
    let mut definition = edge_group_definition(Some(hold_time));
    definition.max_prefixes = Some(max_prefixes);
    rustbgpd_api::peer_types::ConfigEvent::SetPeerGroup {
        name: "edge".to_string(),
        definition,
        ack: None,
    }
}

async fn edge_group_manager_with_members() -> PeerManager {
    let config = load_test_config(EDGE_GROUP_TOML);
    let mut mgr = peer_group_reshape_manager(config.clone());
    for resolved in config.resolved_neighbors().unwrap() {
        mgr.add_peer(
            PeerManager::peer_manager_config_from_resolved(resolved, false),
            false,
        )
        .await
        .unwrap();
    }
    mgr
}

/// Load-bearing: a peer-group edit whose every changed field is
/// reload-matrix `live` must apply to the inheriting members in place.
/// Both halves fail without the impact partition — before it,
/// `apply_peer_group_change` reshaped for *any* group change, so every
/// member's session id changed (a `peer deleted` + re-add on the wire)
/// even though the identical neighbor-level edit hot-applies.
#[tokio::test]
async fn peer_group_hot_field_edit_applies_in_place_without_session_reset() {
    let mut mgr = edge_group_manager_with_members().await;
    let addresses = [
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)),
    ];
    let before: Vec<_> = addresses
        .iter()
        .map(|addr| {
            let managed = mgr.peers.get(&key(*addr)).expect("managed peer");
            assert_eq!(managed.transport_config.max_prefixes, None);
            (*addr, managed.session_id)
        })
        .collect();

    mgr.apply_peer_group_change(edge_group_max_prefixes_event(90, 5_000), addresses.to_vec())
        .await
        .unwrap();

    for (addr, session_id) in before {
        let managed = mgr.peers.get(&key(addr)).expect("hot-applied member");
        assert_eq!(
            managed.session_id, session_id,
            "a pure-hot peer-group edit must not tear down {addr}'s session"
        );
        // Skipping the reshape is only correct if the member's *effective*
        // state actually moved; a path that updated the stored group
        // definition alone would leave both of these stale.
        assert_eq!(
            managed.max_prefixes,
            Some(5_000),
            "{addr} must inherit the new group maximum"
        );
        assert_eq!(managed.transport_config.max_prefixes, Some(5_000));
    }
    assert_eq!(
        mgr.current_config
            .peer_groups
            .get("edge")
            .expect("group definition")
            .max_prefixes,
        Some(5_000)
    );
}

/// The other half of the partition: a change set that mixes a hot field
/// with a session-reset one keeps the ADR-0081 reshape path, because the
/// session-reset field can only take effect on a renegotiated session.
#[tokio::test]
async fn peer_group_mixed_impact_edit_still_reshapes_members() {
    let mut mgr = edge_group_manager_with_members().await;
    let addresses = [
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
    ];
    let before: Vec<_> = addresses
        .iter()
        .map(|addr| (*addr, mgr.peers.get(&key(*addr)).expect("peer").session_id))
        .collect();

    // `hold_time` is OPEN-negotiated (session reset) and `max_prefixes` is
    // hot; a mixed set must not take the in-place path.
    mgr.apply_peer_group_change(edge_group_max_prefixes_event(45, 5_000), addresses.to_vec())
        .await
        .unwrap();

    for (addr, session_id) in before {
        let managed = mgr.peers.get(&key(addr)).expect("reshaped member");
        assert_ne!(
            managed.session_id, session_id,
            "a mixed-impact peer-group edit must still reshape {addr}"
        );
        assert_eq!(managed.hold_time, Some(45));
        assert_eq!(managed.max_prefixes, Some(5_000));
    }
}

/// ADR-0081 for the in-place path: a mid-cohort failure restores the
/// members applied before it from their captured live priors, and
/// `current_config` — so also the stored group definition — never
/// advances.
#[tokio::test]
async fn peer_group_hot_apply_mid_cohort_failure_restores_prior_members() {
    let mut mgr = edge_group_manager_with_members().await;
    let a1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let a2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)); // its hot apply fails
    let a3 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
    mgr.inject_hot_update_failures.insert(key(a2), 0);
    let sessions: Vec<_> = [a1, a2, a3]
        .into_iter()
        .map(|addr| (addr, mgr.peers.get(&key(addr)).expect("peer").session_id))
        .collect();

    let Err(error) = mgr
        .apply_peer_group_change(edge_group_max_prefixes_event(90, 5_000), vec![a1, a2, a3])
        .await
    else {
        panic!("mid-cohort hot-apply failure must surface as Err");
    };
    assert!(
        matches!(error, CatalogMutationError::Internal(_)),
        "{error:?}"
    );
    let message = error.to_string();
    assert!(message.contains("prior peers restored"), "{message}");
    assert!(message.contains("10.0.0.3"), "{message}");

    for (addr, session_id) in sessions {
        let managed = mgr.peers.get(&key(addr)).expect("member");
        assert_eq!(
            managed.max_prefixes, None,
            "{addr} must be back on (or never moved off) its prior value"
        );
        assert_eq!(managed.transport_config.max_prefixes, None);
        assert_eq!(
            managed.session_id, session_id,
            "rollback of an in-place apply must not bounce {addr} either"
        );
    }
    assert!(
        mgr.current_config
            .peer_groups
            .get("edge")
            .expect("group definition")
            .max_prefixes
            .is_none(),
        "a failed hot apply must leave the group definition unchanged"
    );
}

/// Dynamic inheritors are part of the hot cohort: ADR-0081 decision 4
/// defers *reshaping* an accepted dynamic peer, but a hot knob swap needs
/// no reconnect, so the new inherited value reaches the live session
/// without a bounce.
#[tokio::test]
async fn peer_group_hot_field_edit_reaches_live_dynamic_members() {
    let mut mgr = dynamic_test_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 91));
    let (handle, mut applied_caps) = recording_runtime_config_handle();
    insert_test_dynamic_managed_peer(
        &mut mgr,
        addr,
        91,
        handle,
        true,
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
        8,
        "ix-members",
    );
    let session_id = mgr.peers[&key(addr)].session_id;
    let cap_before = mgr.peers[&key(addr)]
        .transport_config
        .gr_peer_restart_time_max;
    assert_ne!(cap_before, 1_800);

    let mut definition = crate::policy_admin::config_peer_group_to_api(
        &mgr.current_config.peer_groups["ix-members"],
    );
    definition.gr_peer_restart_time_max = Some(1_800);
    mgr.apply_peer_group_change(
        rustbgpd_api::peer_types::ConfigEvent::SetPeerGroup {
            name: "ix-members".to_string(),
            definition,
            ack: None,
        },
        Vec::new(),
    )
    .await
    .unwrap();

    assert_eq!(
        applied_caps.try_recv(),
        Ok(1_800),
        "the live dynamic session must receive the new inherited cap"
    );
    let managed = &mgr.peers[&key(addr)];
    assert_eq!(managed.transport_config.gr_peer_restart_time_max, 1_800);
    assert_eq!(
        managed.session_id, session_id,
        "a hot peer-group edit must not bounce the dynamic member"
    );
    assert!(managed.is_dynamic);
}

#[tokio::test]
async fn required_family_group_reconcile_waits_for_dynamic_reconnect() {
    // Load-bearing: this shared SIGHUP/targeted-group reconcile primitive must
    // not reconfigure an accepted dynamic peer in place, while the committed
    // group must advance what its next connection resolves.
    let config = load_test_config(EDGE_GROUP_TOML);
    let mut mgr = peer_group_reshape_manager(config);
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let counters = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer(
        &mut mgr,
        addr,
        fake_peer_handle(addr, SessionState::Established, None, counters.clone()),
        false,
    );
    mgr.peers.get_mut(&key(addr)).unwrap().is_dynamic = true;
    assert!(
        mgr.peers[&key(addr)]
            .transport_config
            .peer
            .required_families
            .is_empty()
    );

    let mut definition =
        crate::policy_admin::config_peer_group_to_api(&mgr.current_config.peer_groups["edge"]);
    definition.required_families = vec!["ipv4_unicast".to_string()];
    mgr.apply_peer_group_change(
        rustbgpd_api::peer_types::ConfigEvent::SetPeerGroup {
            name: "edge".to_string(),
            definition,
            ack: None,
        },
        vec![addr],
    )
    .await
    .unwrap();

    assert_eq!(counters.shutdown.load(Ordering::SeqCst), 0);
    assert!(
        mgr.peers[&key(addr)]
            .transport_config
            .peer
            .required_families
            .is_empty(),
        "accepted dynamic session must retain its running OPEN contract"
    );
    let reconnect = mgr
        .current_config
        .resolve_dynamic_neighbor(
            addr,
            65002,
            "reconnect",
            &mgr.current_config.peer_groups["edge"],
            "edge",
            false,
        )
        .unwrap();
    assert_eq!(
        reconnect.transport_config.peer.required_families,
        vec![(Afi::Ipv4, Safi::Unicast)]
    );
}

/// Regression for the old per-member loop's `None` arm, which DELETED a
/// managed static peer whose neighbor record could not be found in the next
/// config. Peer-group events never remove records, so that state is a
/// snapshot/managed-peer inconsistency: refuse with zero peers touched.
#[tokio::test]
async fn peer_group_reshape_rejects_member_missing_from_next_config() {
    let config = load_test_config(EDGE_GROUP_TOML);
    let mut mgr = peer_group_reshape_manager(config);
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let counters = Arc::new(FakePeerCounters::default());
    // Managed under a scoped key, so the interface-qualified record lookup
    // finds no `[[neighbors]]` entry for it.
    insert_test_scoped_managed_peer(
        &mut mgr,
        addr,
        "rustbgpd-test-missing0",
        7,
        42,
        fake_peer_handle(addr, SessionState::Idle, None, counters.clone()),
    );

    let Err(error) = mgr
        .apply_peer_group_change(set_edge_hold_time_event(45), vec![addr])
        .await
    else {
        panic!("member missing from next_config must be rejected");
    };
    assert!(
        matches!(error, CatalogMutationError::Internal(_)),
        "{error:?}"
    );
    assert!(error.to_string().contains("no neighbor record"), "{error}");

    assert!(
        mgr.peers
            .contains_key(&scoped_key(addr, "rustbgpd-test-missing0")),
        "the member must NOT be deleted (the old loop's None arm did)"
    );
    assert_eq!(counters.shutdown.load(Ordering::SeqCst), 0);
    assert_eq!(
        mgr.current_config
            .peer_groups
            .get("edge")
            .expect("group definition")
            .hold_time,
        Some(90),
        "rejected reshape must not advance current_config"
    );
}
