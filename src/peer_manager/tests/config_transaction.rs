use super::*;

#[tokio::test]
async fn stale_live_snapshot_is_rejected_before_candidate_validation() {
    let config = load_test_config(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
"#,
    );
    let candidate = toml::to_string_pretty(&config).unwrap();
    let (_tx, rx) = mpsc::channel(4);
    let (_internal_tx, internal_rx) = mpsc::unbounded_channel();
    let (rib_tx, mut rib_rx) = mpsc::channel(4);
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
        config,
    );
    let responder = tokio::spawn(async move {
        let Some(RibUpdate::QueryUpdateGroupSnapshot { reply }) = rib_rx.recv().await else {
            panic!("first plan snapshot query missing");
        };
        reply
            .send(rustbgpd_rib::UpdateGroupSnapshot::default())
            .unwrap();
        let Some(RibUpdate::QueryUpdateGroupSnapshot { reply }) = rib_rx.recv().await else {
            panic!("apply re-plan snapshot query missing");
        };
        reply
            .send(rustbgpd_rib::UpdateGroupSnapshot {
                peers: vec![rustbgpd_rib::UpdateGroupPeerSnapshot {
                    peer: "192.0.2.1".parse().unwrap(),
                    input: rustbgpd_rib::UpdateGroupClassifierInput {
                        policy_fingerprint: None,
                        policy_provenance: None,
                        policy_requires_peer_context: false,
                        target_is_ebgp: false,
                        target_is_rr_client: true,
                        target_local_role: None,
                        interpret_rfc1997: true,
                        sendable_families: vec![(1, 1)],
                        llgr_families: vec![],
                        add_path_send: false,
                        per_client_best: false,
                        orr_vantage: None,
                        orf_installed: false,
                    },
                    classification: rustbgpd_rib::UpdateGroupClassification::Groupable(
                        rustbgpd_rib::UpdateGroupFingerprint {
                            policy_fingerprint: None,
                            target_is_ebgp: false,
                            target_is_rr_client: true,
                            target_local_role: None,
                            interpret_rfc1997: true,
                            sendable_ipv4_unicast: true,
                            sendable_ipv6_unicast: false,
                            sendable_vpnv4: false,
                            sendable_vpnv6: false,
                            rtc_negotiated: false,
                            per_client_best: false,
                            llgr_families: vec![],
                        },
                    ),
                    runtime_membership: "group:0".to_string(),
                }],
            })
            .unwrap();
    });
    let planned = mgr.plan_config_transaction(&candidate, None).await.unwrap();
    let error = mgr
        .plan_config_transaction(
            "this is not valid TOML =",
            Some(&planned.runtime_snapshot_token),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        rustbgpd_api::peer_types::RuntimeConfigTransactionPlanError::StaleSnapshot { .. }
    ));
    responder.await.unwrap();
}

#[tokio::test]
async fn candidate_neighbor_resolution_failure_is_invalid_candidate() {
    let config = load_test_config(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
"#,
    );
    let mut candidate = toml::to_string_pretty(&config).unwrap();
    candidate.push_str(
        r#"
[[neighbors]]
address = "fe80::2"
interface = "rustbgpd-interface-that-does-not-exist"
remote_asn = 65002
"#,
    );
    let (_tx, rx) = mpsc::channel(4);
    let (_internal_tx, internal_rx) = mpsc::unbounded_channel();
    let (rib_tx, mut rib_rx) = mpsc::channel(4);
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
        config,
    );
    let responder = tokio::spawn(async move {
        let Some(RibUpdate::QueryUpdateGroupSnapshot { reply }) = rib_rx.recv().await else {
            panic!("plan snapshot query missing");
        };
        reply
            .send(rustbgpd_rib::UpdateGroupSnapshot::default())
            .unwrap();
    });

    let error = mgr
        .plan_config_transaction(&candidate, None)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        rustbgpd_api::peer_types::RuntimeConfigTransactionPlanError::InvalidCandidate(_)
    ));
    responder.await.unwrap();
}

#[tokio::test]
async fn transaction_plan_rejects_full_snapshot_family_with_external_policy_inputs() {
    let dir = tempfile::tempdir().unwrap();
    let rpol_path = dir.path().join("edge.rpol");
    let dataset_path = dir.path().join("customers.list");
    std::fs::write(
        &rpol_path,
        r"
dataset asn-set customers

policy edge-in {
    term customer { if route.origin-as in customers { accept } }
    term rest { reject }
}
",
    )
    .unwrap();
    std::fs::write(&dataset_path, "64500\n").unwrap();
    let config = load_test_config(&format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[policy]
rpol_files = [{rpol_path:?}]

[policy.datasets.customers]
path = {dataset_path:?}

[[neighbors]]
address = "192.0.2.1"
remote_asn = 65002
description = "before"
import_policy_chain = ["edge-in"]
"#,
        rpol_path = rpol_path.display().to_string(),
        dataset_path = dataset_path.display().to_string()
    ));
    let live_dataset = std::sync::Arc::clone(
        config
            .policy
            .dataset_bindings
            .get("customers")
            .expect("live dataset binding"),
    );
    let live_status = live_dataset.status();
    std::fs::write(&dataset_path, "64500\n64999\n").unwrap();
    let mut candidate = config.clone();
    candidate.neighbors[0].description = Some("after".to_string());
    let candidate = toml::to_string_pretty(&candidate).unwrap();
    let (_tx, rx) = mpsc::channel(4);
    let (_internal_tx, internal_rx) = mpsc::unbounded_channel();
    let (rib_tx, mut rib_rx) = mpsc::channel(4);
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
        config,
    );
    let responder = tokio::spawn(async move {
        let Some(RibUpdate::QueryUpdateGroupSnapshot { reply }) = rib_rx.recv().await else {
            panic!("plan snapshot query missing");
        };
        reply
            .send(rustbgpd_rib::UpdateGroupSnapshot::default())
            .unwrap();
    });

    let plan = mgr.plan_config_transaction(&candidate, None).await.unwrap();

    assert_eq!(
        plan.status,
        rustbgpd_api::peer_types::RuntimeConfigTransactionStatus::Rejected
    );
    assert_eq!(plan.supported_sections, vec!["[[neighbors]] modify"]);
    assert_eq!(plan.unsupported_sections.len(), 1);
    assert!(plan.unsupported_sections[0].contains("external inputs"));
    assert_eq!(
        mgr.current_config.neighbors[0].description.as_deref(),
        Some("before")
    );
    assert_eq!(live_dataset.status(), live_status);
    assert_eq!(live_dataset.pin().data.records(), 1);
    responder.await.unwrap();
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "keeps the external dataset, real peer snapshot, and both planner verdicts in one load-bearing scenario"
)]
async fn independent_external_reparse_noop_and_pure_fib_have_zero_update_group_impact() {
    let dir = tempfile::tempdir().unwrap();
    let rpol_path = dir.path().join("catalog.rpol");
    let dataset_path = dir.path().join("customers.list");
    std::fs::write(
        &rpol_path,
        r"
dataset asn-set customers

policy dataset-export {
    term customer { if route.origin-as in customers { accept } }
    term rest { reject }
}
",
    )
    .unwrap();
    std::fs::write(&dataset_path, "64500\n").unwrap();
    let mut current = load_test_config(&format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[policy]
rpol_files = [{rpol_path:?}]

[policy.datasets.customers]
path = {dataset_path:?}

[[neighbors]]
address = "192.0.2.1"
remote_asn = 65002
export_policy_chain = ["dataset-export"]
"#,
        rpol_path = rpol_path.display().to_string(),
        dataset_path = dataset_path.display().to_string()
    ));
    current.fib_tables.push(crate::config::FibTableConfig {
        name: "edge".to_string(),
        table_id: 1000,
        metric: 200,
        families: vec!["ipv4_unicast".to_string()],
        allowed_peer_groups: Vec::new(),
        allowed_neighbors: Vec::new(),
        max_routes: None,
        maximum_paths: None,
        maximum_paths_ebgp: None,
        maximum_paths_ibgp: None,
    });
    let noop_candidate = toml::to_string_pretty(&current).unwrap();
    let mut fib_candidate = current.clone();
    fib_candidate.fib_tables[0].metric = 201;
    let fib_candidate = toml::to_string_pretty(&fib_candidate).unwrap();
    let resolved = current.resolved_neighbors().unwrap();
    let neighbor = &resolved[0];
    let policy = neighbor
        .export_policy
        .as_ref()
        .expect("export chain resolved");
    assert!(policy.references_dataset("customers"));
    let live_input = rustbgpd_rib::UpdateGroupClassifierInput {
        policy_fingerprint: Some(policy.groupability_fingerprint().to_string()),
        policy_provenance: Some(policy.groupability_provenance().to_string()),
        policy_requires_peer_context: policy.requires_peer_context(),
        target_is_ebgp: true,
        target_is_rr_client: neighbor.transport_config.route_reflector_client,
        target_local_role: neighbor
            .transport_config
            .peer
            .local_role
            .map(rustbgpd_wire::BgpRole::to_u8),
        sendable_families: vec![(1, 1)],
        llgr_families: Vec::new(),
        add_path_send: false,
        per_client_best: neighbor.transport_config.per_client_best,
        interpret_rfc1997: neighbor.transport_config.interpret_rfc1997,
        orr_vantage: neighbor.transport_config.orr_vantage,
        orf_installed: false,
    };
    let live_classification = rustbgpd_rib::classify_update_group(live_input.clone());
    let (tx, rx) = mpsc::channel(4);
    let (internal_tx, internal_rx) = mpsc::unbounded_channel();
    let (rib_tx, mut rib_rx) = mpsc::channel(4);
    let raw_prior = current.clone();
    let mut mgr = PeerManager::new_with_config(
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
        current,
    );
    let responder = tokio::spawn(async move {
        for _ in 0..5 {
            let Some(RibUpdate::QueryUpdateGroupSnapshot { reply }) = rib_rx.recv().await else {
                panic!("plan snapshot query missing");
            };
            reply
                .send(rustbgpd_rib::UpdateGroupSnapshot {
                    peers: vec![rustbgpd_rib::UpdateGroupPeerSnapshot {
                        peer: "192.0.2.1".parse().unwrap(),
                        input: live_input.clone(),
                        classification: live_classification.clone(),
                        runtime_membership: "group:0".to_string(),
                    }],
                })
                .unwrap();
        }
    });

    let noop = mgr
        .plan_config_transaction(&noop_candidate, None)
        .await
        .unwrap();
    let fib = mgr
        .plan_config_transaction(&fib_candidate, None)
        .await
        .unwrap();

    assert_eq!(
        noop.status,
        rustbgpd_api::peer_types::RuntimeConfigTransactionStatus::Noop
    );
    assert!(noop.supported_sections.is_empty());
    assert!(noop.unsupported_sections.is_empty());
    assert_eq!(noop.update_group_impact.entries.len(), 1);
    assert_eq!(noop.update_group_impact.entries[0].transition, "no_op");
    assert!(!noop.update_group_impact.entries[0].local_resync);
    assert_eq!(noop.update_group_impact.rollup.affected_peers, 0);
    assert_eq!(noop.update_group_impact.rollup.affected_families, 0);
    assert_eq!(noop.update_group_impact.rollup.local_resyncs, 0);
    assert_eq!(noop.update_group_impact.rollup.no_op, 1);
    assert!(noop.committed_candidate.is_none());
    assert_eq!(
        fib.status,
        rustbgpd_api::peer_types::RuntimeConfigTransactionStatus::Committable
    );
    assert_eq!(fib.supported_sections, vec!["[[fib_tables]]"]);
    assert!(fib.unsupported_sections.is_empty());
    assert_eq!(fib.update_group_impact.entries.len(), 1);
    assert_eq!(fib.update_group_impact.entries[0].transition, "no_op");
    assert!(!fib.update_group_impact.entries[0].local_resync);
    assert_eq!(fib.update_group_impact.rollup.affected_peers, 0);
    assert_eq!(fib.update_group_impact.rollup.affected_families, 0);
    assert_eq!(fib.update_group_impact.rollup.local_resyncs, 0);
    assert_eq!(fib.update_group_impact.rollup.no_op, 1);
    assert!(fib.diff.has_informational_changes);
    assert!(!fib.diff.has_restart_required_changes);
    assert!(
        fib.diff
            .human_text
            .contains("Informational transaction materialization")
    );
    let diff_json: serde_json::Value = serde_json::from_str(&fib.diff.diff_json).unwrap();
    assert_eq!(diff_json["has_informational_changes"], true);
    assert_eq!(
        diff_json["informational"]["rfc8212_materialization"]["route_behavior_changed"],
        false
    );
    let committed = fib
        .committed_candidate
        .as_ref()
        .expect("committable plan must retain one candidate")
        .as_str();
    assert!(committed.contains("config_epoch = 1"), "{committed}");
    assert!(
        committed.contains("ebgp_requires_policy = false"),
        "{committed}"
    );
    let chained = mgr.plan_config_transaction(committed, None).await.unwrap();
    assert_eq!(
        chained.post_commit_runtime_snapshot_token,
        fib.post_commit_runtime_snapshot_token
    );

    // After materialization, trusted rollback must carry the live tuple
    // without losing the accepted raw prior's FIB/source state.
    mgr.current_config.config_epoch = Some(crate::config::ConfigEpoch::V1);
    mgr.current_config.global.ebgp_requires_policy = Some(false);
    mgr.current_config.fib_tables[0].metric = 201;
    let mut rollback_prior = raw_prior.clone();
    let rollback = mgr
        .plan_preloaded_config_transaction(&mut rollback_prior, None)
        .await
        .unwrap();
    assert_eq!(
        rollback.status,
        rustbgpd_api::peer_types::RuntimeConfigTransactionStatus::Committable
    );
    assert_eq!(rollback.supported_sections, vec!["[[fib_tables]]"]);
    assert_eq!(
        rollback_prior.config_epoch,
        Some(crate::config::ConfigEpoch::V1)
    );
    assert_eq!(rollback_prior.global.ebgp_requires_policy, Some(false));
    assert_eq!(rollback_prior.fib_tables[0].metric, 200);
    assert_eq!(
        rollback_prior.policy.rpol_files,
        raw_prior.policy.rpol_files
    );
    assert_eq!(rollback_prior.policy.datasets, raw_prior.policy.datasets);
    mgr.current_config = raw_prior;

    // Capture one accepted candidate, then remove both external sources before
    // the real actor consumes the private command. Any planner reparse or
    // deferred handle read now fails; the captured Arc remains authoritative.
    let retained_path = dir.path().join("retained.toml");
    std::fs::write(&retained_path, &fib_candidate).unwrap();
    let accepted =
        Arc::new(crate::config::AcceptedConfigSnapshot::load(&retained_path, None).unwrap());
    std::fs::remove_file(&rpol_path).unwrap();
    std::fs::remove_file(&dataset_path).unwrap();
    let task = tokio::spawn(mgr.run());
    let (reply_tx, reply_rx) = oneshot::channel();
    internal_tx
        .send(InternalCommand::PlanAcceptedSnapshot {
            snapshot: accepted.clone(),
            expected_runtime_snapshot_token: None,
            reply: reply_tx,
        })
        .unwrap();
    let preloaded = reply_rx.await.unwrap().unwrap();
    assert_eq!(
        preloaded.status,
        rustbgpd_api::peer_types::RuntimeConfigTransactionStatus::Committable
    );
    assert_eq!(preloaded.supported_sections, vec!["[[fib_tables]]"]);
    assert_eq!(preloaded.update_group_impact.rollup.no_op, 1);
    assert!(preloaded.committed_candidate.is_some());
    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    task.await.unwrap();
    responder.await.unwrap();
}

#[tokio::test]
async fn transaction_fib_stage_overlays_only_tables_and_posture_and_restores_raw_prior() {
    let (tx, rx) = mpsc::channel(8);
    let (internal_tx, internal_rx) = mpsc::unbounded_channel();
    let (rib_tx, _rib_rx) = mpsc::channel(8);
    let mut live = make_dynamic_manager_config();
    live.policy.rpol_files = vec!["live-source.rpol".to_string()];
    live.fib_tables = vec![crate::test_support::basic_fib_table("edge", 1000)];
    let mut candidate = live.clone();
    candidate.global.asn = 64512;
    candidate.policy.rpol_files = vec!["candidate-source.rpol".to_string()];
    candidate.config_epoch = Some(crate::config::ConfigEpoch::V1);
    candidate.global.ebgp_requires_policy = Some(false);
    candidate.fib_tables[0].name = "core".to_string();
    candidate.fib_tables[0].table_id = 1001;

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
        live.clone(),
    );
    let handle = tokio::spawn(manager.run());
    let (stage_tx, stage_rx) = oneshot::channel();
    internal_tx
        .send(InternalCommand::StageTransactionConfig {
            candidate: Box::new(candidate),
            reply: stage_tx,
        })
        .unwrap();
    let previous = stage_rx.await.unwrap().unwrap();
    assert_eq!(previous.config_epoch, None);
    assert_eq!(previous.global.ebgp_requires_policy, None);
    assert_eq!(previous.fib_tables[0].name, "edge");

    let (snapshot_tx, snapshot_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::RuntimeConfigSnapshot { reply: snapshot_tx })
        .await
        .unwrap();
    let staged: Config = toml::from_str(&snapshot_rx.await.unwrap().unwrap().toml).unwrap();
    assert_eq!(staged.global.asn, live.global.asn);
    assert_eq!(staged.policy.rpol_files, live.policy.rpol_files);
    assert_eq!(staged.fib_tables[0].name, "core");
    assert_eq!(staged.config_epoch, Some(crate::config::ConfigEpoch::V1));
    assert_eq!(staged.global.ebgp_requires_policy, Some(false));

    let (restore_tx, restore_rx) = oneshot::channel();
    internal_tx
        .send(InternalCommand::RestoreTransactionConfig {
            previous,
            reply: restore_tx,
        })
        .unwrap();
    restore_rx.await.unwrap();
    let (snapshot_tx, snapshot_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::RuntimeConfigSnapshot { reply: snapshot_tx })
        .await
        .unwrap();
    let restored: Config = toml::from_str(&snapshot_rx.await.unwrap().unwrap().toml).unwrap();
    assert_eq!(restored.config_epoch, None);
    assert_eq!(restored.global.ebgp_requires_policy, None);
    assert_eq!(restored.fib_tables[0].name, "edge");
    assert_eq!(restored.policy.rpol_files, live.policy.rpol_files);
    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn stage_config_snapshot_rebuilds_matcher_and_returns_previous_toml() {
    let (tx, rx) = mpsc::channel(16);
    let (_internal_tx, internal_rx) = mpsc::unbounded_channel();
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let config = make_dynamic_manager_config();
    let mut replacement = config.clone();
    replacement.dynamic_neighbors = vec![crate::config::DynamicNeighborConfig {
        prefix: "10.20.0.0/16".to_string(),
        peer_group: "ix-members".to_string(),
        remote_asn: 65020,
        description: Some("transaction range".to_string()),
        tcp_ao: None,
    }];
    let candidate_toml = toml::to_string_pretty(&replacement).unwrap();

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

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::StageConfigSnapshot {
        candidate_toml,
        reply: reply_tx,
    })
    .await
    .unwrap();
    let previous_toml = reply_rx.await.unwrap().unwrap();
    assert!(!previous_toml.contains("config_epoch"), "{previous_toml}");
    assert!(
        !previous_toml.contains("ebgp_requires_policy"),
        "{previous_toml}"
    );
    let previous = Config::load_toml_with_diagnostics(&previous_toml, "previous snapshot").unwrap();
    assert_eq!(previous.dynamic_neighbors[0].prefix, "127.0.0.0/8");

    let (list_tx, list_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::ListDynamicRanges { reply: list_tx })
        .await
        .unwrap();
    let ranges = list_rx.await.unwrap();
    assert_eq!(ranges.len(), 1);
    assert_eq!(ranges[0].prefix, "10.20.0.0/16");
    assert_eq!(ranges[0].peer_group, "ix-members");
    assert_eq!(ranges[0].remote_asn, 65020);

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "transaction fence test covers both reject and restore paths"
)]
async fn staged_snapshot_fences_dynamic_accept_and_restore_reaps_candidate_dynamic_peer() {
    let (tx, rx) = mpsc::channel(16);
    let (_internal_tx, internal_rx) = mpsc::unbounded_channel();
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let mut initial = make_dynamic_manager_config();
    initial.dynamic_neighbors.clear();

    let mut candidate = initial.clone();
    candidate.dynamic_neighbors = vec![crate::config::DynamicNeighborConfig {
        prefix: "127.0.0.0/8".to_string(),
        peer_group: "ix-members".to_string(),
        remote_asn: 0,
        description: Some("candidate-only".to_string()),
        tcp_ao: None,
    }];
    let candidate_toml = toml::to_string_pretty(&candidate).unwrap();

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
        initial,
    );
    let handle = tokio::spawn(manager.run());

    let (stage_tx, stage_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::StageConfigSnapshot {
        candidate_toml,
        reply: stage_tx,
    })
    .await
    .unwrap();
    let previous_toml = stage_rx.await.unwrap().unwrap();

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server_stream, remote_addr) = listener.accept().await.unwrap();
    let client_stream = client.await.unwrap();
    tx.send(PeerManagerCommand::AcceptInbound {
        stream: server_stream,
        peer_addr: remote_addr,
        tcp_ao_info: None,
        tcp_ao_generation: None,
    })
    .await
    .unwrap();

    let (list_tx, list_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::ListPeers { reply: list_tx })
        .await
        .unwrap();
    assert!(
        list_rx.await.unwrap().is_empty(),
        "dynamic inbound must not be accepted while a config snapshot is staged but uncommitted"
    );

    let (commit_tx, commit_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::CommitConfigSnapshotStage { reply: commit_tx })
        .await
        .unwrap();
    commit_rx.await.unwrap();

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let client = tokio::spawn(async move { TcpStream::connect(listener_addr).await.unwrap() });
    let (server_stream, remote_addr) = listener.accept().await.unwrap();
    let client_stream2 = client.await.unwrap();
    tx.send(PeerManagerCommand::AcceptInbound {
        stream: server_stream,
        peer_addr: remote_addr,
        tcp_ao_info: None,
        tcp_ao_generation: None,
    })
    .await
    .unwrap();

    let (list_tx, list_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::ListPeers { reply: list_tx })
        .await
        .unwrap();
    assert_eq!(
        list_rx.await.unwrap().len(),
        1,
        "dynamic inbound should be accepted once the staged snapshot is committed"
    );

    let (restore_tx, restore_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::RestoreConfigSnapshot {
        candidate_toml: previous_toml,
        reply: restore_tx,
    })
    .await
    .unwrap();
    restore_rx.await.unwrap().unwrap();

    let (list_tx, list_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::ListPeers { reply: list_tx })
        .await
        .unwrap();
    assert!(
        list_rx.await.unwrap().is_empty(),
        "rollback must reap dynamic peers accepted by ranges absent from the restored snapshot"
    );

    drop(client_stream);
    drop(client_stream2);
    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn runtime_config_snapshot_returns_current_staged_config() {
    let (tx, rx) = mpsc::channel(16);
    let (_internal_tx, internal_rx) = mpsc::unbounded_channel();
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let config = make_dynamic_manager_config();
    let mut replacement = config.clone();
    replacement.dynamic_neighbors = vec![crate::config::DynamicNeighborConfig {
        prefix: "10.30.0.0/16".to_string(),
        peer_group: "ix-members".to_string(),
        remote_asn: 65030,
        description: Some("transaction range".to_string()),
        tcp_ao: None,
    }];
    let candidate_toml = toml::to_string_pretty(&replacement).unwrap();

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

    let (stage_tx, stage_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::StageConfigSnapshot {
        candidate_toml,
        reply: stage_tx,
    })
    .await
    .unwrap();
    stage_rx.await.unwrap().unwrap();

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::RuntimeConfigSnapshot { reply: reply_tx })
        .await
        .unwrap();
    let snapshot_toml = reply_rx.await.unwrap().unwrap();
    assert!(!snapshot_toml.toml.contains("config_epoch"));
    assert!(!snapshot_toml.toml.contains("ebgp_requires_policy"));
    let snapshot =
        Config::load_toml_with_diagnostics(&snapshot_toml.toml, "runtime snapshot").unwrap();
    assert_eq!(snapshot.config_epoch, None);
    assert_eq!(snapshot.global.ebgp_requires_policy, None);
    assert_eq!(snapshot.dynamic_neighbors.len(), 1);
    assert_eq!(snapshot.dynamic_neighbors[0].prefix, "10.30.0.0/16");
    assert_eq!(snapshot.dynamic_neighbors[0].remote_asn, 65030);

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[test]
fn runtime_config_diff_compares_candidate_against_live_snapshot_and_redacts_secret() {
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
    let current = load_test_config(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
md5_password = "old-secret"
"#,
    );
    let mgr = PeerManager::new_with_config(
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
        current,
    );

    let candidate = tier_authorized_uds_test_config(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
md5_password = "new-secret"
"#,
    );
    let diff = mgr.diff_runtime_config(&candidate).unwrap();

    assert!(diff.has_reload_applied_changes);
    assert!(diff.has_actionable_changes);
    assert!(diff.human_text.contains("md5_password: <changed>"));
    assert!(!diff.human_text.contains("old-secret"));
    assert!(!diff.human_text.contains("new-secret"));
    assert!(diff.diff_json.contains("\"field\": \"md5_password\""));
    assert!(!diff.diff_json.contains("old-secret"));
    assert!(!diff.diff_json.contains("new-secret"));
}
