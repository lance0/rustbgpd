use super::*;

async fn subscribe_policy_events(
    tx: &mpsc::Sender<PeerManagerCommand>,
) -> broadcast::Receiver<PolicyEvent> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::SubscribePolicyEvents { reply: reply_tx })
        .await
        .unwrap();
    reply_rx.await.unwrap()
}

fn validation_import_refresh_metric(mgr: &PeerManager, dependency: &str, outcome: &str) -> f64 {
    mgr.metrics
        .registry()
        .gather()
        .iter()
        .find(|family| family.name() == "bgp_validation_import_refreshes_total")
        .and_then(|family| {
            family.metric.iter().find(|metric| {
                let label_value = |name| {
                    metric
                        .get_label()
                        .iter()
                        .find(|label| label.name() == name)
                        .map(prometheus::proto::LabelPair::value)
                };
                label_value("dependency") == Some(dependency)
                    && label_value("outcome") == Some(outcome)
            })
        })
        .map_or(0.0, |metric| metric.get_counter().value())
}

fn assert_validation_import_refresh_metric(
    mgr: &PeerManager,
    dependency: &str,
    outcome: &str,
    expected: f64,
) {
    let actual = validation_import_refresh_metric(mgr, dependency, outcome);
    assert!(
        (actual - expected).abs() < f64::EPSILON,
        "metric dependency={dependency} outcome={outcome}: got {actual}, expected {expected}"
    );
}

#[tokio::test]
async fn policy_events_publish_successful_policy_mutations() {
    use rustbgpd_api::peer_types::{NamedPolicyDefinition, PolicyStatementDefinition};

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
    let mut events = subscribe_policy_events(&tx).await;

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::SetPolicy {
        name: "audit-policy".to_string(),
        definition: NamedPolicyDefinition {
            default_action: "permit".to_string(),
            statements: Vec::<PolicyStatementDefinition>::new(),
        },
        reply: reply_tx,
    })
    .await
    .unwrap();
    reply_rx.await.unwrap().unwrap();

    let event = tokio::time::timeout(Duration::from_secs(2), events.recv())
        .await
        .expect("policy event timeout")
        .expect("policy event channel closed");
    assert_eq!(event.operation, "set");
    assert_eq!(event.target_type, "policy");
    assert_eq!(event.target, "audit-policy");
    assert_eq!(event.peer, None);
    assert_eq!(event.affected_peer_count, 0);
    assert_eq!(event.reason, "policy set policy audit-policy");

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn apply_policy_change_fans_out_to_scoped_peers() {
    use rustbgpd_api::peer_types::NeighborSetDefinition;

    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                let _ = reply.send(Ok(()));
            }
        }
    });
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
    // Distinct link-local addresses per interface: v1 config requires link-local
    // addresses to be unique across neighbors (ADR-0069), but the scoped PeerKey
    // still keys each peer by (address, interface), so this exercises policy
    // fan-out across two separately-keyed scoped peers.
    let peer0 = IpAddr::V6("fe80::2".parse().unwrap());
    let peer1 = IpAddr::V6("fe80::3".parse().unwrap());
    let eth0 = Arc::new(FakePeerCounters::default());
    let eth1 = Arc::new(FakePeerCounters::default());

    insert_test_scoped_managed_peer(
        &mut mgr,
        peer0,
        "eth0",
        10,
        1,
        fake_peer_handle(peer0, SessionState::Established, None, eth0.clone()),
    );
    insert_test_scoped_managed_peer(
        &mut mgr,
        peer1,
        "eth1",
        11,
        2,
        fake_peer_handle(peer1, SessionState::Established, None, eth1.clone()),
    );

    let mut n0 = config_neighbor(peer0, 65002);
    n0.interface = Some("eth0".to_string());
    let mut n1 = config_neighbor(peer1, 65002);
    n1.interface = Some("eth1".to_string());
    mgr.current_config.neighbors = vec![n0, n1];

    mgr.apply_policy_change(
        ConfigEvent::SetNeighborSet {
            name: "unused".to_string(),
            definition: NeighborSetDefinition {
                addresses: vec!["192.0.2.1".to_string()],
                remote_asns: vec![],
                peer_groups: vec![],
            },
            ack: None,
        },
        None,
    )
    .await
    .unwrap();

    assert_eq!(eth0.query_state.load(Ordering::SeqCst), 1);
    assert_eq!(eth1.query_state.load(Ordering::SeqCst), 1);
    drop(mgr);
    rib_drainer.await.unwrap();
}

/// ADR-0096: `sync_rpol_policies` adopts the new compiled registry,
/// re-resolves live chains through it (Route Refresh for the material
/// import change), and `SetPolicy` cannot shadow an rpol-defined name.
#[tokio::test]
async fn sync_rpol_policies_reresolves_chains_and_rejects_shadowing() {
    use rustbgpd_api::peer_types::NamedPolicyDefinition;
    use rustbgpd_policy::rpol::{RpolFile, RpolPolicyEntry, RpolPolicySet};

    fn registry(source: &str) -> RpolPolicySet {
        let file = std::sync::Arc::new(RpolFile::parse(source).expect("clean rpol"));
        let mut set = RpolPolicySet::default();
        set.policies.insert(
            "edge-in".to_string(),
            RpolPolicyEntry {
                file,
                params: 0,
                path: "policies/core.rpol".to_string(),
            },
        );
        set
    }

    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                let _ = reply.send(Ok(()));
            }
        }
    });
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
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer(
        &mut mgr,
        peer,
        acking_counted_policy_handle(peer, counters.clone()),
        false,
    );
    let mut neighbor = config_neighbor(peer, 65002);
    neighbor.import_policy_chain = vec!["edge-in".to_string()];
    mgr.current_config.neighbors = vec![neighbor];
    mgr.current_config.policy.rpol =
        registry("policy edge-in { term all { set local-pref 150; accept } }");

    // New registry content: chains re-resolve and the peer's import
    // policy now carries the edited compiled body.
    mgr.sync_rpol_policies(
        vec!["policies/core.rpol".to_string()],
        registry("policy edge-in { term all { set local-pref 250; accept } }"),
        rustbgpd_policy::datasets::DatasetBindings::default(),
    )
    .await
    .expect("sync succeeds");
    let managed = mgr.peers.values().next().expect("peer present");
    let chain = managed.import_policy.as_ref().expect("import chain set");
    assert!(chain.policies[0].rpol.is_some());
    let ctx = rustbgpd_policy::RouteContext {
        prefix: None,
        next_hop: None,
        extended_communities: &[],
        communities: &[],
        large_communities: &[],
        as_path_str: "",
        as_path: None,
        as_path_len: 0,
        origin_asn: None,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        peer_address: None,
        peer_asn: None,
        peer_group: None,
        route_type: None,
        family: None,
        evpn_route_type: None,
        local_pref: None,
        med: None,
    };
    assert_eq!(chain.evaluate(&ctx).modifications.set_local_pref, Some(250));

    // The rpol name cannot be shadowed by a TOML SetPolicy.
    let err = mgr
        .apply_policy_change(
            ConfigEvent::SetPolicy {
                name: "edge-in".to_string(),
                definition: NamedPolicyDefinition {
                    default_action: "permit".to_string(),
                    statements: vec![],
                },
                ack: None,
            },
            None,
        )
        .await
        .expect_err("shadowing an rpol policy must be rejected");
    assert!(err.to_string().contains("rpol"), "{err}");

    drop(mgr);
    rib_drainer.await.unwrap();
}

/// LAN-284: a rejected `sync_rpol_policies` (mid-apply chain resolution
/// failure) must leave BOTH policy surfaces on the old registry — the
/// live peer's chain (existing sessions) and `current_config` (what a
/// session created afterwards resolves against). Asserted at decision
/// level: the live chain still evaluates the OLD local-pref.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the extra dataset-bindings argument pushed this linear scenario over the line cap"
)]
async fn sync_rpol_policies_rejection_keeps_old_registry_for_live_and_new_sessions() {
    use rustbgpd_policy::rpol::{RpolFile, RpolPolicyEntry, RpolPolicySet};

    fn registry(name: &str, source: &str) -> RpolPolicySet {
        let file = std::sync::Arc::new(RpolFile::parse(source).expect("clean rpol"));
        let mut set = RpolPolicySet::default();
        set.policies.insert(
            name.to_string(),
            RpolPolicyEntry {
                file,
                params: 0,
                path: "policies/core.rpol".to_string(),
            },
        );
        set
    }

    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                let _ = reply.send(Ok(()));
            }
        }
    });
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
    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer(
        &mut mgr,
        peer,
        acking_counted_policy_handle(peer, counters.clone()),
        false,
    );
    let mut neighbor = config_neighbor(peer, 65002);
    neighbor.import_policy_chain = vec!["edge-in".to_string()];
    mgr.current_config.neighbors = vec![neighbor];
    mgr.current_config.policy.rpol = registry(
        "edge-in",
        "policy edge-in { term all { set local-pref 150; accept } }",
    );
    // Materialize the live chain from the OLD registry.
    mgr.sync_rpol_policies(
        vec!["policies/core.rpol".to_string()],
        registry(
            "edge-in",
            "policy edge-in { term all { set local-pref 150; accept } }",
        ),
        rustbgpd_policy::datasets::DatasetBindings::default(),
    )
    .await
    .expect("baseline sync succeeds");

    // Candidate registry renames the policy, so the static peer's
    // `import_policy_chain = ["edge-in"]` no longer resolves: the sync
    // is rejected mid-apply with zero peers touched.
    mgr.sync_rpol_policies(
        vec!["policies/core.rpol".to_string()],
        registry(
            "edge-in-renamed",
            "policy edge-in-renamed { term all { set local-pref 250; accept } }",
        ),
        rustbgpd_policy::datasets::DatasetBindings::default(),
    )
    .await
    .expect_err("chain resolution failure must reject the sync");

    // Existing session: the live chain still evaluates the OLD decision.
    let managed = mgr.peers.values().next().expect("peer present");
    let chain = managed.import_policy.as_ref().expect("import chain set");
    let ctx = rustbgpd_policy::RouteContext {
        prefix: None,
        next_hop: None,
        extended_communities: &[],
        communities: &[],
        large_communities: &[],
        as_path_str: "",
        as_path: None,
        as_path_len: 0,
        origin_asn: None,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        peer_address: None,
        peer_asn: None,
        peer_group: None,
        route_type: None,
        family: None,
        evpn_route_type: None,
        local_pref: None,
        med: None,
    };
    assert_eq!(chain.evaluate(&ctx).modifications.set_local_pref, Some(150));

    // New session source: chains for a session created AFTER the
    // rejection resolve from `current_config`, which must still carry
    // the old registry — and evaluate the OLD decision.
    let neighbor = mgr.current_config.neighbors[0].clone();
    let (import, _export) = mgr
        .current_config
        .effective_policy_chains_for_neighbor(&neighbor)
        .expect("new-session chains resolve against the old registry");
    let chain = import.expect("import chain configured");
    assert_eq!(chain.evaluate(&ctx).modifications.set_local_pref, Some(150));

    drop(mgr);
    rib_drainer.await.unwrap();
}

/// Read one policy-freshness metric from the gathered exposition:
/// the unlabeled family value, or the child whose `dataset` label
/// matches. `None` when the family/series is absent.
#[expect(
    clippy::cast_possible_truncation,
    reason = "unix-seconds gauges and small test counters fit i64"
)]
fn policy_metric_value(metrics: &BgpMetrics, family: &str, dataset: Option<&str>) -> Option<i64> {
    metrics
        .registry()
        .gather()
        .iter()
        .find(|f| f.name() == family)?
        .get_metric()
        .iter()
        .find(|m| match dataset {
            Some(dataset) => m
                .get_label()
                .iter()
                .any(|l| l.name() == "dataset" && l.value() == dataset),
            None => true,
        })
        .map(|m| {
            // Counter families follow the `_total` naming convention;
            // everything read here otherwise is a gauge.
            if family.ends_with("_total") {
                m.get_counter().value() as i64
            } else {
                m.get_gauge().value() as i64
            }
        })
}

/// Block until the wall clock has advanced past `after` (unix
/// seconds), so a subsequent timestamp stamp is distinguishable
/// from one taken at `after`.
async fn wait_for_unix_second_after(after: i64) {
    loop {
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_secs(),
        )
        .expect("unix seconds fit i64");
        if now > after {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// ADR-0110 load-bearing staleness assertion: a rejected rpol sync
/// keeps the old generation live AND freezes
/// `bgp_policy_generation_loaded_timestamp_seconds` — the timestamp
/// must NOT advance on a failed swap, otherwise `time() - <gauge>`
/// alerting can never see a stuck pipeline. A subsequent successful
/// sync advances it.
#[tokio::test]
async fn rejected_rpol_sync_freezes_policy_generation_timestamp() {
    use rustbgpd_policy::rpol::{RpolFile, RpolPolicyEntry, RpolPolicySet};

    fn registry(name: &str, source: &str) -> RpolPolicySet {
        let file = std::sync::Arc::new(RpolFile::parse(source).expect("clean rpol"));
        let mut set = RpolPolicySet::default();
        set.policies.insert(
            name.to_string(),
            RpolPolicyEntry {
                file,
                params: 0,
                path: "policies/core.rpol".to_string(),
            },
        );
        set
    }

    const FAMILY: &str = "bgp_policy_generation_loaded_timestamp_seconds";
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                let _ = reply.send(Ok(()));
            }
        }
    });
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
    // Initial load: constructing the manager stamped the generation.
    let initial = policy_metric_value(&mgr.metrics, FAMILY, None).expect("stamped at construction");
    assert!(initial > 0);

    let peer: IpAddr = "10.0.0.2".parse().unwrap();
    let counters = Arc::new(FakePeerCounters::default());
    insert_test_managed_peer(
        &mut mgr,
        peer,
        acking_counted_policy_handle(peer, counters.clone()),
        false,
    );
    let mut neighbor = config_neighbor(peer, 65002);
    neighbor.import_policy_chain = vec!["edge-in".to_string()];
    mgr.current_config.neighbors = vec![neighbor];
    mgr.current_config.policy.rpol = registry(
        "edge-in",
        "policy edge-in { term all { set local-pref 150; accept } }",
    );

    // Let the wall clock tick so a (buggy) stamp on the failed swap
    // below would be distinguishable from the construction stamp.
    wait_for_unix_second_after(initial).await;

    // Candidate registry renames the policy, so the static peer's
    // chain no longer resolves: the sync is rejected — and the
    // timestamp must stay frozen at the last ACCEPTED apply.
    mgr.sync_rpol_policies(
        vec!["policies/core.rpol".to_string()],
        registry(
            "edge-in-renamed",
            "policy edge-in-renamed { term all { set local-pref 250; accept } }",
        ),
        rustbgpd_policy::datasets::DatasetBindings::default(),
    )
    .await
    .expect_err("chain resolution failure must reject the sync");
    assert_eq!(
        policy_metric_value(&mgr.metrics, FAMILY, None),
        Some(initial),
        "a rejected swap must not advance the loaded timestamp"
    );

    // A successful sync IS an accept: the timestamp advances.
    mgr.sync_rpol_policies(
        vec!["policies/core.rpol".to_string()],
        registry(
            "edge-in",
            "policy edge-in { term all { set local-pref 250; accept } }",
        ),
        rustbgpd_policy::datasets::DatasetBindings::default(),
    )
    .await
    .expect("sync succeeds");
    let advanced = policy_metric_value(&mgr.metrics, FAMILY, None).expect("still present");
    assert!(
        advanced > initial,
        "successful swap must stamp a newer time"
    );

    drop(mgr);
    rib_drainer.await.unwrap();
}

/// ADR-0110: `RefreshDatasetDependents` stamps
/// `bgp_policy_dataset_loaded_timestamp_seconds{dataset}` for each
/// swapped dataset, while a failed refresh only increments the
/// failure counter — it never creates/advances the loaded timestamp.
#[tokio::test]
async fn dataset_refresh_stamps_swapped_and_freezes_failed() {
    const LOADED: &str = "bgp_policy_dataset_loaded_timestamp_seconds";
    const FAILURES: &str = "bgp_policy_dataset_refresh_errors_total";
    let (_tx, rx) = mpsc::channel(16);
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
    mgr.refresh_dataset_dependents(
        &["customers".to_string()],
        &[("bogons".to_string(), "unreadable".to_string())],
    )
    .await
    .expect("refresh fan-out with no peers succeeds");

    let stamped =
        policy_metric_value(&mgr.metrics, LOADED, Some("customers")).expect("swapped stamped");
    assert!(stamped > 0);
    assert_eq!(
        policy_metric_value(&mgr.metrics, LOADED, Some("bogons")),
        None,
        "a failed refresh must not create a loaded-timestamp series"
    );
    assert_eq!(
        policy_metric_value(&mgr.metrics, FAILURES, Some("bogons")),
        Some(1)
    );
}

/// ADR-0110 reap discipline: a dataset removed from config on a
/// successful rpol sync drops BOTH its per-dataset series (loaded
/// timestamp and failure counter); a dataset introduced by the sync
/// gets its initial stamp.
#[tokio::test]
async fn rpol_sync_reaps_removed_dataset_series() {
    use rustbgpd_policy::datasets::{DatasetBindings, DatasetData, DatasetHandle, DatasetKind};
    use rustbgpd_policy::rpol::RpolPolicySet;
    use rustbgpd_policy::sets::AsnSet;

    const LOADED: &str = "bgp_policy_dataset_loaded_timestamp_seconds";
    const FAILURES: &str = "bgp_policy_dataset_refresh_errors_total";
    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel(64);
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

    // Sync #1 introduces the dataset: its series appears.
    let mut bindings = DatasetBindings::default();
    bindings.insert(std::sync::Arc::new(DatasetHandle::new(
        "customers",
        DatasetKind::Asn,
        DatasetData::Asn(AsnSet::new(std::iter::once(64500))),
    )));
    mgr.sync_rpol_policies(Vec::new(), RpolPolicySet::default(), bindings)
        .await
        .expect("sync with a new dataset succeeds");
    assert!(policy_metric_value(&mgr.metrics, LOADED, Some("customers")).is_some());
    mgr.metrics.record_policy_dataset_refresh_error("customers");
    assert_eq!(
        policy_metric_value(&mgr.metrics, FAILURES, Some("customers")),
        Some(1)
    );

    // Sync #2 removes it from config: both series are reaped.
    mgr.sync_rpol_policies(
        Vec::new(),
        RpolPolicySet::default(),
        DatasetBindings::default(),
    )
    .await
    .expect("sync removing the dataset succeeds");
    assert_eq!(
        policy_metric_value(&mgr.metrics, LOADED, Some("customers")),
        None,
        "removed dataset must not keep advertising freshness"
    );
    assert_eq!(
        policy_metric_value(&mgr.metrics, FAILURES, Some("customers")),
        None
    );
}

/// Regression: catalog policy mutations (`SetPolicy` / neighbor sets / global
/// chains, gRPC and SIGHUP alike) must hot-apply resolved chains to live
/// DYNAMIC peers. Dynamic peers have no `[[neighbors]]` record, and the
/// per-peer loop previously skipped them entirely — a policy edit on a route
/// server never reached established dynamic sessions until they flapped,
/// running split-brain policy between sessions accepted before and after
/// the edit.
#[tokio::test]
async fn apply_policy_change_reaches_live_dynamic_peers() {
    use rustbgpd_api::peer_types::{NamedPolicyDefinition, PolicyStatementDefinition};

    let (_tx, rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                let _ = reply.send(Ok(()));
            }
        }
    });
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

    // Config: the dynamic peers' group resolves an import chain that
    // references the named policy being edited.
    let mut config = make_dynamic_manager_config();
    if let Some(group) = config.peer_groups.get_mut("ix-members") {
        group.import_policy_chain = vec!["ix-import".to_string()];
    }
    mgr.current_config = config;

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let counters = Arc::new(FakePeerCounters::default());
    let handle = acking_counted_policy_handle(addr, counters.clone());
    insert_test_managed_peer(&mut mgr, addr, handle, false);
    let managed = mgr.peers.get_mut(&key(addr)).unwrap();
    managed.is_dynamic = true;
    managed.peer_group = Some("ix-members".to_string());

    mgr.apply_policy_change(
        ConfigEvent::SetPolicy {
            name: "ix-import".to_string(),
            definition: NamedPolicyDefinition {
                default_action: "deny".to_string(),
                statements: Vec::<PolicyStatementDefinition>::new(),
            },
            ack: None,
        },
        None,
    )
    .await
    .unwrap();

    // The dynamic peer must have been processed: chains resolved against the
    // synthetic peer-group-backed neighbor, hot-applied to the session, and
    // the import change refreshed.
    assert_eq!(
        counters.query_state.load(Ordering::SeqCst),
        1,
        "dynamic peer must not be skipped by catalog policy mutations"
    );
    assert_eq!(
        counters.route_refresh.load(Ordering::SeqCst),
        1,
        "import-chain change on a dynamic peer must trigger Route Refresh"
    );
    assert!(
        mgr.peers.get(&key(addr)).unwrap().import_policy.is_some(),
        "resolved import chain must be recorded on the dynamic peer"
    );

    drop(mgr);
    rib_drainer.await.unwrap();
}

#[tokio::test]
async fn set_peer_group_policy_only_change_reaches_live_dynamic_peers() {
    use crate::config::NamedPolicyConfig;

    let (tx, rx) = mpsc::channel(16);
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let rib_drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::ReplacePeerExportPolicy { reply, .. } = update {
                let _ = reply.send(Ok(()));
            }
        }
    });
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

    let mut config = make_dynamic_manager_config();
    config.policy.definitions.insert(
        "deny-import".to_string(),
        NamedPolicyConfig {
            default_action: "deny".to_string(),
            statements: Vec::new(),
        },
    );
    if let Some(group) = config.peer_groups.get_mut("ix-members") {
        group.import_policy_chain = vec!["ix-import".to_string()];
    }
    let mut next_group = crate::policy_admin::config_peer_group_to_api(
        config.peer_groups.get("ix-members").unwrap(),
    );
    next_group.import_policy_chain = vec!["deny-import".to_string()];
    mgr.current_config = config;

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let counters = Arc::new(FakePeerCounters::default());
    let handle = acking_counted_policy_handle(addr, counters.clone());
    insert_test_managed_peer(&mut mgr, addr, handle, false);
    let managed = mgr.peers.get_mut(&key(addr)).unwrap();
    managed.is_dynamic = true;
    managed.peer_group = Some("ix-members".to_string());

    let manager_task = tokio::spawn(mgr.run());
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::SetPeerGroup {
        name: "ix-members".to_string(),
        definition: next_group,
        reply: reply_tx,
    })
    .await
    .unwrap();
    reply_rx.await.unwrap().unwrap();

    assert_eq!(
        counters.query_state.load(Ordering::SeqCst),
        1,
        "SetPeerGroup policy-only edits must not skip live dynamic peers"
    );
    assert_eq!(
        counters.route_refresh.load(Ordering::SeqCst),
        1,
        "dynamic import policy-chain movement must trigger Route Refresh"
    );

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    manager_task.await.unwrap();
    rib_drainer.abort();
}

/// Load-bearing dynamic inheritance proof: dropping the post-commit sync in
/// `apply_peer_group_change` leaves an accepted dynamic peer on the duration
/// it inherited at accept time. The None -> 30 assertion and the 30 -> 60
/// countdown rescheduling each fail independently without that sync.
#[tokio::test(start_paused = true)]
async fn set_peer_group_restart_policy_updates_live_dynamic_peer() {
    let mut mgr = dynamic_test_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 76));
    insert_test_dynamic_managed_peer(
        &mut mgr,
        addr,
        76,
        fake_peer_handle(
            addr,
            SessionState::Idle,
            None,
            Arc::new(FakePeerCounters::default()),
        ),
        false,
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
        8,
        "ix-members",
    );
    assert_eq!(mgr.peers[&key(addr)].max_prefix_restart_seconds, None);

    let mut group = crate::policy_admin::config_peer_group_to_api(
        &mgr.current_config.peer_groups["ix-members"],
    );
    group.max_prefix_restart_seconds = Some(30);
    mgr.apply_peer_group_change(
        rustbgpd_api::peer_types::ConfigEvent::SetPeerGroup {
            name: "ix-members".to_string(),
            definition: group,
            ack: None,
        },
        Vec::new(),
    )
    .await
    .unwrap();
    assert_eq!(mgr.peers[&key(addr)].max_prefix_restart_seconds, Some(30));

    mgr.install_max_prefix_latch(key(addr), 76, "first policy".to_string(), Some(30));
    tokio::time::advance(Duration::from_secs(10)).await;
    let mut group = crate::policy_admin::config_peer_group_to_api(
        &mgr.current_config.peer_groups["ix-members"],
    );
    group.max_prefix_restart_seconds = Some(60);
    mgr.apply_peer_group_change(
        rustbgpd_api::peer_types::ConfigEvent::SetPeerGroup {
            name: "ix-members".to_string(),
            definition: group,
            ack: None,
        },
        Vec::new(),
    )
    .await
    .unwrap();
    assert_eq!(mgr.peers[&key(addr)].max_prefix_restart_seconds, Some(60));
    assert_eq!(
        mgr.max_prefix_latches[&key(addr)].deadline.unwrap() - tokio::time::Instant::now(),
        Duration::from_mins(1),
        "a group duration edit must reschedule the armed countdown to now + new"
    );
}

/// Load-bearing reload-sweep re-arm proof: a config swap that edits a group's
/// restart duration reschedules a still-matched dynamic member's armed
/// countdown to now + new and syncs the managed copy so the due-time policy
/// check passes — the superseded deadline never fires, the re-armed one fires
/// exactly once.
#[tokio::test(start_paused = true)]
async fn reconcile_sweep_rearms_dynamic_peer_on_group_duration_edit() {
    let mut mgr = dynamic_test_manager();
    let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 78));
    let counters = Arc::new(FakePeerCounters::default());
    insert_test_dynamic_managed_peer(
        &mut mgr,
        addr,
        78,
        fake_peer_handle(addr, SessionState::Idle, None, counters.clone()),
        false,
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
        8,
        "ix-members",
    );
    mgr.current_config
        .peer_groups
        .get_mut("ix-members")
        .unwrap()
        .max_prefix_restart_seconds = std::num::NonZeroU32::new(30);
    mgr.peers
        .get_mut(&key(addr))
        .unwrap()
        .max_prefix_restart_seconds = Some(30);
    mgr.install_max_prefix_latch(key(addr), 78, "max-prefix".to_string(), Some(30));

    tokio::time::advance(Duration::from_secs(10)).await;
    mgr.current_config
        .peer_groups
        .get_mut("ix-members")
        .unwrap()
        .max_prefix_restart_seconds = std::num::NonZeroU32::new(60);
    mgr.reconcile_stale_dynamic_max_prefix_restarts();
    assert_eq!(
        mgr.max_prefix_latches[&key(addr)].deadline.unwrap() - tokio::time::Instant::now(),
        Duration::from_mins(1)
    );
    assert_eq!(mgr.peers[&key(addr)].max_prefix_restart_seconds, Some(60));

    // Past the superseded t+30 deadline but before the re-armed t+70 one.
    tokio::time::advance(Duration::from_secs(25)).await;
    mgr.handle_due_max_prefix_restarts().await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(counters.start.load(Ordering::SeqCst), 0);
    assert!(!mgr.peers[&key(addr)].enabled);

    tokio::time::advance(Duration::from_secs(35)).await;
    mgr.handle_due_max_prefix_restarts().await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(counters.start.load(Ordering::SeqCst), 1);
    assert!(mgr.peers[&key(addr)].enabled);
    assert!(!mgr.max_prefix_latches.contains_key(&key(addr)));
}

/// A catalog mutation's fan-out is atomic: when applying the resolved
/// chains to peer 2 fails mid-loop, peer 1 (already updated) is restored
/// to its prior chains, peer 3 is never touched, and `current_config`
/// does not advance — no split-brain where some sessions run the new
/// policy and others the old.
#[tokio::test]
async fn apply_policy_change_mid_fanout_failure_restores_prior_chains() {
    use rustbgpd_api::peer_types::{NamedPolicyDefinition, PolicyStatementDefinition};

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
    // Static records whose import chain references the policy being set.
    mgr.current_config.neighbors = [a1, a2, a3]
        .into_iter()
        .map(|addr| {
            let mut neighbor = config_neighbor(addr, 65002);
            neighbor.import_policy_chain = vec!["edge-import".to_string()];
            neighbor
        })
        .collect();
    let prior = validation_policy_chain(ImportValidationDependency::Rpki);
    for a in [a1, a2, a3] {
        mgr.peers.get_mut(&key(a)).unwrap().import_policy = Some(prior.clone());
    }

    let result = mgr
        .apply_policy_change(
            ConfigEvent::SetPolicy {
                name: "edge-import".to_string(),
                definition: NamedPolicyDefinition {
                    default_action: "deny".to_string(),
                    statements: Vec::<PolicyStatementDefinition>::new(),
                },
                ack: None,
            },
            // Explicit order so peer 1 is applied before peer 2 fails.
            Some(vec![a1, a2, a3]),
        )
        .await;
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
    assert!(
        !mgr.current_config
            .policy
            .definitions
            .contains_key("edge-import"),
        "a failed catalog mutation must not advance current_config"
    );
}

#[tokio::test]
async fn validation_cache_refresh_targets_matching_established_import_policies() {
    let mut mgr = test_peer_manager();
    let rpki_peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 11));
    let aspa_peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 12));
    let no_validation_peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 13));
    let idle_rpki_peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 14));

    let rpki = Arc::new(FakePeerCounters::default());
    let aspa = Arc::new(FakePeerCounters::default());
    let no_validation = Arc::new(FakePeerCounters::default());
    let idle_rpki = Arc::new(FakePeerCounters::default());

    insert_test_managed_peer(
        &mut mgr,
        rpki_peer,
        fake_peer_handle(rpki_peer, SessionState::Established, None, rpki.clone()),
        false,
    );
    insert_test_managed_peer(
        &mut mgr,
        aspa_peer,
        fake_peer_handle(aspa_peer, SessionState::Established, None, aspa.clone()),
        false,
    );
    insert_test_managed_peer(
        &mut mgr,
        no_validation_peer,
        fake_peer_handle(
            no_validation_peer,
            SessionState::Established,
            None,
            no_validation.clone(),
        ),
        false,
    );
    insert_test_managed_peer(
        &mut mgr,
        idle_rpki_peer,
        fake_peer_handle(idle_rpki_peer, SessionState::Idle, None, idle_rpki.clone()),
        false,
    );

    mgr.peers.get_mut(&key(rpki_peer)).unwrap().import_policy =
        Some(validation_policy_chain(ImportValidationDependency::Rpki));
    mgr.peers.get_mut(&key(aspa_peer)).unwrap().import_policy =
        Some(validation_policy_chain(ImportValidationDependency::Aspa));
    mgr.peers
        .get_mut(&key(no_validation_peer))
        .unwrap()
        .import_policy = Some(deny_policy_chain());
    mgr.peers
        .get_mut(&key(idle_rpki_peer))
        .unwrap()
        .import_policy = Some(validation_policy_chain(ImportValidationDependency::Rpki));

    mgr.soft_reset_import_validation_dependents(ImportValidationDependency::Rpki)
        .await
        .unwrap();

    assert_eq!(rpki.query_state.load(Ordering::SeqCst), 1);
    assert_eq!(rpki.route_refresh.load(Ordering::SeqCst), 1);
    assert_eq!(
        idle_rpki.query_state.load(Ordering::SeqCst),
        1,
        "RPKI-dependent idle peers are considered but not refreshed"
    );
    assert_eq!(idle_rpki.route_refresh.load(Ordering::SeqCst), 0);
    assert_eq!(
        aspa.query_state.load(Ordering::SeqCst),
        0,
        "ASPA-only peers must not be touched by an RPKI cache update"
    );
    assert_eq!(aspa.route_refresh.load(Ordering::SeqCst), 0);
    assert_eq!(
        no_validation.query_state.load(Ordering::SeqCst),
        0,
        "peers without validation-state import predicates are not queried"
    );

    mgr.soft_reset_import_validation_dependents(ImportValidationDependency::Aspa)
        .await
        .unwrap();

    assert_eq!(aspa.query_state.load(Ordering::SeqCst), 1);
    assert_eq!(aspa.route_refresh.load(Ordering::SeqCst), 1);
    assert_eq!(
        rpki.route_refresh.load(Ordering::SeqCst),
        1,
        "RPKI peer must not receive a second refresh from an ASPA-only update"
    );

    assert_validation_import_refresh_metric(&mgr, "rpki", "eligible", 2.0);
    assert_validation_import_refresh_metric(&mgr, "rpki", "refreshed", 1.0);
    assert_validation_import_refresh_metric(&mgr, "rpki", "skipped_not_established", 1.0);
    assert_validation_import_refresh_metric(&mgr, "rpki", "failed", 0.0);
    assert_validation_import_refresh_metric(&mgr, "aspa", "eligible", 1.0);
    assert_validation_import_refresh_metric(&mgr, "aspa", "refreshed", 1.0);
}

#[tokio::test]
async fn validation_cache_refresh_times_out_unresponsive_route_refresh() {
    let mut mgr = test_peer_manager();
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 15));
    let counters = Arc::new(FakePeerCounters::default());

    insert_test_managed_peer(
        &mut mgr,
        peer,
        fake_peer_handle_with_route_refresh_reply(
            peer,
            SessionState::Established,
            None,
            counters.clone(),
            false,
        ),
        false,
    );
    mgr.peers.get_mut(&key(peer)).unwrap().import_policy =
        Some(validation_policy_chain(ImportValidationDependency::Rpki));

    let result = tokio::time::timeout(
        PEER_POLICY_UPDATE_TIMEOUT * 3,
        mgr.soft_reset_import_validation_dependents(ImportValidationDependency::Rpki),
    )
    .await
    .expect("outer timeout: cache refresh helper should return after its per-peer timeout");

    let error = result.expect_err("unresponsive route-refresh reply should be reported");
    assert!(
        error.contains("timed out"),
        "timeout failure should be visible in the aggregate error: {error}"
    );
    assert_eq!(counters.query_state.load(Ordering::SeqCst), 1);
    assert_eq!(counters.route_refresh.load(Ordering::SeqCst), 1);
    assert_validation_import_refresh_metric(&mgr, "rpki", "eligible", 1.0);
    assert_validation_import_refresh_metric(&mgr, "rpki", "refreshed", 0.0);
    assert_validation_import_refresh_metric(&mgr, "rpki", "failed", 1.0);
}

/// Regression: when a policy mutation actually changes the
/// effective import policy for an Idle peer (so
/// `import_changed` flips true inside
/// `update_runtime_policies`), the route-refresh trigger must
/// be gated on Established and the mutation must still return
/// Ok. Without the gate, `send_route_refresh` returns "session
/// not Established" for any peer mid-reconnect, which would
/// propagate through `apply_policy_change` and fail the gRPC
/// call. Operators with even one peer mid-reconnect would see
/// every `SetPolicy` / `SetGlobalImportChain` fail.
///
/// The test deliberately wires up a chain reference to the
/// policy so `import_changed` actually fires. Earlier shape
/// (`SetPolicy` with no chain reference) didn't exercise the
/// gate at all — `import_changed` stayed false and the test
/// would pass even with the gate removed.
///
/// Companion (Established-side) coverage — that the auto-refresh
/// actually fires when a peer IS Established — is M34 in the
/// interop suite (needs a real FRR session).
#[tokio::test]
async fn set_policy_does_not_error_on_idle_peers_when_import_changes() {
    use rustbgpd_api::peer_types::{NamedPolicyDefinition, PolicyStatementDefinition};
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

    // sync_config_snapshot = true so PM's current_config tracks
    // the new neighbor. Otherwise apply_policy_change's per-peer
    // loop skips it (the neighbor wouldn't be present in
    // next_config) and update_runtime_policies never runs —
    // making the gate untestable.
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::AddPeer {
        config: make_config(addr, 65002),
        sync_config_snapshot: true,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok(), "AddPeer must succeed");

    // Step 1: install a named policy that the peer's resolved
    // chain will pick up once we attach it via the global
    // import_chain. This call alone doesn't move
    // `import_changed` (no chain references the new policy
    // yet); it's just setup.
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::SetPolicy {
        name: "test-policy".to_string(),
        definition: NamedPolicyDefinition {
            default_action: "deny".to_string(),
            statements: Vec::<PolicyStatementDefinition>::new(),
        },
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(
        reply_rx.await.unwrap().is_ok(),
        "SetPolicy setup step must succeed"
    );

    // Step 2: this is the call that actually flips
    // `import_changed = true`. Setting the global chain to
    // ["test-policy"] makes the peer's resolved import chain
    // move from "empty / inline" to "single-policy chain
    // (deny-default)" — `update_runtime_policies` sees the
    // change and tries to fire `soft_reset_in`. The peer is
    // Idle (unreachable address, no session), so without the
    // Established gate the route-refresh would error and the
    // reply would be Err.
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::SetGlobalImportChain {
        policy_names: vec!["test-policy".to_string()],
        reply: reply_tx,
    })
    .await
    .unwrap();
    let result = reply_rx.await.unwrap();
    assert!(
        result.is_ok(),
        "SetGlobalImportChain with import-changing chain must succeed when the only \
         affected peer is Idle — the auto Route Refresh trigger must be gated on \
         Established or operator gRPC calls would fail every time a peer is mid-reconnect. \
         Got: {result:?}",
    );

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn missing_policy_catalog_references_return_not_found_errors() {
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
    tx.send(PeerManagerCommand::SetGlobalImportChain {
        policy_names: vec!["missing-policy".to_string()],
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(matches!(
        reply_rx.await.unwrap(),
        Err(CatalogMutationError::NotFound(message)) if message.contains("missing-policy")
    ));

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::AddPeer {
        config: make_config(addr, 65002),
        sync_config_snapshot: true,
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(reply_rx.await.unwrap().is_ok(), "AddPeer must succeed");

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(PeerManagerCommand::SetNeighborPeerGroup {
        address: addr,
        peer_group: "missing-group".to_string(),
        reply: reply_tx,
    })
    .await
    .unwrap();
    assert!(matches!(
        reply_rx.await.unwrap(),
        Err(CatalogMutationError::NotFound(message)) if message.contains("missing-group")
    ));

    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    handle.await.unwrap();
}

/// Auto-retry semantics for `pending_refresh`: if a prior call set
/// the flag (because an Established refresh send failed), the next
/// call to `update_runtime_policies` must drain it. When the peer
/// still isn't Established at the time of the next call, the flag
/// must be re-armed so a future call retries — without this, a
/// transient send failure would silently leave the new policy
/// applied to *future* UPDATEs while routes already in `AdjRibIn`
/// keep flowing under the prior policy.
///
/// Construct `ManagedPeer` directly with `pending_refresh = true`
/// to simulate inheriting the flag. Driving the natural failure
/// path (Established → `send_route_refresh` Err) requires a real
/// session, which is what M34 (interop) covers; the unit test
/// focuses on the in-process drain/re-arm bookkeeping.
#[tokio::test]
async fn pending_refresh_re_arms_when_peer_still_not_established() {
    let (_cmd_tx, cmd_rx) = mpsc::channel(16);
    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
    let metrics = BgpMetrics::new();
    let mut mgr = PeerManager::new(
        cmd_rx,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        metrics.clone(),
        rib_tx.clone(),
        None,
    );

    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let peer_config = make_config(addr, 65002);
    let transport = mgr.build_transport_config(&peer_config);
    // Spawn a peer session handle but never call `start()` — the
    // session stays in Idle, so QueryState returns Some(Idle) and
    // is_established == false inside update_runtime_policies.
    let handle = rustbgpd_transport::PeerHandle::spawn(
        transport.clone(),
        metrics,
        rib_tx.clone(),
        None,
        None,
        None,
        None,
        None,
        false,
    );
    let hold = transport.peer.hold_time;
    mgr.peers.insert(
        key(addr),
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
            pending_refresh: true,
            pending_export_apply: false,
            tcp_ao_rotation: TcpAoRotationStatus::default(),
            advertise_graceful_shutdown: false,
        },
    );

    // Same (None) policies — `import_changed = false` here. The
    // refresh intent is carried only by `pending_refresh`; if the
    // drain logic forgot to honor the flag, this call would no-op
    // and pending_refresh would clear silently.
    let result = mgr.update_runtime_policies(addr, None, None).await;
    assert!(
        result.is_ok(),
        "update_runtime_policies on Idle peer must return Ok even when retrying a \
         pending refresh — refresh is gated on Established, so 'not Established yet' \
         is not an error condition. Got: {result:?}"
    );

    let pending = mgr.peers.get(&key(addr)).unwrap().pending_refresh;
    assert!(
        pending,
        "pending_refresh must be re-armed after an update where the peer is still \
         not Established. Without this, a transient Err on the original Established \
         refresh would leave routes in AdjRibIn flowing under the prior policy until \
         an operator manually reissues SetPolicy."
    );
}

#[tokio::test]
async fn channel_full_policy_update_bails_and_preserves_pending_refresh() {
    use rustbgpd_transport::PeerCommand;

    let (session_tx, session_rx) = mpsc::channel::<PeerCommand>(1);
    let (queued_reply, _queued_rx) = oneshot::channel();
    assert!(
        session_tx
            .try_send(PeerCommand::QueryState {
                reply: queued_reply,
            })
            .is_ok(),
        "pre-fill the session command channel so policy hot-apply send blocks"
    );
    let (finish_tx, finish_rx) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        let _session_rx = session_rx;
        let _ = finish_rx.await;
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
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    insert_test_managed_peer(&mut mgr, addr, handle, false);

    let result = mgr
        .update_runtime_policies(addr, Some(deny_policy_chain()), None)
        .await;

    assert!(
        result.is_err(),
        "full session command channel must surface as a failed hot-apply, not a \
         silent policy success. Got: {result:?}"
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("timed out") && err.contains("import:"),
        "error should preserve the channel-full timeout detail: {err}"
    );
    let managed = mgr.peers.get(&key(addr)).expect("peer remains managed");
    assert!(
        managed.pending_refresh,
        "pending_refresh must be set so a later policy update retries after the \
         session command channel drains"
    );
    assert!(
        managed.import_policy.is_none(),
        "daemon bookkeeping must not advance when the session command never accepted \
         the import-policy update"
    );

    let _ = finish_tx.send(());
}

#[tokio::test]
async fn channel_full_soft_reset_in_returns_timeout_instead_of_wedging_manager() {
    use rustbgpd_transport::PeerCommand;

    let (session_tx, session_rx) = mpsc::channel::<PeerCommand>(1);
    assert!(
        session_tx.try_send(PeerCommand::Start).is_ok(),
        "pre-fill the session command channel so route-refresh send blocks"
    );
    let (finish_tx, finish_rx) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        let _session_rx = session_rx;
        let _ = finish_rx.await;
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
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    insert_test_managed_peer(&mut mgr, addr, handle, false);

    let result = tokio::time::timeout(
        Duration::from_secs(2),
        mgr.soft_reset_in(key(addr), vec![(Afi::Ipv4, Safi::Unicast)]),
    )
    .await
    .expect("soft_reset_in should return under the lifecycle command deadline");

    assert!(
        result.is_err(),
        "full session command channel must surface as a failed soft reset, not a silent success"
    );
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("timed out") && err.contains("route refresh"),
        "error should preserve the channel-full route-refresh timeout detail: {err}"
    );

    let _ = finish_tx.send(());
}

#[tokio::test]
async fn channel_full_disable_peer_returns_timeout_instead_of_wedging_manager() {
    use rustbgpd_transport::PeerCommand;

    let (session_tx, session_rx) = mpsc::channel::<PeerCommand>(1);
    assert!(
        session_tx.try_send(PeerCommand::Start).is_ok(),
        "pre-fill the session command channel so stop send blocks"
    );
    let (finish_tx, finish_rx) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        let _session_rx = session_rx;
        let _ = finish_rx.await;
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
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    insert_test_managed_peer(&mut mgr, addr, handle, false);

    let result = tokio::time::timeout(Duration::from_secs(2), mgr.disable_peer(key(addr), None))
        .await
        .expect("disable_peer should return under the lifecycle command deadline");

    assert!(
        result.is_err(),
        "full session command channel must surface as a failed disable, not a silent success"
    );
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("timed out") && err.contains("stop"),
        "error should preserve the channel-full stop timeout detail: {err}"
    );
    assert!(
        !mgr.peers
            .get(&key(addr))
            .expect("peer remains managed")
            .enabled,
        "disable marks desired admin state before signaling the stuck session"
    );

    let _ = finish_tx.send(());
}
