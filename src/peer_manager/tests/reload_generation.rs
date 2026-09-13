use super::*;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Weak;

use crate::config::{
    PreparedDatasetGeneration, ReloadPeerAction, ReloadPeerActionKind, plan_reload_peer_actions,
};
use crate::peer_manager::generation::ReloadGenerationOutcome;
use rustbgpd_policy::PolicyAction;

/// Per-session counters for the fake sessions a generation drives.
#[derive(Default)]
struct GenerationSessionCounters {
    import_installs: AtomicU32,
    export_installs: AtomicU32,
    runtime_config_updates: AtomicU32,
    runtime_remove_private_as: Mutex<Option<rustbgpd_transport::RemovePrivateAs>>,
    route_refreshes: AtomicU32,
    refresh_families: Mutex<Vec<(Afi, Safi)>>,
    refresh_failures: Mutex<std::collections::VecDeque<rustbgpd_transport::PeerCommandError>>,
    states: Mutex<std::collections::VecDeque<SessionState>>,
    no_route_refresh: AtomicBool,
    state_queries: AtomicU32,
    drop_state_after: AtomicU32,
    export_owners: Mutex<Vec<PolicyOwners>>,
}

fn generation_session(addr: IpAddr) -> (PeerHandle, Arc<GenerationSessionCounters>) {
    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(16);
    let (publication, receiver) =
        tokio::sync::watch::channel(Some(installed_policy(1, Some(&PolicyChain::new(vec![])))));
    let counters = Arc::new(GenerationSessionCounters::default());
    let in_task = counters.clone();
    let task = tokio::spawn(async move {
        while let Some(command) = session_rx.recv().await {
            match command {
                PeerCommand::UpdateImportPolicy { policy, reply } => {
                    let generation = in_task.import_installs.fetch_add(1, Ordering::SeqCst) + 2;
                    publication.send_replace(Some(installed_policy(
                        u64::from(generation),
                        policy.as_deref(),
                    )));
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::UpdateExportPolicy { policy, reply } => {
                    if let Some(owners) = policy.as_deref().and_then(PolicyOwners::observe) {
                        in_task.export_owners.lock().unwrap().push(owners);
                    }
                    in_task.export_installs.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::UpdateRuntimeConfig { config, reply } => {
                    *in_task.runtime_remove_private_as.lock().unwrap() =
                        Some(config.remove_private_as);
                    in_task
                        .runtime_config_updates
                        .fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::SendRouteRefresh { afi, safi, reply } => {
                    in_task.refresh_families.lock().unwrap().push((afi, safi));
                    in_task.route_refreshes.fetch_add(1, Ordering::SeqCst);
                    let outcome = in_task
                        .refresh_failures
                        .lock()
                        .unwrap()
                        .pop_front()
                        .map_or(Ok(()), Err);
                    let _ = reply.send(outcome);
                }
                PeerCommand::QueryImportPolicyTermHits { reply } => {
                    let _ = reply.send(Some(rustbgpd_transport::ImportPolicyTermHits {
                        generation: 1,
                        evals: 0,
                        eval_errors: 0,
                        last_error: None,
                        terms: Vec::new(),
                    }));
                }
                PeerCommand::QueryState { reply } => {
                    let query = in_task.state_queries.fetch_add(1, Ordering::SeqCst) + 1;
                    let drop_after = in_task.drop_state_after.load(Ordering::SeqCst);
                    if drop_after != 0 && query >= drop_after {
                        drop(reply);
                        continue;
                    }
                    let fsm = {
                        let mut states = in_task.states.lock().unwrap();
                        if states.len() > 1 {
                            states.pop_front().unwrap()
                        } else {
                            states.front().copied().unwrap_or(SessionState::Established)
                        }
                    };
                    let mut state = policy_test_peer_state(addr, fsm);
                    state.negotiated_session = Some(test_negotiated_session(
                        !in_task.no_route_refresh.load(Ordering::SeqCst),
                    ));
                    state.negotiated_hold_time = Some(90);
                    state.four_octet_as = Some(true);
                    let _ = reply.send(state);
                }
                PeerCommand::Shutdown | PeerCommand::Stop { .. } => break,
                _ => {}
            }
        }
        drop(publication);
        Ok(())
    });
    (
        PeerHandle::from_parts_with_import_policy_counters(session_tx, task, receiver),
        counters,
    )
}

/// A RIB stub that acknowledges every export-policy transition shape the
/// policy snapshot and its rollback can issue.
fn spawn_generation_rib(
    drop_refresh_reply: bool,
) -> (mpsc::Sender<RibUpdate>, tokio::task::JoinHandle<()>) {
    let (rib_tx, mut rib_rx) = mpsc::channel::<RibUpdate>(256);
    let drainer = tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            match update {
                RibUpdate::ReplacePeerExportPolicy { reply, .. }
                | RibUpdate::ReplacePeerExportPoliciesAuthoritatively { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                RibUpdate::RefreshPeerOutbound { reply, .. }
                | RibUpdate::ReevaluatePeerExportPolicies { reply, .. } => {
                    if !drop_refresh_reply {
                        let _ = reply.send(Ok(()));
                    }
                }
                RibUpdate::ReplacePeerExportPolicies { reply, .. } => {
                    let _ = reply.send(Ok(rustbgpd_rib::ExportPolicyCohortOutcome::Committed));
                }
                RibUpdate::RestorePeerExportPoliciesAuthoritatively {
                    replacements,
                    reply,
                } => {
                    let receipts = replacements
                        .iter()
                        .rev()
                        .map(
                            |replacement| rustbgpd_rib::PeerExportPolicyRestoreReceipt::Restored {
                                peer: replacement.peer,
                            },
                        )
                        .collect();
                    let _ = reply.send(Ok(receipts));
                }
                RibUpdate::PrepareExportPolicyDestination { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                RibUpdate::QueryPeerRetainedStale { reply, .. } => {
                    let _ = reply.send(0);
                }
                _ => {}
            }
        }
    });
    (rib_tx, drainer)
}

struct GenerationHarness {
    mgr: PeerManager,
    counters: BTreeMap<IpAddr, Arc<GenerationSessionCounters>>,
    rib: tokio::task::JoinHandle<()>,
}

impl GenerationHarness {
    /// A manager running `config` with one fake Established session per
    /// static neighbor, installed from the same resolution the reload
    /// planner compares against.
    fn new(config: &Config) -> Self {
        let (_tx, rx) = mpsc::channel(16);
        let (rib_tx, rib) = spawn_generation_rib(false);
        let mut mgr = PeerManager::new_with_config(
            rx,
            mpsc::channel(1).1,
            config.global.asn,
            config.global.router_id.parse().unwrap(),
            None,
            None,
            BgpMetrics::new(),
            rib_tx,
            None,
            None,
            config.clone(),
        );
        let mut counters = BTreeMap::new();
        for (index, resolved) in config.resolved_neighbors().unwrap().into_iter().enumerate() {
            let addr = resolved.transport_config.remote_addr.ip();
            let (handle, session_counters) = generation_session(addr);
            counters.insert(addr, session_counters);
            let session_id = u64::try_from(index).unwrap() + 1;
            let peer_key = key(addr);
            let tcp_ao_protected = resolved.transport_config.tcp_ao.is_some();
            mgr.peers.insert(
                peer_key.clone(),
                ManagedPeer {
                    handle,
                    session_id,
                    remote_asn: resolved.transport_config.peer.remote_asn,
                    description: resolved.label,
                    peer_group: resolved.peer_group,
                    enabled: true,
                    hold_time: Some(resolved.transport_config.peer.hold_time),
                    max_prefixes: resolved.transport_config.max_prefixes,
                    max_prefix_restart_seconds: resolved.max_prefix_restart_seconds,
                    transport_config: resolved.transport_config,
                    import_policy: resolved.import_policy,
                    export_policy: resolved.export_policy,
                    pending_inbound: None,
                    is_dynamic: false,
                    rfc8212_external: resolved.rfc8212_external,
                    tcp_ao_protected,
                    tcp_ao_rotation: TcpAoRotationStatus::default(),
                    accepted_dynamic_range: None,
                    pending_refresh: false,
                    pending_export_apply: false,
                    advertise_graceful_shutdown: false,
                },
            );
            mgr.register_session(session_id, &peer_key);
            mgr.next_session_id = session_id + 1;
        }
        Self { mgr, counters, rib }
    }

    fn session_id(&self, address: &str) -> u64 {
        self.mgr.peers[&key(address.parse().unwrap())].session_id
    }

    fn export_installs(&self, address: &str) -> u32 {
        self.counters[&address.parse::<IpAddr>().unwrap()]
            .export_installs
            .load(Ordering::SeqCst)
    }

    fn runtime_config_updates(&self, address: &str) -> u32 {
        self.counters[&address.parse::<IpAddr>().unwrap()]
            .runtime_config_updates
            .load(Ordering::SeqCst)
    }

    fn export_med(&self, address: &str) -> Option<u32> {
        let chain = self.mgr.peers[&key(address.parse().unwrap())]
            .export_policy
            .as_ref()
            .expect("export chain installed");
        chain.evaluate(&sample_route()).modifications.set_med
    }

    async fn apply(&mut self, candidate: &Config) -> ReloadGenerationOutcome {
        let actions = plan_reload_peer_actions(&self.mgr.current_config, candidate).unwrap();
        Box::pin(self.mgr.apply_reload_generation(
            candidate.clone(),
            actions,
            PreparedDatasetGeneration::default(),
        ))
        .await
    }

    async fn shutdown(mut self) {
        for (_, managed) in self.mgr.peers.drain() {
            let _ = managed.handle.shutdown().await;
        }
    }
}

/// Use the same emitted A/B policy files as the mixed dual-stack filtering
/// measurement, with three changed members and one stable member.
fn generated_filter_fixture() -> RsFixture {
    let dir = tempfile::tempdir().unwrap();
    let output = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/bench/scale/reloadstall/gen-scenario.py"
        ))
        .arg("4")
        .arg(dir.path())
        .args(["1790", "3"])
        .env("GEN_DUALSTACK", "1")
        .env("GEN_FILTER_COUNT", "1")
        .env_remove("GEN_IBGP_RR_ASN")
        .env_remove("GEN_TRIP_MAX_PREFIXES")
        .env_remove("GEN_TRIP_RESTART_SECONDS")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    RsFixture {
        config_path: dir.path().join("config.toml"),
        dir,
    }
}

type GenerationPolicyCommands = Arc<Mutex<Vec<(&'static str, Vec<IpAddr>)>>>;

fn record_generation_policy_commands(
    harness: &mut GenerationHarness,
) -> (GenerationPolicyCommands, tokio::task::JoinHandle<()>) {
    let (tx, mut rx) = mpsc::channel::<RibUpdate>(64);
    let downstream = std::mem::replace(&mut harness.mgr.rib_tx, tx);
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let commands = Arc::clone(&recorded);
    let task = tokio::spawn(async move {
        while let Some(command) = rx.recv().await {
            let entry = match &command {
                RibUpdate::PrepareExportPolicyDestination { peer, .. } => {
                    Some(("prepare", vec![*peer]))
                }
                RibUpdate::ReplacePeerExportPolicy { peer, .. } => Some(("replace", vec![*peer])),
                RibUpdate::ReplacePeerExportPolicies { replacements, .. }
                | RibUpdate::ReplacePeerExportPoliciesAuthoritatively { replacements, .. } => {
                    Some((
                        "replace",
                        replacements
                            .iter()
                            .map(|replacement| replacement.peer)
                            .collect(),
                    ))
                }
                RibUpdate::RestorePeerExportPoliciesAuthoritatively { replacements, .. } => Some((
                    "restore",
                    replacements
                        .iter()
                        .map(|replacement| replacement.peer)
                        .collect(),
                )),
                RibUpdate::RefreshPeerOutbound { peer, .. } => Some(("refresh", vec![*peer])),
                RibUpdate::ReevaluatePeerExportPolicies { peers, .. } => {
                    Some(("reevaluate", peers.clone()))
                }
                _ => None,
            };
            if let Some(entry) = entry {
                commands.lock().unwrap().push(entry);
            }
            if downstream.send(command).await.is_err() {
                break;
            }
        }
    });
    (recorded, task)
}

type PolicyCounterPair = (
    Arc<rustbgpd_policy::PolicyHitCounters>,
    Arc<rustbgpd_policy::PolicyHitCounters>,
);

fn installed_policy_counters(harness: &GenerationHarness) -> BTreeMap<IpAddr, PolicyCounterPair> {
    harness
        .mgr
        .peers
        .iter()
        .map(|(peer, managed)| {
            let import = managed.import_policy.as_ref().unwrap();
            let export = managed.export_policy.as_ref().unwrap();
            let _ = import.evaluate(&sample_route());
            let _ = export.evaluate(&sample_route());
            (
                peer.address,
                (
                    Arc::clone(import.hit_counters()),
                    Arc::clone(export.hit_counters()),
                ),
            )
        })
        .collect()
}

#[tokio::test]
async fn generated_filter_generation_skips_unused_source_sets_and_keeps_installed_counters() {
    let fixture = generated_filter_fixture();
    let prior = fixture.load();
    let mut harness = GenerationHarness::new(&prior);
    let counters = installed_policy_counters(&harness);
    let (rib_commands, relay) = record_generation_policy_commands(&mut harness);
    let stable: IpAddr = "127.1.0.4".parse().unwrap();
    for generation in ["b", "a", "b"] {
        std::fs::copy(
            fixture.dir.path().join(format!("gen-{generation}.rpol")),
            fixture.dir.path().join("member.rpol"),
        )
        .unwrap();
        let candidate = fixture.load();
        let before = harness.mgr.peers[&key(stable)]
            .export_policy
            .as_ref()
            .unwrap();
        let next = candidate.resolve_neighbor(&candidate.neighbors[3]).unwrap();
        if generation == "b" {
            assert_ne!(before, next.export_policy.as_ref().unwrap());
        }
        assert_eq!(
            before.compiled(),
            next.export_policy.as_ref().unwrap().compiled()
        );
        let outcome = harness.apply(&candidate).await;
        let ReloadGenerationOutcome::Applied(receipt) = outcome else {
            panic!("{outcome:?}");
        };
        assert_eq!(receipt.policy_updated, 3);
        assert_eq!(
            harness.mgr.current_config, candidate,
            "candidate catalog adopted"
        );
        for (peer, managed) in &harness.mgr.peers {
            assert!(Arc::ptr_eq(
                managed.import_policy.as_ref().unwrap().hit_counters(),
                &counters[&peer.address].0
            ));
            assert!(counters[&peer.address].0.evals() > 0);
            assert_eq!(
                harness.counters[&peer.address]
                    .import_installs
                    .load(Ordering::SeqCst),
                0
            );
            assert_eq!(
                harness.counters[&peer.address]
                    .route_refreshes
                    .load(Ordering::SeqCst),
                0
            );
        }
        assert!(Arc::ptr_eq(
            harness.mgr.peers[&key(stable)]
                .export_policy
                .as_ref()
                .unwrap()
                .hit_counters(),
            &counters[&stable].1
        ));
        assert_eq!(harness.export_installs("127.1.0.4"), 0);
    }
    let commands = rib_commands.lock().unwrap().clone();
    assert_eq!(
        commands
            .iter()
            .filter(|(kind, _)| *kind == "replace")
            .count(),
        3
    );
    assert!(commands.iter().all(|(_, peers)| !peers.contains(&stable)));
    for peer in ["127.1.0.1", "127.1.0.2", "127.1.0.3"] {
        assert_eq!(harness.export_installs(peer), 3);
    }
    harness.shutdown().await;
    relay.await.unwrap();
}

#[tokio::test]
async fn generated_filter_noop_hot_update_and_late_rollback_preserve_installed_policies() {
    for compensate in [false, true] {
        let fixture = generated_filter_fixture();
        let prior = fixture.load();
        let mut harness = GenerationHarness::new(&prior);
        let counters = installed_policy_counters(&harness);
        let (rib_commands, relay) = record_generation_policy_commands(&mut harness);
        let stable: IpAddr = "127.1.0.4".parse().unwrap();
        std::fs::copy(
            fixture.dir.path().join("gen-b.rpol"),
            fixture.dir.path().join("member.rpol"),
        )
        .unwrap();
        let mut candidate = fixture.load();
        candidate.neighbors[3].max_prefixes = Some(1000);
        if compensate {
            candidate.neighbors[2].hold_time = Some(60);
            harness
                .mgr
                .inject_reconfigure_failures
                .insert(key("127.1.0.3".parse().unwrap()), 0);
        }
        let outcome = harness.apply(&candidate).await;
        if compensate {
            assert!(
                matches!(outcome, ReloadGenerationOutcome::FullyCompensated(_)),
                "{outcome:?}"
            );
            assert_eq!(harness.mgr.current_config, prior);
            assert_eq!(
                harness.mgr.peers[&key(stable)].max_prefixes,
                prior.neighbors[3].max_prefixes
            );
        } else {
            let ReloadGenerationOutcome::Applied(receipt) = outcome else {
                panic!("{outcome:?}")
            };
            assert_eq!(receipt.policy_updated, 3);
            assert_eq!(receipt.hot_updated, 1);
            assert_eq!(harness.mgr.current_config, candidate);
            assert_eq!(harness.mgr.peers[&key(stable)].max_prefixes, Some(1000));
        }
        assert_eq!(
            harness.runtime_config_updates("127.1.0.4"),
            if compensate { 2 } else { 1 }
        );
        assert_eq!(harness.export_installs("127.1.0.4"), 0);
        assert_eq!(
            harness.counters[&stable]
                .import_installs
                .load(Ordering::SeqCst),
            0
        );
        assert_eq!(
            harness.counters[&stable]
                .route_refreshes
                .load(Ordering::SeqCst),
            0
        );
        let installed = &harness.mgr.peers[&key(stable)];
        assert!(Arc::ptr_eq(
            installed.import_policy.as_ref().unwrap().hit_counters(),
            &counters[&stable].0
        ));
        assert!(Arc::ptr_eq(
            installed.export_policy.as_ref().unwrap().hit_counters(),
            &counters[&stable].1
        ));
        assert!(
            rib_commands
                .lock()
                .unwrap()
                .iter()
                .all(|(_, peers)| !peers.contains(&stable))
        );
        for changed in ["127.1.0.1", "127.1.0.2"] {
            assert_eq!(
                harness.export_installs(changed),
                if compensate { 2 } else { 1 }
            );
        }
        assert_eq!(
            std::fs::read(fixture.dir.path().join("member.rpol")).unwrap(),
            std::fs::read(fixture.dir.path().join("gen-b.rpol")).unwrap()
        );
        harness.shutdown().await;
        relay.await.unwrap();
    }
}

#[tokio::test]
async fn generated_filter_noop_keeps_pending_import_and_export_retry_work() {
    let fixture = generated_filter_fixture();
    let prior = fixture.load();
    let mut harness = GenerationHarness::new(&prior);
    let (rib_commands, relay) = record_generation_policy_commands(&mut harness);
    let stable: IpAddr = "127.1.0.4".parse().unwrap();
    let managed = harness.mgr.peers.get_mut(&key(stable)).unwrap();
    managed.pending_refresh = true;
    managed.pending_export_apply = true;
    std::fs::copy(
        fixture.dir.path().join("gen-b.rpol"),
        fixture.dir.path().join("member.rpol"),
    )
    .unwrap();
    let candidate = fixture.load();
    let outcome = harness.apply(&candidate).await;
    let ReloadGenerationOutcome::Applied(receipt) = outcome else {
        panic!("{outcome:?}")
    };
    assert_eq!(
        receipt.policy_updated, 4,
        "existing retry target is retained"
    );
    assert_eq!(harness.export_installs("127.1.0.4"), 0);
    assert_eq!(
        harness.counters[&stable]
            .import_installs
            .load(Ordering::SeqCst),
        0
    );
    assert_eq!(
        harness.counters[&stable]
            .route_refreshes
            .load(Ordering::SeqCst),
        2
    );
    assert_eq!(
        *harness.counters[&stable].refresh_families.lock().unwrap(),
        vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)]
    );
    assert!(
        rib_commands
            .lock()
            .unwrap()
            .iter()
            .any(|(kind, peers)| *kind == "replace" && peers.contains(&stable))
    );
    assert!(!harness.mgr.peers[&key(stable)].pending_refresh);
    assert!(!harness.mgr.peers[&key(stable)].pending_export_apply);
    harness.shutdown().await;
    relay.await.unwrap();
}

#[tokio::test]
async fn exact_equal_generation_retries_each_pending_direction() {
    for (pending_refresh, pending_export_apply) in
        [(false, false), (true, false), (false, true), (true, true)]
    {
        let fixture = generated_filter_fixture();
        let prior = fixture.load();
        let mut harness = GenerationHarness::new(&prior);
        let (rib_commands, relay) = record_generation_policy_commands(&mut harness);
        let stable: IpAddr = "127.1.0.4".parse().unwrap();
        let managed = harness.mgr.peers.get_mut(&key(stable)).unwrap();
        managed.pending_refresh = pending_refresh;
        managed.pending_export_apply = pending_export_apply;
        let resolved = prior.resolve_neighbor(&prior.neighbors[3]).unwrap();
        assert_eq!(managed.import_policy, resolved.import_policy);
        assert_eq!(managed.export_policy, resolved.export_policy);

        let outcome = harness.apply(&prior).await;
        let ReloadGenerationOutcome::Applied(receipt) = outcome else {
            panic!("{outcome:?}")
        };
        assert_eq!(
            receipt.policy_updated,
            usize::from(pending_refresh || pending_export_apply)
        );
        for (address, counters) in &harness.counters {
            assert_eq!(counters.import_installs.load(Ordering::SeqCst), 0);
            assert_eq!(counters.export_installs.load(Ordering::SeqCst), 0);
            let expected = if *address == stable && pending_refresh {
                vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)]
            } else {
                Vec::new()
            };
            assert_eq!(*counters.refresh_families.lock().unwrap(), expected);
        }
        let commands = rib_commands.lock().unwrap().clone();
        let replaced: Vec<_> = commands
            .iter()
            .filter(|(kind, _)| *kind == "replace")
            .flat_map(|(_, peers)| peers.iter().copied())
            .collect();
        assert_eq!(
            replaced,
            if pending_export_apply {
                vec![stable]
            } else {
                Vec::new()
            }
        );
        assert!(
            commands
                .iter()
                .all(|(_, peers)| peers.iter().all(|peer| *peer == stable))
        );
        assert!(!harness.mgr.peers[&key(stable)].pending_refresh);
        assert!(!harness.mgr.peers[&key(stable)].pending_export_apply);
        harness.shutdown().await;
        relay.await.unwrap();
    }
}

#[tokio::test]
async fn generation_policy_normalization_preserves_referenced_sets_and_loop_fallback() {
    let prefix_policy = "prefix-set selected { 20.0.0.0/24 }\npolicy members-out { term selected { if route.prefix in selected { accept } } term rest { reject } }";
    let loop_policy = "community-set selected { 65000:1 }\npolicy members-out { term all { for c in route.communities { if c in selected { reject } } accept } }";
    for (before, after, compiled_equal) in [
        (
            prefix_policy,
            prefix_policy.replace("20.0.0.0/24", "20.0.1.0/24"),
            false,
        ),
        (
            prefix_policy,
            prefix_policy.replace("selected", "renamed"),
            false,
        ),
        (
            "asn-set selected { 65001 } policy members-out { term t { let x = route.origin-as; if x in selected { reject } accept } }",
            "asn-set selected { 65002 } policy members-out { term t { let x = route.origin-as; if x in selected { reject } accept } }".to_string(),
            true,
        ),
        (
            "community-set selected { 65000:1 } policy members-out { term t { let x = 4259840001; if x in selected { reject } accept } }",
            "community-set selected { 65000:2 } policy members-out { term t { let x = 4259840001; if x in selected { reject } accept } }".to_string(),
            true,
        ),
        (RS_RPOL_MED_10, RS_RPOL_MED_20.to_string(), false),
        // Nested loop guards are not remapped by RPOL splicing. Even if its
        // projected chain compares equal, keep this source change actionable.
        (loop_policy, loop_policy.replace("65000:1", "65000:2"), true),
    ] {
        let fixture = RsFixture::new();
        let path = fixture.dir.path().join("members.rpol");
        std::fs::write(&path, before).unwrap();
        let prior = fixture.load();
        let mut harness = GenerationHarness::new(&prior);
        let (rib_commands, relay) = record_generation_policy_commands(&mut harness);
        std::fs::write(path, after).unwrap();
        let candidate = fixture.load();
        let old = prior
            .resolve_neighbor(&prior.neighbors[0])
            .unwrap()
            .export_policy
            .unwrap();
        let next = candidate
            .resolve_neighbor(&candidate.neighbors[0])
            .unwrap()
            .export_policy
            .unwrap();
        assert_ne!(old, next);
        assert_eq!(old.compiled() == next.compiled(), compiled_equal);
        let outcome = harness.apply(&candidate).await;
        let ReloadGenerationOutcome::Applied(receipt) = outcome else {
            panic!("{outcome:?}")
        };
        assert_eq!(receipt.policy_updated, 3);
        assert!(
            harness
                .counters
                .values()
                .all(|counters| counters.export_installs.load(Ordering::SeqCst) == 1)
        );
        assert_eq!(
            rib_commands
                .lock()
                .unwrap()
                .iter()
                .filter(|(kind, _)| *kind == "replace")
                .flat_map(|(_, peers)| peers)
                .count(),
            3
        );
        harness.shutdown().await;
        relay.await.unwrap();
    }
}

#[tokio::test]
async fn generation_policy_normalization_keeps_collapsed_alias_names_across_sources() {
    for (kind, value, other_value, third_value, expression) in [
        (
            "prefix-set",
            "20.0.0.0/24",
            "20.0.1.0/24",
            "20.0.2.0/24",
            "route.prefix",
        ),
        (
            "community-set",
            "65000:1",
            "65000:2",
            "65000:3",
            "route.communities",
        ),
        ("asn-set", "65001", "65002", "65003", "route.origin-as"),
    ] {
        let fixture = RsFixture::new();
        let path = fixture.dir.path().join("members.rpol");
        let other = fixture.dir.path().join("other.rpol");
        let source = format!(
            "{kind} first {{ {value} }} {kind} alias {{ {value} }} \
             policy members-out {{ \
             term first {{ if {expression} in first {{ accept }} }} \
             term second {{ if {expression} in alias {{ reject }} }} }}"
        );
        std::fs::write(&path, &source).unwrap();
        // Same names survive in another source, but for different table Arcs.
        // A name-only lookup must not hide the first source's lost alias.
        std::fs::write(
            &other,
            format!(
                "{kind} alias {{ {other_value} }} {kind} renamed {{ {third_value} }} \
             policy other {{ term one {{ if {expression} in alias {{ accept }} }} \
             term two {{ if {expression} in renamed {{ reject }} }} }}"
            ),
        )
        .unwrap();
        fixture.write_toml(
            &fixture
                .base_toml()
                .replace(
                    &format!("rpol_files = [{:?}]", path.to_str().unwrap()),
                    &format!(
                        "rpol_files = [{:?}, {:?}]",
                        path.to_str().unwrap(),
                        other.to_str().unwrap()
                    ),
                )
                .replace("[\"members-out\"]", "[\"other\", \"members-out\"]"),
        );
        let prior = fixture.load();
        let mut harness = GenerationHarness::new(&prior);
        std::fs::write(&path, source.replace("alias", "renamed")).unwrap();
        let candidate = fixture.load();
        let old = prior
            .resolve_neighbor(&prior.neighbors[0])
            .unwrap()
            .export_policy
            .unwrap();
        let next = candidate
            .resolve_neighbor(&candidate.neighbors[0])
            .unwrap()
            .export_policy
            .unwrap();
        assert_ne!(old, next, "{kind}");
        assert_eq!(
            old.compiled(),
            next.compiled(),
            "{kind}: alias is collapsed"
        );
        let outcome = harness.apply(&candidate).await;
        let ReloadGenerationOutcome::Applied(receipt) = outcome else {
            panic!("{outcome:?}")
        };
        assert_eq!(receipt.policy_updated, 3, "{kind}");
        assert!(
            harness
                .counters
                .values()
                .all(|counters| counters.export_installs.load(Ordering::SeqCst) == 1)
        );
        harness.shutdown().await;
    }
}

#[tokio::test]
async fn generation_policy_normalization_keeps_defaults_asn_names_and_presence_distinct() {
    for difference in ["default", "local_asn", "name", "none", "toml"] {
        let fixture = RsFixture::new();
        let candidate = fixture.load();
        let mut harness = GenerationHarness::new(&candidate);
        for managed in harness.mgr.peers.values_mut() {
            let mut prior = managed.export_policy.take().unwrap().clone();
            match difference {
                "default" => {
                    let rpol = Arc::make_mut(prior.policies[0].rpol.as_mut().unwrap());
                    rpol.policies[0].default_action = match rpol.policies[0].default_action {
                        PolicyAction::Permit => PolicyAction::Deny,
                        PolicyAction::Deny => PolicyAction::Permit,
                    };
                }
                "local_asn" => {
                    Arc::make_mut(prior.policies[0].rpol.as_mut().unwrap()).local_asn = Some(65099);
                }
                "name" => prior.policies[0].name = Some("prior-name".into()),
                "none" => continue,
                "toml" => prior.policies[0].rpol = None,
                _ => unreachable!(),
            }
            managed.export_policy = Some(prior);
        }
        let outcome = harness.apply(&candidate).await;
        let ReloadGenerationOutcome::Applied(receipt) = outcome else {
            panic!("{difference}: {outcome:?}")
        };
        assert_eq!(receipt.policy_updated, 3, "{difference}");
        assert!(
            harness
                .counters
                .values()
                .all(|counters| counters.export_installs.load(Ordering::SeqCst) == 1),
            "{difference}"
        );
        harness.shutdown().await;
    }
}

fn sample_route() -> rustbgpd_policy::RouteContext<'static> {
    rustbgpd_policy::RouteContext {
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
    }
}

/// A dual-stack route server: a source, two group members, and a bystander
/// outside the group that references the same real `.rpol` export policy
/// through its own chain, so an `.rpol` edit moves its policy without any
/// session change.
struct RsFixture {
    dir: tempfile::TempDir,
    config_path: PathBuf,
}

const RS_RPOL_MED_10: &str = "policy members-out { term all { set med 10; accept } }";
const RS_RPOL_MED_20: &str = "policy members-out { term all { set med 20; accept } }";

impl RsFixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("members.rpol"), RS_RPOL_MED_10).unwrap();
        let config_path = dir.path().join("config.toml");
        let fixture = Self { dir, config_path };
        fixture.write_toml(&Self::base_toml(&fixture));
        fixture
    }

    fn base_toml(&self) -> String {
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[policy]
rpol_files = [{rpol:?}]

[peer_groups.members]
hold_time = 90
max_prefixes = 1000
export_policy_chain = ["members-out"]

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "members"

[[neighbors]]
address = "2001:db8::3"
remote_asn = 65003
peer_group = "members"

[[neighbors]]
address = "10.0.0.9"
remote_asn = 65009
hold_time = 180
export_policy_chain = ["members-out"]
"#,
            rpol = self.dir.path().join("members.rpol").to_str().unwrap()
        )
    }

    fn write_toml(&self, toml: &str) {
        std::fs::write(&self.config_path, tier_authorized_uds_test_config(toml)).unwrap();
    }

    fn load(&self) -> Config {
        Config::load_with_diagnostics(self.config_path.to_str().unwrap()).unwrap()
    }

    /// The candidate: `.rpol` export MED 10 -> 20, group `hold_time` 90 -> 60
    /// (a session reshape for both members), and member 10.0.0.2 also edits
    /// its own session-bound `remote_asn`. The bystander's session is
    /// untouched; only its export chain moves.
    fn compound_candidate(&self) -> Config {
        std::fs::write(self.dir.path().join("members.rpol"), RS_RPOL_MED_20).unwrap();
        self.write_toml(
            &self
                .base_toml()
                .replace("hold_time = 90", "hold_time = 60")
                .replace("remote_asn = 65002", "remote_asn = 65012"),
        );
        self.load()
    }
}

/// Hold real policy transaction messages while forwarding unrelated RIB work
/// to the existing stub. The rollback hold starts only after forward commit.
#[expect(
    clippy::too_many_lines,
    reason = "the held forward and rollback acknowledgements share one complete generation fixture"
)]
async fn assert_generation_operator_read_boundaries(
    compensate: bool,
    failed_hot_restore: bool,
    dataset: bool,
) {
    let fixture = if dataset {
        dataset_generation_fixture()
    } else {
        RsFixture::new()
    };
    let prior = fixture.load();
    let mut harness = GenerationHarness::new(&prior);
    let (mut candidate, prepared) = if dataset {
        harness
            .mgr
            .inject_reconfigure_failures
            .insert(key("10.0.0.2".parse().unwrap()), 0);
        let (mut candidate, prepared) = prepare_dataset_candidate(&fixture, &prior);
        candidate.neighbors[0].remote_asn = 65012;
        (candidate, prepared)
    } else {
        (
            if compensate {
                harness
                    .mgr
                    .inject_reconfigure_failures
                    .insert(key("10.0.0.2".parse().unwrap()), 0);
                std::fs::write(fixture.dir.path().join("members.rpol"), RS_RPOL_MED_20).unwrap();
                // Leave two policy-only members to exercise the cohort in both
                // directions; the sole replacement fails before any socket work.
                fixture.write_toml(
                    &fixture
                        .base_toml()
                        .replace("remote_asn = 65002", "remote_asn = 65012"),
                );
                fixture.load()
            } else {
                std::fs::write(fixture.dir.path().join("members.rpol"), RS_RPOL_MED_20).unwrap();
                fixture.load()
            },
            PreparedDatasetGeneration::default(),
        )
    };
    if failed_hot_restore {
        candidate.neighbors[2].remove_private_as = Some("all".to_string());
    }
    let (command_tx, command_rx) = mpsc::channel(16);
    harness.mgr.rx = command_rx;
    let (internal_tx, internal_rx) = mpsc::channel(1);
    harness.mgr.internal_rx = Some(internal_rx);
    let (operator_tx, operator_rx) = mpsc::channel(16);
    harness.mgr = harness.mgr.with_operator_queries(operator_rx);
    let (readiness_tx, readiness_rx) = mpsc::channel(4);
    harness.mgr = harness.mgr.with_readiness_queries(readiness_rx);
    let rib_tx = harness.mgr.rib_tx.clone();
    let (proxy_tx, mut proxy_rx) = mpsc::channel(16);
    harness.mgr.rib_tx = proxy_tx;
    let (held_tx, mut held_rx) = mpsc::channel(2);
    let forwarding_tx = rib_tx.clone();
    let proxy = tokio::spawn(async move {
        let mut saw_replace = false;
        let mut held_prepare = false;
        let mut held_replace = false;
        let mut refreshes = 0;
        while let Some(update) = proxy_rx.recv().await {
            if failed_hot_restore && matches!(update, RibUpdate::RefreshPeerOutbound { .. }) {
                refreshes += 1;
                if refreshes == 2 {
                    // The session restored its prior knobs, but this lost RIB
                    // reply prevents manager transport bookkeeping advancing.
                    drop(update);
                    continue;
                }
            }
            let hold = match &update {
                RibUpdate::ReevaluatePeerExportPolicies { .. } if dataset && refreshes == 2 => true,
                RibUpdate::PrepareExportPolicyDestination { .. }
                    if !held_prepare
                        && ((!failed_hot_restore && (!compensate || saw_replace))
                            || (failed_hot_restore && refreshes == 2)) =>
                {
                    held_prepare = true;
                    true
                }
                RibUpdate::ReplacePeerExportPolicies { .. } => {
                    saw_replace = true;
                    let hold = !compensate && !held_replace;
                    held_replace = true;
                    hold
                }
                _ => false,
            };
            if hold {
                held_tx.send(update).await.unwrap();
            } else {
                forwarding_tx.send(update).await.unwrap();
            }
        }
    });
    let counters = harness.counters.clone();
    let driver = async {
        let prepare = held_rx.recv().await.expect("held destination prepare");
        assert!(if dataset {
            matches!(prepare, RibUpdate::ReevaluatePeerExportPolicies { .. })
        } else {
            matches!(prepare, RibUpdate::PrepareExportPolicyDestination { .. })
        });
        let mut prepare = Some(prepare);
        let (mutation_reply, mut mutation_response) = oneshot::channel();
        command_tx
            .send(PeerManagerCommand::EnablePeer {
                peer: key("10.0.0.2".parse().unwrap()),
                reply: mutation_reply,
            })
            .await
            .unwrap();
        if !compensate {
            let (reply, response) = oneshot::channel();
            operator_tx
                .send(PeerManagerOperatorQuery::ListPeers { reply }.into())
                .await
                .unwrap();
            assert_eq!(response.await.unwrap().len(), 3);
            let (reply, response) = oneshot::channel();
            operator_tx
                .send(
                    PeerManagerOperatorQuery::GetPeerState {
                        peer: key("10.0.0.2".parse().unwrap()),
                        reply,
                    }
                    .into(),
                )
                .await
                .unwrap();
            assert!(response.await.unwrap().is_some());
            let (reply, response) = oneshot::channel();
            operator_tx
                .send(
                    PeerManagerOperatorQuery::HasPeerAddress {
                        address: "10.0.0.2".parse().unwrap(),
                        reply,
                    }
                    .into(),
                )
                .await
                .unwrap();
            assert!(response.await.unwrap());
            let (reply, response) = oneshot::channel();
            operator_tx
                .send(PeerManagerOperatorQuery::QueryPolicyDatasets { reply }.into())
                .await
                .unwrap();
            assert!(response.await.unwrap().is_empty());
            assert!(matches!(
                mutation_response.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert!(
                counters
                    .values()
                    .all(|counter| counter.export_installs.load(Ordering::SeqCst) == 0)
            );
            rib_tx.send(prepare.take().unwrap()).await.unwrap();
        }
        let held = if compensate {
            prepare.take().unwrap()
        } else {
            let replace = held_rx.recv().await.expect("held cohort replacement");
            assert!(matches!(
                replace,
                RibUpdate::ReplacePeerExportPolicies { .. }
            ));
            replace
        };
        assert_eq!(
            counters
                .values()
                .filter(|counter| counter.export_installs.load(Ordering::SeqCst) >= 1)
                .count(),
            if dataset {
                0
            } else if compensate {
                2
            } else {
                3
            },
        );
        if compensate {
            assert_eq!(
                counters[&"10.0.0.2".parse::<IpAddr>().unwrap()]
                    .export_installs
                    .load(Ordering::SeqCst),
                0
            );
        }
        let (reply, mut response) = oneshot::channel();
        operator_tx
            .send(PeerManagerOperatorQuery::ListPeers { reply }.into())
            .await
            .unwrap();
        let (reply, ping) = oneshot::channel();
        readiness_tx
            .send(PeerManagerReadinessQuery::Ping { reply })
            .await
            .unwrap();
        ping.await.unwrap();
        let queued_response = if failed_hot_restore {
            assert_eq!(
                *counters[&"10.0.0.9".parse::<IpAddr>().unwrap()]
                    .runtime_remove_private_as
                    .lock()
                    .unwrap(),
                Some(rustbgpd_transport::RemovePrivateAs::Disabled),
                "the prior session knobs were acknowledged before the restoring RIB reply was lost"
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(20), &mut response)
                    .await
                    .is_err(),
                "earlier failed restoration must fence the misleading manager metadata"
            );
            Some(response)
        } else {
            // Forward and clean compensating owners admit live reads while
            // their actual RIB reply is held; queued mutations remain owned.
            let infos = tokio::time::timeout(Duration::from_secs(1), &mut response)
                .await
                .expect("operator reads are served while the cohort RIB reply is held")
                .unwrap();
            assert_eq!(infos.len(), 3);
            None
        };
        assert!(matches!(
            mutation_response.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        rib_tx.send(held).await.unwrap();
        (queued_response, mutation_response)
    };
    let (outcome, (operator_response, mutation_response)) =
        tokio::time::timeout(Duration::from_secs(5), async {
            let actions = plan_reload_peer_actions(&prior, &candidate).unwrap();
            tokio::join!(
                Box::pin(
                    harness
                        .mgr
                        .apply_reload_generation(candidate.clone(), actions, prepared)
                ),
                driver
            )
        })
        .await
        .expect("generation and held-stage driver must finish");
    if compensate {
        assert!(
            if failed_hot_restore {
                matches!(outcome, ReloadGenerationOutcome::CompensationAmbiguous(_))
            } else {
                matches!(outcome, ReloadGenerationOutcome::FullyCompensated(_))
            },
            "{outcome:?}"
        );
        assert_eq!(harness.mgr.current_config, prior);
    } else {
        assert!(
            matches!(outcome, ReloadGenerationOutcome::Applied(_)),
            "{outcome:?}"
        );
        assert_eq!(harness.mgr.current_config, candidate);
    }
    if failed_hot_restore {
        let managed = &harness.mgr.peers[&key("10.0.0.9".parse().unwrap())];
        assert_eq!(
            managed.transport_config.remove_private_as,
            rustbgpd_transport::RemovePrivateAs::All,
            "manager metadata still names candidate knobs although the session acknowledged its prior knobs"
        );
        let state = managed
            .handle
            .query_state_timeout(PEER_QUERY_TIMEOUT)
            .await
            .unwrap();
        let snapshot = super::super::snapshot::build_peer_info(
            &key("10.0.0.9".parse().unwrap()),
            managed,
            Some(&state),
            true,
        );
        assert!(!snapshot.stale);
        assert_ne!(
            Some(snapshot.remove_private_as),
            *counters[&"10.0.0.9".parse::<IpAddr>().unwrap()]
                .runtime_remove_private_as
                .lock()
                .unwrap(),
            "serving this fresh-looking neighbor snapshot would misreport installed session knobs"
        );
        drop(operator_response);
        drop(mutation_response);
        for (_, managed) in harness.mgr.peers.drain() {
            let _ = managed.handle.shutdown().await;
        }
        drop(harness.mgr);
        drop(internal_tx);
        drop(rib_tx);
        proxy.await.unwrap();
        harness.rib.await.unwrap();
        return;
    }
    let manager = tokio::spawn(harness.mgr.run());
    tokio::time::timeout(Duration::from_secs(1), async {
        if let Some(operator_response) = operator_response {
            assert_eq!(operator_response.await.unwrap().len(), 3);
        }
        let _ = mutation_response.await.unwrap();
        command_tx.send(PeerManagerCommand::Shutdown).await.unwrap();
        manager.await.unwrap();
    })
    .await
    .expect("normal actor loop must release queued work");
    drop(internal_tx);
    drop(rib_tx);
    proxy.await.unwrap();
    harness.rib.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn forward_generation_services_operator_reads_through_the_cohort_transition() {
    assert_generation_operator_read_boundaries(false, false, false).await;
}

#[tokio::test(start_paused = true)]
async fn clean_compensated_generation_serves_operator_reads_during_rollback_prestage() {
    assert_generation_operator_read_boundaries(true, false, false).await;
}

#[tokio::test(start_paused = true)]
async fn failed_hot_restore_fences_inconsistent_metadata_during_policy_compensation() {
    assert_generation_operator_read_boundaries(true, true, false).await;
}

#[tokio::test(start_paused = true)]
async fn failed_hot_restore_fences_inconsistent_metadata_during_dataset_compensation() {
    assert_generation_operator_read_boundaries(true, true, true).await;
}

#[tokio::test]
async fn compound_reshape_and_member_edit_replace_each_peer_exactly_once() {
    let fixture = RsFixture::new();
    let prior = fixture.load();
    let mut harness = GenerationHarness::new(&prior);
    let candidate = fixture.compound_candidate();
    let actions = plan_reload_peer_actions(&harness.mgr.current_config, &candidate).unwrap();
    assert_eq!(
        actions,
        vec![
            ReloadPeerAction {
                key: key("10.0.0.2".parse().unwrap()),
                kind: ReloadPeerActionKind::Replace
            },
            ReloadPeerAction {
                key: key("2001:db8::3".parse().unwrap()),
                kind: ReloadPeerActionKind::Replace
            },
        ],
        "one action per touched peer, none for the bystander"
    );
    let bystander_session = harness.session_id("10.0.0.9");
    let member_v4_session = harness.session_id("10.0.0.2");
    let member_v6_session = harness.session_id("2001:db8::3");
    let sessions_before = harness.mgr.next_session_id;

    let outcome = harness.apply(&candidate).await;
    let ReloadGenerationOutcome::Applied(receipt) = outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(receipt.replaced, 2);
    assert_eq!(
        receipt.policy_updated, 1,
        "replaced peers get final policies on re-add; only the bystander's chain is a policy target"
    );
    assert_eq!(receipt.hot_updated, 0);

    // Exactly one new session per replaced peer: the legacy path rebuilt a
    // member touched by both a group reshape and its own edit twice.
    assert_eq!(harness.mgr.next_session_id, sessions_before + 2);
    assert_ne!(harness.session_id("10.0.0.2"), member_v4_session);
    assert_ne!(harness.session_id("2001:db8::3"), member_v6_session);
    assert_eq!(
        harness.session_id("10.0.0.9"),
        bystander_session,
        "bystander keeps its session"
    );
    assert_eq!(harness.export_installs("10.0.0.9"), 1);
    assert_eq!(harness.export_med("10.0.0.9"), Some(20));
    assert_eq!(harness.mgr.current_config, candidate);
    assert_eq!(
        harness.mgr.peers[&key("10.0.0.2".parse().unwrap())].remote_asn,
        65012
    );
    assert_eq!(
        harness.mgr.peers[&key("10.0.0.2".parse().unwrap())].hold_time,
        Some(60)
    );
    // The replacement received the final `.rpol` export rule directly.
    assert_eq!(harness.export_med("10.0.0.2"), Some(20));
    harness.shutdown().await;
}

#[tokio::test]
async fn policy_only_and_hot_only_peers_keep_their_sessions() {
    let fixture = RsFixture::new();
    let prior = fixture.load();
    let mut harness = GenerationHarness::new(&prior);
    // Export MED 10 -> 20 through the `.rpol` file and the group's
    // hot-applied max_prefixes: no session-bound field moves.
    std::fs::write(fixture.dir.path().join("members.rpol"), RS_RPOL_MED_20).unwrap();
    fixture.write_toml(
        &fixture
            .base_toml()
            .replace("max_prefixes = 1000", "max_prefixes = 2000"),
    );
    let candidate = fixture.load();
    let sessions_before = harness.mgr.next_session_id;
    let ids: Vec<u64> = ["10.0.0.2", "2001:db8::3", "10.0.0.9"]
        .iter()
        .map(|address| harness.session_id(address))
        .collect();

    let outcome = harness.apply(&candidate).await;
    let ReloadGenerationOutcome::Applied(receipt) = outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(receipt.replaced, 0);
    assert_eq!(receipt.hot_updated, 2);
    assert_eq!(
        receipt.policy_updated, 3,
        "both members' and the bystander's export chains moved"
    );
    assert_eq!(
        harness.mgr.next_session_id, sessions_before,
        "no session was rebuilt"
    );
    for (address, id) in ["10.0.0.2", "2001:db8::3", "10.0.0.9"].iter().zip(ids) {
        assert_eq!(harness.session_id(address), id, "{address}");
    }
    assert_eq!(harness.export_installs("10.0.0.2"), 1);
    assert_eq!(harness.export_installs("2001:db8::3"), 1);
    assert_eq!(harness.export_installs("10.0.0.9"), 1);
    assert_eq!(harness.runtime_config_updates("10.0.0.2"), 1);
    assert_eq!(harness.runtime_config_updates("10.0.0.9"), 0);
    assert_eq!(harness.export_med("10.0.0.2"), Some(20));
    assert_eq!(
        harness.mgr.peers[&key("10.0.0.2".parse().unwrap())]
            .transport_config
            .max_prefixes,
        Some(2000)
    );
    assert_eq!(harness.mgr.current_config, candidate);
    harness.shutdown().await;
}

/// The acceptance failure injection: a real `.rpol` export rule and a
/// group/member reshape in one generation, with the reshape of the second
/// member failing after the policy snapshot and the first member's
/// replacement already landed. The prior advertised result (export MED),
/// prior chains, prior session configs, and prior snapshot all return; the
/// candidate file stays on disk for the operator.
#[tokio::test]
async fn late_reshape_failure_restores_prior_policy_generation() {
    let fixture = RsFixture::new();
    let prior = fixture.load();
    let mut harness = GenerationHarness::new(&prior);
    let candidate = fixture.compound_candidate();
    let candidate_bytes = std::fs::read(&fixture.config_path).unwrap();
    // Policy-only peer: the bystander references the same `.rpol` export
    // policy through its own chain, so the candidate moves its policy with
    // no session action; the unwind must restore it from the policy priors.
    let bystander_session = harness.session_id("10.0.0.9");
    harness
        .mgr
        .inject_reconfigure_failures
        .insert(key("2001:db8::3".parse().unwrap()), 0);

    let outcome = harness.apply(&candidate).await;
    let ReloadGenerationOutcome::FullyCompensated(error) = outcome else {
        panic!("{outcome:?}");
    };
    assert!(error.contains("session replace"), "{error}");
    assert!(error.contains("prior generation restored"), "{error}");

    // Prior accepted generation: snapshot, chains, session configs.
    assert_eq!(harness.mgr.current_config, prior);
    for address in ["10.0.0.2", "2001:db8::3"] {
        let managed = &harness.mgr.peers[&key(address.parse().unwrap())];
        assert_eq!(managed.hold_time, Some(90), "{address}");
        assert_eq!(
            harness.export_med(address),
            Some(10),
            "{address} advertised result"
        );
    }
    assert_eq!(
        harness.mgr.peers[&key("10.0.0.2".parse().unwrap())].remote_asn,
        65002
    );
    assert_eq!(harness.session_id("10.0.0.9"), bystander_session);
    assert_eq!(
        harness.export_med("10.0.0.9"),
        Some(10),
        "policy-only bystander advertised result restored from the policy priors"
    );
    assert_eq!(
        harness.export_installs("10.0.0.9"),
        2,
        "forward install plus restoring install"
    );
    // The desired file is untouched; an identical retry re-derives the plan.
    assert_eq!(
        std::fs::read(&fixture.config_path).unwrap(),
        candidate_bytes
    );
    assert_eq!(
        std::fs::read_to_string(fixture.dir.path().join("members.rpol")).unwrap(),
        RS_RPOL_MED_20
    );
    let retry_actions = plan_reload_peer_actions(&harness.mgr.current_config, &candidate).unwrap();
    assert_eq!(retry_actions.len(), 2);

    harness.mgr.inject_reconfigure_failures.clear();
    let outcome = harness.apply(&candidate).await;
    assert!(
        matches!(outcome, ReloadGenerationOutcome::Applied(_)),
        "{outcome:?}"
    );
    assert_eq!(harness.mgr.current_config, candidate);
    assert_eq!(harness.export_med("2001:db8::3"), Some(20));
    assert_eq!(harness.export_med("10.0.0.9"), Some(20));
    harness.shutdown().await;
}

#[tokio::test]
async fn hot_update_failure_fences_after_policy_effects() {
    let fixture = RsFixture::new();
    let prior = fixture.load();
    let mut harness = GenerationHarness::new(&prior);
    std::fs::write(fixture.dir.path().join("members.rpol"), RS_RPOL_MED_20).unwrap();
    fixture.write_toml(
        &fixture
            .base_toml()
            .replace("max_prefixes = 1000", "max_prefixes = 2000"),
    );
    let candidate = fixture.load();
    harness
        .mgr
        .inject_hot_update_failures
        .insert(key("2001:db8::3".parse().unwrap()), 0);
    let outcome = harness.apply(&candidate).await;
    assert!(
        matches!(outcome, ReloadGenerationOutcome::CompensationAmbiguous(_)),
        "{outcome:?}"
    );
    // A failed hot primitive does not prove no effect: retain the candidate
    // and let the owner fence, rather than claiming the prior is restored.
    assert_eq!(harness.mgr.current_config, candidate);
    assert_eq!(harness.export_med("10.0.0.2"), Some(20));
    harness.shutdown().await;
}

#[tokio::test]
async fn hot_update_refresh_ack_loss_after_knob_ack_never_claims_restoration() {
    let fixture = RsFixture::new();
    let prior = fixture.load();
    let mut harness = GenerationHarness::new(&prior);
    let (rib_tx, rib) = spawn_generation_rib(true);
    harness.mgr.rib_tx = rib_tx;
    harness.rib.abort();
    harness.rib = rib;
    let mut candidate = prior.clone();
    candidate
        .peer_groups
        .get_mut("members")
        .unwrap()
        .remove_private_as = Some("all".to_string());
    let outcome = harness.apply(&candidate).await;
    let ReloadGenerationOutcome::CompensationAmbiguous(error) = outcome else {
        panic!("{outcome:?}");
    };
    assert!(error.contains("RIB dropped reply"), "{error}");
    assert_eq!(
        harness.runtime_config_updates("10.0.0.2"),
        1,
        "session acknowledged candidate knobs before reply loss"
    );
    assert_eq!(
        harness.mgr.peers[&key("10.0.0.2".parse().unwrap())]
            .transport_config
            .remove_private_as,
        rustbgpd_transport::RemovePrivateAs::Disabled,
        "manager bookkeeping still holds prior knobs"
    );
    harness.shutdown().await;
}

#[tokio::test]
async fn failed_generation_rebuilds_with_prior_diagnostic_settings() {
    // With the bystander removed, outer compensation re-adds it. In both
    // cases the reshape helper first restores the already-replaced member.
    for remove_bystander in [false, true] {
        let fixture = RsFixture::new();
        let prior = fixture.load();
        let mut harness = GenerationHarness::new(&prior);
        let mut candidate = fixture.compound_candidate();
        candidate.policy.explain.enabled = !prior.policy.explain.enabled;
        candidate.policy.explain.cache_size += 1;
        candidate.policy.reject_retention.enabled = !prior.policy.reject_retention.enabled;
        candidate.policy.reject_retention.capacity += 1;
        if remove_bystander {
            candidate
                .neighbors
                .retain(|peer| peer.address != "10.0.0.9");
        }
        harness
            .mgr
            .inject_reconfigure_failures
            .insert(key("2001:db8::3".parse().unwrap()), 0);
        let outcome = harness.apply(&candidate).await;
        assert!(
            matches!(outcome, ReloadGenerationOutcome::FullyCompensated(_)),
            "{outcome:?}"
        );
        assert_eq!(harness.mgr.current_config, prior);
        for address in ["10.0.0.2", "10.0.0.9"] {
            let transport = &harness.mgr.peers[&key(address.parse().unwrap())].transport_config;
            assert_eq!(
                transport.explain_enabled, prior.policy.explain.enabled,
                "{address}"
            );
            assert_eq!(
                transport.explain_cache_size, prior.policy.explain.cache_size,
                "{address}"
            );
            assert_eq!(
                transport.reject_retention_enabled, prior.policy.reject_retention.enabled,
                "{address}"
            );
            assert_eq!(
                transport.reject_retention_capacity, prior.policy.reject_retention.capacity,
                "{address}"
            );
        }
        harness.shutdown().await;
    }
}

#[tokio::test]
async fn replacement_failure_re_adds_removed_peers() {
    let fixture = RsFixture::new();
    let prior = fixture.load();
    let mut harness = GenerationHarness::new(&prior);
    // Remove the bystander and reshape the group; the second member's
    // reshape fails, so the removed bystander must come back.
    fixture.write_toml(
        &fixture
            .base_toml()
            .replace("hold_time = 90", "hold_time = 60")
            .replace(
                "[[neighbors]]\naddress = \"10.0.0.9\"\nremote_asn = 65009\nhold_time = 180\nexport_policy_chain = [\"members-out\"]\n",
                "",
            ),
    );
    let candidate = fixture.load();
    assert_eq!(candidate.neighbors.len(), 2);
    harness
        .mgr
        .inject_reconfigure_failures
        .insert(key("2001:db8::3".parse().unwrap()), 0);

    let outcome = harness.apply(&candidate).await;
    assert!(
        matches!(outcome, ReloadGenerationOutcome::FullyCompensated(_)),
        "{outcome:?}"
    );
    assert_eq!(harness.mgr.current_config, prior);
    let bystander = harness
        .mgr
        .peers
        .get(&key("10.0.0.9".parse().unwrap()))
        .expect("removed bystander re-added from its retained prior");
    assert!(bystander.enabled);
    assert_eq!(bystander.hold_time, Some(180));
    assert_eq!(bystander.remote_asn, 65009);
    harness.shutdown().await;
}

#[tokio::test]
async fn inconsistent_actions_reject_before_any_effect() {
    let fixture = RsFixture::new();
    let prior = fixture.load();
    let mut harness = GenerationHarness::new(&prior);
    let candidate = fixture.compound_candidate();
    let sessions_before = harness.mgr.next_session_id;

    // An addition for a peer that is already managed is a planner/manager
    // disagreement: nothing may move.
    let actions = vec![ReloadPeerAction {
        key: key("10.0.0.2".parse().unwrap()),
        kind: ReloadPeerActionKind::Add,
    }];
    let outcome = Box::pin(harness.mgr.apply_reload_generation(
        candidate.clone(),
        actions,
        PreparedDatasetGeneration::default(),
    ))
    .await;
    assert!(
        matches!(outcome, ReloadGenerationOutcome::RejectedNoEffect(_)),
        "{outcome:?}"
    );
    assert_eq!(harness.mgr.current_config, prior);
    assert_eq!(harness.mgr.next_session_id, sessions_before);
    assert_eq!(harness.export_installs("10.0.0.2"), 0);
    assert_eq!(harness.export_med("10.0.0.2"), Some(10));

    // A candidate that drops a managed static neighbor without a removal
    // action is rejected the same way.
    let actions = Vec::new();
    let mut orphaning = candidate.clone();
    orphaning
        .neighbors
        .retain(|neighbor| neighbor.address != "10.0.0.9");
    let outcome = Box::pin(harness.mgr.apply_reload_generation(
        orphaning,
        actions,
        PreparedDatasetGeneration::default(),
    ))
    .await;
    assert!(
        matches!(outcome, ReloadGenerationOutcome::RejectedNoEffect(_)),
        "{outcome:?}"
    );
    assert_eq!(harness.mgr.current_config, prior);
    harness.shutdown().await;
}

#[tokio::test]
async fn generation_publishes_the_catalog_events_it_contains() {
    let fixture = RsFixture::new();
    let prior = fixture.load();
    let mut harness = GenerationHarness::new(&prior);
    fixture.write_toml(&format!(
        "{}\n[policy.definitions.deny-all]\ndefault_action = \"deny\"\n\n[peer_groups.transit]\nhold_time = 30\n",
        fixture.base_toml()
    ));
    let candidate = fixture.load();
    let mut events = harness.mgr.policy_events_tx.subscribe();
    let outcome = harness.apply(&candidate).await;
    assert!(
        matches!(outcome, ReloadGenerationOutcome::Applied(_)),
        "{outcome:?}"
    );
    let mut seen = Vec::new();
    while let Ok(event) = events.try_recv() {
        seen.push((event.operation, event.target_type, event.target.clone()));
    }
    assert!(
        seen.contains(&("set", "policy", "deny-all".to_string())),
        "{seen:?}"
    );
    assert!(
        seen.contains(&("set", "peer_group", "transit".to_string())),
        "{seen:?}"
    );
    harness.shutdown().await;
}

#[test]
fn sample_route_is_permitted_by_the_fixture_export_rule() {
    let chain = rustbgpd_policy::PolicyChain::new(vec![rustbgpd_policy::Policy {
        entries: Vec::new(),
        default_action: PolicyAction::Permit,
    }]);
    assert_eq!(chain.evaluate(&sample_route()).action, PolicyAction::Permit);
}

#[tokio::test]
async fn generation_policy_rejection_preserves_structured_error_codes() {
    for (state, code) in [
        (SessionState::Established, "policy_preflight_rejected"),
        (SessionState::Idle, "policy_state_non_established"),
    ] {
        let log = tempfile::NamedTempFile::new().unwrap();
        let writer = log.reopen().unwrap();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(move || writer.try_clone().unwrap())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        let fixture = RsFixture::new();
        let mut prior = fixture.load();
        prior.global.ebgp_requires_policy = Some(true);
        prior.neighbors.truncate(1);
        let mut harness = GenerationHarness::new(&prior);
        let addr = prior.neighbors[0].address.parse().unwrap();
        let (session_tx, mut session_rx) = mpsc::channel(16);
        let task = tokio::spawn(async move {
            while let Some(command) = session_rx.recv().await {
                match command {
                    PeerCommand::QueryState { reply } => {
                        let _ = reply.send(policy_test_peer_state(addr, state));
                    }
                    PeerCommand::Shutdown | PeerCommand::Stop { .. } => break,
                    _ => panic!("rejected policy transition must not mutate the session"),
                }
            }
            Ok(())
        });
        let managed = harness.mgr.peers.get_mut(&key(addr)).unwrap();
        let previous = std::mem::replace(
            &mut managed.handle,
            PeerHandle::from_parts(session_tx, task),
        );
        previous.shutdown().await.unwrap().unwrap();
        let (rib_tx, rib_rx) = mpsc::channel(256);
        harness.mgr.rib_tx = rib_tx;
        harness.rib.abort();
        harness.rib = spawn_rfc8212_rib_stub(rib_rx, 3);

        let mut candidate = prior.clone();
        candidate.policy.import_chain = vec!["members-out".to_string()];
        let outcome = harness.apply(&candidate).await;
        assert!(
            matches!(outcome, ReloadGenerationOutcome::RejectedNoEffect(_)),
            "{outcome:?}"
        );
        assert_eq!(harness.mgr.current_config, prior);
        let output = std::fs::read_to_string(log.path()).unwrap();
        let event = output
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .find(|event| event["fields"]["error"] == code)
            .unwrap_or_else(|| panic!("missing structured {code}: {output}"));
        assert_eq!(event["level"], "ERROR");
        assert!(
            event["fields"]["reason"]
                .as_str()
                .unwrap()
                .contains("no peer was modified")
        );
        harness.shutdown().await;
    }
}

/// Observe the installed compiled body and its interned prefix table separately:
/// the parsed file caches tables, and resolved chains can keep them alive too.
struct PolicyOwners {
    body: Weak<rustbgpd_policy::ir::CompiledChain>,
    prefix_sets: Vec<Weak<rustbgpd_policy::sets::PrefixSet>>,
}

impl PolicyOwners {
    fn observe(chain: &PolicyChain) -> Option<Self> {
        let body = chain
            .policies
            .iter()
            .find_map(|policy| policy.rpol.as_ref())?;
        Some(Self {
            body: Arc::downgrade(body),
            prefix_sets: body.prefix_sets.iter().map(Arc::downgrade).collect(),
        })
    }

    fn assert_alive(&self, alive: bool) {
        assert_eq!(self.body.upgrade().is_some(), alive, "compiled policy body");
        assert!(
            !self.prefix_sets.is_empty(),
            "observe real interned prefix data"
        );
        for table in &self.prefix_sets {
            assert_eq!(table.upgrade().is_some(), alive, "interned prefix table");
        }
    }
}

#[tokio::test]
async fn owned_sighup_releases_prior_owners_after_success() {
    assert_owned_sighup_lifetimes(false).await;
}

#[tokio::test]
async fn owned_sighup_releases_candidate_owners_after_late_compensation() {
    assert_owned_sighup_lifetimes(true).await;
}

// This proves generation/accepted-authority and manager-installed ownership.
// Fake session/RIB acknowledgements do not inventory real transport/RIB caches
// or measure peak allocation at an IRR-scale shape.
#[expect(
    clippy::too_many_lines,
    reason = "the lifetime proof keeps actor owners, owned settlement and release assertions in one lexical scope"
)]
async fn assert_owned_sighup_lifetimes(compensate: bool) {
    use crate::config::AcceptedConfigSnapshot;
    use crate::config_persister::ConfigPersister;
    use crate::reload::{
        SighupReloadOutcome, SighupReloadPlan, finalize_sighup_authority,
        reload_config_with_tcp_ao, run_config_bridge_accepted,
    };
    use rustbgpd_api::gnmi_dialout::{DialoutManager, GnmiService};
    use rustbgpd_api::health_probe::DaemonGate;
    use rustbgpd_api::runtime_config_settlement::{
        OwnedRuntimeConfigOutcome, OwnedRuntimeConfigRequestContext, RuntimeConfigOperationKind,
        RuntimeConfigSettlementWatchdog,
    };
    use rustbgpd_api::server::{AccessMode, RuntimeConfigCoordinator};

    let fixture = RsFixture::new();
    let policy_source = |med| {
        format!(
            "prefix-set members {{ 192.0.{med}.0/24 }}\n\
         policy members-out {{\n\
           term prefix {{ if route.prefix in members {{ set med {med}; accept }} }}\n\
           term all {{ set med {med}; accept }}\n\
         }}"
        )
    };
    let rpol_path = fixture.dir.path().join("members.rpol");
    std::fs::write(&rpol_path, policy_source(10)).unwrap();
    let prior = Arc::new(AcceptedConfigSnapshot::load(&fixture.config_path, None).unwrap());
    let prior_snapshot = Arc::downgrade(&prior);
    let prior_file = Arc::downgrade(&prior.config_ref().policy.rpol.policies["members-out"].file);
    // This is the main loop's still-current Config, not a test observer clone.
    let mut current = prior.config();
    let mut harness = GenerationHarness::new(&current);
    let bystander = key("10.0.0.9".parse().unwrap());
    let prior_policy = PolicyOwners::observe(
        harness.mgr.peers[&bystander]
            .export_policy
            .as_ref()
            .unwrap(),
    )
    .expect("fixture installs a compiled rpol policy");
    prior_policy.assert_alive(true);
    let observations = harness.counters[&bystander.address].clone();
    if compensate {
        harness
            .mgr
            .inject_reconfigure_failures
            .insert(key("2001:db8::3".parse().unwrap()), 0);
    }
    let (pm_tx, pm_rx) = mpsc::channel(16);
    let (internal_tx, internal_rx) = mpsc::channel(16);
    harness.mgr.rx = pm_rx;
    harness.mgr.internal_rx = Some(internal_rx);
    let manager = tokio::spawn(harness.mgr.run());
    let (accepted_tx, accepted_rx) = tokio::sync::watch::channel(prior.clone());
    let (events_tx, events_rx) = mpsc::channel(16);
    let (bridge_tx, bridge_rx) = mpsc::channel(16);
    let (mutation_tx, mutation_rx) = mpsc::channel(16);
    let persister = tokio::spawn(
        ConfigPersister::new_accepted(mutation_rx, fixture.config_path.clone(), prior, None).run(),
    );
    let bridge = tokio::spawn(run_config_bridge_accepted(
        events_rx,
        bridge_rx,
        mutation_tx,
        accepted_tx,
    ));
    let dialout = Arc::new(tokio::sync::Mutex::new(DialoutManager::new(
        GnmiService::new(
            65001,
            "10.0.0.1".to_string(),
            AccessMode::ReadWrite,
            pm_tx.clone(),
        ),
        BgpMetrics::new(),
    )));

    // Change actual source bytes, including the material table, so accepted
    // source reuse cannot make the two generations share an allocation.
    drop(fixture.compound_candidate());
    let candidate_rpol = policy_source(20);
    std::fs::write(&rpol_path, &candidate_rpol).unwrap();
    let candidate_bytes = std::fs::read(&fixture.config_path).unwrap();
    let candidate = Arc::new(
        AcceptedConfigSnapshot::load_for_reload(
            &fixture.config_path,
            &accepted_rx.borrow(),
            &current.policy.dataset_bindings,
        )
        .unwrap(),
    );
    let candidate_snapshot = Arc::downgrade(&candidate);
    let candidate_file =
        Arc::downgrade(&candidate.config_ref().policy.rpol.policies["members-out"].file);
    assert!(!Weak::ptr_eq(&prior_file, &candidate_file));
    let plan = SighupReloadPlan {
        baseline_runtime: current.clone(),
        desired: candidate,
    };
    let live_uds = current.global.telemetry.grpc_uds.clone();
    let operation_pm = pm_tx.clone();
    let operation_internal = internal_tx.clone();
    let operation_bridge = bridge_tx.clone();
    let operation_accepted = accepted_rx.clone();
    let watchdog = RuntimeConfigSettlementWatchdog::new();
    let metrics = BgpMetrics::new();
    watchdog.register_metrics(metrics.registry());
    let outcome = watchdog
        .execute_owned(
            RuntimeConfigOperationKind::Sighup,
            RuntimeConfigCoordinator::new(),
            DaemonGate::new(),
            OwnedRuntimeConfigRequestContext::detached().response_attached(),
            move |operation| async move {
                // main retains the accepted baseline throughout its owned body.
                let _prior_accepted = operation_accepted.borrow().clone();
                match reload_config_with_tcp_ao(
                    plan,
                    None,
                    live_uds.as_ref(),
                    &operation_pm,
                    Some(&operation_internal),
                    None,
                    None,
                    None,
                    None,
                    Some(&operation),
                )
                .await
                {
                    SighupReloadOutcome::CleanNoEffect(error) => {
                        OwnedRuntimeConfigOutcome::CleanNoEffect(Err(error))
                    }
                    SighupReloadOutcome::RecoveryFenced { error, reason } => {
                        panic!("unexpected fence: {error}, {reason:?}")
                    }
                    SighupReloadOutcome::Acknowledged(authority) => {
                        finalize_sighup_authority(
                            &operation,
                            authority,
                            &operation_internal,
                            &operation_bridge,
                            &dialout,
                        )
                        .await
                    }
                }
            },
        )
        .await;

    assert!(
        metrics
            .registry()
            .gather()
            .iter()
            .all(|family| { !family.name().starts_with("bgp_runtime_config_settlement_") }),
        "settlement registration is idle after the owned task returns"
    );

    // The watchdog's owned task has returned; runtime actors are still alive.
    // Match main's authority handoff before testing the superseded Config.
    if compensate {
        let error = outcome.err().expect("late replacement failed").to_string();
        assert!(error.contains("session replace"), "{error}");
        assert!(error.contains("prior generation restored"), "{error}");
    } else {
        let authority = outcome.unwrap_or_else(|error| panic!("{error}"));
        assert!(
            prior_snapshot.upgrade().is_none(),
            "old accepted authority released"
        );
        assert!(
            prior_file.upgrade().is_some(),
            "main still owns its old Config"
        );
        current = authority.runtime;
    }
    assert_eq!(
        prior_snapshot.upgrade().is_some(),
        compensate,
        "prior accepted snapshot"
    );
    assert_eq!(
        prior_file.upgrade().is_some(),
        compensate,
        "prior parsed file"
    );
    assert_eq!(
        candidate_snapshot.upgrade().is_some(),
        !compensate,
        "candidate accepted snapshot"
    );
    assert_eq!(
        candidate_file.upgrade().is_some(),
        !compensate,
        "candidate parsed file"
    );
    prior_policy.assert_alive(compensate);
    {
        let installed = observations.export_owners.lock().unwrap();
        assert_eq!(
            installed.len(),
            if compensate { 2 } else { 1 },
            "candidate install then optional restore"
        );
        assert!(!Weak::ptr_eq(&prior_policy.body, &installed[0].body));
        assert!(!Weak::ptr_eq(
            &prior_policy.prefix_sets[0],
            &installed[0].prefix_sets[0]
        ));
        installed[0].assert_alive(!compensate);
        if compensate {
            assert!(
                Weak::ptr_eq(&prior_policy.body, &installed[1].body),
                "restore retained prior compiled body"
            );
            installed[1].assert_alive(true);
        }
    }
    assert_eq!(current, accepted_rx.borrow().config());
    assert_eq!(
        std::fs::read(&fixture.config_path).unwrap(),
        candidate_bytes
    );
    assert_eq!(std::fs::read_to_string(&rpol_path).unwrap(), candidate_rpol);

    pm_tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    manager.await.unwrap();
    drop(events_tx);
    drop(bridge_tx);
    bridge.await.unwrap();
    persister.await.unwrap();
    harness.rib.abort();
    let _ = harness.rib.await;
}

/// The same bound handle feeds import, export, and the retained rollback pin.
fn dataset_generation_fixture() -> RsFixture {
    let fixture = RsFixture::new();
    std::fs::write(fixture.dir.path().join("members.list"), "64500\n").unwrap();
    std::fs::write(
        fixture.dir.path().join("members.rpol"),
        r"
dataset asn-set members
policy members-out {
    term allowed { if route.origin-as in members { accept } }
    term rest { reject }
}",
    )
    .unwrap();
    fixture.write_toml(
        &fixture
            .base_toml()
            .replace(
                "[peer_groups.members]",
                "[policy.datasets.members]\npath = \"members.list\"\n\n[peer_groups.members]",
            )
            .replace(
                "max_prefixes = 1000",
                "max_prefixes = 1000\nimport_policy_chain = [\"members-out\"]",
            ),
    );
    fixture
}

fn prepare_dataset_candidate(
    fixture: &RsFixture,
    prior: &Config,
) -> (Config, crate::config::PreparedDatasetGeneration) {
    std::fs::write(fixture.dir.path().join("members.list"), "64500\n64999\n").unwrap();
    let mut candidate = Config::load_with_diagnostics_and_staged_datasets(
        fixture.config_path.to_str().unwrap(),
        &prior.policy.dataset_bindings,
    )
    .unwrap();
    let staged = candidate.prepare_staged_datasets(&prior.policy.dataset_bindings);
    let prepared = staged.prepare_generation(prior, &candidate).unwrap();
    (candidate, prepared)
}

#[tokio::test]
async fn generation_preserves_distinct_dataset_names_with_equal_contents() {
    let fixture = RsFixture::new();
    let path = fixture.dir.path().join("members.rpol");
    let source = "dataset asn-set left\ndataset asn-set right\n\
        policy members-out { term allowed { if route.origin-as in left { accept } } term rest { reject } }";
    std::fs::write(&path, source).unwrap();
    std::fs::write(fixture.dir.path().join("same.list"), "64500\n").unwrap();
    fixture.write_toml(&format!(
        "{}\n[policy.datasets.left]\npath = \"same.list\"\n\
         [policy.datasets.right]\npath = \"same.list\"\n",
        fixture.base_toml()
    ));
    let prior = fixture.load();
    let left = prior.policy.dataset_bindings.get("left").unwrap();
    let right = prior.policy.dataset_bindings.get("right").unwrap();
    assert_eq!(left.pin().data, right.pin().data);
    assert!(!Arc::ptr_eq(left, right));
    let mut harness = GenerationHarness::new(&prior);
    let (rib_commands, relay) = record_generation_policy_commands(&mut harness);
    std::fs::write(&path, source.replace("in left", "in right")).unwrap();
    let mut candidate = Config::load_with_diagnostics_and_staged_datasets(
        fixture.config_path.to_str().unwrap(),
        &prior.policy.dataset_bindings,
    )
    .unwrap();
    let staged = candidate.prepare_staged_datasets(&prior.policy.dataset_bindings);
    let prepared = staged.prepare_generation(&prior, &candidate).unwrap();
    assert!(prepared.changed_names().is_empty());
    let old = prior
        .resolve_neighbor(&prior.neighbors[0])
        .unwrap()
        .export_policy
        .unwrap();
    let next = candidate
        .resolve_neighbor(&candidate.neighbors[0])
        .unwrap()
        .export_policy
        .unwrap();
    assert_eq!(old.compiled().datasets[0].name.as_ref(), "left");
    assert_eq!(next.compiled().datasets[0].name.as_ref(), "right");
    assert_ne!(old.compiled(), next.compiled());
    let actions = plan_reload_peer_actions(&prior, &candidate).unwrap();
    let outcome = Box::pin(
        harness
            .mgr
            .apply_reload_generation(candidate, actions, prepared),
    )
    .await;
    let ReloadGenerationOutcome::Applied(receipt) = outcome else {
        panic!("{outcome:?}")
    };
    assert_eq!(receipt.policy_updated, 3);
    assert!(harness.counters.values().all(|counters| {
        counters.export_installs.load(Ordering::SeqCst) == 1
            && counters.import_installs.load(Ordering::SeqCst) == 0
            && counters.route_refreshes.load(Ordering::SeqCst) == 0
    }));
    assert_eq!(
        rib_commands
            .lock()
            .unwrap()
            .iter()
            .filter(|(kind, _)| *kind == "replace")
            .flat_map(|(_, peers)| peers)
            .count(),
        3
    );
    harness.shutdown().await;
    relay.await.unwrap();
}

#[tokio::test]
async fn dataset_generation_with_unused_set_changes_still_refreshes_and_compensates() {
    for compensate in [false, true] {
        let fixture = dataset_generation_fixture();
        let toml = std::fs::read_to_string(&fixture.config_path).unwrap();
        std::fs::write(
            &fixture.config_path,
            toml.replace(
                "max_prefixes = 1000",
                "max_prefixes = 1000\nfamilies = [\"ipv4_unicast\", \"ipv6_unicast\"]",
            ),
        )
        .unwrap();
        let path = fixture.dir.path().join("members.rpol");
        let source = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            format!("prefix-set unused {{ 20.0.0.0/24 }}\n{source}"),
        )
        .unwrap();
        let prior = fixture.load();
        let live = Arc::clone(prior.policy.dataset_bindings.get("members").unwrap());
        let prior_data = live.pin().data.clone();
        let mut harness = GenerationHarness::new(&prior);
        let (exports, relay) = intercept_dataset_rib(&mut harness, 0, None);
        std::fs::write(
            &path,
            format!("prefix-set unused {{ 20.0.1.0/24 }}\n{source}"),
        )
        .unwrap();
        let (mut candidate, prepared) = prepare_dataset_candidate(&fixture, &prior);
        if compensate {
            candidate.neighbors[1].hold_time = Some(60);
            harness
                .mgr
                .inject_reconfigure_failures
                .insert(key("2001:db8::3".parse().unwrap()), 0);
        }
        let actions = plan_reload_peer_actions(&prior, &candidate).unwrap();
        let outcome = Box::pin(harness.mgr.apply_reload_generation(
            candidate.clone(),
            actions,
            prepared,
        ))
        .await;
        if compensate {
            assert!(
                matches!(outcome, ReloadGenerationOutcome::FullyCompensated(_)),
                "{outcome:?}"
            );
            assert_eq!(harness.mgr.current_config, prior);
            assert_eq!(live.pin().generation, 3);
            assert_eq!(live.pin().data, prior_data);
        } else {
            let ReloadGenerationOutcome::Applied(receipt) = outcome else {
                panic!("{outcome:?}")
            };
            assert_eq!(receipt.policy_updated, 0);
            assert_eq!(harness.mgr.current_config, candidate);
            assert_eq!(live.pin().generation, 2);
            assert_eq!(live.pin().data.records(), 2);
        }
        assert!(Arc::ptr_eq(
            harness
                .mgr
                .current_config
                .policy
                .dataset_bindings
                .get("members")
                .unwrap(),
            &live
        ));
        let calls = exports.lock().unwrap().clone();
        assert_eq!(calls.len(), if compensate { 2 } else { 1 });
        assert!(calls.iter().all(|peers| peers.len() == 3));
        for (address, counters) in &harness.counters {
            assert_eq!(counters.import_installs.load(Ordering::SeqCst), 0);
            assert_eq!(counters.export_installs.load(Ordering::SeqCst), 0);
            assert_eq!(
                counters.route_refreshes.load(Ordering::SeqCst),
                if *address == "10.0.0.9".parse::<IpAddr>().unwrap() {
                    0
                } else if compensate {
                    4
                } else {
                    2
                }
            );
            let expected = if *address == "10.0.0.9".parse::<IpAddr>().unwrap() {
                Vec::new()
            } else {
                [(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)].repeat(if compensate {
                    2
                } else {
                    1
                })
            };
            assert_eq!(*counters.refresh_families.lock().unwrap(), expected);
        }
        harness.shutdown().await;
        relay.await.unwrap();
    }
}

#[tokio::test]
async fn dataset_generation_refreshes_without_reinstalling_equal_chains() {
    let fixture = dataset_generation_fixture();
    let prior = fixture.load();
    let live = Arc::clone(prior.policy.dataset_bindings.get("members").unwrap());
    let old = live.pin();
    let mut harness = GenerationHarness::new(&prior);
    let (candidate, prepared) = prepare_dataset_candidate(&fixture, &prior);
    let outcome = Box::pin(
        harness
            .mgr
            .apply_reload_generation(candidate, Vec::new(), prepared),
    )
    .await;
    assert!(
        matches!(outcome, ReloadGenerationOutcome::Applied(_)),
        "{outcome:?}"
    );
    assert_eq!(live.pin().generation, 2);
    assert_eq!(live.pin().data.records(), 2);
    assert_eq!(
        Arc::strong_count(&old),
        1,
        "generation released its old snapshot pin"
    );
    for counters in harness.counters.values() {
        assert_eq!(counters.import_installs.load(Ordering::SeqCst), 0);
        assert_eq!(counters.export_installs.load(Ordering::SeqCst), 0);
    }
    assert!(
        harness.counters[&"10.0.0.2".parse::<IpAddr>().unwrap()]
            .route_refreshes
            .load(Ordering::SeqCst)
            > 0
    );
    harness.shutdown().await;
}

#[tokio::test]
async fn dataset_generation_known_refresh_rejection_restores_contents_and_prior_error() {
    let fixture = dataset_generation_fixture();
    let prior = fixture.load();
    let live = Arc::clone(prior.policy.dataset_bindings.get("members").unwrap());
    live.record_error("prior loader failure".to_string());
    let mut harness = GenerationHarness::new(&prior);
    harness.counters[&"10.0.0.2".parse::<IpAddr>().unwrap()]
        .refresh_failures
        .lock()
        .unwrap()
        .push_back(rustbgpd_transport::PeerCommandError::SendFailed(
            "injected writer rejection".to_string(),
        ));
    let (candidate, prepared) = prepare_dataset_candidate(&fixture, &prior);
    std::fs::write(
        fixture.dir.path().join("members.list"),
        "invalid file after preparation",
    )
    .unwrap();
    let outcome = Box::pin(
        harness
            .mgr
            .apply_reload_generation(candidate, Vec::new(), prepared),
    )
    .await;
    assert!(
        matches!(outcome, ReloadGenerationOutcome::FullyCompensated(_)),
        "{outcome:?}"
    );
    assert_eq!(live.pin().generation, 3);
    assert_eq!(live.pin().data.records(), 1);
    assert_eq!(
        live.status().last_error.as_deref(),
        Some("prior loader failure")
    );
    // The forward pass stopped at the first import failure. Compensation
    // still refreshes the second peer from the complete captured union.
    assert!(
        harness.counters[&"2001:db8::3".parse::<IpAddr>().unwrap()]
            .route_refreshes
            .load(Ordering::SeqCst)
            > 0
    );
    for managed in harness.mgr.peers.values() {
        assert!(!managed.pending_refresh);
        assert!(!managed.pending_export_apply);
    }
    harness.shutdown().await;
}

#[tokio::test]
async fn dataset_generation_lost_import_ack_fences_with_required_debt() {
    let fixture = dataset_generation_fixture();
    let prior = fixture.load();
    let live = Arc::clone(prior.policy.dataset_bindings.get("members").unwrap());
    let reader = live.pin();
    let old_snapshot = Arc::downgrade(&reader);
    let mut harness = GenerationHarness::new(&prior);
    let peer = key("10.0.0.2".parse().unwrap());
    harness.counters[&peer.address]
        .refresh_failures
        .lock()
        .unwrap()
        .push_back(rustbgpd_transport::PeerCommandError::ReplyDropped);
    let (candidate, prepared) = prepare_dataset_candidate(&fixture, &prior);
    let outcome = Box::pin(
        harness
            .mgr
            .apply_reload_generation(candidate, Vec::new(), prepared),
    )
    .await;
    assert!(
        matches!(outcome, ReloadGenerationOutcome::CompensationAmbiguous(_)),
        "{outcome:?}"
    );
    assert_eq!(live.pin().generation, 2);
    assert!(harness.mgr.peers[&peer].pending_refresh);
    assert_eq!(reader.generation, 1);
    assert_eq!(
        reader.data.records(),
        1,
        "an evaluator keeps its own old view"
    );
    assert_eq!(
        Arc::strong_count(&reader),
        1,
        "terminal recovery outcome releases the operation pin"
    );
    drop(reader);
    assert!(
        old_snapshot.upgrade().is_none(),
        "no later compensation consumer retains the old snapshot"
    );
    harness.shutdown().await;
}

#[tokio::test]
async fn dataset_generation_clean_down_peer_does_not_block_content_refresh() {
    let fixture = dataset_generation_fixture();
    let prior = fixture.load();
    let mut harness = GenerationHarness::new(&prior);
    let addr = "10.0.0.2".parse::<IpAddr>().unwrap();
    harness.counters[&addr]
        .states
        .lock()
        .unwrap()
        .push_back(SessionState::Idle);
    let (candidate, prepared) = prepare_dataset_candidate(&fixture, &prior);
    let outcome = Box::pin(
        harness
            .mgr
            .apply_reload_generation(candidate, Vec::new(), prepared),
    )
    .await;
    assert!(
        matches!(outcome, ReloadGenerationOutcome::Applied(_)),
        "{outcome:?}"
    );
    assert_eq!(
        harness.counters[&addr]
            .route_refreshes
            .load(Ordering::SeqCst),
        0
    );
    assert!(!harness.mgr.peers[&key(addr)].pending_refresh);
    harness.shutdown().await;
}

#[tokio::test]
async fn dataset_generation_down_to_established_race_requires_restoring_refresh() {
    let fixture = dataset_generation_fixture();
    let prior = fixture.load();
    let live = Arc::clone(prior.policy.dataset_bindings.get("members").unwrap());
    let mut harness = GenerationHarness::new(&prior);
    let addr = "10.0.0.2".parse::<IpAddr>().unwrap();
    harness.counters[&addr].states.lock().unwrap().extend([
        SessionState::Idle,
        SessionState::Idle,
        SessionState::Established,
    ]);
    let (candidate, prepared) = prepare_dataset_candidate(&fixture, &prior);
    let outcome = Box::pin(
        harness
            .mgr
            .apply_reload_generation(candidate, Vec::new(), prepared),
    )
    .await;
    assert!(
        matches!(outcome, ReloadGenerationOutcome::FullyCompensated(_)),
        "{outcome:?}"
    );
    assert_eq!(live.pin().generation, 3);
    assert!(
        harness.counters[&addr]
            .route_refreshes
            .load(Ordering::SeqCst)
            > 0
    );
    harness.shutdown().await;
}

#[tokio::test]
async fn dataset_generation_preflight_rejects_missing_capability_and_existing_debt() {
    for no_capability in [true, false] {
        let fixture = dataset_generation_fixture();
        let prior = fixture.load();
        let live = Arc::clone(prior.policy.dataset_bindings.get("members").unwrap());
        let mut harness = GenerationHarness::new(&prior);
        let peer = key("10.0.0.2".parse().unwrap());
        if no_capability {
            harness.counters[&peer.address]
                .no_route_refresh
                .store(true, Ordering::SeqCst);
        } else {
            harness.mgr.peers.get_mut(&peer).unwrap().pending_refresh = true;
        }
        let (candidate, prepared) = prepare_dataset_candidate(&fixture, &prior);
        let outcome = Box::pin(harness.mgr.apply_reload_generation(
            candidate,
            Vec::new(),
            prepared,
        ))
        .await;
        assert!(
            matches!(outcome, ReloadGenerationOutcome::RejectedNoEffect(_)),
            "{outcome:?}"
        );
        assert_eq!(live.pin().generation, 1);
        assert_eq!(
            harness.counters[&peer.address]
                .route_refreshes
                .load(Ordering::SeqCst),
            0
        );
        harness.shutdown().await;
    }
}

type DatasetExportBatches = Arc<Mutex<Vec<Vec<IpAddr>>>>;

/// Intercept only dataset commands; all policy-generation commands still use
/// the existing generation RIB stub and its ownership receipts.
fn intercept_dataset_rib(
    harness: &mut GenerationHarness,
    retained: usize,
    missing: Option<IpAddr>,
) -> (DatasetExportBatches, tokio::task::JoinHandle<()>) {
    let (tx, mut rx) = mpsc::channel::<RibUpdate>(64);
    let downstream = std::mem::replace(&mut harness.mgr.rib_tx, tx);
    let exports = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&exports);
    let task = tokio::spawn(async move {
        while let Some(command) = rx.recv().await {
            match command {
                RibUpdate::QueryPeerRetainedStale { reply, .. } => {
                    let _ = reply.send(retained);
                }
                RibUpdate::ReevaluatePeerExportPolicies { peers, reply } => {
                    recorded.lock().unwrap().push(peers.clone());
                    let outcome = if missing.is_some_and(|peer| peers.contains(&peer)) {
                        Err(rustbgpd_rib::RibCommandError::not_found(
                            "missing outbound registration",
                        ))
                    } else {
                        Ok(())
                    };
                    let _ = reply.send(outcome);
                }
                other => {
                    if downstream.send(other).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    (exports, task)
}

#[tokio::test]
async fn dataset_generation_clean_down_missing_export_is_vacuous_only_for_that_peer() {
    let fixture = dataset_generation_fixture();
    let prior = fixture.load();
    let mut harness = GenerationHarness::new(&prior);
    let down = "10.0.0.2".parse::<IpAddr>().unwrap();
    harness.counters[&down]
        .states
        .lock()
        .unwrap()
        .push_back(SessionState::Idle);
    let (exports, relay) = intercept_dataset_rib(&mut harness, 0, Some(down));
    let (candidate, prepared) = prepare_dataset_candidate(&fixture, &prior);
    let outcome = Box::pin(
        harness
            .mgr
            .apply_reload_generation(candidate, Vec::new(), prepared),
    )
    .await;
    assert!(
        matches!(outcome, ReloadGenerationOutcome::Applied(_)),
        "{outcome:?}"
    );
    let calls = exports.lock().unwrap().clone();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0], vec![down]);
    assert_eq!(calls[1].len(), 2, "Established dependents remain one batch");
    assert!(!calls[1].contains(&down));
    harness.shutdown().await;
    relay.await.unwrap();
}

#[tokio::test]
async fn dataset_generation_down_peer_with_gr_retention_rejects_before_publication() {
    let fixture = dataset_generation_fixture();
    let prior = fixture.load();
    let live = Arc::clone(prior.policy.dataset_bindings.get("members").unwrap());
    let mut harness = GenerationHarness::new(&prior);
    let down = "10.0.0.2".parse::<IpAddr>().unwrap();
    harness.counters[&down]
        .states
        .lock()
        .unwrap()
        .push_back(SessionState::Idle);
    let (exports, relay) = intercept_dataset_rib(&mut harness, 3, None);
    let (candidate, prepared) = prepare_dataset_candidate(&fixture, &prior);
    let outcome = Box::pin(
        harness
            .mgr
            .apply_reload_generation(candidate, Vec::new(), prepared),
    )
    .await;
    let ReloadGenerationOutcome::RejectedNoEffect(error) = outcome else {
        panic!("{outcome:?}")
    };
    assert!(error.contains("retains 3 stale routes"), "{error}");
    assert_eq!(live.pin().generation, 1);
    assert!(exports.lock().unwrap().is_empty());
    harness.shutdown().await;
    relay.await.unwrap();
}

#[tokio::test]
async fn dataset_generation_lost_export_ack_fences_before_import_refresh() {
    let fixture = dataset_generation_fixture();
    let prior = fixture.load();
    let mut harness = GenerationHarness::new(&prior);
    let (tx, rib) = spawn_generation_rib(true);
    harness.mgr.rib_tx = tx;
    harness.rib.abort();
    harness.rib = rib;
    let (candidate, prepared) = prepare_dataset_candidate(&fixture, &prior);
    let outcome = Box::pin(
        harness
            .mgr
            .apply_reload_generation(candidate, Vec::new(), prepared),
    )
    .await;
    assert!(
        matches!(outcome, ReloadGenerationOutcome::CompensationAmbiguous(_)),
        "{outcome:?}"
    );
    for counters in harness.counters.values() {
        assert_eq!(counters.route_refreshes.load(Ordering::SeqCst), 0);
    }
    assert!(
        harness
            .mgr
            .peers
            .values()
            .all(|managed| managed.pending_export_apply)
    );
    harness.shutdown().await;
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one generation fixture proves the replacement handle and its queued reads while compensation is held"
)]
async fn dataset_generation_late_reshape_compensates_fresh_clean_down_session() {
    let fixture = dataset_generation_fixture();
    let prior = fixture.load();
    let live = Arc::clone(prior.policy.dataset_bindings.get("members").unwrap());
    let mut harness = GenerationHarness::new(&prior);
    let prior_session = harness.session_id("10.0.0.2");
    harness.mgr.dataset_generations_at_peer_construction = Some(Vec::new());
    let (mut candidate, prepared) = prepare_dataset_candidate(&fixture, &prior);
    candidate.peer_groups.get_mut("members").unwrap().hold_time = Some(60);
    harness
        .mgr
        .inject_reconfigure_failures
        .insert(key("2001:db8::3".parse().unwrap()), 0);
    let actions = plan_reload_peer_actions(&prior, &candidate).unwrap();
    let old_commands = harness.mgr.peers[&key("10.0.0.2".parse().unwrap())]
        .handle
        .commands_sender();
    let old_counters = harness.counters[&"10.0.0.2".parse::<IpAddr>().unwrap()].clone();
    let (operator_tx, operator_rx) = mpsc::channel(4);
    harness.mgr = harness.mgr.with_operator_queries(operator_rx);
    let (command_tx, command_rx) = mpsc::channel(4);
    harness.mgr.rx = command_rx;
    let (proxy_tx, mut proxy_rx) = mpsc::channel(16);
    let rib_tx = std::mem::replace(&mut harness.mgr.rib_tx, proxy_tx);
    let forwarding = rib_tx.clone();
    let restored = live.clone();
    let (held_tx, mut held_rx) = mpsc::channel(1);
    let proxy = tokio::spawn(async move {
        let mut held = false;
        while let Some(update) = proxy_rx.recv().await {
            if !held
                && restored.pin().generation == 3
                && matches!(update, RibUpdate::ReevaluatePeerExportPolicies { .. })
            {
                held = true;
                held_tx.send(update).await.unwrap();
            } else {
                forwarding.send(update).await.unwrap();
            }
        }
    });
    let driver = async {
        let held = held_rx
            .recv()
            .await
            .expect("hold the restored dataset's actual export acknowledgement");
        assert!(
            old_commands.is_closed(),
            "the replaced session cannot serve the admitted read"
        );
        let old_queries = old_counters.state_queries.load(Ordering::SeqCst);
        let (reply, mut mutation) = oneshot::channel();
        command_tx
            .send(PeerManagerCommand::EnablePeer {
                peer: key("10.0.0.2".parse().unwrap()),
                reply,
            })
            .await
            .unwrap();
        let (reply, response) = oneshot::channel();
        operator_tx
            .send(PeerManagerOperatorQuery::ListPeers { reply }.into())
            .await
            .unwrap();
        let infos = tokio::time::timeout(Duration::from_secs(1), response)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(infos.len(), 3);
        let rebuilt = infos
            .iter()
            .find(|info| info.address == "10.0.0.2".parse::<IpAddr>().unwrap())
            .unwrap();
        assert!(
            !rebuilt.stale,
            "read resolves the replacement's current handle"
        );
        assert_ne!(rebuilt.state, SessionState::Established);
        assert_eq!(rebuilt.hold_time, Some(90));
        assert_eq!(
            old_counters.state_queries.load(Ordering::SeqCst),
            old_queries
        );
        let (reply, response) = oneshot::channel();
        operator_tx
            .send(
                PeerManagerOperatorQuery::QueryImportPolicyTermHits {
                    peer: None,
                    deadline: tokio::time::Instant::now() + Duration::from_secs(2),
                    reply,
                }
                .into(),
            )
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), response)
                .await
                .unwrap()
                .unwrap()
                .is_ok()
        );
        assert!(matches!(
            mutation.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        rib_tx.send(held).await.unwrap();
    };
    let (outcome, ()) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            Box::pin(
                harness
                    .mgr
                    .apply_reload_generation(candidate, actions, prepared)
            ),
            driver
        )
    })
    .await
    .unwrap();
    assert!(
        matches!(outcome, ReloadGenerationOutcome::FullyCompensated(_)),
        "{outcome:?}"
    );
    assert_eq!(live.pin().generation, 3);
    assert_eq!(
        harness
            .mgr
            .dataset_generations_at_peer_construction
            .as_ref()
            .unwrap(),
        &vec![
            (key("10.0.0.2".parse().unwrap()), "members".to_string(), 2),
            (key("10.0.0.2".parse().unwrap()), "members".to_string(), 3),
        ],
        "the inner prior-session construction must see restored contents"
    );
    assert_eq!(live.pin().data.records(), 1);
    assert_ne!(
        harness.session_id("10.0.0.2"),
        prior_session,
        "compensation recreated the first member"
    );
    assert_eq!(harness.mgr.current_config, prior);
    assert!(!harness.mgr.peers[&key("10.0.0.2".parse().unwrap())].pending_refresh);
    harness.shutdown().await;
    drop(rib_tx);
    proxy.await.unwrap();
}

#[tokio::test]
async fn dataset_generation_unknown_state_rejects_before_publish_and_fences_after() {
    for drop_after in [1, 2] {
        let fixture = dataset_generation_fixture();
        let prior = fixture.load();
        let live = Arc::clone(prior.policy.dataset_bindings.get("members").unwrap());
        let mut harness = GenerationHarness::new(&prior);
        let addr = "10.0.0.2".parse::<IpAddr>().unwrap();
        harness.counters[&addr]
            .drop_state_after
            .store(drop_after, Ordering::SeqCst);
        let (candidate, prepared) = prepare_dataset_candidate(&fixture, &prior);
        let outcome = Box::pin(harness.mgr.apply_reload_generation(
            candidate,
            Vec::new(),
            prepared,
        ))
        .await;
        if drop_after == 1 {
            assert!(
                matches!(outcome, ReloadGenerationOutcome::RejectedNoEffect(_)),
                "{outcome:?}"
            );
            assert_eq!(live.pin().generation, 1);
        } else {
            assert!(
                matches!(outcome, ReloadGenerationOutcome::CompensationAmbiguous(_)),
                "{outcome:?}"
            );
            assert_eq!(live.pin().generation, 2);
            assert!(harness.mgr.peers[&key(addr)].pending_refresh);
            assert!(harness.mgr.peers[&key(addr)].pending_export_apply);
        }
        assert_eq!(
            harness.counters[&addr]
                .route_refreshes
                .load(Ordering::SeqCst),
            0
        );
        harness.shutdown().await;
    }
}

#[tokio::test]
async fn dataset_generation_restores_old_only_dependency_after_chain_change() {
    let fixture = dataset_generation_fixture();
    let prior = fixture.load();
    let live = Arc::clone(prior.policy.dataset_bindings.get("members").unwrap());
    let mut harness = GenerationHarness::new(&prior);
    let (exports, relay) = intercept_dataset_rib(&mut harness, 0, None);
    // The declaration and binding stay, but no candidate chain references it.
    std::fs::write(
        fixture.dir.path().join("members.rpol"),
        "dataset asn-set members\npolicy members-out { term all { accept } }",
    )
    .unwrap();
    let (mut candidate, prepared) = prepare_dataset_candidate(&fixture, &prior);
    candidate.peer_groups.get_mut("members").unwrap().hold_time = Some(60);
    harness
        .mgr
        .inject_reconfigure_failures
        .insert(key("2001:db8::3".parse().unwrap()), 0);
    let actions = plan_reload_peer_actions(&prior, &candidate).unwrap();
    let outcome = Box::pin(
        harness
            .mgr
            .apply_reload_generation(candidate, actions, prepared),
    )
    .await;
    assert!(
        matches!(outcome, ReloadGenerationOutcome::FullyCompensated(_)),
        "{outcome:?}"
    );
    assert_eq!(live.pin().generation, 3);
    let bystander = "10.0.0.9".parse::<IpAddr>().unwrap();
    assert_eq!(
        exports
            .lock()
            .unwrap()
            .iter()
            .filter(|peers| peers.contains(&bystander))
            .count(),
        2,
        "the old-only export dependency is refreshed both forward and during restoration"
    );
    assert!(
        harness.mgr.peers[&key(bystander)]
            .export_policy
            .as_ref()
            .unwrap()
            .references_dataset("members")
    );
    harness.shutdown().await;
    relay.await.unwrap();
}

#[tokio::test]
async fn dataset_generation_refreshes_candidate_only_dependencies() {
    let fixture = dataset_generation_fixture();
    let rpol_path = fixture.dir.path().join("members.rpol");
    let referencing_policy = std::fs::read_to_string(&rpol_path).unwrap();
    std::fs::write(
        &rpol_path,
        "dataset asn-set members\npolicy members-out { term all { accept } }",
    )
    .unwrap();
    let prior = fixture.load();
    let mut harness = GenerationHarness::new(&prior);
    let (exports, relay) = intercept_dataset_rib(&mut harness, 0, None);
    std::fs::write(&rpol_path, referencing_policy).unwrap();
    let (candidate, prepared) = prepare_dataset_candidate(&fixture, &prior);
    let outcome = Box::pin(
        harness
            .mgr
            .apply_reload_generation(candidate, Vec::new(), prepared),
    )
    .await;
    assert!(
        matches!(outcome, ReloadGenerationOutcome::Applied(_)),
        "{outcome:?}"
    );
    let calls = exports.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].len(),
        3,
        "all candidate-only export dependencies are recomputed"
    );
    for managed in harness.mgr.peers.values() {
        assert!(!managed.pending_refresh);
        assert!(!managed.pending_export_apply);
    }
    harness.shutdown().await;
    relay.await.unwrap();
}

#[tokio::test]
async fn dataset_generation_single_replacement_failure_restores_data_before_construction() {
    let fixture = dataset_generation_fixture();
    let prior = fixture.load();
    let live = Arc::clone(prior.policy.dataset_bindings.get("members").unwrap());
    let mut harness = GenerationHarness::new(&prior);
    let addr: IpAddr = "fe80::1".parse().unwrap();
    let interface = "rustbgpd-test-missing0";
    let peer = scoped_key(addr, interface);
    let mut original = make_config(addr, 65002);
    original.interface = Some(interface.to_string());
    original.scope_id = Some(42);
    original.import_policy = harness.mgr.peers[&key("10.0.0.2".parse().unwrap())]
        .import_policy
        .clone();
    harness.mgr.add_peer(original, false).await.unwrap();
    harness.mgr.disable_peer(peer.clone(), None).await.unwrap();
    let (candidate, prepared) = prepare_dataset_candidate(&fixture, &prior);
    let mut dataset_prior = Some(prepared.publish());
    harness.mgr.current_config = candidate;
    harness.mgr.dataset_generations_at_peer_construction = Some(Vec::new());
    let mut replacement = make_config(addr, 65002);
    replacement.interface = Some(interface.to_string());
    // Omitting the saved scope ID makes add fail after the old peer was
    // deleted: this synthetic interface cannot resolve through the OS.
    let outcome = harness
        .mgr
        .apply_peer_reshape_snapshot_classified(vec![replacement], Some(&prior), &mut dataset_prior)
        .await;
    assert!(
        matches!(
            outcome,
            crate::peer_manager::lifecycle::PeerReshapeSnapshotOutcome::FullyCompensated(_)
        ),
        "replacement add failure must restore the prior peer"
    );
    assert!(
        dataset_prior.is_none(),
        "inner recovery consumed the receipt exactly once"
    );
    assert_eq!(live.pin().generation, 3);
    assert_eq!(
        harness
            .mgr
            .dataset_generations_at_peer_construction
            .as_ref()
            .unwrap(),
        &vec![(peer, "members".to_string(), 3)],
        "the restoring session is constructed only after old data is published"
    );
    harness.shutdown().await;
}
