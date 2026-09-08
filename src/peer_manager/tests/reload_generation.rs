use super::*;

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::config::{ReloadPeerAction, ReloadPeerActionKind, plan_reload_peer_actions};
use crate::peer_manager::generation::ReloadGenerationOutcome;
use rustbgpd_policy::PolicyAction;

/// Per-session counters for the fake sessions a generation drives.
#[derive(Default)]
struct GenerationSessionCounters {
    import_installs: AtomicU32,
    export_installs: AtomicU32,
    runtime_config_updates: AtomicU32,
}

fn generation_session(addr: IpAddr) -> (PeerHandle, Arc<GenerationSessionCounters>) {
    let (session_tx, mut session_rx) = mpsc::channel::<PeerCommand>(16);
    let counters = Arc::new(GenerationSessionCounters::default());
    let in_task = counters.clone();
    let task = tokio::spawn(async move {
        while let Some(command) = session_rx.recv().await {
            match command {
                PeerCommand::UpdateImportPolicy { reply, .. } => {
                    in_task.import_installs.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::UpdateExportPolicy { reply, .. } => {
                    in_task.export_installs.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::UpdateRuntimeConfig { reply, .. } => {
                    in_task
                        .runtime_config_updates
                        .fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::QueryState { reply } => {
                    let mut state = policy_test_peer_state(addr, SessionState::Established);
                    state.negotiated_hold_time = Some(90);
                    state.four_octet_as = Some(true);
                    let _ = reply.send(state);
                }
                PeerCommand::Shutdown | PeerCommand::Stop { .. } => break,
                _ => {}
            }
        }
        Ok(())
    });
    (PeerHandle::from_parts(session_tx, task), counters)
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
                RibUpdate::RefreshPeerOutbound { reply, .. } => {
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
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
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
        Box::pin(self.mgr.apply_reload_generation(candidate.clone(), actions)).await
    }

    async fn shutdown(mut self) {
        for (_, managed) in self.mgr.peers.drain() {
            let _ = managed.handle.shutdown().await;
        }
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
    let outcome = Box::pin(
        harness
            .mgr
            .apply_reload_generation(candidate.clone(), actions),
    )
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
    let outcome = Box::pin(harness.mgr.apply_reload_generation(orphaning, actions)).await;
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
