use super::*;

use crate::config::AcceptedConfigSnapshot;
use crate::config_persister::ConfigMutation;
use crate::peer_manager::InternalCommand;
use crate::peer_manager::generation::{ReloadGenerationOutcome, ReloadGenerationReceipt};
use crate::reload::{AcceptedBridgeReplacement, SighupReloadOutcome, SighupReloadPlan};

fn generation_reply(
    outcome: ReloadGenerationOutcome,
) -> (mpsc::Sender<InternalCommand>, tokio::task::JoinHandle<()>) {
    let (tx, mut rx) = mpsc::channel(8);
    let task = tokio::spawn(async move {
        while let Some(command) = rx.recv().await {
            match command {
                InternalCommand::PreflightReloadGeneration { reply, .. } => {
                    reply.send(Ok(())).unwrap();
                }
                InternalCommand::ApplyReloadGeneration {
                    datasets, reply, ..
                } => {
                    if matches!(outcome, ReloadGenerationOutcome::Applied(_)) {
                        drop(datasets.publish());
                    }
                    reply.send(outcome).unwrap();
                    return;
                }
                _ => panic!("unexpected generation command"),
            }
        }
        panic!("generation was never dispatched");
    });
    (tx, task)
}

async fn assert_source_admission(
    apply: &EvpnRuntimeReloadApply,
    admitted: &std::path::Path,
    refused: &std::path::Path,
) {
    let request = |path: &std::path::Path| proto::ApplyEvpnRuntimeRequest {
        candidate_toml: crate::test_support::tier_authorized_uds_test_config(&format!(
            "{}\n[policy]\nrpol_files = [{:?}]\n",
            minimal_runtime_candidate_toml(),
            path.display().to_string(),
        )),
        validate_only: true,
    };
    apply.apply_request(&request(admitted), None).await.unwrap();
    assert!(matches!(
        apply.apply_request(&request(refused), None).await,
        Err(GrpcEvpnRuntimeApplyError::InvalidArgument(_))
    ));
}

#[tokio::test]
async fn evpn_source_authority_follows_generation_bridge_adoption() {
    for outcome in [
        ReloadGenerationOutcome::Applied(ReloadGenerationReceipt::default()),
        ReloadGenerationOutcome::RejectedNoEffect("injected rejection".into()),
        ReloadGenerationOutcome::FullyCompensated("injected compensation".into()),
    ] {
        let applied = matches!(outcome, ReloadGenerationOutcome::Applied(_));
        let dir = tempfile::tempdir().unwrap();
        let roots = [dir.path().join("old"), dir.path().join("new")];
        for root in &roots {
            std::fs::create_dir(root).unwrap();
            std::fs::write(
                root.join("edge.rpol"),
                "policy edge-in { term rest { accept } }\n",
            )
            .unwrap();
        }
        let document = |root: &std::path::Path| {
            crate::test_support::tier_authorized_uds_test_config(&format!(
                "{}\n[policy]\nrpol_roots = [{:?}]\n",
                minimal_runtime_candidate_toml(),
                root.display().to_string(),
            ))
        };
        let path = dir.path().join("config.toml");
        std::fs::write(&path, document(&roots[0])).unwrap();
        let old = Arc::new(AcceptedConfigSnapshot::load(&path, None).unwrap());
        let (accepted_tx, accepted_rx) = watch::channel(Arc::clone(&old));
        let apply = EvpnRuntimeReloadApply::new(
            empty_evpn_runtime_coordinator(),
            Arc::new(tokio::sync::Mutex::new(())),
            Arc::new(TestRuntimeConverger::ok()),
            old.config(),
        )
        .with_accepted_source(Some(accepted_rx.clone()));
        let files = [roots[0].join("edge.rpol"), roots[1].join("edge.rpol")];
        assert_source_admission(&apply, &files[0], &files[1]).await;
        std::fs::write(&path, document(&roots[1])).unwrap();
        let desired = Arc::new(
            AcceptedConfigSnapshot::load_for_reload(&path, &old, &old.policy.dataset_bindings)
                .unwrap(),
        );
        // A sequential EVPN hook cannot publish an unaccepted on-disk config.
        apply
            .apply_config_if_changed(&desired.config(), |_, _| false, || {})
            .await;
        assert_source_admission(&apply, &files[0], &files[1]).await;
        let (generation_tx, generation) = generation_reply(outcome);
        let (peer_tx, _peer_rx) = mpsc::channel(8);
        let result = Box::pin(crate::reload::reload_config_with_tcp_ao(
            SighupReloadPlan {
                baseline_runtime: old.config(),
                desired,
            },
            old.global.telemetry.grpc_tcp.as_ref(),
            old.global.telemetry.grpc_uds.as_ref(),
            &peer_tx,
            Some(&generation_tx),
            None,
            None,
            Some(&apply),
            None,
            None,
        ))
        .await;
        generation.await.unwrap();
        match result {
            SighupReloadOutcome::Acknowledged(authority) => {
                assert!(applied);
                assert_source_admission(&apply, &files[0], &files[1]).await;
                adopt_through_bridge(&apply, accepted_tx, authority.desired, &files).await;
                assert_eq!(
                    accepted_rx.borrow().policy.rpol_roots,
                    vec![roots[1].display().to_string()]
                );
                assert_source_admission(&apply, &files[1], &files[0]).await;
            }
            SighupReloadOutcome::CleanNoEffect(_) => {
                assert!(!applied);
                assert_eq!(
                    accepted_rx.borrow().policy.rpol_roots,
                    old.policy.rpol_roots
                );
                assert_source_admission(&apply, &files[0], &files[1]).await;
            }
            SighupReloadOutcome::RecoveryFenced { .. } => panic!("unexpected fence"),
        }
    }
}

/// The EVPN apply path uses the roots resolved when the config was accepted:
/// a nested root swapped for a symlink afterwards is not followed.
#[tokio::test]
async fn evpn_source_authority_keeps_the_roots_resolved_at_accept() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().canonicalize().unwrap();
    let (policy, outside) = (base.join("policy"), base.join("outside"));
    let lib = policy.join("lib");
    for root in [&policy, &lib, &outside] {
        std::fs::create_dir_all(root).unwrap();
        std::fs::write(
            root.join("edge.rpol"),
            "policy edge-in { term rest { accept } }\n",
        )
        .unwrap();
    }
    let path = base.join("config.toml");
    std::fs::write(
        &path,
        crate::test_support::tier_authorized_uds_test_config(&format!(
            "{}\n[policy]\nrpol_roots = [{:?}, {:?}]\n",
            minimal_runtime_candidate_toml(),
            policy.display().to_string(),
            lib.display().to_string(),
        )),
    )
    .unwrap();
    let accepted = Arc::new(AcceptedConfigSnapshot::load(&path, None).unwrap());
    let (_accepted_tx, accepted_rx) = watch::channel(Arc::clone(&accepted));
    let apply = EvpnRuntimeReloadApply::new(
        empty_evpn_runtime_coordinator(),
        Arc::new(tokio::sync::Mutex::new(())),
        Arc::new(TestRuntimeConverger::ok()),
        accepted.config(),
    )
    .with_accepted_source(Some(accepted_rx));
    assert_source_admission(&apply, &lib.join("edge.rpol"), &outside.join("edge.rpol")).await;
    std::fs::rename(&lib, policy.join("lib.old")).unwrap();
    std::os::unix::fs::symlink(&outside, &lib).unwrap();
    assert_source_admission(&apply, &policy.join("edge.rpol"), &lib.join("edge.rpol")).await;
}

async fn adopt_through_bridge(
    apply: &EvpnRuntimeReloadApply,
    accepted_tx: watch::Sender<Arc<AcceptedConfigSnapshot>>,
    desired: Arc<AcceptedConfigSnapshot>,
    files: &[std::path::PathBuf; 2],
) {
    let (event_tx, event_rx) = mpsc::channel(1);
    let (replace_tx, replace_rx) = mpsc::channel(1);
    let (mutation_tx, mut mutation_rx) = mpsc::channel(1);
    let bridge = tokio::spawn(crate::reload::run_config_bridge_accepted(
        event_rx,
        replace_rx,
        mutation_tx,
        accepted_tx,
    ));
    let (adopted, adopted_rx) = tokio::sync::oneshot::channel();
    replace_tx
        .send(AcceptedBridgeReplacement::for_test(desired, adopted))
        .await
        .unwrap();
    let Some(ConfigMutation::AdoptReloadSnapshot { adopted, .. }) = mutation_rx.recv().await else {
        panic!("expected persister adoption");
    };
    // The generation landed, but the real bridge is still waiting for the
    // persister. Candidate admission must retain the old accepted authority.
    assert_source_admission(apply, &files[0], &files[1]).await;
    adopted.send(()).unwrap();
    assert!(matches!(
        adopted_rx.await.unwrap(),
        rustbgpd_transport::listener::ReloadDispatch::Replied(())
    ));
    drop(event_tx);
    drop(replace_tx);
    bridge.await.unwrap();
}
