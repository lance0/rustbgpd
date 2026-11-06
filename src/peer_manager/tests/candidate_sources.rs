//! External sources named by an API-supplied candidate (`DiffRuntimeConfig`,
//! `PlanConfigTransaction`): confined to the accepted config's policy
//! directories unless the caller is an operator, read off the actor, and
//! never echoed in errors.

use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use super::*;

const POLICY: &str = "policy edge-in {\n    term rest { accept }\n}\n";
const SECRET: &str = "observer-bearer-TOKEN-5c1d";

/// A manager whose accepted config loads `edge.rpol` from `policy_dir`.
fn manager_with_policy_dir(policy_dir: &Path) -> PeerManager {
    let rpol = policy_dir.join("edge.rpol");
    std::fs::write(&rpol, POLICY).unwrap();
    let mut manager = test_peer_manager();
    manager.replace_current_config(load_test_config(&format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[policy]
rpol_files = [{rpol:?}]
"#,
        rpol = rpol.display().to_string(),
    )));
    manager
}

/// Candidate TOML naming `rpol_files` and an optional extra `[policy]` body.
fn candidate(rpol_files: &[&Path], policy_extra: &str) -> String {
    let files: Vec<String> = rpol_files
        .iter()
        .map(|path| path.display().to_string())
        .collect();
    tier_authorized_uds_test_config(&format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[policy]
rpol_files = {files:?}
{policy_extra}
"#
    ))
}

/// Run `manager` and send one `DiffRuntimeConfig` from a caller below
/// `operator_only` (or an operator, with `operator_sources`).
async fn diff(
    mut manager: PeerManager,
    candidate_toml: String,
    operator_sources: bool,
) -> Result<
    rustbgpd_api::peer_types::RuntimeConfigDiff,
    rustbgpd_api::peer_types::RuntimeConfigDiffError,
> {
    let (tx, rx) = mpsc::channel(4);
    manager.rx = rx;
    let task = tokio::spawn(manager.run());
    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::DiffRuntimeConfig {
        candidate_toml,
        operator_sources,
        reply,
    })
    .await
    .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(10), response)
        .await
        .expect("config diff answers")
        .unwrap();
    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    task.await.unwrap();
    result
}

/// [`diff`] from a caller below `operator_only`, expected to be refused.
async fn diff_error(manager: PeerManager, candidate_toml: String) -> String {
    match diff(manager, candidate_toml, false).await {
        Err(rustbgpd_api::peer_types::RuntimeConfigDiffError::InvalidCandidate(message)) => message,
        other => panic!("expected an invalid candidate, got {other:?}"),
    }
}

#[tokio::test]
async fn candidate_rpol_outside_policy_directories_is_refused_without_its_content() {
    let policy_dir = tempfile::tempdir().unwrap();
    let other_dir = tempfile::tempdir().unwrap();
    let token = other_dir.path().join("token.txt");
    std::fs::write(&token, format!("{SECRET}\n")).unwrap();
    let manager = manager_with_policy_dir(policy_dir.path());

    let error = diff_error(manager, candidate(&[&token], "")).await;

    assert!(!error.contains(SECRET), "{error}");
    assert!(
        error.contains("outside the accepted config's policy directories"),
        "{error}"
    );
}

#[tokio::test]
async fn candidate_dataset_and_root_outside_policy_directories_are_refused() {
    let policy_dir = tempfile::tempdir().unwrap();
    let other_dir = tempfile::tempdir().unwrap();
    let secret = other_dir.path().join("secret.list");
    std::fs::write(&secret, format!("{SECRET}\n")).unwrap();
    let declaring = policy_dir.path().join("declaring.rpol");
    std::fs::write(
        &declaring,
        "dataset asn-set customers\npolicy uses { term t { if route.origin-as in customers { accept } } }\n",
    )
    .unwrap();
    let manager = manager_with_policy_dir(policy_dir.path());

    let dataset = format!("[policy.datasets.customers]\npath = {secret:?}\n");
    let error = diff_error(manager, candidate(&[&declaring], &dataset)).await;
    assert!(!error.contains(SECRET), "{error}");
    assert!(error.contains("dataset \"customers\""), "{error}");
    assert!(
        error.contains("outside the accepted config's policy directories"),
        "{error}"
    );

    let manager = manager_with_policy_dir(policy_dir.path());
    let roots = format!(
        "rpol_roots = [{:?}]\n",
        other_dir.path().display().to_string()
    );
    let error = diff_error(
        manager,
        candidate(&[&policy_dir.path().join("edge.rpol")], &roots),
    )
    .await;
    assert!(error.contains("rpol_roots"), "{error}");
    assert!(
        error.contains("outside the accepted config's policy directories"),
        "{error}"
    );
}

#[tokio::test]
async fn candidate_errors_name_locations_not_source_text() {
    let policy_dir = tempfile::tempdir().unwrap();
    let broken = policy_dir.path().join("broken.rpol");
    std::fs::write(&broken, format!("policy p {{\n    {SECRET} !\n}}\n")).unwrap();
    let manager = manager_with_policy_dir(policy_dir.path());
    let error = diff_error(manager, candidate(&[&broken], "")).await;
    assert!(!error.contains(SECRET), "{error}");
    assert!(error.contains("broken.rpol:2:5: "), "{error}");

    let dataset = policy_dir.path().join("customers.list");
    std::fs::write(&dataset, format!("64500\n{SECRET}\n")).unwrap();
    let declaring = policy_dir.path().join("declaring.rpol");
    std::fs::write(
        &declaring,
        "dataset asn-set customers\npolicy uses { term t { if route.origin-as in customers { accept } } }\n",
    )
    .unwrap();
    let manager = manager_with_policy_dir(policy_dir.path());
    let datasets = format!("[policy.datasets.customers]\npath = {dataset:?}\n");
    let error = diff_error(manager, candidate(&[&declaring], &datasets)).await;
    assert!(!error.contains(SECRET), "{error}");
    assert!(error.contains("line 2: invalid entry"), "{error}");
}

#[tokio::test]
async fn candidate_inside_policy_directories_still_diffs() {
    let policy_dir = tempfile::tempdir().unwrap();
    let added = policy_dir.path().join("added.rpol");
    std::fs::write(&added, "policy added-in {\n    term rest { reject }\n}\n").unwrap();
    let mut manager = manager_with_policy_dir(policy_dir.path());
    let (tx, rx) = mpsc::channel(4);
    manager.rx = rx;
    let task = tokio::spawn(manager.run());
    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::DiffRuntimeConfig {
        candidate_toml: candidate(&[&policy_dir.path().join("edge.rpol"), &added], ""),
        operator_sources: false,
        reply,
    })
    .await
    .unwrap();
    let diff = tokio::time::timeout(Duration::from_secs(10), response)
        .await
        .expect("config diff answers")
        .unwrap();
    assert!(diff.is_ok(), "{diff:?}");
    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    task.await.unwrap();
}

/// A FIFO named as an `.rpol` file must not hold the actor (or anything):
/// the diff answers promptly and an ordinary command is still served.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn candidate_fifo_is_refused_promptly_and_the_actor_stays_responsive() {
    let policy_dir = tempfile::tempdir().unwrap();
    let fifo = policy_dir.path().join("pipe.rpol");
    nix::unistd::mkfifo(
        &fifo,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    let mut manager = manager_with_policy_dir(policy_dir.path());
    let (tx, rx) = mpsc::channel(4);
    manager.rx = rx;
    let task = tokio::spawn(manager.run());

    let (reply, diff) = oneshot::channel();
    tx.send(PeerManagerCommand::DiffRuntimeConfig {
        candidate_toml: candidate(&[&fifo], ""),
        operator_sources: false,
        reply,
    })
    .await
    .unwrap();
    let (reply, ping) = oneshot::channel();
    tx.send(PeerManagerCommand::Ping { reply }).await.unwrap();
    let pinged = tokio::time::timeout(Duration::from_secs(5), ping).await;
    let diffed = tokio::time::timeout(Duration::from_secs(5), diff).await;

    // Release a reader blocked in open(2) so a failing run still exits.
    let _ = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&fifo);
    assert!(
        pinged.is_ok(),
        "the actor must answer while the candidate loads"
    );
    let diffed = diffed
        .expect("a FIFO candidate must be refused promptly")
        .unwrap();
    let Err(rustbgpd_api::peer_types::RuntimeConfigDiffError::InvalidCandidate(error)) = diffed
    else {
        panic!("expected an invalid candidate, got {diffed:?}");
    };
    assert!(error.contains("not a regular file"), "{error}");
    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    task.await.unwrap();
}

/// The plan path shares the loader: no source text in its errors either.
#[tokio::test]
async fn plan_candidate_outside_policy_directories_is_refused_without_its_content() {
    let policy_dir = tempfile::tempdir().unwrap();
    let other_dir = tempfile::tempdir().unwrap();
    let token = other_dir.path().join("token.txt");
    std::fs::write(&token, format!("{SECRET}\n")).unwrap();
    let mut manager = manager_with_policy_dir(policy_dir.path());
    let (rib_tx, mut rib_rx) = mpsc::channel(4);
    manager.rib_tx = rib_tx;
    let responder = tokio::spawn(async move {
        let Some(RibUpdate::QueryUpdateGroupSnapshot { reply }) = rib_rx.recv().await else {
            panic!("plan snapshot query missing");
        };
        reply
            .send(rustbgpd_rib::UpdateGroupSnapshot::default())
            .unwrap();
    });
    let error = manager
        .plan_config_transaction(&candidate(&[&token], ""), None, true)
        .await
        .unwrap_err();
    let rustbgpd_api::peer_types::RuntimeConfigTransactionPlanError::InvalidCandidate(error) =
        error
    else {
        panic!("expected an invalid candidate, got {error:?}");
    };
    assert!(!error.contains(SECRET), "{error}");
    assert!(
        error.contains("outside the accepted config's policy directories"),
        "{error}"
    );
    responder.await.unwrap();
}

/// An operator may stage a candidate's sources outside the accepted policy
/// directories (as `rs-config-render` does), and still gets no file text in
/// a compile error.
#[tokio::test]
async fn operator_candidate_may_name_new_directories_without_echoing_source() {
    let policy_dir = tempfile::tempdir().unwrap();
    let staged_dir = tempfile::tempdir().unwrap();
    let staged = staged_dir.path().join("staged.rpol");
    std::fs::write(&staged, "policy staged-in {\n    term rest { accept }\n}\n").unwrap();
    let manager = manager_with_policy_dir(policy_dir.path());
    let diffed = diff(manager, candidate(&[&staged], ""), true).await;
    assert!(diffed.is_ok(), "{diffed:?}");

    let token = staged_dir.path().join("token.txt");
    std::fs::write(&token, format!("{SECRET}\n")).unwrap();
    let manager = manager_with_policy_dir(policy_dir.path());
    let Err(rustbgpd_api::peer_types::RuntimeConfigDiffError::InvalidCandidate(error)) =
        diff(manager, candidate(&[&token], ""), true).await
    else {
        panic!("a token file does not compile");
    };
    assert!(!error.contains(SECRET), "{error}");
    assert!(error.contains("token.txt:1:1: "), "{error}");
}
