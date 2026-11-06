//! External sources named by an API-supplied candidate (`DiffRuntimeConfig`,
//! `PlanConfigTransaction`): confined to the accepted config's policy
//! directories unless the caller is an operator, read off the actor, and
//! never echoed in errors.

use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use super::*;

/// On a tree that opens a FIFO for reading, the reader blocks in open(2),
/// possibly on the runtime's only free worker, so tokio timers alone cannot
/// end the test. From an OS thread this opens `fifo` for writing, which
/// releases such a reader: continuously from 7 s on, after the test's 5 s
/// observation windows, and once more when dropped, before the FIFO's
/// directory is removed.
struct FifoReleaser {
    fifo: std::path::PathBuf,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl FifoReleaser {
    fn new(fifo: &Path) -> Self {
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (thread_fifo, thread_stop) = (fifo.to_path_buf(), std::sync::Arc::clone(&stop));
        std::thread::spawn(move || {
            let start = std::time::Instant::now();
            while !thread_stop.load(std::sync::atomic::Ordering::Relaxed) {
                if start.elapsed() > Duration::from_secs(7) {
                    release_fifo_reader(&thread_fifo);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        Self {
            fifo: fifo.to_path_buf(),
            stop,
        }
    }
}

impl Drop for FifoReleaser {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for _ in 0..10 {
            release_fifo_reader(&self.fifo);
            std::thread::sleep(Duration::from_millis(30));
        }
    }
}

fn release_fifo_reader(fifo: &Path) {
    let _ = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(fifo);
}

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
        error.contains("is not a file under the accepted config's policy directories"),
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
        error.contains("is not a file under the accepted config's policy directories"),
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
        error.contains("is not a file under the accepted config's policy directories"),
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
    let _release = FifoReleaser::new(&fifo);
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
        error.contains("is not a file under the accepted config's policy directories"),
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

/// Config validation reads gRPC credential files, so a candidate's
/// credential paths are held to the running config's below
/// `operator_only`, and every caller's read refuses a FIFO without blocking.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn candidate_credential_files_are_held_to_the_running_config() {
    let policy_dir = tempfile::tempdir().unwrap();
    let fifo = policy_dir.path().join("token.pipe");
    nix::unistd::mkfifo(
        &fifo,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    let _release = FifoReleaser::new(&fifo);
    let with_token = candidate(&[&policy_dir.path().join("edge.rpol")], "").replace(
        "[global.telemetry.grpc_uds]\n",
        &format!(
            "[global.telemetry.grpc_uds]\ntoken_file = {:?}\n",
            fifo.display().to_string()
        ),
    );
    for operator in [false, true] {
        let manager = manager_with_policy_dir(policy_dir.path());
        let diffed = tokio::time::timeout(
            Duration::from_secs(10),
            diff(manager, with_token.clone(), operator),
        )
        .await;
        let Ok(Err(rustbgpd_api::peer_types::RuntimeConfigDiffError::InvalidCandidate(error))) =
            diffed
        else {
            panic!("a FIFO token file must be refused promptly: {diffed:?}");
        };
        let expected = if operator {
            "not a regular file"
        } else {
            "is not one the running config uses"
        };
        assert!(error.contains(expected), "{error}");
    }
}

/// Below `operator_only`, a path that is not admissible gets one answer
/// whatever it names: `..` cannot turn the refusal into an existence,
/// permission or type probe of the filesystem.
#[tokio::test]
async fn inadmissible_paths_get_one_answer_whatever_they_name() {
    use std::os::unix::fs::PermissionsExt as _;

    let policy_dir = tempfile::tempdir().unwrap();
    let other_dir = tempfile::tempdir().unwrap();
    std::fs::write(other_dir.path().join("exists"), POLICY).unwrap();
    let locked = other_dir.path().join("locked");
    std::fs::create_dir(&locked).unwrap();
    std::fs::write(locked.join("inside"), POLICY).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    let up = "../".repeat(policy_dir.path().components().count());
    let other = other_dir
        .path()
        .strip_prefix("/")
        .unwrap()
        .display()
        .to_string();
    let mut answers = Vec::new();
    for name in ["exists", "missing", "locked/inside", "exists/not-a-dir"] {
        let probe = policy_dir.path().join(format!("{up}{other}/{name}"));
        let manager = manager_with_policy_dir(policy_dir.path());
        let error = diff_error(manager, candidate(&[&probe], "")).await;
        answers.push(error.replace(&probe.display().to_string(), "<probe>"));
    }
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        answers.windows(2).all(|pair| pair[0] == pair[1]),
        "{answers:#?}"
    );
    assert!(answers[0].contains("is not a file under"), "{}", answers[0]);
}

/// Below `operator_only`, the running config file itself is not a source,
/// even when it sits in a policy directory (as in the packaged layout).
#[tokio::test]
async fn the_running_config_file_is_not_a_candidate_source() {
    let policy_dir = tempfile::tempdir().unwrap();
    let running = policy_dir.path().join("rustbgpd.toml");
    std::fs::write(&running, format!("# {SECRET}\n")).unwrap();
    let mut manager = manager_with_policy_dir(policy_dir.path());
    manager.current_config.file_path = Some(running.clone());
    let error = diff_error(manager, candidate(&[&running], "")).await;
    assert!(!error.contains(SECRET), "{error}");
    assert!(error.contains("is not a file under"), "{error}");
}

/// Loads run off the actor and, below `operator_only`, at most
/// `MAX_CANDIDATE_LOADS` at a time, with operators exempt. A latch holds
/// four observer loads in flight; the actor still answers `Ping`, a fifth
/// observer diff is refused as unavailable, and an operator plan still runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn held_loads_leave_the_actor_free_and_operators_admitted() {
    use crate::peer_manager::reconcile::load_latch;

    /// Releases the latch even when an assertion fails first.
    struct Release;
    impl Drop for Release {
        fn drop(&mut self) {
            load_latch::release();
        }
    }

    load_latch::arm();
    let _release = Release;
    let policy_dir = tempfile::tempdir().unwrap();
    let mut manager = manager_with_policy_dir(policy_dir.path());
    let (rib_tx, mut rib_rx) = mpsc::channel(4);
    manager.rib_tx = rib_tx;
    tokio::spawn(async move {
        while let Some(update) = rib_rx.recv().await {
            if let RibUpdate::QueryUpdateGroupSnapshot { reply } = update {
                let _ = reply.send(rustbgpd_rib::UpdateGroupSnapshot::default());
            }
        }
    });
    let (tx, rx) = mpsc::channel(16);
    manager.rx = rx;
    let task = tokio::spawn(manager.run());
    let edge = policy_dir.path().join("edge.rpol");
    let latched = format!("{}\n{}\n", candidate(&[&edge], ""), load_latch::MARKER);

    let mut held = Vec::new();
    for _ in 0..4 {
        let (reply, response) = oneshot::channel();
        tx.send(PeerManagerCommand::DiffRuntimeConfig {
            candidate_toml: latched.clone(),
            operator_sources: false,
            reply,
        })
        .await
        .unwrap();
        held.push(response);
    }
    let all_held =
        tokio::task::spawn_blocking(|| load_latch::wait_held(4, Duration::from_secs(10)))
            .await
            .unwrap();

    let (reply, ping) = oneshot::channel();
    tx.send(PeerManagerCommand::Ping { reply }).await.unwrap();
    let pinged = tokio::time::timeout(Duration::from_secs(5), ping).await;

    let (reply, fifth) = oneshot::channel();
    tx.send(PeerManagerCommand::DiffRuntimeConfig {
        candidate_toml: latched.clone(),
        operator_sources: false,
        reply,
    })
    .await
    .unwrap();
    let fifth = tokio::time::timeout(Duration::from_secs(5), fifth).await;

    let (reply, plan) = oneshot::channel();
    tx.send(PeerManagerCommand::PlanConfigTransaction {
        candidate_toml: candidate(&[&edge], ""),
        expected_runtime_snapshot_token: None,
        verify_external_inputs: false,
        operator_sources: true,
        reply,
    })
    .await
    .unwrap();
    let plan = tokio::time::timeout(Duration::from_secs(10), plan).await;

    load_latch::release();
    assert!(all_held, "four observer loads must be in flight at once");
    assert!(pinged.is_ok(), "the actor must answer while loads are held");
    assert!(
        matches!(
            fifth,
            Ok(Ok(Err(
                rustbgpd_api::peer_types::RuntimeConfigDiffError::Unavailable(_)
            )))
        ),
        "a fifth observer load must be refused as unavailable: {fifth:?}"
    );
    assert!(
        matches!(plan, Ok(Ok(Ok(_)))),
        "an operator plan must run while observer loads hold the cap: {plan:?}"
    );
    for response in held {
        let diffed = tokio::time::timeout(Duration::from_secs(10), response)
            .await
            .expect("held diffs answer once released")
            .unwrap();
        assert!(diffed.is_ok(), "{diffed:?}");
    }
    tx.send(PeerManagerCommand::Shutdown).await.unwrap();
    task.await.unwrap();
}
