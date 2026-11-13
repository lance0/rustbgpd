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
    match Box::pin(diff(manager, candidate_toml, false)).await {
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

/// The mTLS client CRL is a credential file like the others: config
/// validation reads it, so below `operator_only` a candidate may only name
/// the running config's CRL, and that CRL is never a policy source.
#[tokio::test]
async fn the_client_crl_is_held_to_the_running_config_and_protected() {
    use std::os::unix::fs::PermissionsExt as _;

    let policy_dir = tempfile::tempdir().unwrap();
    let other_dir = tempfile::tempdir().unwrap();
    let pem = |dir: &Path, name: &str, kind: &str| {
        let path = dir.join(name);
        std::fs::write(
            &path,
            format!("-----BEGIN {kind}-----\n{SECRET}\n-----END {kind}-----\n"),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    };
    let cert = pem(policy_dir.path(), "server.pem", "CERTIFICATE");
    let key = pem(policy_dir.path(), "server.key", "PRIVATE KEY");
    let ca = pem(policy_dir.path(), "ca.pem", "CERTIFICATE");
    let crl = pem(policy_dir.path(), "clients.crl", "X509 CRL");
    let outside = pem(other_dir.path(), "elsewhere.crl", "X509 CRL");
    let grpc_tcp = |crl: &Path| {
        format!(
            "[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:0\"\n\
             tls_cert_file = {:?}\ntls_key_file = {:?}\n\
             tls_client_ca_file = {:?}\ntls_client_crl_file = {:?}\n",
            cert.display().to_string(),
            key.display().to_string(),
            ca.display().to_string(),
            crl.display().to_string(),
        )
    };
    // After the tier wrapper, which refuses a config that already has a
    // gRPC listener.
    let with_tls = |toml: String, crl: &Path| {
        toml.replace(
            "[global.telemetry.grpc_uds]\n",
            &format!("{}\n[global.telemetry.grpc_uds]\n", grpc_tcp(crl)),
        )
    };
    let edge = policy_dir.path().join("edge.rpol");
    let manager = || {
        let mut manager = manager_with_policy_dir(policy_dir.path());
        let running = with_tls(
            tier_authorized_uds_test_config(&format!(
                "[global]\nasn = 65001\nrouter_id = \"10.0.0.1\"\nlisten_port = 179\n\n\
                 [global.telemetry]\nprometheus_addr = \"0.0.0.0:9179\"\nlog_format = \"json\"\n\n\
                 [policy]\nrpol_files = [{:?}]\n",
                edge.display().to_string(),
            )),
            &crl,
        );
        manager.replace_current_config(
            Config::load_toml_with_diagnostics(&running, "running mTLS config").unwrap(),
        );
        manager
    };

    let error = diff_error(manager(), with_tls(candidate(&[&edge], ""), &outside)).await;
    assert!(!error.contains(SECRET), "{error}");
    assert!(
        error.contains("is not one the running config uses"),
        "{error}"
    );
    assert!(
        error.contains("tls_client_crl_file") || error.contains("elsewhere.crl"),
        "{error}"
    );

    let error = diff_error(manager(), with_tls(candidate(&[&crl], ""), &crl)).await;
    assert!(!error.contains(SECRET), "{error}");
    assert!(error.contains("is not a file under"), "{error}");
}

/// A config transaction stages an API candidate, which has no file of its
/// own; the running config file stays protected for the next candidate.
#[tokio::test]
async fn the_running_config_file_stays_protected_after_a_transaction() {
    let policy_dir = tempfile::tempdir().unwrap();
    let running = policy_dir.path().join("rustbgpd.toml");
    std::fs::write(&running, format!("# {SECRET}\n")).unwrap();
    let mut manager = manager_with_policy_dir(policy_dir.path());
    manager.current_config.file_path = Some(running.clone());
    let staged = Config::load_rpc_candidate(
        &candidate(&[&policy_dir.path().join("edge.rpol")], ""),
        "transaction candidate",
        false,
        Some(&manager.current_config.candidate_source_limits()),
    )
    .unwrap();
    assert_eq!(staged.file_path, None);

    let (tx, rx) = mpsc::channel(4);
    manager.rx = rx;
    let (internal_tx, internal_rx) = mpsc::channel(1);
    manager.internal_rx = Some(internal_rx);
    let task = tokio::spawn(manager.run());
    let (stage_tx, stage_rx) = oneshot::channel();
    internal_tx
        .send(InternalCommand::StageTransactionConfig {
            candidate: Box::new(staged),
            scope: TransactionConfigScope::Full,
            reply: stage_tx,
        })
        .await
        .unwrap();
    stage_rx.await.unwrap().expect("the candidate stages");

    let (reply, response) = oneshot::channel();
    tx.send(PeerManagerCommand::DiffRuntimeConfig {
        candidate_toml: candidate(&[&running], ""),
        operator_sources: false,
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
    let Err(rustbgpd_api::peer_types::RuntimeConfigDiffError::InvalidCandidate(error)) = result
    else {
        panic!("expected an invalid candidate, got {result:?}");
    };
    assert!(!error.contains(SECRET), "{error}");
    assert!(error.contains("is not a file under"), "{error}");
}

/// The protected files hold for imports too: a listed `.rpol` whose import
/// chain reaches the running config file is refused at the import, before
/// the config is read and parsed as policy source.
#[tokio::test]
async fn a_transitive_import_cannot_reach_the_running_config_file() {
    let policy_dir = tempfile::tempdir().unwrap();
    let running = policy_dir.path().join("rustbgpd.toml");
    std::fs::write(&running, format!("# {SECRET}\n")).unwrap();
    std::fs::write(
        policy_dir.path().join("mid.rpol"),
        "import \"rustbgpd.toml\"\n",
    )
    .unwrap();
    let top = policy_dir.path().join("top.rpol");
    std::fs::write(&top, format!("import \"mid.rpol\"\n{POLICY}")).unwrap();
    let mut manager = manager_with_policy_dir(policy_dir.path());
    manager.current_config.file_path = Some(running.clone());
    let error = diff_error(manager, candidate(&[&top], "")).await;
    assert!(!error.contains(SECRET), "{error}");
    assert!(error.contains("mid.rpol:1:8: resolve-error"), "{error}");
    assert!(!error.contains("rustbgpd.toml:"), "{error}");
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

#[test]
fn candidate_sources_refuse_unconfirmed_backups() {
    let dir = tempfile::tempdir().unwrap();
    let mut manager = manager_with_policy_dir(dir.path());
    let running = dir.path().join("rustbgpd.toml");
    std::fs::write(&running, "# accepted config\n").unwrap();
    manager.current_config.file_path = Some(running);
    let limits = manager.current_config.candidate_source_limits();
    let backup = dir
        .path()
        .join("rustbgpd.toml.unconfirmed-0123456789abcdef.rpol");
    std::fs::write(&backup, POLICY).unwrap();
    let importer = dir.path().join("imports-backup.rpol");
    std::fs::write(
        &importer,
        "import \"rustbgpd.toml.unconfirmed-0123456789abcdef.rpol\"\n",
    )
    .unwrap();
    for capture in [false, true] {
        for source in [&backup, &importer] {
            let toml = candidate(&[source], "");
            assert!(
                Config::load_rpc_candidate(&toml, "candidate", capture, Some(&limits)).is_err(),
                "backup admitted: {}",
                source.display()
            );
            Config::load_rpc_candidate(&toml, "operator", capture, None)
                .expect("operators retain access");
        }
    }
    let unrelated = dir
        .path()
        .join("other.toml.unconfirmed-0123456789abcdef.rpol");
    std::fs::write(&unrelated, POLICY).unwrap();
    Config::load_rpc_candidate(
        &candidate(&[&unrelated], ""),
        "candidate",
        false,
        Some(&limits),
    )
    .expect("only the running config's backups are protected");
}

#[test]
fn candidate_sources_refuse_hardlinked_protected_files() {
    let dir = tempfile::tempdir().unwrap();
    let mut manager = manager_with_policy_dir(dir.path());
    let running = dir.path().join("rustbgpd.toml");
    // Valid policy bytes make successful parsing evidence of an unintended read.
    std::fs::write(&running, POLICY).unwrap();
    manager.current_config.file_path = Some(running.clone());
    let limits = manager.current_config.candidate_source_limits();
    let linked = dir.path().join("linked.rpol");
    std::fs::hard_link(&running, &linked).unwrap();
    let importer = dir.path().join("imports-hardlink.rpol");
    std::fs::write(&importer, "import \"linked.rpol\"\n").unwrap();
    for capture in [false, true] {
        for source in [&linked, &importer] {
            let toml = candidate(&[source], "");
            let error = Config::load_rpc_candidate(&toml, "candidate", capture, Some(&limits))
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("not an admissible policy source")
                    || error.contains("compile failed"),
                "{error}"
            );
            Config::load_rpc_candidate(&toml, "operator", capture, None)
                .expect("operators retain access");
        }
    }
}

#[test]
fn candidate_datasets_refuse_hardlinked_configs_and_backups() {
    let dir = tempfile::tempdir().unwrap();
    let mut manager = manager_with_policy_dir(dir.path());
    let running = dir.path().join("rustbgpd.toml");
    std::fs::write(&running, "64500\n").unwrap();
    manager.current_config.file_path = Some(running.clone());
    let linked = dir.path().join("linked.list");
    std::fs::hard_link(&running, &linked).unwrap();
    let backup = dir
        .path()
        .join("rustbgpd.toml.unconfirmed-0123456789abcdef");
    std::fs::write(&backup, "64500\n").unwrap();
    let declaring = dir.path().join("declaring.rpol");
    std::fs::write(&declaring, "dataset asn-set customers\npolicy uses { term t { if route.origin-as in customers { accept } } }\n").unwrap();
    let limits = manager.current_config.candidate_source_limits();
    for capture in [false, true] {
        for source in [&linked, &backup] {
            let toml = candidate(
                &[&declaring],
                &format!(
                    "[policy.datasets.customers]\npath = {:?}\n",
                    source.display().to_string()
                ),
            );
            assert!(
                Config::load_rpc_candidate(&toml, "candidate", capture, Some(&limits)).is_err(),
                "protected dataset admitted"
            );
            Config::load_rpc_candidate(&toml, "operator", capture, None)
                .expect("operators retain access");
        }
    }
}

#[test]
fn candidate_backups_follow_terminal_config_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    let edge = dir.path().join("edge.rpol");
    std::fs::write(&edge, POLICY).unwrap();
    let active = dir.path().join("active.toml");
    let launch = dir.path().join("config.toml");
    std::fs::write(&active, candidate(&[&edge], "")).unwrap();
    std::os::unix::fs::symlink("active.toml", &launch).unwrap();
    let accepted = crate::config::AcceptedConfigSnapshot::load(&launch, None).unwrap();
    assert_eq!(
        accepted.config_ref().file_path.as_deref(),
        Some(launch.as_path())
    );
    let limits = accepted.config_ref().candidate_source_limits();
    // Boot revert saves beside the resolved target, not the launch symlink.
    let backup = dir.path().join("active.toml.unconfirmed-0123456789abcdef");
    std::fs::write(&backup, POLICY).unwrap();
    let importer = dir.path().join("imports-target-backup.rpol");
    std::fs::write(
        &importer,
        "import \"active.toml.unconfirmed-0123456789abcdef\"\n",
    )
    .unwrap();
    for capture in [false, true] {
        for source in [&backup, &importer] {
            let toml = candidate(&[source], "");
            assert!(
                Config::load_rpc_candidate(&toml, "candidate", capture, Some(&limits)).is_err(),
                "resolved-target backup admitted: {}",
                source.display()
            );
            Config::load_rpc_candidate(&toml, "operator", capture, None)
                .expect("operators retain access");
        }
    }
}

#[test]
fn candidate_backups_keep_protection_when_config_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let mut manager = manager_with_policy_dir(dir.path());
    let missing = dir.path().join("missing.toml");
    assert!(!missing.exists());
    manager.current_config.file_path = Some(missing);
    let limits = manager.current_config.candidate_source_limits();
    let backup = dir
        .path()
        .join("missing.toml.unconfirmed-0123456789abcdef.rpol");
    std::fs::write(&backup, POLICY).unwrap();
    let ordinary = candidate(&[&dir.path().join("edge.rpol")], "");
    for capture in [false, true] {
        let toml = candidate(&[&backup], "");
        assert!(
            Config::load_rpc_candidate(&toml, "candidate", capture, Some(&limits)).is_err(),
            "missing-config backup admitted"
        );
        Config::load_rpc_candidate(&toml, "operator", capture, None)
            .expect("operators retain access");
        Config::load_rpc_candidate(&ordinary, "candidate", capture, Some(&limits))
            .expect("a missing regular config still admits ordinary confined sources");
    }
}

#[test]
fn candidate_backups_fail_closed_for_a_dangling_config_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let edge = dir.path().join("edge.rpol");
    std::fs::write(&edge, POLICY).unwrap();
    let active = dir.path().join("active.toml");
    let launch = dir.path().join("config.toml");
    std::fs::write(&active, candidate(&[&edge], "")).unwrap();
    std::os::unix::fs::symlink("active.toml", &launch).unwrap();
    let accepted = crate::config::AcceptedConfigSnapshot::load(&launch, None).unwrap();
    let backup = dir.path().join("active.toml.unconfirmed-0123456789abcdef");
    std::fs::write(&backup, POLICY).unwrap();
    let importer = dir.path().join("imports-dangling-target-backup.rpol");
    std::fs::write(
        &importer,
        "import \"active.toml.unconfirmed-0123456789abcdef\"\n",
    )
    .unwrap();
    std::fs::remove_file(&active).unwrap();
    assert!(launch.symlink_metadata().unwrap().file_type().is_symlink());
    let limits = accepted.config_ref().candidate_source_limits();
    for capture in [false, true] {
        for source in [&backup, &importer, &edge] {
            let toml = candidate(&[source], "");
            let error = Config::load_rpc_candidate(&toml, "candidate", capture, Some(&limits))
                .expect_err("an unresolved terminal symlink must fail closed")
                .to_string();
            assert!(error.contains("replaced or removed on disk"), "{error}");
            assert!(!error.contains(dir.path().to_str().unwrap()), "{error}");
            assert!(!error.contains(POLICY), "{error}");
            Config::load_rpc_candidate(&toml, "operator", capture, None)
                .expect("operators retain access when the accepted target disappears");
        }
    }
}

#[test]
fn accepted_target_backups_survive_launch_retarget_and_unlink() {
    for unlink in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let edge = dir.path().join("edge.rpol");
        std::fs::write(&edge, POLICY).unwrap();
        let active = dir.path().join("active.toml");
        let alternate = dir.path().join("alternate.toml");
        let launch = dir.path().join("config.toml");
        std::fs::write(&active, candidate(&[&edge], "")).unwrap();
        std::fs::write(&alternate, candidate(&[&edge], "")).unwrap();
        std::os::unix::fs::symlink(&active, &launch).unwrap();
        let accepted = crate::config::AcceptedConfigSnapshot::load(&launch, None).unwrap();
        let backup = dir.path().join("active.toml.unconfirmed-old.rpol");
        let alias = dir.path().join("innocent.rpol");
        let importer = dir.path().join("importer.rpol");
        std::fs::write(&backup, POLICY).unwrap();
        std::fs::hard_link(&backup, &alias).unwrap();
        std::fs::write(&importer, "import \"innocent.rpol\"\n").unwrap();
        std::fs::remove_file(&launch).unwrap();
        if !unlink {
            std::os::unix::fs::symlink(&alternate, &launch).unwrap();
        }
        let declaring = dir.path().join("declaring.rpol");
        std::fs::write(&declaring, "dataset asn-set customers\npolicy uses { term t { if route.origin-as in customers { accept } } }\n").unwrap();
        let asn_backup = dir.path().join("active.toml.unconfirmed-asns");
        let asn_alias = dir.path().join("customers.list");
        std::fs::write(&asn_backup, "64500\n").unwrap();
        std::fs::hard_link(asn_backup, &asn_alias).unwrap();
        let runtime =
            Config::load_toml_with_diagnostics(&candidate(&[&edge], ""), "runtime").unwrap();
        let derived = accepted.derive_config(runtime).unwrap();
        let restored = crate::config::AcceptedConfigSnapshot::load_retained_with_target(
            accepted.normalized_toml(),
            &launch,
            accepted.config_ref().source_file_target.clone(),
        )
        .unwrap();
        for snapshot in [&accepted, derived.as_ref(), restored.as_ref()] {
            let limits = snapshot.config_ref().candidate_source_limits();
            for capture in [false, true] {
                for source in [&backup, &alias, &importer] {
                    assert!(
                        Config::load_rpc_candidate(
                            &candidate(&[source], ""),
                            "candidate",
                            capture,
                            Some(&limits)
                        )
                        .is_err()
                    );
                    Config::load_rpc_candidate(
                        &candidate(&[source], ""),
                        "operator",
                        capture,
                        None,
                    )
                    .unwrap();
                }
                Config::load_rpc_candidate(
                    &candidate(&[&edge], ""),
                    "candidate",
                    capture,
                    Some(&limits),
                )
                .unwrap();
                let dataset = format!(
                    "[policy.datasets.customers]\npath = {:?}\n",
                    asn_alias.display().to_string()
                );
                let datasets_toml = candidate(&[&declaring], &dataset);
                assert!(
                    Config::load_rpc_candidate(&datasets_toml, "candidate", capture, Some(&limits))
                        .is_err()
                );
                Config::load_rpc_candidate(&datasets_toml, "operator", capture, None).unwrap();
            }
        }
    }
}

#[test]
fn derived_and_retained_snapshots_own_distinct_published_inodes() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    std::fs::write(&config_path, candidate(&[], "")).unwrap();
    let accepted = crate::config::AcceptedConfigSnapshot::load(&config_path, None).unwrap();
    let original_alias = dir.path().join("original.rpol");
    std::fs::hard_link(&config_path, &original_alias).unwrap();
    let derived = accepted.derive_config(accepted.config()).unwrap();
    let retained = crate::config::AcceptedConfigSnapshot::load_retained_with_target(
        accepted.normalized_toml(),
        &config_path,
        accepted.config_ref().source_file_target.clone(),
    )
    .unwrap();
    let mut aliases = vec![original_alias];
    for (index, snapshot) in [derived.as_ref(), retained.as_ref()]
        .into_iter()
        .enumerate()
    {
        let stage = dir.path().join(format!("stage-{index}"));
        let alias = dir.path().join(format!("alias-{index}.rpol"));
        std::fs::write(&stage, POLICY).unwrap();
        let file = std::fs::File::open(&stage).unwrap();
        std::fs::rename(stage, &config_path).unwrap();
        std::fs::hard_link(&config_path, &alias).unwrap();
        snapshot.record_published_file(file);
        aliases.push(alias);
        assert!(
            accepted
                .config_ref()
                .source_file_target
                .as_ref()
                .unwrap()
                .verify_target()
                .is_err()
        );
        assert!(
            snapshot
                .config_ref()
                .source_file_target
                .as_ref()
                .unwrap()
                .verify_target()
                .is_ok()
        );
        if index == 0 {
            assert!(
                retained
                    .config_ref()
                    .source_file_target
                    .as_ref()
                    .unwrap()
                    .verify_target()
                    .is_err()
            );
        }
    }
    let unrelated = dir.path().join("unrelated");
    std::fs::write(&unrelated, "unrelated").unwrap();
    std::fs::rename(unrelated, &config_path).unwrap();
    for snapshot in [&accepted, derived.as_ref(), retained.as_ref()] {
        assert!(
            rustbgpd_policy::datasets::SourceFileProtection::new(
                vec![config_path.clone()],
                Some(config_path.clone()),
            )
            .snapshot(snapshot.config_ref().source_file_target.as_ref())
            .is_err()
        );
    }
}

#[tokio::test]
async fn candidate_admission_uses_the_accepted_watch_file_identity() {
    let dir = tempfile::tempdir().unwrap();
    let edge = dir.path().join("edge.rpol");
    std::fs::write(&edge, POLICY).unwrap();
    let config_path = dir.path().join("config.toml");
    std::fs::write(&config_path, candidate(&[&edge], "")).unwrap();
    let accepted = crate::config::AcceptedConfigSnapshot::load(&config_path, None).unwrap();
    let mut manager = manager_with_policy_dir(dir.path());
    manager.replace_current_config(accepted.config());
    let next = accepted.derive_config(accepted.config()).unwrap();
    let stage = dir.path().join("stage");
    let alias = dir.path().join("published.rpol");
    std::fs::write(&stage, POLICY).unwrap();
    let file = std::fs::File::open(&stage).unwrap();
    std::fs::rename(stage, &config_path).unwrap();
    std::fs::hard_link(&config_path, &alias).unwrap();
    next.record_published_file(file);
    let (_accepted_tx, accepted_rx) = tokio::sync::watch::channel(next);
    let manager = manager.with_accepted_identity(accepted_rx);
    Config::load_rpc_candidate(
        &candidate(&[&edge], ""),
        "healthy published generation",
        false,
        Some(&manager.candidate_source_limits()),
    )
    .unwrap();
    // Any rename-replace of the config (an editor save, a ConfigMap swap).
    let unrelated = dir.path().join("unrelated");
    std::fs::write(&unrelated, "unrelated").unwrap();
    std::fs::rename(unrelated, &config_path).unwrap();
    let limits = manager.candidate_source_limits();
    Config::load_rpc_candidate(&candidate(&[], ""), "source-free", false, Some(&limits))
        .expect("a candidate naming no source file needs no backup inventory");
    for source in [&edge, &alias] {
        let error = Config::load_rpc_candidate(
            &candidate(&[source], ""),
            "names a source",
            false,
            Some(&limits),
        )
        .unwrap_err();
        assert!(
            matches!(&error, crate::config::CandidateLoadError::Invalid(message)
                if message.contains("replaced or removed on disk")
                    && message.contains("SIGHUP")),
            "{error:?}"
        );
    }
    let error = diff_error(manager, candidate(&[&edge], "")).await;
    assert!(error.contains("replaced or removed on disk"), "{error}");
}

#[test]
fn config_directory_change_during_a_candidate_load_is_retryable() {
    let dir = tempfile::tempdir().unwrap();
    let edge = dir.path().join("edge.rpol");
    std::fs::write(&edge, POLICY).unwrap();
    let config_path = dir.path().join("config.toml");
    std::fs::write(&config_path, candidate(&[&edge], "")).unwrap();
    let accepted = crate::config::AcceptedConfigSnapshot::load(&config_path, None).unwrap();
    let limits = accepted.config_ref().candidate_source_limits();
    let toml = candidate(&[&edge], "");
    Config::load_rpc_candidate(&toml, "quiet directory", false, Some(&limits)).unwrap();
    let stage = dir.path().join(".persister-stage");
    crate::config::AFTER_INVENTORY.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || std::fs::write(stage, "x").unwrap()));
    });
    let error =
        Config::load_rpc_candidate(&toml, "busy directory", false, Some(&limits)).unwrap_err();
    assert!(
        matches!(&error, crate::config::CandidateLoadError::Unavailable(message)
            if message.contains("retry")),
        "{error:?}"
    );
    // The next attempt sees a settled directory.
    Config::load_rpc_candidate(&toml, "retry", false, Some(&limits)).unwrap();
}

#[test]
fn candidate_load_errors_map_to_retryable_and_final_statuses() {
    use crate::config::CandidateLoadError;
    use rustbgpd_api::evpn_service::EvpnRuntimeApplyError;
    use rustbgpd_api::peer_types::{RuntimeConfigDiffError, RuntimeConfigTransactionPlanError};
    let busy = || CandidateLoadError::Unavailable("busy".to_string());
    let refused = || CandidateLoadError::Invalid("refused".to_string());
    assert!(matches!(
        RuntimeConfigDiffError::from(busy()),
        RuntimeConfigDiffError::Unavailable(message) if message == "busy"
    ));
    assert!(matches!(
        RuntimeConfigDiffError::from(refused()),
        RuntimeConfigDiffError::InvalidCandidate(message) if message == "refused"
    ));
    assert!(matches!(
        RuntimeConfigTransactionPlanError::from(busy()),
        RuntimeConfigTransactionPlanError::Unavailable(message) if message == "busy"
    ));
    assert!(matches!(
        RuntimeConfigTransactionPlanError::from(refused()),
        RuntimeConfigTransactionPlanError::InvalidCandidate(message) if message == "refused"
    ));
    assert!(matches!(
        EvpnRuntimeApplyError::from(busy()),
        EvpnRuntimeApplyError::Unavailable(message) if message == "busy"
    ));
    assert!(matches!(
        EvpnRuntimeApplyError::from(refused()),
        EvpnRuntimeApplyError::InvalidArgument(message) if message == "refused"
    ));
}

/// Search permission on an ancestor is enough to load the config: boot,
/// `--check` and SIGHUP never list the directories above it.
#[test]
fn config_under_a_search_only_ancestor_loads() {
    use std::os::unix::fs::PermissionsExt;
    struct Restore(std::path::PathBuf);
    impl Drop for Restore {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let ancestor = dir.path().join("search-only");
    let parent = ancestor.join("etc");
    std::fs::create_dir_all(&parent).unwrap();
    let edge = parent.join("edge.rpol");
    std::fs::write(&edge, POLICY).unwrap();
    let config_path = parent.join("config.toml");
    std::fs::write(&config_path, candidate(&[&edge], "")).unwrap();
    std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o311)).unwrap();
    let _restore = Restore(ancestor.clone());
    if std::fs::read_dir(&ancestor).is_ok() {
        eprintln!("skipped: this process bypasses directory read permission");
        return;
    }
    let accepted = crate::config::AcceptedConfigSnapshot::load(&config_path, None).unwrap();
    Config::load_with_diagnostics(config_path.to_str().unwrap()).unwrap();
    let limits = accepted.config_ref().candidate_source_limits();
    Config::load_rpc_candidate(
        &candidate(&[&edge], ""),
        "below operator",
        false,
        Some(&limits),
    )
    .unwrap();
}

const OUTSIDE_POLICY: &str = "policy outside-in {\n    term rest { reject }\n}\n";

/// An accepted config in `etc/` whose `policy/` directory is the only place
/// a candidate below `operator_only` may name; `outside/` is not.
fn swap_fixture() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    crate::config::CandidateSourceLimits,
) {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().canonicalize().unwrap();
    let (etc, policy, outside) = (base.join("etc"), base.join("policy"), base.join("outside"));
    for path in [&etc, &policy, &outside] {
        std::fs::create_dir(path).unwrap();
    }
    let edge = policy.join("edge.rpol");
    std::fs::write(&edge, POLICY).unwrap();
    std::fs::write(outside.join("edge.rpol"), OUTSIDE_POLICY).unwrap();
    let config_path = etc.join("config.toml");
    std::fs::write(&config_path, candidate(&[&edge], "")).unwrap();
    let accepted = crate::config::AcceptedConfigSnapshot::load(&config_path, None).unwrap();
    let limits = accepted.config_ref().candidate_source_limits();
    (dir, policy, outside, limits)
}

fn after_inventory(hook: impl FnOnce() + 'static) {
    crate::config::AFTER_INVENTORY.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

fn policy_names(config: &Config) -> Vec<&str> {
    let mut names: Vec<&str> = config
        .policy
        .rpol
        .policies
        .keys()
        .map(String::as_str)
        .collect();
    names.sort_unstable();
    names
}

/// The entry module is read at the canonical path confinement checked, not
/// wherever its symlink points when the read starts.
#[test]
fn confined_entry_symlink_retargeted_after_the_check_is_not_followed() {
    let (_dir, policy, outside, limits) = swap_fixture();
    let link = policy.join("link.rpol");
    for capture in [false, true] {
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink("edge.rpol", &link).unwrap();
        let (swap, target) = (link.clone(), outside.join("edge.rpol"));
        after_inventory(move || {
            std::fs::remove_file(&swap).unwrap();
            std::os::unix::fs::symlink(target, &swap).unwrap();
        });
        let config = Config::load_rpc_candidate(
            &candidate(&[&link], ""),
            "candidate",
            capture,
            Some(&limits),
        )
        .unwrap();
        assert_eq!(policy_names(&config), ["edge-in"], "capture={capture}");
        // The candidate keeps the path as written.
        assert_eq!(config.policy.rpol_files, [link.display().to_string()]);
    }
}

/// A directory between a root and the entry, swapped for a symlink after the
/// check, is refused by the descriptor walk. File-less limits (no config file
/// or credentials to protect) still walk the checked path.
#[test]
fn confined_entry_refuses_an_ancestor_swapped_into_a_symlink() {
    let (_dir, policy, outside, accepted_limits) = swap_fixture();
    let sub = policy.join("sub");
    std::fs::create_dir(&sub).unwrap();
    let entry = sub.join("edge.rpol");
    std::fs::write(&entry, POLICY).unwrap();
    let fileless = Config::load_toml_with_diagnostics(
        &candidate(&[&policy.join("edge.rpol")], ""),
        "file-less",
    )
    .unwrap();
    assert!(fileless.file_path.is_none());
    let fileless_limits = fileless.candidate_source_limits();
    for limits in [&accepted_limits, &fileless_limits] {
        for capture in [false, true] {
            let (swap, retired, target) = (sub.clone(), policy.join("sub.old"), outside.clone());
            after_inventory(move || {
                std::fs::rename(&swap, &retired).unwrap();
                std::os::unix::fs::symlink(target, &swap).unwrap();
            });
            let loaded = Config::load_rpc_candidate(
                &candidate(&[&entry], ""),
                "candidate",
                capture,
                Some(limits),
            );
            std::fs::remove_file(&sub).unwrap();
            std::fs::rename(policy.join("sub.old"), &sub).unwrap();
            let error = match loaded {
                Ok(config) => panic!(
                    "a swapped ancestor was followed: {:?}",
                    policy_names(&config)
                ),
                Err(error) => error,
            };
            assert!(!error.to_string().contains("outside-in"), "{error}");
        }
    }
}

/// The accepted root directory itself, swapped for a symlink after the check,
/// is refused rather than resolved again.
#[test]
fn confined_entry_refuses_a_root_directory_swap() {
    let (_dir, policy, outside, limits) = swap_fixture();
    let entry = policy.join("edge.rpol");
    let retired = policy.with_extension("old");
    for capture in [false, true] {
        let (swap, aside, target) = (policy.clone(), retired.clone(), outside.clone());
        after_inventory(move || {
            std::fs::rename(&swap, &aside).unwrap();
            std::os::unix::fs::symlink(target, &swap).unwrap();
        });
        let loaded = Config::load_rpc_candidate(
            &candidate(&[&entry], ""),
            "candidate",
            capture,
            Some(&limits),
        );
        std::fs::remove_file(&policy).unwrap();
        std::fs::rename(&retired, &policy).unwrap();
        let error = match loaded {
            Ok(config) => panic!("a swapped root was followed: {:?}", policy_names(&config)),
            Err(error) => error,
        };
        assert!(!error.to_string().contains("outside-in"), "{error}");
    }
}

/// A dataset is read at the canonical path confinement checked, not wherever
/// its symlink points when the read starts.
#[test]
fn confined_dataset_symlink_retargeted_after_the_check_is_not_followed() {
    use rustbgpd_policy::datasets::{DatasetKind, load_dataset_file};
    let (_dir, policy, outside, limits) = swap_fixture();
    let declaring = policy.join("declaring.rpol");
    std::fs::write(&declaring, "dataset asn-set customers\npolicy uses { term t { if route.origin-as in customers { accept } } }\n").unwrap();
    let safe = policy.join("safe.list");
    std::fs::write(&safe, "64500\n").unwrap();
    let secret = outside.join("secret.list");
    std::fs::write(&secret, "64999\n").unwrap();
    let expected = load_dataset_file(&safe, DatasetKind::Asn).unwrap();
    assert_ne!(
        load_dataset_file(&secret, DatasetKind::Asn).unwrap(),
        expected
    );
    let link = policy.join("customers.list");
    let toml = candidate(
        &[&declaring],
        &format!(
            "[policy.datasets.customers]\npath = {:?}\n",
            link.display().to_string()
        ),
    );
    for capture in [false, true] {
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink("safe.list", &link).unwrap();
        let (swap, target) = (link.clone(), secret.clone());
        crate::config::AFTER_DATASET_CONFINEMENT.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                std::fs::remove_file(&swap).unwrap();
                std::os::unix::fs::symlink(target, &swap).unwrap();
            }));
        });
        let config = Config::load_rpc_candidate(&toml, "candidate", capture, Some(&limits))
            .expect("the checked dataset loads");
        let bound = config
            .policy
            .dataset_bindings
            .get("customers")
            .unwrap()
            .pin();
        assert_eq!(bound.data, expected, "capture={capture}");
        assert_eq!(
            config.policy.datasets["customers"].path,
            link.display().to_string()
        );
    }
}

/// A manager and its accepted snapshot, which loads `edge.rpol` from
/// `policy/` under `base`, with the given extra `[policy]` body.
fn accepted_manager(
    base: &Path,
    policy_extra: &str,
) -> (PeerManager, Arc<crate::config::AcceptedConfigSnapshot>) {
    accepted_manager_with(base, |edge| candidate(&[edge], policy_extra))
}

/// [`accepted_manager`] with the accepted document built from `edge.rpol`'s
/// path.
fn accepted_manager_with(
    base: &Path,
    document: impl FnOnce(&Path) -> String,
) -> (PeerManager, Arc<crate::config::AcceptedConfigSnapshot>) {
    let (etc, policy) = (base.join("etc"), base.join("policy"));
    std::fs::create_dir_all(&etc).unwrap();
    std::fs::create_dir_all(&policy).unwrap();
    let edge = policy.join("edge.rpol");
    std::fs::write(&edge, POLICY).unwrap();
    let config_path = etc.join("config.toml");
    std::fs::write(&config_path, document(&edge)).unwrap();
    let accepted =
        Arc::new(crate::config::AcceptedConfigSnapshot::load(&config_path, None).unwrap());
    let mut manager = test_peer_manager();
    manager.replace_current_config(accepted.config());
    let (_accepted_tx, accepted_rx) = tokio::sync::watch::channel(Arc::clone(&accepted));
    (manager.with_accepted_identity(accepted_rx), accepted)
}

/// Roots are resolved when the config is accepted. A nested root swapped
/// for a symlink afterwards does not move the confinement with it, and a
/// later API commit keeps the roots it was accepted with.
#[test]
fn nested_root_swapped_for_a_symlink_after_accept_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().canonicalize().unwrap();
    let (lib, outside) = (base.join("policy/lib"), base.join("outside"));
    std::fs::create_dir_all(&lib).unwrap();
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(lib.join("inside.rpol"), POLICY).unwrap();
    std::fs::write(outside.join("edge.rpol"), OUTSIDE_POLICY).unwrap();
    let (manager, accepted) = accepted_manager(
        &base,
        &format!("rpol_roots = [{:?}]\n", lib.display().to_string()),
    );
    for capture in [false, true] {
        Config::load_rpc_candidate(
            &candidate(&[&lib.join("inside.rpol")], ""),
            "candidate",
            capture,
            Some(&manager.candidate_source_limits()),
        )
        .expect("the nested root admits its own files");
    }
    std::fs::rename(&lib, base.join("policy/lib.old")).unwrap();
    std::os::unix::fs::symlink(&outside, &lib).unwrap();
    let committed = accepted.derive_config(accepted.config()).unwrap();
    let sources = [
        manager.candidate_source_limits(),
        committed.candidate_source_limits(),
    ];
    // The commit kept its roots: it still admits what they hold.
    for capture in [false, true] {
        Config::load_rpc_candidate(
            &candidate(&[&base.join("policy/edge.rpol")], ""),
            "candidate",
            capture,
            Some(&sources[1]),
        )
        .expect("a committed snapshot keeps the accepted roots");
    }
    for (limits, capture) in sources
        .iter()
        .flat_map(|limits| [(limits, false), (limits, true)])
    {
        let loaded = Config::load_rpc_candidate(
            &candidate(&[&lib.join("edge.rpol")], ""),
            "candidate",
            capture,
            Some(limits),
        );
        let error = match loaded {
            Ok(config) => panic!("a swapped root was followed: {:?}", policy_names(&config)),
            Err(error) => error,
        };
        assert!(!error.to_string().contains("outside-in"), "{error}");
    }
}

/// A configured root that is a regular file admits that file alone: it
/// loads, but its imports do not resolve from the directory around it.
#[test]
fn a_root_that_is_a_file_admits_only_that_file() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().canonicalize().unwrap();
    let shared = base.join("shared");
    std::fs::create_dir(&shared).unwrap();
    let (plain, importer, sibling) = (
        shared.join("plain.rpol"),
        shared.join("importer.rpol"),
        shared.join("sibling.rpol"),
    );
    std::fs::write(&plain, "policy plain-in {\n    term rest { accept }\n}\n").unwrap();
    std::fs::write(&importer, "import \"sibling.rpol\"\n").unwrap();
    std::fs::write(&sibling, OUTSIDE_POLICY).unwrap();
    let (manager, _) = accepted_manager(
        &base,
        &format!(
            "rpol_roots = [{:?}, {:?}]\n",
            plain.display().to_string(),
            importer.display().to_string()
        ),
    );
    let limits = manager.candidate_source_limits();
    for capture in [false, true] {
        let config = Config::load_rpc_candidate(
            &candidate(&[&plain], ""),
            "candidate",
            capture,
            Some(&limits),
        )
        .expect("a file root admits itself");
        assert_eq!(policy_names(&config), ["plain-in"]);
        for source in [&importer, &sibling] {
            let loaded = Config::load_rpc_candidate(
                &candidate(&[source], ""),
                "candidate",
                capture,
                Some(&limits),
            );
            let error = match loaded {
                Ok(config) => panic!(
                    "{} reached its directory: {:?}",
                    source.display(),
                    policy_names(&config)
                ),
                Err(error) => error,
            };
            assert!(!error.to_string().contains("outside-in"), "{error}");
        }
    }

    // With its directory under another root, the same file root's imports
    // resolve there as usual.
    let (manager, _) = accepted_manager(
        &base.join("covered"),
        &format!(
            "rpol_roots = [{:?}, {:?}]\n",
            importer.display().to_string(),
            shared.display().to_string()
        ),
    );
    let limits = manager.candidate_source_limits();
    for capture in [false, true] {
        let config = Config::load_rpc_candidate(
            &candidate(&[&importer], ""),
            "candidate",
            capture,
            Some(&limits),
        )
        .expect("a root covers the file root's directory");
        assert_eq!(policy_names(&config), ["outside-in"]);
    }
}

/// Whether a root is a file or a directory is fixed when the config is
/// accepted, and a later API commit keeps it. A directory put where a file
/// root was is not a root, and a file put where a directory root was is not
/// a source.
#[test]
fn a_root_replaced_by_the_other_kind_after_accept_admits_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().canonicalize().unwrap();
    let (file_root, dir_root) = (base.join("shared/plain.rpol"), base.join("lib"));
    std::fs::create_dir(base.join("shared")).unwrap();
    std::fs::create_dir(&dir_root).unwrap();
    std::fs::write(&file_root, POLICY).unwrap();
    let (manager, accepted) = accepted_manager(
        &base,
        &format!(
            "rpol_roots = [{:?}, {:?}]\n",
            file_root.display().to_string(),
            dir_root.display().to_string()
        ),
    );

    std::fs::remove_file(&file_root).unwrap();
    std::fs::create_dir(&file_root).unwrap();
    std::fs::write(file_root.join("child.rpol"), OUTSIDE_POLICY).unwrap();
    std::fs::remove_dir(&dir_root).unwrap();
    std::fs::write(&dir_root, OUTSIDE_POLICY).unwrap();
    let policy = base.join("policy");
    let (importer, reach) = (policy.join("importer.rpol"), policy.join("reach.rpol"));
    std::fs::write(&importer, "import \"child.rpol\"\n").unwrap();
    std::fs::write(&reach, "import \"../lib\"\n").unwrap();

    let root = |path: &Path| format!("rpol_roots = [{:?}]\n", path.display().to_string());
    let cases = [
        (
            "a file beneath a replaced file root",
            candidate(&[&file_root.join("child.rpol")], ""),
        ),
        (
            "an import searched in a replaced file root",
            candidate(&[&importer], &root(&file_root)),
        ),
        (
            "a file that replaced a directory root",
            candidate(&[&dir_root], ""),
        ),
        (
            "an import of a file that replaced a directory root",
            candidate(&[&reach], &root(&dir_root)),
        ),
    ];
    let committed = accepted.derive_config(accepted.config()).unwrap();
    let sources = [
        ("accepted", manager.candidate_source_limits()),
        ("committed", committed.candidate_source_limits()),
    ];
    for ((snapshot, limits), (case, toml), capture) in sources.iter().flat_map(|source| {
        cases
            .iter()
            .flat_map(move |case| [(source, case, false), (source, case, true)])
    }) {
        let loaded = Config::load_rpc_candidate(toml, "candidate", capture, Some(limits));
        let error = match loaded {
            Ok(config) => panic!(
                "{snapshot}: {case} was admitted: {:?}",
                policy_names(&config)
            ),
            Err(error) => error,
        };
        assert!(
            !error.to_string().contains("outside-in"),
            "{snapshot}: {case}: {error}"
        );
    }
}

/// A credential path may be a symlink the operator rotates between reloads.
/// The file it resolves to when a candidate loads is protected, as is the
/// one it resolved to when the config was accepted, which is still the live
/// credential. An API commit after the rotation keeps both.
#[test]
fn a_credential_symlink_rotated_after_accept_protects_both_targets() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().canonicalize().unwrap();
    let policy = base.join("policy");
    std::fs::create_dir(&policy).unwrap();
    let token = |name: &str| {
        let path = policy.join(name);
        std::fs::write(&path, format!("{SECRET}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    };
    let (old, new) = (token("token-v2"), token("token-v3"));
    let link = policy.join("token");
    std::os::unix::fs::symlink("token-v2", &link).unwrap();
    let with_token = |toml: String| {
        toml.replace(
            "[global.telemetry.grpc_uds]\n",
            &format!(
                "[global.telemetry.grpc_uds]\ntoken_file = {:?}\n",
                link.display().to_string()
            ),
        )
    };
    let (manager, accepted) =
        accepted_manager_with(&base, |edge| with_token(candidate(&[edge], "")));
    let declaring = policy.join("declaring.rpol");
    std::fs::write(
        &declaring,
        "dataset asn-set customers\npolicy uses { term t { if route.origin-as in customers { accept } } }\n",
    )
    .unwrap();

    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink("token-v3", &link).unwrap();
    let sources = [
        ("accepted", manager.candidate_source_limits()),
        (
            "committed event",
            accepted
                .derive_config(accepted.config())
                .unwrap()
                .candidate_source_limits(),
        ),
        (
            "committed transaction",
            accepted
                .derive_toml_without_sources(accepted.normalized_toml(), "commit")
                .unwrap()
                .candidate_source_limits(),
        ),
    ];
    for (snapshot, limits) in &sources {
        for (capture, target) in [(false, &old), (false, &new), (true, &old), (true, &new)] {
            let dataset = format!("[policy.datasets.customers]\npath = {target:?}\n");
            for candidate_toml in [candidate(&[target], ""), candidate(&[&declaring], &dataset)] {
                let loaded = Config::load_rpc_candidate(
                    &with_token(candidate_toml),
                    "candidate",
                    capture,
                    Some(limits),
                );
                let Err(error) = loaded else {
                    panic!("{snapshot}: {} was read as a source", target.display());
                };
                let error = error.to_string();
                assert!(
                    error.contains("is not a file under"),
                    "{snapshot}: {}: {error}",
                    target.display()
                );
                assert!(!error.contains(SECRET), "{error}");
            }
        }
    }
}

/// Imports written in an entry admitted only as a file root are looked up
/// under the candidate's policy directories, never relative to the entry's
/// own directory, and another module cannot import a file root. Listing the
/// directory in `rpol_roots` is the remedy for both.
#[test]
fn a_file_root_entry_resolves_imports_only_under_policy_directories() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().canonicalize().unwrap();
    let shared = base.join("shared");
    let (main, lib) = (shared.join("main.rpol"), shared.join("lib"));
    std::fs::create_dir_all(&lib).unwrap();
    std::fs::write(lib.join("common.rpol"), OUTSIDE_POLICY).unwrap();
    std::fs::write(&main, "import \"common.rpol\"\n").unwrap();
    let roots = |extra: &[&Path]| {
        let roots: Vec<String> = [main.as_path(), lib.as_path()]
            .iter()
            .chain(extra)
            .map(|root| root.display().to_string())
            .collect();
        format!("rpol_roots = {roots:?}\n")
    };
    let load = |entry: &Path, roots: &str, limits, capture| {
        Config::load_rpc_candidate(
            &candidate(&[entry], roots),
            "candidate",
            capture,
            Some(limits),
        )
    };
    let (manager, _) = accepted_manager(&base, &roots(&[]));
    let limits = manager.candidate_source_limits();
    let reach = base.join("policy/reach.rpol");
    std::fs::write(&reach, "import \"../shared/main.rpol\"\n").unwrap();
    for capture in [false, true] {
        // `shared/lib/common.rpol` is under a root, but `lib/common.rpol` is
        // relative to the unadmitted `shared/`.
        std::fs::write(&main, "import \"lib/common.rpol\"\n").unwrap();
        let Err(error) = load(&main, &roots(&[]), &limits, capture) else {
            panic!("an import resolved relative to a file root's directory");
        };
        assert!(error.to_string().contains("resolve-error"), "{error}");
        // The same module is found by its path under the `lib` root.
        std::fs::write(&main, "import \"common.rpol\"\n").unwrap();
        let config = load(&main, &roots(&[]), &limits, capture).expect("resolves under a root");
        assert_eq!(policy_names(&config), ["outside-in"]);
        // A module in an admitted directory cannot import the file root.
        let Err(error) = load(&reach, &roots(&[]), &limits, capture) else {
            panic!("a file root was imported by another module");
        };
        assert!(error.to_string().contains("resolve-error"), "{error}");
    }

    // With `shared/` listed, both forms load.
    let listed = base.join("listed");
    let (manager, _) = accepted_manager(&listed, &roots(&[&shared]));
    let limits = manager.candidate_source_limits();
    let reach = listed.join("policy/reach.rpol");
    std::fs::write(&reach, "import \"../../shared/main.rpol\"\n").unwrap();
    for capture in [false, true] {
        std::fs::write(&main, "import \"lib/common.rpol\"\n").unwrap();
        for entry in [&main, &reach] {
            let config =
                load(entry, &roots(&[&shared]), &limits, capture).expect("the directory is a root");
            assert_eq!(policy_names(&config), ["outside-in"]);
        }
    }
}
