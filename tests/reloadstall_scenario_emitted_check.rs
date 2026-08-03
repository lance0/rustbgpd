//! Acceptance gate for the retained 1,000-peer route-server scenario.

#[test]
/// Load-bearing proof: restoring the generator's local ASN to 65500 makes
/// peer 988 iBGP and fails the indexed eBGP assertion before `--check` runs;
/// daemon-invalid generated config or policy fails the real daemon check.
fn emitted_1000_peer_scenario_is_all_ebgp_and_daemon_valid() {
    use std::collections::BTreeSet;

    let dir = tempfile::tempdir().expect("tempdir");
    let generator = format!(
        "{}/bench/scale/reloadstall/gen-scenario.py",
        env!("CARGO_MANIFEST_DIR")
    );
    let output = std::process::Command::new("python3")
        .args([&generator, "1000"])
        .arg(dir.path())
        .args(["1790", "1000"])
        .output()
        .expect("run scenario generator");
    assert!(
        output.status.success(),
        "scenario generator failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let config_path = dir.path().join("config.toml");
    let config_text = std::fs::read_to_string(&config_path).expect("read config");
    let config: toml::Value = toml::from_str(&config_text).expect("parse generated TOML");
    let local_asn = config["global"]["asn"].as_integer().expect("global ASN");
    let neighbors = config["neighbors"].as_array().expect("neighbors array");
    assert_eq!(neighbors.len(), 1000);
    let mut addresses = BTreeSet::new();
    let mut remote_asns = BTreeSet::new();
    let mut common_shape = None;
    for (index, neighbor) in neighbors.iter().enumerate() {
        let address = neighbor["address"].as_str().expect("neighbor address");
        let expected_address = format!("127.1.{}.{}", index / 200, index % 200 + 1);
        assert_eq!(address, expected_address, "peer {index} address");
        assert!(
            addresses.insert(address),
            "duplicate peer address at {index}"
        );
        let remote_asn = neighbor["remote_asn"].as_integer().expect("remote ASN");
        assert_eq!(remote_asn, 64_512 + index as i64, "peer {index} ASN");
        assert!(
            remote_asns.insert(remote_asn),
            "duplicate remote ASN at peer {index}"
        );
        assert_ne!(
            remote_asn, local_asn,
            "peer {index} must be eBGP (local ASN {local_asn}, remote ASN {remote_asn})"
        );
        assert_eq!(neighbor["route_server_client"].as_bool(), Some(true));
        assert_eq!(
            neighbor["families"].as_array(),
            Some(&vec![toml::Value::String("ipv4_unicast".to_owned())]),
            "peer {index} family"
        );
        let mut shape = neighbor.as_table().expect("neighbor table").clone();
        shape.remove("address");
        shape.remove("remote_asn");
        match &common_shape {
            None => common_shape = Some(shape),
            Some(expected) => assert_eq!(&shape, expected, "peer {index} grouped shape"),
        }
    }
    assert_eq!(addresses.len(), 1000);
    assert_eq!(remote_asns.len(), 1000);
    assert!(
        (4_200_000_000..=4_294_967_294).contains(&local_asn),
        "local ASN {local_asn} must be RFC 6996 private four-octet space"
    );

    let checked = std::process::Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
        .arg("--check")
        .arg(&config_path)
        .output()
        .expect("run rustbgpd --check");
    assert!(
        checked.status.success(),
        "rustbgpd --check rejected the generated scenario\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&checked.stdout),
        String::from_utf8_lossy(&checked.stderr)
    );
}

#[test]
/// Red proof: replacing the fingerprint-qualified status match with the old
/// bare `pass` match, or removing the sampler wait/data gate, makes this fail.
/// The column assertion likewise fails if the ambiguous historical label is
/// restored in future output.
fn irr_reload_campaign_seals_resume_rows_and_rss_evidence() {
    let runner = std::fs::read_to_string(format!(
        "{}/bench/scale/irrreload/run-irr-reload.sh",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("read IRR reload runner");

    for required in [
        "pass $CAMPAIGN_FINGERPRINT",
        "provenance.json",
        "DIRTY_STATE_SHA256",
        "bird_image_id",
        "openbgpd_image_id",
        "scenario.sha256",
        "dataset.sha256",
        "dataset_sha256",
        ".runtime_files | select(type == \"array\" and length > 0)[]",
        "cell_receipt_matches",
        "[ \"$actual_sha\" = \"$scenario_sha\" ] || return 1",
        "evidence.sha256",
        "sha256sum --check --strict --status evidence.sha256",
        "cmp -s \"$cdir/rows.csv\" \"$rows_tmp\"",
        "validate_cell_rows \"$cdir/rows.csv\" \"$cell\"",
        "pass $CAMPAIGN_FINGERPRINT $CELL_SCENARIO_SHA256 $CELL_DATASET_SHA256 $CELL_EVIDENCE_SHA256",
        "wait \"$sampler_pid\"",
        "RSS sampler produced empty or invalid data",
        "changed_first_generation_update_p50_ms",
        "changed_first_generation_update_p95_ms",
        "changed_first_generation_update_max_ms",
        "artifact root belongs to campaign",
        "existing failed, interrupted, or inconsistent evidence is immutable",
        "choose a fresh ARTIFACTS_DIR",
        "artifact root has malformed provenance; refusing to overwrite it",
        "non-empty artifact root has no provenance; refusing to overwrite it",
        "refusing to overwrite or repair its provenance",
        "if [ \"$PRIOR_PROVENANCE\" != \"$SEALED_CAMPAIGN_PROVENANCE\" ]; then",
        "if [ -e \"$ART/$cell\" ] || [ \"${existing_rows:-0}\" -ne 0 ]; then",
        "CELLS=(rustbgpd-sighup bird openbgpd)",
        "rustbgpd-txn must use a separate measured campaign",
        "TXN_MAX_CANDIDATE_BYTES",
        "if [ \"$candidate_bytes\" -gt \"$TXN_MAX_CANDIDATE_BYTES\" ]; then",
        "candidate exceeds the ${TXN_MAX_CANDIDATE_BYTES}-byte tonic request budget",
        "cleanup_active_processes",
        "terminate_process_group \"$pid\"",
        "ACTIVE_HARNESS_PID",
        "ACTIVE_SAMPLER_PID",
        "ACTIVE_DAEMON_PID",
        "kill -TERM -- \"-$pid\"",
        "kill -KILL -- \"-$pid\"",
        "trap 'exit 130' INT",
        "trap 'exit 143' TERM",
        "required manifest/provenance retention failed",
        "rc=97",
        "NF != 23 || $1 != cell || $2 != sprintf(\"%d\", NR)",
        "NR != expected",
        "invalid, missing, or duplicate measurement rows",
        "failed to retain measurement rows",
        "rc=96",
        "[ \"${existing_rows:-0}\" -eq \"$RELOADS\" ]",
        "[ \"${rows:-0}\" -ne \"$RELOADS\" ]",
    ] {
        assert!(
            runner.contains(required),
            "missing receipt seal: {required}"
        );
    }
    assert!(
        !runner.contains("changed_first_update_p50_ms"),
        "future rows must not reuse the ambiguous historical column name"
    );
    let retention_gate = runner
        .find("required manifest/provenance retention failed")
        .expect("retention failure gate");
    let scenario_delete = runner
        .rfind("rm -rf \"$run\"")
        .expect("successful scenario deletion");
    assert!(
        retention_gate < scenario_delete,
        "retention must fail closed before successful scenario deletion"
    );
    let cleanup = runner
        .split_once("cleanup() {")
        .and_then(|(_, rest)| rest.split_once("trap cleanup EXIT"))
        .map(|(body, _)| body)
        .expect("cleanup function body");
    assert!(cleanup.contains("cleanup_active_processes"));
    let terminate = runner
        .split_once("terminate_process_group() {")
        .and_then(|(_, rest)| rest.split_once("cleanup_active_processes() {"))
        .map(|(body, _)| body)
        .expect("bounded process-group terminator");
    assert!(terminate.contains("kill -TERM -- \"-$pid\""));
    assert!(terminate.contains("kill -KILL -- \"-$pid\""));
    assert!(terminate.contains("wait \"$pid\""));
}

#[test]
/// Red proof: removing or moving the empty-sample guard after the CSV append
/// makes this fail, restoring the teardown race's bogus terminal `0,0` row.
fn rss_sampler_drops_empty_teardown_samples_before_append() {
    let sampler = std::fs::read_to_string(format!(
        "{}/bench/scale/matrix/rss-sampler.sh",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("read RSS sampler");
    let guard = sampler
        .find("if [ \"$n\" -eq 0 ] || [ \"$total\" -eq 0 ]; then")
        .expect("empty RSS sample guard");
    let append = sampler
        .find("echo \"$(date +%s),$total,$n\" >>\"$out\"")
        .expect("RSS sample append");
    assert!(
        guard < append,
        "empty samples must be rejected before append"
    );
}

#[cfg(target_os = "linux")]
#[test]
/// Red proof: removing the process-group KILL escalation leaves the TERM-
/// ignoring child alive after the helper returns and fails the bounded liveness
/// assertion. The external timeout and cleanup guard turn that regression into
/// a bounded failure rather than a hung test or leaked process.
fn irr_reload_process_group_cleanup_kills_a_stubborn_child() {
    use std::os::unix::process::ExitStatusExt;
    use std::process::Stdio;

    struct ProcessGroupGuard {
        child: std::process::Child,
        pgid: String,
    }

    impl Drop for ProcessGroupGuard {
        fn drop(&mut self) {
            let _ = std::process::Command::new("kill")
                .args(["-KILL", "--", &self.pgid])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    let runner = std::fs::read_to_string(format!(
        "{}/bench/scale/irrreload/run-irr-reload.sh",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("read IRR reload runner");
    let terminate = runner
        .split_once("terminate_process_group() {")
        .and_then(|(_, rest)| rest.split_once("cleanup_active_processes() {"))
        .map(|(body, _)| format!("terminate_process_group() {{{body}"))
        .expect("bounded process-group terminator");

    let ready_dir = tempfile::tempdir().expect("readiness directory");
    let ready_path = ready_dir.path().join("ready");
    let child = std::process::Command::new("setsid")
        .args([
            "bash",
            "-c",
            "trap '' TERM; : >\"$1\"; while :; do sleep 1; done",
            "stubborn-child",
        ])
        .arg(&ready_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start stubborn process group");
    let pid = child.id();
    let pgid = format!("-{pid}");
    let mut stubborn = ProcessGroupGuard { child, pgid };
    let ready = (0..100).any(|_| {
        if ready_path.is_file() {
            true
        } else {
            std::thread::sleep(std::time::Duration::from_millis(10));
            false
        }
    });
    assert!(ready, "stubborn child did not become ready");

    let cleanup = std::process::Command::new("timeout")
        .args(["--signal=KILL", "5s", "bash", "-c"])
        .arg(format!("{terminate}\nterminate_process_group {pid}"))
        .status()
        .expect("run process-group cleanup");
    assert!(cleanup.success(), "cleanup helper failed");

    let status = (0..20)
        .find_map(|_| {
            let status = stubborn.child.try_wait().expect("inspect stubborn process");
            if status.is_none() {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            status
        })
        .expect("stubborn process survived process-group cleanup");
    assert_eq!(status.signal(), Some(9), "stubborn group must reach KILL");
    let gone = (0..20).any(|_| {
        let alive = std::process::Command::new("kill")
            .args(["-0", "--", &stubborn.pgid])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("probe process-group liveness")
            .success();
        if alive {
            std::thread::sleep(std::time::Duration::from_millis(50));
            false
        } else {
            true
        }
    });
    assert!(gone, "stubborn process group survived cleanup");
}

fn sha256_hex(bytes: impl AsRef<[u8]>) -> String {
    use sha2::{Digest, Sha256};

    Sha256::digest(bytes.as_ref())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
/// Red proof: removing the retained-evidence digest check accepts the RSS
/// mutation; removing the exact global/cell row comparison accepts the global
/// row mutation; removing numeric row validation accepts the coherently
/// re-sealed malformed row.
fn irr_reload_resume_rejects_mutated_or_malformed_evidence() {
    let root = env!("CARGO_MANIFEST_DIR");
    let runner = std::fs::read_to_string(format!("{root}/bench/scale/irrreload/run-irr-reload.sh"))
        .expect("read runner");
    let receipt_functions = runner
        .split_once("cell_receipt_matches() {")
        .and_then(|(_, rest)| rest.split_once("seal_scenario() {"))
        .map(|(body, _)| format!("cell_receipt_matches() {{{body}"))
        .expect("receipt functions");

    let art = tempfile::tempdir().expect("artifact root");
    let cdir = art.path().join("bird");
    std::fs::create_dir(&cdir).expect("cell dir");
    std::fs::write(art.path().join("dataset.sha256"), "dataset\n").expect("dataset seal");
    let scenario = "012345  ./manifest.json\n";
    std::fs::write(cdir.join("scenario.sha256"), scenario).expect("scenario roster");
    let scenario_sha = sha256_hex(scenario);
    let provenance = serde_json::json!({
        "fingerprint": "campaign",
        "scenario": {
            "manifest_sha256": scenario_sha,
            "dataset_sha256": "dataset"
        }
    });
    std::fs::write(
        cdir.join("provenance.json"),
        serde_json::to_vec(&provenance).expect("provenance JSON"),
    )
    .expect("provenance");
    let good_row =
        "bird,1,10,1,9,100,1.0,1.1,1.2,2.0,2.1,2.2,3.0,3.1,3.2,4.0,4.1,4.2,100.0,101.0,10,10,0\n";
    let header = "cell,reload,peers_total,peers_changed,peers_stable,prefixes,completion_p50_s,completion_p95_s,completion_max_s,changed_maxgap_p50_ms,changed_maxgap_p95_ms,changed_maxgap_max_ms,all_observer_maxgap_p50_ms,all_observer_maxgap_p95_ms,all_observer_maxgap_max_ms,changed_first_generation_update_p50_ms,changed_first_generation_update_p95_ms,changed_first_generation_update_max_ms,rss_before_mib,rss_after_mib,stable_marker_peers,sessions_up,parse_errors\n";
    for (name, contents) in [
        ("daemon.log", "daemon\n"),
        ("manifest.json", "{}\n"),
        ("reloadstall.log", "receipt\n"),
        ("rows.csv", good_row),
        ("rss.csv", "epoch_s,total_rss_kib,pids\n1,100,1\n"),
    ] {
        std::fs::write(cdir.join(name), contents).expect("cell evidence");
    }
    std::fs::write(art.path().join("rows.csv"), format!("{header}{good_row}"))
        .expect("campaign rows");

    let seal = |cdir: &std::path::Path| {
        let files = [
            "daemon.log",
            "manifest.json",
            "provenance.json",
            "reloadstall.log",
            "rows.csv",
            "rss.csv",
            "scenario.sha256",
        ];
        let mut roster = String::new();
        for name in files {
            let bytes = std::fs::read(cdir.join(name)).expect("read evidence");
            roster.push_str(&format!("{}  {name}\n", sha256_hex(bytes)));
        }
        std::fs::write(cdir.join("evidence.sha256"), &roster).expect("evidence roster");
        let evidence_sha = sha256_hex(roster);
        std::fs::write(
            cdir.join("status"),
            format!("pass campaign {scenario_sha} dataset {evidence_sha}\n"),
        )
        .expect("status");
    };
    seal(&cdir);

    let verify = || {
        std::process::Command::new("bash")
            .arg("-c")
            .arg(format!(
                "set -u\nART='{}'\nRELOADS=1\nCAMPAIGN_FINGERPRINT=campaign\nhash_file() {{ sha256sum -- \"$1\" | cut -d' ' -f1; }}\n{}\ncell_receipt_matches \"$ART/bird\"",
                art.path().display(),
                receipt_functions
            ))
            .status()
            .expect("run receipt verifier")
            .success()
    };

    assert!(verify(), "sealed receipt must resume");
    std::fs::write(
        art.path().join("rows.csv"),
        format!("{header}{}", good_row.replace("1.0", "9.0")),
    )
    .expect("mutate root row");
    assert!(!verify(), "changed global row must invalidate resume");
    std::fs::write(art.path().join("rows.csv"), format!("{header}{good_row}"))
        .expect("restore root row");
    std::fs::write(
        cdir.join("rss.csv"),
        "epoch_s,total_rss_kib,pids\n1,999,1\n",
    )
    .expect("mutate RSS evidence");
    assert!(!verify(), "changed raw evidence must invalidate resume");

    let malformed_row = good_row.replacen("1.0", "oops", 1);
    std::fs::write(
        cdir.join("rss.csv"),
        "epoch_s,total_rss_kib,pids\n1,100,1\n",
    )
    .expect("restore RSS evidence");
    std::fs::write(cdir.join("rows.csv"), &malformed_row).expect("malformed cell row");
    std::fs::write(
        art.path().join("rows.csv"),
        format!("{header}{malformed_row}"),
    )
    .expect("malformed root row");
    seal(&cdir);
    assert!(!verify(), "malformed numeric row must invalidate resume");
}

fn run_irr_protocol(args: &[&str], smoke: bool) -> String {
    let runner = format!(
        "{}/bench/scale/irrreload/run-irr-reload.sh",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut command = std::process::Command::new("bash");
    command.arg(runner).args(args).env("DRY_RUN_PROTOCOL", "1");
    for knob in [
        "N_MEMBERS",
        "TOTAL_PREFIXES",
        "MIN_LIST",
        "MAX_LIST",
        "RELOADS",
        "CONTROL_SECS",
        "TXN_MAX_CANDIDATE_BYTES",
    ] {
        command.env_remove(knob);
    }
    if smoke {
        command.env("SMOKE", "1");
    } else {
        command.env_remove("SMOKE");
    }
    let output = command.output().expect("run IRR protocol resolver");
    assert!(
        output.status.success(),
        "protocol resolver failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("protocol output is UTF-8")
}

#[test]
/// Red proof: restoring the measured four-cell default makes the first
/// assertion fail; removing the separate bounded transaction preset makes
/// the second fail. The smoke assertion keeps all four plumbing paths gated.
fn irr_reload_protocol_separates_full_scale_from_bounded_transaction() {
    let measured = run_irr_protocol(&[], false);
    assert!(measured.contains("cells=rustbgpd-sighup,bird,openbgpd\n"));
    assert!(measured.contains("shape=320,183040,1000,40000\n"));

    let transaction = run_irr_protocol(&["rustbgpd-txn"], false);
    assert!(transaction.contains("cells=rustbgpd-txn\n"));
    assert!(transaction.contains("shape=10,5720,1000,12000\n"));

    let smoke = run_irr_protocol(&[], true);
    assert!(smoke.contains("cells=rustbgpd-sighup,rustbgpd-txn,bird,openbgpd\n"));
    assert!(smoke.contains("shape=10,100,100,100\n"));

    let runner = format!(
        "{}/bench/scale/irrreload/run-irr-reload.sh",
        env!("CARGO_MANIFEST_DIR")
    );
    let mixed = std::process::Command::new("bash")
        .arg(runner)
        .args(["rustbgpd-sighup", "rustbgpd-txn"])
        .env("DRY_RUN_PROTOCOL", "1")
        .env_remove("SMOKE")
        .output()
        .expect("run invalid mixed protocol");
    assert_eq!(mixed.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&mixed.stderr)
            .contains("rustbgpd-txn must use a separate measured campaign")
    );
}

#[test]
/// Red proof: increasing the bounded preset beyond tonic's default message
/// ceiling fails the real Plan/Apply protobuf encoded-size assertions;
/// selecting a seed/shape with no real IRR-list delta fails the changed-member
/// assertion.
fn irr_reload_bounded_transaction_preset_fits_tonic_request() {
    use prost::Message;
    use rustbgpd_api::proto::{ApplyConfigTransactionRequest, PlanConfigTransactionRequest};

    let root = env!("CARGO_MANIFEST_DIR");
    let generator = format!("{root}/bench/scale/reloadstall/gen-irr-scenario.py");
    let protocol = run_irr_protocol(&["rustbgpd-txn"], false);
    let shape = protocol
        .lines()
        .find_map(|line| line.strip_prefix("shape="))
        .expect("resolved transaction shape")
        .split(',')
        .collect::<Vec<_>>();
    assert_eq!(shape.len(), 4);
    let candidate_budget = protocol
        .split_whitespace()
        .find_map(|field| field.strip_prefix("txn_max_candidate_bytes="))
        .expect("resolved transaction message budget")
        .parse::<u64>()
        .expect("numeric transaction message budget");
    let dir = tempfile::tempdir().expect("tempdir");
    let output = std::process::Command::new("python3")
        .args([&generator, "rustbgpd-txn", shape[0], shape[1]])
        .arg(dir.path())
        .args([
            "--port",
            "1790",
            "--seed",
            "61",
            "--min-list",
            shape[2],
            "--max-list",
            shape[3],
            "--changed-fraction",
            "0.1",
        ])
        .output()
        .expect("generate bounded transaction scenario");
    assert!(output.status.success());
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(dir.path().join("manifest.json")).expect("read manifest"),
    )
    .expect("parse manifest");
    assert_eq!(manifest["changed_members"].as_array().unwrap().len(), 1);
    const TONIC_DECODE_LIMIT: usize = 4 * 1024 * 1024;
    const SNAPSHOT_TOKEN: &str = "kv2:0123456789abcdef:8";
    assert_eq!(SNAPSHOT_TOKEN.len(), 22);
    for candidate in ["config.toml", "candidate.toml", "gen-a.toml", "gen-b.toml"] {
        let bytes = manifest["file_bytes"][candidate]
            .as_u64()
            .expect("candidate byte count");
        assert!(bytes <= candidate_budget, "{candidate}: {bytes}");
        let candidate_toml = "x".repeat(bytes as usize);
        let plan = PlanConfigTransactionRequest {
            candidate_toml: candidate_toml.clone(),
            expected_runtime_snapshot_token: String::new(),
        };
        let apply = ApplyConfigTransactionRequest {
            candidate_toml,
            expected_runtime_snapshot_token: SNAPSHOT_TOKEN.to_owned(),
            client_request_id: String::new(),
            comment: String::new(),
            confirm_id: String::new(),
            confirm_timeout_seconds: 0,
        };
        assert!(
            plan.encoded_len() <= TONIC_DECODE_LIMIT,
            "{candidate}: plan"
        );
        assert!(
            apply.encoded_len() <= TONIC_DECODE_LIMIT,
            "{candidate}: apply"
        );
    }
    let at_budget = "x".repeat(candidate_budget as usize);
    let exact_apply = ApplyConfigTransactionRequest {
        candidate_toml: at_budget,
        expected_runtime_snapshot_token: SNAPSHOT_TOKEN.to_owned(),
        client_request_id: String::new(),
        comment: String::new(),
        confirm_id: String::new(),
        confirm_timeout_seconds: 0,
    };
    assert_eq!(exact_apply.encoded_len(), TONIC_DECODE_LIMIT);
    let over_limit = ApplyConfigTransactionRequest {
        candidate_toml: "x".repeat(candidate_budget as usize + 1),
        ..exact_apply
    };
    assert_eq!(over_limit.encoded_len(), TONIC_DECODE_LIMIT + 1);

    let runner = format!("{root}/bench/scale/irrreload/run-irr-reload.sh");
    let rejected = std::process::Command::new("bash")
        .arg(runner)
        .arg("rustbgpd-txn")
        .env("DRY_RUN_PROTOCOL", "1")
        .env(
            "TXN_MAX_CANDIDATE_BYTES",
            (candidate_budget + 1).to_string(),
        )
        .output()
        .expect("run over-limit protocol");
    assert_eq!(rejected.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("TXN_MAX_CANDIDATE_BYTES exceeds the safe apply-request ceiling")
    );
}

#[test]
/// Red proof: including the cell name or native rendering in the canonical
/// dataset digest makes the four-cell equality fail. Omitting or changing any
/// canonical record field fails the independently pinned seed-61 digest; a
/// seed-insensitive digest fails the changed-seed assertion.
fn irr_reload_manifest_seals_a_cell_independent_dataset_digest() {
    use sha2::{Digest, Sha256};

    let root = env!("CARGO_MANIFEST_DIR");
    let generator = format!("{root}/bench/scale/reloadstall/gen-irr-scenario.py");
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(root).join("target"));
    let renderer = target_dir.join("debug/rs-config-render");
    assert!(
        renderer.is_file(),
        "missing renderer at {}",
        renderer.display()
    );
    let mut digests = Vec::new();
    for (cell, expected_roster) in [
        (
            "rustbgpd",
            &["config.toml", "member.rpol", "gen-a.rpol", "gen-b.rpol"][..],
        ),
        (
            "rustbgpd-txn",
            &["config.toml", "candidate.toml", "gen-a.toml", "gen-b.toml"][..],
        ),
        (
            "bird",
            &["bird.conf", "gen.conf", "gen-a.conf", "gen-b.conf"][..],
        ),
        (
            "openbgpd",
            &["bgpd.conf", "gen.conf", "gen-a.conf", "gen-b.conf"][..],
        ),
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let canonical = dir.path().join("canonical-dataset.jsonl");
        let mut command = std::process::Command::new("python3");
        command
            .args([&generator, cell, "10", "100"])
            .arg(dir.path())
            .args([
                "--port",
                "1790",
                "--seed",
                "61",
                "--min-list",
                "100",
                "--max-list",
                "100",
                "--canonical-dataset-out",
            ])
            .arg(&canonical);
        if cell == "rustbgpd" {
            command.arg("--render-bin").arg(&renderer);
        }
        let output = command.output().expect("run IRR generator");
        assert!(output.status.success(), "generator failed for {cell}");
        let manifest: serde_json::Value = serde_json::from_slice(
            &std::fs::read(dir.path().join("manifest.json")).expect("read manifest"),
        )
        .expect("parse manifest");
        let applicable = matches!(cell, "rustbgpd" | "rustbgpd-txn");
        assert_eq!(manifest["path_hiding_applicable"], applicable);
        assert_eq!(manifest["path_hiding_requested"], true);
        let expected_path_hiding = serde_json::json!(applicable.then_some(true));
        assert_eq!(manifest["path_hiding"], expected_path_hiding);
        assert_eq!(
            manifest["admit_churn"], true,
            "default digest path admits churn"
        );
        digests.push(
            manifest["dataset_sha256"]
                .as_str()
                .expect("dataset digest")
                .to_owned(),
        );
        let roster = manifest["runtime_files"]
            .as_array()
            .expect("runtime file roster")
            .iter()
            .map(|value| value.as_str().expect("runtime path"))
            .collect::<Vec<_>>();
        assert_eq!(roster, expected_roster, "{cell} runtime roster");
        let canonical_digest =
            Sha256::digest(std::fs::read(&canonical).expect("read canonical dataset"))
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
        assert_eq!(manifest["dataset_sha256"], canonical_digest);
        assert_eq!(
            canonical_digest, "708688117bf8909ab9b5a631171ae8d4343f38ce813f9ff67e219c2af31df65b",
            "seed-61 canonical dataset contract changed for {cell}"
        );

        let records = std::fs::read_to_string(&canonical)
            .expect("read canonical records")
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("record JSON"))
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 10);
        let first = records[0].as_object().expect("member record object");
        assert_eq!(
            first.keys().map(String::as_str).collect::<Vec<_>>(),
            ["addr", "asn", "idx", "list_a", "list_b"]
        );
        assert_eq!(first["idx"], 0);
        assert_eq!(first["asn"], 64_512);
        assert_eq!(first["addr"], "127.1.0.1");
        let list_a = first["list_a"].as_array().expect("list_a");
        let list_b = first["list_b"].as_array().expect("list_b");
        assert_eq!(list_a.len(), 100);
        assert_eq!(list_b, list_a);
        assert_eq!(list_a[0], "20.0.0.0/24");
        assert_eq!(list_a[9], "20.0.9.0/24");
        assert_eq!(list_a[99], "88.30.166.0/24");
    }
    assert!(digests.windows(2).all(|pair| pair[0] == pair[1]));

    let changed = tempfile::tempdir().expect("tempdir");
    let output = std::process::Command::new("python3")
        .args([&generator, "bird", "10", "100"])
        .arg(changed.path())
        .args([
            "--port",
            "1790",
            "--seed",
            "62",
            "--min-list",
            "100",
            "--max-list",
            "100",
        ])
        .output()
        .expect("run changed-seed IRR generator");
    assert!(output.status.success());
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(changed.path().join("manifest.json")).expect("read manifest"),
    )
    .expect("parse manifest");
    assert_ne!(manifest["dataset_sha256"], digests[0]);
}

#[test]
/// Red proofs: removing a semantic verifier check makes its named corrupt
/// fixture pass; changing the default/control rosters or their explicit mode
/// flags fails the executed dry-protocol assertions. Removing the pre-trigger
/// topology call, quiet double-sample, source fence, identity fence, or final
/// immutable seal fails the corresponding structural assertion below.
fn irr_reload_counterbalanced_receipt_protocol_is_load_bearing() {
    let root = env!("CARGO_MANIFEST_DIR");
    let runner = format!("{root}/bench/scale/irrreload/run-irr-reload.sh");
    let verifier = format!("{root}/bench/scale/irrreload/verify-receipt.py");

    let self_test = std::process::Command::new("python3")
        .args([&verifier, "self-test"])
        .output()
        .expect("run receipt verifier self-test");
    assert!(
        self_test.status.success(),
        "verifier self-test failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&self_test.stdout),
        String::from_utf8_lossy(&self_test.stderr)
    );
    let stdout = String::from_utf8(self_test.stdout).expect("self-test UTF-8");
    for proof in [
        "default-roster",
        "mixed-roster",
        "mode-flags",
        "live-topology-gauge",
        "route-gauge",
        "route-family",
        "one-scrape-drift",
        "add-path",
        "config-count",
        "topology-mutation",
        "barrier-marker",
        "final-barrier-marker",
        "ordering",
        "dirty-commit",
        "origin-only",
        "head-matches-false",
        "mismatched-commit",
        "commit-malformed",
        "scripts-null",
        "scripts-empty-map",
        "binary-malformed",
        "fingerprint-recompute",
        "canonical-changed-fraction",
        "canonical-control-secs",
        "canonical-bird-threads",
        "repeat-image-identity",
        "cell-root-provenance",
        "nonoverlap-order",
        "reused-identity",
        "quiet-spacing",
        "preflight-raw",
        "cell-status",
        "cell-provenance",
        "evidence-roster",
        "scenario-roster",
        "scenario-duplicate",
        "scenario-unsafe-path",
        "scenario-retained-config",
        "cell-root-rows",
        "reload-log-rows",
        "row-invariants",
        "rss-raw",
        "seal-checksum",
        "exact-root-roster",
        "symlink-anywhere",
        "writable-root",
        "grouped-output-isolation",
        "output-exact-roster",
        "output-audit-call",
    ] {
        assert!(
            stdout.contains(&format!("red-proof {proof}=pass")),
            "{proof}"
        );
    }

    let dry = |cells: &[&str]| {
        std::process::Command::new("bash")
            .arg(&runner)
            .args(cells)
            .env("DRY_RUN_PROTOCOL", "1")
            .env_remove("SMOKE")
            .output()
            .expect("run dry protocol")
    };
    let comparison = dry(&[]);
    assert!(comparison.status.success());
    let comparison = String::from_utf8(comparison.stdout).expect("comparison UTF-8");
    assert!(comparison.contains("cells=rustbgpd-sighup,bird,openbgpd\n"));
    assert!(comparison.contains("campaign_kind=full-cross-daemon\n"));
    assert!(comparison.contains("rustbgpd_private=path_hiding:true,admit_churn:true\n"));
    assert!(comparison.contains("competitor_path_hiding=applicable:false,requested:true\n"));
    assert!(comparison.contains("shape=320,183040,1000,40000\n"));

    let grouped = dry(&["rustbgpd-sighup-grouped-control"]);
    assert!(grouped.status.success());
    let grouped = String::from_utf8(grouped.stdout).expect("grouped UTF-8");
    assert!(grouped.contains("cells=rustbgpd-sighup-grouped-control\n"));
    assert!(grouped.contains("campaign_kind=full-grouped-control\n"));
    assert!(
        grouped.contains(
            "rustbgpd_grouped_control=path_hiding:false,admit_churn:true,standalone:true\n"
        )
    );
    let mixed = dry(&["rustbgpd-sighup", "rustbgpd-sighup-grouped-control"]);
    assert!(
        !mixed.status.success(),
        "grouped control entered comparison roster"
    );

    let script = std::fs::read_to_string(&runner).expect("read runner");
    assert!(
        script.lines().count() <= 950,
        "runner parsing belongs in Python"
    );
    for guard in [
        "RELOADSTALL_PRE_CHURN_EVIDENCE_DIR=\"$barrier\"",
        "RELOADSTALL_EVIDENCE_DIR=\"$final_barrier\"",
        "jq -cS . | sha256sum",
        "320,183040,1000,40000,61,4,0.1,1790,30,4194275,7200,600,8",
        "capture_topology \"$topology_mode\" \"$cdir\" \"$run\" \"$hpid\" \"$barrier\"",
        "ack_pre_churn \"$barrier\" true \"$cdir\"",
        "--peers \"$N_MEMBERS\" --total \"$TOTAL_PREFIXES\"",
        "TOPOLOGY_CAPTURE_TIMEOUT=50",
        "deadline=$((SECONDS + TOPOLOGY_CAPTURE_TIMEOUT))",
        "rm -f \"$cdir/topology.json\" \"$cdir\"/metrics-{1,2,3}.prom",
        "bind_first_trigger \"$cdir\"",
        "full measured campaigns require a clean HEAD exactly at origin/main",
        "printf 'sample\\tepoch_s\\tload1\\n'",
        "[ \"$sample\" -gt 2 ] || sleep 30",
        "daemon PID/start identity changed",
        "find . -type f ! -name SHA256SUMS",
        "chmod -R a-w \"$ART\"",
    ] {
        assert!(script.contains(guard), "missing protocol guard: {guard}");
    }
}

#[test]
/// Red proof: moving the atomic `ack` publish before the `/proc` starttime
/// comparison or process.tsv capture fails the source-order assertions;
/// removing the mismatch guard makes the wrong-start invocation create ack.
fn irr_reload_final_evidence_captures_identity_before_ack() {
    let runner = std::fs::read_to_string(format!(
        "{}/bench/scale/irrreload/run-irr-reload.sh",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("read runner");
    let body = runner
        .split_once("ack_final_evidence() {")
        .and_then(|(_, rest)| rest.split_once("bind_first_trigger() {"))
        .map(|(body, _)| format!("ack_final_evidence() {{{body}"))
        .expect("final evidence helper");
    let identity = body.find("after=$(awk").expect("identity read");
    let process = body.find("process.tsv").expect("process receipt");
    let ack = body
        .find("mv -T \"$tmp\" \"$barrier/ack\"")
        .expect("atomic ack");
    assert!(identity < process && process < ack);

    let temp = tempfile::tempdir().unwrap();
    let barrier = temp.path().join("barrier");
    let evidence = temp.path().join("evidence");
    std::fs::create_dir(&barrier).unwrap();
    std::fs::write(barrier.join("ready"), "ready\n").unwrap();
    let pid = std::process::id().to_string();
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let start = stat
        .split_whitespace()
        .nth(21)
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let invalid = std::process::Command::new("bash")
        .args([
            "-c",
            &format!("{body}\nack_final_evidence \"$BARRIER\" \"$EVIDENCE\" \"$PID\" \"$START\""),
        ])
        .env("BARRIER", &barrier)
        .env("EVIDENCE", &evidence)
        .env("PID", &pid)
        .env("START", (start + 1).to_string())
        .status()
        .unwrap();
    assert!(!invalid.success());
    assert!(!barrier.join("ack").exists());
}

#[test]
/// Red proof: removing the evidence-valid guard creates `ack` for the false
/// invocation and fails this test; replacing the atomic regular-file publish
/// with a non-file marker fails the positive half.
fn irr_reload_invalid_topology_never_acknowledges_pre_churn_barrier() {
    let runner = std::fs::read_to_string(format!(
        "{}/bench/scale/irrreload/run-irr-reload.sh",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("read runner");
    let body = runner
        .split_once("ack_pre_churn() {")
        .and_then(|(_, rest)| rest.split_once("bind_first_trigger() {"))
        .map(|(body, _)| format!("ack_pre_churn() {{{body}"))
        .expect("ack helper");
    let temp = tempfile::tempdir().expect("tempdir");
    let barrier = temp.path().join("barrier");
    let evidence = temp.path().join("evidence");
    std::fs::create_dir(&barrier).unwrap();
    std::fs::write(barrier.join("ready"), "ready\n").unwrap();

    let invalid = std::process::Command::new("bash")
        .args([
            "-c",
            &format!("{body}\nack_pre_churn \"$BARRIER\" false \"$EVIDENCE\""),
        ])
        .env("BARRIER", &barrier)
        .env("EVIDENCE", &evidence)
        .status()
        .expect("run invalid acknowledgement");
    assert!(!invalid.success());
    assert!(!barrier.join("ack").exists());

    let valid = std::process::Command::new("bash")
        .args([
            "-c",
            &format!("{body}\nack_pre_churn \"$BARRIER\" true \"$EVIDENCE\""),
        ])
        .env("BARRIER", &barrier)
        .env("EVIDENCE", &evidence)
        .status()
        .expect("run valid acknowledgement");
    assert!(valid.success());
    let metadata = std::fs::symlink_metadata(barrier.join("ack")).unwrap();
    assert!(metadata.file_type().is_file() && !metadata.file_type().is_symlink());
    assert_eq!(
        std::fs::read_to_string(evidence.join("pre-churn/ack")).unwrap(),
        "ack\n"
    );
}

#[test]
/// Red proof: reversing or omitting the path-hiding value changes the emitted
/// context/config assertions; adding it to the canonical record changes the
/// byte-for-byte canonical stream and dataset digest comparison.
fn irr_memory_path_hiding_is_explicit_but_not_dataset_identity() {
    let root = env!("CARGO_MANIFEST_DIR");
    let generator = format!("{root}/bench/scale/reloadstall/gen-irr-scenario.py");
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(root).join("target"));
    let renderer = target_dir.join("debug/rs-config-render");
    assert!(
        renderer.is_file(),
        "build rs-config-render before this test"
    );

    let mut observations = Vec::new();
    for (path_hiding, admit_churn) in [("true", "false"), ("false", "false"), ("true", "true")] {
        let dir = tempfile::tempdir().expect("tempdir");
        let canonical = dir.path().join("canonical.jsonl");
        let output = std::process::Command::new("python3")
            .args([&generator, "rustbgpd", "8", "80"])
            .arg(dir.path())
            .args([
                "--render-bin",
                renderer.to_str().expect("renderer path"),
                "--min-list",
                "10",
                "--max-list",
                "10",
                "--path-hiding",
                path_hiding,
                "--admit-churn",
                admit_churn,
                "--canonical-dataset-out",
            ])
            .arg(&canonical)
            .output()
            .expect("run generator");
        assert!(
            output.status.success(),
            "generator failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let manifest: serde_json::Value = serde_json::from_slice(
            &std::fs::read(dir.path().join("manifest.json")).expect("manifest"),
        )
        .expect("manifest JSON");
        let context: serde_json::Value = serde_json::from_slice(
            &std::fs::read(dir.path().join("context-a.json")).expect("context"),
        )
        .expect("context JSON");
        let config = std::fs::read_to_string(dir.path().join("config.toml")).expect("config");
        let expected = path_hiding == "true";
        let expected_churn = admit_churn == "true";
        let stdout = String::from_utf8(output.stdout).expect("generator stdout");
        let effective_entries = if expected_churn { 208 } else { 80 };
        assert!(stdout.contains(&format!("filter_entries={effective_entries}")));
        assert_eq!(manifest["path_hiding"], expected);
        assert_eq!(manifest["admit_churn"], expected_churn);
        assert_eq!(context["cfg"]["path_hiding"], expected);
        assert_eq!(context["cfg"]["add_path"], false);
        assert_eq!(
            config.matches("per_client_best = true").count(),
            if expected { 8 } else { 0 }
        );
        assert!(!config.contains("[neighbors.add_path]"));
        let policy = std::fs::read_to_string(dir.path().join("member.rpol")).expect("policy");
        assert!(
            policy.contains("20.0.0.0/24"),
            "base prefix must remain admitted"
        );
        if expected_churn {
            assert!(policy.contains("\n    172.16.0.0/24"));
            assert_eq!(manifest["total_filter_entries"], 208);
            assert!(
                manifest["list_sizes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|size| size == 26)
            );
        } else {
            assert!(
                !policy.contains("\n    172."),
                "all churn blocks must be rejected"
            );
            assert_eq!(manifest["total_filter_entries"], 80);
            assert!(
                manifest["list_sizes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|size| size == 10)
            );
        }
        observations.push((
            manifest["dataset_sha256"].as_str().unwrap().to_owned(),
            std::fs::read(canonical).expect("canonical dataset"),
        ));
    }
    assert!(observations.windows(2).all(|pair| pair[0] == pair[1]));
}

#[test]
/// Fixture-backed red proofs execute the same semantic validators as a real
/// run. Each corrupt fixture must be rejected independently; token presence
/// alone cannot make this test pass.
fn irr_memory_protocol_self_test_exercises_semantic_rejections() {
    let runner = format!(
        "{}/bench/scale/irrreload/run-memory-attribution.sh",
        env!("CARGO_MANIFEST_DIR")
    );
    let output = std::process::Command::new("bash")
        .arg(&runner)
        .env("SELF_TEST", "1")
        .env_remove("MODE")
        .output()
        .expect("run memory attribution self-test");
    assert!(
        output.status.success(),
        "self-test failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 self-test output");
    for proof in [
        "leg-reordered",
        "leg-omitted",
        "path-hiding-mapping-and-hash",
        "group-enforcement",
        "queue-enforcement",
        "route-count-enforcement",
        "route-family-enforcement",
        "adj-out-family-enforcement",
        "metric-parser-duplicate-label",
        "metric-parser-malformed-label",
        "metric-parser-malformed-escape",
        "metric-parser-nonfinite",
        "metric-parser-unexpected-label",
        "metric-parser-missing-label",
        "metric-parser-duplicate-peer",
        "fractional-group",
        "three-scrape-stability",
        "allocator-conflation",
        "allocator-omission",
        "pid-reuse",
        "proc-omission",
        "tree-rss-omission",
        "timestamp-retry-accumulation",
        "timestamp-cadence",
        "timestamp-order-reversal",
        "roster-duplicate",
        "roster-root-omission",
        "roster-root-replacement",
        "roster-tree-sum",
        "roster-disconnected",
        "dhat-zero-live",
        "dhat-unsymbolized",
        "dhat-raw-derivative-mismatch",
        "metrics-port-fixed",
        "port-positive",
        "port-range",
        "timeout-numeric",
        "timeout-positive",
        "start-timeout-cap",
        "settle-timeout-cap",
        "leg-timeout-cap",
        "source-dirty",
        "source-diff-failure",
        "source-status-failure",
        "source-untracked-failure",
        "source-head-not-origin-main",
        "source-remote-main-advanced",
    ] {
        assert!(
            stdout.contains(&format!("red-proof {proof}=pass")),
            "{proof}"
        );
    }
    assert!(stdout.contains("positive-proof prometheus-syntax=pass"));
    assert!(stdout.contains("positive-proof source-aligned-clean=pass"));
    assert!(stdout.contains("positive-proof source-bounded-capture=pass"));
    assert!(stdout.contains("positive-proof source-path-alias-stable=pass"));
    assert!(stdout.contains("SELF_TEST pass"));

    let script = std::fs::read_to_string(&runner).expect("runner source");
    let (_, after_start) = script.split_once("full_source_admission() {").unwrap();
    let (admission_body, _) = after_start.split_once("source_admission() {").unwrap();
    let exact_fetch = "GIT_TERMINAL_PROMPT=0 timeout -k 5 60 git -C \"$REPO\" fetch origin '+refs/heads/main:refs/remotes/origin/main'";
    assert!(admission_body.contains(exact_fetch));
    let admission = script.find("source_admission \"$MODE\" || die").unwrap();
    for later in r#"mkdir -p "$(dirname "$ARTIFACT_ROOT")"|mkdir "$ARTIFACT_ROOT"|tests/soak/preflight.sh|RUSTBGPD_HOST_LOCK|flock -n "$LOCK_FD"|cargo build --locked --profile|cargo build --locked --release --manifest-path"#.split('|') {
        assert!(
            admission < script.find(later).unwrap(),
            "admission must precede {later}"
        );
    }

    let failed_tmp = tempfile::tempdir().expect("failed self-test TMPDIR");
    let failed = std::process::Command::new("bash")
        .arg(&runner)
        .env("SELF_TEST", "1")
        .env("GENERATOR", failed_tmp.path().join("missing-generator.py"))
        .env("TMPDIR", failed_tmp.path())
        .output()
        .expect("run deliberately failed self-test");
    assert!(!failed.status.success());
    assert_eq!(
        std::fs::read_dir(failed_tmp.path())
            .expect("read failed self-test TMPDIR")
            .count(),
        0,
        "removing the self-test EXIT trap leaves its generated tempdir behind"
    );

    let implicit = std::process::Command::new("bash")
        .arg(&runner)
        .env_remove("MODE")
        .output()
        .expect("run implicit mode");
    assert_eq!(implicit.status.code(), Some(2));

    let full_without_opt_in = std::process::Command::new("bash")
        .arg(&runner)
        .env("MODE", "full")
        .env("DRY_RUN_PROTOCOL", "1")
        .env_remove("FULL_SHAPE")
        .output()
        .expect("run gated full mode");
    assert!(!full_without_opt_in.status.success());

    for mode in ["smoke", "dhat"] {
        let dry = std::process::Command::new("bash")
            .arg(&runner)
            .env("MODE", mode)
            .env("DRY_RUN_PROTOCOL", "1")
            .output()
            .expect("run bounded dry protocol");
        assert!(dry.status.success(), "{mode} dry protocol");
        let text = String::from_utf8(dry.stdout).expect("dry protocol UTF-8");
        assert!(text.contains("protocol=private,grouped,grouped,private"));
        assert!(text.contains("path_hiding=true,false,false,true"));
        assert!(text.contains("admit_churn=false"));
        assert!(text.contains("ports=1790,9179"));
        assert!(text.contains("rss_abort_gib=100"));
    }
}
