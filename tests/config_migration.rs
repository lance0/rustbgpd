//! Real-binary proofs for the Linux-only offline config migrator.

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant};

const CONFIG: &str = r#"# retained header
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
runtime_state_dir = "/tmp/rustbgpd-config-migration"
# retained posture comment

[global.telemetry]
log_format = "json"

[global.telemetry.grpc_uds]
enabled = true
path = "/tmp/rustbgpd-config-migration/grpc.sock"
mode = 0o600
principal = "operator"

[security.grpc]
enforcement = "tier"

[security.grpc.roles]
operator = "operator"
"#;

fn run(args: &[&Path], literals: &[&str]) -> Output {
    run_env(args, literals, &[])
}

fn run_env(args: &[&Path], literals: &[&str], environment: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rustbgpd"));
    command.arg("--migrate-config");
    for literal in literals {
        command.arg(literal);
    }
    for arg in args {
        command.arg(arg);
    }
    command.envs(environment.iter().copied());
    command.output().expect("run migrator")
}

fn text(output: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn config_file() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    fs::write(&path, CONFIG).unwrap();
    (dir, path)
}

fn validator(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("validator");
    fs::write(&path, body).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

#[test]
fn pin_and_prepare_are_surgical_atomic_and_current_valid() {
    for (action, epoch, posture) in [
        (
            "pin-legacy",
            "config_epoch = 1",
            "ebgp_requires_policy = false",
        ),
        (
            "prepare-secure",
            "config_epoch = 2",
            "ebgp_requires_policy = true",
        ),
    ] {
        let (_dir, path) = config_file();
        let before = fs::metadata(&path).unwrap();
        let output = run(&[&path], &[action, "--offline"]);
        let (stdout, stderr) = text(&output);
        assert!(output.status.success(), "{action}: {stdout}\n{stderr}");
        assert_eq!(
            stdout,
            format!("migration action={action} result=changed written=true\n")
        );
        assert!(stderr.is_empty(), "{stderr}");
        let migrated = fs::read_to_string(&path).unwrap();
        assert!(
            migrated.starts_with(&format!("{epoch}\n# retained header")),
            "{migrated}"
        );
        assert!(migrated.contains(posture), "{migrated}");
        assert!(
            migrated.contains("# retained posture comment"),
            "{migrated}"
        );
        assert_eq!(
            fs::metadata(&path).unwrap().mode() & 0o777,
            before.mode() & 0o777
        );
        assert_eq!(fs::metadata(&path).unwrap().uid(), before.uid());
        assert_eq!(fs::metadata(&path).unwrap().gid(), before.gid());
        assert_ne!(before.ino(), fs::metadata(&path).unwrap().ino());
        assert!(!PathBuf::from(format!("{}.tmp", path.display())).exists());
        let checked = Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
            .args(["--check", path.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            checked.status.success(),
            "{}",
            String::from_utf8_lossy(&checked.stderr)
        );
    }
}

#[test]
fn dry_run_executes_proof_without_replacing_or_leaving_stage() {
    let (_dir, path) = config_file();
    let before = fs::read(&path).unwrap();
    let metadata = fs::metadata(&path).unwrap();
    let output = run(&[&path], &["prepare-secure", "--offline", "--dry-run"]);
    assert!(output.status.success(), "{:?}", text(&output));
    assert_eq!(
        text(&output).0,
        "migration action=prepare-secure result=would-change written=false\n"
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(fs::metadata(&path).unwrap().ino(), metadata.ino());
    assert!(!PathBuf::from(format!("{}.tmp", path.display())).exists());
}

#[test]
fn existing_value_decoration_and_unchanged_result_are_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let source = format!(
        "config_epoch  = 1 # epoch intent\n{}",
        CONFIG.replace(
            "# retained posture comment",
            "ebgp_requires_policy  = true # posture intent\n# retained posture comment"
        )
    );
    fs::write(&path, source).unwrap();
    let changed = run(&[&path], &["pin-legacy", "--offline"]);
    assert!(changed.status.success(), "{:?}", text(&changed));
    let migrated = fs::read_to_string(&path).unwrap();
    assert!(
        migrated.contains("config_epoch  = 1 # epoch intent"),
        "{migrated}"
    );
    assert!(
        migrated.contains("ebgp_requires_policy  = false # posture intent"),
        "{migrated}"
    );
    let before = fs::metadata(&path).unwrap().ino();
    let unchanged = run(&[&path], &["pin-legacy", "--offline"]);
    assert!(unchanged.status.success(), "{:?}", text(&unchanged));
    assert_eq!(
        text(&unchanged).0,
        "migration action=pin-legacy result=unchanged written=false\n"
    );
    assert_eq!(fs::metadata(&path).unwrap().ino(), before);
}

#[test]
fn explicit_offline_path_and_cli_conflicts_fail_closed() {
    let (_dir, path) = config_file();
    for literals in [
        vec!["pin-legacy"],
        vec!["pin-legacy", "--offline", "--check"],
        vec!["pin-legacy", "--offline", "--validator"],
        vec!["unknown", "--offline"],
    ] {
        let output = run(&[&path], &literals);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{literals:?}: {:?}",
            text(&output)
        );
        assert!(text(&output).0.is_empty());
        assert!(
            text(&output)
                .1
                .starts_with("error: config migration refused:")
        );
    }
    let relative = Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
        .current_dir(path.parent().unwrap())
        .args(["--migrate-config", "pin-legacy", "--offline", "config.toml"])
        .output()
        .unwrap();
    assert!(relative.status.success(), "{:?}", text(&relative));

    for args in [
        vec!["--offline"],
        vec!["--dry-run"],
        vec!["--validator", path.to_str().unwrap()],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {:?}",
            text(&output)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stderr),
            "error: config migration refused: missing --migrate-config\n"
        );
    }
}

#[test]
fn large_source_relative_validator_and_stdout_failure_are_bounded() {
    let (dir, path) = config_file();
    let mut source = fs::read_to_string(&path).unwrap();
    source.push_str(&format!("# {}\n", "x".repeat(17 * 1024 * 1024)));
    fs::write(&path, source).unwrap();
    let _validator = validator(
        dir.path(),
        "#!/bin/sh\n[ \"$1\" != --version ] || printf 'rustbgpd 0.64.0\\n'\n",
    );
    let relative = Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
        .current_dir(dir.path())
        .args([
            "--migrate-config",
            "downgrade-v0.64",
            "--offline",
            "--validator",
            "validator",
            "config.toml",
        ])
        .output()
        .unwrap();
    assert!(relative.status.success(), "{:?}", text(&relative));
    let full = fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
        .args(["--migrate-config", "pin-legacy", "--offline"])
        .arg(&path)
        .stdout(full)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(1));
}

#[test]
fn internal_post_transform_invariant_uses_exit_70_and_sanitized_text() {
    let (_dir, path) = config_file();
    let before = fs::read(&path).unwrap();
    let output = run_env(
        &[&path],
        &["pin-legacy", "--offline"],
        &[("RUSTBGPD_TEST_MIGRATION_INVARIANT_FAILURE", "1")],
    );
    assert_eq!(output.status.code(), Some(70), "{:?}", text(&output));
    assert!(
        text(&output)
            .1
            .contains("staged config violates the selected migration posture")
    );
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn retired_source_keeps_actionable_diagnostic_without_publication() {
    let (_dir, path) = config_file();
    fs::write(
        &path,
        CONFIG.replace("enforcement = \"tier\"", "enforcement = \"legacy\""),
    )
    .unwrap();
    let before = fs::read(&path).unwrap();
    let inode = fs::metadata(&path).unwrap().ino();
    let sentinel = path.parent().unwrap().join("sentinel");
    let stage = PathBuf::from(format!("{}.tmp", path.display()));
    fs::write(&sentinel, b"do not replace").unwrap();
    symlink(&sentinel, &stage).unwrap();
    let stage_inode = fs::symlink_metadata(&stage).unwrap().ino();

    let output = run(&[&path], &["pin-legacy", "--offline"]);

    assert_eq!(output.status.code(), Some(1), "{:?}", text(&output));
    assert!(text(&output).0.is_empty());
    assert_eq!(
        text(&output).1,
        "error: config migration refused: migration source validation failed:\n\
error: security.grpc.enforcement = \"legacy\" was removed in v0.63.0 and no longer boots:\n  \
1. legacy mode recorded [security.grpc.roles] as audit context but enforced nothing; that runtime path no longer exists, so there is nothing to opt back into\n  \
2. if your clients are local (rbgp over a UDS socket, including the implicit default at <runtime_state_dir>/grpc.sock), tier enforcement needs no configuration at all — the owner-only socket authorizes them as the implicit \"local-operator\": simply delete the whole [security.grpc] block\n  \
3. a listener with a declared principal keeps working under tier with a role entry; keep this instead:\n\
[security.grpc]\n\
enforcement = \"tier\"\n\
\n\
[security.grpc.roles]\n\
\"<your-principal>\" = \"operator\"\n\
(migration: docs/CONFIGURATION.md [security.grpc]; removal decision: docs/adr/0064-grpc-authorization.md)\n"
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
    assert!(
        fs::symlink_metadata(&stage)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::symlink_metadata(&stage).unwrap().ino(), stage_inode);
    assert_eq!(fs::read_link(&stage).unwrap(), sentinel);
    assert_eq!(fs::read(&sentinel).unwrap(), b"do not replace");
}

#[test]
fn locked_captured_bytes_are_the_only_source_semantics_authority() {
    let source = include_str!("../src/config_migration.rs");
    let start = source.find("fn migrate(").unwrap();
    let end = source[start..].find("\nfn apply(").unwrap() + start;
    let migrate = &source[start..end];
    assert!(migrate.contains("load_captured_config(text, &resolved, \"migration source\")"));
    assert!(!migrate.contains("Config::load_with_diagnostics("));
    let loader = &source[source.find("fn load_captured_config(").unwrap()..];
    assert!(loader.contains("Config::load_toml_with_diagnostics(content, label)"));
}

#[test]
fn downgrade_materializes_effective_bool_removes_epoch_and_runs_exact_validator() {
    for (source, effective) in [
        (CONFIG.to_string(), false),
        (
            format!(
                "config_epoch = 2\n{}",
                CONFIG.replace("[global]", "[global]\nebgp_requires_policy = true")
            ),
            true,
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, source).unwrap();
        let log = dir.path().join("validator.log");
        let script = validator(
            dir.path(),
            &format!(
                "#!/bin/sh\nset -eu\nif [ \"$1\" = --version ]; then printf 'rustbgpd 0.64.0\\n'; exit 0; fi\n[ \"$1\" = --check ]\ngrep -q 'ebgp_requires_policy = {effective}' \"$2\"\n! grep -q config_epoch \"$2\"\nprintf '%s\\n' \"$1\" >> '{}'\n",
                log.display()
            ),
        );
        let output = run(
            &[&validator_path(&script), &path],
            &["downgrade-v0.64", "--offline", "--validator"],
        );
        assert!(output.status.success(), "{:?}", text(&output));
        let migrated = fs::read_to_string(&path).unwrap();
        assert!(!migrated.contains("config_epoch"), "{migrated}");
        assert!(
            migrated.contains(&format!("ebgp_requires_policy = {effective}")),
            "{migrated}"
        );
        assert_eq!(fs::read_to_string(log).unwrap(), "--check\n");
    }
}

#[test]
fn ci_exact_v064_binary_accepts_real_downgrade_bytes() {
    let Some(validator) = std::env::var_os("RUSTBGPD_V064_VALIDATOR").map(PathBuf::from) else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    fs::write(
        &path,
        format!(
            "config_epoch = 2\n{}",
            CONFIG.replace("[global]", "[global]\nebgp_requires_policy = true")
        ),
    )
    .unwrap();
    let rejected = Command::new(&validator)
        .args(["--check", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        !rejected.status.success(),
        "v0.64 unexpectedly accepted config_epoch input"
    );
    let output = run(
        &[&validator, &path],
        &["downgrade-v0.64", "--offline", "--validator"],
    );
    assert!(output.status.success(), "{:?}", text(&output));
    assert_eq!(
        text(&output).0,
        "migration action=downgrade-v0.64 result=changed written=true\n"
    );
}

fn validator_path(path: &Path) -> PathBuf {
    path.to_path_buf()
}

#[test]
fn downgrade_refuses_absent_wrong_or_rejecting_validator_without_change() {
    let (_dir, path) = config_file();
    let before = fs::read(&path).unwrap();
    let absent = run(&[&path], &["downgrade-v0.64", "--offline"]);
    assert_eq!(absent.status.code(), Some(2));
    for script in [
        "#!/bin/sh\nprintf 'rustbgpd 0.63.0\\n'\n",
        "#!/bin/sh\nif [ \"$1\" = --version ]; then printf 'rustbgpd 0.64.0\\n'; else exit 1; fi\n",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let validator = validator(dir.path(), script);
        let output = run(
            &[&validator, &path],
            &["downgrade-v0.64", "--offline", "--validator"],
        );
        assert_eq!(output.status.code(), Some(1), "{:?}", text(&output));
        assert!(text(&output).1.contains("config migration refused"));
        assert_eq!(fs::read(&path).unwrap(), before);
        assert!(!PathBuf::from(format!("{}.tmp", path.display())).exists());
    }
}

#[test]
fn symlink_is_preserved_and_resolved_target_is_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("real.toml");
    let link = dir.path().join("config.toml");
    fs::write(&target, CONFIG).unwrap();
    symlink(&target, &link).unwrap();
    let output = run(&[&link], &["pin-legacy", "--offline"]);
    assert!(output.status.success(), "{:?}", text(&output));
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(
        fs::read_to_string(target)
            .unwrap()
            .contains("config_epoch = 1")
    );
}

#[test]
fn source_or_symlink_change_during_validation_refuses_and_cleans_stage() {
    for swap_link in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.toml");
        let alternate = dir.path().join("alternate.toml");
        let link = dir.path().join("config.toml");
        fs::write(&target, CONFIG).unwrap();
        fs::write(&alternate, CONFIG.replace("65001", "65003")).unwrap();
        symlink(&target, &link).unwrap();
        let validator = validator(
            dir.path(),
            "#!/bin/sh\nif [ \"$1\" = --version ]; then printf 'rustbgpd 0.64.0\\n'; else sleep 1; fi\n",
        );
        let child_link = link.clone();
        let child_target = target.clone();
        let child_alternate = alternate.clone();
        let changer = thread::spawn(move || {
            let stage = PathBuf::from(format!("{}.tmp", child_target.display()));
            let deadline = Instant::now() + Duration::from_secs(5);
            while !stage.exists() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(5));
            }
            assert!(stage.exists(), "stage never appeared");
            if swap_link {
                fs::remove_file(&child_link).unwrap();
                symlink(&child_alternate, &child_link).unwrap();
            } else {
                fs::write(&child_target, CONFIG.replace("65001", "65004")).unwrap();
            }
        });
        let output = run(
            &[&validator, &link],
            &["downgrade-v0.64", "--offline", "--validator"],
        );
        changer.join().unwrap();
        assert_eq!(output.status.code(), Some(1), "{:?}", text(&output));
        assert!(text(&output).1.contains("config migration refused"));
        assert!(!PathBuf::from(format!("{}.tmp", target.display())).exists());
    }
}

#[test]
fn malformed_source_and_sanitized_validator_output_are_never_published() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    fs::write(&path, "secret = 'DO_NOT_PRINT'\nnot valid = [").unwrap();
    let output = run(&[&path], &["pin-legacy", "--offline"]);
    let (stdout, stderr) = text(&output);
    assert_eq!(output.status.code(), Some(1));
    assert!(!stdout.contains("DO_NOT_PRINT") && !stderr.contains("DO_NOT_PRINT"));

    fs::write(&path, CONFIG).unwrap();
    let validator = validator(
        dir.path(),
        "#!/bin/sh\nprintf 'rustbgpd 0.64.0\\nLEAK'\nprintf 'DO_NOT_PRINT' >&2\n",
    );
    let output = run(
        &[&validator, &path],
        &["downgrade-v0.64", "--offline", "--validator"],
    );
    let (stdout, stderr) = text(&output);
    assert_eq!(output.status.code(), Some(1));
    assert!(!stdout.contains("LEAK") && !stderr.contains("DO_NOT_PRINT"));
}

#[test]
fn nonregular_source_refuses_without_blocking() {
    let dir = tempfile::tempdir().unwrap();
    for kind in ["directory", "fifo"] {
        let path = dir.path().join(kind);
        if kind == "directory" {
            fs::create_dir(&path).unwrap();
        } else {
            assert!(
                Command::new("mkfifo")
                    .arg(&path)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let started = Instant::now();
        let output = run(&[&path], &["pin-legacy", "--offline"]);
        assert_eq!(output.status.code(), Some(1), "{kind}: {:?}", text(&output));
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}

#[test]
fn different_target_migrations_in_one_directory_do_not_contend() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("first.toml");
    let second = dir.path().join("second.toml");
    fs::write(&first, CONFIG).unwrap();
    fs::write(&second, CONFIG.replace("65001", "65003")).unwrap();
    let validator = validator(
        dir.path(),
        "#!/bin/sh\nif [ \"$1\" = --version ]; then printf 'rustbgpd 0.64.0\\n'; else sleep 2; fi\n",
    );
    let mut first_child = Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
        .args([
            "--migrate-config",
            "downgrade-v0.64",
            "--offline",
            "--validator",
        ])
        .arg(&validator)
        .arg(&first)
        .spawn()
        .unwrap();
    let first_stage = PathBuf::from(format!("{}.tmp", first.display()));
    let deadline = Instant::now() + Duration::from_secs(5);
    while !first_stage.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    let started = Instant::now();
    let concurrent = run(&[&second], &["pin-legacy", "--offline"]);
    assert!(concurrent.status.success(), "{:?}", text(&concurrent));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(first_child.wait().unwrap().success());
}

#[test]
fn stale_regular_stage_is_reused_but_symlink_and_nonregular_stages_refuse() {
    let (_dir, path) = config_file();
    let stage = PathBuf::from(format!("{}.tmp", path.display()));
    fs::write(&stage, b"stale secret").unwrap();
    let reused = run(&[&path], &["pin-legacy", "--offline"]);
    assert!(reused.status.success(), "{:?}", text(&reused));
    assert!(!stage.exists());

    for kind in ["symlink", "directory"] {
        let (dir, path) = config_file();
        let stage = PathBuf::from(format!("{}.tmp", path.display()));
        if kind == "symlink" {
            let target = dir.path().join("stage-target");
            fs::write(&target, b"do not touch").unwrap();
            symlink(&target, &stage).unwrap();
        } else {
            fs::create_dir(&stage).unwrap();
        }
        let before = fs::read(&path).unwrap();
        let refused = run(&[&path], &["pin-legacy", "--offline"]);
        assert_eq!(
            refused.status.code(),
            Some(1),
            "{kind}: {:?}",
            text(&refused)
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        assert!(fs::symlink_metadata(stage).is_ok());
    }

    for kind in ["hardlink", "fifo"] {
        let (_dir, path) = config_file();
        let stage = PathBuf::from(format!("{}.tmp", path.display()));
        if kind == "hardlink" {
            fs::hard_link(&path, &stage).unwrap();
        } else {
            assert!(
                Command::new("mkfifo")
                    .arg(&stage)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let before = fs::read(&path).unwrap();
        let refused = run(&[&path], &["pin-legacy", "--offline"]);
        assert_eq!(
            refused.status.code(),
            Some(1),
            "{kind}: {:?}",
            text(&refused)
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        assert!(fs::symlink_metadata(stage).is_ok());
    }
}

#[test]
fn migration_preserves_special_mode_bits_and_metadata_failure_cleans_stage() {
    let (_dir, path) = config_file();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o7640)).unwrap();
    let before = fs::metadata(&path).unwrap();
    let output = run(&[&path], &["pin-legacy", "--offline"]);
    assert!(output.status.success(), "{:?}", text(&output));
    let after = fs::metadata(&path).unwrap();
    assert_eq!(
        (after.uid(), after.gid(), after.mode() & 0o7777),
        (before.uid(), before.gid(), 0o7640)
    );

    for step in ["chown", "chmod", "fsync"] {
        let (_dir, path) = config_file();
        let bytes = fs::read(&path).unwrap();
        let before = fs::metadata(&path).unwrap();
        let failed = run_env(
            &[&path],
            &["pin-legacy", "--offline"],
            &[("RUSTBGPD_TEST_MIGRATION_METADATA_FAILURE", step)],
        );
        assert_eq!(failed.status.code(), Some(1), "{step}: {:?}", text(&failed));
        let after = fs::metadata(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(
            (
                after.dev(),
                after.ino(),
                after.uid(),
                after.gid(),
                after.mode()
            ),
            (
                before.dev(),
                before.ino(),
                before.uid(),
                before.gid(),
                before.mode()
            )
        );
        assert!(!PathBuf::from(format!("{}.tmp", path.display())).exists());
    }
}

#[test]
fn post_rename_directory_sync_failure_is_reported_ambiguous() {
    let (_dir, path) = config_file();
    let output = run_env(
        &[&path],
        &["pin-legacy", "--offline"],
        &[("RUSTBGPD_TEST_MIGRATION_DIR_FSYNC_FAILURE", "1")],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output).1.contains(
        "migration publication durability is ambiguous; inspect CONFIG_PATH before retrying"
    ));
    assert!(
        fs::read_to_string(path)
            .unwrap()
            .contains("config_epoch = 1")
    );
}

#[test]
fn validator_identity_swaps_refuse_before_publication() {
    for phase in ["version", "check"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, CONFIG).unwrap();
        let validator_a = dir.path().join("validator-a");
        let validator_b = dir.path().join("validator-b");
        let validator = dir.path().join("validator");
        fs::write(&validator_b, "#!/bin/sh\nprintf 'rustbgpd 0.64.0\\n'\n").unwrap();
        fs::set_permissions(&validator_b, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(
            &validator_a,
            format!(
                "#!/bin/sh\nif [ \"$1\" = --version ]; then printf 'rustbgpd 0.64.0\\n'; {}; else {}; fi\n",
                if phase == "version" {
                    format!(
                        "/bin/ln -sfn -- '{}' '{}'",
                        validator_b.display(),
                        validator.display()
                    )
                } else {
                    ":".to_string()
                },
                if phase == "check" {
                    format!(
                        "/bin/ln -sfn -- '{}' '{}'",
                        validator_b.display(),
                        validator.display()
                    )
                } else {
                    ":".to_string()
                }
            ),
        )
        .unwrap();
        fs::set_permissions(&validator_a, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&validator_a, &validator).unwrap();
        let validator_inode = fs::symlink_metadata(&validator).unwrap().ino();
        let before = fs::read(&path).unwrap();
        let output = run(
            &[&validator, &path],
            &["downgrade-v0.64", "--offline", "--validator"],
        );
        assert_eq!(
            output.status.code(),
            Some(1),
            "{phase}: {:?}",
            text(&output)
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_ne!(
            fs::symlink_metadata(&validator).unwrap().ino(),
            validator_inode,
            "{phase}: {:?}",
            text(&output)
        );
        assert!(
            text(&output)
                .1
                .contains("validator changed during migration"),
            "{:?}",
            text(&output)
        );
    }
}

#[test]
fn downgrade_dry_run_invokes_validator_and_malicious_stage_mutation_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    fs::write(&path, CONFIG).unwrap();
    let before = fs::read(&path).unwrap();
    let log = dir.path().join("log");
    let proof_validator = validator(
        dir.path(),
        &format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then printf 'rustbgpd 0.64.0\\n'; else printf checked > '{}'; fi\n",
            log.display()
        ),
    );
    let dry = run(
        &[&proof_validator, &path],
        &["downgrade-v0.64", "--offline", "--dry-run", "--validator"],
    );
    assert!(dry.status.success(), "{:?}", text(&dry));
    assert_eq!(fs::read_to_string(&log).unwrap(), "checked");
    assert_eq!(fs::read(&path).unwrap(), before);

    let malicious_validator = validator(
        dir.path(),
        "#!/bin/sh\nif [ \"$1\" = --version ]; then printf 'rustbgpd 0.64.0\\n'; else printf '# malicious\\n' > \"$2\"; fi\n",
    );
    let malicious = run(
        &[&malicious_validator, &path],
        &["downgrade-v0.64", "--offline", "--validator"],
    );
    assert_eq!(malicious.status.code(), Some(1), "{:?}", text(&malicious));
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(!PathBuf::from(format!("{}.tmp", path.display())).exists());
}

#[test]
fn both_validator_deadlines_kill_reap_sanitize_and_clean_stage() {
    for phase in ["version", "check"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, CONFIG).unwrap();
        let descendant_pid = dir.path().join("descendant.pid");
        let script = if phase == "version" {
            format!(
                "#!/bin/sh\nprintf DO_NOT_PRINT >&2\nsleep 5 & echo $! > '{}'\n",
                descendant_pid.display()
            )
        } else {
            format!(
                "#!/bin/sh\nif [ \"$1\" = --version ]; then printf 'rustbgpd 0.64.0\\n'; else printf DO_NOT_PRINT >&2; (sleep 1; printf malicious > \"$2\") & echo $! > '{}'; fi\n",
                descendant_pid.display()
            )
        };
        let validator = validator(dir.path(), &script);
        let started = Instant::now();
        let output = run_env(
            &[&validator, &path],
            &["downgrade-v0.64", "--offline", "--validator"],
            &[("RUSTBGPD_TEST_MIGRATION_TIMEOUT_PHASE", phase)],
        );
        assert_eq!(
            output.status.code(),
            Some(1),
            "{phase}: {:?}",
            text(&output)
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(!text(&output).1.contains("DO_NOT_PRINT"));
        let pid = fs::read_to_string(&descendant_pid).unwrap();
        assert!(!Path::new(&format!("/proc/{}", pid.trim())).exists());
        assert!(!PathBuf::from(format!("{}.tmp", path.display())).exists());
        let retry = run(&[&path], &["pin-legacy", "--offline"]);
        assert!(
            retry.status.success(),
            "lock leaked after {phase}: {:?}",
            text(&retry)
        );
    }
}
