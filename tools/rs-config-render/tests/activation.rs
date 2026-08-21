#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rs_config_render::activation::{Error, Options, Status, activate};
use sha2::{Digest, Sha256};

const FIXTURE: &[u8] = include_bytes!("fixtures/ixp-manager-v1-supported.json");
const SECRET: &str = "activation-secret-must-not-escape";

fn mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn assert_mode(path: &Path, want: u32) {
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        want
    );
}

fn executable(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    mode(path, 0o700);
}

fn assert_refused(result: Result<Status, Error>) {
    assert!(matches!(result, Err(Error::Refused(_))));
}

struct Rig {
    _temp: tempfile::TempDir,
    root: PathBuf,
    state: PathBuf,
    checker: PathBuf,
    rbgp: PathBuf,
    activation: PathBuf,
}

impl Rig {
    fn new() -> Self {
        let current = std::env::current_dir().unwrap();
        let temp = tempfile::Builder::new()
            .prefix("activation-")
            .tempdir_in(&current)
            .unwrap();
        let root = temp.path().to_path_buf();
        for (name, value) in [
            ("version", "0.65.0"),
            ("checker-mode", "ok"),
            ("health-mode", "ok"),
            ("activation-mode", "ok"),
        ] {
            fs::write(root.join(name), value).unwrap();
        }
        let checker = root.join("checker.sh");
        executable(
            &checker,
            &format!(
                r#"#!/bin/sh
root=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
printf '%s\n' "$*" >> "$root/checker.log"
if [ "$1" = --version ]; then
  if [ -f "$root/version-stderr" ]; then
    printf 'rustbgpd %s\n' "$(cat "$root/version")" >&2
  else
    printf 'rustbgpd %s {SECRET}\n' "$(cat "$root/version")"
    printf '{SECRET}\n' >&2
  fi
  exit 0
fi
[ "$(cat "$root/checker-mode")" = ok ] || exit 9
printf '{SECRET}\n' >&2
exit 0
"#
            ),
        );
        let rbgp = root.join("rbgp.sh");
        executable(
            &rbgp,
            r#"#!/bin/sh
root=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
printf '%s\n' "$*" >> "$root/rbgp.log"
case "$*" in
  *" health")
    case "$(cat "$root/health-mode")" in
      malformed) printf 'not-json\n'; exit 0 ;;
      auth) printf 'Error: permission denied\n' >&2; exit 1 ;;
    esac
    if [ ! -f "$root/runtime" ]; then
      printf 'Error: cannot reach rustbgpd at test (connection refused)\n' >&2
      exit 1
    fi
    [ "$(cat "$root/health-mode")" = unhealthy ] && healthy=false || healthy=true
    printf '{"healthy":%s}\n' "$healthy"
    exit 0
    ;;
esac
for arg do candidate=$arg; done
target=$(cat "$root/runtime")
current=$(CDPATH= cd -- "$root/state" && pwd -P)/current
grep -F "\"$current/policy/ixp-hygiene.rpol\"" "$candidate" >/dev/null || exit 8
printf 'ABSOLUTE_CURRENT_OK\n' >> "$root/rbgp.log"
if [ -f "$root/reject" ] && [ "$target" = "$(cat "$root/reject")" ]; then exit 2; fi
exit 0
"#,
        );
        let activation = root.join("activate.sh");
        executable(
            &activation,
            &format!(
                r#"#!/bin/sh
root=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
target=$(readlink "$root/state/current") || exit 7
printf '%s\n' "$target" >> "$root/activation.log"
printf '%s\n' "$target" > "$root/runtime"
case "$(cat "$root/activation-mode")" in
  fail-once)
    if [ ! -f "$root/failed-once" ]; then touch "$root/failed-once"; printf '{SECRET}\n'; exit 9; fi ;;
  hang-once)
    if [ ! -f "$root/hung-once" ]; then touch "$root/hung-once"; sleep 30; fi ;;
  reject-current)
    [ -f "$root/reject" ] || printf '%s\n' "$target" > "$root/reject" ;;
esac
printf '{SECRET}\n' >&2
exit 0
"#
            ),
        );
        let state = root.join("state");
        fs::create_dir(&state).unwrap();
        mode(&state, 0o700);
        Self {
            _temp: temp,
            root,
            state,
            checker,
            rbgp,
            activation,
        }
    }

    fn candidate(&self, name: &str, max_prefix: u64) -> PathBuf {
        let mut input: serde_json::Value = serde_json::from_slice(FIXTURE).unwrap();
        input["clients"][0]["max_prefix"] = max_prefix.into();
        let context = self.root.join(format!("{name}.json"));
        fs::write(&context, serde_json::to_vec(&input).unwrap()).unwrap();
        mode(&context, 0o600);
        let out = self.root.join(name);
        rs_config_render::ixp_manager::write_checked_candidate(&context, &out, 300, &self.checker)
            .unwrap();
        out
    }

    fn run(&self, candidate: &Path, initial: bool, command: &Path) -> Result<Status, Error> {
        let args = Vec::new();
        activate(&Options {
            candidate,
            state_dir: &self.state,
            checker: &self.checker,
            rbgp: &self.rbgp,
            rbgp_addr: "test:50051",
            settle: Duration::from_secs(1),
            initial,
            activation_command: command,
            activation_args: &args,
        })
    }

    fn current(&self) -> String {
        fs::read_link(self.root.join("state/current"))
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }

    fn set(&self, name: &str, value: &str) {
        fs::write(self.root.join(name), value).unwrap();
    }

    fn receipt(&self) -> serde_json::Value {
        serde_json::from_slice(&fs::read(self.root.join("state/activation-receipt.json")).unwrap())
            .unwrap()
    }
}

#[test]
fn initial_activation_and_noop_are_private_exact_and_secret_free() {
    let rig = Rig::new();
    let candidate = rig.candidate("candidate-a", 100);
    fs::write(rig.root.join("version-stderr"), "").unwrap();
    assert_eq!(
        rig.run(&candidate, true, &rig.activation),
        Ok(Status::Activated)
    );
    let target = rig.current();
    assert!(target.starts_with("generations/"));
    assert_eq!(
        target,
        fs::read_to_string(rig.root.join("runtime")).unwrap().trim()
    );
    assert!(
        fs::read_to_string(rig.root.join("rbgp.log"))
            .unwrap()
            .contains("ABSOLUTE_CURRENT_OK")
    );
    let receipt = rig.receipt();
    assert_eq!(receipt["status"], "activated");
    assert_eq!(receipt["initial"], true);
    assert_eq!(receipt["strict_check"]["binary_version"], "rustbgpd 0.65.0");
    assert_eq!(receipt["phases"]["initial_unreachable_checked"], true);
    assert_eq!(receipt["phases"]["runtime_equal"], true);
    assert!(!serde_json::to_string(&receipt).unwrap().contains(SECRET));
    assert_mode(&rig.root.join("state"), 0o700);
    assert_mode(&rig.root.join("state/activation.lock"), 0o600);
    let check_log = fs::read_to_string(rig.root.join("checker.log")).unwrap();
    assert!(
        check_log
            .lines()
            .last()
            .unwrap()
            .contains("state/generations/")
    );

    let activations = fs::read_to_string(rig.root.join("activation.log")).unwrap();
    assert_eq!(
        rig.run(&candidate, false, Path::new("/bin/false")),
        Ok(Status::Noop)
    );
    assert_eq!(
        fs::read_to_string(rig.root.join("activation.log")).unwrap(),
        activations
    );
    assert_eq!(rig.receipt()["status"], "noop");

    let limited = Command::new("/bin/sh")
        .args(["-c", "trap '' XFSZ; ulimit -f 0; exec \"$@\"", "sh"])
        .arg(env!("CARGO_BIN_EXE_rs-config-render"))
        .args(["activate", "--candidate"])
        .arg(&candidate)
        .arg("--state-dir")
        .arg(&rig.state)
        .arg("--check-with")
        .arg(&rig.checker)
        .arg("--rbgp")
        .arg(&rig.rbgp)
        .args(["--rbgp-addr", "test:50051", "--activation-command"])
        .arg("/bin/false")
        .output()
        .unwrap();
    assert_eq!(limited.status.code(), Some(2));
    assert!(fs::read_dir(&rig.state).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".compare-")
    }));

    rig.set("version", "0.66.0");
    assert_refused(rig.run(&candidate, false, &rig.activation));
    rig.set("version", "0.65.0");
    let second_state = rig.root.join("state-2");
    fs::create_dir(&second_state).unwrap();
    mode(&second_state, 0o700);
    rig.set("health-mode", "malformed");
    let args = Vec::new();
    let result = activate(&Options {
        candidate: &candidate,
        state_dir: &second_state,
        checker: &rig.checker,
        rbgp: &rig.rbgp,
        rbgp_addr: "test:50051",
        settle: Duration::from_secs(1),
        initial: true,
        activation_command: &rig.activation,
        activation_args: &args,
    });
    assert_refused(result);
    assert!(!second_state.join("current").exists());
}

#[test]
fn changed_candidate_rolls_back_exactly_and_refuses_mutable_aliases() {
    let rig = Rig::new();
    let first = rig.candidate("candidate-a", 100);
    rig.run(&first, true, &rig.activation).unwrap();
    let second = rig.candidate("candidate-b", 101);
    rig.run(&second, false, &rig.activation).unwrap();
    let prior = rig.current();

    let stop = Arc::new(AtomicBool::new(false));
    let observed_bad = Arc::new(AtomicBool::new(false));
    let state = rig.root.join("state");
    let watcher = {
        let stop = Arc::clone(&stop);
        let observed_bad = Arc::clone(&observed_bad);
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if fs::read_link(state.join("current")).is_err() {
                    observed_bad.store(true, Ordering::Relaxed);
                }
            }
        })
    };
    let tampered = rig.candidate("candidate-c", 102);
    fs::write(tampered.join("config.toml"), "tampered").unwrap();
    assert_refused(rig.run(&tampered, false, &rig.activation));
    let linked = rig.candidate("candidate-linked", 103);
    let policy = linked.join("policy/client-3.rpol");
    fs::hard_link(&policy, rig.root.join("mutable-alias.rpol")).unwrap();
    assert_refused(rig.run(&linked, false, &rig.activation));

    let third = rig.candidate("candidate-d", 104);
    let activations = fs::read_to_string(rig.root.join("activation.log")).unwrap();
    assert_eq!(
        rig.run(&third, false, &rig.root.join("missing-command")),
        Err(Error::RolledBack)
    );
    stop.store(true, Ordering::Relaxed);
    watcher.join().unwrap();
    assert!(!observed_bad.load(Ordering::Relaxed));
    assert_eq!(rig.current(), prior);
    assert_eq!(
        fs::read_to_string(rig.root.join("runtime")).unwrap().trim(),
        prior
    );
    let receipt = rig.receipt();
    assert_eq!(receipt["status"], "rolled_back");
    assert_eq!(receipt["activation_runs"], 0);
    assert_eq!(receipt["phases"]["candidate_activation_ran"], false);
    assert_eq!(receipt["phases"]["rollback_activation_ran"], false);
    assert_eq!(receipt["phases"]["runtime_equal"], true);
    assert_eq!(
        fs::read_to_string(rig.root.join("activation.log")).unwrap(),
        activations
    );
}

#[test]
fn started_failure_timeout_and_unsettled_retain_candidate_without_rollback() {
    let started = Instant::now();
    for mode_name in ["fail-once", "hang-once", "reject-current"] {
        let rig = Rig::new();
        let first = rig.candidate("candidate-a", 110);
        rig.run(&first, true, &rig.activation).unwrap();
        let candidate = rig.candidate("candidate-ambiguous", 111);
        let prior = rig.current();
        let activations = fs::read_to_string(rig.root.join("activation.log")).unwrap();
        rig.set("activation-mode", mode_name);
        assert_eq!(
            rig.run(&candidate, false, &rig.activation),
            Err(Error::RecoveryRequired)
        );
        let receipt = rig.receipt();
        assert_ne!(rig.current(), prior);
        assert!(
            rig.current()
                .ends_with(receipt["candidate_sha256"].as_str().unwrap())
        );
        assert_eq!(receipt["status"], "recovery_required");
        assert_eq!(receipt["activation_runs"], 1);
        assert_eq!(receipt["phases"]["rollback_link"]["published"], false);
        assert_eq!(receipt["phases"]["rollback_activation_ran"], false);
        assert_eq!(
            fs::read_to_string(rig.root.join("activation.log"))
                .unwrap()
                .lines()
                .count(),
            activations.lines().count() + 1
        );
    }
    assert!(started.elapsed() < Duration::from_secs(4));
}

#[test]
fn initial_failed_command_exits_five_with_last_recovery_receipt() {
    let rig = Rig::new();
    let candidate = rig.candidate("candidate-recovery", 105);
    rig.set("activation-mode", "fail-once");
    let output = Command::new(env!("CARGO_BIN_EXE_rs-config-render"))
        .args(["activate", "--candidate"])
        .arg(&candidate)
        .arg("--state-dir")
        .arg(&rig.state)
        .arg("--check-with")
        .arg(&rig.checker)
        .arg("--rbgp")
        .arg(&rig.rbgp)
        .args(["--rbgp-addr", "test:50051", "--initial"])
        .arg("--activation-command")
        .arg(&rig.activation)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(5), "{output:?}");
    assert!(!String::from_utf8_lossy(&output.stdout).contains(SECRET));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(SECRET));
    let receipt = rig.receipt();
    assert_eq!(receipt["status"], "recovery_required");
    assert_eq!(receipt["activation_runs"], 1);
    let candidate_hash = receipt["candidate_sha256"].as_str().unwrap();
    assert!(rig.current().ends_with(candidate_hash));
    assert_eq!(receipt["phases"]["runtime_equal"], false);
    assert!(!serde_json::to_string(&receipt).unwrap().contains(SECRET));
}

#[test]
fn cli_help_pins_the_additive_literal_command_contract() {
    let output = Command::new(env!("CARGO_BIN_EXE_rs-config-render"))
        .args(["activate", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for flag in "--candidate --state-dir --check-with --rbgp --rbgp-addr --settle-seconds --initial --activation-command --activation-arg".split_whitespace() {
        assert!(help.contains(flag), "missing {flag}: {help}");
    }
    assert!(help.contains("[default: 30]"));

    let missing = Command::new(env!("CARGO_BIN_EXE_rs-config-render"))
        .output()
        .unwrap();
    let error = String::from_utf8(missing.stderr).unwrap();
    assert_eq!(missing.status.code(), Some(2));
    assert!(error.contains("--context <CONTEXT>\n  --out-dir <OUT_DIR>"));
}

#[test]
fn recovery_boundaries_refuse_before_publication_and_clean_partial_staging() {
    let rig = Rig::new();
    let candidate = rig.candidate("candidate-boundaries", 106);
    let args = Vec::new();
    let run = |state: &Path, settle| {
        activate(&Options {
            candidate: &candidate,
            state_dir: state,
            checker: &rig.checker,
            rbgp: &rig.rbgp,
            rbgp_addr: "test:50051",
            settle,
            initial: true,
            activation_command: &rig.activation,
            activation_args: &args,
        })
    };
    let subsecond = rig.root.join("subsecond-state");
    fs::create_dir(&subsecond).unwrap();
    mode(&subsecond, 0o700);
    assert_refused(run(&subsecond, Duration::from_millis(999)));
    assert_eq!(fs::read_dir(&subsecond).unwrap().count(), 0);
    let relative = rig
        .state
        .strip_prefix(std::env::current_dir().unwrap())
        .unwrap();
    assert_refused(run(relative, Duration::from_secs(1)));
    let absent = rig.root.join("absent-state");
    assert_refused(run(&absent, Duration::from_secs(1)));
    assert!(!absent.exists());
    let linked_state = rig.root.join("linked-state");
    symlink(&rig.state, &linked_state).unwrap();
    assert_refused(run(&linked_state, Duration::from_secs(1)));
    let wrong_mode = rig.root.join("wrong-mode-state");
    fs::create_dir(&wrong_mode).unwrap();
    mode(&wrong_mode, 0o755);
    assert_refused(run(&wrong_mode, Duration::from_secs(1)));

    let config = format!("[oversized]\nvalue = \"{}\"\n", "x".repeat(4_194_300));
    fs::write(candidate.join("config.toml"), &config).unwrap();
    let mut receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(candidate.join("render-receipt.json")).unwrap()).unwrap();
    let hash = Sha256::digest(config.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    receipt["generated_files"]["config.toml"] = hash.into();
    fs::write(
        candidate.join("render-receipt.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
    let oversized = rig.root.join("oversized-state");
    fs::create_dir(&oversized).unwrap();
    mode(&oversized, 0o700);
    assert_refused(run(&oversized, Duration::from_secs(1)));
    assert!(!oversized.join("generations").exists());
    assert!(!oversized.join("current").exists());
    assert!(oversized.join("activation.lock").is_file());

    let partial = rig.candidate("candidate-partial", 107);
    let delayed = rig.root.join("delayed-checker.sh");
    executable(
        &delayed,
        "#!/bin/sh\nroot=$(CDPATH= cd -- \"$(dirname \"$0\")\" && pwd)\n[ \"$1\" = --version ] && { touch \"$root/version-started\"; sleep 1; }\nexec \"$root/checker.sh\" \"$@\"\n",
    );
    let state = rig.root.join("partial-state");
    fs::create_dir(&state).unwrap();
    mode(&state, 0o700);
    let rbgp = rig.rbgp.clone();
    let activation = rig.activation.clone();
    let paths = [partial.clone(), state.clone(), delayed, rbgp, activation];
    let worker = std::thread::spawn(move || {
        let args = Vec::new();
        activate(&Options {
            candidate: &paths[0],
            state_dir: &paths[1],
            checker: &paths[2],
            rbgp: &paths[3],
            rbgp_addr: "test:50051",
            settle: Duration::from_secs(2),
            initial: true,
            activation_command: &paths[4],
            activation_args: &args,
        })
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    while !rig.root.join("version-started").exists() {
        assert!(Instant::now() < deadline, "delayed checker did not start");
        std::thread::sleep(Duration::from_millis(10));
    }
    fs::write(partial.join("policy/client-3.rpol"), "changed after verify").unwrap();
    assert_refused(worker.join().unwrap());
    assert_eq!(fs::read_dir(state.join("generations")).unwrap().count(), 0);
    let source = include_str!("../src/activation.rs");
    assert_eq!(source.matches("sync_dir(&generations)?;").count(), 2);
    assert!(source.contains("staging.0.take();\n        sync_dir(&generations)?;"));
    assert!(source.contains(
        ".and_then(|file| file.sync_all())\n            .map_err(|_| Error::RecoveryRequired)"
    ));
}
