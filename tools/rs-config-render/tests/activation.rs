#![cfg(unix)]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rs_config_render::activation::{Error, Options, Status, activate};
use rs_config_render::ixp_manager_host::Binding;
use sha2::{Digest, Sha256};

const FIXTURE: &[u8] = include_bytes!("fixtures/ixp-manager-v1-supported.json");
const SECRET: &str = "activation-secret-must-not-escape";
/// Settle window every `Rig::run` activation is given.
const SETTLE: Duration = Duration::from_secs(1);
// Serialize the binary. `Command::spawn` in any thread copies every open
// descriptor into its child until that child execs, and flock locks live on
// the open file description: a host lock one test just dropped stays held by
// the ghost copy inside a sibling test's not-yet-exec'd child, and the
// sibling's next claim is refused with "another host command is active".
static ACTIVATION_TEST_LOCK: Mutex<()> = Mutex::new(());

fn activation_test_guard() -> std::sync::MutexGuard<'static, ()> {
    ACTIVATION_TEST_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

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
    runtime: PathBuf,
    host: PathBuf,
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
current=$(CDPATH= cd -- "$root/b2-rs1-lan1-ipv4/activation" && pwd -P)/current
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
target=$(readlink "$root/b2-rs1-lan1-ipv4/activation/current") || exit 7
printf '%s\n' "$target" >> "$root/activation.log"
printf '%s\n' "$target" > "$root/runtime"
case "$(cat "$root/activation-mode")" in
  fail-once)
    if [ ! -f "$root/failed-once" ]; then touch "$root/failed-once"; printf '{SECRET}\n'; exit 9; fi ;;
  hang-once)
    if [ ! -f "$root/hung-once" ]; then touch "$root/hung-once"; exec sleep 120; fi ;;
  reject-current)
    [ -f "$root/reject" ] || printf '%s\n' "$target" > "$root/reject" ;;
esac
printf '{SECRET}\n' >&2
exit 0
"#
            ),
        );
        let runtime = root.join("b2-rs1-lan1-ipv4");
        fs::create_dir(&runtime).unwrap();
        mode(&runtime, 0o700);
        let state = runtime.join("activation");
        let host = root.join("host-state");
        for path in [&state, &host] {
            fs::create_dir(path).unwrap();
            mode(path, 0o700);
        }
        Self {
            _temp: temp,
            root,
            state,
            runtime,
            host,
            checker,
            rbgp,
            activation,
        }
    }

    fn candidate(&self, name: &str, max_prefix: u64) -> PathBuf {
        self.candidate_with_alias(name, max_prefix, 3, 42, "10.1.0.36")
    }

    fn candidate_with_alias(
        &self,
        name: &str,
        max_prefix: u64,
        vli: u64,
        asn: u64,
        address: &str,
    ) -> PathBuf {
        let mut input: serde_json::Value = serde_json::from_slice(FIXTURE).unwrap();
        input["clients"][0]["max_prefix"] = max_prefix.into();
        input["clients"][0]["vlan_interface_id"] = vli.into();
        input["clients"][0]["asn"] = asn.into();
        input["clients"][0]["address"] = address.into();
        input["clients"][0]["peering_ips"] = serde_json::json!([address]);
        input["clients"][0]["origins"] = serde_json::json!([asn]);
        let context = self.root.join(format!("{name}.json"));
        fs::write(&context, serde_json::to_vec(&input).unwrap()).unwrap();
        mode(&context, 0o600);
        let out = self.root.join(name);
        rs_config_render::ixp_manager::write_checked_candidate(
            &context,
            &out,
            300,
            &self.checker,
            &self.binding(&self.state).render_binding(),
            rs_config_render::ixp_manager::SchemaVersion::V1,
        )
        .unwrap();
        out
    }

    fn binding(&self, state: &Path) -> Binding {
        Binding::new(
            "b2-rs1-lan1-ipv4",
            &self.runtime,
            state,
            &self.host,
            &format!("unix://{}", self.runtime.join("grpc.sock").display()),
        )
        .unwrap()
    }

    fn run(&self, candidate: &Path, initial: bool, command: &Path) -> Result<Status, Error> {
        let args = Vec::new();
        activate(&Options {
            candidate,
            state_dir: &self.state,
            checker: &self.checker,
            rbgp: &self.rbgp,
            rbgp_addr: self.binding(&self.state).rbgp_addr(),
            settle: SETTLE,
            initial,
            activation_command: command,
            activation_args: &args,
            binding: &self.binding(&self.state),
        })
    }

    fn current(&self) -> String {
        fs::read_link(self.state.join("current"))
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }

    fn current_alias(&self) -> String {
        fs::read_to_string(self.state.join("current/birdwatcher-protocol-aliases.conf")).unwrap()
    }

    fn set(&self, name: &str, value: &str) {
        fs::write(self.root.join(name), value).unwrap();
    }

    fn receipt(&self) -> serde_json::Value {
        serde_json::from_slice(&fs::read(self.state.join("activation-receipt.json")).unwrap())
            .unwrap()
    }
}

#[test]
fn initial_activation_and_noop_are_private_exact_and_secret_free() {
    let _serial = activation_test_guard();
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
    assert_eq!(
        receipt["host"],
        serde_json::to_value(rig.binding(&rig.state)).unwrap()
    );
    assert!(!serde_json::to_string(&receipt).unwrap().contains(SECRET));
    assert_mode(&rig.state, 0o700);
    assert_mode(&rig.state.join("activation.lock"), 0o600);
    let aliases = rig.state.join("current/birdwatcher-protocol-aliases.conf");
    assert_eq!(
        fs::read_to_string(&aliases).unwrap(),
        "pb_0003_as42=10.1.0.36@master4\n"
    );
    assert_mode(&aliases, 0o600);
    let check_log = fs::read_to_string(rig.root.join("checker.log")).unwrap();
    assert!(
        check_log
            .lines()
            .last()
            .unwrap()
            .contains("activation/generations/")
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

    let limited_rig = Rig::new();
    let limited_candidate = limited_rig.candidate("candidate-limited", 100);
    let limited = Command::new("/bin/sh")
        .args(["-c", "trap '' XFSZ; ulimit -f 0; exec \"$@\"", "sh"])
        .arg(env!("CARGO_BIN_EXE_rs-config-render"))
        .args(["activate", "--candidate"])
        .arg(&limited_candidate)
        .arg("--state-dir")
        .arg(&limited_rig.state)
        .args(["--router-handle", "b2-rs1-lan1-ipv4"])
        .arg("--runtime-state-dir")
        .arg(&limited_rig.runtime)
        .arg("--host-state-dir")
        .arg(&limited_rig.host)
        .arg("--check-with")
        .arg(&limited_rig.checker)
        .arg("--rbgp")
        .arg(&limited_rig.rbgp)
        .arg("--rbgp-addr")
        .arg(limited_rig.binding(&limited_rig.state).rbgp_addr())
        .arg("--activation-command")
        .arg("/bin/false")
        .output()
        .unwrap();
    assert_eq!(limited.status.code(), Some(5));
    assert!(fs::read_dir(&limited_rig.state).unwrap().all(|entry| {
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
        rbgp_addr: rig.binding(&rig.state).rbgp_addr(),
        settle: Duration::from_secs(1),
        initial: true,
        activation_command: &rig.activation,
        activation_args: &args,
        binding: &rig.binding(&rig.state),
    });
    assert_refused(result);
    assert!(!second_state.join("current").exists());
}

#[test]
fn receipt_and_toml_runtime_bindings_are_independently_enforced() {
    let _serial = activation_test_guard();
    let rig = Rig::new();
    let receipt_mismatch = rig.candidate("candidate-receipt-mismatch", 120);
    let receipt_path = receipt_mismatch.join("render-receipt.json");
    let mut receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(&receipt_path).unwrap()).unwrap();
    receipt["host"]["runtime_state_dir"] = "/tmp/foreign".into();
    fs::write(&receipt_path, serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();
    assert_refused(rig.run(&receipt_mismatch, true, &rig.activation));
    assert!(!rig.host.join("ixp-manager-host-fence.json").exists());

    let toml_mismatch = rig.candidate("candidate-toml-mismatch", 121);
    let config_path = toml_mismatch.join("config.toml");
    let config = fs::read_to_string(&config_path)
        .unwrap()
        .replace(rig.runtime.to_str().unwrap(), "/tmp/b2-rs1-lan1-ipv4");
    fs::write(&config_path, &config).unwrap();
    let receipt_path = toml_mismatch.join("render-receipt.json");
    let mut receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(&receipt_path).unwrap()).unwrap();
    receipt["generated_files"]["config.toml"] = Sha256::digest(config.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
        .into();
    fs::write(&receipt_path, serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();
    assert_refused(rig.run(&toml_mismatch, true, &rig.activation));
    assert!(!rig.state.join("current").exists());
}

#[test]
fn changed_candidate_rolls_back_exactly_and_refuses_mutable_aliases() {
    let _serial = activation_test_guard();
    let rig = Rig::new();
    let first = rig.candidate_with_alias("candidate-a", 100, 3, 42, "10.1.0.36");
    rig.run(&first, true, &rig.activation).unwrap();
    let first_generation = rig.current();
    let second = rig.candidate_with_alias("candidate-b", 101, 4, 43, "10.1.0.37");
    rig.run(&second, false, &rig.activation).unwrap();
    let prior = rig.current();
    assert_ne!(prior, first_generation);
    let prior_alias = "pb_0004_as43=10.1.0.37@master4\n";
    assert_eq!(rig.current_alias(), prior_alias);

    let stop = Arc::new(AtomicBool::new(false));
    let observed_bad = Arc::new(AtomicBool::new(false));
    let state = rig.state.clone();
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
    let tampered = rig.candidate_with_alias("candidate-c", 102, 5, 44, "10.1.0.38");
    fs::write(
        tampered.join("birdwatcher-protocol-aliases.conf"),
        "tampered\n",
    )
    .unwrap();
    assert_refused(rig.run(&tampered, false, &rig.activation));
    assert_eq!(rig.current_alias(), prior_alias);
    let linked = rig.candidate_with_alias("candidate-linked", 103, 6, 45, "10.1.0.39");
    let aliases = linked.join("birdwatcher-protocol-aliases.conf");
    fs::hard_link(&aliases, rig.root.join("mutable-alias.conf")).unwrap();
    assert_refused(rig.run(&linked, false, &rig.activation));
    assert_eq!(rig.current_alias(), prior_alias);

    let third = rig.candidate_with_alias("candidate-d", 104, 7, 46, "10.1.0.40");
    let activations = fs::read_to_string(rig.root.join("activation.log")).unwrap();
    assert_eq!(
        rig.run(&third, false, &rig.root.join("missing-command")),
        Err(Error::RolledBack)
    );
    stop.store(true, Ordering::Relaxed);
    watcher.join().unwrap();
    assert!(!observed_bad.load(Ordering::Relaxed));
    assert_eq!(rig.current(), prior);
    assert_eq!(rig.current_alias(), prior_alias);
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
    let _serial = activation_test_guard();
    // The only absolute bound, and it only catches a hang: the hang-once
    // fixture sleeps 120 s, so an activation that is not killed at the settle
    // deadline (or a settle loop that never gives up) overshoots this by far,
    // while scheduler load cannot reach it.
    const HANG_MARGIN: Duration = Duration::from_secs(30);
    for mode_name in ["fail-once", "hang-once", "reject-current"] {
        let rig = Rig::new();
        let first = rig.candidate("candidate-a", 110);
        rig.run(&first, true, &rig.activation).unwrap();
        let candidate = rig.candidate("candidate-ambiguous", 111);
        let prior = rig.current();
        let activations = fs::read_to_string(rig.root.join("activation.log")).unwrap();
        rig.set("activation-mode", mode_name);
        let started = Instant::now();
        assert_eq!(
            rig.run(&candidate, false, &rig.activation),
            Err(Error::RecoveryRequired)
        );
        let elapsed = started.elapsed();
        // A failed command is reported at once; a hung command is killed at
        // the settle deadline and a never-settling runtime is polled until
        // it, so those two are given the whole configured window and no more.
        if mode_name != "fail-once" {
            assert!(
                elapsed >= SETTLE,
                "{mode_name}: gave up before the settle window: {elapsed:?}"
            );
        }
        assert!(
            elapsed < SETTLE + HANG_MARGIN,
            "{mode_name}: ran past the settle deadline: {elapsed:?}"
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
        assert_eq!(receipt["phases"]["candidate_activation_ran"], true);
        assert_eq!(receipt["phases"]["runtime_equal"], false);
        assert_eq!(
            fs::read_to_string(rig.root.join("activation.log"))
                .unwrap()
                .lines()
                .count(),
            activations.lines().count() + 1
        );
    }
}

#[test]
fn initial_failed_command_exits_five_with_last_recovery_receipt() {
    let _serial = activation_test_guard();
    let rig = Rig::new();
    let candidate = rig.candidate("candidate-recovery", 105);
    rig.set("activation-mode", "fail-once");
    let output = Command::new(env!("CARGO_BIN_EXE_rs-config-render"))
        .args(["activate", "--candidate"])
        .arg(&candidate)
        .arg("--state-dir")
        .arg(&rig.state)
        .args(["--router-handle", "b2-rs1-lan1-ipv4"])
        .arg("--runtime-state-dir")
        .arg(&rig.runtime)
        .arg("--host-state-dir")
        .arg(&rig.host)
        .arg("--check-with")
        .arg(&rig.checker)
        .arg("--rbgp")
        .arg(&rig.rbgp)
        .arg("--rbgp-addr")
        .arg(rig.binding(&rig.state).rbgp_addr())
        .arg("--initial")
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
    assert!(rig.host.join("ixp-manager-host-fence.json").exists());
}

#[test]
fn cli_help_pins_the_additive_literal_command_contract() {
    let _serial = activation_test_guard();
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
    let _serial = activation_test_guard();
    let rig = Rig::new();
    let candidate = rig.candidate("candidate-boundaries", 106);
    let args = Vec::new();
    let run = |state: &Path, settle| {
        let binding = rig.binding(&rig.state);
        let address = binding.rbgp_addr();
        activate(&Options {
            candidate: &candidate,
            state_dir: state,
            checker: &rig.checker,
            rbgp: &rig.rbgp,
            rbgp_addr: address,
            settle,
            initial: true,
            activation_command: &rig.activation,
            activation_args: &args,
            binding: &binding,
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

    let candidate = rig.candidate("candidate-oversized", 106);
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
    assert_refused(rig.run(&candidate, true, &rig.activation));
    assert!(!rig.state.join("generations").exists());
    assert!(!rig.state.join("current").exists());
    assert!(!rig.state.join("activation.lock").exists());

    let partial = rig.candidate("candidate-partial", 107);
    let delayed = rig.root.join("delayed-checker.sh");
    executable(
        &delayed,
        "#!/bin/sh\nroot=$(CDPATH= cd -- \"$(dirname \"$0\")\" && pwd)\n[ \"$1\" = --version ] && { touch \"$root/version-started\"; sleep 1; }\nexec \"$root/checker.sh\" \"$@\"\n",
    );
    let state = rig.state.clone();
    let rbgp = rig.rbgp.clone();
    let activation = rig.activation.clone();
    let binding = rig.binding(&state);
    let paths = [partial.clone(), state.clone(), delayed, rbgp, activation];
    let worker = std::thread::spawn(move || {
        let args = Vec::new();
        activate(&Options {
            candidate: &paths[0],
            state_dir: &paths[1],
            checker: &paths[2],
            rbgp: &paths[3],
            rbgp_addr: binding.rbgp_addr(),
            settle: Duration::from_secs(2),
            initial: true,
            activation_command: &paths[4],
            activation_args: &args,
            binding: &binding,
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

/// Relative path → kind and content (file digest or symlink target).
fn snapshot(root: &Path) -> BTreeMap<String, String> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.strip_prefix(root).unwrap().display().to_string();
            let metadata = fs::symlink_metadata(&path).unwrap();
            if metadata.file_type().is_symlink() {
                out.insert(
                    name,
                    format!("link:{}", fs::read_link(&path).unwrap().display()),
                );
            } else if metadata.is_dir() {
                out.insert(name, "dir".to_owned());
                walk(root, &path, out);
            } else {
                let digest: String = Sha256::digest(fs::read(&path).unwrap())
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                out.insert(name, format!("file:{digest}"));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

#[test]
fn refused_after_generation_copy_leaves_the_state_directory_unchanged() {
    let _serial = activation_test_guard();
    let rig = Rig::new();
    let first = rig.candidate("candidate-first", 100);
    assert_eq!(
        rig.run(&first, true, &rig.activation),
        Ok(Status::Activated)
    );
    let second = rig.candidate("candidate-second", 101);
    let before = snapshot(&rig.state);

    rig.set("checker-mode", "fail");
    assert_eq!(
        rig.run(&second, false, &rig.activation),
        Err(Error::Refused("strict candidate check failed"))
    );
    assert_eq!(
        snapshot(&rig.state),
        before,
        "strict-check refusal left a trace"
    );

    rig.set("checker-mode", "ok");
    rig.set("health-mode", "unhealthy");
    assert_eq!(
        rig.run(&second, false, &rig.activation),
        Err(Error::Refused("current runtime is not known-good"))
    );
    assert_eq!(
        snapshot(&rig.state),
        before,
        "known-good refusal left a trace"
    );

    rig.set("health-mode", "ok");
    assert_eq!(
        rig.run(&second, false, &rig.activation),
        Ok(Status::Activated)
    );
    assert_ne!(snapshot(&rig.state), before);
}

#[test]
fn every_activation_test_acquires_the_process_guard_first() {
    let _serial = activation_test_guard();
    let lines: Vec<_> = include_str!("activation.rs").lines().collect();
    let tests = lines
        .windows(3)
        .filter(|window| window[0].trim() == "#[test]")
        .inspect(|window| {
            assert_eq!(
                window[2].trim(),
                "let _serial = activation_test_guard();",
                "{} must acquire the process guard before fixtures or children",
                window[1].trim()
            );
        })
        .count();
    assert_eq!(tests, 11);
}

mod prune {
    use super::*;
    use rs_config_render::prune::{Error as PruneError, Kept, Options as PruneOptions, prune};

    impl Rig {
        fn prune(
            &self,
            keep: usize,
            apply: bool,
        ) -> Result<rs_config_render::prune::Plan, PruneError> {
            prune(&PruneOptions {
                state_dir: &self.state,
                keep,
                apply,
                binding: &self.binding(&self.state),
            })
        }

        /// Activate `count` distinct candidates in order and return their
        /// generation digests, oldest first.
        fn generations(&self, count: u64) -> Vec<String> {
            (0..count)
                .map(|index| {
                    let candidate = self.candidate(&format!("candidate-{index}"), 100 + index);
                    // Distinct directory mtimes order the keep-N window.
                    std::thread::sleep(Duration::from_millis(20));
                    assert_eq!(
                        self.run(&candidate, index == 0, &self.activation),
                        Ok(Status::Activated)
                    );
                    self.current().trim_start_matches("generations/").to_owned()
                })
                .collect()
        }

        fn generation_exists(&self, digest: &str) -> bool {
            self.state.join("generations").join(digest).is_dir()
        }
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn kept(digest: &str, reasons: &[&'static str]) -> Kept {
        Kept {
            digest: digest.to_owned(),
            reasons: reasons.to_vec(),
        }
    }

    #[test]
    fn prune_keeps_current_predecessor_receipt_and_journal_and_refuses_under_a_fence() {
        let _serial = activation_test_guard();
        let rig = Rig::new();
        let g = rig.generations(5);

        // keep 0: only references survive — current (+receipt candidate) and predecessor.
        let plan = rig.prune(0, false).unwrap();
        assert_eq!(
            plan.kept,
            vec![
                kept(&g[4], &["current", "receipt"]),
                kept(&g[3], &["predecessor"])
            ]
        );
        assert_eq!(plan.removed, vec![g[2].clone(), g[1].clone(), g[0].clone()]);
        assert!(plan.failed.is_empty());
        assert!(
            g.iter().all(|digest| rig.generation_exists(digest)),
            "dry run removed nothing"
        );

        // A pending lifecycle journal naming g[1]'s render receipt keeps g[1].
        let journal = serde_json::json!({
            "schema": "rustbgpd.ixp-manager.lifecycle/v1",
            "ixp_manager_version": "7.4.0",
            "origin": "https://ixp.example.net",
            "router_handle": "b2-rs1-lan1-ipv4",
            "host": rig.binding(&rig.state),
            "phase": "manual_recovery",
            "callback": null,
            "callback_attempts": 0,
            "candidate_sha256": sha256_hex(
                &fs::read(rig.state.join("generations").join(&g[1]).join("render-receipt.json")).unwrap()
            ),
            "activation_outcome": "recovery_required",
            "error_class": "activation"
        });
        let journal_path = rig.state.join("ixp-manager-lifecycle.json");
        fs::write(&journal_path, serde_json::to_vec(&journal).unwrap()).unwrap();
        let plan = rig.prune(0, false).unwrap();
        assert_eq!(
            plan.kept,
            vec![
                kept(&g[4], &["current", "receipt"]),
                kept(&g[3], &["predecessor"]),
                kept(&g[1], &["journal"]),
            ]
        );
        assert_eq!(plan.removed, vec![g[2].clone(), g[0].clone()]);

        // An unparseable journal is forensic state: refuse.
        fs::write(&journal_path, b"{not json").unwrap();
        assert!(matches!(rig.prune(0, true), Err(PruneError::Refused(_))));
        fs::write(&journal_path, serde_json::to_vec(&journal).unwrap()).unwrap();

        // Any host fence refuses outright, even with --apply.
        let fence = rig.host.join("ixp-manager-host-fence.json");
        fs::write(&fence, b"{}").unwrap();
        assert_eq!(
            rig.prune(0, true),
            Err(PruneError::Refused(
                "host fence present; resolve it before pruning (retained state is forensic)"
            ))
        );
        assert!(
            g.iter().all(|digest| rig.generation_exists(digest)),
            "refusal removed nothing"
        );
        fs::remove_file(&fence).unwrap();

        // Apply removes exactly the plan and leaves a coherent state.
        let applied = rig.prune(0, true).unwrap();
        assert_eq!(applied.removed, vec![g[2].clone(), g[0].clone()]);
        assert!(applied.failed.is_empty());
        for (index, digest) in g.iter().enumerate() {
            assert_eq!(
                rig.generation_exists(digest),
                [1, 3, 4].contains(&index),
                "{index}"
            );
        }
        assert_eq!(rig.current(), format!("generations/{}", g[4]));
        let again = rig.prune(0, true).unwrap();
        assert!(again.removed.is_empty(), "{again:?}");
        assert_eq!(again.kept.len(), 3);
        fs::remove_file(&journal_path).unwrap();
        let candidate = rig.candidate("candidate-noop", 104);
        assert_eq!(
            rig.run(&candidate, false, Path::new("/bin/false")),
            Ok(Status::Noop)
        );
    }

    #[test]
    fn prune_cli_dry_run_lists_exactly_what_apply_removes_and_is_idempotent() {
        let _serial = activation_test_guard();
        let rig = Rig::new();
        let g = rig.generations(4);
        let run = |apply: bool| {
            let mut command = Command::new(env!("CARGO_BIN_EXE_rs-config-render"));
            command
                .args([
                    "prune",
                    "--router-handle",
                    "b2-rs1-lan1-ipv4",
                    "--keep",
                    "1",
                ])
                .arg("--runtime-state-dir")
                .arg(&rig.runtime)
                .arg("--state-dir")
                .arg(&rig.state)
                .arg("--host-state-dir")
                .arg(&rig.host)
                .arg("--rbgp-addr")
                .arg(rig.binding(&rig.state).rbgp_addr());
            if apply {
                command.arg("--apply");
            }
            let output = command.output().unwrap();
            let stdout = String::from_utf8(output.stdout).unwrap();
            let removed: Vec<String> = stdout
                .lines()
                .filter_map(|line| line.strip_prefix("remove "))
                .map(str::to_owned)
                .collect();
            (output.status.code(), stdout, removed)
        };

        let (code, stdout, dry) = run(false);
        assert_eq!(code, Some(0), "{stdout}");
        assert_eq!(dry, vec![g[1].clone(), g[0].clone()]);
        assert!(
            stdout.contains(&format!("keep {} current,receipt,keep-N\n", g[3])),
            "{stdout}"
        );
        assert!(
            stdout.contains(&format!("keep {} predecessor\n", g[2])),
            "{stdout}"
        );
        assert!(
            stdout.ends_with("prune: dry run — 2 generation(s) would be removed, 2 kept; pass --apply to remove\n"),
            "{stdout}"
        );
        assert!(g.iter().all(|digest| rig.generation_exists(digest)));

        let (code, stdout, applied) = run(true);
        assert_eq!(code, Some(0), "{stdout}");
        assert_eq!(applied, dry);
        assert!(
            stdout.ends_with("prune: removed 2 generation(s), kept 2\n"),
            "{stdout}"
        );
        for (index, digest) in g.iter().enumerate() {
            assert_eq!(rig.generation_exists(digest), index >= 2, "{index}");
        }

        let (code, stdout, second) = run(true);
        assert_eq!(code, Some(0), "{stdout}");
        assert!(second.is_empty(), "{stdout}");
        assert!(
            stdout.ends_with("prune: removed 0 generation(s), kept 2\n"),
            "{stdout}"
        );
    }
}
