//! Real-binary contract for rustbgpd's hand-rolled invocation parser.
//!
//! Ambiguous commands must fail before loading a config or printing one-shot
//! output. Valid flag/positional interleavings remain supported.

use std::path::Path;
use std::process::{Command, Output};

fn run(args: &[&str], cwd: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rustbgpd"));
    command.args(args).env("NO_COLOR", "1");
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    command.output().expect("run rustbgpd")
}

fn assert_invalid(args: &[&str], diagnostic: &str) {
    let output = run(args, None);
    assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
    assert!(
        output.stdout.is_empty(),
        "{args:?}: printed one-shot output"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(diagnostic),
        "{args:?}: missing {diagnostic:?}:\n{stderr}"
    );
}

fn starter_config() -> String {
    let output = run(&["--init-config", "lab", "--stdout"], None);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    String::from_utf8(output.stdout).expect("starter config is UTF-8")
}

#[test]
fn duplicate_paths_and_value_options_are_rejected() {
    let temp = tempfile::tempdir().expect("tempdir");
    let first = temp.path().join("first.toml");
    let second = temp.path().join("second.toml");
    let config = starter_config();
    std::fs::write(&first, &config).expect("write first config");
    std::fs::write(&second, &config).expect("write second config");
    let first = first.to_str().expect("UTF-8 path");
    let second = second.to_str().expect("UTF-8 path");

    assert_invalid(&["--check", first, second], "multiple CONFIG_PATH");
    assert_invalid(
        &[first, "--diff", second, "--diff", first],
        "--diff may only be specified once",
    );
    assert_invalid(
        &["--init-config", "lab", "--init-config", "edge", "--stdout"],
        "--init-config may only be specified once",
    );
}

#[test]
fn option_values_cannot_consume_another_flag() {
    assert_invalid(&["--diff", "--check"], "--diff requires a path argument");
    assert_invalid(
        &["--init-config", "--stdout"],
        "--init-config requires a profile name",
    );
}

#[test]
fn unknown_options_use_the_documented_invocation_exit() {
    let output = run(&["--not-an-option"], None);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown option: --not-an-option"),
        "{stderr}"
    );
    let usage = concat!(
        "usage: rustbgpd [--runtime-state-dir DIR] [--check [--strict]] [--diff PATH] [--json] ",
        "[--init-config PROFILE] [--dump-config-schema] [CONFIG_PATH]\n",
        "       rustbgpd --release-core-isolation --runtime-state-dir DIR\n",
        "       rustbgpd (--help | -h)\n",
        "       rustbgpd (--version | -V)\n",
        "       rustbgpd --man\n",
    );
    assert!(stderr.ends_with(usage), "unexpected usage:\n{stderr}");
    let normal_form = usage.lines().next().expect("normal usage form");
    for standalone in ["--help", "-h", "--version", "-V", "--man"] {
        assert!(
            !normal_form.contains(standalone),
            "standalone mode {standalone} presented as combinable: {normal_form}"
        );
    }
}

#[test]
fn display_modes_are_standalone() {
    for args in [
        &["--help", "--check"][..],
        &["-h", "config.toml"][..],
        &["--version", "--offline"][..],
        &["-V", "--version"][..],
        &["--man", "--dump-config-schema"][..],
    ] {
        assert_invalid(args, "must be used alone");
    }
}

#[test]
fn one_shot_modes_do_not_ignore_competing_inputs() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_path = temp.path().join("config.toml");
    std::fs::write(&config_path, starter_config()).expect("write config");
    let config_path = config_path.to_str().expect("UTF-8 path");

    assert_invalid(
        &["--init-config", "lab", "--stdout", config_path],
        "--init-config cannot be combined with CONFIG_PATH",
    );
    assert_invalid(
        &["--dump-config-schema", config_path],
        "--dump-config-schema cannot be combined with CONFIG_PATH",
    );
    assert_invalid(
        &["--check", config_path, "--diff", config_path],
        "--check cannot be combined with --diff",
    );
}

#[test]
fn valid_one_shot_interleavings_and_literal_dash_paths_still_work() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = starter_config();
    let config_path = temp.path().join("config.toml");
    std::fs::write(&config_path, &config).expect("write config");
    let config_path = config_path.to_str().expect("UTF-8 path");

    for args in [
        vec!["--check", config_path],
        vec![config_path, "--check"],
        vec!["--diff", config_path, config_path],
        vec![config_path, "--diff", config_path],
        vec!["--init-config", "edge"],
        vec!["--init-config", "edge", "--stdout"],
        vec!["--dump-config-schema"],
    ] {
        let output = run(&args, None);
        assert_eq!(output.status.code(), Some(0), "{args:?}: {output:?}");
        assert!(!output.stdout.is_empty(), "{args:?}: no one-shot output");
        assert!(output.stderr.is_empty(), "{args:?}: {output:?}");
    }

    std::fs::write(temp.path().join("-config.toml"), config).expect("write dash config");
    let output = run(&["--check", "./-config.toml"], Some(temp.path()));
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stdout.starts_with(b"config OK:"), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
}

/// `--diff` documents exit 2 for a config that cannot be loaded. The current
/// config (second path) shares its loader with daemon boot and `--check`,
/// which exit 1, so the diff mode must map that failure itself.
#[test]
fn diff_exits_2_when_the_current_config_cannot_be_loaded() {
    let temp = tempfile::tempdir().expect("tempdir");
    let candidate = temp.path().join("candidate.toml");
    std::fs::write(&candidate, starter_config()).expect("write candidate config");
    let candidate = candidate.to_str().expect("UTF-8 path");
    let missing = temp.path().join("missing.toml");
    let missing = missing.to_str().expect("UTF-8 path");

    let output = run(&["--diff", candidate, missing], None);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("error: failed to read") && stderr.contains("missing.toml"),
        "{stderr}"
    );
}

#[test]
fn check_still_exits_1_when_the_config_cannot_be_loaded() {
    let temp = tempfile::tempdir().expect("tempdir");
    let missing = temp.path().join("missing.toml");
    let missing = missing.to_str().expect("UTF-8 path");

    let output = run(&["--check", missing], None);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("error: failed to read") && stderr.contains("missing.toml"),
        "{stderr}"
    );
}

/// ADR-0140: the release helper takes only `--runtime-state-dir`, never
/// reads a config, fails loudly on a missing directory and succeeds on a
/// readable one without a receipt.
#[cfg(target_os = "linux")]
#[test]
fn release_core_isolation_is_a_config_free_one_shot() {
    assert_invalid(
        &["--release-core-isolation"],
        "--release-core-isolation requires --runtime-state-dir DIR",
    );
    assert_invalid(
        &[
            "--release-core-isolation",
            "--runtime-state-dir",
            "/tmp",
            "/etc/rustbgpd/config.toml",
        ],
        "--release-core-isolation takes only --runtime-state-dir DIR",
    );
    assert_invalid(
        &["--runtime-state-dir"],
        "--runtime-state-dir requires a directory argument",
    );

    let temp = tempfile::tempdir().expect("tempdir");
    let missing = temp.path().join("missing");
    let output = run(
        &[
            "--release-core-isolation",
            "--runtime-state-dir",
            missing.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("cannot open runtime-state directory"),
        "{output:?}"
    );

    let dir = temp.path().join("state");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let output = run(
        &[
            "--release-core-isolation",
            "--runtime-state-dir",
            dir.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(dir.join("evpn-core-isolation-owned.json.lock").exists());
}

/// The daemon's `--runtime-state-dir` must name the config's directory.
#[test]
fn runtime_state_dir_flag_must_match_the_config() {
    let temp = tempfile::tempdir().expect("tempdir");
    let state = temp.path().join("state");
    let config = starter_config()
        .lines()
        .map(|line| {
            if line.starts_with("runtime_state_dir") {
                format!("runtime_state_dir = \"{}\"", state.display())
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let config_path = temp.path().join("config.toml");
    std::fs::write(&config_path, config).expect("write config");
    let config_path = config_path.to_str().unwrap();

    let same = format!("{}/", state.display());
    let output = run(
        &["--runtime-state-dir", &same, "--check", config_path],
        None,
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");

    let output = run(
        &["--runtime-state-dir", "/elsewhere", "--check", config_path],
        None,
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("differs from the config"),
        "{output:?}"
    );
    assert_invalid(
        &[
            "--runtime-state-dir",
            "/x",
            "--diff",
            config_path,
            config_path,
        ],
        "--runtime-state-dir applies only to a daemon start or --check",
    );

    // A symlink to the right directory is refused at start, because the
    // release helper would refuse it at stop.
    std::fs::create_dir(&state).unwrap();
    let link = temp.path().join("state-link");
    std::os::unix::fs::symlink(&state, &link).unwrap();
    let output = run(
        &[
            "--runtime-state-dir",
            link.to_str().unwrap(),
            "--check",
            config_path,
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("is a symlink"),
        "{output:?}"
    );
}
