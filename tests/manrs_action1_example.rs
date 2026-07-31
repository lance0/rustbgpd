//! The copyable MANRS Action 1 example stays daemon-valid and its embedded
//! policy tests run through the real `rbgp policy check` command.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn run_rbgp(args: &[&str]) -> Output {
    let sibling = Path::new(env!("CARGO_BIN_EXE_rustbgpd"))
        .parent()
        .expect("rustbgpd binary has a parent")
        .join("rbgp");
    if sibling.is_file() {
        return Command::new(sibling)
            .args(args)
            .current_dir(repo_root())
            .output()
            .expect("run rbgp");
    }

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    Command::new(cargo)
        .args(["run", "--quiet", "-p", "rustbgpctl", "--bin", "rbgp", "--"])
        .args(args)
        .current_dir(repo_root())
        .output()
        .expect("run rbgp through cargo")
}

fn example(path: &str) -> PathBuf {
    repo_root().join("examples/manrs-action1").join(path)
}

#[test]
fn manrs_action1_example_passes_strict_config_and_policy_checks() {
    let config = example("config.toml");
    let config_output = Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
        .args(["--check", "--strict"])
        .arg(&config)
        .output()
        .expect("run rustbgpd --check --strict");
    assert!(
        config_output.status.success(),
        "strict config check failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&config_output.stdout),
        String::from_utf8_lossy(&config_output.stderr)
    );
    assert!(String::from_utf8_lossy(&config_output.stdout).contains("config OK"));

    let policy = example("member-a-irr.rpol");
    let policy_output = run_rbgp(&["policy", "check", policy.to_str().expect("UTF-8 path")]);
    assert!(
        policy_output.status.success(),
        "policy check failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&policy_output.stdout),
        String::from_utf8_lossy(&policy_output.stderr)
    );
}
