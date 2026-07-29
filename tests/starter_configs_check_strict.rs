//! Every shipped starter config passes `rustbgpd --check --strict`.
//!
//! `--check` warns about an eBGP neighbor that resolves no explicit policy,
//! and `--strict` turns that warning into a failing exit code. A starter that
//! trips our own safety warning teaches the operator who runs it first that
//! the warning is noise, which is the one thing that makes the warning
//! worthless. So the starters are held to the strict gate: a first run of a
//! shipped config is clean, or this test is red.
//!
//! Both sides are enumerated rather than listed. Examples come from the
//! `examples/` tree, profiles come from the daemon's own "available:" line,
//! so a starter added later is covered without editing this file — a
//! hand-maintained array here would go stale exactly when it mattered.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The repo's public test-only bearer token, substituted for a starter's
/// `token_file` when that path only exists inside a container.
const TOKEN_FIXTURE: &str = "tests/fixtures/grpc-test-only-operator.token";

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Run the daemon binary and return `(exit_code, stdout, stderr)`.
fn run(args: &[&str]) -> (Option<i32>, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
        .args(args)
        // Warnings are framed for a terminal; keep assertions on text.
        .env("NO_COLOR", "1")
        .current_dir(repo_root())
        .output()
        .expect("run rustbgpd");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The `--init-config` profile names, read off the daemon's own rejection of
/// an unknown profile (`available: lab, edge`). That message is generated
/// from `PROFILE_NAMES`, so adding a profile adds it here too — and the
/// binary is the only place an integration test can see that list, since the
/// `config` module is a lib export only under `bench-internals`.
fn profile_names() -> Vec<String> {
    let (code, _, stderr) = run(&["--init-config", "no-such-profile", "--stdout"]);
    assert_eq!(code, Some(2), "unknown profile must be rejected: {stderr}");
    let listed = stderr
        .split_once("available: ")
        .unwrap_or_else(|| panic!("profile rejection no longer lists the profiles:\n{stderr}"))
        .1;
    listed
        .trim()
        .split(", ")
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Every TOML config under `examples/`. `Cargo.toml` is the only other kind
/// of TOML that lives there (the two runnable adapter crates), so excluding
/// it by name keeps this an enumeration rather than an allowlist.
fn example_configs() -> Vec<PathBuf> {
    let mut configs = Vec::new();
    for entry in fs::read_dir(repo_root().join("examples")).expect("read examples/") {
        let dir = entry.expect("examples/ entry").path();
        if !dir.is_dir() {
            continue;
        }
        for entry in fs::read_dir(&dir).expect("read example dir") {
            let file = entry.expect("example dir entry").path();
            if file.extension().is_some_and(|ext| ext == "toml")
                && file.file_name().is_some_and(|name| name != "Cargo.toml")
            {
                configs.push(file);
            }
        }
    }
    configs.sort();
    configs
}

/// Assert a clean strict check and say which starter failed if not.
fn assert_clean(label: &str, code: Option<i32>, stdout: &str, stderr: &str) {
    assert_eq!(
        code,
        Some(0),
        "{label} does not pass `rustbgpd --check --strict`.\n\
         A shipped starter must be policy-complete: give every eBGP neighbor \
         an explicit import and export chain (permit-all is fine when the \
         comment says it is deliberate).\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("config OK"),
        "{label} exited 0 without a clean summary:\n{stdout}"
    );
}

#[test]
fn every_init_config_profile_passes_check_strict() {
    let profiles = profile_names();
    assert!(!profiles.is_empty(), "enumerated no profiles");

    let dir = tempfile::tempdir().expect("tempdir");
    for profile in &profiles {
        let (code, toml, stderr) = run(&["--init-config", profile, "--stdout"]);
        assert_eq!(code, Some(0), "--init-config {profile} failed:\n{stderr}");
        let path = dir.path().join(format!("{profile}.toml"));
        fs::write(&path, toml).expect("write emitted profile");

        let path = path.to_str().expect("utf-8 temp path");
        let (code, stdout, stderr) = run(&["--check", "--strict", path]);
        assert_clean(&format!("--init-config {profile}"), code, &stdout, &stderr);
    }
}

/// A `[global.telemetry.grpc_tcp] token_file` this host cannot read, if the
/// starter names one. The compose starter's token is bind-mounted at run
/// time, so on a checkout it points at a path that does not exist —
/// `--check` rejects the config before it ever reaches the policy warnings
/// this test is about.
fn unreadable_token_file(source: &str) -> Option<String> {
    let value: toml::Value = toml::from_str(source).ok()?;
    let token = value
        .get("global")?
        .get("telemetry")?
        .get("grpc_tcp")?
        .get("token_file")?
        .as_str()?;
    (!Path::new(token).exists()).then(|| token.to_owned())
}

#[test]
fn every_example_config_passes_check_strict() {
    let configs = example_configs();
    assert!(!configs.is_empty(), "enumerated no example configs");

    for config in &configs {
        let source = fs::read_to_string(config).expect("read example config");
        // Staged beside the original, never elsewhere: `[policy] rpol_files`
        // and other resource paths resolve relative to the config's own
        // directory. Held alive until the check has run.
        let staged = unreadable_token_file(&source).map(|token| {
            let mut file = tempfile::Builder::new()
                .suffix(".config-check")
                .tempfile_in(config.parent().expect("config has a parent directory"))
                .expect("stage config beside its relative resources");
            let host_token = repo_root().join(TOKEN_FIXTURE);
            file.write_all(
                source
                    .replace(&token, &host_token.display().to_string())
                    .as_bytes(),
            )
            .expect("write staged config");
            file
        });
        let checked = staged
            .as_ref()
            .map_or(config.as_path(), tempfile::NamedTempFile::path);

        let path = checked.to_str().expect("utf-8 example path");
        let (code, stdout, stderr) = run(&["--check", "--strict", path]);
        assert_clean(&config.display().to_string(), code, &stdout, &stderr);
    }
}

#[test]
fn route_server_cookbook_does_not_apply_strict_peer_cross_family() {
    let cookbook = fs::read_to_string(repo_root().join("docs/cookbook/route-server.md"))
        .expect("read cookbook");
    let strict_stanza = cookbook
        .split("[[neighbors]]")
        .find(|stanza| stanza.contains("next_hop_ownership = \"strict_peer\""))
        .expect("cookbook must retain a strict_peer example");
    assert!(
        !(strict_stanza.contains("\"ipv4_unicast\"") && strict_stanza.contains("\"ipv6_unicast\"")),
        "strict_peer compares the wire next hop literally with the session address; \
         the cookbook must use same-AF sessions"
    );
}
