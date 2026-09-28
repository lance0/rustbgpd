#![cfg(target_os = "linux")]

//! `policy check` and `policy fmt` diagnostics follow the CLI colour policy:
//! coloured on a terminal, plain under `--no-color`, `NO_COLOR` or
//! `TERM=dumb`. Stderr is a real pty, so only the policy can remove colour.

use std::io::Read;
use std::process::{Command, Stdio};

fn stderr_on_pty(args: &[&str], env: &[(&str, &str)]) -> String {
    let pty = nix::pty::openpty(None, None).expect("open a pty pair");
    let mut command = Command::new(env!("CARGO_BIN_EXE_rbgp"));
    command
        .args(args)
        .env_remove("NO_COLOR")
        .env_remove("FORCE_COLOR")
        .env_remove("CLICOLOR_FORCE")
        .env("TERM", "xterm-256color")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(pty.slave));
    for (key, value) in env {
        command.env(key, value);
    }
    let status = command.status().expect("run rbgp");
    // The Command's slave handle closed after spawn, so reading the master
    // drains what the child wrote and then fails with EIO.
    drop(command);
    assert_eq!(status.code(), Some(1), "{args:?} {env:?}");
    let mut master = std::fs::File::from(pty.master);
    let mut output = Vec::new();
    let mut buf = [0u8; 4096];
    while let Ok(n) = master.read(&mut buf)
        && n > 0
    {
        output.extend_from_slice(&buf[..n]);
    }
    String::from_utf8_lossy(&output).into_owned()
}

/// Runs `policy check` (typecheck error) and `policy fmt --check` (syntax
/// error) with `flag` and `env`, returning each command's stderr.
fn policy_diagnostics(flag: Option<&str>, env: &[(&str, &str)]) -> Vec<(&'static str, String)> {
    let dir = tempfile::tempdir().unwrap();
    let bad_type = dir.path().join("bad_type.rpol");
    std::fs::write(
        &bad_type,
        "policy p { term t { if route.zzz == 1 { accept } } }",
    )
    .unwrap();
    let bad_syntax = dir.path().join("bad_syntax.rpol");
    std::fs::write(&bad_syntax, "policy p { term t {").unwrap();
    let check = ["policy", "check", bad_type.to_str().unwrap()];
    let fmt = ["policy", "fmt", "--check", bad_syntax.to_str().unwrap()];
    [("check", &check[..]), ("fmt", &fmt[..])]
        .into_iter()
        .map(|(name, args)| {
            let args: Vec<&str> = flag.into_iter().chain(args.iter().copied()).collect();
            (name, stderr_on_pty(&args, env))
        })
        .collect()
}

fn assert_plain(flag: Option<&str>, env: &[(&str, &str)]) {
    for (name, output) in policy_diagnostics(flag, env) {
        assert!(
            !output.contains('\x1b'),
            "{name} {flag:?} {env:?}: escape codes in {output:?}"
        );
        assert!(output.contains("rror"), "{name}: {output:?}");
    }
}

#[test]
fn policy_diagnostics_are_coloured_on_a_terminal_by_default() {
    for (name, output) in policy_diagnostics(None, &[]) {
        assert!(output.contains('\x1b'), "{name}: {output:?}");
    }
}

#[test]
fn policy_diagnostics_honor_no_color_flag() {
    assert_plain(Some("--no-color"), &[]);
}

#[test]
fn policy_diagnostics_honor_no_color_env() {
    assert_plain(None, &[("NO_COLOR", "1")]);
}

#[test]
fn policy_diagnostics_honor_term_dumb() {
    assert_plain(None, &[("TERM", "dumb")]);
}
