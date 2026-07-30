#![cfg(unix)]

use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};

fn run_with_closed_stdout(args: &[&str]) {
    let (reader, writer) = UnixStream::pair().unwrap();
    drop(reader);
    let writer: OwnedFd = writer.into();
    let output = Command::new(env!("CARGO_BIN_EXE_rbgp"))
        .args(args)
        .stdout(Stdio::from(writer))
        .stderr(Stdio::piped())
        .env("RUST_BACKTRACE", "1")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.contains("panicked"));
    assert!(!stderr.contains("stack backtrace"));
}

#[test]
fn offline_commands_quietly_handle_closed_stdout() {
    run_with_closed_stdout(&["completions", "bash"]);
    run_with_closed_stdout(&[
        "policy",
        "check",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/route-server/hygiene.rpol"
        ),
    ]);
    run_with_closed_stdout(&[
        "config",
        "import",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/import/frr.conf"
        ),
    ]);
}
