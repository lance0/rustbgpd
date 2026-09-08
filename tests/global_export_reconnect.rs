//! Real-daemon regression for global export removal across reconnects.

mod support;

#[test]
fn global_export_removal_survives_static_and_dynamic_reconnects() {
    let evidence = support::RetainOnPanic::new(
        tempfile::Builder::new()
            .prefix("global-export-")
            .tempdir()
            .expect("test directory"),
    );
    let output = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/global_export_reconnect.py"
        ))
        .arg("--binary")
        .arg(env!("CARGO_BIN_EXE_rustbgpd"))
        .arg("--rbgp")
        .arg(support::rbgp_binary())
        .arg("--out")
        .arg(evidence.path())
        .output()
        .expect("run local BGP regression");
    assert!(
        output.status.success(),
        "global export reconnect regression failed: {}\n{}\n{}",
        evidence.path().display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
