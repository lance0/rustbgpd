//! Emitted-config acceptance gate for `rbgp config import`: the
//! config.toml translated from each checked-in fixture (BIRD 2, FRR,
//! GoBGP) must pass the real daemon's `rustbgpd --check`. Golden
//! translations and report content are pinned in
//! `crates/cli/tests/config_import.rs`; this test owns the
//! must-actually-load bar.

use rustbgpctl::importer::{SourceFormat, import_source};

#[test]
fn emitted_configs_pass_rustbgpd_check() {
    for (format, path, contents) in [
        (
            SourceFormat::Bird,
            "bird.conf",
            include_str!("../crates/cli/tests/fixtures/import/bird.conf"),
        ),
        (
            SourceFormat::Frr,
            "frr.conf",
            include_str!("../crates/cli/tests/fixtures/import/frr.conf"),
        ),
        (
            SourceFormat::Gobgp,
            "gobgp.toml",
            include_str!("../crates/cli/tests/fixtures/import/gobgp.toml"),
        ),
    ] {
        let imported = import_source(format, path, contents)
            .unwrap_or_else(|e| panic!("{path}: import failed: {e}"));
        let dir = tempfile::tempdir().expect("tempdir");
        let config = dir.path().join("config.toml");
        std::fs::write(&config, &imported.config_toml).expect("write config");
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
            .arg("--check")
            .arg(&config)
            .output()
            .expect("run rustbgpd --check");
        assert!(
            output.status.success(),
            "rustbgpd --check rejected the config imported from {path}\nstdout:\n{}\nstderr:\n{}\nconfig:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
            imported.config_toml,
        );
    }
}
