//! Emitted-config acceptance gate for `rbgp config import`: the
//! config.toml translated from each checked-in fixture (BIRD 2, FRR,
//! GoBGP) must pass the real daemon's `rustbgpd --check`, and that check
//! must say out loud that nothing filters those eBGP sessions yet.
//! Golden translations and report content are pinned in
//! `crates/cli/tests/config_import.rs`; this test owns the
//! must-actually-load bar and the last-gate honesty bar.

use rustbgpctl::importer::{SourceFormat, import_source};

const SOURCES: [(SourceFormat, &str, &str); 3] = [
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
];

/// Run the real daemon's `--check` against `config_toml`; returns
/// `(exit_code, stdout, stderr)`.
fn run_check(config_toml: &str) -> (Option<i32>, String, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("config.toml");
    std::fs::write(&config, config_toml).expect("write config");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
        .arg("--check")
        .arg(&config)
        // Warnings are framed for a terminal; keep the assertions on text.
        .env("NO_COLOR", "1")
        .output()
        .expect("run rustbgpd --check");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn emitted_configs_pass_rustbgpd_check() {
    for (format, path, contents) in SOURCES {
        let imported = import_source(format, path, contents)
            .unwrap_or_else(|e| panic!("{path}: import failed: {e}"));
        let (code, stdout, stderr) = run_check(&imported.config_toml);
        assert_eq!(
            code,
            Some(0),
            "rustbgpd --check rejected the config imported from {path}\nstdout:\n{stdout}\nstderr:\n{stderr}\nconfig:\n{}",
            imported.config_toml,
        );
    }
}

/// Fail-closed exit contract: when the emitted config is one the daemon's
/// `--check` rejects (unparseable router-id, dangling peer-group reference),
/// the import itself must exit nonzero — a clean exit 0 alongside a rejected
/// translation would break the ladder's "operator attention is non-zero by
/// construction" promise.
#[test]
fn import_exits_nonzero_when_emitted_config_fails_check() {
    for (format, path, source) in [
        (
            SourceFormat::Frr,
            "frr-badrid.conf",
            "router bgp 64500\n bgp router-id 2001:db8::1\n \
             neighbor 192.0.2.1 remote-as 64496\n!\n",
        ),
        (
            SourceFormat::Gobgp,
            "gobgp-dangling.toml",
            "[global.config]\nas = 64500\nrouter-id = \"192.0.2.10\"\n[[neighbors]]\n\
             [neighbors.config]\nneighbor-address = \"192.0.2.1\"\npeer-as = 64496\n\
             peer-group = \"CORE\"\n",
        ),
    ] {
        let imported = import_source(format, path, source)
            .unwrap_or_else(|e| panic!("{path}: import failed: {e}"));
        let (code, _stdout, stderr) = run_check(&imported.config_toml);
        assert_ne!(
            code,
            Some(0),
            "{path}: precondition — the emitted config must fail --check:\n{stderr}"
        );
        assert_ne!(
            imported.report.exit_code, 0,
            "{path}: import exited 0 while emitting a --check-rejected config:\n{}",
            imported.config_toml
        );
    }
}

/// The defect this gate exists for: an imported config has no policy, and
/// `--check` is the last thing an operator runs before copying it to a
/// production box. It must name the unpoliced neighbors, and its summary
/// line must not be readable as a clean result. Exit stays 0 — a permit-all
/// route server is a legitimate configuration, so this is a warning.
#[test]
fn check_warns_about_unpoliced_ebgp_in_both_enforcement_modes() {
    for (format, path, contents) in SOURCES {
        let imported = import_source(format, path, contents)
            .unwrap_or_else(|e| panic!("{path}: import failed: {e}"));
        let addresses: Vec<&str> = imported
            .config_toml
            .lines()
            .filter_map(|l| l.strip_prefix("address = \""))
            .filter_map(|l| l.strip_suffix('"'))
            .collect();
        assert!(!addresses.is_empty(), "{path}: fixture has no neighbors");

        // As emitted: `ebgp_requires_policy = true`, so the unpoliced
        // directions run the reserved deny and carry nothing.
        let (code, stdout, stderr) = run_check(&imported.config_toml);
        assert_eq!(code, Some(0), "{path}: warnings must not change the exit");
        assert!(
            stderr.contains("WARNING") && stderr.contains("reserved deny"),
            "{path}: fail-closed check must say so:\n{stderr}"
        );
        for address in &addresses {
            assert!(
                stderr.contains(address),
                "{path}: {address} unnamed in:\n{stderr}"
            );
        }
        assert!(
            !stdout.contains("config OK"),
            "{path}: a flagged check must not summarize as OK:\n{stdout}"
        );
        assert!(
            stdout.contains(&format!("{} WARNING", addresses.len())),
            "{path}: the summary must carry the count:\n{stdout}"
        );

        // Same config run permit-all: the same neighbors, the opposite
        // consequence.
        let permit_all: String = imported
            .config_toml
            .lines()
            .filter(|l| !l.starts_with("ebgp_requires_policy"))
            .map(|l| format!("{l}\n"))
            .collect();
        let (code, stdout, stderr) = run_check(&permit_all);
        assert_eq!(code, Some(0), "{path}: warnings must not change the exit");
        assert!(
            stderr.contains("WARNING") && stderr.contains("unfiltered"),
            "{path}: permit-all check must say so:\n{stderr}"
        );
        assert!(!stdout.contains("config OK"), "{path}:\n{stdout}");
    }
}
