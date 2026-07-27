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
/// `--check` rejects, the import itself must exit nonzero — a clean exit 0
/// alongside a rejected translation would break the ladder's "operator
/// attention is non-zero by construction" promise.
///
/// Load-bearing proof: removing any corresponding `finish` guard makes that
/// case return exit 0 while the real daemon still rejects its output.
#[test]
fn import_exits_nonzero_when_emitted_config_fails_check() {
    for (format, path, source, warning) in [
        (
            SourceFormat::Frr,
            "frr-badrid.conf",
            "router bgp 64500\n bgp router-id 2001:db8::1\n \
             neighbor 192.0.2.1 remote-as 64496\n!\n",
            "router-id",
        ),
        (
            SourceFormat::Gobgp,
            "gobgp-dangling.toml",
            "[global.config]\nas = 64500\nrouter-id = \"192.0.2.10\"\n[[neighbors]]\n\
             [neighbors.config]\nneighbor-address = \"192.0.2.1\"\npeer-as = 64496\n\
             peer-group = \"CORE\"\n",
            "CORE",
        ),
        (
            SourceFormat::Frr,
            "frr-local-as-zero.conf",
            "router bgp 0\n bgp router-id 192.0.2.10\n \
             neighbor 192.0.2.1 remote-as 64496\n!\n",
            "local AS 0",
        ),
        (
            SourceFormat::Frr,
            "frr-remote-as-zero.conf",
            "router bgp 64500\n bgp router-id 192.0.2.10\n \
             neighbor 192.0.2.1 remote-as 0\n!\n",
            "remote AS 0",
        ),
        (
            SourceFormat::Gobgp,
            "gobgp-inherited-remote-as-zero.toml",
            "[global.config]\nas = 64500\nrouter-id = \"192.0.2.10\"\n\
             [[peer-groups]]\n[peer-groups.config]\npeer-group-name = \"ixp\"\n\
             peer-as = 0\n[[neighbors]]\n[neighbors.config]\n\
             neighbor-address = \"192.0.2.1\"\npeer-group = \"ixp\"\n",
            "remote AS 0",
        ),
        (
            SourceFormat::Frr,
            "frr-link-local.conf",
            "router bgp 64500\n bgp router-id 192.0.2.10\n \
             neighbor fe80::1 remote-as 64496\n!\n",
            "link-local",
        ),
        (
            SourceFormat::Frr,
            "frr-duplicate-neighbor.conf",
            "router bgp 64500\n bgp router-id 192.0.2.10\n \
             neighbor 2001:0db8:0:0:0:0:0:1 remote-as 64496\n \
             neighbor 2001:db8::1 remote-as 64497\n!\n",
            "duplicate neighbor",
        ),
        (
            SourceFormat::Bird,
            "bird-duplicate-neighbor.conf",
            "router id 192.0.2.10;\n\
             protocol bgp n1 { local as 64500; \
             neighbor 2001:0db8:0:0:0:0:0:1 as 64496; }\n\
             protocol bgp n2 { local as 64500; neighbor 2001:db8::1 as 64497; }\n",
            "duplicate neighbor",
        ),
        (
            SourceFormat::Gobgp,
            "gobgp-duplicate-neighbor.toml",
            "[global.config]\nas = 64500\nrouter-id = \"192.0.2.10\"\n\
             [[neighbors]]\n[neighbors.config]\n\
             neighbor-address = \"2001:0db8:0:0:0:0:0:1\"\npeer-as = 64496\n\
             [[neighbors]]\n[neighbors.config]\n\
             neighbor-address = \"2001:db8::1\"\npeer-as = 64497\n",
            "duplicate neighbor",
        ),
        (
            SourceFormat::Bird,
            "bird-duplicate-group.conf",
            "router id 192.0.2.10;\n\
             template bgp ixp { local as 64500; }\n\
             template bgp ixp { local as 64500; }\n\
             protocol bgp member from ixp { neighbor 192.0.2.1 as 64496; }\n",
            "duplicate peer group",
        ),
        (
            SourceFormat::Gobgp,
            "gobgp-duplicate-group.toml",
            "[global.config]\nas = 64500\nrouter-id = \"192.0.2.10\"\n\
             [[peer-groups]]\n[peer-groups.config]\npeer-group-name = \"ixp\"\n\
             peer-as = 64496\n[[peer-groups]]\n[peer-groups.config]\n\
             peer-group-name = \"ixp\"\npeer-as = 64497\n[[neighbors]]\n\
             [neighbors.config]\nneighbor-address = \"192.0.2.1\"\n\
             peer-group = \"ixp\"\n",
            "duplicate peer group",
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
        assert!(
            imported
                .report
                .warnings
                .iter()
                .any(|message| message.contains(warning)),
            "{path}: report did not name {warning:?}: {:?}",
            imported.report.warnings
        );
    }
}

/// Identity diagnostics apply only to neighbors that survive translation.
///
/// Load-bearing proof: moving link-local/duplicate checks ahead of the
/// missing-AS skip reports two nonexistent emitted rows; the warning
/// assertions fail even though the retained config remains daemon-valid.
#[test]
fn skipped_neighbors_do_not_poison_emitted_identity_checks() {
    let source = "[global.config]\nas = 64500\nrouter-id = \"192.0.2.10\"\n\
                  [[neighbors]]\n[neighbors.config]\nneighbor-address = \"fe80::1\"\n\
                  [[neighbors]]\n[neighbors.config]\n\
                  neighbor-address = \"2001:0db8:0:0:0:0:0:1\"\n\
                  [[neighbors]]\n[neighbors.config]\n\
                  neighbor-address = \"2001:db8::1\"\npeer-as = 64496\n";
    let imported =
        import_source(SourceFormat::Gobgp, "gobgp-skipped-identity.toml", source).expect("import");
    assert_eq!(imported.report.skipped.len(), 2);
    assert!(
        imported
            .report
            .warnings
            .iter()
            .all(|message| !message.contains("link-local")
                && !message.contains("duplicate neighbor")),
        "{:?}",
        imported.report.warnings
    );
    let (code, stdout, stderr) = run_check(&imported.config_toml);
    assert_eq!(
        code,
        Some(0),
        "retained config failed --check\nstdout:\n{stdout}\nstderr:\n{stderr}\nconfig:\n{}",
        imported.config_toml
    );
}

/// Group timers share the daemon's hold-time constraint with neighbors.
///
/// Load-bearing proof: removing the group normalization emits `hold_time = 2`,
/// returns exit 0, and makes the real daemon reject the translation.
#[test]
fn invalid_group_hold_time_is_repaired_and_requires_review() {
    let source = "[global.config]\nas = 64500\nrouter-id = \"192.0.2.10\"\n\
                  [[peer-groups]]\n[peer-groups.config]\npeer-group-name = \"ixp\"\n\
                  peer-as = 64496\n[peer-groups.timers.config]\nhold-time = 2\n\
                  [[neighbors]]\n[neighbors.config]\n\
                  neighbor-address = \"192.0.2.1\"\npeer-group = \"ixp\"\n";
    let imported =
        import_source(SourceFormat::Gobgp, "gobgp-group-hold.toml", source).expect("import");
    let (code, stdout, stderr) = run_check(&imported.config_toml);
    assert_eq!(
        code,
        Some(0),
        "repaired config failed --check\nstdout:\n{stdout}\nstderr:\n{stderr}\nconfig:\n{}",
        imported.config_toml
    );
    assert!(imported.config_toml.contains("hold_time = 3"));
    assert_eq!(imported.report.exit_code, 2);
    assert!(
        imported
            .report
            .warnings
            .iter()
            .any(|message| message.contains("peer group ixp")
                && message.contains("hold time 2")
                && message.contains("minimum 3")),
        "{:?}",
        imported.report.warnings
    );
}

/// TOML-decoded control characters must be re-encoded as valid TOML escapes.
///
/// Load-bearing proof: restoring the old hand-escaper writes a raw U+0001,
/// so the structural escape assertion and the real daemon check both fail.
#[test]
fn imported_control_characters_are_toml_escaped() {
    let source = "[global.config]\nas = 64500\nrouter-id = \"192.0.2.10\"\n\
                  [[neighbors]]\n[neighbors.config]\n\
                  neighbor-address = \"192.0.2.1\"\npeer-as = 64496\n\
                  description = \"\\u0001\\t\"\n";
    let imported =
        import_source(SourceFormat::Gobgp, "gobgp-control.toml", source).expect("import");
    assert_eq!(imported.report.exit_code, 0);
    assert!(
        imported
            .config_toml
            .contains("description = \"\\u0001\\t\""),
        "{}",
        imported.config_toml
    );
    let (code, stdout, stderr) = run_check(&imported.config_toml);
    assert_eq!(
        code,
        Some(0),
        "escaped config failed --check\nstdout:\n{stdout}\nstderr:\n{stderr}\nconfig:\n{}",
        imported.config_toml
    );
}

/// Distinct decoded strings must remain distinct TOML keys after emission.
///
/// Load-bearing proof: replacing LF/CR with spaces collapses all three group
/// names onto one TOML table, so the key assertions and real daemon check fail.
#[test]
fn escaped_group_names_do_not_collapse_onto_space() {
    let source = "[global.config]\nas = 64500\nrouter-id = \"192.0.2.10\"\n\
                  [[peer-groups]]\n[peer-groups.config]\n\
                  peer-group-name = \"ixp\\nred\"\npeer-as = 64496\n\
                  [[peer-groups]]\n[peer-groups.config]\n\
                  peer-group-name = \"ixp\\rred\"\npeer-as = 64497\n\
                  [[peer-groups]]\n[peer-groups.config]\n\
                  peer-group-name = \"ixp red\"\npeer-as = 64498\n\
                  [[neighbors]]\n[neighbors.config]\n\
                  neighbor-address = \"192.0.2.1\"\npeer-as = 64499\n";
    let imported =
        import_source(SourceFormat::Gobgp, "gobgp-group-controls.toml", source).expect("import");
    assert_eq!(imported.report.exit_code, 0);
    for key in [
        "[peer_groups.\"ixp\\nred\"]",
        "[peer_groups.\"ixp\\rred\"]",
        "[peer_groups.\"ixp red\"]",
    ] {
        assert!(imported.config_toml.contains(key), "missing {key:?}");
    }
    let (code, stdout, stderr) = run_check(&imported.config_toml);
    assert_eq!(
        code,
        Some(0),
        "escaped config failed --check\nstdout:\n{stdout}\nstderr:\n{stderr}\nconfig:\n{}",
        imported.config_toml
    );
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
