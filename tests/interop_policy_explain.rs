//! Structural fence for interop receipts that require import-policy explain.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const FIXED_CONFIG_RECEIPTS: &[(&str, &str)] = &[
    (
        "test-m80-rpol-policy-parity-frr.sh",
        "configs/rustbgpd-m80-policy.toml",
    ),
    (
        "test-m83-routeserver-multistack.sh",
        "configs/rustbgpd-m83-rs.toml",
    ),
    (
        "test-m101-routeserver-bird332.sh",
        "configs/rustbgpd-m101-rs.toml",
    ),
    (
        "test-m102-routeserver-openbgpd92.sh",
        "configs/rustbgpd-m102-rs.toml",
    ),
];
/// Scripts that render their daemon config at run time and append the
/// named explain fragment before validating and installing it.
const GENERATED_CONFIG_RECEIPTS: &[(&str, &str)] = &[
    (
        "test-m90-differential.sh",
        "m90-differential/policy-explain.toml",
    ),
    (
        "test-m104-arouteserver-current-rs-differential.sh",
        "m90-differential/policy-explain.toml",
    ),
    (
        "test-m106-rs-white-list-control-differential.sh",
        "m106-rs-white-list-control-differential/policy-explain.toml",
    ),
];
const GENERATED_CONFIG_APPEND: &str =
    "cat \"$POLICY_EXPLAIN_FRAGMENT\" >>\"$RENDER_DIR/config.toml\"";
const GENERATED_CONFIG_COPY: &str =
    "docker cp \"$RENDER_DIR/config.toml\" \"$RUSTBGPD\":/etc/rustbgpd/config.toml";
const GENERATED_CONFIG_CHECK: &str = "--check --strict";
const GENERATED_CONFIG_CHECK_TARGET: &str = "/etc/rustbgpd/config.toml";

fn explain_enabled(source: &str) -> bool {
    let value: toml::Value = toml::from_str(source).expect("fixture must be valid TOML");
    value
        .get("policy")
        .and_then(|policy| policy.get("explain"))
        .and_then(|explain| explain.get("enabled"))
        .and_then(toml::Value::as_bool)
        == Some(true)
}

fn invokes_policy_explain(source: &str) -> bool {
    source.lines().any(|line| {
        let line = line.trim_start();
        !line.starts_with('#') && line.contains("policy explain")
    })
}

/// Removing any explicit opt-in makes this red before a multi-minute interop
/// job can reach an explain RPC. A new receipt invocation also fails until its
/// selected daemon config is added to this exact mapping.
#[test]
fn interop_policy_explain_receipts_explicitly_opt_in() {
    let interop = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/interop");
    let scripts = interop.join("scripts");
    let discovered: BTreeSet<String> = fs::read_dir(&scripts)
        .expect("interop scripts directory must be readable")
        .map(|entry| entry.expect("interop script entry must be readable").path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("sh"))
        .filter_map(|path| {
            let source = fs::read_to_string(&path).expect("interop script must be readable");
            invokes_policy_explain(&source).then(|| {
                path.file_name()
                    .expect("script must have a file name")
                    .to_string_lossy()
                    .into_owned()
            })
        })
        .collect();
    let expected: BTreeSet<String> = FIXED_CONFIG_RECEIPTS
        .iter()
        .map(|(script, _)| (*script).to_owned())
        .chain(
            GENERATED_CONFIG_RECEIPTS
                .iter()
                .map(|(script, _)| (*script).to_owned()),
        )
        .collect();
    assert_eq!(
        discovered, expected,
        "every interop script invoking `policy explain` needs an explicit config mapping"
    );

    for (script, config) in FIXED_CONFIG_RECEIPTS {
        let source = fs::read_to_string(interop.join(config))
            .unwrap_or_else(|error| panic!("{script} config {config} is unreadable: {error}"));
        assert!(
            explain_enabled(&source),
            "{script} invokes `policy explain`, but {config} does not explicitly set \
             [policy.explain] enabled = true"
        );
    }

    for (script, fragment_path) in GENERATED_CONFIG_RECEIPTS {
        let fragment = fs::read_to_string(interop.join(fragment_path))
            .unwrap_or_else(|error| panic!("{fragment_path} is unreadable: {error}"));
        assert!(
            explain_enabled(&fragment),
            "{fragment_path} must explicitly enable policy explain"
        );
        let generated_script = fs::read_to_string(scripts.join(script))
            .unwrap_or_else(|error| panic!("{script} is unreadable: {error}"));
        let append_pos = generated_script
            .find(GENERATED_CONFIG_APPEND)
            .unwrap_or_else(|| panic!("{script} must append its policy-explain fragment"));
        let copy_pos = generated_script[append_pos..]
            .find(GENERATED_CONFIG_COPY)
            .map(|position| append_pos + position)
            .unwrap_or_else(|| {
                panic!("{script} must copy its rendered config into the daemon container")
            });
        let check_pos = generated_script[append_pos..]
            .find(GENERATED_CONFIG_CHECK)
            .map(|position| append_pos + position)
            .unwrap_or_else(|| panic!("{script} must validate its rendered config"));
        let check_target_pos = generated_script[check_pos..]
            .find(GENERATED_CONFIG_CHECK_TARGET)
            .map(|position| check_pos + position)
            .unwrap_or_else(|| panic!("{script} must validate the installed rendered config"));
        assert!(
            append_pos < copy_pos && append_pos < check_pos && check_pos < check_target_pos,
            "{script} must append its policy-explain fragment before config copy and validation"
        );
    }
}
