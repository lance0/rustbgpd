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
];
const GENERATED_CONFIG_RECEIPT: &str = "test-m90-differential.sh";
const GENERATED_CONFIG_FRAGMENT: &str = "m90-differential/policy-explain.toml";
const GENERATED_CONFIG_APPEND: &str =
    "cat \"$POLICY_EXPLAIN_FRAGMENT\" >>\"$RENDER_DIR/config.toml\"";
const GENERATED_CONFIG_COPY: &str =
    "docker cp \"$RENDER_DIR/config.toml\" \"$RUSTBGPD\":/etc/rustbgpd/config.toml";
const GENERATED_CONFIG_CHECK: &str = "--check --strict /etc/rustbgpd/config.toml";

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
        .chain(std::iter::once(GENERATED_CONFIG_RECEIPT.to_owned()))
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

    let generated_script =
        fs::read_to_string(scripts.join(GENERATED_CONFIG_RECEIPT)).expect("M90 script is readable");
    let fragment = fs::read_to_string(interop.join(GENERATED_CONFIG_FRAGMENT))
        .expect("M90 explain fragment is readable");
    assert!(
        explain_enabled(&fragment),
        "{GENERATED_CONFIG_FRAGMENT} must explicitly enable policy explain"
    );
    let append_pos = generated_script
        .find(GENERATED_CONFIG_APPEND)
        .expect("M90 must append its policy-explain fragment");
    let copy_pos = generated_script
        .find(GENERATED_CONFIG_COPY)
        .expect("M90 must copy its rendered config into the daemon container");
    let check_pos = generated_script
        .find(GENERATED_CONFIG_CHECK)
        .expect("M90 must validate its rendered config");
    assert!(
        append_pos < copy_pos && append_pos < check_pos,
        "{GENERATED_CONFIG_RECEIPT} must append its policy-explain fragment before config copy and validation"
    );
}
