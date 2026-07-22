//! Structural and production-loader gate for the active M36-M69 auth migration.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

const TOKEN: &str = "/run/rustbgpd/grpc-test-only-operator.token";
const PRINCIPAL: &str = "rustbgpd://operator/test-only";
const TOKEN_BIND: &str =
    "../fixtures/grpc-test-only-operator.token:/run/rustbgpd/grpc-test-only-operator.token:ro";
const EXCLUDED: &[&str] = &[
    "rustbgpd-m37-originator.toml",
    "rustbgpd-m39-pe1.toml",
    "rustbgpd-m67-vtep.toml",
    "rustbgpd-m44-tier-authz.toml",
    "rustbgpd-m54-gnmi.toml",
    "rustbgpd-m56-gnmi-onchange.toml",
    "rustbgpd-m66-pe1.toml",
    "rustbgpd-m66-pe2.toml",
    "rustbgpd-m67-pe1.toml",
    "rustbgpd-m67-pe2.toml",
];

fn in_scope(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix("rustbgpd-m") else {
        return false;
    };
    let digits: String = suffix.chars().take_while(char::is_ascii_digit).collect();
    name.ends_with(".toml")
        && digits.parse::<u8>().is_ok_and(|n| (36..=69).contains(&n))
        && !EXCLUDED.contains(&name)
}

/// Reverting tier, removing a mount/opt-in/M66 token, bypassing the helper, or
/// omitting a standalone header makes this red; semantic breaks fail `--check`.
#[test]
fn active_dataplane_interop_is_tier_authenticated_end_to_end() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let interop = root.join("tests/interop");
    let config_dir = interop.join("configs");
    let token_host = root.join("tests/fixtures/grpc-test-only-operator.token");
    let mut configs = BTreeSet::new();

    for entry in fs::read_dir(&config_dir).unwrap() {
        let file = entry.unwrap().path();
        let name = file.file_name().unwrap().to_str().unwrap();
        if !in_scope(name) {
            continue;
        }
        let source = fs::read_to_string(&file).expect("interop config must be readable");
        let value: toml::Value =
            toml::from_str(&source).unwrap_or_else(|error| panic!("{name}: {error}"));
        let grpc = &value["global"]["telemetry"]["grpc_tcp"];
        let security = &value["security"]["grpc"];
        assert_eq!(grpc["token_file"].as_str(), Some(TOKEN), "{name}");
        assert_eq!(grpc["principal"].as_str(), Some(PRINCIPAL), "{name}");
        assert_eq!(security["enforcement"].as_str(), Some("tier"), "{name}");
        let role = security["roles"][PRINCIPAL].as_str();
        assert_eq!(role, Some("operator"), "{name}");

        let materialized = source
            .replace(TOKEN, &token_host.display().to_string())
            .replace("STAYRTR_ADDR", "127.0.0.1")
            .replace("BMP_RECEIVER_ADDR", "127.0.0.1");
        let mut staged = tempfile::Builder::new()
            .suffix(".config-check")
            .tempfile_in(&config_dir)
            .expect("create materialized config beside relative resources");
        staged.write_all(materialized.as_bytes()).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
            .arg("--check")
            .arg(staged.path())
            .current_dir(root)
            .output()
            .expect("run production config loader");
        assert!(
            output.status.success(),
            "{name} failed production --check\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        configs.insert(name.to_owned());
    }
    assert_eq!(configs.len(), 37, "classify the changed config inventory");

    let mut topologies = BTreeSet::new();
    let mut mounted = BTreeSet::new();
    for entry in fs::read_dir(&interop).unwrap() {
        let file = entry.unwrap().path();
        let name = file.file_name().unwrap().to_str().unwrap();
        if !name.ends_with(".clab.yml") {
            continue;
        }
        let source = fs::read_to_string(&file).expect("topology must be readable");
        if !configs.iter().any(|config| source.contains(config)) {
            continue;
        }
        let yaml: serde_yaml::Value = serde_yaml::from_str(&source)
            .unwrap_or_else(|error| panic!("{name} invalid YAML: {error}"));
        let nodes = yaml["topology"]["nodes"].as_mapping().expect("nodes map");
        for (node_name, node) in nodes {
            let Some(binds) = node["binds"].as_sequence() else {
                continue;
            };
            let bound: Vec<_> = binds
                .iter()
                .filter_map(serde_yaml::Value::as_str)
                .filter_map(|bind| Path::new(bind.split(':').next()?).file_name()?.to_str())
                .filter(|config| configs.contains(*config))
                .collect();
            if bound.is_empty() {
                continue;
            }
            topologies.insert(name.trim_end_matches(".clab.yml").to_owned());
            mounted.extend(bound.iter().map(|config| (*config).to_owned()));
            assert!(
                binds.iter().any(|bind| bind.as_str() == Some(TOKEN_BIND)),
                "{name} node {node_name:?} lacks shared token beside {bound:?}"
            );
        }
    }
    let unmounted: BTreeSet<_> = configs.difference(&mounted).cloned().collect();
    assert_eq!(
        unmounted,
        BTreeSet::from(["rustbgpd-m47-teardown.toml".into()])
    );
    assert_eq!(topologies.len(), 29, "topology inventory changed");

    let standalone = [
        "m38-evpn-df-election",
        "m46-evpn-df-hrw",
        "m49-evpn-preference-df",
    ];
    for topology in &topologies {
        let driver = match topology.as_str() {
            "m59-aspa-roles-rtr2" => "test-m59-aspa-roles.sh".to_owned(),
            _ => format!("test-{topology}.sh"),
        };
        let source = fs::read_to_string(interop.join("scripts").join(&driver))
            .unwrap_or_else(|error| panic!("{driver}: {error}"));
        if source.contains("source \"$SCRIPT_DIR/test-lib.sh\"") {
            assert!(source.contains("INTEROP_TEST_OPERATOR_AUTH=1"), "{driver}");
            assert!(
                !source.contains("grpcurl -plaintext"),
                "{driver} bypasses helper"
            );
        } else {
            assert!(
                standalone.contains(&topology.as_str()),
                "unexpected {driver}"
            );
            assert!(source.contains(
                "TEST_OPERATOR_TOKEN_FILE=\"tests/fixtures/grpc-test-only-operator.token\""
            ));
            assert!(
                source.contains("\"${GRPC_AUTH[@]}\""),
                "{driver} lacks bearer header"
            );
        }
    }

    let m66: serde_yaml::Value = serde_yaml::from_str(
        &fs::read_to_string(interop.join("m66-evpn-es-drain-handover.clab.yml")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        m66["topology"]["nodes"]["vtep"]["env"]["RUSTBGPD_TOKEN_FILE"].as_str(),
        Some(TOKEN),
        "M66 vtep_ctl must inherit the shared token"
    );
}

/// Load-bearing proof: restoring either daemon-log grep oracle, removing the
/// field-presence lookup, or dropping the assert/clear legs makes this gate red
/// before the expensive M51 topology runs.
#[test]
fn m51_remote_admin_down_uses_the_public_field_as_primary_oracle() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = fs::read_to_string(root.join("tests/interop/scripts/test-m51-bfd-frr.sh"))
        .expect("M51 driver must be readable");

    assert!(source.contains("has(\"remoteAdministrativeDown\")"));
    assert!(source.contains("($session | type) != \"object\""));
    assert!(source.contains("error(\"BFD session is absent\")"));
    assert!(
        source.contains(
            "wait_grpc_bfd_remote_admin_down \"true\" \"asserted while BGP is permitted\""
        )
    );
    assert!(
        source.contains(
            "wait_grpc_bfd_remote_admin_down \"false\" \"cleared after FRR no shutdown\""
        )
    );
    assert!(!source.contains("BFD remote AdminDown.*allowing BGP"));
    assert!(!source.contains("BFD remote AdminDown flip without local transition"));
}
