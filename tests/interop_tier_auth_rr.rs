//! Structural and production-loader gate for the active M70-M93 auth migration.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

const TOKEN: &str = "/run/rustbgpd/grpc-test-only-operator.token";
const PRINCIPAL: &str = "rustbgpd://operator/test-only";
const TOKEN_BIND: &str =
    "../fixtures/grpc-test-only-operator.token:/run/rustbgpd/grpc-test-only-operator.token:ro";
const CONFIGS: &[&str] = &[
    "rustbgpd-m70-vtep.toml",
    "rustbgpd-m71-vtep.toml",
    "rustbgpd-m72-vtep.toml",
    "rustbgpd-m73-bgpls-rr.toml",
    "rustbgpd-m74-vpnv4-rr.toml",
    "rustbgpd-m75-rtc-rr.toml",
    "rustbgpd-m76-orr-rr.toml",
    "rustbgpd-m77-gr-rr.toml",
    "rustbgpd-m78-rr1.toml",
    "rustbgpd-m78-rr2.toml",
    "rustbgpd-m79-labeled-rr.toml",
    "rustbgpd-m80-policy.toml",
    "rustbgpd-m81-bmp-rr.toml",
    "rustbgpd-m82-rr.toml",
    "rustbgpd-m83-rs.toml",
    "rustbgpd-m84-multicache.toml",
    "rustbgpd-m85-client.toml",
    "rustbgpd-m85-rr.toml",
    "rustbgpd-m86-client.toml",
    "rustbgpd-m86-rr.toml",
    "rustbgpd-m87-rs.toml",
    "rustbgpd-m89-paths-limit.toml",
    "rustbgpd-m91-rfc7606.toml",
    "rustbgpd-m92-rs.toml",
    "rustbgpd-m93-required.toml",
];
const TOPOLOGIES: &[&str] = &[
    "m70-evpn-vlan-aware-bridge-frr",
    "m71-evpn-esi-overlay-type5-receive-gobgp",
    "m72-evpn-esi-overlay-type5-all-active-gobgp",
    "m73-bgpls-reflection-gobgp",
    "m74-vpnv4-reflection-gobgp",
    "m75-rtc-vpnv4-filter-gobgp",
    "m76-orr-divergent-best-gobgp",
    "m77-gr-llgr-rr-gobgp",
    "m78-multicluster-orr-gobgp",
    "m79-labeled-reflection-gobgp",
    "m80-rpol-policy-parity-frr",
    "m81-bmp-trio-gobgp",
    "m82-evpn-bundle-srlinux",
    "m82-evpn-bundle-synthetic-gobgp",
    "m83-routeserver-multistack",
    "m84-rtr-multicache",
    "m85-rr-bird",
    "m86-rr-openbgpd",
    "m87-exact-export-rejection",
    "m89-paths-limit-frr",
    "m91-rfc7606-malformed",
    "m92-gobgp-v47-rs-differential",
    "m93-required-families-bird",
];
const LEGACY_ALLOWLIST: &[&str] = &[
    "tests/interop/configs/rustbgpd-frr-badopen.toml",
    "tests/interop/configs/rustbgpd-m33-scale.toml",
    "tests/interop/configs/rustbgpd-m37-originator.toml",
    "tests/interop/configs/rustbgpd-m39-pe1.toml",
    "tests/interop/configs/rustbgpd-m67-vtep.toml",
    "tests/interop/configs/rustbgpd-soak-gr-restart.toml",
    "tests/interop/configs/rustbgpd-soak-hot-reload.toml",
    "tests/interop/configs/rustbgpd-soak-inject-churn.toml",
    "tests/soak/configs/rustbgpd-soak-gate8b-pe1.toml",
    "tests/soak/configs/rustbgpd-soak-gate8b-pe2.toml",
];

fn is_rr_slice(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix("rustbgpd-m") else {
        return false;
    };
    let digits: String = suffix.chars().take_while(char::is_ascii_digit).collect();
    name.ends_with(".toml")
        && digits
            .parse::<u8>()
            .is_ok_and(|n| (70..=93).contains(&n) && n != 90)
}

fn has_legacy_enforcement(source: &str) -> bool {
    let value: toml::Value = toml::from_str(source).expect("config must be valid TOML");
    value
        .get("security")
        .and_then(|security| security.get("grpc"))
        .and_then(|grpc| grpc.get("enforcement"))
        .and_then(toml::Value::as_str)
        == Some("legacy")
}

/// Reverting tier auth, a node bind/env, or driver helper wiring makes this
/// red; semantic config breakage fails the production `--check` subprocess.
#[test]
fn rr_and_route_server_interop_is_tier_authenticated_end_to_end() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let interop = root.join("tests/interop");
    let config_dir = interop.join("configs");
    let token_host = root.join("tests/fixtures/grpc-test-only-operator.token");
    let expected_configs: BTreeSet<_> = CONFIGS.iter().map(|name| (*name).to_owned()).collect();
    let mut configs = BTreeSet::new();

    for entry in fs::read_dir(&config_dir).unwrap() {
        let file = entry.unwrap().path();
        let name = file.file_name().unwrap().to_str().unwrap();
        if !is_rr_slice(name) {
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
        assert_eq!(
            security["roles"][PRINCIPAL].as_str(),
            Some("operator"),
            "{name}"
        );

        let materialized = source
            .replace(TOKEN, &token_host.display().to_string())
            .replace("policies/core.rpol", "rustbgpd-m80-policy.rpol")
            .replace("PMACCT_ADDR", "127.0.0.1")
            .replace("GOBMP_ADDR", "127.0.0.1")
            .replace("SINK_ADDR", "127.0.0.1")
            .replace("ROUTINATOR_ADDR", "127.0.0.1")
            .replace("STAYRTR_ADDR", "127.0.0.1")
            .replace("RTRV2_ADDR", "127.0.0.1");
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
    assert_eq!(configs, expected_configs, "RR config inventory changed");

    let expected_topologies: BTreeSet<_> =
        TOPOLOGIES.iter().map(|name| (*name).to_owned()).collect();
    let mut topologies = BTreeSet::new();
    let mut mounted = BTreeSet::new();
    let mut nodes = 0;
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
        for (node_name, node) in yaml["topology"]["nodes"].as_mapping().expect("nodes map") {
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
            nodes += 1;
            mounted.extend(bound.iter().map(|config| (*config).to_owned()));
            assert!(
                binds.iter().any(|bind| bind.as_str() == Some(TOKEN_BIND)),
                "{name} node {node_name:?} lacks shared token beside {bound:?}"
            );
            assert_eq!(
                node["env"]["RUSTBGPD_TOKEN_FILE"].as_str(),
                Some(TOKEN),
                "{name} node {node_name:?} lacks token environment"
            );
        }
        topologies.insert(name.trim_end_matches(".clab.yml").to_owned());
    }
    assert_eq!(
        topologies, expected_topologies,
        "topology inventory changed"
    );
    assert_eq!(nodes, 26, "rustbgpd node inventory changed");
    assert_eq!(mounted, expected_configs, "config mount inventory changed");

    let mut drivers = BTreeSet::new();
    for topology in &topologies {
        let driver = format!("test-{topology}.sh");
        let source = fs::read_to_string(interop.join("scripts").join(&driver))
            .unwrap_or_else(|error| panic!("{driver}: {error}"));
        let opt_in = source
            .find("INTEROP_TEST_OPERATOR_AUTH=1")
            .expect("auth opt-in");
        let helper = source
            .find("source \"$SCRIPT_DIR/test-lib.sh\"")
            .expect("test-lib");
        assert!(opt_in < helper, "{driver} opts in after sourcing helper");
        assert!(
            !source.contains("grpcurl -plaintext"),
            "{driver} bypasses helper"
        );
        drivers.insert(driver);
    }
    assert_eq!(drivers.len(), 23, "driver inventory changed");
}

/// Adding an unowned legacy config or removing a stale allowlist entry makes
/// this red: equality deliberately fences both sides of the inventory.
#[test]
fn legacy_auth_inventory_is_exactly_the_owned_exceptions() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut live = BTreeSet::new();
    for relative_dir in ["tests/interop/configs", "tests/soak/configs"] {
        for entry in fs::read_dir(root.join(relative_dir)).unwrap() {
            let file = entry.unwrap().path();
            if file.extension().and_then(|ext| ext.to_str()) != Some("toml") {
                continue;
            }
            if has_legacy_enforcement(&fs::read_to_string(&file).expect("config readable")) {
                live.insert(
                    file.strip_prefix(root)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_owned(),
                );
            }
        }
    }
    assert_eq!(
        live,
        LEGACY_ALLOWLIST
            .iter()
            .map(|path| (*path).to_owned())
            .collect()
    );
}

/// Replacing semantic TOML inspection with a text search makes this red: the
/// legacy value uses equivalent single-quote syntax and the tier value names
/// legacy only in a comment.
#[test]
fn legacy_inventory_classification_is_semantic() {
    assert!(has_legacy_enforcement(
        "[security.grpc]\nenforcement = 'legacy'\n"
    ));
    assert!(!has_legacy_enforcement(
        "[security.grpc]\nenforcement = 'tier' # enforcement = \"legacy\"\n"
    ));
}
