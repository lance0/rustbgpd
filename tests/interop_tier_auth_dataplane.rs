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
const CI_PRINCIPAL: &str = "rustbgpd://operator/ci";

// In-range configs pinned to `enforcement = "legacy"`. Each records its reason
// at its own `[security.grpc]` block, and the equality allowlist in
// interop_tier_auth_rr.rs owns the legacy inventory. Excluded here because the
// identity assertions below describe a listener that enforces tier ceilings,
// which these deliberately do not:
//   m37-originator — asserted via FRR's RIB, kernel bridge fdb, and Prometheus
//   m39-pe1 — plaintext grpcurl driver; the Gate 9 soak reuses the config
//   m67-vtep — M67 mounts its operator token on pe1/pe2 only
const LEGACY_EXCEPTIONS: &[&str] = &[
    "rustbgpd-m37-originator.toml",
    "rustbgpd-m39-pe1.toml",
    "rustbgpd-m67-vtep.toml",
];

// In-range configs that DO enforce tier, but authenticate with a lab-owned
// credential rather than the shared test-only operator identity, so the
// `token_file`/`principal` assertions below cannot apply to them. Both shapes
// are intrinsic to what the lab proves:
//   m44/m54/m56 — native mTLS listeners; principals arrive as client-cert URI
//     SANs, so there is no bearer token to mount
//   m66/m67 pe1+pe2 — a bearer-token operator listener plus a UDS observer
//     listener, so the driver can compose an operator drain with a link reason
const LAB_CREDENTIAL_EXCEPTIONS: &[&str] = &[
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
        && !LEGACY_EXCEPTIONS.contains(&name)
        && !LAB_CREDENTIAL_EXCEPTIONS.contains(&name)
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

/// Both exception lists are proven, not merely trusted: a stale entry naming a
/// renamed or deleted config, a legacy pin that silently moved to tier, or a
/// lab config that adopted the shared identity and should rejoin the scoped
/// assertions each make this red.
#[test]
fn auth_exceptions_still_match_their_declared_category() {
    let config_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/interop/configs");
    let read = |name: &str| {
        fs::read_to_string(config_dir.join(name))
            .unwrap_or_else(|error| panic!("{name} is listed but unreadable: {error}"))
    };
    let enforcement = |name: &str, source: &str| {
        let value: toml::Value =
            toml::from_str(source).unwrap_or_else(|error| panic!("{name}: {error}"));
        value["security"]["grpc"]
            .get("enforcement")
            .and_then(toml::Value::as_str)
            .map(str::to_owned)
    };

    for name in LEGACY_EXCEPTIONS {
        let source = read(name);
        assert_eq!(
            enforcement(name, &source).as_deref(),
            Some("legacy"),
            "{name} is listed as a legacy exception but no longer pins legacy"
        );
    }

    for name in LAB_CREDENTIAL_EXCEPTIONS {
        let source = read(name);
        assert_ne!(
            enforcement(name, &source).as_deref(),
            Some("legacy"),
            "{name} is listed as a tier-enforcing exception but pins legacy"
        );
        let value: toml::Value = toml::from_str(&source).unwrap();
        assert_eq!(
            value["security"]["grpc"]["roles"][CI_PRINCIPAL].as_str(),
            Some("operator"),
            "{name} must map the lab-owned CI operator principal"
        );
        assert!(
            !source.contains(PRINCIPAL),
            "{name} uses the shared identity and belongs in the scoped assertions"
        );
    }
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
