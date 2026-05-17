use super::*;
use std::{
    fs,
    path::{Path, PathBuf},
};

use rustbgpd_policy::RouteType;
use rustbgpd_wire::{Afi, Safi};
use tempfile::NamedTempFile;

fn valid_toml() -> &'static str {
    r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
description = "peer-1"
hold_time = 90
"#
}

fn parse(toml_str: &str) -> Result<Config, ConfigError> {
    let config: Config = toml::from_str(toml_str).map_err(ConfigError::Parse)?;
    config.validate()?;
    Ok(config)
}

#[test]
fn valid_config_parses() {
    let config = parse(valid_toml()).unwrap();
    assert_eq!(config.global.asn, 65001);
    assert_eq!(config.neighbors.len(), 1);
    assert_eq!(config.neighbors[0].remote_asn, 65002);
}

#[test]
fn config_examples_parse() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut examples = Vec::new();
    collect_example_toml_files(&root.join("examples"), &mut examples);
    examples.sort();

    assert!(
        examples
            .iter()
            .any(|path| path.ends_with("linux-edge-fib/config.toml")),
        "new Linux edge FIB example must be covered"
    );

    for path in examples {
        let label = path.strip_prefix(root).unwrap_or(&path).display();
        let source = fs::read_to_string(&path).unwrap_or_else(|err| {
            panic!("failed to read example config {label}: {err}");
        });
        parse(&source).unwrap_or_else(|err| {
            panic!("example config {label} failed validation: {err}");
        });
    }
}

fn collect_example_toml_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|err| {
        panic!("failed to read example directory {}: {err}", dir.display());
    }) {
        let path = entry
            .unwrap_or_else(|err| panic!("failed to read example directory entry: {err}"))
            .path();
        if path.is_dir() {
            collect_example_toml_files(&path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("toml") {
            out.push(path);
        }
    }
}

#[test]
fn invalid_router_id_rejected() {
    let toml_str = valid_toml().replace("10.0.0.1", "not-an-ip");
    let err = parse(&toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidRouterId { .. }));
}

#[test]
fn invalid_neighbor_address_rejected() {
    let toml_str = valid_toml().replace("10.0.0.2", "bad-addr");
    let err = parse(&toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidNeighborAddress { .. }));
}

#[test]
fn duplicate_neighbor_address_rejected() {
    let toml_str = format!(
        r#"
{}

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65099
"#,
        valid_toml()
    );
    let err = parse(&toml_str).unwrap_err();
    match err {
        ConfigError::InvalidNeighborAddress { reason, .. } => {
            assert!(reason.contains("duplicate"));
        }
        other => panic!("expected InvalidNeighborAddress, got {other}"),
    }
}

#[test]
fn duplicate_neighbor_address_canonical_form_rejected() {
    let base = valid_toml().replace("10.0.0.2", "::1");
    let toml_str = format!(
        r#"
{base}

[[neighbors]]
address = "0:0:0:0:0:0:0:1"
remote_asn = 65099
"#
    );
    let err = parse(&toml_str).unwrap_err();
    match err {
        ConfigError::InvalidNeighborAddress { reason, .. } => {
            assert!(reason.contains("duplicate"));
        }
        other => panic!("expected InvalidNeighborAddress, got {other}"),
    }
}

#[test]
fn no_neighbors_accepted() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
"#;
    let config = parse(toml_str).unwrap();
    assert!(config.neighbors.is_empty());
}

#[test]
fn hold_time_one_rejected() {
    let toml_str = valid_toml().replace("hold_time = 90", "hold_time = 1");
    let err = parse(&toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidHoldTime { value: 1 }));
}

#[test]
fn hold_time_zero_accepted() {
    let toml_str = valid_toml().replace("hold_time = 90", "hold_time = 0");
    let config = parse(&toml_str).unwrap();
    assert_eq!(config.neighbors[0].hold_time, Some(0));
}

#[test]
fn default_hold_time_applied() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
"#;
    let config = parse(toml_str).unwrap();
    assert_eq!(config.neighbors[0].hold_time, None);

    let peers = config.to_peer_configs().unwrap();
    assert_eq!(peers[0].0.peer.hold_time, 90);
}

#[test]
fn to_peer_configs_maps_correctly() {
    let config = parse(valid_toml()).unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert_eq!(peers.len(), 1);

    let (transport, label, _, _) = &peers[0];
    assert_eq!(transport.peer.local_asn, 65001);
    assert_eq!(transport.peer.remote_asn, 65002);
    assert_eq!(
        transport.remote_addr,
        "10.0.0.2:179".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(label, "peer-1");
}

#[test]
fn prometheus_addr_parsed() {
    let config = parse(valid_toml()).unwrap();
    assert_eq!(
        config.prometheus_addr(),
        Some("0.0.0.0:9179".parse::<SocketAddr>().unwrap())
    );
}

#[test]
fn prometheus_addr_optional() {
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"
"#;
    let config = parse(toml).unwrap();
    assert_eq!(config.prometheus_addr(), None);
}

#[test]
fn looking_glass_addr_parsed() {
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[global.telemetry.looking_glass]
addr = "0.0.0.0:8080"
"#;
    let config = parse(toml).unwrap();
    assert_eq!(
        config.looking_glass_addr(),
        Some("0.0.0.0:8080".parse::<SocketAddr>().unwrap())
    );
}

#[test]
fn looking_glass_optional() {
    let config = parse(valid_toml()).unwrap();
    assert_eq!(config.looking_glass_addr(), None);
}

#[test]
fn looking_glass_invalid_addr_rejected() {
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[global.telemetry.looking_glass]
addr = "not-a-socket-addr"
"#;
    let err = parse(toml).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidGrpcConfig { .. }));
}

#[test]
fn runtime_state_dir_defaults_to_var_lib() {
    let config = parse(valid_toml()).unwrap();
    assert_eq!(
        config.runtime_state_dir(),
        PathBuf::from("/var/lib/rustbgpd")
    );
    assert_eq!(
        config.gr_restart_marker_path(),
        PathBuf::from("/var/lib/rustbgpd/gr-restart.toml")
    );
}

#[test]
fn runtime_state_dir_override_is_used() {
    let toml_str = valid_toml().replace(
        "listen_port = 179",
        "listen_port = 179\nruntime_state_dir = \"/tmp/rustbgpd-test\"",
    );
    let config = parse(&toml_str).unwrap();
    assert_eq!(
        config.runtime_state_dir(),
        PathBuf::from("/tmp/rustbgpd-test")
    );
    assert_eq!(
        config.gr_restart_marker_path(),
        PathBuf::from("/tmp/rustbgpd-test/gr-restart.toml")
    );
}

#[test]
fn grpc_listeners_default_to_uds() {
    let config = parse(valid_toml()).unwrap();
    assert_eq!(
        config.grpc_listeners(),
        vec![GrpcListener::Uds {
            path: PathBuf::from("/var/lib/rustbgpd/grpc.sock"),
            mode: 0o600,
            access_mode: GrpcAccessMode::ReadWrite,
            token_file: None,
        }]
    );
}

#[test]
fn grpc_tcp_listener_parses_when_enabled() {
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\n",
        valid_toml()
    );
    let config = parse(&toml_str).unwrap();
    assert_eq!(
        config.grpc_listeners(),
        vec![GrpcListener::Tcp {
            addr: "127.0.0.1:50051".parse().unwrap(),
            access_mode: GrpcAccessMode::ReadWrite,
            token_file: None,
            tls: None,
        }]
    );
}

#[test]
fn grpc_listener_access_mode_parses() {
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\naccess_mode = \"read_only\"\n",
        valid_toml()
    );
    let config = parse(&toml_str).unwrap();
    assert_eq!(
        config.grpc_listeners(),
        vec![GrpcListener::Tcp {
            addr: "127.0.0.1:50051".parse().unwrap(),
            access_mode: GrpcAccessMode::ReadOnly,
            token_file: None,
            tls: None,
        }]
    );
}

#[test]
fn grpc_uds_relative_path_rejected() {
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_uds]\npath = \"grpc.sock\"\n",
        valid_toml()
    );
    let err = parse(&toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidGrpcConfig { .. }));
}

#[test]
fn grpc_tls_partial_config_rejected() {
    // Only cert_file set — must reject because mTLS requires all three.
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\ntls_cert_file = \"/tmp/cert.pem\"\n",
        valid_toml()
    );
    let err = parse(&toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidGrpcConfig { .. }));

    // cert + key but no client CA — still partial.
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\ntls_cert_file = \"/tmp/cert.pem\"\ntls_key_file = \"/tmp/key.pem\"\n",
        valid_toml()
    );
    let err = parse(&toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidGrpcConfig { .. }));
}

/// Marker-only PEM stubs are enough for structural validation —
/// `validate_grpc_pem_file` checks for `BEGIN/END` framing and the
/// expected block kind, not key/cert math.
const STUB_CERT: &str = "-----BEGIN CERTIFICATE-----\nMIIBstub\n-----END CERTIFICATE-----\n";
const STUB_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIIBstub\n-----END PRIVATE KEY-----\n";

fn write_pem(content: &str) -> NamedTempFile {
    let f = NamedTempFile::new().unwrap();
    std::fs::write(f.path(), content).unwrap();
    f
}

#[test]
fn grpc_tls_full_config_accepted() {
    // All three TLS files set together with real PEM content — should
    // parse cleanly. Validation now reads the files at config load /
    // `--check` time, so paths must point at readable PEM-shaped data.
    let cert = write_pem(STUB_CERT);
    let key = write_pem(STUB_KEY);
    let ca = write_pem(STUB_CERT);
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\ntls_cert_file = {:?}\ntls_key_file = {:?}\ntls_client_ca_file = {:?}\n",
        valid_toml(),
        cert.path(),
        key.path(),
        ca.path(),
    );
    let config = parse(&toml_str).unwrap();
    let listeners = config.grpc_listeners();
    assert_eq!(listeners.len(), 1);
    let GrpcListener::Tcp { tls, .. } = &listeners[0] else {
        panic!("expected Tcp listener");
    };
    assert!(
        tls.is_some(),
        "tls config must be populated when all three files are set"
    );
}

/// Pre-flight catches a missing cert path before the daemon starts.
/// Otherwise a successful `--check` could be followed by a startup
/// failure during cert rotation — the surprise the adversarial review
/// flagged.
#[test]
fn grpc_tls_missing_file_rejected_at_load() {
    let key = write_pem(STUB_KEY);
    let ca = write_pem(STUB_CERT);
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\ntls_cert_file = \"/tmp/rustbgpd-tls-does-not-exist.pem\"\ntls_key_file = {:?}\ntls_client_ca_file = {:?}\n",
        valid_toml(),
        key.path(),
        ca.path(),
    );
    let err = parse(&toml_str).unwrap_err();
    let ConfigError::InvalidGrpcConfig { reason } = err else {
        panic!("expected InvalidGrpcConfig, got {err:?}");
    };
    assert!(
        reason.contains("tls_cert_file") && reason.contains("failed to read"),
        "error must mention the offending field and read failure: {reason}"
    );
}

#[test]
fn grpc_tls_empty_file_rejected_at_load() {
    let cert = NamedTempFile::new().unwrap(); // empty
    let key = write_pem(STUB_KEY);
    let ca = write_pem(STUB_CERT);
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\ntls_cert_file = {:?}\ntls_key_file = {:?}\ntls_client_ca_file = {:?}\n",
        valid_toml(),
        cert.path(),
        key.path(),
        ca.path(),
    );
    let err = parse(&toml_str).unwrap_err();
    let ConfigError::InvalidGrpcConfig { reason } = err else {
        panic!("expected InvalidGrpcConfig");
    };
    assert!(reason.contains("is empty"), "got: {reason}");
}

#[test]
fn grpc_tls_non_pem_file_rejected_at_load() {
    let cert = write_pem("not a pem file at all\n");
    let key = write_pem(STUB_KEY);
    let ca = write_pem(STUB_CERT);
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\ntls_cert_file = {:?}\ntls_key_file = {:?}\ntls_client_ca_file = {:?}\n",
        valid_toml(),
        cert.path(),
        key.path(),
        ca.path(),
    );
    let err = parse(&toml_str).unwrap_err();
    let ConfigError::InvalidGrpcConfig { reason } = err else {
        panic!("expected InvalidGrpcConfig");
    };
    assert!(
        reason.contains("no PEM blocks"),
        "error must mention missing PEM markers: {reason}"
    );
}

/// Operator swapped the cert and key paths — file is structurally
/// PEM but the wrong kind. Catching this at load time prevents a
/// successful `--check` followed by a runtime TLS failure.
#[test]
fn grpc_tls_wrong_kind_pem_rejected_at_load() {
    // cert path points at a private key blob — wrong kind.
    let cert = write_pem(STUB_KEY);
    let key = write_pem(STUB_KEY);
    let ca = write_pem(STUB_CERT);
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\ntls_cert_file = {:?}\ntls_key_file = {:?}\ntls_client_ca_file = {:?}\n",
        valid_toml(),
        cert.path(),
        key.path(),
        ca.path(),
    );
    let err = parse(&toml_str).unwrap_err();
    let ConfigError::InvalidGrpcConfig { reason } = err else {
        panic!("expected InvalidGrpcConfig");
    };
    assert!(
        reason.contains("expected kind") && reason.contains("CERTIFICATE"),
        "error must mention the expected PEM kind: {reason}"
    );
}

#[test]
fn grpc_token_file_must_be_non_empty() {
    let token_file = NamedTempFile::new().unwrap();
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\ntoken_file = {:?}\n",
        valid_toml(),
        token_file.path()
    );
    let err = parse(&toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidGrpcConfig { .. }));
}

#[test]
fn neighbor_max_prefixes() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
max_prefixes = 1000
"#;
    let config = parse(toml_str).unwrap();
    assert_eq!(config.neighbors[0].max_prefixes, Some(1000));

    let peers = config.to_peer_configs().unwrap();
    assert_eq!(peers[0].0.max_prefixes, Some(1000));
}

#[test]
fn neighbor_md5_and_ttl_security() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
md5_password = "secret"
ttl_security = true
"#;
    let config = parse(toml_str).unwrap();
    assert_eq!(config.neighbors[0].md5_password.as_deref(), Some("secret"));
    assert_eq!(config.neighbors[0].ttl_security, Some(true));

    let peers = config.to_peer_configs().unwrap();
    assert_eq!(peers[0].0.md5_password.as_deref(), Some("secret"));
    assert!(peers[0].0.ttl_security);
}

#[test]
fn policy_config_parsed() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002

[[policy.import]]
action = "deny"
prefix = "10.0.0.0/8"
ge = 24
le = 32

[[policy.export]]
action = "permit"
prefix = "192.168.0.0/16"
"#;
    let config = parse(toml_str).unwrap();
    let import = config.import_chain().unwrap().unwrap();
    assert_eq!(import.policies[0].entries.len(), 1);
    let export = config.export_chain().unwrap().unwrap();
    assert_eq!(export.policies[0].entries.len(), 1);
}

#[test]
fn empty_policy_returns_none() {
    let config = parse(valid_toml()).unwrap();
    assert!(config.import_chain().unwrap().is_none());
    assert!(config.export_chain().unwrap().is_none());
}

#[test]
fn multiple_neighbors() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
description = "peer-a"
hold_time = 90

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
hold_time = 180
"#;
    let config = parse(toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert_eq!(peers.len(), 2);
    assert_eq!(peers[0].1, "peer-a");
    assert_eq!(peers[1].1, "10.0.0.3"); // no description → address used
}

#[test]
fn per_neighbor_policy_parsed() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002

[[neighbors.import_policy]]
action = "deny"
prefix = "10.0.0.0/8"

[[neighbors.export_policy]]
action = "permit"
prefix = "192.168.0.0/16"
"#;
    let config = parse(toml_str).unwrap();
    assert_eq!(config.neighbors[0].import_policy.len(), 1);
    assert_eq!(config.neighbors[0].export_policy.len(), 1);

    let peers = config.to_peer_configs().unwrap();
    assert!(peers[0].2.is_some()); // import policy
    assert!(peers[0].3.is_some()); // export policy
}

#[test]
fn per_neighbor_without_policy_falls_back_to_global() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[policy.export]]
action = "deny"
prefix = "10.0.0.0/8"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
"#;
    let config = parse(toml_str).unwrap();
    assert!(config.neighbors[0].import_policy.is_empty());
    assert!(config.neighbors[0].export_policy.is_empty());

    let peers = config.to_peer_configs().unwrap();
    // Should inherit global export policy
    assert!(peers[0].2.is_none()); // no import (neither neighbor nor global)
    assert!(peers[0].3.is_some()); // export from global
}

#[test]
fn ipv6_neighbor_address_accepted() {
    let toml_str = valid_toml().replace("10.0.0.2", "2001:db8::1");
    let config = parse(&toml_str).unwrap();
    assert_eq!(config.neighbors[0].address, "2001:db8::1");
}

#[test]
fn ipv6_neighbor_default_families() {
    let toml_str = valid_toml().replace("10.0.0.2", "2001:db8::1");
    let config = parse(&toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();
    // IPv6 neighbor gets both IPv4 and IPv6 unicast by default
    assert_eq!(peers[0].0.peer.families.len(), 2);
    assert_eq!(peers[0].0.peer.families[0], (Afi::Ipv4, Safi::Unicast));
    assert_eq!(peers[0].0.peer.families[1], (Afi::Ipv6, Safi::Unicast));
}

#[test]
fn unknown_field_in_global_rejected() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
unknown_field = true

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::Parse(_)));
}

#[test]
fn unknown_field_in_neighbor_rejected() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_tme = 90
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::Parse(_)));
}

#[test]
fn per_neighbor_policy_overrides_global() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[policy.export]]
action = "deny"
prefix = "10.0.0.0/8"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002

[[neighbors.export_policy]]
action = "permit"
prefix = "10.0.0.0/8"

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
"#;
    let config = parse(toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();

    // First neighbor: has per-neighbor export → uses that
    let export1 = peers[0].3.as_ref().unwrap();
    assert_eq!(export1.policies[0].entries[0].action, PolicyAction::Permit);

    // Second neighbor: no per-neighbor → falls back to global deny
    let export2 = peers[1].3.as_ref().unwrap();
    assert_eq!(export2.policies[0].entries[0].action, PolicyAction::Deny);
}

#[test]
fn invalid_policy_action_rejected() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002

[[policy.import]]
action = "allow"
prefix = "10.0.0.0/8"
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidPolicyEntry { .. }));
}

#[test]
fn invalid_policy_prefix_rejected() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002

[[policy.export]]
action = "deny"
prefix = "not-a-prefix"
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidPolicyEntry { .. }));
}

#[test]
fn policy_prefix_length_over_32_rejected() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[policy.import]]
action = "deny"
prefix = "10.0.0.0/33"
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidPolicyEntry { .. }));
}

#[test]
fn policy_ge_over_32_rejected() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[policy.import]]
action = "deny"
prefix = "10.0.0.0/8"
ge = 33
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidPolicyEntry { .. }));
}

#[test]
fn policy_ge_less_than_prefix_len_rejected() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[policy.import]]
action = "deny"
prefix = "10.0.0.0/16"
ge = 8
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidPolicyEntry { .. }));
}

#[test]
fn policy_ge_exceeds_le_rejected() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[policy.import]]
action = "deny"
prefix = "10.0.0.0/8"
ge = 24
le = 16
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidPolicyEntry { .. }));
}

#[test]
fn policy_aspath_length_ge_exceeds_le_rejected() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[policy.import]]
action = "deny"
match_as_path_length_ge = 50
match_as_path_length_le = 10
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidPolicyEntry { .. }));
}

fn neighbor_with_nexthop(nexthop: &str) -> String {
    format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
local_ipv6_nexthop = "{nexthop}"
"#
    )
}

#[test]
fn local_ipv6_nexthop_loopback_rejected() {
    let err = parse(&neighbor_with_nexthop("::1")).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidLocalIpv6Nexthop { .. }));
}

#[test]
fn local_ipv6_nexthop_link_local_rejected() {
    let err = parse(&neighbor_with_nexthop("fe80::1")).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidLocalIpv6Nexthop { .. }));
}

#[test]
fn local_ipv6_nexthop_multicast_rejected() {
    let err = parse(&neighbor_with_nexthop("ff02::1")).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidLocalIpv6Nexthop { .. }));
}

#[test]
fn local_ipv6_nexthop_global_accepted() {
    let config = parse(&neighbor_with_nexthop("2001:db8::1")).unwrap();
    assert_eq!(
        config.neighbors[0].local_ipv6_nexthop.as_deref(),
        Some("2001:db8::1")
    );
}

fn gr_toml(gr_fields: &str) -> String {
    format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
{gr_fields}
"#
    )
}

#[test]
fn gr_restart_time_zero_with_gr_enabled_rejected() {
    let err = parse(&gr_toml("gr_restart_time = 0")).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidGrConfig { .. }));
}

#[test]
fn gr_restart_time_zero_with_gr_disabled_accepted() {
    let toml = gr_toml("graceful_restart = false\ngr_restart_time = 0");
    assert!(parse(&toml).is_ok());
}

#[test]
fn gr_stale_routes_time_exceeds_max_rejected() {
    let err = parse(&gr_toml("gr_stale_routes_time = 7200")).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidGrConfig { .. }));
}

#[test]
fn gr_stale_routes_time_at_max_accepted() {
    assert!(parse(&gr_toml("gr_stale_routes_time = 3600")).is_ok());
}

#[test]
fn duplicate_families_deduplicated() {
    let toml =
        gr_toml(r#"families = ["ipv4_unicast", "ipv4_unicast", "ipv6_unicast", "ipv6_unicast"]"#);
    let config = parse(&toml).unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert_eq!(peers[0].0.peer.families.len(), 2);
}

// --- Community match config tests ---

fn community_toml(policy_entries: &str) -> String {
    format!(
        r#"
[global]
asn = 65000
router_id = "1.2.3.4"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.1"
remote_asn = 65001

[[neighbors.import_policy]]
{policy_entries}
"#
    )
}

fn community_export_toml(policy_entries: &str) -> String {
    format!(
        r#"
[global]
asn = 65000
router_id = "1.2.3.4"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.1"
remote_asn = 65001

[[neighbors.export_policy]]
{policy_entries}
"#
    )
}

#[test]
fn community_only_entry_parses() {
    let toml = community_toml(
        r#"action = "deny"
            match_community = ["RT:65001:100"]"#,
    );
    let config = parse(&toml).unwrap();
    let peers = config.to_peer_configs().unwrap();
    let import = peers[0].2.as_ref().unwrap();
    assert_eq!(import.policies[0].entries.len(), 1);
    assert!(import.policies[0].entries[0].prefix.is_none());
    assert_eq!(import.policies[0].entries[0].match_community.len(), 1);
}

#[test]
fn prefix_and_community_parses() {
    let toml = community_toml(
        r#"prefix = "10.0.0.0/8"
            action = "deny"
            match_community = ["RT:65001:100", "RO:65002:200"]"#,
    );
    let config = parse(&toml).unwrap();
    let peers = config.to_peer_configs().unwrap();
    let import = peers[0].2.as_ref().unwrap();
    assert!(import.policies[0].entries[0].prefix.is_some());
    assert_eq!(import.policies[0].entries[0].match_community.len(), 2);
}

#[test]
fn ge_without_prefix_rejected() {
    let toml = community_toml(
        r#"action = "deny"
ge = 16
match_community = ["RT:65001:100"]"#,
    );
    assert!(parse(&toml).is_err());
}

#[test]
fn neither_prefix_nor_community_rejected() {
    let toml = community_toml(r#"action = "deny""#);
    assert!(parse(&toml).is_err());
}

#[test]
fn invalid_community_string_rejected() {
    let toml = community_toml(
        r#"action = "deny"
match_community = ["INVALID"]"#,
    );
    assert!(parse(&toml).is_err());
}

#[test]
fn ipv4_community_parses() {
    let toml = community_toml(
        r#"action = "deny"
            match_community = ["RT:192.0.2.1:100"]"#,
    );
    let config = parse(&toml).unwrap();
    let peers = config.to_peer_configs().unwrap();
    let import = peers[0].2.as_ref().unwrap();
    assert_eq!(import.policies[0].entries[0].match_community.len(), 1);
}

// --- Route Reflector config tests ---

#[test]
fn rr_client_on_ebgp_rejected() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
route_reflector_client = true
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidRrConfig { .. }));
}

#[test]
fn rr_client_on_ibgp_accepted() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65001
route_reflector_client = true
"#;
    let config = parse(toml_str).unwrap();
    assert_eq!(config.neighbors[0].route_reflector_client, Some(true));
}

#[test]
fn route_server_client_on_ebgp_accepted() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
route_server_client = true
"#;
    let config = parse(toml_str).unwrap();
    assert_eq!(config.neighbors[0].route_server_client, Some(true));
}

#[test]
fn route_server_client_on_ibgp_rejected() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65001
route_server_client = true
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidRouteServerConfig { .. }));
}

#[test]
fn route_server_client_defaults_to_false() {
    let config = parse(valid_toml()).unwrap();
    assert_eq!(config.neighbors[0].route_server_client, None);
}

#[test]
fn remove_private_as_on_ibgp_rejected() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65001
remove_private_as = "all"
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidRemovePrivateAs { .. }));
}

#[test]
fn remove_private_as_invalid_mode_rejected() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
remove_private_as = "bogus"
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidRemovePrivateAs { .. }));
}

#[test]
fn remove_private_as_valid_modes_accepted() {
    for mode in &["remove", "all", "replace"] {
        let toml_str = format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
remove_private_as = "{mode}"
"#,
        );
        let config = parse(&toml_str).unwrap();
        assert_eq!(
            config.neighbors[0].remove_private_as.as_deref(),
            Some(*mode)
        );
    }
}

#[test]
fn to_peer_configs_maps_remove_private_as() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
remove_private_as = "all"
"#;
    let config = parse(toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert_eq!(
        peers[0].0.remove_private_as,
        rustbgpd_transport::RemovePrivateAs::All
    );
}

#[test]
fn cluster_id_invalid_rejected() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
cluster_id = "not-an-ip"

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidRrConfig { .. }));
}

#[test]
fn cluster_id_defaults_to_router_id() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65001
route_reflector_client = true
"#;
    let config = parse(toml_str).unwrap();
    assert_eq!(config.cluster_id(), Some(Ipv4Addr::new(10, 0, 0, 1)));
}

#[test]
fn explicit_cluster_id_used() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
cluster_id = "10.0.0.99"

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65001
route_reflector_client = true
"#;
    let config = parse(toml_str).unwrap();
    assert_eq!(config.cluster_id(), Some(Ipv4Addr::new(10, 0, 0, 99)));
}

#[test]
fn no_rr_client_means_no_cluster_id() {
    let config = parse(valid_toml()).unwrap();
    assert_eq!(config.cluster_id(), None);
}

// --- AS_PATH regex config tests ---

#[test]
fn match_as_path_only_parses() {
    let toml = community_toml(
        r#"action = "permit"
            match_as_path = "^65100_""#,
    );
    let config = parse(&toml).unwrap();
    let peers = config.to_peer_configs().unwrap();
    let import = peers[0].2.as_ref().unwrap();
    assert_eq!(import.policies[0].entries.len(), 1);
    assert!(import.policies[0].entries[0].prefix.is_none());
    assert!(import.policies[0].entries[0].match_as_path.is_some());
}

#[test]
fn match_as_path_with_prefix_parses() {
    let toml = community_toml(
        r#"action = "deny"
            prefix = "10.0.0.0/8"
            match_as_path = "_65200_""#,
    );
    let config = parse(&toml).unwrap();
    let peers = config.to_peer_configs().unwrap();
    let import = peers[0].2.as_ref().unwrap();
    assert!(import.policies[0].entries[0].prefix.is_some());
    assert!(import.policies[0].entries[0].match_as_path.is_some());
}

#[test]
fn match_as_path_invalid_regex_rejected() {
    let toml = community_toml(
        r#"action = "deny"
            match_as_path = "[invalid""#,
    );
    assert!(parse(&toml).is_err());
}

#[test]
fn neither_prefix_nor_community_nor_aspath_rejected() {
    let toml = community_toml(r#"action = "deny""#);
    assert!(parse(&toml).is_err());
}

#[test]
fn set_community_rt_4byte_asn_rejected() {
    // build_rt_ec only supports 2-octet AS — 4-byte ASN should fail at config time.
    let toml = community_toml(
        r#"action = "permit"
            prefix = "10.0.0.0/8"
            set_community_add = ["RT:100000:100"]"#,
    );
    let err = parse(&toml).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidPolicyEntry { .. }));
}

#[test]
fn set_community_ro_4byte_asn_rejected() {
    let toml = community_toml(
        r#"action = "permit"
            prefix = "10.0.0.0/8"
            set_community_remove = ["RO:100000:200"]"#,
    );
    let err = parse(&toml).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidPolicyEntry { .. }));
}

#[test]
fn set_community_rt_2byte_asn_accepted() {
    let toml = community_toml(
        r#"action = "permit"
            prefix = "10.0.0.0/8"
            set_community_add = ["RT:65535:100"]"#,
    );
    assert!(parse(&toml).is_ok());
}

#[test]
fn add_path_config_receive_enabled() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002

[neighbors.add_path]
receive = true
"#;
    let config = parse(toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert!(peers[0].0.peer.add_path_receive);
}

#[test]
fn add_path_config_defaults_to_disabled() {
    let config = parse(valid_toml()).unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert!(!peers[0].0.peer.add_path_receive);
}

#[test]
fn add_path_config_send_enabled() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002

[neighbors.add_path]
send = true
send_max = 4
"#;
    let config = parse(toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert!(peers[0].0.peer.add_path_send);
    assert_eq!(peers[0].0.peer.add_path_send_max, 4);
}

#[test]
fn add_path_config_send_and_receive() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002

[neighbors.add_path]
receive = true
send = true
"#;
    let config = parse(toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert!(peers[0].0.peer.add_path_receive);
    assert!(peers[0].0.peer.add_path_send);
    // No send_max → defaults to 0 (unlimited at transport layer)
    assert_eq!(peers[0].0.peer.add_path_send_max, 0);
}

#[test]
fn add_path_config_send_defaults_to_disabled() {
    let config = parse(valid_toml()).unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert!(!peers[0].0.peer.add_path_send);
    assert_eq!(peers[0].0.peer.add_path_send_max, 0);
}

#[test]
fn to_peer_configs_maps_route_server_client() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
route_server_client = true
"#;
    let config = parse(toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert!(peers[0].0.route_server_client);
}

// --- RPKI config tests ---

#[test]
fn rpki_single_cache_server_parses() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[rpki]
[[rpki.cache_servers]]
address = "127.0.0.1:3323"
"#;
    let config = parse(toml_str).unwrap();
    let rpki = config.rpki.as_ref().unwrap();
    assert_eq!(rpki.cache_servers.len(), 1);
    assert_eq!(rpki.cache_servers[0].address, "127.0.0.1:3323");
    // Check defaults
    assert_eq!(rpki.cache_servers[0].refresh_interval, 3600);
    assert_eq!(rpki.cache_servers[0].retry_interval, 600);
    assert_eq!(rpki.cache_servers[0].expire_interval, 7200);
}

#[test]
fn rpki_multiple_cache_servers_parses() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[rpki]
[[rpki.cache_servers]]
address = "10.0.0.10:3323"
refresh_interval = 1800
retry_interval = 300
expire_interval = 3600

[[rpki.cache_servers]]
address = "10.0.0.11:8282"
"#;
    let config = parse(toml_str).unwrap();
    let rpki = config.rpki.as_ref().unwrap();
    assert_eq!(rpki.cache_servers.len(), 2);
    assert_eq!(rpki.cache_servers[0].refresh_interval, 1800);
    assert_eq!(rpki.cache_servers[0].retry_interval, 300);
    assert_eq!(rpki.cache_servers[0].expire_interval, 3600);
    // Second server uses defaults
    assert_eq!(rpki.cache_servers[1].refresh_interval, 3600);
}

#[test]
fn rpki_absent_means_none() {
    let config = parse(valid_toml()).unwrap();
    assert!(config.rpki.is_none());
}

#[test]
fn rpki_policy_match_rpki_validation_parses() {
    let toml = community_export_toml(
        r#"action = "deny"
            match_rpki_validation = "invalid""#,
    );
    let config = parse(&toml).unwrap();
    let peers = config.to_peer_configs().unwrap();
    let export = peers[0].3.as_ref().unwrap();
    assert_eq!(export.policies[0].entries.len(), 1);
    assert_eq!(
        export.policies[0].entries[0].match_rpki_validation,
        Some(rustbgpd_wire::RpkiValidation::Invalid)
    );
}

#[test]
fn rpki_policy_match_rpki_validation_valid() {
    let toml = community_export_toml(
        r#"action = "permit"
            match_rpki_validation = "valid""#,
    );
    let config = parse(&toml).unwrap();
    let peers = config.to_peer_configs().unwrap();
    let export = peers[0].3.as_ref().unwrap();
    assert_eq!(
        export.policies[0].entries[0].match_rpki_validation,
        Some(rustbgpd_wire::RpkiValidation::Valid)
    );
}

#[test]
fn rpki_policy_match_rpki_validation_not_found() {
    let toml = community_export_toml(
        r#"action = "permit"
            match_rpki_validation = "not_found""#,
    );
    let config = parse(&toml).unwrap();
    let peers = config.to_peer_configs().unwrap();
    let export = peers[0].3.as_ref().unwrap();
    assert_eq!(
        export.policies[0].entries[0].match_rpki_validation,
        Some(rustbgpd_wire::RpkiValidation::NotFound)
    );
}

#[test]
fn rpki_policy_match_rpki_validation_bad_value_rejected() {
    let toml = community_toml(
        r#"action = "deny"
            match_rpki_validation = "unknown_state""#,
    );
    assert!(parse(&toml).is_err());
}

#[test]
fn rpki_policy_match_rpki_validation_standalone() {
    // match_rpki_validation alone (without prefix/community/aspath) is valid in export policy
    let toml = community_export_toml(
        r#"action = "deny"
            match_rpki_validation = "invalid""#,
    );
    assert!(parse(&toml).is_ok());
}

#[test]
fn rpki_policy_match_rpki_validation_import_accepted() {
    let toml = community_toml(
        r#"action = "deny"
            match_rpki_validation = "invalid""#,
    );
    let config = parse(&toml).unwrap();
    let peers = config.to_peer_configs().unwrap();
    let import = peers[0].2.as_ref().unwrap();
    assert_eq!(
        import.policies[0].entries[0].match_rpki_validation,
        Some(rustbgpd_wire::RpkiValidation::Invalid)
    );
}

#[test]
fn aspa_policy_match_aspa_validation_import_accepted() {
    let toml = community_toml(
        r#"action = "deny"
            match_aspa_validation = "invalid""#,
    );
    let config = parse(&toml).unwrap();
    let peers = config.to_peer_configs().unwrap();
    let import = peers[0].2.as_ref().unwrap();
    assert_eq!(
        import.policies[0].entries[0].match_aspa_validation,
        Some(rustbgpd_wire::AspaValidation::Invalid)
    );
}

#[test]
fn aspa_policy_match_aspa_validation_export_parses() {
    let toml = community_export_toml(
        r#"action = "deny"
            match_aspa_validation = "invalid""#,
    );
    let config = parse(&toml).unwrap();
    let peers = config.to_peer_configs().unwrap();
    let export = peers[0].3.as_ref().unwrap();
    assert_eq!(
        export.policies[0].entries[0].match_aspa_validation,
        Some(rustbgpd_wire::AspaValidation::Invalid)
    );
}

fn rpki_toml(cache_fields: &str) -> String {
    format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[rpki]
[[rpki.cache_servers]]
address = "127.0.0.1:3323"
{cache_fields}
"#
    )
}

#[test]
fn rpki_zero_refresh_interval_rejected() {
    let err = parse(&rpki_toml("refresh_interval = 0")).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidRpkiConfig { .. }));
}

#[test]
fn rpki_zero_retry_interval_rejected() {
    let err = parse(&rpki_toml("retry_interval = 0")).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidRpkiConfig { .. }));
}

#[test]
fn rpki_zero_expire_interval_rejected() {
    let err = parse(&rpki_toml("expire_interval = 0")).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidRpkiConfig { .. }));
}

#[test]
fn rpki_expire_less_than_refresh_rejected() {
    let err = parse(&rpki_toml(
        "refresh_interval = 3600\nexpire_interval = 1800",
    ))
    .unwrap_err();
    assert!(matches!(err, ConfigError::InvalidRpkiConfig { .. }));
}

#[test]
fn rpki_expire_equals_refresh_accepted() {
    assert!(
        parse(&rpki_toml(
            "refresh_interval = 3600\nexpire_interval = 3600",
        ))
        .is_ok()
    );
}

#[test]
fn rpki_valid_custom_timers_accepted() {
    let config = parse(&rpki_toml(
        "refresh_interval = 1800\nretry_interval = 300\nexpire_interval = 3600",
    ))
    .unwrap();
    let rpki = config.rpki.as_ref().unwrap();
    assert_eq!(rpki.cache_servers[0].refresh_interval, 1800);
    assert_eq!(rpki.cache_servers[0].retry_interval, 300);
    assert_eq!(rpki.cache_servers[0].expire_interval, 3600);
}

// -----------------------------------------------------------------------
// BMP config validation
// -----------------------------------------------------------------------

fn bmp_toml(collector_fields: &str) -> String {
    format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[bmp]
[[bmp.collectors]]
address = "127.0.0.1:11019"
{collector_fields}
"#
    )
}

#[test]
fn bmp_valid_config_accepted() {
    let config = parse(&bmp_toml("")).unwrap();
    let bmp = config.bmp.as_ref().unwrap();
    assert_eq!(bmp.sys_name, "rustbgpd");
    assert_eq!(bmp.collectors.len(), 1);
    assert_eq!(bmp.collectors[0].reconnect_interval, 30);
}

#[test]
fn bmp_invalid_collector_address_rejected() {
    let err = parse(&bmp_toml("").replace("127.0.0.1:11019", "not-a-socket-addr")).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidBmpCollector { .. }));
}

#[test]
fn bmp_zero_reconnect_interval_rejected() {
    let err = parse(&bmp_toml("reconnect_interval = 0")).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidBmpCollector { .. }));
}

#[test]
fn bmp_custom_reconnect_interval_accepted() {
    let config = parse(&bmp_toml("reconnect_interval = 60")).unwrap();
    let bmp = config.bmp.as_ref().unwrap();
    assert_eq!(bmp.collectors[0].reconnect_interval, 60);
}

#[test]
fn bmp_empty_collectors_accepted() {
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[bmp]
"#;
    let config = parse(toml).unwrap();
    let bmp = config.bmp.as_ref().unwrap();
    assert!(bmp.collectors.is_empty());
}

#[test]
fn bmp_custom_sys_name_accepted() {
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[bmp]
sys_name = "my-router"
sys_descr = "production edge"
[[bmp.collectors]]
address = "127.0.0.1:11019"
"#;
    let config = parse(toml).unwrap();
    let bmp = config.bmp.as_ref().unwrap();
    assert_eq!(bmp.sys_name, "my-router");
    assert_eq!(bmp.sys_descr, "production edge");
}

#[test]
fn bmp_duplicate_collector_address_rejected() {
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[bmp]
[[bmp.collectors]]
address = "127.0.0.1:11019"
[[bmp.collectors]]
address = "127.0.0.1:11019"
"#;
    let err = parse(toml).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidBmpCollector { .. }));
}

// -----------------------------------------------------------------------
// Named policies + policy chaining
// -----------------------------------------------------------------------

fn named_policy_toml() -> String {
    format!(
        r#"
{GLOBAL_HEADER}

[policy.definitions.reject-bogons]
default_action = "deny"
[[policy.definitions.reject-bogons.statements]]
action = "permit"
prefix = "0.0.0.0/0"
ge = 8
le = 24

[policy.definitions.set-lp]
[[policy.definitions.set-lp.statements]]
action = "permit"
prefix = "10.0.0.0/8"
set_local_pref = 200

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
"#,
        GLOBAL_HEADER = valid_toml()
    )
}

#[test]
fn named_policy_parses() {
    let config = parse(&named_policy_toml()).unwrap();
    assert_eq!(config.policy.definitions.len(), 2);
    assert!(config.policy.definitions.contains_key("reject-bogons"));
    assert!(config.policy.definitions.contains_key("set-lp"));
}

#[test]
fn named_policy_default_deny() {
    let config = parse(&named_policy_toml()).unwrap();
    let def = &config.policy.definitions["reject-bogons"];
    assert_eq!(def.default_action, "deny");
    let policy = parse_named_policy(
        "reject-bogons",
        def,
        &config.policy.neighbor_sets,
        &config.peer_groups,
    )
    .unwrap();
    assert_eq!(policy.default_action, PolicyAction::Deny);
}

#[test]
fn empty_statements_deny_is_valid() {
    let toml_str = format!(
        r#"
{GLOBAL_HEADER}

[policy.definitions.deny-all]
default_action = "deny"

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
"#,
        GLOBAL_HEADER = valid_toml()
    );
    let config = parse(&toml_str).unwrap();
    let def = &config.policy.definitions["deny-all"];
    let policy = parse_named_policy(
        "deny-all",
        def,
        &config.policy.neighbor_sets,
        &config.peer_groups,
    )
    .unwrap();
    assert_eq!(policy.entries.len(), 0);
    assert_eq!(policy.default_action, PolicyAction::Deny);
}

#[test]
fn undefined_policy_in_chain_is_error() {
    let toml_str = format!(
        r#"
{GLOBAL_HEADER}

[policy]
import_chain = ["nonexistent"]

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
"#,
        GLOBAL_HEADER = valid_toml()
    );
    let err = parse(&toml_str).unwrap_err();
    assert!(err.to_string().contains("nonexistent"));
}

#[test]
fn global_import_chain_works() {
    let toml_str = format!(
        r#"
{GLOBAL_HEADER}

[policy.definitions.set-lp]
[[policy.definitions.set-lp.statements]]
action = "permit"
prefix = "10.0.0.0/8"
set_local_pref = 200

[policy]
import_chain = ["set-lp"]

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
"#,
        GLOBAL_HEADER = valid_toml()
    );
    let config = parse(&toml_str).unwrap();
    let chain = config.import_chain().unwrap().unwrap();
    assert_eq!(chain.policies.len(), 1);
    assert_eq!(chain.policies[0].entries.len(), 1);
}

#[test]
fn neighbor_import_chain_overrides_global() {
    let toml_str = format!(
        r#"
{GLOBAL_HEADER}

[policy.definitions.global-pol]
[[policy.definitions.global-pol.statements]]
action = "deny"
prefix = "10.0.0.0/8"

[policy.definitions.peer-pol]
[[policy.definitions.peer-pol.statements]]
action = "permit"
prefix = "192.168.0.0/16"
set_local_pref = 300

[policy]
import_chain = ["global-pol"]

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
import_policy_chain = ["peer-pol"]
"#,
        GLOBAL_HEADER = valid_toml()
    );
    let config = parse(&toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();
    let (_, _, import, _) = &peers[1]; // skip the first neighbor from valid_toml
    let chain = import.as_ref().unwrap();
    // Peer chain should have peer-pol, not global-pol
    assert_eq!(
        chain.policies[0].entries[0].modifications.set_local_pref,
        Some(300)
    );
}

#[test]
fn inline_and_chain_mutually_exclusive() {
    let toml_str = format!(
        r#"
{GLOBAL_HEADER}

[policy.definitions.some-pol]
[[policy.definitions.some-pol.statements]]
action = "permit"
prefix = "10.0.0.0/8"

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
import_policy_chain = ["some-pol"]

[[neighbors.import_policy]]
action = "deny"
prefix = "192.168.0.0/16"
"#,
        GLOBAL_HEADER = valid_toml()
    );
    let err = parse(&toml_str).unwrap_err();
    assert!(err.to_string().contains("mutually exclusive"));
}

#[test]
fn inline_policy_still_works() {
    let toml_str = format!(
        r#"
{GLOBAL_HEADER}

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003

[[neighbors.import_policy]]
action = "deny"
prefix = "192.168.0.0/16"
"#,
        GLOBAL_HEADER = valid_toml()
    );
    let config = parse(&toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();
    let (_, _, import, _) = &peers[1];
    let chain = import.as_ref().unwrap();
    assert_eq!(chain.policies.len(), 1);
    assert_eq!(chain.policies[0].entries[0].action, PolicyAction::Deny);
}

#[test]
fn no_policy_falls_back_to_global_chain() {
    let toml_str = format!(
        r#"
{GLOBAL_HEADER}

[policy.definitions.global-pol]
[[policy.definitions.global-pol.statements]]
action = "permit"
prefix = "10.0.0.0/8"
set_local_pref = 150

[policy]
import_chain = ["global-pol"]

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
"#,
        GLOBAL_HEADER = valid_toml()
    );
    let config = parse(&toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();
    // Second neighbor (first is from valid_toml) has no per-peer policy
    let (_, _, import, _) = &peers[1];
    let chain = import.as_ref().unwrap();
    assert_eq!(
        chain.policies[0].entries[0].modifications.set_local_pref,
        Some(150)
    );
}

#[test]
fn peer_group_inheritance_applies_to_resolved_neighbor() {
    let toml_str = format!(
        r#"
{GLOBAL_HEADER}

[peer_groups.rs-clients]
hold_time = 30
families = ["ipv4_unicast", "ipv6_unicast"]
route_server_client = true

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "rs-clients"
"#,
        GLOBAL_HEADER = valid_toml()
    );
    let config = parse(&toml_str).unwrap();
    let resolved = config.resolve_neighbor(&config.neighbors[1]).unwrap();
    assert_eq!(resolved.transport_config.peer.hold_time, 30);
    assert_eq!(
        resolved.transport_config.peer.families,
        vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)]
    );
    assert!(resolved.transport_config.route_server_client);
    assert_eq!(resolved.peer_group.as_deref(), Some("rs-clients"));
}

#[test]
fn neighbor_values_override_peer_group_defaults() {
    let toml_str = format!(
        r#"
{GLOBAL_HEADER}

[peer_groups.transit]
hold_time = 30

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "transit"
hold_time = 45
"#,
        GLOBAL_HEADER = valid_toml()
    );
    let config = parse(&toml_str).unwrap();
    let resolved = config.resolve_neighbor(&config.neighbors[1]).unwrap();
    assert_eq!(resolved.transport_config.peer.hold_time, 45);
}

#[test]
fn neighbor_set_and_route_shape_policy_fields_parse() {
    let toml_str = format!(
        r#"
{GLOBAL_HEADER}

[peer_groups.rs-clients]
hold_time = 90

[policy.neighbor_sets.ixp]
addresses = ["10.0.0.3"]
remote_asns = [65003]
peer_groups = ["rs-clients"]

[policy.definitions.prefer-external]
[[policy.definitions.prefer-external.statements]]
action = "permit"
match_neighbor_set = "ixp"
match_route_type = "external"
match_next_hop = "10.0.0.3"
match_local_pref_ge = 200
match_med_le = 50
set_local_pref = 250

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "rs-clients"
"#,
        GLOBAL_HEADER = valid_toml()
    );
    let config = parse(&toml_str).unwrap();
    let def = &config.policy.definitions["prefer-external"];
    let policy = parse_named_policy(
        "prefer-external",
        def,
        &config.policy.neighbor_sets,
        &config.peer_groups,
    )
    .unwrap();
    let statement = &policy.entries[0];
    assert!(statement.match_neighbor_set.is_some());
    assert_eq!(statement.match_route_type, Some(RouteType::External));
    assert_eq!(statement.match_next_hop, Some("10.0.0.3".parse().unwrap()));
    assert_eq!(statement.match_local_pref_ge, Some(200));
    assert_eq!(statement.match_med_le, Some(50));
    assert_eq!(statement.modifications.set_local_pref, Some(250));
}

#[test]
fn match_next_hop_invalid_rejected() {
    let toml_str = format!(
        r#"
{GLOBAL_HEADER}

[policy.definitions.bad]
[[policy.definitions.bad.statements]]
action = "permit"
match_next_hop = "not-an-ip"
set_local_pref = 200

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
"#,
        GLOBAL_HEADER = valid_toml()
    );

    let err = parse(&toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidPolicyEntry { .. }));
    assert!(err.to_string().contains("invalid match_next_hop"));
}

#[test]
fn undefined_peer_group_reference_is_rejected() {
    let toml_str = format!(
        r#"
{GLOBAL_HEADER}

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "missing"
"#,
        GLOBAL_HEADER = valid_toml()
    );
    let err = parse(&toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::UndefinedPeerGroup { .. }));
}

fn test_neighbor(addr: &str, asn: u32) -> Neighbor {
    Neighbor {
        address: addr.to_string(),
        remote_asn: asn,
        description: None,
        peer_group: None,
        hold_time: None,
        max_prefixes: None,
        md5_password: None,
        ttl_security: Some(false),
        families: Vec::new(),
        graceful_restart: None,
        gr_restart_time: None,
        gr_stale_routes_time: None,
        llgr_stale_time: None,
        local_ipv6_nexthop: None,
        route_reflector_client: Some(false),
        route_server_client: Some(false),
        remove_private_as: None,
        add_path: None,
        import_policy: Vec::new(),
        export_policy: Vec::new(),
        import_policy_chain: Vec::new(),
        export_policy_chain: Vec::new(),
        log_level: None,
    }
}

#[test]
fn diff_neighbors_detects_added() {
    let old = vec![test_neighbor("10.0.0.1", 65001)];
    let new = vec![
        test_neighbor("10.0.0.1", 65001),
        test_neighbor("10.0.0.2", 65002),
    ];
    let diff = super::diff_neighbors(&old, &new);
    assert!(diff.removed.is_empty());
    assert!(diff.changed.is_empty());
    assert_eq!(diff.added.len(), 1);
    assert_eq!(diff.added[0].address, "10.0.0.2");
}

#[test]
fn diff_neighbors_detects_removed() {
    let old = vec![
        test_neighbor("10.0.0.1", 65001),
        test_neighbor("10.0.0.2", 65002),
    ];
    let new = vec![test_neighbor("10.0.0.1", 65001)];
    let diff = super::diff_neighbors(&old, &new);
    assert!(diff.added.is_empty());
    assert!(diff.changed.is_empty());
    assert_eq!(diff.removed.len(), 1);
    assert_eq!(diff.removed[0], "10.0.0.2".parse::<IpAddr>().unwrap());
}

#[test]
fn diff_neighbors_detects_changed() {
    let old = vec![test_neighbor("10.0.0.1", 65001)];
    let new = vec![test_neighbor("10.0.0.1", 65099)];
    let diff = super::diff_neighbors(&old, &new);
    assert!(diff.added.is_empty());
    assert!(diff.removed.is_empty());
    assert_eq!(diff.changed.len(), 1);
    assert_eq!(diff.changed[0].remote_asn, 65099);
}

#[test]
fn diff_neighbors_no_changes() {
    let peers = vec![
        test_neighbor("10.0.0.1", 65001),
        test_neighbor("10.0.0.2", 65002),
    ];
    let diff = super::diff_neighbors(&peers, &peers);
    assert!(diff.added.is_empty());
    assert!(diff.removed.is_empty());
    assert!(diff.changed.is_empty());
}

#[test]
fn describe_neighbor_changes_detects_field_diffs() {
    let old = test_neighbor("10.0.0.1", 65001);
    let mut new = old.clone();
    new.remote_asn = 65099;
    new.hold_time = Some(45);
    new.families = vec!["ipv4_unicast".into(), "ipv6_unicast".into()];

    let changes = super::describe_neighbor_changes(&old, &new);
    assert_eq!(changes.len(), 3);
    assert!(changes[0].contains("remote_asn"));
    assert!(changes[1].contains("hold_time"));
    assert!(changes[2].contains("families"));
}

#[test]
fn describe_neighbor_changes_empty_when_equal() {
    let n = test_neighbor("10.0.0.1", 65001);
    let changes = super::describe_neighbor_changes(&n, &n);
    assert!(changes.is_empty());
}

#[test]
fn describe_neighbor_changes_hides_md5_value() {
    let old = test_neighbor("10.0.0.1", 65001);
    let mut new = old.clone();
    new.md5_password = Some("secret".into());

    let changes = super::describe_neighbor_changes(&old, &new);
    assert_eq!(changes.len(), 1);
    assert!(changes[0].contains("<changed>"));
    assert!(!changes[0].contains("secret"));
}

#[test]
fn config_round_trips_through_toml() {
    let config = parse(valid_toml()).unwrap();
    let toml_str = toml::to_string_pretty(&config).unwrap();
    let reloaded: Config = toml::from_str(&toml_str).unwrap();
    assert_eq!(config, reloaded);
}

// ── Config diff tests ────────────────────────────────────────────────

#[test]
fn diff_config_identical_has_no_changes() {
    let config = parse(valid_toml()).unwrap();
    let diff = super::diff_config(&config, &config);
    assert!(!diff.has_any_changes());
}

#[test]
fn diff_config_neighbor_added() {
    let old = parse(valid_toml()).unwrap();
    let new_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
description = "peer-1"
hold_time = 90

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
"#;
    let new = parse(new_toml).unwrap();
    let diff = super::diff_config(&old, &new);
    assert!(diff.has_any_changes());
    assert_eq!(diff.neighbors.added.len(), 1);
    assert_eq!(diff.neighbors.added[0].address, "10.0.0.3");
    assert_eq!(diff.neighbors.added[0].remote_asn, 65003);
    assert!(diff.neighbors.removed.is_empty());
    assert!(diff.neighbors.changed.is_empty());
}

#[test]
fn diff_config_neighbor_removed() {
    let old = parse(valid_toml()).unwrap();
    let new_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
"#;
    let new = parse(new_toml).unwrap();
    let diff = super::diff_config(&old, &new);
    assert!(diff.has_any_changes());
    assert_eq!(diff.neighbors.removed.len(), 1);
    assert_eq!(diff.neighbors.removed[0], "10.0.0.2");
}

#[test]
fn diff_config_neighbor_changed() {
    let old = parse(valid_toml()).unwrap();
    let new_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
description = "peer-1"
hold_time = 45
"#;
    let new = parse(new_toml).unwrap();
    let diff = super::diff_config(&old, &new);
    assert!(diff.has_any_changes());
    assert_eq!(diff.neighbors.changed.len(), 1);
    assert_eq!(diff.neighbors.changed[0].address, "10.0.0.2");
    assert!(
        diff.neighbors.changed[0]
            .changes
            .iter()
            .any(|c| c.contains("hold_time"))
    );
}

#[test]
fn diff_config_global_change_flags_restart() {
    let old = parse(valid_toml()).unwrap();
    let new_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.99"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
description = "peer-1"
hold_time = 90
"#;
    let new = parse(new_toml).unwrap();
    let diff = super::diff_config(&old, &new);
    assert!(diff.has_any_changes());
    assert!(diff.global_changed);
    assert!(!diff.rpki_changed);
}

#[test]
fn diff_config_honor_graceful_shutdown_only_is_reload_applied_not_restart_required() {
    let old = parse(valid_toml()).unwrap();
    let new_toml = valid_toml().replace(
        "listen_port = 179\n",
        "listen_port = 179\nhonor_graceful_shutdown = true\n",
    );
    let new = parse(&new_toml).unwrap();
    let diff = super::diff_config(&old, &new);

    assert!(
        !diff.global_changed,
        "hot-applied honor_graceful_shutdown must not set the coarse restart bucket"
    );
    assert!(diff.honor_graceful_shutdown_changed);
    assert!(!diff.has_restart_required_changes());
    assert!(diff.has_reload_applied_changes());
}

#[test]
fn diff_config_honor_blackhole_only_is_reload_applied_not_restart_required() {
    let old = parse(valid_toml()).unwrap();
    let new_toml = valid_toml().replace(
        "listen_port = 179\n",
        "listen_port = 179\nhonor_blackhole = true\n",
    );
    let new = parse(&new_toml).unwrap();
    let diff = super::diff_config(&old, &new);

    assert!(
        !diff.global_changed,
        "hot-applied honor_blackhole must not set the coarse restart bucket"
    );
    assert!(!diff.blackhole_fib_discard_changed);
    assert!(diff.honor_blackhole_changed);
    assert!(!diff.has_restart_required_changes());
    assert!(diff.has_reload_applied_changes());
}

#[test]
fn diff_config_peer_group_added() {
    let old = parse(valid_toml()).unwrap();
    let new_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
description = "peer-1"
hold_time = 90

[peer_groups.upstream]
hold_time = 30
"#;
    let new = parse(new_toml).unwrap();
    let diff = super::diff_config(&old, &new);
    assert!(diff.has_any_changes());
    assert_eq!(diff.peer_groups.added, vec!["upstream"]);
}

#[test]
fn diff_config_policy_definition_added() {
    let old = parse(valid_toml()).unwrap();
    let new_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
description = "peer-1"
hold_time = 90

[policy.definitions.reject-bogons]
default_action = "permit"

[[policy.definitions.reject-bogons.statements]]
action = "deny"
prefix = "0.0.0.0/0"
"#;
    let new = parse(new_toml).unwrap();
    let diff = super::diff_config(&old, &new);
    assert!(diff.has_any_changes());
    assert_eq!(diff.policy.definitions_added, vec!["reject-bogons"]);
}

#[test]
fn diff_config_json_serializes() {
    let old = parse(valid_toml()).unwrap();
    let diff = super::diff_config(&old, &old);
    let json = serde_json::to_string(&diff).unwrap();
    assert!(json.contains("\"global_changed\":false"));
    // EVPN-instance drift must appear in the serialized diff so JSON
    // consumers (CI guards, dashboards) can act on it.
    assert!(
        json.contains("\"evpn_instances_changed\":false"),
        "expected evpn_instances_changed in serialized diff: {json}"
    );
    assert!(
        json.contains("\"honor_graceful_shutdown_changed\":false"),
        "expected honor_graceful_shutdown_changed in serialized diff: {json}"
    );
    assert!(
        json.contains("\"honor_blackhole_changed\":false"),
        "expected honor_blackhole_changed in serialized diff: {json}"
    );
    assert!(
        json.contains("\"evpn_ip_vrfs_changed\":false"),
        "expected evpn_ip_vrfs_changed in serialized diff: {json}"
    );
    assert!(
        json.contains("\"ethernet_segments_changed\":false"),
        "expected ethernet_segments_changed in serialized diff: {json}"
    );
    assert!(
        json.contains("\"fib_tables_changed\":false"),
        "expected fib_tables_changed in serialized diff: {json}"
    );
    assert!(
        json.contains("\"apply_bum_enforcement_changed\":false"),
        "expected apply_bum_enforcement_changed in serialized diff: {json}"
    );
    assert!(
        json.contains("\"blackhole_fib_discard_changed\":false"),
        "expected blackhole_fib_discard_changed in serialized diff: {json}"
    );
}

#[test]
fn diff_peer_group_changes_detects_field_diffs() {
    let old = PeerGroupConfig {
        hold_time: Some(90),
        ..Default::default()
    };
    let new = PeerGroupConfig {
        hold_time: Some(45),
        ..Default::default()
    };
    let changes = super::describe_peer_group_changes(&old, &new);
    assert_eq!(changes.len(), 1);
    assert!(changes[0].contains("hold_time"));
    assert!(changes[0].contains("90"));
    assert!(changes[0].contains("45"));
}

/// Policy-only edits are now reload-applied (per-named definitions
/// flow through `apply_policy_change` on SIGHUP). Only the inline
/// `policy.import` / `policy.export` statements remain
/// restart-required.
#[test]
fn diff_config_named_policy_only_is_reload_applied() {
    let old = parse(valid_toml()).unwrap();
    let new_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
description = "peer-1"
hold_time = 90

[policy.definitions.new-policy]
default_action = "deny"
"#;
    let new = parse(new_toml).unwrap();
    let diff = super::diff_config(&old, &new);
    assert!(diff.has_any_changes());
    assert!(
        diff.has_reload_applied_changes(),
        "named policy add must be reload-applied"
    );
    assert!(
        !diff.has_informational_changes(),
        "named policy edits no longer fall in the informational bucket"
    );
}

// ── Dynamic neighbor config tests ───────────────────────────────

#[test]
fn dynamic_neighbor_parses() {
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.ix-members]
hold_time = 90

[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "ix-members"
remote_asn = 0
description = "IXP auto-accept"
"#;
    let config = parse(toml).unwrap();
    assert_eq!(config.dynamic_neighbors.len(), 1);
    assert_eq!(config.dynamic_neighbors[0].prefix, "10.0.0.0/24");
    assert_eq!(config.dynamic_neighbors[0].peer_group, "ix-members");
    assert_eq!(config.dynamic_neighbors[0].remote_asn, 0);
}

#[test]
fn dynamic_neighbor_invalid_prefix_rejected() {
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.ix-members]
hold_time = 90

[[dynamic_neighbors]]
prefix = "not-a-prefix"
peer_group = "ix-members"
"#;
    let err = parse(toml).unwrap_err();
    assert!(err.to_string().contains("invalid prefix"));
}

#[test]
fn dynamic_neighbor_ipv4_prefix_too_long_rejected() {
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.ix-members]
hold_time = 90

[[dynamic_neighbors]]
prefix = "10.0.0.0/40"
peer_group = "ix-members"
"#;
    let err = parse(toml).unwrap_err();
    assert!(err.to_string().contains("IPv4 prefix length"));
}

#[test]
fn dynamic_neighbor_ipv6_prefix_too_long_rejected() {
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.ix-v6]
hold_time = 90

[[dynamic_neighbors]]
prefix = "2001:db8::/129"
peer_group = "ix-v6"
"#;
    let err = parse(toml).unwrap_err();
    assert!(err.to_string().contains("IPv6 prefix length"));
}

#[test]
fn dynamic_neighbor_missing_peer_group_rejected() {
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "nonexistent"
"#;
    let err = parse(toml).unwrap_err();
    assert!(err.to_string().contains("not defined"));
}

#[test]
fn static_neighbor_remote_asn_zero_rejected() {
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 0
"#;
    let err = parse(toml).unwrap_err();
    assert!(err.to_string().contains("remote_asn"));
}

#[test]
fn dynamic_neighbor_limit_zero_rejected() {
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
dynamic_neighbor_limit = 0
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
"#;
    let err = parse(toml).unwrap_err();
    assert!(err.to_string().contains("dynamic_neighbor_limit"));
}

#[test]
fn dynamic_neighbor_limit_valid_accepted() {
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
dynamic_neighbor_limit = 500
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
"#;
    let config = parse(toml).unwrap();
    assert_eq!(config.global.dynamic_neighbor_limit, Some(500));
}

#[test]
fn dynamic_neighbor_ipv6_prefix_parses() {
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.ix-v6]
hold_time = 90

[[dynamic_neighbors]]
prefix = "2001:db8::/32"
peer_group = "ix-v6"
"#;
    let config = parse(toml).unwrap();
    assert_eq!(config.dynamic_neighbors[0].prefix, "2001:db8::/32");
}

// ---------------------------------------------------------------------------
// EVPN VTEP foundation — `[[evpn_instances]]` schema, parse, and validation.
//
// These tests pin the operator-facing TOML surface for local EVPN
// instances and the runtime resolution into `EvpnInstanceTable`. They
// cover all six rules from the foundation brief: VNI range, RD parse,
// non-empty RT list, unicast VTEP IP, duplicate VNI, duplicate RD —
// plus the `Display` shape used by future CLI list output.
// ---------------------------------------------------------------------------

fn evpn_toml_with(extra: &str) -> String {
    format!(
        r#"
[global]
asn = 65000
router_id = "10.0.0.100"
listen_port = 179

[global.telemetry]
prometheus_addr = "127.0.0.1:9179"
log_format = "json"
{extra}
"#
    )
}

#[test]
fn evpn_instances_default_empty() {
    // No `[[evpn_instances]]` block ⇒ empty list, valid config (RR mode).
    let config = parse(valid_toml()).unwrap();
    assert!(config.evpn_instances.is_empty());
    assert_eq!(config.resolve_evpn_instances().unwrap().len(), 0);
}

#[test]
fn evpn_instance_minimal_parses() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
"#,
    );
    let config = parse(&toml).unwrap();
    assert_eq!(config.evpn_instances.len(), 1);
    let table = config.resolve_evpn_instances().unwrap();
    assert_eq!(table.len(), 1);
    let inst = table.sorted()[0];
    assert_eq!(inst.id.as_u32(), 100);
    assert_eq!(inst.route_targets.len(), 1);
    assert!(!inst.advertise_svi_mac);
    assert!(inst.bridge.is_none());
}

#[test]
fn evpn_instance_full_parses() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 200
rd = "10.0.0.100:200"
route_targets = ["65000:200", "65000:100"]
local_vtep_ip = "10.0.0.100"
bridge = "br200"
advertise_svi_mac = true
"#,
    );
    let config = parse(&toml).unwrap();
    let table = config.resolve_evpn_instances().unwrap();
    let inst = table.sorted()[0];
    assert_eq!(inst.id.as_u32(), 200);
    assert_eq!(inst.bridge.as_deref(), Some("br200"));
    assert!(inst.advertise_svi_mac);
    // RTs are sorted/deduped on construction.
    assert_eq!(inst.route_targets.len(), 2);
}

#[test]
fn evpn_instance_rejects_unknown_field() {
    // `deny_unknown_fields` — typos must surface, not silently drop.
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
oops_typo = true
"#,
    );
    let err = parse(&toml).unwrap_err();
    assert!(
        matches!(err, ConfigError::Parse(_)),
        "expected toml parse error, got {err}"
    );
}

#[test]
fn evpn_instance_rejects_zero_vni() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 0
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::InvalidEvpnInstance { .. }),
        "expected InvalidEvpnInstance, got {msg}",
    );
    assert!(msg.contains("VNI 0"), "msg must explain why: {msg}");
}

#[test]
fn evpn_instance_rejects_overflow_vni() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 16777216
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
"#,
    );
    let err = parse(&toml).unwrap_err();
    assert!(
        matches!(err, ConfigError::InvalidEvpnInstance { .. }),
        "got {err}"
    );
    assert!(err.to_string().contains("24-bit"));
}

#[test]
fn evpn_instance_accepts_max_vni() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 16777215
rd = "10.0.0.100:1"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
"#,
    );
    parse(&toml).unwrap();
}

#[test]
fn evpn_instance_rejects_invalid_rd() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "not-a-real-rd"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
"#,
    );
    let err = parse(&toml).unwrap_err();
    assert!(
        matches!(err, ConfigError::InvalidEvpnInstance { .. }),
        "got {err}"
    );
    assert!(err.to_string().contains("rd"));
}

#[test]
fn evpn_instance_rejects_empty_route_targets() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = []
local_vtep_ip = "10.0.0.100"
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::InvalidEvpnInstance { .. }),
        "got {msg}"
    );
    assert!(msg.contains("route_targets"));
}

#[test]
fn evpn_instance_rejects_invalid_route_target() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["not-an-rt"]
local_vtep_ip = "10.0.0.100"
"#,
    );
    let err = parse(&toml).unwrap_err();
    assert!(
        matches!(err, ConfigError::InvalidEvpnInstance { .. }),
        "got {err}"
    );
    assert!(err.to_string().contains("route_target"));
}

#[test]
fn evpn_instance_rejects_non_unicast_vtep_ip() {
    for bad in ["0.0.0.0", "127.0.0.1", "224.0.0.1", "::", "::1"] {
        let toml = evpn_toml_with(&format!(
            r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "{bad}"
"#
        ));
        let err = parse(&toml).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidEvpnInstance { .. }),
            "expected InvalidEvpnInstance for {bad}, got {err}",
        );
    }
}

#[test]
fn evpn_instance_rejects_unparseable_vtep_ip() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "not-an-ip"
"#,
    );
    let err = parse(&toml).unwrap_err();
    assert!(
        matches!(err, ConfigError::InvalidEvpnInstance { .. }),
        "got {err}"
    );
    assert!(err.to_string().contains("local_vtep_ip"));
}

#[test]
fn evpn_instance_rejects_empty_bridge() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
bridge = "   "
"#,
    );
    let err = parse(&toml).unwrap_err();
    assert!(
        matches!(err, ConfigError::InvalidEvpnInstance { .. }),
        "got {err}"
    );
    assert!(err.to_string().contains("bridge"));
}

#[test]
fn evpn_instance_rejects_duplicate_vni() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[evpn_instances]]
vni = 100
rd = "10.0.0.100:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.100"
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::InvalidEvpnInstance { .. }),
        "got {msg}"
    );
    assert!(msg.contains("duplicate VNI"), "msg: {msg}");
}

#[test]
fn evpn_instance_rejects_duplicate_rd() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[evpn_instances]]
vni = 200
rd = "10.0.0.100:100"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.100"
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::InvalidEvpnInstance { .. }),
        "got {msg}"
    );
    assert!(msg.contains("duplicate route distinguisher"), "msg: {msg}");
}

#[test]
fn evpn_instances_resolve_in_declaration_order_for_first_error() {
    // First entry is fine; second has a bad RT. The error should
    // identify the second entry, not the first.
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[evpn_instances]]
vni = 200
rd = "10.0.0.100:200"
route_targets = ["bad-rt"]
local_vtep_ip = "10.0.0.100"
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("vni 200"), "msg: {msg}");
}

#[test]
fn evpn_instance_multiple_distinct_instances_resolve_cleanly() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[evpn_instances]]
vni = 200
rd = "10.0.0.100:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.100"

[[evpn_instances]]
vni = 300
rd = "10.0.0.100:300"
route_targets = ["65000:300", "65000:301"]
local_vtep_ip = "10.0.0.100"
bridge = "br300"
advertise_svi_mac = true
"#,
    );
    let config = parse(&toml).unwrap();
    let table = config.resolve_evpn_instances().unwrap();
    assert_eq!(table.len(), 3);
    let sorted: Vec<u32> = table.sorted().iter().map(|i| i.id.as_u32()).collect();
    assert_eq!(sorted, vec![100, 200, 300]);

    // Spot-check display shape on the most-loaded entry.
    let inst300 = table.get(EvpnInstanceId::new(300).unwrap()).unwrap();
    let s = inst300.to_string();
    assert!(
        s.contains("vni=300")
            && s.contains("rd=10.0.0.100:300")
            && s.contains("bridge=br300")
            && s.contains("advertise-svi-mac"),
        "display surface broke: {s}",
    );
}

#[test]
fn evpn_instance_diff_flags_changes_as_restart_required() {
    let with_evi = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
"#,
    ))
    .unwrap();
    let without_evi = parse(valid_toml()).unwrap();

    // Add: empty → one EVI ⇒ restart-required.
    let added = diff_config(&without_evi, &with_evi);
    assert!(added.evpn_instances_changed);
    assert!(added.has_restart_required_changes());

    // Remove: one EVI → empty ⇒ restart-required.
    let removed = diff_config(&with_evi, &without_evi);
    assert!(removed.evpn_instances_changed);
    assert!(removed.has_restart_required_changes());

    // No-op: same config on both sides ⇒ not flagged.
    let same = diff_config(&with_evi, &with_evi);
    assert!(!same.evpn_instances_changed);
}

// -----------------------------------------------------------------------
// RFC 8326 — honor_graceful_shutdown implicit chain-tail import rule
// -----------------------------------------------------------------------

fn gshut_toml(honor: bool, peer_asn: u32) -> String {
    format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
honor_graceful_shutdown = {honor}

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = {peer_asn}
hold_time = 90
"#
    )
}

#[test]
fn effective_chain_appends_gshut_when_honor_enabled_for_ebgp() {
    let cfg = parse(&gshut_toml(true, 65002)).unwrap();
    let neighbor = &cfg.neighbors[0];
    let (import, _export) = cfg.effective_policy_chains_for_neighbor(neighbor).unwrap();
    let chain = import.expect("EBGP + honor enabled must yield an import chain");
    assert!(
        !chain.policies.is_empty(),
        "implicit GShut policy must be present"
    );
    let last = chain.policies.last().expect("chain not empty");
    let stmt = &last.entries[0];
    assert_eq!(
        stmt.match_community,
        vec![rustbgpd_policy::CommunityMatch::Standard {
            value: rustbgpd_wire::COMMUNITY_GRACEFUL_SHUTDOWN,
        }],
        "tail statement must match GRACEFUL_SHUTDOWN"
    );
    assert_eq!(
        stmt.modifications.set_local_pref,
        Some(0),
        "RFC 8326 §4 receiver MUST set local_pref to a low value"
    );
}

#[test]
fn effective_chain_does_not_append_gshut_for_ibgp() {
    // remote_asn == local asn (65001) → iBGP, exempt per RFC 8326 §4.
    let cfg = parse(&gshut_toml(true, 65001)).unwrap();
    let neighbor = &cfg.neighbors[0];
    let (import, _export) = cfg.effective_policy_chains_for_neighbor(neighbor).unwrap();
    assert!(
        import.is_none(),
        "iBGP must not get the implicit GShut rule (LOCAL_PREF preserved within an AS)"
    );
}

#[test]
fn effective_chain_does_not_append_gshut_when_honor_disabled() {
    let cfg = parse(&gshut_toml(false, 65002)).unwrap();
    let neighbor = &cfg.neighbors[0];
    let (import, _export) = cfg.effective_policy_chains_for_neighbor(neighbor).unwrap();
    assert!(
        import.is_none(),
        "honor_graceful_shutdown = false must leave the chain untouched"
    );
}

#[test]
fn effective_chain_gshut_runs_after_operator_chain() {
    // Implicit GShut rule must sit at the END of the chain so its
    // set_local_pref=0 wins over an operator policy that also sets
    // local_pref. PolicyChain::evaluate accumulates with last-writer-
    // wins on scalar fields; running first would let the operator's
    // value silently overwrite the GShut demotion.
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
honor_graceful_shutdown = true

[global.telemetry]
log_format = "json"

[policy.definitions.deny-everything]
default_action = "deny"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
import_policy_chain = ["deny-everything"]
"#;
    let cfg = parse(toml).unwrap();
    let neighbor = &cfg.neighbors[0];
    let (import, _export) = cfg.effective_policy_chains_for_neighbor(neighbor).unwrap();
    let chain = import.expect("EBGP + honor enabled must yield an import chain");
    assert!(
        chain.policies.len() >= 2,
        "chain must contain operator's deny-everything + implicit GShut policy"
    );
    let last = chain.policies.last().expect("chain not empty");
    let stmt = &last.entries[0];
    assert_eq!(
        stmt.match_community,
        vec![rustbgpd_policy::CommunityMatch::Standard {
            value: rustbgpd_wire::COMMUNITY_GRACEFUL_SHUTDOWN,
        }],
        "implicit GShut policy must be at chain tail (last index), AFTER operator policies"
    );
}

#[test]
fn gshut_demotion_wins_over_operator_local_pref() {
    // Headline RFC 8326 §4 invariant: when both an operator policy
    // and the implicit GShut rule set local_pref on the same route,
    // the GShut demotion must win — otherwise an operator who set
    // local_pref = 200 on EBGP imports would silently defeat the
    // RFC 8326 receiver semantics for any GShut-tagged path.
    use rustbgpd_policy::{RouteContext, evaluate_chain};
    use rustbgpd_wire::{AspaValidation, RpkiValidation};
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
honor_graceful_shutdown = true

[global.telemetry]
log_format = "json"

[policy.definitions.bump-local-pref]
default_action = "permit"

  [[policy.definitions.bump-local-pref.statements]]
  prefix = "0.0.0.0/0"
  ge = 0
  action = "permit"
  set_local_pref = 200

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
import_policy_chain = ["bump-local-pref"]
"#;
    let cfg = parse(toml).unwrap();
    let neighbor = &cfg.neighbors[0];
    let (import, _export) = cfg.effective_policy_chains_for_neighbor(neighbor).unwrap();
    let chain = import.expect("EBGP + honor enabled must yield an import chain");

    // Build a context for a route carrying GRACEFUL_SHUTDOWN.
    let prefix = rustbgpd_wire::Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
        std::net::Ipv4Addr::new(10, 0, 0, 0),
        8,
    ));
    let comms = [rustbgpd_wire::COMMUNITY_GRACEFUL_SHUTDOWN];
    let ctx = RouteContext {
        prefix,
        next_hop: None,
        extended_communities: &[],
        communities: &comms,
        large_communities: &[],
        as_path_str: "",
        as_path_len: 0,
        validation_state: RpkiValidation::NotFound,
        aspa_state: AspaValidation::Unknown,
        peer_address: None,
        peer_asn: None,
        peer_group: None,
        route_type: None,
        evpn_route_type: None,
        local_pref: None,
        med: None,
    };
    let result = evaluate_chain(Some(&chain), &ctx);
    assert_eq!(
        result.action,
        rustbgpd_policy::PolicyAction::Permit,
        "GShut-tagged route must permit through operator + implicit chain"
    );
    assert_eq!(
        result.modifications.set_local_pref,
        Some(0),
        "GShut demotion at chain tail MUST overwrite operator's set_local_pref=200; \
         got {:?}",
        result.modifications.set_local_pref
    );
}

// -----------------------------------------------------------------------
// RFC 7999 — honor_blackhole implicit chain-tail import rule
// -----------------------------------------------------------------------

fn blackhole_toml(honor: bool, peer_asn: u32) -> String {
    format!(
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
honor_blackhole = {honor}

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = {peer_asn}
hold_time = 90
"#
    )
}

#[test]
fn effective_chain_appends_blackhole_when_honor_enabled_for_ebgp() {
    let cfg = parse(&blackhole_toml(true, 65002)).unwrap();
    let neighbor = &cfg.neighbors[0];
    let (import, _export) = cfg.effective_policy_chains_for_neighbor(neighbor).unwrap();
    let chain = import.expect("EBGP + honor enabled must yield an import chain");
    let last = chain.policies.last().expect("chain not empty");
    let stmt = &last.entries[0];
    assert_eq!(
        stmt.match_community,
        vec![rustbgpd_policy::CommunityMatch::Standard {
            value: rustbgpd_wire::COMMUNITY_BLACKHOLE,
        }],
        "tail statement must match BLACKHOLE"
    );
    assert_eq!(
        stmt.modifications.communities_add,
        vec![
            rustbgpd_wire::COMMUNITY_BLACKHOLE,
            rustbgpd_wire::COMMUNITY_NO_ADVERTISE,
        ],
        "RFC 7999 receiver scoping must preserve BLACKHOLE and add NO_ADVERTISE"
    );
}

#[test]
fn effective_chain_does_not_append_blackhole_for_ibgp() {
    let cfg = parse(&blackhole_toml(true, 65001)).unwrap();
    let neighbor = &cfg.neighbors[0];
    let (import, _export) = cfg.effective_policy_chains_for_neighbor(neighbor).unwrap();
    assert!(
        import.is_none(),
        "iBGP must not get the implicit BLACKHOLE receiver rule"
    );
}

#[test]
fn effective_chain_does_not_append_blackhole_when_honor_disabled() {
    let cfg = parse(&blackhole_toml(false, 65002)).unwrap();
    let neighbor = &cfg.neighbors[0];
    let (import, _export) = cfg.effective_policy_chains_for_neighbor(neighbor).unwrap();
    assert!(
        import.is_none(),
        "honor_blackhole = false must leave the chain untouched"
    );
}

#[test]
fn blackhole_fib_discard_defaults_off() {
    let cfg = parse(&blackhole_toml(false, 65002)).unwrap();
    assert!(!cfg.global.install_blackhole_discard);
    assert!(!cfg.global.allow_blackhole_broad_prefixes);
}

#[test]
fn blackhole_fib_discard_flags_parse() {
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
honor_blackhole = true
install_blackhole_discard = true
allow_blackhole_broad_prefixes = true

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
"#;
    let cfg = parse(toml).unwrap();
    assert!(cfg.global.honor_blackhole);
    assert!(cfg.global.install_blackhole_discard);
    assert!(cfg.global.allow_blackhole_broad_prefixes);
}

#[test]
fn blackhole_fib_discard_diff_marks_restart_required() {
    let old = parse(valid_toml()).unwrap();
    let new_toml = valid_toml().replace(
        "listen_port = 179\n",
        "listen_port = 179\ninstall_blackhole_discard = true\nallow_blackhole_broad_prefixes = true\n",
    );
    let new = parse(&new_toml).unwrap();
    let diff = super::diff_config(&old, &new);

    assert!(diff.blackhole_fib_discard_changed);
    assert!(diff.has_restart_required_changes());
}

#[test]
fn blackhole_honor_change_with_fib_discard_marks_fib_restart_only() {
    let old_toml = valid_toml().replace(
        "listen_port = 179\n",
        "listen_port = 179\nhonor_blackhole = false\ninstall_blackhole_discard = true\n",
    );
    let new_toml = valid_toml().replace(
        "listen_port = 179\n",
        "listen_port = 179\nhonor_blackhole = true\ninstall_blackhole_discard = true\n",
    );
    let old = parse(&old_toml).unwrap();
    let new = parse(&new_toml).unwrap();
    let diff = super::diff_config(&old, &new);

    assert!(!diff.global_changed);
    assert!(!diff.honor_blackhole_changed);
    assert!(diff.blackhole_fib_discard_changed);
    assert!(diff.has_restart_required_changes());
}

#[test]
fn blackhole_tail_readds_marker_and_no_advertise_after_operator_remove() {
    use rustbgpd_policy::{RouteContext, evaluate_chain};
    use rustbgpd_wire::{AspaValidation, RpkiValidation};

    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
honor_blackhole = true

[global.telemetry]
log_format = "json"

[policy.definitions.strip-communities]
default_action = "permit"

  [[policy.definitions.strip-communities.statements]]
  prefix = "0.0.0.0/0"
  ge = 0
  action = "permit"
  set_community_remove = ["BLACKHOLE", "NO_ADVERTISE"]

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_time = 90
import_policy_chain = ["strip-communities"]
"#;
    let cfg = parse(toml).unwrap();
    let neighbor = &cfg.neighbors[0];
    let (import, _export) = cfg.effective_policy_chains_for_neighbor(neighbor).unwrap();
    let chain = import.expect("EBGP + honor enabled must yield an import chain");

    let prefix = rustbgpd_wire::Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
        std::net::Ipv4Addr::new(10, 0, 0, 0),
        8,
    ));
    let comms = [rustbgpd_wire::COMMUNITY_BLACKHOLE];
    let ctx = RouteContext {
        prefix,
        next_hop: None,
        extended_communities: &[],
        communities: &comms,
        large_communities: &[],
        as_path_str: "",
        as_path_len: 0,
        validation_state: RpkiValidation::NotFound,
        aspa_state: AspaValidation::Unknown,
        peer_address: None,
        peer_asn: None,
        peer_group: None,
        route_type: None,
        evpn_route_type: None,
        local_pref: None,
        med: None,
    };
    let result = evaluate_chain(Some(&chain), &ctx);
    assert_eq!(result.action, rustbgpd_policy::PolicyAction::Permit);
    assert_eq!(
        result.modifications.communities_add,
        vec![
            rustbgpd_wire::COMMUNITY_BLACKHOLE,
            rustbgpd_wire::COMMUNITY_NO_ADVERTISE,
        ],
        "BLACKHOLE chain-tail rule must win after an earlier remove"
    );
    assert!(
        result.modifications.communities_remove.is_empty(),
        "tail add should cancel earlier removes for BLACKHOLE / NO_ADVERTISE"
    );
}

#[test]
fn evpn_instance_ipv6_vtep_accepted() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "2001:db8::1"
"#,
    );
    let config = parse(&toml).unwrap();
    let table = config.resolve_evpn_instances().unwrap();
    let inst = table.get(EvpnInstanceId::new(100).unwrap()).unwrap();
    assert_eq!(
        inst.local_vtep_ip,
        std::net::IpAddr::V6("2001:db8::1".parse().unwrap())
    );
}

// ---------------------------------------------------------------------------
// ADR-0056 — sticky_macs schema. Validates parse, dedupe, and the
// restart-required diff path.
// ---------------------------------------------------------------------------

#[test]
fn evpn_sticky_macs_default_empty() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
"#,
    );
    let table = parse(&toml).unwrap().resolve_evpn_instances().unwrap();
    let inst = table.get(EvpnInstanceId::new(100).unwrap()).unwrap();
    assert!(inst.sticky_macs.is_empty());
}

#[test]
fn evpn_sticky_macs_round_trip() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
sticky_macs = ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]
"#,
    );
    let table = parse(&toml).unwrap().resolve_evpn_instances().unwrap();
    let inst = table.get(EvpnInstanceId::new(100).unwrap()).unwrap();
    assert_eq!(inst.sticky_macs.len(), 2);
    let want_a = rustbgpd_wire::MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
    let want_b = rustbgpd_wire::MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02]);
    assert!(inst.sticky_macs.contains(&want_a));
    assert!(inst.sticky_macs.contains(&want_b));
}

#[test]
fn evpn_sticky_macs_rejects_malformed() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
sticky_macs = ["not-a-mac"]
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::InvalidEvpnInstance { .. }),
        "expected InvalidEvpnInstance, got {msg}"
    );
    assert!(msg.contains("sticky_mac"), "msg must explain why: {msg}");
}

#[test]
fn evpn_sticky_macs_rejects_duplicate_within_instance() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
sticky_macs = ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:01"]
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::InvalidEvpnInstance { .. }),
        "expected InvalidEvpnInstance, got {msg}"
    );
    assert!(
        msg.to_lowercase().contains("duplicate"),
        "msg must call out duplicate: {msg}"
    );
}

#[test]
fn evpn_sticky_macs_diff_marks_restart_required() {
    // Adding sticky_macs to an existing instance must flip
    // evpn_instances_changed (restart-required bucket per ADR-0056).
    let base = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
"#,
    );
    let with_sticky = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
sticky_macs = ["aa:bb:cc:dd:ee:01"]
"#,
    );
    let old = parse(&base).unwrap();
    let new = parse(&with_sticky).unwrap();
    let diff = diff_config(&old, &new);
    assert!(
        diff.evpn_instances_changed,
        "adding sticky_macs must flip evpn_instances_changed"
    );
    assert!(
        diff.has_restart_required_changes(),
        "evpn_instances_changed must surface as restart-required"
    );
}

// ---------------------------------------------------------------------------
// RFC 7432 §15.1 — duplicate MAC detection / local suppression schema.
// ---------------------------------------------------------------------------

#[test]
fn evpn_duplicate_mac_detection_defaults_detect_only() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
"#,
    );
    let table = parse(&toml).unwrap().resolve_evpn_instances().unwrap();
    let inst = table.get(EvpnInstanceId::new(100).unwrap()).unwrap();
    assert_eq!(
        inst.duplicate_mac_detection.action,
        rustbgpd_evpn::DuplicateMacAction::DetectOnly
    );
    assert_eq!(
        inst.duplicate_mac_detection.window,
        std::time::Duration::from_mins(3)
    );
    assert_eq!(inst.duplicate_mac_detection.threshold, 5);
    assert_eq!(
        inst.duplicate_mac_detection.recovery,
        std::time::Duration::from_mins(9)
    );
}

#[test]
fn evpn_duplicate_mac_detection_round_trip_suppress_local() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
duplicate_mac_detection = { action = "suppress_local", window_seconds = 30, threshold = 2, recovery_seconds = 90 }
"#,
    );
    let table = parse(&toml).unwrap().resolve_evpn_instances().unwrap();
    let inst = table.get(EvpnInstanceId::new(100).unwrap()).unwrap();
    assert_eq!(
        inst.duplicate_mac_detection.action,
        rustbgpd_evpn::DuplicateMacAction::SuppressLocal
    );
    assert_eq!(
        inst.duplicate_mac_detection.window,
        std::time::Duration::from_secs(30)
    );
    assert_eq!(inst.duplicate_mac_detection.threshold, 2);
    assert_eq!(
        inst.duplicate_mac_detection.recovery,
        std::time::Duration::from_secs(90)
    );
}

#[test]
fn evpn_duplicate_mac_detection_rejects_zero_values() {
    for (field, value) in [
        ("window_seconds", "0"),
        ("threshold", "0"),
        ("recovery_seconds", "0"),
        ("recovery_seconds", "31536001"),
    ] {
        let toml = evpn_toml_with(&format!(
            r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
duplicate_mac_detection = {{ {field} = {value} }}
"#
        ));
        let err = parse(&toml).unwrap_err();
        let msg = err.to_string();
        assert!(
            matches!(err, ConfigError::InvalidEvpnInstance { .. }),
            "expected InvalidEvpnInstance for {field}, got {msg}"
        );
        assert!(msg.contains(field), "message should name {field}: {msg}");
    }
}

#[test]
fn evpn_duplicate_mac_detection_diff_marks_restart_required() {
    let base = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
"#,
    );
    let suppress = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
duplicate_mac_detection = { action = "suppress_local" }
"#,
    );
    let old = parse(&base).unwrap();
    let new = parse(&suppress).unwrap();
    let diff = diff_config(&old, &new);
    assert!(diff.evpn_instances_changed);
    assert!(diff.has_restart_required_changes());
}

#[test]
fn ethernet_segments_diff_marks_restart_required() {
    let old = parse(valid_toml()).unwrap();
    let new_toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.100"
"#,
    );
    let new = parse(&new_toml).unwrap();
    let diff = diff_config(&old, &new);
    assert!(diff.ethernet_segments_changed);
    assert!(diff.has_restart_required_changes());
}

#[test]
fn evpn_ip_vrfs_diff_marks_restart_required() {
    let old = parse(valid_toml()).unwrap();
    let new_toml = evpn_toml_with(
        r#"
[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
    );
    let new = parse(&new_toml).unwrap();
    let diff = diff_config(&old, &new);
    assert!(diff.evpn_ip_vrfs_changed);
    assert!(diff.has_restart_required_changes());
}

#[test]
fn apply_bum_enforcement_diff_marks_restart_required() {
    let old = parse(valid_toml()).unwrap();
    let new_toml = format!("apply_bum_enforcement = true\n{}", valid_toml());
    let new = parse(&new_toml).unwrap();
    let diff = diff_config(&old, &new);
    assert!(diff.apply_bum_enforcement_changed);
    assert!(diff.has_restart_required_changes());
}

// ---------------------------------------------------------------------------
// ADR-0061 — general-purpose unicast Linux FIB config skeleton.
// ---------------------------------------------------------------------------

#[test]
fn fib_tables_default_empty() {
    let config = parse(valid_toml()).unwrap();
    assert!(config.fib_tables.is_empty());
}

#[test]
fn fib_tables_parse_explicit_opt_in() {
    let toml = format!(
        r#"
{}

[[fib_tables]]
name = "edge"
table_id = 1000
metric = 200
"#,
        valid_toml()
    );
    let config = parse(&toml).unwrap();

    assert_eq!(config.fib_tables.len(), 1);
    let table = &config.fib_tables[0];
    assert_eq!(table.name, "edge");
    assert_eq!(table.table_id, 1000);
    assert_eq!(table.metric, 200);
    assert_eq!(table.families, ["ipv4_unicast", "ipv6_unicast"]);
    assert!(table.allowed_peer_groups.is_empty());
    assert!(table.allowed_neighbors.is_empty());
    assert_eq!(table.max_routes, None);
}

#[test]
fn fib_tables_reject_reserved_table_ids() {
    for id in [0, 252, 253, 254, 255] {
        let toml = format!(
            r#"
{}

[[fib_tables]]
name = "edge"
table_id = {id}
metric = 200
"#,
            valid_toml()
        );
        let err = parse(&toml).unwrap_err();
        let ConfigError::InvalidFibTable { reason } = err else {
            panic!("expected InvalidFibTable for table {id}, got {err}");
        };
        assert!(
            reason.contains("reserved"),
            "expected reserved-table error for {id}, got {reason}"
        );
    }
}

#[test]
fn fib_tables_reject_duplicate_names_and_tables() {
    let toml = format!(
        r#"
{}

[[fib_tables]]
name = "edge"
table_id = 1000
metric = 200

[[fib_tables]]
name = "edge"
table_id = 1001
metric = 200
"#,
        valid_toml()
    );
    assert!(matches!(
        parse(&toml),
        Err(ConfigError::InvalidFibTable { .. })
    ));

    let toml = format!(
        r#"
{}

[[fib_tables]]
name = "edge-a"
table_id = 1000
metric = 200

[[fib_tables]]
name = "edge-b"
table_id = 1000
metric = 200
"#,
        valid_toml()
    );
    assert!(matches!(
        parse(&toml),
        Err(ConfigError::InvalidFibTable { .. })
    ));
}

#[test]
fn fib_tables_reject_non_unicast_families() {
    let toml = format!(
        r#"
{}

[[fib_tables]]
name = "edge"
table_id = 1000
metric = 200
families = ["ipv4_flowspec"]
"#,
        valid_toml()
    );
    let err = parse(&toml).unwrap_err();
    let ConfigError::InvalidFibTable { reason } = err else {
        panic!("expected InvalidFibTable, got {err}");
    };
    assert!(reason.contains("unsupported family"));
}

#[test]
fn fib_tables_parse_guardrails() {
    let toml = format!(
        r#"
{}

[peer_groups.transit]

[[fib_tables]]
name = "edge"
table_id = 1000
metric = 200
families = ["ipv4_unicast"]
allowed_peer_groups = ["transit"]
allowed_neighbors = ["198.51.100.1", "2001:db8::1"]
max_routes = 1000
"#,
        valid_toml()
    );
    let config = parse(&toml).unwrap();
    let table = &config.fib_tables[0];

    assert_eq!(table.allowed_peer_groups, ["transit"]);
    assert_eq!(table.allowed_neighbors, ["198.51.100.1", "2001:db8::1"]);
    assert_eq!(table.max_routes, Some(1000));
}

#[test]
fn fib_tables_reject_invalid_guardrails() {
    let cases = [
        (
            r#"allowed_peer_groups = ["missing"]"#,
            "undefined peer_group",
        ),
        (
            r#"allowed_neighbors = ["not-an-ip"]"#,
            "invalid allowed_neighbors",
        ),
        (
            r#"allowed_neighbors = ["198.51.100.1", "198.51.100.1"]"#,
            "duplicate allowed_neighbors",
        ),
        (r"max_routes = 0", "max_routes must be greater than zero"),
    ];

    for (line, expected) in cases {
        let toml = format!(
            r#"
{}

[[fib_tables]]
name = "edge"
table_id = 1000
metric = 200
{line}
"#,
            valid_toml()
        );
        let err = parse(&toml).unwrap_err();
        let ConfigError::InvalidFibTable { reason } = err else {
            panic!("expected InvalidFibTable, got {err}");
        };
        assert!(
            reason.contains(expected),
            "expected {expected:?} in error, got {reason:?}"
        );
    }
}

#[test]
fn fib_tables_reject_duplicate_allowed_peer_groups() {
    let toml = format!(
        r#"
{}

[peer_groups.transit]

[[fib_tables]]
name = "edge"
table_id = 1000
metric = 200
allowed_peer_groups = ["transit", "transit"]
"#,
        valid_toml()
    );
    let err = parse(&toml).unwrap_err();
    let ConfigError::InvalidFibTable { reason } = err else {
        panic!("expected InvalidFibTable, got {err}");
    };
    assert!(
        reason.contains("duplicate allowed_peer_groups"),
        "unexpected error: {reason}"
    );
}

#[test]
fn fib_tables_diff_marks_restart_required() {
    let old = parse(valid_toml()).unwrap();
    let toml = format!(
        r#"
{}

[[fib_tables]]
name = "edge"
table_id = 1000
metric = 200
"#,
        valid_toml()
    );
    let new = parse(&toml).unwrap();
    let diff = diff_config(&old, &new);

    assert!(diff.fib_tables_changed);
    assert!(diff.has_restart_required_changes());
}

// ---------------------------------------------------------------------------
// ADR-0057 — Ethernet Segment config. Validates Gate 8's operator-facing
// `[[ethernet_segments]]` block before the daemon spawns the orchestrator.
// ---------------------------------------------------------------------------

#[test]
fn ethernet_segments_default_empty() {
    let config = parse(valid_toml()).unwrap();
    assert!(config.ethernet_segments.is_empty());
    assert!(config.resolve_ethernet_segments().unwrap().is_empty());
}

#[test]
fn ethernet_segments_reject_member_vni_shared_across_segments() {
    // Gate 8b ESI-aware MAC origination keys on `(VNI -> ESI)`.
    // If two segments listed the same member VNI, the origination
    // path would silently pick whichever resolved first and emit
    // wrong-ESI Type 2 routes for MACs the operator actually
    // intended for the other segment. Reject at config load.
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:02"
member_vnis = [100]
originator_ip = "10.0.0.100"
"#,
    );
    // Validation fires inside `Config::load` / `parse`, so the
    // error surfaces here before any caller can construct the
    // ambiguous segment table at runtime.
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("VNI 100") && msg.contains("multiple ethernet_segments"),
        "expected VNI-collision error, got: {msg}"
    );
}

#[test]
fn ethernet_segment_minimal_parses() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.100"
"#,
    );
    let config = parse(&toml).unwrap();
    let segments = config.resolve_ethernet_segments().unwrap();
    assert_eq!(segments.len(), 1);
    assert_eq!(segments[0].member_vnis.len(), 1);
    assert_eq!(segments[0].df_algorithm, DfAlgorithm::DefaultModulo);
    assert_eq!(segments[0].df_preference, 32_768);
}

#[test]
fn ethernet_segment_rejects_empty_member_vnis() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = []
originator_ip = "10.0.0.100"
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::InvalidEthernetSegment { .. }),
        "expected InvalidEthernetSegment, got {msg}"
    );
    assert!(
        msg.contains("member_vnis"),
        "msg must call out member_vnis: {msg}"
    );
}

#[test]
fn ethernet_segment_rejects_non_default_df_algorithm() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
df_algorithm = "preference-based"
originator_ip = "10.0.0.100"
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::InvalidEthernetSegment { .. }),
        "expected InvalidEthernetSegment, got {msg}"
    );
    assert!(
        msg.contains("default-modulo"),
        "msg must name supported algorithm: {msg}"
    );
}

#[test]
fn ethernet_segment_rejects_non_default_df_preference() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
df_preference = 100
originator_ip = "10.0.0.100"
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::InvalidEthernetSegment { .. }),
        "expected InvalidEthernetSegment, got {msg}"
    );
    assert!(
        msg.contains("32768"),
        "msg must name supported preference: {msg}"
    );
}

// ---------------------------------------------------------------------------
// EVPN Gate 9 — `[[evpn_ip_vrfs]]` schema, parse, validation. ADR-0058.
//
// These tests pin the operator-facing TOML surface for local IP-VRFs
// and the resolution into `IpVrfTable`. They cover the per-entry parse
// (name shape / VNI range / RD / RT / VTEP / Router MAC / device /
// table id), the table-level uniqueness checks, the L2↔L3 VNI overlap
// check, and the `[[evpn_instances]].ip_vrf` cross-reference.
// ---------------------------------------------------------------------------

#[test]
fn evpn_ip_vrfs_default_empty() {
    // No `[[evpn_ip_vrfs]]` block ⇒ L2-only VTEP / RR shape stays valid.
    let config = parse(valid_toml()).unwrap();
    assert!(config.evpn_ip_vrfs.is_empty());
    assert!(config.resolve_evpn_ip_vrfs().unwrap().is_empty());
}

#[test]
fn evpn_ip_vrf_minimal_parses() {
    let toml = evpn_toml_with(
        r#"
[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
    );
    let config = parse(&toml).unwrap();
    assert_eq!(config.evpn_ip_vrfs.len(), 1);
    let table = config.resolve_evpn_ip_vrfs().unwrap();
    assert_eq!(table.len(), 1);
    let vrf = table.get("tenant-blue").unwrap();
    assert_eq!(vrf.id.as_u32(), 5000);
    assert_eq!(vrf.vrf_device, "vrf-blue");
    assert_eq!(vrf.l3vxlan_device, "vni5000");
    assert_eq!(vrf.table_id, 5000);
}

#[test]
fn evpn_ip_vrf_rejects_l3vni_colliding_with_l2vni() {
    // L2VNI 100 declared, then [[evpn_ip_vrfs]] tries to reuse it as L3VNI.
    // Must be rejected at config-load time — the wire VNI space is shared.
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 100
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni100"
table_id = 5000
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("collides") && msg.contains("100"),
        "msg must call out the VNI collision: {msg}"
    );
}

#[test]
fn evpn_ip_vrf_rejects_duplicate_name() {
    let toml = evpn_toml_with(
        r#"
[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5001
rd = "65000:5001"
route_targets = ["65000:5001"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:02"
vrf_device = "vrf-blue-2"
l3vxlan_device = "vni5001"
table_id = 5001
"#,
    );
    let err = parse(&toml).unwrap_err();
    assert!(
        err.to_string().contains("duplicate name"),
        "msg must mention duplicate name: {err}"
    );
}

#[test]
fn evpn_ip_vrf_rejects_bad_router_mac() {
    let toml = evpn_toml_with(
        r#"
[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "01:00:5e:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
    );
    let err = parse(&toml).unwrap_err();
    assert!(
        err.to_string().contains("router_mac"),
        "msg must name the bad field: {err}"
    );
}

#[test]
fn evpn_ip_vrf_rejects_bad_name_shape() {
    let toml = evpn_toml_with(
        r#"
[[evpn_ip_vrfs]]
name = "1bad"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
    );
    let err = parse(&toml).unwrap_err();
    assert!(
        err.to_string().contains("name"),
        "msg must name the offending field: {err}"
    );
}

#[test]
fn evpn_instance_ip_vrf_link_must_resolve() {
    // An [[evpn_instances]] entry referencing an undeclared IP-VRF is
    // rejected at config-load time.
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"
"#,
    );
    let err = parse(&toml).unwrap_err();
    assert!(
        err.to_string().contains("ip_vrf"),
        "msg must mention ip_vrf reference: {err}"
    );
}

#[test]
fn evpn_instance_ip_vrf_link_marks_referenced() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000

[[evpn_ip_vrfs]]
name = "tenant-red"
vni = 5001
rd = "65000:5001"
route_targets = ["65000:5001"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:02"
vrf_device = "vrf-red"
l3vxlan_device = "vni5001"
table_id = 5001
"#,
    );
    let config = parse(&toml).unwrap();
    let table = config.resolve_evpn_ip_vrfs().unwrap();
    assert_eq!(table.len(), 2);
    assert!(
        table.is_referenced("tenant-blue"),
        "tenant-blue is bound by [[evpn_instances]].ip_vrf"
    );
    assert!(
        !table.is_referenced("tenant-red"),
        "tenant-red has no L2VNI binding"
    );
}

#[test]
fn evpn_ip_vrf_validation_catches_errors_at_validate() {
    // Top-level `validate()` (called inside the test `parse` helper)
    // must surface IP-VRF errors so a malformed [[evpn_ip_vrfs]] block
    // doesn't slip past `Config::load`.
    let toml = evpn_toml_with(
        r#"
[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "not a real rd"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
    );
    let err = parse(&toml).unwrap_err();
    assert!(
        err.to_string().contains("rd"),
        "validate() must surface the bad rd: {err}"
    );
}
