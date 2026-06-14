use super::*;
use std::{
    fs,
    path::{Path, PathBuf},
};

use rustbgpd_api::peer_types::PeerKey;
use rustbgpd_policy::RouteType;
use rustbgpd_wire::{Afi, BgpRole, Safi};
use tempfile::NamedTempFile;

fn valid_toml() -> &'static str {
    // Shared test fixture used by hundreds of config tests below.
    // Opts into `enforcement = "legacy"` explicitly so the fixture
    // exercises pre-v0.24.0 gRPC authorization behavior; tier-mode
    // semantics are covered by dedicated tests via `valid_toml_no_grpc_security`.
    r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[security.grpc]
enforcement = "legacy"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
description = "peer-1"
hold_time = 90
"#
}

fn valid_toml_no_grpc_security() -> &'static str {
    // Variant of `valid_toml()` without a `[security.grpc]` block so
    // gRPC security tests can append their own enforcement / roles
    // sections without colliding with a duplicate-key TOML error.
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

/// Test entry that exercises the production parse + validate path
/// without injecting any test-only defaults. gRPC security tests use
/// this so they see the v0.24.0 production-default `enforcement =
/// "tier"` behavior, including the validation failures an unstaged
/// operator config would hit.
fn parse_strict(toml_str: &str) -> Result<Config, ConfigError> {
    let config: Config = toml::from_str(toml_str).map_err(ConfigError::Parse)?;
    config.validate()?;
    Ok(config)
}

/// Test entry used by most config tests. Auto-injects
/// `[security.grpc] enforcement = "legacy"` when the input lacks a
/// `[security.grpc]` block, so tests that do not exercise the gRPC
/// authorization surface keep working after the v0.24.0 default flip
/// without hundreds of one-line opt-in edits. Dedicated
/// `grpc_security_*` tests use `parse_strict()` so they see the
/// production behavior unchanged.
fn parse(toml_str: &str) -> Result<Config, ConfigError> {
    let augmented;
    let to_parse = if toml_str.contains("[security.grpc]") {
        toml_str
    } else {
        augmented = format!("[security.grpc]\nenforcement = \"legacy\"\n{toml_str}");
        augmented.as_str()
    };
    let config: Config = toml::from_str(to_parse).map_err(ConfigError::Parse)?;
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
        // parse_strict (not parse) so every shipped example is validated under
        // the production v0.24.0 `enforcement = "tier"` default. parse() would
        // auto-inject `enforcement = "legacy"` for configs lacking a
        // [security.grpc] block, masking examples that cannot actually start
        // under defaults — the gap that shipped all examples unstartable until
        // the v0.33.0 fixup. This guard fails closed if a new example omits the
        // gRPC authorization config.
        parse_strict(&source).unwrap_or_else(|err| {
            panic!("example config {label} failed validation under the tier default: {err}");
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
            // Some `examples/` entries are Rust workspace members
            // (e.g. ADR-0072 `examples/event-bridge/`) and ship a
            // `Cargo.toml`, not a daemon config. Skip those here;
            // their compile-time correctness is enforced by the
            // workspace build, not this validator.
            if path.file_name().and_then(|f| f.to_str()) == Some("Cargo.toml") {
                continue;
            }
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
fn link_local_neighbor_requires_interface() {
    let toml_str = valid_toml().replace("10.0.0.2", "fe80::1");
    let err = parse(&toml_str).unwrap_err();
    match err {
        ConfigError::InvalidNeighborConfig { field, reason, .. } => {
            assert_eq!(field, "interface");
            assert!(reason.contains("link-local"));
        }
        other => panic!("expected InvalidNeighborConfig, got {other}"),
    }
}

#[test]
fn link_local_neighbor_rejects_same_address_on_different_interfaces() {
    // v1 limitation (ADR-0069 Deferred): the RIB keys peers by bare address, so
    // the same link-local address on two interfaces would alias in the RIB.
    // Validation rejects it until the RIB carries scoped peer identity.
    let base = valid_toml().replace(
        r#"address = "10.0.0.2""#,
        r#"address = "fe80::1"
interface = "lo""#,
    );
    let toml_str = format!(
        r#"
{base}

[[neighbors]]
address = "fe80::1"
interface = "eth0"
remote_asn = 65099
"#
    );
    let err = parse(&toml_str).unwrap_err();
    match err {
        ConfigError::InvalidNeighborConfig { field, reason, .. } => {
            assert_eq!(field, "interface");
            assert!(reason.contains("multiple"), "unexpected reason: {reason}");
        }
        other => panic!("expected InvalidNeighborConfig, got {other}"),
    }
}

#[test]
fn link_local_neighbor_rejects_duplicate_address_interface() {
    let base = valid_toml().replace(
        r#"address = "10.0.0.2""#,
        r#"address = "fe80::1"
interface = "lo""#,
    );
    let toml_str = format!(
        r#"
{base}

[[neighbors]]
address = "fe80::1"
interface = "lo"
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
fn non_link_local_neighbor_rejects_interface() {
    let toml_str = valid_toml().replace(
        r#"address = "10.0.0.2""#,
        r#"address = "2001:db8::1"
interface = "lo""#,
    );
    let err = parse(&toml_str).unwrap_err();
    match err {
        ConfigError::InvalidNeighborConfig { field, reason, .. } => {
            assert_eq!(field, "interface");
            assert!(reason.contains("only valid"));
        }
        other => panic!("expected InvalidNeighborConfig, got {other}"),
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
            max_tier: GrpcMaxTier::OperatorOnly,
            token_file: None,
            principal: None,
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
            max_tier: GrpcMaxTier::OperatorOnly,
            token_file: None,
            principal: None,
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
            max_tier: GrpcMaxTier::SensitiveRead,
            token_file: None,
            principal: None,
            tls: None,
        }]
    );
}

#[test]
fn grpc_listener_max_tier_parses() {
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\nmax_tier = \"mutating\"\n",
        valid_toml()
    );
    let config = parse(&toml_str).unwrap();
    assert_eq!(
        config.grpc_listeners(),
        vec![GrpcListener::Tcp {
            addr: "127.0.0.1:50051".parse().unwrap(),
            access_mode: GrpcAccessMode::ReadWrite,
            max_tier: GrpcMaxTier::Mutating,
            token_file: None,
            principal: None,
            tls: None,
        }]
    );
}

#[test]
fn grpc_listener_access_mode_read_only_caps_max_tier() {
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\naccess_mode = \"read_only\"\nmax_tier = \"operator_only\"\n",
        valid_toml()
    );
    let config = parse(&toml_str).unwrap();
    assert_eq!(
        config.grpc_listeners(),
        vec![GrpcListener::Tcp {
            addr: "127.0.0.1:50051".parse().unwrap(),
            access_mode: GrpcAccessMode::ReadOnly,
            max_tier: GrpcMaxTier::SensitiveRead,
            token_file: None,
            principal: None,
            tls: None,
        }]
    );
}

#[test]
fn grpc_listener_max_tier_can_be_stricter_than_access_mode() {
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_uds]\npath = \"/tmp/rustbgpd-test.sock\"\nmax_tier = \"read\"\n",
        valid_toml()
    );
    let config = parse(&toml_str).unwrap();
    assert_eq!(
        config.grpc_listeners(),
        vec![GrpcListener::Uds {
            path: PathBuf::from("/tmp/rustbgpd-test.sock"),
            mode: 0o600,
            access_mode: GrpcAccessMode::ReadWrite,
            max_tier: GrpcMaxTier::Read,
            token_file: None,
            principal: None,
        }]
    );
}

#[test]
fn grpc_security_roles_parse_with_explicit_legacy_enforcement() {
    // After the v0.24.0 default flip, operators who want the prior
    // pre-enforcement posture must set `enforcement = "legacy"`
    // explicitly. This test pins that the explicit opt-out still
    // parses cleanly alongside a populated roles map (operators
    // staging roles ahead of flipping enforcement to "tier").
    let toml_str = format!(
        "{}\n[security.grpc]\nenforcement = \"legacy\"\n\n[security.grpc.roles]\n\"observer-readonly\" = \"observer\"\n\"automation.example\" = \"automation\"\n\"operator.example\" = \"operator\"\n",
        valid_toml_no_grpc_security()
    );
    let config = parse(&toml_str).unwrap();
    assert_eq!(
        config.security.grpc.enforcement,
        GrpcEnforcementConfig::Legacy
    );
    assert_eq!(
        config.security.grpc.roles["observer-readonly"],
        GrpcRoleConfig::Observer
    );
    assert_eq!(
        config.security.grpc.roles["automation.example"],
        GrpcRoleConfig::Automation
    );
    assert_eq!(
        config.security.grpc.roles["operator.example"],
        GrpcRoleConfig::Operator
    );
}

#[test]
fn grpc_security_default_is_tier_since_v0_24() {
    // Pinned by the v0.24.0 ADR-0064 slice 4b default flip. If this
    // regresses to Legacy without a deliberate schema change, the
    // production security posture has silently rolled back. Builds
    // a minimal tier-ready config (no [security.grpc] block — relies
    // entirely on the default — plus one role + grpc_uds with
    // matching principal) so validation passes.
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[global.telemetry.grpc_uds]
path = "/tmp/rustbgpd-default-tier-test.sock"
principal = "local-operator"

[security.grpc.roles]
"local-operator" = "operator"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
description = "peer-1"
hold_time = 90
"#;
    // parse_strict bypasses the test-only legacy auto-inject so we
    // observe the actual schema default that production sees.
    let config = parse_strict(toml_str).unwrap();
    assert_eq!(
        config.security.grpc.enforcement,
        GrpcEnforcementConfig::Tier,
        "GrpcEnforcementConfig default flipped to Tier in v0.24.0; \
         regression would silently restore pre-enforcement behavior"
    );
}

#[test]
fn grpc_security_empty_config_fails_tier_validation_with_legacy_hint() {
    // After the v0.24.0 default flip, an operator who upgrades
    // without staging [security.grpc.roles] should see a clean
    // validation failure whose error message points at the
    // migration checklist AND the legacy escape hatch. Uses a TOML
    // without any [security.grpc] block to exercise the bare-upgrade
    // path.
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
description = "peer-1"
hold_time = 90
"#;
    // parse_strict bypasses the test-only legacy auto-inject so this
    // test sees the v0.24.0 production-default tier validation path.
    let result = parse_strict(toml_str);
    let err = result.expect_err("default-tier mode with no roles must fail validation");
    let msg = format!("{err}");
    assert!(
        msg.contains("v0.24.0 default"),
        "validation error should call out the v0.24.0 default flip: {msg}"
    );
    assert!(
        msg.contains("enforcement = \\\"legacy\\\"") || msg.contains("enforcement = \"legacy\""),
        "validation error should mention the legacy escape hatch: {msg}"
    );
}

#[test]
fn grpc_security_tier_enforcement_parses_with_explicit_uds_principal() {
    let toml_str = format!(
        "{}\n[security.grpc]\nenforcement = \"tier\"\n\n[security.grpc.roles]\n\"local-admin\" = \"operator\"\n\n[global.telemetry.grpc_uds]\npath = \"/tmp/rustbgpd-test.sock\"\nprincipal = \"local-admin\"\n",
        valid_toml_no_grpc_security()
    );
    let config = parse(&toml_str).unwrap();
    assert_eq!(
        config.security.grpc.enforcement,
        GrpcEnforcementConfig::Tier
    );
    assert_eq!(
        config.security.grpc.roles["local-admin"],
        GrpcRoleConfig::Operator
    );
}

#[test]
fn grpc_security_empty_role_principal_rejected() {
    let toml_str = format!(
        "{}\n[security.grpc.roles]\n\"   \" = \"observer\"\n",
        valid_toml()
    );
    let err = parse(&toml_str).unwrap_err();
    let ConfigError::InvalidGrpcConfig { reason } = err else {
        panic!("expected InvalidGrpcConfig");
    };
    assert!(
        reason.contains("principal keys must not be empty"),
        "got unexpected reason: {reason}"
    );
}

#[test]
fn grpc_security_reserved_unresolved_mtls_role_rejected() {
    let toml_str = format!(
        "{}\n[security.grpc.roles]\n\"mtls-unresolved\" = \"operator\"\n",
        valid_toml()
    );
    let err = parse(&toml_str).unwrap_err();
    let ConfigError::InvalidGrpcConfig { reason } = err else {
        panic!("expected InvalidGrpcConfig");
    };
    assert!(
        reason.contains("reserved principal"),
        "got unexpected reason: {reason}"
    );
}

#[test]
fn grpc_security_tier_requires_roles() {
    let toml_str = format!(
        "{}\n[security.grpc]\nenforcement = \"tier\"\n\n[global.telemetry.grpc_uds]\npath = \"/tmp/rustbgpd-test.sock\"\nprincipal = \"local-admin\"\n",
        valid_toml_no_grpc_security()
    );
    let err = parse(&toml_str).unwrap_err();
    let ConfigError::InvalidGrpcConfig { reason } = err else {
        panic!("expected InvalidGrpcConfig");
    };
    assert!(
        reason.contains("requires at least one"),
        "got unexpected reason: {reason}"
    );
}

#[test]
fn grpc_security_tier_rejects_implicit_uds_without_principal() {
    let toml_str = format!(
        "{}\n[security.grpc]\nenforcement = \"tier\"\n\n[security.grpc.roles]\n\"local-admin\" = \"operator\"\n",
        valid_toml_no_grpc_security()
    );
    let err = parse(&toml_str).unwrap_err();
    let ConfigError::InvalidGrpcConfig { reason } = err else {
        panic!("expected InvalidGrpcConfig");
    };
    assert!(
        reason.contains("implicit UDS listener"),
        "got unexpected reason: {reason}"
    );
}

#[test]
fn grpc_security_tier_rejects_uds_without_principal() {
    let toml_str = format!(
        "{}\n[security.grpc]\nenforcement = \"tier\"\n\n[security.grpc.roles]\n\"local-admin\" = \"operator\"\n\n[global.telemetry.grpc_uds]\npath = \"/tmp/rustbgpd-test.sock\"\n",
        valid_toml_no_grpc_security()
    );
    let err = parse(&toml_str).unwrap_err();
    let ConfigError::InvalidGrpcConfig { reason } = err else {
        panic!("expected InvalidGrpcConfig");
    };
    assert!(
        reason.contains("requires grpc_uds.principal"),
        "got unexpected reason: {reason}"
    );
}

#[test]
fn grpc_security_tier_rejects_bearer_tcp_without_principal() {
    let token_file = NamedTempFile::new().unwrap();
    fs::write(token_file.path(), "secret").unwrap();
    let toml_str = format!(
        "{}\n[security.grpc]\nenforcement = \"tier\"\n\n[security.grpc.roles]\n\"automation.example\" = \"automation\"\n\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\ntoken_file = {:?}\n",
        valid_toml_no_grpc_security(),
        token_file.path()
    );
    let err = parse(&toml_str).unwrap_err();
    let ConfigError::InvalidGrpcConfig { reason } = err else {
        panic!("expected InvalidGrpcConfig");
    };
    assert!(
        reason.contains("requires grpc_tcp.principal"),
        "got unexpected reason: {reason}"
    );
}

#[test]
fn grpc_security_tier_rejects_non_mtls_principal_absent_from_roles() {
    let token_file = NamedTempFile::new().unwrap();
    fs::write(token_file.path(), "secret").unwrap();
    let toml_str = format!(
        "{}\n[security.grpc]\nenforcement = \"tier\"\n\n[security.grpc.roles]\n\"other.example\" = \"automation\"\n\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\ntoken_file = {:?}\nprincipal = \"automation.example\"\n",
        valid_toml_no_grpc_security(),
        token_file.path()
    );
    let err = parse(&toml_str).unwrap_err();
    let ConfigError::InvalidGrpcConfig { reason } = err else {
        panic!("expected InvalidGrpcConfig");
    };
    assert!(
        reason.contains("to be present in [security.grpc.roles]"),
        "got unexpected reason: {reason}"
    );
}

#[test]
fn grpc_security_tier_rejects_unauthenticated_tcp() {
    let toml_str = format!(
        "{}\n[security.grpc]\nenforcement = \"tier\"\n\n[security.grpc.roles]\n\"automation.example\" = \"automation\"\n\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\n",
        valid_toml_no_grpc_security()
    );
    let err = parse(&toml_str).unwrap_err();
    let ConfigError::InvalidGrpcConfig { reason } = err else {
        panic!("expected InvalidGrpcConfig");
    };
    assert!(
        reason.contains("rejects unauthenticated TCP"),
        "got unexpected reason: {reason}"
    );
}

#[test]
fn grpc_security_tier_accepts_native_mtls_without_configured_principal() {
    let cert = write_pem(STUB_CERT);
    let key = write_pem(STUB_KEY);
    let ca = write_pem(STUB_CERT);
    let toml_str = format!(
        "{}\n[security.grpc]\nenforcement = \"tier\"\n\n[security.grpc.roles]\n\"rustbgpd://operator/alice\" = \"operator\"\n\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\ntls_cert_file = {:?}\ntls_key_file = {:?}\ntls_client_ca_file = {:?}\n",
        valid_toml_no_grpc_security(),
        cert.path(),
        key.path(),
        ca.path()
    );
    let config = parse(&toml_str).unwrap();
    assert_eq!(
        config.security.grpc.enforcement,
        GrpcEnforcementConfig::Tier
    );
    let listeners = config.grpc_listeners();
    let GrpcListener::Tcp { principal, tls, .. } = &listeners[0] else {
        panic!("expected TCP listener");
    };
    assert_eq!(principal, &None);
    assert!(tls.is_some());
}

#[test]
fn grpc_tcp_principal_requires_bearer_token_without_mtls() {
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\nprincipal = \"automation.example\"\n",
        valid_toml()
    );
    let err = parse(&toml_str).unwrap_err();
    let ConfigError::InvalidGrpcConfig { reason } = err else {
        panic!("expected InvalidGrpcConfig");
    };
    assert!(
        reason.contains("requires grpc_tcp.token_file"),
        "got unexpected reason: {reason}"
    );
}

#[test]
fn grpc_tcp_bearer_principal_parses() {
    let token_file = NamedTempFile::new().unwrap();
    fs::write(token_file.path(), "secret").unwrap();
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\ntoken_file = {:?}\nprincipal = \"automation.example\"\n",
        valid_toml(),
        token_file.path()
    );
    let config = parse(&toml_str).unwrap();
    assert_eq!(
        config.grpc_listeners(),
        vec![GrpcListener::Tcp {
            addr: "127.0.0.1:50051".parse().unwrap(),
            access_mode: GrpcAccessMode::ReadWrite,
            max_tier: GrpcMaxTier::OperatorOnly,
            token_file: Some(token_file.path().to_path_buf()),
            principal: Some("automation.example".to_string()),
            tls: None,
        }]
    );
}

#[test]
fn grpc_security_tier_accepts_bearer_tcp_with_principal_role() {
    let token_file = NamedTempFile::new().unwrap();
    fs::write(token_file.path(), "secret").unwrap();
    let toml_str = format!(
        "{}\n[security.grpc]\nenforcement = \"tier\"\n\n[security.grpc.roles]\n\"automation.example\" = \"automation\"\n\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\ntoken_file = {:?}\nprincipal = \"automation.example\"\nmax_tier = \"mutating\"\n",
        valid_toml_no_grpc_security(),
        token_file.path()
    );
    let config = parse(&toml_str).unwrap();
    assert_eq!(
        config.security.grpc.enforcement,
        GrpcEnforcementConfig::Tier
    );
    assert_eq!(
        config.security.grpc.roles["automation.example"],
        GrpcRoleConfig::Automation
    );
    assert_eq!(
        config.grpc_listeners(),
        vec![GrpcListener::Tcp {
            addr: "127.0.0.1:50051".parse().unwrap(),
            access_mode: GrpcAccessMode::ReadWrite,
            max_tier: GrpcMaxTier::Mutating,
            token_file: Some(token_file.path().to_path_buf()),
            principal: Some("automation.example".to_string()),
            tls: None,
        }]
    );
}

#[test]
fn grpc_tcp_principal_rejected_with_mtls() {
    let cert = write_pem(STUB_CERT);
    let key = write_pem(STUB_KEY);
    let ca = write_pem(STUB_CERT);
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_tcp]\naddress = \"127.0.0.1:50051\"\nprincipal = \"automation.example\"\ntls_cert_file = {:?}\ntls_key_file = {:?}\ntls_client_ca_file = {:?}\n",
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
        reason.contains("non-mTLS bearer-token listeners"),
        "got unexpected reason: {reason}"
    );
}

#[test]
fn grpc_uds_principal_parses() {
    let toml_str = format!(
        "{}\n[global.telemetry.grpc_uds]\npath = \"/tmp/rustbgpd-test.sock\"\nprincipal = \"local-admin\"\n",
        valid_toml()
    );
    let config = parse(&toml_str).unwrap();
    assert_eq!(
        config.grpc_listeners(),
        vec![GrpcListener::Uds {
            path: PathBuf::from("/tmp/rustbgpd-test.sock"),
            mode: 0o600,
            access_mode: GrpcAccessMode::ReadWrite,
            max_tier: GrpcMaxTier::OperatorOnly,
            token_file: None,
            principal: Some("local-admin".to_string()),
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
fn neighbor_tcp_ao_schema_maps_to_transport_config() {
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
tcp_ao = { key = "secret", send_id = 7, recv_id = 9, algorithm = "hmac(sha256)", preferred = true }
"#;
    let config = parse(toml_str).unwrap();
    let tcp_ao = config.neighbors[0].tcp_ao.as_ref().unwrap();
    assert_eq!(tcp_ao.key, "secret");
    assert_eq!(tcp_ao.send_id, 7);
    assert_eq!(tcp_ao.recv_id, 9);
    assert_eq!(tcp_ao.algorithm, "hmac(sha256)");
    assert!(tcp_ao.preferred);
    assert!(!tcp_ao.deprecated);

    let peers = config.to_peer_configs().unwrap();
    assert!(peers[0].0.md5_password.is_none());
    let runtime_tcp_ao = peers[0].0.tcp_ao.as_ref().unwrap();
    assert_eq!(runtime_tcp_ao.key, "secret");
    assert_eq!(runtime_tcp_ao.send_id, 7);
    assert_eq!(runtime_tcp_ao.recv_id, 9);
    assert_eq!(
        runtime_tcp_ao.algorithm,
        rustbgpd_transport::TcpAoAlgorithm::HmacSha256
    );
}

#[test]
fn neighbor_tcp_ao_rejects_md5_conflicts() {
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
md5_password = "md5-secret"
tcp_ao = { key = "secret", send_id = 1, recv_id = 1, algorithm = "hmac(sha1)" }
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(matches!(
        err,
        ConfigError::InvalidNeighborConfig { field, .. } if field == "tcp_ao"
    ));
}

#[test]
fn neighbor_tcp_ao_rejects_inherited_md5_conflict() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.secure]
md5_password = "md5-secret"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "secure"
tcp_ao = { key = "secret", send_id = 1, recv_id = 1, algorithm = "hmac(sha1)" }
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(matches!(
        err,
        ConfigError::InvalidNeighborConfig { field, .. } if field == "tcp_ao"
    ));
}

#[test]
fn peer_group_tcp_ao_is_rejected() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.secure]
tcp_ao = { key = "secret", send_id = 1, recv_id = 1, algorithm = "hmac(sha1)" }

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "secure"
"#;
    let err = parse(toml_str).unwrap_err();
    let ConfigError::Parse(parse_err) = err else {
        panic!("peer-group tcp_ao must be rejected by TOML schema, got {err:?}");
    };
    let message = parse_err.to_string();
    assert!(message.contains("unknown field"), "{message}");
    assert!(message.contains("tcp_ao"), "{message}");
}

#[test]
fn neighbor_tcp_ao_rejects_invalid_key_and_algorithm() {
    let base = r#"
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

    let empty_key = format!(
        "{base}tcp_ao = {{ key = \"\", send_id = 1, recv_id = 1, algorithm = \"hmac(sha1)\" }}\n"
    );
    assert!(matches!(
        parse(&empty_key).unwrap_err(),
        ConfigError::InvalidNeighborConfig { field, .. } if field == "tcp_ao.key"
    ));

    let long_key = "x".repeat(81);
    let long_key_toml = format!(
        "{base}tcp_ao = {{ key = \"{long_key}\", send_id = 1, recv_id = 1, algorithm = \"hmac(sha1)\" }}\n"
    );
    assert!(matches!(
        parse(&long_key_toml).unwrap_err(),
        ConfigError::InvalidNeighborConfig { field, .. } if field == "tcp_ao.key"
    ));

    let bad_alg = format!(
        "{base}tcp_ao = {{ key = \"secret\", send_id = 1, recv_id = 1, algorithm = \"md5\" }}\n"
    );
    assert!(matches!(
        parse(&bad_alg).unwrap_err(),
        ConfigError::InvalidNeighborConfig { field, .. } if field == "tcp_ao.algorithm"
    ));
}

#[test]
fn neighbor_tcp_ao_rejects_conflicting_rollover_flags() {
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
tcp_ao = { key = "secret", send_id = 1, recv_id = 1, algorithm = "hmac(sha1)", preferred = true, deprecated = true }
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(matches!(
        err,
        ConfigError::InvalidNeighborConfig { field, .. } if field == "tcp_ao"
    ));
}

#[test]
fn neighbor_tcp_ao_rejects_unknown_field() {
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
tcp_ao = { key = "secret", send_id = 1, recv_id = 1, algorithm = "hmac(sha1)", typo = true }
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(matches!(err, ConfigError::Parse(_)));
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
fn prefix_orf_receive_enabled_on_neighbor() {
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
prefix_orf_receive = true
"#;
    let config = parse(toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert!(peers[0].0.peer.prefix_orf_receive);
}

#[test]
fn prefix_orf_receive_defaults_to_disabled() {
    let config = parse(valid_toml()).unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert!(!peers[0].0.peer.prefix_orf_receive);
}

#[test]
fn prefix_orf_receive_inherited_from_peer_group() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.clients]
prefix_orf_receive = true

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "clients"
"#;
    let config = parse(toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert!(peers[0].0.peer.prefix_orf_receive);
}

#[test]
fn disable_ipv4_unicast_enabled_on_neighbor() {
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
families = ["ipv6_unicast"]
disable_ipv4_unicast = true
"#;
    let config = parse(toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert!(peers[0].0.peer.disable_ipv4_unicast);
}

#[test]
fn disable_ipv4_unicast_defaults_to_disabled() {
    let config = parse(valid_toml()).unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert!(!peers[0].0.peer.disable_ipv4_unicast);
}

#[test]
fn disable_ipv4_unicast_inherited_from_peer_group() {
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.fabric]
families = ["ipv6_unicast"]
disable_ipv4_unicast = true

[[neighbors]]
address = "fd00::2"
remote_asn = 65002
peer_group = "fabric"
"#;
    let config = parse(toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert!(peers[0].0.peer.disable_ipv4_unicast);
}

#[test]
fn disable_ipv4_unicast_neighbor_overrides_group() {
    // Option<bool> resolution: an explicit neighbor `false` wins over the
    // group's `true`.
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.fabric]
families = ["ipv6_unicast"]
disable_ipv4_unicast = true

[[neighbors]]
address = "fd00::2"
remote_asn = 65002
peer_group = "fabric"
disable_ipv4_unicast = false
"#;
    let config = parse(toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert!(!peers[0].0.peer.disable_ipv4_unicast);
}

#[test]
fn disable_ipv4_unicast_rejects_ipv4_only_families() {
    // Explicit ipv4_unicast-only families + the flag is contradictory:
    // nothing could ever be negotiated on the session.
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
families = ["ipv4_unicast"]
disable_ipv4_unicast = true
"#;
    let err = parse(toml_str).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("disable_ipv4_unicast"),
        "error must name the contradictory field, got: {msg}"
    );
}

#[test]
fn disable_ipv4_unicast_rejects_default_ipv4_only_families() {
    // An IPv4 neighbor with no explicit families resolves to the implicit
    // ["ipv4_unicast"] default — also contradictory with the flag.
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
disable_ipv4_unicast = true
"#;
    let err = parse(toml_str).unwrap_err();
    assert!(err.to_string().contains("disable_ipv4_unicast"));
}

#[test]
fn disable_ipv4_unicast_accepts_ipv6_neighbor_default_families() {
    // An IPv6 neighbor's default families are ["ipv4_unicast",
    // "ipv6_unicast"]; the flag simply drops IPv4 from the effective set.
    let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "fd00::2"
remote_asn = 65002
disable_ipv4_unicast = true
"#;
    let config = parse(toml_str).unwrap();
    let peers = config.to_peer_configs().unwrap();
    assert!(peers[0].0.peer.disable_ipv4_unicast);
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

#[test]
fn empty_policy_definition_name_is_rejected() {
    // The empty name is the inline-policy sentinel in the explain
    // surface; a quoted-empty definition key must not collide with it.
    let toml_str = format!(
        r#"
{GLOBAL_HEADER}

[policy.definitions.""]
default_action = "deny"
[[policy.definitions."".statements]]
action = "permit"
prefix = "10.0.0.0/8"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
"#,
        GLOBAL_HEADER = valid_toml()
    );
    let err = parse(&toml_str).unwrap_err();
    assert!(
        matches!(err, ConfigError::InvalidPolicyEntry { .. }),
        "{err:?}"
    );
}

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
role = "route_server"
strict_role = true

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
    assert_eq!(
        resolved.transport_config.peer.local_role,
        Some(BgpRole::RouteServer)
    );
    assert!(resolved.transport_config.peer.strict_role);
    assert_eq!(resolved.peer_group.as_deref(), Some("rs-clients"));
}

#[test]
fn neighbor_values_override_peer_group_defaults() {
    let toml_str = format!(
        r#"
{GLOBAL_HEADER}

[peer_groups.transit]
hold_time = 30
role = "provider"
strict_role = false

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "transit"
hold_time = 45
role = "customer"
strict_role = true
"#,
        GLOBAL_HEADER = valid_toml()
    );
    let config = parse(&toml_str).unwrap();
    let resolved = config.resolve_neighbor(&config.neighbors[1]).unwrap();
    assert_eq!(resolved.transport_config.peer.hold_time, 45);
    assert_eq!(
        resolved.transport_config.peer.local_role,
        Some(BgpRole::Customer)
    );
    assert!(resolved.transport_config.peer.strict_role);
}

#[test]
fn bgp_role_on_ibgp_neighbor_is_rejected() {
    let toml_str = format!(
        r#"
{GLOBAL_HEADER}

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65001
role = "peer"
"#,
        GLOBAL_HEADER = valid_toml()
    );
    let err = parse(&toml_str).unwrap_err();
    match err {
        ConfigError::InvalidNeighborConfig { field, reason, .. } => {
            assert_eq!(field, "role");
            assert!(reason.contains("eBGP"), "unexpected reason: {reason}");
        }
        other => panic!("expected InvalidNeighborConfig, got {other}"),
    }
}

#[test]
fn bgp_role_config_accepts_rfc_aliases() {
    let toml_str = format!(
        r#"
{GLOBAL_HEADER}

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
role = "rs"

[[neighbors]]
address = "10.0.0.4"
remote_asn = 65004
role = "rs-client"
"#,
        GLOBAL_HEADER = valid_toml()
    );
    let config = parse(&toml_str).unwrap();

    let rs = config.resolve_neighbor(&config.neighbors[1]).unwrap();
    let client = config.resolve_neighbor(&config.neighbors[2]).unwrap();
    assert_eq!(
        rs.transport_config.peer.local_role,
        Some(BgpRole::RouteServer)
    );
    assert_eq!(
        client.transport_config.peer.local_role,
        Some(BgpRole::RouteServerClient)
    );
}

#[test]
fn strict_role_without_role_is_rejected() {
    let toml_str = format!(
        r#"
{GLOBAL_HEADER}

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
strict_role = true
"#,
        GLOBAL_HEADER = valid_toml()
    );
    let err = parse(&toml_str).unwrap_err();
    match err {
        ConfigError::InvalidNeighborConfig { field, reason, .. } => {
            assert_eq!(field, "strict_role");
            assert!(
                reason.contains("requires role"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected InvalidNeighborConfig, got {other}"),
    }
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
        interface: None,
        remote_asn: asn,
        description: None,
        peer_group: None,
        hold_time: None,
        max_prefixes: None,
        md5_password: None,
        tcp_ao: None,
        bfd: None,
        ttl_security: Some(false),
        families: Vec::new(),
        graceful_restart: None,
        gr_restart_time: None,
        gr_stale_routes_time: None,
        llgr_stale_time: None,
        local_ipv6_nexthop: None,
        route_reflector_client: Some(false),
        route_server_client: Some(false),
        role: None,
        strict_role: None,
        prefix_orf_receive: None,
        disable_ipv4_unicast: None,
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
    assert_eq!(
        diff.removed[0],
        PeerKey::new("10.0.0.2".parse::<IpAddr>().unwrap(), None)
    );
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
fn diff_neighbors_ignores_tcp_ao_only_changes_because_reload_pins_them() {
    let old = vec![test_neighbor("10.0.0.1", 65001)];
    let mut new_neighbor = test_neighbor("10.0.0.1", 65001);
    new_neighbor.tcp_ao = Some(TcpAoConfig {
        key: "secret".into(),
        send_id: 1,
        recv_id: 1,
        algorithm: "hmac(sha256)".into(),
        preferred: true,
        deprecated: false,
    });

    let diff = super::diff_neighbors(&old, &[new_neighbor]);
    assert!(diff.added.is_empty());
    assert!(diff.removed.is_empty());
    assert!(diff.changed.is_empty());
}

#[test]
fn diff_neighbors_detects_prefix_orf_receive_only_change() {
    // ORF is negotiated in OPEN like add_path / families / role, so it is live
    // config (effective on the next session via the ReconcilePeers delete/re-add
    // path), NOT a startup-pinned resource like tcp_ao / bfd. A bare
    // prefix_orf_receive toggle must therefore surface as a changed neighbor,
    // not a silent no-op (the inverse of the tcp_ao case above).
    let old = vec![test_neighbor("10.0.0.1", 65001)];
    let mut new_neighbor = test_neighbor("10.0.0.1", 65001);
    new_neighbor.prefix_orf_receive = Some(true);

    let diff = super::diff_neighbors(&old, &[new_neighbor]);
    assert!(diff.added.is_empty());
    assert!(diff.removed.is_empty());
    assert_eq!(diff.changed.len(), 1);

    let changes = super::describe_neighbor_changes(&old[0], &diff.changed[0]);
    assert!(
        changes.iter().any(|c| c.contains("prefix_orf_receive")),
        "describe_neighbor_changes must name prefix_orf_receive, got {changes:?}"
    );
}

#[test]
fn diff_neighbors_detects_disable_ipv4_unicast_only_change() {
    // disable_ipv4_unicast is an OPEN-time property like prefix_orf_receive:
    // live config, effective on the next session via ReconcilePeers. A bare
    // toggle must surface as a changed neighbor, not a silent no-op.
    let old = vec![test_neighbor("10.0.0.1", 65001)];
    let mut new_neighbor = test_neighbor("10.0.0.1", 65001);
    new_neighbor.disable_ipv4_unicast = Some(true);

    let diff = super::diff_neighbors(&old, &[new_neighbor]);
    assert!(diff.added.is_empty());
    assert!(diff.removed.is_empty());
    assert_eq!(diff.changed.len(), 1);

    let changes = super::describe_neighbor_changes(&old[0], &diff.changed[0]);
    assert!(
        changes.iter().any(|c| c.contains("disable_ipv4_unicast")),
        "describe_neighbor_changes must name disable_ipv4_unicast, got {changes:?}"
    );
}

#[test]
fn diff_config_flags_tcp_ao_changes_as_restart_required() {
    let mut old = parse(valid_toml()).unwrap();
    old.neighbors[0].tcp_ao = Some(TcpAoConfig {
        key: "old-secret".into(),
        send_id: 1,
        recv_id: 1,
        algorithm: "hmac(sha256)".into(),
        preferred: false,
        deprecated: false,
    });
    let mut new = old.clone();
    new.neighbors[0].tcp_ao = Some(TcpAoConfig {
        key: "new-secret".into(),
        send_id: 1,
        recv_id: 1,
        algorithm: "hmac(sha256)".into(),
        preferred: false,
        deprecated: false,
    });

    let diff = super::diff_config(&old, &new);
    assert!(diff.neighbor_tcp_ao_changed);
    assert!(diff.has_restart_required_changes());
    assert!(!diff.has_reload_applied_changes());

    let json = super::config_diff_json_value(&diff);
    assert_eq!(json["restart_required"]["neighbor_tcp_ao_changed"], true);

    let text = super::format_config_diff_with_style(&diff, &super::ConfigDiffTextStyle::default());
    assert!(text.contains("[[neighbors]].tcp_ao changed"));
    assert!(!text.contains("old-secret"));
    assert!(!text.contains("new-secret"));
}

#[test]
fn resolve_neighbor_threads_policy_explain_settings() {
    // ADR-0073: the resolved-neighbor transport path (used by
    // snapshot-sync gRPC peer adds via PeerManager) must thread the
    // [policy.explain] knobs, not leave them at TransportConfig::new
    // defaults.
    let mut config = parse(valid_toml()).unwrap();
    config.policy.explain.enabled = false;
    config.policy.explain.cache_size = 256;
    let resolved = config.resolve_neighbor(&config.neighbors[0]).unwrap();
    assert!(
        !resolved.transport_config.explain_enabled,
        "enabled must propagate through resolve_neighbor"
    );
    assert_eq!(resolved.transport_config.explain_cache_size, 256);
}

#[test]
fn diff_config_flags_policy_explain_as_restart_required() {
    // ADR-0073: a [policy.explain] edit is restart-required-per-peer and
    // must be visible in `--diff` (JSON + text), not silently dropped.
    let old = parse(valid_toml()).unwrap();
    let mut new = old.clone();
    new.policy.explain.enabled = false;
    new.policy.explain.cache_size = 512;

    let diff = super::diff_config(&old, &new);
    assert!(diff.policy_explain_changed);
    assert!(diff.has_restart_required_changes());
    assert!(
        !diff.has_reload_applied_changes(),
        "an explain-only edit does not hot-apply"
    );

    let json = super::config_diff_json_value(&diff);
    assert_eq!(json["restart_required"]["policy_explain_changed"], true);

    let text = super::format_config_diff_with_style(&diff, &super::ConfigDiffTextStyle::default());
    assert!(text.contains("[policy.explain]"), "{text}");
}

#[test]
fn diff_config_no_policy_explain_change_is_clean() {
    let old = parse(valid_toml()).unwrap();
    let new = old.clone();
    let diff = super::diff_config(&old, &new);
    assert!(!diff.policy_explain_changed);
    assert!(!diff.has_actionable_changes());
}

#[test]
fn diff_config_pins_entire_neighbor_when_tcp_ao_changes() {
    let mut old = parse(valid_toml()).unwrap();
    old.neighbors[0].hold_time = Some(90);
    old.neighbors[0].tcp_ao = Some(TcpAoConfig {
        key: "old-secret".into(),
        send_id: 1,
        recv_id: 1,
        algorithm: "hmac(sha256)".into(),
        preferred: false,
        deprecated: false,
    });
    let mut new = old.clone();
    new.neighbors[0].hold_time = Some(120);
    new.neighbors[0].tcp_ao = Some(TcpAoConfig {
        key: "new-secret".into(),
        send_id: 1,
        recv_id: 1,
        algorithm: "hmac(sha256)".into(),
        preferred: false,
        deprecated: false,
    });

    let diff = super::diff_config(&old, &new);

    assert!(diff.neighbor_tcp_ao_changed);
    assert!(diff.neighbors.changed.is_empty());
    assert!(!diff.has_reload_applied_changes());
    assert!(diff.has_restart_required_changes());
}

#[test]
fn diff_config_pins_tcp_ao_neighbor_dependencies() {
    let old_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[peer_groups.secure]
hold_time = 90
import_policy_chain = ["keep"]

[peer_groups.rs-clients]
hold_time = 60

[policy.neighbor_sets.ixp]
peer_groups = ["rs-clients"]

[[policy.definitions.keep.statements]]
action = "permit"
match_neighbor_set = "ixp"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "secure"
tcp_ao = { key = "old-secret", send_id = 1, recv_id = 1, algorithm = "hmac(sha256)" }
"#;
    let new_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[peer_groups.secure]
hold_time = 90
md5_password = "md5-secret"
import_policy_chain = ["keep"]

[policy.definitions.keep]
default_action = "deny"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "secure"
"#;
    let old = parse(old_toml).unwrap();
    let new = parse(new_toml).unwrap();

    let diff = super::diff_config(&old, &new);

    assert!(diff.neighbor_tcp_ao_changed);
    assert!(diff.peer_groups.changed.is_empty());
    assert!(diff.policy.definitions_changed.is_empty());
    assert!(!diff.has_reload_applied_changes());
    assert!(diff.has_restart_required_changes());
}

#[test]
fn diff_config_pins_removed_tcp_ao_neighbor_dependencies() {
    let old_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[peer_groups.secure]
hold_time = 90
import_policy_chain = ["keep"]

[peer_groups.rs-clients]
hold_time = 60

[policy.neighbor_sets.ixp]
peer_groups = ["rs-clients"]

[[policy.definitions.keep.statements]]
action = "permit"
match_neighbor_set = "ixp"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "secure"
tcp_ao = { key = "old-secret", send_id = 1, recv_id = 1, algorithm = "hmac(sha256)" }
"#;
    let new_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"
"#;
    let old = parse(old_toml).unwrap();
    let mut runtime = parse(new_toml).unwrap();

    let pinned = super::pin_tcp_ao_startup_only_runtime(&mut runtime, &old);

    assert_eq!(pinned, 1);
    assert!(runtime.validate().is_ok());
    assert!(
        runtime
            .neighbors
            .iter()
            .any(|neighbor| neighbor.address == "10.0.0.2"
                && neighbor.peer_group.as_deref() == Some("secure")
                && neighbor.tcp_ao.is_some())
    );
    assert!(runtime.peer_groups.contains_key("secure"));
    assert!(runtime.peer_groups.contains_key("rs-clients"));
    assert!(runtime.policy.definitions.contains_key("keep"));
    assert!(runtime.policy.neighbor_sets.contains_key("ixp"));

    let diff = super::diff_config(&old, &runtime);
    assert!(diff.neighbors.removed.is_empty());
    assert!(diff.peer_groups.removed.is_empty());
    assert!(diff.policy.definitions_removed.is_empty());
    assert!(diff.policy.neighbor_sets_removed.is_empty());
}

#[test]
fn tcp_ao_pinning_preserves_inherited_global_policy_chains() {
    let old_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[policy]
import_chain = ["import-keep"]
export_chain = ["export-keep"]

[policy.definitions.import-keep]
default_action = "permit"

[policy.definitions.export-keep]
default_action = "permit"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
tcp_ao = { key = "old-secret", send_id = 1, recv_id = 1, algorithm = "hmac(sha256)" }
"#;
    let new_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"
"#;
    let old = parse(old_toml).unwrap();
    let mut runtime = parse(new_toml).unwrap();

    let pinned = super::pin_tcp_ao_startup_only_runtime(&mut runtime, &old);

    assert_eq!(pinned, 1);
    assert_eq!(runtime.policy.import_chain, vec!["import-keep"]);
    assert_eq!(runtime.policy.export_chain, vec!["export-keep"]);
    assert!(runtime.policy.definitions.contains_key("import-keep"));
    assert!(runtime.policy.definitions.contains_key("export-keep"));
    assert!(runtime.validate().is_ok());

    let diff = super::diff_config(&old, &runtime);
    assert!(!diff.policy.import_chain_changed);
    assert!(!diff.policy.export_chain_changed);
    assert!(diff.policy.definitions_removed.is_empty());
}

#[test]
fn tcp_ao_pinning_keeps_global_asn_with_removed_rr_neighbor() {
    let old_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65001
route_reflector_client = true
tcp_ao = { key = "old-secret", send_id = 1, recv_id = 1, algorithm = "hmac(sha256)" }
"#;
    let new_toml = r#"
[global]
asn = 65002
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"
"#;
    let old = parse(old_toml).unwrap();
    let mut runtime = parse(new_toml).unwrap();

    let pinned = super::pin_tcp_ao_startup_only_runtime(&mut runtime, &old);

    assert_eq!(pinned, 1);
    assert_eq!(runtime.global.asn, 65001);
    assert!(runtime.validate().is_ok());
    assert!(runtime.neighbors.iter().any(|neighbor| {
        neighbor.address == "10.0.0.2"
            && neighbor.remote_asn == 65001
            && neighbor.route_reflector_client == Some(true)
            && neighbor.tcp_ao.is_some()
    }));
}

#[test]
fn tcp_ao_pinning_keeps_global_asn_with_rotated_rr_neighbor() {
    let old_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65001
route_reflector_client = true
tcp_ao = { key = "old-secret", send_id = 1, recv_id = 1, algorithm = "hmac(sha256)" }
"#;
    let new_toml = r#"
[global]
asn = 65002
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
route_reflector_client = true
tcp_ao = { key = "new-secret", send_id = 2, recv_id = 2, algorithm = "hmac(sha256)" }
"#;
    let old = parse(old_toml).unwrap();
    let mut runtime = parse(new_toml).unwrap();

    let pinned = super::pin_tcp_ao_startup_only_runtime(&mut runtime, &old);

    assert_eq!(pinned, 1);
    assert_eq!(runtime.global.asn, 65001);
    assert!(runtime.validate().is_ok());
    let neighbor = runtime
        .neighbors
        .iter()
        .find(|neighbor| neighbor.address == "10.0.0.2")
        .expect("pinned neighbor restored");
    assert_eq!(neighbor.remote_asn, 65001);
    assert_eq!(
        neighbor.tcp_ao.as_ref().map(|tcp_ao| tcp_ao.key.as_str()),
        Some("old-secret")
    );
}

#[test]
fn diff_config_preserves_unrelated_policy_diff_when_tcp_ao_neighbor_is_pinned() {
    let old_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
tcp_ao = { key = "old-secret", send_id = 1, recv_id = 1, algorithm = "hmac(sha256)" }
"#;
    let new_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
log_format = "json"

[[policy.import]]
action = "permit"
prefix = "10.0.0.0/8"

[policy.definitions.unrelated]
default_action = "permit"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
"#;
    let old = parse(old_toml).unwrap();
    let new = parse(new_toml).unwrap();

    let diff = super::diff_config(&old, &new);

    assert!(diff.neighbor_tcp_ao_changed);
    assert!(diff.policy.import_changed);
    assert_eq!(diff.policy.definitions_added, vec!["unrelated"]);
    assert!(diff.has_reload_applied_changes());
    assert!(diff.has_restart_required_changes());
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "fixture-heavy TCP-AO pinning regression"
)]
fn tcp_ao_pinning_keeps_new_unprotected_neighbor_peer_group_valid() {
    let old = parse(valid_toml()).unwrap();
    let mut new = old.clone();
    new.peer_groups.insert(
        "new-group".to_string(),
        PeerGroupConfig {
            hold_time: Some(60),
            max_prefixes: None,
            md5_password: None,
            ttl_security: None,
            bfd: None,
            families: Vec::new(),
            graceful_restart: None,
            gr_restart_time: None,
            gr_stale_routes_time: None,
            llgr_stale_time: None,
            local_ipv6_nexthop: None,
            route_reflector_client: None,
            route_server_client: None,
            role: None,
            strict_role: None,
            prefix_orf_receive: None,
            disable_ipv4_unicast: None,
            remove_private_as: None,
            add_path: None,
            log_level: None,
            import_policy: Vec::new(),
            export_policy: Vec::new(),
            import_policy_chain: Vec::new(),
            export_policy_chain: Vec::new(),
        },
    );
    new.neighbors.push(Neighbor {
        address: "10.0.0.3".into(),
        interface: None,
        remote_asn: 65003,
        description: None,
        peer_group: Some("new-group".into()),
        hold_time: None,
        max_prefixes: None,
        md5_password: None,
        bfd: None,
        tcp_ao: Some(TcpAoConfig {
            key: "secret".into(),
            send_id: 1,
            recv_id: 1,
            algorithm: "hmac(sha256)".into(),
            preferred: false,
            deprecated: false,
        }),
        ttl_security: None,
        families: Vec::new(),
        graceful_restart: None,
        gr_restart_time: None,
        gr_stale_routes_time: None,
        llgr_stale_time: None,
        local_ipv6_nexthop: None,
        route_reflector_client: None,
        route_server_client: None,
        role: None,
        strict_role: None,
        prefix_orf_receive: None,
        disable_ipv4_unicast: None,
        remove_private_as: None,
        add_path: None,
        import_policy: Vec::new(),
        export_policy: Vec::new(),
        import_policy_chain: Vec::new(),
        export_policy_chain: Vec::new(),
        log_level: None,
    });
    new.neighbors.push(Neighbor {
        address: "10.0.0.4".into(),
        interface: None,
        remote_asn: 65004,
        description: None,
        peer_group: Some("new-group".into()),
        hold_time: None,
        max_prefixes: None,
        md5_password: None,
        tcp_ao: None,
        bfd: None,
        ttl_security: None,
        families: Vec::new(),
        graceful_restart: None,
        gr_restart_time: None,
        gr_stale_routes_time: None,
        llgr_stale_time: None,
        local_ipv6_nexthop: None,
        route_reflector_client: None,
        route_server_client: None,
        role: None,
        strict_role: None,
        prefix_orf_receive: None,
        disable_ipv4_unicast: None,
        remove_private_as: None,
        add_path: None,
        import_policy: Vec::new(),
        export_policy: Vec::new(),
        import_policy_chain: Vec::new(),
        export_policy_chain: Vec::new(),
        log_level: None,
    });

    let pinned = super::pin_tcp_ao_startup_only_runtime(&mut new, &old);

    assert_eq!(pinned, 1);
    assert!(new.validate().is_ok());
    assert!(new.neighbors.iter().any(|neighbor| {
        neighbor.address == "10.0.0.4" && neighbor.peer_group.as_deref() == Some("new-group")
    }));
    assert!(
        new.neighbors
            .iter()
            .all(|neighbor| neighbor.address != "10.0.0.3")
    );
}

#[test]
fn diff_config_does_not_mark_tcp_ao_neighbor_add_as_reload_applied() {
    let old = parse(valid_toml()).unwrap();
    let mut new = old.clone();
    new.neighbors.push(Neighbor {
        address: "10.0.0.3".into(),
        interface: None,
        remote_asn: 65003,
        description: None,
        peer_group: None,
        hold_time: None,
        max_prefixes: None,
        md5_password: None,
        bfd: None,
        tcp_ao: Some(TcpAoConfig {
            key: "secret".into(),
            send_id: 1,
            recv_id: 1,
            algorithm: "hmac(sha256)".into(),
            preferred: false,
            deprecated: false,
        }),
        ttl_security: None,
        families: Vec::new(),
        graceful_restart: None,
        gr_restart_time: None,
        gr_stale_routes_time: None,
        llgr_stale_time: None,
        local_ipv6_nexthop: None,
        route_reflector_client: None,
        route_server_client: None,
        role: None,
        strict_role: None,
        prefix_orf_receive: None,
        disable_ipv4_unicast: None,
        remove_private_as: None,
        add_path: None,
        import_policy: Vec::new(),
        export_policy: Vec::new(),
        import_policy_chain: Vec::new(),
        export_policy_chain: Vec::new(),
        log_level: None,
    });

    let diff = super::diff_config(&old, &new);

    assert!(diff.neighbor_tcp_ao_changed);
    assert!(diff.neighbors.added.is_empty());
    assert!(!diff.has_reload_applied_changes());
    assert!(diff.has_restart_required_changes());
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
fn describe_neighbor_changes_hides_tcp_ao_key() {
    let old = test_neighbor("10.0.0.1", 65001);
    let mut new = old.clone();
    new.tcp_ao = Some(TcpAoConfig {
        key: "secret".into(),
        send_id: 1,
        recv_id: 1,
        algorithm: "hmac(sha256)".into(),
        preferred: true,
        deprecated: false,
    });

    let changes = super::describe_neighbor_changes(&old, &new);
    assert_eq!(
        changes,
        vec!["tcp_ao: <changed restart-required>".to_string()]
    );
}

#[test]
fn tcp_ao_debug_redacts_key() {
    let tcp_ao = TcpAoConfig {
        key: "secret".into(),
        send_id: 1,
        recv_id: 1,
        algorithm: "hmac(sha256)".into(),
        preferred: false,
        deprecated: false,
    };

    let rendered = format!("{tcp_ao:?}");

    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains("secret"));
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
fn diff_config_role_change_is_reload_applied() {
    let old = parse(valid_toml()).unwrap();
    let new_toml = valid_toml().replace(
        "hold_time = 90\n",
        "hold_time = 90\nrole = \"provider\"\nstrict_role = true\n",
    );
    let new = parse(&new_toml).unwrap();
    let diff = super::diff_config(&old, &new);

    assert!(
        diff.has_reload_applied_changes(),
        "PeerManager applies Role capability changes by reconfiguring the peer session"
    );
    assert!(
        diff.neighbors
            .changed
            .iter()
            .any(|summary| summary.address == "10.0.0.2"
                && summary.changes.iter().any(|change| change.contains("role"))
                && summary
                    .changes
                    .iter()
                    .any(|change| change.contains("strict_role"))),
        "neighbor details must explain role/strict_role drift: {:?}",
        diff.neighbors.changed
    );
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
fn dynamic_neighbor_peer_group_with_bfd_rejected() {
    // v1 BFD is static-neighbors only (ADR-0067). A dynamic range whose peer
    // group enables BFD must be rejected so the operator isn't misled into
    // thinking dynamic peers are BFD-protected.
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[bfd_profiles]]
name = "fast"

[peer_groups.ix-members]
hold_time = 90
bfd = { profile = "fast" }

[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "ix-members"
"#;
    let err = parse(toml).unwrap_err();
    assert!(
        err.to_string()
            .contains("BFD is not supported for dynamic neighbors"),
        "unexpected error: {err}"
    );

    // The same group with BFD explicitly disabled is accepted.
    let ok = toml.replace(
        r#"bfd = { profile = "fast" }"#,
        r#"bfd = { profile = "fast", enabled = false }"#,
    );
    assert!(
        parse(&ok).is_ok(),
        "explicitly-disabled BFD should be allowed"
    );
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
fn dynamic_neighbor_duplicate_effective_prefix_rejected() {
    // 10.0.0.0/24 and 10.0.0.9/24 both normalize to 10.0.0.0/24 — ambiguous.
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.g]
families = ["ipv4_unicast"]

[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "g"

[[dynamic_neighbors]]
prefix = "10.0.0.9/24"
peer_group = "g"
"#;
    let err = parse(toml).unwrap_err();
    assert!(
        err.to_string().contains("duplicate effective prefix"),
        "{err}"
    );
}

#[test]
fn dynamic_neighbor_overlapping_different_lengths_allowed() {
    // Overlapping ranges of DIFFERENT lengths are fine — longest-prefix-match
    // resolves them at accept time, so this must NOT be rejected.
    let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.g]
families = ["ipv4_unicast"]

[[dynamic_neighbors]]
prefix = "10.0.0.0/16"
peer_group = "g"

[[dynamic_neighbors]]
prefix = "10.0.5.0/24"
peer_group = "g"
"#;
    parse(toml).expect("overlapping ranges of different lengths are allowed");
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
fn evpn_instance_auto_derives_route_target() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
auto_derive_route_target = true
local_vtep_ip = "10.0.0.100"
"#,
    );
    let config = parse(&toml).unwrap();
    let table = config.resolve_evpn_instances().unwrap();
    let inst = table.sorted()[0];
    assert_eq!(
        inst.route_targets
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        vec!["65000:268435556"]
    );
}

#[test]
fn evpn_instance_auto_derives_and_preserves_explicit_route_targets() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100", "65000:268435556"]
auto_derive_route_target = true
local_vtep_ip = "10.0.0.100"
"#,
    );
    let config = parse(&toml).unwrap();
    let table = config.resolve_evpn_instances().unwrap();
    let inst = table.sorted()[0];
    assert_eq!(
        inst.route_targets
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        vec!["65000:100", "65000:268435556"],
        "explicit RTs are preserved and the derived RT is deduped"
    );
}

#[test]
fn evpn_instance_auto_derive_rejects_four_octet_asn() {
    let toml = r#"
[global]
asn = 4200000000
router_id = "10.0.0.100"
listen_port = 179

[global.telemetry]
prometheus_addr = "127.0.0.1:9179"
log_format = "json"

[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
auto_derive_route_target = true
local_vtep_ip = "10.0.0.100"
"#;
    let err = parse(toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("auto_derive_route_target")
            && msg.contains("2-octet AS")
            && msg.contains("route_targets manually"),
        "msg must explain the 4-octet ASN limitation: {msg}"
    );
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
fn evpn_instance_rejects_missing_route_targets_without_auto_derive() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
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
fn evpn_instance_single_add_diff_marks_reload_applied() {
    let without_evi = parse(&evpn_toml_with("")).unwrap();
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

    let added = diff_config(&without_evi, &with_evi);
    assert!(added.evpn_instances_changed);
    assert_eq!(
        added.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadApplied
    );
    assert!(added.has_reload_applied_changes());
    assert!(!added.has_restart_required_changes());

    let removed = diff_config(&with_evi, &without_evi);
    assert!(removed.evpn_instances_changed);
    assert_eq!(
        removed.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadApplied
    );
    assert!(removed.has_reload_applied_changes());
    assert!(!removed.has_restart_required_changes());

    let json = config_diff_json_value(&added);
    assert_eq!(json["evpn_runtime_change_class"], "reload_applied");
    assert_eq!(json["reload_applied"]["evpn_runtime_changed"], true);
    assert_eq!(json["reload_applied"]["evpn_instances_changed"], true);
    assert_eq!(json["restart_required"]["evpn_instances_changed"], false);
    let text = format_config_diff(&added);
    assert!(
        text.contains("EVPN runtime model hot-applied through the ADR-0063 coordinator"),
        "expected EVPN runtime reload-applied text, got:\n{text}"
    );
    assert!(
        !text.contains("[[evpn_instances]] changed"),
        "supported EVPN runtime shape must not be listed as restart-required:\n{text}"
    );

    // No-op: same config on both sides ⇒ not flagged.
    let same = diff_config(&with_evi, &with_evi);
    assert!(!same.evpn_instances_changed);
    assert_eq!(
        same.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::Unchanged
    );
}

#[test]
fn evpn_instance_standalone_swap_diff_marks_reload_applied() {
    let old = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
"#,
    ))
    .unwrap();
    let new = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 200
rd = "10.0.0.100:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.100"
"#,
    ))
    .unwrap();
    let diff = diff_config(&old, &new);

    assert!(diff.evpn_instances_changed);
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadApplied
    );
    assert!(diff.has_reload_applied_changes());
    assert!(!diff.has_restart_required_changes());
    let json = config_diff_json_value(&diff);
    assert_eq!(json["evpn_runtime_change_class"], "reload_applied");
    assert_eq!(json["reload_applied"]["evpn_runtime_changed"], true);
    assert_eq!(json["restart_required"]["evpn_instances_changed"], false);
}

#[test]
fn evpn_instance_swap_with_es_member_delete_stays_restart_required() {
    let old = parse(&evpn_toml_with(
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

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.100"
"#,
    ))
    .unwrap();
    let new = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 200
rd = "10.0.0.100:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.100"

[[evpn_instances]]
vni = 300
rd = "10.0.0.100:300"
route_targets = ["65000:300"]
local_vtep_ip = "10.0.0.100"
"#,
    ))
    .unwrap();
    let diff = diff_config(&old, &new);

    assert!(diff.evpn_instances_changed);
    assert!(diff.ethernet_segments_changed);
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::RestartRequired
    );
    assert!(!diff.has_reload_applied_changes());
    assert!(diff.has_restart_required_changes());
}

#[test]
fn evpn_instance_swap_with_ip_vrf_link_marks_reload_applied() {
    let old = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[evpn_instances]]
vni = 200
rd = "10.0.0.100:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "10.0.0.100:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
    ))
    .unwrap();
    let new = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[evpn_instances]]
vni = 300
rd = "10.0.0.100:300"
route_targets = ["65000:300"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "10.0.0.100:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
    ))
    .unwrap();
    let diff = diff_config(&old, &new);

    assert!(diff.evpn_instances_changed);
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadApplied
    );
    assert!(diff.has_reload_applied_changes());
    assert!(!diff.has_restart_required_changes());
    let json = config_diff_json_value(&diff);
    assert_eq!(json["evpn_runtime_change_class"], "reload_applied");
    assert_eq!(json["reload_applied"]["evpn_runtime_changed"], true);
    assert_eq!(json["restart_required"]["evpn_instances_changed"], false);
}

#[test]
fn evpn_instance_linked_swap_with_ip_vrf_identity_change_stays_restart_required() {
    // A linked L2VNI swap hot-applies, but only when the referenced IP-VRF
    // *row* is unchanged. Pin the boundary this slice moved: a swap that also
    // flips an IP-VRF identity field (here table_id) must fail closed to
    // restart-required, never riding the reload-applied swap path.
    let old = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[evpn_instances]]
vni = 200
rd = "10.0.0.100:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "10.0.0.100:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
    ))
    .unwrap();
    let new = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[evpn_instances]]
vni = 300
rd = "10.0.0.100:300"
route_targets = ["65000:300"]
local_vtep_ip = "10.0.0.100"
ip_vrf = "tenant-blue"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "10.0.0.100:5000"
route_targets = ["65000:5000"]
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5001
"#,
    ))
    .unwrap();
    let diff = diff_config(&old, &new);

    assert!(diff.evpn_instances_changed);
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::RestartRequired
    );
    assert!(!diff.has_reload_applied_changes());
    assert!(diff.has_restart_required_changes());
    let json = config_diff_json_value(&diff);
    assert_eq!(json["evpn_runtime_change_class"], "restart_required");
    assert_eq!(json["reload_applied"]["evpn_runtime_changed"], false);
    assert_eq!(json["restart_required"]["evpn_instances_changed"], true);
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
fn evpn_sticky_macs_diff_marks_reload_applied() {
    // Adding sticky_macs to an existing instance is a single L2VNI
    // redefine. The ADR-0063 runtime coordinator can reconfigure that
    // shape live, so `--diff` must not leave it in the old
    // restart-required bucket.
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
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadApplied
    );
    assert!(diff.has_reload_applied_changes());
    assert!(!diff.has_restart_required_changes());
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
fn evpn_duplicate_mac_detection_rejects_invalid_values() {
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
fn evpn_duplicate_mac_detection_diff_marks_reload_applied() {
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
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadApplied
    );
    assert!(diff.has_reload_applied_changes());
    assert!(!diff.has_restart_required_changes());
}

#[test]
fn ethernet_segment_add_diff_marks_reload_applied() {
    let old = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
"#,
    ))
    .unwrap();
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
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadApplied
    );
    assert!(diff.has_reload_applied_changes());
    assert!(!diff.has_restart_required_changes());
}

#[test]
fn ethernet_segment_binding_only_diff_marks_reload_applied() {
    let old_toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.100"
"#,
    );
    let new_toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "10.0.0.100:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.100"
interface = "eth2"
recovery_delay_secs = 7
"#,
    );
    let old = parse(&old_toml).unwrap();
    let new = parse(&new_toml).unwrap();
    let diff = diff_config(&old, &new);

    assert!(diff.ethernet_segments_changed);
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadApplied
    );
    assert!(diff.has_reload_applied_changes());
    assert!(!diff.has_restart_required_changes());
}

#[test]
fn evpn_ip_vrf_add_diff_marks_reload_applied() {
    let old = parse(&evpn_toml_with("")).unwrap();
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
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadApplied
    );
    assert!(diff.has_reload_applied_changes());
    assert!(!diff.has_restart_required_changes());
}

#[test]
fn evpn_ip_vrf_identity_redefine_diff_marks_restart_required() {
    let old_toml = evpn_toml_with(
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
table_id = 5001
"#,
    );
    let old = parse(&old_toml).unwrap();
    let new = parse(&new_toml).unwrap();
    let diff = diff_config(&old, &new);

    assert!(diff.evpn_ip_vrfs_changed);
    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::RestartRequired
    );
    assert!(!diff.has_reload_applied_changes());
    assert!(diff.has_restart_required_changes());
}

#[test]
fn apply_bum_enforcement_default_is_true() {
    // Pinned by the v0.23.0 production-default flip after the
    // Gate 8b 24h MAC-churn soak (2026-05-16, postmortem
    // `docs/soak-gate8b-mac-churn-24h.md`) and the M37
    // local-origination 24h soak (2026-05-19, postmortem
    // `docs/soak-m37-local-origination-churn-24h.md`) both passed
    // clean. If this regresses to `false` without a deliberate
    // schema change, the production posture has silently rolled back.
    let config = parse(valid_toml()).unwrap();
    assert!(
        config.apply_bum_enforcement,
        "apply_bum_enforcement default flipped to true in v0.23.0; \
         regression would silently restore observe-only behavior"
    );
}

#[test]
fn apply_bum_enforcement_honors_explicit_false() {
    // Operators who need the prior observe-only posture must still
    // be able to opt out explicitly after the default flip.
    let toml = format!("apply_bum_enforcement = false\n{}", valid_toml());
    let config = parse(&toml).unwrap();
    assert!(
        !config.apply_bum_enforcement,
        "explicit `apply_bum_enforcement = false` must be honored \
         after the v0.23.0 default flip"
    );
}

#[test]
fn apply_bum_enforcement_diff_marks_restart_required() {
    // Default is now true, so the diff has to be driven by an
    // explicit opt-out on the new side.
    let old = parse(valid_toml()).unwrap();
    let new_toml = format!("apply_bum_enforcement = false\n{}", valid_toml());
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
maximum_paths = 4
"#,
        valid_toml()
    );
    let config = parse(&toml).unwrap();
    let table = &config.fib_tables[0];

    assert_eq!(table.allowed_peer_groups, ["transit"]);
    assert_eq!(table.allowed_neighbors, ["198.51.100.1", "2001:db8::1"]);
    assert_eq!(table.max_routes, Some(1000));
    assert_eq!(table.maximum_paths, Some(4));
}

#[test]
fn fib_tables_maximum_paths_defaults_to_none() {
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
    assert_eq!(config.fib_tables[0].maximum_paths, None);
}

#[test]
fn multipath_relax_parses_and_defaults_false() {
    // ADR-0066 multipath-relax is a global best-path knob, default off.
    let base = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"
"#;
    assert!(
        !parse(base).unwrap().global.multipath_relax,
        "multipath_relax defaults to false"
    );
    let on = base.replace(
        "listen_port = 179",
        "listen_port = 179\nmultipath_relax = true",
    );
    assert!(parse(&on).unwrap().global.multipath_relax);
}

#[test]
fn link_bandwidth_weighted_parses_and_defaults_false() {
    // ADR-0068 weighted multipath is a global best-path knob, default off.
    let base = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
[global.telemetry]
log_format = "json"
"#;
    assert!(
        !parse(base).unwrap().global.link_bandwidth_weighted,
        "link_bandwidth_weighted defaults to false"
    );
    let on = base.replace(
        "listen_port = 179",
        "listen_port = 179\nlink_bandwidth_weighted = true",
    );
    assert!(parse(&on).unwrap().global.link_bandwidth_weighted);
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
        (
            r"maximum_paths = 0",
            "maximum_paths must be greater than zero",
        ),
        (r"maximum_paths = 9999", "exceeds the supported cap"),
        (
            r"maximum_paths_ebgp = 0",
            "maximum_paths_ebgp must be greater than zero",
        ),
        (
            r"maximum_paths_ibgp = 9999",
            "maximum_paths_ibgp 9999 exceeds the supported cap",
        ),
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
fn fib_tables_per_class_maximum_paths_round_trip() {
    let toml = format!(
        r#"
{}

[[fib_tables]]
name = "edge"
table_id = 1000
metric = 200
maximum_paths = 2
maximum_paths_ebgp = 4
maximum_paths_ibgp = 8
"#,
        valid_toml()
    );
    let t = &parse(&toml).unwrap().fib_tables[0];
    assert_eq!(t.maximum_paths, Some(2));
    assert_eq!(t.maximum_paths_ebgp, Some(4));
    assert_eq!(t.maximum_paths_ibgp, Some(8));
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
fn bfd_profiles_parse_and_neighbor_reference() {
    let toml = format!(
        r#"
{}

[[bfd_profiles]]
name = "fast"
min_tx_interval = 250
min_rx_interval = 250
multiplier = 4

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
bfd = {{ profile = "fast", strict = true }}
"#,
        valid_toml()
    );
    let config = parse(&toml).unwrap();
    assert_eq!(config.bfd_profiles.len(), 1);
    assert_eq!(config.bfd_profiles[0].min_tx_interval, 250);
    assert_eq!(config.bfd_profiles[0].multiplier, 4);
    let n = config
        .neighbors
        .iter()
        .find(|n| n.address == "10.0.0.3")
        .unwrap();
    let bfd = n.bfd.as_ref().unwrap();
    assert_eq!(bfd.profile, "fast");
    assert!(bfd.strict);
}

#[test]
fn bfd_profile_defaults_are_300_300_3() {
    let toml = format!(
        r#"
{}

[[bfd_profiles]]
name = "p"
"#,
        valid_toml()
    );
    let p = &parse(&toml).unwrap().bfd_profiles[0];
    assert_eq!(
        (p.min_tx_interval, p.min_rx_interval, p.multiplier),
        (300, 300, 3)
    );
}

#[test]
fn bfd_rejects_invalid_profiles() {
    let cases = [
        ("name = \"p\"\nmin_tx_interval = 50", "must be >= 100"),
        ("name = \"p\"\nmultiplier = 1", "multiplier must be >= 2"),
        // Upper bounds: out-of-range values must be rejected, not silently
        // clamped by the actor's u8 / microsecond conversions.
        (
            "name = \"p\"\nmultiplier = 1000",
            "multiplier must be <= 255",
        ),
        ("name = \"p\"\nmin_rx_interval = 5000000", "must be <= "),
        (
            "name = \"dup\"\n\n[[bfd_profiles]]\nname = \"dup\"",
            "duplicate bfd_profile",
        ),
    ];
    for (body, expected) in cases {
        let toml = format!("{}\n\n[[bfd_profiles]]\n{body}\n", valid_toml());
        let err = parse(&toml).unwrap_err();
        let ConfigError::InvalidBfd { reason } = err else {
            panic!("expected InvalidBfd, got {err}");
        };
        assert!(
            reason.contains(expected),
            "expected {expected:?} in {reason:?}"
        );
    }
}

#[test]
fn bfd_rejects_undefined_profile_reference() {
    let toml = format!(
        r#"
{}

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
bfd = {{ profile = "nope" }}
"#,
        valid_toml()
    );
    let err = parse(&toml).unwrap_err();
    let ConfigError::InvalidBfd { reason } = err else {
        panic!("expected InvalidBfd, got {err}");
    };
    assert!(reason.contains("not defined"), "unexpected: {reason}");
}

#[test]
fn fib_tables_diff_marks_reload_applied() {
    // N→M edit: a table already exists at startup (so the reconciler is live),
    // and the new config tweaks it. These hot-apply via SIGHUP / gRPC
    // (`FibRuntimeCommand::ReplaceTables`), so the static diff classifies them
    // reload-applied, not restart-required.
    let with_table = |metric: u32| {
        format!(
            r#"
{}

[[fib_tables]]
name = "edge"
table_id = 1000
metric = {metric}
"#,
            valid_toml()
        )
    };
    let old = parse(&with_table(200)).unwrap();
    let new = parse(&with_table(250)).unwrap();
    let diff = diff_config(&old, &new);

    assert!(diff.fib_tables_changed);
    assert!(!diff.fib_tables_requires_restart);
    assert!(diff.has_reload_applied_changes());
    assert!(!diff.has_restart_required_changes());
}

#[test]
fn fib_tables_diff_from_empty_marks_restart_required() {
    // 0→N: no tables at startup means the reconciler was never spawned, so
    // SIGHUP cannot hot-start it — `src/reload.rs` rejects this as
    // restart-required. The static diff knows the empty-startup case (even
    // though it can't predict a netlink spawn failure), so it must match the
    // runtime and classify 0→N restart-required, not reload-applied.
    let old = parse(valid_toml()).unwrap();
    let new_toml = format!(
        r#"
{}

[[fib_tables]]
name = "edge"
table_id = 1000
metric = 200
"#,
        valid_toml()
    );
    let new = parse(&new_toml).unwrap();
    let diff = diff_config(&old, &new);

    assert!(diff.fib_tables_changed);
    assert!(diff.fib_tables_requires_restart);
    assert!(diff.has_restart_required_changes());
    assert!(!diff.has_reload_applied_changes());
}

#[test]
fn dynamic_neighbors_diff_marks_reload_applied() {
    let old_toml = format!(
        r#"
{}

[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
"#,
        valid_toml()
    );
    let new_toml = format!(
        r#"
{}

[peer_groups.ix-members]

[[dynamic_neighbors]]
prefix = "192.0.3.0/24"
peer_group = "ix-members"
"#,
        valid_toml()
    );
    let old = parse(&old_toml).unwrap();
    let new = parse(&new_toml).unwrap();
    let diff = diff_config(&old, &new);
    let json = config_diff_json_value(&diff);
    let text = format_config_diff(&diff);

    assert!(diff.dynamic_neighbors_changed);
    assert!(diff.has_reload_applied_changes());
    assert!(!diff.has_restart_required_changes());
    assert_eq!(
        json["reload_applied"]["dynamic_neighbors_changed"],
        serde_json::Value::Bool(true)
    );
    assert!(text.contains("[[dynamic_neighbors]] matcher rebuilt"));
}

#[test]
fn transaction_v1_classifies_noop_candidate() {
    let config = parse(valid_toml()).unwrap();
    let diff = diff_config(&config, &config);
    let class = classify_config_transaction_v1(&diff);

    assert!(class.is_noop());
    assert!(!class.is_committable());
}

#[test]
fn transaction_v1_classifies_supported_runtime_sections() {
    let with_table = |table_id: u32| {
        format!(
            r#"
{}

[peer_groups.ix-members]

[[neighbors]]
address = "10.0.0.99"
remote_asn = 65099

[[fib_tables]]
name = "edge"
table_id = {table_id}
metric = 200

[[dynamic_neighbors]]
prefix = "192.0.2.0/24"
peer_group = "ix-members"
"#,
            valid_toml()
        )
    };
    let old = parse(&with_table(1000)).unwrap();
    let new_toml = format!(
        r#"
{}

[peer_groups.ix-members]

[[neighbors]]
address = "10.0.0.100"
remote_asn = 65100

[[fib_tables]]
name = "edge"
table_id = 1001
metric = 200

[[dynamic_neighbors]]
prefix = "192.0.3.0/24"
peer_group = "ix-members"
"#,
        valid_toml()
    );
    let new = parse(&new_toml).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(!class.is_committable());
    assert_eq!(
        class.supported_sections,
        vec![
            "[[neighbors]] add",
            "[[neighbors]] delete",
            "[[dynamic_neighbors]]",
            "[[fib_tables]]",
        ]
    );
    assert_eq!(
        class.unsupported_sections,
        vec!["mixed transaction families"]
    );
    assert!(class.restart_required_sections.is_empty());
}

#[test]
fn transaction_v1_classifies_evpn_runtime_shape_as_unsupported_coordinator() {
    let old = parse(&evpn_toml_with("")).unwrap();
    let new = parse(&evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"
"#,
    ))
    .unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert_eq!(
        diff.evpn_runtime_change_class,
        EvpnRuntimeChangeClass::ReloadApplied
    );
    assert!(!class.is_committable());
    assert!(class.supported_sections.is_empty(), "{class:?}");
    assert_eq!(class.unsupported_sections, vec!["EVPN runtime coordinator"]);
    assert!(class.restart_required_sections.is_empty(), "{class:?}");
}

#[test]
fn transaction_v1_classifies_static_neighbor_add_delete_as_one_family() {
    let old_toml = format!(
        r#"
{}

[[neighbors]]
address = "10.0.0.99"
remote_asn = 65099
"#,
        valid_toml()
    );
    let new_toml = format!(
        r#"
{}

[[neighbors]]
address = "10.0.0.100"
remote_asn = 65100
"#,
        valid_toml()
    );
    let old = parse(&old_toml).unwrap();
    let new = parse(&new_toml).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(class.is_committable());
    assert_eq!(
        class.supported_sections,
        vec!["[[neighbors]] add", "[[neighbors]] delete"]
    );
    assert!(class.unsupported_sections.is_empty());
    assert!(class.restart_required_sections.is_empty());
}

#[test]
fn transaction_v1_rejects_unsupported_reload_sections() {
    let old_toml = format!(
        r#"
{}

[peer_groups.ix-members]
hold_time = 90

[[neighbors]]
address = "10.0.0.101"
remote_asn = 65101
hold_time = 90
peer_group = "ix-members"
"#,
        valid_toml()
    );
    let new_toml = format!(
        r#"
{}

[peer_groups.ix-members]
hold_time = 120

[[neighbors]]
address = "10.0.0.101"
remote_asn = 65101
hold_time = 120
peer_group = "ix-members"
"#,
        valid_toml()
    );
    let old = parse(&old_toml).unwrap();
    let new = parse(&new_toml).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(!class.is_committable());
    assert_eq!(
        class.supported_sections,
        vec![
            "[[neighbors]] modify",
            "[peer_groups] catalog",
            "effective neighbor session reshape",
        ]
    );
    assert!(
        class
            .unsupported_sections
            .contains(&"mixed transaction families".to_string())
    );
    assert!(class.restart_required_sections.is_empty());
}

#[test]
fn transaction_v1_classifies_catalog_only_policy_and_peer_group_changes() {
    let old = parse(valid_toml()).unwrap();
    let new_toml = format!(
        r#"
{}

[peer_groups.unused]
hold_time = 120

[policy.neighbor_sets.ixp]
addresses = ["10.0.0.2"]

[policy.definitions.prep-only]
default_action = "permit"
"#,
        valid_toml()
    );
    let new = parse(&new_toml).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(class.is_committable());
    assert_eq!(
        class.supported_sections,
        vec![
            "[policy] definitions",
            "[policy] neighbor_sets",
            "[peer_groups] catalog",
        ]
    );
    assert!(class.unsupported_sections.is_empty());
    assert!(class.restart_required_sections.is_empty());
    assert!(
        diff.effective_neighbor_impact.is_empty(),
        "catalog-only changes must not affect existing neighbors"
    );
}

#[test]
fn transaction_v1_classifies_catalog_only_global_chain_without_neighbors() {
    let old_toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[security.grpc]
enforcement = "legacy"
"#;
    let new_toml = format!(
        r#"
{old_toml}

[policy]
import_chain = ["prep-only"]

[policy.definitions.prep-only]
default_action = "permit"
"#
    );
    let old = parse(old_toml).unwrap();
    let new = parse(&new_toml).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(class.is_committable());
    assert_eq!(
        class.supported_sections,
        vec!["[policy] definitions", "[policy] global chains"]
    );
    assert!(class.unsupported_sections.is_empty());
    assert!(class.restart_required_sections.is_empty());
}

#[test]
fn transaction_v1_classifies_static_neighbor_policy_chain_move_as_live_impact() {
    // A policy-definition edit referenced via a static neighbor's import chain
    // moves that neighbor's resolved import policy with no transport/peer-group
    // reshape — committable by the live-impact executor (re-apply in place).
    let with_policy = |default_action: &str| {
        format!(
            r#"
{}

[policy.definitions.import-filter]
default_action = "{default_action}"
"#,
            valid_toml().replace(
                "hold_time = 90",
                "hold_time = 90\nimport_policy_chain = [\"import-filter\"]",
            )
        )
    };
    let old = parse(&with_policy("permit")).unwrap();
    let new = parse(&with_policy("deny")).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(class.is_committable(), "{class:?}");
    assert_eq!(
        class.supported_sections,
        vec!["[policy] definitions", "[policy] live impact"]
    );
    assert!(class.unsupported_sections.is_empty(), "{class:?}");
    assert!(class.restart_required_sections.is_empty());
    assert!(
        diff.effective_neighbor_impact
            .iter()
            .all(
                |impact| impact.kind == EffectiveNeighborImpactKind::PolicyChain
                    && !impact.is_dynamic_range
            ),
        "{:?}",
        diff.effective_neighbor_impact
    );
    let json = super::config_diff_json_value(&diff);
    assert_eq!(
        json["reload_applied"]["effective_neighbor_impact"][0]["kind"],
        serde_json::json!("policy_chain")
    );
}

#[test]
fn transaction_v1_rejects_policy_chain_move_with_tcp_ao_key_rotation_as_non_policy_impact() {
    // TCP-AO key material is redacted from Debug, so the live-impact classifier
    // must compare resolved transport config structurally rather than through
    // rendered strings. A key rotation is restart-required transport impact even
    // when the same candidate also moves a policy chain.
    let with_policy_and_tcp_ao = |default_action: &str, key: &str| {
        format!(
            r#"
{}

[policy.definitions.import-filter]
default_action = "{default_action}"
"#,
            valid_toml().replace(
                "hold_time = 90",
                &format!(
                    "hold_time = 90\nimport_policy_chain = [\"import-filter\"]\ntcp_ao = {{ key = \"{key}\", send_id = 1, recv_id = 1, algorithm = \"hmac(sha256)\" }}"
                ),
            )
        )
    };
    let old = parse(&with_policy_and_tcp_ao("permit", "old-secret")).unwrap();
    let new = parse(&with_policy_and_tcp_ao("deny", "new-secret")).unwrap();
    let peer_groups = diff_peer_groups(&old.peer_groups, &new.peer_groups);
    let policy = diff_policy(&old.policy, &new.policy);
    let impact = super::compute_effective_neighbor_impact(&old, &new, &peer_groups, &policy);

    assert!(
        impact
            .iter()
            .any(|impact| impact.kind == EffectiveNeighborImpactKind::SessionReshape),
        "{impact:?}"
    );
}

#[test]
fn transaction_v1_classifies_peer_group_field_reshape_with_live_neighbor_impact() {
    // A peer-group hold_time edit reshapes the resolved transport_config of its
    // member neighbor — that needs a session reconfigure, not an in-place chain
    // re-apply, so it routes to the session-reshape executor.
    let with_hold = |hold: u32| {
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[security.grpc]
enforcement = "legacy"

[peer_groups.edge]
hold_time = {hold}

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "edge"
"#
        )
    };
    let old = parse(&with_hold(90)).unwrap();
    let new = parse(&with_hold(45)).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(class.is_committable(), "{class:?}");
    assert_eq!(
        class.supported_sections,
        vec![
            "[peer_groups] catalog",
            "effective neighbor session reshape",
        ]
    );
    assert!(class.unsupported_sections.is_empty(), "{class:?}");
    assert!(
        class.restart_required_sections.is_empty(),
        "{:?}",
        class.restart_required_sections
    );
    assert!(
        diff.effective_neighbor_impact
            .iter()
            .any(|impact| impact.kind == EffectiveNeighborImpactKind::SessionReshape),
        "{:?}",
        diff.effective_neighbor_impact
    );
    let json = super::config_diff_json_value(&diff);
    assert_eq!(
        json["reload_applied"]["effective_neighbor_impact"][0]["kind"],
        serde_json::json!("session_reshape")
    );
}

#[test]
fn transaction_v1_classifies_static_peer_group_reassignment_as_session_reshape() {
    let config = |group: &str| {
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[security.grpc]
enforcement = "legacy"

[peer_groups.edge]
hold_time = 90

[peer_groups.core]
hold_time = 45

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "{group}"
"#
        )
    };
    let old = parse(&config("edge")).unwrap();
    let new = parse(&config("core")).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(class.is_committable(), "{class:?}");
    assert_eq!(
        class.supported_sections,
        vec!["[[neighbors]] modify", "effective neighbor session reshape",]
    );
    assert!(class.unsupported_sections.is_empty(), "{class:?}");
    assert!(
        diff.effective_neighbor_impact
            .iter()
            .all(|impact| impact.kind == EffectiveNeighborImpactKind::SessionReshape),
        "{:?}",
        diff.effective_neighbor_impact
    );
}

#[test]
fn transaction_v1_rejects_mixed_policy_and_session_reshape_impact() {
    // A candidate that only needs a policy refresh for one peer and a session
    // rebuild for another requires a combined executor. The planner must not
    // route this to the session-reshape executor and silently skip the
    // policy-only peer.
    let config = |hold: u32, action: &str| {
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[security.grpc]
enforcement = "legacy"

[peer_groups.rebuild]
hold_time = {hold}

[policy.definitions.filter]
default_action = "{action}"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "rebuild"

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
import_policy_chain = ["filter"]
"#
        )
    };
    let old = parse(&config(90, "permit")).unwrap();
    let new = parse(&config(45, "deny")).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(!class.is_committable(), "{class:?}");
    assert!(
        class
            .unsupported_sections
            .contains(&"effective neighbor inheritance impact".to_string()),
        "{:?}",
        class.unsupported_sections
    );
    assert!(
        diff.effective_neighbor_impact
            .iter()
            .any(|impact| impact.kind == EffectiveNeighborImpactKind::PolicyChain),
        "{:?}",
        diff.effective_neighbor_impact
    );
    assert!(
        diff.effective_neighbor_impact
            .iter()
            .any(|impact| impact.kind == EffectiveNeighborImpactKind::SessionReshape),
        "{:?}",
        diff.effective_neighbor_impact
    );
    let json = super::config_diff_json_value(&diff);
    assert_eq!(
        json["reload_applied"]["effective_neighbor_impact"][0]["kind"],
        serde_json::json!("session_reshape")
    );
}

#[test]
fn transaction_v1_classifies_catalog_policy_change_feeding_dynamic_range_as_live_impact() {
    // A policy-definition edit reaches an established dynamic session through
    // its peer group's chain, even with no static neighbor referencing it.
    // SIGHUP live-reconciles dynamic peers, so the transaction planner must
    // surface the range as live-policy impact rather than treating the edit as
    // catalog-only.
    let config = |action: &str| {
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[security.grpc]
enforcement = "legacy"

[peer_groups.ix]
import_policy_chain = ["import-filter"]

[policy.definitions.import-filter]
default_action = "{action}"

[[dynamic_neighbors]]
prefix = "10.30.0.0/16"
peer_group = "ix"
remote_asn = 65030
"#
        )
    };
    let old = parse(&config("permit")).unwrap();
    let new = parse(&config("deny")).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(class.is_committable(), "{class:?}");
    assert_eq!(
        class.supported_sections,
        vec!["[policy] definitions", "[policy] live impact"]
    );
    assert!(class.unsupported_sections.is_empty(), "{class:?}");
    assert_eq!(
        diff.effective_neighbor_impact
            .iter()
            .map(|impact| impact.address.clone())
            .collect::<Vec<_>>(),
        vec!["10.30.0.0/16".to_string()],
        "the dynamic range inheriting the changed policy must be flagged"
    );
    assert!(
        diff.effective_neighbor_impact
            .iter()
            .all(
                |impact| impact.kind == EffectiveNeighborImpactKind::PolicyChain
                    && impact.is_dynamic_range
            ),
        "{:?}",
        diff.effective_neighbor_impact
    );
    assert!(class.restart_required_sections.is_empty());
}

#[test]
fn transaction_v1_classifies_dynamic_range_peer_group_field_reshape_as_session_reshape() {
    // A dynamic range whose peer-group policy did not move but whose inherited
    // session settings did move is not a dynamic live-policy impact; it routes
    // to the session reshape executor, which gracefully resets the range's
    // live sessions after persist so they re-accept under the committed
    // config.
    let config = |hold: u32| {
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[security.grpc]
enforcement = "legacy"

[peer_groups.ix]
hold_time = {hold}

[[dynamic_neighbors]]
prefix = "10.30.0.0/16"
peer_group = "ix"
remote_asn = 65030
"#
        )
    };
    let old = parse(&config(90)).unwrap();
    let new = parse(&config(45)).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(class.is_committable(), "{class:?}");
    assert_eq!(
        class.supported_sections,
        vec![
            "[peer_groups] catalog",
            "effective neighbor session reshape"
        ]
    );
    assert!(class.unsupported_sections.is_empty(), "{class:?}");
    assert!(
        diff.effective_neighbor_impact
            .iter()
            .all(
                |impact| impact.kind == EffectiveNeighborImpactKind::SessionReshape
                    && impact.is_dynamic_range
            ),
        "{:?}",
        diff.effective_neighbor_impact
    );
}

#[test]
fn transaction_v1_classifies_dynamic_range_combined_transport_and_policy_change_as_session_reshape()
{
    // A peer-group edit that moves BOTH the resolved policy chain AND a
    // transport/session field (hold_time) for a dynamic range is not a pure
    // policy-chain move: the live-impact executor reconfigures policy via a
    // Route Refresh but cannot reconfigure the session transport. It routes to
    // the session reshape executor instead — the post-persist graceful reset
    // covers both deltas, because the re-accepted session resolves its
    // transport AND policy chains from the committed config. It must never be
    // mis-classified as a committable dynamic live-policy move (which would
    // silently drop the reconfigure).
    let config = |hold: u32, action: &str| {
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[security.grpc]
enforcement = "legacy"

[peer_groups.ix]
hold_time = {hold}
import_policy_chain = ["filter"]

[policy.definitions.filter]
default_action = "{action}"

[[dynamic_neighbors]]
prefix = "10.30.0.0/16"
peer_group = "ix"
remote_asn = 65030
"#
        )
    };
    let old = parse(&config(90, "permit")).unwrap();
    let new = parse(&config(45, "deny")).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(class.is_committable(), "{class:?}");
    assert!(
        class
            .supported_sections
            .contains(&"effective neighbor session reshape".to_string()),
        "{:?}",
        class.supported_sections
    );
    assert!(
        !class
            .supported_sections
            .contains(&"[policy] live impact".to_string()),
        "{:?}",
        class.supported_sections
    );
    assert!(class.unsupported_sections.is_empty(), "{class:?}");
    assert!(
        diff.effective_neighbor_impact
            .iter()
            .all(
                |impact| impact.kind == EffectiveNeighborImpactKind::SessionReshape
                    && impact.is_dynamic_range
            ),
        "{:?}",
        diff.effective_neighbor_impact
    );
}

#[test]
fn transaction_v1_rejects_dynamic_range_peer_group_reassignment_as_inheritance_impact() {
    // Reassigning a `[[dynamic_neighbors]]` range to a different peer group is
    // a range-record edit, not a peer-group field reshape: sessions accepted
    // under the old group cannot be live-reassigned, and the record edit
    // belongs to the dynamic-neighbor executor family. The reshape family must
    // not claim it.
    let config = |group: &str| {
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[security.grpc]
enforcement = "legacy"

[peer_groups.ix]
hold_time = 90

[peer_groups.transit]
hold_time = 45

[[dynamic_neighbors]]
prefix = "10.30.0.0/16"
peer_group = "{group}"
remote_asn = 65030
"#
        )
    };
    let old = parse(&config("ix")).unwrap();
    let new = parse(&config("transit")).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(!class.is_committable(), "{class:?}");
    assert!(
        class
            .unsupported_sections
            .contains(&"effective neighbor inheritance impact".to_string()),
        "{:?}",
        class.unsupported_sections
    );
    assert!(
        !class
            .supported_sections
            .contains(&"effective neighbor session reshape".to_string()),
        "{:?}",
        class.supported_sections
    );
}

#[test]
fn transaction_v1_classifies_prefix_orf_receive_toggle_as_neighbor_modify() {
    // A bare prefix_orf_receive toggle on an existing neighbor is a
    // [[neighbors]] modify. The transaction surface now commits static neighbor
    // modifies by reconfiguring the peer, so this must be committable — not a
    // no-op (which it silently was while prefix_orf_receive was invisible to
    // the diff).
    let with_orf = |orf: bool| {
        format!(
            r#"
{}

[[neighbors]]
address = "10.0.0.102"
remote_asn = 65102
prefix_orf_receive = {orf}
"#,
            valid_toml()
        )
    };
    let old = parse(&with_orf(false)).unwrap();
    let new = parse(&with_orf(true)).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(!class.is_noop(), "ORF toggle must not classify as a no-op");
    assert!(class.is_committable());
    assert_eq!(class.supported_sections, vec!["[[neighbors]] modify"]);
    assert!(class.unsupported_sections.is_empty());
    assert!(class.restart_required_sections.is_empty());
}

#[test]
fn transaction_v1_rejects_restart_required_sections() {
    let old = parse(valid_toml()).unwrap();
    let new_toml = format!(
        r#"
{}

[[fib_tables]]
name = "edge"
table_id = 1000
metric = 200
"#,
        valid_toml()
    );
    let new = parse(&new_toml).unwrap();
    let diff = diff_config(&old, &new);
    let class = classify_config_transaction_v1(&diff);

    assert!(!class.is_committable());
    assert!(class.supported_sections.is_empty());
    assert!(
        class
            .restart_required_sections
            .contains(&"[[fib_tables]] startup-from-empty".to_string())
    );
}

#[test]
fn runtime_snapshot_token_is_stable_and_changes_with_config() {
    let old = parse(valid_toml()).unwrap();
    let mut new = old.clone();
    new.global.honor_graceful_shutdown = !new.global.honor_graceful_shutdown;

    // Same key + same config => same token; same key + changed config => differs.
    let key = RuntimeSnapshotKey::random();
    let token_a = key.token(&old).unwrap();
    let token_b = key.token(&old).unwrap();
    let token_c = key.token(&new).unwrap();

    assert_eq!(token_a, token_b);
    assert_ne!(token_a, token_c);
    assert!(token_a.starts_with("kv1:"));
}

#[test]
fn runtime_snapshot_token_changes_when_only_a_secret_rotates() {
    // The token hashes the full config, secrets included, so a bare secret
    // rotation still invalidates a stale optimistic-concurrency token (ADR-0076:
    // the token must change if any candidate-relevant config byte changes).
    let mut old = parse(valid_toml()).unwrap();
    old.neighbors[0].md5_password = Some("old-secret".to_string());
    let mut new = old.clone();
    new.neighbors[0].md5_password = Some("new-secret".to_string());

    let key = RuntimeSnapshotKey::random();
    assert_ne!(key.token(&old).unwrap(), key.token(&new).unwrap());
}

#[test]
fn runtime_snapshot_token_differs_across_keys() {
    // The token is keyed: a caller who does not hold the per-process key cannot
    // reproduce the digest for a known config. That is what closes the
    // secret-guessing oracle — two independently seeded keys must disagree on
    // the same config.
    let config = parse(valid_toml()).unwrap();
    let key_a = RuntimeSnapshotKey::random();
    let key_b = RuntimeSnapshotKey::random();
    assert_ne!(key_a.token(&config).unwrap(), key_b.token(&config).unwrap());
}

#[test]
fn runtime_snapshot_token_canonicalizes_map_order() {
    let mut left = parse(valid_toml()).unwrap();
    let mut right = left.clone();

    left.security.grpc.roles.clear();
    left.security
        .grpc
        .roles
        .insert("operator.example".to_string(), GrpcRoleConfig::Operator);
    left.security
        .grpc
        .roles
        .insert("observer.example".to_string(), GrpcRoleConfig::Observer);

    right.security.grpc.roles.clear();
    right
        .security
        .grpc
        .roles
        .insert("observer.example".to_string(), GrpcRoleConfig::Observer);
    right
        .security
        .grpc
        .roles
        .insert("operator.example".to_string(), GrpcRoleConfig::Operator);

    // Map insertion order must not perturb the token (same key both sides).
    let key = RuntimeSnapshotKey::random();
    assert_eq!(key.token(&left).unwrap(), key.token(&right).unwrap());
}

#[test]
fn bfd_rejects_ipv6_link_local_neighbor() {
    // v1 ships IPv4 + IPv6 global only; link-local BFD is deferred to v1.1
    // even though BGP link-local peers now carry interface scope.
    let toml = format!(
        r#"
{}

[[bfd_profiles]]
name = "fast"

[[neighbors]]
address = "fe80::1"
interface = "eth0"
remote_asn = 65003
bfd = {{ profile = "fast" }}
"#,
        valid_toml()
    );
    let err = parse(&toml).unwrap_err();
    let ConfigError::InvalidBfd { reason } = err else {
        panic!("expected InvalidBfd, got {err}");
    };
    assert!(reason.contains("link-local"), "unexpected: {reason}");
}

#[test]
fn bfd_link_local_rejected_via_peer_group_inheritance() {
    // Inheriting BFD from a peer-group must also be rejected on a link-local
    // neighbor — the effective config is what matters, not just the inline form.
    let toml = format!(
        r#"
{}

[[bfd_profiles]]
name = "fast"

[peer_groups.rrc]
bfd = {{ profile = "fast" }}

[[neighbors]]
address = "fe80::2"
interface = "eth0"
remote_asn = 65003
peer_group = "rrc"
"#,
        valid_toml()
    );
    let err = parse(&toml).unwrap_err();
    let ConfigError::InvalidBfd { reason } = err else {
        panic!("expected InvalidBfd, got {err}");
    };
    assert!(reason.contains("link-local"), "unexpected: {reason}");
}

#[test]
fn bfd_diff_marks_restart_required_and_pins() {
    let old = parse(valid_toml()).unwrap();
    let toml = format!(
        r#"
{}

[[bfd_profiles]]
name = "fast"
min_tx_interval = 200
min_rx_interval = 200
multiplier = 3

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
bfd = {{ profile = "fast" }}
"#,
        valid_toml()
    );
    let new = parse(&toml).unwrap();

    // The effective BFD session set changed → restart-required + surfaced.
    let diff = diff_config(&old, &new);
    assert!(diff.bfd_changed);
    assert!(diff.has_restart_required_changes());

    // A SIGHUP reload pins the BFD config back to the live snapshot so the
    // persisted config does not silently advance past the running actor.
    let mut runtime = new.clone();
    assert!(super::pin_bfd_startup_only_runtime(&mut runtime, &old));
    assert!(runtime.bfd_profiles.is_empty(), "profiles pinned to live");
    let pinned_neighbor = runtime
        .neighbors
        .iter()
        .find(|n| n.address == "10.0.0.3")
        .unwrap();
    assert!(
        pinned_neighbor.bfd.is_none(),
        "hot-added neighbor's bfd pinned off until restart"
    );
    // After pinning, a re-diff against the live snapshot shows no BFD drift.
    assert!(!diff_config(&old, &runtime).bfd_changed);
}

/// The effective BFD session set must survive peer-group *membership* changes,
/// not just raw `neighbor.bfd` edits — BFD can be inherited, so moving a
/// neighbor between groups (or in/out of a BFD-bearing one) changes its
/// effective session without touching `neighbor.bfd`. The pin must restore the
/// live effective attachment for an existing neighbor in all three shapes.
#[test]
fn bfd_pin_restores_effective_set_across_peer_group_membership_changes() {
    // Live config: neighbor 10.0.0.3 inherits BFD from peer-group `rrc`.
    let live = parse(&format!(
        r#"
{}

[[bfd_profiles]]
name = "fast"

[peer_groups.rrc]
bfd = {{ profile = "fast" }}

[peer_groups.plain]
hold_time = 30

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "rrc"
"#,
        valid_toml()
    ))
    .unwrap();

    // Detach: move the neighbor to a non-BFD group. Effective BFD would drop to
    // None, but the actor still runs the session → pin must keep it.
    let detached = parse(&format!(
        r#"
{}

[[bfd_profiles]]
name = "fast"

[peer_groups.rrc]
bfd = {{ profile = "fast" }}

[peer_groups.plain]
hold_time = 30

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "plain"
"#,
        valid_toml()
    ))
    .unwrap();
    assert!(diff_config(&live, &detached).bfd_changed);
    let mut runtime = detached.clone();
    assert!(super::pin_bfd_startup_only_runtime(&mut runtime, &live));
    assert!(
        !diff_config(&live, &runtime).bfd_changed,
        "detach via peer-group membership must be pinned back to the live session"
    );

    // Attach: a neighbor with no BFD moves into the BFD group. The actor has no
    // session → pin must keep effective BFD off.
    let plain_live = parse(&format!(
        r#"
{}

[[bfd_profiles]]
name = "fast"

[peer_groups.rrc]
bfd = {{ profile = "fast" }}

[peer_groups.plain]
hold_time = 30

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "plain"
"#,
        valid_toml()
    ))
    .unwrap();
    let attached = live.clone(); // same file: neighbor in `rrc` (BFD) group
    assert!(diff_config(&plain_live, &attached).bfd_changed);
    let mut runtime = attached.clone();
    assert!(super::pin_bfd_startup_only_runtime(
        &mut runtime,
        &plain_live
    ));
    assert!(
        !diff_config(&plain_live, &runtime).bfd_changed,
        "attach via peer-group membership must be pinned off until restart"
    );
}

/// A neighbor *added* in the same reload that *inherits* BFD from a pre-existing
/// BFD peer-group has no live actor session; the pin must materialize a disabled
/// inline block so the runtime's effective set still matches the live actor
/// (the `BfdConfig.enabled` tri-state makes "inherit-but-off" expressible).
#[test]
fn bfd_pin_disables_inherited_bfd_on_newly_added_neighbor() {
    let live = parse(&format!(
        r#"
{}

[[bfd_profiles]]
name = "fast"

[peer_groups.rrc]
bfd = {{ profile = "fast" }}
"#,
        valid_toml()
    ))
    .unwrap();
    // Candidate adds a brand-new neighbor into the BFD-bearing peer-group.
    let added = parse(&format!(
        r#"
{}

[[bfd_profiles]]
name = "fast"

[peer_groups.rrc]
bfd = {{ profile = "fast" }}

[[neighbors]]
address = "10.0.0.9"
remote_asn = 65009
peer_group = "rrc"
"#,
        valid_toml()
    ))
    .unwrap();
    assert!(diff_config(&live, &added).bfd_changed);

    let mut runtime = added.clone();
    assert!(super::pin_bfd_startup_only_runtime(&mut runtime, &live));
    let pinned = runtime
        .neighbors
        .iter()
        .find(|n| n.address == "10.0.0.9")
        .unwrap();
    assert_eq!(
        pinned.bfd.as_ref().map(|b| b.enabled),
        Some(false),
        "added neighbor's inherited BFD must be pinned to a disabled inline block"
    );
    assert!(
        !diff_config(&live, &runtime).bfd_changed,
        "after pinning, the added neighbor must contribute no effective session"
    );
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
    assert_eq!(segments[0].redundancy_mode, RedundancyMode::AllActive);
}

#[test]
fn ethernet_segment_interface_binding_parses_and_resolves() {
    let toml = evpn_toml_with(
        r#"
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.100"

[[evpn_instances]]
vni = 200
rd = "65000:200"
route_targets = ["65000:200"]
local_vtep_ip = "10.0.0.100"

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"
member_vnis = [100]
originator_ip = "10.0.0.100"
interface = "bond0"
recovery_delay_secs = 5

[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:02"
member_vnis = [200]
originator_ip = "10.0.0.100"
"#,
    );
    let config = parse(&toml).unwrap();
    let segments = config.resolve_ethernet_segments().unwrap();
    assert_eq!(
        segments.len(),
        2,
        "bindings must not leak into the domain type"
    );

    let bindings = config.resolve_es_link_bindings().unwrap();
    assert_eq!(
        bindings.len(),
        1,
        "only the bound segment resolves a binding"
    );
    let binding = bindings.get(&segments[0].esi).expect("bound ESI present");
    assert_eq!(binding.interface, "bond0");
    assert_eq!(binding.recovery_delay, std::time::Duration::from_secs(5));
    assert!(
        !bindings.contains_key(&segments[1].esi),
        "unbound segment has no binding entry"
    );
}

#[test]
fn ethernet_segment_recovery_delay_defaults_to_thirty_seconds() {
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
interface = "eth1"
"#,
    );
    let config = parse(&toml).unwrap();
    let bindings = config.resolve_es_link_bindings().unwrap();
    assert_eq!(
        bindings.values().next().unwrap().recovery_delay,
        std::time::Duration::from_secs(30),
        "ADR-0085 decision 3 default"
    );
}

#[test]
fn ethernet_segment_rejects_recovery_delay_without_interface() {
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
recovery_delay_secs = 5
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::InvalidEthernetSegment { .. }),
        "expected InvalidEthernetSegment, got {msg}"
    );
    assert!(
        msg.contains("recovery_delay_secs") && msg.contains("interface"),
        "msg must explain the dependency: {msg}"
    );
}

#[test]
fn ethernet_segment_rejects_recovery_delay_out_of_range() {
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
interface = "eth1"
recovery_delay_secs = 3601
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::InvalidEthernetSegment { .. }),
        "expected InvalidEthernetSegment, got {msg}"
    );
    assert!(msg.contains("3601") && msg.contains("3600"), "{msg}");
}

#[test]
fn ethernet_segment_rejects_empty_or_overlong_interface() {
    for (interface, needle) in [
        ("\"\"", "must not be empty"),
        ("\"a-name-longer-than-ifnamsiz\"", "IFNAMSIZ"),
    ] {
        let toml = evpn_toml_with(&format!(
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
interface = {interface}
"#
        ));
        let err = parse(&toml).unwrap_err();
        let msg = err.to_string();
        assert!(
            matches!(err, ConfigError::InvalidEthernetSegment { .. }),
            "expected InvalidEthernetSegment for {interface}, got {msg}"
        );
        assert!(msg.contains(needle), "{msg}");
    }
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
fn ethernet_segment_accepts_highest_random_weight_df_algorithm() {
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
df_algorithm = "highest-random-weight"
originator_ip = "10.0.0.100"
"#,
    );
    let config = parse(&toml).unwrap();
    let segments = config.resolve_ethernet_segments().unwrap();
    assert_eq!(segments[0].df_algorithm, DfAlgorithm::HighestRandomWeight);
}

#[test]
fn ethernet_segment_accepts_highest_preference_df_algorithm() {
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
df_algorithm = "highest-preference"
df_preference = 100
originator_ip = "10.0.0.100"
"#,
    );
    let config = parse(&toml).unwrap();
    let segments = config.resolve_ethernet_segments().unwrap();
    assert_eq!(segments[0].df_algorithm, DfAlgorithm::HighestPreference);
    assert_eq!(segments[0].df_preference, 100);
}

#[test]
fn ethernet_segment_accepts_lowest_preference_df_algorithm() {
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
df_algorithm = "lowest-preference"
df_preference = 42
originator_ip = "10.0.0.100"
"#,
    );
    let config = parse(&toml).unwrap();
    let segments = config.resolve_ethernet_segments().unwrap();
    assert_eq!(segments[0].df_algorithm, DfAlgorithm::LowestPreference);
    assert_eq!(segments[0].df_preference, 42);
}

#[test]
fn ethernet_segment_accepts_df_dont_preempt_with_preference_algorithm() {
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
df_algorithm = "highest-preference"
df_preference = 100
df_dont_preempt = true
originator_ip = "10.0.0.100"
"#,
    );
    let config = parse(&toml).unwrap();
    let segments = config.resolve_ethernet_segments().unwrap();
    assert!(segments[0].df_dont_preempt);
}

#[test]
fn ethernet_segment_rejects_df_dont_preempt_without_preference_algorithm() {
    // DP is meaningless for default-modulo (the default algorithm) — fail closed
    // rather than silently ignore it.
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
df_dont_preempt = true
originator_ip = "10.0.0.100"
"#,
    );
    let err = parse(&toml).unwrap_err();
    assert!(
        matches!(err, ConfigError::InvalidEthernetSegment { .. }),
        "expected InvalidEthernetSegment, got {err:?}"
    );
}

#[test]
fn ethernet_segment_rejects_df_dont_preempt_with_highest_random_weight() {
    // DP is meaningless for HRW too — only the preference algorithms carry it.
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
df_algorithm = "highest-random-weight"
df_dont_preempt = true
originator_ip = "10.0.0.100"
"#,
    );
    let err = parse(&toml).unwrap_err();
    assert!(
        matches!(err, ConfigError::InvalidEthernetSegment { .. }),
        "expected InvalidEthernetSegment, got {err:?}"
    );
}

#[test]
fn ethernet_segment_accepts_df_dont_preempt_with_lowest_preference() {
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
df_algorithm = "lowest-preference"
df_preference = 42
df_dont_preempt = true
originator_ip = "10.0.0.100"
"#,
    );
    let config = parse(&toml).unwrap();
    let segments = config.resolve_ethernet_segments().unwrap();
    assert_eq!(segments[0].df_algorithm, DfAlgorithm::LowestPreference);
    assert!(segments[0].df_dont_preempt);
}

#[test]
fn m49_interop_configs_describe_preference_df_with_dont_preempt() {
    // Pin the M49 interop fixtures: PE1 (pref 100, revertive) and PE2 (pref
    // 200, non-revertive) both run highest-preference. Guards the smoke against
    // drift in the configs or the DF config surface.
    let pe1 = parse(include_str!(
        "../../tests/interop/configs/rustbgpd-m49-pe1.toml"
    ))
    .unwrap();
    let s1 = pe1.resolve_ethernet_segments().unwrap();
    assert_eq!(s1[0].df_algorithm, DfAlgorithm::HighestPreference);
    assert_eq!(s1[0].df_preference, 100);
    assert!(!s1[0].df_dont_preempt);

    let pe2 = parse(include_str!(
        "../../tests/interop/configs/rustbgpd-m49-pe2.toml"
    ))
    .unwrap();
    let s2 = pe2.resolve_ethernet_segments().unwrap();
    assert_eq!(s2[0].df_algorithm, DfAlgorithm::HighestPreference);
    assert_eq!(s2[0].df_preference, 200);
    assert!(s2[0].df_dont_preempt);
}

#[test]
fn m51_interop_config_describes_non_strict_bfd_with_fast_profile() {
    // Pin the M51 interop fixture: a single eBGP neighbor with non-strict BFD on
    // a "fast" 300/300/3 profile (detection ≈ 900 ms) and a 90 s BGP hold timer.
    // Guards the smoke against drift in the config or the BFD config surface —
    // the whole point of M51 is that a BFD-down failover beats the hold timer.
    let config = parse(include_str!(
        "../../tests/interop/configs/rustbgpd-m51-bfd.toml"
    ))
    .unwrap();
    let profile = &config.bfd_profiles[0];
    assert_eq!(profile.name, "fast");
    assert_eq!(profile.min_tx_interval, 300);
    assert_eq!(profile.min_rx_interval, 300);
    assert_eq!(profile.multiplier, 3);

    let n = config
        .neighbors
        .iter()
        .find(|n| n.address == "10.0.0.2")
        .unwrap();
    assert_eq!(n.hold_time, Some(90));
    let bfd = n.bfd.as_ref().unwrap();
    assert_eq!(bfd.profile, "fast");
    assert!(bfd.enabled);
    assert!(!bfd.strict);
}

#[test]
fn m52_interop_config_enables_multipath_relax_with_mixed_asns() {
    // Pin the M52 interop fixture: multipath_relax on, maximum_paths 2, and two
    // neighbors in *different* ASes (65002 / 65003) — the whole point of the
    // smoke is that only multipath-relax co-installs the equal-length,
    // different-AS paths.
    let config = parse(include_str!(
        "../../tests/interop/configs/rustbgpd-m52-fib-ecmp-relax.toml"
    ))
    .unwrap();
    assert!(config.global.multipath_relax);
    assert_eq!(config.fib_tables[0].maximum_paths, Some(2));
    let asns: Vec<u32> = config.neighbors.iter().map(|n| n.remote_asn).collect();
    assert_eq!(asns, vec![65002, 65003], "peers must be in different ASes");
}

#[test]
fn m55_interop_config_pins_role_matrix_and_strict_neighbor() {
    // Pin the M55 interop fixture: it needs three compatible role pairs, one
    // incompatible Provider/Provider pair, one strict-role/no-remote-role peer,
    // and one raw Customer fixture for deliberate OTC leak injection.
    let config = parse(include_str!(
        "../../tests/interop/configs/rustbgpd-m55-bgp-roles-otc.toml"
    ))
    .unwrap();
    let roles: Vec<(String, u32, Option<BgpRole>, Option<bool>)> = config
        .neighbors
        .iter()
        .map(|n| {
            (
                n.address.clone(),
                n.remote_asn,
                n.role.map(BgpRoleConfig::to_wire),
                n.strict_role,
            )
        })
        .collect();
    assert_eq!(
        roles,
        vec![
            (
                "10.55.1.2".to_string(),
                65002,
                Some(BgpRole::Provider),
                None,
            ),
            (
                "10.55.2.2".to_string(),
                65003,
                Some(BgpRole::RouteServer),
                None,
            ),
            ("10.55.3.2".to_string(), 65004, Some(BgpRole::Peer), None),
            (
                "10.55.4.2".to_string(),
                65005,
                Some(BgpRole::Provider),
                None,
            ),
            (
                "10.55.5.2".to_string(),
                65006,
                Some(BgpRole::Provider),
                Some(true),
            ),
            (
                "10.55.6.2".to_string(),
                65007,
                Some(BgpRole::Provider),
                None,
            ),
        ]
    );
}

#[test]
fn ethernet_segment_rejects_ambiguous_preference_df_algorithm_alias() {
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
        msg.contains("ambiguous RFC 9785 alias"),
        "msg must call out the ambiguous alias: {msg}"
    );
}

#[test]
fn ethernet_segment_accepts_single_active_redundancy_mode() {
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
redundancy_mode = "single-active"
originator_ip = "10.0.0.100"
"#,
    );
    let config = parse(&toml).unwrap();
    let segments = config.resolve_ethernet_segments().unwrap();
    assert_eq!(segments[0].redundancy_mode, RedundancyMode::SingleActive);
}

#[test]
fn ethernet_segment_rejects_unknown_redundancy_mode() {
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
redundancy_mode = "active-standby"
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
        msg.contains("redundancy_mode"),
        "msg must call out redundancy_mode: {msg}"
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

#[test]
fn ethernet_segment_rejects_out_of_range_df_preference() {
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
df_algorithm = "highest-preference"
df_preference = 65536
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
        msg.contains("0..=65535"),
        "msg must name the RFC 9785 preference range: {msg}"
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
    assert_eq!(
        vrf.overlay_index_mode,
        rustbgpd_evpn::OverlayIndexMode::InterfaceLess,
        "omitted overlay_index_mode defaults to interface_less"
    );
}

#[test]
fn evpn_ip_vrf_gateway_ip_mode_requires_linked_l2vni() {
    // gateway_ip on an IP-VRF with no [[evpn_instances]].ip_vrf link
    // is rejected at load (ADR-0087 decision 3).
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
overlay_index_mode = "gateway_ip"
"#,
    );
    // `parse` runs full validation, which resolves the IP-VRF table
    // (validation.rs), so the rejection surfaces here.
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("gateway_ip") && msg.contains("ip_vrf"),
        "expected gateway_ip-without-linked-L2VNI rejection, got {msg}"
    );
}

#[test]
fn evpn_ip_vrf_gateway_ip_mode_with_linked_l2vni_parses() {
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
overlay_index_mode = "gateway_ip"
"#,
    );
    let config = parse(&toml).unwrap();
    let table = config.resolve_evpn_ip_vrfs().unwrap();
    assert_eq!(
        table.get("tenant-blue").unwrap().overlay_index_mode,
        rustbgpd_evpn::OverlayIndexMode::GatewayIp,
    );
}

#[test]
fn evpn_ip_vrf_rejects_unknown_overlay_index_mode() {
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
overlay_index_mode = "asymmetric"
"#,
    );
    assert!(parse(&toml).is_err(), "unknown mode must fail to parse");
}

#[test]
fn evpn_ip_vrf_auto_derives_route_target() {
    let toml = evpn_toml_with(
        r#"
[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
auto_derive_route_target = true
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
    );
    let config = parse(&toml).unwrap();
    let table = config.resolve_evpn_ip_vrfs().unwrap();
    let vrf = table.get("tenant-blue").unwrap();
    // L3VNI / IP-VRF auto-RT is plain AS:VNI (matches FRR's default
    // tenant-VRF auto-RT), not the RFC 8365 opaque L2VNI form.
    assert_eq!(
        vrf.route_targets
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        vec!["65000:5000"]
    );
}

#[test]
fn evpn_ip_vrf_auto_derives_and_preserves_explicit_route_targets() {
    let toml = evpn_toml_with(
        r#"
[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
route_targets = ["65000:9999"]
auto_derive_route_target = true
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
    );
    let config = parse(&toml).unwrap();
    let table = config.resolve_evpn_ip_vrfs().unwrap();
    let vrf = table.get("tenant-blue").unwrap();
    // Explicit RT (65000:9999) and the derived AS:VNI RT (65000:5000)
    // both present; config resolution sorts the RT list.
    assert_eq!(
        vrf.route_targets
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        vec!["65000:5000", "65000:9999"]
    );
}

#[test]
fn evpn_ip_vrf_auto_derive_rejects_four_octet_asn() {
    let toml = r#"
[global]
asn = 4200000000
router_id = "10.0.0.100"
listen_port = 179

[global.telemetry]
prometheus_addr = "127.0.0.1:9179"
log_format = "json"

[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
auto_derive_route_target = true
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#;
    let err = parse(toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("auto_derive_route_target")
            && msg.contains("2-octet AS")
            && msg.contains("route_targets manually"),
        "msg must explain the 4-octet ASN limitation: {msg}"
    );
}

#[test]
fn evpn_ip_vrf_rejects_missing_route_targets_without_auto_derive() {
    let toml = evpn_toml_with(
        r#"
[[evpn_ip_vrfs]]
name = "tenant-blue"
vni = 5000
rd = "65000:5000"
local_vtep_ip = "10.0.0.100"
router_mac = "02:00:00:00:00:01"
vrf_device = "vrf-blue"
l3vxlan_device = "vni5000"
table_id = 5000
"#,
    );
    let err = parse(&toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        matches!(err, ConfigError::InvalidEvpnIpVrf { .. }),
        "got {msg}"
    );
    assert!(msg.contains("route_targets"));
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
    let linked_vnis = table
        .referenced_l2vnis("tenant-blue")
        .expect("tenant-blue should carry linked L2VNI set");
    assert!(linked_vnis.contains(&rustbgpd_evpn::EvpnInstanceId::new(100).unwrap()));
    assert!(
        !table.is_referenced("tenant-red"),
        "tenant-red has no L2VNI binding"
    );
    assert!(table.referenced_l2vnis("tenant-red").is_none());
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

// ─────────────────────────────────────────────────────────────────────
// docs/reload-matrix.md structural test
//
// Catches the "added a Neighbor / PeerGroupConfig field but forgot to
// document its reload class" drift. The list is intentionally
// **maintained explicitly**: serde aliases / #[serde(default)] /
// #[serde(flatten)] make deriving from the struct brittle, and the
// matrix doc has to mention each field name by hand anyway. One line
// to add here when a field lands, with a clear failure message
// pointing at the work that's missing.
// ─────────────────────────────────────────────────────────────────────

/// All Neighbor field names. Updated when `pub struct Neighbor` in
/// `src/config/schema.rs` gains a field. The reload-matrix test below
/// will fail loudly if this list and the doc fall out of sync.
const RELOAD_MATRIX_NEIGHBOR_FIELDS: &[&str] = &[
    "address",
    "interface",
    "remote_asn",
    "description",
    "peer_group",
    "hold_time",
    "max_prefixes",
    "md5_password",
    "tcp_ao",
    "bfd",
    "ttl_security",
    "families",
    "graceful_restart",
    "gr_restart_time",
    "gr_stale_routes_time",
    "llgr_stale_time",
    "local_ipv6_nexthop",
    "route_reflector_client",
    "route_server_client",
    "role",
    "strict_role",
    "prefix_orf_receive",
    "disable_ipv4_unicast",
    "remove_private_as",
    "add_path",
    "log_level",
    "import_policy",
    "export_policy",
    "import_policy_chain",
    "export_policy_chain",
];

/// All `PeerGroupConfig` field names. Mirror of the `Neighbor` list
/// minus the identity triple (`address`, `interface`, `remote_asn`) and
/// TCP-AO.
const RELOAD_MATRIX_PEER_GROUP_FIELDS: &[&str] = &[
    "hold_time",
    "max_prefixes",
    "md5_password",
    "bfd",
    "ttl_security",
    "families",
    "graceful_restart",
    "gr_restart_time",
    "gr_stale_routes_time",
    "llgr_stale_time",
    "local_ipv6_nexthop",
    "route_reflector_client",
    "route_server_client",
    "role",
    "strict_role",
    "prefix_orf_receive",
    "disable_ipv4_unicast",
    "remove_private_as",
    "add_path",
    "log_level",
    "import_policy",
    "export_policy",
    "import_policy_chain",
    "export_policy_chain",
];

fn load_reload_matrix() -> String {
    // CARGO_MANIFEST_DIR is the daemon crate root (`/home/.../rustbgpd`),
    // so the matrix lives next to the docs/ tree two levels up from this
    // test module.
    let matrix_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/reload-matrix.md");
    fs::read_to_string(&matrix_path).unwrap_or_else(|err| {
        panic!(
            "could not read {} for reload-matrix structural test: {err}",
            matrix_path.display()
        )
    })
}

#[test]
fn reload_matrix_documents_every_neighbor_field() {
    let matrix = load_reload_matrix();
    for field in RELOAD_MATRIX_NEIGHBOR_FIELDS {
        let needle = format!("`{field}`");
        assert!(
            matrix.contains(&needle),
            "Neighbor field {needle} is in RELOAD_MATRIX_NEIGHBOR_FIELDS \
             (src/config/tests.rs) but absent from docs/reload-matrix.md. \
             Either add a row for it in the [[neighbors]] section of the \
             matrix, or remove the entry from the list."
        );
    }
}

#[test]
fn reload_matrix_documents_every_peer_group_field() {
    let matrix = load_reload_matrix();
    for field in RELOAD_MATRIX_PEER_GROUP_FIELDS {
        let needle = format!("`{field}`");
        assert!(
            matrix.contains(&needle),
            "PeerGroupConfig field {needle} is in \
             RELOAD_MATRIX_PEER_GROUP_FIELDS (src/config/tests.rs) but \
             absent from docs/reload-matrix.md. Either add a row for it \
             in the [[peer_groups]] section of the matrix, or remove the \
             entry from the list."
        );
    }
}
